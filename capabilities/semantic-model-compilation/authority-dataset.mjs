// The one canonical authority-dataset loader.
//
// Two near-identical loaders previously existed — one under
// `processes/semantic-assurance/`, one under
// `capabilities/repository-external-artefact-materialisation/`. They diverged in
// how they resolved a registered entry to an absolute path, and neither said
// which graphs it was actually loading. A generator, a proof and a command could
// therefore each believe they had read "the live authority" while holding three
// different graph subsets.
//
// This module replaces both. Every generator, proof, command and test routes
// through it, and every load is bound to an EXPLICITLY NAMED SCOPE that declares
// the manifest sections it draws from and records the ones it deliberately omits.
// An authored-only dataset is never called "the complete live authority": the
// scope name and its declared sections travel with the dataset and into every
// generation receipt.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DataFactory, Parser, Store } from 'n3';

import {
  ManifestError,
  authoredLoadList,
  reviewLoadList,
} from './manifest.mjs';

const { namedNode } = DataFactory;

export const RDF_TYPE = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
export const USF = 'urn:usf:ontology:';

// The digest algorithm for a generation input. It is deliberately NOT the
// published authority witness algorithm (`sha256-rdfc10-graph-inventory-v2`):
// this measures the exact registered graph subset a generator read, which may be
// a subset of published authority, and the two must never be confused.
//
// It digests the ORDERED SOURCE BYTES of the scope's registered entries, not the
// parsed quads. A quad-level digest is not reproducible here: the registered
// sources contain blank nodes, and the parser mints fresh blank-node labels on
// every load, so two loads of identical bytes produce different quad terms and
// therefore different digests. Source bytes are exactly "the graph subset used
// to generate", and they are stable across processes and machines.
export const GENERATION_INPUT_DIGEST_ALGORITHM = 'sha256-registered-source-bytes-v1';

// Closed, named scopes. `sections` are manifest sections loaded as data;
// `omits` records what is deliberately left out and why, so a caller reading a
// dataset can always tell what it is not.
export const AUTHORITY_DATASET_SCOPES = Object.freeze({
  // The generation input: definition graphs, authored graphs, shape graphs AND
  // derived graphs.
  //
  // Derived graphs are included because a declared generator depends on them:
  // `urn:usf:generator:proof` selects `usf:ProofObligation`, and 130 of the 135
  // published proof obligations are rule output in `urn:usf:graph:derived:
  // obligations`. An authored-only dataset answers that generator's
  // semanticInputQuery with 5 resources where published authority answers 135,
  // so the projection it produced was never a projection of live authority.
  // `assertGeneratorProjectionParity` proves this scope agrees with the
  // published answer for every declared generator and fails closed otherwise.
  //
  // Review graphs remain omitted: a managed observation about the semantic
  // inventory must not be able to author or recursively change the inventory it
  // reviews. Parity proves no generator depends on them.
  'generation-input': Object.freeze({
    name: 'generation-input',
    sections: Object.freeze(['definitions', 'authored', 'shapes', 'derived']),
    omits: Object.freeze({
      review: 'a managed review observation may not author the inventory it reviews',
    }),
  }),
  // The historical authored-only subset, retained ONLY so a test can demonstrate
  // that it disagrees with published authority. Never a production input.
  'authored-only-superseded': Object.freeze({
    name: 'authored-only-superseded',
    sections: Object.freeze(['definitions', 'authored', 'shapes']),
    omits: Object.freeze({
      review: 'a managed review observation may not author the inventory it reviews',
      derived: 'SUPERSEDED: a declared generator does depend on derived rule output',
    }),
  }),
  // Every managed graph the compiler writes, including review and derived. Used
  // by surfaces that must reason about the complete managed dataset rather than
  // the generation input.
  'complete-managed': Object.freeze({
    name: 'complete-managed',
    sections: Object.freeze(['definitions', 'authored', 'shapes', 'review', 'derived']),
    omits: Object.freeze({}),
  }),
});

export const DEFAULT_SCOPE = 'generation-input';

// Sections whose entries stand alone. `definitions` and `authored` are excluded
// here because they share one declared load order and are resolved together.
const SECTION_ENTRIES = Object.freeze({
  shapes: (manifest) => manifest.shapes,
  review: (manifest) => reviewLoadList(manifest),
  derived: (manifest) => manifest.derived,
});

// `definitions` and `authored` are loaded in the manifest's declared order, so
// they are resolved together rather than section-by-section.
function scopeEntries(manifest, scope) {
  const entries = [];
  if (scope.sections.includes('definitions') || scope.sections.includes('authored')) {
    for (const entry of authoredLoadList(manifest)) {
      const isDefinition = manifest.definitions.includes(entry);
      if (isDefinition && !scope.sections.includes('definitions')) continue;
      if (!isDefinition && !scope.sections.includes('authored')) continue;
      entries.push(entry);
    }
  }
  for (const section of ['shapes', 'review', 'derived']) {
    if (!scope.sections.includes(section)) continue;
    entries.push(...SECTION_ENTRIES[section](manifest));
  }
  return entries.filter((entry) => entry.file || entry.path);
}

// The registered manifest exposes each entry's `file` relative to manifest.root
// and, when it was resolved through `loadManifest`, an absolute `path`. Resolve
// both forms here so no caller has to reimplement the load list.
const entryPath = (root, entry) => entry.path || join(root, entry.file);

function parseEntry(entry, text) {
  const parser = new Parser({ format: entry.contentType, baseIRI: 'urn:usf:' });
  const target = namedNode(entry.graph);
  return parser.parse(text)
    .map((quad) => DataFactory.quad(quad.subject, quad.predicate, quad.object, target));
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

// Deterministic digest of the exact registered graph subset: one sorted line per
// registered entry binding its target graph, its registered path and the sha256
// of its exact bytes.
export function generationInputDigest(entryDigests) {
  const rows = entryDigests
    .map((entry) => `${entry.graph} ${entry.file} ${entry.contentDigest}`)
    .sort();
  return `sha256:${sha256(rows.join('\n'))}`;
}

/**
 * Load one explicitly scoped authority dataset.
 *
 * @param manifest the registered manifest (from `loadManifest`)
 * @param options.scope one of `AUTHORITY_DATASET_SCOPES`; defaults to the
 *   generation input. An unknown scope is a fail-closed error, never a silent
 *   fallback to "everything".
 */
export function loadAuthorityDataset(manifest, options = {}) {
  const scopeName = options.scope ?? DEFAULT_SCOPE;
  const scope = AUTHORITY_DATASET_SCOPES[scopeName];
  if (!scope) throw new ManifestError(`unknown authority dataset scope: ${scopeName}`);

  const store = new Store();
  const entries = scopeEntries(manifest, scope);
  const counts = {};
  const graphs = new Map();
  const entryDigests = [];
  for (const entry of entries) {
    const bytes = readFileSync(entryPath(manifest.root, entry));
    const quads = parseEntry(entry, bytes.toString('utf8'));
    store.addQuads(quads);
    counts[entry.file] = quads.length;
    entryDigests.push({
      graph: entry.graph,
      file: entry.file,
      role: entry.role,
      bytes: bytes.length,
      contentDigest: `sha256:${sha256(bytes)}`,
      quads: quads.length,
    });
    const record = graphs.get(entry.graph) || { graph: entry.graph, role: entry.role, files: [], quads: 0 };
    record.files.push(entry.file);
    record.quads += quads.length;
    graphs.set(entry.graph, record);
  }

  const inventory = [...graphs.values()]
    .map((record) => Object.freeze({ ...record, files: Object.freeze([...record.files].sort()) }))
    .sort((left, right) => left.graph.localeCompare(right.graph));

  return Object.freeze({
    store,
    counts,
    files: entries.length,
    quads: store.size,
    scope: Object.freeze({
      name: scope.name,
      sections: scope.sections,
      omits: scope.omits,
    }),
    graphInventory: Object.freeze(inventory),
    graphCount: inventory.length,
    sourceEntries: Object.freeze(entryDigests
      .map((item) => Object.freeze(item))
      .sort((left, right) => left.file.localeCompare(right.file))),
    inputDigestAlgorithm: GENERATION_INPUT_DIGEST_ALGORITHM,
    inputDigest: generationInputDigest(entryDigests),
  });
}

export function oneObject(store, subject, predicate) {
  const values = store.getObjects(subject, predicate, null);
  return values.length === 1 ? values[0] : null;
}

export function objects(store, subject, predicate) {
  return store.getObjects(subject, predicate, null);
}

export function subjectsOfType(store, classIri) {
  return store.getSubjects(RDF_TYPE, namedNode(classIri), null);
}

export function literalValue(term) {
  return term?.termType === 'Literal' ? term.value : null;
}

export function iriValue(term) {
  return term?.termType === 'NamedNode' ? term.value : null;
}

export function canonicalResource(store, subject) {
  const quads = store.getQuads(subject, null, null, null)
    .map((quad) => ({ predicate: quad.predicate.value, value: quad.object.value, termType: quad.object.termType }))
    .sort((a, b) => a.predicate.localeCompare(b.predicate) || a.value.localeCompare(b.value));
  return { id: subject.value, statements: quads };
}
