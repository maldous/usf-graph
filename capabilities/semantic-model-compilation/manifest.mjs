// Manifest loading for the USF semantic compiler.
//
// semantic-model/manifest.yaml is the canonical repository-local loading registry.
// It projects current Stardog authority inputs but does not itself establish semantic
// truth. This module reads it but never writes it. Every registered entry
// is resolved to { file, graph, contentType, role, order }. contentType and
// role are DERIVED deterministically from the manifest section and file path,
// not read from (or written back to) the manifest.

import { readFileSync } from 'node:fs';
import { join, isAbsolute, normalize, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';

export class ManifestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ManifestError';
  }
}

// The closed, canonical set of roles. A derived role outside this set is a bug.
export const ROLES = Object.freeze([
  'authority',
  'ontology',
  'vocabulary',
  'contracts',
  'assurance',
  'realisation',
  'execution',
  'shapes',
  'rules',
  'derived',
  'permutation',
  'review',
]);

// The one required derivation order. Obligations → evidence → surfaces →
// coverage → readiness. Whole-dataset integrity is checked last.
export const DERIVATION_ORDER = Object.freeze([
  'obligations',
  'evidence',
  'surfaces',
  'coverage',
  'readiness',
]);

const CONTENT_TYPES = Object.freeze({
  '.ttl': 'text/turtle',
  '.trig': 'application/trig',
  '.rq': 'application/sparql-query',
});
const PROVIDER_STATEMENT_LIMITS = Object.freeze({ stardogcloudfree: 1_000_000 });

function authorityPublicationBudget(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ManifestError('authorityPublicationBudget is required');
  }
  const provider = raw.provider;
  const hardStatementLimit = raw.hardStatementLimit;
  const reserveStatementCount = raw.reserveStatementCount;
  const policyIri = raw.policyIri;
  const providerLimit = PROVIDER_STATEMENT_LIMITS[provider];
  if (!providerLimit || hardStatementLimit !== providerLimit
    || !Number.isSafeInteger(reserveStatementCount) || reserveStatementCount < 1
    || reserveStatementCount >= hardStatementLimit
    || typeof policyIri !== 'string' || !policyIri.startsWith('urn:usf:permutationpublicationbudget:')) {
    throw new ManifestError('authorityPublicationBudget is invalid or exceeds the supported provider limit');
  }
  return Object.freeze({
    hardStatementLimit,
    maximumProjectedStatementCount: hardStatementLimit - reserveStatementCount,
    policyIri,
    provider,
    reserveStatementCount,
  });
}

function contentTypeFor(file) {
  const dot = file.lastIndexOf('.');
  const ext = dot >= 0 ? file.slice(dot).toLowerCase() : '';
  const ct = CONTENT_TYPES[ext];
  if (!ct) throw new ManifestError(`Unsupported file extension for ${file}`);
  return ct;
}

// Role derivation is a pure function of (section, file). It never consults the
// manifest for a role field, because roles are not authored there.
function roleFor(section, file) {
  const first = file.split('/')[0];
  const base = file.split('/').pop();
  switch (section) {
    case 'shapes':
      return 'shapes';
    case 'rules':
      return 'rules';
    case 'derived':
      return 'derived';
    case 'review':
      if (first === 'permutation') return 'review';
      throw new ManifestError(`Cannot derive role for review file ${file}`);
    case 'definition':
      if (base === 'ontology.ttl') return 'ontology';
      if (base === 'vocabulary.ttl' || base === 'taxonomy.ttl') return 'vocabulary';
      if (base === 'authority.ttl' || base === 'registry.ttl') return 'authority';
      throw new ManifestError(`Cannot derive role for definition file ${file}`);
    case 'authored':
      if (first === 'contracts') return 'contracts';
      if (first === 'assurance') return 'assurance';
      if (first === 'realisation') return 'realisation';
      if (first === 'execution') return 'execution';
      if (first === 'permutation') return 'permutation';
      if (!file.includes('/')) return 'authority'; // authored top-level registries
      throw new ManifestError(`Cannot derive role for authored file ${file}`);
    default:
      throw new ManifestError(`Unknown section ${section}`);
  }
}

// A registered path must stay inside the graph directory. Reject absolute
// paths, parent traversal, and anything that normalises outside the root.
function assertContained(graphDir, file) {
  if (isAbsolute(file) || file.includes('\\')) {
    throw new ManifestError(`Registered path must be relative and POSIX: ${file}`);
  }
  const abs = normalize(join(graphDir, file));
  const rootWithSep = graphDir.endsWith(sep) ? graphDir : graphDir + sep;
  if (!abs.startsWith(rootWithSep)) {
    throw new ManifestError(`Registered path escapes the graph directory: ${file}`);
  }
  return abs;
}

function entry(section, raw, graphDir, order) {
  if (!raw || (typeof raw.file !== 'string' && typeof raw.collector !== 'string')) {
    throw new ManifestError(`Malformed ${section} entry: missing file or collector`);
  }
  if (raw.file && raw.collector) throw new ManifestError(`Malformed ${section} entry: file and collector are mutually exclusive`);
  const file = raw.file || null;
  return Object.freeze({
    file,
    collector: raw.collector || null,
    path: file ? assertContained(graphDir, file) : null,
    graph: raw.graph || null,
    output: raw.output || null,
    kind: raw.kind || null,
    role: roleFor(section, file || raw.collector),
    contentType: file ? contentTypeFor(file) : 'text/turtle',
    order,
    validationOrder: raw.validationOrder ?? null,
    // Registered SHACL that the live semantic store cannot evaluate (it does
    // not support advanced SHACL) is validated exclusively by the local
    // registered harness; it is still loaded as shape-graph data.
    liveValidation: raw.liveValidation !== false,
  });
}

function retiredGraph(raw) {
  if (!raw || typeof raw.graph !== 'string' || !raw.graph.startsWith('urn:usf:graph:') || /[\s<>]/.test(raw.graph)) {
    throw new ManifestError('Malformed retired graph entry: exact graph IRI is required');
  }
  if (typeof raw.supersededBy !== 'string' || !raw.supersededBy.startsWith('urn:usf:semanticcorrectiondecision:') || /[\s<>]/.test(raw.supersededBy)) {
    throw new ManifestError(`Malformed retired graph entry for ${raw.graph}: semantic correction decision is required`);
  }
  return Object.freeze({ graph: raw.graph, supersededBy: raw.supersededBy });
}

function inactiveSource(raw, graphDir) {
  if (!raw || typeof raw.file !== 'string') {
    throw new ManifestError('Malformed inactive source entry: exact file is required');
  }
  if (raw.disposition !== 'CANDIDATE_MIGRATION_MATERIAL' || raw.authorityEligible !== false) {
    throw new ManifestError(`Inactive source ${raw.file} must be non-authorising candidate migration material`);
  }
  if (typeof raw.contentDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(raw.contentDigest)) {
    throw new ManifestError(`Inactive source ${raw.file} requires an exact sha256 content digest`);
  }
  return Object.freeze({
    authorityEligible: false,
    contentDigest: raw.contentDigest,
    contentType: contentTypeFor(raw.file),
    disposition: raw.disposition,
    file: raw.file,
    path: assertContained(graphDir, raw.file),
  });
}

export function loadManifest(graphDir) {
  const root = normalize(isAbsolute(graphDir) ? graphDir : join(process.cwd(), graphDir));
  const text = readFileSync(join(root, 'manifest.yaml'), 'utf8');
  const doc = parseYaml(text);
  if (!doc || typeof doc !== 'object') throw new ManifestError('manifest.yaml is empty or invalid');

  const definitions = (doc.definitionGraphs || []).map((r) =>
    entry('definition', r, root, r.loadOrder)
  );
  const authored = (doc.authoredGraphs || []).map((r) => entry('authored', r, root, r.loadOrder));
  const reviews = (doc.reviewGraphs || []).map((r) => entry('review', r, root, r.loadOrder));
  if (Array.isArray(doc.observedGraphs) && doc.observedGraphs.length > 0) {
    throw new ManifestError('observedGraphs is retired; current evidence enters through registered authored resources');
  }
  const shapes = (doc.shapeGraphs || []).map((r, i) => entry('shapes', r, root, r.loadOrder ?? 1000 + i));
  const rules = (doc.rules || []).map((r, i) => entry('rules', r, root, i));
  const derived = (doc.derivedGraphs || []).map((r, i) => entry('derived', r, root, r.loadOrder ?? 2000 + i));
  const retired = (doc.retiredGraphs || []).map(retiredGraph);
  const inactiveSources = (doc.inactiveSources || []).map((source) => inactiveSource(source, root));
  const publicationBudget = authorityPublicationBudget(doc.authorityPublicationBudget);

  const fixtures = doc.fixtures
    ? Object.freeze({
        conforming: doc.fixtures.conforming || null,
        defects: doc.fixtures.defects || null,
        loadAsAuthority: doc.fixtures.loadAsAuthority === true,
      })
    : null;

  return Object.freeze({
    root,
    version: doc.version,
    database: doc.database,
    baseIri: doc.baseIri,
    definitions: Object.freeze(definitions),
    authored: Object.freeze(authored),
    reviews: Object.freeze(reviews),
    shapes: Object.freeze(shapes),
    rules: Object.freeze(rules),
    derived: Object.freeze(derived),
    retired: Object.freeze(retired),
    inactiveSources: Object.freeze(inactiveSources),
    publicationBudget,
    fixtures,
  });
}

// The ordered semantic inputs loaded as authorising data. Derived, review and
// fixture data are never part of this list.
export function authoredLoadList(manifest) {
  return [...manifest.definitions, ...manifest.authored].sort((a, b) => a.order - b.order);
}

// Review records are managed, validated observations. They are deliberately
// separate from authoredLoadList so their bytes cannot author or recursively
// change the semantic inventory that they review.
export function reviewLoadList(manifest) {
  return [...manifest.reviews].sort((a, b) => a.order - b.order);
}

// The single shapes graph IRI (all shape files register into one graph).
export function shapesGraph(manifest) {
  const iris = new Set(manifest.shapes.map((s) => s.graph));
  if (iris.size !== 1) throw new ManifestError('Expected exactly one shapes graph IRI');
  return [...iris][0];
}

// Every named graph the compiler is permitted to clear and (re)write: the
// semantic-input and review graphs, the shapes graph, and the derived graphs. This is the
// closed allow-list for named-graph clearing — nothing else may be touched,
// and the whole database is never cleared.
export function managedGraphs(manifest) {
  const set = new Set();
  for (const e of authoredLoadList(manifest)) set.add(e.graph);
  for (const e of reviewLoadList(manifest)) set.add(e.graph);
  set.add(shapesGraph(manifest));
  for (const d of manifest.derived) set.add(d.graph);
  for (const r of manifest.rules) if (r.output) set.add(r.output);
  return [...set];
}

// Exact historical graphs cleared during the same transaction but excluded
// from the current authority witness. This prevents removed derivations from
// silently surviving a manifest change while keeping the clear boundary closed.
export function clearableGraphs(manifest) {
  return [...new Set([...managedGraphs(manifest), ...manifest.retired.map((entry) => entry.graph)])];
}

// Derivation rules in required execution order; integrity checked separately.
export function derivationRules(manifest) {
  return manifest.rules.filter((r) => r.kind === 'derivation');
}
export function integrityRules(manifest) {
  return manifest.rules.filter((r) => r.kind === 'integrity');
}
