import { readFileSync } from 'node:fs';
import { DataFactory, Parser, Store } from 'n3';
import { join } from 'node:path';
import { authoredLoadList } from '../semantic-model-compilation/manifest.mjs';

const { namedNode } = DataFactory;

export const RDF_TYPE = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
export const USF = 'urn:usf:ontology:';

// The registered manifest exposes each entry's `file` relative to manifest.root;
// this loader needs an absolute path. Resolve it here rather than duplicating the
// load list, so the authored set stays exactly the manifest's.
const entryPath = (root, entry) => entry.path || join(root, entry.file);

function parseEntry(root, entry) {
  const parser = new Parser({
    format: entry.contentType,
    baseIRI: 'urn:usf:',
  });
  const parsed = parser.parse(readFileSync(entryPath(root, entry), 'utf8'));
  const target = namedNode(entry.graph);
  return parsed.map((quad) => DataFactory.quad(quad.subject, quad.predicate, quad.object, target));
}

export function loadAuthorityDataset(manifest) {
  const store = new Store();
  const entries = [...authoredLoadList(manifest), ...manifest.shapes];
  const counts = {};
  for (const entry of entries) {
    const quads = parseEntry(manifest.root, entry);
    store.addQuads(quads);
    counts[entry.file] = quads.length;
  }
  return Object.freeze({ store, counts, files: entries.length, quads: store.size });
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
