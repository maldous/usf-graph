import { readFileSync } from 'node:fs';
import path from 'node:path';
import { Parser, Store } from 'n3';
import YAML from 'yaml';

const ROOT = process.argv[2];
const MODEL = path.join(ROOT, 'semantic-model');
const manifest = YAML.parse(readFileSync(path.join(MODEL, 'manifest.yaml'), 'utf8'));
const SH = 'http://www.w3.org/ns/shacl#';
const RDFS = 'http://www.w3.org/2000/01/rdf-schema#';
const RDFT = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';

function load(files) {
  const store = new Store();
  for (const f of files) {
    const abs = path.join(MODEL, f);
    const parser = new Parser({ format: abs.endsWith('.trig') ? 'application/trig' : 'text/turtle', baseIRI: 'urn:usf:' });
    store.addQuads(parser.parse(readFileSync(abs, 'utf8')));
  }
  return store;
}
const data = load([...manifest.definitionGraphs, ...manifest.authoredGraphs, ...manifest.derivedGraphs].map(g => g.file));
const shapeFileList = manifest.shapeGraphs.map(g => g.file);
const shapesByFile = new Map();
for (const f of shapeFileList) shapesByFile.set(f, load([f]));
const shapes = load(shapeFileList);

const byPath = new Map();
for (const q of shapes.getQuads(null, SH + 'path', null, null)) {
  if (q.object.termType !== 'NamedNode') continue;
  const cs = new Set(shapes.getQuads(q.subject, null, null, null).map(c => c.predicate.value.replace(SH, 'sh:')));
  if (!byPath.has(q.object.value)) byPath.set(q.object.value, []);
  byPath.get(q.object.value).push(cs);
}

// node shapes by targetClass -> {shape, file}
const targetClassIndex = new Map();
for (const [file, st] of shapesByFile) {
  for (const q of st.getQuads(null, SH + 'targetClass', null, null)) {
    if (!targetClassIndex.has(q.object.value)) targetClassIndex.set(q.object.value, []);
    targetClassIndex.get(q.object.value).push({ shape: q.subject.value, file });
  }
}

const preds = new Map();
for (const q of data.getQuads(null, null, null, null)) {
  const p = q.predicate.value;
  if (!/digest$/i.test(p)) continue;
  if (!preds.has(p)) preds.set(p, { count: 0, subjects: new Set(), bad: [], ok: 0, graphs: new Set() });
  const e = preds.get(p);
  e.count++; e.subjects.add(q.subject.value); e.graphs.add(q.graph.value);
  if (q.object.termType === 'Literal' && /^sha256:[0-9a-f]{64}$/.test(q.object.value)) e.ok++;
  else e.bad.push(q.object.value);
}

const lines = [];
for (const [p, e] of [...preds].sort()) {
  const sf = byPath.get(p) || [];
  if (sf.some(s => s.has('sh:pattern'))) continue;
  const domains = data.getQuads(p, RDFS + 'domain', null, null).map(q => q.object.value);
  // classes of actual subjects
  const subjClasses = new Set();
  for (const s of e.subjects) for (const t of data.getQuads(s, RDFT, null, null)) subjClasses.add(t.object.value);
  // pick the domain-declared class if present
  const cands = domains.length ? domains : [...subjClasses];
  const shapesForClass = cands.flatMap(c => (targetClassIndex.get(c) || []).map(x => `${x.shape.replace('urn:usf:shacl:','shp:')}@${x.file}`));
  // instances of domain class missing the predicate (minCount safety)
  let missing = -1;
  if (domains.length === 1) {
    const insts = new Set(data.getQuads(null, RDFT, domains[0], null).map(q => q.subject.value));
    missing = [...insts].filter(s => data.getQuads(s, p, null, null).length === 0).length;
    var instCount = insts.size;
  }
  // max values per subject
  let maxPer = 0;
  for (const s of e.subjects) maxPer = Math.max(maxPer, data.getQuads(s, p, null, null).length);
  lines.push(`${p.replace('urn:usf:ontology:','')}\n  n=${e.count} subjects=${e.subjects.size} maxPerSubject=${maxPer} sha256ok=${e.ok} nonconf=${e.bad.length}` +
    `\n  domain=${domains.map(d=>d.replace('urn:usf:ontology:','')).join(',')||'(none)'} instances=${instCount ?? '?'} missingPred=${missing}` +
    `\n  subjectClasses=${[...subjClasses].map(d=>d.replace('urn:usf:ontology:','')).join(',')}` +
    `\n  targetClassShapes=${shapesForClass.join(' | ')||'(NONE)'}` +
    (e.bad.length ? `\n  NONCONF=${JSON.stringify([...new Set(e.bad)].slice(0,5))}` : ''));
}
console.log(lines.join('\n'));
console.log('\ntotal needing pattern: ' + lines.length);
