// Machine-generated semantic coverage inventory over tracked USF source.
// Tracked source == live authority (proven by `npm run authority:drift`
// mismatched: [] and by publish:authority:validate reproducing the live digest),
// so a source-side inventory is authority-equivalent.
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Parser, Store, DataFactory } from 'n3';
import { parse as parseYaml } from 'yaml';

const ROOT = process.env.USF_ROOT || '/usf';
const MODEL = join(ROOT, 'semantic-model');
const USF = 'urn:usf:ontology:';
const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
const RDFS = 'http://www.w3.org/2000/01/rdf-schema#';
const OWL = 'http://www.w3.org/2002/07/owl#';
const SH = 'http://www.w3.org/ns/shacl#';
const { namedNode } = DataFactory;

const manifest = parseYaml(readFileSync(join(MODEL, 'manifest.yaml'), 'utf8'));
const entries = [
  ...(manifest.definitionGraphs || []),
  ...(manifest.authoredGraphs || []),
  ...(manifest.shapeGraphs || []),
  ...(manifest.derivedGraphs || []),
].filter((e) => e.file);

const store = new Store();
const graphOf = new Map(); // "s|p|o" not needed; we track per-file classification
const fileByGraph = new Map();
const definitionFiles = new Set((manifest.definitionGraphs || []).map((e) => e.file));
const shapeFiles = new Set((manifest.shapeGraphs || []).map((e) => e.file));
const derivedFiles = new Set((manifest.derivedGraphs || []).map((e) => e.file));

const perFile = new Map();
for (const entry of entries) {
  const text = readFileSync(join(MODEL, entry.file), 'utf8');
  const parser = new Parser({
    format: entry.file.endsWith('.trig') ? 'application/trig' : 'text/turtle',
    baseIRI: 'urn:usf:',
  });
  const quads = parser.parse(text);
  perFile.set(entry.file, quads);
  for (const q of quads) store.addQuad(q.subject, q.predicate, q.object, namedNode(entry.graph));
  fileByGraph.set(entry.graph, entry.file);
}

const t = (s, p, o) => store.getQuads(s ? namedNode(s) : null, p ? namedNode(p) : null,
  typeof o === 'string' ? namedNode(o) : o, null);
const objs = (s, p) => t(s, p, null).map((q) => q.object);
const subjOfType = (cls) => [...new Set(t(null, `${RDF}type`, cls).map((q) => q.subject.value))];

// ---------------------------------------------------------------- classes
const classes = subjOfType(`${OWL}Class`).filter((c) => c.startsWith(USF)).sort();
const controlledValueClasses = new Set();
const subClassOf = new Map();
for (const c of classes) {
  const parents = objs(c, `${RDFS}subClassOf`).map((o) => o.value);
  subClassOf.set(c, parents);
}
// transitive closure to usf:ControlledValue
const isControlled = (c, seen = new Set()) => {
  if (seen.has(c)) return false;
  seen.add(c);
  const parents = subClassOf.get(c) || [];
  if (parents.includes(`${USF}ControlledValue`)) return true;
  return parents.some((p) => isControlled(p, seen));
};
for (const c of classes) if (isControlled(c)) controlledValueClasses.add(c);

// ------------------------------------------------------------- predicates
const predKinds = [`${OWL}ObjectProperty`, `${OWL}DatatypeProperty`, `${OWL}AnnotationProperty`, `${RDF}Property`];
const predicates = [...new Set(predKinds.flatMap((k) => subjOfType(k)))]
  .filter((p) => p.startsWith(USF)).sort();
const functional = new Set(subjOfType(`${OWL}FunctionalProperty`));

// --------------------------------------------------------------- shapes
// Shape graph quads only.
const shapeStore = new Store();
for (const [file, quads] of perFile) {
  if (!shapeFiles.has(file)) continue;
  for (const q of quads) shapeStore.addQuad(q);
}
const st = (s, p, o) => shapeStore.getQuads(s || null, p ? namedNode(p) : null, o || null, null);
const sObjs = (s, p) => st(s, p, null).map((q) => q.object);

const nodeShapes = [...new Set(st(null, `${RDF}type`, namedNode(`${SH}NodeShape`)).map((q) => q.subject.value))];
const TARGET_PREDS = ['targetClass', 'targetNode', 'targetSubjectsOf', 'targetObjectsOf'];
// Any subject bearing a target declaration counts as an active shape.
const shapeTargets = new Map(); // shapeIri -> {kind:[values]}
for (const kind of TARGET_PREDS) {
  for (const q of st(null, `${SH}${kind}`, null)) {
    const key = q.subject.value;
    if (!shapeTargets.has(key)) shapeTargets.set(key, {});
    (shapeTargets.get(key)[kind] ||= []).push(q.object.value);
  }
}
// implicit class targets: sh:NodeShape that is also an rdfs:Class -> not used here.

// classes with a governing shape (targetClass, or targetNode of a member, or subclass-of-target)
const targetedClasses = new Set();
for (const [, kinds] of shapeTargets) for (const v of kinds.targetClass || []) targetedClasses.add(v);

// property paths constrained anywhere in the shape graph (including nested
// property shapes reached through sh:property / sh:node / sh:qualifiedValueShape)
const constrainedPaths = new Map(); // predicateIri -> Set(constraint components)
const CONSTRAINT_COMPONENTS = ['minCount', 'maxCount', 'datatype', 'class', 'nodeKind', 'pattern',
  'in', 'hasValue', 'minLength', 'maxLength', 'minInclusive', 'maxInclusive', 'lessThan', 'equals',
  'disjoint', 'node', 'not', 'or', 'and', 'xone', 'qualifiedValueShape', 'languageIn', 'uniqueLang',
  'sparql', 'closed'];
for (const q of st(null, `${SH}path`, null)) {
  if (q.object.termType !== 'NamedNode') continue; // sequence/inverse/alternative paths handled below
  const path = q.object.value;
  if (!constrainedPaths.has(path)) constrainedPaths.set(path, new Set());
  const set = constrainedPaths.get(path);
  for (const c of CONSTRAINT_COMPONENTS) {
    if (st(q.subject, `${SH}${c}`, null).length > 0) set.add(c);
  }
}
// complex paths (inverse/sequence) -> record the referenced predicates as "path-referenced"
const complexPathPredicates = new Set();
for (const q of st(null, `${SH}path`, null)) {
  if (q.object.termType === 'NamedNode') continue;
  for (const inner of shapeStore.getQuads(q.object, null, null, null)) {
    if (inner.object.termType === 'NamedNode' && inner.object.value.startsWith(USF)) {
      complexPathPredicates.add(inner.object.value);
    }
  }
}
// predicates named inside sh:select / sh:ask SPARQL text
const sparqlText = [...st(null, `${SH}select`, null), ...st(null, `${SH}ask`, null)]
  .map((q) => q.object.value).join('\n');
const sparqlMentioned = new Set();
for (const p of predicates) {
  const local = p.slice(USF.length);
  if (sparqlText.includes(`usf:${local}`) || sparqlText.includes(`<${p}>`)) sparqlMentioned.add(p);
}
// targetSubjectsOf / targetObjectsOf also govern a predicate
const targetOfPredicates = new Set();
for (const [, kinds] of shapeTargets) {
  for (const v of [...(kinds.targetSubjectsOf || []), ...(kinds.targetObjectsOf || [])]) targetOfPredicates.add(v);
}

// -------------------------------------------------- instances / usage counts
const instanceCount = new Map(); // class -> count of typed instances
for (const c of classes) instanceCount.set(c, t(null, `${RDF}type`, c).length);
const predUse = new Map(); // predicate -> count of assertions (any graph)
for (const p of predicates) predUse.set(p, t(null, p, null).length);
// usage restricted to non-definition graphs (real instance data)
const predUseInstance = new Map();
for (const p of predicates) {
  const q = t(null, p, null).filter((x) => {
    const file = fileByGraph.get(x.graph.value);
    return file && !definitionFiles.has(file) && !shapeFiles.has(file);
  });
  predUseInstance.set(p, q.length);
}

// ------------------------------------------------------ term usage states
const termUsageState = new Map();
for (const q of t(null, `${USF}termUsageState`, null)) termUsageState.set(q.subject.value, q.object.value);
const termUsageRationale = new Map();
for (const q of t(null, `${USF}termUsageRationale`, null)) termUsageRationale.set(q.subject.value, q.object.value);

// -------------------------------------------------------------- domain/range
const domainOf = new Map(); const rangeOf = new Map();
for (const p of predicates) {
  domainOf.set(p, objs(p, `${RDFS}domain`).map((o) => o.value));
  rangeOf.set(p, objs(p, `${RDFS}range`).map((o) => o.value));
}
const inverseOf = new Map();
for (const q of t(null, `${OWL}inverseOf`, null)) inverseOf.set(q.subject.value, q.object.value);

// --------------------------------------------------------------- test corpus
const testFiles = [];
const walk = (dir) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.includes('.test.') || e.name.includes('hostile-test')) testFiles.push(p);
  }
};
for (const d of ['assurance', 'capabilities', 'configuration', 'processes', 'provider-bindings']) walk(join(ROOT, d));
const testCorpus = testFiles.map((f) => readFileSync(f, 'utf8')).join('\n');
const testsTrig = readFileSync(join(MODEL, 'assurance/tests.trig'), 'utf8');
const mentionedInTests = (iri) => {
  const local = iri.slice(USF.length);
  return testCorpus.includes(local) || testsTrig.includes(local);
};

// ---------------------------------------------------------------- reporting
const classRows = classes.map((c) => ({
  class: c.slice(USF.length),
  iri: c,
  label: objs(c, `${RDFS}label`).map((o) => o.value)[0] || null,
  comment: objs(c, `${RDFS}comment`).length > 0,
  subClassOf: (subClassOf.get(c) || []).map((p) => p.startsWith(USF) ? p.slice(USF.length) : p),
  controlledValue: controlledValueClasses.has(c),
  instances: instanceCount.get(c),
  hasTargetClassShape: targetedClasses.has(c),
  inTests: mentionedInTests(c),
}));

const predRows = predicates.map((p) => {
  const constraints = [...(constrainedPaths.get(p) || new Set())].sort();
  return {
    predicate: p.slice(USF.length),
    iri: p,
    domain: (domainOf.get(p) || []).map((d) => d.startsWith(USF) ? d.slice(USF.length) : d),
    range: (rangeOf.get(p) || []).map((d) => d.startsWith(USF) ? d.slice(USF.length) : d),
    functional: functional.has(p),
    inverseOf: inverseOf.get(p) || null,
    constraints,
    shapeGoverned: constraints.length > 0 || sparqlMentioned.has(p)
      || targetOfPredicates.has(p) || complexPathPredicates.has(p),
    viaSparqlOnly: constraints.length === 0 && sparqlMentioned.has(p),
    assertions: predUse.get(p),
    instanceAssertions: predUseInstance.get(p),
    termUsageState: (termUsageState.get(p) || '').replace('urn:usf:termusagestate:', '') || null,
    rationale: termUsageRationale.has(p),
    inTests: mentionedInTests(p),
  };
});

// controlled vocabularies: which controlled-value classes are closed by sh:in
const shInLists = new Set();
for (const q of st(null, `${SH}in`, null)) {
  // walk the RDF list
  let node = q.object; const members = [];
  const first = (n) => shapeStore.getQuads(n, namedNode(`${RDF}first`), null, null)[0]?.object;
  const rest = (n) => shapeStore.getQuads(n, namedNode(`${RDF}rest`), null, null)[0]?.object;
  let guard = 0;
  while (node && node.value !== `${RDF}nil` && guard++ < 500) {
    const f = first(node); if (f) members.push(f.value);
    node = rest(node);
  }
  for (const m of members) shInLists.add(m);
}
const controlledRows = [...controlledValueClasses].sort().map((c) => {
  const inst = t(null, `${RDF}type`, c).map((q) => q.subject.value);
  const closedMembers = inst.filter((i) => shInLists.has(i));
  // is the class range-restricted anywhere by sh:in over exactly its members?
  return {
    class: c.slice(USF.length),
    instances: inst.length,
    membersAppearingInShIn: closedMembers.length,
    closed: inst.length > 0 && closedMembers.length === inst.length,
    hasTargetClassShape: targetedClasses.has(c),
  };
});

const out = {
  generatedFrom: 'tracked source at /usf semantic-model (drift-verified equal to live)',
  totals: {
    graphs: entries.length,
    classes: classes.length,
    classesWithTargetClassShape: classRows.filter((r) => r.hasTargetClassShape).length,
    classesZeroInstances: classRows.filter((r) => r.instances === 0).length,
    controlledValueClasses: controlledRows.length,
    controlledValueClassesClosedByShIn: controlledRows.filter((r) => r.closed).length,
    predicates: predicates.length,
    predicatesShapeGoverned: predRows.filter((r) => r.shapeGoverned).length,
    predicatesWithPropertyShapeConstraints: predRows.filter((r) => r.constraints.length > 0).length,
    predicatesSparqlOnly: predRows.filter((r) => r.viaSparqlOnly).length,
    predicatesNoGovernance: predRows.filter((r) => !r.shapeGoverned).length,
    predicatesZeroAssertions: predRows.filter((r) => r.assertions === 0).length,
    predicatesZeroInstanceAssertions: predRows.filter((r) => r.instanceAssertions === 0).length,
    predicatesWithReservedFutureScope: predRows.filter((r) => r.termUsageState === 'reservedfuturescope').length,
    predicatesNotInTests: predRows.filter((r) => !r.inTests).length,
    predicatesWithDomain: predRows.filter((r) => r.domain.length > 0).length,
    predicatesWithRange: predRows.filter((r) => r.range.length > 0).length,
  },
  classes: classRows,
  predicates: predRows,
  controlledVocabularies: controlledRows,
  shapes: {
    nodeShapeCount: nodeShapes.length,
    shapesWithTargets: shapeTargets.size,
    targets: [...shapeTargets].map(([iri, kinds]) => ({ shape: iri, ...kinds })),
  },
};
writeFileSync('/tmp/claude-0/-usf/80755bd0-e418-43b1-8cb9-5c3a82c2c8b1/scratchpad/inventory.json', JSON.stringify(out, null, 1));
console.log(JSON.stringify(out.totals, null, 1));
