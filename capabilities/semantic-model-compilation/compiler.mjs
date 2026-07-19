// The USF semantic compiler.
//
// JavaScript owns orchestration only. The repository-local graph owns all
// meaning: ontology, vocabulary, SHACL constraints, derivation rules,
// integrity invariants and readiness. Nothing here duplicates that meaning,
// and authored graph files are never modified during normal execution.

import { createHash } from 'node:crypto';
import { readFileSync, statSync, readdirSync } from 'node:fs';
import { basename, dirname, join, relative, sep } from 'node:path';
import { DataFactory, Parser, Store, Writer } from 'n3';
import * as rdfCanonize from 'rdf-canonize';
import {
  authoredLoadList,
  shapesGraph,
  managedGraphs,
  clearableGraphs,
  derivationRules,
  integrityRules,
  DERIVATION_ORDER,
} from './manifest.mjs';
import { EXTERNAL_ORIGIN_PATTERNS, validateOriginIndependence } from './origin-independence.mjs';

export class CompilerError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'CompilerError';
    Object.assign(this, details);
  }
}

export function verificationConforms(report) {
  return report.reachable === true && report.validationConforms === true &&
    report.integrityConforms === true && report.contaminationCount === 0 &&
    report.missingGraphs.length === 0 && report.unexpectedGraphs.length === 0 &&
    Number.isFinite(report.readinessCount) && report.readinessCount > 0;
}

// Forbidden content that must never appear in graph data. These are generic
// detectors (work-tracking, repository and source-control markers), not
// references to any specific item. The shapes graph legitimately contains
// these strings as its own SHACL detectors, so it is always excluded from
// contamination scans.
export const CONTAMINATION_PATTERNS = Object.freeze([
  'github\\.com',
  'gitlab\\.com',
  'ADR-[0-9]',
  'branchName',
  'commitSha',
  'refs/heads',
  ...EXTERNAL_ORIGIN_PATTERNS,
]);
const CONTAMINATION_RE = new RegExp(CONTAMINATION_PATTERNS.join('|'));
// Backslashes must be doubled so the SPARQL string literal yields each
// intended detector rather than an invalid string escape.
const SPARQL_CONTAMINATION = CONTAMINATION_PATTERNS.join('|').replace(/\\/g, '\\\\');
const SHAPES_GRAPH_MARKER = 'urn:usf:graph:shapes';
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

const readText = (p) => readFileSync(p, 'utf8');
const { namedNode } = DataFactory;
const RDF_TYPE = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
const USF = 'urn:usf:ontology:';
const NQUADS = 'application/n-quads';
const XSD = 'http://www.w3.org/2001/XMLSchema#';
const XSD_INTEGER_FAMILY = new Set([
  'nonNegativeInteger', 'positiveInteger', 'nonPositiveInteger', 'negativeInteger',
  'long', 'int', 'short', 'byte',
  'unsignedLong', 'unsignedInt', 'unsignedShort', 'unsignedByte',
].map((name) => XSD + name));

function validatedReceipt(receipt, shapes, phase) {
  // Bind the exact document bytes transmitted for validation: non-base shape
  // documents carry the shared declaration header prepended by
  // shapeConstraints, so raw file bytes would not match what was validated.
  const expectedInputs = shapes.map(({ file, content }) => ({
    path: `semantic-model/${file}`,
    digest: sha256(content),
  })).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const expectedSetDigest = sha256(canonicalJson(expectedInputs));
  const fields = ['conforms', 'observationSetDigest', 'receiptDigest', 'validatedDocumentCount', 'validatedDocumentSetDigest'];
  const core = receipt && typeof receipt === 'object' ? Object.fromEntries(fields.filter((field) => field !== 'receiptDigest').map((field) => [field, receipt[field]])) : null;
  if (!receipt || Array.isArray(receipt) || canonicalJson(Object.keys(receipt).sort()) !== canonicalJson(fields)
      || receipt.conforms !== true || receipt.validatedDocumentCount !== expectedInputs.length
      || receipt.validatedDocumentSetDigest !== expectedSetDigest
      || !SHA256.test(receipt.observationSetDigest || '')
      || receipt.receiptDigest !== sha256(canonicalJson(core))) {
    throw new CompilerError('live SHACL provider returned an incomplete or mismatched validation receipt', { phase });
  }
  return Object.freeze(receipt);
}

function canonicalLiteralQuad(item) {
  const object = item.object;
  if (object.termType !== 'Literal' || !XSD_INTEGER_FAMILY.has(object.datatype.value)) return item;
  return DataFactory.quad(
    item.subject,
    item.predicate,
    DataFactory.literal(object.value, DataFactory.namedNode(XSD + 'integer')),
    item.graph,
  );
}

export async function canonicalNQuads(nquads) {
  const quads = new Parser({ format: NQUADS }).parse(nquads).map(canonicalLiteralQuad);
  return rdfCanonize.canonize(quads, { algorithm: 'RDFC-1.0', format: NQUADS });
}

export async function canonicalGraphDigest(nquads) {
  const canonical = await canonicalNQuads(nquads);
  return {
    algorithm: 'RDFC-1.0',
    digestAlgorithm: 'sha256',
    sha256: createHash('sha256').update(canonical).digest('hex'),
    triples: canonical.split('\n').filter(Boolean).length,
  };
}

function nquadsFor(quads) {
  return new Promise((resolveOutput, reject) => {
    const writer = new Writer({ format: 'N-Quads' });
    writer.addQuads(quads);
    writer.end((error, output) => error ? reject(error) : resolveOutput(output));
  });
}

function candidateGraphStores(manifest) {
  return new Map(managedGraphs(manifest).map((graph) => [graph, new Store()]));
}

function addCandidateContent(stores, content, contentType, targetGraph, scope) {
  const parsed = new Parser({ format: contentType, baseIRI: 'urn:usf:' }).parse(content);
  const blankNodes = new Map();
  const transport = [];
  const scoped = (term) => {
    if (term.termType !== 'BlankNode') return term;
    if (!blankNodes.has(term.value)) blankNodes.set(term.value, DataFactory.blankNode(`${scope}_${blankNodes.size}`));
    return blankNodes.get(term.value);
  };
  for (const item of parsed) {
    const graph = item.graph.termType === 'NamedNode' ? item.graph.value : targetGraph;
    const store = stores.get(graph);
    if (!store) throw new Error(`candidate RDF writes outside a managed graph: ${graph ?? '(default)'}`);
    const subject = scoped(item.subject);
    const object = scoped(item.object);
    store.addQuad(DataFactory.quad(subject, item.predicate, object));
    transport.push(DataFactory.quad(subject, item.predicate, object, namedNode(graph)));
  }
  return transport;
}

function registryParityFailures(manifest) {
  const failures = [];
  const registry = manifest.definitions.find((entry) => entry.file === 'registry.ttl');
  if (!registry) return ['manifest has no registry.ttl definition graph'];
  let store;
  try {
    store = new Store(new Parser({ format: 'text/turtle', baseIRI: 'urn:usf:' }).parse(readText(registry.path)));
  } catch (error) {
    return [`registry.ttl is not parseable RDF: ${error.message}`];
  }
  const one = (subject, local) => {
    const values = store.getObjects(subject, namedNode(`${USF}${local}`), null);
    return values.length === 1 ? values[0] : null;
  };
  const namedGraphClass = namedNode(`${USF}NamedGraph`);
  const registryRows = new Map();
  for (const subject of store.getSubjects(RDF_TYPE, namedGraphClass, null)) {
    const graph = one(subject, 'graphIri')?.value;
    if (!graph) { failures.push(`registry named graph has no unique graphIri: ${subject.value}`); continue; }
    if (registryRows.has(graph)) failures.push(`registry graph IRI is declared more than once: ${graph}`);
    registryRows.set(graph, {
      subject,
      graphClass: one(subject, 'graphClass')?.value,
      loadOrder: Number(one(subject, 'loadOrder')?.value),
      validationOrder: Number(one(subject, 'graphValidationOrder')?.value),
    });
  }
  const expected = new Map();
  const add = (entries, graphClass) => {
    for (const entry of entries) {
      const prior = expected.get(entry.graph);
      const row = { graphClass: `urn:usf:graphclass:${graphClass}`, loadOrder: entry.order, validationOrder: entry.validationOrder };
      if (prior && (prior.graphClass !== row.graphClass || prior.loadOrder !== row.loadOrder || prior.validationOrder !== row.validationOrder)) {
        failures.push(`manifest entries disagree for shared graph: ${entry.graph}`);
      } else expected.set(entry.graph, row);
    }
  };
  add(manifest.definitions, 'definitiongraph');
  add(manifest.authored, 'authoredgraph');
  add(manifest.shapes, 'shapegraph');
  add(manifest.derived, 'derivedgraph');
  for (const graph of expected.keys()) if (!registryRows.has(graph)) failures.push(`manifest graph absent from RDF registry: ${graph}`);
  for (const graph of registryRows.keys()) if (!expected.has(graph)) failures.push(`RDF registry graph absent from manifest: ${graph}`);
  for (const [graph, row] of expected) {
    const actual = registryRows.get(graph);
    if (!actual) continue;
    if (actual.graphClass !== row.graphClass) failures.push(`registry graph class mismatch for ${graph}`);
    if (!Number.isFinite(row.loadOrder) || actual.loadOrder !== row.loadOrder) failures.push(`registry load order mismatch for ${graph}`);
    if (!Number.isFinite(row.validationOrder) || actual.validationOrder !== row.validationOrder) failures.push(`registry validation order mismatch for ${graph}`);
  }
  const derivedByOrder = [...manifest.derived].sort((a, b) => a.order - b.order).map((entry) => entry.graph);
  const ruleOutputs = derivationRules(manifest).map((rule) => rule.output);
  if (derivedByOrder.join('\0') !== ruleOutputs.join('\0')) failures.push('registry/manifest derived graph order differs from compiler rule order');
  const ruleClass = namedNode(`${USF}DerivationRule`);
  const registeredRules = new Map();
  for (const subject of store.getSubjects(RDF_TYPE, ruleClass, null)) {
    const name = one(subject, 'canonicalName')?.value;
    const graphSubject = one(subject, 'inNamedGraph');
    const graph = graphSubject ? one(graphSubject, 'graphIri')?.value : null;
    if (!name || !graph) failures.push(`registry derivation rule is incomplete: ${subject.value}`);
    else registeredRules.set(name, graph);
  }
  for (const rule of derivationRules(manifest)) {
    const name = rule.file.split('/').pop().replace('.rq', '').replace(/[^a-z0-9]/g, '');
    if (registeredRules.get(name) !== rule.output) failures.push(`registry rule output mismatch for ${name}`);
  }
  if (registeredRules.size !== derivationRules(manifest).length) failures.push('registry and manifest derivation rule sets differ');
  return failures;
}

// --- Local, offline checks -------------------------------------------------

// Recursively list loadable graph files (*.ttl / *.trig / *.rq) under root.
function listLoadable(root) {
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, name.name);
      if (name.isDirectory()) walk(full);
      else if (/\.(ttl|trig|rq)$/.test(name.name)) out.push(full);
    }
  };
  walk(root);
  return out;
}

export function checkLocal(manifest) {
  const failures = [];
  const fail = (m) => failures.push(m);
  const originRoot = ['graph', 'semantic-model'].includes(basename(manifest.root))
    ? dirname(manifest.root)
    : manifest.root;
  const originResult = validateOriginIndependence(originRoot);
  for (const finding of originResult.findings) fail(`origin independence ${finding.code}: ${finding.path}:${finding.line}`);

  const all = [
    ...manifest.definitions,
    ...manifest.authored,
    ...manifest.shapes,
    ...manifest.rules,
    ...manifest.derived,
  ];

  // Parse every RDF authority, snapshot, and fixture file locally. TriG graph
  // placement is checked against the registered graph IRI so valid syntax in
  // the wrong named graph cannot pass merely because Stardog accepts it.
  const entryByPath = new Map(all.filter((entry) => entry.path).map((entry) => [entry.path, entry]));
  for (const path of listLoadable(manifest.root)) {
    if (path.endsWith('.rq')) continue;
    try {
      const format = path.endsWith('.trig') ? 'application/trig' : 'text/turtle';
      const quads = new Parser({ format, baseIRI: 'urn:usf:' }).parse(readText(path));
      const registeredEntry = entryByPath.get(path);
      if (registeredEntry && format === 'application/trig') {
        const misplaced = quads.find((quad) => quad.graph.termType !== 'NamedNode' || quad.graph.value !== registeredEntry.graph);
        if (misplaced) fail(`registered TriG file writes outside its graph: ${relative(manifest.root, path)}`);
      }
    } catch (error) {
      fail(`RDF parse failed for ${relative(manifest.root, path)}: ${error.message}`);
    }
  }

  // Every registered file exists, is a regular file, and is non-empty.
  for (const e of all) {
    if (e.collector && !e.path) continue;
    let st;
    try {
      st = statSync(e.path);
    } catch {
      fail(`registered file missing: ${e.file}`);
      continue;
    }
    if (!st.isFile()) fail(`registered path is not a file: ${e.file}`);
    else if (readText(e.path).trim().length === 0) fail(`registered file is empty: ${e.file}`);
  }

  // No unregistered loadable file exists outside the fixtures directory.
  const registered = new Set(all.map((e) => e.path).filter(Boolean));
  const fixturesRoot = manifest.fixtures
    ? join(manifest.root, 'fixtures')
    : null;
  for (const path of listLoadable(manifest.root)) {
    if (registered.has(path)) continue;
    if (fixturesRoot && (path === fixturesRoot || path.startsWith(fixturesRoot + sep))) continue;
    fail(`unregistered loadable file: ${relative(manifest.root, path)}`);
  }

  // Graph IRIs of authored data are unique; derived IRIs are unique; the two
  // sets are disjoint (authored and derived are distinguishable).
  const authoredGraphs = authoredLoadList(manifest).map((e) => e.graph);
  const dupAuthored = authoredGraphs.filter((g, i) => authoredGraphs.indexOf(g) !== i);
  if (dupAuthored.length) fail(`duplicate authored graph IRI: ${[...new Set(dupAuthored)].join(', ')}`);

  const derivedGraphs = manifest.derived.map((d) => d.graph);
  const dupDerived = derivedGraphs.filter((g, i) => derivedGraphs.indexOf(g) !== i);
  if (dupDerived.length) fail(`duplicate derived graph IRI: ${[...new Set(dupDerived)].join(', ')}`);

  for (const g of authoredGraphs) {
    if (derivedGraphs.includes(g)) fail(`graph IRI used as both authored and derived: ${g}`);
  }
  const retiredGraphs = manifest.retired.map((entry) => entry.graph);
  const duplicateRetired = retiredGraphs.filter((graph, index) => retiredGraphs.indexOf(graph) !== index);
  if (duplicateRetired.length) fail(`duplicate retired graph IRI: ${[...new Set(duplicateRetired)].join(', ')}`);
  const currentGraphs = new Set([...authoredGraphs, ...derivedGraphs, shapesGraph(manifest)]);
  for (const graph of retiredGraphs) {
    if (currentGraphs.has(graph)) fail(`retired graph IRI remains current: ${graph}`);
  }

  // Named-graph load order is deterministic across definitions, authored,
  // shapes and derived snapshots. Multiple shape files share one
  // graph and therefore one order.
  const orderedGraphEntries = [
    ...authoredLoadList(manifest),
    manifest.shapes[0],
    ...manifest.derived,
  ].filter(Boolean);
  const orders = orderedGraphEntries.map((e) => e.order);
  if (orders.some((o, i) => orders.indexOf(o) !== i) || orders.some((o) => typeof o !== 'number')) {
    fail('authored load order is not a unique, total ordering');
  }

  // Rule order is deterministic and matches the one required derivation order.
  const ruleNames = derivationRules(manifest).map((r) => r.file.split('/').pop().replace('.rq', ''));
  if (ruleNames.join(',') !== DERIVATION_ORDER.join(',')) {
    fail(`derivation rule order is ${ruleNames.join(',')}, expected ${DERIVATION_ORDER.join(',')}`);
  }
  if (integrityRules(manifest).length === 0) fail('no integrity rule registered');

  for (const failure of registryParityFailures(manifest)) fail(failure);

  // Each rule output is a registered derived graph (no rule writes elsewhere).
  for (const r of derivationRules(manifest)) {
    if (!derivedGraphs.includes(r.output)) fail(`rule ${r.file} targets unregistered graph ${r.output}`);
  }

  // Fixture data is never treated as authority.
  if (manifest.fixtures && manifest.fixtures.loadAsAuthority) {
    fail('fixtures are marked loadAsAuthority: they must never be loaded as authority');
  }

  // Contamination scan of file contents (shapes files excluded — they are the
  // detectors and legitimately contain the patterns).
  for (const e of all) {
    if (e.role === 'shapes') continue;
    if (!e.path) continue;
    if (CONTAMINATION_RE.test(readText(e.path))) {
      fail(`forbidden content in graph file: ${e.file}`);
    }
  }

  if (failures.length) {
    throw new CompilerError('local checks failed', { phase: 'check', failures });
  }
  return {
    ok: true,
    files: all.length,
    authoredGraphs: authoredGraphs.length,
    derivedGraphs: derivedGraphs.length,
    originIndependenceDigest: originResult.resultDigest,
    originIndependenceScannedFiles: originResult.scannedFileCount,
  };
}

// --- Deterministic operation plan -----------------------------------------

// The exact, ordered sequence of graph operations a compile performs. It is a
// pure function of the manifest, so two runs produce an identical plan — the
// basis of idempotence.
export function buildPlan(manifest) {
  const plan = [];
  for (const g of clearableGraphs(manifest)) plan.push({ op: 'clear', graph: g });
  for (const e of authoredLoadList(manifest)) plan.push({ op: 'load', graph: e.graph, file: e.file });
  const sg = shapesGraph(manifest);
  for (const s of manifest.shapes) plan.push({ op: 'loadShapes', graph: sg, file: s.file });
  plan.push({ op: 'validate', state: 'authored' });
  for (const r of derivationRules(manifest)) plan.push({ op: 'derive', rule: r.file, graph: r.output });
  plan.push({ op: 'validate', state: 'derived' });
  plan.push({ op: 'integrity' });
  plan.push({ op: 'contamination' });
  plan.push({ op: 'verifyCounts' });
  plan.push({ op: 'commit' });
  return plan;
}

// --- Compile ---------------------------------------------------------------

// Preserve module boundaries so the Stardog adapter can validate bounded
// documents. A single concatenated request exceeds the managed service's
// accepted SHACL payload even though every module is valid Turtle.
function shapeConstraints(manifest) {
  const documents = manifest.shapes
    .filter((shape) => shape.liveValidation !== false)
    .map((shape) => ({ file: shape.file, path: shape.path, content: readText(shape.path) }));
  const base = documents.find((document) => document.file === 'shapes.ttl');
  if (!base) throw new CompilerError('base shapes document is not registered', {
    phase: 'shapes:prefixes',
  });
  if (documents.length === 1) return documents;
  const firstShape = /(?:^|\n)shp:[A-Za-z0-9_-]+\s+a\s+sh:NodeShape\b/m.exec(base.content);
  const boundary = firstShape?.index ?? base.content.length;
  const sharedDeclarations = base.content.slice(0, boundary);
  return documents.map((document) => document === base ? document : {
    ...document,
    content: `${sharedDeclarations}\n${document.content}`,
  });
}

const countInTx = async (client, tx, graph) => {
  const rows = await client.selectInTransaction(
    tx,
    `SELECT (COUNT(*) AS ?c) WHERE { GRAPH <${graph}> { ?s ?p ?o } }`
  );
  return rows.length ? Number(rows[0].c.value) : 0;
};

async function candidateGraphWitness(stores) {
  const graphs = [];
  for (const graph of [...stores.keys()].sort()) {
    graphs.push({ graph, ...await canonicalGraphDigest(await nquadsFor(
      stores.get(graph).getQuads(null, null, null, null),
    )) });
  }
  const body = graphs.map(({ graph, sha256, triples }) => `${graph}=${sha256}:${triples}`).join('\n');
  return {
    algorithm: 'sha256-rdfc10-managed-graph-inventory-v1',
    digest: `sha256:${createHash('sha256').update(body).digest('hex')}`,
    graphs,
  };
}

async function liveManagedGraphWitness(manifest, client) {
  const graphs = [];
  for (const graph of [...managedGraphs(manifest)].sort()) {
    const query = `CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`;
    const content = await client.construct(query, NQUADS);
    graphs.push({ graph, ...await canonicalGraphDigest(content) });
  }
  const body = graphs.map(({ graph, sha256, triples }) => `${graph}=${sha256}:${triples}`).join('\n');
  return {
    algorithm: 'sha256-rdfc10-managed-graph-inventory-v1',
    digest: `sha256:${createHash('sha256').update(body).digest('hex')}`,
    graphs,
  };
}

function rollbackFailure(primaryError, ...rollbackErrors) {
  return new CompilerError('compiler transaction failed and rollback was not confirmed', {
    phase: primaryError.phase ?? 'compile',
    cause: primaryError,
    errors: [primaryError, ...rollbackErrors],
    rollbackConfirmed: false,
  });
}

export async function compile({
  manifest,
  client,
  publicationMode = 'commit',
}) {
  if (!['commit', 'validate'].includes(publicationMode)) {
    throw new CompilerError('unsupported compiler publication mode', {
      phase: 'compile:configuration',
      publicationMode,
    });
  }
  checkLocal(manifest);
  await client.connectivity();
  if (typeof client.validateInTransactionWithReceipt !== 'function') {
    throw new CompilerError('semantic authority provider lacks digest-bound live SHACL validation receipts', { phase: 'validate:provider' });
  }

  const shapes = shapeConstraints(manifest);
  const integrity = integrityRules(manifest);
  const derivedTriples = {};
  const candidateStores = candidateGraphStores(manifest);
  let candidateScope = 0;
  const recordCandidate = (content, contentType, graph) => {
    const transport = addCandidateContent(candidateStores, content, contentType, graph, `load${candidateScope}`);
    candidateScope += 1;
    return transport;
  };
  let commitOutcome;
  let authoredValidationReceipt;
  let derivedValidationReceipt;
  let tx;

  try {
    tx = await client.begin();

    // Clear only registered named graphs — never the whole database. Preserve
    // the current constraint graph until the candidate authored state has been
    // checked: Stardog resolves SHACL prefix declarations from that graph and
    // rejects a partially rebuilt constraint graph eagerly.
    const constraintGraph = shapesGraph(manifest);
    const initiallyClearedGraphs = clearableGraphs(manifest).filter((graph) => graph !== constraintGraph);
    await client.clearGraphs(tx, initiallyClearedGraphs);

    // Load authored RDF in manifest order. Validate it with the exact supplied
    // shape bytes before publishing those shapes into Stardog's configured
    // constraint graph; otherwise an existing ICV configuration can reject the
    // shape upload itself before the compiler can produce a bounded report.
    const authoredTransport = [];
    for (const e of authoredLoadList(manifest)) {
      const content = readText(e.path);
      try {
        authoredTransport.push(...recordCandidate(content, e.contentType, e.graph));
      } catch (error) {
        throw new CompilerError(error.message, { phase: 'load:authored-prepare', file: e.file, graph: e.graph });
      }
    }
    try {
      await client.addData(tx, await nquadsFor(authoredTransport), NQUADS, null);
    } catch (error) {
      throw new CompilerError(error.message, {
        phase: 'load:authored',
        file: authoredLoadList(manifest).map((entry) => entry.file).join(','),
        graph: 'registered-authored-graphs',
      });
    }

    // Validate the authored state before deriving.
    const authoredReceipt = await client.validateInTransactionWithReceipt(tx, shapes);
    if (authoredReceipt?.conforms !== true) {
      const report = await client.reportInTransaction(tx, shapes);
      throw new CompilerError('authored state failed SHACL validation', { phase: 'validate:authored', report });
    }
    authoredValidationReceipt = validatedReceipt(authoredReceipt, shapes, 'validate:authored-receipt');

    // Replace the configured constraint graph in one complete upload. Loading
    // modules one at a time exposes an invalid partial constraints graph to
    // Stardog's eager ICV enforcement.
    await client.clearGraphs(tx, [constraintGraph]);
    const shapeTransport = [];
    for (const shape of manifest.shapes) {
      shapeTransport.push(...recordCandidate(readText(shape.path), shape.contentType, shape.graph));
    }
    try {
      await client.addData(tx, await nquadsFor(shapeTransport), NQUADS, null);
    } catch (error) {
      throw new CompilerError(error.message, {
        phase: 'load:shapes',
        file: manifest.shapes.map((shape) => shape.file).join(','),
        graph: constraintGraph,
      });
    }

    // Execute derivation rules in the required order. Rule text is used
    // verbatim (CONSTRUCT), and its output is inserted into the rule's
    // registered derived graph — orchestration, not re-authoring.
    for (const rule of derivationRules(manifest)) {
      const blocks = readText(rule.path).split('#---NEXT---#').map((b) => b.trim()).filter(Boolean);
      for (const block of blocks) {
        const turtle = await client.constructInTransaction(tx, block);
        if (turtle && turtle.trim()) {
          await client.addData(tx, turtle, 'text/turtle', rule.output);
          recordCandidate(turtle, 'text/turtle', rule.output);
        }
      }
      derivedTriples[rule.output] = await countInTx(client, tx, rule.output);
    }

    // Validate the derived state.
    const derivedReceipt = await client.validateInTransactionWithReceipt(tx, shapes);
    if (derivedReceipt?.conforms !== true) {
      const report = await client.reportInTransaction(tx, shapes);
      throw new CompilerError('derived state failed SHACL validation', { phase: 'validate:derived', report });
    }
    derivedValidationReceipt = validatedReceipt(derivedReceipt, shapes, 'validate:derived-receipt');

    // Every registered integrity SELECT must return zero rows, in manifest
    // order. No later lifecycle rule may be silently omitted.
    for (const rule of integrity) {
      const violations = await client.selectInTransaction(tx, readText(rule.path));
      if (violations.length) {
        throw new CompilerError('integrity violations present', {
          phase: 'integrity',
          integrityRule: rule.file,
          violations: violations.slice(0, 20).map((v) => ({
            rule: v.violation?.value,
            subject: v.subject?.value,
          })),
        });
      }
    }

    // Contamination: no forbidden markers in any non-shapes graph.
    const contam = await client.selectInTransaction(
      tx,
      `SELECT (COUNT(*) AS ?c) WHERE {
         GRAPH ?g { ?s ?p ?o }
         FILTER(STR(?g) != "${SHAPES_GRAPH_MARKER}")
         FILTER(REGEX(CONCAT(STR(?s)," ",STR(?p)," ",STR(?o)), "${SPARQL_CONTAMINATION}"))
       }`
    );
    const contamCount = contam.length ? Number(contam[0].c.value) : 0;
    if (contamCount > 0) {
      throw new CompilerError('contaminated content present in graph data', {
        phase: 'contamination',
        count: contamCount,
      });
    }

    // Required-resource check: every authored graph and every derived graph
    // holds content.
    for (const e of authoredLoadList(manifest)) {
      if ((await countInTx(client, tx, e.graph)) === 0) {
        throw new CompilerError(`authored graph is empty after load: ${e.graph}`, {
          phase: 'verifyCounts',
        });
      }
    }
    for (const d of manifest.derived) {
      if ((await countInTx(client, tx, d.graph)) === 0) {
        throw new CompilerError(`derived graph is empty after derivation: ${d.graph}`, {
          phase: 'verifyCounts',
        });
      }
    }
    const candidateWitness = await candidateGraphWitness(candidateStores);
    if (publicationMode === 'validate') {
      await client.rollback(tx);
      tx = null;
      commitOutcome = {
        state: 'validated-rolled-back',
        exactCandidateStateVerified: true,
        candidateDigest: candidateWitness.digest,
        candidateGraphs: candidateWitness.graphs,
      };
    } else try {
      await client.commit(tx);
      tx = null;
      commitOutcome = {
        state: 'confirmed-response',
        exactCandidateStateVerified: true,
        candidateDigest: candidateWitness.digest,
      };
    } catch (commitError) {
      let rollbackError;
      try {
        await client.rollback(tx);
      } catch (error) {
        rollbackError = error;
      }
      if (!rollbackError) {
        tx = null;
        throw commitError;
      }

      let transactionClosedVerified = false;
      let probeError;
      try {
        await client.selectInTransaction(tx, 'SELECT * WHERE { } LIMIT 1');
      } catch (error) {
        probeError = error;
        transactionClosedVerified = client.isTransactionClosedError?.(error) === true;
      }
      if (!probeError) {
        let recoveryRollbackError;
        try {
          await client.rollback(tx);
        } catch (error) {
          recoveryRollbackError = error;
        }
        tx = null;
        if (!recoveryRollbackError) {
          throw new CompilerError('commit failed; rollback required a verified-open transaction retry', {
            phase: 'compile:commit',
            cause: commitError,
            errors: [commitError, rollbackError],
            rollbackConfirmed: true,
          });
        }
        throw new CompilerError('commit and rollback outcomes remained unresolved for a verified-open transaction', {
          phase: 'compile:commit-outcome',
          cause: commitError,
          errors: [commitError, rollbackError, recoveryRollbackError],
          rollbackConfirmed: false,
          candidateDigest: candidateWitness.digest,
          observedDigest: null,
        });
      }
      tx = null;

      let liveWitness;
      let reconciliationError;
      if (transactionClosedVerified) try {
        liveWitness = await liveManagedGraphWitness(manifest, client);
      } catch (error) {
        reconciliationError = error;
      }
      if (transactionClosedVerified && liveWitness?.digest === candidateWitness.digest) {
        commitOutcome = {
          state: 'reconciled-committed',
          exactCandidateStateVerified: true,
          transactionClosedVerified: true,
          candidateDigest: candidateWitness.digest,
          observedDigest: liveWitness.digest,
          commitResponseLost: true,
        };
      } else {
        const errors = [commitError, rollbackError, ...(probeError ? [probeError] : []), ...(reconciliationError ? [reconciliationError] : [])];
        throw new CompilerError('commit outcome could not be reconciled to the exact candidate graph state', {
          phase: 'compile:commit-outcome',
          cause: commitError,
          errors,
          rollbackConfirmed: false,
          transactionClosedVerified,
          candidateDigest: candidateWitness.digest,
          observedDigest: liveWitness?.digest ?? null,
        });
      }
    }
    const liveValidationCore = {
      authored: authoredValidationReceipt,
      derived: derivedValidationReceipt,
      validatedDocumentCount: manifest.shapes.length,
      validatedDocumentSetDigest: authoredValidationReceipt.validatedDocumentSetDigest,
    };
    return {
      ok: true,
      graphsCleared: clearableGraphs(manifest).length,
      authoredLoaded: authoredLoadList(manifest).length,
      shapesLoaded: manifest.shapes.length,
      derived: derivedTriples,
      contaminationCount: 0,
      commitOutcome,
      liveValidation: {
        ...liveValidationCore,
        receiptDigest: sha256(canonicalJson(liveValidationCore)),
      },
    };
  } catch (err) {
    if (tx) {
      let rollbackError;
      try {
        await client.rollback(tx);
      } catch (error) {
        rollbackError = error;
      }
      if (rollbackError) {
        let probeError;
        try {
          await client.selectInTransaction(tx, 'SELECT * WHERE { } LIMIT 1');
        } catch (error) {
          probeError = error;
        }
        if (!(probeError && client.isTransactionClosedError?.(probeError) === true)) {
          if (probeError) {
            tx = null;
            throw rollbackFailure(err, rollbackError, probeError);
          }
          let recoveryRollbackError;
          try {
            await client.rollback(tx);
          } catch (error) {
            recoveryRollbackError = error;
          }
          if (recoveryRollbackError) {
            tx = null;
            throw rollbackFailure(err, rollbackError, recoveryRollbackError);
          }
        }
      }
      tx = null;
    }
    if (err instanceof CompilerError) throw err;
    throw new CompilerError(err.message, { phase: 'compile' });
  }
}

// --- Verify (read-only) ----------------------------------------------------

export async function verify({ manifest, client }) {
  const database = manifest.database;
  const registeredGraphs = managedGraphs(manifest);
  const result = {
    database,
    reachable: false,
    databaseGraphCount: 0,
    databaseTripleCount: 0,
    registeredGraphCount: 0,
    registeredTripleCount: 0,
    // Compatibility aliases for the read-only database report. These retain
    // their historical whole-database meaning; signed attestations project
    // explicitly registered-USF-scoped totals instead.
    graphCount: 0,
    tripleCount: 0,
    registeredGraphs,
    missingGraphs: [],
    unexpectedGraphs: [],
    validationConforms: null,
    integrityConforms: null,
    contaminationCount: null,
    readinessCount: null,
  };

  try {
    result.databaseTripleCount = await client.size();
    result.tripleCount = result.databaseTripleCount;
    result.reachable = true;
  } catch {
    return result; // unreachable: report what we know, leave checks null
  }

  const graphRows = await client.select(
    `SELECT ?g (COUNT(*) AS ?c) WHERE { GRAPH ?g { ?s ?p ?o } } GROUP BY ?g`
  );
  const present = new Map(graphRows.map((r) => [r.g.value, Number(r.c.value)]));
  result.databaseGraphCount = present.size;
  result.graphCount = result.databaseGraphCount;
  result.registeredGraphCount = registeredGraphs.filter((graph) => (present.get(graph) ?? 0) > 0).length;
  result.registeredTripleCount = registeredGraphs.reduce((sum, graph) => sum + (present.get(graph) ?? 0), 0);
  result.missingGraphs = registeredGraphs.filter((g) => !present.has(g) || present.get(g) === 0);
  result.unexpectedGraphs = [...present.keys()].filter(
    (g) => g.startsWith('urn:usf:graph:') && !registeredGraphs.includes(g)
  );

  result.validationConforms = await client.validate(shapeConstraints(manifest));

  const integrity = integrityRules(manifest);
  const violationCounts = [];
  for (const rule of integrity) {
    violationCounts.push((await client.select(readText(rule.path))).length);
  }
  result.integrityConforms = violationCounts.every((count) => count === 0);

  const contam = await client.select(
    `SELECT (COUNT(*) AS ?c) WHERE {
       GRAPH ?g { ?s ?p ?o }
       FILTER(STR(?g) != "${SHAPES_GRAPH_MARKER}")
       FILTER(REGEX(CONCAT(STR(?s)," ",STR(?p)," ",STR(?o)), "${SPARQL_CONTAMINATION}"))
     }`
  );
  result.contaminationCount = contam.length ? Number(contam[0].c.value) : 0;

  const readiness = await client.select(
    `SELECT (COUNT(?r) AS ?c) WHERE {
       GRAPH <urn:usf:graph:derived:readiness> { ?r a <urn:usf:ontology:Readiness> }
     }`
  );
  result.readinessCount = readiness.length ? Number(readiness[0].c.value) : 0;

  return result;
}
