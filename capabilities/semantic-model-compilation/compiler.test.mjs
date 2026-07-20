// Unit tests for the USF semantic compiler.
//
// These never contact Stardog Cloud: the SDK adapter is replaced by a
// recording fake injected at the compiler boundary, and manifests are built in
// throwaway temp directories. Run with `npm test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DataFactory, Parser, Store, Writer } from 'n3';

// The standalone repository owns the real graph; an explicit override remains
// available for isolated fixtures.
const REAL_GRAPH_DIR = process.env.USF_GRAPH_DIR
  || join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'semantic-model');
const realGraphAbsent = (t) => {
  if (existsSync(join(REAL_GRAPH_DIR, 'manifest.yaml'))) return false;
  t.skip('standalone graph is not present in this isolated test fixture');
  return true;
};


import { loadManifest, managedGraphs, clearableGraphs, ManifestError } from './manifest.mjs';
import {
  checkLocal,
  compile,
  buildPlan,
  CompilerError,
  publicationBudgetWitness,
} from './compiler.mjs';

// --- Fixtures --------------------------------------------------------------

// A minimal but structurally complete graph that passes all local checks.
function baseSpec() {
  const rule = (name) =>
    `PREFIX usf: <urn:usf:ontology:>\nCONSTRUCT { ?x a usf:${name} } WHERE { ?x a usf:Thing }\n`;
  return {
    'manifest.yaml': `version: 1
database: USF
baseIri: "urn:usf:"
authorityPublicationBudget:
  provider: stardogcloudfree
  policyIri: "urn:usf:permutationpublicationbudget:stardogcloudfreeauthoritycapacity"
  hardStatementLimit: 1000000
  reserveStatementCount: 200000
definitionGraphs:
  - { file: ontology.ttl, graph: "urn:usf:graph:ontology", loadOrder: 1, validationOrder: 1 }
  - { file: registry.ttl, graph: "urn:usf:graph:registry", loadOrder: 2, validationOrder: 2 }
authoredGraphs:
  - { file: providers.ttl, graph: "urn:usf:graph:providers", loadOrder: 3, validationOrder: 3 }
shapeGraphs:
  - { file: shapes.ttl, graph: "urn:usf:graph:shapes", loadOrder: 4, validationOrder: 4 }
rules:
  - { file: rules/obligations.rq, output: "urn:usf:graph:derived:obligations", kind: derivation }
  - { file: rules/evidence.rq, output: "urn:usf:graph:derived:evidence", kind: derivation }
  - { file: rules/surfaces.rq, output: "urn:usf:graph:derived:surfaces", kind: derivation }
  - { file: rules/coverage.rq, output: "urn:usf:graph:derived:coverage", kind: derivation }
  - { file: rules/readiness.rq, output: "urn:usf:graph:derived:readiness", kind: derivation }
  - { file: rules/integrity.rq, kind: integrity }
derivedGraphs:
  - { file: derived/obligations.trig, graph: "urn:usf:graph:derived:obligations", loadOrder: 11, validationOrder: 11 }
  - { file: derived/evidence.trig, graph: "urn:usf:graph:derived:evidence", loadOrder: 12, validationOrder: 12 }
  - { file: derived/surfaces.trig, graph: "urn:usf:graph:derived:surfaces", loadOrder: 13, validationOrder: 13 }
  - { file: derived/coverage.trig, graph: "urn:usf:graph:derived:coverage", loadOrder: 14, validationOrder: 14 }
  - { file: derived/readiness.trig, graph: "urn:usf:graph:derived:readiness", loadOrder: 15, validationOrder: 15 }
retiredGraphs:
  - { graph: "urn:usf:graph:derived:retiredfixture", supersededBy: "urn:usf:semanticcorrectiondecision:test" }
fixtures:
  conforming: fixtures/conforming
  defects: fixtures/defects
  loadAsAuthority: false
`,
    'ontology.ttl': '@prefix usf: <urn:usf:ontology:> .\nusf:Thing a <http://www.w3.org/2002/07/owl#Class> .\n',
    'registry.ttl': `@prefix usf: <urn:usf:ontology:> .
@prefix ng: <urn:usf:namedgraph:> . @prefix rl: <urn:usf:rule:> . @prefix gcl: <urn:usf:graphclass:> .
ng:o a usf:NamedGraph ; usf:canonicalName "ontology" ; usf:graphIri "urn:usf:graph:ontology" ; usf:graphClass gcl:definitiongraph ; usf:loadOrder 1 ; usf:graphValidationOrder 1 .
ng:r a usf:NamedGraph ; usf:canonicalName "registry" ; usf:graphIri "urn:usf:graph:registry" ; usf:graphClass gcl:definitiongraph ; usf:loadOrder 2 ; usf:graphValidationOrder 2 .
ng:p a usf:NamedGraph ; usf:canonicalName "providers" ; usf:graphIri "urn:usf:graph:providers" ; usf:graphClass gcl:authoredgraph ; usf:loadOrder 3 ; usf:graphValidationOrder 3 .
ng:s a usf:NamedGraph ; usf:canonicalName "shapes" ; usf:graphIri "urn:usf:graph:shapes" ; usf:graphClass gcl:shapegraph ; usf:loadOrder 4 ; usf:graphValidationOrder 4 .
ng:d1 a usf:NamedGraph ; usf:canonicalName "d1" ; usf:graphIri "urn:usf:graph:derived:obligations" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 11 ; usf:graphValidationOrder 11 .
ng:d2 a usf:NamedGraph ; usf:canonicalName "d2" ; usf:graphIri "urn:usf:graph:derived:evidence" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 12 ; usf:graphValidationOrder 12 .
ng:d3 a usf:NamedGraph ; usf:canonicalName "d3" ; usf:graphIri "urn:usf:graph:derived:surfaces" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 13 ; usf:graphValidationOrder 13 .
ng:d4 a usf:NamedGraph ; usf:canonicalName "d4" ; usf:graphIri "urn:usf:graph:derived:coverage" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 14 ; usf:graphValidationOrder 14 .
ng:d5 a usf:NamedGraph ; usf:canonicalName "d5" ; usf:graphIri "urn:usf:graph:derived:readiness" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 15 ; usf:graphValidationOrder 15 .
rl:r1 a usf:DerivationRule ; usf:canonicalName "obligations" ; usf:inNamedGraph ng:d1 .
rl:r2 a usf:DerivationRule ; usf:canonicalName "evidence" ; usf:inNamedGraph ng:d2 .
rl:r3 a usf:DerivationRule ; usf:canonicalName "surfaces" ; usf:inNamedGraph ng:d3 .
rl:r4 a usf:DerivationRule ; usf:canonicalName "coverage" ; usf:inNamedGraph ng:d4 .
rl:r5 a usf:DerivationRule ; usf:canonicalName "readiness" ; usf:inNamedGraph ng:d5 .
`,
    'providers.ttl': '@prefix usf: <urn:usf:> .\nusf:providers:acme a usf:ontology:Thing .\n',
    'shapes.ttl':
      '# SHACL detectors encode prohibited markers without embedding a match\n@prefix sh: <http://www.w3.org/ns/shacl#> .\n',
    'rules/obligations.rq': rule('ProofObligation'),
    'rules/evidence.rq': rule('EvidenceRequirement'),
    'rules/surfaces.rq': rule('Surface'),
    'rules/coverage.rq': rule('Coverage'),
    'rules/readiness.rq': rule('Readiness'),
    'rules/integrity.rq':
      'SELECT ?violation ?subject WHERE { ?subject a ?t . BIND("x" AS ?violation) FILTER(false) }\n',
    'derived/obligations.trig': '@prefix usf: <urn:usf:ontology:> .\nGRAPH <urn:usf:graph:derived:obligations> { usf:x a usf:ProofObligation }\n',
    'derived/evidence.trig': 'GRAPH <urn:usf:graph:derived:evidence> { <urn:usf:x> a <urn:usf:ontology:EvidenceRequirement> . }\n',
    'derived/surfaces.trig': 'GRAPH <urn:usf:graph:derived:surfaces> { <urn:usf:x> a <urn:usf:ontology:Surface> . }\n',
    'derived/coverage.trig': 'GRAPH <urn:usf:graph:derived:coverage> { <urn:usf:x> a <urn:usf:ontology:Coverage> . }\n',
    'derived/readiness.trig': 'GRAPH <urn:usf:graph:derived:readiness> { <urn:usf:x> a <urn:usf:ontology:Readiness> . }\n',
    'fixtures/conforming/sample.ttl': '# fixture, never loaded as authority\n<urn:usf:x> a <urn:usf:ontology:Thing> .\n',
  };
}

// A validator asserting a CompilerError whose failure list mentions `substr`.
const hasFailure = (substr) => (e) =>
  e instanceof CompilerError && Array.isArray(e.failures) && e.failures.some((f) => f.includes(substr));

let dirs = [];
function writeGraph(spec) {
  const dir = mkdtempSync(join(tmpdir(), 'usf-graph-'));
  dirs.push(dir);
  for (const [rel, content] of Object.entries(spec)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

test.after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

// A recording fake standing in for the SDK adapter.
function recordedGraphNQuads(added, graph) {
  const store = new Store();
  for (const [scope, entry] of added.entries()) {
    const blankNodes = new Map();
    const scoped = (term) => {
      if (term.termType !== 'BlankNode') return term;
      if (!blankNodes.has(term.value)) blankNodes.set(term.value, DataFactory.blankNode(`record${scope}_${blankNodes.size}`));
      return blankNodes.get(term.value);
    };
    for (const item of new Parser({ format: entry.contentType, baseIRI: 'urn:usf:' }).parse(entry.content)) {
      const itemGraph = item.graph.termType === 'NamedNode' ? item.graph.value : entry.graph;
      if (itemGraph === graph) store.addQuad(DataFactory.quad(scoped(item.subject), item.predicate, scoped(item.object)));
    }
  }
  return new Promise((resolveOutput, reject) => {
    const writer = new Writer({ format: 'N-Quads' });
    writer.addQuads(store.getQuads(null, null, null, null));
    writer.end((error, output) => error ? reject(error) : resolveOutput(output));
  });
}

function fakeClient(overrides = {}) {
  const stable = (value) => Array.isArray(value)
    ? value.map(stable)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
      : value;
  const canonicalJson = (value) => JSON.stringify(stable(value));
  const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
  const receipt = (shapes, conforms = true) => {
    const inputs = shapes.map(({ file, path }) => ({ path: `semantic-model/${file}`, digest: sha256(readFileSync(path)) }))
      .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
    const core = {
      conforms,
      validatedDocumentCount: inputs.length,
      validatedDocumentSetDigest: sha256(canonicalJson(inputs)),
      observationSetDigest: sha256(canonicalJson(inputs.map((input) => ({ ...input, conforms })))),
    };
    return { ...core, receiptDigest: sha256(canonicalJson(core)) };
  };
  const rec = { cleared: [], added: [], committed: false, rolledBack: false, began: false };
  const client = {
    async connectivity() {
      return 0;
    },
    async begin() {
      rec.began = true;
      return 'tx-1';
    },
    async commit() {
      rec.committed = true;
    },
    async rollback() {
      rec.rolledBack = true;
    },
    async clearGraphs(tx, graphs) {
      assert.ok(Array.isArray(graphs) && graphs.length > 0, 'clearGraphs requires named graphs');
      rec.cleared.push(...graphs);
    },
    async addData(tx, content, contentType, graph) {
      rec.added.push({ graph, contentType, content });
    },
    async constructInTransaction(_tx, _query, accept) {
      if (accept === 'application/n-quads') {
        return '<urn:usf:x> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <urn:usf:ontology:ProofObligation> .\n';
      }
      return '<urn:usf:x> a <urn:usf:ontology:ProofObligation> .';
    },
    async construct(query) {
      const graph = query.match(/GRAPH <([^>]+)>/)?.[1];
      return recordedGraphNQuads(rec.added, graph);
    },
    async validateInTransaction() {
      return true;
    },
    async validateInTransactionWithReceipt(_transaction, shapes) {
      return receipt(shapes);
    },
    async selectInTransaction(tx, q) {
      if (/REGEX/.test(q)) return [{ c: { value: '0' } }]; // contamination
      if (/\?violation/.test(q)) return []; // integrity: conforming
      return [{ c: { value: '5' } }]; // counts
    },
    async reportInTransaction() {
      return {};
    },
  };
  return { client: Object.assign(client, overrides), rec };
}

const TEST_AUTHORITY_WITNESS = Object.freeze({
  algorithm: 'sha256-rdfc10-graph-inventory-v2',
  digest: `sha256:${'a'.repeat(64)}`,
  inventory: Object.freeze([]),
  triples: 0,
});
const compileCandidate = (input) => compile({
  authorityWitness: TEST_AUTHORITY_WITNESS,
  publicationBudgetPolicy: input.manifest.publicationBudget,
  ...input,
});

// --- manifest and local validation ---------------------------------------------

test('manifest: a missing manifest file throws', () => {
  assert.throws(() => loadManifest(join(tmpdir(), 'nope-does-not-exist')), Error);
});

test('manifest: a path escaping the graph directory is rejected', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace('file: ontology.ttl', 'file: ../ontology.ttl');
  const dir = writeGraph(spec);
  assert.throws(() => loadManifest(dir), ManifestError);
});

test('manifest: an unsupported (incorrect) content type is rejected', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace('file: ontology.ttl', 'file: ontology.md');
  spec['ontology.md'] = 'not rdf';
  const dir = writeGraph(spec);
  assert.throws(() => loadManifest(dir), ManifestError);
});

test('checkLocal: the base graph passes', () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  assert.equal(checkLocal(m).ok, true);
});

test('checkLocal: a duplicate authored graph IRI fails', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace(
    '  - { file: providers.ttl, graph: "urn:usf:graph:providers", loadOrder: 3, validationOrder: 3 }',
    '  - { file: providers.ttl, graph: "urn:usf:graph:providers", loadOrder: 3, validationOrder: 3 }\n  - { file: providers2.ttl, graph: "urn:usf:graph:providers", loadOrder: 4, validationOrder: 4 }'
  );
  spec['providers2.ttl'] = '<urn:usf:providers:beta> a <urn:usf:ontology:Thing> .\n';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('duplicate authored graph IRI'));
});

test('checkLocal: a non-deterministic (duplicate) load order fails', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace('loadOrder: 2', 'loadOrder: 1');
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('load order'));
});

test('checkLocal: RDF registry graph class and order must match the manifest', () => {
  const spec = baseSpec();
  spec['registry.ttl'] = spec['registry.ttl'].replace(
    'usf:graphClass gcl:authoredgraph ; usf:loadOrder 3',
    'usf:graphClass gcl:definitiongraph ; usf:loadOrder 99',
  );
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('registry graph class mismatch'));
});

test('checkLocal: RDF registry derivation ownership must match compiler rule outputs', () => {
  const spec = baseSpec();
  spec['registry.ttl'] = spec['registry.ttl'].replace('usf:canonicalName "obligations" ; usf:inNamedGraph ng:d1', 'usf:canonicalName "obligations" ; usf:inNamedGraph ng:d2');
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('registry rule output mismatch'));
});

test('checkLocal: an unexpected unregistered graph file fails', () => {
  const spec = baseSpec();
  spec['stray.ttl'] = '<urn:usf:x> a <urn:usf:ontology:Thing> .\n';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('unregistered loadable file'));
});

test('checkLocal: an exact inactive candidate source is retained without becoming authority', () => {
  const spec = baseSpec();
  const bytes = '<urn:usf:candidate:x> a <urn:usf:ontology:Thing> .\n';
  const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  spec['candidate.trig'] = bytes;
  spec['manifest.yaml'] = spec['manifest.yaml'].replace(
    'retiredGraphs:',
    `inactiveSources:\n  - file: candidate.trig\n    contentDigest: "${digest}"\n    disposition: CANDIDATE_MIGRATION_MATERIAL\n    authorityEligible: false\nretiredGraphs:`,
  );
  const manifest = loadManifest(writeGraph(spec));
  const result = checkLocal(manifest);
  assert.equal(result.inactiveSources, 1);
  assert.equal(managedGraphs(manifest).some((graph) => graph.includes('candidate')), false);
});

test('checkLocal: an inactive candidate with drifted bytes fails closed', () => {
  const spec = baseSpec();
  spec['candidate.trig'] = '<urn:usf:candidate:x> a <urn:usf:ontology:Thing> .\n';
  spec['manifest.yaml'] = spec['manifest.yaml'].replace(
    'retiredGraphs:',
    `inactiveSources:\n  - file: candidate.trig\n    contentDigest: "sha256:${'0'.repeat(64)}"\n    disposition: CANDIDATE_MIGRATION_MATERIAL\n    authorityEligible: false\nretiredGraphs:`,
  );
  assert.throws(() => checkLocal(loadManifest(writeGraph(spec))), hasFailure('inactive source digest mismatch'));
});

test('manifest: an inactive source cannot be authority eligible', () => {
  const spec = baseSpec();
  spec['candidate.trig'] = '<urn:usf:candidate:x> a <urn:usf:ontology:Thing> .\n';
  spec['manifest.yaml'] = spec['manifest.yaml'].replace(
    'retiredGraphs:',
    `inactiveSources:\n  - file: candidate.trig\n    contentDigest: "sha256:${'0'.repeat(64)}"\n    disposition: CANDIDATE_MIGRATION_MATERIAL\n    authorityEligible: true\nretiredGraphs:`,
  );
  assert.throws(() => loadManifest(writeGraph(spec)), ManifestError);
});

test('checkLocal: malformed RDF fails before any live transaction', () => {
  const spec = baseSpec();
  spec['providers.ttl'] = '<urn:usf:broken';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('RDF parse failed'));
});

test('checkLocal: registered TriG cannot write to another named graph', () => {
  const spec = baseSpec();
  spec['derived/obligations.trig'] = 'GRAPH <urn:usf:graph:wrong> { <urn:usf:x> a <urn:usf:ontology:ProofObligation> . }\n';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('writes outside its graph'));
});

test('checkLocal: a derived graph treated as authored fails', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace(
    '  - { file: providers.ttl, graph: "urn:usf:graph:providers", loadOrder: 3, validationOrder: 3 }',
    '  - { file: providers.ttl, graph: "urn:usf:graph:derived:obligations", loadOrder: 3, validationOrder: 3 }'
  );
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('both authored and derived'));
});

test('checkLocal: forbidden contamination in an authored file fails', () => {
  const spec = baseSpec();
  spec['providers.ttl'] = '<urn:usf:x> <urn:usf:ontology:src> "see https://github.com/acme/repo" .\n';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('forbidden content'));
});

test('checkLocal: encoded detector expressions inside shapes are allowed', () => {
  const spec = baseSpec();
  spec['shapes.ttl'] = '@prefix sh: <http://www.w3.org/ns/shacl#> .\n# detector forms: git[h]ub\\.com and U[S]F-[0-9]+ and commit[S]ha\nsh:x a sh:NodeShape .\n';
  const dir = writeGraph(spec);
  assert.equal(checkLocal(loadManifest(dir)).ok, true);
});

// --- compile (mocked SDK) --------------------------------------------------

test('compile: only current and exact retired manifest graphs are cleared, and never the whole database', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient();
  await compileCandidate({ manifest: m, client });
  assert.deepEqual([...rec.cleared].sort(), [...clearableGraphs(m)].sort());
  assert.equal(managedGraphs(m).includes('urn:usf:graph:derived:retiredfixture'), false);
  assert.equal(clearableGraphs(m).includes('urn:usf:graph:derived:retiredfixture'), true);
  // The adapter exposes no whole-database clear operation.
  assert.equal(typeof client.clearDatabase, 'undefined');
});

test('publication budget witness is deterministic and conservative at the exact boundary', () => {
  const policy = loadManifest(writeGraph(baseSpec())).publicationBudget;
  const candidateWitness = {
    digest: `sha256:${'b'.repeat(64)}`,
    graphs: [{ graph: 'urn:test:graph', triples: 10 }],
  };
  const authorityWitness = {
    ...TEST_AUTHORITY_WITNESS,
    inventory: [{ graph: 'urn:test:existing', triples: 799_990 }],
    triples: 799_990,
  };
  const first = publicationBudgetWitness({ authorityWitness, candidateWitness, policy });
  const second = publicationBudgetWitness({ authorityWitness, candidateWitness, policy });
  assert.deepEqual(second, first);
  assert.equal(first.projectedStatementUpperBound, 800_000);
  assert.equal(first.result, 'PASS');
  assert.match(first.budgetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(publicationBudgetWitness({
    authorityWitness: { ...authorityWitness, inventory: [{ graph: 'urn:test:existing', triples: 799_991 }], triples: 799_991 },
    candidateWitness,
    policy,
  }).result, 'REJECTED');
});

test('compile: rejects an over-budget candidate before uploading candidate bytes', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  const { client, rec } = fakeClient();
  await assert.rejects(
    () => compileCandidate({
      authorityWitness: {
        ...TEST_AUTHORITY_WITNESS,
        inventory: [{ graph: 'urn:test:existing', triples: 800_000 }],
        triples: 800_000,
      },
      client,
      manifest,
    }),
    (error) => error instanceof CompilerError
      && error.code === 'PUBLICATION_TRIPLE_BUDGET_EXCEEDED'
      && error.phase === 'publication:budget',
  );
  assert.equal(rec.began, true);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.added.length, 0);
});

test('compile: rejects absent baseline and malformed budget inputs before a transaction', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  const { client, rec } = fakeClient();
  await assert.rejects(
    () => compile({ client, manifest, publicationBudgetPolicy: manifest.publicationBudget }),
    (error) => error.code === 'PUBLICATION_BASELINE_WITNESS_INVALID',
  );
  await assert.rejects(
    () => compile({
      authorityWitness: TEST_AUTHORITY_WITNESS,
      client,
      manifest,
      publicationBudgetPolicy: { ...manifest.publicationBudget, hardStatementLimit: 2_000_000 },
    }),
    (error) => error.code === 'PUBLICATION_BUDGET_POLICY_INVALID',
  );
  assert.equal(rec.began, false);
});

test('compile: commits after full success', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient();
  const result = await compileCandidate({ manifest: m, client });
  assert.equal(result.ok, true);
  assert.equal(rec.committed, true);
  assert.equal(rec.rolledBack, false);
  assert.equal(result.commitOutcome.state, 'confirmed-response');
  assert.equal(result.commitOutcome.exactCandidateStateVerified, true);
});

test('compile: validates the exact candidate and rolls back without publication', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient();
  const result = await compileCandidate({ manifest: m, client, publicationMode: 'validate' });
  assert.equal(result.ok, true);
  assert.equal(rec.committed, false);
  assert.equal(rec.rolledBack, true);
  assert.equal(result.commitOutcome.state, 'validated-rolled-back');
  assert.equal(result.commitOutcome.exactCandidateStateVerified, true);
  assert.match(result.commitOutcome.candidateDigest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(result.commitOutcome.candidateGraphs.length > 0);
});

test('compile: rejects an unknown publication mode before opening a transaction', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient();
  await assert.rejects(
    () => compileCandidate({ manifest: m, client, publicationMode: 'preview' }),
    (error) => error instanceof CompilerError && error.phase === 'compile:configuration',
  );
  assert.equal(rec.began, false);
});

test('compile: reconciles an exact committed graph state after a lost commit response', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  const { client, rec } = fakeClient();
  const commit = client.commit.bind(client);
  const selectInTransaction = client.selectInTransaction.bind(client);
  let transactionClosed = false;
  client.commit = async (tx) => {
    await commit(tx);
    transactionClosed = true;
    throw new Error('response lost after server commit');
  };
  client.rollback = async () => {
    rec.rolledBack = true;
    throw new Error('transaction is already closed');
  };
  client.selectInTransaction = async (...args) => {
    if (transactionClosed) throw Object.assign(new Error('transaction is already closed'), { status: 400 });
    return selectInTransaction(...args);
  };
  client.isTransactionClosedError = (error) => error.status === 400;
  const result = await compileCandidate({ manifest, client });
  assert.equal(rec.committed, true);
  assert.equal(rec.rolledBack, true);
  assert.equal(result.commitOutcome.state, 'reconciled-committed');
  assert.equal(result.commitOutcome.exactCandidateStateVerified, true);
  assert.equal(result.commitOutcome.transactionClosedVerified, true);
  assert.equal(result.commitOutcome.candidateDigest, result.commitOutcome.observedDigest);
});

test('compile: fails closed with both errors when commit and rollback fail without candidate-state parity', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  const { client } = fakeClient();
  let transactionClosed = false;
  client.commit = async () => { transactionClosed = true; throw new Error('commit response lost'); };
  client.rollback = async () => { throw new Error('rollback response lost'); };
  const selectInTransaction = client.selectInTransaction.bind(client);
  client.selectInTransaction = async (...args) => {
    if (transactionClosed) throw Object.assign(new Error('transaction is already closed'), { status: 400 });
    return selectInTransaction(...args);
  };
  client.isTransactionClosedError = (error) => error.status === 400;
  client.construct = async () => '<urn:usf:different> <urn:usf:p> <urn:usf:o> .\n';
  await assert.rejects(
    () => compileCandidate({ manifest, client }),
    (error) => error instanceof CompilerError
      && error.phase === 'compile:commit-outcome'
      && error.rollbackConfirmed === false
      && error.errors.slice(0, 2).map((item) => item.message).join('|') === 'commit response lost|rollback response lost'
      && error.transactionClosedVerified === true
      && error.candidateDigest !== error.observedDigest,
  );
});

test('compile: retries rollback after a verified-open pre-commit failure', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  let rollbackCalls = 0;
  const { client } = fakeClient({
    async addData() { throw new Error('primary load failure'); },
    async rollback() {
      rollbackCalls += 1;
      if (rollbackCalls === 1) throw new Error('transient rollback failure');
    },
  });
  await assert.rejects(() => compileCandidate({ manifest, client }), /primary load failure/);
  assert.equal(rollbackCalls, 2);
});

test('compile: accepts verified transaction closure after a pre-commit rollback response failure', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  let rollbackCalls = 0;
  const { client } = fakeClient({
    async addData() { throw new Error('primary load failure'); },
    async rollback() {
      rollbackCalls += 1;
      throw new Error('rollback response lost');
    },
    async selectInTransaction() {
      throw Object.assign(new Error('transaction is already closed'), { status: 400 });
    },
    isTransactionClosedError(error) { return error.status === 400; },
  });
  await assert.rejects(() => compileCandidate({ manifest, client }), /primary load failure/);
  assert.equal(rollbackCalls, 1);
});

test('compile: preserves the primary pre-commit failure and both rollback failures', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  let rollbackCalls = 0;
  const { client } = fakeClient({
    async addData() { throw new Error('primary load failure'); },
    async rollback() {
      rollbackCalls += 1;
      throw new Error(`rollback failure ${rollbackCalls}`);
    },
  });
  await assert.rejects(
    () => compileCandidate({ manifest, client }),
    (error) => error instanceof CompilerError
      && error.rollbackConfirmed === false
      && error.errors.map((item) => item.message).join('|') === 'primary load failure|rollback failure 1|rollback failure 2'
      && error.cause === error.errors[0],
  );
  assert.equal(rollbackCalls, 2);
});

test('compile: rolls back after a load failure', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async addData() {
      throw new Error('load boom');
    },
  });
  await assert.rejects(() => compileCandidate({ manifest: m, client }), CompilerError);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after a validation failure', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async validateInTransactionWithReceipt(_transaction, shapes) {
      const inputs = shapes.map(({ file, path }) => ({ path: `semantic-model/${file}`, digest: `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}` }));
      return { conforms: false, validatedDocumentCount: inputs.length };
    },
  });
  await assert.rejects(() => compileCandidate({ manifest: m, client }), /SHACL validation/);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after a derivation failure', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async constructInTransaction() {
      throw new Error('derive boom');
    },
  });
  await assert.rejects(() => compileCandidate({ manifest: m, client }), CompilerError);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after an integrity violation', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async selectInTransaction(tx, q) {
      if (/REGEX/.test(q)) return [{ c: { value: '0' } }];
      if (/\?violation/.test(q)) return [{ violation: { value: 'hyphenatedidentifier' }, subject: { value: 'urn:usf:bad_name' } }];
      return [{ c: { value: '5' } }];
    },
  });
  await assert.rejects(() => compileCandidate({ manifest: m, client }), /integrity/);
  assert.equal(rec.rolledBack, true);
});

test('compile: an error never carries the token', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client } = fakeClient({
    async addData() {
      throw new Error('network error at https://example.stardog.cloud:5820');
    },
  });
  await assert.rejects(
    () => compileCandidate({ manifest: m, client }),
    (e) => !JSON.stringify({ m: e.message, ...e }).includes('super-secret-token')
  );
});

test('buildPlan: repeated compilation produces an identical operation plan', () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  assert.deepEqual(buildPlan(m), buildPlan(m));
  // Evidence is derived before readiness; commit is last; no whole-db clear.
  const ops = buildPlan(m);
  const kinds = ops.map((o) => o.op);
  assert.ok(kinds.indexOf('derive') !== -1);
  assert.equal(ops[ops.length - 1].op, 'commit');
  assert.ok(!ops.some((o) => o.op === 'clear' && !o.graph));
});
