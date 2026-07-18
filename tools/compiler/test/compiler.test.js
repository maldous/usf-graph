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
  || join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'graph');
const realGraphAbsent = (t) => {
  if (existsSync(join(REAL_GRAPH_DIR, 'manifest.yaml'))) return false;
  t.skip('standalone graph is not present in this isolated test fixture');
  return true;
};


import { loadConfig, describeConfig, ConfigError } from '../src/config.js';
import { loadManifest, managedGraphs, clearableGraphs, ManifestError } from '../src/manifest.js';
import { checkLocal, compile, buildPlan, verify, verificationConforms, CompilerError, CONTAMINATION_PATTERNS } from '../src/compiler.js';
import { createClient, stardogInternals } from '../src/stardog.js';
import { loadAuthorityDataset } from '../src/authority-dataset.js';
import { buildGenerationPlan, requireCompleteGenerationPlan } from '../src/generation-plan.js';
import {
  canonicalGraphDigest,
  canonicalGraphTrig,
  compareGraphDigests,
  liveAttestationInternals,
} from '../src/live-attestation.js';
import { generateAuthority, generatorInternals, verifyOutput } from '../src/generate.js';

// --- Fixtures --------------------------------------------------------------

// A minimal but structurally complete graph that passes all local checks.
function baseSpec() {
  const rule = (name) =>
    `PREFIX usf: <urn:usf:ontology:>\nCONSTRUCT { ?x a usf:${name} } WHERE { ?x a usf:Thing }\n`;
  return {
    'manifest.yaml': `version: 1
database: USF
baseIri: "urn:usf:"
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
    async clearGraph(tx, graph) {
      assert.ok(graph, 'clearGraph must always receive a named graph');
      rec.cleared.push(graph);
    },
    async addData(tx, content, contentType, graph) {
      rec.added.push({ graph, contentType, content });
    },
    async constructInTx(_tx, _query, accept) {
      if (accept === 'application/n-quads') {
        return '<urn:usf:x> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <urn:usf:ontology:ProofObligation> .\n';
      }
      return '<urn:usf:x> a <urn:usf:ontology:ProofObligation> .';
    },
    async construct(query) {
      const graph = query.match(/GRAPH <([^>]+)>/)?.[1];
      return recordedGraphNQuads(rec.added, graph);
    },
    async validateInTx() {
      return true;
    },
    async selectInTx(tx, q) {
      if (/REGEX/.test(q)) return [{ c: { value: '0' } }]; // contamination
      if (/\?violation/.test(q)) return []; // integrity: conforming
      return [{ c: { value: '5' } }]; // counts
    },
    async reportInTx() {
      return {};
    },
  };
  return { client: Object.assign(client, overrides), rec };
}

// --- config.js -------------------------------------------------------------

test('config: missing configuration is rejected', () => {
  assert.throws(() => loadConfig({}), ConfigError);
});

test('config: token authentication is accepted and takes precedence', () => {
  const c = loadConfig({
    STARDOG_SERVER: 'https://example.stardog.cloud:5820',
    STARDOG_DATABASE: 'USF',
    STARDOG_TOKEN: 'tok',
    STARDOG_USERNAME: 'u',
    STARDOG_PASSWORD: 'p',
  });
  assert.equal(c.auth.kind, 'token');
});

test('config: username and password authentication is accepted', () => {
  const c = loadConfig({
    STARDOG_SERVER: 'https://example.stardog.cloud:5820',
    STARDOG_USERNAME: 'u',
    STARDOG_PASSWORD: 'p',
  });
  assert.equal(c.auth.kind, 'basic');
  assert.equal(c.database, 'USF'); // documented default
});

test('config: a non-HTTPS endpoint is rejected', () => {
  assert.throws(
    () => loadConfig({ STARDOG_SERVER: 'http://example.stardog.cloud:5820', STARDOG_TOKEN: 't' }),
    ConfigError
  );
});

test('config: a localhost endpoint is rejected', () => {
  assert.throws(
    () => loadConfig({ STARDOG_SERVER: 'https://localhost:5820', STARDOG_TOKEN: 't' }),
    ConfigError
  );
});

test('config: credentials never appear in the describeConfig output', () => {
  const config = loadConfig({
    STARDOG_SERVER: 'https://example.stardog.cloud:5820',
    STARDOG_TOKEN: 'super-secret-token',
  });
  const described = describeConfig(config);
  const json = JSON.stringify(described);
  assert.ok(!json.includes('super-secret-token'));
  assert.deepEqual(Object.keys(described).sort(), ['authMode', 'database', 'endpoint']);
});

// --- manifest.js / checkLocal ---------------------------------------------

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
  await compile({ manifest: m, client });
  assert.deepEqual([...rec.cleared].sort(), [...clearableGraphs(m)].sort());
  assert.equal(managedGraphs(m).includes('urn:usf:graph:derived:retiredfixture'), false);
  assert.equal(clearableGraphs(m).includes('urn:usf:graph:derived:retiredfixture'), true);
  // The adapter exposes no whole-database clear operation.
  assert.equal(typeof client.clearDatabase, 'undefined');
});

test('compile: commits after full success', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient();
  const result = await compile({ manifest: m, client });
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
  const result = await compile({ manifest: m, client, publicationMode: 'validate' });
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
    () => compile({ manifest: m, client, publicationMode: 'preview' }),
    (error) => error instanceof CompilerError && error.phase === 'compile:configuration',
  );
  assert.equal(rec.began, false);
});

test('compile: reconciles an exact committed graph state after a lost commit response', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  const { client, rec } = fakeClient();
  const commit = client.commit.bind(client);
  const selectInTx = client.selectInTx.bind(client);
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
  client.selectInTx = async (...args) => {
    if (transactionClosed) throw Object.assign(new Error('transaction is already closed'), { status: 400 });
    return selectInTx(...args);
  };
  client.isTransactionClosedError = (error) => error.status === 400;
  const result = await compile({ manifest, client });
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
  const selectInTx = client.selectInTx.bind(client);
  client.selectInTx = async (...args) => {
    if (transactionClosed) throw Object.assign(new Error('transaction is already closed'), { status: 400 });
    return selectInTx(...args);
  };
  client.isTransactionClosedError = (error) => error.status === 400;
  client.construct = async () => '<urn:usf:different> <urn:usf:p> <urn:usf:o> .\n';
  await assert.rejects(
    () => compile({ manifest, client }),
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
  await assert.rejects(() => compile({ manifest, client }), /primary load failure/);
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
    async selectInTx() {
      throw Object.assign(new Error('transaction is already closed'), { status: 400 });
    },
    isTransactionClosedError(error) { return error.status === 400; },
  });
  await assert.rejects(() => compile({ manifest, client }), /primary load failure/);
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
    () => compile({ manifest, client }),
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
  await assert.rejects(() => compile({ manifest: m, client }), CompilerError);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after a validation failure', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async validateInTx() {
      return false;
    },
  });
  await assert.rejects(() => compile({ manifest: m, client }), /SHACL validation/);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after a derivation failure', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async constructInTx() {
      throw new Error('derive boom');
    },
  });
  await assert.rejects(() => compile({ manifest: m, client }), CompilerError);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after an integrity violation', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async selectInTx(tx, q) {
      if (/REGEX/.test(q)) return [{ c: { value: '0' } }];
      if (/\?violation/.test(q)) return [{ violation: { value: 'hyphenatedidentifier' }, subject: { value: 'urn:usf:bad_name' } }];
      return [{ c: { value: '5' } }];
    },
  });
  await assert.rejects(() => compile({ manifest: m, client }), /integrity/);
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
    () => compile({ manifest: m, client }),
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

test('adapter: createClient exposes no whole-database clear', () => {
  const client = createClient(
    loadConfig({ STARDOG_SERVER: 'https://example.stardog.cloud:5820', STARDOG_TOKEN: 't' })
  );
  assert.equal(typeof client.clearDatabase, 'undefined');
  assert.equal(typeof client.clearGraph, 'function');
});

test('adapter: failed responses never include Stardog response bodies', () => {
  const protectedValue = 'response-body-must-not-escape';
  assert.throws(
    () => stardogInternals.ok({ ok: false, status: 500, body: { diagnostic: protectedValue } }, 'select'),
    (error) => error.status === 500 && !error.message.includes(protectedValue) && error.message === 'Stardog select failed (status 500)',
  );
});

test('adapter: resolves only one explicit SHACL validation report conformance value', () => {
  const report = (conforms) => ({
    '@graph': [{ '@type': 'sh:ValidationReport', 'sh:conforms': { '@value': conforms } }],
  });
  assert.equal(stardogInternals.reportConforms(report(true)), true);
  assert.equal(stardogInternals.reportConforms(report(false)), false);
  assert.equal(stardogInternals.reportConforms({ '@graph': [] }), null);
  assert.equal(stardogInternals.reportConforms({ '@graph': [report(true)['@graph'][0], report(true)['@graph'][0]] }), null);
});

test('generation plan fails closed when graph authority has no artefact plans', () => {
  const dir = writeGraph(baseSpec());
  const dataset = loadAuthorityDataset(loadManifest(dir));
  const plan = buildGenerationPlan(dataset.store);
  assert.equal(plan.complete, false);
  assert.ok(plan.obligations.some((item) => item.kind === 'missing-artefact-plans'));
  assert.throws(() => requireCompleteGenerationPlan(dataset.store), /generation plan is incomplete/);
});

function generationStore(body) {
  return new Store(new Parser({ format: 'text/turtle' }).parse(`
@prefix usf: <urn:usf:ontology:> .
${body}
`));
}

const completeGenerator = (name = 'complete') => `
<urn:usf:generator:${name}> a usf:CompilerComponent ;
  usf:semanticInputQuery "SELECT ?resource WHERE { ?resource a <urn:usf:ontology:SemanticContract> . }" ;
  usf:outputSchema <urn:usf:artefact:schema> ;
  usf:outputPathRule <urn:usf:pathrule:${name}> ;
  usf:integrityPolicy <urn:usf:policy:integrity> ;
  usf:normalisationPolicy <urn:usf:policy:normalisation> ;
  usf:missingSemanticsConstraint <urn:usf:constraint:missing> ;
  usf:requiresEquivalenceKind <urn:usf:equivalencekind:semantic> .
<urn:usf:pathrule:${name}> usf:pathPattern "generated/${name}.json" .
`;

test('generation plan rejects zero/multiple plan owners and output paths', () => {
  const store = generationStore(`
<urn:usf:repository:a> a usf:Repository . <urn:usf:repository:b> a usf:Repository .
<urn:usf:artefactplan:noowner> a usf:ArtefactPlan ; usf:plansArtefact <urn:usf:artefact:noowner> .
<urn:usf:artefactplan:multiowner> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:a>, <urn:usf:repository:b> ; usf:plansArtefact <urn:usf:artefact:multiowner> .
<urn:usf:artefactplan:nopath> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:a> ; usf:plansArtefact <urn:usf:artefact:nopath> .
<urn:usf:artefactplan:multipath> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:a> ; usf:plansArtefact <urn:usf:artefact:multipath> .
<urn:usf:artefact:noowner> a usf:Artefact ; usf:canonicalPath "generated/noowner.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:noowner> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:artefact:multiowner> a usf:Artefact ; usf:canonicalPath "generated/multiowner.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:multiowner> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:artefact:nopath> a usf:Artefact ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:nopath> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:artefact:multipath> a usf:Artefact ; usf:canonicalPath "generated/left.json", "generated/right.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:multipath> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:pathrule:noowner> usf:pathPattern "generated/noowner.json" .
<urn:usf:pathrule:multiowner> usf:pathPattern "generated/multiowner.json" .
<urn:usf:pathrule:nopath> usf:pathPattern "generated/nopath.json" .
<urn:usf:pathrule:multipath> usf:pathPattern "generated/{side}.json" .
${completeGenerator()}
`);
  const plan = buildGenerationPlan(store);
  assert.ok(plan.obligations.some((item) => item.kind === 'plan-owner-cardinality' && item.observed === 0));
  assert.ok(plan.obligations.some((item) => item.kind === 'plan-owner-cardinality' && item.observed === 2));
  assert.ok(plan.obligations.some((item) => item.kind === 'plan-path-cardinality' && item.observed === 0));
  assert.ok(plan.obligations.some((item) => item.kind === 'plan-path-cardinality' && item.observed === 2));
});

test('generation plan reports an incomplete generator contract', () => {
  const store = generationStore(`
<urn:usf:repository:foundation> a usf:Repository .
<urn:usf:artefactplan:output> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:foundation> ; usf:plansArtefact <urn:usf:artefact:output> .
<urn:usf:artefact:output> a usf:Artefact ; usf:canonicalPath "generated/output.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:output> ; usf:generatedByComponent <urn:usf:generator:incomplete> .
<urn:usf:pathrule:output> usf:pathPattern "generated/output.json" .
<urn:usf:generator:incomplete> a usf:CompilerComponent ; usf:outputSchema <urn:usf:artefact:schema> ; usf:outputPathRule <urn:usf:pathrule:output> ; usf:integrityPolicy <urn:usf:policy:integrity> ; usf:normalisationPolicy <urn:usf:policy:normalisation> ; usf:missingSemanticsConstraint <urn:usf:constraint:missing> ; usf:requiresEquivalenceKind <urn:usf:equivalencekind:semantic> .
`);
  const plan = buildGenerationPlan(store);
  assert.ok(plan.obligations.some((item) => item.kind === 'missing-semantic-input-query'));
  assert.ok(plan.obligations.some((item) => item.kind === 'incomplete-generator' && item.observed.includes('missing-semantic-input-query')));
});

test('generation plan requires executable ownership and detects path collisions', () => {
  const spec = baseSpec();
  spec['providers.ttl'] = `@prefix usf: <urn:usf:ontology:> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<urn:usf:repository:foundation> a usf:Repository .
<urn:usf:artefactplan:a> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:foundation> ; usf:plansArtefact <urn:usf:artefact:a> .
<urn:usf:artefactplan:b> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:foundation> ; usf:plansArtefact <urn:usf:artefact:b> .
<urn:usf:artefact:a> a usf:Artefact ; usf:canonicalPath "contracts/index.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:a> ; usf:generatedByComponent <urn:usf:generator:a> .
<urn:usf:artefact:b> a usf:Artefact ; usf:canonicalPath "contracts/index.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:b> ; usf:generatedByComponent <urn:usf:generator:a> .
<urn:usf:pathrule:a> usf:pathPattern "contracts/index.json" .
<urn:usf:pathrule:b> usf:pathPattern "contracts/index.json" .
<urn:usf:generator:a> usf:semanticInputQuery "SELECT ?resource WHERE { ?resource a <urn:usf:ontology:SemanticContract> . }" ; usf:outputSchema <urn:usf:artefact:a> ; usf:outputPathRule <urn:usf:pathrule:a> ; usf:integrityPolicy <urn:usf:policy:integrity> ; usf:normalisationPolicy <urn:usf:policy:normalisation> ; usf:missingSemanticsConstraint <urn:usf:constraint:missing> ; usf:requiresEquivalenceKind <urn:usf:equivalencekind:semantic> .
`;
  const plan = buildGenerationPlan(loadAuthorityDataset(loadManifest(writeGraph(spec))).store);
  assert.equal(plan.complete, false);
  assert.ok(plan.obligations.some((item) => item.kind === 'path-collision'));
});

test('live attestation: RDF canonicalization ignores blank-node labels', async () => {
  const left = '_:left <urn:usf:p> "value" .\n';
  const right = '_:unrelated <urn:usf:p> "value" .\n';
  assert.deepEqual(await canonicalGraphDigest(left), await canonicalGraphDigest(right));
});

test('verification: zero readiness fails the verification contract', () => {
  const conforming = {
    reachable: true,
    validationConforms: true,
    integrityConforms: true,
    contaminationCount: 0,
    missingGraphs: [],
    unexpectedGraphs: [],
    readinessCount: 1,
  };
  assert.equal(verificationConforms(conforming), true);
  assert.equal(verificationConforms({ ...conforming, readinessCount: 0 }), false);
  assert.equal(liveAttestationInternals.verificationPasses({
    ...conforming,
    countScope: 'registered-usf-graphs',
  }), true);
  assert.equal(liveAttestationInternals.verificationPasses({
    ...conforming,
    countScope: 'registered-usf-graphs',
    readinessCount: 0,
  }), false);
});

test('live attestation: census-facing totals are explicitly registered-USF scoped', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  const registered = managedGraphs(manifest);
  const report = await verify({
    manifest,
    client: {
      async size() { return 999; },
      async select(query) {
        if (query.includes('GROUP BY ?g')) {
          return [
            ...registered.map((graph) => ({ g: { value: graph }, c: { value: '2' } })),
            { g: { value: 'urn:external:graph' }, c: { value: '100' } },
          ];
        }
        if (query.includes('?violation')) return [];
        if (query.includes('REGEX(CONCAT')) return [{ c: { value: '0' } }];
        if (query.includes('derived:readiness')) return [{ c: { value: '1' } }];
        throw new Error(`unexpected query: ${query}`);
      },
      async validate() { return true; },
    },
  });
  assert.equal(report.databaseGraphCount, registered.length + 1);
  assert.equal(report.databaseTripleCount, 999);
  assert.equal(report.registeredGraphCount, registered.length);
  assert.equal(report.registeredTripleCount, registered.length * 2);
  const projection = liveAttestationInternals.verificationProjection(report);
  assert.equal(projection.countScope, 'registered-usf-graphs');
  assert.equal(projection.graphCount, registered.length);
  assert.equal(projection.tripleCount, registered.length * 2);
  assert.equal(projection.readinessCount, 1);
});

test('live attestation: rollback contract includes explicit activation barriers', () => {
  assert.deepEqual(liveAttestationInternals.requiredRollbackFaults, [
    'clear-graph',
    'commit',
    'commit-response',
    'contamination',
    'derive',
    'derived-insert',
    'integrity',
    'load',
    'rollback-response',
    'validate-authored',
    'validate-derived',
    'verify-counts',
    'wrong-rule-output',
  ]);
});

test('derived snapshot: canonical TriG is deterministic across blank-node labels', async () => {
  const graph = 'urn:usf:graph:derived:test';
  const left = '_:left <urn:usf:p> "value" .\n';
  const right = '_:unrelated <urn:usf:p> "value" .\n';
  assert.equal(await canonicalGraphTrig(graph, left), await canonicalGraphTrig(graph, right));
  assert.match(await canonicalGraphTrig(graph, left), /^GRAPH <urn:usf:graph:derived:test>/);
});

test('UI semantic closure is exact, contract-scoped, and exposure-complete', (t) => {
  if (realGraphAbsent(t)) return;
  const graphDir = REAL_GRAPH_DIR;
  const store = loadAuthorityDataset(loadManifest(graphDir)).store;
  const rdfType = DataFactory.namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const usf = (local) => DataFactory.namedNode(`urn:usf:ontology:${local}`);
  const iri = (value) => DataFactory.namedNode(value);
  const values = (terms) => [...new Set(terms.map((term) => term.value))].sort();
  const subjects = (predicate, object) => values(store.getSubjects(predicate, object, null));
  const objects = (subject, predicate) => values(store.getObjects(iri(subject), predicate, null));
  const models = subjects(rdfType, usf('UISemanticModel'));
  const facets = subjects(usf('facetKind'), iri('urn:usf:facetkind:uisemantics'));
  const complete = facets.filter((facet) => objects(facet, usf('facetStatus')).includes('urn:usf:facetstatus:complete'));
  const notApplicable = facets.filter((facet) => objects(facet, usf('facetStatus')).includes('urn:usf:facetstatus:notapplicable'));
  const gaps = facets.filter((facet) => objects(facet, usf('facetStatus')).includes('urn:usf:facetstatus:gap'));
  const expectedBindings = new Map([
    ['urn:usf:uisemanticmodel:authenticationplatform', {
      operations: ['urn:usf:operation:authloginpost'], permissions: ['urn:usf:permission:authlogin'],
    }],
    ['urn:usf:uisemanticmodel:apikeyspersonalaccesstokens', {
      operations: ['urn:usf:operation:apikeycreate'], permissions: ['urn:usf:permission:apikeycreate'],
    }],
    ['urn:usf:uisemanticmodel:apidocsdeveloperportalsdksratelimits', {
      operations: [], permissions: ['urn:usf:permission:routeaccessnone'],
    }],
    ['urn:usf:uisemanticmodel:enduserprofileandpreferencesselfservice', {
      operations: ['urn:usf:operation:profiledetailget', 'urn:usf:operation:profilelistget'], permissions: ['urn:usf:permission:tenantmembersread'],
    }],
    ['urn:usf:uisemanticmodel:notificationdeliveryandpreferencesandchannels', {
      operations: ['urn:usf:operation:notificationsget', 'urn:usf:operation:notificationslist'], permissions: ['urn:usf:permission:notificationlist', 'urn:usf:permission:notificationread'],
    }],
  ]);

  assert.equal(facets.length, 64);
  assert.equal(complete.length, 5);
  assert.equal(notApplicable.length, 59);
  assert.equal(gaps.length, 0);
  assert.deepEqual(models, [...expectedBindings.keys()].sort());
  assert.equal(notApplicable.filter((facet) => {
    const contract = subjects(usf('declaresFacet'), iri(facet))[0];
    return !objects(contract, usf('semanticLifecycleState')).includes('urn:usf:semanticlifecyclestate:deprecated');
  }).length, 59);

  for (const facet of facets) {
    const contracts = subjects(usf('declaresFacet'), iri(facet));
    assert.equal(contracts.length, 1, `${facet} must have one owning contract`);
    const contract = contracts[0];
    const capabilities = subjects(usf('hasContract'), iri(contract));
    assert.equal(capabilities.length, 1, `${contract} must have one owning capability`);
    const capability = capabilities[0];
    const exposure = objects(capability, usf('uiExposure'));
    const capabilityModels = objects(capability, usf('hasUISemanticModel'));
    if (complete.includes(facet)) {
      assert.deepEqual(exposure, ['urn:usf:uiexposureclass:uiexposed']);
      assert.equal(capabilityModels.length, 1);
    } else {
      assert.notEqual(exposure[0], 'urn:usf:uiexposureclass:uiexposed');
      assert.deepEqual(capabilityModels, []);
    }
  }

  for (const model of models) {
    assert.deepEqual(objects(model, usf('disclaims')), [], `${model} must not inherit SemanticContract through disclaims domain`);
    const viewModels = objects(model, usf('hasViewModel'));
    const surfaces = objects(model, usf('hasSurface'));
    const operations = values([
      ...viewModels.flatMap((viewModel) => store.getObjects(iri(viewModel), usf('loadsOperation'), null)),
      ...surfaces.flatMap((surface) => store.getObjects(iri(surface), usf('submitsOperation'), null)),
    ]);
    const permissions = values(surfaces.flatMap((surface) => store.getObjects(iri(surface), usf('uiRequiresPermission'), null)));
    assert.deepEqual(operations, expectedBindings.get(model).operations);
    assert.deepEqual(permissions, expectedBindings.get(model).permissions);
  }
});

test('generation: real authority has no semantic gaps and reuses deterministic incremental outputs', () => {
  const graphDir = REAL_GRAPH_DIR;
  const repositoryRoot = join(graphDir, '..');
  const manifest = loadManifest(graphDir);
  const dataset = loadAuthorityDataset(manifest);
  const currentGenerationPlan = requireCompleteGenerationPlan(dataset.store);
  assert.ok(currentGenerationPlan.outputs.every((output) => !output.template));
  const webQuery = generatorInternals.componentQuery(dataset.store, 'urn:usf:generator:webui');
  const mobileQuery = generatorInternals.componentQuery(dataset.store, 'urn:usf:generator:mobileui');
  assert.deepEqual(webQuery.constraints, [
    { predicate: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type', object: 'urn:usf:ontology:RendererContract' },
    { predicate: 'urn:usf:ontology:rendererTarget', object: 'urn:usf:renderertarget:web' },
  ]);
  assert.deepEqual(mobileQuery.constraints, [
    { predicate: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type', object: 'urn:usf:ontology:RendererContract' },
    { predicate: 'urn:usf:ontology:rendererTarget', object: 'urn:usf:renderertarget:mobile' },
  ]);
  const incompleteOutput = mkdtempSync(join(tmpdir(), 'usf-incomplete-generation-'));
  dirs.push(incompleteOutput);
  const gapStatus = DataFactory.namedNode('urn:usf:facetstatus:gap');
  const facetStatus = DataFactory.namedNode('urn:usf:ontology:facetStatus');
  assert.equal(dataset.store.getQuads(null, facetStatus, gapStatus, null).length, 0);
  assert.throws(
    () => generateAuthority({ store: dataset.store, outputDir: join(incompleteOutput, 'output'), mode: 'full' }),
    (error) => error instanceof CompilerError && error.phase === 'generate:signing',
  );
  const keys = generateKeyPairSync('ed25519');
  const fingerprint = createHash('sha256').update(keys.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  const identity = DataFactory.namedNode('urn:usf:signingidentity:foundationrelease');
  const predicate = DataFactory.namedNode('urn:usf:ontology:signingKeyFingerprint');
  dataset.store.removeQuads(dataset.store.getQuads(identity, predicate, null, null));
  dataset.store.addQuad(identity, predicate, DataFactory.literal(fingerprint));
  const root = mkdtempSync(join(tmpdir(), 'usf-real-generation-'));
  dirs.push(root);
  const keyPath = join(root, 'signing-key.pem');
  writeFileSync(keyPath, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const outputDir = join(root, 'output');
  const full = generateAuthority({ store: dataset.store, outputDir, mode: 'full', signingKeyPath: keyPath });
  assert.ok(full.outputCount > 0);
  const semanticContractFiles = readdirSync(join(outputDir, '.work/generated/semantic-contracts')).sort();
  assert.equal(semanticContractFiles.length, currentGenerationPlan.outputs.filter((output) => output.component === 'urn:usf:generator:semanticcontract').length);
  const generatedContract = JSON.parse(readFileSync(join(outputDir, '.work/generated/semantic-contracts/authenticationplatform.json'), 'utf8'));
  assert.equal(generatedContract.id, 'urn:usf:semanticcontract:authenticationplatform');
  assert.equal(generatedContract.facets.length, 10);
  assert.ok(generatedContract.facets.every((facet) => facet.status === 'complete' || facet.status === 'notapplicable'));
  assert.equal(generatedContract.authorityDigest.length, 64);
  assert.equal('sourceEquivalence' in generatedContract, false);
  assert.equal(existsSync(join(outputDir, '.work/generated/automation/proof-anchor.yaml')), true);
  assert.equal(existsSync(join(outputDir, '.work/generated/automation/validate-spec.yaml')), true);
  assert.equal(verifyOutput(outputDir, true, fingerprint).independent.signingIdentityTrusted, true);

  const wrong = generateKeyPairSync('ed25519');
  const wrongPath = join(root, 'wrong-key.pem');
  writeFileSync(wrongPath, wrong.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  assert.throws(
    () => generateAuthority({ store: dataset.store, outputDir, mode: 'incremental', signingKeyPath: wrongPath }),
    (error) => error instanceof CompilerError && error.phase === 'generate:signing-authority',
  );
  assert.equal(verifyOutput(outputDir, true, fingerprint).ok, true);

  const incremental = generateAuthority({ store: dataset.store, outputDir, mode: 'incremental', signingKeyPath: keyPath });
  assert.equal(incremental.aggregateDigest, full.aggregateDigest);
  assert.equal(incremental.changed, 0);
  assert.ok(incremental.reused > 0);
});

test('live attestation: graph comparison reports missing, unexpected and mismatched graphs', () => {
  const source = [
    { graph: 'urn:g:a', sha256: 'a', triples: 1 },
    { graph: 'urn:g:b', sha256: 'b', triples: 2 },
  ];
  const database = [
    { graph: 'urn:g:a', sha256: 'changed', triples: 1 },
    { graph: 'urn:g:c', sha256: 'c', triples: 3 },
  ];
  assert.deepEqual(compareGraphDigests(source, database), {
    missingGraphs: ['urn:g:b'],
    unexpectedGraphs: ['urn:g:c'],
    mismatchedGraphs: ['urn:g:a'],
  });
});
