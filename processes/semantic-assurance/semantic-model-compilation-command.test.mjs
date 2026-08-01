import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DataFactory, Parser, Writer } from 'n3';

import {
  SEMANTIC_MODEL_PATH,
  createSemanticModelCompilationCommand,
} from './semantic-model-compilation-command.mjs';

const authorityDigest = `sha256:${'a'.repeat(64)}`;
const repositories = [];

function repository() {
  const root = mkdtempSync(join(tmpdir(), 'usf-semantic-assurance-'));
  mkdirSync(join(root, SEMANTIC_MODEL_PATH));
  repositories.push(root);
  return root;
}

test.after(() => repositories.forEach((root) => rmSync(root, { recursive: true, force: true })));

function client() { return { connectivity: async () => 1 }; }

test('validates the canonical semantic model with an exact authority binding', async () => {
  const calls = [];
  const command = createSemanticModelCompilationCommand({
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    loadManifestFunction: (path) => ({ path }),
    compileFunction: async (input) => { calls.push(input); return { ok: true, commitOutcome: { state: 'validated-rolled-back' } }; },
  });
  const result = await command.execute({ expectedAuthorityDigest: authorityDigest });
  assert.equal(result.semanticModelPath, SEMANTIC_MODEL_PATH);
  assert.equal(result.evaluatedAuthorityDigest, authorityDigest);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].publicationMode, 'validate');
  assert.equal(calls[0].authorityWitness.digest, authorityDigest);
  assert.ok(calls[0].manifest.path.endsWith(`/${SEMANTIC_MODEL_PATH}`));
});

test('fails before loading or compiling when authority drift is observed', async () => {
  let loaded = false;
  const command = createSemanticModelCompilationCommand({
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: `sha256:${'b'.repeat(64)}` }),
    loadManifestFunction: () => { loaded = true; },
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({ expectedAuthorityDigest: authorityDigest }), /drifted before compilation/);
  assert.equal(loaded, false);
});

test('detects mutation during a validate-only transaction', async () => {
  let reads = 0;
  const command = createSemanticModelCompilationCommand({
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: reads++ === 0 ? authorityDigest : `sha256:${'c'.repeat(64)}` }),
    loadManifestFunction: () => ({}),
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({ expectedAuthorityDigest: authorityDigest }), /validate-only compilation changed/);
});

test('requires an explicit digest and the canonical non-symlink path', async () => {
  const command = createSemanticModelCompilationCommand({
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    loadManifestFunction: () => ({}),
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({}), /expected authority digest/);
});

test('composes and applies exact D0 stage1 and D1 stage2 source-plus-generated deltas', async () => {
  const root = repository();
  const graph = 'urn:test:graph';
  const shapesPath = join(root, SEMANTIC_MODEL_PATH, 'shapes.ttl');
  writeFileSync(shapesPath, '@prefix sh: <http://www.w3.org/ns/shacl#> .\n');
  let live = new Map([[graph, '<urn:test:s> <urn:test:p> "d0" .\n']]);
  let authority = `sha256:${'d'.repeat(64)}`;
  const snapshots = new Map();
  let next = 0;
  const fakeClient = {
    async connectivity() { return 1; },
    async begin() { const id = `tx-${next += 1}`; snapshots.set(id, new Map(live)); return id; },
    async rollback(id) { snapshots.delete(id); },
    async commit(id) { live = snapshots.get(id); snapshots.delete(id); authority = `sha256:${String(next).padStart(64, '0')}`; },
    async constructInTransaction(id, query) {
      const name = /GRAPH <([^>]+)>/.exec(query)?.[1];
      return snapshots.get(id).get(name) || '';
    },
    async clearGraphs(id, graphs) { for (const name of graphs) snapshots.get(id).set(name, ''); },
    async addData(id, content, _type, target) {
      const parsed = new Parser({ format: target ? 'text/turtle' : 'application/n-quads' }).parse(content);
      const byGraph = new Map();
      for (const item of parsed) {
        const name = target || item.graph.value;
        if (!byGraph.has(name)) byGraph.set(name, []);
        byGraph.get(name).push(DataFactory.quad(item.subject, item.predicate, item.object));
      }
      for (const [name, items] of byGraph) {
        const value = await new Promise((resolveText, reject) => {
          const writer = new Writer({ format: 'N-Triples' });
          writer.addQuads(items);
          writer.end((error, output) => error ? reject(error) : resolveText(output));
        });
        snapshots.get(id).set(name, value);
      }
    },
    async validateInTransactionWithReceipt() { return { conforms: true, receiptDigest: `sha256:${'e'.repeat(64)}` }; },
    async reportInTransaction() { return []; },
    async selectInTransaction() { return []; },
  };
  const manifest = {
    authored: [], definitions: [{ file: 'authority.ttl', graph }], derived: [], reviews: [], rules: [],
    shapes: [{ file: 'shapes.ttl', graph: 'urn:usf:graph:shapes', liveValidation: true, path: shapesPath }],
    publicationBudget: { maximumProjectedStatementCount: 999999 },
  };
  let sourceValue = 'source';
  const sourceCompiler = async ({ client: transactionClient, publicationMode }) => {
    assert.equal(publicationMode, 'validate');
    const tx = await transactionClient.begin();
    await transactionClient.clearGraphs(tx, [graph]);
    await transactionClient.addData(tx, `<urn:test:s> <urn:test:p> "${sourceValue}" .\n`, 'text/turtle', graph);
    const liveValidation = await transactionClient.validateInTransactionWithReceipt(tx, []);
    await transactionClient.rollback(tx);
    return { ok: true, liveValidation };
  };
  const command = createSemanticModelCompilationCommand({
    checkLocalFunction: () => {}, client: Object.freeze(fakeClient), compileFunction: sourceCompiler,
    loadManifestFunction: () => manifest,
    readAuthorityWitness: async () => ({ digest: authority, inventory: [], triples: 1 }),
    repositoryRoot: root,
  });
  const candidate = (label) => {
    const bytes = Buffer.from(`# semantic-proof-v1 canonical-rdf-patch-v1 stage1\nA <urn:test:blank> <urn:test:p> _:${label} <${graph}> .\n`);
    return { bytes, digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}` };
  };
  const canonicalBlankNode = candidate('c14n0');
  assert.equal((await command.inspectCandidateState({
    candidateBytes: canonicalBlankNode.bytes,
    candidateDigest: canonicalBlankNode.digest,
  })).state, 'pre');
  const nonCanonicalBlankNode = candidate('sourceBlank');
  await assert.rejects(() => command.inspectCandidateState({
    candidateBytes: nonCanonicalBlankNode.bytes,
    candidateDigest: nonCanonicalBlankNode.digest,
  }), /canonical quad/);
  const originalLive = live;
  live = new Map([[graph, '<urn:test:blank> <urn:test:p> _:source .\n']]);
  const deletionBytes = Buffer.from(`# semantic-proof-v1 canonical-rdf-patch-v1 stage1\nD <urn:test:blank> <urn:test:p> _:c14n0 <${graph}> .\n`);
  assert.equal((await command.inspectCandidateState({
    candidateBytes: deletionBytes,
    candidateDigest: `sha256:${createHash('sha256').update(deletionBytes).digest('hex')}`,
  })).state, 'pre');
  live = originalLive;
  const generated = (stage, from, to) => Buffer.from(`# semantic-proof-v1 canonical-rdf-patch-v1 ${stage}\nD <urn:test:s> <urn:test:p> "${from}" <${graph}> .\nA <urn:test:s> <urn:test:p> "${to}" <${graph}> .\n`);
  const stage1 = await command.composeCandidate({ generatedCandidateBytes: generated('stage1', 'source', 'd1'), expectedAuthorityDigest: authority });
  assert.equal((await command.inspectCandidateState({ candidateBytes: stage1.bytes, candidateDigest: stage1.digest })).state, 'pre');
  await command.execute({ candidateBytes: stage1.bytes, candidateDigest: stage1.digest, expectedAuthorityDigest: authority, publicationMode: 'commit' });
  assert.match(live.get(graph), /"d1"/);
  const d1 = authority;
  const stage2 = await command.composeCandidate({ generatedCandidateBytes: generated('stage2', 'source', 'final'), expectedAuthorityDigest: d1 });
  assert.equal((await command.inspectCandidateState({ candidateBytes: stage2.bytes, candidateDigest: stage2.digest })).state, 'pre');
  await command.execute({ candidateBytes: stage2.bytes, candidateDigest: stage2.digest, expectedAuthorityDigest: d1, publicationMode: 'commit' });
  assert.match(live.get(graph), /"final"/);
});
