import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { repositoryRoot } from '../src/constants.mjs';
import { repositoryState, stableJson, verifyStardogObservation } from '../audit/live-observation.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

test('independent Stardog observation verifies signature, trust, repository, digests, validation and rollback', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const fingerprint = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  const graph = { graph: 'urn:usf:graph:test', algorithm: 'URDNA2015', digestAlgorithm: 'sha256', sha256: 'a'.repeat(64), triples: 1 };
  const names = [
    'clear-graph', 'load', 'collect-observed', 'invalid-observed-rdf', 'validate-authored', 'validate-observed',
    'derive', 'wrong-rule-output', 'derived-insert', 'validate-derived', 'integrity', 'contamination', 'verify-counts',
    'commit', 'rollback-response'
  ];
  const payload = {
    schemaVersion: 1,
    kind: 'source-to-database',
    observationKind: 'stardog-access-boundary',
    accessMethod: 'official-sdk',
    connectionAttempted: true,
    observedAt: new Date().toISOString(),
    repository: repositoryState(repositoryRoot),
    canonicalization: { algorithm: 'URDNA2015', digestAlgorithm: 'sha256' },
    sourceGraphDigests: [graph],
    databaseGraphDigests: [graph],
    comparison: { missingGraphs: [], unexpectedGraphs: [], mismatchedGraphs: [] },
    verification: { reachable: true, countScope: 'registered-usf-graphs', graphCount: 1, tripleCount: 1, missingGraphs: [], unexpectedGraphs: [], validationConforms: true, integrityConforms: true, contaminationCount: 0, readinessCount: 1 },
    rollback: {
      ok: true,
      faultCount: names.length,
      digestsUnchanged: true,
      faults: names.map((name) => ({ name, rollbackCount: 1, activationCount: 1, injectionPoint: `injection:${name}`, errorPhase: name })),
      commitOutcomeCoverage: { mode: 'pre-dispatch-only', ambiguousPostDispatchOutcomeProven: false, limitation: 'post-dispatch ambiguity is not injected' },
    },
  };
  const envelope = {
    payload,
    signature: { algorithm: 'Ed25519', publicKey: publicKeyPem, publicKeyFingerprint: fingerprint, value: sign(null, Buffer.from(stableJson(payload)), privateKey).toString('base64') },
  };
  const target = path.join(os.tmpdir(), `usf-stardog-observation-${process.pid}.json`);
  fs.writeFileSync(target, JSON.stringify(envelope));
  try {
    const result = verifyStardogObservation(target, fingerprint, repositoryRoot);
    assert.equal(result.status, 'observed');
    assert.equal(result.observation.rollbackFaultCount, 15);
    assert.equal(result.observation.countScope, 'registered-usf-graphs');
    assert.equal(result.observation.readinessCount, 1);
    assert.deepEqual(payload.repository.excludedPaths, ['v2/usf/census/audit.json', 'v2/usf/census/closure.json', 'v2/usf/.work/']);
    envelope.payload.verification.tripleCount = 2;
    fs.writeFileSync(target, JSON.stringify(envelope));
    assert.equal(verifyStardogObservation(target, fingerprint, repositoryRoot).status, 'invalid');
  } finally {
    fs.rmSync(target, { force: true });
  }
});

test('independent Stardog observation rejects weakened verification and rollback proof contracts', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const fingerprint = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  const names = [
    'clear-graph', 'collect-observed', 'commit', 'contamination', 'derive', 'derived-insert', 'integrity',
    'invalid-observed-rdf', 'load', 'rollback-response', 'validate-authored', 'validate-derived',
    'validate-observed', 'verify-counts', 'wrong-rule-output',
  ];
  const graph = { graph: 'urn:usf:graph:test', algorithm: 'URDNA2015', digestAlgorithm: 'sha256', sha256: 'a'.repeat(64), triples: 1 };
  const base = {
    observationKind: 'stardog-access-boundary', accessMethod: 'official-sdk', connectionAttempted: true, observedAt: new Date().toISOString(),
    repository: repositoryState(repositoryRoot), canonicalization: { algorithm: 'URDNA2015', digestAlgorithm: 'sha256' },
    sourceGraphDigests: [graph], databaseGraphDigests: [graph], comparison: { missingGraphs: [], unexpectedGraphs: [], mismatchedGraphs: [] },
    verification: { reachable: true, countScope: 'registered-usf-graphs', graphCount: 1, tripleCount: 1, missingGraphs: [], unexpectedGraphs: [], validationConforms: true, integrityConforms: true, contaminationCount: 0, readinessCount: 1 },
    rollback: {
      ok: true, faultCount: 15, digestsUnchanged: true,
      faults: names.map((name) => ({ name, rollbackCount: 1, activationCount: 1, injectionPoint: `injection:${name}`, errorPhase: name })),
      commitOutcomeCoverage: { mode: 'pre-dispatch-only', ambiguousPostDispatchOutcomeProven: false, limitation: 'post-dispatch ambiguity is not injected' },
    },
  };
  const target = path.join(os.tmpdir(), `usf-stardog-weakened-${process.pid}.json`);
  const writeSigned = (payload) => fs.writeFileSync(target, JSON.stringify({
    payload,
    signature: { algorithm: 'Ed25519', publicKey: publicKeyPem, publicKeyFingerprint: fingerprint, value: sign(null, Buffer.from(stableJson(payload)), privateKey).toString('base64') },
  }));
  const mutations = [
    (payload) => { payload.verification.countScope = 'whole-database'; },
    (payload) => { payload.verification.graphCount = 2; },
    (payload) => { payload.verification.tripleCount = 2; },
    (payload) => { payload.verification.readinessCount = 0; },
    (payload) => { payload.rollback.faults = payload.rollback.faults.filter((fault) => fault.name !== 'clear-graph'); },
    (payload) => { payload.rollback.faults[0].activationCount = 0; },
    (payload) => { payload.rollback.faults[0].injectionPoint = ''; },
    (payload) => { delete payload.rollback.commitOutcomeCoverage; },
    (payload) => { payload.rollback.commitOutcomeCoverage.mode = 'post-dispatch'; },
    (payload) => { payload.rollback.commitOutcomeCoverage.ambiguousPostDispatchOutcomeProven = true; },
    (payload) => { payload.rollback.commitOutcomeCoverage.limitation = ''; },
  ];
  try {
    for (const mutate of mutations) {
      const payload = structuredClone(base);
      mutate(payload);
      writeSigned(payload);
      assert.equal(verifyStardogObservation(target, fingerprint, repositoryRoot).status, 'invalid');
    }
  } finally {
    fs.rmSync(target, { force: true });
  }
});

test('repository binding excludes tracked and untracked V2 scratch from file and status evidence', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'usf-repository-binding-'));
  const git = (args) => execFileSync('git', args, { cwd: root, stdio: 'pipe' });
  const write = (relative, value) => {
    const target = path.join(root, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, value);
  };
  try {
    git(['init', '-q']);
    git(['config', 'user.email', 'audit@example.invalid']);
    git(['config', 'user.name', 'Independent Audit']);
    write('authority.txt', 'authority\n');
    write('v2/usf/.work/tracked/proposal.json', '{"proposal":true}\n');
    git(['add', '.']);
    git(['commit', '-qm', 'fixture']);

    const baseline = repositoryState(root);
    write('v2/usf/.work/tracked/proposal.json', '{"proposal":false}\n');
    write('v2/usf/.work/untracked/result.json', '{"result":true}\n');
    const withScratch = repositoryState(root);

    assert.equal(baseline.files, 1);
    assert.equal(withScratch.files, 1);
    assert.equal(withScratch.contentRootSha256, baseline.contentRootSha256);
    assert.equal(withScratch.statusSha256, baseline.statusSha256);
    assert.equal(withScratch.clean, baseline.clean);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
