import test from 'node:test';
import assert from 'node:assert/strict';
import { framedDigest, sha256 } from '../src/canonical.mjs';
import { identifyFormat } from '../src/universe.mjs';
import { addCrossArtifactFindings, inventoryKind } from '../src/index.mjs';
import { validateRelationship } from '../src/contract.mjs';

const baseMember = {
  path: 'fixture.txt',
  universe: 'repository-output',
  sourceState: 'tracked',
  contentDigest: sha256('fixture'),
  byteSize: 7,
  fileMode: '100644',
  executable: false,
  binary: false,
  extension: '.txt',
  mediaType: 'text/plain',
  formatKind: 'plain-text',
  symbolicLinkTarget: null
};

function digest(rows) {
  return framedDigest(rows, ['universe', 'path', 'sourceState', 'fileMode', 'contentDigest']);
}

for (const [label, universe, sourceState, path] of [
  ['new tracked repository file', 'repository-output', 'tracked', 'new-repository.txt'],
  ['new nonignored untracked file', 'repository-output', 'untracked', 'new-untracked.txt'],
  ['new graph file', 'v2-graph-authority', 'tracked', 'v2/usf/graph/new.ttl'],
  ['new compiler file', 'v2-compiler-implementation', 'tracked', 'v2/usf/compiler/new.mjs'],
  ['new support file', 'v2-support-provisioning', 'tracked', 'v2/new-support.sh']
]) {
  test(`${label} changes framed universe identity`, () => {
    const added = { ...baseMember, universe, sourceState, path, contentDigest: sha256(path) };
    assert.notEqual(digest([baseMember]), digest([baseMember, added]));
  });
}

test('unknown extension is explicitly represented as plain text', () => {
  const format = identifyFormat('fixture.unseen-format', Buffer.from('opaque but readable'), '100644');
  assert.equal(format.formatKind, 'plain-text');
  assert.equal(format.binary, false);
});

test('new structured inventory shape is represented generically', () => {
  const kind = inventoryKind({ alpha: [{ source: 'a', target: 'b' }] }, baseMember, { paths: [], declarations: [] });
  assert.equal(kind, 'relationship-collection');
});

test('new relationship kinds cannot pass the closed contract', () => {
  assert.throws(() => validateRelationship({
    source: 'fixture.txt',
    relationshipType: 'novel-unregistered-kind',
    target: 'target.txt',
    targetKind: 'artifact',
    extractionMethod: 'adversarial-fixture',
    confidence: { level: 'high', score: 1, reasons: ['machine-verifiable-extraction'] },
    resolved: false,
    reasonCodes: ['unresolved-target-finding']
  }), /invalid relationshipTypes/);
});

test('orphaned generators, validators, proofs, evidence, and checksums become findings', () => {
  const names = [
    'generator-orphan.mjs',
    'validator-orphan.mjs',
    'proof-orphan.mjs',
    'evidence-orphan.json',
    'checksum-orphan-a.json',
    'checksum-orphan-b.json'
  ];
  const members = names.map((path) => ({ ...baseMember, path, contentDigest: sha256(path) }));
  const findings = addCrossArtifactFindings(members, []);
  const codes = findings.map((finding) => finding.detailCode);
  assert.ok(codes.includes('generator-output-not-linked'));
  assert.ok(codes.includes('validator-rule-or-fixture-not-linked'));
  assert.ok(codes.includes('proof-obligation-not-linked'));
  assert.ok(codes.includes('evidence-collector-or-ingestion-not-linked'));
  assert.equal(codes.filter((code) => code === 'integrity-protected-input-not-linked').length, 2);
});
