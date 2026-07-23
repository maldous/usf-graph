import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  ACCEPTED,
  ACTIVE,
  MATERIALISATION_CONTRACT,
  SUCCESSFUL,
  assertNoSymlinkSegments,
  canonicalJson,
  createMaterialisationPlan,
  materialisePlan,
  sha256,
  validateMaterialisationPlan,
} from './materialisation-plan.mjs';

const role = 'urn:usf:pathrole:capabilitysource';
const family = 'urn:usf:artefactfamily:capabilitysource';
const format = 'urn:usf:representationformat:ecmascriptmodule2024';

function authority() {
  return {
    authorityDigest: `sha256:${'a'.repeat(64)}`,
    contract: {
      id: MATERIALISATION_CONTRACT,
      activationState: ACTIVE,
      proofResultState: SUCCESSFUL,
      decisionState: ACCEPTED,
    },
    acceptedDecisionCount: 1,
    authorisedPaths: ['capabilities'],
    pathRoles: [{ id: role, canonicalName: 'capabilitysource', parent: 'capabilities', onDemand: true }],
    rules: [{ family, pathRole: role, representationFormat: format, namingPattern: '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\\.[a-z0-9]+)+$' }],
  };
}

function writeOperation(content = 'export const ready = true;\n', index = 0, path = 'capabilities/example/example-capability.mjs') {
  return { action: 'write-file', artefactFamily: family, content, contentDigest: sha256(content), contentEncoding: 'utf8', fileMode: '0644', index, path, pathRole: role, representationFormat: format };
}

test('creates a deterministic authority-bound plan', () => {
  const first = createMaterialisationPlan(authority(), [writeOperation()]);
  const second = createMaterialisationPlan(authority(), [writeOperation()]);
  assert.deepEqual(first, second);
  assert.equal(validateMaterialisationPlan(authority(), first).ok, true);
  assert.equal(first.planDigest, sha256(canonicalJson({ ...first, planDigest: undefined })));
});

test('rejects stale authority, tampered bytes and forbidden durable identities', () => {
  const plan = createMaterialisationPlan(authority(), [writeOperation()]);
  const stale = authority();
  stale.authorityDigest = `sha256:${'b'.repeat(64)}`;
  assert.equal(validateMaterialisationPlan(stale, plan).ok, false);
  const tampered = structuredClone(plan);
  tampered.operations[0].content = 'tampered\n';
  assert.equal(validateMaterialisationPlan(authority(), tampered).ok, false);
  assert.throws(() => createMaterialisationPlan(authority(), [writeOperation('x\n', 0, 'capabilities/legacy/example.mjs')]), /operation-path/);
});

test('applies a plan idempotently and reports exact operation states', () => {
  const root = mkdtempSync(join(tmpdir(), 'materialisation-cell-'));
  const content = 'export const ready = true;\n';
  const plan = createMaterialisationPlan(authority(), [writeOperation(content)]);
  const first = materialisePlan({ authority: authority(), plan, repositoryRoot: root, apply: true });
  assert.equal(first.applied, true);
  assert.equal(first.operations[0].state, 'applied');
  assert.equal(readFileSync(join(root, 'capabilities/example/example-capability.mjs'), 'utf8'), content);
  const second = materialisePlan({ authority: authority(), plan, repositoryRoot: root, apply: true });
  assert.equal(second.operations[0].state, 'already-applied');
});

test('declared file mode and idempotence do not inherit a restrictive supervisor umask', () => {
  const root = mkdtempSync(join(tmpdir(), 'materialisation-cell-'));
  const content = 'export const ready = true;\n';
  const plan = createMaterialisationPlan(authority(), [writeOperation(content)]);
  const priorUmask = process.umask(0o077);
  try {
    const first = materialisePlan({
      authority: authority(), plan, repositoryRoot: root, apply: true,
    });
    const second = materialisePlan({
      authority: authority(), plan, repositoryRoot: root, apply: true,
    });
    assert.equal(first.operations[0].state, 'applied');
    assert.equal(statSync(join(root, 'capabilities/example/example-capability.mjs')).mode & 0o777, 0o644);
    assert.equal(second.operations[0].state, 'already-applied');
  } finally {
    process.umask(priorUmask);
  }
});

test('dry-run performs no repository mutation', () => {
  const root = mkdtempSync(join(tmpdir(), 'materialisation-cell-'));
  const plan = createMaterialisationPlan(authority(), [writeOperation()]);
  const result = materialisePlan({ authority: authority(), plan, repositoryRoot: root });
  assert.equal(result.dryRun, true);
  assert.throws(() => readFileSync(join(root, 'capabilities/example/example-capability.mjs')));
});

test('rolls back earlier operations after a later optimistic-concurrency failure', () => {
  const root = mkdtempSync(join(tmpdir(), 'materialisation-cell-'));
  mkdirSync(join(root, 'capabilities/example'), { recursive: true });
  writeFileSync(join(root, 'capabilities/example/existing.mjs'), 'current\n');
  const second = writeOperation('replacement\n', 1, 'capabilities/example/existing.mjs');
  second.sourceDigest = sha256('stale\n');
  const plan = createMaterialisationPlan(authority(), [writeOperation('created\n'), second]);
  assert.throws(() => materialisePlan({ authority: authority(), plan, repositoryRoot: root, apply: true }), /source digest mismatch/);
  assert.throws(() => readFileSync(join(root, 'capabilities/example/example-capability.mjs')));
  assert.equal(readFileSync(join(root, 'capabilities/example/existing.mjs'), 'utf8'), 'current\n');
});

test('rejects symbolic-link traversal', () => {
  const root = '/repository';
  const target = '/repository/capabilities/example/example-capability.mjs';
  assert.throws(() => assertNoSymlinkSegments(root, target, 'write target', {
    existsSync: (path) => path === '/repository/capabilities/example',
    lstatSync: () => ({ isSymbolicLink: () => true }),
  }), /symbolic link/);
});

test('verifies digest-bound CAS content before writing', () => {
  const root = mkdtempSync(join(tmpdir(), 'materialisation-cell-'));
  const cas = mkdtempSync(join(tmpdir(), 'materialisation-cas-'));
  const content = 'export const fromCas = true;\n';
  const contentDigest = sha256(content);
  const hex = contentDigest.slice(7);
  mkdirSync(join(cas, 'sha256', hex.slice(0, 2)), { recursive: true });
  writeFileSync(join(cas, 'sha256', hex.slice(0, 2), hex), content);
  const operation = writeOperation(content);
  delete operation.content;
  delete operation.contentEncoding;
  operation.contentDigest = contentDigest;
  operation.contentLocator = `cas://sha256/${hex}`;
  const plan = createMaterialisationPlan(authority(), [operation]);
  assert.equal(materialisePlan({ authority: authority(), plan, repositoryRoot: root, casRoot: cas, apply: true }).applied, true);
});
