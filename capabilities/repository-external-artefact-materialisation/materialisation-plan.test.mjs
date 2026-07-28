import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  ACCEPTED,
  ACTIVE,
  MATERIALISATION_CONTRACT,
  MATERIALISATION_PERMISSION_INVARIANT,
  MATERIALISATION_SOURCE_COLLECTION_CLASSIFICATION,
  PROVIDER_FACTORY_ACTIONS,
  PROVIDER_FACTORY_DIRECTORIES,
  PROVIDER_FACTORY_FAMILIES,
  PROVIDER_FACTORY_PATH_SCOPES,
  PROVIDER_FACTORY_REPOSITORY,
  PROVIDER_FACTORY_RULES,
  SUCCESSFUL,
  assertNoSymlinkSegments,
  canonicalJson,
  createMaterialisationPlan,
  materialisePlan,
  scopedPermissionSet,
  scopedPermissionSetDigest,
  sha256,
  validateMaterialisationPlan,
  validatePlanOperation,
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

test('proof and implementation source observations cannot grant semantic mutation authority', () => {
  const scopedAuthority = {
    authorisedRepositories: [PROVIDER_FACTORY_REPOSITORY],
    authorisedPaths: ['config/providers.yaml'],
    authorisedDirectoryPrefixes: [...PROVIDER_FACTORY_DIRECTORIES],
    authorisedActions: [...PROVIDER_FACTORY_ACTIONS],
    authorisedFamilies: [...PROVIDER_FACTORY_FAMILIES],
    rules: PROVIDER_FACTORY_RULES.map((rule) => ({ ...rule })),
    pathRoles: [{
      id: 'urn:usf:pathrole:factorypythonpackagesource',
      parent: 'src/usf_factory',
    }],
    decisionScopedMaterialisationRequired: true,
  };
  const baselineScope = scopedPermissionSet(scopedAuthority);
  const baselineDigest = scopedPermissionSetDigest(scopedAuthority);
  const implementationSources = Array.from({ length: 60 }, (_, index) => ({
    path: `src/untrusted-implementation-evidence-${index}.py`,
    digest: `sha256:${index.toString(16).padStart(64, '0')}`,
  }));
  const proofInputSources = Array.from({ length: 26 }, (_, index) => ({
    path: `src/untrusted-proof-input-${index}.py`,
    digest: `sha256:${(index + 60).toString(16).padStart(64, '0')}`,
  }));
  const observedAuthority = {
    ...scopedAuthority,
    implementationSources,
    proofInputSources,
  };

  assert.deepEqual(MATERIALISATION_SOURCE_COLLECTION_CLASSIFICATION, {
    implementationSources: 'IMPLEMENTATION_EVIDENCE_ONLY',
    proofInputSources: 'READ_ONLY_PROOF_INPUT_ONLY',
  });
  assert.equal(MATERIALISATION_PERMISSION_INVARIANT.permissionSource, 'ACCEPTED_SEMANTIC_REALISATION_DECISION_ONLY');
  assert.ok(!MATERIALISATION_PERMISSION_INVARIANT.permissionFields.includes('implementationSources'));
  assert.ok(!MATERIALISATION_PERMISSION_INVARIANT.permissionFields.includes('proofInputSources'));
  assert.equal(implementationSources.length, 60);
  assert.equal(proofInputSources.length, 26);
  assert.deepEqual(scopedPermissionSet(observedAuthority), baselineScope);
  assert.equal(scopedPermissionSetDigest(observedAuthority), baselineDigest);
  assert.deepEqual(observedAuthority.authorisedPaths, scopedAuthority.authorisedPaths);
  assert.deepEqual(observedAuthority.authorisedDirectoryPrefixes, scopedAuthority.authorisedDirectoryPrefixes);
  assert.deepEqual(observedAuthority.authorisedActions, scopedAuthority.authorisedActions);
  assert.deepEqual(observedAuthority.authorisedFamilies, scopedAuthority.authorisedFamilies);

  const rule = PROVIDER_FACTORY_RULES.find(({ family: candidate }) => (
    candidate === 'urn:usf:artefactfamily:factorypythonpackagerealisation'
  ));
  const bytes = 'pass\n';
  for (const untrustedPath of [implementationSources[0].path, proofInputSources[0].path]) {
    const failures = validatePlanOperation({
      action: 'write-file',
      artefactFamily: rule.family,
      content: bytes,
      contentDigest: sha256(bytes),
      contentEncoding: 'utf8',
      fileMode: '0644',
      index: 0,
      path: untrustedPath,
      pathRole: rule.pathRole,
      representationFormat: rule.representationFormat,
    }, 0, observedAuthority);
    assert.ok(failures.some(({ code }) => code === 'operation-decision-path'));
  }
});

test('provider decision path counts and narrow semantic mutation scope remain exact', () => {
  assert.deepEqual(PROVIDER_FACTORY_PATH_SCOPES, {
    'urn:usf:semanticcontract:providerconfigurationplane': {
      count: 102,
      digest: 'sha256:cfb3cc646ac93a523c5b108174114dd943ec46485dbc5fc4a955f3c51e8c11f9',
    },
    'urn:usf:semanticcontract:providerenvironmentclassification': {
      count: 63,
      digest: 'sha256:13624cf373024e620d1b91a31a8d7539669c7853a72fc9815f3235a768a20d42',
    },
    'urn:usf:semanticcontract:servicecatalogandproviderintegrationmodel': {
      count: 63,
      digest: 'sha256:13624cf373024e620d1b91a31a8d7539669c7853a72fc9815f3235a768a20d42',
    },
  });
  assert.deepEqual(PROVIDER_FACTORY_DIRECTORIES, [
    'src/usf_factory/providers',
    'tests/provider_workforce',
  ]);
  assert.deepEqual(PROVIDER_FACTORY_ACTIONS, ['write-file']);
  assert.deepEqual(PROVIDER_FACTORY_FAMILIES, PROVIDER_FACTORY_RULES.map(({ family: authorisedFamily }) => authorisedFamily));
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
