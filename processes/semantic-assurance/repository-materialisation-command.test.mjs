import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  ACCEPTED,
  ACTIVE,
  MATERIALISATION_CONTRACT,
  SUCCESSFUL,
  createMaterialisationPlan,
  sha256,
} from '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';
import { runRepositoryMaterialisationCommand } from './repository-materialisation-command.mjs';

const role = 'urn:usf:pathrole:capabilitysource';
const family = 'urn:usf:artefactfamily:capabilitysource';
const format = 'urn:usf:representationformat:ecmascriptmodule2024';

function fixture() {
  const authority = {
    authorityDigest: `sha256:${'c'.repeat(64)}`,
    contract: { id: MATERIALISATION_CONTRACT, activationState: ACTIVE, proofResultState: SUCCESSFUL, decisionState: ACCEPTED },
    acceptedDecisionCount: 1,
    authorisedPaths: ['capabilities'],
    authorisedFormats: [format],
    pathRoles: [{ id: role, parent: 'capabilities' }],
    rules: [{ family, pathRole: role, representationFormat: format, namingPattern: '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\\.[a-z0-9]+)+$' }],
  };
  const content = 'export const assembled = true;\n';
  const plan = createMaterialisationPlan(authority, [{ action: 'write-file', artefactFamily: family, content, contentDigest: sha256(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/example/assembled.mjs', pathRole: role, representationFormat: format }]);
  return { authority, plan };
}

test('thin process assembly validates and applies explicit inputs', () => {
  const work = mkdtempSync(join(tmpdir(), 'semantic-assurance-command-'));
  const repository = mkdtempSync(join(tmpdir(), 'semantic-assurance-repository-'));
  const { authority, plan } = fixture();
  const authorityPath = join(work, 'authority.json');
  const planPath = join(work, 'plan.json');
  writeFileSync(authorityPath, JSON.stringify(authority));
  writeFileSync(planPath, JSON.stringify(plan));
  let output = '';
  const writer = { write: (chunk) => { output += chunk; } };
  assert.equal(runRepositoryMaterialisationCommand(['validate', authorityPath, planPath], writer).ok, true);
  assert.match(output, /"ok":true/);
  // dry-run and apply are gone: this command took its authority projection from a
  // FILE, so a hand-written projection could drive a coordinator apply with no live
  // authority decision. Materialisation apply exists only in the canonical gateway
  // under a digest-stable realisation verdict.
  for (const mutating of ['dry-run', 'apply']) {
    assert.throws(
      () => runRepositoryMaterialisationCommand([mutating, authorityPath, planPath, repository], writer),
      /only available through the canonical materialisation gateway/,
      mutating,
    );
  }
  assert.equal(existsSync(join(repository, 'capabilities/example/assembled.mjs')), false);
});

test('thin process assembly fails closed on absent or empty decision formats', () => {
  const work = mkdtempSync(join(tmpdir(), 'semantic-assurance-command-'));
  const { authority, plan } = fixture();
  const planPath = join(work, 'plan.json');
  writeFileSync(planPath, JSON.stringify(plan));
  const absent = structuredClone(authority);
  delete absent.authorisedFormats;
  for (const [name, candidate] of [
    ['absent', absent],
    ['empty', { ...authority, authorisedFormats: [] }],
  ]) {
    const authorityPath = join(work, `${name}-authority.json`);
    writeFileSync(authorityPath, JSON.stringify(candidate));
    const result = runRepositoryMaterialisationCommand(['validate', authorityPath, planPath], { write() {} });
    assert.equal(result.ok, false);
    assert.deepEqual(result.failures.filter((item) => item.code === 'authorised-formats'), [
      { code: 'authorised-formats' },
    ]);
    assert.equal(result.failures.some((item) => item.code === 'operation-decision-representation-format'), true);
  }
});

test('thin process assembly rejects ambient defaults and unknown commands', () => {
  assert.throws(() => runRepositoryMaterialisationCommand(['validate']), /authority projection path is required/);
  const work = mkdtempSync(join(tmpdir(), 'semantic-assurance-command-'));
  const { authority, plan } = fixture();
  const authorityPath = join(work, 'authority.json');
  const planPath = join(work, 'plan.json');
  writeFileSync(authorityPath, JSON.stringify(authority));
  writeFileSync(planPath, JSON.stringify(plan));
  assert.throws(() => runRepositoryMaterialisationCommand(['unknown', authorityPath, planPath]), /command must be/);
});
