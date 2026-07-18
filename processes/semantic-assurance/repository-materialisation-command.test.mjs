import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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
  assert.equal(runRepositoryMaterialisationCommand(['apply', authorityPath, planPath, repository], writer).applied, true);
  assert.equal(readFileSync(join(repository, 'capabilities/example/assembled.mjs'), 'utf8'), 'export const assembled = true;\n');
  assert.match(output, /"applied":true/);
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
