import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { sha256 } from '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';
import { createSemanticAuthorityGateway } from './semantic-authority-gateway.mjs';

const authorityDigest = `sha256:${'d'.repeat(64)}`;
const contract = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const decision = 'urn:usf:realisationdecision:repositoryarchitectureandnaming';
const role = 'urn:usf:pathrole:capabilitysource';
const family = 'urn:usf:artefactfamily:capabilitysource';
const format = 'urn:usf:representationformat:ecmascriptmodule2024';
const binding = (value) => ({ value });

function client(expected = authorityDigest) {
  return {
    expectedAuthorityDigest: expected,
    connectivity: async () => 100,
    select: async (sparql) => {
      if (sparql.includes('COUNT(*) AS ?count')) return [{ count: binding('1') }];
      if (sparql.includes('SELECT ?canonicalName ?lifecycle')) return [{ canonicalName: binding('repositoryexternalartefactmaterialisation'), lifecycle: binding('urn:usf:semanticlifecyclestate:active'), activation: binding('urn:usf:contractactivationstate:active'), proof: binding('urn:usf:proofresult:repositorymaterialisationcontrolplane'), proofState: binding('urn:usf:proofresultstate:successful'), decision: binding(decision), decisionState: binding('urn:usf:decisionstate:accepted'), authorisedPath: binding('capabilities') }];
      if (sparql.includes('a <urn:usf:ontology:PathRole>')) return [{ role: binding(role), canonicalName: binding('capabilitysource'), parent: binding('capabilities'), onDemand: binding('true') }];
      if (sparql.includes('a <urn:usf:ontology:ArtefactFamily>')) return [{ family: binding(family), familyName: binding('capabilitysource'), storage: binding('urn:usf:storageclass:gittrackedsource'), pathRole: binding(role), format: binding(format), namingPattern: binding('^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\\.[a-z0-9]+)+$') }];
      throw new Error(`unexpected query: ${sparql}`);
    },
  };
}

const witness = async () => ({ digest: authorityDigest, algorithm: 'sha256-rdfc10-graph-inventory-v2', inventory: [] });

test('assembles live authority context, deterministic planning and validation', async () => {
  const gateway = createSemanticAuthorityGateway({ client: client(), readAuthorityWitness: witness });
  const content = 'export const gateway = true;\n';
  const operation = { action: 'write-file', artefactFamily: family, content, contentDigest: sha256(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/example/gateway.mjs', pathRole: role, representationFormat: format };
  const plan = await gateway.createPlan({ operations: [operation] });
  assert.equal((await gateway.validatePlan(plan)).ok, true);
  assert.equal((await gateway.health()).authorityDigest, authorityDigest);
});

test('requires explicit coordinator authority before apply and writes only after it is supplied', async () => {
  const gateway = createSemanticAuthorityGateway({ client: client(), readAuthorityWitness: witness });
  const content = 'export const gateway = true;\n';
  const plan = await gateway.createPlan({ operations: [{ action: 'write-file', artefactFamily: family, content, contentDigest: sha256(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/example/gateway.mjs', pathRole: role, representationFormat: format }] });
  const root = mkdtempSync(join(tmpdir(), 'semantic-authority-gateway-'));
  await assert.rejects(() => gateway.materialise({ plan, repositoryRoot: root, apply: true }), /coordinator authority/);
  assert.equal((await gateway.materialise({ plan, repositoryRoot: root, apply: true, coordinator: true })).applied, true);
  assert.equal(readFileSync(join(root, 'capabilities/example/gateway.mjs'), 'utf8'), content);
});

test('fails closed on authority drift before planning', async () => {
  const gateway = createSemanticAuthorityGateway({ client: client(`sha256:${'e'.repeat(64)}`), readAuthorityWitness: witness });
  await assert.rejects(() => gateway.createPlan({ operations: [] }), /differs from configured digest/);
});

test('fails closed when a bounded materialisation-rule projection is truncated', async () => {
  const incomplete = client();
  const select = incomplete.select;
  incomplete.select = async (sparql) => sparql.includes('COUNT(*) AS ?count')
    ? [{ count: binding('2') }]
    : select(sparql);
  const gateway = createSemanticAuthorityGateway({ client: incomplete, readAuthorityWitness: witness });
  await assert.rejects(() => gateway.layoutContext(), /rule projection is incomplete/);
});
