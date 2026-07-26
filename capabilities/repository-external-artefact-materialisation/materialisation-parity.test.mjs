// Parity between the two materialisation surfaces.
//
// There are two legitimate callers of the materialisation mechanics: the canonical
// gateway (processes/semantic-assurance/repository-materialisation-gateway.mjs),
// which owns the live authority read, the realisation verdict and the witness
// bracketing and is the only production create/validate/dry-run/apply path; and
// this capability module, whose create/validate/apply surface exists solely for the
// materialisation control-plane proof harness that produces
// urn:usf:proofresult:repositorymaterialisationcontrolplane.
//
// Those two must never disagree about what a valid plan is. They previously each
// declared their own path policy and operation validator, so a path one rejected
// the other could accept. These tests assert the mechanics are now shared by
// behaviour, not by counting imports.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  FORBIDDEN_SEGMENTS,
  safeRelativePath,
  validateMaterialisationPlan,
  validatePlanOperation,
  canonicalJson,
  sha256,
} from './materialisation-plan.mjs';
import { validateLayoutPlan } from '../../processes/semantic-assurance/repository-materialisation-gateway.mjs';

const REPOSITORY_ROOT = join(import.meta.dirname, '..', '..');
const GATEWAY = 'processes/semantic-assurance/repository-materialisation-gateway.mjs';
const ENGINE = 'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';

const FAMILY = 'urn:usf:artefactfamily:capabilitysource';
const FORMAT = 'urn:usf:representationformat:ecmascriptmodule2024';
const ROLE = 'urn:usf:pathrole:capabilitysource';
const DIGEST = `sha256:${'a1'.repeat(32)}`;

const context = () => ({
  authorityDigest: DIGEST,
  contract: {
    id: 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation',
    lifecycleState: 'urn:usf:semanticlifecyclestate:active',
    activationState: 'urn:usf:contractactivationstate:active',
    proofResultState: 'urn:usf:proofresultstate:successful',
    decision: 'urn:usf:realisationdecision:repositoryarchitectureandnaming',
    decisionState: 'urn:usf:decisionstate:accepted',
  },
  acceptedDecisionCount: 1,
  authorisedPaths: ['capabilities', '.claude/skills/usf'],
  pathRoles: [{ id: ROLE, canonicalName: 'capabilitysource', parent: 'capabilities', onDemand: true }],
  rules: [{ family: FAMILY, representationFormat: FORMAT, pathRole: ROLE, namingPattern: '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:.[a-z0-9]+)+$' }],
});

// A verdict the gateway will accept, so the only thing under test is the operation
// and path mechanics rather than the live-authority decision the gateway owns.
const verdict = () => ({
  actionState: 'PROCEED',
  actionStateReasons: [],
  stateFailureCode: 'plan-realisation-not-proceed',
  validation: { validationSatisfied: false },
  context: context(),
  witness: { digest: DIGEST, graphCount: 1, triples: 1 },
});

function operation(path, content = 'export default 1;\n') {
  return {
    index: 0,
    action: 'write-file',
    path,
    pathRole: ROLE,
    artefactFamily: FAMILY,
    representationFormat: FORMAT,
    content,
    contentEncoding: 'utf8',
    contentDigest: sha256(Buffer.from(content)),
    fileMode: '0644',
  };
}

function plan(operations) {
  const body = {
    schemaVersion: 1,
    authorityDigest: DIGEST,
    contract: 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation',
    operations,
  };
  return { ...body, planDigest: sha256(canonicalJson(body)) };
}

const codesOf = (result) => [...new Set(result.failures.map((item) => item.code))].sort();

// Paths that must be judged identically by both surfaces. The forbidden set is the
// authority-declared prohibitedCanonicalToken list plus the structural `usf` rule.
const PATH_CASES = [
  ['capabilities/example/assembled.mjs', true],
  ['capabilities/legacy/example.mjs', false],
  ['capabilities/v2/example.mjs', false],
  ['capabilities/temporary/example.mjs', false],
  ['capabilities/migration/example.mjs', false],
  ['capabilities/replacement/example.mjs', false],
  ['capabilities/bootstrap/example.mjs', false],
  ['capabilities/utils/example.mjs', false],
  ['capabilities/shared/example.mjs', false],
  ['capabilities/usf/example.mjs', false],
  ['capabilities/wave-one/example.mjs', false],
  ['capabilities/usf-3/example.mjs', false],
];

test('one path policy governs both materialisation surfaces', async () => {
  for (const [path, portable] of PATH_CASES) {
    const accepted = (() => {
      try { safeRelativePath(path); return true; } catch { return false; }
    })();
    assert.equal(accepted, portable, `shared policy disagreed for ${path}`);

    const candidate = plan([operation(path)]);
    const engineResult = validateMaterialisationPlan(context(), candidate);
    const gatewayResult = await validateLayoutPlan({}, candidate, verdict());
    // Both surfaces must reach the same verdict on the same bytes.
    assert.equal(
      engineResult.failures.some((item) => item.code === 'operation-path'),
      !portable,
      `engine path verdict wrong for ${path}`,
    );
    assert.equal(
      gatewayResult.failures.some((item) => item.code === 'operation-path'),
      !portable,
      `gateway path verdict wrong for ${path}`,
    );
    assert.equal(engineResult.ok, gatewayResult.ok, `surfaces disagreed on ${path}`);
  }
});

test('the forbidden-segment set is exactly the authority-declared vocabulary plus the structural usf rule', () => {
  // Kept explicit so a silent widening or narrowing of the policy fails here
  // rather than showing up as an accepted unauthorised path.
  assert.deepEqual([...FORBIDDEN_SEGMENTS].sort(), [
    'bootstrap', 'common', 'core', 'executable-suite', 'helpers', 'initial-suite',
    'legacy', 'migration', 'misc', 'reference-kernel', 'replacement', 'shared',
    'temporary', 'transitional', 'usf', 'utils', 'v2',
  ]);
  // The agent-skill directories are the one authorised `usf` exception.
  assert.equal(safeRelativePath('.claude/skills/usf/SKILL.md'), '.claude/skills/usf/SKILL.md');
  assert.equal(safeRelativePath('.codex/skills/usf/SKILL.md'), '.codex/skills/usf/SKILL.md');
  assert.throws(() => safeRelativePath('capabilities/usf/x.mjs'), /forbidden durable identity/);
});

test('one operation schema governs both surfaces', async () => {
  // A malformed operation must produce the same code set from either surface.
  const malformed = [
    { ...operation('capabilities/example/assembled.mjs'), action: 'chmod-path' },
  ];
  const candidate = plan(malformed);
  const engineResult = validateMaterialisationPlan(context(), candidate);
  const gatewayResult = await validateLayoutPlan({}, candidate, verdict());
  assert.ok(codesOf(engineResult).includes('operation-action'));
  assert.deepEqual(codesOf(gatewayResult), codesOf(engineResult));

  const unauthorisedRepresentation = plan([
    { ...operation('capabilities/example/assembled.mjs'), representationFormat: 'urn:usf:representationformat:sqltext' },
  ]);
  const engineRepresentation = validateMaterialisationPlan(context(), unauthorisedRepresentation);
  const gatewayRepresentation = await validateLayoutPlan({}, unauthorisedRepresentation, verdict());
  assert.ok(codesOf(engineRepresentation).includes('operation-write-representation'));
  assert.deepEqual(codesOf(gatewayRepresentation), codesOf(engineRepresentation));
});

test('a well-formed plan is accepted identically by both surfaces', async () => {
  const candidate = plan([operation('capabilities/example/assembled.mjs')]);
  const engineResult = validateMaterialisationPlan(context(), candidate);
  const gatewayResult = await validateLayoutPlan({}, candidate, verdict());
  assert.deepEqual(engineResult.failures, []);
  assert.deepEqual(gatewayResult.failures, []);
  assert.equal(engineResult.expectedPlanDigest, gatewayResult.expectedPlanDigest);
  assert.equal(engineResult.operationCount, gatewayResult.operationCount);
});

test('the gateway declares no private copy of the shared mechanics', () => {
  const source = readFileSync(join(REPOSITORY_ROOT, GATEWAY), 'utf8');
  for (const helper of ['safeRelativePath', 'inside', 'containedBy', 'treeEntries', 'decisionAuthorisesPath', 'assertNoSymlinkSegments']) {
    assert.equal(
      new RegExp(`^function ${helper}\\b`, 'm').test(source),
      false,
      `${GATEWAY} still declares its own ${helper}`,
    );
  }
  assert.match(source, /from '\.\.\/\.\.\/capabilities\/repository-external-artefact-materialisation\/materialisation-plan\.mjs'/);
});

test('the validation-only command shares the same validator and can never apply', () => {
  const source = readFileSync(join(REPOSITORY_ROOT, 'processes/semantic-assurance/repository-materialisation-command.mjs'), 'utf8');
  // Same validator as the proof engine, and no apply capability anywhere in it.
  assert.match(source, /validateMaterialisationPlan/);
  assert.equal(/\bmaterialisePlan\b/.test(source), false, 'the command must not reference the apply capability');
  assert.equal(/\bapplyLayoutPlan\b/.test(source), false, 'the command must not reference the gateway apply');
  // The engine keeps its apply surface for the control-plane proof only.
  const engineSource = readFileSync(join(REPOSITORY_ROOT, ENGINE), 'utf8');
  assert.match(engineSource, /^export function materialisePlan\b/m);
});
