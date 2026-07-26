// Proof currentness is a derived conclusion with exactly three outcomes.
//
// The defect these close: `hasProofResultState successful` selected PROCEED. A
// successful result is a fact about an evaluation that happened, not evidence
// that it still describes the running system.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  PROOF_CURRENTNESS,
  PROOF_CURRENTNESS_CODES,
  PROOF_CURRENTNESS_STATE_IRI,
  deriveProofCurrentness,
} from './proof-currentness.mjs';
import { GAP_DISPOSITIONS, ACTION_STATES } from './repository-materialisation-gateway.mjs';

const REPOSITORY_ROOT = join(import.meta.dirname, '..', '..');
const binding = (value) => ({ value });

const ALGORITHM = 'urn:usf:proofalgorithm:repositorymaterialisationcontrolplane';
const VERSION = 'urn:usf:proofalgorithmversion:current';
const SOURCE = `sha256:${'11'.repeat(32)}`;
const IMPLEMENTATION = `sha256:${'22'.repeat(32)}`;
const DEPENDENCY = `sha256:${'33'.repeat(32)}`;
const DEPENDENCY_ALGORITHM = 'sha256-rdfc10-nonpublication-graph-inventory-v1';
const OBLIGATION = 'urn:usf:proofobligation:repositoryexternalartefactmaterialisation';

function facts(overrides = {}) {
  const base = {
    resultRows: [{
      result: binding('urn:usf:proofresult:repositorymaterialisationcontrolplane'),
      state: binding('urn:usf:proofresultstate:successful'),
      obligation: binding(OBLIGATION),
      proof: binding('urn:usf:proof:repositorymaterialisationcontrolplane'),
      algorithm: binding(ALGORITHM),
      algorithmVersion: binding(VERSION),
      evidenceSetDigest: binding(`sha256:${'44'.repeat(32)}`),
      implementationDigest: binding(IMPLEMENTATION),
      dependencyDigest: binding(DEPENDENCY),
      dependencyAlgorithm: binding(DEPENDENCY_ALGORITHM),
      binding: binding('urn:usf:proofauthoritybinding:repositorymaterialisationcontrolplane'),
      evidence: binding('urn:usf:evidenceresult:repositorymaterialisationcontrolplane'),
    }],
    evidenceRows: [{
      evidence: binding('urn:usf:evidenceresult:repositorymaterialisationcontrolplane'),
      admission: binding('urn:usf:evidenceadmissionstate:admitted'),
      freshness: binding('urn:usf:evidencefreshnessstate:fresh'),
      integrity: binding('urn:usf:evidenceintegritystate:valid'),
      withinScope: binding('true'),
      validUntil: binding('2099-01-01T00:00:00Z'),
    }],
    algorithmRows: [{
      algorithm: binding(ALGORITHM),
      sourceDigest: binding(SOURCE),
      currentSourceDigest: binding(SOURCE),
      currentVersion: binding(VERSION),
      currentImplementation: binding(IMPLEMENTATION),
      currentDependency: binding(DEPENDENCY),
      currentDependencyAlgorithm: binding(DEPENDENCY_ALGORITHM),
    }],
    bindingRows: [{
      binding: binding('urn:usf:proofauthoritybinding:repositorymaterialisationcontrolplane'),
      rule: binding('urn:usf:authoritybindingrule:selfpublicationclosure'),
      requiresReevaluation: binding('true'),
      reevaluationState: binding('urn:usf:proofreevaluationstate:successful'),
      settledDigest: binding(`sha256:${'66'.repeat(32)}`),
      reevaluationDependency: binding(DEPENDENCY),
      bindingDependency: binding(DEPENDENCY),
    }],
  };
  return { ...base, ...overrides };
}

const derive = (overrides, options = {}) => deriveProofCurrentness(facts(overrides), {
  mandatoryObligations: [OBLIGATION],
  observedAt: '2026-07-26T00:00:00Z',
  ...options,
});
const mutate = (key, index, changes) => {
  const rows = facts()[key].map((row) => ({ ...row }));
  rows[index] = { ...rows[index], ...changes };
  return { [key]: rows };
};
const without = (key, index, field) => {
  const rows = facts()[key].map((row) => ({ ...row }));
  delete rows[index][field];
  return { [key]: rows };
};

test('a complete agreeing chain is the only way to reach CURRENT', () => {
  const verdict = derive({});
  assert.equal(verdict.state, PROOF_CURRENTNESS.current);
  assert.deepEqual([...verdict.reasons], []);
  assert.equal(verdict.stateIri, PROOF_CURRENTNESS_STATE_IRI.CURRENT);
  assert.equal(verdict.facts.proofResultState, 'urn:usf:proofresultstate:successful');
});

test('a successful result alone does not reach CURRENT', () => {
  // Everything about the result is successful; only the algorithm has moved.
  const verdict = derive(mutate('algorithmRows', 0, { currentSourceDigest: binding(`sha256:${'ff'.repeat(32)}`) }));
  assert.equal(verdict.facts.proofResultState, 'urn:usf:proofresultstate:successful');
  assert.equal(verdict.state, PROOF_CURRENTNESS.stale);
  assert.ok(verdict.reasons.includes(PROOF_CURRENTNESS_CODES.algorithmDigestStale));
});

test('every explicit mismatch is STALE_BLOCK under its own code', () => {
  const cases = [
    [mutate('algorithmRows', 0, { currentVersion: binding('urn:usf:proofalgorithmversion:other') }), PROOF_CURRENTNESS_CODES.algorithmDigestStale],
    [mutate('algorithmRows', 0, { currentImplementation: binding(`sha256:${'ab'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.implementationDigestStale],
    [mutate('algorithmRows', 0, { currentDependency: binding(`sha256:${'cd'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.dependencyDigestStale],
    [mutate('algorithmRows', 0, { currentDependencyAlgorithm: binding('sha256-other') }), PROOF_CURRENTNESS_CODES.dependencyDigestStale],
    [mutate('evidenceRows', 0, { freshness: binding('urn:usf:evidencefreshnessstate:stale') }), PROOF_CURRENTNESS_CODES.evidenceStale],
    [mutate('evidenceRows', 0, { integrity: binding('urn:usf:evidenceintegritystate:invalid') }), PROOF_CURRENTNESS_CODES.evidenceInvalid],
    [mutate('evidenceRows', 0, { admission: binding('urn:usf:evidenceadmissionstate:rejected') }), PROOF_CURRENTNESS_CODES.evidenceInvalid],
    [mutate('evidenceRows', 0, { withinScope: binding('false') }), PROOF_CURRENTNESS_CODES.evidenceStale],
    [mutate('evidenceRows', 0, { validUntil: binding('2020-01-01T00:00:00Z') }), PROOF_CURRENTNESS_CODES.evidenceStale],
    [mutate('evidenceRows', 0, { invalidation: binding('urn:usf:condition:x') }), PROOF_CURRENTNESS_CODES.evidenceInvalid],
    [mutate('evidenceRows', 0, { supersession: binding('urn:usf:evidenceresult:newer') }), PROOF_CURRENTNESS_CODES.evidenceStale],
    [mutate('resultRows', 0, { supersession: binding('urn:usf:proofresult:newer') }), PROOF_CURRENTNESS_CODES.evidenceStale],
    [mutate('resultRows', 0, { invalidation: binding('urn:usf:condition:y') }), PROOF_CURRENTNESS_CODES.evidenceInvalid],
    [mutate('bindingRows', 0, { reevaluationState: binding('urn:usf:proofreevaluationstate:failed') }), PROOF_CURRENTNESS_CODES.authorityBindingStale],
    [mutate('bindingRows', 0, { reevaluationDependency: binding(`sha256:${'ef'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.authorityBindingStale],
  ];
  for (const [overrides, code] of cases) {
    const verdict = derive(overrides);
    assert.equal(verdict.state, PROOF_CURRENTNESS.stale, `${code} should be STALE_BLOCK: ${JSON.stringify(verdict.reasons)}`);
    assert.ok(verdict.reasons.includes(code), `expected ${code}, saw ${JSON.stringify(verdict.reasons)}`);
  }
});

test('missing or ambiguous information is UNRESOLVED_FAIL_CLOSED, never CURRENT', () => {
  const cases = [
    without('resultRows', 0, 'state'),
    without('resultRows', 0, 'obligation'),
    without('resultRows', 0, 'proof'),
    without('resultRows', 0, 'evidenceSetDigest'),
    without('resultRows', 0, 'implementationDigest'),
    without('resultRows', 0, 'dependencyDigest'),
    without('resultRows', 0, 'binding'),
    without('resultRows', 0, 'evidence'),
    without('algorithmRows', 0, 'currentImplementation'),
    without('algorithmRows', 0, 'currentDependency'),
    without('evidenceRows', 0, 'admission'),
    without('evidenceRows', 0, 'freshness'),
    without('evidenceRows', 0, 'integrity'),
    without('evidenceRows', 0, 'withinScope'),
    without('evidenceRows', 0, 'validUntil'),
    { bindingRows: [] },
    { resultRows: [] },
  ];
  for (const overrides of cases) {
    const verdict = derive(overrides);
    assert.notEqual(verdict.state, PROOF_CURRENTNESS.current, `absence reached CURRENT: ${JSON.stringify(overrides).slice(0, 90)}`);
  }
  // Two contradictory relied-on results are ambiguous, not "the first one".
  const ambiguous = derive({
    resultRows: [
      ...facts().resultRows,
      { ...facts().resultRows[0], result: binding('urn:usf:proofresult:other') },
    ],
  });
  assert.equal(ambiguous.state, PROOF_CURRENTNESS.unresolved);
  assert.ok(ambiguous.reasons.includes(PROOF_CURRENTNESS_CODES.currentnessAmbiguous));
});

test('a pending post-publication reevaluation fails closed rather than blocking', () => {
  // Stage 1 published, stage 2 not yet run: absence of a conclusion, not a
  // negative one. Asserting reevaluation happened is exactly the shortcut the
  // two-stage closure exists to prevent.
  const pending = derive(mutate('bindingRows', 0, { reevaluationState: binding('urn:usf:proofreevaluationstate:pending') }));
  assert.equal(pending.state, PROOF_CURRENTNESS.unresolved);
  assert.ok(pending.reasons.includes(PROOF_CURRENTNESS_CODES.currentnessUnresolved));

  const unrecorded = derive(without('bindingRows', 0, 'reevaluationState'));
  assert.equal(unrecorded.state, PROOF_CURRENTNESS.unresolved);

  // A successful reevaluation that names nothing it settled against is not a
  // conclusion either.
  const unnamed = derive(without('bindingRows', 0, 'settledDigest'));
  assert.equal(unnamed.state, PROOF_CURRENTNESS.unresolved);

  // A binding that does not require reevaluation is current without one.
  const notRequired = derive({
    bindingRows: [{
      binding: binding('urn:usf:proofauthoritybinding:repositorymaterialisationcontrolplane'),
      requiresReevaluation: binding('false'),
      bindingDependency: binding(DEPENDENCY),
    }],
  });
  assert.equal(notRequired.state, PROOF_CURRENTNESS.current);
});

test('a proof for an obligation the contract does not mandate is not current', () => {
  const verdict = derive(mutate('resultRows', 0, { obligation: binding('urn:usf:proofobligation:unrelated') }));
  assert.equal(verdict.state, PROOF_CURRENTNESS.stale);
  assert.ok(verdict.reasons.includes(PROOF_CURRENTNESS_CODES.currentnessAmbiguous));
});

test('every currentness code has exactly one declared factory disposition', () => {
  const expected = {
    [PROOF_CURRENTNESS_CODES.currentnessUnresolved]: ACTION_STATES.unresolved,
    [PROOF_CURRENTNESS_CODES.currentnessAmbiguous]: ACTION_STATES.unresolved,
    [PROOF_CURRENTNESS_CODES.evidenceStale]: ACTION_STATES.block,
    [PROOF_CURRENTNESS_CODES.evidenceInvalid]: ACTION_STATES.block,
    [PROOF_CURRENTNESS_CODES.authorityBindingStale]: ACTION_STATES.block,
    [PROOF_CURRENTNESS_CODES.implementationDigestStale]: ACTION_STATES.block,
    [PROOF_CURRENTNESS_CODES.dependencyDigestStale]: ACTION_STATES.block,
    [PROOF_CURRENTNESS_CODES.algorithmDigestStale]: ACTION_STATES.block,
  };
  for (const [code, disposition] of Object.entries(expected)) {
    assert.equal(GAP_DISPOSITIONS[code], disposition, code);
  }
});

test('no manually asserted proofCurrent boolean exists anywhere in the model or runtime', () => {
  // The conclusion must be derived. A boolean anybody can author would be a
  // second, weaker way to claim currentness.
  for (const path of [
    'semantic-model/ontology.ttl',
    'processes/semantic-assurance/proof-currentness.mjs',
    'processes/semantic-assurance/repository-materialisation-gateway.mjs',
  ]) {
    const source = readFileSync(join(REPOSITORY_ROOT, path), 'utf8');
    assert.equal(/proofCurrent\s*[=:]\s*true/.test(source), false, `${path} asserts proofCurrent`);
    assert.equal(/usf:proofCurrent\b/.test(source), false, `${path} declares a proofCurrent property`);
  }
});

test('no MCP surface can inject a currentness or action state', () => {
  const mcp = readFileSync(join(REPOSITORY_ROOT, 'processes/semantic-assurance/semantic-authority-mcp.mjs'), 'utf8');
  for (const injected of ['currentness', 'proofCurrentness', 'actionState', 'verdict']) {
    assert.equal(
      new RegExp(`args\\.${injected}\\b`).test(mcp),
      false,
      `MCP forwards a caller-supplied ${injected}`,
    );
  }
});
