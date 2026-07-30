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
  readProofCurrentnessFacts,
} from './proof-currentness.mjs';
import { GAP_DISPOSITIONS, ACTION_STATES } from './repository-materialisation-gateway.mjs';

const REPOSITORY_ROOT = join(import.meta.dirname, '..', '..');
const binding = (value) => ({ value });

const ALGORITHM = 'urn:usf:proofalgorithm:repositorymaterialisationcontrolplane';
const VERSION = 'urn:usf:proofalgorithmversion:current';
const SOURCE = `sha256:${'11'.repeat(32)}`;
const SOURCE_SET = `sha256:${'12'.repeat(32)}`;
const PROVIDER_SOURCE_SET = 'sha256:257d2d196df67927af2458aa46f5e49d0ec013843b1ccf96f249c7bac964fbdf';
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
      algorithmVersionOwner: binding(ALGORITHM),
      algorithmSourceSetDigest: binding(SOURCE_SET),
      algorithmVersionSourceSetDigest: binding(SOURCE_SET),
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
      sourceSetDigest: binding(SOURCE_SET),
      currentSourceSetDigest: binding(SOURCE_SET),
      currentVersion: binding(VERSION),
      currentVersionOwner: binding(ALGORITHM),
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
      evaluatedDigest: binding(`sha256:${'55'.repeat(32)}`),
      bindingDependency: binding(DEPENDENCY),
      bindingDependencyAlgorithm: binding(DEPENDENCY_ALGORITHM),
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

test('a successful result alone does not reach CURRENT after the algorithm source set moves', () => {
  // Everything about the result is successful; only the complete algorithm
  // source set has moved.
  const verdict = derive(mutate('algorithmRows', 0, { currentSourceSetDigest: binding(`sha256:${'ff'.repeat(32)}`) }));
  assert.equal(verdict.facts.proofResultState, 'urn:usf:proofresultstate:successful');
  assert.equal(verdict.state, PROOF_CURRENTNESS.stale);
  assert.ok(verdict.reasons.includes(PROOF_CURRENTNESS_CODES.algorithmDigestStale));
});

test('every explicit mismatch is STALE_BLOCK under its own code', () => {
  const cases = [
    [mutate('algorithmRows', 0, { currentVersion: binding('urn:usf:proofalgorithmversion:other') }), PROOF_CURRENTNESS_CODES.algorithmDigestStale],
    [mutate('algorithmRows', 0, { sourceSetDigest: binding(`sha256:${'a1'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.algorithmDigestStale],
    [mutate('resultRows', 0, { algorithmSourceSetDigest: binding(`sha256:${'a2'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.algorithmDigestStale],
    [mutate('resultRows', 0, { algorithmVersionSourceSetDigest: binding(`sha256:${'a3'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.algorithmDigestStale],
    [mutate('algorithmRows', 0, { currentImplementation: binding(`sha256:${'ab'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.implementationDigestStale],
    [mutate('algorithmRows', 0, { currentDependency: binding(`sha256:${'cd'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.dependencyDigestStale],
    [mutate('algorithmRows', 0, { currentDependencyAlgorithm: binding('sha256-other') }), PROOF_CURRENTNESS_CODES.dependencyDigestStale],
    [mutate('resultRows', 0, { algorithmVersionOwner: binding('urn:usf:proofalgorithm:other') }), PROOF_CURRENTNESS_CODES.algorithmDigestStale],
    [mutate('algorithmRows', 0, { currentVersionOwner: binding('urn:usf:proofalgorithm:other') }), PROOF_CURRENTNESS_CODES.algorithmDigestStale],
    [mutate('algorithmRows', 0, { algorithm: binding('urn:usf:proofalgorithm:other') }), PROOF_CURRENTNESS_CODES.algorithmDigestStale],
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
    [mutate('bindingRows', 0, { bindingDependency: binding(`sha256:${'ed'.repeat(32)}`) }), PROOF_CURRENTNESS_CODES.authorityBindingStale],
    [mutate('bindingRows', 0, { bindingDependencyAlgorithm: binding('sha256-other') }), PROOF_CURRENTNESS_CODES.authorityBindingStale],
    [mutate('bindingRows', 0, { binding: binding('urn:usf:proofauthoritybinding:other') }), PROOF_CURRENTNESS_CODES.authorityBindingStale],
  ];
  for (const [overrides, code] of cases) {
    const verdict = derive(overrides);
    assert.equal(verdict.state, PROOF_CURRENTNESS.stale, `${code} should be STALE_BLOCK: ${JSON.stringify(verdict.reasons)}`);
    assert.ok(verdict.reasons.includes(code), `expected ${code}, saw ${JSON.stringify(verdict.reasons)}`);
  }
});

test('authority binding rule and reevaluation requirement must be explicit and coherent', () => {
  const wrongRule = derive(mutate('bindingRows', 0, {
    rule: binding('urn:usf:authoritybindingrule:other'),
  }));
  assert.equal(wrongRule.state, PROOF_CURRENTNESS.unresolved);
  assert.ok(wrongRule.reasons.includes(PROOF_CURRENTNESS_CODES.currentnessAmbiguous));

  const unknownRequirement = derive(mutate('bindingRows', 0, {
    requiresReevaluation: binding('unknown'),
  }));
  assert.equal(unknownRequirement.state, PROOF_CURRENTNESS.unresolved);
  assert.ok(
    unknownRequirement.reasons.includes(
      PROOF_CURRENTNESS_CODES.currentnessAmbiguous,
    ),
  );
});

test('algorithm versions must be singly owned by the evaluated proof algorithm', () => {
  for (const overrides of [
    mutate('resultRows', 0, {
      algorithmVersionOwner: binding('urn:usf:proofalgorithm:other'),
    }),
    mutate('algorithmRows', 0, {
      currentVersionOwner: binding('urn:usf:proofalgorithm:other'),
    }),
  ]) {
    const verdict = derive(overrides);
    assert.equal(verdict.state, PROOF_CURRENTNESS.stale);
    assert.ok(verdict.reasons.includes(PROOF_CURRENTNESS_CODES.algorithmDigestStale));
  }

  const ambiguous = derive({
    resultRows: [
      ...facts().resultRows,
      {
        ...facts().resultRows[0],
        algorithmVersionOwner: binding('urn:usf:proofalgorithm:other'),
      },
    ],
  });
  assert.equal(ambiguous.state, PROOF_CURRENTNESS.unresolved);
  assert.ok(ambiguous.reasons.includes(PROOF_CURRENTNESS_CODES.currentnessUnresolved));
});

test('fact projection retrieves ownership for both used and current algorithm versions', async () => {
  const queries = [];
  await readProofCurrentnessFacts({
    select: async (query) => {
      queries.push(query);
      return [];
    },
  }, 'urn:usf:semanticcontract:test');
  assert.equal(queries.length, 4);
  assert.match(queries[0], /\?algorithmVersionOwner/u);
  assert.match(
    queries[0],
    /\?algorithmVersion <urn:usf:ontology:proofAlgorithmVersionOf> \?algorithmVersionOwner/u,
  );
  assert.match(queries[2], /\?currentVersionOwner/u);
  assert.match(
    queries[2],
    /\?currentVersion <urn:usf:ontology:proofAlgorithmVersionOf> \?currentVersionOwner/u,
  );
});

test('missing or ambiguous information is UNRESOLVED_FAIL_CLOSED, never CURRENT', () => {
  const cases = [
    without('resultRows', 0, 'state'),
    without('resultRows', 0, 'obligation'),
    without('resultRows', 0, 'proof'),
    without('resultRows', 0, 'algorithm'),
    without('resultRows', 0, 'algorithmVersion'),
    without('resultRows', 0, 'algorithmVersionOwner'),
    without('resultRows', 0, 'evidenceSetDigest'),
    without('resultRows', 0, 'implementationDigest'),
    without('resultRows', 0, 'dependencyDigest'),
    without('resultRows', 0, 'dependencyAlgorithm'),
    without('resultRows', 0, 'binding'),
    without('resultRows', 0, 'evidence'),
    without('resultRows', 0, 'algorithmSourceSetDigest'),
    without('resultRows', 0, 'algorithmVersionSourceSetDigest'),
    without('algorithmRows', 0, 'sourceSetDigest'),
    without('algorithmRows', 0, 'currentSourceSetDigest'),
    without('algorithmRows', 0, 'currentVersion'),
    without('algorithmRows', 0, 'currentVersionOwner'),
    without('algorithmRows', 0, 'currentImplementation'),
    without('algorithmRows', 0, 'currentDependency'),
    without('algorithmRows', 0, 'currentDependencyAlgorithm'),
    without('evidenceRows', 0, 'admission'),
    without('evidenceRows', 0, 'freshness'),
    without('evidenceRows', 0, 'integrity'),
    without('evidenceRows', 0, 'withinScope'),
    without('evidenceRows', 0, 'validUntil'),
    without('bindingRows', 0, 'rule'),
    without('bindingRows', 0, 'requiresReevaluation'),
    without('bindingRows', 0, 'evaluatedDigest'),
    without('bindingRows', 0, 'bindingDependency'),
    without('bindingRows', 0, 'bindingDependencyAlgorithm'),
    { bindingRows: [] },
    { resultRows: [] },
  ];
  for (const overrides of cases) {
    const verdict = derive(overrides);
    assert.equal(
      verdict.state,
      PROOF_CURRENTNESS.unresolved,
      `absence did not fail unresolved: ${JSON.stringify(overrides).slice(0, 90)}`,
    );
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

test('source-set currentness never falls back when only part of the set axis is declared', () => {
  const algorithm = facts().algorithmRows.map((row) => ({ ...row }));
  delete algorithm[0].sourceSetDigest;
  delete algorithm[0].currentSourceSetDigest;
  const result = facts().resultRows.map((row) => ({ ...row }));
  delete result[0].algorithmVersionSourceSetDigest;

  // The result still declares one source-set binding, while the legacy
  // primary-file bindings agree. That is unresolved, never current.
  const verdict = derive({ algorithmRows: algorithm, resultRows: result });
  assert.equal(verdict.state, PROOF_CURRENTNESS.unresolved);
  assert.ok(verdict.reasons.includes(PROOF_CURRENTNESS_CODES.currentnessUnresolved));
});

test('legacy primary-file comparison applies only when no source-set binding exists anywhere', () => {
  const algorithm = facts().algorithmRows.map((row) => ({ ...row }));
  delete algorithm[0].sourceSetDigest;
  delete algorithm[0].currentSourceSetDigest;
  const result = facts().resultRows.map((row) => ({ ...row }));
  delete result[0].algorithmSourceSetDigest;
  delete result[0].algorithmVersionSourceSetDigest;

  assert.equal(derive({ algorithmRows: algorithm, resultRows: result }).state, PROOF_CURRENTNESS.current);
  algorithm[0].currentSourceDigest = binding(`sha256:${'fe'.repeat(32)}`);
  const stale = derive({ algorithmRows: algorithm, resultRows: result });
  assert.equal(stale.state, PROOF_CURRENTNESS.stale);
  assert.ok(stale.reasons.includes(PROOF_CURRENTNESS_CODES.algorithmDigestStale));
});

test('an agreeing complete source set is authoritative over the descriptive primary-file pair', () => {
  const verdict = derive(mutate('algorithmRows', 0, {
    currentSourceDigest: binding(`sha256:${'fd'.repeat(32)}`),
  }));
  assert.equal(verdict.state, PROOF_CURRENTNESS.current);
  assert.equal(verdict.facts.algorithmSourceSetDigest, SOURCE_SET);
});

test('ambiguous source-set values fail closed rather than selecting a favourable binding', () => {
  const resultRows = [
    ...facts().resultRows,
    {
      ...facts().resultRows[0],
      algorithmSourceSetDigest: binding(`sha256:${'fc'.repeat(32)}`),
    },
  ];
  const verdict = derive({ resultRows });
  assert.equal(verdict.state, PROOF_CURRENTNESS.unresolved);
  assert.ok(verdict.reasons.includes(PROOF_CURRENTNESS_CODES.currentnessUnresolved));
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
      rule: binding('urn:usf:authoritybindingrule:directauthoritybinding'),
      requiresReevaluation: binding('false'),
      evaluatedDigest: binding(`sha256:${'55'.repeat(32)}`),
      bindingDependency: binding(DEPENDENCY),
      bindingDependencyAlgorithm: binding(DEPENDENCY_ALGORITHM),
    }],
  });
  assert.equal(notRequired.state, PROOF_CURRENTNESS.current);
});

test('Stage-1 pending remains unresolved through publication and fresh Stage-2 becomes CURRENT', () => {
  const stageOne = facts().bindingRows.map((row) => ({ ...row }));
  stageOne[0].reevaluationState = binding(
    'urn:usf:proofreevaluationstate:pending',
  );
  delete stageOne[0].settledDigest;
  delete stageOne[0].reevaluationDependency;
  const beforePublication = derive({ bindingRows: stageOne });
  assert.equal(beforePublication.state, PROOF_CURRENTNESS.unresolved);

  // Publication moves authority outside this pure resolver. Until a new
  // reevaluation fact is projected, the same bound Stage-1 input must remain
  // unresolved rather than being inferred current from successful proof state.
  const afterPublication = derive({
    bindingRows: stageOne.map((row) => ({ ...row })),
  });
  assert.equal(afterPublication.state, PROOF_CURRENTNESS.unresolved);

  const stageTwo = stageOne.map((row) => ({
    ...row,
    reevaluationState: binding('urn:usf:proofreevaluationstate:successful'),
    settledDigest: binding(`sha256:${'66'.repeat(32)}`),
    reevaluationDependency: binding(DEPENDENCY),
  }));
  const fresh = derive({ bindingRows: stageTwo });
  assert.equal(fresh.state, PROOF_CURRENTNESS.current);
  assert.deepEqual([...fresh.reasons], []);
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

test('semantic source-set vocabulary is functional, constrained and bound by the provider proof', () => {
  const ontology = readFileSync(join(REPOSITORY_ROOT, 'semantic-model/ontology.ttl'), 'utf8');
  const shapes = readFileSync(join(REPOSITORY_ROOT, 'semantic-model/shapes/lifecycle.ttl'), 'utf8');
  const integrity = readFileSync(join(REPOSITORY_ROOT, 'semantic-model/rules/integrity.rq'), 'utf8');
  const proofs = readFileSync(join(REPOSITORY_ROOT, 'semantic-model/assurance/proofs.trig'), 'utf8');
  for (const property of [
    'proofAlgorithmSourceSetDigest',
    'currentAlgorithmSourceSetDigest',
    'algorithmSourceSetDigest',
    'proofAlgorithmVersionSourceSetDigest',
  ]) {
    assert.ok(
      ontology.includes(`usf:${property} a owl:DatatypeProperty, owl:FunctionalProperty;`),
      `${property} must be functional`,
    );
    assert.ok(shapes.includes(`sh:path usf:${property}`), `${property} must have a lifecycle shape`);
    assert.ok(proofs.includes(`usf:${property} "${PROVIDER_SOURCE_SET}"`), `provider proof must bind ${property}`);
  }
  assert.ok(integrity.includes('BIND("proofalgorithmsourcesetbindingincomplete" AS ?violation)'));
  assert.ok(integrity.includes('BIND("proofalgorithmsourcesetbindingmismatch" AS ?violation)'));
});
