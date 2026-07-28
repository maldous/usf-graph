// The one proof-currentness resolver.
//
// `hasProofResultState successful` is a historical fact about an evaluation that
// happened. It says nothing about whether that evaluation still describes the
// running system: the algorithm may have moved, the implementation bytes it
// exercised may have changed, its evidence may have expired or been superseded,
// or its authority binding may never have been closed. Selecting PROCEED from a
// successful result alone is exactly how a stale proof keeps authorising apply.
//
// This module derives a closed conclusion with three outcomes and nothing else:
//
//   CURRENT                 every required binding is present and agrees
//   STALE_BLOCK             an explicit mismatch, expiry, invalidation or supersession
//   UNRESOLVED_FAIL_CLOSED  missing, ambiguous or incomplete information
//
// It is derived, never asserted: the algorithm declares what current IS, the
// result records what it actually evaluated, and agreement between the two is
// the conclusion. No digest is compiled into this file, and there is no
// `proofCurrent` boolean in the model for anything to read.

export const PROOF_CURRENTNESS = Object.freeze({
  current: 'CURRENT',
  stale: 'STALE_BLOCK',
  unresolved: 'UNRESOLVED_FAIL_CLOSED',
});

export const PROOF_CURRENTNESS_STATE_IRI = Object.freeze({
  [PROOF_CURRENTNESS.current]: 'urn:usf:proofcurrentnessstate:current',
  [PROOF_CURRENTNESS.stale]: 'urn:usf:proofcurrentnessstate:staleblock',
  [PROOF_CURRENTNESS.unresolved]: 'urn:usf:proofcurrentnessstate:unresolvedfailclosed',
});

// Stable reason codes. Every code maps to exactly one factory disposition in
// the gateway's GAP_DISPOSITIONS table.
export const PROOF_CURRENTNESS_CODES = Object.freeze({
  currentnessUnresolved: 'proof-currentness-unresolved',
  currentnessAmbiguous: 'proof-currentness-ambiguous',
  evidenceStale: 'proof-evidence-stale',
  evidenceInvalid: 'proof-evidence-invalid',
  authorityBindingStale: 'proof-authority-binding-stale',
  implementationDigestStale: 'proof-implementation-digest-stale',
  dependencyDigestStale: 'proof-dependency-digest-stale',
  algorithmDigestStale: 'proof-algorithm-digest-stale',
});

const ADMITTED = 'urn:usf:evidenceadmissionstate:admitted';
const FRESH = 'urn:usf:evidencefreshnessstate:fresh';
const INTEGRITY_VALID = 'urn:usf:evidenceintegritystate:valid';
const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
const REEVALUATION_SUCCESSFUL = 'urn:usf:proofreevaluationstate:successful';
const REEVALUATION_PENDING = 'urn:usf:proofreevaluationstate:pending';
const REEVALUATION_FAILED = 'urn:usf:proofreevaluationstate:failed';
const SELF_PUBLICATION_CLOSURE = 'urn:usf:authoritybindingrule:selfpublicationclosure';

const value = (row, key) => row[key]?.value ?? null;
const distinct = (rows, key) => [...new Set(rows.map((row) => value(row, key)).filter((item) => item !== null))];

// Exactly one value, or a typed absence/ambiguity. A second contradictory value
// is never allowed to hide behind a favourable first one.
function sole(rows, key) {
  const values = distinct(rows, key);
  if (values.length === 0) return { state: 'absent', value: null };
  if (values.length > 1) return { state: 'ambiguous', value: null, observed: values.sort() };
  return { state: 'present', value: values[0] };
}

export async function readProofCurrentnessFacts(client, contract) {
  const [resultRows, evidenceRows, algorithmRows, bindingRows] = await Promise.all([
    client.select(`SELECT ?result ?state ?obligation ?proof ?algorithm ?algorithmVersion
        ?algorithmSourceSetDigest ?algorithmVersionSourceSetDigest ?evidenceSetDigest
        ?implementationDigest ?dependencyDigest ?dependencyAlgorithm ?toolchainDigest ?packageLockDigest
        ?producerCommit ?producerTree ?binding ?evidence ?invalidation ?supersession WHERE {
      <${contract}> <urn:usf:ontology:reliesOnProofResult> ?result .
      OPTIONAL { ?result <urn:usf:ontology:hasProofResultState> ?state }
      OPTIONAL { ?result <urn:usf:ontology:proofResultForObligation> ?obligation }
      OPTIONAL { ?result <urn:usf:ontology:resultForProof> ?proof }
      OPTIONAL { ?result <urn:usf:ontology:usesProofAlgorithm> ?algorithm }
      OPTIONAL { ?result <urn:usf:ontology:usesAlgorithmVersion> ?algorithmVersion }
      OPTIONAL { ?result <urn:usf:ontology:algorithmSourceSetDigest> ?algorithmSourceSetDigest }
      OPTIONAL {
        ?result <urn:usf:ontology:usesAlgorithmVersion> ?algorithmVersion .
        ?algorithmVersion <urn:usf:ontology:proofAlgorithmVersionSourceSetDigest> ?algorithmVersionSourceSetDigest
      }
      OPTIONAL { ?result <urn:usf:ontology:evidenceSetDigest> ?evidenceSetDigest }
      OPTIONAL { ?result <urn:usf:ontology:implementationSourceSetDigest> ?implementationDigest }
      OPTIONAL { ?result <urn:usf:ontology:dependencySetDigest> ?dependencyDigest }
      OPTIONAL { ?result <urn:usf:ontology:dependencyDigestAlgorithm> ?dependencyAlgorithm }
      OPTIONAL { ?result <urn:usf:ontology:toolchainDigest> ?toolchainDigest }
      OPTIONAL { ?result <urn:usf:ontology:packageLockDigest> ?packageLockDigest }
      OPTIONAL { ?result <urn:usf:ontology:proofProducerCommit> ?producerCommit }
      OPTIONAL { ?result <urn:usf:ontology:proofProducerTree> ?producerTree }
      OPTIONAL { ?result <urn:usf:ontology:hasAuthorityBinding> ?binding }
      OPTIONAL { ?result <urn:usf:ontology:usesAdmittedEvidence> ?evidence }
      OPTIONAL { ?result <urn:usf:ontology:hasInvalidation> ?invalidation }
      OPTIONAL { ?result <urn:usf:ontology:supersededByProofResult> ?supersession }
    } LIMIT 256`),
    client.select(`SELECT ?evidence ?admission ?freshness ?integrity ?withinScope ?validUntil ?invalidation ?supersession ?contentDigest WHERE {
      <${contract}> <urn:usf:ontology:reliesOnProofResult> ?result .
      ?result <urn:usf:ontology:usesAdmittedEvidence> ?evidence .
      OPTIONAL { ?evidence <urn:usf:ontology:hasAdmissionState> ?admission }
      OPTIONAL { ?evidence <urn:usf:ontology:hasFreshnessState> ?freshness }
      OPTIONAL { ?evidence <urn:usf:ontology:hasIntegrityState> ?integrity }
      OPTIONAL { ?evidence <urn:usf:ontology:withinValidityScope> ?withinScope }
      OPTIONAL { ?evidence <urn:usf:ontology:validUntil> ?validUntil }
      OPTIONAL { ?evidence <urn:usf:ontology:hasInvalidationCondition> ?invalidation }
      OPTIONAL { ?evidence <urn:usf:ontology:supersededByEvidenceResult> ?supersession }
      OPTIONAL { ?evidence <urn:usf:ontology:contentDigest> ?contentDigest }
    } ORDER BY ?evidence LIMIT 256`),
    client.select(`SELECT ?algorithm ?sourceDigest ?currentSourceDigest ?sourceSetDigest ?currentSourceSetDigest
        ?currentVersion ?currentImplementation
        ?currentDependency ?currentDependencyAlgorithm ?currentToolchain ?currentPackageLock ?requiresGraphSource WHERE {
      <${contract}> <urn:usf:ontology:reliesOnProofResult> ?result .
      ?result <urn:usf:ontology:usesProofAlgorithm> ?algorithm .
      OPTIONAL { ?algorithm <urn:usf:ontology:proofAlgorithmSourceDigest> ?sourceDigest }
      OPTIONAL { ?algorithm <urn:usf:ontology:currentAlgorithmSourceDigest> ?currentSourceDigest }
      OPTIONAL { ?algorithm <urn:usf:ontology:proofAlgorithmSourceSetDigest> ?sourceSetDigest }
      OPTIONAL { ?algorithm <urn:usf:ontology:currentAlgorithmSourceSetDigest> ?currentSourceSetDigest }
      OPTIONAL { ?algorithm <urn:usf:ontology:currentAlgorithmVersion> ?currentVersion }
      OPTIONAL { ?algorithm <urn:usf:ontology:currentImplementationSourceSetDigest> ?currentImplementation }
      OPTIONAL { ?algorithm <urn:usf:ontology:currentDependencySetDigest> ?currentDependency }
      OPTIONAL { ?algorithm <urn:usf:ontology:currentDependencyDigestAlgorithm> ?currentDependencyAlgorithm }
      OPTIONAL { ?algorithm <urn:usf:ontology:currentToolchainDigest> ?currentToolchain }
      OPTIONAL { ?algorithm <urn:usf:ontology:currentPackageLockDigest> ?currentPackageLock }
      OPTIONAL { ?algorithm <urn:usf:ontology:requiresGraphSourceBinding> ?requiresGraphSource }
    } LIMIT 64`),
    client.select(`SELECT ?binding ?rule ?requiresReevaluation ?reevaluationState ?settledDigest
        ?reevaluationDependency ?evaluatedDigest ?bindingDependency ?bindingDependencyAlgorithm WHERE {
      <${contract}> <urn:usf:ontology:reliesOnProofResult> ?result .
      ?result <urn:usf:ontology:hasAuthorityBinding> ?binding .
      OPTIONAL { ?binding <urn:usf:ontology:usesAuthorityBindingRule> ?rule }
      OPTIONAL { ?binding <urn:usf:ontology:requiresPostPublicationReevaluation> ?requiresReevaluation }
      OPTIONAL { ?binding <urn:usf:ontology:hasPostPublicationReevaluationState> ?reevaluationState }
      OPTIONAL { ?binding <urn:usf:ontology:reevaluationSettledAuthorityDigest> ?settledDigest }
      OPTIONAL { ?binding <urn:usf:ontology:reevaluationDependencySetDigest> ?reevaluationDependency }
      OPTIONAL { ?binding <urn:usf:ontology:bindingEvaluatedAuthorityDigest> ?evaluatedDigest }
      OPTIONAL { ?binding <urn:usf:ontology:bindingDependencySetDigest> ?bindingDependency }
      OPTIONAL { ?binding <urn:usf:ontology:bindingDependencyDigestAlgorithm> ?bindingDependencyAlgorithm }
    } LIMIT 64`),
  ]);
  return { resultRows, evidenceRows, algorithmRows, bindingRows };
}

/**
 * Derive the currentness conclusion. Pure over already-read facts so it can be
 * exercised without a live client.
 */
export function deriveProofCurrentness(facts, { mandatoryObligations = [], observedAt = null } = {}) {
  const { resultRows, evidenceRows, algorithmRows, bindingRows } = facts;
  const reasons = [];
  const unresolved = (code, detail) => reasons.push({ code, state: PROOF_CURRENTNESS.unresolved, detail });
  const stale = (code, detail) => reasons.push({ code, state: PROOF_CURRENTNESS.stale, detail });

  // Exactly one relied-on proof result.
  const results = distinct(resultRows, 'result');
  if (results.length === 0) {
    unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'contract relies on no proof result');
    return conclude(reasons, {});
  }
  if (results.length > 1) {
    unresolved(PROOF_CURRENTNESS_CODES.currentnessAmbiguous, `contract relies on ${results.length} proof results`);
    return conclude(reasons, { proofResult: null });
  }
  const proofResult = results[0];

  const state = sole(resultRows, 'state');
  if (state.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'proof result state is absent or ambiguous');
  else if (state.value !== SUCCESSFUL) stale(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `proof result state is ${state.value}`);

  // Exact proof-result-to-obligation identity.
  const obligation = sole(resultRows, 'obligation');
  if (obligation.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'proof result names no single obligation');
  else if (mandatoryObligations.length > 0 && !mandatoryObligations.includes(obligation.value)) {
    stale(PROOF_CURRENTNESS_CODES.currentnessAmbiguous, `proof result is for ${obligation.value}, which the contract does not mandate`);
  }
  if (sole(resultRows, 'proof').state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'proof result names no single proof');

  if (distinct(resultRows, 'invalidation').length > 0) stale(PROOF_CURRENTNESS_CODES.evidenceInvalid, 'proof result carries an invalidation');
  if (distinct(resultRows, 'supersession').length > 0) stale(PROOF_CURRENTNESS_CODES.evidenceStale, 'proof result is superseded');

  // Evidence: exactly the admitted set the proof requires, each admitted, fresh,
  // integrity-valid, in scope, unexpired, uninvalidated and unsuperseded.
  const evidence = distinct(resultRows, 'evidence');
  if (evidence.length === 0) unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'proof result uses no admitted evidence');
  const seen = new Set();
  for (const row of evidenceRows) {
    const id = value(row, 'evidence');
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const rows = evidenceRows.filter((item) => value(item, 'evidence') === id);
    const admission = sole(rows, 'admission');
    const freshness = sole(rows, 'freshness');
    const integrity = sole(rows, 'integrity');
    const withinScope = sole(rows, 'withinScope');
    const validUntil = sole(rows, 'validUntil');
    if (admission.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `evidence ${id} has no admission state`);
    else if (admission.value !== ADMITTED) stale(PROOF_CURRENTNESS_CODES.evidenceInvalid, `evidence ${id} is ${admission.value}`);
    if (freshness.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `evidence ${id} has no freshness state`);
    else if (freshness.value !== FRESH) stale(PROOF_CURRENTNESS_CODES.evidenceStale, `evidence ${id} is ${freshness.value}`);
    if (integrity.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `evidence ${id} has no integrity state`);
    else if (integrity.value !== INTEGRITY_VALID) stale(PROOF_CURRENTNESS_CODES.evidenceInvalid, `evidence ${id} integrity is ${integrity.value}`);
    if (withinScope.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `evidence ${id} declares no validity scope`);
    else if (withinScope.value !== 'true') stale(PROOF_CURRENTNESS_CODES.evidenceStale, `evidence ${id} is outside its validity scope`);
    if (validUntil.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `evidence ${id} declares no validity horizon`);
    else if (observedAt && validUntil.value <= observedAt) stale(PROOF_CURRENTNESS_CODES.evidenceStale, `evidence ${id} expired at ${validUntil.value}`);
    if (distinct(rows, 'invalidation').length > 0) stale(PROOF_CURRENTNESS_CODES.evidenceInvalid, `evidence ${id} carries an invalidation condition`);
    if (distinct(rows, 'supersession').length > 0) stale(PROOF_CURRENTNESS_CODES.evidenceStale, `evidence ${id} is superseded`);
  }

  // Algorithm identity and the digests it declares current.
  const algorithm = sole(algorithmRows, 'algorithm');
  if (algorithm.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'proof result names no single algorithm');
  const compare = (declared, observed, code, label) => {
    if (declared.state !== 'present') { unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `algorithm declares no current ${label}`); return; }
    if (observed.state !== 'present') { unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `proof result records no ${label}`); return; }
    if (declared.value !== observed.value) stale(code, `${label}: result ${observed.value} != current ${declared.value}`);
  };
  // A source-set binding supersedes the legacy primary-file binding. The set
  // axis is all-or-nothing: once any participant declares it, the algorithm's
  // authored set, the algorithm's current set, the result's observed set and
  // the exact version's set must all be present and agree. Falling back to the
  // primary file while only one side is missing would make ancillary proof
  // source movement invisible.
  const sourceSetBindings = [
    ['algorithm source-set digest', sole(algorithmRows, 'sourceSetDigest')],
    ['current algorithm source-set digest', sole(algorithmRows, 'currentSourceSetDigest')],
    ['proof-result algorithm source-set digest', sole(resultRows, 'algorithmSourceSetDigest')],
    ['algorithm-version source-set digest', sole(resultRows, 'algorithmVersionSourceSetDigest')],
  ];
  const sourceSetDeclared = sourceSetBindings.some(([, binding]) => binding.state !== 'absent');
  if (sourceSetDeclared) {
    for (const [label, binding] of sourceSetBindings) {
      if (binding.state !== 'present') {
        unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `${label} is absent or ambiguous`);
      }
    }
    const currentSourceSet = sourceSetBindings[1][1];
    if (currentSourceSet.state === 'present') {
      for (const [label, binding] of [sourceSetBindings[0], ...sourceSetBindings.slice(2)]) {
        if (binding.state === 'present' && binding.value !== currentSourceSet.value) {
          stale(
            PROOF_CURRENTNESS_CODES.algorithmDigestStale,
            `${label}: ${binding.value} != current ${currentSourceSet.value}`,
          );
        }
      }
    }
  } else {
    compare(sole(algorithmRows, 'currentSourceDigest'), sole(algorithmRows, 'sourceDigest'),
      PROOF_CURRENTNESS_CODES.algorithmDigestStale, 'algorithm source digest');
  }
  compare(sole(algorithmRows, 'currentVersion'), sole(resultRows, 'algorithmVersion'),
    PROOF_CURRENTNESS_CODES.algorithmDigestStale, 'algorithm version');
  compare(sole(algorithmRows, 'currentImplementation'), sole(resultRows, 'implementationDigest'),
    PROOF_CURRENTNESS_CODES.implementationDigestStale, 'implementation source-set digest');
  compare(sole(algorithmRows, 'currentDependency'), sole(resultRows, 'dependencyDigest'),
    PROOF_CURRENTNESS_CODES.dependencyDigestStale, 'dependency-set digest');
  compare(sole(algorithmRows, 'currentDependencyAlgorithm'), sole(resultRows, 'dependencyAlgorithm'),
    PROOF_CURRENTNESS_CODES.dependencyDigestStale, 'dependency digest algorithm');
  // Toolchain and lock bindings are required only when the algorithm declares
  // one; an algorithm that declares none is not thereby stale.
  for (const [declaredKey, observedKey, label] of [
    ['currentToolchain', 'toolchainDigest', 'toolchain digest'],
    ['currentPackageLock', 'packageLockDigest', 'package-lock digest'],
  ]) {
    const declared = sole(algorithmRows, declaredKey);
    if (declared.state === 'absent') continue;
    compare(declared, sole(resultRows, observedKey), PROOF_CURRENTNESS_CODES.dependencyDigestStale, label);
  }
  if (sole(algorithmRows, 'requiresGraphSource').value === 'true') {
    for (const [key, label] of [['producerCommit', 'producer commit'], ['producerTree', 'producer tree']]) {
      if (sole(resultRows, key).state !== 'present') {
        unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, `proof result records no ${label} though the algorithm requires a graph source binding`);
      }
    }
  }

  if (sole(resultRows, 'evidenceSetDigest').state !== 'present') {
    unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'proof result records no evidence-set digest');
  }

  // Authority binding, including the two-stage self-publication closure. The
  // RESULT must name it: discovering a binding only through the binding query
  // would let a result with no declared binding borrow someone else's.
  const declaredBinding = sole(resultRows, 'binding');
  if (declaredBinding.state !== 'present') {
    unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'proof result names no single authority binding');
  }
  const binding = sole(bindingRows, 'binding');
  if (binding.state !== 'present') {
    unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'proof result has no single authority binding');
  } else {
    const bindingDependency = sole(bindingRows, 'bindingDependency');
    const resultDependency = sole(resultRows, 'dependencyDigest');
    if (bindingDependency.state === 'present' && resultDependency.state === 'present'
      && bindingDependency.value !== resultDependency.value) {
      stale(PROOF_CURRENTNESS_CODES.authorityBindingStale, 'authority binding dependency-set digest differs from the proof result');
    }
    const requiresReevaluation = sole(bindingRows, 'requiresReevaluation');
    const rule = sole(bindingRows, 'rule');
    if (requiresReevaluation.value === 'true') {
      if (rule.value !== SELF_PUBLICATION_CLOSURE) {
        unresolved(PROOF_CURRENTNESS_CODES.currentnessAmbiguous, 'post-publication reevaluation is required under no declared closure rule');
      }
      const reevaluation = sole(bindingRows, 'reevaluationState');
      if (reevaluation.state !== 'present' || reevaluation.value === REEVALUATION_PENDING) {
        // Stage 1 is published but stage 2 has not run. Fail closed: this is
        // absence of a conclusion, not a negative one.
        unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'post-publication reevaluation has not been recorded');
      } else if (reevaluation.value === REEVALUATION_FAILED) {
        stale(PROOF_CURRENTNESS_CODES.authorityBindingStale, 'post-publication reevaluation failed');
      } else if (reevaluation.value !== REEVALUATION_SUCCESSFUL) {
        unresolved(PROOF_CURRENTNESS_CODES.currentnessAmbiguous, `unknown reevaluation state ${reevaluation.value}`);
      } else {
        // A successful reevaluation must actually name what it settled against
        // and must agree with the binding's dependency set.
        const settled = sole(bindingRows, 'settledDigest');
        const reevaluationDependency = sole(bindingRows, 'reevaluationDependency');
        if (settled.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'reevaluation records no settled authority digest');
        if (reevaluationDependency.state !== 'present') unresolved(PROOF_CURRENTNESS_CODES.currentnessUnresolved, 'reevaluation records no dependency-set digest');
        else if (bindingDependency.state === 'present' && reevaluationDependency.value !== bindingDependency.value) {
          stale(PROOF_CURRENTNESS_CODES.authorityBindingStale, 'reevaluation dependency set differs from the bound dependency set');
        }
      }
    }
  }

  return conclude(reasons, {
    proofResult,
    proofResultState: state.value,
    obligation: obligation.value,
    algorithm: algorithm.value,
    algorithmSourceDigest: sole(algorithmRows, 'sourceDigest').value,
    proofAlgorithmSourceSetDigest: sole(algorithmRows, 'sourceSetDigest').value,
    currentAlgorithmSourceSetDigest: sole(algorithmRows, 'currentSourceSetDigest').value,
    algorithmSourceSetDigest: sole(resultRows, 'algorithmSourceSetDigest').value,
    algorithmVersionSourceSetDigest: sole(resultRows, 'algorithmVersionSourceSetDigest').value,
    algorithmVersion: sole(resultRows, 'algorithmVersion').value,
    implementationSourceSetDigest: sole(resultRows, 'implementationDigest').value,
    dependencySetDigest: sole(resultRows, 'dependencyDigest').value,
    evidenceSetDigest: sole(resultRows, 'evidenceSetDigest').value,
    evidence: evidence.sort(),
    authorityBinding: binding.value,
    authorityBindingRule: sole(bindingRows, 'rule').value,
    reevaluationState: sole(bindingRows, 'reevaluationState').value,
    evaluatedAuthorityDigest: sole(bindingRows, 'evaluatedDigest').value,
    settledAuthorityDigest: sole(bindingRows, 'settledDigest').value,
  });
}

// An explicit negative outranks an unproven one; CURRENT is reached only when
// nothing else applies.
function conclude(reasons, facts) {
  const state = reasons.some((reason) => reason.state === PROOF_CURRENTNESS.stale)
    ? PROOF_CURRENTNESS.stale
    : reasons.length > 0
      ? PROOF_CURRENTNESS.unresolved
      : PROOF_CURRENTNESS.current;
  return Object.freeze({
    state,
    stateIri: PROOF_CURRENTNESS_STATE_IRI[state],
    reasons: Object.freeze([...new Set(reasons.map((reason) => reason.code))].sort()),
    reasonDetail: Object.freeze(reasons.map((reason) => Object.freeze({ ...reason }))),
    facts: Object.freeze(facts),
  });
}

export async function proofCurrentnessVerdict(client, contract, options = {}) {
  const facts = await readProofCurrentnessFacts(client, contract);
  return deriveProofCurrentness(facts, options);
}
