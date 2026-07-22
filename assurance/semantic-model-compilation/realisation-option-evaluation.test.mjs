import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { DataFactory, Parser, Store } from 'n3';

import {
  canonicalJson,
  evaluateRealisationOptionClosure,
  evaluationInternals,
  GATE_COUNTER_NAMES,
  REASON_COUNTER,
  REASON_PRECEDENCE,
  loadSemanticStore,
  realisationOptionShaclFocusRoots,
  runRealisationOptionClosure,
  sha256,
} from './realisation-option-evaluation.mjs';

const { literal, quad } = DataFactory;
const {
  RDF_TYPE, term, iri, objects, subjects, validateEvidenceContext, validateRawAcquisition,
  expectedSupportingManifests,
} = evaluationInternals;
const root = resolve(process.env.USF_TEST_REPOSITORY_ROOT || process.cwd());
const baseline = loadSemanticStore(root).store;
const decision = iri('urn:usf:realisationdecision:semanticmodelcompilationrealisation');
const architectureDecision = iri('urn:usf:realisationdecision:repositoryarchitectureandnaming');
const evaluation = iri('urn:usf:decisionevaluation:semanticmodelcompilationrealisation');
const selected = iri('urn:usf:realisationoption:nodeecmascriptsemanticmodelcompiler');
const alternative = iri('urn:usf:realisationoption:javardfsemanticmodelcompiler');
const authorityDecision = iri('urn:usf:realisationdecision:semanticauthoritycontrolselection');
const authorityEvaluation = iri('urn:usf:decisionevaluation:semanticauthoritycontrolselection');
const authoritySelected = iri('urn:usf:realisationoption:livestardogwithverifiedreadonlyexport');
const expectedWitness = {
  authorityDigest: objects(baseline, evaluation, term('evaluationAuthorityDigest'))[0]?.value,
  signerFingerprint: objects(baseline, iri('urn:usf:signingidentity:realisationoptionevaluationintegrity'), term('signingKeyFingerprint'))[0]?.value,
};
const baselineContext = validateEvidenceContext(root, baseline, '/var/lib/usf-cas', expectedWitness);

const baselineQuads = baseline.getQuads(null, null, null, null);
const clone = () => new Store(baselineQuads);
const cloneContext = () => ({
  ...baselineContext,
  payload: structuredClone(baselineContext.payload),
  assessmentRecords: new Map([...baselineContext.assessmentRecords].map(([key, value]) => [key, structuredClone(value)])),
  componentObservations: new Map([...baselineContext.componentObservations].map(([key, value]) => [key, structuredClone(value)])),
  failures: [...baselineContext.failures],
});
const remove = (store, subject, predicate, object = null) => store.removeQuads(store.getQuads(subject, predicate, object, null));
const add = (store, subject, predicate, object) => store.addQuad(quad(subject, predicate, object));
const replaceLiteral = (store, subject, predicate, value) => { remove(store, subject, predicate); add(store, subject, predicate, literal(value)); };
const first = (store, subject, predicate) => objects(store, subject, predicate)[0];
const mutationReasons = new Set();

const readCasJson = (digest) => {
  const hex = digest.slice(7);
  return JSON.parse(readFileSync(join('/var/lib/usf-cas', 'sha256', hex.slice(0, 2), hex)));
};

function resealAcquisition(acquisition, payload) {
  for (const manifest of acquisition.manifests) {
    const observationDigest = sha256(canonicalJson(manifest.observations));
    manifest.descriptorDigest = sha256(canonicalJson({
      authorityDigest: manifest.authorityDigest,
      collectedAt: manifest.collectedAt,
      collectorDigest: manifest.collectorDigest,
      observationDigest,
      scope: manifest.scope,
      validUntil: manifest.validUntil,
    }));
    delete manifest.manifestDigest;
    manifest.manifestDigest = sha256(canonicalJson(manifest));
  }
  acquisition.manifests.sort((left, right) => Buffer.compare(Buffer.from(left.scope), Buffer.from(right.scope)));
  acquisition.acquisitionSetDigest = sha256(canonicalJson(acquisition.manifests.map((manifest) => ({
    scope: manifest.scope,
    digest: manifest.manifestDigest,
    collectorDigest: manifest.collectorDigest,
    descriptorDigest: manifest.descriptorDigest,
    collectedAt: manifest.collectedAt,
    validUntil: manifest.validUntil,
  }))));
  payload.acquisitionSetDigest = acquisition.acquisitionSetDigest;
  const derived = payload.supportingEvidenceManifests.filter(({ scope }) => scope === 'DETERMINISTIC_EVALUATION');
  payload.supportingEvidenceManifests = [...expectedSupportingManifests(acquisition), ...derived]
    .sort((left, right) => Buffer.compare(Buffer.from(left.identity), Buffer.from(right.identity)));
}

function updateObservation(store, context, identity, update) {
  const current = structuredClone(context.componentObservations.get(identity.value));
  assert.ok(current, `missing component observation for ${identity.value}`);
  delete current.observationDigest;
  update(current);
  current.observationDigest = sha256(canonicalJson(current));
  context.componentObservations.set(identity.value, current);
  context.payload.componentObservations[identity.value] = structuredClone(current);
  replaceLiteral(store, identity, term('componentObservationDigest'), current.observationDigest);
}

function copyResource(store, source, target) {
  for (const item of store.getQuads(source, null, null, null)) add(store, target, item.predicate, item.object);
}

function componentAssessment(store, component, criterionSuffix = 'semanticcontractfit') {
  return subjects(store, term('assessmentForComponent'), component).find((assessment) =>
    first(store, assessment, term('assessmentForCriterion'))?.value.endsWith(criterionSuffix));
}

function setAssessmentResult(store, context, assessment, resultName) {
  const assessmentEvaluation = first(store, assessment, term('assessmentForEvaluation'));
  const option = first(store, assessment, term('assessmentForOption'));
  const component = first(store, assessment, term('assessmentForComponent'));
  const criterion = first(store, assessment, term('assessmentForCriterion'));
  const key = [component ? 'COMPONENT' : 'OPTION', first(store, assessmentEvaluation, term('canonicalName')).value,
    first(store, option, term('canonicalName')).value, component ? first(store, component, term('canonicalName')).value : '',
    first(store, criterion, term('canonicalName')).value].join('|');
  const record = { ...context.assessmentRecords.get(key), result: resultName };
  record.supportDigest = sha256(canonicalJson({
    scope: record.scope, decision: record.decision, option: record.option, component: record.component,
    criterion: record.criterion, result: record.result, method: record.method,
    supportingManifests: record.supportingManifests,
    authorityDigest: context.authorityDigest, implementationSourceDigest: context.implementationSourceDigest,
  }));
  context.assessmentRecords.set(key, record);
  remove(store, assessment, term('assessmentResult'));
  add(store, assessment, term('assessmentResult'), iri(`urn:usf:assessmentresult:${resultName}`));
  replaceLiteral(store, first(store, assessment, term('hasCriterionEvidenceBinding')), term('bindingSupportDigest'), record.supportDigest);
}

function synchroniseComponentAssessmentResponsibilities(store, context, option, component) {
  const responsibilities = objects(store, option, term('hasComponentResponsibility'))
    .filter((item) => objects(store, item, term('responsibilityForComponent')).some(({ value }) => value === component.value))
    .map(({ value }) => value).sort();
  for (const assessment of subjects(store, term('assessmentForComponent'), component)) {
    remove(store, assessment, term('assessmentForResponsibility'));
    for (const responsibility of responsibilities) add(store, assessment, term('assessmentForResponsibility'), iri(responsibility));
    const assessmentEvaluation = first(store, assessment, term('assessmentForEvaluation'));
    const criterion = first(store, assessment, term('assessmentForCriterion'));
    const key = ['COMPONENT', first(store, assessmentEvaluation, term('canonicalName')).value,
      first(store, option, term('canonicalName')).value, first(store, component, term('canonicalName')).value,
      first(store, criterion, term('canonicalName')).value].join('|');
    context.assessmentRecords.set(key, { ...context.assessmentRecords.get(key), responsibilities });
  }
}

function synchroniseCompositionProof(store, context, decisionResource, evaluationResource, option) {
  const contract = first(store, decisionResource, term('decisionForContract'));
  const components = objects(store, option, term('hasOptionComponent'));
  const composition = evaluationInternals.recomputeComposition(
    store, decisionResource, evaluationResource, option, contract, components, context,
  );
  const decisionName = first(store, decisionResource, term('canonicalName')).value;
  context.payload.compositionProofs[decisionName] = { ...composition.proofCore, proofDigest: composition.proofDigest };
  const proof = first(store, option, term('hasCompositionCoverageProof'));
  replaceLiteral(store, proof, term('compositionProjectionDigest'), composition.compositionProjectionDigest);
  replaceLiteral(store, proof, term('compositionProofDigest'), composition.proofDigest);
}

function assertRejected(expected, mutate, mutateContext = () => {}) {
  mutationReasons.add(expected);
  const store = clone();
  const context = cloneContext();
  mutate(store, context);
  mutateContext(context, store);
  const result = evaluateRealisationOptionClosure(store, context);
  assert.equal(result.ok, false);
  assert.equal(result.findings[0]?.reasonCode, expected, JSON.stringify(result.findings.slice(0, 8)));
  assert.ok(result.gateCounters[REASON_COUNTER[expected]] > 0, `${expected} did not increment ${REASON_COUNTER[expected]}`);
  const affected = result.findings.find(({ reasonCode }) => reasonCode === expected)?.decision;
  if (affected) assert.equal(result.closureStates.find(({ decision: item }) => item === affected)?.state, 'INCOMPLETE');
}

const ZERO_DIGEST = `sha256:${'0'.repeat(64)}`;
const applyEvaluationDependencyDrift = (store) => replaceLiteral(store, evaluation, term('evaluationDependencySetDigest'), ZERO_DIGEST);
const applyFakeCredibleCandidate = (store) => {
  const fake = iri('urn:usf:realisationoption:unsupporteddecoy');
  const credibility = iri('urn:usf:candidatecredibilityassessment:unsupporteddecoy');
  add(store, decision, term('considersOption'), fake);
  add(store, evaluation, term('hasCandidateCredibilityAssessment'), credibility);
  add(store, credibility, RDF_TYPE, term('CandidateCredibilityAssessment'));
  add(store, credibility, term('credibilityForOption'), fake);
  add(store, credibility, term('credibilityState'), iri('urn:usf:candidatecredibilitystate:credible'));
  add(store, credibility, term('credibilityEvidence'), iri('urn:usf:evidenceresult:realisationoptionevaluation'));
};
const evaluateWith = (...mutators) => {
  const store = clone();
  const context = cloneContext();
  for (const mutate of mutators) mutate(store);
  return evaluateRealisationOptionClosure(store, context);
};

test('current candidate closes every required zero counter deterministically', () => {
  assert.equal(baselineContext.ok, true, JSON.stringify(baselineContext.failures));
  const firstRun = runRealisationOptionClosure(root, '/var/lib/usf-cas', expectedWitness);
  const secondRun = runRealisationOptionClosure(root, '/var/lib/usf-cas', expectedWitness);
  assert.deepEqual(secondRun, firstRun);
  assert.equal(firstRun.ok, true, JSON.stringify(firstRun.findings));
  assert.deepEqual(Object.keys(firstRun.gateCounters).sort(), [...GATE_COUNTER_NAMES].sort());
  assert.ok(Object.values(firstRun.gateCounters).every((value) => value === 0));
  assert.equal(firstRun.acceptedDecisionCount, 3);
  assert.equal(firstRun.criterionCount, 31);
  const focusRoots = realisationOptionShaclFocusRoots(baseline);
  assert.equal(new Set(focusRoots).size, focusRoots.length);
  assert.ok(focusRoots.length >= 325);
  for (const evaluationResource of objects(baseline, decision, term('hasDecisionEvaluation'))) {
    for (const requirement of objects(baseline, evaluationResource, term('hasCriterionRequirement'))) assert.ok(focusRoots.includes(requirement.value));
  }
  for (const contract of objects(baseline, decision, term('decisionForContract'))) assert.ok(focusRoots.includes(contract.value));
  for (const component of objects(baseline, selected, term('hasOptionComponent'))) {
    assert.ok(focusRoots.includes(component.value));
    for (const identity of objects(baseline, component, term('componentIdentity'))) assert.ok(focusRoots.includes(identity.value));
  }
});

test('raw acquisition and composite scope contracts reject exact structural defects', () => {
  assert.equal(baselineContext.ok, true, JSON.stringify(baselineContext.failures));
  const collectorDigest = baselineContext.payload.sourceRecords.find(({ path }) => path === 'assurance/semantic-model-compilation/realisation-option-acquisition.mjs').digest;
  const original = readCasJson(baselineContext.payload.acquisitionInputDigest);
  const validate = (mutateAcquisition = () => {}, mutatePayload = () => {}) => {
    const acquisition = structuredClone(original);
    const payload = structuredClone(baselineContext.payload);
    mutateAcquisition(acquisition);
    resealAcquisition(acquisition, payload);
    mutatePayload(payload);
    return validateRawAcquisition(acquisition, payload, collectorDigest, '/var/lib/usf-cas');
  };
  assert.equal(validate(), true);
  assert.equal(validate((acquisition) => acquisition.manifests.pop()), false, 'missing acquisition scope accepted');
  assert.equal(validate((acquisition) => {
    acquisition.manifests.find(({ scope }) => scope === 'HERMETIC_LOCAL_RAW').observations.undeclaredProviderDatum = 'prohibited';
  }), false, 'undeclared raw field accepted');
  assert.equal(validate((acquisition) => {
    const metadata = acquisition.manifests.find(({ scope }) => scope === 'DECLARED_PROVIDER_METADATA_RAW').observations.stardog;
    metadata.version = '12.1.1';
  }), false, 'stale nested provider metadata digest accepted');
  assert.equal(validate(() => {}, (payload) => {
    [payload.supportingEvidenceManifests[0].identity, payload.supportingEvidenceManifests[1].identity]
      = [payload.supportingEvidenceManifests[1].identity, payload.supportingEvidenceManifests[0].identity];
  }), false, 'cross-scope manifest identity substitution accepted');

  const flattened = clone();
  add(flattened, iri('urn:usf:evidenceresult:realisationoptionevaluation'), term('usesProviderMode'), iri('urn:usf:providermode:deterministictestsubstitute'));
  const flattenedContext = validateEvidenceContext(root, flattened, '/var/lib/usf-cas', expectedWitness);
  assert.equal(flattenedContext.ok, false);
  assert.ok(flattenedContext.failures.includes('EVIDENCE_SCOPE_OR_ACQUISITION_BINDING_INVALID'));
});

test('decision and dependency defects reach exact precedence branches', () => {
  assertRejected('ACTIVE_CONTRACT_SELECTION_EVALUATION_MISSING', (store) => {
    const contract = iri('urn:usf:semanticcontract:unevaluatedselection');
    add(store, contract, RDF_TYPE, term('SemanticContract'));
    add(store, contract, term('requiresRealisationOptionEvaluation'), literal('true'));
    add(store, contract, term('hasActivationState'), iri('urn:usf:contractactivationstate:active'));
  });
  assertRejected('DECISION_STATE_CARDINALITY', (store) => add(store, decision, term('decisionState'), iri('urn:usf:decisionstate:reopened')));
  assertRejected('DECISION_CONTRACT_CARDINALITY', (store) => remove(store, decision, term('decisionForContract')));
  assertRejected('DECISION_EVALUATION_CARDINALITY', (store) => remove(store, decision, term('hasDecisionEvaluation')));
  assertRejected('EVALUATION_DEPENDENCY_DRIFT', (store) => replaceLiteral(store, evaluation, term('evaluationDependencySetDigest'), `sha256:${'0'.repeat(64)}`));
});

test('dual dependency-drift and fake-candidate defects keep EVALUATION_DEPENDENCY_DRIFT first and increment both counters', () => {
  const result = evaluateWith(applyEvaluationDependencyDrift, applyFakeCredibleCandidate);
  assert.equal(result.ok, false);
  const affected = result.findings.filter(({ decision: item }) => item === decision.value).map(({ reasonCode }) => reasonCode);
  assert.ok(affected.includes('EVALUATION_DEPENDENCY_DRIFT'), JSON.stringify(result.findings.slice(0, 8)));
  assert.ok(affected.includes('FAKE_OR_DUPLICATE_CREDIBLE_CANDIDATE'), JSON.stringify(result.findings.slice(0, 8)));
  assert.ok(affected.indexOf('EVALUATION_DEPENDENCY_DRIFT') < affected.indexOf('FAKE_OR_DUPLICATE_CREDIBLE_CANDIDATE'),
    JSON.stringify(result.findings.slice(0, 8)));
  assert.equal(result.findings[0].reasonCode, 'EVALUATION_DEPENDENCY_DRIFT', JSON.stringify(result.findings.slice(0, 8)));
  assert.ok(result.gateCounters[REASON_COUNTER.EVALUATION_DEPENDENCY_DRIFT] > 0, 'dependency-drift counter did not increment');
  assert.ok(result.gateCounters[REASON_COUNTER.FAKE_OR_DUPLICATE_CREDIBLE_CANDIDATE] > 0, 'credible-candidate counter did not increment');
  const repeat = evaluateWith(applyEvaluationDependencyDrift, applyFakeCredibleCandidate);
  assert.deepEqual(repeat, result);
});

test('isolated dependency drift and the dual defect are order-independent and non-leaking', () => {
  const isolatedForward = evaluateWith(applyEvaluationDependencyDrift);
  const dualForward = evaluateWith(applyEvaluationDependencyDrift, applyFakeCredibleCandidate);
  const dualReverse = evaluateWith(applyEvaluationDependencyDrift, applyFakeCredibleCandidate);
  const isolatedReverse = evaluateWith(applyEvaluationDependencyDrift);
  assert.deepEqual(isolatedReverse, isolatedForward);
  assert.deepEqual(dualReverse, dualForward);
  assert.equal(isolatedForward.findings[0].reasonCode, 'EVALUATION_DEPENDENCY_DRIFT', JSON.stringify(isolatedForward.findings.slice(0, 8)));
  assert.ok(!isolatedForward.findings.some(({ reasonCode }) => reasonCode === 'FAKE_OR_DUPLICATE_CREDIBLE_CANDIDATE'),
    JSON.stringify(isolatedForward.findings.slice(0, 8)));
  const baselineRerun = runRealisationOptionClosure(root, '/var/lib/usf-cas', expectedWitness);
  assert.equal(baselineRerun.ok, true, JSON.stringify(baselineRerun.findings));
});

test('candidate-set defects reach exact precedence branches', () => {
  assertRejected('INCOMPLETE_CANDIDATE_SET', (store) => {
    for (const option of objects(store, decision, term('considersOption')).filter(({ value }) => value !== selected.value)) remove(store, decision, term('considersOption'), option);
    for (const record of objects(store, evaluation, term('hasCandidateCredibilityAssessment')).filter((item) => first(store, item, term('credibilityForOption')).value !== selected.value)) remove(store, evaluation, term('hasCandidateCredibilityAssessment'), record);
  });
  assertRejected('FAKE_OR_DUPLICATE_CREDIBLE_CANDIDATE', (store) => {
    const fake = iri('urn:usf:realisationoption:unsupporteddecoy');
    const credibility = iri('urn:usf:candidatecredibilityassessment:unsupporteddecoy');
    add(store, decision, term('considersOption'), fake);
    add(store, evaluation, term('hasCandidateCredibilityAssessment'), credibility);
    add(store, credibility, RDF_TYPE, term('CandidateCredibilityAssessment'));
    add(store, credibility, term('credibilityForOption'), fake);
    add(store, credibility, term('credibilityState'), iri('urn:usf:candidatecredibilitystate:credible'));
    add(store, credibility, term('credibilityEvidence'), iri('urn:usf:evidenceresult:realisationoptionevaluation'));
  });
  assertRejected('MISSING_SELECTED_OPTION', (store) => remove(store, decision, term('selectsOption')));
  assertRejected('MULTIPLE_SELECTED_OPTIONS', (store) => add(store, decision, term('selectsOption'), alternative));
  assertRejected('SELECTED_OPTION_OUTSIDE_CANDIDATE_SET', (store) => remove(store, decision, term('considersOption'), selected));
});

test('criterion, evidence and mitigation defects reach exact precedence branches', () => {
  const requirement = objects(baseline, evaluation, term('hasCriterionRequirement')).find((item) => first(baseline, item, term('requiresCriterion')).value.endsWith('semanticcontractfit'));
  const criterion = first(baseline, requirement, term('requiresCriterion'));
  const assessment = subjects(baseline, term('assessmentForEvaluation'), evaluation).find((item) =>
    objects(baseline, item, term('assessmentForOption')).some(({ value }) => value === selected.value)
    && objects(baseline, item, term('assessmentForCriterion')).some(({ value }) => value === criterion.value)
    && objects(baseline, item, term('assessmentForComponent')).length === 0);
  assertRejected('MISSING_APPLICABLE_CRITERION', (store) => remove(store, evaluation, term('hasCriterionRequirement'), requirement));
  assertRejected('MISSING_CANDIDATE_CRITERION_ASSESSMENT', (store) => remove(store, assessment, term('assessmentForEvaluation')));
  assertRejected('ASSESSMENT_EVIDENCE_INVALID', (store) => remove(store, assessment, term('assessmentEvidence')));
  assertRejected('ASSESSMENT_EVIDENCE_INVALID', (store) => {
    const binding = first(store, assessment, term('hasCriterionEvidenceBinding'));
    remove(store, binding, term('bindingSupportingManifest'));
  });
  assertRejected('ASSESSMENT_EVIDENCE_INVALID', (store) => {
    const binding = first(store, assessment, term('hasCriterionEvidenceBinding'));
    remove(store, binding, term('bindingSupportingManifest'));
    add(store, binding, term('bindingSupportingManifest'), iri('urn:usf:evidencescopemanifest:realisationoptionevaluationexternalstatic'));
  });
  assertRejected('ASSESSMENT_EVIDENCE_INVALID', (store) => {
    const binding = first(store, assessment, term('hasCriterionEvidenceBinding'));
    remove(store, binding, term('bindingSupportDigest'));
  });
  assertRejected('ASSESSMENT_EVIDENCE_INVALID', (store) => {
    const binding = first(store, assessment, term('hasCriterionEvidenceBinding'));
    const manifest = first(store, binding, term('bindingSupportingManifest'));
    add(store, manifest, term('scopeProhibitsCriterion'), criterion);
  });
  assertRejected('UNJUSTIFIED_NOT_APPLICABLE_CRITERION', (store) => {
    remove(store, requirement, term('criterionApplicability'));
    add(store, requirement, term('criterionApplicability'), iri('urn:usf:criterionapplicability:notapplicable'));
    remove(store, requirement, term('applicabilityJustification'));
  });
  assertRejected('MANDATORY_CRITERION_NOT_CLOSED', (store, context) => {
    setAssessmentResult(store, context, assessment, 'partiallysatisfies');
  });
});

test('selection rejection defects reach exact precedence branches', () => {
  const rejection = objects(baseline, evaluation, term('hasOptionRejection')).find((item) => objects(baseline, item, term('rejectsOption')).some(({ value }) => value === alternative.value));
  const reason = first(baseline, rejection, term('hasRejectionReason'));
  assertRejected('REJECTED_CANDIDATE_REASON_MISSING', (store) => remove(store, rejection, term('hasRejectionReason')));
  assertRejected('REJECTION_REASON_EVIDENCE_MISSING', (store) => remove(store, reason, term('rejectionEvidence')));
  assertRejected('LEGACY_SELECTION_WITHOUT_INDEPENDENT_BASIS', (store) => remove(store, evaluation, term('independentSelectionBasis')));
});

test('package integrity defects reach exact precedence branches', () => {
  const identity = iri('urn:usf:componentidentity:nodejsruntime');
  assertRejected('FLOATING_COMPONENT_VERSION', (store) => replaceLiteral(store, identity, term('componentVersion'), 'latest'));
  assertRejected('COMPONENT_INTEGRITY_BINDING_MISSING', (store) => remove(store, identity, term('componentIntegrityDigest')));
  assertRejected('LICENCE_ASSESSMENT_INVALID', (store) => replaceLiteral(store, first(store, identity, term('hasLicenceAssessment')), term('licenceIdentifier'), 'UNKNOWN'));
  assertRejected('VULNERABILITY_ASSESSMENT_MISSING', (store) => remove(store, identity, term('hasVulnerabilityAssessment')));
  assertRejected('VULNERABILITY_ASSESSMENT_MISSING', (store) => {
    replaceLiteral(store, first(store, identity, term('hasVulnerabilityAssessment')), term('acceptedVulnerabilityCount'), '1');
  });
  assertRejected('SUPPLY_CHAIN_ASSESSMENT_MISSING', (store) => remove(store, identity, term('hasSupplyChainAssessment')));
  assertRejected('LICENCE_ASSESSMENT_INVALID', (store) => {
    const licence = first(store, identity, term('hasLicenceAssessment'));
    const alternateEvidence = iri('urn:usf:evidenceresult:realisationoptionevaluationlicencealternate');
    copyResource(store, first(store, evaluation, term('evaluationEvidenceResult')), alternateEvidence);
    remove(store, licence, term('licenceEvidence'));
    add(store, licence, term('licenceEvidence'), alternateEvidence);
  });
  assertRejected('LICENCE_ASSESSMENT_INVALID', (store) => {
    const licence = first(store, identity, term('hasLicenceAssessment'));
    const alternateEvidence = iri('urn:usf:evidenceresult:realisationoptionevaluationlicenceduplicate');
    copyResource(store, first(store, evaluation, term('evaluationEvidenceResult')), alternateEvidence);
    add(store, licence, term('licenceEvidence'), alternateEvidence);
  });
});

test('composition defects reach exact precedence branches', () => {
  const proof = first(baseline, selected, term('hasCompositionCoverageProof'));
  const components = objects(baseline, selected, term('hasOptionComponent'));
  const responsibilityList = objects(baseline, selected, term('hasComponentResponsibility'));
  const component = components.find((candidate) => responsibilityList.some((item) => objects(baseline, item, term('responsibilityForComponent')).some(({ value }) => value === candidate.value)));
  const componentResponsibilities = responsibilityList.filter((item) => objects(baseline, item, term('responsibilityForComponent')).some(({ value }) => value === component.value));
  assertRejected('COMPONENT_RESPONSIBILITY_MISSING', (store, context) => {
    for (const responsibility of componentResponsibilities) {
      remove(store, selected, term('hasComponentResponsibility'), responsibility);
    }
    synchroniseComponentAssessmentResponsibilities(store, context, selected, component);
  });
  assertRejected('COMPONENT_BOUNDARY_INCOMPLETE', (store) => remove(store, component, term('componentSecurityBoundary')));
  assertRejected('COMPOSITION_FACET_UNCOVERED', (store) => {
    // Each selected component owns exactly one facet, so redirect one responsibility onto an
    // already-covered requirement: its former facet becomes uncovered and the target facet gains a
    // duplicate owner, while every component keeps a valid responsibility (no COMPONENT_RESPONSIBILITY_MISSING).
    const [firstResponsibility, secondResponsibility] = responsibilityList;
    const secondRequirement = first(store, secondResponsibility, term('responsibilityForRequirement'));
    remove(store, firstResponsibility, term('responsibilityForRequirement'));
    add(store, firstResponsibility, term('responsibilityForRequirement'), secondRequirement);
  });
  assertRejected('COMPONENT_VERSION_INCOMPATIBLE', (store) => {
    const dependencySource = components.find((candidate) => objects(store, candidate, term('dependsOnOptionComponent')).length > 0);
    const dependencyTarget = first(store, dependencySource, term('dependsOnOptionComponent'));
    const compatibility = subjects(store, term('compatibilityForSourceComponent'), dependencySource)
      .find((item) => objects(store, item, term('compatibilityForTargetComponent')).some(({ value }) => value === dependencyTarget.value));
    replaceLiteral(store, compatibility, term('compatibilityTargetVersion'), '0.0.0');
  });
  assertRejected('COMPOSITION_COVERAGE_PROOF_STALE_OR_MISSING', (store) => remove(store, proof, term('compositionProofCurrent')));
  assertRejected('UNCLASSIFIED_COMPOSITION_PERMUTATION', (store) => {
    const permutation = first(store, selected, term('hasCompositionPermutationAssessment'));
    remove(store, permutation, term('permutationDisposition'), first(store, permutation, term('permutationDisposition')));
  });
  assertRejected('PROVIDER_ENVIRONMENT_BINDING_MISSING', (store, context) => {
    const missingEnvironment = iri('urn:usf:environment:hermetic');
    for (const item of components) {
      remove(store, item, term('componentEnvironmentBinding'), missingEnvironment);
      const mapping = subjects(store, term('componentMappingForComponent'), item)[0];
      for (const binding of objects(store, item, term('componentProviderBinding'))
        .filter((candidate) => objects(store, candidate, term('bindingEnvironment')).some(({ value }) => value === missingEnvironment.value))) {
        remove(store, item, term('componentProviderBinding'), binding);
        if (mapping) remove(store, mapping, term('componentMappingToProviderBinding'), binding);
      }
    }
    synchroniseCompositionProof(store, context, decision, evaluation, selected);
  });
});

test('registry, raw evidence and sole-candidate defects reach exact precedence branches', () => {
  assertRejected('FAILURE_REGISTRY_DRIFT', (store) => {
    const code = subjects(store, RDF_TYPE, term('ValidationFailureCode'))[0];
    remove(store, code, RDF_TYPE, term('ValidationFailureCode'));
  });
  assertRejected('EVIDENCE_ASSESSMENT_RECORD_DUPLICATE', () => {}, (_context) => {
    _context.ok = false;
    _context.failures = ['EVIDENCE_ASSESSMENT_RECORD_DUPLICATE'];
  });
  assertRejected('CANDIDATE_SEARCH_SPACE_INCOMPLETE', (store) => {
    const sole = first(store, authorityEvaluation, term('hasSoleCandidateJustification'));
    const searchSpace = first(store, sole, term('hasCandidateSearchSpace'));
    remove(store, searchSpace, term('searchesRealisationClass'), first(store, searchSpace, term('searchesRealisationClass')));
  });
  assertRejected('REALISATION_OPTION_VALIDATOR_GRAPH_SCOPE_MISMATCH', (store) => {
    remove(store, iri('urn:usf:validatorrule:validaterealisationoptionevaluation'), term('targetsGraph'), iri('urn:usf:namedgraph:evidence'));
  });
  assertRejected('REALISATION_OPTION_VALIDATOR_GRAPH_SCOPE_MISMATCH', (store) => {
    add(store, iri('urn:usf:validatorrule:validaterealisationoptionevaluation'), term('targetsGraph'), iri('urn:usf:namedgraph:validators'));
  });
});

test('component assessment defects reach exact precedence branches', () => {
  const component = objects(baseline, selected, term('hasOptionComponent'))[0];
  const assessment = componentAssessment(baseline, component);
  assert.ok(assessment);
  assertRejected('COMPONENT_CRITERION_ASSESSMENT_MISSING', (store) => remove(store, assessment, term('assessmentForEvaluation')));
  assertRejected('COMPONENT_CRITERION_ASSESSMENT_DUPLICATE', (store) => {
    copyResource(store, assessment, iri(`${assessment.value}duplicate`));
  });
  assertRejected('COMPONENT_ASSESSMENT_RESPONSIBILITY_MISMATCH', (store) => {
    remove(store, assessment, term('assessmentForResponsibility'), first(store, assessment, term('assessmentForResponsibility')));
  });
  assertRejected('COMPONENT_ASSESSMENT_EVIDENCE_INVALID', (store) => remove(store, assessment, term('assessmentEvidence')));
  assertRejected('COMPONENT_ASSESSMENT_EVIDENCE_INVALID', (store) => {
    const binding = first(store, assessment, term('hasCriterionEvidenceBinding'));
    remove(store, binding, term('bindingSupportingManifest'));
  });
  assertRejected('COMPONENT_MANDATORY_CRITERION_NOT_CLOSED', (store, context) => {
    setAssessmentResult(store, context, assessment, 'partiallysatisfies');
  });
});

test('kind-specific component identity defects reach exact precedence branches', () => {
  const repositoryIdentity = iri('urn:usf:componentidentity:semanticmodelcompiler');
  const externalIdentity = iri('urn:usf:componentidentity:livestardogauthority');
  const externalComponent = objects(baseline, selected, term('hasOptionComponent'))
    .find((component) => objects(baseline, component, term('componentIdentity')).some(({ value }) => value === externalIdentity.value));
  assertRejected('COMPONENT_KIND_CARDINALITY', (store) => add(store, repositoryIdentity, RDF_TYPE, term('PackageComponent')));
  assertRejected('REPOSITORY_LOCAL_SOURCE_DIGEST_MISSING', (store, context) => {
    remove(store, repositoryIdentity, term('componentImplementationSourceDigest'));
    updateObservation(store, context, repositoryIdentity, (observation) => { delete observation.sourceDigest; });
  });
  assertRejected('REPOSITORY_LOCAL_SOURCE_INTEGRITY_MISMATCH', (store, context) => {
    const digest = `sha256:${'0'.repeat(64)}`;
    replaceLiteral(store, repositoryIdentity, term('componentImplementationSourceDigest'), digest);
    updateObservation(store, context, repositoryIdentity, (observation) => { observation.sourceDigest = digest; });
  });
  assertRejected('REPOSITORY_LOCAL_TOOLCHAIN_DIGEST_MISSING', (store, context) => {
    remove(store, repositoryIdentity, term('componentToolchainDigest'));
    updateObservation(store, context, repositoryIdentity, (observation) => { delete observation.toolchainDigest; });
  });
  assertRejected('VULNERABILITY_ASSESSMENT_MISSING', (store) => remove(store, repositoryIdentity, term('hasVulnerabilityAssessment')));
  assertRejected('SUPPLY_CHAIN_ASSESSMENT_MISSING', (store) => remove(store, repositoryIdentity, term('hasSupplyChainAssessment')));
  assertRejected('EXTERNAL_PROVIDER_IDENTITY_INCOMPLETE', (store, context) => {
    replaceLiteral(store, externalIdentity, term('componentVersion'), 'managed-service');
    updateObservation(store, context, externalIdentity, (observation) => { observation.version = 'managed-service'; });
  });
  assertRejected('LICENCE_ASSESSMENT_INVALID', (store) => remove(store, externalIdentity, term('hasLicenceAssessment')));
  assertRejected('EXTERNAL_PROVIDER_BINDING_MISSING', (store) => {
    remove(store, externalComponent, term('componentProviderBinding'), first(store, externalComponent, term('componentProviderBinding')));
  });
  assertRejected('EXTERNAL_PROVIDER_MODE_OR_ENVIRONMENT_MISMATCH', (store) => {
    const binding = first(store, externalComponent, term('componentProviderBinding'));
    remove(store, binding, term('hasProviderMode'));
    add(store, binding, term('hasProviderMode'), iri('urn:usf:providermode:deterministictestsubstitute'));
  });
});

test('container-image identity defects reach exact precedence branches', () => {
  const identity = iri('urn:usf:componentidentity:nodejsruntime');
  const asContainer = (store, context, source) => {
    remove(store, identity, RDF_TYPE, term('RuntimeComponent'));
    add(store, identity, RDF_TYPE, term('ContainerImageComponent'));
    remove(store, identity, term('componentAcquisitionSource'));
    add(store, identity, term('componentAcquisitionSource'), literal(source));
    updateObservation(store, context, identity, (observation) => {
      observation.kind = 'ContainerImageComponent';
      observation.acquisitionSource = source;
    });
  };
  assertRejected('CONTAINER_IMAGE_MUTABLE_REFERENCE', (store, context) => asContainer(store, context, 'https://registry.example.invalid/usf/node:latest'));
  assertRejected('CONTAINER_IMAGE_DIGEST_MISMATCH', (store, context) => asContainer(store, context, `https://registry.example.invalid/usf/node@sha256:${'0'.repeat(64)}`));
  assertRejected('COMPONENT_INTEGRITY_BINDING_MISSING', (store, context) => {
    const digest = first(store, identity, term('componentIntegrityDigest')).value;
    asContainer(store, context, `https://registry.example.invalid/usf/node@${digest}`);
    remove(store, identity, term('componentDependencyLockDigest'));
  });
});

test('composition dependency, interface and permutation defects reach exact precedence branches', () => {
  const components = objects(baseline, selected, term('hasOptionComponent'));
  const dependencySource = components.find((candidate) => objects(baseline, candidate, term('dependsOnOptionComponent')).length > 0);
  const dependencyTarget = first(baseline, dependencySource, term('dependsOnOptionComponent'));
  assertRejected('COMPOSITION_DEPENDENCY_INVALID', (store) => add(store, dependencyTarget, term('dependsOnOptionComponent'), dependencySource));
  assertRejected('COMPOSITION_INTERFACE_INCOMPATIBLE', (store) => {
    remove(store, dependencyTarget, term('componentInterface'), first(store, dependencyTarget, term('componentInterface')));
  });
  assertRejected('PERMUTATION_RULE_SET_INVALID', (store) => {
    const permutation = first(store, selected, term('hasCompositionPermutationAssessment'));
    remove(store, permutation, term('usesPermutationRuleSet'));
  });
  assertRejected('PERMUTATION_EQUIVALENCE_PROOF_MISSING', (store) => {
    const permutation = first(store, selected, term('hasCompositionPermutationAssessment'));
    const ruleSet = first(store, permutation, term('usesPermutationRuleSet'));
    const rule = objects(store, ruleSet, term('hasPermutationClassificationRule'))
      .find((item) => objects(store, item, term('permutationEquivalenceProof')).length === 1);
    remove(store, rule, term('permutationEquivalenceProof'));
  });
});

test('concrete realisation mapping defects reach exact precedence branches', () => {
  const mapping = subjects(baseline, term('mappingForDecision'), decision)[0];
  const component = objects(baseline, selected, term('hasOptionComponent'))
    .find((item) => first(baseline, item, term('componentRole')).value !== 'urn:usf:componentrole:provider');
  const componentMapping = subjects(baseline, term('componentMappingForComponent'), component)[0];
  assertRejected('SELECTED_OPTION_REALISATION_MAPPING_CARDINALITY', (store) => remove(store, mapping, term('mappingForDecision')));
  assertRejected('SELECTED_OPTION_REALISATION_MAPPING_CARDINALITY', (store) => copyResource(store, mapping, iri(`${mapping.value}duplicate`)));
  assertRejected('SELECTED_COMPONENT_CONCRETE_MAPPING_CARDINALITY', (store) => remove(store, componentMapping, term('componentMappingForComponent')));
  assertRejected('SELECTED_COMPONENT_CONCRETE_MAPPING_CARDINALITY', (store) => copyResource(store, componentMapping, iri(`${componentMapping.value}duplicate`)));
  assertRejected('SELECTED_COMPONENT_CONCRETE_MAPPING_TYPE_MISMATCH', (store) => {
    const targets = [
      ...objects(store, componentMapping, term('componentMappingToImplementation')),
      ...objects(store, componentMapping, term('componentMappingToAdapter')),
      ...objects(store, componentMapping, term('componentMappingToDependencyBinding')),
    ];
    assert.ok(targets.length > 0);
    for (const target of targets) remove(store, target, RDF_TYPE);
  });
  assertRejected('SELECTION_MAPPING_DEPENDENCY_DRIFT', (store) => replaceLiteral(store, mapping, term('mappingEvaluationDigest'), `sha256:${'0'.repeat(64)}`));
  assertRejected('SELECTION_MAPPING_DEPENDENCY_DRIFT', (store) => replaceLiteral(store, componentMapping, term('mappingImplementationSourceDigest'), `sha256:${'0'.repeat(64)}`));
});

test('every executable reason has an exact counter mapping and isolated mutation', () => {
  assert.equal(Object.keys(REASON_COUNTER).length, REASON_PRECEDENCE.length);
  assert.equal(new Set(Object.values(REASON_COUNTER)).size, GATE_COUNTER_NAMES.length);
  assert.ok(Object.values(REASON_COUNTER).every((counter) => GATE_COUNTER_NAMES.includes(counter)));
  assert.equal(first(baseline, architectureDecision, term('decisionState')).value, 'urn:usf:decisionstate:accepted');
  assert.deepEqual([...mutationReasons].sort(), [...REASON_PRECEDENCE].sort());
  const shapeStore = new Store();
  for (const name of readdirSync(join(root, 'semantic-model', 'shapes')).filter((item) => item.endsWith('.ttl')).sort()) {
    shapeStore.addQuads(new Parser({ format: 'text/turtle' }).parse(readFileSync(join(root, 'semantic-model', 'shapes', name), 'utf8')));
  }
  const shaclCodes = new Set(shapeStore.getQuads(null, term('constraintFailureCode'), null, null).map(({ object }) => object.value));
  const integritySource = readFileSync(join(root, 'semantic-model', 'rules', 'integrity.rq'), 'utf8');
  const integrityCodes = new Set([...integritySource.matchAll(/BIND\("([a-z0-9]+)"\s+AS\s+\?violation\)/g)].map((match) => match[1]));
  for (const resource of subjects(baseline, RDF_TYPE, term('ValidationFailureCode'))) {
    const canonicalName = first(baseline, resource, term('canonicalName')).value;
    const expectedLayers = ['urn:usf:validationlayer:evaluator'];
    if (integrityCodes.has(canonicalName)) expectedLayers.push('urn:usf:validationlayer:integrity');
    if (shaclCodes.has(resource.value)) expectedLayers.push('urn:usf:validationlayer:shacl');
    assert.deepEqual(objects(baseline, resource, term('failureLayer')).map(({ value }) => value).sort(), expectedLayers.sort(), canonicalName);
  }
});
