import assert from 'node:assert/strict';
import test from 'node:test';

import { Parser } from 'n3';

import {
  AGGREGATE_ALGORITHM_DIGEST,
  AGGREGATE_ALGORITHM_VERSION,
  COMPONENT_PROOFS,
  COMPONENT_SET_DIGEST,
  aggregateCompilerProofInternals,
} from './aggregate-compiler-proof.mjs';
import {
  AUTHORITY_PRINCIPAL,
  canonicalJson,
  ownerAssignmentCandidateDigest,
  publicationReceiptDigest,
  sourceScopeDigest,
} from '../../processes/semantic-assurance/semantic-proof-v1.mjs';
import {
  aggregateCompilerAuthorityCandidateInternals as internals,
  materializeAggregateCompilerAuthorityCandidate,
} from './aggregate-compiler-authority-candidate.mjs';

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const USF = 'urn:usf:ontology:';
const FINAL_RESULT = 'urn:usf:proofresult:compilersemanticenforcementaggregate';
const FINAL_PROOF = 'urn:usf:proof:compilersemanticenforcementaggregate';
const AGGREGATE_ALGORITHM = 'urn:usf:proofalgorithm:compilersemanticenforcementaggregate';
const AGGREGATE_VERSION = 'urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210';
const VALIDATION_RULE = 'urn:usf:authoritybindingrule:validationnonpublicationdependencyclosure';
const SELF_PUBLICATION_RULE = 'urn:usf:authoritybindingrule:selfpublicationclosure';
const AGGREGATE_ADMISSION_PATH = 'urn:usf:evidenceadmissionpath:compilersemanticenforcementaggregate';
const digest = (character) => `sha256:${character.repeat(64)}`;
const D0 = digest('1');
const D1 = digest('2');
const PROSPECTIVE_INVENTORY = Object.freeze([
  Object.freeze({ graph: 'urn:usf:graph:authority', sha256: digest('5'), triples: 1 }),
  Object.freeze({ graph: 'urn:usf:graph:proofs', sha256: digest('6'), triples: 1 }),
]);
const DEPENDENCY_SET = internals.nonPublicationDependencySetDigest(PROSPECTIVE_INVENTORY);
const HEAD = '4'.repeat(40);
const TREE = '5'.repeat(40);
const GRAPH_PATHS = [
  'assurance/semantic-model-compilation/aggregate-compiler-proof.mjs',
  'processes/semantic-assurance/semantic-proof-v1.mjs',
];
const FACTORY_PATHS = [
  'src/usf_factory/provider_catalog.py',
  'src/usf_factory/semantic_factory.py',
];
const SOURCE_SCOPE = sourceScopeDigest(GRAPH_PATHS);
const SOURCE_BINDING = {
  head: HEAD,
  reachableFrom: 'refs/remotes/origin/main',
  repository: 'maldous/usf-graph',
  sourcePaths: GRAPH_PATHS,
  sourceScopeDigest: SOURCE_SCOPE,
  tree: TREE,
};
const SOURCE_BINDING_DIGEST = aggregateCompilerProofInternals.sourceBindingDigest(SOURCE_BINDING);

function pendingPackage() {
  const components = COMPONENT_PROOFS.map((component, index) => ({
    currentness: {
      admittedEvidence: [{ digest: digest(String(index + 6)), iri: `urn:usf:evidenceresult:component${index}` }],
      authorityDigest: D0,
      historicalResultDigest: digest('a'),
      invalidated: false,
      observedAt: '2026-08-01T00:00:00Z',
      projectionReceiptDigest: digest('b'),
      proofState: 'successful',
      resultState: 'passed',
      snapshotDigest: digest('c'),
      supersededBy: null,
      validFrom: '2026-07-01T00:00:00Z',
      validUntil: '2026-09-01T00:00:00Z',
    },
    dimension: component.dimension,
    evidenceReferences: [{
      bytesBase64: Buffer.from(`component-${index}`).toString('base64'),
      digest: digest(String(index + 6)),
      iri: `urn:usf:evidenceresult:component${index}`,
    }],
    historicalResult: {
      authorityBindingDigest: digest('d'),
      component,
      digest: digest('e'),
      evaluatedAt: '2026-07-20T00:00:00Z',
      evidenceSet: [{ digest: digest(String(index + 6)), iri: `urn:usf:evidenceresult:component${index}` }],
      proof: `urn:usf:proof:component${index}`,
      proofAlgorithm: `urn:usf:proofalgorithm:component${index}`,
      proofAlgorithmSourceDigest: digest('f'),
      proofAlgorithmVersion: `urn:usf:proofalgorithmversion:component${index}`,
      proofAlgorithmVersionIdentifier: '1.0.0',
      proofEvaluation: `urn:usf:proofevaluation:component${index}`,
      proofExecution: `urn:usf:proofexecution:component${index}`,
      schema: 'aggregate-historical-component-result-v1',
    },
    obligation: component.obligation,
    result: component.result,
  }));
  const evaluation = {
    algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
    algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
    authorityDigest: D0,
    componentSetDigest: COMPONENT_SET_DIGEST,
    components,
    evaluatedAt: '2026-08-01T00:00:00Z',
    evidenceSetDigest: digest('6'),
    phase: 'PRE_PUBLICATION_PREPARATION',
    postPublicationReevaluation: null,
    sourceBinding: SOURCE_BINDING,
    sourceBindingDigest: SOURCE_BINDING_DIGEST,
  };
  return {
    aggregateResult: {
      evaluation,
      evaluationDigest: internals.sha256Json(evaluation),
      passed: false,
      proofCurrentness: 'PENDING',
      resultState: 'PENDING',
      selectable: false,
    },
    evaluatedAuthorityDigest: D0,
    evaluationReceiptDigest: digest('7'),
    executionReceiptDigest: digest('8'),
    ok: true,
    proofCurrentness: 'PENDING',
    resultState: 'PENDING',
    selectable: false,
    state: 'PENDING_PREPARATION',
  };
}

const SHARED_VERIFIER = Object.freeze({
  identityDigest: digest('a'),
  implementationRelease: 'semantic-proof-v1.0.0',
  sourceHead: HEAD,
  sourcePaths: GRAPH_PATHS,
  sourceScopeDigest: SOURCE_SCOPE,
  sourceTree: TREE,
  trustAnchorDigest: digest('b'),
});

function ownerAuthorityFor({ admission, descriptor, descriptorReceipt, domain, envelope, repository, sourcePaths, verification }) {
  return {
    admission: { receiptDigest: digest(admission) },
    assignment: {
      authorityPreDigest: D0,
      candidateDigest: ownerAssignmentCandidateDigest({
        authorityDomain: domain,
        principal: AUTHORITY_PRINCIPAL,
        repository,
        sourcePaths,
      }),
      envelopeDigest: digest(envelope),
      sourcePaths,
      sourceScopeDigest: sourceScopeDigest(sourcePaths),
    },
    descriptor: {
      byteLength: 512,
      digest: digest(descriptor),
      mediaType: 'application/json',
      receiptDigest: digest(descriptorReceipt),
    },
    verification: { receiptDigest: digest(verification), verifiedAt: '2026-08-01T00:00:01Z' },
    verifier: { ...SHARED_VERIFIER },
  };
}

function ownerAuthority() {
  return {
    factoryproviderdurablecontrolplane: ownerAuthorityFor({
      admission: 'c',
      descriptor: 'f',
      descriptorReceipt: '7',
      domain: 'urn:usf:capabilityowner:factoryproviderdurablecontrolplane',
      envelope: 'e',
      repository: 'maldous/usf-factory',
      sourcePaths: FACTORY_PATHS,
      verification: 'b',
    }),
    providerconfigurationplane: ownerAuthorityFor({
      admission: 'a',
      descriptor: 'd',
      descriptorReceipt: 'e',
      domain: 'urn:usf:capabilityowner:providerconfigurationplane',
      envelope: 'c',
      repository: 'maldous/usf-factory',
      sourcePaths: FACTORY_PATHS,
      verification: 'f',
    }),
    semanticmodelcompilation: ownerAuthorityFor({
      admission: 'b',
      descriptor: 'e',
      descriptorReceipt: 'f',
      domain: 'urn:usf:capabilityowner:semanticmodelcompilation',
      envelope: 'd',
      repository: 'maldous/usf-graph',
      sourcePaths: GRAPH_PATHS,
      verification: 'a',
    }),
  };
}

function publicationReceipt(candidateDigest) {
  return {
    action_state: 'UNRESOLVED_FAIL_CLOSED',
    authority_after_digest: D1,
    authority_before_digest: D0,
    authority_domain: 'urn:usf:capabilityowner:semanticmodelcompilation',
    authority_publication_digest: D1,
    candidate_approval_envelope_digest: digest('4'),
    candidate_digest: candidateDigest,
    committed_candidate_state: 'COMMITTED',
    current_proof_results: 0,
    direct_provisional_aggregate_selections: 1,
    grant_consumed: true,
    grant_nonce: '12345678-1234-4123-8123-123456789abc',
    owner_assignment_envelope_digest: digest('5'),
    proof_currentness: 'PENDING',
    projection_observation_receipt_digest: digest('6'),
    protocol: 'semantic-proof-v1',
    publication_grant_envelope_digest: digest('7'),
    publication_outcome: 'committed_pending_reevaluation',
    publication_phase: 'initial',
    published_at: '2026-08-01T00:01:00Z',
    reevaluation_authority_digest: null,
    reevaluation_evaluation_receipt_digest: null,
    reevaluation_execution_receipt_digest: null,
    repository: 'maldous/usf-graph',
    schema_version: 1,
    selected_aggregate_result: null,
    selected_provisional_aggregate_result: internals.PROVISIONAL_RESULT,
    source_scope_digest: SOURCE_SCOPE,
    terminal_state: 'PENDING',
  };
}

function stage2Package(candidateDigest) {
  const receipt = publicationReceipt(candidateDigest);
  const receiptDigest = publicationReceiptDigest(receipt);
  const executionReceipt = {
    algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
    algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
    authorityAfterDigest: D1,
    completedAt: '2026-08-01T00:02:00Z',
    componentSetDigest: COMPONENT_SET_DIGEST,
    evidenceSetDigest: digest('6'),
    publicationReceiptDigest: receiptDigest,
    schema: 'aggregate-post-publication-execution-v1',
    sourceBindingDigest: SOURCE_BINDING_DIGEST,
    startedAt: '2026-08-01T00:01:01Z',
  };
  const executionReceiptDigest = internals.sha256Json(executionReceipt);
  const evaluationReceipt = {
    algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
    algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
    authorityAfterDigest: D1,
    componentSetDigest: COMPONENT_SET_DIGEST,
    evaluatedAt: '2026-08-01T00:02:00Z',
    evidenceSetDigest: digest('6'),
    executionReceiptDigest,
    publicationReceiptDigest: receiptDigest,
    resultState: 'passed',
    schema: 'aggregate-post-publication-evaluation-v1',
    sourceBindingDigest: SOURCE_BINDING_DIGEST,
  };
  const descriptor = (iri, value, persistenceReceiptDigest) => {
    const bytes = Buffer.from(canonicalJson(value), 'utf8');
    return {
      byteLength: bytes.length,
      bytesBase64: bytes.toString('base64'),
      digest: internals.sha256Json(value),
      iri,
      mediaType: 'application/json',
      persistenceReceiptDigest,
    };
  };
  const compilerValidationReceipt = {
    authorityAfterDigest: D1,
    authorityBeforeDigest: D0,
    candidateDigest,
    conforms: true,
    evaluatedAt: '2026-08-01T00:00:30Z',
    evaluationReceiptDigest: digest('a'),
    executionReceiptDigest: digest('b'),
    schema: 'semantic-authority-compiler-validation-v1',
    sourceBindingDigest: SOURCE_BINDING_DIGEST,
    validationReportDigest: digest('c'),
  };
  return {
    compilerValidation: {
      descriptor: descriptor('urn:usf:validationevidence:compilersemanticenforcementcompilervalidation',
        compilerValidationReceipt, digest('d')),
      receipt: compilerValidationReceipt,
    },
    evaluationReceipt,
    evaluationReceiptDescriptor: descriptor(
      'urn:usf:validationevidence:compilersemanticenforcementaggregateevaluation', evaluationReceipt, digest('e')),
    executionReceipt,
    executionReceiptDescriptor: descriptor(
      'urn:usf:validationevidence:compilersemanticenforcementaggregateexecution', executionReceipt, digest('f')),
    package: {
      candidateDigest,
      evaluatedAuthorityDigest: D1,
      evaluationReceiptDigest: internals.sha256Json(evaluationReceipt),
      executionReceiptDigest,
      ok: true,
      operation: 'produce_initial',
      protocol: 'semantic-proof-v1',
      state: 'REEVALUATION_CANDIDATE_PREPARED',
    },
    publicationReceipt: receipt,
  };
}

function baseSemanticDelta() {
  const additions = [
    '<urn:usf:principal:matthewaldous> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <urn:usf:ontology:AuthorityPrincipal> <urn:usf:graph:authority> .',
    '<urn:usf:semanticproofprotocol:v1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <urn:usf:ontology:SemanticProofProtocol> <urn:usf:graph:authority> .',
  ].sort();
  const bytes = Buffer.from([
    '# semantic-proof-v1 canonical-rdf-patch-v1 base',
    ...additions.map((line) => `A ${line}`),
    '',
  ].join('\n'), 'utf8');
  return {
    authorityPreDigest: D0,
    bytesBase64: bytes.toString('base64'),
    candidateDigest: internals.sha256Bytes(bytes),
    exactCandidateStateVerified: true,
    mediaType: 'application/rdf-patch',
    state: 'VALIDATED_ROLLBACK',
    validationReceiptDigest: digest('9'),
  };
}

const stage1Input = () => ({
  baseSemanticDelta: baseSemanticDelta(),
  currentnessBinding: { prospectiveAuthorityInventory: PROSPECTIVE_INVENTORY.map((record) => ({ ...record })) },
  ownerAuthority: ownerAuthority(),
  pendingPackage: pendingPackage(),
  stage: 'stage1',
});
const stage2Input = () => {
  const stage1CandidateDigest = materializeAggregateCompilerAuthorityCandidate(stage1Input()).candidateDigest;
  return {
    currentnessBinding: { prospectiveAuthorityInventory: PROSPECTIVE_INVENTORY.map((record) => ({ ...record })) },
    ownerAuthority: ownerAuthority(),
    pendingPackage: pendingPackage(),
    stage: 'stage2',
    stage2Package: stage2Package(stage1CandidateDigest),
  };
};

function parsePatch(bytes) {
  const operations = { additions: [], deletions: [] };
  for (const operation of Object.keys(operations)) {
    const marker = operation === 'additions' ? 'A ' : 'D ';
    const source = bytes.toString('utf8').split('\n').filter((line) => line.startsWith(marker))
      .map((line) => line.slice(2)).join('\n');
    operations[operation] = source ? new Parser({ format: 'N-Quads' }).parse(source) : [];
  }
  return operations;
}

function rawPatch(bytes) {
  const operations = { additions: [], deletions: [] };
  for (const line of bytes.toString('utf8').split('\n')) {
    if (line.startsWith('A ')) operations.additions.push(line.slice(2));
    if (line.startsWith('D ')) operations.deletions.push(line.slice(2));
  }
  return operations;
}

function initialD0State() {
  return new Set([
    `<urn:usf:semanticcontract:compilersemanticenforcement> <${USF}hasActivationState> <urn:usf:contractactivationstate:active> <urn:usf:graph:capabilities> .`,
    `<urn:usf:realisation:semanticauthoritycontrol> <${USF}realisationState> <urn:usf:realisationstate:implementable> <urn:usf:graph:bindings> .`,
    `<urn:usf:realisation:semanticcontractcompilersemanticenforcement> <${USF}realisationState> <urn:usf:realisationstate:implementable> <urn:usf:graph:bindings> .`,
    ...COMPONENT_PROOFS.flatMap(({ obligation, result }) => [
      `<urn:usf:semanticcontract:compilersemanticenforcement> <${USF}mandatoryProofObligation> <${obligation}> <urn:usf:graph:capabilities> .`,
      `<urn:usf:semanticcontract:compilersemanticenforcement> <${USF}reliesOnProofResult> <${result}> <urn:usf:graph:capabilities> .`,
    ]),
  ]);
}

function applyExactPatch(state, bytes) {
  const operations = rawPatch(bytes);
  for (const quad of operations.deletions) {
    assert.equal(state.has(quad), true, `deletion is absent from pre-state: ${quad}`);
    state.delete(quad);
  }
  for (const quad of operations.additions) {
    assert.equal(state.has(quad), false, `addition is already present in pre-state: ${quad}`);
    state.add(quad);
  }
  return state;
}

function applyDesiredPatch(state, bytes) {
  const operations = rawPatch(bytes);
  for (const quad of operations.deletions) state.delete(quad);
  for (const quad of operations.additions) state.add(quad);
  return state;
}

function parseState(state) {
  return new Parser({ format: 'N-Quads' }).parse([...state].sort().join('\n'));
}

const objects = (quads, subject, predicate) => quads
  .filter((quad) => quad.subject.value === subject && quad.predicate.value === predicate)
  .map((quad) => quad.object.value);
const has = (quads, subject, predicate, object) => objects(quads, subject, predicate).includes(object);
const typedAs = (quads, subject, classIri) => has(quads, subject, RDF_TYPE, classIri);

function assertReferencedTypes(quads) {
  const references = new Map([
    [`${USF}verificationAdmissionUsesEvidencePath`, `${USF}EvidenceAdmissionPath`],
    [`${USF}hasEnvelopeVerificationAdmission`, `${USF}SemanticProofEnvelopeVerificationAdmission`],
    [`${USF}verificationCASDescriptor`, `${USF}SemanticProofVerificationCASDescriptor`],
    [`${USF}hasAuthorityBinding`, `${USF}ProofAuthorityBinding`],
    [`${USF}usesAuthorityBindingRule`, `${USF}AuthorityBindingRule`],
    [`${USF}validationUsesAuthorityBindingRule`, `${USF}AuthorityBindingRule`],
    [`${USF}validationUsesEvidenceAdmissionPath`, `${USF}EvidenceAdmissionPath`],
    [`${USF}authorityBindingEvidenceAdmissionPath`, `${USF}EvidenceAdmissionPath`],
  ]);
  for (const [predicate, classIri] of references) {
    for (const quad of quads.filter((item) => item.predicate.value === predicate)) {
      assert.equal(typedAs(quads, quad.object.value, classIri), true,
        `${quad.object.value} referenced by ${predicate} lacks ${classIri}`);
    }
  }
}

function assertCommonCurrentnessFacts(quads, result, proof, binding, confidenceState = 'warranted') {
  assert.equal(has(quads, result, `${USF}proofResultForObligation`, internals.AGGREGATE_OBLIGATION), true);
  assert.equal(has(quads, result, `${USF}resultForProof`, proof), true);
  assert.equal(has(quads, result, `${USF}usesProofAlgorithm`, AGGREGATE_ALGORITHM), true);
  assert.equal(has(quads, result, `${USF}usesAlgorithmVersion`, AGGREGATE_VERSION), true);
  assert.equal(objects(quads, result, `${USF}usesAdmittedEvidence`).length, COMPONENT_PROOFS.length);
  assert.deepEqual(objects(quads, result, `${USF}evidenceSetDigest`), [digest('6')]);
  assert.deepEqual(objects(quads, result, `${USF}implementationSourceSetDigest`), [SOURCE_BINDING_DIGEST]);
  assert.deepEqual(objects(quads, result, `${USF}dependencySetDigest`), [DEPENDENCY_SET]);
  assert.deepEqual(objects(quads, result, `${USF}dependencyDigestAlgorithm`),
    ['sha256-rdfc10-nonpublication-graph-inventory-v1']);
  assert.deepEqual(objects(quads, result, `${USF}proofProducerCommit`), [HEAD]);
  assert.deepEqual(objects(quads, result, `${USF}proofProducerTree`), [TREE]);
  assert.equal(has(quads, result, `${USF}hasAuthorityBinding`, binding), true);
  assert.equal(has(quads, result, `${USF}hasFreshness`, 'urn:usf:freshness:fresh'), true);
  if (confidenceState === null) {
    assert.equal(objects(quads, result, `${USF}hasConfidenceState`).length, 0);
    assert.equal(objects(quads, result, `${USF}confidenceBasis`).length, 0);
  } else {
    assert.equal(has(quads, result, `${USF}hasConfidenceState`, `urn:usf:proofconfidencestate:${confidenceState}`), true);
    assert.ok(objects(quads, result, `${USF}confidenceBasis`).length > 0);
  }
  assert.equal(objects(quads, result, `${USF}hasInvalidation`).length, 0);
  assert.equal(objects(quads, result, `${USF}supersededByProofResult`).length, 0);
  assert.equal(objects(quads, result, `${USF}hasInvalidationCondition`).length, 3);
  assert.equal(typedAs(quads, binding, `${USF}ProofAuthorityBinding`), true);
  assert.equal(has(quads, binding, `${USF}usesAuthorityBindingRule`, SELF_PUBLICATION_RULE), true);
  assert.deepEqual(objects(quads, binding, `${USF}bindingDependencySetDigest`), [DEPENDENCY_SET]);
  assert.deepEqual(objects(quads, AGGREGATE_ALGORITHM, `${USF}currentAlgorithmSourceDigest`),
    [AGGREGATE_ALGORITHM_DIGEST]);
  assert.deepEqual(objects(quads, AGGREGATE_ALGORITHM, `${USF}currentImplementationSourceSetDigest`),
    [SOURCE_BINDING_DIGEST]);
  assert.deepEqual(objects(quads, AGGREGATE_ALGORITHM, `${USF}currentDependencySetDigest`), [DEPENDENCY_SET]);
}

test('stage 1 is deterministic, parses as RDF Patch and preserves immutable component results', () => {
  const first = materializeAggregateCompilerAuthorityCandidate(stage1Input());
  const second = materializeAggregateCompilerAuthorityCandidate(stage1Input());
  assert.equal(first.candidateDigest, second.candidateDigest);
  assert.deepEqual(first.bytes, second.bytes);
  const { additions, deletions } = parsePatch(first.bytes);
  assert.equal(has(additions, 'urn:usf:semanticcontract:compilersemanticenforcement', `${USF}reliesOnProofResult`,
    internals.PROVISIONAL_RESULT), true);
  assert.equal(has(additions, 'urn:usf:semanticcontract:compilersemanticenforcement', `${USF}hasActivationState`,
    'urn:usf:contractactivationstate:proofblocked'), true);
  for (const component of COMPONENT_PROOFS) {
    assert.equal(deletions.some((quad) => quad.object.value === component.result
      && quad.graph.value === 'urn:usf:graph:capabilities'), true);
    assert.equal(deletions.some((quad) => quad.subject.value === component.result), false);
    assert.equal(has(additions, component.result, `${USF}proofResultForObligation`, component.obligation), true);
  }
  for (const realisation of [
    'urn:usf:realisation:semanticauthoritycontrol',
    'urn:usf:realisation:semanticcontractcompilersemanticenforcement',
  ]) {
    assert.equal(has(additions, realisation, `${USF}realisationState`, 'urn:usf:realisationstate:deferred'), true);
    assert.equal(deletions.some((quad) => quad.subject.value === realisation
      && quad.object.value === 'urn:usf:realisationstate:implementable'), true);
  }
  assert.equal(deletions.some((quad) => quad.predicate.value === `${USF}assignmentState`), false);
});

test('stage 2 desired overlay converges after source reload and preserves stage-1 evidence', () => {
  const state = initialD0State();
  const stage1 = materializeAggregateCompilerAuthorityCandidate(stage1Input());
  applyExactPatch(state, stage1.bytes);
  const stage1State = new Set(state);
  const stage2 = materializeAggregateCompilerAuthorityCandidate(stage2Input());
  applyDesiredPatch(state, stage2.bytes);
  assert.equal(state.has([...rawPatch(stage2.bytes).additions][0]), true);
  assert.equal(rawPatch(stage2.bytes).additions.some((quad) => !stage1State.has(quad) && state.has(quad)), true);
  assert.equal(rawPatch(stage2.bytes).additions.some((quad) => quad.includes('OwnerAssignment')), true);
  assert.equal(rawPatch(stage2.bytes).additions.some((quad) =>
    quad.includes('compilersemanticenforcementaggregateprepublication')), true);
});

test('stage 1 materializes all independently scoped owner assignments and every referenced admission path', () => {
  const { additions } = parsePatch(materializeAggregateCompilerAuthorityCandidate(stage1Input()).bytes);
  const expectations = [
    ['factoryproviderdurablecontrolplane', 'maldous/usf-factory'],
    ['providerconfigurationplane', 'maldous/usf-factory'],
    ['semanticmodelcompilation', 'maldous/usf-graph'],
  ];
  for (const [key, repository] of expectations) {
    const scope = internals.OWNER_SCOPES[key];
    assert.equal(typedAs(additions, scope.assignment, `${USF}OwnerAssignment`), true);
    assert.equal(has(additions, scope.assignment, `${USF}authorityDomain`, scope.domain), true);
    assert.deepEqual(objects(additions, scope.assignment, `${USF}authorityRepository`), [repository]);
    assert.deepEqual(objects(additions, scope.assignment, `${USF}assignmentState`), ['active']);
    assert.equal(typedAs(additions, scope.verification, `${USF}SemanticProofEnvelopeVerification`), true);
    assert.equal(typedAs(additions, scope.verificationAdmission,
      `${USF}SemanticProofEnvelopeVerificationAdmission`), true);
    assert.equal(typedAs(additions, scope.verificationDescriptor,
      `${USF}SemanticProofVerificationCASDescriptor`), true);
    assert.equal(typedAs(additions, scope.evidenceAdmissionPath, `${USF}EvidenceAdmissionPath`), true);
    assert.equal(typedAs(additions, scope.validationProducer, `${USF}ValidationProducer`), true);
    assert.equal(has(additions, scope.verificationAdmission, `${USF}verificationAdmissionUsesEvidencePath`,
      scope.evidenceAdmissionPath), true);
  }
  assert.equal(typedAs(additions, AGGREGATE_ADMISSION_PATH, `${USF}EvidenceAdmissionPath`), true);
  assertReferencedTypes(additions);
});

test('provisional aggregate has the complete structural currentness binding and remains explicitly pending', () => {
  const { additions } = parsePatch(materializeAggregateCompilerAuthorityCandidate(stage1Input()).bytes);
  assertCommonCurrentnessFacts(additions, internals.PROVISIONAL_RESULT,
    'urn:usf:proof:compilersemanticenforcementaggregateprepublication',
    'urn:usf:proofauthoritybinding:compilersemanticenforcementaggregateprepublication', null);
  assert.deepEqual(objects(additions, internals.PROVISIONAL_RESULT, `${USF}resultState`), ['urn:usf:resultstate:notrun']);
  assert.equal(objects(additions, internals.PROVISIONAL_RESULT, `${USF}hasConfidenceState`).length, 0);
  assert.equal(objects(additions, internals.PROVISIONAL_RESULT, `${USF}confidenceBasis`).length, 0);
  assert.deepEqual(objects(additions, internals.PROVISIONAL_RESULT, `${USF}claimedRung`),
    ['urn:usf:proofrung:behaviour']);
  assert.deepEqual(objects(additions, internals.PROVISIONAL_RESULT, `${USF}inEnvironment`),
    ['urn:usf:environment:authoritycontrol']);
  assert.equal(objects(additions, internals.PROVISIONAL_RESULT, `${USF}hasProofResultState`).length, 0);
  assert.deepEqual(objects(additions, 'urn:usf:proofauthoritybinding:compilersemanticenforcementaggregateprepublication',
    `${USF}hasPostPublicationReevaluationState`), ['urn:usf:proofreevaluationstate:pending']);
});

test('stage 1 materializes authored aggregate obligation and canonical metadata closure', () => {
  const { additions } = parsePatch(materializeAggregateCompilerAuthorityCandidate(stage1Input()).bytes);
  const obligation = 'urn:usf:proofobligation:compilersemanticenforcementaggregate';
  assert.deepEqual(objects(additions, obligation, `${USF}obligationFor`),
    ['urn:usf:semanticcontract:compilersemanticenforcement']);
  assert.deepEqual(objects(additions, obligation, `${USF}requiresRung`), ['urn:usf:proofrung:behaviour']);
  assert.equal(objects(additions, obligation, `${USF}requiresEvidence`).length, 3);
  assert.deepEqual(objects(additions, obligation, `${USF}usesAssuranceCell`),
    ['urn:usf:assurancecell:behaviourliveauthoritycontrol']);
  for (const subject of [
    obligation,
    AGGREGATE_ALGORITHM,
    AGGREGATE_VERSION,
    internals.PROVISIONAL_RESULT,
    'urn:usf:proof:compilersemanticenforcementaggregateprepublication',
    'urn:usf:proofexecution:compilersemanticenforcementaggregateprepublication',
    'urn:usf:proofevaluation:compilersemanticenforcementaggregateprepublication',
    'urn:usf:proofauthoritybinding:compilersemanticenforcementaggregateprepublication',
    VALIDATION_RULE,
  ]) assert.equal(objects(additions, subject, `${USF}canonicalName`).length, 1, subject);
  assert.deepEqual(objects(additions, AGGREGATE_VERSION, `${USF}canonicalName`),
    ['compilersemanticenforcementaggregatev210']);
  for (const component of COMPONENT_PROOFS) {
    const requirement = `urn:usf:componentproofrequirement:compilersemanticenforcementaggregate:${component.dimension}`;
    assert.deepEqual(objects(additions, requirement, `${USF}canonicalName`), [component.dimension]);
  }
  assert.deepEqual(objects(additions, AGGREGATE_ALGORITHM, `${USF}proofAlgorithmSourcePath`),
    ['assurance/semantic-model-compilation/aggregate-compiler-proof.mjs']);
});

test('stage 2 final aggregate carries every CURRENT projection fact and coherent authority closure', () => {
  const state = initialD0State();
  applyExactPatch(state, materializeAggregateCompilerAuthorityCandidate(stage1Input()).bytes);
  applyDesiredPatch(state, materializeAggregateCompilerAuthorityCandidate(stage2Input()).bytes);
  const quads = parseState(state);
  const contract = 'urn:usf:semanticcontract:compilersemanticenforcement';
  assert.deepEqual(objects(quads, contract, `${USF}reliesOnProofResult`), [FINAL_RESULT]);
  assert.deepEqual(objects(quads, contract, `${USF}mandatoryProofObligation`), [internals.AGGREGATE_OBLIGATION]);
  assert.deepEqual(objects(quads, contract, `${USF}hasActivationState`),
    ['urn:usf:contractactivationstate:active']);
  const validationObligation = 'urn:usf:validationobligation:compilersemanticenforcement';
  const validationExecution = 'urn:usf:validationexecution:compilersemanticenforcementaggregate';
  const validationResult = 'urn:usf:validationresult:compilersemanticenforcementaggregate';
  const compilerEvidence = 'urn:usf:validationevidence:compilersemanticenforcementcompilervalidation';
  assert.deepEqual(objects(quads, validationObligation, `${USF}hasValidationActivationState`),
    ['urn:usf:validationactivationstate:activated']);
  assert.deepEqual(objects(quads, validationExecution, `${USF}executesValidation`), [validationObligation]);
  assert.deepEqual(objects(quads, validationExecution, `${USF}producesValidationResult`), [validationResult]);
  assert.deepEqual(objects(quads, validationResult, `${USF}resultForValidationObligation`), [validationObligation]);
  assert.deepEqual(objects(quads, validationResult, `${USF}validationEvaluatedAuthorityDigest`), [D1]);
  assert.deepEqual(objects(quads, validationResult, `${USF}validationEvaluatedSourceHead`), [HEAD]);
  assert.deepEqual(objects(quads, validationResult, `${USF}entersEvidenceLifecycleAs`), [compilerEvidence]);
  assert.equal(objects(quads, validationResult, `${USF}usesAdmittedValidationEvidence`).length, 3);
  for (const evidence of objects(quads, validationResult, `${USF}usesAdmittedValidationEvidence`)) {
    assert.equal(typedAs(quads, evidence, `${USF}EvidenceResult`), true);
    assert.equal(typedAs(quads, evidence, `${USF}ValidationEvidence`), evidence === compilerEvidence);
    assert.deepEqual(objects(quads, evidence, `${USF}evidenceFor`), [contract]);
    assert.deepEqual(objects(quads, evidence, `${USF}hasAdmissionState`),
      ['urn:usf:evidenceadmissionstate:admitted']);
  }
  assert.deepEqual(objects(quads, compilerEvidence, `${USF}validationEvidenceForExecution`),
    [validationExecution]);
  assert.deepEqual(objects(quads, compilerEvidence, `${USF}validationEvidenceAdmittedThrough`),
    [AGGREGATE_ADMISSION_PATH]);
  for (const realisation of [
    'urn:usf:realisation:semanticauthoritycontrol',
    'urn:usf:realisation:semanticcontractcompilersemanticenforcement',
  ]) assert.deepEqual(objects(quads, realisation, `${USF}realisationState`),
    ['urn:usf:realisationstate:implementable']);
  assert.equal(quads.filter((quad) => quad.subject.value === contract
    && [`${USF}reliesOnProofResult`, `${USF}mandatoryProofObligation`, `${USF}hasActivationState`]
      .includes(quad.predicate.value))
    .every((quad) => quad.graph.value === 'urn:usf:graph:capabilities'), true);
  assertCommonCurrentnessFacts(quads, FINAL_RESULT, FINAL_PROOF, internals.FINAL_BINDING);
  assert.deepEqual(objects(quads, FINAL_RESULT, `${USF}hasProofResultState`),
    ['urn:usf:proofresultstate:successful']);
  assert.deepEqual(objects(quads, internals.FINAL_BINDING, `${USF}bindingEvaluatedAuthorityDigest`), [D1]);
  assert.deepEqual(objects(quads, internals.FINAL_BINDING, `${USF}reevaluationSettledAuthorityDigest`), []);
  assert.deepEqual(objects(quads, internals.FINAL_BINDING, `${USF}reevaluationDependencySetDigest`), [DEPENDENCY_SET]);
  assert.deepEqual(objects(quads, internals.FINAL_BINDING, `${USF}hasPostPublicationReevaluationState`),
    ['urn:usf:proofreevaluationstate:successful']);
  assert.equal(typedAs(quads, SELF_PUBLICATION_RULE, `${USF}AuthorityBindingRule`), true);
  assert.equal(typedAs(quads, VALIDATION_RULE, `${USF}AuthorityBindingRule`), true);
  const binding = 'urn:usf:validationselfpublicationbinding:compilersemanticenforcementaggregate';
  assert.deepEqual(objects(quads, binding, `${USF}validationStageOneEvaluatedAuthorityDigest`), [D0]);
  assert.deepEqual(objects(quads, binding, `${USF}validationStageOneSettledAuthorityDigest`), [D1]);
  assertReferencedTypes(quads);
});

test('stage 2 references only persisted compiler and reevaluation receipt descriptors', () => {
  const result = materializeAggregateCompilerAuthorityCandidate(stage2Input());
  assert.equal(Object.hasOwn(result, 'casRecords'), false);
  const { additions } = parsePatch(result.bytes);
  const descriptors = [
    stage2Input().stage2Package.compilerValidation.descriptor,
    stage2Input().stage2Package.executionReceiptDescriptor,
    stage2Input().stage2Package.evaluationReceiptDescriptor,
  ];
  for (const descriptor of descriptors) {
    assert.deepEqual(objects(additions, descriptor.iri, `${USF}contentDigest`), [descriptor.digest]);
    assert.deepEqual(objects(additions, descriptor.iri, `${USF}validationEvidencePersistenceReceiptDigest`),
      [descriptor.persistenceReceiptDigest]);
  }
});

test('rejects unknown fields at top level and inside finalized packages', () => {
  const top = stage1Input(); top.extra = true;
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(top), { code: 'CANDIDATE_INPUT_SCHEMA_INVALID' });
  const nested = stage1Input(); nested.pendingPackage.aggregateResult.evaluation.components[0].mystery = true;
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(nested), { code: 'CANDIDATE_PACKAGE_UNKNOWN_FIELD' });
  const currentness = stage1Input(); currentness.currentnessBinding.extra = true;
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(currentness),
    { code: 'CANDIDATE_CURRENTNESS_BINDING_INVALID' });
});

test('rejects placeholders and all-zero digests', () => {
  const placeholder = stage1Input();
  placeholder.ownerAuthority.semanticmodelcompilation.verifier.implementationRelease = 'TBD';
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(placeholder),
    { code: 'CANDIDATE_PLACEHOLDER_REJECTED' });
  const zero = stage1Input(); zero.currentnessBinding.prospectiveAuthorityInventory[0].sha256 = digest('0');
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(zero),
    { code: 'CANDIDATE_DIGEST_INVALID' });
});

test('rejects component omission, duplication and mapping substitution', () => {
  const missing = stage1Input(); missing.pendingPackage.aggregateResult.evaluation.components.pop();
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(missing),
    { code: 'CANDIDATE_COMPONENT_SET_INVALID' });
  const duplicate = stage1Input();
  duplicate.pendingPackage.aggregateResult.evaluation.components[1]
    = duplicate.pendingPackage.aggregateResult.evaluation.components[0];
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(duplicate),
    { code: 'CANDIDATE_COMPONENT_SET_INVALID' });
  const substituted = stage1Input();
  substituted.pendingPackage.aggregateResult.evaluation.components[0].result = COMPONENT_PROOFS[1].result;
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(substituted),
    { code: 'CANDIDATE_COMPONENT_SET_INVALID' });
});

test('rejects pending evaluation and authority digest tampering', () => {
  const evaluation = stage1Input(); evaluation.pendingPackage.aggregateResult.evaluation.evidenceSetDigest = digest('9');
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(evaluation),
    { code: 'CANDIDATE_PENDING_BINDING_INVALID' });
  const authority = stage1Input(); authority.pendingPackage.aggregateResult.evaluation.authorityDigest = D1;
  authority.pendingPackage.aggregateResult.evaluationDigest
    = internals.sha256Json(authority.pendingPackage.aggregateResult.evaluation);
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(authority),
    { code: 'CANDIDATE_PENDING_BINDING_INVALID' });
});

test('rejects omitted, cross-scoped or substituted owner assignments', () => {
  const omitted = stage1Input(); delete omitted.ownerAuthority.providerconfigurationplane;
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(omitted),
    { code: 'CANDIDATE_OWNER_SCHEMA_INVALID' });
  const repository = stage1Input();
  repository.ownerAuthority.providerconfigurationplane.assignment.candidateDigest = ownerAssignmentCandidateDigest({
    authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane',
    principal: AUTHORITY_PRINCIPAL,
    repository: 'maldous/usf-graph',
    sourcePaths: FACTORY_PATHS,
  });
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(repository),
    { code: 'CANDIDATE_OWNER_BINDING_INVALID' });
  const envelope = stage1Input();
  envelope.ownerAuthority.providerconfigurationplane.assignment.envelopeDigest
    = envelope.ownerAuthority.semanticmodelcompilation.assignment.envelopeDigest;
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(envelope),
    { code: 'CANDIDATE_OWNER_BINDING_INVALID' });
});

test('reuses active owner assignments without rewriting their historical issuance baseline', () => {
  const input = stage1Input();
  input.ownerAuthority.semanticmodelcompilation.assignment.authorityPreDigest = digest('d');
  input.ownerAuthority.providerconfigurationplane.assignment.authorityPreDigest = digest('e');
  const candidate = materializeAggregateCompilerAuthorityCandidate(input);
  assert.equal(candidate.stage, 'stage1');
  assert.match(candidate.bytes.toString('utf8'), /sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/);
  assert.match(candidate.bytes.toString('utf8'), /sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/);
});

test('rejects stage-1 publication transition and any future authority self-reference', () => {
  const candidate = stage2Input(); candidate.stage2Package.publicationReceipt.candidate_digest = digest('9');
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(candidate),
    { code: 'CANDIDATE_REEVALUATION_BINDING_INVALID' });
  const future = stage2Input(); future.stage2Package.package.settledAuthorityDigest = digest('3');
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(future),
    { code: 'CANDIDATE_REEVALUATION_SCHEMA_INVALID' });
});

test('rejects reevaluation receipt substitution and unknown receipt fields', () => {
  const substituted = stage2Input(); substituted.stage2Package.executionReceipt.evidenceSetDigest = digest('9');
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(substituted),
    { code: 'CANDIDATE_REEVALUATION_BINDING_INVALID' });
  const unknown = stage2Input(); unknown.stage2Package.evaluationReceipt.extra = true;
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(unknown),
    { code: 'CANDIDATE_REEVALUATION_SCHEMA_INVALID' });
});

test('stage 2 requires a genuine postpublication receipt and ordered trusted times', () => {
  const missing = stage2Input(); delete missing.stage2Package.publicationReceipt;
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(missing));
  const unordered = stage2Input(); unordered.stage2Package.executionReceipt.startedAt = '2026-08-01T00:00:01Z';
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(unordered),
    { code: 'CANDIDATE_REEVALUATION_BINDING_INVALID' });
});

test('rejects unvalidated, mixed, conflicting or byte-tampered base semantic deltas', () => {
  const unvalidated = stage1Input(); unvalidated.baseSemanticDelta.state = 'UNVALIDATED';
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(unvalidated),
    { code: 'CANDIDATE_BASE_DELTA_INVALID' });
  const tampered = stage1Input(); tampered.baseSemanticDelta.bytesBase64
    = Buffer.from('not a canonical patch').toString('base64');
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(tampered),
    { code: 'CANDIDATE_BASE_DELTA_INVALID' });
  const conflicting = stage1Input();
  const generated = materializeAggregateCompilerAuthorityCandidate(conflicting);
  const aggregateAddition = rawPatch(generated.bytes).additions.find((quad) =>
    quad.includes('<urn:usf:proofobligation:compilersemanticenforcementaggregate>'));
  assert.ok(aggregateAddition);
  const bytes = Buffer.from([
    '# semantic-proof-v1 canonical-rdf-patch-v1 base',
    `A ${aggregateAddition}`,
    '',
  ].join('\n'), 'utf8');
  conflicting.baseSemanticDelta.bytesBase64 = bytes.toString('base64');
  conflicting.baseSemanticDelta.candidateDigest = internals.sha256Bytes(bytes);
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(conflicting),
    { code: 'CANDIDATE_BASE_DELTA_CONFLICT' });
});

test('rejects receipt descriptors that are unpersisted or do not match exact CAS bytes', () => {
  const unpersisted = stage2Input();
  unpersisted.stage2Package.compilerValidation.descriptor.persistenceReceiptDigest = digest('0');
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(unpersisted),
    { code: 'CANDIDATE_DIGEST_INVALID' });
  const tampered = stage2Input();
  tampered.stage2Package.executionReceiptDescriptor.bytesBase64
    = Buffer.from('{}', 'utf8').toString('base64');
  assert.throws(() => materializeAggregateCompilerAuthorityCandidate(tampered),
    { code: 'CANDIDATE_RECEIPT_DESCRIPTOR_INVALID' });
});

test('canonical bytes contain only the approved authority principal and protocol', () => {
  const text = materializeAggregateCompilerAuthorityCandidate(stage1Input()).bytes.toString('utf8');
  assert.match(text, /urn:usf:principal:matthewaldous/);
  assert.match(text, /urn:usf:signingidentity:matthewaldoussemanticproofv1/);
  assert.match(text, /urn:usf:capabilityowner:providerconfigurationplane/);
  assert.match(text, /urn:usf:capabilityowner:semanticmodelcompilation/);
  assert.doesNotMatch(text, /integrityonly|foundationrelease|unsigned/i);
  assert.equal(canonicalJson({ algorithm: 'openpgp', fingerprint: 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D' }),
    '{"algorithm":"openpgp","fingerprint":"B6CBC89C7978AF26F53C33A197E5F20D2A340E5D"}');
});
