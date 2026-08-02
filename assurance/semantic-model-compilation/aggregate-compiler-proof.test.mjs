import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';

import {
  AGGREGATE_ALGORITHM_DIGEST,
  AGGREGATE_ALGORITHM_VERSION,
  AGGREGATE_REPOSITORY,
  COMPONENT_PROOFS,
  COMPONENT_SET_DIGEST,
  GIT_EXECUTABLE,
  ORPHANED_ATTESTATION_DIGEST,
  SHARED_HERMETIC_EVIDENCE,
  SHARED_HERMETIC_RESULTS,
  SHARED_LIVE_AUTHORITY_EVIDENCE,
  SHARED_LIVE_AUTHORITY_RESULTS,
  aggregateCompilerProofInternals,
  evaluateAggregateCompilerProof,
} from './aggregate-compiler-proof.mjs';
import { sourceScopeDigest as protocolSourceScopeDigest } from '../../processes/semantic-assurance/semantic-proof-v1.mjs';

const digest = (label) => aggregateCompilerProofInternals.sha256(label);
const immutableJson = (value) => {
  const text = aggregateCompilerProofInternals.canonicalJson(value);
  return { bytesBase64: Buffer.from(text, 'utf8').toString('base64'), digest: digest(text) };
};
const immutablePublicationReceipt = (value) => {
  const text = `${aggregateCompilerProofInternals.canonicalJson(value)}\n`;
  return { bytesBase64: Buffer.from(text, 'utf8').toString('base64'), digest: digest(text) };
};
const immutableEvidence = (index) => {
  const bytes = Buffer.from(`immutable-evidence-${index}`, 'utf8');
  return {
    bytesBase64: bytes.toString('base64'),
    digest: aggregateCompilerProofInternals.sha256Bytes(bytes),
    iri: `urn:usf:evidenceresult:aggregatecomponent${index}`,
  };
};
const jsonValue = (blob) => JSON.parse(Buffer.from(blob.bytesBase64, 'base64').toString('utf8'));

const childProcessDenied = process.env.USF_EXPECTED_CHILD_PROCESS_PERMISSION === 'denied';
const permissionModelEnabled = process.permission !== undefined;
let repositoryPath;
let sourceHead;
let sourceTree;
const command = (...args) => {
  const result = spawnSync(GIT_EXECUTABLE, ['-C', repositoryPath, ...args], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
};
const sourcePaths = ['assurance/aggregate.mjs', 'assurance/aggregate.test.mjs'];
if (!childProcessDenied) {
  repositoryPath = mkdtempSync(join(tmpdir(), 'usf-aggregate-proof-'));
  command('init', '--quiet');
  command('config', 'user.name', 'Aggregate Proof Test');
  command('config', 'user.email', 'aggregate-proof@example.invalid');
  command('checkout', '--quiet', '-b', 'main');
  mkdirSync(join(repositoryPath, 'assurance'));
  writeFileSync(join(repositoryPath, sourcePaths[0]), 'export const aggregate = true;\n');
  writeFileSync(join(repositoryPath, sourcePaths[1]), 'export const aggregateTest = true;\n');
  command('add', ...sourcePaths);
  command('commit', '--quiet', '-m', 'fixture');
  sourceHead = command('rev-parse', 'HEAD');
  sourceTree = command('rev-parse', 'HEAD^{tree}');
} else {
  repositoryPath = '/virtual/usf-aggregate-proof';
  sourceHead = 'a'.repeat(40);
  sourceTree = 'b'.repeat(40);
}
after(() => {
  if (repositoryPath && !childProcessDenied) rmSync(repositoryPath, { force: true, recursive: true });
});
const inProcessSourceBindingDependency = ({ args, executable, repositoryPath: requestedRepositoryPath }) => {
  const success = (stdout = '') => ({ status: 0, stderr: '', stdout });
  const failure = () => ({ status: 1, stderr: 'fixture source binding mismatch', stdout: '' });
  if (executable !== GIT_EXECUTABLE || requestedRepositoryPath !== repositoryPath) return failure();
  if (args[0] === 'rev-parse' && args[1] === '--verify' && args.length === 3) {
    if (args[2] === `${sourceHead}^{commit}`) return success(sourceHead);
    if (args[2] === 'refs/heads/main^{commit}') return success(sourceHead);
    return failure();
  }
  if (args[0] === 'merge-base' && args[1] === '--is-ancestor' && args.length === 4) {
    return args[2] === sourceHead && args[3] === 'refs/heads/main' ? success() : failure();
  }
  if (args[0] === 'rev-parse' && args.length === 2 && args[1] === `${sourceHead}^{tree}`) {
    return success(sourceTree);
  }
  if (args[0] === 'cat-file' && args[1] === '-e' && args.length === 3) {
    return sourcePaths.some((path) => args[2] === `${sourceHead}:${path}`) ? success() : failure();
  }
  return failure();
};
const sourceBindingDependency = permissionModelEnabled ? inProcessSourceBindingDependency : undefined;

const authorityPreDigest = digest('authority-pre');
const authorityAfterDigest = digest('authority-after');
const preEvaluationTime = '2026-08-01T11:00:00Z';
const publishedAt = '2026-08-01T12:00:00Z';
const observedAt = '2026-08-01T12:02:00Z';
const startedAt = '2026-08-01T12:02:00Z';
const completedAt = '2026-08-01T12:03:00Z';
const evaluatedAt = '2026-08-01T12:04:00Z';

const sourceBinding = () => ({
  head: sourceHead,
  reachableFrom: 'refs/heads/main',
  repository: AGGREGATE_REPOSITORY,
  sourcePaths: [...sourcePaths],
  sourceScopeDigest: aggregateCompilerProofInternals.sourceScopeDigest(sourcePaths),
  tree: sourceTree,
});

function component(index, {
  authorityDigest = authorityAfterDigest,
  evidence = immutableEvidence(index),
  observed = observedAt,
  validFrom = publishedAt,
  validUntil = '2026-09-01T00:00:00Z',
  proofState = 'successful',
  resultState = 'passed',
  invalidated = false,
  supersededBy = null,
} = {}) {
  const expected = COMPONENT_PROOFS[index];
  const evidenceReferences = [evidence];
  const evidenceDescriptors = evidenceReferences.map(({ iri, digest: evidenceDigest }) => ({
    digest: evidenceDigest,
    iri,
  }));
  const historicalResult = immutableJson({
    authorityBindingDigest: digest(`historical-authority-${index}`),
    component: expected,
    evaluatedAt: '2026-07-31T12:00:00Z',
    evidenceSet: evidenceDescriptors,
    proof: `urn:usf:proof:aggregatefixture${index}`,
    proofEvaluation: `urn:usf:proofevaluation:aggregatefixture${index}`,
    proofExecution: `urn:usf:proofexecution:aggregatefixture${index}`,
    proofState: 'successful',
    resultState: 'passed',
    schema: 'usf-component-proof-result-v1',
    sourceBinding: {
      proofAlgorithm: `urn:usf:proofalgorithm:aggregatefixture${index}`,
      proofAlgorithmSourceDigest: digest(`historical-algorithm-source-${index}`),
      proofAlgorithmVersion: `urn:usf:proofalgorithmversion:aggregatefixture${index}v1`,
    },
  });
  const snapshot = immutableJson({
    admittedEvidence: evidenceDescriptors,
    authorityDigest,
    componentResult: expected.result,
    historicalResultDigest: historicalResult.digest,
    invalidated,
    observedAt: observed,
    proofState,
    resultState,
    schema: 'usf-authority-component-currentness-v1',
    supersededBy,
    validFrom,
    validUntil,
  });
  const projectionReceipt = immutableJson({
    authorityDigest,
    componentResult: expected.result,
    producedAt: observed,
    producer: 'urn:usf:validationproducer:authoritycurrentnessprojection',
    schema: 'usf-authority-currentness-projection-receipt-v1',
    snapshotDigest: snapshot.digest,
  });
  return {
    ...expected,
    currentness: { projectionReceipt, snapshot },
    evidenceReferences,
    historicalResult,
  };
}

const components = (authorityDigest = authorityAfterDigest) => COMPONENT_PROOFS.map((_, index) => component(index, { authorityDigest }));
const evidenceSetDigest = (values) => aggregateCompilerProofInternals.descriptorSetDigest(
  values.flatMap(({ evidenceReferences }) => evidenceReferences.map(({ iri, digest: evidenceDigest }) => ({
    digest: evidenceDigest,
    iri,
  }))),
);

function reevaluation(values, binding = sourceBinding()) {
  const aggregateEvidenceDigest = evidenceSetDigest(values);
  const aggregateSourceDigest = aggregateCompilerProofInternals.sourceBindingDigest(binding);
  const publicationReceipt = immutablePublicationReceipt({
    action_state: 'UNRESOLVED_FAIL_CLOSED',
    authority_after_digest: authorityAfterDigest,
    authority_before_digest: authorityPreDigest,
    authority_domain: 'urn:usf:capabilityowner:semanticmodelcompilation',
    authority_publication_digest: authorityAfterDigest,
    candidate_approval_envelope_digest: digest('candidate-approval-envelope'),
    candidate_digest: digest('candidate'),
    committed_candidate_state: 'COMMITTED',
    current_proof_results: 0,
    direct_provisional_aggregate_selections: 1,
    grant_consumed: true,
    grant_nonce: '018f6b3c-7d2e-4a91-8c5f-123456789abc',
    owner_assignment_envelope_digest: digest('owner-assignment-envelope'),
    proof_currentness: 'PENDING',
    projection_observation_receipt_digest: digest('projection-observation-receipt'),
    protocol: 'semantic-proof-v1',
    publication_grant_envelope_digest: digest('publication-grant-envelope'),
    publication_outcome: 'committed_pending_reevaluation',
    publication_phase: 'initial',
    published_at: publishedAt,
    reevaluation_authority_digest: null,
    reevaluation_evaluation_receipt_digest: null,
    reevaluation_execution_receipt_digest: null,
    repository: AGGREGATE_REPOSITORY,
    schema_version: 1,
    selected_aggregate_result: null,
    selected_provisional_aggregate_result: 'urn:usf:proofresult:aggregatecompilersemanticenforcement',
    source_scope_digest: binding.sourceScopeDigest,
    terminal_state: 'PENDING',
  });
  const executionReceipt = immutableJson({
    algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
    algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
    authorityAfterDigest,
    completedAt,
    componentSetDigest: COMPONENT_SET_DIGEST,
    evidenceSetDigest: aggregateEvidenceDigest,
    publicationReceiptDigest: publicationReceipt.digest,
    schema: 'aggregate-post-publication-execution-v1',
    sourceBindingDigest: aggregateSourceDigest,
    startedAt,
  });
  const evaluationReceipt = immutableJson({
    algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
    algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
    authorityAfterDigest,
    componentSetDigest: COMPONENT_SET_DIGEST,
    evaluatedAt,
    evidenceSetDigest: aggregateEvidenceDigest,
    executionReceiptDigest: executionReceipt.digest,
    publicationReceiptDigest: publicationReceipt.digest,
    resultState: 'passed',
    schema: 'aggregate-post-publication-evaluation-v1',
    sourceBindingDigest: aggregateSourceDigest,
  });
  return { evaluationReceipt, executionReceipt, publicationReceipt };
}

function postRun(overrides = {}) {
  const values = overrides.components || components();
  const binding = overrides.sourceBinding || sourceBinding();
  const postPublicationReevaluation = Object.hasOwn(overrides, 'postPublicationReevaluation')
    ? overrides.postPublicationReevaluation : reevaluation(values, binding);
  return evaluateAggregateCompilerProof({
    algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
    authorityDigest: authorityAfterDigest,
    components: values,
    evaluatedAt,
    phase: 'post-publication',
    postPublicationReevaluation,
    sourceBinding: binding,
    sourceBindingDependency,
    sourceRepositoryPath: repositoryPath,
    ...overrides,
  });
}

function replaceCurrentness(value, changes) {
  const snapshotValue = { ...jsonValue(value.currentness.snapshot), ...changes };
  const snapshot = immutableJson(snapshotValue);
  const projectionValue = {
    ...jsonValue(value.currentness.projectionReceipt),
    authorityDigest: snapshotValue.authorityDigest,
    producedAt: snapshotValue.observedAt,
    snapshotDigest: snapshot.digest,
  };
  return { ...value, currentness: { projectionReceipt: immutableJson(projectionValue), snapshot } };
}

test('component dimensions use the compact SHACL values', () => {
  assert.deepEqual(COMPONENT_PROOFS.map(({ dimension }) => dimension), [
    'compilercontractbehaviour',
    'hermeticsubstitutebehaviour',
    'importedauthoritycounterfactualadequacy',
    'liveauthoritycontrol',
  ]);
});

test('pre-publication preparation is PENDING and never passing or selectable', () => {
  const result = evaluateAggregateCompilerProof({
    authorityDigest: authorityPreDigest,
    components: components(authorityPreDigest).map((value) => replaceCurrentness(value, {
      observedAt: '2026-08-01T10:59:00Z',
      validFrom: '2026-08-01T10:00:00Z',
    })),
    evaluatedAt: preEvaluationTime,
    phase: 'pre-publication',
    sourceBinding: sourceBinding(),
    sourceBindingDependency,
    sourceRepositoryPath: repositoryPath,
  });
  assert.equal(result.passed, false);
  assert.equal(result.selectable, false);
  assert.equal(result.resultState, 'PENDING');
  assert.equal(result.proofCurrentness, 'PENDING');
  assert.throws(() => evaluateAggregateCompilerProof({
    authorityDigest: authorityPreDigest,
    components: components(authorityPreDigest).map((value) => replaceCurrentness(value, {
      observedAt: '2026-08-01T10:59:00Z',
      validFrom: '2026-08-01T10:00:00Z',
    })),
    evaluatedAt: preEvaluationTime,
    phase: 'pre-publication',
    postPublicationReevaluation: {},
    sourceBinding: sourceBinding(),
    sourceBindingDependency,
    sourceRepositoryPath: repositoryPath,
  }), /PREPARATION_REEVALUATION_FORBIDDEN/);
});

test('post-publication reevaluation passes with immutable historical bindings preserved', () => {
  const result = postRun();
  assert.equal(result.passed, true);
  assert.equal(result.selectable, true);
  assert.equal(result.proofCurrentness, 'CURRENT');
  assert.equal(result.evaluation.components.length, 4);
  assert.equal(result.evaluation.components[0].currentness.authorityDigest, authorityAfterDigest);
  assert.notEqual(result.evaluation.components[0].historicalResult.authorityBindingDigest, authorityAfterDigest);
  assert.equal(result.evaluation.components.find(({ result: componentResult }) => (
    componentResult === 'urn:usf:proofresult:compilercontractbehaviour'
  )).historicalResult.sourceBinding.proofAlgorithm,
    'urn:usf:proofalgorithm:aggregatefixture0');
  assert.equal('head' in result.evaluation.components[0].historicalResult.sourceBinding, false);
  assert.equal(Object.isFrozen(result.evaluation.components[0].historicalResult.sourceBinding), true);
  assert.throws(() => {
    result.evaluation.components[0].historicalResult.authorityBindingDigest = authorityAfterDigest;
  }, TypeError);
  assert.throws(() => {
    result.evaluation.components[0].evidenceReferences.push(immutableEvidence(99));
  }, TypeError);
});

test('historical source identity cannot be replaced with aggregate Git HEAD and tree', () => {
  const values = components();
  values[0] = {
    ...values[0],
    historicalResult: immutableJson({
      ...jsonValue(values[0].historicalResult),
      sourceBinding: sourceBinding(),
    }),
  };
  assert.throws(() => postRun({ components: values }), /HISTORICAL_SOURCE_BINDING_INVALID/);
});

test('historical results reject fabricated execution and evaluation receipt digests', () => {
  const values = components();
  values[0] = {
    ...values[0],
    historicalResult: immutableJson({
      ...jsonValue(values[0].historicalResult),
      evaluationReceiptDigest: digest('fabricated-historical-evaluation-receipt'),
      executionReceiptDigest: digest('fabricated-historical-execution-receipt'),
    }),
  };
  assert.throws(() => postRun({ components: values }), /HISTORICAL_RESULT_INVALID/);
});

test('evidence digests are recomputed and caller-supplied verification is rejected', () => {
  const tampered = components();
  tampered[0] = {
    ...tampered[0],
    evidenceReferences: [{ ...tampered[0].evidenceReferences[0], digest: digest('substituted') }],
  };
  assert.throws(() => postRun({ components: tampered }), /EVIDENCE_DIGEST_MISMATCH/);

  const asserted = components();
  asserted[0] = {
    ...asserted[0],
    evidenceReferences: [{ ...asserted[0].evidenceReferences[0], verified: true }],
  };
  assert.throws(() => postRun({ components: asserted }), /EVIDENCE_INVALID/);

  const orphan = components();
  orphan[0] = {
    ...orphan[0],
    evidenceReferences: [{ ...orphan[0].evidenceReferences[0], digest: ORPHANED_ATTESTATION_DIGEST }],
  };
  assert.throws(() => postRun({ components: orphan }), /ORPHAN_EVIDENCE_REJECTED/);
});

test('evidence identity and bytes are globally unique across all dimensions', () => {
  const values = components();
  values[1] = component(1, { evidence: values[0].evidenceReferences[0] });
  assert.throws(() => postRun({ components: values }), /DUPLICATE_EVIDENCE/);
});

test('the exact two hermetic descriptors may be shared only by the exact two component results', () => {
  const completeSharing = SHARED_HERMETIC_RESULTS.map((result) => ({
    descriptors: SHARED_HERMETIC_EVIDENCE.map((descriptor) => ({ ...descriptor })),
    result,
  }));
  const aggregateDescriptors = aggregateCompilerProofInternals.aggregateEvidenceDescriptors(completeSharing);
  assert.deepEqual(aggregateDescriptors, SHARED_HERMETIC_EVIDENCE.map((descriptor) => ({ ...descriptor })));
  assert.equal(
    aggregateCompilerProofInternals.descriptorSetDigest(aggregateDescriptors),
    aggregateCompilerProofInternals.descriptorSetDigest(SHARED_HERMETIC_EVIDENCE),
  );

  const partial = structuredClone(completeSharing);
  partial[1].descriptors.pop();
  assert.throws(() => aggregateCompilerProofInternals.aggregateEvidenceDescriptors(partial),
    /SHARED_EVIDENCE_INCOMPLETE/);

  const substituted = structuredClone(completeSharing);
  substituted[0].descriptors[0].digest = digest('substituted-shared-evidence');
  assert.throws(() => aggregateCompilerProofInternals.aggregateEvidenceDescriptors(substituted),
    /SHARED_EVIDENCE_SUBSTITUTED/);

  const wrongResult = structuredClone(completeSharing);
  wrongResult.push({
    descriptors: [{ ...SHARED_HERMETIC_EVIDENCE[0] }],
    result: 'urn:usf:proofresult:importedauthoritycounterfactualadequacy',
  });
  assert.throws(() => aggregateCompilerProofInternals.aggregateEvidenceDescriptors(wrongResult),
    /SHARED_EVIDENCE_SUBSTITUTED/);
});

test('the exact live-authority descriptors may share their exact verified CAS bytes', () => {
  const completeSharing = SHARED_LIVE_AUTHORITY_RESULTS.map((result) => ({
    descriptors: SHARED_LIVE_AUTHORITY_EVIDENCE.map((descriptor) => ({ ...descriptor })),
    result,
  }));
  assert.deepEqual(
    aggregateCompilerProofInternals.aggregateEvidenceDescriptors(completeSharing),
    SHARED_LIVE_AUTHORITY_EVIDENCE.map((descriptor) => ({ ...descriptor })),
  );

  const partial = structuredClone(completeSharing);
  partial[0].descriptors.pop();
  assert.throws(() => aggregateCompilerProofInternals.aggregateEvidenceDescriptors(partial),
    /SHARED_EVIDENCE_INCOMPLETE/);

  const substituted = structuredClone(completeSharing);
  substituted[0].descriptors[0].digest = digest('substituted-live-authority-evidence');
  assert.throws(() => aggregateCompilerProofInternals.aggregateEvidenceDescriptors(substituted),
    /SHARED_EVIDENCE_SUBSTITUTED/);
});

test('every non-exempt duplicate evidence IRI or digest remains rejected', () => {
  assert.throws(() => aggregateCompilerProofInternals.aggregateEvidenceDescriptors([
    { result: COMPONENT_PROOFS[0].result, descriptors: [{ iri: 'urn:usf:evidence:a', digest: digest('a') }] },
    { result: COMPONENT_PROOFS[1].result, descriptors: [{ iri: 'urn:usf:evidence:a', digest: digest('b') }] },
  ]), /DUPLICATE_EVIDENCE/);
  assert.throws(() => aggregateCompilerProofInternals.aggregateEvidenceDescriptors([
    { result: COMPONENT_PROOFS[0].result, descriptors: [{ iri: 'urn:usf:evidence:a', digest: digest('same') }] },
    { result: COMPONENT_PROOFS[1].result, descriptors: [{ iri: 'urn:usf:evidence:b', digest: digest('same') }] },
  ]), /DUPLICATE_EVIDENCE/);
});

test('missing, duplicate and unexpected components fail closed', () => {
  assert.throws(() => postRun({ components: components().slice(1) }), /MISSING_COMPONENT/);
  const duplicate = components();
  duplicate[1] = { ...duplicate[0] };
  assert.throws(() => postRun({ components: duplicate }), /DUPLICATE_COMPONENT/);
  const unexpected = components();
  unexpected[0] = { ...unexpected[0], result: 'urn:usf:proofresult:unexpected' };
  assert.throws(() => postRun({ components: unexpected }), /UNEXPECTED_COMPONENT/);
});

test('authority-derived currentness rejects failure, staleness, invalidation and supersession', () => {
  for (const [changes, pattern] of [
    [{ resultState: 'failed' }, /COMPONENT_FAILED/],
    [{ validUntil: evaluatedAt }, /COMPONENT_STALE/],
    [{ invalidated: true }, /COMPONENT_INVALIDATED/],
    [{ supersededBy: 'urn:usf:proofresult:replacement' }, /SUPERSESSION_UNRESOLVED/],
    [{ authorityDigest: authorityPreDigest }, /CURRENTNESS_AUTHORITY_MISMATCH/],
  ]) {
    const values = components();
    values[0] = replaceCurrentness(values[0], changes);
    assert.throws(() => postRun({ components: values }), pattern);
  }
});

test('currentness snapshot must bind the exact admitted evidence and projection receipt', () => {
  const values = components();
  values[0] = replaceCurrentness(values[0], { admittedEvidence: [{ iri: 'urn:usf:evidence:other', digest: digest('other') }] });
  assert.throws(() => postRun({ components: values }), /CURRENTNESS_EVIDENCE_MISMATCH/);

  const receiptTampered = components();
  receiptTampered[0] = {
    ...receiptTampered[0],
    currentness: {
      ...receiptTampered[0].currentness,
      projectionReceipt: {
        ...receiptTampered[0].currentness.projectionReceipt,
        digest: digest('tampered-projection'),
      },
    },
  };
  assert.throws(() => postRun({ components: receiptTampered }), /IMMUTABLE_RECORD_DIGEST_MISMATCH/);
});

test('aggregate source binding verifies repository, scope, reachable HEAD and exact tree', () => {
  assert.equal(GIT_EXECUTABLE, '/usr/bin/git');
  assert.equal(sourceBinding().sourceScopeDigest, protocolSourceScopeDigest(sourcePaths));
  assert.equal(sourceBinding().sourceScopeDigest, aggregateCompilerProofInternals.sourceScopeDigest(sourcePaths));
  assert.notEqual(sourceBinding().sourceScopeDigest, digest(aggregateCompilerProofInternals.canonicalJson({
    repository: AGGREGATE_REPOSITORY,
    sourcePaths,
  })));
  assert.throws(() => postRun({ sourceBinding: { ...sourceBinding(), repository: 'maldous/other' } }),
    /SOURCE_REPOSITORY_MISMATCH/);
  assert.throws(() => postRun({ sourceBinding: { ...sourceBinding(), sourceScopeDigest: digest('wrong-scope') } }),
    /SOURCE_SCOPE_DIGEST_MISMATCH/);
  assert.throws(() => postRun({ sourceBinding: { ...sourceBinding(), head: 'f'.repeat(40) } }),
    /SOURCE_HEAD_UNREACHABLE/);
  assert.throws(() => postRun({ sourceBinding: { ...sourceBinding(), tree: 'e'.repeat(40) } }),
    /SOURCE_TREE_MISMATCH/);
  assert.throws(() => postRun({
    sourceBindingDependency: () => ({ status: 0, stderr: '', stdout: sourceHead, unexpected: true }),
  }), /SOURCE_DEPENDENCY_INVALID/);
  assert.throws(() => postRun({
    sourceBindingDependency: () => { throw new Error('dependency unavailable'); },
  }), /SOURCE_DEPENDENCY_FAILURE/);
});

test('passing always requires immutable post-publication receipts', () => {
  assert.throws(() => postRun({ postPublicationReevaluation: null }), /REEVALUATION_REQUIRED/);
  const value = reevaluation(components(), sourceBinding());
  value.executionReceipt = { ...value.executionReceipt, digest: digest('tampered-execution') };
  assert.throws(() => postRun({ postPublicationReevaluation: value }), /IMMUTABLE_RECORD_DIGEST_MISMATCH/);
});

test('publication receipt is the LF-framed Semantic Proof Protocol v1 INITIAL receipt', () => {
  const wrongGrant = reevaluation(components(), sourceBinding());
  wrongGrant.publicationReceipt = immutablePublicationReceipt({
    ...JSON.parse(Buffer.from(wrongGrant.publicationReceipt.bytesBase64, 'base64').toString('utf8')),
    grant_consumed: false,
  });
  assert.throws(() => postRun({ postPublicationReevaluation: wrongGrant }), /PUBLICATION_RECEIPT_INVALID/);

  const unframed = reevaluation(components(), sourceBinding());
  const receipt = JSON.parse(Buffer.from(unframed.publicationReceipt.bytesBase64, 'base64').toString('utf8'));
  unframed.publicationReceipt = immutableJson(receipt);
  assert.throws(() => postRun({ postPublicationReevaluation: unframed }), /PUBLICATION_RECEIPT_INVALID/);

  const missingPublishedAt = reevaluation(components(), sourceBinding());
  const incompleteReceipt = JSON.parse(Buffer.from(
    missingPublishedAt.publicationReceipt.bytesBase64, 'base64',
  ).toString('utf8'));
  delete incompleteReceipt.published_at;
  missingPublishedAt.publicationReceipt = immutablePublicationReceipt(incompleteReceipt);
  assert.throws(() => postRun({ postPublicationReevaluation: missingPublishedAt }),
    /PUBLICATION_RECEIPT_INVALID/);
});

test('reevaluation rejects algorithm, evidence, source and receipt-link substitutions', () => {
  for (const [field, replacement] of [
    ['algorithmDigest', digest('other-algorithm')],
    ['evidenceSetDigest', digest('other-evidence')],
    ['sourceBindingDigest', digest('other-source')],
    ['publicationReceiptDigest', digest('other-publication')],
  ]) {
    const value = reevaluation(components(), sourceBinding());
    const execution = immutableJson({ ...jsonValue(value.executionReceipt), [field]: replacement });
    value.executionReceipt = execution;
    value.evaluationReceipt = immutableJson({
      ...jsonValue(value.evaluationReceipt),
      executionReceiptDigest: execution.digest,
    });
    assert.throws(() => postRun({ postPublicationReevaluation: value }), /POST_PUBLICATION_BINDING_MISMATCH/);
  }
});

test('reevaluation rejects pre-publication snapshots and untrusted ordering', () => {
  const prePublicationComponents = components().map((value) => replaceCurrentness(value, {
    observedAt: '2026-08-01T11:59:59Z',
    validFrom: '2026-08-01T11:00:00Z',
  }));
  assert.throws(() => postRun({
    components: prePublicationComponents,
    postPublicationReevaluation: reevaluation(prePublicationComponents, sourceBinding()),
  }), /CURRENTNESS_NOT_POST_PUBLICATION/);

  const value = reevaluation(components(), sourceBinding());
  const execution = immutableJson({ ...jsonValue(value.executionReceipt), startedAt: '2026-08-01T12:03:01Z' });
  value.executionReceipt = execution;
  value.evaluationReceipt = immutableJson({
    ...jsonValue(value.evaluationReceipt),
    executionReceiptDigest: execution.digest,
  });
  assert.throws(() => postRun({ postPublicationReevaluation: value }), /POST_PUBLICATION_ORDER_INVALID/);
});

test('algorithm and historical evidence bindings cannot be substituted', () => {
  assert.throws(() => postRun({ algorithmVersion: '3.0.0' }), /ALGORITHM_VERSION_MISMATCH/);
  const values = components();
  values[0] = {
    ...values[0],
    historicalResult: immutableJson({
      ...jsonValue(values[0].historicalResult),
      evidenceSet: [{ digest: digest('unrelated-evidence'), iri: 'urn:usf:evidence:unrelated' }],
    }),
  };
  assert.throws(() => postRun({ components: values }), /HISTORICAL_RESULT_BINDING_MISMATCH/);
});
