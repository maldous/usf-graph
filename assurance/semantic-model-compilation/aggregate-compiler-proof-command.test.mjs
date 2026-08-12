import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  AGGREGATE_RESULT_IRI,
  AGGREGATE_REVIEWED_SOURCE_PATHS,
  DEFAULT_AGGREGATE_REACHABLE_REF,
  EVENT_HISTORY_CHECKPOINT_DEPENDENCY_PATHS,
  EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS,
  PROVISIONAL_AGGREGATE_RESULT_IRI,
  assertEventHistoryCheckpointWorktreeBinding,
  createAggregateCompilerProofProducer,
  eventHistoryCheckpointEvidenceCore,
  eventHistoryCheckpointFactoryEnvironment,
  eventHistoryCheckpointGpgHome,
  eventHistoryCheckpointImplementationScopeDigest,
  eventHistoryCheckpointPythonPath,
} from './aggregate-compiler-proof-command.mjs';
import {
  COMPONENT_PROOFS,
  ORPHANED_ATTESTATION_DIGEST,
  aggregateCompilerProofInternals,
  evaluateAggregateCompilerProof,
} from './aggregate-compiler-proof.mjs';
import { canonicalJson as semanticProofCanonicalJson, publicationReceiptDigest } from '../../processes/semantic-assurance/semantic-proof-v1.mjs';
import { semanticModelCompilationCommandInternals } from '../../processes/semantic-assurance/semantic-model-compilation-command.mjs';

const roots = [];
const D0 = `sha256:${'0'.repeat(64)}`;
const D1 = `sha256:${'1'.repeat(64)}`;
const D2 = `sha256:${'2'.repeat(64)}`;
const HISTORICAL = `sha256:${'a'.repeat(64)}`;
const CANDIDATE = `sha256:${'c'.repeat(64)}`;
const TRUSTED_AT = '2026-08-01T00:10:00Z';
const binding = (value) => ({ value: String(value) });
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const CHILD_PROCESS_DENIED = process.env.USF_EXPECTED_CHILD_PROCESS_PERMISSION === 'denied';
const PERMISSION_MODEL_ENABLED = process.permission !== undefined;
const IN_PROCESS_HEAD = 'd'.repeat(40);
const IN_PROCESS_TREE = 'e'.repeat(40);
const IN_PROCESS_REPOSITORY = '/in-process-permission-fixture';
const requiredHistoryMode = ['lin', 'ear'].join('');
const oneParentHistoryShape = ['one-parent-lin', 'ear'].join('');
const ACTIVE_AUTHORITY_SOURCE = `<urn:usf:ownerassignment:test> a <urn:usf:ontology:OwnerAssignment>;
  <urn:usf:ontology:assignmentState> "active".\n`;
const pendingInitialProjection = (overrides = {}) => ({
  actionState: 'BLOCK',
  contractState: {
    activation: 'urn:usf:contractactivationstate:proofblocked',
    decision: 'urn:usf:decisionstate:accepted',
    lifecycle: 'urn:usf:semanticlifecyclestate:active',
    proof: null,
  },
  proofCurrentness: {
    perProof: [{
      currentAuthorityDigest: D1,
      proofResult: PROVISIONAL_AGGREGATE_RESULT_IRI,
      reevaluationState: 'urn:usf:proofreevaluationstate:pending',
    }],
    proofResults: [PROVISIONAL_AGGREGATE_RESULT_IRI],
    reasons: ['proof-currentness-ambiguous', 'proof-currentness-unresolved'],
    state: 'STALE_BLOCK',
    stateIri: 'urn:usf:proofcurrentnessstate:staleblock',
  },
  authorityDigest: D1,
  ...overrides,
});
const EXPECTED_REVIEWED_SOURCE_PATHS = Object.freeze([
  'assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.test.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof-command.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof-command.test.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof.test.mjs',
  'package-lock.json',
  'package.json',
  'processes/semantic-assurance/compiler-proof-command.mjs',
  'processes/semantic-assurance/proof-currentness.mjs',
  'processes/semantic-assurance/proof-currentness.test.mjs',
  'processes/semantic-assurance/repository-materialisation-gateway.mjs',
  'processes/semantic-assurance/repository-materialisation-gateway.test.mjs',
  'processes/semantic-assurance/semantic-authority-publication.mjs',
  'processes/semantic-assurance/semantic-authority-publication.test.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.test.mjs',
  'processes/semantic-assurance/semantic-proof-v1.mjs',
  'processes/semantic-assurance/semantic-proof-v1.test.mjs',
  'processes/semantic-assurance/semantic-proof-v2.mjs',
  'processes/semantic-assurance/semantic-proof-v2.test.mjs',
  'semantic-model/assurance/evidence.trig',
  'semantic-model/assurance/proofs.trig',
  'semantic-model/authority.ttl',
  'semantic-model/contracts/capabilities.trig',
  'semantic-model/manifest.yaml',
  'semantic-model/ontology.ttl',
  'semantic-model/permutation/families.trig',
  'semantic-model/realisation/bindings.trig',
  'semantic-model/rules/evidence.rq',
  'semantic-model/shapes/assurance.ttl',
  'semantic-model/vocabulary.ttl',
]);

const EXPECTED_EVENT_HISTORY_CHECKPOINT_PATHS = Object.freeze([
  'src/usf_factory/cli.py',
  'src/usf_factory/event_store.py',
  'src/usf_factory/maintenance.py',
  'src/usf_factory/v3_events.py',
  'tests/test_v3_event_store.py',
  'tests/test_v3_maintenance.py',
]);

const checkpointRecord = (path) => Object.freeze({
  byteSize: path.length,
  digest: sha256(Buffer.from(`${path}\n`)),
  path,
});
const checkpointCommand = (id, exitStatus = 0) => Object.freeze({
  arguments: [],
  executable: '/usr/bin/true',
  exitStatus,
  id,
  signal: null,
  stderrDigest: sha256(Buffer.alloc(0)),
  stdoutDigest: sha256(Buffer.alloc(0)),
});
const checkpointEvidenceInput = (overrides = {}) => ({
  authorityDigest: D0,
  candidateCommit: 'a'.repeat(40),
  commands: [
    checkpointCommand('focused-checkpoint-pruning'),
    checkpointCommand('admission-critical'),
    checkpointCommand('complete-owner-service-gate'),
  ],
  dependencyRecords: EVENT_HISTORY_CHECKPOINT_DEPENDENCY_PATHS.map(checkpointRecord),
  evaluatedAt: '2026-08-11T00:00:00Z',
  factoryTree: 'b'.repeat(40),
  implementationRecords: EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS.map(checkpointRecord),
  proofAlgorithmSourceDigest: `sha256:${'f'.repeat(64)}`,
  protectedCommit: 'c'.repeat(40),
  validUntil: '2026-08-12T00:00:00Z',
  ...overrides,
});

test('event-history checkpoint evidence has an exact bounded Factory source scope', () => {
  assert.deepEqual(EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS, EXPECTED_EVENT_HISTORY_CHECKPOINT_PATHS);
  assert.equal(
    eventHistoryCheckpointImplementationScopeDigest(),
    'sha256:a0edf0a8cb3f6fbb3805aac5b98083603d56b63a838eda88424181a3e60783a4',
  );
  for (const prohibited of [
    'src/usf_factory/activation.py',
    'src/usf_factory/checkpoint_replay.py',
    'src/usf_factory/pruning_policy.py',
    'processes/semantic-assurance/semantic-proof-v2.mjs',
  ]) {
    assert.equal(EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS.includes(prohibited), false, prohibited);
    assert.equal(EVENT_HISTORY_CHECKPOINT_DEPENDENCY_PATHS.includes(prohibited), false, prohibited);
  }
  assert.equal(
    EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS.some(
      (path) => EVENT_HISTORY_CHECKPOINT_DEPENDENCY_PATHS.includes(path),
    ),
    false,
  );
  const collectorSource = readFileSync(new URL('./aggregate-compiler-proof-command.mjs', import.meta.url), 'utf8');
  assert.match(collectorSource, /createCasEvidenceStore\(casRoot\)/u);
});

test('event-history checkpoint evidence is deterministic, closed and never vacuously eligible', () => {
  const input = checkpointEvidenceInput();
  const first = eventHistoryCheckpointEvidenceCore(input);
  const second = eventHistoryCheckpointEvidenceCore(structuredClone(input));
  assert.deepEqual(second, first);
  assert.equal(first.passed, true);
  assert.equal(first.eligibleForAdmission, true);
  assert.equal(first.productionWrites, 0);
  assert.equal(first.providerContacts, 0);

  const failed = eventHistoryCheckpointEvidenceCore(checkpointEvidenceInput({
    commands: [
      checkpointCommand('focused-checkpoint-pruning'),
      checkpointCommand('admission-critical', 1),
      checkpointCommand('complete-owner-service-gate'),
    ],
  }));
  assert.equal(failed.passed, false);
  assert.equal(failed.eligibleForAdmission, false);
  assert.throws(
    () => eventHistoryCheckpointEvidenceCore({ ...checkpointEvidenceInput(), undeclared: true }),
    { code: 'EVENT_HISTORY_CHECKPOINT_EVIDENCE_INPUT_NOT_CLOSED' },
  );
  assert.throws(
    () => eventHistoryCheckpointEvidenceCore(checkpointEvidenceInput({ commands: [] })),
    { code: 'EVENT_HISTORY_CHECKPOINT_EVIDENCE_COMMAND_SET_INVALID' },
  );
  assert.throws(
    () => eventHistoryCheckpointImplementationScopeDigest(
      EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS.slice(1),
    ),
    { code: 'EVENT_HISTORY_CHECKPOINT_SOURCE_SCOPE_NOT_EXACT' },
  );
});

test('event-history checkpoint evidence binds the exact signed candidate and its verifier environment', () => {
  const candidateCommit = 'a'.repeat(40);
  const protectedCommit = 'b'.repeat(40);
  const expectedTree = 'c'.repeat(40);
  const exact = {
    candidateCommit,
    candidateTree: expectedTree,
    expectedTree,
    protectedCommit,
    protectedTree: expectedTree,
    status: '',
    worktreeHead: candidateCommit,
  };
  assert.equal(assertEventHistoryCheckpointWorktreeBinding(exact), true);
  assert.throws(
    () => assertEventHistoryCheckpointWorktreeBinding({
      ...exact,
      worktreeHead: 'd'.repeat(40),
    }),
    { code: 'EVENT_HISTORY_CHECKPOINT_FACTORY_WORKTREE_HEAD_MISMATCH' },
  );
  assert.throws(
    () => assertEventHistoryCheckpointWorktreeBinding({
      ...exact,
      protectedTree: 'e'.repeat(40),
    }),
    { code: 'EVENT_HISTORY_CHECKPOINT_FACTORY_TREE_IDENTITY_MISMATCH' },
  );
  assert.equal(
    eventHistoryCheckpointPythonPath('/factory-reviewed', '/factory-reviewed/.venv/bin/python'),
    '/factory-reviewed/.venv/bin/python',
  );
  assert.throws(
    () => eventHistoryCheckpointPythonPath('/factory-reviewed', '/factory-deployed/.venv/bin/python'),
    { code: 'EVENT_HISTORY_CHECKPOINT_PYTHON_SOURCE_MISMATCH' },
  );
  const environmentRoot = mkdtempSync(join(tmpdir(), 'checkpoint-gpg-home-'));
  roots.push(environmentRoot);
  const gpgHome = join(environmentRoot, '.gnupg');
  mkdirSync(gpgHome);
  assert.equal(eventHistoryCheckpointGpgHome({ HOME: environmentRoot }), gpgHome);
  assert.equal(eventHistoryCheckpointGpgHome({ GNUPGHOME: gpgHome }), gpgHome);
  assert.throws(
    () => eventHistoryCheckpointGpgHome({ HOME: join(environmentRoot, 'missing') }),
    { code: 'EVENT_HISTORY_CHECKPOINT_GPG_HOME_INVALID' },
  );
  const sourceBoundEnvironment = eventHistoryCheckpointFactoryEnvironment(
    '/factory-reviewed',
    '/factory-reviewed/.venv/bin/python',
    { HOME: '/operator', PATH: '/foreign/bin', PYTHONPATH: '/foreign/src' },
  );
  assert.equal(sourceBoundEnvironment.HOME, '/operator');
  assert.equal(
    sourceBoundEnvironment.PATH,
    `/factory-reviewed/.venv/bin:${dirname(process.execPath)}:/usr/bin:/bin`,
  );
  assert.equal(sourceBoundEnvironment.PYTHONPATH, '/factory-reviewed/src');
  assert.equal(sourceBoundEnvironment.TZ, 'UTC');
});

test.after(() => roots.forEach((root) => rmSync(root, { recursive: true, force: true })));

function git(cwd, ...args) {
  const result = spawnSync('/usr/bin/git', ['-C', cwd, ...args], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function inProcessSourceBinding({ reachableFrom, sourcePaths }) {
  return {
    head: IN_PROCESS_HEAD,
    reachableFrom,
    repository: 'maldous/usf-graph',
    sourcePaths,
    sourceScopeDigest: aggregateCompilerProofInternals.sourceScopeDigest(sourcePaths),
    tree: IN_PROCESS_TREE,
  };
}

function inProcessGitDependency({ args, executable, repositoryPath }) {
  const success = (stdout = '') => ({ status: 0, stderr: '', stdout });
  const failure = () => ({ status: 1, stderr: 'fixture source binding mismatch', stdout: '' });
  if (executable !== '/usr/bin/git' || repositoryPath !== IN_PROCESS_REPOSITORY) return failure();
  if (args[0] === 'rev-parse' && args[1] === '--verify' && args.length === 3) {
    if (args[2] === `${IN_PROCESS_HEAD}^{commit}` || args[2] === 'refs/heads/main^{commit}'
        || args[2] === `${DEFAULT_AGGREGATE_REACHABLE_REF}^{commit}`) return success(IN_PROCESS_HEAD);
    return failure();
  }
  if (args[0] === 'merge-base' && args[1] === '--is-ancestor' && args.length === 4) {
    return args[2] === IN_PROCESS_HEAD
      && ['refs/heads/main', DEFAULT_AGGREGATE_REACHABLE_REF].includes(args[3]) ? success() : failure();
  }
  if (args[0] === 'rev-parse' && args.length === 2 && args[1] === `${IN_PROCESS_HEAD}^{tree}`) {
    return success(IN_PROCESS_TREE);
  }
  if (args[0] === 'cat-file' && args[1] === '-e' && args.length === 3) {
    return AGGREGATE_REVIEWED_SOURCE_PATHS.some((path) => args[2] === `${IN_PROCESS_HEAD}:${path}`)
      ? success() : failure();
  }
  return failure();
}

function inProcessEvaluateProof(input) {
  return evaluateAggregateCompilerProof({
    ...input,
    sourceBindingDependency: inProcessGitDependency,
    sourceRepositoryPath: IN_PROCESS_REPOSITORY,
  });
}

function fixture({ authoritySource = ACTIVE_AUTHORITY_SOURCE, explicitBranch = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'aggregate-producer-'));
  roots.push(root);
  const repositoryPath = join(root, 'repo');
  const casRoot = join(root, 'cas');
  mkdirSync(repositoryPath);
  mkdirSync(casRoot);
  for (const path of AGGREGATE_REVIEWED_SOURCE_PATHS) {
    const target = join(repositoryPath, path);
    mkdirSync(join(target, '..'), { recursive: true });
    writeFileSync(target, path === 'semantic-model/authority.ttl' ? authoritySource : `${path}\n`);
  }
  if (!CHILD_PROCESS_DENIED) {
    git(repositoryPath, 'init', '-q', '-b', 'main');
    git(repositoryPath, 'config', 'user.name', 'Aggregate Test');
    git(repositoryPath, 'config', 'user.email', 'aggregate@example.invalid');
    git(repositoryPath, 'add', '.');
    git(repositoryPath, 'commit', '-q', '-m', 'fixture');
    git(repositoryPath, 'update-ref', DEFAULT_AGGREGATE_REACHABLE_REF, 'HEAD');
  }
  const injected = {
    ...((CHILD_PROCESS_DENIED || PERMISSION_MODEL_ENABLED) ? {
      evaluateProof: inProcessEvaluateProof,
      readSourceText: ({ path }) => path === 'semantic-model/authority.ttl' ? authoritySource : `${path}\n`,
      resolveSourceBinding: inProcessSourceBinding,
    } : {}),
    ...(PERMISSION_MODEL_ENABLED ? { syncDescriptor: () => {} } : {}),
  };
  return explicitBranch
    ? { ...injected, casRoot, repositoryPath, reachableFrom: 'refs/heads/main' }
    : { ...injected, casRoot, repositoryPath };
}

function casPath(root, contentDigest) {
  const hex = contentDigest.slice(7);
  return join(root, 'sha256', hex.slice(0, 2), hex);
}

function putCas(root, bytes, claimed = sha256(bytes)) {
  const path = casPath(root, claimed);
  mkdirSync(join(path, '..'), { recursive: true });
  if (existsSync(path)) {
    assert.deepEqual(readFileSync(path), bytes);
    return claimed;
  }
  writeFileSync(path, bytes);
  return claimed;
}

function putJson(root, value) {
  return putCas(root, Buffer.from(aggregateCompilerProofInternals.canonicalJson(value), 'utf8'));
}

function memoryProtocolJournal() {
  const ledger = { nonces: {} };
  const clone = (value) => JSON.parse(semanticProofCanonicalJson(value));
  const current = (grant) => ledger.nonces[grant.nonce];
  const update = (grant, transform) => {
    const next = transform(current(grant));
    ledger.nonces[grant.nonce] = next;
    return Object.freeze({ nonce: grant.nonce, ...clone(next) });
  };
  return Object.freeze({
    reserveGrantNonce(grant, { observedAt, publicationPhase }) {
      return update(grant, (record) => {
        if (record) throw new Error('publication grant nonce was replayed or already entered the transaction journal');
        return {
          authority_pre_digest: grant.authority_pre_digest,
          candidate_digest: grant.candidate_digest,
          grant_envelope_digest: grant.envelope_digest,
          publication_outcome: 'pending', publication_phase: publicationPhase,
          reserved_at: observedAt, state: 'reserved',
        };
      });
    },
    readPublicationTransaction(grant) { return current(grant) ? Object.freeze(clone(current(grant))) : null; },
    readPublicationTransactionForEnvelope(envelope) {
      const record = ledger.nonces[envelope?.payload?.nonce];
      return record ? Object.freeze(clone(record)) : null;
    },
    recordPublicationOutcome(grant, {
      authorityPublicationDigest, committedCandidateState, observedAt, publishedAt,
    }) {
      return update(grant, (record) => ({
        ...record, authority_publication_digest: authorityPublicationDigest,
        committed_at: observedAt, committed_candidate_state: committedCandidateState,
        publication_outcome: 'committed', published_at: publishedAt,
        state: 'published_pending_reevaluation',
      }));
    },
    recordInitialProjectionObservation(grant, observation, { observedAt }) {
      return update(grant, (record) => ({
        ...record,
        initial_projection_observation: {
          package: clone(observation), package_digest: sha256(semanticProofCanonicalJson(observation)),
          recorded_at: observedAt,
        },
      }));
    },
    recordInitialReevaluationPreparation(grant, preparation, { observedAt }) {
      return update(grant, (record) => ({
        ...record,
        reevaluation_preparation: {
          package: clone(preparation), package_digest: sha256(semanticProofCanonicalJson(preparation)),
          recorded_at: observedAt,
        },
      }));
    },
    assertReevaluationPredecessor({ priorReceipt, preparation, authorityPreDigest }) {
      const prior = ledger.nonces[priorReceipt.grant_nonce];
      if (!prior || prior.state !== 'consumed' || prior.publication_phase !== 'initial'
          || priorReceipt.publication_phase !== 'initial' || priorReceipt.terminal_state !== 'PENDING'
          || priorReceipt.authority_after_digest !== authorityPreDigest
          || preparation.evaluatedAuthorityDigest !== authorityPreDigest
          || preparation.candidateDigest !== priorReceipt.candidate_digest
          || prior.final_receipt_digest !== publicationReceiptDigest(priorReceipt)
          || prior.reevaluation_preparation?.package_digest
            !== sha256(semanticProofCanonicalJson(preparation))
          || semanticProofCanonicalJson(prior.reevaluation_preparation?.package)
            !== semanticProofCanonicalJson(preparation)) {
        throw new Error('reevaluation publication has no durable stage-1 transaction linkage');
      }
      return Object.freeze({ prior: clone(prior), preparation: clone(preparation) });
    },
    recordPostPublicationReevaluation(grant, reevaluation, { observedAt }) {
      return update(grant, (record) => ({
        ...record, action_state: reevaluation.actionState,
        authority_after_digest: reevaluation.authorityAfterDigest,
        current_proof_results: reevaluation.currentProofResults,
        proof_currentness: reevaluation.proofCurrentness, reevaluated_at: observedAt,
        reevaluation_evaluation_receipt_digest: reevaluation.evaluationReceiptDigest,
        reevaluation_execution_receipt_digest: reevaluation.executionReceiptDigest,
        selected_aggregate_result: reevaluation.selectedAggregateResult,
        state: 'reevaluated_pending_receipt',
      }));
    },
    consumeGrantNonce(grant, { receipt, observedAt }) {
      return update(grant, (record) => ({
        ...record, consumed_at: observedAt, final_receipt: clone(receipt),
        final_receipt_digest: publicationReceiptDigest(receipt),
        publication_outcome: receipt.publication_outcome,
        published_at: receipt.published_at, state: 'consumed',
      }));
    },
    failGrantNonce(grant, { stage, observedAt }) {
      return update(grant, (record) => ({
        ...record, failed_at: observedAt, failure_stage: stage,
        previous_state: record.state, state: 'failed',
      }));
    },
  });
}

function receiptDescriptor(root, iri, value) {
  const bytes = Buffer.from(aggregateCompilerProofInternals.canonicalJson(value), 'utf8');
  const digest = putCas(root, bytes);
  const persistenceReceiptDigest = putJson(root, {
    contentDigest: digest, persisted: true, schema: 'usf-cas-persistence-receipt-v1',
  });
  return {
    byteLength: bytes.length,
    bytesBase64: bytes.toString('base64'),
    digest,
    iri,
    mediaType: 'application/json',
    persistenceReceiptDigest,
  };
}

function componentRows(casRoot) {
  return COMPONENT_PROOFS.map((component, index) => ({
    admissionState: binding('urn:usf:evidenceadmissionstate:admitted'),
    algorithm: binding(`urn:usf:proofalgorithm:component${index}`),
    algorithmSourceDigest: binding(`sha256:${String(index + 1).repeat(64)}`),
    algorithmVersion: binding(`urn:usf:proofalgorithmversion:component${index}`),
    algorithmVersionIdentifier: binding('1.0.0'),
    evidence: binding(`urn:usf:evidenceresult:component${index}`),
    evidenceDigest: binding(putCas(casRoot, Buffer.from(`evidence-${index}`))),
    evidenceFreshness: binding('urn:usf:freshness:fresh'),
    evidenceFreshnessState: binding('urn:usf:evidencefreshnessstate:fresh'),
    evidenceStage: binding('urn:usf:evidencestage:integrityverified'),
    evaluationObligation: binding(component.obligation),
    execution: binding(`urn:usf:proofexecution:component${index}`),
    executionProof: binding(`urn:usf:proof:component${index}`),
    historicalAuthorityDigest: binding(HISTORICAL),
    integrityState: binding('urn:usf:evidenceintegritystate:valid'),
    obligation: binding(component.obligation),
    proof: binding(`urn:usf:proof:component${index}`),
    proofEvaluation: binding(`urn:usf:proofevaluation:component${index}`),
    proofState: binding('urn:usf:proofresultstate:successful'),
    result: binding(component.result),
    resultEvaluatedAt: binding('2026-07-20T00:00:00Z'),
    resultFreshness: binding('urn:usf:freshness:fresh'),
    resultState: binding('urn:usf:resultstate:passed'),
    validFrom: binding('2026-07-20T00:00:00Z'),
    validUntil: binding('2026-09-01T00:00:00Z'),
    withinValidityScope: binding('true'),
  }));
}

function dependentValidationRows(casRoot, {
  admissionHead = '8'.repeat(40),
  admissionPaths = [
    'processes/semantic-assurance/semantic-authority-publication.mjs',
    'semantic-model/assurance/evidence.trig',
  ],
  admissionTree = '9'.repeat(40),
  producerHead = '6'.repeat(40),
  producerPaths = [
    'src/usf_factory/provider_plane_runtime.py',
    'tests/test_v3_provider_refresh_authority.py',
  ],
  producerTree = '7'.repeat(40),
} = {}) {
  const executionReceiptDigest = putCas(casRoot, Buffer.from('factory-validation-execution-receipt'));
  const evaluationReceiptDigest = putCas(casRoot, Buffer.from('factory-validation-evaluation-receipt'));
  return producerPaths.flatMap((producerSourcePath) => admissionPaths.map((admissionSourcePath) => ({
    admissionPath: binding('urn:usf:evidenceadmissionpath:factoryproviderv3implementation'),
    admissionProducer: binding('urn:usf:validationproducer:factoryproviderv3implementation'),
    admissionRepository: binding('maldous/usf-graph'),
    admissionSourceHead: binding(admissionHead),
    admissionSourcePath: binding(admissionSourcePath),
    admissionSourceScopeDigest: binding(aggregateCompilerProofInternals.sourceScopeDigest(admissionPaths)),
    admissionSourceTree: binding(admissionTree),
    evaluation: binding('urn:usf:validationevaluation:factoryproviderv3implementation'),
    evaluationReceiptDigest: binding(evaluationReceiptDigest),
    execution: binding('urn:usf:validationexecution:factoryproviderv3implementation'),
    executionReceiptDigest: binding(executionReceiptDigest),
    obligation: binding('urn:usf:validationobligation:providerconfigurationplane'),
    producer: binding('urn:usf:validationproducer:factoryproviderv3implementation'),
    producerRelease: binding('factory-v3-currentness-alignment-v1'),
    producerRepository: binding('maldous/usf-factory'),
    producerSourceHead: binding(producerHead),
    producerSourcePath: binding(producerSourcePath),
    producerSourceScopeDigest: binding(aggregateCompilerProofInternals.sourceScopeDigest(producerPaths)),
    producerSourceTree: binding(producerTree),
    result: binding('urn:usf:validationresult:factoryproviderv3implementation'),
    resultAuthorityDigest: binding(HISTORICAL),
    resultSourceHead: binding(producerHead),
    resultState: binding('urn:usf:resultstate:passed'),
    validationEvidence: binding('urn:usf:evidenceresult:factoryproviderv3implementation'),
  })));
}

function dependentTerminalProjection(authorityDigest = D2, overrides = {}) {
  const factoryResult = 'urn:usf:proofresult:factoryproviderv3implementation';
  const workforceResult = 'urn:usf:proofresult:providerworkforceauthorityproviderconfigurationplane';
  const factoryObligation = 'urn:usf:proofobligation:factoryproviderv3implementation';
  const workforceObligation = 'urn:usf:proofobligation:p7515b7117898c8bf9cedd38642fd544b19bd241c7e53cf392161edda5065843f';
  const perProof = [[factoryResult, factoryObligation], [workforceResult, workforceObligation]].map(
    ([proofResult, obligation], index) => ({
      algorithmSourceDigest: `sha256:${String(index + 3).repeat(64)}`,
      currentAuthorityDigest: authorityDigest,
      dependencySetDigest: `sha256:${String(index + 4).repeat(64)}`,
      evaluatedAuthorityDigest: D1,
      evidenceSetDigest: `sha256:${String(index + 5).repeat(64)}`,
      implementationSourceSetDigest: `sha256:${String(index + 6).repeat(64)}`,
      obligation,
      proofResult,
      proofResultState: 'urn:usf:proofresultstate:successful',
      reevaluationState: 'urn:usf:proofreevaluationstate:successful',
      settledAuthorityDigest: D1,
    }),
  );
  return {
    actionState: 'PROCEED',
    actionStateReasons: [],
    authorityDigest,
    contract: 'urn:usf:semanticcontract:providerconfigurationplane',
    proofCurrentness: {
      mandatoryObligations: [factoryObligation, workforceObligation],
      obligationProofResults: [
        { obligation: factoryObligation, proofResult: factoryResult },
        { obligation: workforceObligation, proofResult: workforceResult },
      ],
      perProof,
      proofResults: [factoryResult, workforceResult],
      reasons: [],
      state: 'CURRENT',
    },
    validationActionState: 'PROCEED',
    validationGaps: [],
    validationObligations: [{
      id: 'urn:usf:validationobligation:providerconfigurationplane',
      recordedSatisfactionCount: 1,
      satisfactionCurrent: true,
    }],
    validationSatisfied: true,
    ...overrides,
  };
}

function initialReceipt(overrides = {}) {
  return {
    action_state: 'UNRESOLVED_FAIL_CLOSED', authority_after_digest: D1, authority_before_digest: D0,
    authority_domain: 'urn:usf:capabilityowner:semanticmodelcompilation', authority_publication_digest: D1,
    candidate_approval_envelope_digest: `sha256:${'3'.repeat(64)}`, candidate_digest: CANDIDATE,
    committed_candidate_state: 'COMMITTED', current_proof_results: 0,
    direct_provisional_aggregate_selections: 1, grant_consumed: true,
    grant_nonce: '00000000-0000-4000-8000-000000000001',
    owner_assignment_envelope_digest: `sha256:${'4'.repeat(64)}`, proof_currentness: 'PENDING',
    projection_observation_receipt_digest: `sha256:${'7'.repeat(64)}`,
    protocol: 'semantic-proof-v1', publication_grant_envelope_digest: `sha256:${'5'.repeat(64)}`,
    publication_outcome: 'committed_pending_reevaluation', publication_phase: 'initial',
    published_at: '2026-08-01T00:00:00Z', reevaluation_authority_digest: null,
    reevaluation_evaluation_receipt_digest: null, reevaluation_execution_receipt_digest: null,
    repository: 'maldous/usf-graph', schema_version: 1, selected_aggregate_result: null,
    selected_provisional_aggregate_result: AGGREGATE_RESULT_IRI,
    source_scope_digest: `sha256:${'6'.repeat(64)}`, terminal_state: 'PENDING', ...overrides,
  };
}

function validationRows(casRoot, authorityDigest = D1) {
  const validationResult = 'urn:usf:validationresult:aggregate';
  const validationEvaluation = 'urn:usf:validationevaluation:aggregate';
  const validationExecution = 'urn:usf:validationexecution:aggregate';
  const producer = 'urn:usf:validationproducer:aggregate';
  const admissionPath = 'urn:usf:evidenceadmissionpath:aggregate';
  const validationEvidence = 'urn:usf:validationevidence:aggregate';
  const compilerValidationEvidence = 'urn:usf:validationevidence:compiler';
  const evidenceDigest = putCas(casRoot, Buffer.from('validation-evidence'));
  const compilerValidationEvidenceDigest = putCas(casRoot, Buffer.from('compiler-validation-evidence'));
  const executionReceiptDigest = putJson(casRoot, {
    admissionPath, authorityDigest, evidence: [{ digest: evidenceDigest, iri: validationEvidence }],
    execution: validationExecution, producer, schema: 'usf-validation-execution-receipt-v1',
  });
  const evaluationReceiptDigest = putJson(casRoot, {
    authorityDigest, evaluation: validationEvaluation, executionReceiptDigest, resultState: 'passed',
    schema: 'usf-validation-evaluation-receipt-v1', validationResult,
  });
  return [{
    admissionPath: binding(admissionPath), bindingEvaluationReceiptDigest: binding(evaluationReceiptDigest),
    bindingExecutionReceiptDigest: binding(executionReceiptDigest), evaluationReceiptDigest: binding(evaluationReceiptDigest),
    executionReceiptDigest: binding(executionReceiptDigest), producer: binding(producer),
    compilerValidationEvidence: binding(compilerValidationEvidence),
    compilerValidationEvidenceDigest: binding(compilerValidationEvidenceDigest),
    reevaluationState: binding('urn:usf:resultstate:passed'), resultState: binding('urn:usf:resultstate:passed'),
    stageOneSettledAuthorityDigest: binding(authorityDigest), validationEvaluation: binding(validationEvaluation),
    validationEvidence: binding(validationEvidence), validationEvidenceDigest: binding(evidenceDigest),
    validationExecution: binding(validationExecution), validationResult: binding(validationResult),
  }];
}

function witnessReader(...digests) {
  let index = 0;
  return async () => ({
    digest: digests[Math.min(index++, digests.length - 1)], inventory: [],
    totalSource: 'canonical-graph-inventory', triples: 0,
  });
}

function liveBinding(preparation, overrides = {}) {
  return {
    evaluatedAuthorityDigest: binding(D1), evaluationReceiptDigest: binding(preparation.evaluationReceiptDigest),
    executionReceiptDigest: binding(preparation.executionReceiptDigest),
    reevaluation: binding('urn:usf:postpublicationreevaluation:aggregate'), result: binding(AGGREGATE_RESULT_IRI),
    ...overrides,
  };
}

function harness(base, rows, options = {}) {
  const authority = options.authority || D0;
  const metrics = { componentQueries: 0, trustedTimeQueries: 0 };
  const projection = options.projection || {
    actionState: 'PROCEED',
    proofCurrentness: {
      perProof: [{ proofResult: AGGREGATE_RESULT_IRI }],
      proofResults: [AGGREGATE_RESULT_IRI],
      state: 'CURRENT',
    },
  };
  const client = { async select(query) {
    if (query.includes('aggregate-trusted-time-v1')) { metrics.trustedTimeQueries += 1; return [{ now: binding(options.trustedAt || TRUSTED_AT) }]; }
    if (query.includes('aggregate-component-fact-count-v1')) {
      metrics.componentQueries += 1; if (options.rejectComponents) throw new Error('stage-2 component manufacture');
      return [{ count: binding(rows.length) }];
    }
    if (query.includes('aggregate-component-facts-v1')) {
      metrics.componentQueries += 1; if (options.rejectComponents) throw new Error('stage-2 component manufacture');
      return rows;
    }
    if (query.includes('aggregate-dependent-validation-facts-v1')) {
      return options.dependentValidationRows || dependentValidationRows(base.casRoot);
    }
    if (query.includes('aggregate-initial-provisional-projection-v1')) return options.provisionalRows || [{
      current: binding('false'), provisional: binding('true'), result: binding(PROVISIONAL_AGGREGATE_RESULT_IRI),
    }];
    if (query.includes('aggregate-contract-selection-v1')) return [{ result: binding(AGGREGATE_RESULT_IRI) }];
    if (query.includes('aggregate-live-reevaluation-bindings-v1')) return [options.receiptBinding];
    if (query.includes('aggregate-final-validation-bindings-v1')) return options.validationRows || [];
    throw new Error(`unexpected query ${query.slice(0, 70)}`);
  } };
  return {
    metrics,
    producer: createAggregateCompilerProofProducer({
      ...base, client, contractProjector: async (_client, contract) => contract
        === 'urn:usf:semanticcontract:providerconfigurationplane'
        ? (options.dependentProjection || dependentTerminalProjection(authority)) : projection,
      readAuthorityWitness: witnessReader(...(options.witnesses || [authority, authority])),
    }),
  };
}

async function stage1(base) {
  return harness(base, componentRows(base.casRoot), { authority: D1 }).producer.produceInitial({
    candidateDigest: CANDIDATE, pendingPublicationReceipt: initialReceipt(), requestedAuthorityDigest: D1,
  });
}

async function finalPackageFixture(base) {
  const pending = await harness(base, componentRows(base.casRoot)).producer.preparePending({ requestedAuthorityDigest: D0 });
  const preparation = await stage1(base);
  const executionReceipt = JSON.parse(readFileSync(casPath(base.casRoot, preparation.executionReceiptDigest), 'utf8'));
  const evaluationReceipt = JSON.parse(readFileSync(casPath(base.casRoot, preparation.evaluationReceiptDigest), 'utf8'));
  const compilerReceipt = {
    authorityAfterDigest: D1,
    authorityBeforeDigest: D0,
    candidateDigest: CANDIDATE,
    conforms: true,
    evaluatedAt: '2026-08-01T00:00:00Z',
    evaluationReceiptDigest: putCas(base.casRoot, Buffer.from('compiler-evaluation')),
    executionReceiptDigest: putCas(base.casRoot, Buffer.from('compiler-execution')),
    schema: 'semantic-authority-compiler-validation-v1',
    sourceBindingDigest: pending.aggregateResult.evaluation.sourceBindingDigest,
    validationReportDigest: putCas(base.casRoot, Buffer.from('compiler-report')),
  };
  return {
    input: {
      compilerValidation: {
        descriptor: receiptDescriptor(base.casRoot,
          'urn:usf:validationevidence:compilersemanticenforcementcompilervalidation', compilerReceipt),
        receipt: compilerReceipt,
      },
      evaluationReceiptDescriptor: receiptDescriptor(base.casRoot,
        'urn:usf:validationevidence:compilersemanticenforcementaggregateevaluation', evaluationReceipt),
      executionReceiptDescriptor: receiptDescriptor(base.casRoot,
        'urn:usf:validationevidence:compilersemanticenforcementaggregateexecution', executionReceipt),
      pending,
      publicationReceipt: initialReceipt(),
      stage1Preparation: preparation,
    },
    preparation,
  };
}

test('observes exactly one provisional D1 result in PENDING fail-closed state', async () => {
  const base = fixture();
  const run = harness(base, [], {
    authority: D1, projection: pendingInitialProjection(),
  });
  const value = await run.producer.observeInitialProjection({ requestedAuthorityDigest: D1 });
  assert.deepEqual(Object.keys(value).sort(), [
    'actionState', 'authorityDigest', 'currentProofResults', 'directProvisionalAggregateSelections',
    'observationReceiptDigest', 'ok', 'operation', 'proofCurrentness',
    'selectedProvisionalAggregateResult',
  ]);
  assert.equal(value.currentProofResults, 0);
  assert.equal(value.directProvisionalAggregateSelections, 1);
  assert.equal(value.proofCurrentness, 'PENDING');
  assert.equal(value.actionState, 'UNRESOLVED_FAIL_CLOSED');
  assert.equal(value.operation, 'observe_initial');
  const receipt = JSON.parse(readFileSync(casPath(base.casRoot, value.observationReceiptDigest), 'utf8'));
  assert.equal(receipt.schema, 'aggregate-initial-projection-observation-receipt-v1');
  assert.equal(receipt.observedAt, TRUSTED_AT);
  assert.equal(receipt.selectedProvisionalAggregateResult, value.selectedProvisionalAggregateResult);
  assert.equal(run.metrics.trustedTimeQueries, 1);
});

test('rejects a proof-blocked D1 projection without the exact pending reevaluation binding', async () => {
  const base = fixture();
  const projection = pendingInitialProjection();
  projection.proofCurrentness.perProof[0].reevaluationState = null;
  await assert.rejects(() => harness(base, [], { authority: D1, projection })
    .producer.observeInitialProjection({ requestedAuthorityDigest: D1 }),
  (error) => error.code === 'AGGREGATE_PRODUCER_INITIAL_PROJECTION_INVALID');
});

test('reviewed authority-construction source scope is complete, canonical and path-list-digested', async () => {
  assert.deepEqual(AGGREGATE_REVIEWED_SOURCE_PATHS, EXPECTED_REVIEWED_SOURCE_PATHS);
  assert.deepEqual(AGGREGATE_REVIEWED_SOURCE_PATHS, [...AGGREGATE_REVIEWED_SOURCE_PATHS].sort());
  assert.equal(new Set(AGGREGATE_REVIEWED_SOURCE_PATHS).size, AGGREGATE_REVIEWED_SOURCE_PATHS.length);
  const base = fixture({ explicitBranch: false });
  const pending = await harness(base, componentRows(base.casRoot)).producer.preparePending({ requestedAuthorityDigest: D0 });
  const bindingValue = pending.aggregateResult.evaluation.sourceBinding;
  assert.deepEqual(bindingValue.sourcePaths, AGGREGATE_REVIEWED_SOURCE_PATHS);
  assert.equal(bindingValue.sourceScopeDigest,
    aggregateCompilerProofInternals.sourceScopeDigest(AGGREGATE_REVIEWED_SOURCE_PATHS));
  for (const invalidResponse of [undefined, { ...bindingValue, head: 'not-a-git-object' }]) {
    const invalid = harness({
      ...base, resolveSourceBinding: async () => invalidResponse,
    }, componentRows(base.casRoot));
    await assert.rejects(() => invalid.producer.preparePending({ requestedAuthorityDigest: D0 }));
  }
});

test('source-bound authority contains no pending OwnerAssignment instance', async () => {
  const active = fixture();
  await harness(active, componentRows(active.casRoot)).producer.preparePending({ requestedAuthorityDigest: D0 });
  const pending = fixture({ authoritySource: `<urn:usf:ownerassignment:test> a <urn:usf:ontology:OwnerAssignment>;
    <urn:usf:ontology:assignmentState> "pending-verification".\n` });
  await assert.rejects(
    () => harness(pending, componentRows(pending.casRoot)).producer.preparePending({ requestedAuthorityDigest: D0 }),
    (error) => error.code === 'AGGREGATE_PRODUCER_SOURCE_INVALID',
  );
});

test('uses one Stardog NOW() and defaults source reachability to origin/main', async () => {
  const base = fixture({ explicitBranch: false });
  const run = harness(base, componentRows(base.casRoot));
  const pending = await run.producer.preparePending({ requestedAuthorityDigest: D0 });
  assert.equal(pending.aggregateResult.evaluation.evaluatedAt, TRUSTED_AT);
  assert.equal(pending.aggregateResult.evaluation.sourceBinding.reachableFrom, DEFAULT_AGGREGATE_REACHABLE_REF);
  assert.equal(run.metrics.trustedTimeQueries, 1);
});

test('fractional Stardog trusted time is canonicalized to a protocol UTC second', async () => {
  const base = fixture();
  const pending = await harness(base, componentRows(base.casRoot), {
    trustedAt: '2026-08-01T00:10:00.577Z',
  }).producer.preparePending({ requestedAuthorityDigest: D0 });
  assert.equal(pending.aggregateResult.evaluation.evaluatedAt, TRUSTED_AT);
});

test('evidence lifecycle history requires but does not scalarize integrity-verified stage', async () => {
  const base = fixture();
  const rows = componentRows(base.casRoot);
  rows.push(
    { ...rows[0], evidenceStage: binding('urn:usf:evidencestage:collected') },
    { ...rows[0], evidenceStage: binding('urn:usf:evidencestage:signed') },
  );
  const pending = await harness(base, rows).producer.preparePending({ requestedAuthorityDigest: D0 });
  assert.equal(pending.ok, true);

  const incompleteBase = fixture();
  const incomplete = componentRows(incompleteBase.casRoot);
  incomplete[0] = { ...incomplete[0], evidenceStage: binding('urn:usf:evidencestage:signed') };
  await assert.rejects(
    () => harness(incompleteBase, incomplete).producer.preparePending({ requestedAuthorityDigest: D0 }),
    /AGGREGATE_PRODUCER_STATE_INVALID/,
  );
});

test('historical component record preserves queried identities without synthetic receipt claims', async () => {
  const base = fixture();
  const pending = await harness(base, componentRows(base.casRoot)).producer.preparePending({ requestedAuthorityDigest: D0 });
  const historical = pending.aggregateResult.evaluation.components[0].historicalResult;
  const componentIndex = COMPONENT_PROOFS.findIndex(({ result }) => result === historical.component.result);
  assert.equal(historical.authorityBindingDigest, HISTORICAL);
  assert.equal(historical.evaluatedAt, '2026-07-20T00:00:00Z');
  assert.equal(historical.proof, `urn:usf:proof:component${componentIndex}`);
  assert.equal(historical.proofExecution, `urn:usf:proofexecution:component${componentIndex}`);
  assert.equal(historical.proofEvaluation, `urn:usf:proofevaluation:component${componentIndex}`);
  assert.equal(historical.evidenceSet.length, 1);
  assert.equal(Object.hasOwn(historical, 'executionReceiptDigest'), false);
  assert.equal(Object.hasOwn(historical, 'evaluationReceiptDigest'), false);
  const persisted = JSON.parse(readFileSync(casPath(base.casRoot, historical.digest), 'utf8'));
  assert.equal(persisted.proofExecution, historical.proofExecution);
  assert.equal(persisted.proofEvaluation, historical.proofEvaluation);
  assert.deepEqual(persisted.evidenceSet, historical.evidenceSet);
});

test('D1 preparation is the exact closed protocol shape and binds canonical CAS receipts', async () => {
  const base = fixture();
  const preparation = await stage1(base);
  assert.deepEqual(Object.keys(preparation).sort(), [
    'candidateDigest', 'evaluatedAuthorityDigest', 'evaluationReceiptDigest', 'executionReceiptDigest',
    'ok', 'operation', 'protocol', 'state',
  ]);
  assert.equal(preparation.operation, 'produce_initial');
  assert.equal(preparation.protocol, 'semantic-proof-v1');
  const evaluation = JSON.parse(readFileSync(casPath(base.casRoot, preparation.evaluationReceiptDigest), 'utf8'));
  assert.equal(evaluation.publicationReceiptDigest, publicationReceiptDigest(initialReceipt()));
  assert.equal(readFileSync(casPath(base.casRoot, evaluation.publicationReceiptDigest), 'utf8'),
    `${semanticProofCanonicalJson(initialReceipt())}\n`);
});

test('final package binds actual compiler and postpublication receipt descriptors from CAS', async () => {
  const base = fixture();
  const { input, preparation } = await finalPackageFixture(base);
  const value = await harness(base, []).producer.prepareFinalPackage(input);
  assert.deepEqual(Object.keys(value).sort(), [
    'compilerValidation', 'evaluationReceipt', 'evaluationReceiptDescriptor', 'executionReceipt',
    'executionReceiptDescriptor', 'package', 'publicationReceipt',
  ]);
  assert.deepEqual(value.package, preparation);
  assert.equal(value.executionReceiptDescriptor.digest, preparation.executionReceiptDigest);
  assert.equal(value.evaluationReceiptDescriptor.digest, preparation.evaluationReceiptDigest);
  assert.equal(value.compilerValidation.receipt.authorityAfterDigest, D1);
  assert.equal(Object.hasOwn(value.compilerValidation.receipt, 'settledAuthorityDigest'), false);
});

test('D2 refreshes the dependent Factory validation closure from exact D1 authority', async () => {
  const base = fixture();
  const admissionPaths = [
    'assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.mjs',
    'processes/semantic-assurance/semantic-authority-publication.mjs',
    'semantic-model/assurance/evidence.trig',
  ];
  const producerPaths = [
    'src/usf_factory/adaptive_routing.py',
    'src/usf_factory/provider_plane_runtime.py',
    'tests/test_v3_provider_refresh_authority.py',
  ];
  const rows = dependentValidationRows(base.casRoot, {
    admissionHead: 'c'.repeat(40),
    admissionPaths,
    admissionTree: 'd'.repeat(40),
    producerHead: 'a'.repeat(40),
    producerPaths,
    producerTree: 'b'.repeat(40),
  });
  const refreshed = await harness(base, [], {
    authority: D1,
    dependentValidationRows: rows,
  }).producer.refreshDependentValidation({ requestedAuthorityDigest: D1 });
  assert.equal(refreshed.authorityDigest, HISTORICAL);
  assert.equal(refreshed.admission.sourceHead, 'c'.repeat(40));
  assert.equal(refreshed.admission.sourceTree, 'd'.repeat(40));
  assert.deepEqual(refreshed.admission.sourcePaths, admissionPaths);
  assert.equal(refreshed.producer.sourceHead, 'a'.repeat(40));
  assert.equal(refreshed.producer.sourceTree, 'b'.repeat(40));
  assert.deepEqual(refreshed.producer.sourcePaths, producerPaths);
});

test('final package fails closed when a lifecycle receipt CAS object is missing', async () => {
  const base = fixture();
  const { input } = await finalPackageFixture(base);
  rmSync(casPath(base.casRoot, input.compilerValidation.receipt.validationReportDigest));
  await assert.rejects(() => harness(base, []).producer.prepareFinalPackage(input));
});

test('D2 verifies D1 package and validation CAS bytes without manufacturing component proof', async () => {
  const base = fixture();
  const preparation = await stage1(base);
  const run = harness(base, [], {
    authority: D2, receiptBinding: liveBinding(preparation), rejectComponents: true,
    validationRows: validationRows(base.casRoot),
  });
  const terminal = await run.producer.produceTerminal({
    expectedStage1AuthorityDigest: D1, requestedAuthorityDigest: D2, stage1Preparation: preparation,
  });
  assert.equal(terminal.evaluatedAuthorityDigest, D1);
  assert.equal(terminal.authorityAfterDigest, D2);
  assert.equal(run.metrics.componentQueries, 0);
  assert.equal(run.metrics.trustedTimeQueries, 1);
});

test('pending preparation closes the exact cross-repository Factory validation identity', async () => {
  const base = fixture();
  const pending = await harness(base, componentRows(base.casRoot)).producer.preparePending({ requestedAuthorityDigest: D0 });
  assert.equal(pending.dependentValidation.result,
    'urn:usf:validationresult:factoryproviderv3implementation');
  assert.equal(pending.dependentValidation.producer.repository, 'maldous/usf-factory');
  assert.equal(pending.dependentValidation.admission.repository, 'maldous/usf-graph');
  assert.notEqual(pending.dependentValidation.producer.sourceScopeDigest,
    pending.dependentValidation.admission.sourceScopeDigest);

  for (const mutate of [
    (rows) => { for (const row of rows) row.admissionRepository = binding('maldous/usf-factory'); },
    (rows) => { for (const row of rows) row.producerSourceScopeDigest = binding(`sha256:${'f'.repeat(64)}`); },
    (rows) => { rows.push({ ...rows[0], validationEvidence: binding('urn:usf:validationevidence:substituted') }); },
  ]) {
    const invalidBase = fixture();
    const dependentRows = dependentValidationRows(invalidBase.casRoot);
    mutate(dependentRows);
    await assert.rejects(() => harness(invalidBase, componentRows(invalidBase.casRoot), {
      dependentValidationRows: dependentRows,
    }).producer.preparePending({ requestedAuthorityDigest: D0 }),
    (error) => error.code === 'AGGREGATE_DEPENDENT_VALIDATION_INVALID');
  }
});

test('terminal closure rejects CURRENT proofs when dependent validation is still stale', async () => {
  const base = fixture();
  const preparation = await stage1(base);
  const staleValidationProjection = dependentTerminalProjection(D2, {
    actionState: 'BLOCK',
    actionStateReasons: ['validation-satisfaction-not-current'],
    validationGaps: [{ code: 'validation-satisfaction-not-current' }],
    validationObligations: [{
      id: 'urn:usf:validationobligation:providerconfigurationplane',
      recordedSatisfactionCount: 1,
      satisfactionCurrent: false,
    }],
    validationSatisfied: false,
  });
  const run = harness(base, [], {
    authority: D2,
    dependentProjection: staleValidationProjection,
    receiptBinding: liveBinding(preparation),
    rejectComponents: true,
    validationRows: validationRows(base.casRoot),
  });
  await assert.rejects(() => run.producer.produceTerminal({
    expectedStage1AuthorityDigest: D1, requestedAuthorityDigest: D2, stage1Preparation: preparation,
  }), (error) => error.code === 'AGGREGATE_PRODUCER_TERMINAL_DEPENDENT_CLOSURE_INVALID');
});

test('rejects validation receipt substitution even when graph digest equality is preserved', async () => {
  const base = fixture();
  const preparation = await stage1(base);
  const rows = validationRows(base.casRoot);
  const substituted = putJson(base.casRoot, {
    authorityDigest: D1, evaluation: 'urn:usf:validationevaluation:substituted',
    executionReceiptDigest: rows[0].executionReceiptDigest.value, resultState: 'passed',
    schema: 'usf-validation-evaluation-receipt-v1', validationResult: rows[0].validationResult.value,
  });
  rows[0].evaluationReceiptDigest = binding(substituted);
  rows[0].bindingEvaluationReceiptDigest = binding(substituted);
  const run = harness(base, [], {
    authority: D2, receiptBinding: liveBinding(preparation), rejectComponents: true, validationRows: rows,
  });
  await assert.rejects(() => run.producer.produceTerminal({
    expectedStage1AuthorityDigest: D1, requestedAuthorityDigest: D2, stage1Preparation: preparation,
  }), (error) => error.code === 'AGGREGATE_PRODUCER_VALIDATION_EVIDENCE_INVALID');
});

test('rejects complete stage-1 evaluation receipt substitution', async () => {
  const base = fixture();
  const preparation = await stage1(base);
  const evaluation = JSON.parse(readFileSync(casPath(base.casRoot, preparation.evaluationReceiptDigest), 'utf8'));
  const substituted = {
    ...preparation,
    evaluationReceiptDigest: putJson(base.casRoot, {
      ...evaluation, evidenceSetDigest: `sha256:${'9'.repeat(64)}`,
    }),
  };
  const run = harness(base, [], {
    authority: D2, receiptBinding: liveBinding(substituted), rejectComponents: true,
    validationRows: validationRows(base.casRoot),
  });
  await assert.rejects(() => run.producer.produceTerminal({
    expectedStage1AuthorityDigest: D1, requestedAuthorityDigest: D2, stage1Preparation: substituted,
  }), (error) => error.code === 'AGGREGATE_PRODUCER_STAGE1_PREPARATION_INVALID');
});

test('rejects CURRENT initial projection and non-CURRENT final projection', async () => {
  const initialBase = fixture();
  const initial = harness(initialBase, [], {
    authority: D1, provisionalRows: [{ current: binding('true'), provisional: binding('false'), result: binding(AGGREGATE_RESULT_IRI) }],
  });
  await assert.rejects(() => initial.producer.observeInitialProjection({ requestedAuthorityDigest: D1 }),
    (error) => error.code === 'AGGREGATE_PRODUCER_INITIAL_PROJECTION_INVALID');

  const finalBase = fixture();
  const preparation = await stage1(finalBase);
  const finalRun = harness(finalBase, [], {
    authority: D2, receiptBinding: liveBinding(preparation), rejectComponents: true,
    validationRows: validationRows(finalBase.casRoot),
    projection: { actionState: 'UNRESOLVED_FAIL_CLOSED', proofCurrentness: { state: 'AMBIGUOUS' } },
  });
  await assert.rejects(() => finalRun.producer.produceTerminal({
    expectedStage1AuthorityDigest: D1, requestedAuthorityDigest: D2, stage1Preparation: preparation,
  }), (error) => error.code === 'AGGREGATE_PRODUCER_TERMINAL_PROJECTION_INVALID');
});

test('terminal observation rejects the retired singular proof-result projection', async () => {
  const base = fixture();
  const preparation = await stage1(base);
  const run = harness(base, [], {
    authority: D2, receiptBinding: liveBinding(preparation), rejectComponents: true,
    validationRows: validationRows(base.casRoot),
    projection: {
      actionState: 'PROCEED',
      proofCurrentness: { proofResult: AGGREGATE_RESULT_IRI, state: 'CURRENT' },
    },
  });
  await assert.rejects(() => run.producer.produceTerminal({
    expectedStage1AuthorityDigest: D1, requestedAuthorityDigest: D2, stage1Preparation: preparation,
  }), (error) => error.code === 'AGGREGATE_PRODUCER_TERMINAL_PROJECTION_INVALID');
});

test('authority drift, stale evidence, invalid evidence and orphan evidence fail closed', async () => {
  const driftBase = fixture();
  await assert.rejects(() => harness(driftBase, componentRows(driftBase.casRoot), { witnesses: [D0, D1] })
    .producer.preparePending({ requestedAuthorityDigest: D0 }), (error) => error.code === 'AGGREGATE_PRODUCER_AUTHORITY_DRIFT');
  const staleBase = fixture(); const stale = componentRows(staleBase.casRoot);
  stale[0].validUntil = binding('2026-07-31T23:59:59Z');
  await assert.rejects(() => harness(staleBase, stale).producer.preparePending({ requestedAuthorityDigest: D0 }),
    (error) => error.code === 'AGGREGATE_COMPONENT_STALE');
  const invalidBase = fixture(); const invalid = componentRows(invalidBase.casRoot);
  invalid[0].integrityState = binding('urn:usf:evidenceintegritystate:invalid');
  await assert.rejects(() => harness(invalidBase, invalid).producer.preparePending({ requestedAuthorityDigest: D0 }),
    (error) => error.code === 'AGGREGATE_PRODUCER_STATE_INVALID');
  const orphanBase = fixture(); const orphan = componentRows(orphanBase.casRoot);
  orphan[0].evidenceDigest = binding(ORPHANED_ATTESTATION_DIGEST);
  await assert.rejects(() => harness(orphanBase, orphan).producer.preparePending({ requestedAuthorityDigest: D0 }),
    (error) => error.code === 'AGGREGATE_ORPHAN_EVIDENCE_REJECTED');
});

function externalAuthorityLifecycleFixture(commandModule, protocolModule, source, authority) {
  const canonicalBytes = (value) => Buffer.from(
    `${JSON.stringify(JSON.parse(protocolModule.canonicalJson(value)), null, 2)}\n`,
  );
  const descriptor = (bytes) => Object.freeze({
    byteSize: bytes.length,
    digest: sha256(bytes),
    jcsDigest: sha256(Buffer.from(protocolModule.canonicalJson(JSON.parse(bytes.toString('utf8'))))),
  });
  const path = 'processes/semantic-assurance/semantic-model-compilation-command.mjs';
  const sourcePaths = [path];
  const sourceScopeDigest = protocolModule.sourceScopeDigest(sourcePaths);
  const predecessor = sha256(Buffer.from('predecessor\n'));
  const successorContent = 'successor\n';
  const successor = sha256(Buffer.from(successorContent));
  const successorTree = '6'.repeat(40);
  const obligation = 'urn:usf:validationobligation:operationexpectedoutcomeerrorclass';
  const operations = [{
    action: 'write-file', artefactFamily: 'urn:usf:artefactfamily:processsource',
    content: successorContent, contentDigest: successor, contentEncoding: 'utf8', index: 0,
    path, pathRole: 'urn:usf:pathrole:processsource',
    representationFormat: 'urn:usf:representationformat:ecmascriptmodule2024', sourceDigest: predecessor,
  }];
  const operationDigest = sha256(Buffer.from(protocolModule.canonicalJson({
    operations, repository: source.repository, schemaVersion: 1,
  })));
  const inventory = {
    authority: { digest: authority, graph_count: 1, triple_count: 1 },
    candidate_source: {
      added_path_count: 0, changed_path_count: 1, deleted_path_count: 0,
      focused_verification: { failed: 0, passed: 1 }, history_shape: oneParentHistoryShape,
      predecessor_commit: source.head, predecessor_tree: source.tree, repository: source.repository,
      source_records: [{ mode: '100644', path, predecessor_digest: predecessor, successor_digest: successor }],
      staged_deletions: 1, staged_insertions: 1, staged_successor_tree: successorTree,
    },
    corrections: [{
      candidate: {}, defect: 'exact defect', obligation, owner_authored_paths: sourcePaths,
      status: 'REFERENCE_ONLY_CANDIDATE',
    }],
    current_execution_boundary: {
      action_state: 'PROCEED', execution_scope_digest: sha256(Buffer.from('scope')),
      execution_scope_iri: 'urn:usf:contractexecutionscope:fixture',
      execution_scope_projection_digest: sha256(Buffer.from('projection')),
      maximum_repository_writes: 0, mode: 'readonlysemanticvalidation',
      permitted_effect: 'urn:usf:executioneffect:validationevidencecandidate',
      repository_mutation_permitted: false,
      status: 'CONFLICT_RESOLUTION_AND_VALIDATION_CLOSURE_REQUIRED_FAIL_CLOSED',
      unresolved_validation_obligations: [obligation], validation_satisfied: false, write_paths: [],
    },
    nonclaims: [], owner_precedent: {}, predecessor_request: {}, proof_preflight: {},
    protected_graph_source: { commit: source.head, parent: '5'.repeat(40), required_history: requiredHistoryMode, tree: source.tree },
    required_authority_actions: [], required_validation_invariants: [],
    schema: 'usf-repository-materialisation-semantic-correction-authority-request-v3',
    source_scope: {
      authority_projection_additions: {}, current_path_count: 1, current_scope_digest: sourceScopeDigest,
      successor_path_count: 1, successor_scope_digest: sourceScopeDigest,
    },
    status: 'REFERENCE_ONLY_VALIDATION_EVIDENCE_CANDIDATE_AWAITING_EXACT_CONFLICT_RESOLUTION',
    supporting_integrity_corrections: {},
  };
  const inventoryBytes = canonicalBytes(inventory);
  const inventoryDescriptor = descriptor(inventoryBytes);
  const review = {
    authorshipIndependence: {
      candidateDerivationParticipation: false, priorReviewConclusionsUsed: false,
      reviewDerivation: 'independent exact recomputation', reviewerRole: 'independent-usf-semantic-reviewer',
    },
    candidateSource: {
      baseCommit: source.head, baseParent: '5'.repeat(40), baseTree: source.tree,
      changedPaths: sourcePaths, sourceRecordCount: 1, sourceRecordsExact: true,
      sourceRecordsJcsSha256: sha256(Buffer.from(protocolModule.canonicalJson(inventory.candidate_source.source_records))),
      stagedDeletions: 1, stagedInsertions: 1, stagedSuccessorTree: successorTree,
      trackedDeltaExact: true, trackedPathAdditions: 0, trackedPathDeletions: 0,
    },
    currentExecutionBoundary: {}, governanceIndependentReviewSatisfied: true,
    liveAuthority: {
      digest: authority, digestAlgorithm: 'sha256-rdfc10-graph-inventory-v2',
      graphCount: 1, stableAcrossReview: true, tripleCount: 1,
    },
    nonclaims: [],
    obligations: {
      currentValidationResultCounts: { [obligation]: 0 }, requiredAuthorityActionCount: 1,
      requiredValidationInvariantCount: 1, targetValidationObligations: [obligation],
    },
    publicationReadiness: 'NOT_READY_REFERENCE_ONLY_AWAITING_OWNER_DECISION_PROOF_AND_V1_PUBLICATION',
    request: {
      byteCount: inventoryBytes.length, jcsSha256: inventoryDescriptor.jcsDigest, path: '.work/request.json',
      rawSha256: inventoryDescriptor.digest, schema: inventory.schema, status: inventory.status, terminalLf: true,
    },
    reviewArtifactStorageClass: 'session-transient-gitignored',
    schema: 'usf-semantic-adequacy-review-core-v1', sourceOrAuthorityMutationPerformed: false,
    verdict: 'ACCEPTED', verification: {},
  };
  const operationsBytes = canonicalBytes(operations);
  const reviewBytes = canonicalBytes(review);
  const inputs = {
    inventory: inventoryDescriptor,
    operations: descriptor(operationsBytes),
    review: descriptor(reviewBytes),
  };
  const ownerAssignmentIri = 'urn:usf:ownerassignment:semanticmodelcompilation:matthewaldous';
  const conflictBinding = {
    conflictingAuthorities: [
      'urn:usf:semanticcontract:compilersemanticenforcement',
      'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation',
    ],
    operationDigest, requestedActions: ['write-file'], requestedEffects: ['urn:usf:obligationeffect:blocking'],
    requestedFormats: ['urn:usf:representationformat:ecmascriptmodule2024'], requestedPaths: sourcePaths,
    sourcePaths, sourceScopeDigest, successorSourceTree: successorTree, validationObligations: [obligation],
  };
  const proof = {
    artifacts: inputs, authorityDigest: authority, candidateDigest: inventoryDescriptor.digest,
    conflict: {
      authorities: conflictBinding.conflictingAuthorities, operationDigest,
      requestedActions: conflictBinding.requestedActions, requestedEffects: conflictBinding.requestedEffects,
      requestedFormats: conflictBinding.requestedFormats, requestedPaths: sourcePaths,
      validationObligations: [obligation],
    },
    decision: {
      ownerAssignmentIri, rationale: 'Approve only this exact reviewed correction and no unrelated effect.',
      state: 'ACCEPTED',
    },
    evidenceSetDigest: sha256(Buffer.from(protocolModule.canonicalJson(inputs))),
    nonclaims: ['NO_FACTORY_MUTATION', 'NO_PRODUCTION_PRUNING', 'NO_PROVIDER_CONTACT', 'NO_V2_ACTIVATION', 'NO_DEPLOYMENT'],
    proof: {
      algorithmIri: 'urn:usf:proofalgorithm:compilersemanticenforcementaggregate',
      algorithmVersionIri: 'urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210',
      evaluatedAt: '2026-08-01T00:04:59Z',
      obligationIri: 'urn:usf:proofobligation:compilersemanticenforcementaggregate',
      resultState: 'SUCCESSFUL', state: 'PASSED', subjectCandidateDigest: inventoryDescriptor.digest,
      validUntil: '2026-08-02T00:04:59Z',
    },
    repository: source.repository,
    review: { defectCount: 0, digest: inputs.review.digest, independent: true, state: 'ACCEPTED' },
    schema: 'usf-authority-conflict-proof-decision-v1',
    source: {
      predecessorHead: source.head, predecessorTree: source.tree, sourcePaths, sourceScopeDigest,
      successorTree,
    },
  };
  const proofBytes = canonicalBytes(proof);
  const proofDigest = sha256(proofBytes);
  const proofApprovalEnvelope = { payload: { candidate_digest: proofDigest }, signature: 'fixture-owner-signature' };
  const verifyProofApprovalEnvelope = () => ({
    authority_domain: 'urn:usf:capabilityowner:semanticmodelcompilation', authority_pre_digest: authority,
    candidate_digest: proofDigest, claim_type: 'candidate_approval', expires_at: '2026-08-02T00:04:59Z',
    fingerprint: protocolModule.AUTHORITY_FINGERPRINT, principal: protocolModule.AUTHORITY_PRINCIPAL,
    repository: source.repository, signing_identity: protocolModule.AUTHORITY_SIGNING_IDENTITY,
    single_use: false, source_scope_digest: sourceScopeDigest,
  });
  const artifactBytes = new Map([
    ['inventory', inventoryBytes], ['operations', operationsBytes], ['proof', proofBytes], ['review', reviewBytes],
  ]);
  const packageValue = commandModule.semanticModelCompilationCommandInternals.createExternalAuthorityDeltaPackage({
    artifacts: [...artifactBytes].map(([role, bytes]) => ({ bytes, role })),
    authorityDigest: authority, conflictBinding, correctionCandidateDigest: inventoryDescriptor.digest,
    now: new Date('2026-08-01T00:05:00Z'), ownerAssignmentIri,
    predecessorSourceHead: source.head, predecessorSourceTree: source.tree,
    proofApprovalEnvelope, repository: source.repository, verifyProofApprovalEnvelope,
  });
  return Object.freeze({ artifactBytes, packageValue, verifyProofApprovalEnvelope });
}

test('production aggregate adapter executes D0 through D1 and D2 to CURRENT PROCEED', async () => {
  const [{ DataFactory, Parser, Store, Writer }, compilerModule, publisherModule, commandModule, protocolModule] = await Promise.all([
    import('n3'),
    import('../../capabilities/semantic-model-compilation/compiler.mjs'),
    import('../../processes/semantic-assurance/semantic-authority-publication.mjs'),
    import('../../processes/semantic-assurance/semantic-model-compilation-command.mjs'),
    import('../../processes/semantic-assurance/semantic-proof-v1.mjs'),
  ]);
  const d0 = `sha256:${'a'.repeat(64)}`;
  const d1 = `sha256:${'b'.repeat(64)}`;
  const d2 = `sha256:${'c'.repeat(64)}`;
  const authorityGraph = 'urn:usf:graph:authority';
  const bindingsGraph = 'urn:usf:graph:bindings';
  const capabilitiesGraph = 'urn:usf:graph:capabilities';
  const evidenceGraph = 'urn:usf:graph:evidence';
  const proofsGraph = 'urn:usf:graph:proofs';
  const shapesGraph = 'urn:usf:graph:shapes';
  const graphs = [authorityGraph, bindingsGraph, capabilitiesGraph, evidenceGraph, proofsGraph, shapesGraph];
  let phase = 0;
  let live = new Map(graphs.map((graph) => [graph, new Store()]));
  const rdfType = DataFactory.namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  live.get(capabilitiesGraph).addQuad(DataFactory.quad(
    DataFactory.namedNode('urn:usf:semanticcontract:compilersemanticenforcement'),
    DataFactory.namedNode('urn:usf:ontology:hasActivationState'),
    DataFactory.namedNode('urn:usf:contractactivationstate:active'),
  ));
  for (const { obligation, result } of COMPONENT_PROOFS) {
    live.get(capabilitiesGraph).addQuad(DataFactory.quad(
      DataFactory.namedNode('urn:usf:semanticcontract:compilersemanticenforcement'),
      DataFactory.namedNode('urn:usf:ontology:reliesOnProofResult'),
      DataFactory.namedNode(result),
    ));
    live.get(capabilitiesGraph).addQuad(DataFactory.quad(
      DataFactory.namedNode('urn:usf:semanticcontract:compilersemanticenforcement'),
      DataFactory.namedNode('urn:usf:ontology:mandatoryProofObligation'),
      DataFactory.namedNode(obligation),
    ));
  }
  for (const realisation of [
    'urn:usf:realisation:semanticauthoritycontrol',
    'urn:usf:realisation:semanticcontractcompilersemanticenforcement',
  ]) {
    live.get(bindingsGraph).addQuad(DataFactory.quad(
      DataFactory.namedNode(realisation),
      DataFactory.namedNode('urn:usf:ontology:realisationState'),
      DataFactory.namedNode('urn:usf:realisationstate:implementable'),
    ));
  }
  const transactions = new Map();
  let transactionIndex = 0;
  const cloneDataset = (dataset) => new Map([...dataset].map(([graph, store]) => [graph, new Store(store.getQuads(null, null, null, null))]));
  const trackedSource = cloneDataset(live);
  const serialize = async (store, format = 'Turtle') => new Promise((resolveText, reject) => {
    const writer = new Writer({ format });
    writer.addQuads(store.getQuads(null, null, null, null));
    writer.end((error, output) => error ? reject(error) : resolveText(output));
  });
  const client = {
    async connectivity() { return 1; },
    async begin() { const id = `tx-${transactionIndex += 1}`; transactions.set(id, cloneDataset(live)); return id; },
    async rollback(id) { transactions.delete(id); },
    async commit(id) { live = transactions.get(id); transactions.delete(id); phase += 1; },
    async constructInTransaction(id, query) {
      const graph = /GRAPH <([^>]+)>/.exec(query)?.[1];
      return serialize(transactions.get(id).get(graph));
    },
    async clearGraphs(id, values) { for (const graph of values) transactions.get(id).set(graph, new Store()); },
    async addData(id, content, contentType, targetGraph) {
      const values = new Parser({ format: contentType, baseIRI: 'urn:usf:' }).parse(content);
      for (const item of values) {
        const graph = targetGraph || item.graph.value;
        transactions.get(id).get(graph).addQuad(DataFactory.quad(item.subject, item.predicate, item.object));
      }
    },
    async validateInTransactionWithReceipt() {
      return { conforms: true, receiptDigest: `sha256:${'d'.repeat(64)}` };
    },
    async reportInTransaction() { return []; },
    async selectInTransaction() { return []; },
  };
  const authorityDigest = () => [d0, d1, d2][Math.min(phase, 2)];
  const readAuthorityWitness = async () => {
    const inventory = [];
    let triples = 0;
    for (const [graph, store] of [...live].sort(([left], [right]) => left.localeCompare(right))) {
      const nquads = new Store(store.getQuads(null, null, null, null).map((item) => DataFactory.quad(
        item.subject, item.predicate, item.object, DataFactory.namedNode(graph),
      )));
      const record = await compilerModule.canonicalGraphDigest(await serialize(nquads, 'N-Quads'));
      // The live authority gateway transports canonical per-graph RDFC digests
      // as lowercase hex; the publication lifecycle canonicalises the scheme.
      inventory.push({ graph, sha256: record.sha256, triples: record.triples });
      triples += record.triples;
    }
    return { digest: authorityDigest(), inventory, triples };
  };
  const manifest = {
    authored: [
      { file: 'capabilities.trig', graph: capabilitiesGraph, order: 2 },
      { file: 'bindings.trig', graph: bindingsGraph, order: 3 },
      { file: 'evidence.trig', graph: evidenceGraph, order: 4 },
      { file: 'proofs.trig', graph: proofsGraph, order: 5 },
    ],
    definitions: [{ file: 'authority.ttl', graph: authorityGraph, order: 1 }],
    derived: [], reviews: [], rules: [],
    shapes: [{
      file: 'shapes.ttl', graph: shapesGraph, liveValidation: true,
      path: join(import.meta.dirname, '../../semantic-model/shapes.ttl'),
    }],
    publicationBudget: { maximumProjectedStatementCount: 999999 },
  };
  const sourceCompiler = async ({ client: sourceClient }) => {
    const tx = await sourceClient.begin();
    await sourceClient.clearGraphs(tx, graphs);
    for (const [graph, store] of trackedSource) {
      const content = await serialize(store);
      if (content) await sourceClient.addData(tx, content, 'text/turtle', graph);
    }
    const derived = await sourceClient.validateInTransactionWithReceipt(tx, []);
    await sourceClient.rollback(tx);
    return { ok: true, liveValidation: { derived, receiptDigest: derived.receiptDigest } };
  };
  let verifyExternalAuthorityProofApproval = () => { throw new Error('external proof fixture not initialised'); };
  const command = commandModule.createSemanticModelCompilationCommand({
    checkLocalFunction: () => {}, client, compileFunction: sourceCompiler,
    loadManifestFunction: () => manifest, readAuthorityWitness,
    repositoryRoot: join(import.meta.dirname, '../..'),
    trustedNow: () => new Date('2026-08-11T00:05:00Z'),
    verifyExternalAuthorityProofApproval: (...args) => verifyExternalAuthorityProofApproval(...args),
  });
  const base = fixture();
  let finalPackage;
  const refreshedProducerPaths = [
    'src/usf_factory/adaptive_routing.py',
    'src/usf_factory/provider_plane_runtime.py',
    'tests/test_v3_provider_refresh_authority.py',
  ];
  const producer = {
    preparePending: (input) => harness(base, componentRows(base.casRoot), { authority: d0 }).producer.preparePending(input),
    observeInitialProjection: (input) => {
      const selections = live.get(capabilitiesGraph).getQuads(
        DataFactory.namedNode('urn:usf:semanticcontract:compilersemanticenforcement'),
        DataFactory.namedNode('urn:usf:ontology:reliesOnProofResult'), null, null,
      ).map((quad) => quad.object.value);
      const provisionalRows = selections.map((result) => ({
        current: binding(String(result === AGGREGATE_RESULT_IRI)),
        provisional: binding(String(result
          === 'urn:usf:proofresult:compilersemanticenforcementaggregateprepublication')),
        result: binding(result),
      }));
      const pending = provisionalRows.length === 1 && provisionalRows[0].provisional.value === 'true';
      return harness(base, [], {
        authority: d1,
        projection: pending ? pendingInitialProjection() : {
          actionState: 'BLOCK', proofCurrentness: { state: 'AMBIGUOUS' },
        },
        provisionalRows,
      }).producer.observeInitialProjection(input);
    },
    produceInitial: (input) => harness(base, componentRows(base.casRoot), { authority: d1 }).producer.produceInitial(input),
    refreshDependentValidation: (input) => harness(base, [], {
      authority: d1,
      dependentValidationRows: dependentValidationRows(base.casRoot, {
        admissionHead: 'c'.repeat(40),
        admissionPaths: [
          'assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.mjs',
          'processes/semantic-assurance/semantic-authority-publication.mjs',
          'semantic-model/assurance/evidence.trig',
        ],
        admissionTree: 'd'.repeat(40),
        producerHead: 'a'.repeat(40),
        producerPaths: refreshedProducerPaths,
        producerTree: 'b'.repeat(40),
      }),
    }).producer.refreshDependentValidation(input),
    async prepareFinalPackage(input) {
      finalPackage = await harness(base, [], { authority: d1 }).producer.prepareFinalPackage(input);
      return finalPackage;
    },
    produceTerminal(input) {
      const receipt = finalPackage.compilerValidation.receipt;
      const evidenceDescriptors = [finalPackage.executionReceiptDescriptor, finalPackage.evaluationReceiptDescriptor];
      const rows = evidenceDescriptors.map((descriptor) => ({
        admissionPath: binding('urn:usf:evidenceadmissionpath:compilersemanticenforcementaggregate'),
        bindingEvaluationReceiptDigest: binding(receipt.evaluationReceiptDigest),
        bindingExecutionReceiptDigest: binding(receipt.executionReceiptDigest),
        compilerValidationEvidence: binding(finalPackage.compilerValidation.descriptor.iri),
        compilerValidationEvidenceDigest: binding(finalPackage.compilerValidation.descriptor.digest),
        evaluationReceiptDigest: binding(receipt.evaluationReceiptDigest),
        executionReceiptDigest: binding(receipt.executionReceiptDigest),
        producer: binding('urn:usf:validationproducer:compilersemanticenforcementaggregate'),
        reevaluationState: binding('urn:usf:resultstate:passed'),
        resultState: binding('urn:usf:resultstate:passed'),
        stageOneSettledAuthorityDigest: binding(d1),
        validationEvaluation: binding('urn:usf:validationevaluation:compilersemanticenforcementaggregate'),
        validationEvidence: binding(descriptor.iri),
        validationEvidenceDigest: binding(descriptor.digest),
        validationExecution: binding('urn:usf:validationexecution:compilersemanticenforcementaggregate'),
        validationResult: binding('urn:usf:validationresult:compilersemanticenforcementaggregate'),
      }));
      return harness(base, [], {
        authority: d2,
        receiptBinding: {
          evaluatedAuthorityDigest: binding(d1), evaluationReceiptDigest: binding(input.stage1Preparation.evaluationReceiptDigest),
          executionReceiptDigest: binding(input.stage1Preparation.executionReceiptDigest),
          reevaluation: binding('urn:usf:postpublicationreevaluation:compilersemanticenforcementaggregate'),
          result: binding(AGGREGATE_RESULT_IRI),
        },
        rejectComponents: true,
        validationRows: rows,
      }).producer.produceTerminal(input);
    },
  };
  const pendingForExternalDelta = await producer.preparePending({ requestedAuthorityDigest: d0 });
  const expectedSource = pendingForExternalDelta.aggregateResult.evaluation.sourceBinding;
  const externalFixture = externalAuthorityLifecycleFixture(commandModule, protocolModule, expectedSource, d0);
  verifyExternalAuthorityProofApproval = externalFixture.verifyProofApprovalEnvelope;
  for (const bytes of externalFixture.artifactBytes.values()) putCas(base.casRoot, bytes);
  const externalAuthorityDelta = externalFixture.packageValue;
  const trustAnchor = {
    algorithm: 'openpgp', approvalThreshold: 1,
    authorityScopes: [
      { authorityDomain: 'urn:usf:capabilityowner:semanticmodelcompilation', repository: 'maldous/usf-graph' },
      { authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane', repository: 'maldous/usf-factory' },
      { authorityDomain: 'urn:usf:capabilityowner:factoryproviderdurablecontrolplane', repository: 'maldous/usf-factory' },
    ],
    fingerprint: 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D', githubPrincipal: 'maldous',
    principal: protocolModule.AUTHORITY_PRINCIPAL, protocol: 'semantic-proof-v1',
  };
  const graphPaths = AGGREGATE_REVIEWED_SOURCE_PATHS;
  const providerPaths = ['src/usf_factory/provider_catalog.py'];
  const durableProviderPaths = ['src/usf_factory/v3_events.py'];
  const ownerAssignments = [
    { authorityDomain: 'urn:usf:capabilityowner:semanticmodelcompilation', repository: 'maldous/usf-graph', sourcePaths: graphPaths, envelope: { payload: { authority_pre_digest: d0 }, signature: 'fixture' } },
    { authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane', repository: 'maldous/usf-factory', sourcePaths: providerPaths, envelope: { payload: { authority_pre_digest: d0 }, signature: 'fixture' } },
    { authorityDomain: 'urn:usf:capabilityowner:factoryproviderdurablecontrolplane', repository: 'maldous/usf-factory', sourcePaths: durableProviderPaths, envelope: { payload: { authority_pre_digest: d0 }, signature: 'fixture' } },
  ];
  const verifyOwnerAssignment = (envelope, options) => ({
    algorithm: trustAnchor.algorithm,
    authority_pre_digest: envelope.payload.authority_pre_digest,
    candidate_digest: options.candidateDigest,
    envelope_digest: protocolModule.sha256(protocolModule.canonicalJson({ envelope, domain: options.authorityDomain })),
    fingerprint: trustAnchor.fingerprint,
    issued_at: '2026-08-01T00:00:00Z',
    source_scope_digest: protocolModule.sourceScopeDigest(options.sourcePaths),
  });
  const ledgerPath = join(base.repositoryPath, '..', 'publication-ledger.json');
  writeFileSync(ledgerPath, '{"nonces":{},"protocol":"semantic-proof-v1"}\n', { mode: 0o600 });
  let nonce = 0;
  const result = await publisherModule.runAggregateCompilerProductionLifecycle({
    expectedAuthorityDigest: d0, externalAuthorityDelta, ownerAssignments, trustAnchor, producer,
    command, readAuthorityWitness,
    trustedTime: async () => '2026-08-01T00:05:00Z',
    evidenceStore: publisherModule.createCasEvidenceStore(base.casRoot),
    claimProvider: async ({ authorityDigest: pre, canonicalCandidateBytes, candidateDigest }) => {
      assert.equal(sha256(Buffer.from(canonicalCandidateBytes, 'base64')), candidateDigest);
      nonce += 1;
      const publicationGrant = { payload: {
        authority_pre_digest: pre, candidate_digest: candidateDigest, claim_type: 'publication_grant',
        nonce: `00000000-0000-4000-8000-${String(nonce).padStart(12, '0')}`,
      }, signature: 'fixture' };
      return { candidateApproval: { payload: { candidate_digest: candidateDigest }, signature: 'fixture' }, publicationGrant };
    },
    publicationOptions: {
      ledgerPath,
      persist: (receipt) => ({ digest: protocolModule.publicationReceiptDigest(receipt), path: '/fixture/receipt.json' }),
      protocolJournal: PERMISSION_MODEL_ENABLED ? memoryProtocolJournal() : undefined,
      settle: async (_read, first) => first,
      verifyOwnerAssignment,
      verifyBundle: ({ publicationGrant }) => ({
        assignment: {}, approval: {}, grant: {
          ...publicationGrant.payload,
          envelope_digest: protocolModule.envelopeDigest(publicationGrant),
          single_use: true,
        },
      }),
    },
  });
  assert.equal(result.terminal.current_proof_results, 1);
  assert.equal(result.externalAuthorityDelta.patchDigest, externalAuthorityDelta.patchDigest);
  assert.equal(result.terminal.proof_currentness, 'CURRENT');
  assert.equal(result.terminal.action_state, 'PROCEED');
  assert.equal(phase, 2);
  assert.equal(live.get(proofsGraph).has(
    DataFactory.namedNode(externalAuthorityDelta.resolutionIri),
    DataFactory.namedNode('urn:usf:ontology:resolvesAuthorityConflict'),
    DataFactory.namedNode(externalAuthorityDelta.conflictIri),
    null,
  ), true);
  assert.equal(
    result.stage2.candidate.bytes.toString('utf8').includes(
      `D <${externalAuthorityDelta.resolutionIri}> <urn:usf:ontology:resolvesAuthorityConflict>`,
    ),
    false,
  );
  assert.equal(live.get(proofsGraph).has(null, rdfType, DataFactory.namedNode('urn:usf:ontology:PostPublicationAggregateProofResult'), null), true);
  assert.equal(live.get(proofsGraph).has(
    DataFactory.namedNode('urn:usf:validationselfpublicationbinding:factoryproviderv3implementation'),
    DataFactory.namedNode('urn:usf:ontology:validationBindingProducerSourcePath'),
    DataFactory.literal('src/usf_factory/adaptive_routing.py'),
    null,
  ), true);
  assert.equal(live.get(proofsGraph).has(
    DataFactory.namedNode('urn:usf:validationselfpublicationbinding:factoryproviderv3implementation'),
    DataFactory.namedNode('urn:usf:ontology:validationBindingProducerSourceHead'),
    DataFactory.literal('a'.repeat(40)),
    null,
  ), true);
  assert.equal(live.get(proofsGraph).has(
    DataFactory.namedNode('urn:usf:validationselfpublicationbinding:factoryproviderv3implementation'),
    DataFactory.namedNode('urn:usf:ontology:validationBindingAdmissionSourceHead'),
    DataFactory.literal('c'.repeat(40)),
    null,
  ), true);
});
