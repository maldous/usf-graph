import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  assertAcceptedCompilerResult,
  DEFAULT_PROTOCOL_JOURNAL,
  runPublication,
} from './semantic-authority-publication.mjs';
import { createSemanticModelCompilationCommand } from './semantic-model-compilation-command.mjs';
import {
  consumeGrantNonce,
  canonicalJson,
  envelopeDigest,
  publicationReceiptDigest,
  sha256,
} from './semantic-proof-v1.mjs';

const PRE = `sha256:${'1'.repeat(64)}`;
const INITIAL_BYTES = Buffer.from('# semantic-proof-v1 canonical-rdf-patch-v1 stage1\nD <urn:test:s> <urn:test:p> "old" <urn:test:graph> .\nA <urn:test:s> <urn:test:p> "new" <urn:test:graph> .\n');
const INITIAL_CANDIDATE = sha256(INITIAL_BYTES);
const STAGE_ONE = `sha256:${'3'.repeat(64)}`;
const FINAL = `sha256:${'4'.repeat(64)}`;
const REEVALUATION_BYTES = Buffer.from('# semantic-proof-v1 canonical-rdf-patch-v1 stage2\nD <urn:test:s> <urn:test:p> "new" <urn:test:graph> .\nA <urn:test:s> <urn:test:p> "final" <urn:test:graph> .\n');
const REEVALUATION_CANDIDATE = sha256(REEVALUATION_BYTES);
const EXECUTION_BYTES = Buffer.from('{"schema":"execution"}');
const EVALUATION_BYTES = Buffer.from('{"schema":"evaluation"}');
const EXECUTION = sha256(EXECUTION_BYTES);
const EVALUATION = sha256(EVALUATION_BYTES);
const OBSERVATION = `sha256:${'8'.repeat(64)}`;
const DOMAIN = 'urn:usf:capabilityowner:semanticmodelcompilation';
const REPOSITORY = 'maldous/usf-graph';
const PATHS = ['processes/semantic-assurance/semantic-proof-v1.mjs'];
const PROVIDER_PATHS = ['usf_factory/provider_catalogue.py'];
const INITIAL_NONCE = '00000000-0000-4000-8000-000000000001';
const REEVALUATION_NONCE = '00000000-0000-4000-8000-000000000002';
const PUBLISHED_AT = '2026-08-01T12:00:00Z';

const ownerAssignment = { payload: { claim: 'owner' }, signature: 'owner' };
const candidateApproval = { payload: { claim: 'approval' }, signature: 'approval' };
const witness = (digest) => ({ algorithm: 'sha256-rdfc10', digest, inventory: [], triples: 0 });
const compilerResult = (state, candidateDigest) => ({
  ok: true,
  commitOutcome: { candidateDigest, exactCandidateStateVerified: true, state },
});

function grantEnvelope(authorityPreDigest, candidateDigest, nonce) {
  return {
    payload: {
      authority_pre_digest: authorityPreDigest,
      candidate_digest: candidateDigest,
      claim_type: 'publication_grant',
      nonce,
    },
    signature: 'grant',
  };
}

function verifiedGrant(envelope) {
  return Object.freeze({
    ...envelope.payload,
    envelope_digest: envelopeDigest(envelope),
    single_use: true,
  });
}

const initialEnvelope = grantEnvelope(PRE, INITIAL_CANDIDATE, INITIAL_NONCE);
const reevaluationEnvelope = grantEnvelope(STAGE_ONE, REEVALUATION_CANDIDATE, REEVALUATION_NONCE);
const initialGrant = verifiedGrant(initialEnvelope);
const reevaluationGrant = verifiedGrant(reevaluationEnvelope);

function command(candidateDigest, {
  validate = compilerResult('VALIDATED_ROLLBACK', candidateDigest),
  commit = compilerResult('COMMITTED', candidateDigest),
  throwAfterCommit,
} = {}) {
  const evidenceBytes = Buffer.from(`${canonicalJson({ candidateDigest, conforms: true })}\n`);
  const withEvidence = (result) => ({
    ...result,
    validationEvidence: { bytes: evidenceBytes, digest: sha256(evidenceBytes) },
  });
  return {
    calls: [],
    state: 'pre',
    async inspectCandidateState() { return { candidateDigest, state: this.state }; },
    async execute(input) {
      this.calls.push({ expectedAuthorityDigest: input.expectedAuthorityDigest, publicationMode: input.publicationMode });
      if (input.publicationMode !== 'commit') return withEvidence(validate);
      this.state = 'post';
      if (throwAfterCommit) throw new Error(throwAfterCommit);
      return withEvidence(commit);
    },
    async composeCandidate({ generatedCandidateBytes }) {
      return { bytes: generatedCandidateBytes, digest: sha256(generatedCandidateBytes) };
    },
  };
}

function memoryEvidenceStore() {
  const values = new Map([[EXECUTION, EXECUTION_BYTES], [EVALUATION, EVALUATION_BYTES]]);
  return Object.freeze({
    persist(bytes) { const digest = sha256(bytes); values.set(digest, Buffer.from(bytes)); return { digest, size: bytes.length }; },
    read(digest) { if (!values.has(digest)) throw new Error(`missing CAS object ${digest}`); return Buffer.from(values.get(digest)); },
    verify(digest) { const bytes = this.read(digest); assert.equal(sha256(bytes), digest); return { digest, size: bytes.length }; },
  });
}

const ownerAssignments = Object.freeze([
  Object.freeze({ authorityDomain: DOMAIN, repository: REPOSITORY, sourcePaths: PATHS, envelope: ownerAssignment }),
  Object.freeze({
    authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane',
    repository: 'maldous/usf-factory', sourcePaths: PROVIDER_PATHS,
    envelope: { payload: { claim: 'provider-owner' }, signature: 'provider-owner' },
  }),
]);

function witnessReader(digests) {
  const values = [...digests];
  return async () => {
    if (values.length === 0) throw new Error('unexpected authority witness read');
    return witness(values.shift());
  };
}

function timeReader(values = [PUBLISHED_AT]) {
  const times = [...values];
  let last = times.at(-1);
  return async () => {
    if (times.length > 0) last = times.shift();
    return last;
  };
}

const settle = async (_read, first) => first;
const observation = (overrides = {}) => ({
  actionState: 'UNRESOLVED_FAIL_CLOSED',
  authorityDigest: STAGE_ONE,
  currentProofResults: 0,
  directProvisionalAggregateSelections: 1,
  observationReceiptDigest: OBSERVATION,
  ok: true,
  operation: 'observe_initial',
  proofCurrentness: 'PENDING',
  selectedProvisionalAggregateResult: 'urn:usf:proofresult:provisionalaggregatecompilerproof',
  ...overrides,
});
const preparation = (overrides = {}) => ({
  candidateDigest: INITIAL_CANDIDATE,
  evaluatedAuthorityDigest: STAGE_ONE,
  evaluationReceiptDigest: EVALUATION,
  executionReceiptDigest: EXECUTION,
  ok: true,
  operation: 'produce_initial',
  protocol: 'semantic-proof-v1',
  state: 'REEVALUATION_CANDIDATE_PREPARED',
  ...overrides,
});
const terminal = (overrides = {}) => ({
  actionState: 'PROCEED',
  authorityAfterDigest: FINAL,
  currentProofResults: 1,
  evaluatedAuthorityDigest: STAGE_ONE,
  evaluationReceiptDigest: EVALUATION,
  executionReceiptDigest: EXECUTION,
  ok: true,
  operation: 'verify_reevaluation',
  proofCurrentness: 'CURRENT',
  selectedAggregateResult: 'urn:usf:proofresult:aggregatecompilerproof',
  ...overrides,
});

function producer({ observe = observation, produce = preparation, verify = terminal, calls = [] } = {}) {
  return async (request) => {
    calls.push(request.operation);
    if (request.operation === 'observe_initial') return observe();
    if (request.operation === 'produce_initial') return produce();
    if (request.operation === 'verify_reevaluation') return verify();
    throw new Error(`unexpected producer operation ${request.operation}`);
  };
}

const permissionJournals = new Map();

function memoryProtocolJournal(ledger) {
  const clone = (value) => JSON.parse(canonicalJson(value));
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
          package: clone(observation), package_digest: sha256(canonicalJson(observation)), recorded_at: observedAt,
        },
      }));
    },
    recordInitialReevaluationPreparation(grant, preparationValue, { observedAt }) {
      return update(grant, (record) => ({
        ...record,
        reevaluation_preparation: {
          package: clone(preparationValue), package_digest: sha256(canonicalJson(preparationValue)), recorded_at: observedAt,
        },
      }));
    },
    assertReevaluationPredecessor({ priorReceipt, preparation: preparationValue, authorityPreDigest }) {
      const prior = ledger.nonces[priorReceipt.grant_nonce];
      if (!prior || prior.state !== 'consumed' || prior.publication_phase !== 'initial'
          || priorReceipt.publication_phase !== 'initial' || priorReceipt.terminal_state !== 'PENDING'
          || priorReceipt.authority_after_digest !== authorityPreDigest
          || preparationValue.evaluatedAuthorityDigest !== authorityPreDigest
          || preparationValue.candidateDigest !== priorReceipt.candidate_digest
          || prior.final_receipt_digest !== publicationReceiptDigest(priorReceipt)
          || prior.reevaluation_preparation?.package_digest !== sha256(canonicalJson(preparationValue))
          || canonicalJson(prior.reevaluation_preparation?.package) !== canonicalJson(preparationValue)) {
        throw new Error('reevaluation publication has no durable stage-1 transaction linkage');
      }
      return Object.freeze({ prior: clone(prior), preparation: clone(preparationValue) });
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

function journal() {
  if (process.permission) {
    const ledgerPath = `memory:semantic-publisher-test-${permissionJournals.size + 1}`;
    const ledger = { nonces: {}, protocol: 'semantic-proof-v1' };
    const protocolJournal = memoryProtocolJournal(ledger);
    permissionJournals.set(ledgerPath, protocolJournal);
    return {
      ledgerPath,
      protocolJournal,
      read: () => JSON.parse(canonicalJson(ledger)),
      remove: () => permissionJournals.delete(ledgerPath),
    };
  }
  const directory = mkdtempSync(join(tmpdir(), 'semantic-publisher-test-'));
  const ledgerPath = join(directory, 'ledger.json');
  writeFileSync(ledgerPath, '{"nonces":{},"protocol":"semantic-proof-v1"}\n', { mode: 0o600 });
  return {
    ledgerPath,
    read: () => JSON.parse(readFileSync(ledgerPath, 'utf8')),
    remove: () => { unlinkSync(ledgerPath); rmdirSync(directory); },
  };
}

function invocation({
  publicationPhase = 'initial',
  expectedAuthorityDigest = PRE,
  expectedCandidateDigest = INITIAL_CANDIDATE,
  publicationGrant = initialEnvelope,
  grant = initialGrant,
  commandInstance = command(expectedCandidateDigest),
  readAuthorityWitness = witnessReader([expectedAuthorityDigest, expectedAuthorityDigest]),
  ...overrides
} = {}) {
  const invocationValue = {
    authorityDomain: DOMAIN,
    candidateApproval,
    candidateBytes: expectedCandidateDigest === REEVALUATION_CANDIDATE ? REEVALUATION_BYTES : INITIAL_BYTES,
    command: commandInstance,
    expectedAuthorityDigest,
    expectedCandidateDigest,
    ownerAssignments,
    publicationGrant,
    publicationPhase,
    readAuthorityWitness,
    repository: REPOSITORY,
    sourcePaths: PATHS,
    trustedTime: timeReader(),
    evidenceStore: memoryEvidenceStore(),
    trustAnchor: { principal: 'urn:usf:principal:matthewaldous' },
    verifyBundle: () => ({ assignment: {}, approval: {}, grant }),
    verifyOwnerAssignment: () => ({}),
    ...overrides,
  };
  if (!invocationValue.protocolJournal && permissionJournals.has(invocationValue.ledgerPath)) {
    invocationValue.protocolJournal = permissionJournals.get(invocationValue.ledgerPath);
  }
  return invocationValue;
}

async function publishInitial(state, overrides = {}) {
  let persistedReceipt;
  const compiler = overrides.commandInstance || command(INITIAL_CANDIDATE);
  const output = await runPublication(invocation({
    mode: 'commit',
    commandInstance: compiler,
    ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE, STAGE_ONE, STAGE_ONE, STAGE_ONE]),
    settle,
    postPublicationReevaluate: producer(),
    persist: (receipt) => {
      persistedReceipt = receipt;
      return { digest: publicationReceiptDigest(receipt), path: '/proof/initial.json' };
    },
    ...overrides,
  }));
  return { compiler, output, preparation: output.reevaluationPreparation, receipt: persistedReceipt };
}

test('prepare is read-only and derives the canonical candidate without authority claims', async () => {
  const compiler = command(INITIAL_CANDIDATE);
  const prepared = await runPublication({
    mode: 'prepare', publicationPhase: 'initial', expectedAuthorityDigest: PRE,
    candidateBytes: INITIAL_BYTES, command: compiler, readAuthorityWitness: witnessReader([PRE, PRE]),
    evidenceStore: memoryEvidenceStore(),
  });
  assert.equal(prepared.canonicalCandidateDigest, INITIAL_CANDIDATE);
  assert.deepEqual(Buffer.from(prepared.canonicalCandidateBytes, 'base64'), INITIAL_BYTES);
  assert.deepEqual(compiler.calls, [{ expectedAuthorityDigest: PRE, publicationMode: 'validate' }]);
});

test('both independently scoped owner assignments are verified before validation and CAS bytes round-trip', async () => {
  const calls = [];
  const store = memoryEvidenceStore();
  const result = await runPublication(invocation({
    mode: 'validate', evidenceStore: store,
    verifyOwnerAssignment: (_envelope, options) => { calls.push([options.authorityDomain, options.repository]); return {}; },
  }));
  assert.deepEqual(calls, [
    [DOMAIN, REPOSITORY],
    ['urn:usf:capabilityowner:providerconfigurationplane', 'maldous/usf-factory'],
  ]);
  assert.equal(sha256(store.read(result.validationEvidence.digest)), result.validationEvidence.digest);
});

test('actual RDF Patch compiler adapter validates and commits the identical canonical bytes', async () => {
  const graph = 'urn:test:graph';
  let value = 'old';
  const transaction = () => ({ value });
  const client = {
    async connectivity() { return 1; },
    async begin() { return transaction(); },
    async rollback() {},
    async commit(tx) { value = tx.value; },
    async constructInTransaction(tx) {
      return `<urn:test:s> <urn:test:p> "${tx.value}" .\n`;
    },
    async clearGraphs(tx) { tx.value = null; },
    async addData(tx, content) {
      const match = /<urn:test:s>\s+<urn:test:p>\s+"([^"]+)"/.exec(content);
      tx.value = match?.[1] ?? null;
    },
    async validateInTransactionWithReceipt() { return { conforms: true }; },
    async reportInTransaction() { return []; },
    async selectInTransaction() { return []; },
  };
  const manifest = {
    authored: [], definitions: [{ file: 'authority.ttl', graph }], derived: [], reviews: [], rules: [],
    shapes: [{
      file: 'shapes.ttl', graph: 'urn:usf:graph:shapes', liveValidation: true,
      path: join(import.meta.dirname, '../../semantic-model/shapes.ttl'),
    }],
    publicationBudget: { maximumProjectedStatementCount: 999999 },
  };
  const compiler = createSemanticModelCompilationCommand({
    checkLocalFunction: () => {}, client,
    loadManifestFunction: () => manifest,
    readAuthorityWitness: async () => witness(value === 'old' ? PRE : FINAL),
    repositoryRoot: join(import.meta.dirname, '../..'),
  });
  const validation = await compiler.execute({
    candidateBytes: INITIAL_BYTES, candidateDigest: INITIAL_CANDIDATE,
    expectedAuthorityDigest: PRE, publicationMode: 'validate',
  });
  assert.equal(validation.commitOutcome.candidateDigest, INITIAL_CANDIDATE);
  assert.equal(validation.commitOutcome.state, 'VALIDATED_ROLLBACK');
  assert.equal(value, 'old');
  const committed = await compiler.execute({
    candidateBytes: INITIAL_BYTES, candidateDigest: INITIAL_CANDIDATE,
    expectedAuthorityDigest: PRE, publicationMode: 'commit',
  });
  assert.equal(committed.commitOutcome.candidateDigest, validation.commitOutcome.candidateDigest);
  assert.equal(committed.commitOutcome.state, 'COMMITTED');
  assert.equal(value, 'new');
  assert.equal((await compiler.inspectCandidateState({
    candidateBytes: INITIAL_BYTES, candidateDigest: INITIAL_CANDIDATE,
  })).state, 'post');
});

test('trusted Stardog time absence fails closed before signed validation', async () => {
  await assert.rejects(runPublication(invocation({
    mode: 'validate', trustedTime: undefined,
  })), /trusted-time reader/);
});

test('fractional Stardog publication time is canonicalized before envelope verification', async () => {
  let verifiedAt;
  const result = await runPublication(invocation({
    mode: 'validate',
    trustedTime: async () => '2026-08-01T11:00:00.577Z',
    verifyBundle: ({ now }) => {
      verifiedAt = now.toISOString();
      return { assignment: {}, approval: {}, grant: initialGrant };
    },
  }));
  assert.equal(result.mode, 'validate');
  assert.equal(verifiedAt, '2026-08-01T11:00:00.000Z');
});

test('crash after atomic commit recovers from exact post-state without republishing', async () => {
  const state = journal();
  const compiler = command(INITIAL_CANDIDATE, { throwAfterCommit: 'process interrupted after commit' });
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE]), settle,
    postPublicationReevaluate: producer(),
  })), /process interrupted after commit/);
  assert.equal(state.read().nonces[INITIAL_NONCE].state, 'reserved');
  const recovered = await runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([FINAL, FINAL, FINAL]), settle,
    postPublicationReevaluate: producer({
      observe: () => observation({ authorityDigest: FINAL }),
      produce: () => preparation({ evaluatedAuthorityDigest: FINAL }),
    }),
    persist: (receipt) => ({ digest: publicationReceiptDigest(receipt), path: '/proof/recovered.json' }),
  }));
  assert.equal(recovered.recovered, true);
  assert.equal(compiler.calls.filter(({ publicationMode }) => publicationMode === 'commit').length, 1);
  state.remove();
});

test('compiler failure, unaccepted state, inexact candidate, and digest mismatch fail closed', async () => {
  for (const [bad, pattern] of [
    [{ ...compilerResult('VALIDATED_ROLLBACK', INITIAL_CANDIDATE), ok: false }, /not an exact accepted/],
    [compilerResult('COMMITTED', INITIAL_CANDIDATE), /not an exact accepted/],
    [{ ...compilerResult('VALIDATED_ROLLBACK', INITIAL_CANDIDATE), commitOutcome: { ...compilerResult('VALIDATED_ROLLBACK', INITIAL_CANDIDATE).commitOutcome, exactCandidateStateVerified: false } }, /not an exact accepted/],
    [compilerResult('VALIDATED_ROLLBACK', sha256('wrong')), /differs from the expected/],
  ]) await assert.rejects(runPublication(invocation({
    mode: 'validate', commandInstance: command(INITIAL_CANDIDATE, { validate: bad }),
    readAuthorityWitness: witnessReader([PRE, PRE]),
  })), pattern);
  assert.throws(() => assertAcceptedCompilerResult(compilerResult('FAILED', INITIAL_CANDIDATE), {
    phase: 'commit', expectedCandidateDigest: INITIAL_CANDIDATE,
  }), /not an exact accepted/);
});

test('both commit phases require the injected producer callback', async () => {
  await assert.rejects(runPublication(invocation({ mode: 'commit' })), /requires an injected mandatory/);
  await assert.rejects(runPublication(invocation({
    mode: 'commit', publicationPhase: 'reevaluation', expectedAuthorityDigest: STAGE_ONE,
    expectedCandidateDigest: REEVALUATION_CANDIDATE, publicationGrant: reevaluationEnvelope,
    grant: reevaluationGrant,
  })), /requires an injected mandatory/);
});

test('stage-1 state comes from observe_initial and produce_initial runs only after durable consumption', async () => {
  const state = journal();
  const calls = [];
  let stateAtProduce;
  const stage = await publishInitial(state, {
    postPublicationReevaluate: producer({
      calls,
      produce: () => {
        stateAtProduce = state.read().nonces[INITIAL_NONCE].state;
        return preparation();
      },
    }),
  });
  assert.deepEqual(calls, ['observe_initial', 'produce_initial']);
  assert.equal(stateAtProduce, 'consumed');
  assert.equal(stage.output.direct_provisional_aggregate_selections, 1);
  assert.equal(stage.output.current_proof_results, 0);
  assert.equal(stage.output.proof_currentness, 'PENDING');
  assert.equal(stage.output.action_state, 'UNRESOLVED_FAIL_CLOSED');
  assert.equal(stage.output.selected_provisional_aggregate_result, 'urn:usf:proofresult:provisionalaggregatecompilerproof');
  assert.equal(state.read().nonces[INITIAL_NONCE].published_at, PUBLISHED_AT);
  state.remove();
});

test('stage-1 projection mismatch is rejected without a false receipt or generic permanent failure', async () => {
  const state = journal();
  await assert.rejects(runPublication(invocation({
    mode: 'commit', ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE, STAGE_ONE, STAGE_ONE]), settle,
    postPublicationReevaluate: producer({ observe: () => observation({ directProvisionalAggregateSelections: 0 }) }),
    persist: () => { throw new Error('receipt must not persist'); },
  })), /exactly one provisional aggregate/);
  const record = state.read().nonces[INITIAL_NONCE];
  assert.equal(record.state, 'published_pending_reevaluation');
  assert.equal(record.final_receipt, undefined);
  state.remove();
});

test('reevaluation requires exact full preparation package and durable predecessor equality', async () => {
  const state = journal();
  const stageOne = await publishInitial(state);
  const stageTwo = {
    mode: 'validate', publicationPhase: 'reevaluation', ledgerPath: state.ledgerPath,
    expectedAuthorityDigest: STAGE_ONE, expectedCandidateDigest: REEVALUATION_CANDIDATE,
    publicationGrant: reevaluationEnvelope, grant: reevaluationGrant,
    commandInstance: command(REEVALUATION_CANDIDATE),
    priorPublicationReceipt: stageOne.receipt,
  };
  await assert.rejects(runPublication(invocation({
    ...stageTwo, readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]),
    reevaluationPreparation: { ...stageOne.preparation, executionReceiptDigest: sha256('substituted') },
  })), /no durable stage-1 transaction linkage/);
  await assert.rejects(runPublication(invocation({
    ...stageTwo, readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]),
    priorPublicationReceipt: { ...stageOne.receipt, candidate_digest: REEVALUATION_CANDIDATE },
    reevaluationPreparation: { ...stageOne.preparation, candidateDigest: REEVALUATION_CANDIDATE },
  })), /no durable stage-1 transaction linkage/);
  const accepted = await runPublication(invocation({
    ...stageTwo, readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]),
    reevaluationPreparation: stageOne.preparation,
  }));
  assert.equal(accepted.canonicalCandidateDigest, REEVALUATION_CANDIDATE);
  assert.equal(stageOne.preparation.candidateDigest, INITIAL_CANDIDATE);
  assert.equal(state.read().nonces[INITIAL_NONCE].reevaluation_preparation.package_digest,
    stageOne.output.reevaluationPreparationDigest);
  state.remove();
});

test('expiry during validation is rechecked immediately before commit', async () => {
  const state = journal();
  const compiler = command(INITIAL_CANDIDATE);
  const expires = Date.parse('2026-08-01T12:00:00Z');
  const verifyBundle = ({ now }) => {
    if (now.getTime() >= expires) throw new Error('signed envelope is not current at trusted time');
    return { assignment: {}, approval: {}, grant: initialGrant };
  };
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE]), settle,
    trustedTime: timeReader(['2026-08-01T11:00:00Z', '2026-08-01T11:59:59Z', '2026-08-01T12:00:00Z']),
    verifyBundle, postPublicationReevaluate: producer(),
  })), /not current at trusted time/);
  assert.deepEqual(compiler.calls, [{ expectedAuthorityDigest: PRE, publicationMode: 'validate' }]);
  assert.equal(state.read().nonces[INITIAL_NONCE].state, 'failed');
  state.remove();
});

test('consume failure is recoverable without republishing', async () => {
  const state = journal();
  const compiler = command(INITIAL_CANDIDATE);
  let consumeAttempts = 0;
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE, STAGE_ONE, STAGE_ONE]), settle,
    postPublicationReevaluate: producer(),
    protocolJournal: {
      ...(state.protocolJournal || DEFAULT_PROTOCOL_JOURNAL),
      consumeGrantNonce: () => { consumeAttempts += 1; throw new Error('journal write interrupted'); },
    },
  })), /journal write interrupted/);
  assert.equal(state.read().nonces[INITIAL_NONCE].state, 'published_pending_reevaluation');
  const recovered = await runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]), settle,
    postPublicationReevaluate: producer(),
    persist: (receipt) => ({ digest: publicationReceiptDigest(receipt), path: '/proof/recovered.json' }),
  }));
  assert.equal(recovered.recovered, true);
  assert.equal(consumeAttempts, 1);
  assert.deepEqual(compiler.calls, [
    { expectedAuthorityDigest: PRE, publicationMode: 'validate' },
    { expectedAuthorityDigest: PRE, publicationMode: 'commit' },
  ]);
  state.remove();
});

test('persist failure leaves a full consumed receipt and recovery resumes producer without republishing', async () => {
  const state = journal();
  const compiler = command(INITIAL_CANDIDATE);
  let produceCalls = 0;
  const callback = producer({ produce: () => { produceCalls += 1; return preparation(); } });
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE, STAGE_ONE, STAGE_ONE]), settle,
    postPublicationReevaluate: callback,
    persist: () => { throw new Error('receipt store interrupted'); },
  })), /receipt store interrupted/);
  const interrupted = state.read().nonces[INITIAL_NONCE];
  assert.equal(interrupted.state, 'consumed');
  assert.equal(interrupted.final_receipt.grant_consumed, true);
  assert.equal(interrupted.final_receipt_digest, publicationReceiptDigest(interrupted.final_receipt));
  const recovered = await runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]), settle,
    postPublicationReevaluate: callback,
    persist: (receipt) => ({ digest: publicationReceiptDigest(receipt), path: '/proof/recovered.json' }),
  }));
  assert.equal(recovered.recovered, true);
  assert.equal(produceCalls, 1);
  assert.equal(state.read().nonces[INITIAL_NONCE].reevaluation_preparation.package.candidateDigest, INITIAL_CANDIDATE);
  assert.equal(compiler.calls.filter((call) => call.publicationMode === 'commit').length, 1);
  state.remove();
});

test('reevaluation terminal verification resumes after post-commit process failure without republishing', async () => {
  const state = journal();
  const stageOne = await publishInitial(state);
  const compiler = command(REEVALUATION_CANDIDATE);
  let terminalAttempts = 0;
  const second = invocation({
    mode: 'commit', publicationPhase: 'reevaluation', ledgerPath: state.ledgerPath,
    expectedAuthorityDigest: STAGE_ONE, expectedCandidateDigest: REEVALUATION_CANDIDATE,
    publicationGrant: reevaluationEnvelope, grant: reevaluationGrant, commandInstance: compiler,
    readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE, FINAL, FINAL]), settle,
    priorPublicationReceipt: stageOne.receipt, reevaluationPreparation: stageOne.preparation,
    postPublicationReevaluate: producer({ verify: () => {
      terminalAttempts += 1;
      if (terminalAttempts === 1) throw new Error('projector interrupted');
      return terminal();
    } }),
    persist: (receipt) => ({ digest: publicationReceiptDigest(receipt), path: '/proof/final.json' }),
  });
  await assert.rejects(runPublication(second), /projector interrupted/);
  assert.equal(state.read().nonces[REEVALUATION_NONCE].state, 'published_pending_reevaluation');
  const recovered = await runPublication({
    ...second,
    readAuthorityWitness: witnessReader([FINAL]),
  });
  assert.equal(recovered.proof_currentness, 'CURRENT');
  assert.equal(recovered.action_state, 'PROCEED');
  assert.equal(terminalAttempts, 2);
  assert.equal(compiler.calls.filter((call) => call.publicationMode === 'commit').length, 1);
  state.remove();
});
