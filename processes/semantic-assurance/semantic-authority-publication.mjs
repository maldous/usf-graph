#!/usr/bin/env node
import { chmodSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  aggregateCompilerAuthorityCandidateInternals,
  materializeAggregateCompilerAuthorityCandidate,
} from '../../assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.mjs';

import {
  assertInitialProjectionObservation,
  assertInitialReevaluationPreparation,
  assertPostPublicationTerminalState,
  assertReevaluationPredecessor,
  assertSemanticProofPublicationReceipt,
  canonicalJson,
  canonicalUtcSecond,
  consumeGrantNonce,
  envelopeDigest,
  ownerAssignmentCandidateDigest,
  failGrantNonce,
  publicationReceiptDigest,
  readEnvelope,
  readPublicationTransaction,
  readPublicationTransactionForEnvelope,
  readTrustAnchor,
  recordInitialProjectionObservation,
  recordInitialReevaluationPreparation,
  recordPostPublicationReevaluation,
  recordPublicationOutcome,
  reserveGrantNonce,
  sha256,
  sourceScopeDigest,
  verifyEnvelope,
  verifyPublicationBundle,
} from './semantic-proof-v1.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const PREPARE_STATES = new Set(['ROLLED_BACK', 'VALIDATED', 'VALIDATED_ROLLBACK']);
const COMMIT_STATE = 'COMMITTED';
const POST_PUBLICATION_JOURNAL_STATES = new Set([
  'published_pending_reevaluation', 'reevaluated_pending_receipt', 'consumed',
]);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const GRAPH_DOMAIN = 'urn:usf:capabilityowner:semanticmodelcompilation';
const FACTORY_DOMAIN = 'urn:usf:capabilityowner:providerconfigurationplane';
const FACTORY_DURABLE_DOMAIN = 'urn:usf:capabilityowner:factoryproviderdurablecontrolplane';
const OWNER_SCOPES = Object.freeze([
  Object.freeze({ authorityDomain: GRAPH_DOMAIN, repository: 'maldous/usf-graph' }),
  Object.freeze({ authorityDomain: FACTORY_DOMAIN, repository: 'maldous/usf-factory' }),
  Object.freeze({ authorityDomain: FACTORY_DURABLE_DOMAIN, repository: 'maldous/usf-factory' }),
]);
const COMPILER_VALIDATION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementcompilervalidation';
const AGGREGATE_EXECUTION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementaggregateexecution';
const AGGREGATE_EVALUATION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementaggregateevaluation';

export const DEFAULT_PROTOCOL_JOURNAL = Object.freeze({
  assertReevaluationPredecessor,
  consumeGrantNonce,
  failGrantNonce,
  readPublicationTransaction,
  readPublicationTransactionForEnvelope,
  recordInitialProjectionObservation,
  recordInitialReevaluationPreparation,
  recordPostPublicationReevaluation,
  recordPublicationOutcome,
  reserveGrantNonce,
});

const PROTOCOL_JOURNAL_OPERATIONS = Object.freeze(Object.keys(DEFAULT_PROTOCOL_JOURNAL));

function protocolJournalAdapter(value) {
  if (!value || PROTOCOL_JOURNAL_OPERATIONS.some((operation) => typeof value[operation] !== 'function')) {
    throw new Error('publisher requires a complete protocol journal IO/synchronization adapter');
  }
  return value;
}

function requiredArgument(argv, name) {
  const prefix = `--${name}=`;
  const matches = argv.filter((value) => value.startsWith(prefix));
  if (matches.length !== 1 || matches[0].length === prefix.length) throw new Error(`exactly one explicit ${prefix}<value> is required`);
  return matches[0].slice(prefix.length);
}

function optionalArgument(argv, name) {
  const prefix = `--${name}=`;
  const matches = argv.filter((value) => value.startsWith(prefix));
  if (matches.length > 1 || matches.some((value) => value.length === prefix.length)) throw new Error(`at most one explicit ${prefix}<value> is permitted`);
  return matches.length === 1 ? matches[0].slice(prefix.length) : undefined;
}

function repeatedArgument(argv, name) {
  const prefix = `--${name}=`;
  const values = argv.filter((value) => value.startsWith(prefix)).map((value) => value.slice(prefix.length));
  if (values.length < 1 || values.some((value) => value.length < 1)) throw new Error(`at least one explicit ${prefix}<value> is required`);
  return values;
}

const phase = (witness) => ({ digest: witness.digest, graphCount: witness.inventory.length, triples: witness.triples });

function sameWitness(left, right) {
  return left.digest === right.digest && left.triples === right.triples && left.inventory.length === right.inventory.length;
}

export async function settledWitness(readAuthorityWitness, first) {
  let previous = first;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, attempt === 0 ? 0 : 1000));
    const current = await readAuthorityWitness();
    if (sameWitness(current, previous)) return current;
    previous = current;
  }
  throw new Error('semantic authority did not settle after publication');
}

export function persistReceipt(receipt) {
  assertSemanticProofPublicationReceipt(receipt);
  const bytes = `${canonicalJson(receipt)}\n`;
  const digest = publicationReceiptDigest(receipt);
  const directory = '/var/lib/usf-programme/publication-receipts';
  const path = `${directory}/${digest.slice(7)}.json`;
  mkdirSync(directory, { recursive: true, mode: 0o755 });
  try {
    writeFileSync(path, bytes, { flag: 'wx', mode: 0o444 });
  } catch (error) {
    if (error.code !== 'EEXIST' || readFileSync(path, 'utf8') !== bytes) throw error;
  }
  chmodSync(path, 0o444);
  return Object.freeze({ digest, path });
}

export function assertAcceptedCompilerResult(result, { phase: compilerPhase, expectedCandidateDigest } = {}) {
  const outcome = result?.commitOutcome;
  const acceptedStates = compilerPhase === 'commit' ? new Set([COMMIT_STATE]) : PREPARE_STATES;
  if (result?.ok !== true || !outcome || outcome.exactCandidateStateVerified !== true
      || !acceptedStates.has(outcome.state) || !SHA256.test(outcome.candidateDigest || '')) {
    throw new Error(`compiler ${compilerPhase} result is not an exact accepted candidate state`);
  }
  if (expectedCandidateDigest !== undefined && outcome.candidateDigest !== expectedCandidateDigest) {
    throw new Error(`compiler ${compilerPhase} candidate digest differs from the expected canonical candidate`);
  }
  return outcome;
}

function assertExpectedDigest(value, label) {
  if (!SHA256.test(value || '')) throw new Error(`${label} must be an exact sha256 digest`);
  return value;
}

async function trustedInstant(trustedTime) {
  if (typeof trustedTime !== 'function') throw new Error('publisher requires an injected trusted-time reader');
  const observed = await trustedTime();
  const value = observed instanceof Date ? observed.toISOString() : observed;
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
      || Number.isNaN(Date.parse(value))) {
    throw new Error('trusted publication time must be an RFC3339 UTC instant');
  }
  const canonical = canonicalUtcSecond(
    new Date(Math.floor(Date.parse(value) / 1000) * 1000).toISOString().replace('.000Z', 'Z'),
    'trusted publication time',
  );
  return Object.freeze({ canonical, date: new Date(canonical) });
}

function exactCandidate(candidateBytes, expectedCandidateDigest) {
  if (!Buffer.isBuffer(candidateBytes) || candidateBytes.length === 0) {
    throw new Error('publisher requires exact canonical candidate bytes');
  }
  const observed = sha256(candidateBytes);
  if (expectedCandidateDigest !== undefined && observed !== expectedCandidateDigest) {
    throw new Error('publisher candidate bytes differ from the signed candidate digest');
  }
  return Object.freeze({ bytes: Buffer.from(candidateBytes), digest: observed });
}

export function createCasEvidenceStore(casRoot = '/var/lib/usf-cas') {
  const canonicalRoot = realpathSync(casRoot);
  const rootStat = lstatSync(canonicalRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error('evidence CAS root must be a canonical directory');
  const ensureDirectory = (path) => {
    mkdirSync(path, { recursive: true, mode: 0o755 });
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) {
      throw new Error('evidence CAS directory is unsafe');
    }
    chmodSync(path, 0o755);
  };
  const pathFor = (contentDigest) => {
    assertExpectedDigest(contentDigest, 'evidence digest');
    const hexadecimal = contentDigest.slice(7);
    return `${canonicalRoot}/sha256/${hexadecimal.slice(0, 2)}/${hexadecimal}`;
  };
  const read = (contentDigest) => {
    const path = pathFor(contentDigest);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path) throw new Error('evidence CAS object is unsafe');
    const bytes = readFileSync(path);
    if (sha256(bytes) !== contentDigest) throw new Error('evidence CAS object failed digest verification');
    return bytes;
  };
  return Object.freeze({
    persist(bytes) {
      if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new Error('evidence CAS requires non-empty bytes');
      const contentDigest = sha256(bytes);
      const path = pathFor(contentDigest);
      ensureDirectory(`${canonicalRoot}/sha256`);
      ensureDirectory(dirname(path));
      try { writeFileSync(path, bytes, { flag: 'wx', mode: 0o444 }); } catch (error) {
        if (error.code !== 'EEXIST' || !read(contentDigest).equals(bytes)) throw error;
      }
      chmodSync(path, 0o444);
      if (!read(contentDigest).equals(bytes)) throw new Error('evidence CAS round-trip failed');
      return Object.freeze({ digest: contentDigest, path, size: bytes.length });
    },
    read,
    verify(contentDigest) {
      const bytes = read(contentDigest);
      return Object.freeze({ digest: contentDigest, size: bytes.length });
    },
  });
}

function evidenceStoreAdapter(value) {
  if (!value || typeof value.persist !== 'function' || typeof value.read !== 'function' || typeof value.verify !== 'function') {
    throw new Error('publisher requires one CAS evidence admission adapter');
  }
  return value;
}

function admitValidationEvidence(result, evidenceStore) {
  const evidence = result?.validationEvidence;
  if (!evidence || !Buffer.isBuffer(evidence.bytes) || evidence.digest !== sha256(evidence.bytes)) {
    throw new Error('compiler validation evidence is absent or non-canonical');
  }
  const persisted = evidenceStore.persist(evidence.bytes);
  if (persisted.digest !== evidence.digest || !evidenceStore.read(evidence.digest).equals(evidence.bytes)) {
    throw new Error('compiler validation evidence was not admitted exactly');
  }
  return Object.freeze({ digest: evidence.digest, size: evidence.bytes.length });
}

function persistenceDescriptor(evidenceStore, iri, bytes) {
  const persisted = evidenceStore.persist(bytes);
  if (sha256(evidenceStore.read(persisted.digest)) !== persisted.digest) throw new Error(`CAS persistence failed for ${iri}`);
  const persistenceReceiptBytes = Buffer.from(canonicalJson({
    byteLength: bytes.length,
    contentDigest: persisted.digest,
    iri,
    schema: 'semantic-proof-v1-cas-persistence-receipt-v1',
  }), 'utf8');
  const persistence = evidenceStore.persist(persistenceReceiptBytes);
  if (sha256(evidenceStore.read(persistence.digest)) !== persistence.digest) {
    throw new Error(`CAS persistence receipt failed for ${iri}`);
  }
  return Object.freeze({
    byteLength: bytes.length,
    bytesBase64: bytes.toString('base64'),
    digest: persisted.digest,
    iri,
    mediaType: 'application/json',
    persistenceReceiptDigest: persistence.digest,
  });
}

function descriptorForExistingCas(evidenceStore, iri, contentDigest) {
  const bytes = evidenceStore.read(assertExpectedDigest(contentDigest, `${iri} digest`));
  if (sha256(bytes) !== contentDigest) throw new Error(`${iri} CAS bytes do not match their digest`);
  return persistenceDescriptor(evidenceStore, iri, bytes);
}

function ownerAuthorityFromVerification({ assignments, pendingPackage, trustAnchor, evidenceStore }) {
  const source = pendingPackage?.aggregateResult?.evaluation?.sourceBinding;
  if (!source || !Array.isArray(source.sourcePaths)) throw new Error('verified owner authority requires the exact pending source binding');
  const verifier = Object.freeze({
    identityDigest: sha256(canonicalJson({
      algorithm: trustAnchor.algorithm,
      fingerprint: trustAnchor.fingerprint,
      principal: trustAnchor.principal,
      protocol: trustAnchor.protocol,
    })),
    implementationRelease: 'semantic-proof-v1.0.0',
    sourceHead: source.head,
    sourcePaths: source.sourcePaths,
    sourceScopeDigest: source.sourceScopeDigest,
    sourceTree: source.tree,
    trustAnchorDigest: sha256(canonicalJson(trustAnchor)),
  });
  const values = assignments.map((assignment) => {
    const verified = assignment.verified;
    const key = assignment.authorityDomain.split(':').at(-1);
    const verificationBytes = Buffer.from(canonicalJson({
      authorityDomain: assignment.authorityDomain,
      envelopeDigest: verified.envelope_digest,
      fingerprint: verified.fingerprint,
      repository: assignment.repository,
      schema: 'semantic-proof-v1-owner-assignment-verification-v1',
      signedCandidateDigest: verified.candidate_digest,
      signedSourceScopeDigest: verified.source_scope_digest,
    }), 'utf8');
    const descriptor = persistenceDescriptor(
      evidenceStore,
      `urn:usf:semanticproofcasdescriptor:ownerassignment:${key}:matthewaldous`,
      verificationBytes,
    );
    const admissionBytes = Buffer.from(canonicalJson({
      authorityDomain: assignment.authorityDomain,
      repository: assignment.repository,
      schema: 'semantic-proof-v1-owner-assignment-admission-v1',
      verificationReceiptDigest: descriptor.digest,
    }), 'utf8');
    const admission = evidenceStore.persist(admissionBytes);
    return [key, Object.freeze({
      admission: Object.freeze({ receiptDigest: admission.digest }),
      assignment: Object.freeze({
        authorityPreDigest: verified.authority_pre_digest,
        candidateDigest: verified.candidate_digest,
        envelopeDigest: verified.envelope_digest,
        sourcePaths: assignment.sourcePaths,
        sourceScopeDigest: verified.source_scope_digest,
      }),
      descriptor: Object.freeze({
        byteLength: descriptor.byteLength,
        digest: descriptor.digest,
        mediaType: descriptor.mediaType,
        receiptDigest: descriptor.persistenceReceiptDigest,
      }),
      verification: Object.freeze({ receiptDigest: descriptor.digest, verifiedAt: verified.issued_at }),
      verifier,
    })];
  });
  const authority = Object.freeze(Object.fromEntries(values));
  const expectedOwnerKeys = OWNER_SCOPES
    .map(({ authorityDomain }) => authorityDomain.slice(authorityDomain.lastIndexOf(':') + 1))
    .sort()
    .join(',');
  if (Object.keys(authority).sort().join(',') !== expectedOwnerKeys) {
    throw new Error(`verified owner authority did not produce the exact ${OWNER_SCOPES.length} owner domains`);
  }
  return authority;
}

export function verifyAndDeriveOwnerAuthority({
  ownerAssignments,
  pendingPackage,
  trustAnchor,
  evidenceStore,
  now,
  verifyOwnerAssignment = verifyEnvelope,
}) {
  const admitted = evidenceStoreAdapter(evidenceStore);
  const activeTrustAnchor = trustAnchor || readTrustAnchor();
  const assignments = verifyOwnerAssignmentSet({
    ownerAssignments, trustAnchor: activeTrustAnchor, now, verifyOwnerAssignment,
  });
  return ownerAuthorityFromVerification({
    assignments, pendingPackage, trustAnchor: activeTrustAnchor, evidenceStore: admitted,
  });
}

function compilerValidationPackage({
  validationEvidence,
  evidenceStore,
  authorityBeforeDigest,
  authorityAfterDigest,
  candidateDigest,
  evaluatedAt,
  sourceBindingDigest,
  executionReceiptDescriptor,
  evaluationReceiptDescriptor,
}) {
  const reportBytes = evidenceStore.read(validationEvidence.digest);
  const report = JSON.parse(reportBytes.toString('utf8'));
  if (report.schema !== 'semantic-authority-compiler-validation-report-v1'
      || report.authorityDigest !== authorityBeforeDigest || report.candidateDigest !== candidateDigest
      || report.providerValidationReceipt?.conforms !== true || sha256(reportBytes) !== validationEvidence.digest) {
    throw new Error('real compiler validation report is not bound to the publication candidate');
  }
  const evidence = [executionReceiptDescriptor, evaluationReceiptDescriptor]
    .map(({ digest, iri }) => ({ digest, iri }))
    .sort((left, right) => left.iri.localeCompare(right.iri));
  const execution = Object.freeze({
    admissionPath: 'urn:usf:evidenceadmissionpath:compilersemanticenforcementaggregate',
    authorityDigest: authorityAfterDigest,
    evidence,
    execution: 'urn:usf:validationexecution:compilersemanticenforcementaggregate',
    producer: 'urn:usf:validationproducer:compilersemanticenforcementaggregate',
    schema: 'usf-validation-execution-receipt-v1',
  });
  const executionDescriptor = persistenceDescriptor(
    evidenceStore,
    'urn:usf:validationreceipt:compilersemanticenforcementexecution',
    Buffer.from(canonicalJson(execution), 'utf8'),
  );
  const evaluation = Object.freeze({
    authorityDigest: authorityAfterDigest,
    evaluation: 'urn:usf:validationevaluation:compilersemanticenforcementaggregate',
    executionReceiptDigest: executionDescriptor.digest,
    resultState: 'passed',
    schema: 'usf-validation-evaluation-receipt-v1',
    validationResult: 'urn:usf:validationresult:compilersemanticenforcementaggregate',
  });
  const evaluationDescriptor = persistenceDescriptor(
    evidenceStore,
    'urn:usf:validationreceipt:compilersemanticenforcementevaluation',
    Buffer.from(canonicalJson(evaluation), 'utf8'),
  );
  const receipt = Object.freeze({
    authorityAfterDigest,
    authorityBeforeDigest,
    candidateDigest,
    conforms: true,
    evaluatedAt,
    evaluationReceiptDigest: evaluationDescriptor.digest,
    executionReceiptDigest: executionDescriptor.digest,
    schema: 'semantic-authority-compiler-validation-v1',
    sourceBindingDigest,
    validationReportDigest: validationEvidence.digest,
  });
  const descriptor = persistenceDescriptor(
    evidenceStore,
    COMPILER_VALIDATION_EVIDENCE_IRI,
    Buffer.from(canonicalJson(receipt), 'utf8'),
  );
  return Object.freeze({ descriptor, receipt });
}

function verifyReevaluationEvidence(preparation, evidenceStore) {
  return Object.freeze(['executionReceiptDigest', 'evaluationReceiptDigest'].map((field) => {
    const contentDigest = assertExpectedDigest(preparation?.[field], field);
    const verified = evidenceStore.verify(contentDigest);
    if (verified.digest !== contentDigest || sha256(evidenceStore.read(contentDigest)) !== contentDigest) {
      throw new Error(`reevaluation ${field} failed CAS round-trip verification`);
    }
    return Object.freeze({ digest: contentDigest, role: field, size: verified.size });
  }));
}

function ownerAssignmentSet(ownerAssignments) {
  if (!Array.isArray(ownerAssignments) || ownerAssignments.length !== OWNER_SCOPES.length) {
    throw new Error(`exactly ${OWNER_SCOPES.length} independently scoped owner assignments are required`);
  }
  return Object.freeze(OWNER_SCOPES.map((scope) => {
    const matches = ownerAssignments.filter((entry) => entry?.authorityDomain === scope.authorityDomain
      && entry?.repository === scope.repository);
    if (matches.length !== 1 || !Array.isArray(matches[0].sourcePaths) || !matches[0].envelope) {
      throw new Error(`one exact owner assignment is required for ${scope.authorityDomain}`);
    }
    return Object.freeze({ ...scope, sourcePaths: matches[0].sourcePaths, envelope: matches[0].envelope });
  }));
}

function verifyOwnerAssignmentSet({ ownerAssignments, trustAnchor, now, verifyOwnerAssignment }) {
  return Object.freeze(ownerAssignmentSet(ownerAssignments).map((assignment) => Object.freeze({
    ...assignment,
    verified: verifyOwnerAssignment(assignment.envelope, {
      trustAnchor,
      claimType: 'owner_assignment',
      authorityDomain: assignment.authorityDomain,
      repository: assignment.repository,
      sourcePaths: assignment.sourcePaths,
      authorityPreDigest: assignment.envelope.payload.authority_pre_digest,
      candidateDigest: ownerAssignmentCandidateDigest({
        authorityDomain: assignment.authorityDomain,
        principal: trustAnchor.principal,
        repository: assignment.repository,
        sourcePaths: assignment.sourcePaths,
      }),
      expectedSingleUse: false,
      now,
    }),
  })));
}

export function createAggregatePublicationAdapter(producer, { reevaluationPreparation } = {}) {
  if (!producer || typeof producer.observeInitialProjection !== 'function'
      || typeof producer.produceInitial !== 'function' || typeof producer.produceTerminal !== 'function') {
    throw new Error('aggregate publication adapter requires the complete aggregate producer');
  }
  return async (request) => {
    if (request.operation === 'observe_initial') {
      const observed = await producer.observeInitialProjection({
        requestedAuthorityDigest: request.authorityPublicationDigest,
      });
      return Object.freeze({
        actionState: observed.actionState,
        authorityDigest: observed.authorityDigest,
        currentProofResults: observed.currentProofResults,
        directProvisionalAggregateSelections: 1,
        observationReceiptDigest: sha256(canonicalJson(observed)),
        ok: true,
        operation: 'observe_initial',
        proofCurrentness: observed.proofCurrentness,
        selectedProvisionalAggregateResult: observed.selectedProvisionalAggregateResult,
      });
    }
    if (request.operation === 'produce_initial') {
      return producer.produceInitial({
        candidateDigest: request.candidateDigest,
        pendingPublicationReceipt: request.pendingPublicationReceipt,
        requestedAuthorityDigest: request.authorityPublicationDigest,
      });
    }
    if (request.operation === 'verify_reevaluation') {
      return producer.produceTerminal({
        expectedStage1AuthorityDigest: request.authorityBeforeDigest,
        requestedAuthorityDigest: request.authorityPublicationDigest,
        stage1Preparation: reevaluationPreparation,
      });
    }
    throw new Error(`unsupported aggregate publication operation: ${request.operation}`);
  };
}

function buildReceipt({
  publicationPhase,
  authorityDomain,
  repository,
  sourcePaths,
  expectedAuthorityDigest,
  expectedCandidateDigest,
  authorityPublicationDigest,
  committedState,
  ownerAssignment,
  candidateApproval,
  publicationGrant,
  publishedAt,
  grant,
  initialObservation,
  reevaluation,
}) {
  const terminal = publicationPhase === 'reevaluation';
  return assertSemanticProofPublicationReceipt({
    action_state: terminal ? reevaluation.actionState : initialObservation.actionState,
    authority_after_digest: terminal ? reevaluation.authorityAfterDigest : authorityPublicationDigest,
    authority_before_digest: expectedAuthorityDigest,
    authority_domain: authorityDomain,
    authority_publication_digest: authorityPublicationDigest,
    candidate_approval_envelope_digest: envelopeDigest(candidateApproval),
    candidate_digest: expectedCandidateDigest,
    committed_candidate_state: committedState,
    current_proof_results: terminal ? reevaluation.currentProofResults : initialObservation.currentProofResults,
    direct_provisional_aggregate_selections: terminal ? 0 : initialObservation.directProvisionalAggregateSelections,
    grant_consumed: true,
    grant_nonce: grant.nonce,
    owner_assignment_envelope_digest: envelopeDigest(ownerAssignment),
    proof_currentness: terminal ? reevaluation.proofCurrentness : initialObservation.proofCurrentness,
    projection_observation_receipt_digest: terminal ? null : initialObservation.observationReceiptDigest,
    protocol: 'semantic-proof-v1',
    publication_grant_envelope_digest: envelopeDigest(publicationGrant),
    publication_outcome: terminal ? 'accepted' : 'committed_pending_reevaluation',
    publication_phase: publicationPhase,
    published_at: publishedAt,
    reevaluation_authority_digest: terminal ? reevaluation.evaluatedAuthorityDigest : null,
    reevaluation_evaluation_receipt_digest: terminal ? reevaluation.evaluationReceiptDigest : null,
    reevaluation_execution_receipt_digest: terminal ? reevaluation.executionReceiptDigest : null,
    repository,
    schema_version: 1,
    selected_aggregate_result: terminal ? reevaluation.selectedAggregateResult : null,
    selected_provisional_aggregate_result: terminal ? null : initialObservation.selectedProvisionalAggregateResult,
    source_scope_digest: sourceScopeDigest(sourcePaths),
    terminal_state: terminal ? 'PROCEED' : 'PENDING',
  });
}

function publicationOutput(receipt, persisted, extra = {}) {
  return Object.freeze({
    ...receipt,
    mode: 'commit',
    ok: true,
    publicationReceipt: Object.freeze(persisted),
    semanticProofReceipt: receipt,
    ...extra,
  });
}

function persistConsumedReceipt(transaction, persist) {
  if (transaction.state !== 'consumed' || !transaction.final_receipt) {
    throw new Error('publication receipt cannot persist before durable grant consumption');
  }
  const receipt = assertSemanticProofPublicationReceipt(transaction.final_receipt);
  const persisted = persist(receipt);
  if (persisted?.digest !== transaction.final_receipt_digest
      || persisted.digest !== publicationReceiptDigest(receipt)) {
    throw new Error('persisted publication receipt digest mismatch');
  }
  return Object.freeze({ persisted, receipt });
}

async function resumePublication({
  transaction,
  bundle,
  publicationPhase,
  expectedAuthorityDigest,
  expectedCandidateDigest,
  authorityDomain,
  repository,
  sourcePaths,
  ownerAssignment,
  candidateApproval,
  publicationGrant,
  readAuthorityWitness,
  postPublicationReevaluate,
  ledgerPath,
  settle,
  persist,
  protocolJournal,
  evidenceStore,
  validationEvidence,
  compilerValidation,
  pendingPackage,
  reevaluationPreparation,
  recovering,
}) {
  if (transaction.publication_phase !== publicationPhase) throw new Error('publication recovery phase mismatch');
  if (transaction.state === 'reserved') {
    throw new Error('reserved publication has no durable commit outcome; automatic republishing is refused');
  }
  if (transaction.state === 'failed') throw new Error('failed pre-commit publication grant cannot be replayed');

  let current = transaction;
  let live = await settle(readAuthorityWitness, await readAuthorityWitness());
  if (publicationPhase === 'reevaluation') verifyReevaluationEvidence(reevaluationPreparation, evidenceStore);
  if (current.state !== 'consumed' && live.digest !== current.authority_publication_digest) {
    throw new Error('live authority does not match the durable committed publication outcome');
  }

  if (publicationPhase === 'initial') {
    if (current.state === 'published_pending_reevaluation') {
      let observation = current.initial_projection_observation?.package;
      if (!observation) {
        observation = assertInitialProjectionObservation(await postPublicationReevaluate(Object.freeze({
          operation: 'observe_initial',
          authorityBeforeDigest: expectedAuthorityDigest,
          authorityPublicationDigest: current.authority_publication_digest,
          candidateDigest: expectedCandidateDigest,
          publicationPhase: 'initial',
        })));
        if (observation.authorityDigest !== current.authority_publication_digest) {
          throw new Error('stage-1 observation did not project the settled D1 authority');
        }
        protocolJournal.recordInitialProjectionObservation(bundle.grant, observation, { ledgerPath });
        current = protocolJournal.readPublicationTransaction(bundle.grant, { ledgerPath });
      }
      const receipt = buildReceipt({
        publicationPhase, authorityDomain, repository, sourcePaths, expectedAuthorityDigest,
        expectedCandidateDigest, authorityPublicationDigest: current.authority_publication_digest,
        committedState: current.committed_candidate_state, ownerAssignment, candidateApproval,
        publicationGrant, publishedAt: current.published_at, grant: bundle.grant,
        initialObservation: observation, reevaluation: null,
      });
      protocolJournal.consumeGrantNonce(bundle.grant, { receipt, ledgerPath });
      current = protocolJournal.readPublicationTransaction(bundle.grant, { ledgerPath });
    }
    if (current.state !== 'consumed') throw new Error('initial publication recovery reached an invalid journal state');
    const durable = persistConsumedReceipt(current, persist);
    let preparation = current.reevaluation_preparation?.package;
    if (!preparation) {
      if (live.digest !== current.authority_publication_digest) {
        throw new Error('stage-1 producer cannot resume after authority changed without a durable preparation');
      }
      preparation = assertInitialReevaluationPreparation(await postPublicationReevaluate(Object.freeze({
        operation: 'produce_initial',
        authorityBeforeDigest: expectedAuthorityDigest,
        authorityPublicationDigest: current.authority_publication_digest,
        candidateDigest: expectedCandidateDigest,
        pendingPublicationReceipt: durable.receipt,
        publicationPhase: 'initial',
      })));
      if (preparation.evaluatedAuthorityDigest !== current.authority_publication_digest
          || preparation.candidateDigest !== expectedCandidateDigest) {
        throw new Error('stage-1 preparation is not bound to D1 and its published candidate');
      }
      const afterProducer = await settle(readAuthorityWitness, await readAuthorityWitness());
      if (!sameWitness(live, afterProducer)) throw new Error('stage-1 reevaluation producer mutated semantic authority');
      protocolJournal.recordInitialReevaluationPreparation(bundle.grant, preparation, { ledgerPath });
      current = protocolJournal.readPublicationTransaction(bundle.grant, { ledgerPath });
    }
    const reevaluationEvidence = verifyReevaluationEvidence(current.reevaluation_preparation.package, evidenceStore);
    const executionReceiptDescriptor = descriptorForExistingCas(
      evidenceStore,
      AGGREGATE_EXECUTION_EVIDENCE_IRI,
      current.reevaluation_preparation.package.executionReceiptDigest,
    );
    const evaluationReceiptDescriptor = descriptorForExistingCas(
      evidenceStore,
      AGGREGATE_EVALUATION_EVIDENCE_IRI,
      current.reevaluation_preparation.package.evaluationReceiptDigest,
    );
    const closedCompilerValidation = compilerValidation || (pendingPackage ? compilerValidationPackage({
      validationEvidence,
      evidenceStore,
      authorityBeforeDigest: expectedAuthorityDigest,
      authorityAfterDigest: current.authority_publication_digest,
      candidateDigest: expectedCandidateDigest,
      evaluatedAt: current.published_at,
      sourceBindingDigest: pendingPackage.aggregateResult.evaluation.sourceBindingDigest,
      executionReceiptDescriptor,
      evaluationReceiptDescriptor,
    }) : null);
    return publicationOutput(durable.receipt, durable.persisted, {
      compilerValidation: closedCompilerValidation,
      evaluationReceiptDescriptor,
      executionReceiptDescriptor,
      recovered: recovering,
      reevaluationPreparation: Object.freeze(current.reevaluation_preparation.package),
      reevaluationPreparationDigest: current.reevaluation_preparation.package_digest,
      reevaluationEvidence,
      validationEvidence,
      witnesses: Object.freeze({ publication: phase(live) }),
    });
  }

  if (current.state === 'published_pending_reevaluation') {
    const reevaluation = assertPostPublicationTerminalState(await postPublicationReevaluate(Object.freeze({
      operation: 'verify_reevaluation',
      authorityBeforeDigest: expectedAuthorityDigest,
      authorityPublicationDigest: current.authority_publication_digest,
      candidateDigest: expectedCandidateDigest,
      committedCandidateState: current.committed_candidate_state,
      publicationPhase: 'reevaluation',
    })));
    if (reevaluation.evaluatedAuthorityDigest !== expectedAuthorityDigest
        || reevaluation.authorityAfterDigest !== live.digest) {
      throw new Error('terminal projection did not verify the stage-1-bound reevaluation publication');
    }
    protocolJournal.recordPostPublicationReevaluation(bundle.grant, reevaluation, { ledgerPath });
    current = protocolJournal.readPublicationTransaction(bundle.grant, { ledgerPath });
  }
  if (current.state === 'reevaluated_pending_receipt') {
    const reevaluation = {
      actionState: current.action_state,
      authorityAfterDigest: current.authority_after_digest,
      currentProofResults: current.current_proof_results,
      evaluatedAuthorityDigest: current.authority_pre_digest,
      evaluationReceiptDigest: current.reevaluation_evaluation_receipt_digest,
      executionReceiptDigest: current.reevaluation_execution_receipt_digest,
      ok: true,
      operation: 'verify_reevaluation',
      proofCurrentness: current.proof_currentness,
      selectedAggregateResult: current.selected_aggregate_result,
    };
    const receipt = buildReceipt({
      publicationPhase, authorityDomain, repository, sourcePaths, expectedAuthorityDigest,
      expectedCandidateDigest, authorityPublicationDigest: current.authority_publication_digest,
      committedState: current.committed_candidate_state, ownerAssignment, candidateApproval,
      publicationGrant, publishedAt: current.published_at, grant: bundle.grant,
      initialObservation: null, reevaluation,
    });
    protocolJournal.consumeGrantNonce(bundle.grant, { receipt, ledgerPath });
    current = protocolJournal.readPublicationTransaction(bundle.grant, { ledgerPath });
  }
  if (current.state !== 'consumed') throw new Error('reevaluation publication recovery reached an invalid journal state');
  const durable = persistConsumedReceipt(current, persist);
  return publicationOutput(durable.receipt, durable.persisted, {
    recovered: recovering,
    validationEvidence,
    witnesses: Object.freeze({ publication: phase(live) }),
  });
}

export async function runPublication({
  mode,
  publicationPhase,
  expectedAuthorityDigest,
  expectedCandidateDigest,
  authorityDomain,
  repository,
  sourcePaths,
  ownerAssignments,
  expectedOwnerAuthority,
  pendingPackage,
  candidateApproval,
  publicationGrant,
  recoveryValidationEvidence,
  priorPublicationReceipt,
  reevaluationPreparation,
  trustAnchor,
  candidateBytes,
  command,
  readAuthorityWitness,
  postPublicationReevaluate,
  ledgerPath,
  verifyBundle = verifyPublicationBundle,
  verifyOwnerAssignment = verifyEnvelope,
  settle = settledWitness,
  persist = persistReceipt,
  protocolJournal = DEFAULT_PROTOCOL_JOURNAL,
  trustedTime,
  evidenceStore,
} = {}) {
  if (!['prepare', 'validate', 'commit'].includes(mode)) throw new Error('mode must be prepare, validate or commit');
  if (!['initial', 'reevaluation'].includes(publicationPhase)) throw new Error('publicationPhase must be initial or reevaluation');
  if (recoveryValidationEvidence !== undefined
      && (mode !== 'commit' || publicationPhase !== 'initial')) {
    throw new Error('recovery validation evidence is restricted to initial publication recovery');
  }
  assertExpectedDigest(expectedAuthorityDigest, 'authority digest');
  if (!command || typeof command.execute !== 'function' || typeof readAuthorityWitness !== 'function') {
    throw new Error('publisher requires injected compiler command and authority witness reader');
  }
  const admittedEvidence = evidenceStoreAdapter(evidenceStore);
  let candidate = candidateBytes === undefined
    ? null
    : exactCandidate(candidateBytes, mode === 'prepare' ? undefined : expectedCandidateDigest);
  if (mode === 'prepare') {
    if (candidate === null) throw new Error('publisher requires exact canonical candidate bytes');
    if (typeof command.composeCandidate !== 'function') throw new Error('prepare requires full source and aggregate candidate composition');
    const composed = await command.composeCandidate({ generatedCandidateBytes: candidate.bytes, expectedAuthorityDigest });
    candidate = exactCandidate(composed?.bytes, composed?.digest);
  }
  if (typeof command.inspectCandidateState !== 'function') {
    throw new Error('publisher requires exact candidate pre/post-state inspection');
  }
  if (mode === 'commit' && typeof postPublicationReevaluate !== 'function') {
    throw new Error('commit requires an injected mandatory postPublicationReevaluate callback');
  }
  protocolJournalAdapter(protocolJournal);

  let bundle;
  let graphOwnerAssignment;
  let verifiedOwnerAuthority;
  let existing = null;
  if (mode !== 'prepare') {
    assertExpectedDigest(expectedCandidateDigest, 'candidate digest');
    existing = mode === 'commit'
      ? protocolJournal.readPublicationTransactionForEnvelope(publicationGrant, { ledgerPath })
      : null;
    const currentVerificationTime = await trustedInstant(trustedTime);
    let verificationTime = currentVerificationTime;
    if (existing && POST_PUBLICATION_JOURNAL_STATES.has(existing.state)) {
      const publishedAt = canonicalUtcSecond(existing.published_at, 'journal published_at');
      if (Date.parse(publishedAt) > currentVerificationTime.date.getTime()) {
        throw new Error('journal publication time is later than current trusted time');
      }
      verificationTime = Object.freeze({ canonical: publishedAt, date: new Date(publishedAt) });
    }
    const activeTrustAnchor = trustAnchor || readTrustAnchor();
    const assignments = verifyOwnerAssignmentSet({
      ownerAssignments, trustAnchor: activeTrustAnchor, now: verificationTime.date, verifyOwnerAssignment,
    });
    graphOwnerAssignment = assignments.find(({ authorityDomain: domain }) => domain === GRAPH_DOMAIN).envelope;
    if (expectedOwnerAuthority !== undefined) {
      verifiedOwnerAuthority = ownerAuthorityFromVerification({
        assignments, pendingPackage, trustAnchor: activeTrustAnchor, evidenceStore: admittedEvidence,
      });
      if (canonicalJson(verifiedOwnerAuthority) !== canonicalJson(expectedOwnerAuthority)) {
        throw new Error('materializer owner authority differs from the two verified envelope results');
      }
    }
    bundle = verifyBundle({
      ownerAssignment: graphOwnerAssignment, candidateApproval, publicationGrant, trustAnchor: activeTrustAnchor,
      authorityDomain, repository, sourcePaths, authorityPreDigest: expectedAuthorityDigest,
      candidateDigest: expectedCandidateDigest, now: verificationTime.date,
    });
    if (publicationPhase === 'reevaluation') {
      protocolJournal.assertReevaluationPredecessor({
        priorReceipt: priorPublicationReceipt,
        preparation: reevaluationPreparation,
        authorityPreDigest: expectedAuthorityDigest,
        ledgerPath,
      });
    }
    if (existing?.state === 'reserved') {
      if (candidate === null) {
        throw new Error('reserved publication recovery requires exact canonical candidate bytes');
      }
      const observed = await command.inspectCandidateState({
        candidateBytes: candidate.bytes, candidateDigest: candidate.digest,
      });
      const live = await settle(readAuthorityWitness, await readAuthorityWitness());
      if (observed?.state === 'post') {
        if (live.digest === expectedAuthorityDigest) {
          throw new Error('candidate post-state was observed without an authority digest transition');
        }
        const recoveredAt = (await trustedInstant(trustedTime)).canonical;
        protocolJournal.recordPublicationOutcome(bundle.grant, {
          authorityPublicationDigest: live.digest,
          committedCandidateState: COMMIT_STATE,
          ledgerPath,
          observedAt: recoveredAt,
          publishedAt: recoveredAt,
        });
        existing = protocolJournal.readPublicationTransaction(bundle.grant, { ledgerPath });
      } else if (observed?.state !== 'pre' || live.digest !== expectedAuthorityDigest) {
        throw new Error('reserved publication cannot be reconciled to an exact pre-state or post-state');
      }
    }
    if (existing && existing.state !== 'reserved') {
      const admittedRecoveryValidation = recoveryValidationEvidence === undefined ? null
        : admitValidationEvidence({ validationEvidence: recoveryValidationEvidence }, admittedEvidence);
      return resumePublication({
        transaction: protocolJournal.readPublicationTransaction(bundle.grant, { ledgerPath }), bundle,
        publicationPhase, expectedAuthorityDigest, expectedCandidateDigest, authorityDomain,
        repository, sourcePaths, ownerAssignment: graphOwnerAssignment, candidateApproval, publicationGrant,
        readAuthorityWitness, postPublicationReevaluate, ledgerPath, settle, persist, protocolJournal,
        evidenceStore: admittedEvidence, validationEvidence: admittedRecoveryValidation, compilerValidation: null,
        pendingPackage, reevaluationPreparation,
        recovering: true,
      });
    }
  }

  if (candidate === null) throw new Error('publisher requires exact canonical candidate bytes');

  if (recoveryValidationEvidence !== undefined) {
    throw new Error('recovery validation evidence requires an existing durable publication outcome');
  }

  const before = await readAuthorityWitness();
  if (before.digest !== expectedAuthorityDigest) throw new Error('semantic authority drifted before candidate preparation');
  const beforeCandidateState = await command.inspectCandidateState({
    candidateBytes: candidate.bytes, candidateDigest: candidate.digest,
  });
  if (beforeCandidateState?.state !== 'pre') throw new Error('candidate is not in its exact live pre-state');
  const validation = await command.execute({
    candidateBytes: candidate.bytes,
    candidateDigest: candidate.digest,
    expectedAuthorityDigest,
    publicationMode: 'validate',
  });
  const prepared = assertAcceptedCompilerResult(validation, {
    phase: 'validate', expectedCandidateDigest: mode === 'prepare' ? undefined : expectedCandidateDigest,
  });
  const validationEvidence = admitValidationEvidence(validation, admittedEvidence);
  const afterValidation = await readAuthorityWitness();
  if (!sameWitness(before, afterValidation)) throw new Error('validate-and-rollback changed semantic authority');
  if (mode === 'prepare') {
    return Object.freeze({
      authorityDigest: expectedAuthorityDigest,
      canonicalCandidateDigest: candidate.digest,
      canonicalCandidateBytes: candidate.bytes.toString('base64'),
      exactCandidateStateVerified: true,
      mode: 'prepare',
      ok: true,
      publicationPhase,
      state: prepared.state,
      validationEvidence,
    });
  }
  if (mode === 'validate') {
    return Object.freeze({
      authorityDigest: expectedAuthorityDigest,
      canonicalCandidateDigest: candidate.digest,
      exactCandidateStateVerified: true,
      mode: 'validate',
      ok: true,
      publicationAuthorised: true,
      publicationPhase,
      state: prepared.state,
      validationEvidence,
    });
  }

  if (!existing) {
    const reservationTime = await trustedInstant(trustedTime);
    protocolJournal.reserveGrantNonce(bundle.grant, {
      ledgerPath, publicationPhase, observedAt: reservationTime.canonical,
    });
  }
  try {
    const commitTime = await trustedInstant(trustedTime);
    const activeTrustAnchor = trustAnchor || readTrustAnchor();
    verifyOwnerAssignmentSet({ ownerAssignments, trustAnchor: activeTrustAnchor, now: commitTime.date, verifyOwnerAssignment });
    const rechecked = verifyBundle({
      ownerAssignment: graphOwnerAssignment, candidateApproval, publicationGrant, trustAnchor: activeTrustAnchor,
      authorityDomain, repository, sourcePaths, authorityPreDigest: expectedAuthorityDigest,
      candidateDigest: expectedCandidateDigest, now: commitTime.date,
    });
    if (rechecked.grant.envelope_digest !== bundle.grant.envelope_digest) {
      throw new Error('publication grant changed before compiler commit');
    }
  } catch (error) {
    protocolJournal.failGrantNonce(bundle.grant, { stage: 'precommit_currentness', ledgerPath });
    throw error;
  }

  const compilation = await command.execute({
    candidateBytes: candidate.bytes,
    candidateDigest: candidate.digest,
    expectedAuthorityDigest,
    publicationMode: 'commit',
  });
  const committed = assertAcceptedCompilerResult(compilation, {
    phase: 'commit', expectedCandidateDigest,
  });
  const publicationWitness = await readAuthorityWitness();
  const settledPublication = await settle(readAuthorityWitness, publicationWitness);
  if (settledPublication.digest === before.digest) throw new Error('committed publication did not change semantic authority');
  const committedCandidateState = await command.inspectCandidateState({
    candidateBytes: candidate.bytes, candidateDigest: candidate.digest,
  });
  if (committedCandidateState?.state !== 'post') {
    throw new Error('committed authority does not expose the exact candidate post-state');
  }
  const publishedAt = (await trustedInstant(trustedTime)).canonical;
  protocolJournal.recordPublicationOutcome(bundle.grant, {
    authorityPublicationDigest: settledPublication.digest,
    committedCandidateState: committed.state,
    publishedAt,
    observedAt: publishedAt,
    ledgerPath,
  });
  return resumePublication({
    transaction: protocolJournal.readPublicationTransaction(bundle.grant, { ledgerPath }), bundle,
    publicationPhase, expectedAuthorityDigest, expectedCandidateDigest, authorityDomain,
    repository, sourcePaths, ownerAssignment: graphOwnerAssignment, candidateApproval, publicationGrant,
    readAuthorityWitness, postPublicationReevaluate, ledgerPath, settle, persist, protocolJournal,
    evidenceStore: admittedEvidence, validationEvidence, compilerValidation: null,
    pendingPackage, reevaluationPreparation,
    recovering: false,
  });
}

function canonicalAuthorityInventory(witness) {
  if (!Array.isArray(witness?.inventory) || witness.inventory.length === 0) {
    throw new Error('authority witness inventory is required for prospective dependency closure');
  }
  const records = witness.inventory.map((record) => {
    const transportedDigest = record.sha256 || record.digest;
    const sha256 = /^[0-9a-f]{64}$/.test(transportedDigest || '')
      ? `sha256:${transportedDigest}`
      : transportedDigest;
    return Object.freeze({ graph: record.graph, sha256, triples: record.triples });
  }).sort((left, right) => left.graph.localeCompare(right.graph));
  for (const record of records) {
    if (typeof record.graph !== 'string' || !SHA256.test(record.sha256 || '')
        || !Number.isSafeInteger(record.triples) || record.triples < 0) {
      throw new Error('authority witness inventory is not canonical');
    }
  }
  return Object.freeze(records);
}

async function stabilizedCandidate({ stage, input, command, expectedAuthorityDigest, initialInventory }) {
  const materialize = (inventory) => materializeAggregateCompilerAuthorityCandidate({
    ...input,
    currentnessBinding: { prospectiveAuthorityInventory: inventory },
    stage,
  });
  const compose = async (inventory) => {
    const generated = materialize(inventory);
    const composed = await command.composeCandidate({
      generatedCandidateBytes: generated.bytes,
      expectedAuthorityDigest,
    });
    return Object.freeze({
      ...generated,
      bytes: composed.bytes,
      candidateDigest: composed.digest,
    });
  };
  const seed = await compose(initialInventory);
  const firstPreview = await command.previewCandidateInventory({
    candidateBytes: seed.bytes,
    candidateDigest: seed.candidateDigest,
    expectedAuthorityDigest,
  });
  const candidate = await compose(firstPreview.inventory);
  const settledPreview = await command.previewCandidateInventory({
    candidateBytes: candidate.bytes,
    candidateDigest: candidate.candidateDigest,
    expectedAuthorityDigest,
  });
  const firstDigest = aggregateCompilerAuthorityCandidateInternals
    .nonPublicationDependencySetDigest(firstPreview.inventory);
  const settledDigest = aggregateCompilerAuthorityCandidateInternals
    .nonPublicationDependencySetDigest(settledPreview.inventory);
  if (firstDigest !== settledDigest) throw new Error(`${stage} prospective non-publication dependency inventory did not stabilize`);
  return Object.freeze({ candidate, dependencySetDigest: settledDigest, inventory: settledPreview.inventory });
}

export async function runAggregateCompilerProductionLifecycle({
  expectedAuthorityDigest,
  ownerAssignments,
  trustAnchor,
  claimProvider,
  producer,
  command,
  readAuthorityWitness,
  trustedTime,
  evidenceStore,
  publicationOptions = {},
}) {
  if (typeof claimProvider !== 'function' || !producer || typeof producer.preparePending !== 'function'
      || typeof producer.prepareFinalPackage !== 'function'
      || typeof producer.refreshDependentValidation !== 'function' || !command
      || typeof command.prepareSourceDelta !== 'function' || typeof command.composeCandidate !== 'function'
      || typeof command.previewCandidateInventory !== 'function') {
    throw new Error('aggregate production lifecycle requires the real producer, materializer compiler and claim provider');
  }
  const d0 = await readAuthorityWitness();
  if (d0.digest !== expectedAuthorityDigest) throw new Error('aggregate lifecycle D0 authority digest drifted');
  const pendingPackage = await producer.preparePending({ requestedAuthorityDigest: expectedAuthorityDigest });
  const base = await command.prepareSourceDelta({ expectedAuthorityDigest });
  const baseValidation = admitValidationEvidence({ validationEvidence: base.validationEvidence }, evidenceStoreAdapter(evidenceStore));
  if (baseValidation.digest !== base.baseSemanticDelta.validationReceiptDigest) {
    throw new Error('base source-delta validation receipt was not admitted exactly');
  }
  const verificationTime = await trustedInstant(trustedTime);
  const ownerAuthority = verifyAndDeriveOwnerAuthority({
    ownerAssignments,
    pendingPackage,
    trustAnchor,
    evidenceStore,
    now: verificationTime.date,
    verifyOwnerAssignment: publicationOptions.verifyOwnerAssignment || verifyEnvelope,
  });
  const graphSourcePaths = pendingPackage.aggregateResult.evaluation.sourceBinding.sourcePaths;
  const stage1 = await stabilizedCandidate({
    stage: 'stage1',
    input: {
      baseSemanticDelta: base.baseSemanticDelta,
      ownerAuthority,
      pendingPackage,
    },
    command,
    expectedAuthorityDigest,
    initialInventory: canonicalAuthorityInventory(d0),
  });
  const stage1Claims = await claimProvider(Object.freeze({
    authorityDigest: expectedAuthorityDigest,
    canonicalCandidateBytes: stage1.candidate.bytes.toString('base64'),
    candidateDigest: stage1.candidate.candidateDigest,
    stage: 'stage1',
  }));
  const callback = createAggregatePublicationAdapter(producer);
  const initial = await runPublication({
    ...publicationOptions,
    mode: 'commit',
    publicationPhase: 'initial',
    expectedAuthorityDigest,
    expectedCandidateDigest: stage1.candidate.candidateDigest,
    authorityDomain: GRAPH_DOMAIN,
    repository: 'maldous/usf-graph',
    sourcePaths: graphSourcePaths,
    ownerAssignments,
    expectedOwnerAuthority: ownerAuthority,
    pendingPackage,
    candidateApproval: stage1Claims.candidateApproval,
    publicationGrant: stage1Claims.publicationGrant,
    trustAnchor,
    candidateBytes: stage1.candidate.bytes,
    command,
    readAuthorityWitness,
    postPublicationReevaluate: callback,
    trustedTime,
    evidenceStore,
  });
  if (!initial.compilerValidation || !initial.executionReceiptDescriptor || !initial.evaluationReceiptDescriptor) {
    throw new Error('stage1 did not produce the closed compiler and reevaluation descriptor package');
  }
  const d1 = await readAuthorityWitness();
  if (d1.digest !== initial.authority_after_digest) throw new Error('aggregate lifecycle D1 authority digest drifted');
  const refreshedDependentValidation = await producer.refreshDependentValidation({
    requestedAuthorityDigest: d1.digest,
  });
  const refreshedPendingPackage = Object.freeze({
    ...pendingPackage,
    dependentValidation: refreshedDependentValidation,
  });
  const stage2Package = await producer.prepareFinalPackage({
    compilerValidation: initial.compilerValidation,
    evaluationReceiptDescriptor: initial.evaluationReceiptDescriptor,
    executionReceiptDescriptor: initial.executionReceiptDescriptor,
    pending: refreshedPendingPackage,
    publicationReceipt: initial.semanticProofReceipt,
    stage1Preparation: initial.reevaluationPreparation,
  });
  const stage2 = await stabilizedCandidate({
    stage: 'stage2',
    input: { ownerAuthority, pendingPackage: refreshedPendingPackage, stage2Package },
    command,
    expectedAuthorityDigest: d1.digest,
    initialInventory: canonicalAuthorityInventory(d1),
  });
  const stage2Claims = await claimProvider(Object.freeze({
    authorityDigest: d1.digest,
    canonicalCandidateBytes: stage2.candidate.bytes.toString('base64'),
    candidateDigest: stage2.candidate.candidateDigest,
    stage: 'stage2',
  }));
  const terminal = await runPublication({
    ...publicationOptions,
    mode: 'commit',
    publicationPhase: 'reevaluation',
    expectedAuthorityDigest: d1.digest,
    expectedCandidateDigest: stage2.candidate.candidateDigest,
    authorityDomain: GRAPH_DOMAIN,
    repository: 'maldous/usf-graph',
    sourcePaths: graphSourcePaths,
    ownerAssignments,
    expectedOwnerAuthority: ownerAuthority,
    pendingPackage,
    candidateApproval: stage2Claims.candidateApproval,
    publicationGrant: stage2Claims.publicationGrant,
    priorPublicationReceipt: initial.semanticProofReceipt,
    reevaluationPreparation: initial.reevaluationPreparation,
    trustAnchor,
    candidateBytes: stage2.candidate.bytes,
    command,
    readAuthorityWitness,
    postPublicationReevaluate: createAggregatePublicationAdapter(producer, {
      reevaluationPreparation: initial.reevaluationPreparation,
    }),
    trustedTime,
    evidenceStore,
  });
  if (terminal.current_proof_results !== 1 || terminal.proof_currentness !== 'CURRENT'
      || terminal.action_state !== 'PROCEED') {
    throw new Error('aggregate lifecycle did not reach one CURRENT proof and PROCEED');
  }
  return Object.freeze({
    baseSemanticDelta: base.baseSemanticDelta,
    initial,
    ownerAuthority,
    pendingPackage,
    stage1,
    stage2,
    stage2Package,
    terminal,
  });
}

async function configureLiveDependencies(expectedAuthorityDigest, env) {
  try { await fetch('http://127.0.0.1:1/', { signal: AbortSignal.timeout(20) }); } catch { /* initialise dispatcher */ }
  const dispatcherSymbol = Symbol.for('undici.globalDispatcher.1');
  const currentDispatcher = globalThis[dispatcherSymbol];
  if (!currentDispatcher) throw new Error('global fetch dispatcher unavailable; cannot extend validation timeout');
  globalThis[dispatcherSymbol] = new currentDispatcher.constructor({ headersTimeout: 0, bodyTimeout: 0 });
  const [{ default: stardog }, { createStardogSemanticAuthorityClient }, { validateSemanticAuthorityConfiguration },
    { readSemanticAuthorityWitness }, { createSemanticModelCompilationCommand },
    { createAggregateCompilerProofProducer, createLiveAggregateCompilerProofDependencies }] = await Promise.all([
    import('stardog'),
    import('../../provider-bindings/stardog/semantic-authority.mjs'),
    import('../../configuration/semantic-assurance/semantic-authority.mjs'),
    import('./semantic-authority-gateway.mjs'),
    import('./semantic-model-compilation-command.mjs'),
    import('../../assurance/semantic-model-compilation/aggregate-compiler-proof-command.mjs'),
  ]);
  const { STARDOG_SERVER, STARDOG_DATABASE, STARDOG_TOKEN } = env;
  if (!STARDOG_SERVER || !STARDOG_DATABASE || !STARDOG_TOKEN) throw new Error('STARDOG_SERVER, STARDOG_DATABASE and STARDOG_TOKEN are required');
  const client = createStardogSemanticAuthorityClient({
    sdk: stardog,
    configuration: validateSemanticAuthorityConfiguration({
      accessMode: 'live', expectedAuthorityDigest, endpoint: STARDOG_SERVER, database: STARDOG_DATABASE,
      authentication: { mode: 'token', tokenReference: 'secret://semantic-authority/token' },
    }),
    resolveSecret: (reference) => {
      if (reference !== 'secret://semantic-authority/token') throw new Error('unexpected secret reference');
      return STARDOG_TOKEN;
    },
  });
  const aggregateProducer = createAggregateCompilerProofProducer(
    createLiveAggregateCompilerProofDependencies({ env, repositoryPath: root }),
  );
  const trustedTime = async () => {
    const rows = await client.select('SELECT (NOW() AS ?now) WHERE {}');
    const value = rows?.[0]?.now?.value;
    if (rows.length !== 1 || typeof value !== 'string') {
      throw new Error('Stardog trusted time was unavailable or ambiguous');
    }
    return value;
  };
  return {
    aggregateProducer,
    command: createSemanticModelCompilationCommand({
      client, readAuthorityWitness: readSemanticAuthorityWitness, repositoryRoot: root,
    }),
    readAuthorityWitness: () => readSemanticAuthorityWitness(client),
    trustedTime,
    evidenceStore: createCasEvidenceStore(env.USF_CAS_ROOT || '/var/lib/usf-cas'),
  };
}

export async function main({
  argv = process.argv.slice(2),
  env = process.env,
  postPublicationReevaluate,
} = {}) {
  const mode = requiredArgument(argv, 'mode');
  if (!['prepare', 'validate', 'commit', 'lifecycle'].includes(mode)) throw new Error('--mode must be prepare, validate, commit or lifecycle');
  if (requiredArgument(argv, 'producer') !== 'aggregate-compiler-v1') throw new Error('--producer must be aggregate-compiler-v1');
  const expectedAuthorityDigest = requiredArgument(argv, 'authority-digest');
  const publicationPhase = requiredArgument(argv, 'publication-phase');
  const live = await configureLiveDependencies(expectedAuthorityDigest, env);
  if (mode === 'lifecycle') {
    if (publicationPhase !== 'aggregate') throw new Error('lifecycle mode requires --publication-phase=aggregate');
    const ownerAssignments = [
      {
        authorityDomain: GRAPH_DOMAIN,
        repository: 'maldous/usf-graph',
        sourcePaths: repeatedArgument(argv, 'source-path'),
        envelope: readEnvelope(requiredArgument(argv, 'owner-assignment-semanticmodelcompilation')),
      },
      {
        authorityDomain: FACTORY_DOMAIN,
        repository: 'maldous/usf-factory',
        sourcePaths: repeatedArgument(argv, 'provider-source-path'),
        envelope: readEnvelope(requiredArgument(argv, 'owner-assignment-providerconfigurationplane')),
      },
      {
        authorityDomain: FACTORY_DURABLE_DOMAIN,
        repository: 'maldous/usf-factory',
        sourcePaths: repeatedArgument(argv, 'provider-v3-source-path'),
        envelope: readEnvelope(requiredArgument(argv, 'owner-assignment-factoryproviderdurablecontrolplane')),
      },
    ];
    const claims = Object.freeze({
      stage1: Object.freeze({
        candidateApproval: readEnvelope(requiredArgument(argv, 'stage1-candidate-approval')),
        publicationGrant: readEnvelope(requiredArgument(argv, 'stage1-publication-grant')),
      }),
      stage2: Object.freeze({
        candidateApproval: readEnvelope(requiredArgument(argv, 'stage2-candidate-approval')),
        publicationGrant: readEnvelope(requiredArgument(argv, 'stage2-publication-grant')),
      }),
    });
    const result = await runAggregateCompilerProductionLifecycle({
      expectedAuthorityDigest,
      ownerAssignments,
      trustAnchor: readTrustAnchor(requiredArgument(argv, 'trust-anchor')),
      claimProvider: async ({ authorityDigest, candidateDigest, stage }) => {
        const selected = claims[stage];
        if (selected.candidateApproval.payload.authority_pre_digest !== authorityDigest
            || selected.candidateApproval.payload.candidate_digest !== candidateDigest
            || selected.publicationGrant.payload.authority_pre_digest !== authorityDigest
            || selected.publicationGrant.payload.candidate_digest !== candidateDigest) {
          throw new Error(`${stage} signed claims do not bind the generated candidate and authority digest`);
        }
        return selected;
      },
      producer: live.aggregateProducer,
      command: live.command,
      readAuthorityWitness: live.readAuthorityWitness,
      trustedTime: live.trustedTime,
      evidenceStore: live.evidenceStore,
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
    return result;
  }
  const candidateBytes = readFileSync(requiredArgument(argv, 'candidate'));
  const priorPublicationReceipt = publicationPhase === 'reevaluation'
    ? assertSemanticProofPublicationReceipt(JSON.parse(readFileSync(requiredArgument(argv, 'prior-publication-receipt'), 'utf8')))
    : undefined;
  const reevaluationPreparation = publicationPhase === 'reevaluation'
    ? assertInitialReevaluationPreparation(JSON.parse(readFileSync(requiredArgument(argv, 'reevaluation-preparation'), 'utf8')))
    : undefined;
  const aggregateCallback = postPublicationReevaluate || createAggregatePublicationAdapter(
    live.aggregateProducer, { reevaluationPreparation },
  );
  const { aggregateProducer: _aggregateProducer, ...livePublisher } = live;
  const common = {
    mode, publicationPhase, expectedAuthorityDigest, candidateBytes,
    ...livePublisher,
    postPublicationReevaluate: aggregateCallback,
  };
  let result;
  if (mode === 'prepare') {
    if (optionalArgument(argv, 'candidate-digest') !== undefined) throw new Error('prepare mode derives the candidate digest and does not accept --candidate-digest');
    result = await runPublication(common);
    const outputPath = optionalArgument(argv, 'canonical-candidate-output');
    if (outputPath) writeFileSync(outputPath, Buffer.from(result.canonicalCandidateBytes, 'base64'), { flag: 'wx', mode: 0o444 });
  } else {
    const ownerAssignments = [
      {
        authorityDomain: GRAPH_DOMAIN,
        repository: 'maldous/usf-graph',
        sourcePaths: repeatedArgument(argv, 'source-path'),
        envelope: readEnvelope(requiredArgument(argv, 'owner-assignment-semanticmodelcompilation')),
      },
      {
        authorityDomain: FACTORY_DOMAIN,
        repository: 'maldous/usf-factory',
        sourcePaths: repeatedArgument(argv, 'provider-source-path'),
        envelope: readEnvelope(requiredArgument(argv, 'owner-assignment-providerconfigurationplane')),
      },
      {
        authorityDomain: FACTORY_DURABLE_DOMAIN,
        repository: 'maldous/usf-factory',
        sourcePaths: repeatedArgument(argv, 'provider-v3-source-path'),
        envelope: readEnvelope(requiredArgument(argv, 'owner-assignment-factoryproviderdurablecontrolplane')),
      },
    ];
    result = await runPublication({
      ...common,
      expectedCandidateDigest: requiredArgument(argv, 'candidate-digest'),
      authorityDomain: requiredArgument(argv, 'authority-domain'),
      repository: requiredArgument(argv, 'repository'),
      sourcePaths: ownerAssignments[0].sourcePaths,
      ownerAssignments,
      candidateApproval: readEnvelope(requiredArgument(argv, 'candidate-approval')),
      publicationGrant: readEnvelope(requiredArgument(argv, 'publication-grant')),
      trustAnchor: readTrustAnchor(requiredArgument(argv, 'trust-anchor')),
      priorPublicationReceipt,
      reevaluationPreparation,
    });
  }
  process.stdout.write(`${canonicalJson(result)}\n`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}

export {
  PUBLICATION_RECEIPT_SCHEMA_VERSION as HISTORICAL_PUBLICATION_RECEIPT_SCHEMA_VERSION,
  assertSupportedPublicationReceipt as assertHistoricalPublicationReceipt,
} from './publication-receipt.mjs';

// V2 is exported through the canonical publisher but remains inactive until a
// governed V1→V2 activation receipt selects it.  Its Graph coordinator never
// writes Factory successors; it verifies the Factory-owned closure receipt.
export {
  advanceDurableSemanticProofV2Publication,
  advanceSemanticProofV2Publication,
  assertFactoryClosureReceiptV2,
  assertProspectivePublicationPlanV2,
  factoryClosureReceiptDigestV2,
  graphPublicationReceiptDigestV2,
  HermeticSemanticProofV2Journal,
  prospectivePublicationPlanDigestV2,
  SemanticProofV2JournalState,
} from './semantic-proof-v2.mjs';
