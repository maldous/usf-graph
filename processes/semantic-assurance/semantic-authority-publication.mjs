#!/usr/bin/env node
import {
  chmodSync, closeSync, existsSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync,
  readFileSync, readdirSync, realpathSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  aggregateCompilerAuthorityCandidateInternals,
  materializeAggregateCompilerAuthorityCandidate,
  materializeAggregateOwnerAuthorityValidationContext,
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
  readImplementationWorkGrantTransaction,
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
  IMPLEMENTATION_WORK_GRANT_ALLOWED_ACTIONS,
  IMPLEMENTATION_WORK_GRANT_DENIED_EFFECTS,
  semanticProofV1Internals,
  verifyImplementationWorkGrantEnvelope,
  verifyPublicationBundle,
} from './semantic-proof-v1.mjs';
import * as semanticProofV2 from './semantic-proof-v2.mjs';
import { semanticModelCompilationCommandInternals } from './semantic-model-compilation-command.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const PREPARE_STATES = new Set(['ROLLED_BACK', 'VALIDATED', 'VALIDATED_ROLLBACK']);
const COMMIT_STATE = 'COMMITTED';
const POST_PUBLICATION_JOURNAL_STATES = new Set([
  'published_pending_reevaluation', 'reevaluated_pending_receipt', 'consumed',
]);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const GRAPH_DOMAIN = 'urn:usf:capabilityowner:semanticmodelcompilation';
const REPOSITORY_EXTERNAL_DOMAIN = 'urn:usf:capabilityowner:repositoryexternalartefactmaterialisation';
const FACTORY_DOMAIN = 'urn:usf:capabilityowner:providerconfigurationplane';
const FACTORY_DURABLE_DOMAIN = 'urn:usf:capabilityowner:factoryproviderdurablecontrolplane';
const CURRENT_OWNER_SCOPES = Object.freeze([
  Object.freeze({ authorityDomain: GRAPH_DOMAIN, repository: 'maldous/usf-graph' }),
  Object.freeze({ authorityDomain: FACTORY_DOMAIN, repository: 'maldous/usf-factory' }),
  Object.freeze({ authorityDomain: FACTORY_DURABLE_DOMAIN, repository: 'maldous/usf-factory' }),
]);
const FINAL_V1_OWNER_SCOPES = Object.freeze([
  CURRENT_OWNER_SCOPES[0],
  Object.freeze({ authorityDomain: REPOSITORY_EXTERNAL_DOMAIN, repository: 'maldous/usf-graph' }),
  CURRENT_OWNER_SCOPES[1],
  CURRENT_OWNER_SCOPES[2],
]);
const COMPILER_VALIDATION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementcompilervalidation';
const AGGREGATE_EXECUTION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementaggregateexecution';
const AGGREGATE_EVALUATION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementaggregateevaluation';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const USF_ONTOLOGY = 'urn:usf:ontology:';
const GRAPH_OWNER_RESOURCES_V2 = Object.freeze({
  assignment: 'urn:usf:ownerassignment:semanticmodelcompilation:matthewaldous',
  verification: 'urn:usf:semanticproofverification:ownerassignment:semanticmodelcompilation:matthewaldous',
  descriptor: 'urn:usf:semanticproofcasdescriptor:ownerassignment:semanticmodelcompilation:matthewaldous',
  admission: 'urn:usf:semanticproofverificationadmission:ownerassignment:semanticmodelcompilation:matthewaldous',
  evidenceAdmission: 'urn:usf:evidenceadmissionpath:ownerassignment:semanticmodelcompilation:matthewaldous',
  producer: 'urn:usf:validationproducer:ownerassignment:semanticmodelcompilation:matthewaldous',
});
const GRAPH_VALIDATION_RESOURCES_V2 = Object.freeze({
  binding: 'urn:usf:validationselfpublicationbinding:compilersemanticenforcementaggregate',
  result: 'urn:usf:validationresult:compilersemanticenforcementaggregate',
  evaluation: 'urn:usf:validationevaluation:compilersemanticenforcementaggregate',
  execution: 'urn:usf:validationexecution:compilersemanticenforcementaggregate',
  proofResult: 'urn:usf:proofresult:compilersemanticenforcementaggregate',
  producer: 'urn:usf:validationproducer:compilersemanticenforcementaggregate',
  evidenceAdmission: 'urn:usf:evidenceadmissionpath:compilersemanticenforcementaggregate',
});
const GRAPH_OWNED_CONSUMER_IRIS_V2 = Object.freeze({
  owner: 'urn:usf:derivedconsumer:v2:owner-envelope-successor',
  validation: 'urn:usf:derivedconsumer:v2:validation-currentness-binding',
});

export async function readImplementationWorkGrantAuthorityStateV1(client, grantIri, {
  casRoot = '/var/lib/usf-cas',
  createEvidenceStore = createCasEvidenceStore,
  evidenceStore = null,
  implementationWorkGrantJournalIo,
  implementationWorkGrantLedgerPath,
  now = new Date(),
  nonPublicationDependencySetDigest = null,
  requireReservedTransaction = false,
  verifyImplementationWorkGrant = verifyImplementationWorkGrantEnvelope,
} = {}) {
  if (!client || typeof client.select !== 'function'
      || !/^urn:usf:implementationworkgrant:[0-9a-f]{64}$/.test(grantIri || '')) {
    throw new Error('implementation work grant readback requires an exact client and grant IRI');
  }
  const [scalarRows, setRows, scopeRows, descriptorRows] = await Promise.all([
    client.select(`SELECT ?authorityDigest ?purpose ?state ?nonce ?evidenceSetDigest ?nonPublicationDependencySetDigest ?candidateDigest
        ?envelopeDigest ?issuedAt ?expiresAt WHERE {
      <${grantIri}> a <urn:usf:ontology:ImplementationWorkGrant> ;
        <urn:usf:ontology:implementationWorkGrantAuthorityDigest> ?authorityDigest ;
        <urn:usf:ontology:implementationWorkGrantPurpose> ?purpose ;
        <urn:usf:ontology:implementationWorkGrantState> ?state ;
        <urn:usf:ontology:implementationWorkGrantNonce> ?nonce ;
        <urn:usf:ontology:implementationWorkGrantEvidenceSetDigest> ?evidenceSetDigest ;
        <urn:usf:ontology:implementationWorkGrantNonPublicationDependencySetDigest> ?nonPublicationDependencySetDigest ;
        <urn:usf:ontology:implementationWorkGrantCandidateDigest> ?candidateDigest ;
        <urn:usf:ontology:implementationWorkGrantEnvelopeDigest> ?envelopeDigest ;
        <urn:usf:ontology:implementationWorkGrantIssuedAt> ?issuedAt ;
        <urn:usf:ontology:implementationWorkGrantExpiresAt> ?expiresAt .
    } LIMIT 2`),
    client.select(`SELECT ?kind ?item WHERE {
      { <${grantIri}> <urn:usf:ontology:implementationWorkGrantAllows> ?item . BIND("allow" AS ?kind) }
      UNION { <${grantIri}> <urn:usf:ontology:implementationWorkGrantDenies> ?item . BIND("deny" AS ?kind) }
      UNION { <${grantIri}> <urn:usf:ontology:implementationWorkGrantEvidenceDescriptor> ?item . BIND("evidence" AS ?kind) }
    } ORDER BY ?kind ?item LIMIT 64`),
    client.select(`SELECT ?scope ?repository ?predecessorCommit ?predecessorTree ?sourceScopeDigest ?path WHERE {
      <${grantIri}> <urn:usf:ontology:implementationWorkGrantRepositoryScope> ?scope .
      ?scope a <urn:usf:ontology:ImplementationWorkRepositoryScope> ;
        <urn:usf:ontology:implementationWorkRepository> ?repository ;
        <urn:usf:ontology:implementationWorkPredecessorCommit> ?predecessorCommit ;
        <urn:usf:ontology:implementationWorkPredecessorTree> ?predecessorTree ;
        <urn:usf:ontology:implementationWorkSourceScopeDigest> ?sourceScopeDigest ;
        <urn:usf:ontology:implementationWorkSourcePath> ?path .
    } ORDER BY ?scope ?path LIMIT 128`),
    client.select(`SELECT ?descriptor ?family ?format ?mediaType ?digest ?byteSize ?locator ?artefactType ?storage WHERE {
      <${grantIri}> <urn:usf:ontology:implementationWorkGrantEvidenceDescriptor> ?descriptor .
      ?descriptor a <urn:usf:ontology:ExternalPayloadDescriptor> ;
        <urn:usf:ontology:descriptorArtefactFamily> ?family ;
        <urn:usf:ontology:descriptorRepresentationFormat> ?format ;
        <urn:usf:ontology:descriptorMediaType> ?mediaType ;
        <urn:usf:ontology:descriptorDigest> ?digest ;
        <urn:usf:ontology:descriptorByteSize> ?byteSize ;
        <urn:usf:ontology:descriptorLocator> ?locator ;
        <urn:usf:ontology:descriptorArtefactType> ?artefactType ;
        <urn:usf:ontology:descriptorStorageClass> ?storage .
    } ORDER BY ?descriptor LIMIT 5`),
  ]);
  if (scalarRows.length !== 1 || scopeRows.length < 2 || scopeRows.length >= 128
      || setRows.length >= 64 || descriptorRows.length !== 4) {
    throw new Error('implementation work grant readback cardinality is invalid');
  }
  const scalar = scalarRows[0];
  const text = (row, key) => row?.[key]?.value ?? null;
  const sets = (kind) => setRows.filter((row) => text(row, 'kind') === kind).map((row) => text(row, 'item')).sort();
  const allowedActions = sets('allow');
  const deniedEffects = sets('deny');
  const expectedAllowed = IMPLEMENTATION_WORK_GRANT_ALLOWED_ACTIONS
    .map((value) => `urn:usf:implementationworkaction:${value.replaceAll('_', '')}`).sort();
  const expectedDenied = IMPLEMENTATION_WORK_GRANT_DENIED_EFFECTS
    .map((value) => `urn:usf:implementationworkeffect:${value.replaceAll('_', '')}`).sort();
  const evidenceDescriptors = sets('evidence');
  if (canonicalJson(allowedActions) !== canonicalJson(expectedAllowed)
      || canonicalJson(deniedEffects) !== canonicalJson(expectedDenied)
      || evidenceDescriptors.length !== 4) {
    throw new Error('implementation work grant readback ALLOW, DENY or evidence closure is incomplete');
  }
  const grouped = new Map();
  for (const row of scopeRows) {
    const scope = text(row, 'scope');
    const current = grouped.get(scope) || {
      predecessor_commit: text(row, 'predecessorCommit'), predecessor_tree: text(row, 'predecessorTree'),
      repository: text(row, 'repository'), source_paths: [], source_scope_digest: text(row, 'sourceScopeDigest'),
    };
    if (current.repository !== text(row, 'repository')
        || current.predecessor_commit !== text(row, 'predecessorCommit')
        || current.predecessor_tree !== text(row, 'predecessorTree')
        || current.source_scope_digest !== text(row, 'sourceScopeDigest')) {
      throw new Error('implementation work repository scope readback is ambiguous');
    }
    current.source_paths.push(text(row, 'path'));
    grouped.set(scope, current);
  }
  const repositories = [...grouped.values()].map((scope) => ({
    ...scope, source_paths: [...new Set(scope.source_paths)].sort(),
  })).sort((left, right) => left.repository.localeCompare(right.repository));
  if (repositories.length !== 2
      || repositories[0].repository !== 'maldous/usf-factory'
      || repositories[1].repository !== 'maldous/usf-graph'
      || repositories.some((scope) => sourceScopeDigest(scope.source_paths) !== scope.source_scope_digest)) {
    throw new Error('implementation work grant readback repository closure is invalid');
  }
  if (![text(scalar, 'authorityDigest'), text(scalar, 'candidateDigest'), text(scalar, 'envelopeDigest'),
    text(scalar, 'evidenceSetDigest'), text(scalar, 'nonPublicationDependencySetDigest')]
    .every((value) => SHA256.test(value || ''))
      || text(scalar, 'purpose') !== 'urn:usf:implementationworkpurpose:v2nativehandover'
      || text(scalar, 'state') !== 'urn:usf:implementationworkgrantstate:reserved'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(text(scalar, 'nonce') || '')
      || !Number.isFinite(Date.parse(text(scalar, 'issuedAt')))
      || !Number.isFinite(Date.parse(text(scalar, 'expiresAt')))) {
    throw new Error('implementation work grant readback scalar closure is invalid');
  }
  if (grantIri !== `urn:usf:implementationworkgrant:${text(scalar, 'candidateDigest').slice(7)}`) {
    throw new Error('implementation work grant readback IRI does not bind its candidate digest');
  }
  const roles = ['decision', 'grant', 'review', 'validation'];
  const artefactTypePrefix = 'urn:usf:artefacttype:implementationworkgrant';
  const descriptorByRole = new Map();
  for (const row of descriptorRows) {
    const descriptor = text(row, 'descriptor');
    const artefactType = text(row, 'artefactType');
    const role = artefactType?.startsWith(artefactTypePrefix) ? artefactType.slice(artefactTypePrefix.length) : null;
    const contentDigest = text(row, 'digest');
    const byteSize = Number(text(row, 'byteSize'));
    if (!roles.includes(role) || descriptorByRole.has(role) || !evidenceDescriptors.includes(descriptor)
        || text(row, 'family') !== 'urn:usf:artefactfamily:evidencepayload'
        || text(row, 'format') !== 'urn:usf:representationformat:jsondata8259'
        || text(row, 'mediaType') !== 'application/json'
        || !SHA256.test(contentDigest || '') || !Number.isSafeInteger(byteSize) || byteSize < 2
        || text(row, 'locator') !== `cas://sha256/${contentDigest.slice(7)}`
        || text(row, 'storage') !== 'urn:usf:storageclass:contentaddressedobjectstorage') {
      throw new Error('implementation work grant evidence descriptor closure is invalid');
    }
    descriptorByRole.set(role, Object.freeze({ byteSize, contentDigest, descriptor }));
  }
  if (canonicalJson([...descriptorByRole.keys()].sort()) !== canonicalJson(roles)) {
    throw new Error('implementation work grant evidence descriptor role set is incomplete');
  }
  const store = evidenceStore || createEvidenceStore(casRoot ?? '/var/lib/usf-cas');
  const artifacts = new Map();
  for (const role of roles) {
    const descriptor = descriptorByRole.get(role);
    const bytes = store.read(descriptor.contentDigest);
    if (!Buffer.isBuffer(bytes) || bytes.length !== descriptor.byteSize || sha256(bytes) !== descriptor.contentDigest) {
      throw new Error('implementation work grant CAS evidence differs from its live descriptor');
    }
    artifacts.set(role, bytes);
  }
  const validation = semanticModelCompilationCommandInternals.validateImplementationWorkGrantArtifacts({
    artifacts,
    authorityDigest: text(scalar, 'authorityDigest'),
    now,
    verifyImplementationWorkGrant,
  });
  const verified = validation.verified;
  const expectedRepositories = verified.repositories.map((scope) => ({
    predecessor_commit: scope.predecessor_commit,
    predecessor_tree: scope.predecessor_tree,
    repository: scope.repository,
    source_paths: scope.source_paths,
    source_scope_digest: scope.source_scope_digest,
  }));
  if (verified.candidate_digest !== text(scalar, 'candidateDigest')
      || verified.envelope_digest !== text(scalar, 'envelopeDigest')
      || verified.evidence_set_digest !== text(scalar, 'evidenceSetDigest')
      || verified.nonpublication_dependency_set_digest !== text(scalar, 'nonPublicationDependencySetDigest')
      || verified.nonce !== text(scalar, 'nonce')
      || verified.issued_at !== text(scalar, 'issuedAt')
      || verified.expires_at !== text(scalar, 'expiresAt')
      || canonicalJson(repositories.map((scope) => ({
        predecessor_commit: scope.predecessor_commit,
        predecessor_tree: scope.predecessor_tree,
        repository: scope.repository,
        source_paths: scope.source_paths,
        source_scope_digest: scope.source_scope_digest,
      }))) !== canonicalJson(expectedRepositories)) {
    throw new Error('implementation work grant live RDF differs from its verified canonical CAS artifacts');
  }
  const transaction = requireReservedTransaction
    ? readImplementationWorkGrantTransaction(verified, {
      journalIo: implementationWorkGrantJournalIo,
      ledgerPath: implementationWorkGrantLedgerPath,
      nonPublicationDependencySetDigest,
      now,
    })
    : null;
  if (requireReservedTransaction && transaction?.state !== 'reserved') {
    throw new Error('implementation work grant has no exact durable reserved transaction');
  }
  return Object.freeze({
    allowedActions: Object.freeze(allowedActions),
    authorityDigest: text(scalar, 'authorityDigest'),
    deniedEffects: Object.freeze(deniedEffects),
    evidenceSetDigest: text(scalar, 'evidenceSetDigest'),
    expiresAt: text(scalar, 'expiresAt'),
    grantCandidateDigest: text(scalar, 'candidateDigest'),
    grantIri,
    issuedAt: text(scalar, 'issuedAt'),
    nonce: text(scalar, 'nonce'),
    nonPublicationDependencySetDigest: text(scalar, 'nonPublicationDependencySetDigest'),
    purpose: text(scalar, 'purpose'),
    repositories: Object.freeze(repositories.map((scope) => Object.freeze({
      predecessorCommit: scope.predecessor_commit,
      predecessorTree: scope.predecessor_tree,
      repository: scope.repository,
      sourcePaths: Object.freeze(scope.source_paths),
      sourceScopeDigest: scope.source_scope_digest,
    }))),
    state: text(scalar, 'state'),
    transactionState: transaction?.state ?? null,
  });
}

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

// Node disables the fsync API outright under --permission, so a process running
// inside the permission model cannot obtain a storage durability barrier at all.
// That is observed from the process, never declared by a caller or an env var,
// and it is reported rather than assumed: a publication that could not fsync
// still completes atomically (open wx -> write -> link -> byte readback) but
// must not be recorded as storage-durable.
const PUBLICATION_DURABILITY_BARRIER = process.permission === undefined
  ? 'FSYNC'
  : 'UNAVAILABLE_UNDER_NODE_PERMISSION_MODEL';

export function publicationDurabilityBarrier() {
  return PUBLICATION_DURABILITY_BARRIER;
}

function durabilityBarrierSync(descriptor) {
  if (PUBLICATION_DURABILITY_BARRIER === 'FSYNC') fsyncSync(descriptor);
}

function publishImmutableFile(path, bytes, { mode = 0o444 } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
    throw new Error('immutable publication requires non-empty bytes');
  }
  const temporary = `${path}.tmp.${process.pid}.${sha256(bytes).slice(7)}`;
  if (existsSync(temporary)) {
    const stat = lstatSync(temporary);
    if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(temporary) !== temporary) {
      throw new Error('immutable publication temporary path is unsafe');
    }
    unlinkSync(temporary);
  }
  let descriptor;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    writeFileSync(descriptor, bytes);
    durabilityBarrierSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    try { linkSync(temporary, path); } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    try { unlinkSync(temporary); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path
      || !readFileSync(path).equals(bytes)) {
    throw new Error('immutable publication readback differs');
  }
  chmodSync(path, mode);
  const directory = openSync(dirname(path), 'r');
  try { durabilityBarrierSync(directory); } finally { closeSync(directory); }
  return Object.freeze({
    path,
    size: bytes.length,
    durabilityBarrier: PUBLICATION_DURABILITY_BARRIER,
  });
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
      publishImmutableFile(path, bytes);
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

function ownerScopesFor(assignments) {
  if (!Array.isArray(assignments)) throw new Error('owner assignments must be an array');
  const observed = assignments
    .map(({ authorityDomain, repository }) => `${authorityDomain}\u0000${repository}`)
    .sort()
    .join('\n');
  for (const scopes of [CURRENT_OWNER_SCOPES, FINAL_V1_OWNER_SCOPES]) {
    const expected = scopes
      .map(({ authorityDomain, repository }) => `${authorityDomain}\u0000${repository}`)
      .sort()
      .join('\n');
    if (observed === expected && assignments.length === scopes.length) return scopes;
  }
  throw new Error('owner assignments must be the exact current or final V1 governed scope set');
}

function ownerAuthorityFromVerification({ assignments, pendingPackage, trustAnchor, evidenceStore }) {
  const ownerScopes = ownerScopesFor(assignments);
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
  const expectedOwnerKeys = ownerScopes
    .map(({ authorityDomain }) => authorityDomain.slice(authorityDomain.lastIndexOf(':') + 1))
    .sort()
    .join(',');
  if (Object.keys(authority).sort().join(',') !== expectedOwnerKeys) {
    throw new Error(`verified owner authority did not produce the exact ${ownerScopes.length} owner domains`);
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
  const ownerScopes = ownerScopesFor(ownerAssignments);
  return Object.freeze(ownerScopes.map((scope) => {
    const matches = ownerAssignments.filter((entry) => entry?.authorityDomain === scope.authorityDomain
      && entry?.repository === scope.repository);
    if (matches.length !== 1 || !Array.isArray(matches[0].sourcePaths) || !matches[0].envelope) {
      throw new Error(`one exact owner assignment is required for ${scope.authorityDomain}`);
    }
    return Object.freeze({ ...scope, sourcePaths: matches[0].sourcePaths, envelope: matches[0].envelope });
  }));
}

function ownerAssignmentsFromArgv(argv) {
  const assignments = [
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
  const repositoryExternalEnvelope = optionalArgument(
    argv, 'owner-assignment-repositoryexternalartefactmaterialisation',
  );
  const repositoryExternalPaths = repeatedArgument(argv, 'repositoryexternal-source-path');
  if ((repositoryExternalEnvelope === undefined) !== (repositoryExternalPaths.length === 0)) {
    throw new Error('repository external owner assignment and source paths must be supplied together');
  }
  if (repositoryExternalEnvelope !== undefined) {
    assignments.splice(1, 0, {
      authorityDomain: REPOSITORY_EXTERNAL_DOMAIN,
      repository: 'maldous/usf-graph',
      sourcePaths: repositoryExternalPaths,
      envelope: readEnvelope(repositoryExternalEnvelope),
    });
  }
  return Object.freeze(assignments);
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

async function stabilizedCandidate({
  stage,
  input,
  command,
  expectedAuthorityDigest,
  initialInventory,
  preservedAuthorityDelta = null,
}) {
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
      preservedAuthorityDelta,
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
  externalAuthorityDelta = null,
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
  const verificationTime = await trustedInstant(trustedTime);
  const pendingPackage = await producer.preparePending({ requestedAuthorityDigest: expectedAuthorityDigest });
  const ownerAuthority = verifyAndDeriveOwnerAuthority({
    ownerAssignments,
    pendingPackage,
    trustAnchor,
    evidenceStore,
    now: verificationTime.date,
    verifyOwnerAssignment: publicationOptions.verifyOwnerAssignment || verifyEnvelope,
  });
  const ownerValidationContext = materializeAggregateOwnerAuthorityValidationContext({
    ownerAuthority,
    pendingPackage,
  });
  const base = await command.prepareSourceDelta({
    expectedAuthorityDigest,
    evidenceStore,
    expectedSource: pendingPackage.aggregateResult.evaluation.sourceBinding,
    externalAuthorityDelta,
    validationAuthorityContext: Object.freeze({
      bytesBase64: ownerValidationContext.bytes.toString('base64'),
      digest: ownerValidationContext.digest,
    }),
    trustedNow: verificationTime.date,
  });
  const baseValidation = admitValidationEvidence({ validationEvidence: base.validationEvidence }, evidenceStoreAdapter(evidenceStore));
  if (baseValidation.digest !== base.baseSemanticDelta.validationReceiptDigest) {
    throw new Error('base source-delta validation receipt was not admitted exactly');
  }
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
  const refreshedDependentValidations = await producer.refreshDependentValidation({
    requestedAuthorityDigest: d1.digest,
  });
  const refreshedPendingPackage = Object.freeze({
    ...pendingPackage,
    checkpointValidation: refreshedDependentValidations.checkpointValidation,
    dependentValidation: refreshedDependentValidations.dependentValidation,
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
    preservedAuthorityDelta: base.preservedAuthorityDelta,
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
    externalAuthorityDelta: base.externalAuthorityDelta,
    initial,
    ownerAuthority,
    pendingPackage,
    stage1,
    stage2,
    stage2Package,
    terminal,
  });
}

export async function configureLiveDependencies(expectedAuthorityDigest, env) {
  try { await fetch('http://127.0.0.1:1/', { signal: AbortSignal.timeout(20) }); } catch { /* initialise dispatcher */ }
  const dispatcherSymbol = Symbol.for('undici.globalDispatcher.1');
  const currentDispatcher = globalThis[dispatcherSymbol];
  if (!currentDispatcher) throw new Error('global fetch dispatcher unavailable; cannot extend validation timeout');
  globalThis[dispatcherSymbol] = new currentDispatcher.constructor({ headersTimeout: 0, bodyTimeout: 0 });
  const [{ default: stardog }, { createStardogSemanticAuthorityClient }, { validateSemanticAuthorityConfiguration },
    { readSemanticAuthorityWitness }, {
      createSemanticModelCompilationCommand, semanticModelCompilationCommandInternals,
    },
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
    client,
    command: createSemanticModelCompilationCommand({
      client,
      readAuthorityWitness: readSemanticAuthorityWitness,
      repositoryRoot: root,
      publicationLane: semanticModelCompilationCommandInternals.createSemanticPublicationLaneV2(
        env.USF_PROGRAMME_ROOT || '/var/lib/usf-programme',
      ),
      nativeGraphStore: createGraphNativeSuccessorStoreV2({
        nativeRoot: `${env.USF_PROGRAMME_ROOT || '/var/lib/usf-programme'}/v2-native-graph-successors`,
        casStore: createCasEvidenceStore(env.USF_CAS_ROOT || '/var/lib/usf-cas'),
      }),
      trustedNow: async () => new Date(await trustedTime()),
      verifyExternalAuthorityProofApproval: verifyEnvelope,
      verifyImplementationWorkGrantEnvelope,
    }),
    readAuthorityWitness: () => readSemanticAuthorityWitness(client),
    readGraphOwnedConsumers: ({ authorityDigest }) => readGraphOwnedProductionConsumersV2(
      client,
      { authorityDigest },
    ),
    trustedTime,
    evidenceStore: createCasEvidenceStore(env.USF_CAS_ROOT || '/var/lib/usf-cas'),
  };
}

export function createReadOnlyStardogShadowClientV2(client) {
  const readOperations = [
    'begin',
    'rollback',
    'connectivity',
    'construct',
    'select',
    'constructInTransaction',
    'selectInTransaction',
  ];
  if (!client || readOperations.some((operation) => typeof client[operation] !== 'function')) {
    throw new Error('V2 Graph production shadow requires the complete read/rollback Stardog surface');
  }
  const refuse = async () => {
    throw new Error('V2_GRAPH_PRODUCTION_WRITES_DISABLED');
  };
  return Object.freeze({
    expectedAuthorityDigest: client.expectedAuthorityDigest,
    ...Object.fromEntries(readOperations.map((operation) => [
      operation,
      (...args) => client[operation](...args),
    ])),
    commit: refuse,
    clearGraphs: refuse,
    addData: refuse,
    validateInTransaction: refuse,
    validateInTransactionWithReceipt: refuse,
  });
}

function createGraphProductionReceiptStoreV2(
  receiptRoot = '/var/lib/usf-programme/v2-publication-receipts',
) {
  mkdirSync(receiptRoot, { recursive: true, mode: 0o755 });
  const canonicalRoot = realpathSync(receiptRoot);
  const rootStat = lstatSync(canonicalRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('V2 Graph receipt root must be a canonical directory');
  }
  chmodSync(canonicalRoot, 0o755);
  return Object.freeze({
    persist(receipt, expectedDigest = sha256(canonicalJson(receipt))) {
      assertExpectedDigest(expectedDigest, 'V2 Graph receipt digest');
      if (sha256(canonicalJson(receipt)) !== expectedDigest) {
        throw new Error('V2 Graph receipt differs from its canonical digest');
      }
      const bytes = Buffer.from(canonicalJson(receipt), 'utf8');
      const path = `${canonicalRoot}/${expectedDigest.slice(7)}.json`;
      publishImmutableFile(path, bytes);
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path
          || !readFileSync(path).equals(bytes)) {
        throw new Error('V2 Graph receipt read-back differs');
      }
      return Object.freeze({ digest: expectedDigest, path });
    },
  });
}

export function createGraphNativeSuccessorStoreV2({
  nativeRoot = '/var/lib/usf-programme/v2-native-graph-successors',
  casStore = createCasEvidenceStore(),
  verifyValidationCurrentnessSignature = (bytes, signature, expectedFingerprint) => (
    semanticProofV1Internals.defaultDetachedVerifier(bytes, signature) === expectedFingerprint
  ),
} = {}) {
  if (!casStore || typeof casStore.persist !== 'function'
      || typeof casStore.read !== 'function' || typeof casStore.verify !== 'function') {
    throw new Error('V2 Graph native successor store requires typed CAS');
  }
  if (typeof verifyValidationCurrentnessSignature !== 'function') {
    throw new Error('V2 Graph native successor store requires validation signature verification');
  }
  const requestedRoot = resolve(nativeRoot);
  const canonicalRoot = ({ create = false } = {}) => {
    if (create) mkdirSync(requestedRoot, { recursive: true, mode: 0o755 });
    if (!existsSync(requestedRoot)) throw new Error('V2_GRAPH_NATIVE_ROOT_MISSING');
    const observed = realpathSync(requestedRoot);
    const rootStat = lstatSync(observed);
    if (observed !== requestedRoot || !rootStat.isDirectory() || rootStat.isSymbolicLink()) {
      throw new Error('V2 Graph native successor root must be canonical');
    }
    return observed;
  };
  const graphSuccessors = (plan) => {
    semanticProofV2.assertProspectivePublicationPlanV2(plan);
    const values = plan.derived_consumers
      .filter((item) => item.expected_successor?.storage_owner === 'GRAPH')
      .sort((left, right) => left.consumer_kind.localeCompare(right.consumer_kind));
    if (values.length !== 2
        || canonicalJson(values.map((item) => item.consumer_kind)) !== canonicalJson([
          'owner_envelope_successor', 'validation_currentness_binding',
        ])) {
      throw new Error('V2 Graph native successor set is not the exact Graph-owned pair');
    }
    return values;
  };
  const nativeRootState = (plan, consumerKind) => {
    const item = graphSuccessors(plan).find((value) => value.consumer_kind === consumerKind);
    if (!item) throw new Error('V2_GRAPH_NATIVE_CONSUMER_MISSING');
    return Object.freeze({
      native_state: Object.freeze(item.expected_successor.payload_preimage.native_state),
      payload_digest: item.expected_successor.payload_digest,
      successor: item.expected_successor,
    });
  };
  const generationPath = (plan, options) => `${canonicalRoot(options)}/${plan.handover_generation_digest.slice(7)}`;
  const createGenerationDirectory = (plan) => {
    const path = generationPath(plan, { create: true });
    mkdirSync(path, { recursive: true, mode: 0o755 });
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) {
      throw new Error('V2 Graph native successor generation directory is unsafe');
    }
    return path;
  };
  const readGenerationDirectory = (plan) => {
    const path = generationPath(plan);
    if (!existsSync(path)) throw new Error('V2_GRAPH_NATIVE_GENERATION_MISSING');
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) {
      throw new Error('V2 Graph native successor generation directory is unsafe');
    }
    return path;
  };
  const readCanonicalFile = (path, missingError) => {
    if (!existsSync(path)) throw new Error(missingError);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path) {
      throw new Error('V2_GRAPH_NATIVE_FILE_UNSAFE');
    }
    return readFileSync(path);
  };
  const currentnessDirectory = (plan, { create = false } = {}) => {
    const generation = create ? createGenerationDirectory(plan) : readGenerationDirectory(plan);
    const path = `${generation}/validation-currentness`;
    if (create) mkdirSync(path, { recursive: true, mode: 0o755 });
    if (!existsSync(path)) throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_STORE_MISSING');
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== path) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_STORE_UNSAFE');
    }
    return path;
  };
  const canonicalTrustedTime = (value) => {
    const text = value instanceof Date ? value.toISOString().replace('.000Z', 'Z') : value;
    if (typeof text !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(text)
        || Number.isNaN(Date.parse(text))) {
      throw new Error('V2_GRAPH_VALIDATION_TRUSTED_TIME_INVALID');
    }
    return text;
  };
  const readCanonicalCasJson = (digest, missingError) => {
    if (!SHA256.test(digest || '')) throw new Error(missingError);
    const bytes = casStore.read(digest);
    if (sha256(bytes) !== digest) throw new Error(missingError);
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new Error(missingError); }
    if (canonicalJson(value) !== bytes.toString('utf8')) throw new Error(missingError);
    return Object.freeze({ bytes, value: Object.freeze(value) });
  };
  const validateCurrentnessEvidenceClosure = (verified, plan, owner, validation) => {
    let latestEvidenceTime = Number.NEGATIVE_INFINITY;
    let earliestEvidenceExpiry = Number.POSITIVE_INFINITY;
    const compilerValidationReportDigests = new Set();
    const providerValidationReceiptDigests = new Set();
    for (const evidenceDigest of verified.payload.evidence_identity_digests) {
      const { value } = readCanonicalCasJson(
        evidenceDigest, 'V2_GRAPH_VALIDATION_CURRENTNESS_EVIDENCE_MISSING',
      );
      const fields = [
        'admission_receipt_digest', 'admission_state', 'authority_digest',
        'compiler_candidate_digest', 'compiler_validation_report_digest',
        'evidence_subject_digest',
        'evidence_admission_path_iri', 'freshness_state', 'handover_generation_digest',
        'observed_at', 'provider_validation_receipt_digest', 'result_state', 'schema',
        'semantic_scope_digest', 'valid_until',
        'validation_producer_identity_digest', 'validation_producer_iri',
        'validation_root_payload_digest',
      ].sort();
      if (canonicalJson(Object.keys(value).sort()) !== canonicalJson(fields)
          || value.schema !== 'usf-v2-native-validation-currentness-evidence-v1'
          || value.admission_state !== 'ADMITTED'
          || value.authority_digest !== plan.predicted_d2_authority_digest
          || value.handover_generation_digest !== plan.handover_generation_digest
          || value.validation_root_payload_digest
            !== verified.payload.validation_root_payload_digest
          || value.semantic_scope_digest !== verified.payload.semantic_scope_digest
          || value.validation_producer_identity_digest
            !== validation.native_state.renewal_rule
              .evidence_admission_producer_identity_digest
          || value.validation_producer_iri
            !== validation.native_state.renewal_rule.validation_producer_iri
          || value.evidence_admission_path_iri
            !== validation.native_state.renewal_rule.evidence_admission_path_iri
          || value.result_state !== 'PASSING'
          || value.freshness_state !== 'CURRENT'
          || !SHA256.test(value.admission_receipt_digest || '')
          || !SHA256.test(value.evidence_subject_digest || '')
          || value.compiler_candidate_digest !== verified.payload.validation_candidate_digest
          || !SHA256.test(value.compiler_validation_report_digest || '')
          || !SHA256.test(value.provider_validation_receipt_digest || '')) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_EVIDENCE_INVALID');
      }
      const reportBytes = casStore.read(value.compiler_validation_report_digest);
      let report;
      try { report = JSON.parse(reportBytes.toString('utf8')); } catch {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_COMPILER_REPORT_INVALID');
      }
      const reportFields = [
        'authorityDigest', 'candidateDigest', 'providerValidationReceipt', 'schema', 'state',
      ].sort();
      if (canonicalJson(Object.keys(report).sort()) !== canonicalJson(reportFields)
          || !reportBytes.equals(Buffer.from(`${canonicalJson(report)}\n`, 'utf8'))
          || sha256(reportBytes) !== value.compiler_validation_report_digest
          || report.schema !== 'semantic-authority-compiler-validation-report-v1'
          || report.authorityDigest !== plan.predicted_d2_authority_digest
          || report.candidateDigest !== value.compiler_candidate_digest
          || !['ROLLED_BACK', 'VALIDATED', 'VALIDATED_ROLLBACK'].includes(report.state)
          || report.providerValidationReceipt?.conforms !== true
          || semanticProofV2.canonicalDigestV2(report.providerValidationReceipt)
            !== value.provider_validation_receipt_digest) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_COMPILER_REPORT_INVALID');
      }
      const evidenceAdmission = readCanonicalCasJson(
        value.admission_receipt_digest,
        'V2_GRAPH_VALIDATION_CURRENTNESS_EVIDENCE_ADMISSION_MISSING',
      ).value;
      const admissionFields = [
        'admission_state', 'admitted_at', 'authority_digest',
        'evidence_admission_path_iri', 'evidence_claim_digest', 'handover_generation_digest',
        'schema', 'validation_producer_iri',
      ].sort();
      if (canonicalJson(Object.keys(evidenceAdmission).sort())
          !== canonicalJson(admissionFields)
          || evidenceAdmission.schema
            !== 'usf-v2-native-validation-currentness-evidence-admission-v1'
          || evidenceAdmission.admission_state !== 'ADMITTED'
          || evidenceAdmission.authority_digest !== plan.predicted_d2_authority_digest
          || evidenceAdmission.handover_generation_digest !== plan.handover_generation_digest
          || evidenceAdmission.evidence_claim_digest !== value.evidence_subject_digest
          || evidenceAdmission.validation_producer_iri !== value.validation_producer_iri
          || evidenceAdmission.evidence_admission_path_iri
            !== value.evidence_admission_path_iri) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_EVIDENCE_ADMISSION_INVALID');
      }
      const {
        admission_receipt_digest: _admissionDigest,
        evidence_subject_digest: _evidenceSubject,
        ...evidenceClaim
      } = value;
      if (value.evidence_subject_digest !== semanticProofV2.canonicalDigestV2({
        schema: 'usf-v2-native-validation-currentness-evidence-claim-v1',
        evidence: evidenceClaim,
      }) || value.admission_receipt_digest !== semanticProofV2.canonicalDigestV2(
        evidenceAdmission,
      )) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_EVIDENCE_ADMISSION_INVALID');
      }
      latestEvidenceTime = Math.max(
        latestEvidenceTime,
        Date.parse(canonicalTrustedTime(value.observed_at)),
        Date.parse(canonicalTrustedTime(evidenceAdmission.admitted_at)),
      );
      earliestEvidenceExpiry = Math.min(
        earliestEvidenceExpiry, Date.parse(canonicalTrustedTime(value.valid_until)),
      );
      compilerValidationReportDigests.add(value.compiler_validation_report_digest);
      providerValidationReceiptDigests.add(value.provider_validation_receipt_digest);
    }
    const proof = readCanonicalCasJson(
      verified.payload.proof_result_digest,
      'V2_GRAPH_VALIDATION_CURRENTNESS_PROOF_MISSING',
    ).value;
    const proofFields = [
      'authority_digest', 'evidence_set_digest', 'handover_generation_digest',
      'evaluation_digest', 'external_verifier_iri', 'predecessor_descendant_digest',
      'proof_algorithm_digest', 'proof_evaluated_at', 'result_state', 'schema',
      'semantic_scope_digest', 'validation_candidate_digest',
      'validation_root_payload_digest',
    ].sort();
    if (canonicalJson(Object.keys(proof).sort()) !== canonicalJson(proofFields)
        || proof.schema !== 'usf-v2-native-validation-currentness-proof-v1'
        || proof.result_state !== 'SUCCESSFUL'
        || proof.authority_digest !== plan.predicted_d2_authority_digest
        || proof.handover_generation_digest !== plan.handover_generation_digest
        || proof.validation_root_payload_digest
          !== verified.payload.validation_root_payload_digest
        || proof.predecessor_descendant_digest
          !== verified.payload.predecessor_descendant_digest
        || proof.semantic_scope_digest !== verified.payload.semantic_scope_digest
        || proof.evidence_set_digest !== verified.payload.evidence_set_digest
        || proof.validation_candidate_digest !== verified.payload.validation_candidate_digest
        || proof.proof_algorithm_digest
          !== validation.native_state.renewal_rule.proof_algorithm_digest
        || proof.external_verifier_iri
          !== validation.native_state.renewal_rule.external_verifier_iri
        || proof.proof_evaluated_at !== verified.payload.proof_evaluated_at) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_PROOF_INVALID');
    }
    const expectedEvaluationDigest = semanticProofV2.canonicalDigestV2({
      schema: 'usf-v2-native-validation-currentness-evaluation-v1',
      authority_digest: proof.authority_digest,
      evidence_set_digest: proof.evidence_set_digest,
      external_verifier_iri: proof.external_verifier_iri,
      handover_generation_digest: proof.handover_generation_digest,
      predecessor_descendant_digest: proof.predecessor_descendant_digest,
      proof_algorithm_digest: proof.proof_algorithm_digest,
      semantic_scope_digest: proof.semantic_scope_digest,
      validation_candidate_digest: proof.validation_candidate_digest,
      validation_root_payload_digest: proof.validation_root_payload_digest,
    });
    if (proof.evaluation_digest !== expectedEvaluationDigest) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_PROOF_EVALUATION_INVALID');
    }
    const proofTime = Date.parse(canonicalTrustedTime(proof.proof_evaluated_at));
    if (latestEvidenceTime > proofTime) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_EVIDENCE_CHRONOLOGY_INVALID');
    }
    if (Date.parse(verified.payload.valid_until) > earliestEvidenceExpiry) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_EVIDENCE_EXPIRES_FIRST');
    }
    const admissionTime = Date.parse(verified.envelope.admission_receipt.admitted_at);
    if (admissionTime < proofTime) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_ADMISSION_CHRONOLOGY_INVALID');
    }
    const admission = readCanonicalCasJson(
      verified.admission_receipt_digest,
      'V2_GRAPH_VALIDATION_CURRENTNESS_ADMISSION_MISSING',
    ).value;
    if (canonicalJson(admission) !== canonicalJson(verified.envelope.admission_receipt)) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_ADMISSION_INVALID');
    }
    const genesis = validation.native_state.handover_currentness;
    const maximumValidity = Date.parse(genesis.valid_until) - Date.parse(genesis.valid_from);
    const requestedValidity = Date.parse(verified.payload.valid_until)
      - Date.parse(verified.payload.valid_from);
    if (!Number.isFinite(maximumValidity) || maximumValidity <= 0
        || requestedValidity <= 0 || requestedValidity > maximumValidity) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_VALIDITY_EXCEEDS_ADMITTED_ROOT');
    }
    if (compilerValidationReportDigests.size !== 1
        || providerValidationReceiptDigests.size !== 1) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_VALIDATION_EVIDENCE_AMBIGUOUS');
    }
    return Object.freeze({
      admission,
      compiler_validation_report_digest: [...compilerValidationReportDigests][0],
      proof,
      provider_validation_receipt_digest: [...providerValidationReceiptDigests][0],
      validation_candidate_digest: proof.validation_candidate_digest,
    });
  };
  const readValidationCurrentness = (plan, {
    trustedNow = null,
    allowOrphanDigest = null,
  } = {}) => {
    semanticProofV2.assertProspectivePublicationPlanV2(plan);
    const owner = nativeRootState(plan, 'owner_envelope_successor');
    const validation = nativeRootState(plan, 'validation_currentness_binding');
    const genesis = validation.native_state.handover_currentness;
    if (genesis.owner_identity_digest !== owner.native_state.owner_identity_digest) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_OWNER_MISMATCH');
    }
    const directory = currentnessDirectory(plan);
    const files = readdirSync(directory).sort();
    const envelopeNames = files.filter((name) => /^descendant-[0-9a-f]{64}\.json$/.test(name));
    const claimNames = files.filter((name) => /^claim-[0-9a-f]{64}\.json$/.test(name));
    if (files.length !== envelopeNames.length + claimNames.length) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_STORE_UNKNOWN_ENTRY');
    }
    const rootDigest = validation.payload_digest;
    let predecessorDigest = rootDigest;
    let current = Object.freeze({
      admission_receipt_digest: genesis.admission_receipt_digest,
      digest: rootDigest,
      evidence_set_digest: genesis.evidence_set_digest,
      proof_result_digest: genesis.proof_result_digest,
      semantic_scope_digest: validation.successor.semantic_scope_digest,
      valid_from: genesis.valid_from,
      valid_until: genesis.valid_until,
      source: 'HANDOVER_GENESIS',
    });
    const visitedClaims = new Set();
    const visitedEnvelopes = new Set();
    while (true) {
      const claimName = `claim-${predecessorDigest.slice(7)}.json`;
      if (!files.includes(claimName)) break;
      const claimBytes = readCanonicalFile(
        `${directory}/${claimName}`, 'V2_GRAPH_VALIDATION_CURRENTNESS_CLAIM_MISSING',
      );
      const claim = JSON.parse(claimBytes.toString('utf8'));
      const expectedClaimFields = [
        'handover_generation_digest', 'predecessor_digest', 'schema', 'successor_digest',
      ].sort();
      if (canonicalJson(Object.keys(claim).sort()) !== canonicalJson(expectedClaimFields)
          || canonicalJson(claim) !== claimBytes.toString('utf8')
          || claim.schema !== 'usf-v2-native-validation-currentness-lineage-claim-v1'
          || claim.handover_generation_digest !== plan.handover_generation_digest
          || claim.predecessor_digest !== predecessorDigest
          || !SHA256.test(claim.successor_digest || '')) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_CLAIM_INVALID');
      }
      if (visitedClaims.has(claimName)) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_LINEAGE_CYCLE');
      }
      visitedClaims.add(claimName);
      const envelopeName = `descendant-${claim.successor_digest.slice(7)}.json`;
      const envelopeBytes = readCanonicalFile(
        `${directory}/${envelopeName}`,
        'V2_GRAPH_VALIDATION_CURRENTNESS_DESCENDANT_MISSING',
      );
      if (!casStore.read(claim.successor_digest).equals(envelopeBytes)) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_DESCENDANT_CAS_MISMATCH');
      }
      const envelope = JSON.parse(envelopeBytes.toString('utf8'));
      if (canonicalJson(envelope) !== envelopeBytes.toString('utf8')
          || sha256(envelopeBytes) !== claim.successor_digest) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_DESCENDANT_MISMATCH');
      }
      const verified = semanticProofV2.assertValidationCurrentnessDescendantV2(envelope, {
        authorityDigest: plan.predicted_d2_authority_digest,
        handoverGenerationDigest: plan.handover_generation_digest,
        ownerIdentityDigest: owner.native_state.owner_identity_digest,
        predecessorDigest,
        semanticScopeDigest: validation.successor.semantic_scope_digest,
        validationRootPayloadDigest: validation.payload_digest,
        verifySignature: (bytes, signature) => verifyValidationCurrentnessSignature(
          bytes, signature, owner.native_state.owner_signing_fingerprint,
        ),
      });
      validateCurrentnessEvidenceClosure(verified, plan, owner, validation);
      visitedEnvelopes.add(envelopeName);
      predecessorDigest = verified.digest;
      current = Object.freeze({
        admission_receipt_digest: verified.admission_receipt_digest,
        digest: verified.digest,
        evidence_set_digest: verified.payload.evidence_set_digest,
        proof_result_digest: verified.payload.proof_result_digest,
        semantic_scope_digest: verified.payload.semantic_scope_digest,
        valid_from: verified.payload.valid_from,
        valid_until: verified.payload.valid_until,
        source: 'V2_MATERIALISATION_CURRENTNESS_DESCENDANT',
      });
    }
    const unexpectedClaims = claimNames.filter((name) => !visitedClaims.has(name));
    const unexpectedEnvelopes = envelopeNames.filter((name) => !visitedEnvelopes.has(name)
      && name !== (allowOrphanDigest === null
        ? '' : `descendant-${allowOrphanDigest.slice(7)}.json`));
    if (unexpectedClaims.length || unexpectedEnvelopes.length) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_LINEAGE_FORK');
    }
    const nowText = trustedNow === null ? null : canonicalTrustedTime(trustedNow);
    const state = nowText === null ? 'UNOBSERVED'
      : (Date.parse(nowText) < Date.parse(current.valid_from)
        || Date.parse(nowText) >= Date.parse(current.valid_until))
        ? 'STALE' : 'CURRENT';
    return Object.freeze({
      ...current,
      handover_generation_digest: plan.handover_generation_digest,
      lineage_length: visitedClaims.size,
      state,
      trusted_now: nowText,
      validation_root_payload_digest: validation.payload_digest,
    });
  };
  const read = (plan, { trustedNow = null } = {}) => {
    semanticProofV2.assertProspectivePublicationPlanV2(plan);
    const expectedPlanBytes = Buffer.from(semanticProofV2.canonicalJsonV2(plan), 'utf8');
    const expectedPlanDigest = semanticProofV2.prospectivePublicationPlanDigestV2(plan);
    if (!casStore.read(expectedPlanDigest).equals(expectedPlanBytes)) {
      throw new Error('V2_GRAPH_NATIVE_PLAN_CAS_MISMATCH');
    }
    const directory = readGenerationDirectory(plan);
    const observations = graphSuccessors(plan).map((item) => {
      const recordBytes = Buffer.from(semanticProofV2.canonicalJsonV2(item.expected_successor));
      const recordDigest = semanticProofV2.canonicalDigestV2(item.expected_successor);
      const recordPath = `${directory}/${item.consumer_kind}.json`;
      const observedRecord = readCanonicalFile(
        recordPath, 'V2_GRAPH_NATIVE_SUCCESSOR_MISSING',
      );
      if (!observedRecord.equals(recordBytes)
          || semanticProofV2.sha256V2(observedRecord) !== recordDigest) {
        throw new Error('V2_GRAPH_NATIVE_SUCCESSOR_RECORD_MISMATCH');
      }
      const recordCasBytes = casStore.read(recordDigest);
      if (!recordCasBytes.equals(recordBytes)) {
        throw new Error('V2_GRAPH_NATIVE_SUCCESSOR_RECORD_CAS_MISMATCH');
      }
      const payloadBytes = casStore.read(item.expected_successor.payload_digest);
      if (semanticProofV2.sha256V2(payloadBytes) !== item.expected_successor.payload_digest
          || payloadBytes.length !== item.expected_successor.payload_size
          || !payloadBytes.equals(Buffer.from(
            semanticProofV2.canonicalJsonV2(item.expected_successor.payload_preimage),
          ))) {
        throw new Error('V2_GRAPH_NATIVE_SUCCESSOR_PAYLOAD_MISMATCH');
      }
      const payload = JSON.parse(payloadBytes.toString('utf8'));
      const core = Object.freeze({
        schema: 'usf-v2-native-successor-readback-v1',
        consumer_kind: item.consumer_kind,
        successor_record_digest: recordDigest,
        handover_generation_digest: plan.handover_generation_digest,
        storage_owner: 'GRAPH',
        production_reader: `urn:usf:productionreader:graph:${item.consumer_kind.replaceAll('_', '-')}:v2`,
        native_payload_digest: item.expected_successor.payload_digest,
        native_payload_cas_uri: item.expected_successor.payload_cas_uri,
        native_payload_size: item.expected_successor.payload_size,
        observation_state: 'EXACT',
      });
      const readback = Object.freeze({
        ...core,
        observation_digest: semanticProofV2.canonicalDigestV2(core),
      });
      semanticProofV2.nativeSuccessorReadbackDigestV2(readback);
      return Object.freeze({
        consumer_kind: item.consumer_kind,
        native_state: Object.freeze(payload.native_state),
        readback,
        successor: item.expected_successor,
      });
    });
    const readbacks = Object.freeze(observations.map((item) => item.readback));
    const nativeSuccessors = Object.freeze(observations.map((item) => item.successor));
    return Object.freeze({
      handover_generation_digest: plan.handover_generation_digest,
      native_successors: nativeSuccessors,
      readbacks,
      validation_currentness: readValidationCurrentness(plan, { trustedNow }),
      observation_digest: semanticProofV2.graphOwnedNativeObservationDigestV2(
        plan.handover_generation_digest, readbacks,
      ),
    });
  };
  const reservePlan = (plan) => {
    semanticProofV2.assertProspectivePublicationPlanV2(plan);
    const directory = createGenerationDirectory(plan);
    const planBytes = Buffer.from(semanticProofV2.canonicalJsonV2(plan), 'utf8');
    const planCas = casStore.persist(planBytes);
    if (planCas.digest !== semanticProofV2.prospectivePublicationPlanDigestV2(plan)) {
      throw new Error('V2 Graph native successor plan CAS persistence differs');
    }
    const planPath = `${directory}/prospective-plan.json`;
    publishImmutableFile(planPath, planBytes);
    if (!readCanonicalFile(planPath, 'V2_GRAPH_NATIVE_PLAN_MISSING').equals(planBytes)) {
      throw new Error('V2 Graph native successor plan readback differs');
    }
    return Object.freeze({
      digest: planCas.digest,
      handover_generation_digest: plan.handover_generation_digest,
      path: planPath,
      size: planBytes.length,
    });
  };
  return Object.freeze({
    reservePlan,
    persistCurrentnessArtifact(value, expectedSchema) {
      if (!value || typeof value !== 'object' || Array.isArray(value)
          || typeof expectedSchema !== 'string' || value.schema !== expectedSchema) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_ARTIFACT_INVALID');
      }
      const bytes = Buffer.from(canonicalJson(value), 'utf8');
      const persisted = casStore.persist(bytes);
      if (!casStore.read(persisted.digest).equals(bytes)) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_ARTIFACT_CAS_MISMATCH');
      }
      return Object.freeze({ ...persisted, bytes });
    },
    persistCurrentnessValidationEvidence(bytes) {
      if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_VALIDATION_BYTES_REQUIRED');
      }
      let report;
      try { report = JSON.parse(bytes.toString('utf8')); } catch {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_COMPILER_REPORT_INVALID');
      }
      if (!bytes.equals(Buffer.from(`${canonicalJson(report)}\n`, 'utf8'))
          || report.schema !== 'semantic-authority-compiler-validation-report-v1'
          || report.providerValidationReceipt?.conforms !== true
          || !SHA256.test(report.authorityDigest || '')
          || !SHA256.test(report.candidateDigest || '')) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_COMPILER_REPORT_INVALID');
      }
      const persisted = casStore.persist(bytes);
      if (!casStore.read(persisted.digest).equals(bytes)) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_VALIDATION_CAS_MISMATCH');
      }
      return persisted;
    },
    install(plan, { trustedNow = null } = {}) {
      reservePlan(plan);
      const directory = readGenerationDirectory(plan);
      for (const item of graphSuccessors(plan)) {
        const successor = item.expected_successor;
        const payloadBytes = Buffer.from(
          semanticProofV2.canonicalJsonV2(successor.payload_preimage), 'utf8',
        );
        const payload = casStore.persist(payloadBytes);
        if (payload.digest !== successor.payload_digest
            || payload.size !== successor.payload_size) {
          throw new Error('V2 Graph native successor CAS persistence differs from plan');
        }
        const recordBytes = Buffer.from(semanticProofV2.canonicalJsonV2(successor), 'utf8');
        const recordDigest = semanticProofV2.canonicalDigestV2(successor);
        const recordCas = casStore.persist(recordBytes);
        if (recordCas.digest !== recordDigest) {
          throw new Error('V2 Graph native successor record CAS persistence differs from plan');
        }
        const path = `${directory}/${item.consumer_kind}.json`;
        publishImmutableFile(path, recordBytes);
        if (!readCanonicalFile(path, 'V2_GRAPH_NATIVE_SUCCESSOR_MISSING')
          .equals(recordBytes)) throw new Error('V2 Graph native successor immutable fork');
      }
      currentnessDirectory(plan, { create: true });
      return read(plan, { trustedNow });
    },
    read,
    readConsumer(plan, consumerKind, { trustedNow = null } = {}) {
      if (!['owner_envelope_successor', 'validation_currentness_binding']
        .includes(consumerKind)) {
        throw new Error('V2_GRAPH_NATIVE_CONSUMER_NOT_REGISTERED');
      }
      if (consumerKind === 'validation_currentness_binding' && trustedNow === null) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_TRUSTED_TIME_REQUIRED');
      }
      const native = read(plan, { trustedNow });
      const successor = native.native_successors.find(
        (item) => item.consumer_kind === consumerKind,
      );
      const readback = native.readbacks.find((item) => item.consumer_kind === consumerKind);
      if (!successor || !readback) throw new Error('V2_GRAPH_NATIVE_CONSUMER_MISSING');
      return Object.freeze({
        native_state: Object.freeze(successor.payload_preimage.native_state),
        readback,
        successor,
        validation_currentness: consumerKind === 'validation_currentness_binding'
          ? native.validation_currentness : null,
      });
    },
    installValidationCurrentnessDescendant(plan, envelope, {
      expectedCompilerValidationReportDigest = null,
      expectedProviderValidationReceiptDigest = null,
      expectedValidationCandidateDigest = null,
      trustedNow,
    } = {}) {
      const envelopeBytes = Buffer.from(semanticProofV2.canonicalJsonV2(envelope), 'utf8');
      const envelopeDigest = semanticProofV2.sha256V2(envelopeBytes);
      const owner = nativeRootState(plan, 'owner_envelope_successor');
      const validation = nativeRootState(plan, 'validation_currentness_binding');
      const verified = semanticProofV2.assertValidationCurrentnessDescendantV2(envelope, {
        authorityDigest: plan.predicted_d2_authority_digest,
        handoverGenerationDigest: plan.handover_generation_digest,
        ownerIdentityDigest: owner.native_state.owner_identity_digest,
        predecessorDigest: envelope.payload.predecessor_descendant_digest,
        semanticScopeDigest: validation.successor.semantic_scope_digest,
        validationRootPayloadDigest: validation.payload_digest,
        trustedNow: canonicalTrustedTime(trustedNow),
        verifySignature: (bytes, signature) => verifyValidationCurrentnessSignature(
          bytes, signature, owner.native_state.owner_signing_fingerprint,
        ),
      });
      const closure = validateCurrentnessEvidenceClosure(verified, plan, owner, validation);
      if ((expectedCompilerValidationReportDigest !== null
            && closure.compiler_validation_report_digest
              !== expectedCompilerValidationReportDigest)
          || (expectedProviderValidationReceiptDigest !== null
            && closure.provider_validation_receipt_digest
              !== expectedProviderValidationReceiptDigest)
          || (expectedValidationCandidateDigest !== null
            && closure.validation_candidate_digest !== expectedValidationCandidateDigest)) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_FRESH_VALIDATION_MISMATCH');
      }
      if (verified.digest !== envelopeDigest) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_DESCENDANT_IDENTITY_MISMATCH');
      }
      const directory = currentnessDirectory(plan);
      const descendantPath = `${directory}/descendant-${envelopeDigest.slice(7)}.json`;
      const persisted = casStore.persist(envelopeBytes);
      if (persisted.digest !== envelopeDigest) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_DESCENDANT_PERSISTENCE_MISMATCH');
      }
      const claimPath = `${directory}/claim-${envelope.payload.predecessor_descendant_digest.slice(7)}.json`;
      const claim = Object.freeze({
        schema: 'usf-v2-native-validation-currentness-lineage-claim-v1',
        handover_generation_digest: plan.handover_generation_digest,
        predecessor_digest: envelope.payload.predecessor_descendant_digest,
        successor_digest: envelopeDigest,
      });
      if (!existsSync(claimPath)) {
        const current = readValidationCurrentness(plan, { allowOrphanDigest: envelopeDigest });
        if (current.digest === envelopeDigest) {
          return readValidationCurrentness(plan, { trustedNow });
        }
        if (current.digest !== envelope.payload.predecessor_descendant_digest) {
          throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_PREDECESSOR_NOT_HEAD');
        }
      }
      // The immutable predecessor claim is the linearisation point.  Publishing it before
      // the native record means two competing descendants cannot both become reachable;
      // interruption after the claim is recoverable only with its exact CAS-bound envelope.
      publishImmutableFile(claimPath, Buffer.from(canonicalJson(claim), 'utf8'));
      publishImmutableFile(descendantPath, envelopeBytes);
      if (!readCanonicalFile(
        descendantPath, 'V2_GRAPH_VALIDATION_CURRENTNESS_DESCENDANT_MISSING',
      ).equals(envelopeBytes)) {
        throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_DESCENDANT_PERSISTENCE_MISMATCH');
      }
      return readValidationCurrentness(plan, { trustedNow });
    },
    readValidationCurrentness,
    persistReceipt(bytes) {
      if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
        throw new Error('V2 Graph terminal receipt CAS bytes are required');
      }
      const receipt = JSON.parse(bytes.toString('utf8'));
      const digest = semanticProofV2.graphPublicationReceiptDigestV2(receipt);
      if (semanticProofV2.canonicalJsonV2(receipt) !== bytes.toString('utf8')) {
        throw new Error('V2 Graph terminal receipt bytes are not canonical');
      }
      const directory = readGenerationDirectory({
        handover_generation_digest: receipt.handover_generation_digest,
      });
      const path = `${directory}/terminal-receipt.json`;
      publishImmutableFile(path, bytes);
      if (!readCanonicalFile(path, 'V2_GRAPH_TERMINAL_RECEIPT_MISSING').equals(bytes)) {
        throw new Error('V2 Graph terminal receipt immutable fork');
      }
      const persisted = casStore.persist(bytes);
      if (persisted.digest !== digest) {
        throw new Error('V2 Graph terminal receipt store/CAS identity mismatch');
      }
      return persisted;
    },
    persistGrantConsumption(bytes) {
      if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
        throw new Error('V2 grant consumption receipt CAS bytes are required');
      }
      const receipt = JSON.parse(bytes.toString('utf8'));
      const digest = sha256(bytes);
      if (canonicalJson(receipt) !== bytes.toString('utf8')
          || receipt.schema !== 'usf-graph-grant-consumption-receipt-v2'
          || receipt.handover_generation_digest === undefined) {
        throw new Error('V2 grant consumption receipt bytes are not canonical');
      }
      const directory = readGenerationDirectory({
        handover_generation_digest: receipt.handover_generation_digest,
      });
      const path = `${directory}/grant-consumption-receipt.json`;
      publishImmutableFile(path, bytes);
      const persisted = casStore.persist(bytes);
      if (persisted.digest !== digest) {
        throw new Error('V2 grant consumption receipt store/CAS identity mismatch');
      }
      return persisted;
    },
    persistFactoryClosure(bytes, handoverGenerationDigest) {
      if (!Buffer.isBuffer(bytes) || bytes.length === 0
          || !SHA256.test(handoverGenerationDigest || '')) {
        throw new Error('V2 Factory closure durable bytes/generation are required');
      }
      const receipt = JSON.parse(bytes.toString('utf8'));
      if (canonicalJson(receipt) !== bytes.toString('utf8')) {
        throw new Error('V2 Factory closure receipt bytes are not canonical');
      }
      const directory = readGenerationDirectory({
        handover_generation_digest: handoverGenerationDigest,
      });
      const path = `${directory}/factory-closure-receipt.json`;
      publishImmutableFile(path, bytes);
      const persisted = casStore.persist(bytes);
      return Object.freeze({ ...persisted, path });
    },
    persistPreFenceEvidence({
      factoryPrepareReceiptBytes,
      graphReservationReceiptBytes,
      handoverGenerationDigest,
    }) {
      if (!Buffer.isBuffer(factoryPrepareReceiptBytes)
          || !Buffer.isBuffer(graphReservationReceiptBytes)
          || !SHA256.test(handoverGenerationDigest || '')) {
        throw new Error('V2 pre-fence evidence bytes/generation are required');
      }
      const directory = readGenerationDirectory({
        handover_generation_digest: handoverGenerationDigest,
      });
      const persist = (name, bytes) => {
        const parsed = JSON.parse(bytes.toString('utf8'));
        if (canonicalJson(parsed) !== bytes.toString('utf8')) {
          throw new Error('V2 pre-fence evidence bytes are not canonical');
        }
        const path = `${directory}/${name}.json`;
        publishImmutableFile(path, bytes);
        const cas = casStore.persist(bytes);
        return Object.freeze({ ...cas, path });
      };
      return Object.freeze({
        factory_prepare: persist('factory-prepare-receipt', factoryPrepareReceiptBytes),
        graph_reservation: persist('graph-reservation-receipt', graphReservationReceiptBytes),
      });
    },
    verifyReceipt(receipt) {
      const digest = semanticProofV2.graphPublicationReceiptDigestV2(receipt);
      const expected = Buffer.from(semanticProofV2.canonicalJsonV2(receipt), 'utf8');
      const observed = casStore.read(digest);
      if (!observed.equals(expected)) {
        throw new Error('V2_GRAPH_TERMINAL_RECEIPT_CAS_MISMATCH');
      }
      return Object.freeze({ digest, size: observed.length });
    },
    // The irreversible terminal floor. Terminal V2 ownership is derived from
    // DURABLE ADMITTED STATE, not from the presence of a runtime fence quad.
    // Deleting the fence, losing the observer, restarting, restoring or
    // reconstructing a deployment must never make V1 reachable again, so this
    // enumerates the durable generations and reports any that already hold a
    // terminal receipt. Read-only; it never creates anything.
    readTerminalOwnershipFloor() {
      const root = resolve(nativeRoot);
      if (!existsSync(root)) return Object.freeze({ terminal: false, generations: Object.freeze([]) });
      const stat = lstatSync(root);
      if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(root) !== root) {
        throw new Error('V2 Graph native successor root is unsafe');
      }
      const generations = [];
      for (const name of readdirSync(root).sort()) {
        if (!/^[0-9a-f]{64}$/.test(name)) continue;
        if (!existsSync(`${root}/${name}/terminal-receipt.json`)) continue;
        generations.push(`sha256:${name}`);
      }
      return Object.freeze({
        terminal: generations.length > 0,
        generations: Object.freeze(generations),
      });
    },
    loadGeneration(handoverGenerationDigest) {
      if (!SHA256.test(handoverGenerationDigest || '')) {
        throw new Error('V2 Graph native generation identity is invalid');
      }
      const directory = readGenerationDirectory({
        handover_generation_digest: handoverGenerationDigest,
      });
      const planPath = `${directory}/prospective-plan.json`;
      const planBytes = readCanonicalFile(planPath, 'V2_GRAPH_NATIVE_PLAN_MISSING');
      const plan = JSON.parse(planBytes.toString('utf8'));
      semanticProofV2.assertProspectivePublicationPlanV2(plan);
      const planDigest = semanticProofV2.prospectivePublicationPlanDigestV2(plan);
      if (plan.handover_generation_digest !== handoverGenerationDigest
          || !planBytes.equals(Buffer.from(semanticProofV2.canonicalJsonV2(plan), 'utf8'))
          || !casStore.read(planDigest).equals(planBytes)) {
        throw new Error('V2_GRAPH_NATIVE_PLAN_MISMATCH');
      }
      const terminalPath = `${directory}/terminal-receipt.json`;
      const consumptionPath = `${directory}/grant-consumption-receipt.json`;
      const closurePath = `${directory}/factory-closure-receipt.json`;
      const preparePath = `${directory}/factory-prepare-receipt.json`;
      const reservationPath = `${directory}/graph-reservation-receipt.json`;
      const loadEvidence = (path, missingError) => {
        const bytes = readCanonicalFile(path, missingError);
        const value = JSON.parse(bytes.toString('utf8'));
        const digest = sha256(bytes);
        if (canonicalJson(value) !== bytes.toString('utf8')
            || !casStore.read(digest).equals(bytes)) {
          throw new Error('V2_GRAPH_PREFENCE_EVIDENCE_STORE_MISMATCH');
        }
        return Object.freeze({ bytes, digest, value: Object.freeze(value) });
      };
      const prepare = loadEvidence(preparePath, 'V2_GRAPH_FACTORY_PREPARE_RECEIPT_MISSING');
      const reservation = loadEvidence(
        reservationPath, 'V2_GRAPH_RESERVATION_RECEIPT_MISSING',
      );
      let factoryClosureReceipt = null;
      let factoryClosureReceiptDigest = null;
      if (existsSync(closurePath)) {
        const closureBytes = readCanonicalFile(
          closurePath, 'V2_GRAPH_FACTORY_CLOSURE_RECEIPT_MISSING',
        );
        factoryClosureReceipt = JSON.parse(closureBytes.toString('utf8'));
        factoryClosureReceiptDigest = sha256(closureBytes);
        if (canonicalJson(factoryClosureReceipt) !== closureBytes.toString('utf8')
            || !casStore.read(factoryClosureReceiptDigest).equals(closureBytes)) {
          throw new Error('V2_GRAPH_FACTORY_CLOSURE_RECEIPT_STORE_MISMATCH');
        }
      }
      let grantConsumptionReceipt = null;
      let grantConsumptionReceiptDigest = null;
      if (existsSync(consumptionPath)) {
        const consumptionBytes = readCanonicalFile(
          consumptionPath, 'V2_GRAPH_GRANT_CONSUMPTION_RECEIPT_MISSING',
        );
        grantConsumptionReceipt = JSON.parse(consumptionBytes.toString('utf8'));
        grantConsumptionReceiptDigest = sha256(consumptionBytes);
        if (canonicalJson(grantConsumptionReceipt) !== consumptionBytes.toString('utf8')
            || !casStore.read(grantConsumptionReceiptDigest).equals(consumptionBytes)) {
          throw new Error('V2_GRAPH_GRANT_CONSUMPTION_RECEIPT_STORE_MISMATCH');
        }
      }
      if (!existsSync(terminalPath)) {
        return Object.freeze({
          factory_prepare_receipt: prepare.value,
          factory_prepare_receipt_digest: prepare.digest,
          graph_reservation_receipt: reservation.value,
          graph_reservation_receipt_digest: reservation.digest,
          grant_consumption_receipt: grantConsumptionReceipt,
          grant_consumption_receipt_digest: grantConsumptionReceiptDigest,
          factory_closure_receipt: factoryClosureReceipt,
          factory_closure_receipt_digest: factoryClosureReceiptDigest,
          plan,
          plan_digest: planDigest,
          terminal_receipt: null,
        });
      }
      const terminalBytes = readCanonicalFile(
        terminalPath, 'V2_GRAPH_TERMINAL_RECEIPT_MISSING',
      );
      const terminalReceipt = JSON.parse(terminalBytes.toString('utf8'));
      const terminalDigest = semanticProofV2.graphPublicationReceiptDigestV2(terminalReceipt);
      if (!terminalBytes.equals(Buffer.from(
        semanticProofV2.canonicalJsonV2(terminalReceipt), 'utf8',
      )) || !casStore.read(terminalDigest).equals(terminalBytes)) {
        throw new Error('V2_GRAPH_TERMINAL_RECEIPT_STORE_MISMATCH');
      }
      return Object.freeze({
        factory_prepare_receipt: prepare.value,
        factory_prepare_receipt_digest: prepare.digest,
        graph_reservation_receipt: reservation.value,
        graph_reservation_receipt_digest: reservation.digest,
        grant_consumption_receipt: grantConsumptionReceipt,
        grant_consumption_receipt_digest: grantConsumptionReceiptDigest,
        factory_closure_receipt: factoryClosureReceipt,
        factory_closure_receipt_digest: factoryClosureReceiptDigest,
        plan,
        plan_digest: planDigest,
        terminal_receipt: terminalReceipt,
        terminal_receipt_digest: terminalDigest,
      });
    },
  });
}

function explicitGrantDigestsFromPlanV2(plan) {
  const values = plan.derived_consumers
    .map((consumer) => consumer.explicit_authorization_grant_digest)
    .filter((value) => value !== null && value !== undefined)
    .sort();
  if (new Set(values).size !== values.length
      || values.some((value) => !SHA256.test(value))) {
    throw new Error('V2 plan explicit grant digest set is not canonical');
  }
  return Object.freeze(values);
}

function exactGraphProductionInputsV2(inputs, configuration, {
  requireFactoryPrepare = true,
} = {}) {
  const { plan } = inputs || {};
  semanticProofV2.assertProspectivePublicationPlanV2(plan);
  if (plan.outcome !== 'PROCEED'
      || plan.graph_protected_commit !== configuration.graphCommit
      || plan.graph_protected_tree !== configuration.graphTree
      || plan.factory_deployment_commit !== inputs.factory_commit
      || plan.factory_deployment_tree !== inputs.factory_tree
      || inputs.graph_commit !== configuration.graphCommit
      || inputs.graph_tree !== configuration.graphTree
      || inputs.publisher_implementation_digest !== configuration.publisherImplementationDigest
      || inputs.publisher_command_digest !== configuration.publisherCommandDigest) {
    throw new Error('V2 Graph production inputs differ from the exact admitted release');
  }
  if (requireFactoryPrepare) {
    const graphReservationReceiptDigest = semanticProofV2.graphReservationReceiptDigestV2(
      inputs.graph_reservation_receipt,
      plan,
      { graphCommit: inputs.graph_commit, graphTree: inputs.graph_tree },
    );
    semanticProofV2.assertFactoryPrepareReceiptV2(inputs.factory_prepare_receipt, plan, {
      factoryCommit: inputs.factory_commit,
      factoryTree: inputs.factory_tree,
    });
    if (inputs.factory_prepare_receipt.graph_reservation_receipt_digest
        !== graphReservationReceiptDigest) {
      throw new Error('Factory PREPARE does not bind the exact Graph reservation receipt');
    }
  }
  return Object.freeze({
    plan,
    planDigest: semanticProofV2.prospectivePublicationPlanDigestV2(plan),
    explicitGrantDigests: explicitGrantDigestsFromPlanV2(plan),
  });
}

function v2BoundaryReceipt(kind, binding, fields = {}) {
  return Object.freeze({
    schema: `usf-graph-${kind}-receipt-v2`,
    protocol: 'semantic-proof-v2',
    release_subject_digest: binding.plan.release_subject_digest,
    prospective_publication_plan_digest: binding.planDigest,
    explicit_authorization_grant_digests: binding.explicitGrantDigests,
    ...fields,
  });
}

function assertDurableGrantConsumptionV2(receipt, binding, closure) {
  const expected = v2BoundaryReceipt('grant-consumption', binding, {
    d2_authority_digest: binding.plan.predicted_d2_authority_digest,
    factory_closure_receipt_digest: semanticProofV2.factoryClosureReceiptDigestV2(
      closure, binding.plan,
    ),
    handover_generation_digest: binding.plan.handover_generation_digest,
    state: 'consumed_for_terminal',
  });
  if (canonicalJson(receipt) !== canonicalJson(expected)) {
    throw new Error('V2 durable grant consumption differs from exact closure/generation');
  }
  return Object.freeze({
    digest: sha256(canonicalJson(receipt)),
    receipt: Object.freeze(receipt),
  });
}

export function createGraphProductionAdapterV2({
  command,
  readAuthorityWitness,
  readGraphOwnedConsumers,
  d1CandidateBytes,
  d1CandidateIdentityBytes,
  d2CandidateBytes,
  d2CandidateIdentityBytes,
  graphCommit,
  graphTree,
  publisherImplementationDigest,
  publisherCommandDigest,
  trustedTime,
  receiptStore = createGraphProductionReceiptStoreV2(),
  nativeGraphStore = createGraphNativeSuccessorStoreV2(),
} = {}) {
  if (!command || typeof command.previewPublicationSequence !== 'function'
      || typeof command.executeV2Candidate !== 'function'
      || typeof command.reserveV2HandoverGeneration !== 'function'
      || typeof command.bindV2FactoryPrepare !== 'function'
      || typeof command.observeV2D1Dependencies !== 'function'
      || typeof command.inspectCandidateState !== 'function'
      || typeof readAuthorityWitness !== 'function'
      || typeof readGraphOwnedConsumers !== 'function'
      || !Buffer.isBuffer(d1CandidateIdentityBytes) || d1CandidateIdentityBytes.length === 0
      || !Buffer.isBuffer(d2CandidateIdentityBytes) || d2CandidateIdentityBytes.length === 0
      || !/^[0-9a-f]{40}$/.test(graphCommit || '')
      || !/^[0-9a-f]{40}$/.test(graphTree || '')
      || !SHA256.test(publisherImplementationDigest || '')
      || !SHA256.test(publisherCommandDigest || '')
      || typeof trustedTime !== 'function'
      || typeof receiptStore?.persist !== 'function'
      || typeof nativeGraphStore?.install !== 'function'
      || typeof nativeGraphStore?.reservePlan !== 'function'
      || typeof nativeGraphStore?.read !== 'function'
      || typeof nativeGraphStore?.persistReceipt !== 'function'
      || typeof nativeGraphStore?.persistGrantConsumption !== 'function'
      || typeof nativeGraphStore?.persistFactoryClosure !== 'function'
      || typeof nativeGraphStore?.persistPreFenceEvidence !== 'function'
      || typeof nativeGraphStore?.verifyReceipt !== 'function') {
    throw new Error('V2 Graph production adapter configuration is incomplete');
  }
  const d1 = exactCandidate(d1CandidateBytes);
  const d2 = exactCandidate(d2CandidateBytes);
  const configuration = Object.freeze({
    graphCommit,
    graphTree,
    publisherImplementationDigest,
    publisherCommandDigest,
  });
  const persistBoundary = (receipt) => Object.freeze({
    ...receiptStore.persist(receipt),
    receipt: Object.freeze(receipt),
  });
  const preview = async (binding) => {
    if (binding.plan.graph_d1_candidate_digest !== d1.digest
        || binding.plan.graph_d2_candidate_digest !== d2.digest) {
      throw new Error('V2 Graph candidate bytes differ from the approved plan');
    }
    const result = await command.previewPublicationSequence({
      d1CandidateBytes: d1.bytes,
      d1CandidateDigest: d1.digest,
      d1CandidateIdentityBytes,
      d2CandidateBytes: d2.bytes,
      d2CandidateDigest: d2.digest,
      d2CandidateIdentityBytes,
      expectedD0AuthorityDigest: binding.plan.d0_authority_digest,
    });
    if (result.d0AuthorityDigest !== binding.plan.d0_authority_digest
        || result.d1.authorityDigest !== binding.plan.predicted_d1_authority_digest
        || canonicalJson(result.d1.dependencyIdentityDigests)
          !== canonicalJson(binding.plan.d1_dependency_identity_digests)
        || result.d2.authorityDigest !== binding.plan.predicted_d2_authority_digest
        || result.d2.evaluationInputAuthorityDigest
          !== binding.plan.d2_evaluation_input_authority_digest
        || result.candidateBindings.releaseSubjectDigest !== binding.plan.release_subject_digest
        || result.candidateBindings.externalAttestationSetRootDigest
          !== binding.plan.external_attestation_set_root_digest
        || result.candidateBindings.candidateGeneratorImplementationDigest
          !== binding.plan.candidate_generator_implementation_digest
        || result.candidateBindings.candidateCommandDigest
          !== binding.plan.candidate_command_digest) {
      throw new Error('V2 Graph production preview differs from the approved plan');
    }
    return result;
  };
  const observe = () => readAuthorityWitness();
  return Object.freeze({
    mode: 'production-v2',
    observe,
    readGraphOwnedConsumers: (authorityDigest) => readGraphOwnedConsumers({ authorityDigest }),
    previewPublication: (input) => command.previewPublicationSequence(input),
    async reserveGrant(inputs) {
      const binding = exactGraphProductionInputsV2(inputs, configuration, {
        requireFactoryPrepare: false,
      });
      const before = await readAuthorityWitness();
      if (before.digest !== binding.plan.d0_authority_digest) {
        throw new Error('V2 grant reservation did not observe exact D0');
      }
      await preview(binding);
      const planReservation = nativeGraphStore.reservePlan(binding.plan);
      if (planReservation.digest !== binding.planDigest
          || planReservation.handover_generation_digest
            !== binding.plan.handover_generation_digest) {
        throw new Error('V2 durable plan reservation differs from the exact handover');
      }
      const reservation = await command.reserveV2HandoverGeneration({
        d0AuthorityDigest: binding.plan.d0_authority_digest,
        handoverGenerationDigest: binding.plan.handover_generation_digest,
        prospectivePublicationPlanDigest: binding.planDigest,
        recoveryAuthorityDigests: [
          binding.plan.predicted_d1_authority_digest,
          binding.plan.predicted_d2_authority_digest,
        ],
      });
      if (reservation.handover_generation_digest !== binding.plan.handover_generation_digest
          || reservation.prospective_publication_plan_digest !== binding.planDigest) {
        throw new Error('V2 handover reservation readback differs from the exact plan');
      }
      const reservationDigest = sha256(canonicalJson(reservation));
      return persistBoundary(v2BoundaryReceipt('grant-reservation', binding, {
        d0_authority_digest: before.digest,
        graph_commit: graphCommit,
        graph_tree: graphTree,
        handover_generation_digest: binding.plan.handover_generation_digest,
        lane_reservation_digest: reservationDigest,
        lane_reservation_schema: reservation.schema,
        reservation_state: 'V2_HANDOVER_RESERVED',
      }));
    },
    async commitD1(inputs) {
      const binding = exactGraphProductionInputsV2(inputs, configuration);
      const factoryPrepareReceiptDigest = semanticProofV2.factoryPrepareReceiptDigestV2(
        inputs.factory_prepare_receipt,
        binding.plan,
        { factoryCommit: inputs.factory_commit, factoryTree: inputs.factory_tree },
      );
      const graphReservationReceiptDigest = semanticProofV2.graphReservationReceiptDigestV2(
        inputs.graph_reservation_receipt,
        binding.plan,
        { graphCommit: inputs.graph_commit, graphTree: inputs.graph_tree },
      );
      if (inputs.factory_prepare_receipt.graph_reservation_receipt_digest
          !== graphReservationReceiptDigest) {
        throw new Error('V2 Factory PREPARE references another Graph reservation');
      }
      const prefence = nativeGraphStore.persistPreFenceEvidence({
        factoryPrepareReceiptBytes: Buffer.from(canonicalJson(inputs.factory_prepare_receipt)),
        graphReservationReceiptBytes: Buffer.from(canonicalJson(inputs.graph_reservation_receipt)),
        handoverGenerationDigest: binding.plan.handover_generation_digest,
      });
      if (prefence.factory_prepare.digest !== factoryPrepareReceiptDigest
          || prefence.graph_reservation.digest !== graphReservationReceiptDigest) {
        throw new Error('V2 pre-fence evidence CAS readback differs');
      }
      const prepareBinding = command.bindV2FactoryPrepare({ factoryPrepareReceiptDigest });
      if (prepareBinding.factory_prepare_receipt_digest !== factoryPrepareReceiptDigest
          || prepareBinding.handover_generation_digest
            !== binding.plan.handover_generation_digest
          || prepareBinding.prospective_publication_plan_digest !== binding.planDigest) {
        throw new Error('V2 Factory prepare binding differs from the reserved generation');
      }
      const witness = await readAuthorityWitness();
      const state = await command.inspectCandidateState({
        candidateBytes: d1.bytes,
        candidateDigest: d1.digest,
      });
      if (witness.digest === binding.plan.d0_authority_digest && state.state === 'pre') {
        await command.executeV2Candidate({
          candidateBytes: d1.bytes,
          candidateDigest: d1.digest,
          candidateIdentityBytes: d1CandidateIdentityBytes,
          expectedD0AuthorityDigest: binding.plan.d0_authority_digest,
          expectedAuthorityDigest: binding.plan.d0_authority_digest,
          expectedPostAuthorityDigest: binding.plan.predicted_d1_authority_digest,
          prospectivePublicationPlanDigest: binding.planDigest,
          factoryPrepareReceiptDigest,
          publicationMode: 'commit',
          stage: 'C1',
        });
      } else if (witness.digest !== binding.plan.predicted_d1_authority_digest
          || state.state !== 'post') {
        throw new Error('V2 D1 commit cannot reconcile the live authority and candidate state');
      }
      const settled = await settledWitness(readAuthorityWitness, await readAuthorityWitness());
      if (settled.digest !== binding.plan.predicted_d1_authority_digest) {
        throw new Error('V2 D1 did not settle at the approved authority');
      }
      const persisted = persistBoundary(v2BoundaryReceipt('d1-commit', binding, {
        authority_digest: settled.digest,
        candidate_digest: d1.digest,
        graph_count: settled.inventory.length,
        triples: settled.triples,
      }));
      return Object.freeze({ authority_digest: settled.digest, receipt_digest: persisted.digest });
    },
    async observeD1(inputs) {
      const binding = exactGraphProductionInputsV2(inputs, configuration);
      const observation = await command.observeV2D1Dependencies({
        expectedAuthorityDigest: binding.plan.predicted_d1_authority_digest,
      });
      if (canonicalJson(observation.dependencyIdentityDigests)
          !== canonicalJson(binding.plan.d1_dependency_identity_digests)) {
        throw new Error('V2 D1 dependency observation differs from the approved plan');
      }
      const persisted = persistBoundary(v2BoundaryReceipt('d1-observation', binding, {
        authority_digest: observation.authorityDigest,
        dependency_identity_digests: observation.dependencyIdentityDigests,
      }));
      return Object.freeze({
        authority_digest: observation.authorityDigest,
        dependency_identity_digests: observation.dependencyIdentityDigests,
        receipt_digest: persisted.digest,
      });
    },
    async commitD2(inputs) {
      const binding = exactGraphProductionInputsV2(inputs, configuration);
      const factoryPrepareReceiptDigest = semanticProofV2.factoryPrepareReceiptDigestV2(
        inputs.factory_prepare_receipt,
        binding.plan,
        { factoryCommit: inputs.factory_commit, factoryTree: inputs.factory_tree },
      );
      await command.reserveV2HandoverGeneration({
        d0AuthorityDigest: binding.plan.d0_authority_digest,
        handoverGenerationDigest: binding.plan.handover_generation_digest,
        prospectivePublicationPlanDigest: binding.planDigest,
        recoveryAuthorityDigests: [
          binding.plan.predicted_d1_authority_digest,
          binding.plan.predicted_d2_authority_digest,
        ],
      });
      const prepareBinding = command.bindV2FactoryPrepare({ factoryPrepareReceiptDigest });
      if (prepareBinding.factory_prepare_receipt_digest !== factoryPrepareReceiptDigest) {
        throw new Error('V2 D2 recovery Factory prepare binding differs');
      }
      const witness = await readAuthorityWitness();
      const state = await command.inspectCandidateState({
        candidateBytes: d2.bytes,
        candidateDigest: d2.digest,
      });
      if (witness.digest === binding.plan.predicted_d1_authority_digest && state.state === 'pre') {
        await command.executeV2Candidate({
          candidateBytes: d2.bytes,
          candidateDigest: d2.digest,
          candidateIdentityBytes: d2CandidateIdentityBytes,
          expectedD0AuthorityDigest: binding.plan.d0_authority_digest,
          expectedAuthorityDigest: binding.plan.predicted_d1_authority_digest,
          expectedPostAuthorityDigest: binding.plan.predicted_d2_authority_digest,
          prospectivePublicationPlanDigest: binding.planDigest,
          factoryPrepareReceiptDigest: semanticProofV2.factoryPrepareReceiptDigestV2(
            inputs.factory_prepare_receipt,
            binding.plan,
            { factoryCommit: inputs.factory_commit, factoryTree: inputs.factory_tree },
          ),
          publicationMode: 'commit',
          stage: 'C2',
        });
      } else if (witness.digest !== binding.plan.predicted_d2_authority_digest
          || state.state !== 'post') {
        throw new Error('V2 D2 commit cannot reconcile the live authority and candidate state');
      }
      const settled = await settledWitness(readAuthorityWitness, await readAuthorityWitness());
      if (settled.digest !== binding.plan.predicted_d2_authority_digest) {
        throw new Error('V2 D2 did not settle at the approved authority');
      }
      const installationTime = (await trustedInstant(trustedTime)).canonical;
      const nativeGraph = nativeGraphStore.install(binding.plan, { trustedNow: installationTime });
      if (nativeGraph.handover_generation_digest !== binding.plan.handover_generation_digest) {
        throw new Error('V2 Graph native successor installation used another generation');
      }
      if (nativeGraph.validation_currentness.state !== 'CURRENT') {
        throw new Error('V2 Graph native validation currentness is not current at D2');
      }
      const persisted = persistBoundary(v2BoundaryReceipt('d2-commit', binding, {
        authority_digest: settled.digest,
        candidate_digest: d2.digest,
        evaluated_authority_digest: binding.plan.predicted_d1_authority_digest,
        graph_count: settled.inventory.length,
        triples: settled.triples,
        handover_generation_digest: binding.plan.handover_generation_digest,
        graph_native_successor_readbacks: nativeGraph.readbacks,
        graph_owned_observation_digest: nativeGraph.observation_digest,
      }));
      return Object.freeze({
        authority_digest: settled.digest,
        evaluated_authority_digest: binding.plan.predicted_d1_authority_digest,
        receipt_digest: persisted.digest,
        graph_native_successor_readbacks: nativeGraph.readbacks,
        graph_owned_observation_digest: nativeGraph.observation_digest,
      });
    },
    async persistTerminalReceipt(receipt, inputs) {
      const binding = exactGraphProductionInputsV2(inputs, configuration);
      const digest = semanticProofV2.graphPublicationReceiptDigestV2(receipt);
      if (receipt.prospective_publication_plan_digest !== binding.planDigest) {
        throw new Error('V2 terminal receipt differs from the approved plan');
      }
      const terminalTime = (await trustedInstant(trustedTime)).canonical;
      const nativeGraph = nativeGraphStore.read(binding.plan, { trustedNow: terminalTime });
      if (nativeGraph.validation_currentness.state !== 'CURRENT') {
        throw new Error('V2 terminal receipt requires CURRENT Graph validation currentness');
      }
      const closure = semanticProofV2.assertFactoryClosureReceiptV2(
        inputs.factory_closure_receipt, binding.plan,
      );
      const durable = nativeGraphStore.loadGeneration(binding.plan.handover_generation_digest);
      if (canonicalJson(durable.factory_closure_receipt) !== canonicalJson(closure)
          || durable.factory_closure_receipt_digest
            !== semanticProofV2.factoryClosureReceiptDigestV2(closure, binding.plan)) {
        throw new Error('V2 terminal receipt lacks exact durable Factory closure');
      }
      const prepareDigest = semanticProofV2.factoryPrepareReceiptDigestV2(
        durable.factory_prepare_receipt,
        binding.plan,
        { factoryCommit: inputs.factory_commit, factoryTree: inputs.factory_tree },
      );
      const reservationDigest = semanticProofV2.graphReservationReceiptDigestV2(
        durable.graph_reservation_receipt,
        binding.plan,
        { graphCommit: inputs.graph_commit, graphTree: inputs.graph_tree },
      );
      if (prepareDigest !== receipt.factory_prepare_receipt_digest
          || durable.factory_prepare_receipt_digest !== prepareDigest
          || durable.graph_reservation_receipt_digest !== reservationDigest
          || durable.factory_prepare_receipt.graph_reservation_receipt_digest
            !== reservationDigest) {
        throw new Error('V2 terminal receipt lacks exact durable reservation/PREPARE chain');
      }
      const consumption = assertDurableGrantConsumptionV2(
        durable.grant_consumption_receipt, binding, closure,
      );
      const graphReadbacks = closure.native_successor_readbacks
        .filter((item) => item.storage_owner === 'GRAPH');
      if (canonicalJson(graphReadbacks) !== canonicalJson(nativeGraph.readbacks)
          || closure.graph_owned_observation_digest !== nativeGraph.observation_digest
          || receipt.graph_owned_observation_digest !== nativeGraph.observation_digest
          || receipt.grant_consumption_receipt_digest !== consumption.digest
          || durable.grant_consumption_receipt_digest !== consumption.digest) {
        throw new Error('V2 terminal receipt does not match Graph production reread');
      }
      const bytes = Buffer.from(semanticProofV2.canonicalJsonV2(receipt), 'utf8');
      const cas = nativeGraphStore.persistReceipt(bytes);
      if (cas.digest !== digest || cas.size !== bytes.length) {
        throw new Error('V2 terminal receipt CAS identity differs from canonical bytes');
      }
      const persisted = receiptStore.persist(receipt, digest);
      return Object.freeze({
        ...persisted,
        cas_uri: `cas://sha256/${digest.slice(7)}`,
        size: bytes.length,
      });
    },
    async consumeGrant(closureReceipt, inputs) {
      const binding = exactGraphProductionInputsV2(inputs, configuration);
      const closure = semanticProofV2.assertFactoryClosureReceiptV2(
        closureReceipt, binding.plan,
      );
      const receipt = v2BoundaryReceipt('grant-consumption', binding, {
        d2_authority_digest: binding.plan.predicted_d2_authority_digest,
        factory_closure_receipt_digest: semanticProofV2.factoryClosureReceiptDigestV2(
          closure, binding.plan,
        ),
        handover_generation_digest: binding.plan.handover_generation_digest,
        state: 'consumed_for_terminal',
      });
      const closureBytes = Buffer.from(semanticProofV2.canonicalJsonV2(closure), 'utf8');
      const closurePersisted = nativeGraphStore.persistFactoryClosure(
        closureBytes, binding.plan.handover_generation_digest,
      );
      if (closurePersisted.digest
          !== semanticProofV2.factoryClosureReceiptDigestV2(closure, binding.plan)) {
        throw new Error('V2 Factory closure Graph CAS persistence differs');
      }
      const bytes = Buffer.from(canonicalJson(receipt), 'utf8');
      const native = nativeGraphStore.persistGrantConsumption(bytes);
      const persisted = persistBoundary(receipt);
      if (native.digest !== persisted.digest || native.size !== bytes.length) {
        throw new Error('V2 grant consumption durable evidence differs');
      }
      return Object.freeze({
        ...persisted,
        cas_uri: `cas://sha256/${persisted.digest.slice(7)}`,
        size: bytes.length,
      });
    },
    async verifyTerminalOwnership(receipt, inputs) {
      const binding = exactGraphProductionInputsV2(inputs, configuration);
      const digest = semanticProofV2.graphPublicationReceiptDigestV2(receipt);
      if (receipt.prospective_publication_plan_digest !== binding.planDigest
          || receipt.handover_generation_digest !== binding.plan.handover_generation_digest
          || receipt.d2_authority_digest !== binding.plan.predicted_d2_authority_digest) {
        throw new Error('V2 terminal ownership receipt differs from the admitted generation');
      }
      const witness = await readAuthorityWitness();
      if (witness.digest !== binding.plan.predicted_d2_authority_digest) {
        throw new Error('V2 terminal ownership no longer observes exact D2 authority');
      }
      const durable = nativeGraphStore.loadGeneration(binding.plan.handover_generation_digest);
      if (canonicalJson(durable.plan) !== canonicalJson(binding.plan)
          || canonicalJson(durable.terminal_receipt) !== canonicalJson(receipt)) {
        throw new Error('V2 terminal ownership durable generation differs');
      }
      const verificationTime = (await trustedInstant(trustedTime)).canonical;
      const nativeGraph = nativeGraphStore.read(durable.plan, { trustedNow: verificationTime });
      if (nativeGraph.validation_currentness.state !== 'CURRENT') {
        throw new Error('V2 terminal ownership execution is blocked by validation currentness');
      }
      const closure = semanticProofV2.assertFactoryClosureReceiptV2(
        inputs.factory_closure_receipt, binding.plan,
      );
      const consumption = assertDurableGrantConsumptionV2(
        durable.grant_consumption_receipt, binding, closure,
      );
      const prepareDigest = semanticProofV2.factoryPrepareReceiptDigestV2(
        durable.factory_prepare_receipt,
        binding.plan,
        { factoryCommit: inputs.factory_commit, factoryTree: inputs.factory_tree },
      );
      const reservationDigest = semanticProofV2.graphReservationReceiptDigestV2(
        durable.graph_reservation_receipt,
        binding.plan,
        { graphCommit: inputs.graph_commit, graphTree: inputs.graph_tree },
      );
      const graphReadbacks = closure.native_successor_readbacks
        .filter((item) => item.storage_owner === 'GRAPH');
      if (canonicalJson(graphReadbacks) !== canonicalJson(nativeGraph.readbacks)
          || receipt.graph_owned_observation_digest !== nativeGraph.observation_digest) {
        throw new Error('V2 terminal ownership Graph native readback drifted');
      }
      if (durable.terminal_receipt_digest !== digest) {
        throw new Error('V2 terminal ownership CAS drifted');
      }
      if (durable.factory_closure_receipt_digest
            !== semanticProofV2.factoryClosureReceiptDigestV2(closure, binding.plan)
          || canonicalJson(durable.factory_closure_receipt) !== canonicalJson(closure)
          || durable.grant_consumption_receipt_digest !== consumption.digest
          || receipt.factory_prepare_receipt_digest !== prepareDigest
          || durable.factory_prepare_receipt_digest !== prepareDigest
          || durable.factory_prepare_receipt.graph_reservation_receipt_digest
            !== reservationDigest
          || durable.graph_reservation_receipt_digest !== reservationDigest
          || receipt.grant_consumption_receipt_digest !== consumption.digest) {
        throw new Error('V2 terminal ownership durable consumption/closure drifted');
      }
      return Object.freeze({
        authority_digest: witness.digest,
        graph_native_successors: nativeGraph.native_successors,
        graph_native_successor_readbacks: nativeGraph.readbacks,
        graph_owned_observation_digest: nativeGraph.observation_digest,
        handover_generation_digest: binding.plan.handover_generation_digest,
        ownership_state: 'V2_TERMINAL_OWNER',
        terminal_receipt_digest: digest,
      });
    },
  });
}

function canonicalSparqlTermV2(term) {
  if (!term || !['uri', 'literal'].includes(term.type)
      || typeof term.value !== 'string' || term.value.length === 0) {
    throw new Error('V2_GRAPH_CONSUMER_UNKNOWN_RDF_TERM');
  }
  return Object.freeze({
    term_type: term.type,
    value: term.value,
    datatype: term.datatype || null,
    language: term.lang || term['xml:lang'] || null,
  });
}

async function readExactResourceStatementsV2(client, resourceIris) {
  if (!Array.isArray(resourceIris) || resourceIris.length === 0
      || new Set(resourceIris).size !== resourceIris.length
      || resourceIris.some((iri) => typeof iri !== 'string' || !iri.startsWith('urn:usf:'))) {
    throw new Error('V2 Graph consumer resource set is not exact');
  }
  const values = resourceIris.slice().sort().map((iri) => `<${iri}>`).join(' ');
  const rows = await client.select(`SELECT ?subject ?predicate ?object WHERE {
    VALUES ?subject { ${values} }
    ?subject ?predicate ?object .
  } ORDER BY ?subject ?predicate ?object`);
  const statements = rows.map((row) => Object.freeze({
    subject: row.subject?.value,
    predicate: row.predicate?.value,
    object: canonicalSparqlTermV2(row.object),
  })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  if (statements.some((statement) => !resourceIris.includes(statement.subject)
      || typeof statement.predicate !== 'string')
      || new Set(statements.map((statement) => JSON.stringify(statement))).size !== statements.length) {
    throw new Error('V2 Graph consumer materialisation is non-canonical');
  }
  for (const iri of resourceIris) {
    if (!statements.some((statement) => statement.subject === iri)) {
      throw new Error(`V2_GRAPH_CONSUMER_CARDINALITY:0:${iri}`);
    }
  }
  return Object.freeze(statements);
}

const statementsForV2 = (statements, subject, predicate) => statements.filter(
  (statement) => statement.subject === subject && statement.predicate === predicate,
);

function soleObjectV2(statements, subject, predicate, { termType, value } = {}) {
  const matches = statementsForV2(statements, subject, predicate);
  if (matches.length !== 1) {
    throw new Error(`V2_GRAPH_CONSUMER_CARDINALITY:${matches.length}:${subject}:${predicate}`);
  }
  const object = matches[0].object;
  if ((termType && object.term_type !== termType) || (value && object.value !== value)) {
    throw new Error(`V2_GRAPH_CONSUMER_SCHEMA_MISMATCH:${subject}:${predicate}`);
  }
  return object.value;
}

function manyObjectsV2(statements, subject, predicate, { exactCount, termType } = {}) {
  const values = statementsForV2(statements, subject, predicate).map((statement) => {
    if (termType && statement.object.term_type !== termType) {
      throw new Error(`V2_GRAPH_CONSUMER_SCHEMA_MISMATCH:${subject}:${predicate}`);
    }
    return statement.object.value;
  }).sort();
  if ((exactCount !== undefined && values.length !== exactCount)
      || values.length === 0 || new Set(values).size !== values.length) {
    throw new Error(`V2_GRAPH_CONSUMER_CARDINALITY:${values.length}:${subject}:${predicate}`);
  }
  return Object.freeze(values);
}

function requireTypesV2(statements, subject, expectedTypes) {
  const types = manyObjectsV2(statements, subject, RDF_TYPE, {
    exactCount: expectedTypes.length, termType: 'uri',
  });
  if (JSON.stringify(types) !== JSON.stringify(expectedTypes.slice().sort())) {
    throw new Error(`V2_GRAPH_CONSUMER_UNKNOWN_SCHEMA:${subject}`);
  }
}

function exactSha256ValueV2(value, label) {
  if (!SHA256.test(value || '')) throw new Error(`${label} is not an exact sha256 identity`);
  return value;
}

function readOwnerConsumerFactsV2(statements) {
  const r = GRAPH_OWNER_RESOURCES_V2;
  requireTypesV2(statements, r.assignment, [`${USF_ONTOLOGY}OwnerAssignment`]);
  requireTypesV2(statements, r.verification, [`${USF_ONTOLOGY}SemanticProofEnvelopeVerification`]);
  requireTypesV2(statements, r.descriptor, [`${USF_ONTOLOGY}SemanticProofVerificationCASDescriptor`]);
  requireTypesV2(statements, r.admission, [`${USF_ONTOLOGY}SemanticProofEnvelopeVerificationAdmission`]);
  requireTypesV2(statements, r.evidenceAdmission, [`${USF_ONTOLOGY}EvidenceAdmissionPath`]);
  requireTypesV2(statements, r.producer, [`${USF_ONTOLOGY}ValidationProducer`]);
  const one = (subject, predicate, options) => soleObjectV2(
    statements, subject, `${USF_ONTOLOGY}${predicate}`, options,
  );
  const assignment = Object.freeze({
    principal: one(r.assignment, 'authorityPrincipal', { termType: 'uri' }),
    signing_identity: one(r.assignment, 'authoritySigningIdentity', { termType: 'uri' }),
    authority_domain: one(r.assignment, 'authorityDomain', { termType: 'uri' }),
    repository: one(r.assignment, 'authorityRepository', { termType: 'literal' }),
    source_scope_digest: exactSha256ValueV2(one(r.assignment, 'sourceScopeDigest'), 'owner source scope'),
    source_paths: manyObjectsV2(statements, r.assignment,
      `${USF_ONTOLOGY}ownerAssignmentSourcePath`, { termType: 'literal' }),
  });
  const assignmentCandidate = exactSha256ValueV2(
    one(r.assignment, 'assignmentCandidateDigest'), 'owner assignment candidate',
  );
  const authorityPre = exactSha256ValueV2(
    one(r.assignment, 'assignmentAuthorityPreDigest'), 'owner assignment authority pre-digest',
  );
  const envelope = exactSha256ValueV2(one(r.assignment, 'signedEnvelopeDigest'), 'owner envelope');
  one(r.assignment, 'assignmentState', { value: 'active' });
  one(r.assignment, 'hasAdmittedEnvelopeVerification', { termType: 'uri', value: r.verification });
  one(r.verification, 'verificationForOwnerAssignment', { termType: 'uri', value: r.assignment });
  one(r.verification, 'verifiedAuthorityPrincipal', { termType: 'uri', value: assignment.principal });
  one(r.verification, 'verifiedAuthoritySigningIdentity', { termType: 'uri', value: assignment.signing_identity });
  one(r.verification, 'verifiedAuthorityDomain', { termType: 'uri', value: assignment.authority_domain });
  one(r.verification, 'verifiedAuthorityRepository', { value: assignment.repository });
  one(r.verification, 'verifiedSourceScopeDigest', { value: assignment.source_scope_digest });
  one(r.verification, 'verifiedAssignmentCandidateDigest', { value: assignmentCandidate });
  one(r.verification, 'verifiedAssignmentAuthorityPreDigest', { value: authorityPre });
  one(r.verification, 'verifiedEnvelopeDigest', { value: envelope });
  one(r.verification, 'envelopeVerificationState', {
    termType: 'uri', value: 'urn:usf:resultstate:passed',
  });
  one(r.verification, 'verificationCASDescriptor', { termType: 'uri', value: r.descriptor });
  one(r.verification, 'hasEnvelopeVerificationAdmission', { termType: 'uri', value: r.admission });
  const verifiedPaths = manyObjectsV2(statements, r.verification,
    `${USF_ONTOLOGY}verifiedOwnerAssignmentSourcePath`, { termType: 'literal' });
  if (JSON.stringify(verifiedPaths) !== JSON.stringify(assignment.source_paths)) {
    throw new Error('V2 owner-envelope verification source scope drifted');
  }
  one(r.descriptor, 'semanticProofCASVerificationState', {
    termType: 'uri', value: 'urn:usf:resultstate:passed',
  });
  exactSha256ValueV2(one(r.descriptor, 'semanticProofCASDigest'), 'owner verification CAS');
  one(r.admission, 'admitsEnvelopeVerification', { termType: 'uri', value: r.verification });
  one(r.admission, 'admittedVerificationCASDescriptor', { termType: 'uri', value: r.descriptor });
  one(r.admission, 'verificationAdmissionUsesEvidencePath', {
    termType: 'uri', value: r.evidenceAdmission,
  });
  one(r.admission, 'verificationAdmissionState', {
    termType: 'uri', value: 'urn:usf:resultstate:passed',
  });
  return Object.freeze({
    consumer_kind: 'owner_envelope_successor',
    consumer_iri: GRAPH_OWNED_CONSUMER_IRIS_V2.owner,
    predecessor_record_iri: r.assignment,
    semantic_scope: assignment,
    materialisation: statements,
    validation_input_authority_digest: null,
    validation_input_identity_digests: Object.freeze([]),
  });
}

function readValidationConsumerFactsV2(statements) {
  const r = GRAPH_VALIDATION_RESOURCES_V2;
  requireTypesV2(statements, r.binding, [`${USF_ONTOLOGY}ValidationSelfPublicationBinding`]);
  requireTypesV2(statements, r.result, [`${USF_ONTOLOGY}ValidationResult`]);
  requireTypesV2(statements, r.evaluation, [`${USF_ONTOLOGY}ValidationEvaluation`]);
  requireTypesV2(statements, r.execution, [`${USF_ONTOLOGY}ValidationExecution`]);
  requireTypesV2(statements, r.proofResult, [
    `${USF_ONTOLOGY}PostPublicationAggregateProofResult`, `${USF_ONTOLOGY}ProofResult`,
  ]);
  requireTypesV2(statements, r.producer, [`${USF_ONTOLOGY}ValidationProducer`]);
  requireTypesV2(statements, r.evidenceAdmission, [`${USF_ONTOLOGY}EvidenceAdmissionPath`]);
  const one = (subject, predicate, options) => soleObjectV2(
    statements, subject, `${USF_ONTOLOGY}${predicate}`, options,
  );
  const bindingResult = one(r.binding, 'authorityBindingForValidationResult', {
    termType: 'uri', value: r.result,
  });
  const producer = one(r.binding, 'authorityBindingValidationProducer', {
    termType: 'uri', value: r.producer,
  });
  const admission = one(r.binding, 'authorityBindingEvidenceAdmissionPath', {
    termType: 'uri', value: r.evidenceAdmission,
  });
  const d0 = exactSha256ValueV2(
    one(r.binding, 'validationStageOneEvaluatedAuthorityDigest'), 'validation D0 authority',
  );
  const d1 = exactSha256ValueV2(
    one(r.binding, 'validationStageOneSettledAuthorityDigest'), 'validation D1 authority',
  );
  const dependency = exactSha256ValueV2(
    one(r.binding, 'validationNonPublicationDependencySetDigest'), 'validation dependency set',
  );
  one(r.binding, 'validationReevaluationDependencyDigest', { value: dependency });
  one(r.binding, 'validationPostPublicationReevaluationState', {
    termType: 'uri', value: 'urn:usf:resultstate:passed',
  });
  one(r.binding, 'validationRequiresPostPublicationReevaluation', { value: 'true' });
  const executionReceipt = exactSha256ValueV2(
    one(r.binding, 'validationBindingExecutionReceiptDigest'), 'validation execution receipt',
  );
  const evaluationReceipt = exactSha256ValueV2(
    one(r.binding, 'validationBindingEvaluationReceiptDigest'), 'validation evaluation receipt',
  );
  const sourceScope = exactSha256ValueV2(
    one(r.binding, 'validationBindingSourceScopeDigest'), 'validation source scope',
  );
  const sourceHead = one(r.binding, 'validationBindingSourceHead');
  const sourceTree = one(r.binding, 'validationBindingSourceTree');
  one(r.result, 'hasValidationSelfPublicationAuthorityBinding', {
    termType: 'uri', value: r.binding,
  });
  one(r.result, 'resultState', { termType: 'uri', value: 'urn:usf:resultstate:passed' });
  one(r.result, 'hasFreshness', { termType: 'uri', value: 'urn:usf:freshness:fresh' });
  one(r.result, 'validationEvaluatedAuthorityDigest', { value: d1 });
  one(r.result, 'validationEvaluatedSourceHead', { value: sourceHead });
  one(r.result, 'validationResultOfEvaluation', { termType: 'uri', value: r.evaluation });
  one(r.evaluation, 'validationEvaluationOfExecution', { termType: 'uri', value: r.execution });
  one(r.evaluation, 'validationEvaluationReceiptDigest', { value: evaluationReceipt });
  one(r.execution, 'producesValidationResult', { termType: 'uri', value: r.result });
  one(r.execution, 'validationExecutedByProducer', { termType: 'uri', value: producer });
  one(r.execution, 'validationUsesEvidenceAdmissionPath', { termType: 'uri', value: admission });
  one(r.execution, 'validationExecutionReceiptDigest', { value: executionReceipt });
  one(r.proofResult, 'aggregateAuthorityDigest', { value: d1 });
  one(r.proofResult, 'aggregateSourceHead', { value: sourceHead });
  one(r.proofResult, 'dependencySetDigest', { value: dependency });
  one(r.proofResult, 'hasProofResultState', {
    termType: 'uri', value: 'urn:usf:proofresultstate:successful',
  });
  one(r.proofResult, 'resultState', { termType: 'uri', value: 'urn:usf:resultstate:passed' });
  one(r.proofResult, 'hasFreshness', { termType: 'uri', value: 'urn:usf:freshness:fresh' });
  one(r.proofResult, 'evaluatedAt'); // exact resource, never selected by recency
  const evidenceIris = manyObjectsV2(statements, r.result,
    `${USF_ONTOLOGY}usesAdmittedValidationEvidence`, { exactCount: 3, termType: 'uri' });
  const evidenceDigests = evidenceIris.map((evidenceIri) => {
    requireTypesV2(statements, evidenceIri, evidenceIri === COMPILER_VALIDATION_EVIDENCE_IRI
      ? [`${USF_ONTOLOGY}EvidenceResult`, `${USF_ONTOLOGY}ValidationEvidence`]
      : [`${USF_ONTOLOGY}EvidenceResult`]);
    soleObjectV2(statements, evidenceIri, `${USF_ONTOLOGY}hasAdmissionState`, {
      termType: 'uri', value: 'urn:usf:evidenceadmissionstate:admitted',
    });
    soleObjectV2(statements, evidenceIri, `${USF_ONTOLOGY}hasFreshnessState`, {
      termType: 'uri', value: 'urn:usf:evidencefreshnessstate:fresh',
    });
    soleObjectV2(statements, evidenceIri, `${USF_ONTOLOGY}hasIntegrityState`, {
      termType: 'uri', value: 'urn:usf:evidenceintegritystate:valid',
    });
    soleObjectV2(statements, evidenceIri, `${USF_ONTOLOGY}withinValidityScope`, { value: 'true' });
    return exactSha256ValueV2(
      soleObjectV2(statements, evidenceIri, `${USF_ONTOLOGY}contentDigest`),
      `validation evidence ${evidenceIri}`,
    );
  });
  const validationInputIdentities = [
    dependency, evaluationReceipt, executionReceipt, sourceScope, ...evidenceDigests,
  ].sort();
  if (new Set(validationInputIdentities).size !== validationInputIdentities.length) {
    throw new Error('V2 validation D0 input identities are not unique');
  }
  return Object.freeze({
    consumer_kind: 'validation_currentness_binding',
    consumer_iri: GRAPH_OWNED_CONSUMER_IRIS_V2.validation,
    predecessor_record_iri: bindingResult === r.result ? r.binding : null,
    semantic_scope: Object.freeze({
      authority_binding_rule: one(r.binding, 'validationUsesAuthorityBindingRule', { termType: 'uri' }),
      evidence_admission_path: admission,
      envelope_verification: one(r.binding, 'validationBindingEnvelopeVerification', {
        termType: 'uri',
      }),
      external_verifier: one(r.binding, 'validationBindingExternalVerifier', {
        termType: 'uri',
      }),
      producer,
      repository: one(r.binding, 'validationBindingRepository'),
      requires_postpublication_reevaluation: true,
      source_paths: manyObjectsV2(statements, r.binding,
        `${USF_ONTOLOGY}validationBindingSourcePath`, { termType: 'literal' }),
      source_scope_digest: sourceScope,
      validation_obligation: one(r.result, 'resultForValidationObligation', { termType: 'uri' }),
      verification_cas_descriptor: one(r.binding,
        'validationBindingVerificationCASDescriptor', { termType: 'uri' }),
    }),
    materialisation: statements,
    validation_input_authority_digest: d0,
    validation_input_identity_digests: Object.freeze(validationInputIdentities),
    source_tree: sourceTree,
  });
}

export async function readGraphOwnedProductionConsumersV2(client, { authorityDigest } = {}) {
  assertExpectedDigest(authorityDigest, 'V2 Graph-owned consumer authority');
  if (!client || typeof client.select !== 'function') {
    throw new Error('V2 Graph-owned consumer observation requires read-only Stardog');
  }
  const activeFence = await client.select(`SELECT ?fence WHERE {
    GRAPH ?graph { ?fence a <${USF_ONTOLOGY}V2NativeHandoverFence> }
  } ORDER BY ?fence`);
  if (!Array.isArray(activeFence) || activeFence.length > 0) {
    throw new Error(activeFence?.length
      ? 'V2_GRAPH_PREDECESSOR_READER_RETIRED'
      : 'V2_GRAPH_HANDOVER_FENCE_OBSERVATION_INVALID');
  }
  const ownerIris = Object.values(GRAPH_OWNER_RESOURCES_V2);
  const validationBaseIris = Object.values(GRAPH_VALIDATION_RESOURCES_V2);
  const ownerStatements = await readExactResourceStatementsV2(client, ownerIris);
  const validationBase = await readExactResourceStatementsV2(client, validationBaseIris);
  const evidenceIris = manyObjectsV2(validationBase, GRAPH_VALIDATION_RESOURCES_V2.result,
    `${USF_ONTOLOGY}usesAdmittedValidationEvidence`, { exactCount: 3, termType: 'uri' });
  const evidenceStatements = await readExactResourceStatementsV2(client, evidenceIris);
  const validationStatements = Object.freeze([...validationBase, ...evidenceStatements]
    .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))));
  return Object.freeze([
    readOwnerConsumerFactsV2(ownerStatements),
    readValidationConsumerFactsV2(validationStatements),
  ]);
}

export async function resolveGraphNativeOwnershipV2({
  client,
  readAuthorityWitness,
  nativeGraphStore = createGraphNativeSuccessorStoreV2(),
  readRuntimeSourceIdentity = readInstalledGraphSourceIdentityV2,
  trustedTime,
  expectedPlan = null,
  expectedTerminalReceipt = null,
} = {}) {
  if (!client || typeof client.select !== 'function'
      || typeof readAuthorityWitness !== 'function'
      || typeof nativeGraphStore?.read !== 'function'
      || typeof nativeGraphStore?.loadGeneration !== 'function'
      || typeof readRuntimeSourceIdentity !== 'function'
      || typeof trustedTime !== 'function') {
    throw new Error('V2 Graph native ownership resolver configuration is incomplete');
  }
  const before = await readAuthorityWitness(client);
  const fences = await client.select(`SELECT ?fence ?generation ?state ?v1state WHERE {
    GRAPH ?graph {
      ?fence a <${USF_ONTOLOGY}V2NativeHandoverFence> .
      OPTIONAL { ?fence <${USF_ONTOLOGY}handoverGenerationDigest> ?generation }
      OPTIONAL { ?fence <${USF_ONTOLOGY}handoverOwnershipState> ?state }
      OPTIONAL { ?fence <${USF_ONTOLOGY}handoverCurrentV1PublicationState> ?v1state }
    }
  } ORDER BY ?fence ?generation ?state ?v1state`);
  if (!Array.isArray(fences) || fences.length !== 1
      || fences[0].fence?.value !== 'urn:usf:v2nativehandoverfence:current'
      || !SHA256.test(fences[0].generation?.value || '')
      || fences[0].state?.value !== 'urn:usf:v2ownershipstate:handoverpending'
      || fences[0].v1state?.value !== 'urn:usf:v1publicationstate:fenced') {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_FENCE_MISMATCH');
  }
  const generationDigest = fences[0].generation.value;
  const rows = await client.select(`SELECT ?fence ?generation ?state ?v1state ?binding ?consumer ?owner WHERE {
    GRAPH ?graph {
      ?fence a <${USF_ONTOLOGY}V2NativeHandoverFence>;
        <${USF_ONTOLOGY}handoverGenerationDigest> ?generation;
        <${USF_ONTOLOGY}handoverOwnershipState> ?state;
        <${USF_ONTOLOGY}handoverCurrentV1PublicationState> ?v1state;
        <${USF_ONTOLOGY}handoverGraphNativeSuccessorBinding> ?binding .
      ?binding a <${USF_ONTOLOGY}V2NativeGraphSuccessorBinding>;
        <${USF_ONTOLOGY}handoverGraphNativeConsumer> ?consumer;
        <${USF_ONTOLOGY}handoverStorageOwner> ?owner;
        <${USF_ONTOLOGY}handoverGenerationDigest> ?generation .
    }
  } ORDER BY ?consumer`);
  const expectedConsumers = [
    'urn:usf:derivedconsumer:v2:owner-envelope-successor',
    'urn:usf:derivedconsumer:v2:validation-currentness-binding',
  ];
  if (!Array.isArray(rows) || rows.length !== 2
      || rows.some((row) => row.fence?.value !== 'urn:usf:v2nativehandoverfence:current'
        || row.generation?.value !== generationDigest
        || row.state?.value !== 'urn:usf:v2ownershipstate:handoverpending'
        || row.v1state?.value !== 'urn:usf:v1publicationstate:fenced'
        || row.owner?.value !== 'urn:usf:v2nativeowner:graph')
      || canonicalJson(rows.map((row) => row.consumer?.value))
        !== canonicalJson(expectedConsumers)) {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_FENCE_MISMATCH');
  }
  const durable = nativeGraphStore.loadGeneration(generationDigest);
  const plan = durable.plan;
  const terminalReceipt = durable.terminal_receipt;
  if (terminalReceipt === null) throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_RECOVERY_REQUIRED');
  if (expectedPlan !== null && canonicalJson(expectedPlan) !== canonicalJson(plan)) {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_EXPECTED_PLAN_MISMATCH');
  }
  if (expectedTerminalReceipt !== null
      && canonicalJson(expectedTerminalReceipt) !== canonicalJson(terminalReceipt)) {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_EXPECTED_RECEIPT_MISMATCH');
  }
  if (before.digest !== plan.predicted_d2_authority_digest) {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_D2_AUTHORITY_MISMATCH');
  }
  const receiptDigest = semanticProofV2.graphPublicationReceiptDigestV2(terminalReceipt);
  const closure = semanticProofV2.assertFactoryClosureReceiptV2(
    durable.factory_closure_receipt, plan,
  );
  const recoveryBinding = Object.freeze({
    explicitGrantDigests: explicitGrantDigestsFromPlanV2(plan),
    plan,
    planDigest: semanticProofV2.prospectivePublicationPlanDigestV2(plan),
  });
  const consumption = assertDurableGrantConsumptionV2(
    durable.grant_consumption_receipt, recoveryBinding, closure,
  );
  const prepareDigest = semanticProofV2.factoryPrepareReceiptDigestV2(
    durable.factory_prepare_receipt,
    plan,
    { factoryCommit: terminalReceipt.factory_commit, factoryTree: terminalReceipt.factory_tree },
  );
  const reservationReceiptDigest = semanticProofV2.graphReservationReceiptDigestV2(
    durable.graph_reservation_receipt,
    plan,
    { graphCommit: terminalReceipt.graph_commit, graphTree: terminalReceipt.graph_tree },
  );
  const runtimeSource = await readRuntimeSourceIdentity();
  if (!runtimeSource || !/^[0-9a-f]{40}$/.test(runtimeSource.commit || '')
      || !/^[0-9a-f]{40}$/.test(runtimeSource.tree || '')
      || runtimeSource.clean !== true) {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_RUNTIME_SOURCE_UNATTESTED');
  }
  if (terminalReceipt.handover_generation_digest !== generationDigest
      || terminalReceipt.prospective_publication_plan_digest
        !== semanticProofV2.prospectivePublicationPlanDigestV2(plan)
      || terminalReceipt.d2_authority_digest !== plan.predicted_d2_authority_digest
      || terminalReceipt.graph_commit !== runtimeSource.commit
      || terminalReceipt.graph_tree !== runtimeSource.tree
      || plan.graph_protected_tree !== runtimeSource.tree
      || terminalReceipt.factory_closure_receipt_digest
        !== durable.factory_closure_receipt_digest
      || terminalReceipt.grant_consumption_receipt_digest !== consumption.digest
      || durable.grant_consumption_receipt_digest !== consumption.digest
      || terminalReceipt.factory_prepare_receipt_digest !== prepareDigest
      || durable.factory_prepare_receipt_digest !== prepareDigest
      || durable.factory_prepare_receipt.graph_reservation_receipt_digest
        !== reservationReceiptDigest
      || durable.graph_reservation_receipt_digest !== reservationReceiptDigest
      || terminalReceipt.ownership_state !== 'V2_TERMINAL_OWNER'
      || terminalReceipt.current_v1_publication_state !== 'RETIRED') {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_TERMINAL_RECEIPT_MISMATCH');
  }
  const currentTime = (await trustedInstant(trustedTime)).canonical;
  const nativeGraph = nativeGraphStore.read(plan, { trustedNow: currentTime });
  if (nativeGraph.observation_digest !== terminalReceipt.graph_owned_observation_digest) {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_READBACK_MISMATCH');
  }
  const after = await readAuthorityWitness(client);
  if (canonicalJson(after) !== canonicalJson(before)) {
    throw new Error('V2_GRAPH_NATIVE_OWNERSHIP_AUTHORITY_DRIFT');
  }
  const reservationDigest = semanticProofV2.canonicalDigestV2({
    schema: 'usf-v2-native-handover-reservation-v1',
    d0_authority_digest: plan.d0_authority_digest,
    handover_generation_digest: generationDigest,
    prospective_publication_plan_digest:
      semanticProofV2.prospectivePublicationPlanDigestV2(plan),
  });
  const core = Object.freeze({
    schema: 'usf-graph-native-ownership-observation-v2',
    authority_digest: before.digest,
    authority_observation_digest: semanticProofV2.canonicalDigestV2(before),
    current_v1_publication_state: 'RETIRED',
    d2_fence_state: 'V2_HANDOVER_PENDING',
    execution_state: nativeGraph.validation_currentness.state === 'CURRENT'
      ? 'EXECUTION_PERMITTED' : 'BLOCKED_VALIDATION_CURRENTNESS',
    factory_closure_receipt_digest: durable.factory_closure_receipt_digest,
    factory_closure_receipt_cas_uri:
      `cas://sha256/${durable.factory_closure_receipt_digest.slice(7)}`,
    grant_consumption_receipt_digest: durable.grant_consumption_receipt_digest,
    grant_consumption_receipt_cas_uri:
      `cas://sha256/${durable.grant_consumption_receipt_digest.slice(7)}`,
    graph_commit: runtimeSource.commit,
    graph_tree: runtimeSource.tree,
    graph_native_successors: nativeGraph.native_successors,
    graph_native_successor_readbacks: nativeGraph.readbacks,
    graph_owned_observation_digest: nativeGraph.observation_digest,
    graph_reservation_digest: reservationDigest,
    handover_generation_digest: generationDigest,
    ownership_state: 'V2_TERMINAL_OWNER',
    terminal_receipt_digest: receiptDigest,
    terminal_receipt_cas_uri: `cas://sha256/${receiptDigest.slice(7)}`,
    validation_currentness: nativeGraph.validation_currentness,
  });
  const {
    execution_state: _executionState,
    validation_currentness: _validationCurrentness,
    ...stableOwnershipCore
  } = core;
  const ownershipIdentityDigest = semanticProofV2.canonicalDigestV2(stableOwnershipCore);
  const currentnessObservationDigest = semanticProofV2.canonicalDigestV2(
    nativeGraph.validation_currentness,
  );
  const observationCore = Object.freeze({
    ...core,
    currentness_observation_digest: currentnessObservationDigest,
    ownership_identity_digest: ownershipIdentityDigest,
  });
  const observation = Object.freeze({
    ...observationCore,
    observation_identity_digest: semanticProofV2.canonicalDigestV2(observationCore),
  });
  semanticProofV2.assertGraphNativeOwnershipObservationV2(observation, plan);
  return observation;
}

export async function renewGraphNativeValidationCurrentnessV2({
  client,
  envelope,
  expectedAuthorityDigest,
  nativeGraphStore,
  publicationLane,
  readAuthorityWitness,
  readRuntimeSourceIdentity = readInstalledGraphSourceIdentityV2,
  trustedTime,
  validateCurrentnessCandidate,
} = {}) {
  if (!envelope || typeof envelope !== 'object'
      || !publicationLane || typeof publicationLane.acquire !== 'function'
      || !nativeGraphStore || typeof nativeGraphStore.installValidationCurrentnessDescendant
        !== 'function'
      || typeof nativeGraphStore.persistCurrentnessValidationEvidence !== 'function'
      || typeof validateCurrentnessCandidate !== 'function') {
    throw new Error('V2 Graph validation-currentness renewal configuration is incomplete');
  }
  const resolverInputs = {
    client,
    expectedAuthorityDigest,
    nativeGraphStore,
    readAuthorityWitness,
    readRuntimeSourceIdentity,
    trustedTime,
  };
  const before = await resolveGraphNativeOwnershipV2(resolverInputs);
  if (before.ownership_state !== 'V2_TERMINAL_OWNER') {
    throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_RENEWAL_REQUIRES_TERMINAL_OWNER');
  }
  const release = publicationLane.acquire();
  try {
    const locked = await resolveGraphNativeOwnershipV2(resolverInputs);
    if (locked.ownership_identity_digest !== before.ownership_identity_digest) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_OWNERSHIP_DRIFT');
    }
    const authorityBeforeValidation = await readAuthorityWitness();
    const validation = await validateCurrentnessCandidate({
      authorityDigest: locked.authority_digest,
      expectedCandidateDigest: envelope.payload.validation_candidate_digest,
    });
    const accepted = assertAcceptedCompilerResult(validation, {
      phase: 'prepare',
      expectedCandidateDigest: envelope.payload.validation_candidate_digest,
    });
    if (validation.evaluatedAuthorityDigest !== locked.authority_digest
        || validation.validationEvidence?.record?.authorityDigest !== locked.authority_digest
        || validation.validationEvidence?.record?.candidateDigest !== accepted.candidateDigest
        || validation.validationEvidence?.record?.providerValidationReceipt?.conforms !== true
        || validation.validationEvidence.digest
          !== sha256(validation.validationEvidence.bytes)) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_CANONICAL_VALIDATION_INVALID');
    }
    const authorityAfterValidation = await readAuthorityWitness();
    if (!sameWitness(authorityBeforeValidation, authorityAfterValidation)
        || authorityAfterValidation.digest !== locked.authority_digest) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_VALIDATION_MUTATED_AUTHORITY');
    }
    const admittedValidation = nativeGraphStore.persistCurrentnessValidationEvidence(
      validation.validationEvidence.bytes,
    );
    if (admittedValidation.digest !== validation.validationEvidence.digest) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_VALIDATION_CAS_MISMATCH');
    }
    const generation = nativeGraphStore.loadGeneration(locked.handover_generation_digest);
    const trustedNow = (await trustedInstant(trustedTime)).canonical;
    const installed = nativeGraphStore.installValidationCurrentnessDescendant(
      generation.plan, envelope, {
        expectedCompilerValidationReportDigest: admittedValidation.digest,
        expectedProviderValidationReceiptDigest:
          semanticProofV2.canonicalDigestV2(
            validation.validationEvidence.record.providerValidationReceipt,
          ),
        expectedValidationCandidateDigest: accepted.candidateDigest,
        trustedNow,
      },
    );
    if (installed.state !== 'CURRENT') {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_RENEWAL_NOT_CURRENT');
    }
    const after = await resolveGraphNativeOwnershipV2(resolverInputs);
    if (after.ownership_identity_digest !== before.ownership_identity_digest
        || after.validation_currentness.digest !== installed.digest
        || after.execution_state !== 'EXECUTION_PERMITTED') {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_RENEWAL_READBACK_MISMATCH');
    }
    return after;
  } finally {
    release();
  }
}

export async function prepareGraphNativeValidationCurrentnessV2({
  client,
  expectedAuthorityDigest,
  nativeGraphStore,
  publicationLane,
  readAuthorityWitness,
  readRuntimeSourceIdentity = readInstalledGraphSourceIdentityV2,
  renewalNonce,
  trustedTime,
  validUntil,
  validateCurrentnessCandidate,
} = {}) {
  if (!publicationLane || typeof publicationLane.acquire !== 'function'
      || !nativeGraphStore || typeof nativeGraphStore.persistCurrentnessArtifact !== 'function'
      || typeof nativeGraphStore.persistCurrentnessValidationEvidence !== 'function'
      || typeof nativeGraphStore.readConsumer !== 'function'
      || typeof nativeGraphStore.readValidationCurrentness !== 'function'
      || typeof validateCurrentnessCandidate !== 'function'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        renewalNonce || '',
      )) {
    throw new Error('V2 Graph validation-currentness preparation is incomplete');
  }
  const validUntilText = canonicalUtcSecond(validUntil, 'validation currentness validity end');
  const resolverInputs = {
    client,
    expectedAuthorityDigest,
    nativeGraphStore,
    readAuthorityWitness,
    readRuntimeSourceIdentity,
    trustedTime,
  };
  const release = publicationLane.acquire();
  try {
    const ownership = await resolveGraphNativeOwnershipV2(resolverInputs);
    if (ownership.ownership_state !== 'V2_TERMINAL_OWNER') {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_PREPARE_REQUIRES_TERMINAL_OWNER');
    }
    const generation = nativeGraphStore.loadGeneration(ownership.handover_generation_digest);
    const plan = generation.plan;
    const validationRoot = nativeGraphStore.readConsumer(
      plan, 'validation_currentness_binding', {
        trustedNow: ownership.validation_currentness.trusted_now,
      },
    );
    const ownerRoot = nativeGraphStore.readConsumer(plan, 'owner_envelope_successor');
    const renewalRule = validationRoot.native_state.renewal_rule;
    const current = nativeGraphStore.readValidationCurrentness(plan, {
      trustedNow: ownership.validation_currentness.trusted_now,
    });
    const authorityBefore = await readAuthorityWitness();
    const validation = await validateCurrentnessCandidate({
      authorityDigest: ownership.authority_digest,
      handoverGenerationDigest: ownership.handover_generation_digest,
    });
    const accepted = assertAcceptedCompilerResult(validation, {
      phase: 'prepare',
      expectedCandidateDigest: validation?.validationEvidence?.record?.candidateDigest,
    });
    if (validation.evaluatedAuthorityDigest !== ownership.authority_digest
        || validation.validationEvidence?.record?.authorityDigest !== ownership.authority_digest
        || validation.validationEvidence?.record?.candidateDigest !== accepted.candidateDigest
        || validation.validationEvidence?.record?.providerValidationReceipt?.conforms !== true
        || validation.validationEvidence.digest !== sha256(validation.validationEvidence.bytes)) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_CANONICAL_VALIDATION_INVALID');
    }
    const authorityAfter = await readAuthorityWitness();
    if (!sameWitness(authorityBefore, authorityAfter)
        || authorityAfter.digest !== ownership.authority_digest) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_VALIDATION_MUTATED_AUTHORITY');
    }
    const observedAt = (await trustedInstant(trustedTime)).canonical;
    const genesis = validationRoot.native_state.handover_currentness;
    const maximumValidity = Date.parse(genesis.valid_until) - Date.parse(genesis.valid_from);
    if (Date.parse(validUntilText) <= Date.parse(observedAt)
        || Date.parse(validUntilText) - Date.parse(observedAt) > maximumValidity) {
      throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_VALIDITY_WINDOW_INVALID');
    }
    const compilerReport = nativeGraphStore.persistCurrentnessValidationEvidence(
      validation.validationEvidence.bytes,
    );
    const providerReceiptDigest = semanticProofV2.canonicalDigestV2(
      validation.validationEvidence.record.providerValidationReceipt,
    );
    const evidenceClaim = Object.freeze({
      admission_state: 'ADMITTED',
      authority_digest: ownership.authority_digest,
      compiler_candidate_digest: accepted.candidateDigest,
      compiler_validation_report_digest: compilerReport.digest,
      evidence_admission_path_iri: renewalRule.evidence_admission_path_iri,
      freshness_state: 'CURRENT',
      handover_generation_digest: ownership.handover_generation_digest,
      observed_at: observedAt,
      provider_validation_receipt_digest: providerReceiptDigest,
      result_state: 'PASSING',
      schema: 'usf-v2-native-validation-currentness-evidence-v1',
      semantic_scope_digest: validationRoot.successor.semantic_scope_digest,
      valid_until: validUntilText,
      validation_producer_identity_digest:
        renewalRule.evidence_admission_producer_identity_digest,
      validation_producer_iri: renewalRule.validation_producer_iri,
      validation_root_payload_digest: validationRoot.successor.payload_digest,
    });
    const evidenceSubjectDigest = semanticProofV2.canonicalDigestV2({
      schema: 'usf-v2-native-validation-currentness-evidence-claim-v1',
      evidence: evidenceClaim,
    });
    const evidenceAdmission = Object.freeze({
      admission_state: 'ADMITTED',
      admitted_at: observedAt,
      authority_digest: ownership.authority_digest,
      evidence_admission_path_iri: renewalRule.evidence_admission_path_iri,
      evidence_claim_digest: evidenceSubjectDigest,
      handover_generation_digest: ownership.handover_generation_digest,
      schema: 'usf-v2-native-validation-currentness-evidence-admission-v1',
      validation_producer_iri: renewalRule.validation_producer_iri,
    });
    const evidenceAdmissionCas = nativeGraphStore.persistCurrentnessArtifact(
      evidenceAdmission, evidenceAdmission.schema,
    );
    const evidence = Object.freeze({
      ...evidenceClaim,
      admission_receipt_digest: evidenceAdmissionCas.digest,
      evidence_subject_digest: evidenceSubjectDigest,
    });
    const evidenceCas = nativeGraphStore.persistCurrentnessArtifact(evidence, evidence.schema);
    const evidenceIdentityDigests = Object.freeze([evidenceCas.digest]);
    const evidenceSetDigest = semanticProofV2.canonicalDigestV2({
      schema: 'usf-v2-native-validation-currentness-evidence-set-v1',
      evidence_identity_digests: evidenceIdentityDigests,
    });
    const proofCore = Object.freeze({
      authority_digest: ownership.authority_digest,
      evidence_set_digest: evidenceSetDigest,
      external_verifier_iri: renewalRule.external_verifier_iri,
      handover_generation_digest: ownership.handover_generation_digest,
      predecessor_descendant_digest: current.digest,
      proof_algorithm_digest: renewalRule.proof_algorithm_digest,
      proof_evaluated_at: observedAt,
      semantic_scope_digest: validationRoot.successor.semantic_scope_digest,
      validation_candidate_digest: accepted.candidateDigest,
      validation_root_payload_digest: validationRoot.successor.payload_digest,
    });
    const evaluation = Object.freeze({
      schema: 'usf-v2-native-validation-currentness-evaluation-v1',
      authority_digest: proofCore.authority_digest,
      evidence_set_digest: proofCore.evidence_set_digest,
      external_verifier_iri: proofCore.external_verifier_iri,
      handover_generation_digest: proofCore.handover_generation_digest,
      predecessor_descendant_digest: proofCore.predecessor_descendant_digest,
      proof_algorithm_digest: proofCore.proof_algorithm_digest,
      semantic_scope_digest: proofCore.semantic_scope_digest,
      validation_candidate_digest: proofCore.validation_candidate_digest,
      validation_root_payload_digest: proofCore.validation_root_payload_digest,
    });
    const proof = Object.freeze({
      ...proofCore,
      evaluation_digest: semanticProofV2.canonicalDigestV2(evaluation),
      result_state: 'SUCCESSFUL',
      schema: 'usf-v2-native-validation-currentness-proof-v1',
    });
    const proofCas = nativeGraphStore.persistCurrentnessArtifact(proof, proof.schema);
    const claimPayload = Object.freeze({
      authority_digest: ownership.authority_digest,
      evidence_identity_digests: evidenceIdentityDigests,
      evidence_set_digest: evidenceSetDigest,
      handover_generation_digest: ownership.handover_generation_digest,
      predecessor_descendant_digest: current.digest,
      proof_evaluated_at: observedAt,
      proof_result_digest: proofCas.digest,
      proof_state: 'SUCCESSFUL',
      renewal_nonce: renewalNonce,
      schema: 'usf-v2-native-validation-currentness-descendant-v1',
      semantic_scope_digest: validationRoot.successor.semantic_scope_digest,
      transition: 'MATERIALISATION_CURRENTNESS',
      trusted_time_authority_digest: ownership.authority_digest,
      valid_from: observedAt,
      valid_until: validUntilText,
      validation_candidate_digest: accepted.candidateDigest,
      validation_root_payload_digest: validationRoot.successor.payload_digest,
    });
    const currentnessClaimDigest = semanticProofV2.canonicalDigestV2({
      schema: 'usf-v2-native-validation-currentness-claim-v1', payload: claimPayload,
    });
    const admission = Object.freeze({
      admission_state: 'ADMITTED',
      admitted_at: observedAt,
      authority_digest: ownership.authority_digest,
      currentness_claim_digest: currentnessClaimDigest,
      evidence_set_digest: evidenceSetDigest,
      handover_generation_digest: ownership.handover_generation_digest,
      owner_identity_digest: ownerRoot.native_state.owner_identity_digest,
      proof_result_digest: proofCas.digest,
      schema: 'usf-v2-native-validation-currentness-admission-v1',
    });
    const admissionCas = nativeGraphStore.persistCurrentnessArtifact(admission, admission.schema);
    const payload = Object.freeze({
      ...claimPayload,
      admission_receipt_digest: admissionCas.digest,
    });
    const signedSubject = Object.freeze({
      admission_receipt: admission,
      payload,
      schema: 'usf-v2-native-validation-currentness-signed-subject-v1',
    });
    const signedSubjectBytes = Buffer.from(semanticProofV2.canonicalJsonV2(signedSubject), 'utf8');
    return Object.freeze({
      admission_receipt: admission,
      admission_receipt_digest: admissionCas.digest,
      compiler_validation_report_digest: compilerReport.digest,
      evidence_identity_digests: evidenceIdentityDigests,
      evidence_set_digest: evidenceSetDigest,
      owner_signing_fingerprint: ownerRoot.native_state.owner_signing_fingerprint,
      payload,
      proof_result_digest: proofCas.digest,
      schema: 'usf-v2-native-validation-currentness-signing-request-v1',
      signed_subject: signedSubject,
      signed_subject_digest: sha256(signedSubjectBytes),
    });
  } finally {
    release();
  }
}

export function validationCurrentnessEnvelopeFromSigningRequestV2(request, signature) {
  const fields = [
    'admission_receipt', 'admission_receipt_digest',
    'compiler_validation_report_digest', 'evidence_identity_digests',
    'evidence_set_digest', 'owner_signing_fingerprint', 'payload',
    'proof_result_digest', 'schema', 'signed_subject', 'signed_subject_digest',
  ].sort();
  if (!request || typeof request !== 'object' || Array.isArray(request)
      || canonicalJson(Object.keys(request).sort()) !== canonicalJson(fields)
      || request.schema !== 'usf-v2-native-validation-currentness-signing-request-v1'
      || !/^[0-9A-F]{40}$/.test(request.owner_signing_fingerprint || '')
      || typeof signature !== 'string' || !signature.includes('BEGIN PGP SIGNATURE')) {
    throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_SIGNING_REQUEST_INVALID');
  }
  const signedSubject = Object.freeze({
    admission_receipt: request.admission_receipt,
    payload: request.payload,
    schema: 'usf-v2-native-validation-currentness-signed-subject-v1',
  });
  const signedBytes = Buffer.from(semanticProofV2.canonicalJsonV2(signedSubject), 'utf8');
  if (canonicalJson(request.signed_subject) !== canonicalJson(signedSubject)
      || request.signed_subject_digest !== sha256(signedBytes)
      || request.admission_receipt_digest
        !== semanticProofV2.canonicalDigestV2(request.admission_receipt)
      || request.payload.admission_receipt_digest !== request.admission_receipt_digest
      || request.evidence_set_digest !== request.payload.evidence_set_digest
      || request.proof_result_digest !== request.payload.proof_result_digest
      || canonicalJson(request.evidence_identity_digests)
        !== canonicalJson(request.payload.evidence_identity_digests)) {
    throw new Error('V2_GRAPH_VALIDATION_CURRENTNESS_SIGNING_REQUEST_MISMATCH');
  }
  return Object.freeze({
    admission_receipt: Object.freeze(request.admission_receipt),
    payload: Object.freeze(request.payload),
    schema: 'usf-v2-native-validation-currentness-descendant-envelope-v1',
    signature,
  });
}

export async function observeGraphRuntimeOwnershipV2(options = {}) {
  const {
    client, expectedAuthorityDigest, readAuthorityWitness, publicationLane = null,
    nativeGraphStore = createGraphNativeSuccessorStoreV2(),
  } = options;
  if (!client || typeof client.select !== 'function'
      || typeof readAuthorityWitness !== 'function'
      || !SHA256.test(expectedAuthorityDigest || '')) {
    throw new Error('Graph runtime ownership observation requires read-only authority inputs');
  }
  const before = await readAuthorityWitness(client);
  if (before.digest !== expectedAuthorityDigest) {
    throw new Error('V2_GRAPH_RUNTIME_OWNERSHIP_EXPECTED_AUTHORITY_MISMATCH');
  }
  const fences = await client.select(`SELECT ?fence ?generation WHERE {
    GRAPH ?graph {
      ?fence a <${USF_ONTOLOGY}V2NativeHandoverFence> .
      OPTIONAL { ?fence <${USF_ONTOLOGY}handoverGenerationDigest> ?generation }
    }
  } ORDER BY ?fence ?generation`);
  if (!Array.isArray(fences) || fences.length > 1) {
    throw new Error('V2_GRAPH_RUNTIME_OWNERSHIP_AMBIGUOUS');
  }
  if (fences.length === 0) {
    // A missing fence is NOT evidence that V1 owns the runtime. Terminal V2 is
    // derived from durable admitted state, so if any durable generation already
    // holds a terminal receipt, the fence's absence means the fence was deleted
    // or lost -- never that V1 may execute again. Fail closed; rollback to V1 is
    // not a reachable state.
    // The floor is REQUIRED, not duck-typed. A store that cannot report it
    // cannot establish that V1 is the owner either, so a missing reader refuses
    // instead of silently degrading to V1 -- which would reopen the exact
    // fence-deletion hole this barrier exists to close.
    if (typeof nativeGraphStore?.readTerminalOwnershipFloor !== 'function') {
      throw new Error('V2_GRAPH_TERMINAL_OWNERSHIP_FLOOR_READER_REQUIRED');
    }
    if (nativeGraphStore.readTerminalOwnershipFloor().terminal) {
      throw new Error('V2_GRAPH_TERMINAL_OWNERSHIP_FENCE_MISSING');
    }
    const reservation = publicationLane === null ? null : publicationLane.readReservation();
    if (reservation !== null) {
      if (reservation.d0_authority_digest !== before.digest) {
        throw new Error('V2_GRAPH_RUNTIME_OWNERSHIP_RESERVATION_AUTHORITY_MISMATCH');
      }
      const after = await readAuthorityWitness(client);
      if (canonicalJson(after) !== canonicalJson(before)) {
        throw new Error('V2_GRAPH_RUNTIME_OWNERSHIP_AUTHORITY_DRIFT');
      }
      const core = Object.freeze({
        schema: 'usf-graph-runtime-ownership-observation-v2',
        authority_digest: before.digest,
        authority_observation_digest: semanticProofV2.canonicalDigestV2(before),
        current_v1_publication_state: 'FENCED',
        graph_reservation_digest: semanticProofV2.canonicalDigestV2(reservation),
        handover_generation_digest: reservation.handover_generation_digest,
        ownership_state: 'V2_HANDOVER_PENDING',
        recovery_required: true,
      });
      return Object.freeze({
        ...core,
        observation_identity_digest: semanticProofV2.canonicalDigestV2(core),
      });
    }
    const after = await readAuthorityWitness(client);
    if (canonicalJson(after) !== canonicalJson(before)) {
      throw new Error('V2_GRAPH_RUNTIME_OWNERSHIP_AUTHORITY_DRIFT');
    }
    const core = Object.freeze({
      schema: 'usf-graph-runtime-ownership-observation-v2',
      authority_digest: before.digest,
      authority_observation_digest: semanticProofV2.canonicalDigestV2(before),
      current_v1_publication_state: 'ACTIVE',
      handover_generation_digest: null,
      ownership_state: 'V1_OWNER',
      recovery_required: false,
    });
    return Object.freeze({
      ...core,
      observation_identity_digest: semanticProofV2.canonicalDigestV2(core),
    });
  }
  if (fences[0].fence?.value !== 'urn:usf:v2nativehandoverfence:current'
      || !SHA256.test(fences[0].generation?.value || '')) {
    throw new Error('V2_GRAPH_RUNTIME_OWNERSHIP_AMBIGUOUS');
  }
  try {
    return await resolveGraphNativeOwnershipV2(options);
  } catch (error) {
    if (!['V2_GRAPH_NATIVE_OWNERSHIP_RECOVERY_REQUIRED',
      'V2_GRAPH_NATIVE_ROOT_MISSING', 'V2_GRAPH_NATIVE_GENERATION_MISSING',
      'V2_GRAPH_TERMINAL_RECEIPT_MISSING'].includes(error.message)) throw error;
    const after = await readAuthorityWitness(client);
    if (canonicalJson(after) !== canonicalJson(before)) {
      throw new Error('V2_GRAPH_RUNTIME_OWNERSHIP_AUTHORITY_DRIFT');
    }
    const core = Object.freeze({
      schema: 'usf-graph-runtime-ownership-observation-v2',
      authority_digest: before.digest,
      authority_observation_digest: semanticProofV2.canonicalDigestV2(before),
      current_v1_publication_state: 'FENCED',
      handover_generation_digest: fences[0].generation.value,
      ownership_state: 'V2_HANDOVER_PENDING',
      recovery_required: true,
    });
    return Object.freeze({
      ...core,
      observation_identity_digest: semanticProofV2.canonicalDigestV2(core),
    });
  }
}

export async function observeGraphNativeWorkPlanV2(options = {}) {
  const ownership = await observeGraphRuntimeOwnershipV2(options);
  if (ownership.ownership_state !== 'V2_TERMINAL_OWNER') {
    throw new Error('V2_GRAPH_NATIVE_WORK_PLAN_REQUIRES_TERMINAL_OWNER');
  }
  const currentness = ownership.validation_currentness;
  const core = Object.freeze({
    action: currentness.state === 'CURRENT' ? 'PROCEED' : 'BLOCK',
    authority_digest: ownership.authority_digest,
    current_v1_publication_state: ownership.current_v1_publication_state,
    currentness_observation_digest: ownership.currentness_observation_digest,
    handover_generation_digest: ownership.handover_generation_digest,
    ownership_identity_digest: ownership.ownership_identity_digest,
    reason: currentness.state === 'CURRENT'
      ? 'V2_NATIVE_VALIDATION_CURRENT' : 'V2_NATIVE_VALIDATION_CURRENTNESS_STALE',
    schema: 'usf-graph-native-work-plan-v2',
    terminal_receipt_digest: ownership.terminal_receipt_digest,
    trusted_now: currentness.trusted_now,
    valid_until: currentness.valid_until,
    validation_currentness_digest: currentness.digest,
    validation_currentness_root_payload_digest: currentness.validation_root_payload_digest,
    validation_currentness_state: currentness.state,
  });
  const result = Object.freeze({
    ...core,
    observation_identity_digest: semanticProofV2.canonicalDigestV2(core),
  });
  semanticProofV2.graphNativeWorkPlanDigestV2(result);
  return result;
}

export function readInstalledGraphSourceIdentityV2(repositoryRoot = root) {
  const canonicalRoot = realpathSync(repositoryRoot);
  const git = (...args) => execFileSync('/usr/bin/git', ['-C', canonicalRoot, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
  const commit = git('rev-parse', '--verify', 'HEAD^{commit}');
  const tree = git('rev-parse', '--verify', 'HEAD^{tree}');
  const status = git('status', '--porcelain=v1', '--untracked-files=all');
  if (!/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree) || status !== '') {
    throw new Error('V2_GRAPH_RUNTIME_SOURCE_DIRTY_OR_INVALID');
  }
  return Object.freeze({ clean: true, commit, tree });
}

export async function configureLiveGraphProductionShadowV2(expectedAuthorityDigest, env = process.env) {
  assertExpectedDigest(expectedAuthorityDigest, 'V2 Graph production shadow D0 authority');
  try { await fetch('http://127.0.0.1:1/', { signal: AbortSignal.timeout(20) }); } catch { /* initialise dispatcher */ }
  const dispatcherSymbol = Symbol.for('undici.globalDispatcher.1');
  const currentDispatcher = globalThis[dispatcherSymbol];
  if (!currentDispatcher) {
    throw new Error('global fetch dispatcher unavailable; cannot extend validation timeout');
  }
  globalThis[dispatcherSymbol] = new currentDispatcher.constructor({
    headersTimeout: 0,
    bodyTimeout: 0,
  });
  const [
    { default: stardog },
    { createStardogSemanticAuthorityClient },
    { validateSemanticAuthorityConfiguration },
    { readSemanticAuthorityWitness },
    { createSemanticModelCompilationCommand, semanticModelCompilationCommandInternals },
    { createReadOnlyGraphProductionAdapterV2 },
  ] = await Promise.all([
    import('stardog'),
    import('../../provider-bindings/stardog/semantic-authority.mjs'),
    import('../../configuration/semantic-assurance/semantic-authority.mjs'),
    import('./semantic-authority-gateway.mjs'),
    import('./semantic-model-compilation-command.mjs'),
    import('./semantic-proof-v2.mjs'),
  ]);
  const { STARDOG_SERVER, STARDOG_DATABASE, STARDOG_TOKEN } = env;
  if (!STARDOG_SERVER || !STARDOG_DATABASE || !STARDOG_TOKEN) {
    throw new Error('STARDOG_SERVER, STARDOG_DATABASE and STARDOG_TOKEN are required');
  }
  const client = createStardogSemanticAuthorityClient({
    sdk: stardog,
    configuration: validateSemanticAuthorityConfiguration({
      accessMode: 'live',
      expectedAuthorityDigest,
      endpoint: STARDOG_SERVER,
      database: STARDOG_DATABASE,
      authentication: { mode: 'token', tokenReference: 'secret://semantic-authority/token' },
    }),
    resolveSecret: (reference) => {
      if (reference !== 'secret://semantic-authority/token') {
        throw new Error('unexpected secret reference');
      }
      return STARDOG_TOKEN;
    },
  });
  const shadowClient = createReadOnlyStardogShadowClientV2(client);
  const command = createSemanticModelCompilationCommand({
    client: shadowClient,
    readAuthorityWitness: readSemanticAuthorityWitness,
    repositoryRoot: root,
    publicationLane: semanticModelCompilationCommandInternals.createSemanticPublicationLaneV2(
      env.USF_PROGRAMME_ROOT || '/var/lib/usf-programme',
    ),
    nativeGraphStore: createGraphNativeSuccessorStoreV2({
      nativeRoot: `${env.USF_PROGRAMME_ROOT || '/var/lib/usf-programme'}/v2-native-graph-successors`,
      casStore: createCasEvidenceStore(env.USF_CAS_ROOT || '/var/lib/usf-cas'),
    }),
  });
  const readAuthorityWitness = () => readSemanticAuthorityWitness(shadowClient);
  const trustedTime = async () => {
    const rows = await shadowClient.select('SELECT (NOW() AS ?now) WHERE {}');
    const value = rows?.[0]?.now?.value;
    if (rows?.length !== 1 || typeof value !== 'string') {
      throw new Error('Stardog trusted time was unavailable or ambiguous');
    }
    return value;
  };
  return Object.freeze({
    adapter: createReadOnlyGraphProductionAdapterV2({
      command,
      readAuthorityWitness,
      readGraphOwnedConsumers: ({ authorityDigest }) => readGraphOwnedProductionConsumersV2(
        shadowClient, { authorityDigest },
      ),
    }),
    previewV2PublicationFromFrozenInputs: (frozenInputs) => (
      command.previewV2PublicationFromFrozenInputs({
        frozenInputs,
        expectedD0AuthorityDigest: expectedAuthorityDigest,
      })
    ),
    readAuthorityWitness,
    client: shadowClient,
    trustedTime,
  });
}

export async function configureLiveGraphProductionV2(
  expectedAuthorityDigest,
  adapterConfiguration,
  env = process.env,
) {
  assertExpectedDigest(expectedAuthorityDigest, 'V2 Graph production D0 authority');
  const live = await configureLiveDependencies(expectedAuthorityDigest, env);
  return Object.freeze({
    adapter: createGraphProductionAdapterV2({
      command: live.command,
      readAuthorityWitness: live.readAuthorityWitness,
      readGraphOwnedConsumers: live.readGraphOwnedConsumers,
      trustedTime: live.trustedTime,
      ...adapterConfiguration,
    }),
    previewV2PublicationFromFrozenInputs: (frozenInputs) => (
      live.command.previewV2PublicationFromFrozenInputs({
        frozenInputs,
        expectedD0AuthorityDigest: expectedAuthorityDigest,
      })
    ),
    readAuthorityWitness: live.readAuthorityWitness,
    trustedTime: live.trustedTime,
  });
}

export async function main({
  argv = process.argv.slice(2),
  env = process.env,
  postPublicationReevaluate,
} = {}) {
  const mode = requiredArgument(argv, 'mode');
  if (!['prepare', 'validate', 'commit', 'lifecycle', 'native-v2-ownership',
    'native-v2-currentness-prepare', 'native-v2-currentness-renew',
    'native-v2-publish', 'native-v2-work-plan',
    'native-v2-reservation'].includes(mode)) {
    throw new Error('--mode is not one of the closed semantic publication modes');
  }
  const expectedAuthorityDigest = requiredArgument(argv, 'authority-digest');
  if (mode === 'native-v2-reservation') {
    // Read-only reread of one already-persisted D0 handover reservation
    // receipt.  Factory PREPARE must not accept a reservation receipt merely
    // because a coordinator handed it over; it rereads the exact bytes here,
    // by digest, and this mode additionally proves the receipt is the one the
    // durable publication lane actually reserved against the expected D0.
    const reservationDigest = requiredArgument(argv, 'reservation-digest');
    if (!/^sha256:[0-9a-f]{64}$/.test(reservationDigest)) {
      throw new Error('--reservation-digest is not an exact sha256 digest');
    }
    const casStore = createCasEvidenceStore(env.USF_CAS_ROOT || '/var/lib/usf-cas');
    const bytes = casStore.read(reservationDigest);
    if (sha256(bytes) !== reservationDigest) {
      throw new Error('V2_GRAPH_RESERVATION_RECEIPT_CAS_DIGEST_MISMATCH');
    }
    const receipt = JSON.parse(bytes.toString('utf8'));
    if (canonicalJson(receipt) !== bytes.toString('utf8')) {
      throw new Error('V2_GRAPH_RESERVATION_RECEIPT_NOT_CANONICAL');
    }
    const lane = semanticModelCompilationCommandInternals.createSemanticPublicationLaneV2(
      env.USF_PROGRAMME_ROOT || '/var/lib/usf-programme',
    );
    const reservation = lane.readReservation();
    if (!reservation
        || sha256(Buffer.from(canonicalJson(reservation), 'utf8'))
          !== receipt.lane_reservation_digest
        || reservation.d0_authority_digest !== expectedAuthorityDigest
        || receipt.d0_authority_digest !== expectedAuthorityDigest
        || reservation.handover_generation_digest !== receipt.handover_generation_digest) {
      throw new Error('V2_GRAPH_RESERVATION_RECEIPT_LANE_MISMATCH');
    }
    process.stdout.write(`${bytes.toString('utf8')}\n`);
    return receipt;
  }
  if (mode === 'native-v2-ownership' || mode === 'native-v2-work-plan') {
    const live = await configureLiveGraphProductionShadowV2(expectedAuthorityDigest, env);
    const observe = mode === 'native-v2-work-plan'
      ? observeGraphNativeWorkPlanV2 : observeGraphRuntimeOwnershipV2;
    const result = await observe({
      client: live.client,
      expectedAuthorityDigest,
      readAuthorityWitness: () => live.readAuthorityWitness(),
      trustedTime: live.trustedTime,
      nativeGraphStore: createGraphNativeSuccessorStoreV2({
        nativeRoot: env.USF_V2_NATIVE_GRAPH_ROOT
          || '/var/lib/usf-programme/v2-native-graph-successors',
        casStore: createCasEvidenceStore(env.USF_CAS_ROOT || '/var/lib/usf-cas'),
      }),
      publicationLane: semanticModelCompilationCommandInternals.createSemanticPublicationLaneV2(
        env.USF_PROGRAMME_ROOT || '/var/lib/usf-programme',
      ),
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
    return result;
  }
  if (mode === 'native-v2-currentness-prepare'
      || mode === 'native-v2-currentness-renew') {
    const liveMutable = await configureLiveDependencies(expectedAuthorityDigest, env);
    const live = Object.freeze({
      client: createReadOnlyStardogShadowClientV2(liveMutable.client),
      command: liveMutable.command,
      readAuthorityWitness: liveMutable.readAuthorityWitness,
      trustedTime: liveMutable.trustedTime,
    });
    const nativeGraphStore = createGraphNativeSuccessorStoreV2({
      nativeRoot: env.USF_V2_NATIVE_GRAPH_ROOT
        || '/var/lib/usf-programme/v2-native-graph-successors',
      casStore: createCasEvidenceStore(env.USF_CAS_ROOT || '/var/lib/usf-cas'),
    });
    const lane = semanticModelCompilationCommandInternals.createSemanticPublicationLaneV2(
      env.USF_PROGRAMME_ROOT || '/var/lib/usf-programme',
    );
    if (mode === 'native-v2-currentness-prepare') {
      const result = await prepareGraphNativeValidationCurrentnessV2({
        client: live.client,
        expectedAuthorityDigest,
        nativeGraphStore,
        publicationLane: lane,
        readAuthorityWitness: () => live.readAuthorityWitness(),
        renewalNonce: requiredArgument(argv, 'renewal-nonce'),
        trustedTime: live.trustedTime,
        validUntil: requiredArgument(argv, 'valid-until'),
        validateCurrentnessCandidate: ({ authorityDigest, handoverGenerationDigest }) => (
          live.command.validateNativeV2Currentness({
            expectedAuthorityDigest: authorityDigest,
            handoverGenerationDigest,
          })
        ),
      });
      process.stdout.write(`${canonicalJson(result)}\n`);
      return result;
    }
    const signingRequest = JSON.parse(readFileSync(
      requiredArgument(argv, 'currentness-signing-request'), 'utf8',
    ));
    const envelope = validationCurrentnessEnvelopeFromSigningRequestV2(
      signingRequest,
      readFileSync(requiredArgument(argv, 'currentness-signature'), 'utf8'),
    );
    const result = await renewGraphNativeValidationCurrentnessV2({
      client: live.client,
      envelope,
      expectedAuthorityDigest,
      nativeGraphStore,
      publicationLane: lane,
      readAuthorityWitness: () => live.readAuthorityWitness(),
      trustedTime: live.trustedTime,
      validateCurrentnessCandidate: ({ authorityDigest }) => (
        live.command.validateNativeV2Currentness({
          expectedAuthorityDigest: authorityDigest,
          handoverGenerationDigest: envelope.payload.handover_generation_digest,
        })
      ),
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
    return result;
  }
  if (mode === 'native-v2-publish') {
    const inputs = JSON.parse(readFileSync(requiredArgument(argv, 'v2-inputs'), 'utf8'));
    semanticProofV2.assertProspectivePublicationPlanV2(inputs.plan);
    const installedSource = readInstalledGraphSourceIdentityV2();
    if (installedSource.commit !== inputs.graph_commit
        || installedSource.tree !== inputs.graph_tree
        || inputs.plan.graph_protected_commit !== installedSource.commit
        || inputs.plan.graph_protected_tree !== installedSource.tree) {
      throw new Error('V2 native publisher inputs differ from the clean running Graph source');
    }
    const live = await configureLiveGraphProductionV2(expectedAuthorityDigest, {
      d1CandidateBytes: readFileSync(requiredArgument(argv, 'd1-candidate')),
      d1CandidateIdentityBytes: readFileSync(requiredArgument(argv, 'd1-candidate-identity')),
      d2CandidateBytes: readFileSync(requiredArgument(argv, 'd2-candidate')),
      d2CandidateIdentityBytes: readFileSync(requiredArgument(argv, 'd2-candidate-identity')),
      graphCommit: installedSource.commit,
      graphTree: installedSource.tree,
      publisherImplementationDigest: inputs.publisher_implementation_digest,
      publisherCommandDigest: inputs.publisher_command_digest,
      nativeGraphStore: createGraphNativeSuccessorStoreV2({
        nativeRoot: env.USF_V2_NATIVE_GRAPH_ROOT
          || '/var/lib/usf-programme/v2-native-graph-successors',
        casStore: createCasEvidenceStore(env.USF_CAS_ROOT || '/var/lib/usf-cas'),
      }),
    }, env);
    const trustedAt = (await trustedInstant(live.trustedTime)).canonical;
    const result = await semanticProofV2.advanceDurableSemanticProofV2Publication({
      ...inputs,
      graph_adapter: live.adapter,
      trusted_at: trustedAt,
    }, {
      journalPath: requiredArgument(argv, 'v2-journal'),
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
    return result;
  }
  if (requiredArgument(argv, 'producer') !== 'aggregate-compiler-v1') {
    throw new Error('--producer must be aggregate-compiler-v1');
  }
  const publicationPhase = requiredArgument(argv, 'publication-phase');
  const live = await configureLiveDependencies(expectedAuthorityDigest, env);
  if (mode === 'lifecycle') {
    if (publicationPhase !== 'aggregate') throw new Error('lifecycle mode requires --publication-phase=aggregate');
    const ownerAssignments = ownerAssignmentsFromArgv(argv);
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
    const externalAuthorityDeltaPath = optionalArgument(argv, 'external-authority-delta');
    const result = await runAggregateCompilerProductionLifecycle({
      expectedAuthorityDigest,
      externalAuthorityDelta: externalAuthorityDeltaPath === undefined
        ? null
        : JSON.parse(readFileSync(externalAuthorityDeltaPath, 'utf8')),
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
    const ownerAssignments = ownerAssignmentsFromArgv(argv);
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
  // main() must not be awaited during this module's own evaluation. It dynamically imports
  // semantic-model-compilation-command.mjs, which statically imports
  // aggregate-compiler-proof-command.mjs, which imports this module back. A top-level await
  // here keeps this module suspended mid-evaluation, so that cycle can never resolve: the
  // dynamic import never settles, no I/O is left pending, the event loop drains, and Node
  // reports an unsettled top-level await and exits 13 having written neither the payload nor
  // the error. Every consumer that spawns this file as a subprocess saw only a non-zero exit
  // with empty stdout even when the operation had in fact succeeded — the Factory's Graph
  // ownership reader raised V2_NATIVE_GRAPH_OWNERSHIP_OBSERVATION_FAILED for exactly this.
  //
  // setImmediate defers the call until after evaluation completes, so the cycle resolves
  // normally. The referenced timer keeps the loop alive until main() settles, and the
  // explicit handlers guarantee the payload reaches stdout or the diagnosis reaches stderr.
  const keepEventLoopReferenced = setInterval(() => {}, 2_147_483_647);
  setImmediate(() => {
    main()
      .catch((error) => {
        process.stderr.write(`${error?.stack ?? String(error)}\n`);
        process.exitCode = 1;
      })
      .finally(() => clearInterval(keepEventLoopReferenced));
  });
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
  assertGraphProductionShadowPlanBindingV2,
  assertProspectivePublicationPlanV2,
  canonicalGraphOwnedConsumerObservationBytesV2,
  canonicalGraphOwnedConsumerRecordBytesV2,
  canonicalGraphProductionShadowReceiptBytesV2,
  captureGraphOwnedConsumerObservationV2,
  captureGraphProductionShadowV2,
  createReadOnlyGraphProductionAdapterV2,
  factoryClosureReceiptDigestV2,
  graphOwnedConsumerObservationDigestV2,
  graphOwnedConsumerRecordDigestV2,
  graphProductionShadowReceiptDigestV2,
  graphPublicationReceiptDigestV2,
  HermeticSemanticProofV2Journal,
  prospectivePublicationPlanDigestV2,
  SemanticProofV2JournalState,
} from './semantic-proof-v2.mjs';
