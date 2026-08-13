import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { GOVERNANCE_ROOT, verifyInstalledAnchor } from './root-trust-v1.mjs';

export const SEMANTIC_PROOF_PROTOCOL = 'semantic-proof-v1';
export const AUTHORITY_FINGERPRINT = 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D';
export const AUTHORITY_PRINCIPAL = 'urn:usf:principal:matthewaldous';
export const AUTHORITY_SIGNING_IDENTITY = 'urn:usf:signingidentity:matthewaldoussemanticproofv1';
export const AUTHORITY_ALGORITHM = 'openpgp';
export const CLAIM_TYPES = Object.freeze(['owner_assignment', 'candidate_approval', 'publication_grant']);
export const DEFAULT_TRUST_ANCHOR = '/var/lib/usf-programme/trust/semantic-authority.json';
export const DEFAULT_PUBLIC_KEY = '/var/lib/usf-programme/trust/semantic-authority-public-key.gpg';
export const DEFAULT_REPLAY_LEDGER = '/var/lib/usf-programme/trust/semantic-proof-v1-replay-ledger.json';
export const GPGV_EXECUTABLE = '/usr/bin/gpgv';
export const APPROVED_AUTHORITY_SCOPES = Object.freeze([
  Object.freeze({
    authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane',
    repository: 'maldous/usf-factory',
  }),
  Object.freeze({
    authorityDomain: 'urn:usf:capabilityowner:semanticmodelcompilation',
    repository: 'maldous/usf-graph',
  }),
]);
export const FACTORY_PROVIDER_DURABLE_CONTROL_PLANE_SCOPE = Object.freeze({
  authorityDomain: 'urn:usf:capabilityowner:factoryproviderdurablecontrolplane',
  repository: 'maldous/usf-factory',
});
export const REPOSITORY_EXTERNAL_ARTEFACT_MATERIALISATION_SCOPE = Object.freeze({
  authorityDomain: 'urn:usf:capabilityowner:repositoryexternalartefactmaterialisation',
  repository: 'maldous/usf-graph',
});
export const GOVERNED_AUTHORITY_SCOPES = Object.freeze([
  FACTORY_PROVIDER_DURABLE_CONTROL_PLANE_SCOPE,
  ...APPROVED_AUTHORITY_SCOPES,
]);
export const FINAL_V1_GOVERNED_AUTHORITY_SCOPES = Object.freeze([
  FACTORY_PROVIDER_DURABLE_CONTROL_PLANE_SCOPE,
  APPROVED_AUTHORITY_SCOPES[0],
  REPOSITORY_EXTERNAL_ARTEFACT_MATERIALISATION_SCOPE,
  APPROVED_AUTHORITY_SCOPES[1],
]);

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RFC3339_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const NONCE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IRI = /^urn:[^\s]+$/;
const PAYLOAD_FIELDS = Object.freeze([
  'algorithm', 'authority_domain', 'authority_pre_digest', 'candidate_digest', 'claim_type',
  'expires_at', 'fingerprint', 'issued_at', 'nonce', 'principal', 'protocol', 'repository',
  'signing_identity', 'single_use', 'source_scope_digest',
]);
const RECEIPT_FIELDS = Object.freeze([
  'action_state', 'authority_after_digest', 'authority_before_digest', 'authority_domain',
  'authority_publication_digest', 'candidate_approval_envelope_digest', 'candidate_digest',
  'committed_candidate_state', 'current_proof_results', 'direct_provisional_aggregate_selections',
  'grant_consumed', 'grant_nonce',
  'owner_assignment_envelope_digest', 'proof_currentness', 'protocol',
  'projection_observation_receipt_digest',
  'publication_grant_envelope_digest', 'publication_outcome', 'publication_phase', 'published_at',
  'reevaluation_authority_digest',
  'reevaluation_evaluation_receipt_digest', 'reevaluation_execution_receipt_digest', 'repository',
  'schema_version', 'selected_aggregate_result', 'selected_provisional_aggregate_result',
  'source_scope_digest', 'terminal_state',
]);
const INITIAL_OBSERVATION_FIELDS = Object.freeze([
  'actionState', 'authorityDigest', 'currentProofResults', 'directProvisionalAggregateSelections',
  'observationReceiptDigest', 'ok', 'operation', 'proofCurrentness',
  'selectedProvisionalAggregateResult',
]);
const INITIAL_PREPARATION_FIELDS = Object.freeze([
  'candidateDigest', 'evaluatedAuthorityDigest', 'evaluationReceiptDigest', 'executionReceiptDigest',
  'ok', 'operation', 'protocol', 'state',
]);
const TRUST_ANCHOR_FIELDS = Object.freeze([
  'algorithm', 'approvalThreshold', 'authorityScopes', 'fingerprint', 'githubPrincipal',
  'principal', 'protocol',
]);
const TRUST_ANCHOR_SCOPE_FIELDS = Object.freeze(['authorityDomain', 'repository']);

const utf8 = (left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8).map((key) => [key, stable(value[key])]))
    : value;

export const canonicalJson = (value) => JSON.stringify(stable(value));
export const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

function exactObject(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const observed = Object.keys(value).sort(utf8);
  const expected = [...fields].sort(utf8);
  if (canonicalJson(observed) !== canonicalJson(expected)) throw new Error(`${label} fields are not the closed protocol contract`);
  return value;
}

function exactDigest(value, label) {
  if (!SHA256.test(value)) throw new Error(`${label} must be an exact sha256 digest`);
  return value;
}

export function canonicalSourcePaths(paths) {
  if (!Array.isArray(paths) || paths.length < 1) throw new Error('source scope requires at least one path');
  const canonical = [...paths].sort(utf8);
  if (new Set(canonical).size !== canonical.length) throw new Error('source scope contains duplicate paths');
  for (const path of canonical) {
    if (typeof path !== 'string' || path.length < 1 || path.startsWith('/') || path.includes('\\')
        || path.split('/').some((part) => part === '' || part === '.' || part === '..')) {
      throw new Error(`source scope path is not canonical repository-relative identity: ${path}`);
    }
  }
  return Object.freeze(canonical);
}

export const sourceScopeDigest = (paths) => sha256(canonicalJson(canonicalSourcePaths(paths)));
export const envelopeDigest = (envelope) => sha256(canonicalJson(envelope));
export const publicationReceiptDigest = (receipt) => sha256(`${canonicalJson(receipt)}\n`);

export function ownerAssignmentCandidateDigest({ authorityDomain, principal, repository, sourcePaths }) {
  const canonicalPaths = canonicalSourcePaths(sourcePaths);
  return sha256(canonicalJson({
    authority_domain: authorityDomain,
    principal,
    repository,
    source_paths: canonicalPaths,
    source_scope_digest: sourceScopeDigest(canonicalPaths),
  }));
}

export function readTrustAnchor(path = DEFAULT_TRUST_ANCHOR) {
  assertRootOwnedReadOnlyFile(path, DEFAULT_TRUST_ANCHOR, 'semantic authority trust anchor');
  const anchor = JSON.parse(readFileSync(path, 'utf8'));
  assertTrustAnchor(anchor);
  if (anchor.protocol !== SEMANTIC_PROOF_PROTOCOL || anchor.principal !== AUTHORITY_PRINCIPAL
      || anchor.githubPrincipal !== 'maldous' || anchor.fingerprint !== AUTHORITY_FINGERPRINT
      || anchor.algorithm !== AUTHORITY_ALGORITHM || anchor.approvalThreshold !== 1) {
    throw new Error('trust anchor does not match the approved semantic authority signer');
  }
  return Object.freeze(anchor);
}

function assertApprovedTrustAnchorScopeSet(scopes) {
  const observed = canonicalJson(scopes);
  if (observed === canonicalJson(APPROVED_AUTHORITY_SCOPES)) return false;
  if (![GOVERNED_AUTHORITY_SCOPES, FINAL_V1_GOVERNED_AUTHORITY_SCOPES]
    .some((approved) => observed === canonicalJson(approved))) {
    throw new Error('trust anchor contains an unapproved authority domain or repository pair');
  }
  return true;
}

function assertTrustAnchor(anchor) {
  exactObject(anchor, TRUST_ANCHOR_FIELDS, 'trust anchor');
  if (!Array.isArray(anchor.authorityScopes)) throw new Error('trust anchor authority scopes must be an array');
  const scopes = anchor.authorityScopes.map((scope) => exactObject(scope, TRUST_ANCHOR_SCOPE_FIELDS, 'trust anchor authority scope'));
  if (!assertApprovedTrustAnchorScopeSet(scopes)) return anchor;
  if (!existsSync(`${GOVERNANCE_ROOT}/registry.json`)) {
    throw new Error('extended trust anchor requires the governed root-trust version registry');
  }
  const governed = verifyInstalledAnchor();
  if (canonicalJson(governed.anchor) !== canonicalJson(anchor)) {
    throw new Error('extended trust anchor differs from the active governed registry version');
  }
  return anchor;
}

function assertApprovedAuthorityScope(anchor, authorityDomain, repository) {
  assertTrustAnchor(anchor);
  if (!anchor.authorityScopes.some((scope) => scope.authorityDomain === authorityDomain
      && scope.repository === repository)) {
    throw new Error('authority domain and repository pair is not approved by the external trust anchor');
  }
}

export function readEnvelope(path) {
  const envelope = JSON.parse(readFileSync(path, 'utf8'));
  exactObject(envelope, ['payload', 'signature'], 'signed envelope');
  exactObject(envelope.payload, PAYLOAD_FIELDS, 'signed envelope payload');
  if (typeof envelope.signature !== 'string' || !envelope.signature.includes('BEGIN PGP SIGNATURE')) {
    throw new Error('signed envelope requires one ASCII-armored OpenPGP signature');
  }
  return Object.freeze({ payload: Object.freeze({ ...envelope.payload }), signature: envelope.signature });
}

const REAL_METADATA_IO = Object.freeze({ lstat: lstatSync, realpath: realpathSync, stat: statSync });

function assertMetadataIo(metadataIo) {
  if (!metadataIo || typeof metadataIo.lstat !== 'function' || typeof metadataIo.realpath !== 'function'
      || typeof metadataIo.stat !== 'function') {
    throw new Error('file metadata adapter must provide lstat, realpath and stat');
  }
  return metadataIo;
}

function assertRootOwnedExecutable(path = GPGV_EXECUTABLE, metadataIo = REAL_METADATA_IO) {
  if (path !== GPGV_EXECUTABLE) throw new Error(`OpenPGP verification executable must be ${GPGV_EXECUTABLE}`);
  const metadata = assertMetadataIo(metadataIo);
  const link = metadata.lstat(path);
  if (link.uid !== 0 || (link.mode & 0o022) !== 0) throw new Error('OpenPGP verification executable path is not root-controlled');
  const resolved = metadata.realpath(path);
  const target = metadata.stat(resolved);
  if (!target.isFile() || target.uid !== 0 || (target.mode & 0o022) !== 0 || (target.mode & 0o111) === 0) {
    throw new Error('OpenPGP verification executable target is not a root-owned, non-writable executable');
  }
  return resolved;
}

function assertRootOwnedReadOnlyFile(path, expectedPath, label, metadataIo = REAL_METADATA_IO) {
  if (path !== expectedPath) throw new Error(`${label} must use canonical path ${expectedPath}`);
  const observed = assertMetadataIo(metadataIo).lstat(path);
  if (!observed.isFile() || observed.isSymbolicLink() || observed.uid !== 0 || observed.gid !== 0
      || (observed.mode & 0o777) !== 0o444) {
    throw new Error(`${label} must be a root-owned regular non-symlink with mode 0444`);
  }
  return path;
}

function verifyDetachedWithGpgv(payloadBytes, signature, { publicKeyPath, executable = GPGV_EXECUTABLE } = {}) {
  if (!Buffer.isBuffer(payloadBytes) || payloadBytes.length === 0) throw new Error('OpenPGP payload bytes are required');
  if (typeof signature !== 'string' || !signature.includes('BEGIN PGP SIGNATURE')) {
    throw new Error('ASCII-armored OpenPGP detached signature is required');
  }
  if (typeof publicKeyPath !== 'string' || publicKeyPath.length === 0) throw new Error('OpenPGP public key path is required');
  const root = mkdtempSync(join(tmpdir(), 'semantic-proof-v1-'));
  const payloadPath = join(root, 'payload.json');
  const signaturePath = join(root, 'payload.asc');
  try {
    writeFileSync(payloadPath, payloadBytes, { mode: 0o600, flag: 'wx' });
    writeFileSync(signaturePath, signature, { mode: 0o600, flag: 'wx' });
    const result = spawnSync(executable, [
      '--status-fd', '1', '--keyring', publicKeyPath, signaturePath, payloadPath,
    ], { encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C' } });
    if (result.status !== 0) throw new Error(`OpenPGP signature verification failed: ${(result.stderr || '').trim()}`);
    const valid = (result.stdout || '').split('\n').find((line) => line.startsWith('[GNUPG:] VALIDSIG '));
    const fingerprint = valid?.split(/\s+/)[2];
    if (!fingerprint) throw new Error('OpenPGP verifier returned no VALIDSIG fingerprint');
    return fingerprint;
  } finally {
    for (const path of [signaturePath, payloadPath]) {
      try { unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    rmdirSync(root);
  }
}

function defaultDetachedVerifier(payloadBytes, signature, {
  publicKeyPath = DEFAULT_PUBLIC_KEY,
  metadataIo = REAL_METADATA_IO,
} = {}) {
  const executable = assertRootOwnedExecutable(GPGV_EXECUTABLE, metadataIo);
  assertRootOwnedReadOnlyFile(publicKeyPath, DEFAULT_PUBLIC_KEY, 'semantic authority public key', metadataIo);
  return verifyDetachedWithGpgv(payloadBytes, signature, { publicKeyPath, executable });
}

function timestamp(value, label) {
  if (typeof value !== 'string' || !RFC3339_SECOND.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an RFC3339 UTC second`);
  }
  return Date.parse(value);
}

export function canonicalUtcSecond(value, label = 'timestamp') {
  const parsed = timestamp(value, label);
  const canonical = new Date(parsed).toISOString().replace('.000Z', 'Z');
  if (canonical !== value) throw new Error(`${label} must be a canonical RFC3339 UTC second`);
  return value;
}

export function verifyEnvelope(envelope, {
  trustAnchor = readTrustAnchor(),
  publicKeyPath = DEFAULT_PUBLIC_KEY,
  verifyDetached = defaultDetachedVerifier,
  claimType,
  authorityDomain,
  repository,
  sourcePaths,
  authorityPreDigest,
  candidateDigest,
  metadataIo,
  now = new Date(),
  expectedSingleUse,
} = {}) {
  assertApprovedAuthorityScope(trustAnchor, authorityDomain, repository);
  exactObject(envelope, ['payload', 'signature'], 'signed envelope');
  const payload = exactObject(envelope.payload, PAYLOAD_FIELDS, 'signed envelope payload');
  if (!CLAIM_TYPES.includes(payload.claim_type) || payload.claim_type !== claimType) throw new Error('signed envelope claim type is not authorised for this operation');
  if (payload.protocol !== trustAnchor.protocol || payload.principal !== trustAnchor.principal
      || payload.fingerprint !== trustAnchor.fingerprint || payload.algorithm !== trustAnchor.algorithm
      || payload.signing_identity !== AUTHORITY_SIGNING_IDENTITY) {
    throw new Error('signed envelope signer, fingerprint, algorithm or identity is not the external trust anchor');
  }
  if (payload.authority_domain !== authorityDomain) throw new Error('signed envelope authority domain mismatch');
  if (payload.repository !== repository) throw new Error('signed envelope repository mismatch');
  if (payload.source_scope_digest !== sourceScopeDigest(sourcePaths)) throw new Error('signed envelope source scope mismatch');
  if (payload.authority_pre_digest !== authorityPreDigest) throw new Error('signed envelope authority pre-digest mismatch');
  if (payload.candidate_digest !== candidateDigest) throw new Error('signed envelope candidate digest mismatch');
  if (!SHA256.test(payload.authority_pre_digest) || !SHA256.test(payload.candidate_digest)
      || !SHA256.test(payload.source_scope_digest)) throw new Error('signed envelope digest syntax is invalid');
  if (!NONCE.test(payload.nonce)) throw new Error('signed envelope nonce is invalid');
  if (typeof payload.single_use !== 'boolean' || (expectedSingleUse !== undefined && payload.single_use !== expectedSingleUse)) {
    throw new Error('signed envelope single-use policy mismatch');
  }
  const issued = timestamp(payload.issued_at, 'issued_at');
  const expires = timestamp(payload.expires_at, 'expires_at');
  const observed = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(observed) || issued > observed || expires <= observed || expires <= issued) {
    throw new Error('signed envelope is not current at trusted time');
  }
  const fingerprint = verifyDetached(Buffer.from(`${canonicalJson(payload)}\n`), envelope.signature, {
    publicKeyPath, metadataIo,
  });
  if (fingerprint !== trustAnchor.fingerprint) throw new Error('OpenPGP signature was made by an unknown or integrity-only signer');
  return Object.freeze({ ...payload, envelope_digest: envelopeDigest(envelope) });
}

export function verifyPublicationBundle({
  ownerAssignment,
  candidateApproval,
  publicationGrant,
  trustAnchor = readTrustAnchor(),
  publicKeyPath = DEFAULT_PUBLIC_KEY,
  verifyDetached = defaultDetachedVerifier,
  authorityDomain,
  repository,
  sourcePaths,
  authorityPreDigest,
  candidateDigest,
  ownerAssignmentAuthorityPreDigest = ownerAssignment?.payload?.authority_pre_digest,
  now = new Date(),
}) {
  if (!ownerAssignment) throw new Error('owner assignment is required');
  const common = { trustAnchor, publicKeyPath, verifyDetached, authorityDomain, repository, sourcePaths, now };
  const assignment = verifyEnvelope(ownerAssignment, {
    ...common,
    claimType: 'owner_assignment',
    authorityPreDigest: ownerAssignmentAuthorityPreDigest,
    candidateDigest: ownerAssignmentCandidateDigest({
      authorityDomain, principal: trustAnchor.principal, repository, sourcePaths,
    }),
    expectedSingleUse: false,
  });
  const approval = verifyEnvelope(candidateApproval, {
    ...common, claimType: 'candidate_approval', authorityPreDigest, candidateDigest, expectedSingleUse: false,
  });
  const grant = verifyEnvelope(publicationGrant, {
    ...common, claimType: 'publication_grant', authorityPreDigest, candidateDigest, expectedSingleUse: true,
  });
  if (new Set([assignment.nonce, approval.nonce, grant.nonce]).size !== 3) throw new Error('authoritative claims must use distinct nonces');
  return Object.freeze({ assignment, approval, grant });
}

function withLedgerLock(ledgerPath, callback) {
  const lockPath = `${ledgerPath}.lock`;
  let descriptor;
  try {
    descriptor = openSync(lockPath, 'wx', 0o600);
    return callback();
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
      try { unlinkSync(lockPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
}

function writeFsyncLedger(path, contents) {
  const temporary = `${path}.tmp`;
  let descriptor;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    writeFileSync(descriptor, contents);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    chmodSync(path, 0o600);
    const directoryDescriptor = openSync(dirname(path), 'r');
    try { fsyncSync(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { unlinkSync(temporary); } catch (unlinkError) { if (unlinkError.code !== 'ENOENT') throw unlinkError; }
    throw error;
  }
}

export const REAL_JOURNAL_IO = Object.freeze({
  ensureDirectory: (path) => mkdirSync(path, { recursive: true, mode: 0o755 }),
  read: (path) => readFileSync(path, 'utf8'),
  withLock: withLedgerLock,
  write: writeFsyncLedger,
});

function assertJournalIo(journalIo) {
  if (!journalIo || typeof journalIo.ensureDirectory !== 'function' || typeof journalIo.read !== 'function'
      || typeof journalIo.withLock !== 'function' || typeof journalIo.write !== 'function') {
    throw new Error('journal IO adapter must provide ensureDirectory, read, withLock and write');
  }
  return journalIo;
}

function readLedger(path, journalIo = REAL_JOURNAL_IO) {
  const ledger = JSON.parse(assertJournalIo(journalIo).read(path));
  if (ledger.protocol !== SEMANTIC_PROOF_PROTOCOL || !ledger.nonces || typeof ledger.nonces !== 'object'
      || Array.isArray(ledger.nonces)) throw new Error('publication transaction journal is invalid');
  return ledger;
}

function writeLedger(path, ledger, journalIo = REAL_JOURNAL_IO) {
  assertJournalIo(journalIo).write(path, `${canonicalJson(ledger)}\n`);
}

function verifiedGrant(grant) {
  if (grant?.claim_type !== 'publication_grant' || grant.single_use !== true || !NONCE.test(grant.nonce)
      || !SHA256.test(grant.candidate_digest) || !SHA256.test(grant.authority_pre_digest)
      || !SHA256.test(grant.envelope_digest)) {
    throw new Error('only a verified single-use publication grant can enter the publication journal');
  }
  return grant;
}

function updateJournal(grant, ledgerPath, update, journalIo = REAL_JOURNAL_IO) {
  verifiedGrant(grant);
  const io = assertJournalIo(journalIo);
  return io.withLock(ledgerPath, () => {
    const ledger = readLedger(ledgerPath, io);
    const current = ledger.nonces[grant.nonce];
    const next = update(ledger, current);
    ledger.nonces[grant.nonce] = next;
    writeLedger(ledgerPath, ledger, io);
    return Object.freeze({ nonce: grant.nonce, ...next });
  });
}

export function reserveGrantNonce(grant, {
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
  observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  publicationPhase,
} = {}) {
  verifiedGrant(grant);
  if (!['initial', 'reevaluation'].includes(publicationPhase)) throw new Error('publication phase must be initial or reevaluation');
  assertJournalIo(journalIo).ensureDirectory(dirname(ledgerPath));
  return updateJournal(grant, ledgerPath, (ledger, current) => {
    if (current) throw new Error('publication grant nonce was replayed or already entered the transaction journal');
    const conflicting = Object.values(ledger.nonces).find((record) => record.candidate_digest === grant.candidate_digest
      && record.authority_pre_digest === grant.authority_pre_digest);
    if (conflicting) throw new Error('candidate and authority pre-state already have a publication transaction journal entry');
    return {
      authority_pre_digest: grant.authority_pre_digest,
      candidate_digest: grant.candidate_digest,
      grant_envelope_digest: grant.envelope_digest,
      publication_outcome: 'pending',
      publication_phase: publicationPhase,
      reserved_at: observedAt,
      state: 'reserved',
    };
  }, journalIo);
}

export function readPublicationTransaction(grant, {
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
} = {}) {
  verifiedGrant(grant);
  const current = readLedger(ledgerPath, journalIo).nonces[grant.nonce];
  if (!current) return null;
  if (current.authority_pre_digest !== grant.authority_pre_digest
      || current.candidate_digest !== grant.candidate_digest
      || current.grant_envelope_digest !== grant.envelope_digest) {
    throw new Error('publication transaction journal binding mismatch');
  }
  return Object.freeze(JSON.parse(canonicalJson(current)));
}

export function readPublicationTransactionForEnvelope(envelope, {
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
} = {}) {
  const payload = envelope?.payload;
  if (!payload || payload.claim_type !== 'publication_grant' || !NONCE.test(payload.nonce)) return null;
  const current = readLedger(ledgerPath, journalIo).nonces[payload.nonce];
  if (!current) return null;
  if (current.grant_envelope_digest !== envelopeDigest(envelope)
      || current.authority_pre_digest !== payload.authority_pre_digest
      || current.candidate_digest !== payload.candidate_digest) {
    throw new Error('publication transaction envelope does not match the durable journal');
  }
  return Object.freeze(JSON.parse(canonicalJson(current)));
}

export function recordPublicationOutcome(grant, {
  authorityPublicationDigest,
  committedCandidateState,
  publishedAt,
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
  observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
} = {}) {
  exactDigest(authorityPublicationDigest, 'publication authority digest');
  canonicalUtcSecond(publishedAt, 'published_at');
  if (committedCandidateState !== 'COMMITTED') throw new Error('publication outcome must be the exact COMMITTED compiler state');
  return updateJournal(grant, ledgerPath, (_ledger, current) => {
    if (!current) throw new Error('publication transaction was not reserved');
    if (current.state === 'published_pending_reevaluation') {
      if (current.authority_publication_digest !== authorityPublicationDigest
          || current.committed_candidate_state !== committedCandidateState
          || current.published_at !== publishedAt) throw new Error('publication outcome substitution was rejected');
      return current;
    }
    if (current.state !== 'reserved') throw new Error('publication transaction was not reserved');
    return {
      ...current,
      authority_publication_digest: authorityPublicationDigest,
      committed_at: observedAt,
      committed_candidate_state: committedCandidateState,
      publication_outcome: 'committed',
      published_at: publishedAt,
      state: 'published_pending_reevaluation',
    };
  }, journalIo);
}

export function recordPostPublicationReevaluation(grant, reevaluation, {
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
  observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
} = {}) {
  assertPostPublicationTerminalState(reevaluation);
  return updateJournal(grant, ledgerPath, (_ledger, current) => {
    if (!current) throw new Error('publication is not awaiting reevaluation');
    if (current.state === 'reevaluated_pending_receipt') {
      if (current.authority_after_digest !== reevaluation.authorityAfterDigest
          || current.reevaluation_execution_receipt_digest !== reevaluation.executionReceiptDigest
          || current.reevaluation_evaluation_receipt_digest !== reevaluation.evaluationReceiptDigest
          || current.selected_aggregate_result !== reevaluation.selectedAggregateResult) {
        throw new Error('post-publication reevaluation substitution was rejected');
      }
      return current;
    }
    if (current.state !== 'published_pending_reevaluation') throw new Error('publication is not awaiting reevaluation');
    if (current.publication_phase !== 'reevaluation'
        || current.authority_pre_digest !== reevaluation.evaluatedAuthorityDigest) {
      throw new Error('reevaluation did not evaluate the stage-1 authority digest');
    }
    return {
      ...current,
      action_state: reevaluation.actionState,
      authority_after_digest: reevaluation.authorityAfterDigest,
      current_proof_results: reevaluation.currentProofResults,
      proof_currentness: reevaluation.proofCurrentness,
      reevaluated_at: observedAt,
      reevaluation_evaluation_receipt_digest: reevaluation.evaluationReceiptDigest,
      reevaluation_execution_receipt_digest: reevaluation.executionReceiptDigest,
      selected_aggregate_result: reevaluation.selectedAggregateResult,
      state: 'reevaluated_pending_receipt',
    };
  }, journalIo);
}

export function assertInitialProjectionObservation(result) {
  exactObject(result, INITIAL_OBSERVATION_FIELDS, 'stage-1 projection observation');
  if (result.ok !== true || result.operation !== 'observe_initial'
      || result.authorityDigest === undefined || !SHA256.test(result.authorityDigest)
      || result.directProvisionalAggregateSelections !== 1 || result.currentProofResults !== 0
      || result.proofCurrentness !== 'PENDING' || result.actionState !== 'UNRESOLVED_FAIL_CLOSED'
      || !IRI.test(result.selectedProvisionalAggregateResult || '')
      || !SHA256.test(result.observationReceiptDigest || '')) {
    throw new Error('stage-1 authority projection is not exactly one provisional aggregate and zero CURRENT results');
  }
  return Object.freeze(JSON.parse(canonicalJson(result)));
}

export function recordInitialProjectionObservation(grant, observation, {
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
  observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
} = {}) {
  const canonical = assertInitialProjectionObservation(observation);
  const digest = sha256(canonicalJson(canonical));
  return updateJournal(grant, ledgerPath, (_ledger, current) => {
    if (!current || current.state !== 'published_pending_reevaluation' || current.publication_phase !== 'initial'
        || current.authority_publication_digest !== canonical.authorityDigest) {
      throw new Error('stage-1 publication is not eligible for projection observation');
    }
    if (current.initial_projection_observation) {
      if (current.initial_projection_observation.package_digest !== digest
          || canonicalJson(current.initial_projection_observation.package) !== canonicalJson(canonical)) {
        throw new Error('stage-1 projection observation substitution was rejected');
      }
      return current;
    }
    return {
      ...current,
      initial_projection_observation: { package: canonical, package_digest: digest, recorded_at: observedAt },
    };
  }, journalIo);
}

export function assertInitialReevaluationPreparation(result) {
  exactObject(result, INITIAL_PREPARATION_FIELDS, 'stage-1 reevaluation preparation');
  if (result.ok !== true || result.operation !== 'produce_initial'
      || result.protocol !== SEMANTIC_PROOF_PROTOCOL || result.state !== 'REEVALUATION_CANDIDATE_PREPARED'
      || !SHA256.test(result.evaluatedAuthorityDigest || '') || !SHA256.test(result.candidateDigest || '')
      || !SHA256.test(result.executionReceiptDigest || '') || !SHA256.test(result.evaluationReceiptDigest || '')) {
    throw new Error('stage-1 reevaluation producer did not return an exact candidate-bound preparation');
  }
  return Object.freeze(JSON.parse(canonicalJson(result)));
}

export function recordInitialReevaluationPreparation(grant, preparation, {
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
  observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
} = {}) {
  assertInitialReevaluationPreparation(preparation);
  const canonical = assertInitialReevaluationPreparation(preparation);
  const packageDigest = sha256(canonicalJson(canonical));
  return updateJournal(grant, ledgerPath, (_ledger, current) => {
    if (!current || current.state !== 'consumed' || current.publication_phase !== 'initial'
        || current.authority_publication_digest !== preparation.evaluatedAuthorityDigest) {
      throw new Error('stage-1 publication is not eligible to record reevaluation preparation');
    }
    if (current.reevaluation_preparation) {
      if (current.reevaluation_preparation.package_digest !== packageDigest
          || canonicalJson(current.reevaluation_preparation.package) !== canonicalJson(canonical)) {
        throw new Error('stage-1 reevaluation preparation substitution was rejected');
      }
      return current;
    }
    return {
      ...current,
      reevaluation_preparation: {
        package: canonical,
        package_digest: packageDigest,
        recorded_at: observedAt,
      },
    };
  }, journalIo);
}

export function assertReevaluationPredecessor({
  priorReceipt,
  preparation,
  authorityPreDigest,
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
}) {
  assertSemanticProofPublicationReceipt(priorReceipt);
  assertInitialReevaluationPreparation(preparation);
  if (priorReceipt.publication_phase !== 'initial' || priorReceipt.terminal_state !== 'PENDING'
      || priorReceipt.authority_after_digest !== authorityPreDigest
      || preparation.evaluatedAuthorityDigest !== authorityPreDigest
      || preparation.candidateDigest !== priorReceipt.candidate_digest) {
    throw new Error('reevaluation publication does not match its stage-1 predecessor');
  }
  const ledger = readLedger(ledgerPath, journalIo);
  const prior = ledger.nonces[priorReceipt.grant_nonce];
  const preparationDigest = sha256(canonicalJson(preparation));
  if (!prior || prior.state !== 'consumed' || prior.publication_phase !== 'initial'
      || prior.final_receipt_digest !== publicationReceiptDigest(priorReceipt)
      || prior.published_at !== priorReceipt.published_at
      || prior.reevaluation_preparation?.package_digest !== preparationDigest
      || canonicalJson(prior.reevaluation_preparation?.package) !== canonicalJson(preparation)) {
    throw new Error('reevaluation publication has no durable stage-1 transaction linkage');
  }
  return Object.freeze({ prior, preparation });
}

export function consumeGrantNonce(grant, {
  receipt,
  receiptDigest = publicationReceiptDigest(receipt),
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
  observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
} = {}) {
  assertSemanticProofPublicationReceipt(receipt);
  if (receiptDigest !== publicationReceiptDigest(receipt)) throw new Error('final publication receipt digest mismatch');
  return updateJournal(grant, ledgerPath, (_ledger, current) => {
    if (current?.state === 'consumed') {
      if (current.final_receipt_digest !== receiptDigest
          || canonicalJson(current.final_receipt) !== canonicalJson(receipt)) {
        throw new Error('consumed publication receipt substitution was rejected');
      }
      return current;
    }
    const expectedState = receipt.publication_phase === 'initial'
      ? 'published_pending_reevaluation'
      : 'reevaluated_pending_receipt';
    if (!current || current.state !== expectedState || current.publication_phase !== receipt.publication_phase) {
      throw new Error('publication grant is not awaiting this phase receipt');
    }
    const bindings = [
      ['authority_pre_digest', receipt.authority_before_digest],
      ['candidate_digest', receipt.candidate_digest],
      ['grant_envelope_digest', receipt.publication_grant_envelope_digest],
      ['authority_publication_digest', receipt.authority_publication_digest],
    ];
    if (receipt.publication_phase === 'reevaluation') bindings.push(
      ['authority_after_digest', receipt.authority_after_digest],
      ['reevaluation_execution_receipt_digest', receipt.reevaluation_execution_receipt_digest],
      ['reevaluation_evaluation_receipt_digest', receipt.reevaluation_evaluation_receipt_digest],
      ['selected_aggregate_result', receipt.selected_aggregate_result],
    );
    if (bindings.some(([field, value]) => current[field] !== value)) throw new Error('final receipt does not match the publication transaction journal');
    return {
      ...current,
      consumed_at: observedAt,
      final_receipt: JSON.parse(canonicalJson(receipt)),
      final_receipt_digest: receiptDigest,
      publication_outcome: receipt.publication_outcome,
      published_at: receipt.published_at,
      state: 'consumed',
    };
  }, journalIo);
}

export function failGrantNonce(grant, {
  stage,
  journalIo = REAL_JOURNAL_IO,
  ledgerPath = DEFAULT_REPLAY_LEDGER,
  observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
} = {}) {
  if (typeof stage !== 'string' || !/^[a-z][a-z0-9_]{1,63}$/.test(stage)) throw new Error('publication failure stage is invalid');
  return updateJournal(grant, ledgerPath, (_ledger, current) => {
    if (!current) throw new Error('publication transaction does not exist');
    if (current.state !== 'reserved') throw new Error('a committed or consumed publication transaction cannot become a generic failure');
    return { ...current, failed_at: observedAt, failure_stage: stage, previous_state: current.state, state: 'failed' };
  }, journalIo);
}

export function assertPostPublicationTerminalState(result) {
  if (!result || typeof result !== 'object' || result.ok !== true || result.operation !== 'verify_reevaluation'
      || result.currentProofResults !== 1 || result.proofCurrentness !== 'CURRENT'
      || result.actionState !== 'PROCEED' || !IRI.test(result.selectedAggregateResult || '')
      || !SHA256.test(result.evaluatedAuthorityDigest || '') || !SHA256.test(result.authorityAfterDigest || '')
      || !SHA256.test(result.executionReceiptDigest || '') || !SHA256.test(result.evaluationReceiptDigest || '')) {
    throw new Error('post-publication reevaluation did not reach the exact aggregate CURRENT/PROCEED terminal state');
  }
  return result;
}

export function assertSemanticProofPublicationReceipt(receipt) {
  exactObject(receipt, RECEIPT_FIELDS, 'semantic proof publication receipt');
  canonicalUtcSecond(receipt.published_at, 'published_at');
  const commonDigests = [
    receipt.authority_before_digest, receipt.authority_publication_digest, receipt.authority_after_digest,
    receipt.candidate_digest, receipt.source_scope_digest, receipt.owner_assignment_envelope_digest,
    receipt.candidate_approval_envelope_digest, receipt.publication_grant_envelope_digest,
  ];
  if (receipt.protocol !== SEMANTIC_PROOF_PROTOCOL || receipt.schema_version !== 1
      || receipt.grant_consumed !== true || !NONCE.test(receipt.grant_nonce)
      || !commonDigests.every((item) => SHA256.test(item))
      || receipt.committed_candidate_state !== 'COMMITTED') {
    throw new Error('semantic proof publication receipt is invalid or incomplete');
  }
  if (receipt.publication_phase === 'initial') {
    if (receipt.terminal_state !== 'PENDING' || receipt.publication_outcome !== 'committed_pending_reevaluation'
        || receipt.authority_after_digest !== receipt.authority_publication_digest
        || receipt.current_proof_results !== 0 || receipt.proof_currentness !== 'PENDING'
        || receipt.action_state !== 'UNRESOLVED_FAIL_CLOSED' || receipt.selected_aggregate_result !== null
        || receipt.direct_provisional_aggregate_selections !== 1
        || !IRI.test(receipt.selected_provisional_aggregate_result || '')
        || !SHA256.test(receipt.projection_observation_receipt_digest || '')
        || receipt.reevaluation_authority_digest !== null
        || receipt.reevaluation_execution_receipt_digest !== null
        || receipt.reevaluation_evaluation_receipt_digest !== null) {
      throw new Error('initial publication receipt is not the exact fail-closed PENDING state');
    }
  } else if (receipt.publication_phase === 'reevaluation') {
    if (receipt.terminal_state !== 'PROCEED' || receipt.publication_outcome !== 'accepted'
        || receipt.reevaluation_authority_digest !== receipt.authority_before_digest
        || ![receipt.reevaluation_execution_receipt_digest, receipt.reevaluation_evaluation_receipt_digest]
          .every((item) => SHA256.test(item))
        || receipt.current_proof_results !== 1 || receipt.proof_currentness !== 'CURRENT'
        || receipt.action_state !== 'PROCEED' || !IRI.test(receipt.selected_aggregate_result || '')) {
      throw new Error('reevaluation publication receipt is not the exact aggregate CURRENT/PROCEED state');
    }
    if (receipt.direct_provisional_aggregate_selections !== 0
        || receipt.selected_provisional_aggregate_result !== null
        || receipt.projection_observation_receipt_digest !== null) {
      throw new Error('reevaluation publication receipt retained invalid provisional projection state');
    }
  } else {
    throw new Error('semantic proof publication receipt phase is invalid');
  }
  return receipt;
}

export const semanticProofV1Internals = Object.freeze({
  assertApprovedAuthorityScope,
  assertApprovedTrustAnchorScopeSet,
  assertRootOwnedReadOnlyFile,
  assertRootOwnedExecutable,
  assertTrustAnchor,
  REAL_JOURNAL_IO,
  REAL_METADATA_IO,
  defaultDetachedVerifier,
  exactObject,
  stable,
  verifyDetachedWithGpgv,
});
