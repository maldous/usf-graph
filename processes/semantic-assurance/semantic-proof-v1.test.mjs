import assert from 'node:assert/strict';
import test from 'node:test';

import {
  APPROVED_AUTHORITY_SCOPES,
  AUTHORITY_FINGERPRINT,
  AUTHORITY_PRINCIPAL,
  AUTHORITY_SIGNING_IDENTITY,
  GPGV_EXECUTABLE,
  assertSemanticProofPublicationReceipt,
  canonicalJson,
  consumeGrantNonce,
  ownerAssignmentCandidateDigest,
  publicationReceiptDigest,
  recordPostPublicationReevaluation,
  recordPublicationOutcome,
  reserveGrantNonce,
  semanticProofV1Internals,
  sha256,
  sourceScopeDigest,
  verifyEnvelope,
  verifyPublicationBundle,
} from './semantic-proof-v1.mjs';
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, rmdirSync, symlinkSync, unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const DOMAIN = 'urn:usf:capabilityowner:semanticmodelcompilation';
const REPOSITORY = 'maldous/usf-graph';
const PATHS = ['processes/semantic-assurance/semantic-proof-v1.mjs', 'semantic-model/ontology.ttl'];
const PRE = `sha256:${'1'.repeat(64)}`;
const CANDIDATE = `sha256:${'2'.repeat(64)}`;
const PUBLISHED = `sha256:${'3'.repeat(64)}`;
const AFTER = `sha256:${'4'.repeat(64)}`;
const EXECUTION = `sha256:${'5'.repeat(64)}`;
const EVALUATION = `sha256:${'6'.repeat(64)}`;
const NOW = new Date('2026-08-01T12:00:00Z');
const permissionModelActive = typeof process.permission?.has === 'function';
const anchor = Object.freeze({
  algorithm: 'openpgp', approvalThreshold: 1, fingerprint: AUTHORITY_FINGERPRINT,
  githubPrincipal: 'maldous', principal: AUTHORITY_PRINCIPAL, protocol: 'semantic-proof-v1',
  authorityScopes: APPROVED_AUTHORITY_SCOPES,
});
const signature = '-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n';
const verifyDetached = () => AUTHORITY_FINGERPRINT;
const nonce = (digit) => `00000000-0000-4000-8000-00000000000${digit}`;

function runGpg(args, options = {}) {
  const result = spawnSync('/usr/bin/gpg', args, {
    ...options,
    env: { ...process.env, LANG: 'C', LC_ALL: 'C', ...(options.env || {}) },
  });
  assert.equal(result.status, 0, `gpg failed: ${String(result.stderr || '').trim()}`);
  return result;
}

function ephemeralSigner(root, label) {
  const home = join(root, `${label}-gnupg`);
  const keyring = join(root, `${label}-public.gpg`);
  const user = `Semantic Proof v1 ${label} <${label}@invalid.example>`;
  mkdirSync(home, { mode: 0o700 });
  runGpg([
    '--homedir', home, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
    '--quick-generate-key', user, 'rsa2048', 'sign', '0',
  ]);
  const listing = runGpg([
    '--homedir', home, '--batch', '--with-colons', '--fingerprint', '--list-secret-keys', user,
  ], { encoding: 'utf8' }).stdout;
  const fingerprint = listing.split('\n').find((line) => line.startsWith('fpr:'))?.split(':')[9];
  assert.match(fingerprint || '', /^[0-9A-F]{40}$/);
  const exported = runGpg(['--homedir', home, '--batch', '--export', fingerprint]).stdout;
  writeFileSync(keyring, exported, { mode: 0o600, flag: 'wx' });
  return { fingerprint, home, keyring };
}

function detachedSignature(signer, payloadBytes, root, label) {
  const payloadPath = join(root, `${label}.json`);
  const signaturePath = join(root, `${label}.asc`);
  writeFileSync(payloadPath, payloadBytes, { mode: 0o600, flag: 'wx' });
  runGpg([
    '--homedir', signer.home, '--batch', '--yes', '--armor', '--detach-sign',
    '--local-user', signer.fingerprint, '--output', signaturePath, payloadPath,
  ]);
  return readFileSync(signaturePath, 'utf8');
}

function memoryJournalIo(ledgerPath) {
  let contents = '{"nonces":{},"protocol":"semantic-proof-v1"}\n';
  let locked = false;
  return {
    ensureDirectory: () => {},
    read: (path) => {
      assert.equal(path, ledgerPath);
      return contents;
    },
    withLock: (path, callback) => {
      assert.equal(path, ledgerPath);
      assert.equal(locked, false, 'deterministic journal lock must not be re-entered');
      locked = true;
      try { return callback(); } finally { locked = false; }
    },
    write: (path, value) => {
      assert.equal(path, ledgerPath);
      contents = value;
    },
  };
}

const executableMetadataIo = Object.freeze({
  lstat: () => ({ mode: 0o100755, uid: 0 }),
  realpath: (path) => path,
  stat: () => ({ isFile: () => true, mode: 0o100755, uid: 0 }),
});

function envelope(claimType, overrides = {}) {
  return {
    payload: {
      algorithm: 'openpgp', authority_domain: DOMAIN, authority_pre_digest: PRE,
      candidate_digest: CANDIDATE, claim_type: claimType, expires_at: '2026-08-02T12:00:00Z',
      fingerprint: AUTHORITY_FINGERPRINT, issued_at: '2026-08-01T11:00:00Z', nonce: nonce('1'),
      principal: AUTHORITY_PRINCIPAL, protocol: 'semantic-proof-v1', repository: REPOSITORY,
      signing_identity: AUTHORITY_SIGNING_IDENTITY, single_use: claimType === 'publication_grant',
      source_scope_digest: sourceScopeDigest(PATHS), ...overrides,
    },
    signature,
  };
}

const verify = (value, options = {}) => verifyEnvelope(value, {
  trustAnchor: anchor, verifyDetached, claimType: value.payload.claim_type, authorityDomain: DOMAIN,
  repository: REPOSITORY, sourcePaths: PATHS, authorityPreDigest: PRE, candidateDigest: CANDIDATE,
  expectedSingleUse: value.payload.claim_type === 'publication_grant', now: NOW, ...options,
});

function terminalReceipt(grant, publicationPhase = 'reevaluation') {
  const terminal = publicationPhase === 'reevaluation';
  return {
    action_state: terminal ? 'PROCEED' : 'UNRESOLVED_FAIL_CLOSED',
    authority_after_digest: terminal ? AFTER : PUBLISHED, authority_before_digest: PRE,
    authority_domain: DOMAIN, authority_publication_digest: PUBLISHED,
    candidate_approval_envelope_digest: sha256('approval'), candidate_digest: CANDIDATE,
    committed_candidate_state: 'COMMITTED', current_proof_results: terminal ? 1 : 0,
    direct_provisional_aggregate_selections: terminal ? 0 : 1, grant_consumed: true,
    grant_nonce: grant.nonce, owner_assignment_envelope_digest: sha256('assignment'),
    proof_currentness: terminal ? 'CURRENT' : 'PENDING', protocol: 'semantic-proof-v1',
    projection_observation_receipt_digest: terminal ? null : sha256('initial-observation'),
    publication_grant_envelope_digest: grant.envelope_digest,
    publication_outcome: terminal ? 'accepted' : 'committed_pending_reevaluation',
    publication_phase: publicationPhase,
    published_at: '2026-08-01T12:00:00Z',
    reevaluation_authority_digest: terminal ? PRE : null,
    reevaluation_evaluation_receipt_digest: terminal ? EVALUATION : null,
    reevaluation_execution_receipt_digest: terminal ? EXECUTION : null,
    repository: REPOSITORY, schema_version: 1,
    selected_aggregate_result: terminal ? 'urn:usf:proofresult:aggregatecompilerproof' : null,
    selected_provisional_aggregate_result: terminal ? null : 'urn:usf:proofresult:provisionalaggregatecompilerproof',
    source_scope_digest: sourceScopeDigest(PATHS),
    terminal_state: terminal ? 'PROCEED' : 'PENDING',
  };
}

test('approved signer is accepted through the one canonical envelope', () => {
  assert.equal(verify(envelope('candidate_approval')).fingerprint, AUTHORITY_FINGERPRINT);
  assert.equal(canonicalJson({ b: 2, a: 1 }), '{"a":1,"b":2}');
});

test('unknown and integrity-only signers cannot establish authority', () => {
  assert.throws(() => verify(envelope('candidate_approval'), { verifyDetached: () => 'A'.repeat(40) }), /unknown or integrity-only/);
  assert.throws(() => verify(envelope('candidate_approval', { fingerprint: 'D3E5E55B71044AECC0143EF490B67F399DC49FC6' })), /not the external trust anchor/);
});

test('tampering and scope substitutions fail closed', () => {
  for (const [overrides, options, pattern] of [
    [{ candidate_digest: sha256('tampered') }, {}, /candidate digest mismatch/],
    [{ authority_pre_digest: sha256('tampered') }, {}, /authority pre-digest mismatch/],
    [{ repository: 'maldous/usf-factory' }, {}, /repository mismatch/],
    [{ source_scope_digest: sha256('tampered') }, {}, /source scope mismatch/],
    [{ algorithm: 'ed25519' }, {}, /not the external trust anchor/],
    [{ expires_at: '2026-08-01T12:00:00Z' }, {}, /not current/],
  ]) assert.throws(() => verify(envelope('candidate_approval', overrides), options), pattern);
});

test('owner domains are independently scoped and all three claim types use one verifier', () => {
  const assignment = envelope('owner_assignment', {
    candidate_digest: ownerAssignmentCandidateDigest({ authorityDomain: DOMAIN, principal: AUTHORITY_PRINCIPAL, repository: REPOSITORY, sourcePaths: PATHS }),
    nonce: nonce('1'), single_use: false,
  });
  const approval = envelope('candidate_approval', { nonce: nonce('2') });
  const grant = envelope('publication_grant', { nonce: nonce('3') });
  assert.equal(verifyPublicationBundle({
    ownerAssignment: assignment, candidateApproval: approval, publicationGrant: grant,
    trustAnchor: anchor, verifyDetached, authorityDomain: DOMAIN, repository: REPOSITORY,
    sourcePaths: PATHS, authorityPreDigest: PRE, candidateDigest: CANDIDATE, now: NOW,
  }).grant.nonce, nonce('3'));
  assert.throws(() => verifyPublicationBundle({
    ownerAssignment: assignment, candidateApproval: approval, publicationGrant: grant,
    trustAnchor: anchor, verifyDetached, authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane',
    repository: REPOSITORY, sourcePaths: PATHS, authorityPreDigest: PRE, candidateDigest: CANDIDATE, now: NOW,
  }), /not approved by the external trust anchor/);
});

test('external trust anchor pins exactly the two approved domain and repository pairs', () => {
  const factoryDomain = 'urn:usf:capabilityowner:providerconfigurationplane';
  const factoryRepository = 'maldous/usf-factory';
  const factoryPaths = ['factory/provider_catalog.py'];
  const factoryEnvelope = envelope('candidate_approval', {
    authority_domain: factoryDomain,
    repository: factoryRepository,
    source_scope_digest: sourceScopeDigest(factoryPaths),
  });
  assert.equal(verifyEnvelope(factoryEnvelope, {
    trustAnchor: anchor, verifyDetached, claimType: 'candidate_approval',
    authorityDomain: factoryDomain, repository: factoryRepository, sourcePaths: factoryPaths,
    authorityPreDigest: PRE, candidateDigest: CANDIDATE, expectedSingleUse: false, now: NOW,
  }).repository, factoryRepository);
  assert.throws(() => verifyEnvelope(factoryEnvelope, {
    trustAnchor: anchor, verifyDetached, claimType: 'candidate_approval',
    authorityDomain: factoryDomain, repository: REPOSITORY, sourcePaths: factoryPaths,
    authorityPreDigest: PRE, candidateDigest: CANDIDATE, expectedSingleUse: false, now: NOW,
  }), /not approved by the external trust anchor/);
  assert.throws(() => verify(envelope('candidate_approval'), {
    trustAnchor: { ...anchor, authorityScopes: [APPROVED_AUTHORITY_SCOPES[1]] },
  }), /must pin exactly/);
  assert.throws(() => verify(envelope('candidate_approval'), {
    trustAnchor: {
      ...anchor,
      authorityScopes: [...APPROVED_AUTHORITY_SCOPES, {
        authorityDomain: 'urn:usf:capabilityowner:unapproved', repository: 'maldous/unapproved',
      }],
    },
  }), /must pin exactly/);
});

test('real OpenPGP detached verification accepts the ephemeral signer and rejects tampering and a wrong key', () => {
  if (permissionModelActive) {
    const approvedFingerprint = 'A'.repeat(40);
    const approvedKeyring = 'deterministic:approved-keyring';
    const wrongKeyring = 'deterministic:wrong-keyring';
    const unsigned = envelope('candidate_approval', { fingerprint: approvedFingerprint });
    const payloadBytes = Buffer.from(`${canonicalJson(unsigned.payload)}\n`);
    const signed = { ...unsigned, signature };
    const deterministicVerifier = (bytes, detached, { publicKeyPath }) => {
      if (!bytes.equals(payloadBytes) || detached !== signature || publicKeyPath !== approvedKeyring) {
        throw new Error('OpenPGP signature verification failed: deterministic permission adapter rejected input');
      }
      return approvedFingerprint;
    };
    const options = {
      trustAnchor: { ...anchor, fingerprint: approvedFingerprint },
      publicKeyPath: approvedKeyring,
      verifyDetached: deterministicVerifier,
      claimType: 'candidate_approval', authorityDomain: DOMAIN, repository: REPOSITORY,
      sourcePaths: PATHS, authorityPreDigest: PRE, candidateDigest: CANDIDATE,
      expectedSingleUse: false, now: NOW,
    };
    assert.equal(verifyEnvelope(signed, options).fingerprint, approvedFingerprint);
    const tamperedDigest = sha256('cryptographic-tamper');
    assert.throws(() => verifyEnvelope({
      ...signed, payload: { ...signed.payload, candidate_digest: tamperedDigest },
    }, { ...options, candidateDigest: tamperedDigest }), /OpenPGP signature verification failed/);
    assert.throws(() => verifyEnvelope(signed, {
      ...options, publicKeyPath: wrongKeyring,
    }), /OpenPGP signature verification failed/);
    return;
  }
  const root = mkdtempSync(join(tmpdir(), 'semantic-proof-openpgp-test-'));
  try {
    const approved = ephemeralSigner(root, 'approved');
    const wrong = ephemeralSigner(root, 'wrong');
    const unsigned = envelope('candidate_approval', { fingerprint: approved.fingerprint });
    const payloadBytes = Buffer.from(`${canonicalJson(unsigned.payload)}\n`);
    const signed = { ...unsigned, signature: detachedSignature(approved, payloadBytes, root, 'approved-payload') };
    const testAnchor = { ...anchor, fingerprint: approved.fingerprint };
    const actualVerifier = (bytes, detached, { publicKeyPath }) => (
      semanticProofV1Internals.verifyDetachedWithGpgv(bytes, detached, { publicKeyPath })
    );
    const options = {
      trustAnchor: testAnchor, publicKeyPath: approved.keyring, verifyDetached: actualVerifier,
      claimType: 'candidate_approval', authorityDomain: DOMAIN, repository: REPOSITORY,
      sourcePaths: PATHS, authorityPreDigest: PRE, candidateDigest: CANDIDATE,
      expectedSingleUse: false, now: NOW,
    };
    assert.equal(verifyEnvelope(signed, options).fingerprint, approved.fingerprint);
    const tamperedDigest = sha256('cryptographic-tamper');
    assert.throws(() => verifyEnvelope({
      ...signed, payload: { ...signed.payload, candidate_digest: tamperedDigest },
    }, { ...options, candidateDigest: tamperedDigest }), /OpenPGP signature verification failed/);
    assert.throws(() => verifyEnvelope(signed, {
      ...options, publicKeyPath: wrong.keyring,
    }), /OpenPGP signature verification failed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('gpgv verification is pinned to the root-controlled absolute executable', () => {
  const metadataIo = permissionModelActive ? executableMetadataIo : undefined;
  assert.equal(semanticProofV1Internals.assertRootOwnedExecutable(GPGV_EXECUTABLE, metadataIo), GPGV_EXECUTABLE);
  assert.throws(() => semanticProofV1Internals.assertRootOwnedExecutable('/tmp/gpgv'), /must be \/usr\/bin\/gpgv/);
});

test('publication journal is one-way and binds the final terminal receipt', () => {
  const directory = permissionModelActive ? null : mkdtempSync(join(tmpdir(), 'semantic-proof-ledger-'));
  const ledgerPath = permissionModelActive ? 'deterministic:semantic-proof-ledger' : join(directory, 'ledger.json');
  const journalIo = permissionModelActive ? memoryJournalIo(ledgerPath) : undefined;
  const journalOptions = journalIo ? { journalIo, ledgerPath } : { ledgerPath };
  if (!permissionModelActive) writeFileSync(ledgerPath, '{"nonces":{},"protocol":"semantic-proof-v1"}\n', { mode: 0o600 });
  const grant = verify(envelope('publication_grant'));
  assert.equal(reserveGrantNonce(grant, { ...journalOptions, publicationPhase: 'reevaluation' }).state, 'reserved');
  assert.throws(() => reserveGrantNonce(grant, { ...journalOptions, publicationPhase: 'reevaluation' }), /replayed or already entered/);
  assert.equal(recordPublicationOutcome(grant, {
    authorityPublicationDigest: PUBLISHED, committedCandidateState: 'COMMITTED',
    publishedAt: '2026-08-01T12:00:00Z', ...journalOptions,
  }).state, 'published_pending_reevaluation');
  assert.equal(recordPostPublicationReevaluation(grant, {
    ok: true, evaluatedAuthorityDigest: PRE, authorityAfterDigest: AFTER,
    operation: 'verify_reevaluation',
    executionReceiptDigest: EXECUTION, evaluationReceiptDigest: EVALUATION,
    selectedAggregateResult: 'urn:usf:proofresult:aggregatecompilerproof', currentProofResults: 1,
    proofCurrentness: 'CURRENT', actionState: 'PROCEED',
  }, journalOptions).state, 'reevaluated_pending_receipt');
  const receipt = terminalReceipt(grant);
  assert.equal(consumeGrantNonce(grant, { receipt, ...journalOptions }).state, 'consumed');
  const ledger = journalIo ? journalIo.read(ledgerPath) : readFileSync(ledgerPath, 'utf8');
  assert.equal(JSON.parse(ledger).nonces[grant.nonce].final_receipt_digest, publicationReceiptDigest(receipt));
  assert.equal(consumeGrantNonce(grant, { receipt, ...journalOptions }).state, 'consumed');
  if (!permissionModelActive) {
    unlinkSync(ledgerPath);
    rmdirSync(directory);
  }
});

test('receipt verification rejects every non-terminal projection', () => {
  const grant = verify(envelope('publication_grant'));
  const receipt = terminalReceipt(grant);
  assert.equal(assertSemanticProofPublicationReceipt(receipt), receipt);
  for (const patch of [
    { grant_consumed: false }, { current_proof_results: 2 }, { proof_currentness: 'AMBIGUOUS' },
    { action_state: 'UNRESOLVED_FAIL_CLOSED' }, { publication_outcome: 'committed' },
    { reevaluation_authority_digest: AFTER },
  ]) assert.throws(() => assertSemanticProofPublicationReceipt({ ...receipt, ...patch }), /CURRENT\/PROCEED|invalid or incomplete/);
  const pending = terminalReceipt(grant, 'initial');
  assert.equal(assertSemanticProofPublicationReceipt(pending), pending);
  assert.throws(() => assertSemanticProofPublicationReceipt({ ...pending, action_state: 'PROCEED' }), /fail-closed PENDING/);
  const { published_at: _missing, ...missingTimestamp } = pending;
  assert.throws(() => assertSemanticProofPublicationReceipt(missingTimestamp), /fields are not the closed protocol contract/);
  assert.throws(() => assertSemanticProofPublicationReceipt({ ...pending, published_at: '2026-08-01T12:00:00.000Z' }), /RFC3339 UTC second/);
  assert.throws(() => assertSemanticProofPublicationReceipt({ ...pending, published_at: '2026-08-01T24:00:00Z' }), /canonical RFC3339 UTC second/);
});

test('root-owned read-only trust material rejects noncanonical paths, writable files, and symlinks', () => {
  if (permissionModelActive) {
    const file = '/deterministic/trust/anchor.json';
    const link = '/deterministic/trust/anchor-link.json';
    let mode = 0o100600;
    const metadataIo = {
      lstat: (path) => ({
        gid: 0,
        isFile: () => path === file,
        isSymbolicLink: () => path === link,
        mode,
        uid: 0,
      }),
      realpath: (path) => path,
      stat: () => ({ isFile: () => true, mode: 0o100444, uid: 0 }),
    };
    assert.throws(() => semanticProofV1Internals.assertRootOwnedReadOnlyFile(
      file, '/canonical/anchor.json', 'anchor', metadataIo,
    ), /canonical path/);
    assert.throws(() => semanticProofV1Internals.assertRootOwnedReadOnlyFile(
      file, file, 'anchor', metadataIo,
    ), /mode 0444/);
    mode = 0o100444;
    assert.equal(semanticProofV1Internals.assertRootOwnedReadOnlyFile(
      file, file, 'anchor', metadataIo,
    ), file);
    assert.throws(() => semanticProofV1Internals.assertRootOwnedReadOnlyFile(
      link, link, 'anchor', metadataIo,
    ), /regular non-symlink/);
    return;
  }
  const directory = mkdtempSync(join(tmpdir(), 'semantic-trust-test-'));
  const file = join(directory, 'anchor.json');
  const link = join(directory, 'anchor-link.json');
  writeFileSync(file, '{}\n', { mode: 0o600 });
  assert.throws(() => semanticProofV1Internals.assertRootOwnedReadOnlyFile(file, '/canonical/anchor.json', 'anchor'), /canonical path/);
  assert.throws(() => semanticProofV1Internals.assertRootOwnedReadOnlyFile(file, file, 'anchor'), /mode 0444/);
  chmodSync(file, 0o444);
  assert.equal(semanticProofV1Internals.assertRootOwnedReadOnlyFile(file, file, 'anchor'), file);
  symlinkSync(file, link);
  assert.throws(() => semanticProofV1Internals.assertRootOwnedReadOnlyFile(link, link, 'anchor'), /regular non-symlink/);
  unlinkSync(link);
  unlinkSync(file);
  rmdirSync(directory);
});
