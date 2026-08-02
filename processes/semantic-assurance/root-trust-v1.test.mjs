import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  ANCHOR_PROTOCOL,
  FINGERPRINT,
  INSTALL_GRANT_SCHEMA,
  PRINCIPAL,
  PROTOCOL,
  ROLLBACK_GRANT_SCHEMA,
  SIGNING_IDENTITY,
  assertAdditiveTransition,
  assertAnchor,
  atomicWrite,
  buildAdditiveAnchor,
  canonicalBytes,
  canonicalContentDigest,
  canonicalJson,
  initializeRegistry,
  installAnchor,
  readRegistry,
  rollbackAnchor,
  rootTrustInternals,
  sha256,
  verifyInstalledAnchor,
  verifySignedEnvelope,
} from './root-trust-v1.mjs';

const NOW = '2026-08-02T13:00:00Z';
const signature = '-----BEGIN PGP SIGNATURE-----\ntest-only\n-----END PGP SIGNATURE-----\n';
const validSignature = () => FINGERPRINT;
const d = (label) => sha256(Buffer.from(label, 'utf8'));

const baseAnchor = () => ({
  algorithm: 'openpgp',
  approvalThreshold: 1,
  authorityScopes: [
    { authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane', repository: 'maldous/usf-factory' },
    { authorityDomain: 'urn:usf:capabilityowner:semanticmodelcompilation', repository: 'maldous/usf-graph' },
  ],
  fingerprint: FINGERPRINT,
  githubPrincipal: 'maldous',
  principal: PRINCIPAL,
  protocol: ANCHOR_PROTOCOL,
});

const third = {
  authorityDomain: 'urn:usf:capabilityowner:factoryproviderdurablecontrolplane',
  repository: 'maldous/usf-factory',
};

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), 'usf-root-trust-test-'));
  chmodSync(root, 0o700);
  const anchorPath = join(root, 'semantic-authority.json');
  writeFileSync(anchorPath, canonicalBytes(baseAnchor()), { mode: 0o444 });
  const governanceRoot = join(root, 'root-trust-v1');
  initializeRegistry(anchorPath, governanceRoot, '2026-08-02T12:59:00Z', root);
  return { anchorPath, governanceRoot, root };
}

function evidence(label = 'genesis') {
  return {
    admission_path_source_scope_digest: d(`${label}:admission-path`),
    admission_receipt_digest: d(`${label}:admission-receipt`),
    installer_source_scope_digest: d(`${label}:installer`),
    option_evaluation_digest: d(`${label}:evaluation`),
    owner_decision_digest: d(`${label}:decision`),
    validation_evidence_digest: d(`${label}:validation`),
    validation_producer_source_scope_digest: d(`${label}:producer`),
  };
}

function installGrant({ anchorPath, candidate, current, currentVersion, effect, extension, label, resultingVersion, root }) {
  const bound = evidence(label);
  return {
    evidence: bound,
    envelope: {
      payload: {
        admission_path_source_scope_digest: bound.admission_path_source_scope_digest,
        admission_receipt_digest: bound.admission_receipt_digest,
        approved_extension: extension,
        authority_effect: effect,
        expires_at: '2026-08-02T14:00:00Z',
        fingerprint: FINGERPRINT,
        installer_source_scope_digest: bound.installer_source_scope_digest,
        issued_at: '2026-08-02T12:00:00Z',
        nonce: label === 'genesis' ? '11111111-1111-4111-8111-111111111111'
          : label === 'extension' ? '22222222-2222-4222-8222-222222222222'
            : label === 'restore' ? '44444444-4444-4444-8444-444444444444'
              : '55555555-5555-4555-8555-555555555555',
        nonclaims: ['no unrestricted semantic authority', 'no arbitrary repository authority'],
        operation: 'install-root-trust-anchor',
        option_evaluation_digest: bound.option_evaluation_digest,
        owner_decision_digest: bound.owner_decision_digest,
        predecessor_anchor_content_digest: canonicalContentDigest(current),
        predecessor_anchor_file_digest: sha256(canonicalBytes(current)),
        predecessor_version: currentVersion,
        principal: PRINCIPAL,
        protocol: PROTOCOL,
        resulting_anchor_content_digest: canonicalContentDigest(candidate),
        resulting_anchor_file_digest: sha256(canonicalBytes(candidate)),
        resulting_version: resultingVersion,
        schema: INSTALL_GRANT_SCHEMA,
        signing_identity: SIGNING_IDENTITY,
        single_use: true,
        status: 'approved-single-use',
        target_anchor_path: anchorPath,
        target_installation_root: root,
        validation_evidence_digest: bound.validation_evidence_digest,
        validation_producer_source_scope_digest: bound.validation_producer_source_scope_digest,
      },
      signature,
    },
  };
}

function install(s, grant, candidate, fault = null) {
  return installAnchor({
    ...s,
    candidateBytes: canonicalBytes(candidate),
    evidence: grant.evidence,
    fault,
    grantEnvelope: grant.envelope,
    installedAt: NOW,
    signatureVerifier: validSignature,
    trustRoot: s.root,
  });
}

test('canonical anchor bytes and digests are deterministic', () => {
  const first = baseAnchor();
  const second = { principal: PRINCIPAL, ...first };
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.equal(sha256(canonicalBytes(first)), sha256(canonicalBytes(second)));
  assert.equal(assertAnchor(first), first);
});

test('builder permits exactly one bounded additive pair and preserves predecessors', () => {
  const candidate = buildAdditiveAnchor(baseAnchor(), third);
  const transition = assertAdditiveTransition(baseAnchor(), candidate, third);
  assert.equal(transition.preserved, 2);
  assert.deepEqual(transition.additions, [third]);
  assert.throws(() => buildAdditiveAnchor(candidate, third), /duplicate or conflicting/);
  assert.throws(() => buildAdditiveAnchor(baseAnchor(), {
    authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane', repository: 'maldous/other',
  }), /duplicate or conflicting/);
});

test('mutation, deletion, an extra fourth pair and malformed pairs fail closed', () => {
  const base = baseAnchor();
  const candidate = buildAdditiveAnchor(base, third);
  assert.throws(() => assertAdditiveTransition(base, { ...candidate, principal: 'urn:usf:principal:other' }, third), /identity or protocol/);
  assert.throws(() => assertAdditiveTransition(base, { ...base, authorityScopes: base.authorityScopes.slice(1) }, null), /deletion or mutation/);
  const fourth = { authorityDomain: 'urn:usf:capabilityowner:unauthorizedfourth', repository: 'maldous/other' };
  assert.throws(() => assertAdditiveTransition(base, {
    ...candidate, authorityScopes: [...candidate.authorityScopes, fourth].sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b))),
  }, third), /broader than/);
  assert.throws(() => buildAdditiveAnchor(base, { authorityDomain: 'not-an-iri', repository: '../escape' }), /bounded/);
});

test('signed grants reject invalid signer, stale time, wrong identity and unknown fields', () => {
  const s = sandbox();
  const grant = installGrant({
    ...s, candidate: baseAnchor(), current: baseAnchor(), currentVersion: 0,
    effect: 'governed-root-trust-lifecycle-installation', extension: null, label: 'genesis', resultingVersion: 1,
  }).envelope;
  assert.throws(() => verifySignedEnvelope(grant, {
    now: new Date(NOW), operation: 'install-root-trust-anchor', schema: INSTALL_GRANT_SCHEMA,
    signatureVerifier: () => 'A'.repeat(40),
  }), /bound identity/);
  assert.throws(() => verifySignedEnvelope({ ...grant, payload: { ...grant.payload, expires_at: '2026-08-02T12:30:00Z' } }, {
    now: new Date(NOW), operation: 'install-root-trust-anchor', schema: INSTALL_GRANT_SCHEMA, signatureVerifier: validSignature,
  }), /stale or premature/);
  assert.throws(() => verifySignedEnvelope({ ...grant, payload: { ...grant.payload, principal: 'urn:usf:principal:other' } }, {
    now: new Date(NOW), operation: 'install-root-trust-anchor', schema: INSTALL_GRANT_SCHEMA, signatureVerifier: validSignature,
  }), /identity or operation/);
  assert.throws(() => verifySignedEnvelope({ ...grant, payload: { ...grant.payload, unexpected: true } }, {
    now: new Date(NOW), operation: 'install-root-trust-anchor', schema: INSTALL_GRANT_SCHEMA, signatureVerifier: validSignature,
  }), /closed contract/);
});

test('predecessor, admitted evidence and temporary read-back mismatches fail closed', () => {
  const s = sandbox();
  const grant = installGrant({
    ...s, candidate: baseAnchor(), current: baseAnchor(), currentVersion: 0,
    effect: 'governed-root-trust-lifecycle-installation', extension: null, label: 'genesis', resultingVersion: 1,
  });
  const wrongPredecessor = {
    ...grant,
    envelope: {
      ...grant.envelope,
      payload: { ...grant.envelope.payload, predecessor_anchor_file_digest: d('wrong-predecessor') },
    },
  };
  assert.throws(() => install(s, wrongPredecessor, baseAnchor()), /exact predecessor and candidate/);
  assert.throws(() => install(s, { ...grant, evidence: { ...grant.evidence, admission_receipt_digest: d('wrong-admission') } }, baseAnchor()), /evidence mismatch/);
  const target = join(s.root, 'read-back-mismatch');
  assert.throws(() => atomicWrite(target, Buffer.from('approved'), {
    fault: 'temporary-read-back-mismatch', root: s.root,
  }), /read-back mismatch/);
  assert.equal(existsSync(target), false);
});

test('atomic writer refuses traversal and symlinks and removes interrupted temporary state', () => {
  const s = sandbox();
  const safe = join(s.root, 'safe');
  mkdirSync(safe, { mode: 0o700 });
  assert.throws(() => atomicWrite(join(s.root, '..', 'escape'), Buffer.from('x'), { root: s.root }), /escapes/);
  const target = join(safe, 'target');
  if (typeof process.permission?.has === 'function') {
    assert.throws(() => rootTrustInternals.assertNotSymbolicLink({ isSymbolicLink: () => true }, 'atomic target'), /symlink/);
  } else {
    symlinkSync('/tmp', target);
    assert.throws(() => atomicWrite(target, Buffer.from('x'), { root: s.root }), /symlink/);
  }
  assert.throws(() => atomicWrite(join(safe, 'interrupted'), Buffer.from('x'), { fault: 'before-rename', root: s.root }), /interruption/);
  assert.equal(existsSync(join(safe, 'interrupted')), false);
  assert.equal(lstatSync(safe).isDirectory(), true);
});

test('genesis installation, bounded extension, replay rejection, rollback and restore are exact', () => {
  const s = sandbox();
  const genesis = installGrant({
    ...s, candidate: baseAnchor(), current: baseAnchor(), currentVersion: 0,
    effect: 'governed-root-trust-lifecycle-installation', extension: null, label: 'genesis', resultingVersion: 1,
  });
  const installedGenesis = install(s, genesis, baseAnchor());
  assert.equal(installedGenesis.receipt.read_back_verified, true);
  assert.equal(verifyInstalledAnchor({ ...s, trustRoot: s.root }).version, 1);
  assert.throws(() => install(s, genesis, baseAnchor()), /replayed/);

  const extended = buildAdditiveAnchor(baseAnchor(), third);
  const extension = installGrant({
    ...s, candidate: extended, current: baseAnchor(), currentVersion: 1,
    effect: 'bounded-trust-scope-installation', extension: third, label: 'extension', resultingVersion: 2,
  });
  install(s, extension, extended);
  assert.equal(verifyInstalledAnchor({ ...s, trustRoot: s.root }).version, 2);
  assert.equal(verifyInstalledAnchor({ ...s, trustRoot: s.root }).anchor.authorityScopes.length, 3);

  const rollback = {
    payload: {
      authority_effect: 'immediately-previous-anchor-rollback',
      current_anchor_file_digest: sha256(canonicalBytes(extended)),
      current_version: 2,
      expires_at: '2026-08-02T14:00:00Z',
      fingerprint: FINGERPRINT,
      issued_at: '2026-08-02T12:00:00Z',
      nonce: '33333333-3333-4333-8333-333333333333',
      nonclaims: ['no arbitrary downgrade', 'no historical deletion'],
      operation: 'rollback-root-trust-anchor',
      principal: PRINCIPAL,
      protocol: PROTOCOL,
      reason_digest: d('isolated-rehearsal'),
      rollback_anchor_file_digest: sha256(canonicalBytes(baseAnchor())),
      rollback_to_version: 1,
      schema: ROLLBACK_GRANT_SCHEMA,
      signing_identity: SIGNING_IDENTITY,
      single_use: true,
      status: 'approved-single-use',
      target_anchor_path: s.anchorPath,
      target_installation_root: s.root,
    },
    signature,
  };
  assert.throws(() => rollbackAnchor({
    ...s,
    grantEnvelope: { ...rollback, payload: { ...rollback.payload, target_anchor_path: join(s.root, 'other-anchor') } },
    rolledBackAt: NOW,
    signatureVerifier: validSignature,
    trustRoot: s.root,
  }), /immediately previous verified anchor/);
  const rolledBack = rollbackAnchor({
    ...s, grantEnvelope: rollback, rolledBackAt: NOW, signatureVerifier: validSignature, trustRoot: s.root,
  });
  assert.equal(rolledBack.receipt.read_back_verified, true);
  assert.equal(verifyInstalledAnchor({ ...s, trustRoot: s.root }).version, 1);
  assert.equal(readRegistry(s.governanceRoot, s.root).versions.length, 3);
  assert.throws(() => rollbackAnchor({
    ...s, grantEnvelope: rollback, rolledBackAt: NOW, signatureVerifier: validSignature, trustRoot: s.root,
  }), /replayed/);

  const restore = installGrant({
    ...s, candidate: extended, current: baseAnchor(), currentVersion: 1,
    effect: 'bounded-trust-scope-installation', extension: third, label: 'restore', resultingVersion: 3,
  });
  install(s, restore, extended);
  const final = verifyInstalledAnchor({ ...s, trustRoot: s.root });
  assert.equal(final.version, 3);
  assert.equal(final.fileDigest, sha256(canonicalBytes(extended)));
  assert.equal(readRegistry(s.governanceRoot, s.root).versions.length, 4);
});

for (const fault of ['before-rename', 'after-rename']) {
  test(`interrupted ${fault} installation leaves predecessor active and no partial version`, () => {
    const s = sandbox();
    const genesis = installGrant({
      ...s, candidate: baseAnchor(), current: baseAnchor(), currentVersion: 0,
      effect: 'governed-root-trust-lifecycle-installation', extension: null, label: 'genesis', resultingVersion: 1,
    });
    install(s, genesis, baseAnchor());
    const extended = buildAdditiveAnchor(baseAnchor(), third);
    const grant = installGrant({
      ...s, candidate: extended, current: baseAnchor(), currentVersion: 1,
      effect: 'bounded-trust-scope-installation', extension: third, label: 'interrupted', resultingVersion: 2,
    });
    const before = readFileSync(s.anchorPath);
    assert.throws(() => install(s, grant, extended, fault), /interruption/);
    assert.deepEqual(readFileSync(s.anchorPath), before);
    assert.equal(readRegistry(s.governanceRoot, s.root).current_version, 1);
    assert.equal(existsSync(join(s.governanceRoot, 'versions', '000002.json')), false);
  });
}
