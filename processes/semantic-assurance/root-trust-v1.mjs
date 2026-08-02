import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

export const ROOT_TRUST_SCHEMA = 'usf-root-trust-lifecycle-v1';
export const REGISTRY_SCHEMA = 'usf-root-trust-version-registry-v1';
export const INSTALL_GRANT_SCHEMA = 'usf-root-trust-installation-grant-v1';
export const ROLLBACK_GRANT_SCHEMA = 'usf-root-trust-rollback-grant-v1';
export const INSTALL_RECEIPT_SCHEMA = 'usf-root-trust-installation-receipt-v1';
export const ROLLBACK_RECEIPT_SCHEMA = 'usf-root-trust-rollback-receipt-v1';
export const PRINCIPAL = 'urn:usf:principal:matthewaldous';
export const SIGNING_IDENTITY = 'urn:usf:signingidentity:matthewaldoussemanticproofv1';
export const FINGERPRINT = 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D';
export const PROTOCOL = 'urn:usf:semanticproofprotocol:v1';
export const ANCHOR_PROTOCOL = 'semantic-proof-v1';
export const PUBLIC_KEY = '/var/lib/usf-programme/trust/semantic-authority-public-key.gpg';
export const TRUST_ROOT = '/var/lib/usf-programme/trust';
export const ANCHOR_PATH = '/var/lib/usf-programme/trust/semantic-authority.json';
export const GOVERNANCE_ROOT = '/var/lib/usf-programme/trust/root-trust-v1';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DOMAIN = /^urn:usf:capabilityowner:[a-z0-9]+$/;
const REPOSITORY = /^[a-z0-9-]+\/[a-z0-9-]+$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const utf8 = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8).map((key) => [key, stable(value[key])]))
    : value;

export const canonicalJson = (value) => JSON.stringify(stable(value));
export const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
export const canonicalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
export const canonicalContentDigest = (value) => sha256(Buffer.from(canonicalJson(value), 'utf8'));

function exactObject(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  if (canonicalJson(Object.keys(value).sort(utf8)) !== canonicalJson([...fields].sort(utf8))) {
    throw new Error(`${label} fields are not the closed contract`);
  }
  return value;
}

function digest(value, label) {
  if (!SHA256.test(value || '')) throw new Error(`${label} must be an exact sha256 digest`);
  return value;
}

function instant(value, label) {
  if (!RFC3339.test(value || '') || Number.isNaN(Date.parse(value))) throw new Error(`${label} must be RFC3339 UTC seconds`);
  return value;
}

export function assertScope(scope) {
  exactObject(scope, ['authorityDomain', 'repository'], 'authority scope');
  if (!DOMAIN.test(scope.authorityDomain) || !REPOSITORY.test(scope.repository)) {
    throw new Error('authority scope is not a bounded domain/repository pair');
  }
  return scope;
}

export function assertAnchor(anchor) {
  exactObject(anchor, [
    'algorithm', 'approvalThreshold', 'authorityScopes', 'fingerprint', 'githubPrincipal',
    'principal', 'protocol',
  ], 'trust anchor');
  if (anchor.protocol !== ANCHOR_PROTOCOL || anchor.principal !== PRINCIPAL
      || anchor.githubPrincipal !== 'maldous' || anchor.fingerprint !== FINGERPRINT
      || anchor.algorithm !== 'openpgp' || anchor.approvalThreshold !== 1
      || !Array.isArray(anchor.authorityScopes) || anchor.authorityScopes.length < 1) {
    throw new Error('trust anchor identity or protocol binding is invalid');
  }
  const scopes = anchor.authorityScopes.map(assertScope);
  const ordered = [...scopes].sort((a, b) => utf8(canonicalJson(a), canonicalJson(b)));
  if (canonicalJson(scopes) !== canonicalJson(ordered)
      || new Set(scopes.map(canonicalJson)).size !== scopes.length) {
    throw new Error('trust anchor scopes must be canonical, unique and non-conflicting');
  }
  return anchor;
}

export function buildAdditiveAnchor(currentAnchor, extension) {
  assertAnchor(currentAnchor);
  assertScope(extension);
  if (currentAnchor.authorityScopes.some((scope) => scope.authorityDomain === extension.authorityDomain
      || scope.repository === extension.repository && scope.authorityDomain === extension.authorityDomain)) {
    throw new Error('duplicate or conflicting authority scope is refused');
  }
  const authorityScopes = [...currentAnchor.authorityScopes, { ...extension }]
    .sort((a, b) => utf8(canonicalJson(a), canonicalJson(b)));
  const candidate = Object.freeze({ ...currentAnchor, authorityScopes: Object.freeze(authorityScopes) });
  assertAdditiveTransition(currentAnchor, candidate, extension);
  return candidate;
}

export function assertAdditiveTransition(currentAnchor, candidateAnchor, approvedExtension = null) {
  assertAnchor(currentAnchor);
  assertAnchor(candidateAnchor);
  const fixed = ['algorithm', 'approvalThreshold', 'fingerprint', 'githubPrincipal', 'principal', 'protocol'];
  for (const field of fixed) {
    if (candidateAnchor[field] !== currentAnchor[field]) throw new Error(`trust anchor ${field} mutation is refused`);
  }
  const prior = new Set(currentAnchor.authorityScopes.map(canonicalJson));
  const next = new Set(candidateAnchor.authorityScopes.map(canonicalJson));
  for (const scope of prior) if (!next.has(scope)) throw new Error('deletion or mutation of an approved scope is refused');
  const additions = candidateAnchor.authorityScopes.filter((scope) => !prior.has(canonicalJson(scope)));
  if (approvedExtension === null) {
    if (additions.length !== 0) throw new Error('genesis candidate must preserve the existing anchor exactly');
  } else if (additions.length !== 1 || canonicalJson(additions[0]) !== canonicalJson(assertScope(approvedExtension))) {
    throw new Error('candidate is broader than the single approved scope extension');
  }
  return Object.freeze({ additions: Object.freeze(additions), preserved: prior.size });
}

function assertSafeDirectory(path, allowedRoot, { create = false } = {}) {
  const resolvedRoot = resolve(allowedRoot);
  const resolved = resolve(path);
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}/`)) throw new Error('path escapes the governed root');
  if (create) mkdirSync(resolved, { recursive: true, mode: 0o700 });
  let cursor = resolved;
  while (cursor.startsWith(resolvedRoot)) {
    const item = lstatSync(cursor);
    if (!item.isDirectory() || item.isSymbolicLink() || item.uid !== 0 || item.gid !== 0 || (item.mode & 0o022) !== 0) {
      throw new Error(`governed directory is unsafe: ${cursor}`);
    }
    if (cursor === resolvedRoot) break;
    cursor = dirname(cursor);
  }
  return resolved;
}

function assertRegular(path, { mode, label, root = TRUST_ROOT } = {}) {
  const resolved = resolve(path);
  if (relative(resolve(root), resolved).startsWith('..') || resolved === resolve(root)) throw new Error(`${label} escapes governed root`);
  const item = lstatSync(resolved);
  if (!item.isFile() || item.isSymbolicLink() || item.uid !== 0 || item.gid !== 0
      || mode !== undefined && (item.mode & 0o777) !== mode || realpathSync(resolved) !== resolved) {
    throw new Error(`${label} metadata is unsafe`);
  }
  return item;
}

function assertNotSymbolicLink(item, label) {
  if (item?.isSymbolicLink?.()) throw new Error(`${label} cannot be a symlink`);
  return item;
}

function hermeticFsyncDenialIsExpected(error, path, root) {
  if (error?.code !== 'ERR_ACCESS_DENIED' || typeof process.permission?.has !== 'function'
      || process.env.USF_HERMETIC_TEST_MODE !== '1') return false;
  const runtimeRoot = process.env.TMPDIR && resolve(process.env.TMPDIR);
  const governedRoot = resolve(root);
  const target = resolve(path);
  return runtimeRoot !== null && governedRoot.startsWith(`${runtimeRoot}/`)
    && (target === governedRoot || target.startsWith(`${governedRoot}/`));
}

function governedFsync(fd, path, root) {
  try {
    fsyncSync(fd);
  } catch (error) {
    // Node disables fsync under its Permission Model even when the containing
    // runtime directory is explicitly write-authorised. The repository's
    // immutable hermetic runner uses that model. Permit only its disposable
    // TMPDIR root to model the operation; the production trust root can never
    // enter this branch. Uncontained, non-hermetic and production calls retain
    // the mandatory real fsync.
    if (!hermeticFsyncDenialIsExpected(error, path, root)) throw error;
  }
}

function fsyncDirectory(path, root) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try { governedFsync(fd, path, root); } finally { closeSync(fd); }
}

export function atomicWrite(path, bytes, { mode = 0o444, fault = null, root = TRUST_ROOT } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new Error('atomic write requires non-empty bytes');
  const parent = assertSafeDirectory(dirname(path), root);
  const target = resolve(path);
  if (target !== resolve(parent, target.split('/').pop())) throw new Error('atomic target is not a direct governed child');
  if (existsSync(target)) assertNotSymbolicLink(lstatSync(target), 'atomic target');
  const temporary = `${target}.tmp-${process.pid}-${Date.now()}`;
  try {
    const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
    try {
      writeFileSync(fd, bytes);
      governedFsync(fd, temporary, root);
    } finally {
      closeSync(fd);
    }
    chmodSync(temporary, mode);
    if (fault === 'temporary-read-back-mismatch') {
      writeFileSync(temporary, Buffer.concat([bytes, Buffer.from('corrupt')]), { flag: 'r+' });
    }
    assertRegular(temporary, { mode, label: 'temporary installation file', root });
    if (sha256(readFileSync(temporary)) !== sha256(bytes)) throw new Error('temporary installation read-back mismatch');
    fsyncDirectory(parent, root);
    if (fault === 'before-rename') throw new Error('injected interruption before atomic rename');
    renameSync(temporary, target);
  } catch (error) {
    if (existsSync(temporary)) unlinkSync(temporary);
    fsyncDirectory(parent, root);
    throw error;
  }
  fsyncDirectory(parent, root);
  assertRegular(target, { mode, label: 'installed file', root });
  if (!readFileSync(target).equals(bytes)) throw new Error('installed bytes differ from approved bytes');
  return Object.freeze({ byteLength: bytes.length, digest: sha256(bytes), path: target });
}

function verifyDetached(payloadBytes, signature, publicKeyPath = PUBLIC_KEY) {
  if (!Buffer.isBuffer(payloadBytes) || payloadBytes.length === 0
      || typeof signature !== 'string' || !signature.includes('BEGIN PGP SIGNATURE')) {
    throw new Error('one detached OpenPGP signature is required');
  }
  assertRegular(publicKeyPath, { mode: 0o444, label: 'root trust public key' });
  const work = `/tmp/usf-root-trust-${process.pid}-${Date.now()}`;
  mkdirSync(work, { mode: 0o700 });
  const payloadPath = join(work, 'payload');
  const signaturePath = join(work, 'payload.asc');
  try {
    writeFileSync(payloadPath, payloadBytes, { flag: 'wx', mode: 0o600 });
    writeFileSync(signaturePath, signature, { flag: 'wx', mode: 0o600 });
    const result = spawnSync('/usr/bin/gpgv', ['--status-fd', '1', '--keyring', publicKeyPath, signaturePath, payloadPath], {
      encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C' },
    });
    if (result.status !== 0) throw new Error('root trust OpenPGP signature verification failed');
    const line = result.stdout.split('\n').find((item) => item.startsWith('[GNUPG:] VALIDSIG '));
    const observed = line?.split(' ')[2];
    if (observed !== FINGERPRINT) throw new Error('root trust signature is not from the bound identity');
    return observed;
  } finally {
    for (const path of [signaturePath, payloadPath]) if (existsSync(path)) {
      try { writeFileSync(path, Buffer.alloc(statSync(path).size), { flag: 'r+' }); } catch { /* public material only */ }
      try { requireRemoval(path); } catch { /* best effort */ }
    }
    try { requireDirectoryRemoval(work); } catch { /* best effort */ }
  }
}

function requireRemoval(path) {
  const result = spawnSync('/usr/bin/unlink', [path], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error('temporary public material cleanup failed');
}

function requireDirectoryRemoval(path) {
  const result = spawnSync('/usr/bin/rmdir', [path], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error('temporary directory cleanup failed');
}

export function verifySignedEnvelope(envelope, {
  now = new Date(), operation, publicKeyPath = PUBLIC_KEY, schema, signatureVerifier = verifyDetached,
} = {}) {
  exactObject(envelope, ['payload', 'signature'], 'root trust signed envelope');
  const payload = envelope.payload;
  const common = [
    'authority_effect', 'expires_at', 'fingerprint', 'issued_at', 'nonce', 'nonclaims', 'operation',
    'principal', 'protocol', 'schema', 'signing_identity', 'single_use', 'status',
  ];
  const schemaFields = schema === INSTALL_GRANT_SCHEMA ? [
    ...common, 'admission_path_source_scope_digest', 'admission_receipt_digest', 'approved_extension',
    'installer_source_scope_digest', 'option_evaluation_digest', 'owner_decision_digest',
    'predecessor_anchor_content_digest', 'predecessor_anchor_file_digest', 'predecessor_version',
    'resulting_anchor_content_digest', 'resulting_anchor_file_digest', 'resulting_version',
    'target_anchor_path', 'target_installation_root', 'validation_evidence_digest',
    'validation_producer_source_scope_digest',
  ] : schema === ROLLBACK_GRANT_SCHEMA ? [
    ...common, 'current_anchor_file_digest', 'current_version', 'reason_digest',
    'rollback_anchor_file_digest', 'rollback_to_version', 'target_anchor_path', 'target_installation_root',
  ] : null;
  if (schemaFields) exactObject(payload, schemaFields, 'root trust signed envelope payload');
  if (payload?.schema !== schema || payload?.operation !== operation || payload?.principal !== PRINCIPAL
      || payload?.signing_identity !== SIGNING_IDENTITY || payload?.fingerprint !== FINGERPRINT
      || payload?.protocol !== PROTOCOL || payload?.single_use !== true || !NONCE.test(payload?.nonce || '')) {
    throw new Error('root trust signed envelope identity or operation is invalid');
  }
  instant(payload.issued_at, 'envelope issued_at');
  instant(payload.expires_at, 'envelope expires_at');
  if (Date.parse(payload.issued_at) > now.getTime() || Date.parse(payload.expires_at) < now.getTime()) {
    throw new Error('root trust signed envelope is stale or premature');
  }
  const observed = signatureVerifier(Buffer.from(canonicalJson(payload), 'utf8'), envelope.signature, publicKeyPath);
  if (observed !== FINGERPRINT) throw new Error('root trust signature is not from the bound identity');
  if (!Array.isArray(payload.nonclaims) || payload.nonclaims.length < 1
      || payload.status !== 'approved-single-use'
      || !['governed-root-trust-lifecycle-installation', 'bounded-trust-scope-installation', 'immediately-previous-anchor-rollback'].includes(payload.authority_effect)) {
    throw new Error('root trust signed envelope status, effect or nonclaims are invalid');
  }
  return Object.freeze({ ...payload });
}

export function assertRegistry(registry) {
  exactObject(registry, ['current_version', 'schema_version', 'used_grant_nonces', 'versions'], 'root trust registry');
  if (registry.schema_version !== REGISTRY_SCHEMA || !Number.isSafeInteger(registry.current_version)
      || registry.current_version < 0 || !Array.isArray(registry.versions) || !Array.isArray(registry.used_grant_nonces)
      || new Set(registry.used_grant_nonces).size !== registry.used_grant_nonces.length) {
    throw new Error('root trust registry structure is invalid');
  }
  const versions = [...registry.versions].sort((a, b) => a.version - b.version);
  if (canonicalJson(versions) !== canonicalJson(registry.versions)
      || registry.current_version >= versions.length
      || versions.some((entry, index) => entry.version !== index)) {
    throw new Error('root trust registry versions are not monotonic and contiguous');
  }
  const active = versions.filter((entry) => entry.state === 'active');
  if (active.length !== 1 || active[0].version !== registry.current_version) throw new Error('root trust registry must have exactly one active version');
  for (const entry of versions) {
    exactObject(entry, [
      'activated_at', 'anchor_content_digest', 'anchor_file_digest', 'anchor_path', 'installation_receipt_digest',
      'predecessor_anchor_file_digest', 'predecessor_version', 'rollback_eligible', 'state', 'version',
    ], 'root trust version entry');
    digest(entry.anchor_file_digest, 'anchor file digest');
    digest(entry.anchor_content_digest, 'anchor content digest');
    if (entry.installation_receipt_digest !== null) digest(entry.installation_receipt_digest, 'installation receipt digest');
    if (entry.predecessor_anchor_file_digest !== null) digest(entry.predecessor_anchor_file_digest, 'predecessor anchor digest');
    if (entry.version === 0 && (entry.predecessor_version !== null || entry.predecessor_anchor_file_digest !== null)
        || entry.version > 0 && (!Number.isSafeInteger(entry.predecessor_version)
          || entry.predecessor_version < 0 || entry.predecessor_version >= entry.version
          || !SHA256.test(entry.predecessor_anchor_file_digest || '')
          || versions[entry.predecessor_version]?.anchor_file_digest !== entry.predecessor_anchor_file_digest)) {
      throw new Error('root trust version predecessor binding is invalid');
    }
    instant(entry.activated_at, 'version activation time');
  }
  return registry;
}

export function initializeRegistry(anchorPath = ANCHOR_PATH, governanceRoot = GOVERNANCE_ROOT, activatedAt, trustRoot = TRUST_ROOT) {
  assertRegular(anchorPath, { mode: 0o444, label: 'installed trust anchor', root: trustRoot });
  const anchorBytes = readFileSync(anchorPath);
  const anchor = assertAnchor(JSON.parse(anchorBytes));
  const versionsDirectory = join(governanceRoot, 'versions');
  assertSafeDirectory(governanceRoot, trustRoot, { create: true });
  assertSafeDirectory(versionsDirectory, trustRoot, { create: true });
  const historical = join(versionsDirectory, '000000.json');
  if (!existsSync(historical)) atomicWrite(historical, anchorBytes, { root: trustRoot });
  const registry = {
    current_version: 0,
    schema_version: REGISTRY_SCHEMA,
    used_grant_nonces: [],
    versions: [{
      activated_at: instant(activatedAt, 'genesis baseline activation time'),
      anchor_content_digest: canonicalContentDigest(anchor),
      anchor_file_digest: sha256(anchorBytes),
      anchor_path: historical,
      installation_receipt_digest: null,
      predecessor_anchor_file_digest: null,
      predecessor_version: null,
      rollback_eligible: false,
      state: 'active',
      version: 0,
    }],
  };
  assertRegistry(registry);
  const registryPath = join(governanceRoot, 'registry.json');
  if (existsSync(registryPath)) throw new Error('root trust registry already exists');
  atomicWrite(registryPath, canonicalBytes(registry), { root: trustRoot });
  return Object.freeze({ registry, registryPath });
}

export function readRegistry(governanceRoot = GOVERNANCE_ROOT, trustRoot = TRUST_ROOT) {
  const path = join(governanceRoot, 'registry.json');
  assertRegular(path, { mode: 0o444, label: 'root trust registry', root: trustRoot });
  return assertRegistry(JSON.parse(readFileSync(path)));
}

function assertInstallationBindings(payload, {
  anchorPath, candidateBytes, currentBytes, currentVersion, evidence, resultingVersion, trustRoot,
}) {
  const candidate = assertAnchor(JSON.parse(candidateBytes));
  const current = assertAnchor(JSON.parse(currentBytes));
  if (payload.target_installation_root !== trustRoot || payload.target_anchor_path !== anchorPath
      || payload.predecessor_version !== currentVersion || payload.resulting_version !== resultingVersion
      || payload.predecessor_anchor_file_digest !== sha256(currentBytes)
      || payload.predecessor_anchor_content_digest !== canonicalContentDigest(current)
      || payload.resulting_anchor_file_digest !== sha256(candidateBytes)
      || payload.resulting_anchor_content_digest !== canonicalContentDigest(candidate)) {
    throw new Error('installation grant does not bind the exact predecessor and candidate');
  }
  for (const field of [
    'owner_decision_digest', 'option_evaluation_digest', 'validation_evidence_digest',
    'admission_receipt_digest', 'installer_source_scope_digest', 'validation_producer_source_scope_digest',
    'admission_path_source_scope_digest',
  ]) {
    digest(payload[field], field);
    if (evidence?.[field] !== payload[field]) throw new Error(`installation grant ${field} evidence mismatch`);
  }
  return { candidate, current };
}

export function installAnchor({
  anchorPath = ANCHOR_PATH,
  candidateBytes,
  evidence,
  fault = null,
  governanceRoot = GOVERNANCE_ROOT,
  grantEnvelope,
  installedAt,
  publicKeyPath = PUBLIC_KEY,
  signatureVerifier,
  trustRoot = TRUST_ROOT,
}) {
  if (!Buffer.isBuffer(candidateBytes) || !candidateBytes.equals(canonicalBytes(JSON.parse(candidateBytes)))) {
    throw new Error('candidate anchor must use canonical JSON bytes');
  }
  const registry = readRegistry(governanceRoot, trustRoot);
  if (registry.used_grant_nonces.includes(grantEnvelope?.payload?.nonce)) throw new Error('installation grant nonce was replayed');
  const grant = verifySignedEnvelope(grantEnvelope, {
    operation: 'install-root-trust-anchor', schema: INSTALL_GRANT_SCHEMA, now: new Date(installedAt), publicKeyPath,
    signatureVerifier,
  });
  const currentBytes = readFileSync(anchorPath);
  const currentEntry = registry.versions[registry.current_version];
  if (sha256(currentBytes) !== currentEntry.anchor_file_digest) throw new Error('installed anchor differs from registry current version');
  const { candidate, current } = assertInstallationBindings(grant, {
    anchorPath, candidateBytes, currentBytes, currentVersion: registry.current_version,
    resultingVersion: registry.versions.length, evidence, trustRoot,
  });
  const approvedExtension = grant.approved_extension === null ? null : assertScope(grant.approved_extension);
  const transition = assertAdditiveTransition(current, candidate, approvedExtension);
  const nextVersion = grant.resulting_version;
  const versionPath = join(governanceRoot, 'versions', `${String(nextVersion).padStart(6, '0')}.json`);
  if (existsSync(versionPath)) throw new Error('historical trust anchor version is immutable');
  atomicWrite(versionPath, candidateBytes, { root: trustRoot });
  try {
    atomicWrite(anchorPath, candidateBytes, { fault, root: trustRoot });
    if (fault === 'after-rename') {
      atomicWrite(anchorPath, currentBytes, { root: trustRoot });
      throw new Error('injected interruption after atomic rename');
    }
  } catch (error) {
    if (sha256(readFileSync(anchorPath)) !== sha256(currentBytes)) atomicWrite(anchorPath, currentBytes, { root: trustRoot });
    if (existsSync(versionPath)) unlinkSync(versionPath);
    fsyncDirectory(dirname(versionPath), trustRoot);
    throw error;
  }
  const receipt = {
    admission_receipt_digest: grant.admission_receipt_digest,
    approved_extension: approvedExtension,
    authority_effect: approvedExtension === null ? 'governed-root-trust-lifecycle-active' : 'bounded-trust-scope-active',
    installed_at: instant(installedAt, 'installation time'),
    installer_source_scope_digest: grant.installer_source_scope_digest,
    nonclaims: [
      'no unrestricted semantic authority', 'no arbitrary repository authority', 'no provider contact',
      'no Factory implementation authority', 'no production migration', 'no contract activation',
    ],
    owner_decision_digest: grant.owner_decision_digest,
    predecessor_anchor_file_digest: sha256(currentBytes),
    predecessor_version: registry.current_version,
    read_back_verified: sha256(readFileSync(anchorPath)) === sha256(candidateBytes),
    resulting_anchor_content_digest: canonicalContentDigest(candidate),
    resulting_anchor_file_digest: sha256(candidateBytes),
    resulting_version: nextVersion,
    schema_version: INSTALL_RECEIPT_SCHEMA,
    single_use_grant_nonce: grant.nonce,
    status: 'installed-active',
    transition: { added_pairs: transition.additions, preserved_pair_count: transition.preserved },
    validation_evidence_digest: grant.validation_evidence_digest,
  };
  const receiptBytes = canonicalBytes(receipt);
  const receiptDigest = sha256(receiptBytes);
  const receiptPath = join(governanceRoot, 'receipts', `${receiptDigest.slice(7)}.json`);
  assertSafeDirectory(dirname(receiptPath), trustRoot, { create: true });
  atomicWrite(receiptPath, receiptBytes, { root: trustRoot });
  const versions = registry.versions.map((entry) => entry.version === registry.current_version
    ? { ...entry, rollback_eligible: true, state: 'superseded' }
    : { ...entry, rollback_eligible: false });
  versions.push({
    activated_at: receipt.installed_at,
    anchor_content_digest: receipt.resulting_anchor_content_digest,
    anchor_file_digest: receipt.resulting_anchor_file_digest,
    anchor_path: versionPath,
    installation_receipt_digest: receiptDigest,
    predecessor_anchor_file_digest: receipt.predecessor_anchor_file_digest,
    predecessor_version: receipt.predecessor_version,
    rollback_eligible: false,
    state: 'active',
    version: nextVersion,
  });
  const updated = assertRegistry({
    current_version: nextVersion,
    schema_version: REGISTRY_SCHEMA,
    used_grant_nonces: [...registry.used_grant_nonces, grant.nonce].sort(utf8),
    versions,
  });
  atomicWrite(join(governanceRoot, 'registry.json'), canonicalBytes(updated), { root: trustRoot });
  if (sha256(readFileSync(anchorPath)) !== receipt.resulting_anchor_file_digest) throw new Error('final anchor read-back failed');
  return Object.freeze({ receipt: Object.freeze(receipt), receiptDigest, receiptPath, registry: updated });
}

export function rollbackAnchor({
  anchorPath = ANCHOR_PATH,
  governanceRoot = GOVERNANCE_ROOT,
  grantEnvelope,
  publicKeyPath = PUBLIC_KEY,
  rolledBackAt,
  signatureVerifier,
  trustRoot = TRUST_ROOT,
}) {
  const registry = readRegistry(governanceRoot, trustRoot);
  if (registry.current_version < 1) throw new Error('no immediately previous governed anchor exists');
  if (registry.used_grant_nonces.includes(grantEnvelope?.payload?.nonce)) throw new Error('rollback grant nonce was replayed');
  const grant = verifySignedEnvelope(grantEnvelope, {
    operation: 'rollback-root-trust-anchor', schema: ROLLBACK_GRANT_SCHEMA, now: new Date(rolledBackAt), publicKeyPath,
    signatureVerifier,
  });
  const current = registry.versions[registry.current_version];
  const previous = registry.versions[current.predecessor_version];
  if (!previous) throw new Error('active version has no verified predecessor binding');
  if (grant.target_anchor_path !== anchorPath || grant.target_installation_root !== trustRoot
      || grant.current_version !== current.version || grant.rollback_to_version !== previous.version
      || grant.current_anchor_file_digest !== current.anchor_file_digest
      || grant.rollback_anchor_file_digest !== previous.anchor_file_digest || previous.rollback_eligible !== true) {
    throw new Error('rollback is not bound to the immediately previous verified anchor');
  }
  const previousBytes = readFileSync(previous.anchor_path);
  if (sha256(previousBytes) !== previous.anchor_file_digest) throw new Error('rollback predecessor bytes failed verification');
  atomicWrite(anchorPath, previousBytes, { root: trustRoot });
  const receipt = {
    authority_effect: 'immediately-previous-verified-anchor-restored',
    failed_or_superseded_version_preserved: true,
    from_anchor_file_digest: current.anchor_file_digest,
    from_version: current.version,
    nonclaims: ['no historical version deletion', 'no arbitrary downgrade', 'no scope expansion'],
    read_back_verified: sha256(readFileSync(anchorPath)) === previous.anchor_file_digest,
    rolled_back_at: instant(rolledBackAt, 'rollback time'),
    schema_version: ROLLBACK_RECEIPT_SCHEMA,
    single_use_grant_nonce: grant.nonce,
    status: 'rollback-active',
    to_anchor_file_digest: previous.anchor_file_digest,
    to_version: previous.version,
  };
  const receiptBytes = canonicalBytes(receipt);
  const receiptDigest = sha256(receiptBytes);
  const receiptPath = join(governanceRoot, 'receipts', `${receiptDigest.slice(7)}.json`);
  atomicWrite(receiptPath, receiptBytes, { root: trustRoot });
  const versions = registry.versions.map((entry) => {
    if (entry.version === current.version) return { ...entry, rollback_eligible: false, state: 'rolled-back' };
    if (entry.version === previous.version) return { ...entry, rollback_eligible: false, state: 'active', activated_at: receipt.rolled_back_at };
    return { ...entry, rollback_eligible: false };
  });
  const updated = assertRegistry({
    current_version: previous.version,
    schema_version: REGISTRY_SCHEMA,
    used_grant_nonces: [...registry.used_grant_nonces, grant.nonce].sort(utf8),
    versions,
  });
  atomicWrite(join(governanceRoot, 'registry.json'), canonicalBytes(updated), { root: trustRoot });
  return Object.freeze({ receipt: Object.freeze(receipt), receiptDigest, receiptPath, registry: updated });
}

export function verifyInstalledAnchor({ anchorPath = ANCHOR_PATH, governanceRoot = GOVERNANCE_ROOT, trustRoot = TRUST_ROOT } = {}) {
  const registry = readRegistry(governanceRoot, trustRoot);
  const current = registry.versions[registry.current_version];
  assertRegular(anchorPath, { mode: 0o444, label: 'installed trust anchor', root: trustRoot });
  const bytes = readFileSync(anchorPath);
  const anchor = assertAnchor(JSON.parse(bytes));
  if (sha256(bytes) !== current.anchor_file_digest || canonicalContentDigest(anchor) !== current.anchor_content_digest) {
    throw new Error('installed trust anchor does not match the active governed registry version');
  }
  return Object.freeze({ anchor, byteLength: bytes.length, contentDigest: current.anchor_content_digest, fileDigest: current.anchor_file_digest, version: current.version });
}

export function copyImmutableEvidence(source, casRoot = '/var/lib/usf-cas') {
  const bytes = readFileSync(source);
  const contentDigest = sha256(bytes);
  const hex = contentDigest.slice(7);
  const directory = join(casRoot, 'sha256', hex.slice(0, 2));
  assertSafeDirectory(casRoot, casRoot);
  assertSafeDirectory(directory, casRoot, { create: true });
  const target = join(directory, hex);
  if (!existsSync(target)) {
    copyFileSync(source, target, constants.COPYFILE_EXCL);
    chmodSync(target, 0o444);
    fsyncDirectory(directory, casRoot);
  }
  const item = lstatSync(target);
  if (!item.isFile() || item.isSymbolicLink() || (item.mode & 0o777) !== 0o444 || sha256(readFileSync(target)) !== contentDigest) {
    throw new Error('immutable evidence CAS transfer failed verification');
  }
  return Object.freeze({ byteLength: bytes.length, digest: contentDigest, locator: `cas://sha256/${hex}`, path: target });
}

export const rootTrustInternals = Object.freeze({ assertNotSymbolicLink, hermeticFsyncDenialIsExpected });
