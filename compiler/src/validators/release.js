import { createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseJsonDocument, validateApplicableFormat } from './formats.js';
import { resolveContainedPath } from './paths.js';
import { GeneratedOutputValidationError } from './validation-error.js';

const HEX_256 = /^[0-9a-f]{64}$/;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const finding = (code, path, message, details = {}) => ({ code, path, message, ...details });

export const REQUIRED_OUTPUT_FAMILIES = Object.freeze([
  ['authority', (path) => path.startsWith('authority/')],
  ['json-schema', (path) => path.startsWith('contracts/schemas/') && path.endsWith('.schema.json')],
  ['openapi', (path) => path.startsWith('contracts/openapi/') && path.endsWith('.openapi.json')],
  ['graphql', (path) => path.startsWith('contracts/graphql/') && path.endsWith('.graphql')],
  ['documentation', (path) => path.startsWith('docs/')],
  ['assurance', (path) => path.startsWith('assurance/')],
  ['proof', (path) => path.startsWith('proof/')],
  ['runtime', (path) => path.startsWith('runtime/')],
  ['ui', (path) => path.startsWith('ui/')],
  ['generated-tests', (path) => path.startsWith('tests/') || path.startsWith('workspace/test/')],
  ['validators', (path) => path.startsWith('validation/')],
  ['workspace-package', (path) => path === 'workspace/package.json'],
  ['workspace-source', (path) => path.startsWith('workspace/src/')],
  ['workflow', (path) => /^\.github\/workflows\/.*\.ya?ml$/.test(path)],
  ['sbom', (path) => path === 'release/sbom.json'],
  ['provenance', (path) => path === 'release/provenance.json'],
  ['checksums', (path) => path === 'release/checksums.json'],
]);

function validateManifestSchema(manifest, findings) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    findings.push(finding('invalid-manifest-schema', 'release/manifest.json', 'manifest root must be an object'));
    return false;
  }
  if (manifest.schemaVersion !== 1) findings.push(finding('invalid-manifest-schema', 'release/manifest.json', 'schemaVersion must equal 1'));
  if (typeof manifest.compilerVersion !== 'string' || !/^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$/.test(manifest.compilerVersion)) findings.push(finding('invalid-manifest-schema', 'release/manifest.json', 'compilerVersion must be SemVer-shaped'));
  if (typeof manifest.releaseVersion !== 'string' || !/^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$/.test(manifest.releaseVersion)) findings.push(finding('invalid-manifest-schema', 'release/manifest.json', 'releaseVersion must be SemVer-shaped'));
  if (typeof manifest.releaseVersionResource !== 'string' || !manifest.releaseVersionResource.startsWith('urn:usf:version:')) findings.push(finding('invalid-manifest-schema', 'release/manifest.json', 'releaseVersionResource must identify the governed graph version'));
  if (typeof manifest.authorityDigest !== 'string' || !HEX_256.test(manifest.authorityDigest)) findings.push(finding('invalid-manifest-schema', 'release/manifest.json', 'authorityDigest must be a lowercase SHA-256 digest'));
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
    findings.push(finding('invalid-manifest-schema', 'release/manifest.json', 'files must be a non-empty array'));
    return false;
  }
  const seen = new Set();
  let previous = '';
  for (const [index, record] of manifest.files.entries()) {
    const recordPath = `release/manifest.json#/files/${index}`;
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      findings.push(finding('invalid-manifest-schema', recordPath, 'file record must be an object'));
      continue;
    }
    if (typeof record.path !== 'string' || !record.path) findings.push(finding('invalid-manifest-schema', recordPath, 'file path is required'));
    else {
      if (seen.has(record.path)) findings.push(finding('duplicate-manifest-path', record.path, 'manifest paths must be unique'));
      seen.add(record.path);
      if (previous && previous.localeCompare(record.path) > 0) findings.push(finding('unsorted-manifest', record.path, 'manifest files must use deterministic lexical order'));
      previous = record.path;
    }
    if (!Number.isSafeInteger(record.bytes) || record.bytes < 0) findings.push(finding('invalid-manifest-schema', recordPath, 'bytes must be a non-negative safe integer'));
    if (typeof record.sha256 !== 'string' || !HEX_256.test(record.sha256)) findings.push(finding('invalid-manifest-schema', recordPath, 'sha256 must be a lowercase SHA-256 digest'));
  }
  return true;
}

function validateLinkMap({ manifest, document, path, collection, nameField, hashField, code, findings }) {
  if (!document || !Array.isArray(document[collection])) {
    findings.push(finding(code, path, `${collection} must be an array`));
    return;
  }
  const expected = manifest.files.filter((record) => !record.path.startsWith('release/'));
  const linked = new Map();
  for (const item of document[collection]) {
    const itemPath = item?.[nameField];
    let digest = item?.[hashField];
    if (collection === 'components') digest = item?.hashes?.find((hash) => hash?.alg === 'SHA-256')?.content;
    if (typeof itemPath !== 'string' || typeof digest !== 'string') continue;
    if (linked.has(itemPath)) findings.push(finding(code, path, `duplicate linkage for ${itemPath}`));
    linked.set(itemPath, digest);
  }
  for (const record of expected) {
    if (!linked.has(record.path)) findings.push(finding(code, path, `missing linkage for ${record.path}`, { outputPath: record.path }));
    else if (linked.get(record.path) !== record.sha256) findings.push(finding(code, path, `digest linkage mismatch for ${record.path}`, { outputPath: record.path }));
  }
  for (const itemPath of linked.keys()) {
    if (!manifest.files.some((record) => record.path === itemPath)) findings.push(finding(code, path, `linkage references an unknown manifest path ${itemPath}`, { outputPath: itemPath }));
  }
}

function validateSbom(root, manifest, findings) {
  const path = 'release/sbom.json';
  const resolved = resolveContainedPath(root, path);
  if (!resolved.ok || !existsSync(resolved.target)) return;
  const parsed = parseJsonDocument(readFileSync(resolved.target, 'utf8'), path, 'invalid-sbom');
  findings.push(...parsed.findings);
  if (!parsed.value) return;
  if (parsed.value.bomFormat !== 'CycloneDX' || typeof parsed.value.specVersion !== 'string') findings.push(finding('invalid-sbom', path, 'SBOM must declare CycloneDX and a specVersion'));
  validateLinkMap({ manifest, document: parsed.value, path, collection: 'components', nameField: 'name', code: 'sbom-linkage', findings });
}

function validateProvenance(root, manifest, findings) {
  const path = 'release/provenance.json';
  const resolved = resolveContainedPath(root, path);
  if (!resolved.ok || !existsSync(resolved.target)) return;
  const parsed = parseJsonDocument(readFileSync(resolved.target, 'utf8'), path, 'invalid-provenance');
  findings.push(...parsed.findings);
  if (!parsed.value) return;
  if (parsed.value.authorityDigest !== manifest.authorityDigest) findings.push(finding('provenance-linkage', path, 'provenance authorityDigest does not match the release manifest'));
  validateLinkMap({ manifest, document: parsed.value, path, collection: 'materials', nameField: 'path', hashField: 'sha256', code: 'provenance-linkage', findings });
}

function validateChecksums(root, manifest, findings) {
  const path = 'release/checksums.json';
  const resolved = resolveContainedPath(root, path);
  if (!resolved.ok || !existsSync(resolved.target)) return;
  const parsed = parseJsonDocument(readFileSync(resolved.target, 'utf8'), path, 'invalid-checksums');
  findings.push(...parsed.findings);
  if (!parsed.value) return;
  if (parsed.value.algorithm !== 'sha256' || !Array.isArray(parsed.value.files)) {
    findings.push(finding('invalid-checksums', path, 'checksums must declare sha256 and a files array'));
    return;
  }
  const expected = manifest.files.filter((record) => record.path !== path);
  const observed = new Map(parsed.value.files.map((record) => [record?.path, record?.sha256]));
  for (const record of expected) {
    if (!observed.has(record.path)) findings.push(finding('checksum-linkage', path, `missing checksum for ${record.path}`, { outputPath: record.path }));
    else if (observed.get(record.path) !== record.sha256) findings.push(finding('checksum-linkage', path, `checksum mismatch for ${record.path}`, { outputPath: record.path }));
  }
  for (const outputPath of observed.keys()) {
    if (!expected.some((record) => record.path === outputPath)) findings.push(finding('checksum-linkage', path, `checksum references unknown path ${outputPath}`, { outputPath }));
  }
}

function validateSignature(root, manifest, manifestBytes, findings, expectedPublicKeyFingerprint) {
  const path = 'release/signature.json';
  const resolved = resolveContainedPath(root, path);
  if (!resolved.ok || !existsSync(resolved.target)) {
    findings.push(finding('missing-release-signature', path, 'release signature is required and must remain external to the signed manifest'));
    return;
  }
  const parsed = parseJsonDocument(readFileSync(resolved.target, 'utf8'), path, 'invalid-release-signature');
  findings.push(...parsed.findings);
  const signature = parsed.value;
  if (!signature) return;
  if (signature.algorithm !== 'Ed25519' || signature.signedPath !== 'release/manifest.json' || typeof signature.publicKey !== 'string' || typeof signature.publicKeyFingerprint !== 'string' || typeof signature.signingIdentity !== 'string' || !signature.signingIdentity.startsWith('urn:usf:signingidentity:') || typeof signature.signature !== 'string') {
    findings.push(finding('invalid-release-signature', path, 'signature must declare Ed25519, release manifest path, public key, governed signing identity, fingerprint, and base64 signature'));
    return;
  }
  const manifestDigest = sha256(manifestBytes);
  let publicKey;
  let fingerprint;
  try {
    publicKey = createPublicKey(signature.publicKey);
    fingerprint = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  } catch (error) {
    findings.push(finding('invalid-release-signature', path, error.message));
    return;
  }
  if (signature.signedSha256 !== manifestDigest) findings.push(finding('invalid-release-signature', path, 'signedSha256 does not match the release manifest'));
  if (signature.publicKeyFingerprint !== fingerprint) findings.push(finding('invalid-release-signature', path, 'public key fingerprint does not match the embedded key'));
  if (expectedPublicKeyFingerprint && signature.publicKeyFingerprint !== expectedPublicKeyFingerprint) findings.push(finding('unexpected-signing-identity', path, 'release was not signed by the expected identity'));
  try {
    const bytes = Buffer.from(signature.signature, 'base64');
    if (!bytes.length || !verify(null, manifestBytes, publicKey, bytes)) findings.push(finding('invalid-release-signature', path, 'Ed25519 signature verification failed'));
  } catch (error) {
    findings.push(finding('invalid-release-signature', path, error.message));
  }
  const attestationPath = 'release/attestation.json';
  const attestationResolved = resolveContainedPath(root, attestationPath);
  if (!attestationResolved.ok || !existsSync(attestationResolved.target)) {
    findings.push(finding('missing-release-attestation', attestationPath, 'signed release attestation is required'));
    return;
  }
  const attestation = parseJsonDocument(readFileSync(attestationResolved.target, 'utf8'), attestationPath, 'invalid-release-attestation');
  findings.push(...attestation.findings);
  if (!attestation.value) return;
  const value = attestation.value;
  if (value.schemaVersion !== 1 || value.kind !== 'cleanroomgeneration' || value.authorityDigest !== manifest.authorityDigest || value.manifestPath !== 'release/manifest.json' || value.manifestSha256 !== manifestDigest || value.signaturePath !== path || value.signingIdentity !== signature.signingIdentity || value.signingIdentityFingerprint !== fingerprint || value.releaseVersion !== manifest.releaseVersion || value.verificationRequired !== true) {
    findings.push(finding('invalid-release-attestation', attestationPath, 'attestation is not consistently bound to authority, manifest, signature, and signing identity'));
  }
}

export function validateGeneratedOutput(outputDir, { requiredFamilies = REQUIRED_OUTPUT_FAMILIES, expectedPublicKeyFingerprint = null } = {}) {
  const root = resolve(outputDir);
  const findings = [];
  const manifestPath = resolveContainedPath(root, 'release/manifest.json');
  if (!manifestPath.ok || !existsSync(manifestPath.target)) {
    findings.push(finding('missing-release-manifest', 'release/manifest.json', manifestPath.reason ?? 'release manifest is missing'));
    return { ok: false, outputDir: root, checked: 0, findings };
  }
  const manifestBytes = readFileSync(manifestPath.target);
  const parsed = parseJsonDocument(manifestBytes.toString('utf8'), 'release/manifest.json', 'invalid-manifest-json');
  findings.push(...parsed.findings);
  const manifest = parsed.value;
  if (!manifest || !validateManifestSchema(manifest, findings) || !Array.isArray(manifest.files)) return { ok: false, outputDir: root, checked: 0, findings };

  const paths = [];
  for (const record of manifest.files) {
    if (!record || typeof record.path !== 'string') continue;
    paths.push(record.path);
    const contained = resolveContainedPath(root, record.path);
    if (!contained.ok) {
      findings.push(finding('path-containment', record.path, contained.reason));
      continue;
    }
    if (!existsSync(contained.target)) {
      findings.push(finding('missing-output', record.path, 'manifest output is missing'));
      continue;
    }
    const content = readFileSync(contained.target);
    if (content.length !== record.bytes) findings.push(finding('byte-count-mismatch', record.path, 'manifest byte count does not match output', { expected: record.bytes, observed: content.length }));
    const observed = sha256(content);
    if (observed !== record.sha256) findings.push(finding('digest-mismatch', record.path, 'manifest digest does not match output', { expected: record.sha256, observed }));
    findings.push(...validateApplicableFormat(record.path, content.toString('utf8')));
  }

  for (const [family, matches] of requiredFamilies) {
    if (!paths.some(matches)) findings.push(finding('missing-output-family', 'release/manifest.json', `required output family is absent: ${family}`, { family }));
  }
  validateSbom(root, manifest, findings);
  validateProvenance(root, manifest, findings);
  validateChecksums(root, manifest, findings);
  validateSignature(root, manifest, manifestBytes, findings, expectedPublicKeyFingerprint);
  return { ok: findings.length === 0, outputDir: root, checked: manifest.files.length, authorityDigest: manifest.authorityDigest,
    signatureVerified: !findings.some((item) => item.code.includes('signature') || item.code.includes('attestation')),
    signingIdentityTrusted: Boolean(expectedPublicKeyFingerprint) && !findings.some((item) => item.code === 'unexpected-signing-identity'), findings };
}

export function assertGeneratedOutput(outputDir, options) {
  const report = validateGeneratedOutput(outputDir, options);
  if (!report.ok) throw new GeneratedOutputValidationError('generated output failed independent validation', report);
  return report;
}
