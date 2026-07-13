import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { assertGeneratedOutput, GeneratedOutputValidationError, validateGeneratedOutput } from '../src/validators/index.js';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const json = (value) => `${JSON.stringify(value, null, 2)}\n`;

function write(root, path, content) {
  const target = join(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

function filesUnder(root, directory = root) {
  const paths = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const target = join(directory, entry.name);
    if (entry.isDirectory()) paths.push(...filesUnder(root, target));
    else paths.push(relative(root, target).split('\\').join('/'));
  }
  return paths;
}

function records(root, paths) {
  return paths.sort().map((path) => {
    const content = readFileSync(join(root, path));
    return { path, bytes: content.length, sha256: sha256(content) };
  });
}

function signManifest(root, keys, mutate = (value) => value) {
  const manifestPath = join(root, 'release/manifest.json');
  const manifest = mutate(JSON.parse(readFileSync(manifestPath, 'utf8')));
  const bytes = Buffer.from(json(manifest));
  writeFileSync(manifestPath, bytes);
  const signature = {
    algorithm: 'Ed25519',
    signedPath: 'release/manifest.json',
    signedSha256: sha256(bytes),
    publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }),
    publicKeyFingerprint: sha256(keys.publicKey.export({ type: 'spki', format: 'der' })),
    signingIdentity: 'urn:usf:signingidentity:test',
    signature: sign(null, bytes, keys.privateKey).toString('base64'),
  };
  writeFileSync(join(root, 'release/signature.json'), json(signature));
  writeFileSync(join(root, 'release/attestation.json'), json({
    schemaVersion: 1,
    kind: 'cleanroomgeneration',
    authorityDigest: manifest.authorityDigest,
    manifestPath: 'release/manifest.json',
    manifestSha256: sha256(bytes),
    signaturePath: 'release/signature.json',
    signingIdentity: signature.signingIdentity,
    signingIdentityFingerprint: signature.publicKeyFingerprint,
    releaseVersion: manifest.releaseVersion,
    verificationRequired: true,
  }));
}

function refreshManifest(root, keys) {
  const checksumPaths = filesUnder(root).filter((path) => !['release/manifest.json', 'release/signature.json', 'release/attestation.json', 'release/checksums.json'].includes(path));
  write(root, 'release/checksums.json', json({ algorithm: 'sha256', files: records(root, checksumPaths) }));
  const paths = filesUnder(root).filter((path) => !['release/manifest.json', 'release/signature.json', 'release/attestation.json'].includes(path));
  const manifest = {
    schemaVersion: 1,
    compilerVersion: '0.1.0',
    releaseVersion: '0.1.0',
    releaseVersionResource: 'urn:usf:version:test010',
    authorityDigest: 'a'.repeat(64),
    files: records(root, paths),
  };
  writeFileSync(join(root, 'release/manifest.json'), json(manifest));
  signManifest(root, keys);
}

function refreshLinkDocuments(root, keys) {
  const ordinary = records(root, filesUnder(root).filter((path) => !path.startsWith('release/')));
  write(root, 'release/sbom.json', json({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    components: ordinary.map((record) => ({ type: 'file', name: record.path, hashes: [{ alg: 'SHA-256', content: record.sha256 }] })),
  }));
  write(root, 'release/provenance.json', json({
    schemaVersion: 1,
    authorityDigest: 'a'.repeat(64),
    materials: ordinary.map(({ path, sha256: digest }) => ({ path, sha256: digest })),
  }));
  refreshManifest(root, keys);
}

function validBundle() {
  const root = mkdtempSync(join(tmpdir(), 'usf-generated-output-'));
  const keys = generateKeyPairSync('ed25519');
  write(root, 'authority/index.json', json({ schemaVersion: 1 }));
  write(root, 'contracts/schemas/output.schema.json', json({ $schema: 'https://json-schema.org/draft/2020-12/schema', type: 'object', required: [] }));
  write(root, 'contracts/openapi/foundation.openapi.json', json({ openapi: '3.1.0', info: { title: 'Generated foundation', version: '0.1.0' }, paths: {} }));
  write(root, 'contracts/graphql/foundation.graphql', 'scalar USFSemanticResource\ntype Query { semanticResources: [USFSemanticResource!]! }\n');
  write(root, 'docs/architecture/index.md', '# Generated architecture\n');
  write(root, 'assurance/statement-of-applicability.json', json({ approvalState: 'draft' }));
  write(root, 'proof/evidence-pipeline.mjs', 'export const verify = () => true;\n');
  write(root, 'runtime/compose.json', json({ services: {} }));
  write(root, 'ui/models/index.json', json({ models: [] }));
  write(root, 'tests/e2e/uijourneys/index.json', json({ journeys: [] }));
  write(root, 'validation/validators.json', json({ validators: [] }));
  write(root, 'workspace/package.json', json({ name: 'generated-foundation', version: '0.1.0', private: true, scripts: { test: 'node --test', validate: 'node validate.mjs', proof: 'node proof.mjs' } }));
  write(root, 'workspace/src/index.mjs', 'export default [];\n');
  write(root, 'workspace/test/generated.test.mjs', 'import test from "node:test"; test("generated", () => {});\n');
  write(root, '.github/workflows/validate.yml', 'name: generated-validation\non:\n  push:\njobs:\n  validate:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n');
  refreshLinkDocuments(root, keys);
  return { root, keys };
}

function withBundle(run) {
  const fixture = validBundle();
  try { return run(fixture); }
  finally { rmSync(fixture.root, { recursive: true, force: true }); }
}

const codes = (report) => new Set(report.findings.map((item) => item.code));

test('independent validator accepts a complete, linked, cryptographically signed bundle', () => withBundle(({ root }) => {
  const report = assertGeneratedOutput(root);
  assert.equal(report.ok, true);
  assert.equal(report.signatureVerified, true);
  assert.ok(report.checked > 0);
}));

test('planted defect: invalid manifest schema fails closed', () => withBundle(({ root, keys }) => {
  signManifest(root, keys, (manifest) => ({ ...manifest, schemaVersion: 2 }));
  assert.ok(codes(validateGeneratedOutput(root)).has('invalid-manifest-schema'));
}));

test('planted defect: missing governed release version fails closed', () => withBundle(({ root, keys }) => {
  signManifest(root, keys, (manifest) => ({ ...manifest, releaseVersion: undefined }));
  assert.ok(codes(validateGeneratedOutput(root)).has('invalid-manifest-schema'));
}));

test('planted defect: parent path in the manifest is rejected before reading it', () => withBundle(({ root, keys }) => {
  signManifest(root, keys, (manifest) => ({ ...manifest, files: [{ path: '../escape.json', bytes: 0, sha256: '0'.repeat(64) }, ...manifest.files] }));
  assert.ok(codes(validateGeneratedOutput(root)).has('path-containment'));
}));

test('planted defect: modified output produces a digest mismatch', () => withBundle(({ root }) => {
  write(root, 'authority/index.json', json({ tampered: true }));
  assert.ok(codes(validateGeneratedOutput(root)).has('digest-mismatch'));
}));

test('planted defect: missing required output family is explicit', () => withBundle(({ root, keys }) => {
  unlinkSync(join(root, 'ui/models/index.json'));
  refreshLinkDocuments(root, keys);
  const report = validateGeneratedOutput(root);
  assert.ok(report.findings.some((item) => item.code === 'missing-output-family' && item.family === 'ui'));
}));

for (const [name, path, invalid, expected] of [
  ['OpenAPI', 'contracts/openapi/foundation.openapi.json', json({ resources: [] }), 'invalid-openapi'],
  ['GraphQL', 'contracts/graphql/foundation.graphql', 'type Query { broken: String\n', 'invalid-graphql'],
  ['renderer JSON Schema', 'contracts/schemas/output.schema.json', json({ resources: [] }), 'invalid-json-schema'],
  ['package', 'workspace/package.json', json({ name: 'generated-foundation', version: 'not-semver', private: false, scripts: {} }), 'invalid-package'],
  ['workflow', '.github/workflows/validate.yml', 'name: invalid\njobs: [\n', 'invalid-workflow'],
]) {
  test(`planted defect: generated ${name} syntax or structure is rejected`, () => withBundle(({ root, keys }) => {
    write(root, path, invalid);
    refreshLinkDocuments(root, keys);
    assert.ok(codes(validateGeneratedOutput(root)).has(expected));
  }));
}

test('planted defect: SBOM digest linkage must cover generated non-release outputs', () => withBundle(({ root, keys }) => {
  const path = join(root, 'release/sbom.json');
  const sbom = JSON.parse(readFileSync(path, 'utf8'));
  sbom.components[0].hashes[0].content = '0'.repeat(64);
  writeFileSync(path, json(sbom));
  refreshManifest(root, keys);
  assert.ok(codes(validateGeneratedOutput(root)).has('sbom-linkage'));
}));

test('planted defect: provenance digest linkage must match generated inputs', () => withBundle(({ root, keys }) => {
  const path = join(root, 'release/provenance.json');
  const provenance = JSON.parse(readFileSync(path, 'utf8'));
  provenance.materials[0].sha256 = '0'.repeat(64);
  writeFileSync(path, json(provenance));
  refreshManifest(root, keys);
  assert.ok(codes(validateGeneratedOutput(root)).has('provenance-linkage'));
}));

test('planted defect: missing release signature fails closed', () => withBundle(({ root }) => {
  unlinkSync(join(root, 'release/signature.json'));
  assert.ok(codes(validateGeneratedOutput(root)).has('missing-release-signature'));
}));

test('planted defect: invalid release signature fails cryptographic verification', () => withBundle(({ root }) => {
  const path = join(root, 'release/signature.json');
  const signature = JSON.parse(readFileSync(path, 'utf8'));
  signature.signature = Buffer.alloc(64).toString('base64');
  writeFileSync(path, json(signature));
  assert.ok(codes(validateGeneratedOutput(root)).has('invalid-release-signature'));
}));

test('planted defect: unexpected release signing identity fails trust verification', () => withBundle(({ root }) => {
  const report = validateGeneratedOutput(root, { expectedPublicKeyFingerprint: '0'.repeat(64) });
  assert.ok(codes(report).has('unexpected-signing-identity'));
}));

test('assertion API exposes structured findings without compiler coupling', () => withBundle(({ root }) => {
  unlinkSync(join(root, 'release/signature.json'));
  assert.throws(() => assertGeneratedOutput(root), (error) => {
    assert.ok(error instanceof GeneratedOutputValidationError);
    assert.equal(error.phase, 'verify-output:independent');
    assert.ok(error.findings.some((item) => item.code === 'missing-release-signature'));
    return true;
  });
}));
