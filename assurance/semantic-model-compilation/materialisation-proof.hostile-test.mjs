import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import test, { after, before } from 'node:test';

const sourceRoot = resolve(import.meta.dirname, '../..');
const relativeRunner = 'assurance/semantic-model-compilation/materialisation-proof.mjs';
const sourceRunner = join(sourceRoot, relativeRunner);
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

let root;
let repository;
let gnupgHome;
let fingerprint;
let signingFingerprint;
let keyringDigest;
let graphCommit;
let graphTree;
let runner;

function command(executable, args, { cwd = root, env = {} } = {}) {
  const result = spawnSync(executable, args, {
    cwd,
    env: {
      HOME: '/nonexistent',
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      PATH: '/usr/bin:/bin',
      TZ: 'UTC',
      ...env,
    },
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60_000,
  });
  if (result.error || result.signal || result.status !== 0) {
    throw new Error(`fixture command failed: ${executable} ${args.join(' ')} (${result.status ?? result.signal})\n${result.stderr}`);
  }
  return result.stdout.trim();
}

function git(args, options = {}) { return command('/usr/bin/git', args, { cwd: repository, ...options }); }

function signCommit(message) {
  git(['add', '.']);
  git([
    '-c', 'user.name=USF validation fixture',
    '-c', 'user.email=usf-validation-fixture@example.invalid',
    '-c', `user.signingkey=${fingerprint}`,
    '-c', 'gpg.program=/usr/bin/gpg',
    'commit', '-S', '-m', message,
  ], { env: { GNUPGHOME: gnupgHome } });
  graphCommit = git(['rev-parse', 'HEAD']);
  graphTree = git(['rev-parse', 'HEAD^{tree}']);
}

function producerEnvironment(overrides = {}) {
  return {
    HOME: '/nonexistent',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
    USF_AUTHORITY_DIGEST: `sha256:${'1'.repeat(64)}`,
    USF_CAS_ROOT: join(root, 'cas'),
    USF_EVALUATED_AT: '2026-07-23T00:00:00Z',
    USF_EXPECTED_GRAPH_TREE: graphTree,
    USF_EXPECTED_KEYRING_DIGEST: keyringDigest,
    USF_EXPECTED_SIGNER_FINGERPRINT: fingerprint,
    USF_GNUPGHOME: gnupgHome,
    USF_GRAPH_COMMIT: graphCommit,
    USF_PROOF_OUTPUT: join('/tmp', `usf-materialisation-control-plane-proof-test-${process.pid}`),
    USF_REPO: repository,
    ...overrides,
  };
}

function runProducer({ executable = runner, environment = {}, mode = '--test-preflight-only' } = {}) {
  const result = spawnSync(process.execPath, [executable, mode], {
    cwd: repository,
    env: producerEnvironment(environment),
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60_000,
  });
  const lines = result.stdout.trim().split('\n').filter(Boolean);
  return { result, receipt: JSON.parse(lines.at(-1)) };
}

before(() => {
  root = mkdtempSync(join(tmpdir(), 'usf-materialisation-proof-test-'));
  repository = join(root, 'repository');
  gnupgHome = join(root, 'gnupg');
  mkdirSync(join(repository, 'assurance/semantic-model-compilation'), { recursive: true });
  mkdirSync(join(repository, 'capabilities/semantic-model-compilation'), { recursive: true });
  mkdirSync(join(repository, 'configuration/semantic-assurance'), { recursive: true });
  mkdirSync(join(repository, 'provider-bindings/stardog'), { recursive: true });
  mkdirSync(join(repository, 'semantic-model'), { recursive: true });
  mkdirSync(gnupgHome, { mode: 0o700 });
  mkdirSync(join(root, 'cas'), { mode: 0o700 });
  chmodSync(gnupgHome, 0o700);
  cpSync(sourceRunner, join(repository, relativeRunner));
  cpSync(
    join(sourceRoot, 'capabilities/semantic-model-compilation/authority-binding.mjs'),
    join(repository, 'capabilities/semantic-model-compilation/authority-binding.mjs'),
  );
  cpSync(
    join(sourceRoot, 'configuration/semantic-assurance/semantic-authority.mjs'),
    join(repository, 'configuration/semantic-assurance/semantic-authority.mjs'),
  );
  cpSync(
    join(sourceRoot, 'provider-bindings/stardog/semantic-authority.mjs'),
    join(repository, 'provider-bindings/stardog/semantic-authority.mjs'),
  );
  cpSync(join(sourceRoot, 'semantic-model/manifest.yaml'), join(repository, 'semantic-model/manifest.yaml'));
  cpSync(join(sourceRoot, 'package-lock.json'), join(repository, 'package-lock.json'));
  command('/usr/bin/gpg', [
    '--homedir', gnupgHome,
    '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
    '--quick-generate-key', 'USF validation fixture <usf-validation-fixture@example.invalid>', 'ed25519', 'cert', '0',
  ]);
  const keyListing = command('/usr/bin/gpg', ['--homedir', gnupgHome, '--batch', '--with-colons', '--list-secret-keys']);
  fingerprint = [...keyListing.matchAll(/^fpr:::::::::([0-9A-F]{40}):$/gmu)][0]?.[1];
  assert.match(fingerprint, /^[0-9A-F]{40}$/u);
  command('/usr/bin/gpg', [
    '--homedir', gnupgHome,
    '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
    '--quick-add-key', fingerprint, 'ed25519', 'sign', '0',
  ]);
  const listingWithSubkey = command('/usr/bin/gpg', ['--homedir', gnupgHome, '--batch', '--with-colons', '--list-secret-keys']);
  signingFingerprint = [...listingWithSubkey.matchAll(/^fpr:::::::::([0-9A-F]{40}):$/gmu)][1]?.[1];
  assert.match(signingFingerprint, /^[0-9A-F]{40}$/u);
  assert.notEqual(signingFingerprint, fingerprint);
  command('/usr/bin/git', ['init', '--quiet', repository]);
  signCommit('signed validation fixture');
  keyringDigest = sha256(readFileSync(join(gnupgHome, 'pubring.kbx')));
  runner = join(repository, relativeRunner);
});

after(() => rmSync(root, { recursive: true, force: true }));

test('preflight binds the exact signed graph, keyring, runner and toolchain without authority claims', () => {
  const { result, receipt } = runProducer();
  assert.equal(result.status, 0);
  assert.equal(receipt.recordKind, 'USF_TEST_ONLY_VALIDATION_PREFLIGHT');
  assert.equal(receipt.preflightPassed, true);
  assert.equal(receipt.realisationValidationPassed, false);
  assert.equal(receipt.eligibleForAdmission, false);
  assert.deepEqual(receipt.authorityClaims, []);
  assert.equal(receipt.graphCommit, graphCommit);
  assert.equal(receipt.graphTree, graphTree);
  assert.equal(receipt.signatureVerification.primaryKeyFingerprint, fingerprint);
  assert.equal(receipt.signatureVerification.signingKeyFingerprint, signingFingerprint);
  assert.equal(receipt.signatureVerification.goodSignatureKeyId, signingFingerprint.slice(-16));
  assert.equal(receipt.signatureVerification.publicKeyringDigest, keyringDigest);
  assert.match(receipt.runner.sourceDigest, /^sha256:[0-9a-f]{64}$/u);
  assert.match(receipt.runner.executable.digest, /^sha256:[0-9a-f]{64}$/u);
  assert.match(receipt.toolchainDigest, /^sha256:[0-9a-f]{64}$/u);
  assert.ok(receipt.commands.every(({ exitStatus }) => exitStatus === 0));
});

test('preflight receipt is deterministic for identical explicit inputs', () => {
  const first = runProducer();
  const second = runProducer();
  assert.equal(first.result.status, 0);
  assert.equal(second.result.status, 0);
  assert.deepEqual(first.receipt, second.receipt);
});

test('assertion failures report a stable exact code without claiming evidence success', () => {
  const { result, receipt } = runProducer({ mode: '--test-assertion-failure-only' });
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['ASSERTION_FAILED_TEST_EXPLICIT_FAILURE']);
  assert.deepEqual(receipt.failedAssertion, {
    id: 'test-explicit-failure',
    expectedDigest: sha256('{"value":true,"valueState":"DEFINED"}'),
    observedDigest: sha256('{"value":false,"valueState":"DEFINED"}'),
  });
  assert.equal(receipt.eligibleForAdmission, false);
  assert.deepEqual(receipt.authorityClaims, []);
});

test('undefined assertion values retain the exact failure code and digest binding', () => {
  const { result, receipt } = runProducer({
    mode: '--test-undefined-assertion-failure-only',
  });
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['ASSERTION_FAILED_TEST_UNDEFINED_FAILURE']);
  assert.deepEqual(receipt.failedAssertion, {
    id: 'test-undefined-failure',
    expectedDigest: sha256('{"value":"required","valueState":"DEFINED"}'),
    observedDigest: sha256('{"valueState":"UNDEFINED"}'),
  });
  assert.equal(receipt.eligibleForAdmission, false);
  assert.deepEqual(receipt.authorityClaims, []);
});

test('post-preflight loading resolves the canonical authority binding and semantic-model manifest', () => {
  const { result, receipt } = runProducer({ mode: '--test-authority-loading-only' });
  assert.equal(result.status, 0);
  assert.equal(receipt.recordKind, 'USF_TEST_ONLY_AUTHORITY_LOADING');
  assert.equal(receipt.preflightPassed, true);
  assert.equal(receipt.authorityBindingModuleLoaded, true);
  assert.equal(receipt.semanticManifestPath, join(repository, 'semantic-model/manifest.yaml'));
  assert.match(receipt.semanticManifestDigest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(receipt.realisationValidationPassed, false);
  assert.equal(receipt.eligibleForAdmission, false);
  assert.deepEqual(receipt.authorityClaims, []);
});

test('producer compile assembly supplies the canonical receipt-capable semantic authority client', () => {
  const { result, receipt } = runProducer({
    mode: '--test-client-assembly-only',
    environment: { USF_TEST_COMPILER_CLIENT_MODE: 'receipt-capable' },
  });
  assert.equal(result.status, 0);
  assert.equal(receipt.recordKind, 'USF_TEST_ONLY_COMPILER_CLIENT_ASSEMBLY');
  assert.equal(receipt.assemblyPassed, true);
  assert.equal(receipt.receiptCapable, true);
  assert.equal(receipt.expectedAuthorityDigest, `sha256:${'1'.repeat(64)}`);
  assert.equal(receipt.realisationValidationPassed, false);
  assert.equal(receipt.eligibleForAdmission, false);
  assert.deepEqual(receipt.authorityClaims, []);
});

test('producer compile assembly fails closed when the provider lacks validation receipts', () => {
  const { result, receipt } = runProducer({
    mode: '--test-client-assembly-only',
    environment: { USF_TEST_COMPILER_CLIENT_MODE: 'missing-receipts' },
  });
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['SEMANTIC_AUTHORITY_RECEIPT_PROVIDER_REQUIRED']);
  assert.equal(receipt.eligibleForAdmission, false);
  assert.deepEqual(receipt.authorityClaims, []);
});

test('preflight rejects an unexpected graph head', () => {
  const { result, receipt } = runProducer({ environment: { USF_GRAPH_COMMIT: '0'.repeat(40) } });
  assert.equal(result.status, 1);
  assert.equal(receipt.passed, false);
  assert.deepEqual(receipt.failureCodes, ['GRAPH_HEAD_MISMATCH']);
});

test('preflight rejects a keyring digest mismatch before signature verification', () => {
  const { result, receipt } = runProducer({ environment: { USF_EXPECTED_KEYRING_DIGEST: `sha256:${'0'.repeat(64)}` } });
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['PUBLIC_KEYRING_DIGEST_MISMATCH']);
});

test('preflight rejects a signing subkey substituted for the required primary fingerprint', () => {
  const { result, receipt } = runProducer({ environment: { USF_EXPECTED_SIGNER_FINGERPRINT: signingFingerprint } });
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['GRAPH_PRIMARY_FINGERPRINT_MISMATCH']);
});

test('preflight rejects a conflicting verified primary fingerprint', () => {
  const { result, receipt } = runProducer({ environment: { USF_EXPECTED_SIGNER_FINGERPRINT: 'A'.repeat(40) } });
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['GRAPH_PRIMARY_FINGERPRINT_MISMATCH']);
});

test('preflight ignores replace objects and hostile ambient global Git configuration', () => {
  const replacement = git([
    '-c', 'user.name=Hostile replacement fixture',
    '-c', 'user.email=hostile-replacement@example.invalid',
    'commit-tree', graphTree, '-p', graphCommit, '-m', 'unsigned hostile replacement',
  ]);
  git(['replace', graphCommit, replacement]);
  const hostileConfig = join(root, 'hostile.gitconfig');
  writeFileSync(hostileConfig, '[gpg]\n\tformat = ssh\n[core]\n\tfsmonitor = /bin/false\n');
  try {
    const { result, receipt } = runProducer({ environment: { GIT_CONFIG_GLOBAL: hostileConfig } });
    assert.equal(result.status, 0);
    assert.equal(receipt.graphCommit, graphCommit);
    assert.equal(receipt.graphTree, graphTree);
    assert.equal(receipt.signatureVerification.primaryKeyFingerprint, fingerprint);
  } finally {
    git(['replace', '-d', graphCommit]);
  }
});

test('preflight records a failed signature command and fails closed', () => {
  const unrelatedHome = join(root, 'unrelated-gnupg');
  mkdirSync(unrelatedHome, { mode: 0o700 });
  command('/usr/bin/gpg', [
    '--homedir', unrelatedHome,
    '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
    '--quick-generate-key', 'Unrelated fixture <unrelated@example.invalid>', 'ed25519', 'sign', '0',
  ]);
  const unrelatedDigest = sha256(readFileSync(join(unrelatedHome, 'pubring.kbx')));
  const { result, receipt } = runProducer({
    environment: {
      USF_GNUPGHOME: unrelatedHome,
      USF_EXPECTED_KEYRING_DIGEST: unrelatedDigest,
    },
  });
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['COMMAND_FAILED_GIT_VERIFY_COMMIT']);
  assert.equal(receipt.commands.at(-1).id, 'git-verify-commit');
  assert.notEqual(receipt.commands.at(-1).exitStatus, 0);
});

test('preflight rejects execution from runner bytes outside the signed graph', () => {
  const outsideRunner = join(root, 'outside-materialisation-proof.mjs');
  cpSync(runner, outsideRunner);
  const { result, receipt } = runProducer({ executable: outsideRunner });
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['RUNNER_SOURCE_OUTSIDE_GRAPH_BYTES']);
});

test('preflight rejects a signed graph with the wrong dependency lock', () => {
  writeFileSync(join(repository, 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}\n');
  signCommit('hostile dependency lock');
  const { result, receipt } = runProducer();
  assert.equal(result.status, 1);
  assert.deepEqual(receipt.failureCodes, ['PACKAGE_LOCK_DIGEST_MISMATCH']);
});
