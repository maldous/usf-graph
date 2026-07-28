import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, test } from 'node:test';
import {
  HERMITIC_CAS_RESIDUAL_RISKS,
  HERMITIC_CAS_TEST_HOOK,
  HermeticCasError,
  putCasObject,
  readCasObject,
  verifyCasObject,
} from './hermetic-cas.mjs';

const roots = [];
const bytes = Buffer.from('hermetic-cas-test-payload\n');
const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const hexadecimal = digest.slice(7);
const protocol = 'usf-hermetic-cas-gnu-mv-noreplace-v1';
const moduleUrl = new URL('./hermetic-cas.mjs', import.meta.url).href;

const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

function systemFileRecord(path) {
  const stat = statSync(path);
  return Object.freeze({
    path,
    digest: sha256(readFileSync(path)),
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode & 0o7777,
    size: stat.size,
  });
}

function buildSystemPublisher(executablePath = '/usr/bin/mv') {
  const executable = systemFileRecord(executablePath);
  const loader = systemFileRecord('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2');
  const libraries = [
    '/usr/lib/x86_64-linux-gnu/libc.so.6',
    '/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2',
    '/usr/lib/x86_64-linux-gnu/libattr.so.1.1.2501',
    '/usr/lib/x86_64-linux-gnu/libacl.so.1.1.2301',
    '/usr/lib/x86_64-linux-gnu/libselinux.so.1',
  ].map(systemFileRecord);
  const closure = { executable, libraries, loader };
  const version = spawnSync('/usr/bin/mv', ['--version'], {
    env: { LANG: 'C', LC_ALL: 'C' },
    encoding: null,
  });
  assert.equal(version.status, 0);
  assert.equal(version.stderr.length, 0);
  return Object.freeze({
    protocol,
    executable,
    loader,
    libraries: Object.freeze(libraries),
    closureDigest: sha256(Buffer.from(canonicalJson(closure))),
    version: 'mv (GNU coreutils) 9.1',
    versionStdoutDigest: sha256(version.stdout),
  });
}

const systemPublisher = buildSystemPublisher();

function temporaryDirectory(prefix = 'usf-hermetic-cas-') {
  const path = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(path, 0o700);
  roots.push(path);
  return path;
}

function paths(root) {
  const shard = join(root, 'sha256', hexadecimal.slice(0, 2));
  return {
    shard,
    staging: join(shard, '.staging'),
    object: join(shard, hexadecimal),
  };
}

async function put(root, options = {}) {
  return putCasObject({
    root,
    bytes,
    mediaType: 'application/octet-stream',
    systemPublisher,
    ...options,
  });
}

async function rejectsCode(promise, codes) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof HermeticCasError, error?.stack);
    assert.ok([].concat(codes).includes(error.code), `unexpected error code ${error.code}`);
    return true;
  });
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function child(script, args) {
  const processHandle = spawn(
    process.execPath,
    ['--input-type=module', '--eval', script, ...args],
    {
      env: { LANG: 'C', LC_ALL: 'C' },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  const stdout = [];
  const stderr = [];
  processHandle.stdout.on('data', (chunk) => stdout.push(chunk));
  processHandle.stderr.on('data', (chunk) => stderr.push(chunk));
  return {
    processHandle,
    completed: new Promise((resolve) => {
      processHandle.on('close', (status, signal) => resolve({
        status,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      }));
    }),
  };
}

async function waitFor(path, deadlineMs = 10_000) {
  const deadline = Date.now() + deadlineMs;
  while (!existsSync(path)) {
    if (Date.now() >= deadline) throw new Error(`barrier deadline expired: ${path}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const writerScript = `
import { putCasObject } from ${JSON.stringify(moduleUrl)};
const [root, publisherBase64, payload] = process.argv.slice(1);
const result = await putCasObject({
  root,
  bytes: Buffer.from(payload, 'base64'),
  mediaType: 'application/octet-stream',
  systemPublisher: JSON.parse(Buffer.from(publisherBase64, 'base64').toString('utf8')),
});
process.stdout.write(JSON.stringify(result));
`;

function startBarrierWriter(root, ready, release, phase) {
  const script = `
import { writeFileSync, existsSync } from 'node:fs';
import { putCasObject, HERMITIC_CAS_TEST_HOOK } from ${JSON.stringify(moduleUrl)};
const [root, publisherBase64, payload, ready, release, phase] = process.argv.slice(1);
await putCasObject({
  root,
  bytes: Buffer.from(payload, 'base64'),
  mediaType: 'application/octet-stream',
  systemPublisher: JSON.parse(Buffer.from(publisherBase64, 'base64').toString('utf8')),
  [HERMITIC_CAS_TEST_HOOK]: async (event) => {
    if (event.phase !== phase) return;
    writeFileSync(ready, event.phase);
    while (!existsSync(release)) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  },
});
`;
  return child(script, [
    root,
    Buffer.from(JSON.stringify(systemPublisher)).toString('base64'),
    bytes.toString('base64'),
    ready,
    release,
    phase,
  ]);
}

test('fails closed without the exact GNU mv runtime descriptor', async () => {
  const root = temporaryDirectory();
  await rejectsCode(putCasObject({
    root,
    bytes,
    mediaType: 'application/octet-stream',
  }), 'CAS_SYSTEM_PUBLISHER_REQUIRED');
  assert.equal(existsSync(join(root, 'sha256')), false);
});

test('pinned GNU mv 9.1 uses renameat2 RENAME_NOREPLACE without clobbering', () => {
  const root = temporaryDirectory('usf-cas-mv-semantics-');
  const source = join(root, 'source');
  const secondSource = join(root, 'second-source');
  const target = join(root, 'target');
  const firstTrace = join(root, 'first.trace');
  const existingTrace = join(root, 'existing.trace');
  writeFileSync(source, 'first', { mode: 0o600 });
  writeFileSync(secondSource, 'second', { mode: 0o600 });
  const loaderArguments = [
    '--inhibit-cache',
    '--library-path',
    '/nonexistent',
    '--preload',
    systemPublisher.libraries.map(({ path }) => path).join(':'),
    systemPublisher.executable.path,
    '--no-clobber',
    '--no-target-directory',
    '--',
  ];
  const first = spawnSync('/usr/bin/strace', [
    '-f', '-qq', '-e', 'trace=renameat2', '-o', firstTrace,
    systemPublisher.loader.path,
    ...loaderArguments,
    source,
    target,
  ], { env: { LANG: 'C', LC_ALL: 'C' }, encoding: 'utf8' });
  assert.equal(first.status, 0, first.stderr);
  assert.match(readFileSync(firstTrace, 'utf8'), /renameat2\(.*RENAME_NOREPLACE\) = 0/);
  assert.equal(readFileSync(target, 'utf8'), 'first');

  const existing = spawnSync('/usr/bin/strace', [
    '-f', '-qq', '-e', 'trace=renameat2', '-o', existingTrace,
    systemPublisher.loader.path,
    ...loaderArguments,
    secondSource,
    target,
  ], { env: { LANG: 'C', LC_ALL: 'C' }, encoding: 'utf8' });
  assert.equal(existing.status, 0, existing.stderr);
  assert.match(
    readFileSync(existingTrace, 'utf8'),
    /renameat2\(.*RENAME_NOREPLACE\) = -1 EEXIST/,
  );
  assert.equal(readFileSync(target, 'utf8'), 'first');
  assert.equal(readFileSync(secondSource, 'utf8'), 'second');
});

test('creates, reads, verifies and idempotently reuses one addressed object', async () => {
  const root = temporaryDirectory();
  const first = await put(root);
  const second = await put(root);
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(first.digest, digest);
  assert.deepEqual(readdirSync(paths(root).staging), []);
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
  assert.deepEqual(await verifyCasObject({ root, descriptor: first }), {
    verified: true,
    digest,
    byteSize: bytes.length,
    mediaType: 'application/octet-stream',
  });
});

test('publishes N cross-process writers once and quarantines losing staging files', async () => {
  const root = temporaryDirectory();
  const publisherBase64 = Buffer.from(JSON.stringify(systemPublisher)).toString('base64');
  const writers = Array.from({ length: 12 }, () => child(writerScript, [
    root,
    publisherBase64,
    bytes.toString('base64'),
  ]));
  const completed = await Promise.all(writers.map(({ completed: done }) => done));
  completed.forEach((result) => assert.equal(result.status, 0, result.stderr));
  const results = completed.map(({ stdout }) => JSON.parse(stdout));
  assert.equal(results.filter(({ created }) => created).length, 1);
  assert.equal(results.filter(({ created }) => !created).length, 11);
  assert.equal(statSync(paths(root).object).nlink, 1);
  assert.equal(statSync(paths(root).object).mode & 0o7777, 0o600);
  for (const name of readdirSync(paths(root).staging)) {
    const orphan = join(paths(root).staging, name);
    assert.equal(statSync(orphan).nlink, 1);
    assert.equal(statSync(orphan).mode & 0o7777, 0o600);
    assert.deepEqual(readFileSync(orphan), bytes);
  }
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
});

test('reader sees no partial final while a fsynced staging writer is blocked', async () => {
  const root = temporaryDirectory();
  const barriers = temporaryDirectory('usf-cas-reader-barrier-');
  const ready = join(barriers, 'ready');
  const release = join(barriers, 'release');
  const writer = startBarrierWriter(root, ready, release, 'after-temporary-verified');
  await waitFor(ready);
  assert.equal(readdirSync(paths(root).staging).length, 1);
  await rejectsCode(readCasObject({ root, digest }), 'CAS_OBJECT_OPEN_FAILED');
  writeFileSync(release, 'release');
  const result = await writer.completed;
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
});

test('SIGKILL before rename leaves only quarantined staging and restart succeeds', async () => {
  const root = temporaryDirectory();
  const barriers = temporaryDirectory('usf-cas-kill-before-');
  const ready = join(barriers, 'ready');
  const release = join(barriers, 'never-release');
  const writer = startBarrierWriter(root, ready, release, 'after-temporary-verified');
  await waitFor(ready);
  writer.processHandle.kill('SIGKILL');
  const killed = await writer.completed;
  assert.equal(killed.signal, 'SIGKILL');
  assert.equal(existsSync(paths(root).object), false);
  assert.equal(readdirSync(paths(root).staging).length, 1);
  assert.equal((await put(root)).created, true);
});

test('SIGKILL after rename leaves one-link final and restart reuses it', async () => {
  const root = temporaryDirectory();
  const barriers = temporaryDirectory('usf-cas-kill-after-');
  const ready = join(barriers, 'ready');
  const release = join(barriers, 'never-release');
  const writer = startBarrierWriter(root, ready, release, 'after-publish');
  await waitFor(ready);
  writer.processHandle.kill('SIGKILL');
  const killed = await writer.completed;
  assert.equal(killed.signal, 'SIGKILL');
  assert.equal(statSync(paths(root).object).nlink, 1);
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
  assert.equal((await put(root)).created, false);
});

test('unsupported version behavior fails before CAS staging', async () => {
  const root = temporaryDirectory();
  await rejectsCode(
    put(root, {
      systemPublisher: {
        ...systemPublisher,
        versionStdoutDigest: `sha256:${'0'.repeat(64)}`,
      },
    }),
    'CAS_SYSTEM_PUBLISHER_OUTPUT_INVALID',
  );
  assert.equal(existsSync(join(root, 'sha256')), false);
});

test('descriptor rejects protocol, closure, version, digest and metadata drift', async () => {
  const root = temporaryDirectory();
  await rejectsCode(put(root, {
    systemPublisher: { ...systemPublisher, protocol: 'unknown' },
  }), 'CAS_SYSTEM_PUBLISHER_PROTOCOL_INVALID');
  await rejectsCode(put(root, {
    systemPublisher: { ...systemPublisher, version: 'mv (GNU coreutils) unknown' },
  }), 'CAS_SYSTEM_PUBLISHER_VERSION_INVALID');
  await rejectsCode(put(root, {
    systemPublisher: { ...systemPublisher, closureDigest: `sha256:${'0'.repeat(64)}` },
  }), 'CAS_SYSTEM_PUBLISHER_CLOSURE_DIGEST_INVALID');
  const wrongExecutable = {
    ...systemPublisher.executable,
    digest: `sha256:${'0'.repeat(64)}`,
  };
  const wrongClosure = {
    executable: wrongExecutable,
    libraries: systemPublisher.libraries,
    loader: systemPublisher.loader,
  };
  await rejectsCode(put(root, {
    systemPublisher: {
      ...systemPublisher,
      executable: wrongExecutable,
      closureDigest: sha256(Buffer.from(canonicalJson(wrongClosure))),
    },
  }), 'CAS_SYSTEM_PUBLISHER_DIGEST_INVALID');
  const wrongMode = { ...systemPublisher.executable, mode: 0o700 };
  const wrongModeClosure = {
    executable: wrongMode,
    libraries: systemPublisher.libraries,
    loader: systemPublisher.loader,
  };
  await rejectsCode(put(root, {
    systemPublisher: {
      ...systemPublisher,
      executable: wrongMode,
      closureDigest: sha256(Buffer.from(canonicalJson(wrongModeClosure))),
    },
  }), 'CAS_SYSTEM_PUBLISHER_METADATA_INVALID');
  const wrongPath = systemFileRecord('/usr/bin/false');
  const wrongPathClosure = {
    executable: wrongPath,
    libraries: systemPublisher.libraries,
    loader: systemPublisher.loader,
  };
  await rejectsCode(put(root, {
    systemPublisher: {
      ...systemPublisher,
      executable: wrongPath,
      closureDigest: sha256(Buffer.from(canonicalJson(wrongPathClosure))),
    },
  }), 'CAS_SYSTEM_PUBLISHER_PATH_INVALID');
});

test('rejects symlink parent/leaf, special type and hard-linked object', async () => {
  const parent = temporaryDirectory();
  const real = temporaryDirectory();
  const linked = join(parent, 'cas');
  symlinkSync(real, linked, 'dir');
  await rejectsCode(put(linked), 'CAS_DIRECTORY_OPEN_FAILED');

  const root = temporaryDirectory();
  const outside = temporaryDirectory();
  symlinkSync(outside, join(root, 'sha256'), 'dir');
  await rejectsCode(put(root), 'CAS_DIRECTORY_OPEN_FAILED');
  rmSync(join(root, 'sha256'));
  mkdirSync(join(root, 'sha256'), { mode: 0o700 });
  symlinkSync(outside, join(root, 'sha256', hexadecimal.slice(0, 2)), 'dir');
  await rejectsCode(put(root), 'CAS_DIRECTORY_OPEN_FAILED');

  const fifoRoot = temporaryDirectory();
  const fifoPaths = paths(fifoRoot);
  mkdirSync(fifoPaths.shard, { recursive: true, mode: 0o700 });
  const fifo = spawnSync('/usr/bin/mkfifo', [fifoPaths.object], { encoding: 'utf8' });
  assert.equal(fifo.status, 0, fifo.stderr);
  await rejectsCode(put(fifoRoot), ['CAS_OBJECT_NOT_REGULAR', 'CAS_OBJECT_OPEN_FAILED']);

  const hardlinkRoot = temporaryDirectory();
  await put(hardlinkRoot);
  const alias = join(temporaryDirectory(), 'alias');
  linkSync(paths(hardlinkRoot).object, alias);
  await rejectsCode(readCasObject({ root: hardlinkRoot, digest }), 'CAS_OBJECT_LINK_COUNT_INVALID');
});

test('hard-linked or substituted staging/final entries are never ambiguously deleted', async () => {
  const stagingRoot = temporaryDirectory();
  const stagingAlias = join(temporaryDirectory(), 'staging-alias');
  await rejectsCode(put(stagingRoot, {
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, stagingPath }) => {
      if (phase === 'after-temporary-verified') linkSync(stagingPath, stagingAlias);
    },
  }), 'CAS_OBJECT_LINK_COUNT_INVALID');
  assert.deepEqual(readFileSync(stagingAlias), bytes);
  assert.equal(readdirSync(paths(stagingRoot).staging).length, 1);

  const finalRoot = temporaryDirectory();
  let displaced;
  await rejectsCode(put(finalRoot, {
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, objectPath }) => {
      if (phase !== 'after-publish') return;
      displaced = `${objectPath}-displaced`;
      renameSync(objectPath, displaced);
      writeFileSync(objectPath, bytes, { mode: 0o600 });
    },
  }), ['CAS_OBJECT_CHANGED_DURING_READ', 'CAS_OBJECT_IDENTITY_CHANGED']);
  assert.deepEqual(readFileSync(displaced), bytes);
  assert.deepEqual(readFileSync(paths(finalRoot).object), bytes);
});

test('detects parent and leaf substitution during verified reads', async () => {
  const leafRoot = temporaryDirectory();
  await put(leafRoot);
  let displacedLeaf;
  await rejectsCode(readCasObject({
    root: leafRoot,
    digest,
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, objectPath }) => {
      if (phase !== 'after-object-read') return;
      displacedLeaf = `${objectPath}-displaced`;
      renameSync(objectPath, displacedLeaf);
      writeFileSync(objectPath, bytes, { mode: 0o600 });
    },
  }), ['CAS_OBJECT_CHANGED_AFTER_READ', 'CAS_OBJECT_IDENTITY_CHANGED']);

  const parentRoot = temporaryDirectory();
  await put(parentRoot);
  let displacedShard;
  await rejectsCode(readCasObject({
    root: parentRoot,
    digest,
    [HERMITIC_CAS_TEST_HOOK]: ({ phase }) => {
      if (phase !== 'after-object-read') return;
      displacedShard = `${paths(parentRoot).shard}-displaced`;
      renameSync(paths(parentRoot).shard, displacedShard);
      mkdirSync(paths(parentRoot).shard, { mode: 0o700 });
    },
  }), 'CAS_DIRECTORY_IDENTITY_CHANGED');
  assert.deepEqual(readFileSync(join(displacedShard, hexadecimal)), bytes);
});

test('enforces exact 0700 directories and exact 0600 objects', async () => {
  const unsafeRoot = temporaryDirectory();
  chmodSync(unsafeRoot, 0o755);
  await rejectsCode(put(unsafeRoot), 'CAS_DIRECTORY_PERMISSIONS_UNSAFE');

  const algorithmRoot = temporaryDirectory();
  mkdirSync(join(algorithmRoot, 'sha256'), { mode: 0o755 });
  await rejectsCode(put(algorithmRoot), 'CAS_DIRECTORY_PERMISSIONS_UNSAFE');

  const shardRoot = temporaryDirectory();
  mkdirSync(paths(shardRoot).shard, { recursive: true, mode: 0o755 });
  await rejectsCode(put(shardRoot), 'CAS_DIRECTORY_PERMISSIONS_UNSAFE');

  const objectRoot = temporaryDirectory();
  await put(objectRoot);
  chmodSync(paths(objectRoot).object, 0o644);
  await rejectsCode(readCasObject({ root: objectRoot, digest }), 'CAS_OBJECT_PERMISSIONS_UNSAFE');
});

test('bounds input before copy and rejects invalid descriptors and options', async () => {
  const root = temporaryDirectory();
  await rejectsCode(put(root, { maxBytes: bytes.length - 1 }), 'CAS_OBJECT_TOO_LARGE');
  assert.equal(existsSync(join(root, 'sha256')), false);
  await rejectsCode(readCasObject({ root, digest: '../escape' }), 'CAS_DIGEST_INVALID');
  await rejectsCode(putCasObject({
    root,
    bytes: 'not-byte-input',
    mediaType: 'application/octet-stream',
    systemPublisher,
  }), 'CAS_BYTES_INVALID');
  await rejectsCode(readCasObject({ root, digest, unrecognised: true }), 'CAS_OPTION_UNKNOWN');
  const saved = await put(root);
  await rejectsCode(verifyCasObject({
    root,
    descriptor: { ...saved, locator: 'cas://sha256/not-the-object' },
  }), 'CAS_DESCRIPTOR_LOCATOR_INVALID');
});

test('documents the exact remaining system boundary', () => {
  assert.deepEqual(HERMITIC_CAS_RESIDUAL_RISKS, [
    'NODE_HAS_NO_OPENAT2_RESOLVE_BENEATH',
    'GNU_MV_RUNTIME_DESCRIPTOR_REQUIRED_FOR_CREATION',
    'KERNEL_VDSO_IS_OUTSIDE_FILE_DIGEST_CLOSURE',
    'FAILED_STAGING_RECOVERY_IS_SEPARATE_AND_FAIL_CLOSED',
    'HOSTILE_WRITER_CAN_MUTATE_NAMESPACE_AFTER_RETURN',
  ]);
});
