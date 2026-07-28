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
  symlinkSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  after,
  afterEach,
  before,
  test,
} from 'node:test';
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
const protocol = 'usf-hermetic-cas-linkat-empty-path-v1';
const moduleUrl = new URL('./hermetic-cas.mjs', import.meta.url).href;
let helperRoot;
let nativePublisher;
let failingPublisher;
let linkThenFailPublisher;

function sha256File(path) {
  return `sha256:${createHash('sha256').update(readFileSync(path)).digest('hex')}`;
}

function buildPublisher(name, { fail = false, failAfterLink = false } = {}) {
  const assembly = join(helperRoot, `${name}.s`);
  const object = join(helperRoot, `${name}.o`);
  const executable = join(helperRoot, name);
  const source = fail
    ? `
.global _start
.text
_start:
  mov $60, %rax
  mov $70, %rdi
  syscall
`
    : `
.global _start
.section .rodata
empty:
  .byte 0
.text
_start:
  mov $265, %rax
  mov $4, %rdi
  lea empty(%rip), %rsi
  mov $5, %rdx
  mov 24(%rsp), %r10
  mov $4096, %r8
  syscall
  test %rax, %rax
  jz published
  neg %rax
  cmp $17, %rax
  je existing
  mov $70, %rdi
  jmp exit
published:
${failAfterLink ? `  mov $60, %rax
  mov $72, %rdi
  syscall` : `\
  mov $74, %rax
  mov $5, %rdi
  syscall
  test %rax, %rax
  js sync_failed
  xor %rdi, %rdi
  jmp exit`}
existing:
  mov $17, %rdi
  jmp exit
sync_failed:
  mov $71, %rdi
exit:
  mov $60, %rax
  syscall
`;
  writeFileSync(assembly, source, { mode: 0o600 });
  const assembled = spawnSync('/usr/bin/as', ['-o', object, assembly], { encoding: 'utf8' });
  assert.equal(assembled.status, 0, assembled.stderr);
  const linked = spawnSync('/usr/bin/ld', ['-o', executable, object], { encoding: 'utf8' });
  assert.equal(linked.status, 0, linked.stderr);
  chmodSync(executable, 0o500);
  return Object.freeze({
    executable,
    digest: sha256File(executable),
    protocol,
  });
}

before(() => {
  assert.equal(process.platform, 'linux');
  assert.equal(process.arch, 'x64');
  helperRoot = mkdtempSync(join(tmpdir(), 'usf-hermetic-cas-native-helper-'));
  chmodSync(helperRoot, 0o700);
  nativePublisher = buildPublisher('publisher');
  failingPublisher = buildPublisher('publisher-failure', { fail: true });
  linkThenFailPublisher = buildPublisher('publisher-link-then-failure', { failAfterLink: true });
});

after(() => {
  rmSync(helperRoot, { recursive: true, force: true });
});

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
    object: join(shard, hexadecimal),
  };
}

async function put(root, options = {}) {
  return putCasObject({
    root,
    bytes,
    mediaType: 'application/octet-stream',
    nativePublisher,
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
const [root, executable, helperDigest, payload] = process.argv.slice(1);
const result = await putCasObject({
  root,
  bytes: Buffer.from(payload, 'base64'),
  mediaType: 'application/octet-stream',
  nativePublisher: {
    executable,
    digest: helperDigest,
    protocol: ${JSON.stringify(protocol)},
  },
});
process.stdout.write(JSON.stringify(result));
`;

function startBarrierWriter(root, ready, release, phase) {
  const script = `
import { writeFileSync, existsSync } from 'node:fs';
import { putCasObject, HERMITIC_CAS_TEST_HOOK } from ${JSON.stringify(moduleUrl)};
const [root, executable, helperDigest, payload, ready, release, phase] = process.argv.slice(1);
await putCasObject({
  root,
  bytes: Buffer.from(payload, 'base64'),
  mediaType: 'application/octet-stream',
  nativePublisher: {
    executable,
    digest: helperDigest,
    protocol: ${JSON.stringify(protocol)},
  },
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
    nativePublisher.executable,
    nativePublisher.digest,
    bytes.toString('base64'),
    ready,
    release,
    phase,
  ]);
}

test('fails closed when no authority-approved native publisher is supplied', async () => {
  const root = temporaryDirectory();
  await rejectsCode(putCasObject({
    root,
    bytes,
    mediaType: 'application/octet-stream',
  }), 'CAS_NATIVE_PUBLISHER_REQUIRED');
  assert.equal(existsSync(join(root, 'sha256')), false);
});

test('creates, reads, verifies and idempotently reuses one addressed object', async () => {
  const root = temporaryDirectory();
  const first = await put(root);
  const second = await put(root);
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(first.digest, digest);
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
  assert.deepEqual(await verifyCasObject({ root, descriptor: first }), {
    verified: true,
    digest,
    byteSize: bytes.length,
    mediaType: 'application/octet-stream',
  });
});

test('publishes N cross-process identical writers exactly once', async () => {
  const root = temporaryDirectory();
  const writers = Array.from({ length: 12 }, () => child(writerScript, [
    root,
    nativePublisher.executable,
    nativePublisher.digest,
    bytes.toString('base64'),
  ]));
  const completed = await Promise.all(writers.map(({ completed: done }) => done));
  completed.forEach((result) => assert.equal(result.status, 0, result.stderr));
  const results = completed.map(({ stdout }) => JSON.parse(stdout));
  assert.equal(results.filter(({ created }) => created).length, 1);
  assert.equal(results.filter(({ created }) => !created).length, 11);
  assert.equal(statSync(paths(root).object).nlink, 1);
  assert.equal(statSync(paths(root).object).mode & 0o7777, 0o600);
  assert.deepEqual(readdirSync(paths(root).shard), [hexadecimal]);
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
});

test('a reader sees no partial object while anonymous staging is blocked', async () => {
  const root = temporaryDirectory();
  const barrierRoot = temporaryDirectory('usf-cas-barrier-');
  const ready = join(barrierRoot, 'ready');
  const release = join(barrierRoot, 'release');
  const writer = startBarrierWriter(root, ready, release, 'after-temporary-verified');
  await waitFor(ready);
  await rejectsCode(readCasObject({ root, digest }), 'CAS_OBJECT_OPEN_FAILED');
  writeFileSync(release, 'release');
  const result = await writer.completed;
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
});

test('kill before publication leaves no named staging or final object and restart succeeds', async () => {
  const root = temporaryDirectory();
  const barrierRoot = temporaryDirectory('usf-cas-kill-before-');
  const ready = join(barrierRoot, 'ready');
  const release = join(barrierRoot, 'never-release');
  const writer = startBarrierWriter(root, ready, release, 'after-temporary-verified');
  await waitFor(ready);
  writer.processHandle.kill('SIGKILL');
  const killed = await writer.completed;
  assert.equal(killed.signal, 'SIGKILL');
  assert.equal(existsSync(paths(root).object), false);
  assert.deepEqual(readdirSync(paths(root).shard), []);
  assert.deepEqual(await put(root), {
    digest,
    byteSize: bytes.length,
    mediaType: 'application/octet-stream',
    locator: `cas://sha256/${hexadecimal}`,
    created: true,
  });
});

test('kill after publication leaves one-link valid final object and restart reuses it', async () => {
  const root = temporaryDirectory();
  const barrierRoot = temporaryDirectory('usf-cas-kill-after-');
  const ready = join(barrierRoot, 'ready');
  const release = join(barrierRoot, 'never-release');
  const writer = startBarrierWriter(root, ready, release, 'after-publish');
  await waitFor(ready);
  writer.processHandle.kill('SIGKILL');
  const killed = await writer.completed;
  assert.equal(killed.signal, 'SIGKILL');
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
  assert.equal((await put(root)).created, false);
});

test('native publisher failure leaves no named staging or final object', async () => {
  const root = temporaryDirectory();
  await rejectsCode(put(root, { nativePublisher: failingPublisher }), 'CAS_NATIVE_PUBLISHER_STATUS_INVALID');
  assert.equal(existsSync(paths(root).object), false);
  assert.deepEqual(readdirSync(paths(root).shard), []);
  assert.deepEqual(await put(root), {
    digest,
    byteSize: bytes.length,
    mediaType: 'application/octet-stream',
    locator: `cas://sha256/${hexadecimal}`,
    created: true,
  });
});

test('failure after atomic publication never unlinks the one-link final object', async () => {
  const root = temporaryDirectory();
  await rejectsCode(
    put(root, { nativePublisher: linkThenFailPublisher }),
    'CAS_NATIVE_PUBLISHER_STATUS_INVALID',
  );
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
  assert.equal((await put(root)).created, false);
});

test('rejects publisher substitution, wrong mode and wrong digest', async () => {
  const root = temporaryDirectory();
  await rejectsCode(put(root, {
    nativePublisher: { ...nativePublisher, digest: `sha256:${'0'.repeat(64)}` },
  }), 'CAS_OBJECT_DIGEST_MISMATCH');
  chmodSync(nativePublisher.executable, 0o700);
  try {
    await rejectsCode(put(root), 'CAS_OBJECT_PERMISSIONS_UNSAFE');
  } finally {
    chmodSync(nativePublisher.executable, 0o500);
  }
});

test('rejects a symlink used as the CAS root, algorithm, shard or object', async () => {
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

  rmSync(join(root, 'sha256'), { recursive: true });
  const { shard, object } = paths(root);
  mkdirSync(shard, { recursive: true, mode: 0o700 });
  const outsideObject = join(outside, 'outside-object');
  writeFileSync(outsideObject, bytes, { mode: 0o600 });
  symlinkSync(outsideObject, object);
  await rejectsCode(put(root), 'CAS_OBJECT_OPEN_FAILED');
  assert.deepEqual(readFileSync(outsideObject), bytes);
});

test('rejects special-file and hard-link object leaves', async () => {
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

test('never unlinks a published name after hard-link or identity failure', async () => {
  const hardlinkRoot = temporaryDirectory();
  const alias = join(temporaryDirectory(), 'published-alias');
  await rejectsCode(put(hardlinkRoot, {
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, objectPath }) => {
      if (phase === 'after-publish') linkSync(objectPath, alias);
    },
  }), 'CAS_OBJECT_LINK_COUNT_INVALID');
  assert.equal(existsSync(paths(hardlinkRoot).object), true);
  assert.deepEqual(readFileSync(alias), bytes);

  const substitutionRoot = temporaryDirectory();
  let displaced;
  await rejectsCode(put(substitutionRoot, {
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, objectPath }) => {
      if (phase !== 'after-publish') return;
      displaced = `${objectPath}-displaced`;
      renameSync(objectPath, displaced);
      writeFileSync(objectPath, bytes, { mode: 0o600 });
    },
  }), ['CAS_OBJECT_CHANGED_DURING_READ', 'CAS_OBJECT_IDENTITY_CHANGED']);
  assert.deepEqual(readFileSync(displaced), bytes);
  assert.deepEqual(readFileSync(paths(substitutionRoot).object), bytes);
});

test('detects parent and leaf rename/substitution races during read', async () => {
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
      const { shard } = paths(parentRoot);
      displacedShard = `${shard}-displaced`;
      renameSync(shard, displacedShard);
      mkdirSync(shard, { mode: 0o700 });
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

test('bounds input before copying and rejects invalid descriptors and options', async () => {
  const root = temporaryDirectory();
  await rejectsCode(put(root, { maxBytes: bytes.length - 1 }), 'CAS_OBJECT_TOO_LARGE');
  assert.equal(existsSync(join(root, 'sha256')), false);
  await rejectsCode(readCasObject({ root, digest: '../escape' }), 'CAS_DIGEST_INVALID');
  await rejectsCode(putCasObject({
    root,
    bytes: 'not-byte-input',
    mediaType: 'application/octet-stream',
    nativePublisher,
  }), 'CAS_BYTES_INVALID');
  await rejectsCode(readCasObject({ root, digest, unrecognised: true }), 'CAS_OPTION_UNKNOWN');
  const saved = await put(root);
  await rejectsCode(verifyCasObject({
    root,
    descriptor: { ...saved, locator: 'cas://sha256/not-the-object' },
  }), 'CAS_DESCRIPTOR_LOCATOR_INVALID');
});

test('documents the exact remaining Node/Linux boundary', () => {
  assert.deepEqual(HERMITIC_CAS_RESIDUAL_RISKS, [
    'NODE_HAS_NO_OPENAT2_RESOLVE_BENEATH',
    'NATIVE_LINKAT_AT_EMPTY_PATH_HELPER_REQUIRED_FOR_CREATION',
    'HOSTILE_WRITER_CAN_MUTATE_NAMESPACE_AFTER_RETURN',
  ]);
});
