import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
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

test('publishes concurrent identical writers once without clobbering', async () => {
  const root = temporaryDirectory();
  const results = await Promise.all([put(root), put(root), put(root)]);
  assert.equal(results.filter(({ created }) => created).length, 1);
  assert.equal(results.filter(({ created }) => !created).length, 2);
  assert.deepEqual((await readCasObject({ root, digest })).bytes, bytes);
});

test('rejects a symlink used as the CAS root', async () => {
  const parent = temporaryDirectory();
  const real = temporaryDirectory();
  const linked = join(parent, 'cas');
  symlinkSync(real, linked, 'dir');
  await rejectsCode(put(linked), 'CAS_DIRECTORY_OPEN_FAILED');
});

test('rejects a symlink used as an algorithm or shard parent', async () => {
  const root = temporaryDirectory();
  const outside = temporaryDirectory();
  symlinkSync(outside, join(root, 'sha256'), 'dir');
  await rejectsCode(put(root), 'CAS_DIRECTORY_OPEN_FAILED');

  rmSync(join(root, 'sha256'));
  mkdirSync(join(root, 'sha256'), { mode: 0o700 });
  symlinkSync(outside, join(root, 'sha256', hexadecimal.slice(0, 2)), 'dir');
  await rejectsCode(put(root), 'CAS_DIRECTORY_OPEN_FAILED');
});

test('rejects a symlink at the object leaf without following it', async () => {
  const root = temporaryDirectory();
  const outside = join(temporaryDirectory(), 'outside');
  writeFileSync(outside, bytes);
  const { shard, object } = paths(root);
  mkdirSync(shard, { recursive: true, mode: 0o700 });
  symlinkSync(outside, object);
  await rejectsCode(put(root), 'CAS_OBJECT_OPEN_FAILED');
  assert.deepEqual(readFileSync(outside), bytes);
});

test('rejects a special file at the object leaf', async () => {
  const root = temporaryDirectory();
  const { shard, object } = paths(root);
  mkdirSync(shard, { recursive: true, mode: 0o700 });
  const result = spawnSync('/usr/bin/mkfifo', [object], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  await rejectsCode(put(root), ['CAS_OBJECT_NOT_REGULAR', 'CAS_OBJECT_OPEN_FAILED']);
});

test('rejects an existing hard-linked object', async () => {
  const root = temporaryDirectory();
  await put(root);
  const { object } = paths(root);
  const alias = join(temporaryDirectory(), 'alias');
  linkSync(object, alias);
  await rejectsCode(readCasObject({ root, digest }), 'CAS_OBJECT_LINK_COUNT_INVALID');
});

test('detects a hard link added to the temporary object before publication', async () => {
  const root = temporaryDirectory();
  const alias = join(temporaryDirectory(), 'temporary-alias');
  await rejectsCode(put(root, {
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, temporaryPath }) => {
      if (phase === 'after-temporary-verified') linkSync(temporaryPath, alias);
    },
  }), 'CAS_OBJECT_LINK_COUNT_INVALID');
  assert.equal(existsSync(paths(root).object), false);
  assert.deepEqual(readFileSync(alias), bytes);
});

test('detects a hard link added to the published object', async () => {
  const root = temporaryDirectory();
  const alias = join(temporaryDirectory(), 'published-alias');
  await rejectsCode(put(root, {
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, objectPath }) => {
      if (phase === 'after-publish') linkSync(objectPath, alias);
    },
  }), 'CAS_OBJECT_LINK_COUNT_INVALID');
  assert.deepEqual(readFileSync(alias), bytes);
});

test('detects shard rename and substitution during creation', async () => {
  const root = temporaryDirectory();
  let displaced;
  await rejectsCode(put(root, {
    [HERMITIC_CAS_TEST_HOOK]: ({ phase }) => {
      if (phase !== 'after-temporary-verified') return;
      const { shard } = paths(root);
      displaced = `${shard}-displaced`;
      renameSync(shard, displaced);
      mkdirSync(shard, { mode: 0o700 });
    },
  }), 'CAS_DIRECTORY_IDENTITY_CHANGED');
  assert.equal(existsSync(paths(root).object), false);
  assert.equal(existsSync(join(displaced, hexadecimal)), false);
});

test('detects same-byte leaf rename and substitution after publication', async () => {
  const root = temporaryDirectory();
  let displaced;
  await rejectsCode(put(root, {
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, objectPath }) => {
      if (phase !== 'after-publish') return;
      displaced = `${objectPath}-displaced`;
      renameSync(objectPath, displaced);
      writeFileSync(objectPath, bytes, { mode: 0o600 });
    },
  }), ['CAS_OBJECT_CHANGED_DURING_READ', 'CAS_OBJECT_IDENTITY_CHANGED']);
  assert.deepEqual(readFileSync(displaced), bytes);
  assert.deepEqual(readFileSync(paths(root).object), bytes);
});

test('detects same-byte leaf rename and substitution during read', async () => {
  const root = temporaryDirectory();
  await put(root);
  let displaced;
  await rejectsCode(readCasObject({
    root,
    digest,
    [HERMITIC_CAS_TEST_HOOK]: ({ phase, objectPath }) => {
      if (phase !== 'after-object-read') return;
      displaced = `${objectPath}-displaced`;
      renameSync(objectPath, displaced);
      writeFileSync(objectPath, bytes, { mode: 0o600 });
    },
  }), ['CAS_OBJECT_CHANGED_AFTER_READ', 'CAS_OBJECT_IDENTITY_CHANGED']);
  assert.deepEqual(readFileSync(displaced), bytes);
});

test('detects shard rename and substitution during read', async () => {
  const root = temporaryDirectory();
  await put(root);
  let displaced;
  await rejectsCode(readCasObject({
    root,
    digest,
    [HERMITIC_CAS_TEST_HOOK]: ({ phase }) => {
      if (phase !== 'after-object-read') return;
      const { shard } = paths(root);
      displaced = `${shard}-displaced`;
      renameSync(shard, displaced);
      mkdirSync(shard, { mode: 0o700 });
    },
  }), 'CAS_DIRECTORY_IDENTITY_CHANGED');
  assert.deepEqual(readFileSync(join(displaced, hexadecimal)), bytes);
});

test('rejects unsafe object and directory permissions', async () => {
  const unsafeRoot = temporaryDirectory();
  chmodSync(unsafeRoot, 0o777);
  await rejectsCode(put(unsafeRoot), 'CAS_DIRECTORY_PERMISSIONS_UNSAFE');

  const root = temporaryDirectory();
  await put(root);
  chmodSync(paths(root).object, 0o666);
  await rejectsCode(readCasObject({ root, digest }), 'CAS_OBJECT_PERMISSIONS_UNSAFE');
});

test('rejects invalid addresses, bounds and descriptors without filesystem contact', async () => {
  const root = temporaryDirectory();
  await rejectsCode(readCasObject({ root, digest: '../escape' }), 'CAS_DIGEST_INVALID');
  await rejectsCode(put(root, { maxBytes: bytes.length - 1 }), 'CAS_OBJECT_TOO_LARGE');
  await rejectsCode(putCasObject({
    root,
    bytes: 'not-byte-input',
    mediaType: 'application/octet-stream',
  }), 'CAS_BYTES_INVALID');
  await rejectsCode(readCasObject({ root, digest, unrecognised: true }), 'CAS_OPTION_UNKNOWN');
  const saved = await put(root);
  await rejectsCode(verifyCasObject({
    root,
    descriptor: { ...saved, locator: 'cas://sha256/not-the-object' },
  }), 'CAS_DESCRIPTOR_LOCATOR_INVALID');
});

test('documents the exact Node/Linux syscall residuals', () => {
  assert.deepEqual(HERMITIC_CAS_RESIDUAL_RISKS, [
    'NODE_HAS_NO_OPENAT2_RESOLVE_BENEATH',
    'NODE_HAS_NO_RENAMEAT2_NOREPLACE',
    'NODE_HAS_NO_INODE_CONDITIONAL_UNLINKAT',
    'HOSTILE_WRITER_CAN_MUTATE_NAMESPACE_AFTER_RETURN',
  ]);
});
