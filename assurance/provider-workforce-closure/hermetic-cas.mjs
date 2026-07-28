import { createHash, randomBytes } from 'node:crypto';
import {
  constants as fsConstants,
  link,
  mkdir,
  open,
  unlink,
} from 'node:fs/promises';
import {
  isAbsolute,
  join,
  normalize,
  parse,
} from 'node:path';

const {
  O_CREAT,
  O_DIRECTORY,
  O_EXCL,
  O_NONBLOCK,
  O_NOFOLLOW,
  O_RDONLY,
  O_RDWR,
} = fsConstants;

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const SAFE_MEDIA_TYPE = /^[\x21-\x7e]{1,255}$/;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const DIRECTORY_FLAGS = O_RDONLY | O_DIRECTORY | O_NOFOLLOW;
const FILE_READ_FLAGS = O_RDONLY | O_NOFOLLOW | O_NONBLOCK;
const FILE_CREATE_FLAGS = O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW;
const PROC_FD_ROOT = '/proc/self/fd';

/*
 * This symbol exists only so the adversarial tests can stop execution at exact
 * boundaries. A hook cannot waive a check: every hook is followed by another
 * fd, namespace and digest verification.
 */
export const HERMITIC_CAS_TEST_HOOK = Symbol('HERMITIC_CAS_TEST_HOOK');

/*
 * Node does not expose openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS),
 * renameat2(RENAME_NOREPLACE), or an inode-conditional unlinkat. This module
 * therefore traverses pinned directory fds through /proc/self/fd, publishes
 * with atomic link(2)-if-absent instead of clobbering rename(2), and always
 * reopens/verifies the final name. A hostile peer with write access can still
 * change a pathname immediately after the final verification, or race the
 * best-effort rollback unlink. Consumers must read through readCasObject for
 * every use; a returned filesystem pathname is intentionally not exposed.
 */
export const HERMITIC_CAS_RESIDUAL_RISKS = Object.freeze([
  'NODE_HAS_NO_OPENAT2_RESOLVE_BENEATH',
  'NODE_HAS_NO_RENAMEAT2_NOREPLACE',
  'NODE_HAS_NO_INODE_CONDITIONAL_UNLINKAT',
  'HOSTILE_WRITER_CAN_MUTATE_NAMESPACE_AFTER_RETURN',
]);

export class HermeticCasError extends Error {
  constructor(code, message, options = {}) {
    super(message, options);
    this.name = 'HermeticCasError';
    this.code = code;
    if (Array.isArray(options.cleanupFailures) && options.cleanupFailures.length) {
      this.cleanupFailures = Object.freeze([...options.cleanupFailures]);
    }
  }
}

function fail(code, message, cause) {
  throw new HermeticCasError(code, message, cause ? { cause } : {});
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function checkedRoot(root) {
  if (typeof root !== 'string' || !isAbsolute(root) || root === parse(root).root) {
    fail('CAS_ROOT_INVALID', 'CAS root must be a non-root absolute path');
  }
  if (root !== normalize(root)) {
    fail('CAS_ROOT_NOT_NORMALIZED', 'CAS root must be lexically normalized');
  }
  return root;
}

function checkedDigest(digest) {
  if (typeof digest !== 'string' || !SHA256.test(digest)) {
    fail('CAS_DIGEST_INVALID', 'CAS digest must be a lowercase sha256 digest');
  }
  return digest;
}

function checkedMaxBytes(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('CAS_MAX_BYTES_INVALID', 'CAS maximum byte count must be a non-negative safe integer');
  }
  return value;
}

function checkedBytes(value, maximum) {
  if (!(value instanceof Uint8Array)) {
    fail('CAS_BYTES_INVALID', 'CAS object bytes must be a Buffer or Uint8Array');
  }
  const bytes = Buffer.from(value);
  if (bytes.length > maximum) {
    fail('CAS_OBJECT_TOO_LARGE', 'CAS object exceeds the configured byte bound');
  }
  return bytes;
}

function checkedMediaType(mediaType) {
  if (typeof mediaType !== 'string' || !SAFE_MEDIA_TYPE.test(mediaType)) {
    fail('CAS_MEDIA_TYPE_INVALID', 'CAS media type is missing or unsafe');
  }
  return mediaType;
}

function procEntry(directoryHandle, name) {
  if (!Number.isInteger(directoryHandle?.fd) || directoryHandle.fd < 0) {
    fail('CAS_DIRECTORY_HANDLE_INVALID', 'CAS directory handle is not open');
  }
  if (typeof name !== 'string' || !name || name === '.' || name === '..' || name.includes('/')) {
    fail('CAS_PATH_COMPONENT_INVALID', 'CAS path component is unsafe');
  }
  return `${PROC_FD_ROOT}/${directoryHandle.fd}/${name}`;
}

function directoryIdentity(stat) {
  return Object.freeze({
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: Number(stat.mode),
    nlink: String(stat.nlink),
    uid: Number(stat.uid),
    gid: Number(stat.gid),
  });
}

function fileIdentity(stat) {
  return Object.freeze({
    ...directoryIdentity(stat),
    size: String(stat.size),
    mtimeNs: String(stat.mtimeNs),
    ctimeNs: String(stat.ctimeNs),
  });
}

function sameIdentity(left, right, fields) {
  return fields.every((field) => left[field] === right[field]);
}

function sameDirectoryIdentity(left, right) {
  return sameIdentity(left, right, ['dev', 'ino', 'mode', 'uid', 'gid']);
}

function sameFileIdentity(left, right) {
  return sameIdentity(left, right, [
    'dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs',
  ]);
}

function sameInode(left, right) {
  return sameIdentity(left, right, ['dev', 'ino']);
}

function assertDirectoryStat(stat, label, { secureOwner = false } = {}) {
  if (!stat.isDirectory()) {
    fail('CAS_DIRECTORY_NOT_DIRECTORY', `${label} is not a directory`);
  }
  if (secureOwner) {
    const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : null;
    if (effectiveUid === null || Number(stat.uid) !== effectiveUid || (Number(stat.mode) & 0o022) !== 0) {
      fail('CAS_DIRECTORY_PERMISSIONS_UNSAFE', `${label} ownership or permissions are unsafe`);
    }
  }
}

function assertFileStat(stat, label) {
  if (!stat.isFile()) {
    fail('CAS_OBJECT_NOT_REGULAR', `${label} is not a regular file`);
  }
  if (stat.nlink !== 1n) {
    fail('CAS_OBJECT_LINK_COUNT_INVALID', `${label} must have exactly one link`);
  }
  const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (effectiveUid === null || Number(stat.uid) !== effectiveUid || (Number(stat.mode) & 0o022) !== 0) {
    fail('CAS_OBJECT_PERMISSIONS_UNSAFE', `${label} ownership or permissions are unsafe`);
  }
}

async function closeHandles(handles) {
  const failures = [];
  for (const handle of [...handles].reverse()) {
    try {
      await handle.close();
    } catch (error) {
      failures.push(error.code || error.name || 'CLOSE_FAILED');
    }
  }
  return failures;
}

async function openDirectory(path, label, { secureOwner = false } = {}) {
  let handle;
  try {
    handle = await open(path, DIRECTORY_FLAGS);
    const stat = await handle.stat({ bigint: true });
    assertDirectoryStat(stat, label, { secureOwner });
    return handle;
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error instanceof HermeticCasError) throw error;
    fail('CAS_DIRECTORY_OPEN_FAILED', `${label} could not be opened without following symlinks`, error);
  }
}

async function openAbsoluteDirectoryChain(root) {
  const handles = [];
  try {
    let current = await openDirectory(parse(root).root, 'filesystem root');
    handles.push(current);
    for (const component of root.split('/').filter(Boolean)) {
      current = await openDirectory(procEntry(current, component), `CAS root component ${component}`);
      handles.push(current);
    }
    const rootStat = await current.stat({ bigint: true });
    assertDirectoryStat(rootStat, 'CAS root', { secureOwner: true });
    return handles;
  } catch (error) {
    await closeHandles(handles);
    throw error;
  }
}

async function openOrCreateDirectory(parentHandle, name, label, create) {
  const path = procEntry(parentHandle, name);
  if (create) {
    let created = false;
    try {
      await mkdir(path, { mode: 0o700 });
      created = true;
    } catch (error) {
      if (error.code !== 'EEXIST') {
        fail('CAS_DIRECTORY_CREATE_FAILED', `${label} could not be created`, error);
      }
    }
    if (created) {
      try {
        await parentHandle.sync();
      } catch (error) {
        fail('CAS_DIRECTORY_SYNC_FAILED', `${label} parent could not be synchronised`, error);
      }
    }
  }
  return openDirectory(path, label, { secureOwner: true });
}

async function openCasDirectoryChain(root, hexadecimal, { create }) {
  const handles = await openAbsoluteDirectoryChain(root);
  try {
    const algorithm = await openOrCreateDirectory(
      handles.at(-1), 'sha256', 'CAS sha256 directory', create,
    );
    handles.push(algorithm);
    const shard = await openOrCreateDirectory(
      algorithm, hexadecimal.slice(0, 2), 'CAS shard directory', create,
    );
    handles.push(shard);
    const identities = [];
    for (const handle of handles) {
      const stat = await handle.stat({ bigint: true });
      assertDirectoryStat(stat, 'CAS directory chain entry');
      identities.push(directoryIdentity(stat));
    }
    return { handles, identities, shard };
  } catch (error) {
    await closeHandles(handles);
    throw error;
  }
}

async function assertDirectoryChainStable(root, hexadecimal, expected) {
  const reopened = await openCasDirectoryChain(root, hexadecimal, { create: false });
  try {
    if (reopened.identities.length !== expected.length) {
      fail('CAS_DIRECTORY_IDENTITY_CHANGED', 'CAS directory chain length changed');
    }
    for (let index = 0; index < expected.length; index += 1) {
      if (!sameDirectoryIdentity(reopened.identities[index], expected[index])) {
        fail('CAS_DIRECTORY_IDENTITY_CHANGED', `CAS directory identity changed at index ${index}`);
      }
    }
  } finally {
    await closeHandles(reopened.handles);
  }
}

async function readHandleExact(handle, stat, maximum, label) {
  if (stat.size > BigInt(maximum) || stat.size > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('CAS_OBJECT_TOO_LARGE', `${label} exceeds the configured byte bound`);
  }
  const length = Number(stat.size);
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await handle.read(bytes, offset, length - offset, offset);
    if (bytesRead === 0) fail('CAS_OBJECT_TRUNCATED', `${label} ended before its recorded size`);
    offset += bytesRead;
  }
  const sentinel = Buffer.alloc(1);
  const { bytesRead: trailing } = await handle.read(sentinel, 0, 1, length);
  if (trailing !== 0) fail('CAS_OBJECT_GREW', `${label} grew while being read`);
  return bytes;
}

async function openObject(shard, hexadecimal, label = 'CAS object') {
  let handle;
  try {
    handle = await open(procEntry(shard, hexadecimal), FILE_READ_FLAGS);
    const stat = await handle.stat({ bigint: true });
    assertFileStat(stat, label);
    return { handle, stat };
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error instanceof HermeticCasError) throw error;
    fail('CAS_OBJECT_OPEN_FAILED', `${label} could not be opened safely`, error);
  }
}

async function readAndVerifyOpenObject(handle, initialStat, expectedDigest, maximum, label) {
  assertFileStat(initialStat, label);
  const before = fileIdentity(initialStat);
  const bytes = await readHandleExact(handle, initialStat, maximum, label);
  const afterStat = await handle.stat({ bigint: true });
  assertFileStat(afterStat, label);
  const after = fileIdentity(afterStat);
  if (!sameFileIdentity(before, after)) {
    fail('CAS_OBJECT_CHANGED_DURING_READ', `${label} changed while being read`);
  }
  if (sha256(bytes) !== expectedDigest) {
    fail('CAS_OBJECT_DIGEST_MISMATCH', `${label} bytes do not match their address`);
  }
  return { bytes, identity: after };
}

async function invokeTestHook(options, phase, context) {
  const hook = options?.[HERMITIC_CAS_TEST_HOOK];
  if (hook === undefined) return;
  if (typeof hook !== 'function') fail('CAS_TEST_HOOK_INVALID', 'CAS test hook must be callable');
  await hook(Object.freeze({ phase, ...context }));
}

function assertKnownOptions(options) {
  for (const key of Reflect.ownKeys(options)) {
    if (key !== HERMITIC_CAS_TEST_HOOK) {
      fail('CAS_OPTION_UNKNOWN', `unknown CAS option ${String(key)}`);
    }
  }
}

async function verifyFinalName({
  root,
  hexadecimal,
  expectedDigest,
  maximum,
  directoryIdentities,
  expectedInode,
}) {
  await assertDirectoryChainStable(root, hexadecimal, directoryIdentities);
  const reopened = await openCasDirectoryChain(root, hexadecimal, { create: false });
  try {
    const { handle, stat } = await openObject(reopened.shard, hexadecimal, 'published CAS object');
    try {
      const verified = await readAndVerifyOpenObject(
        handle, stat, expectedDigest, maximum, 'published CAS object',
      );
      if (expectedInode && !sameInode(verified.identity, expectedInode)) {
        fail('CAS_OBJECT_IDENTITY_CHANGED', 'published CAS object identity changed');
      }
      return verified;
    } finally {
      await handle.close();
    }
  } finally {
    await closeHandles(reopened.handles);
  }
}

async function removeEntryIfIdentity(shard, name, expectedInode) {
  const failures = [];
  let candidate;
  try {
    candidate = await openObject(shard, name, 'CAS rollback object');
    const identity = fileIdentity(candidate.stat);
    if (!sameInode(identity, expectedInode)) {
      return ['ROLLBACK_IDENTITY_MISMATCH'];
    }
    await candidate.handle.close();
    candidate = null;
    await unlink(procEntry(shard, name));
    await shard.sync();
  } catch (error) {
    if (error.code !== 'ENOENT') failures.push(error.code || error.name || 'ROLLBACK_FAILED');
  } finally {
    await candidate?.handle.close().catch(() => {});
  }
  return failures;
}

async function removeTemporary(shard, name) {
  try {
    await unlink(procEntry(shard, name));
    await shard.sync();
    return [];
  } catch (error) {
    return error.code === 'ENOENT' ? [] : [error.code || error.name || 'TEMP_CLEANUP_FAILED'];
  }
}

function descriptor(digest, byteSize, mediaType, created) {
  return Object.freeze({
    digest,
    byteSize,
    mediaType,
    locator: `cas://sha256/${digest.slice(7)}`,
    created,
  });
}

export async function putCasObject({
  root,
  bytes: input,
  mediaType,
  expectedDigest,
  mode = 0o600,
  maxBytes = DEFAULT_MAX_BYTES,
  ...options
}) {
  assertKnownOptions(options);
  const canonicalRoot = checkedRoot(root);
  const maximum = checkedMaxBytes(maxBytes);
  const bytes = checkedBytes(input, maximum);
  const checkedType = checkedMediaType(mediaType);
  if (mode !== 0o600 && mode !== 0o400) {
    fail('CAS_OBJECT_MODE_INVALID', 'CAS object mode must be 0600 or 0400');
  }
  const digest = sha256(bytes);
  if (expectedDigest !== undefined && checkedDigest(expectedDigest) !== digest) {
    fail('CAS_EXPECTED_DIGEST_MISMATCH', 'CAS object does not match the expected digest');
  }
  const hexadecimal = digest.slice(7);
  const directories = await openCasDirectoryChain(canonicalRoot, hexadecimal, { create: true });
  const temporaryName = `.tmp-${process.pid}-${randomBytes(24).toString('hex')}`;
  const temporaryPath = join(canonicalRoot, 'sha256', hexadecimal.slice(0, 2), temporaryName);
  const objectPath = join(canonicalRoot, 'sha256', hexadecimal.slice(0, 2), hexadecimal);
  let temporaryHandle;
  let temporaryIdentity;
  let publishedByThisCall = false;
  let publishedIdentity;
  let temporaryExists = false;
  try {
    try {
      temporaryHandle = await open(procEntry(directories.shard, temporaryName), FILE_CREATE_FLAGS, mode);
      temporaryExists = true;
    } catch (error) {
      fail('CAS_TEMP_CREATE_FAILED', 'CAS temporary object could not be created exclusively', error);
    }
    const emptyStat = await temporaryHandle.stat({ bigint: true });
    assertFileStat(emptyStat, 'CAS temporary object');
    await temporaryHandle.writeFile(bytes);
    await temporaryHandle.sync();
    const writtenStat = await temporaryHandle.stat({ bigint: true });
    assertFileStat(writtenStat, 'CAS temporary object');
    if (writtenStat.size !== BigInt(bytes.length)) {
      fail('CAS_TEMP_SIZE_MISMATCH', 'CAS temporary object size is incorrect');
    }
    const verifiedTemporary = await readAndVerifyOpenObject(
      temporaryHandle, writtenStat, digest, maximum, 'CAS temporary object',
    );
    temporaryIdentity = verifiedTemporary.identity;
    await invokeTestHook(options, 'after-temporary-verified', {
      rootPath: canonicalRoot,
      temporaryPath,
      objectPath,
      digest,
    });
    const postHookTemporaryStat = await temporaryHandle.stat({ bigint: true });
    assertFileStat(postHookTemporaryStat, 'CAS temporary object');
    if (!sameFileIdentity(temporaryIdentity, fileIdentity(postHookTemporaryStat))) {
      fail('CAS_TEMP_IDENTITY_CHANGED', 'CAS temporary object changed before publication');
    }
    await assertDirectoryChainStable(canonicalRoot, hexadecimal, directories.identities);

    try {
      await link(
        procEntry(directories.shard, temporaryName),
        procEntry(directories.shard, hexadecimal),
      );
      publishedByThisCall = true;
      const linkedStat = await temporaryHandle.stat({ bigint: true });
      if (linkedStat.nlink !== 2n) {
        fail('CAS_PUBLISH_LINK_COUNT_INVALID', 'CAS publication did not create exactly one final link');
      }
      publishedIdentity = fileIdentity(linkedStat);
    } catch (error) {
      if (error.code !== 'EEXIST') {
        if (error instanceof HermeticCasError) throw error;
        fail('CAS_PUBLISH_FAILED', 'CAS object could not be published atomically', error);
      }
    }

    if (publishedByThisCall) {
      await unlink(procEntry(directories.shard, temporaryName));
      temporaryExists = false;
      await directories.shard.sync();
      const finalStat = await temporaryHandle.stat({ bigint: true });
      assertFileStat(finalStat, 'published CAS object');
      publishedIdentity = fileIdentity(finalStat);
      await invokeTestHook(options, 'after-publish', {
        rootPath: canonicalRoot,
        temporaryPath,
        objectPath,
        digest,
      });
      const finalVerified = await readAndVerifyOpenObject(
        temporaryHandle, finalStat, digest, maximum, 'published CAS object',
      );
      if (!sameInode(finalVerified.identity, publishedIdentity)) {
        fail('CAS_OBJECT_IDENTITY_CHANGED', 'published CAS object identity changed');
      }
      await verifyFinalName({
        root: canonicalRoot,
        hexadecimal,
        expectedDigest: digest,
        maximum,
        directoryIdentities: directories.identities,
        expectedInode: publishedIdentity,
      });
      return descriptor(digest, bytes.length, checkedType, true);
    }

    const cleanup = await removeTemporary(directories.shard, temporaryName);
    temporaryExists = false;
    if (cleanup.length) {
      throw new HermeticCasError(
        'CAS_TEMP_CLEANUP_FAILED',
        'CAS temporary object could not be removed after concurrent publication',
        { cleanupFailures: cleanup },
      );
    }
    const existing = await verifyFinalName({
      root: canonicalRoot,
      hexadecimal,
      expectedDigest: digest,
      maximum,
      directoryIdentities: directories.identities,
    });
    if (existing.bytes.length !== bytes.length) {
      fail('CAS_EXISTING_SIZE_MISMATCH', 'existing CAS object size is incorrect');
    }
    return descriptor(digest, bytes.length, checkedType, false);
  } catch (error) {
    const cleanupFailures = [];
    if (temporaryExists) {
      cleanupFailures.push(...await removeTemporary(directories.shard, temporaryName));
      temporaryExists = false;
    }
    if (publishedByThisCall && publishedIdentity) {
      cleanupFailures.push(...await removeEntryIfIdentity(
        directories.shard, hexadecimal, publishedIdentity,
      ));
    }
    if (cleanupFailures.length && error instanceof HermeticCasError) {
      error.cleanupFailures = Object.freeze(cleanupFailures);
    }
    throw error;
  } finally {
    await temporaryHandle?.close().catch(() => {});
    await closeHandles(directories.handles);
  }
}

export async function readCasObject({
  root,
  digest,
  maxBytes = DEFAULT_MAX_BYTES,
  ...options
}) {
  assertKnownOptions(options);
  const canonicalRoot = checkedRoot(root);
  const checked = checkedDigest(digest);
  const maximum = checkedMaxBytes(maxBytes);
  const hexadecimal = checked.slice(7);
  if (!HEX_SHA256.test(hexadecimal)) {
    fail('CAS_DIGEST_INVALID', 'CAS digest hexadecimal is invalid');
  }
  const directories = await openCasDirectoryChain(canonicalRoot, hexadecimal, { create: false });
  let object;
  try {
    object = await openObject(directories.shard, hexadecimal);
    const verified = await readAndVerifyOpenObject(
      object.handle, object.stat, checked, maximum, 'CAS object',
    );
    await invokeTestHook(options, 'after-object-read', {
      rootPath: canonicalRoot,
      objectPath: join(canonicalRoot, 'sha256', hexadecimal.slice(0, 2), hexadecimal),
      digest: checked,
    });
    const afterHook = await object.handle.stat({ bigint: true });
    assertFileStat(afterHook, 'CAS object');
    if (!sameFileIdentity(verified.identity, fileIdentity(afterHook))) {
      fail('CAS_OBJECT_CHANGED_AFTER_READ', 'CAS object changed after its verified read');
    }
    await verifyFinalName({
      root: canonicalRoot,
      hexadecimal,
      expectedDigest: checked,
      maximum,
      directoryIdentities: directories.identities,
      expectedInode: verified.identity,
    });
    return Object.freeze({
      digest: checked,
      byteSize: verified.bytes.length,
      bytes: Buffer.from(verified.bytes),
    });
  } finally {
    await object?.handle.close().catch(() => {});
    await closeHandles(directories.handles);
  }
}

export async function verifyCasObject({
  root,
  descriptor: expected,
  maxBytes = DEFAULT_MAX_BYTES,
  ...options
}) {
  assertKnownOptions(options);
  if (!expected || typeof expected !== 'object' || Array.isArray(expected)) {
    fail('CAS_DESCRIPTOR_INVALID', 'CAS descriptor must be an object');
  }
  const digest = checkedDigest(expected.digest);
  if (!Number.isSafeInteger(expected.byteSize) || expected.byteSize < 0) {
    fail('CAS_DESCRIPTOR_SIZE_INVALID', 'CAS descriptor byte size is invalid');
  }
  if (expected.locator !== `cas://sha256/${digest.slice(7)}`) {
    fail('CAS_DESCRIPTOR_LOCATOR_INVALID', 'CAS descriptor locator is not canonical');
  }
  if (expected.mediaType !== undefined) checkedMediaType(expected.mediaType);
  const observed = await readCasObject({
    root,
    digest,
    maxBytes,
    ...options,
  });
  if (observed.byteSize !== expected.byteSize) {
    fail('CAS_DESCRIPTOR_SIZE_MISMATCH', 'CAS object does not match the descriptor byte size');
  }
  return Object.freeze({
    verified: true,
    digest,
    byteSize: observed.byteSize,
    mediaType: expected.mediaType ?? null,
  });
}
