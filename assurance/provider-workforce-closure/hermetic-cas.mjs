import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  constants as fsConstants,
  mkdir,
  open,
} from 'node:fs/promises';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  normalize,
  parse,
} from 'node:path';

const {
  O_DIRECTORY,
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
// Linux UAPI: __O_TMPFILE (0x400000) | O_DIRECTORY (0x10000).
const O_TMPFILE_LINUX = 0x410000;
const ANONYMOUS_STAGING_FLAGS = O_RDWR | O_TMPFILE_LINUX;
const PROC_FD_ROOT = '/proc/self/fd';
const NATIVE_PUBLISH_PROTOCOL = 'usf-hermetic-cas-linkat-empty-path-v1';
const NATIVE_PUBLISH_EXISTING_STATUS = 17;

/*
 * This symbol exists only so the adversarial tests can stop execution at exact
 * boundaries. A hook cannot waive a check: every hook is followed by another
 * fd, namespace and digest verification.
 */
export const HERMITIC_CAS_TEST_HOOK = Symbol('HERMITIC_CAS_TEST_HOOK');

/*
 * Node does not expose linkat(AT_EMPTY_PATH), openat2, or renameat2. Creation
 * consequently requires an authority-approved native publisher whose exact
 * executable bytes are digest pinned. Node creates and verifies an anonymous
 * O_TMPFILE inode; the publisher may only link fd 4 into pinned directory fd 5
 * at the requested digest name. No published name is ever removed here.
 *
 * Consumers must still read through readCasObject for every use: a same-uid
 * hostile process can mutate a pathname after verification. A returned
 * filesystem pathname is intentionally not exposed.
 */
export const HERMITIC_CAS_RESIDUAL_RISKS = Object.freeze([
  'NODE_HAS_NO_OPENAT2_RESOLVE_BENEATH',
  'NATIVE_LINKAT_AT_EMPTY_PATH_HELPER_REQUIRED_FOR_CREATION',
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
  if (value.byteLength > maximum) {
    fail('CAS_OBJECT_TOO_LARGE', 'CAS object exceeds the configured byte bound');
  }
  return Buffer.from(value);
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
    if (
      effectiveUid === null
      || Number(stat.uid) !== effectiveUid
      || (Number(stat.mode) & 0o7777) !== 0o700
    ) {
      fail('CAS_DIRECTORY_PERMISSIONS_UNSAFE', `${label} ownership or permissions are unsafe`);
    }
  }
}

function assertFileStat(stat, label, { links = 1n, mode = 0o600 } = {}) {
  if (!stat.isFile()) {
    fail('CAS_OBJECT_NOT_REGULAR', `${label} is not a regular file`);
  }
  if (stat.nlink !== links) {
    fail('CAS_OBJECT_LINK_COUNT_INVALID', `${label} has an invalid link count`);
  }
  const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (
    effectiveUid === null
    || Number(stat.uid) !== effectiveUid
    || (Number(stat.mode) & 0o7777) !== mode
  ) {
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

async function readAndVerifyOpenObject(
  handle,
  initialStat,
  expectedDigest,
  maximum,
  label,
  statPolicy = {},
) {
  assertFileStat(initialStat, label, statPolicy);
  const before = fileIdentity(initialStat);
  const bytes = await readHandleExact(handle, initialStat, maximum, label);
  const afterStat = await handle.stat({ bigint: true });
  assertFileStat(afterStat, label, statPolicy);
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

function checkedNativePublisher(publisher) {
  if (!publisher || typeof publisher !== 'object' || Array.isArray(publisher)) {
    fail(
      'CAS_NATIVE_PUBLISHER_REQUIRED',
      'CAS creation requires an authority-approved digest-pinned native publisher',
    );
  }
  const keys = Object.keys(publisher).sort();
  if (keys.length !== 3 || keys.join(',') !== 'digest,executable,protocol') {
    fail('CAS_NATIVE_PUBLISHER_INVALID', 'native publisher descriptor fields are not exact');
  }
  if (publisher.protocol !== NATIVE_PUBLISH_PROTOCOL) {
    fail('CAS_NATIVE_PUBLISHER_PROTOCOL_INVALID', 'native publisher protocol is not supported');
  }
  if (
    typeof publisher.executable !== 'string'
    || !isAbsolute(publisher.executable)
    || normalize(publisher.executable) !== publisher.executable
    || publisher.executable === parse(publisher.executable).root
  ) {
    fail('CAS_NATIVE_PUBLISHER_PATH_INVALID', 'native publisher path is not exact and absolute');
  }
  return Object.freeze({
    executable: publisher.executable,
    digest: checkedDigest(publisher.digest),
    protocol: publisher.protocol,
  });
}

async function assertAbsoluteDirectoryChainStable(path, expected) {
  const reopened = await openAbsoluteDirectoryChain(path);
  try {
    if (reopened.length !== expected.length) {
      fail('CAS_NATIVE_PUBLISHER_DIRECTORY_CHANGED', 'native publisher directory chain changed');
    }
    for (let index = 0; index < expected.length; index += 1) {
      const observed = directoryIdentity(await reopened[index].stat({ bigint: true }));
      if (!sameDirectoryIdentity(observed, expected[index])) {
        fail(
          'CAS_NATIVE_PUBLISHER_DIRECTORY_CHANGED',
          `native publisher directory changed at index ${index}`,
        );
      }
    }
  } finally {
    await closeHandles(reopened);
  }
}

async function openPinnedNativePublisher(publisher) {
  const parentPath = dirname(publisher.executable);
  const name = basename(publisher.executable);
  const directoryHandles = await openAbsoluteDirectoryChain(parentPath);
  let handle;
  try {
    handle = await open(procEntry(directoryHandles.at(-1), name), FILE_READ_FLAGS);
    const stat = await handle.stat({ bigint: true });
    const verified = await readAndVerifyOpenObject(
      handle,
      stat,
      publisher.digest,
      16 * 1024 * 1024,
      'native CAS publisher',
      { links: 1n, mode: 0o500 },
    );
    const directoryIdentities = [];
    for (const directoryHandle of directoryHandles) {
      directoryIdentities.push(directoryIdentity(await directoryHandle.stat({ bigint: true })));
    }
    return {
      handle,
      identity: verified.identity,
      directoryHandles,
      directoryIdentities,
      parentPath,
    };
  } catch (error) {
    await handle?.close().catch(() => {});
    await closeHandles(directoryHandles);
    if (error instanceof HermeticCasError) throw error;
    fail('CAS_NATIVE_PUBLISHER_OPEN_FAILED', 'native publisher could not be pinned', error);
  }
}

async function closePinnedNativePublisher(pinned) {
  await pinned?.handle.close().catch(() => {});
  await closeHandles(pinned?.directoryHandles || []);
}

async function invokeNativePublisher({
  publisher,
  pinned,
  stagingHandle,
  shardHandle,
  hexadecimal,
}) {
  const result = spawnSync(
    '/proc/self/fd/3',
    [publisher.protocol, hexadecimal],
    {
      env: Object.freeze({ LANG: 'C', LC_ALL: 'C' }),
      encoding: null,
      maxBuffer: 64 * 1024,
      timeout: 10_000,
      stdio: [
        'ignore',
        'pipe',
        'pipe',
        pinned.handle.fd,
        stagingHandle.fd,
        shardHandle.fd,
      ],
    },
  );
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
  if (result.error || result.signal || stdout.length || stderr.length) {
    fail('CAS_NATIVE_PUBLISHER_EXECUTION_FAILED', 'native publisher execution was not clean', result.error);
  }
  if (result.status !== 0 && result.status !== NATIVE_PUBLISH_EXISTING_STATUS) {
    fail(
      'CAS_NATIVE_PUBLISHER_STATUS_INVALID',
      `native publisher returned unsupported status ${String(result.status)}`,
    );
  }
  const after = fileIdentity(await pinned.handle.stat({ bigint: true }));
  if (!sameFileIdentity(pinned.identity, after)) {
    fail('CAS_NATIVE_PUBLISHER_CHANGED', 'native publisher changed during execution');
  }
  await assertAbsoluteDirectoryChainStable(pinned.parentPath, pinned.directoryIdentities);
  return result.status === 0 ? 'PUBLISHED' : 'EXISTING';
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
  nativePublisher,
  mode = 0o600,
  maxBytes = DEFAULT_MAX_BYTES,
  ...options
}) {
  assertKnownOptions(options);
  const canonicalRoot = checkedRoot(root);
  const maximum = checkedMaxBytes(maxBytes);
  const bytes = checkedBytes(input, maximum);
  const checkedType = checkedMediaType(mediaType);
  if (mode !== 0o600) {
    fail('CAS_OBJECT_MODE_INVALID', 'CAS object mode must be exactly 0600');
  }
  const digest = sha256(bytes);
  if (expectedDigest !== undefined && checkedDigest(expectedDigest) !== digest) {
    fail('CAS_EXPECTED_DIGEST_MISMATCH', 'CAS object does not match the expected digest');
  }
  const hexadecimal = digest.slice(7);
  const publisher = checkedNativePublisher(nativePublisher);
  const pinnedPublisher = await openPinnedNativePublisher(publisher);
  let directories;
  let stagingHandle;
  const objectPath = join(canonicalRoot, 'sha256', hexadecimal.slice(0, 2), hexadecimal);
  try {
    directories = await openCasDirectoryChain(canonicalRoot, hexadecimal, { create: true });
    try {
      stagingHandle = await open(
        `${PROC_FD_ROOT}/${directories.shard.fd}`,
        ANONYMOUS_STAGING_FLAGS,
        mode,
      );
    } catch (error) {
      fail(
        'CAS_ANONYMOUS_STAGING_UNAVAILABLE',
        'CAS filesystem does not support safe anonymous O_TMPFILE staging',
        error,
      );
    }
    const emptyStat = await stagingHandle.stat({ bigint: true });
    assertFileStat(emptyStat, 'CAS anonymous staging object', { links: 0n, mode });
    await stagingHandle.writeFile(bytes);
    await stagingHandle.sync();
    const writtenStat = await stagingHandle.stat({ bigint: true });
    assertFileStat(writtenStat, 'CAS anonymous staging object', { links: 0n, mode });
    if (writtenStat.size !== BigInt(bytes.length)) {
      fail('CAS_STAGING_SIZE_MISMATCH', 'CAS anonymous staging object size is incorrect');
    }
    const verifiedStaging = await readAndVerifyOpenObject(
      stagingHandle,
      writtenStat,
      digest,
      maximum,
      'CAS anonymous staging object',
      { links: 0n, mode },
    );
    await invokeTestHook(options, 'after-temporary-verified', {
      rootPath: canonicalRoot,
      objectPath,
      digest,
      anonymousStaging: true,
    });
    const postHookStagingStat = await stagingHandle.stat({ bigint: true });
    assertFileStat(postHookStagingStat, 'CAS anonymous staging object', { links: 0n, mode });
    if (!sameFileIdentity(verifiedStaging.identity, fileIdentity(postHookStagingStat))) {
      fail('CAS_STAGING_IDENTITY_CHANGED', 'CAS anonymous staging object changed before publication');
    }
    await assertDirectoryChainStable(canonicalRoot, hexadecimal, directories.identities);

    const publication = await invokeNativePublisher({
      publisher,
      pinned: pinnedPublisher,
      stagingHandle,
      shardHandle: directories.shard,
      hexadecimal,
    });
    if (publication === 'PUBLISHED') {
      const finalStat = await stagingHandle.stat({ bigint: true });
      assertFileStat(finalStat, 'published CAS object', { links: 1n, mode });
      const publishedIdentity = fileIdentity(finalStat);
      await directories.shard.sync();
      await invokeTestHook(options, 'after-publish', {
        rootPath: canonicalRoot,
        objectPath,
        digest,
      });
      const finalVerified = await readAndVerifyOpenObject(
        stagingHandle,
        finalStat,
        digest,
        maximum,
        'published CAS object',
        { links: 1n, mode },
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

    const unpublishedStat = await stagingHandle.stat({ bigint: true });
    assertFileStat(unpublishedStat, 'unpublished CAS staging object', { links: 0n, mode });
    if (!sameFileIdentity(verifiedStaging.identity, fileIdentity(unpublishedStat))) {
      fail('CAS_STAGING_IDENTITY_CHANGED', 'unpublished CAS staging object changed');
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
  } finally {
    await stagingHandle?.close().catch(() => {});
    await closeHandles(directories?.handles || []);
    await closePinnedNativePublisher(pinnedPublisher);
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
