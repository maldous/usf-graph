import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
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
const STAGING_CREATE_FLAGS = O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW;
const PROC_FD_ROOT = '/proc/self/fd';
const SYSTEM_PUBLISH_PROTOCOL = 'usf-hermetic-cas-gnu-mv-noreplace-v1';
const SYSTEM_PUBLISH_EXECUTABLE = '/usr/bin/mv';
const SYSTEM_PUBLISH_LOADER = '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2';
const SYSTEM_PUBLISH_LIBRARIES = Object.freeze([
  '/usr/lib/x86_64-linux-gnu/libc.so.6',
  '/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2',
  '/usr/lib/x86_64-linux-gnu/libattr.so.1.1.2501',
  '/usr/lib/x86_64-linux-gnu/libacl.so.1.1.2301',
  '/usr/lib/x86_64-linux-gnu/libselinux.so.1',
]);

/*
 * This symbol exists only so the adversarial tests can stop execution at exact
 * boundaries. A hook cannot waive a check: every hook is followed by another
 * fd, namespace and digest verification.
 */
export const HERMITIC_CAS_TEST_HOOK = Symbol('HERMITIC_CAS_TEST_HOOK');

/*
 * Node does not expose renameat2(RENAME_NOREPLACE) or openat2. Creation
 * consequently requires an authority-approved GNU mv runtime whose exact
 * executable, loader and library bytes are digest pinned. The fixed installed
 * GNU mv 9.1 protocol has been observed to use RENAME_NOREPLACE for -n on this
 * platform. It atomically renames a unique, fsynced, same-filesystem staging
 * file. Failed or losing staging names are quarantined and never deleted here.
 *
 * Consumers must still read through readCasObject for every use: a same-uid
 * hostile process can mutate a pathname after verification. A returned
 * filesystem pathname is intentionally not exposed.
 */
export const HERMITIC_CAS_RESIDUAL_RISKS = Object.freeze([
  'NODE_HAS_NO_OPENAT2_RESOLVE_BENEATH',
  'GNU_MV_RUNTIME_DESCRIPTOR_REQUIRED_FOR_CREATION',
  'KERNEL_VDSO_IS_OUTSIDE_FILE_DIGEST_CLOSURE',
  'FAILED_STAGING_RECOVERY_IS_SEPARATE_AND_FAIL_CLOSED',
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

const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));

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

async function openAbsoluteDirectoryChain(root, { secureLeaf = true } = {}) {
  const handles = [];
  try {
    let current = await openDirectory(parse(root).root, 'filesystem root');
    handles.push(current);
    for (const component of root.split('/').filter(Boolean)) {
      current = await openDirectory(procEntry(current, component), `CAS root component ${component}`);
      handles.push(current);
    }
    const rootStat = await current.stat({ bigint: true });
    assertDirectoryStat(rootStat, 'absolute directory leaf', { secureOwner: secureLeaf });
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

function checkedSystemFileRecord(record, label) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    fail('CAS_SYSTEM_PUBLISHER_RECORD_INVALID', `${label} record is not an object`);
  }
  const keys = Object.keys(record).sort();
  if (keys.join(',') !== 'digest,gid,mode,path,size,uid') {
    fail('CAS_SYSTEM_PUBLISHER_RECORD_INVALID', `${label} record fields are not exact`);
  }
  if (
    typeof record.path !== 'string'
    || !isAbsolute(record.path)
    || normalize(record.path) !== record.path
    || record.path === parse(record.path).root
  ) {
    fail('CAS_SYSTEM_PUBLISHER_PATH_INVALID', `${label} path is not exact and absolute`);
  }
  for (const field of ['uid', 'gid', 'mode', 'size']) {
    if (!Number.isSafeInteger(record[field]) || record[field] < 0) {
      fail('CAS_SYSTEM_PUBLISHER_RECORD_INVALID', `${label} ${field} is invalid`);
    }
  }
  return Object.freeze({
    path: record.path,
    digest: checkedDigest(record.digest),
    uid: record.uid,
    gid: record.gid,
    mode: record.mode,
    size: record.size,
  });
}

function checkedSystemPublisher(publisher) {
  if (!publisher || typeof publisher !== 'object' || Array.isArray(publisher)) {
    fail(
      'CAS_SYSTEM_PUBLISHER_REQUIRED',
      'CAS creation requires an authority-approved digest-pinned GNU mv runtime',
    );
  }
  const keys = Object.keys(publisher).sort();
  if (
    keys.join(',')
    !== 'closureDigest,executable,libraries,loader,protocol,version,versionStdoutDigest'
  ) {
    fail('CAS_SYSTEM_PUBLISHER_INVALID', 'system publisher descriptor fields are not exact');
  }
  if (publisher.protocol !== SYSTEM_PUBLISH_PROTOCOL) {
    fail('CAS_SYSTEM_PUBLISHER_PROTOCOL_INVALID', 'system publisher protocol is not supported');
  }
  if (publisher.version !== 'mv (GNU coreutils) 9.1') {
    fail('CAS_SYSTEM_PUBLISHER_VERSION_INVALID', 'system publisher version is not approved');
  }
  if (!Array.isArray(publisher.libraries) || publisher.libraries.length === 0) {
    fail('CAS_SYSTEM_PUBLISHER_CLOSURE_INVALID', 'system publisher libraries are missing');
  }
  const executable = checkedSystemFileRecord(publisher.executable, 'publisher executable');
  const loader = checkedSystemFileRecord(publisher.loader, 'publisher loader');
  const libraries = publisher.libraries.map((record, index) => (
    checkedSystemFileRecord(record, `publisher library ${index}`)
  ));
  if (
    executable.path !== SYSTEM_PUBLISH_EXECUTABLE
    || loader.path !== SYSTEM_PUBLISH_LOADER
    || canonicalJson(libraries.map(({ path }) => path)) !== canonicalJson(SYSTEM_PUBLISH_LIBRARIES)
  ) {
    fail('CAS_SYSTEM_PUBLISHER_PATH_INVALID', 'system publisher runtime paths are not approved');
  }
  if (
    executable.uid !== 0
    || executable.gid !== 0
    || executable.mode !== 0o755
    || loader.uid !== 0
    || loader.gid !== 0
    || loader.mode !== 0o755
    || libraries.some((record, index) => (
      record.uid !== 0
      || record.gid !== 0
      || record.mode !== (index === 0 ? 0o755 : 0o644)
    ))
  ) {
    fail('CAS_SYSTEM_PUBLISHER_METADATA_INVALID', 'system publisher ownership or modes are not approved');
  }
  const paths = [loader.path, executable.path, ...libraries.map(({ path }) => path)];
  if (new Set(paths).size !== paths.length) {
    fail('CAS_SYSTEM_PUBLISHER_CLOSURE_INVALID', 'system publisher paths are not unique');
  }
  const closure = { executable, libraries, loader };
  if (checkedDigest(publisher.closureDigest) !== sha256(Buffer.from(canonicalJson(closure)))) {
    fail('CAS_SYSTEM_PUBLISHER_CLOSURE_DIGEST_INVALID', 'system publisher closure digest is invalid');
  }
  return Object.freeze({
    closureDigest: publisher.closureDigest,
    executable,
    libraries: Object.freeze(libraries),
    loader,
    protocol: publisher.protocol,
    version: publisher.version,
    versionStdoutDigest: checkedDigest(publisher.versionStdoutDigest),
  });
}

function assertSystemFileStat(stat, record, label) {
  if (!stat.isFile() || stat.nlink !== 1n) {
    fail('CAS_SYSTEM_PUBLISHER_FILE_INVALID', `${label} type or link count is invalid`);
  }
  if (
    Number(stat.uid) !== record.uid
    || Number(stat.gid) !== record.gid
    || (Number(stat.mode) & 0o7777) !== record.mode
    || stat.size !== BigInt(record.size)
  ) {
    fail('CAS_SYSTEM_PUBLISHER_FILE_INVALID', `${label} metadata is invalid`);
  }
}

async function assertAbsoluteDirectoryChainStable(path, expected, { secureLeaf = true } = {}) {
  const reopened = await openAbsoluteDirectoryChain(path, { secureLeaf });
  try {
    if (reopened.length !== expected.length) {
      fail('CAS_SYSTEM_PUBLISHER_DIRECTORY_CHANGED', 'system publisher directory chain changed');
    }
    for (let index = 0; index < expected.length; index += 1) {
      const observed = directoryIdentity(await reopened[index].stat({ bigint: true }));
      if (!sameDirectoryIdentity(observed, expected[index])) {
        fail(
          'CAS_SYSTEM_PUBLISHER_DIRECTORY_CHANGED',
          `system publisher directory changed at index ${index}`,
        );
      }
    }
  } finally {
    await closeHandles(reopened);
  }
}

async function openPinnedSystemFile(record, label) {
  const parentPath = dirname(record.path);
  const name = basename(record.path);
  const directoryHandles = await openAbsoluteDirectoryChain(parentPath, { secureLeaf: false });
  let handle;
  try {
    handle = await open(procEntry(directoryHandles.at(-1), name), FILE_READ_FLAGS);
    const stat = await handle.stat({ bigint: true });
    assertSystemFileStat(stat, record, label);
    const before = fileIdentity(stat);
    const bytes = await readHandleExact(handle, stat, 64 * 1024 * 1024, label);
    const afterStat = await handle.stat({ bigint: true });
    assertSystemFileStat(afterStat, record, label);
    const after = fileIdentity(afterStat);
    if (!sameFileIdentity(before, after) || sha256(bytes) !== record.digest) {
      fail('CAS_SYSTEM_PUBLISHER_DIGEST_INVALID', `${label} bytes or identity are invalid`);
    }
    const directoryIdentities = [];
    for (const directoryHandle of directoryHandles) {
      directoryIdentities.push(directoryIdentity(await directoryHandle.stat({ bigint: true })));
    }
    return {
      handle,
      identity: after,
      directoryHandles,
      directoryIdentities,
      parentPath,
      record,
      label,
    };
  } catch (error) {
    await handle?.close().catch(() => {});
    await closeHandles(directoryHandles);
    if (error instanceof HermeticCasError) throw error;
    fail('CAS_SYSTEM_PUBLISHER_OPEN_FAILED', `${label} could not be pinned`, error);
  }
}

async function openPinnedSystemRuntime(publisher) {
  const pinned = [];
  try {
    pinned.push(await openPinnedSystemFile(publisher.loader, 'publisher loader'));
    pinned.push(await openPinnedSystemFile(publisher.executable, 'publisher executable'));
    for (let index = 0; index < publisher.libraries.length; index += 1) {
      pinned.push(await openPinnedSystemFile(
        publisher.libraries[index],
        `publisher library ${index}`,
      ));
    }
    return pinned;
  } catch (error) {
    for (const entry of pinned.reverse()) {
      await entry.handle.close().catch(() => {});
      await closeHandles(entry.directoryHandles);
    }
    throw error;
  }
}

async function closePinnedSystemRuntime(pinned) {
  for (const entry of [...(pinned || [])].reverse()) {
    await entry.handle.close().catch(() => {});
    await closeHandles(entry.directoryHandles);
  }
}

async function verifyPinnedSystemRuntime(pinned) {
  for (const entry of pinned) {
    const stat = await entry.handle.stat({ bigint: true });
    assertSystemFileStat(stat, entry.record, entry.label);
    const before = fileIdentity(stat);
    const bytes = await readHandleExact(
      entry.handle,
      stat,
      64 * 1024 * 1024,
      entry.label,
    );
    const after = fileIdentity(await entry.handle.stat({ bigint: true }));
    if (
      !sameFileIdentity(entry.identity, before)
      || !sameFileIdentity(before, after)
      || sha256(bytes) !== entry.record.digest
    ) {
      fail('CAS_SYSTEM_PUBLISHER_CHANGED', `${entry.label} changed during execution`);
    }
    await assertAbsoluteDirectoryChainStable(
      entry.parentPath,
      entry.directoryIdentities,
      { secureLeaf: false },
    );
  }
}

function runPinnedSystemPublisher({
  publisher,
  pinned,
  stagingDirectory,
  shardHandle,
  arguments: mvArguments,
  expectedOutput,
}) {
  const loaderChildFd = 3;
  const executableChildFd = 4;
  const firstLibraryChildFd = 5;
  const stagingDirectoryChildFd = firstLibraryChildFd + publisher.libraries.length;
  const shardChildFd = stagingDirectoryChildFd + 1;
  const preload = publisher.libraries
    .map((_, index) => `/proc/self/fd/${firstLibraryChildFd + index}`)
    .join(':');
  const stdio = [
    'ignore',
    'pipe',
    'pipe',
    ...pinned.map(({ handle }) => handle.fd),
    stagingDirectory.fd,
    shardHandle.fd,
  ];
  const result = spawnSync(
    `/proc/self/fd/${loaderChildFd}`,
    [
      '--inhibit-cache',
      '--library-path',
      '/nonexistent',
      '--preload',
      preload,
      `/proc/self/fd/${executableChildFd}`,
      ...mvArguments({ stagingDirectoryChildFd, shardChildFd }),
    ],
    {
      env: Object.freeze({ LANG: 'C', LC_ALL: 'C' }),
      encoding: null,
      maxBuffer: 64 * 1024,
      timeout: 10_000,
      stdio,
    },
  );
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
  if (result.error || result.signal || stderr.length || result.status !== 0) {
    fail('CAS_SYSTEM_PUBLISHER_EXECUTION_FAILED', 'system publisher execution was not clean', result.error);
  }
  if (expectedOutput === null ? stdout.length !== 0 : sha256(stdout) !== expectedOutput) {
    fail('CAS_SYSTEM_PUBLISHER_OUTPUT_INVALID', 'system publisher output is not approved');
  }
  return { stagingDirectoryChildFd, shardChildFd };
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

async function openObjectOrAbsent(directory, name, label) {
  try {
    return await openObject(directory, name, label);
  } catch (error) {
    if (error.code === 'CAS_OBJECT_OPEN_FAILED' && error.cause?.code === 'ENOENT') return null;
    throw error;
  }
}

async function assertChildDirectoryStable(parent, name, expected, label) {
  const reopened = await openDirectory(procEntry(parent, name), label, { secureOwner: true });
  try {
    const observed = directoryIdentity(await reopened.stat({ bigint: true }));
    if (!sameDirectoryIdentity(observed, expected)) {
      fail('CAS_DIRECTORY_IDENTITY_CHANGED', `${label} identity changed`);
    }
  } finally {
    await reopened.close();
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
  systemPublisher,
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
  const publisher = checkedSystemPublisher(systemPublisher);
  const pinnedRuntime = await openPinnedSystemRuntime(publisher);
  let directories;
  let stagingDirectory;
  let stagingHandle;
  let stagingName;
  const objectPath = join(canonicalRoot, 'sha256', hexadecimal.slice(0, 2), hexadecimal);
  try {
    runPinnedSystemPublisher({
      publisher,
      pinned: pinnedRuntime,
      stagingDirectory: { fd: pinnedRuntime.at(-1).handle.fd },
      shardHandle: { fd: pinnedRuntime.at(-1).handle.fd },
      arguments: () => ['--version'],
      expectedOutput: publisher.versionStdoutDigest,
    });
    await verifyPinnedSystemRuntime(pinnedRuntime);
    directories = await openCasDirectoryChain(canonicalRoot, hexadecimal, { create: true });
    const existingBeforeStaging = await openObjectOrAbsent(
      directories.shard,
      hexadecimal,
      'existing CAS object',
    );
    if (existingBeforeStaging) {
      try {
        const verified = await readAndVerifyOpenObject(
          existingBeforeStaging.handle,
          existingBeforeStaging.stat,
          digest,
          maximum,
          'existing CAS object',
        );
        if (verified.bytes.length !== bytes.length) {
          fail('CAS_EXISTING_SIZE_MISMATCH', 'existing CAS object size is incorrect');
        }
        return descriptor(digest, bytes.length, checkedType, false);
      } finally {
        await existingBeforeStaging.handle.close();
      }
    }
    stagingDirectory = await openOrCreateDirectory(
      directories.shard,
      '.staging',
      'CAS staging quarantine directory',
      true,
    );
    const stagingDirectoryIdentity = directoryIdentity(
      await stagingDirectory.stat({ bigint: true }),
    );
    stagingName = `${hexadecimal}.${process.pid}.${randomBytes(24).toString('hex')}`;
    try {
      stagingHandle = await open(procEntry(stagingDirectory, stagingName), STAGING_CREATE_FLAGS, mode);
    } catch (error) {
      fail(
        'CAS_STAGING_CREATE_FAILED',
        'CAS unique staging object could not be created exclusively',
        error,
      );
    }
    const emptyStat = await stagingHandle.stat({ bigint: true });
    assertFileStat(emptyStat, 'CAS staging object', { links: 1n, mode });
    await stagingHandle.writeFile(bytes);
    await stagingHandle.sync();
    const writtenStat = await stagingHandle.stat({ bigint: true });
    assertFileStat(writtenStat, 'CAS staging object', { links: 1n, mode });
    if (writtenStat.size !== BigInt(bytes.length)) {
      fail('CAS_STAGING_SIZE_MISMATCH', 'CAS staging object size is incorrect');
    }
    const verifiedStaging = await readAndVerifyOpenObject(
      stagingHandle,
      writtenStat,
      digest,
      maximum,
      'CAS staging object',
      { links: 1n, mode },
    );
    await invokeTestHook(options, 'after-temporary-verified', {
      rootPath: canonicalRoot,
      objectPath,
      digest,
      stagingName,
      stagingPath: join(
        canonicalRoot,
        'sha256',
        hexadecimal.slice(0, 2),
        '.staging',
        stagingName,
      ),
    });
    const postHookStagingStat = await stagingHandle.stat({ bigint: true });
    assertFileStat(postHookStagingStat, 'CAS staging object', { links: 1n, mode });
    if (!sameFileIdentity(verifiedStaging.identity, fileIdentity(postHookStagingStat))) {
      fail('CAS_STAGING_IDENTITY_CHANGED', 'CAS staging object changed before publication');
    }
    await assertDirectoryChainStable(canonicalRoot, hexadecimal, directories.identities);
    await assertChildDirectoryStable(
      directories.shard,
      '.staging',
      stagingDirectoryIdentity,
      'CAS staging quarantine directory',
    );

    runPinnedSystemPublisher({
      publisher,
      pinned: pinnedRuntime,
      stagingDirectory,
      shardHandle: directories.shard,
      arguments: ({ stagingDirectoryChildFd, shardChildFd }) => [
        '--no-clobber',
        '--no-target-directory',
        '--',
        `/proc/self/fd/${stagingDirectoryChildFd}/${stagingName}`,
        `/proc/self/fd/${shardChildFd}/${hexadecimal}`,
      ],
      expectedOutput: null,
    });
    await verifyPinnedSystemRuntime(pinnedRuntime);
    const remainingStaging = await openObjectOrAbsent(
      stagingDirectory,
      stagingName,
      'quarantined CAS staging object',
    );
    if (!remainingStaging) {
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

    try {
      const quarantined = await readAndVerifyOpenObject(
        remainingStaging.handle,
        remainingStaging.stat,
        digest,
        maximum,
        'quarantined CAS staging object',
      );
      if (!sameInode(quarantined.identity, verifiedStaging.identity)) {
        fail('CAS_STAGING_IDENTITY_CHANGED', 'quarantined CAS staging identity changed');
      }
    } finally {
      await remainingStaging.handle.close();
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
    await stagingDirectory?.close().catch(() => {});
    await closeHandles(directories?.handles || []);
    await closePinnedSystemRuntime(pinnedRuntime);
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
