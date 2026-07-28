import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  chmodSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import {
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';

const GIT_OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const reservedEnvironmentNames = /^(?:BASH_ENV|ENV|GIT_|HOME$|LANG$|LANGUAGE$|LC_|LD_|LOCPATH$|NLSPATH$|NODE_|DYLD_|OPENSSL_|PATH$|PYTHON|SSL_CERT_DIR$|SSL_CERT_FILE$|SSLKEYLOGFILE$|TEMP$|TMP$|TMPDIR$|TZ$|TZDIR$|UV_THREADPOOL_SIZE$|XDG_)/;
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const completeTreeBoundCeilings = Object.freeze({
  maxTrackedPaths: 100_000,
  maxTotalBytes: 512 * 1024 * 1024,
  maxPathBytes: 4096,
  maxDepth: 128,
  maxGitObjectBytes: 256 * 1024 * 1024,
});

export function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== 'object' || Buffer.isBuffer(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort(utf8Compare).map((key) => [key, canonical(value[key])]),
  );
}

function canonicalJson(value) {
  return JSON.stringify(canonical(value));
}

function assertNoSymlinkComponents(path, code, boundary = '/') {
  const absolute = resolve(path);
  const root = resolve(boundary);
  const remainder = relative(root, absolute);
  if (remainder === '..' || remainder.startsWith(`..${sep}`) || isAbsolute(remainder)) {
    throw new Error(`${code}_OUTSIDE_BOUNDARY`);
  }
  let current = root;
  if (lstatSync(current).isSymbolicLink()) throw new Error(`${code}_SYMLINK_COMPONENT`);
  for (const component of remainder.split(sep).filter(Boolean)) {
    current = join(current, component);
    if (lstatSync(current).isSymbolicLink()) throw new Error(`${code}_SYMLINK_COMPONENT`);
  }
  return absolute;
}

function exactDirectory(path, code) {
  const absolute = resolve(path);
  assertNoSymlinkComponents(absolute, code);
  const canonicalPath = realpathSync(absolute);
  if (canonicalPath !== absolute || !statSync(canonicalPath).isDirectory()) {
    throw new Error(code);
  }
  return canonicalPath;
}

function identity(stat) {
  return {
    device: stat.dev.toString(),
    inode: stat.ino.toString(),
    mode: Number(stat.mode & 0o7777n),
    linkCount: stat.nlink.toString(),
    byteLength: stat.size.toString(),
    ctimeNanoseconds: stat.ctimeNs.toString(),
  };
}

function identitiesEqual(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function readPinnedBytes(fd, stat) {
  if (!stat.isFile()) throw new Error('PINNED_OBJECT_NOT_REGULAR_FILE');
  if (stat.size > BigInt(256 * 1024 * 1024)) throw new Error('PINNED_OBJECT_TOO_LARGE');
  const bytes = Buffer.alloc(Number(stat.size));
  let offset = 0;
  while (offset < bytes.length) {
    const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (count === 0) throw new Error('PINNED_OBJECT_TRUNCATED_DURING_READ');
    offset += count;
  }
  return bytes;
}

function openPinnedRegularFile(path, code) {
  assertNoSymlinkComponents(path, code);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const beforeStat = fstatSync(fd, { bigint: true });
    if (!beforeStat.isFile()) throw new Error(`${code}_NOT_REGULAR`);
    if (beforeStat.nlink !== 1n) throw new Error(`${code}_LINK_COUNT_NOT_ONE`);
    const bytes = readPinnedBytes(fd, beforeStat);
    const afterStat = fstatSync(fd, { bigint: true });
    if (!identitiesEqual(identity(beforeStat), identity(afterStat))) {
      throw new Error(`${code}_MOVED_DURING_READ`);
    }
    return {
      fd,
      bytes,
      digest: sha256(bytes),
      identity: identity(afterStat),
    };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function closePinned(pinned) {
  if (pinned && Number.isInteger(pinned.fd)) closeSync(pinned.fd);
}

function readPinnedUtf8(path, code) {
  const pinned = openPinnedRegularFile(path, code);
  try {
    const text = pinned.bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(pinned.bytes)) throw new Error(`${code}_NOT_STRICT_UTF8`);
    return text;
  } finally {
    closePinned(pinned);
  }
}

export function buildSanitizedExecutionEnvironment({
  homeDirectory,
  explicitEnvironment = {},
  allowedEnvironmentNames = [],
  includeGitControls = false,
} = {}) {
  if (!homeDirectory) throw new Error('HOME_DIRECTORY_REQUIRED');
  const home = exactDirectory(homeDirectory, 'HOME_NOT_EXACT_DIRECTORY');
  if (!Array.isArray(allowedEnvironmentNames)) throw new Error('ENVIRONMENT_ALLOWLIST_REQUIRED');
  const allowed = new Set(allowedEnvironmentNames);
  if (allowed.size !== allowedEnvironmentNames.length) throw new Error('ENVIRONMENT_ALLOWLIST_NOT_UNIQUE');
  for (const name of allowed) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(name) || reservedEnvironmentNames.test(name)) {
      throw new Error(`RESERVED_ENVIRONMENT_NAME_${name}`);
    }
  }
  for (const name of Object.keys(explicitEnvironment)) {
    if (reservedEnvironmentNames.test(name)) throw new Error(`RESERVED_ENVIRONMENT_NAME_${name}`);
    if (!allowed.has(name)) throw new Error(`ENVIRONMENT_NAME_NOT_ALLOWLISTED_${name}`);
  }
  const environment = {
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    PATH: '',
    LANG: 'C',
    LC_ALL: 'C',
    NODE_OPTIONS: '',
    NODE_PATH: '',
    OPENSSL_CONF: '/dev/null',
    OPENSSL_MODULES: '',
    TZ: 'UTC',
    ...explicitEnvironment,
  };
  mkdirSync(environment.XDG_CONFIG_HOME, { recursive: true, mode: 0o700 });
  if (includeGitControls) {
    Object.assign(environment, {
      GIT_ASKPASS: '/bin/false',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_NO_REPLACE_OBJECTS: '1',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_TERMINAL_PROMPT: '0',
      GCM_INTERACTIVE: 'never',
      SSH_ASKPASS: '/bin/false',
    });
  }
  return Object.freeze(environment);
}

function resolveRepositoryObjectStore(repository) {
  const worktree = exactDirectory(repository, 'REPOSITORY_NOT_EXACT_DIRECTORY');
  const dotGit = join(worktree, '.git');
  const dotGitStat = lstatSync(dotGit);
  let gitDirectory;
  if (dotGitStat.isDirectory() && !dotGitStat.isSymbolicLink()) {
    gitDirectory = realpathSync(dotGit);
  } else if (dotGitStat.isFile() && !dotGitStat.isSymbolicLink()) {
    const match = /^gitdir: ([^\0\r\n]+)\n?$/.exec(readPinnedUtf8(dotGit, 'GITDIR_POINTER'));
    if (!match) throw new Error('GITDIR_POINTER_INVALID');
    gitDirectory = realpathSync(resolve(worktree, match[1]));
  } else {
    throw new Error('GITDIR_NOT_EXACT');
  }
  if (!statSync(gitDirectory).isDirectory()) throw new Error('GITDIR_NOT_DIRECTORY');
  const commonDirectoryFile = join(gitDirectory, 'commondir');
  let commonDirectory = gitDirectory;
  if (existsSync(commonDirectoryFile)) {
    const commondir = readPinnedUtf8(commonDirectoryFile, 'COMMONDIR_POINTER').trim();
    if (!commondir || commondir.includes('\0')) throw new Error('COMMONDIR_POINTER_INVALID');
    commonDirectory = realpathSync(resolve(gitDirectory, commondir));
  }
  const objectStorePath = join(commonDirectory, 'objects');
  if (lstatSync(objectStorePath).isSymbolicLink()) throw new Error('OBJECT_STORE_SYMLINK_REFUSED');
  const objectStore = exactDirectory(objectStorePath, 'OBJECT_STORE_NOT_EXACT_DIRECTORY');
  const alternates = join(objectStore, 'info', 'alternates');
  if (existsSync(alternates) && readPinnedUtf8(alternates, 'OBJECT_ALTERNATES').trim()) {
    throw new Error('SOURCE_OBJECT_ALTERNATES_UNSUPPORTED');
  }
  const objectStoreStat = statSync(objectStore, { bigint: true });
  return {
    worktree,
    gitDirectory,
    commonDirectory,
    objectStore,
    objectStoreIdentity: identity(objectStoreStat),
  };
}

function createIsolatedObjectRepository(sourceObjectStore) {
  const root = mkdtempSync(join(tmpdir(), 'usf-isolated-git-'));
  const gitDirectory = join(root, 'repository.git');
  mkdirSync(join(gitDirectory, 'objects', 'info'), { recursive: true, mode: 0o700 });
  mkdirSync(join(gitDirectory, 'refs'), { recursive: true, mode: 0o700 });
  writeFileSync(join(gitDirectory, 'HEAD'), 'ref: refs/heads/hermetic\n', { mode: 0o600 });
  writeFileSync(
    join(gitDirectory, 'objects', 'info', 'alternates'),
    `${sourceObjectStore}\n`,
    { mode: 0o600 },
  );
  return { root, gitDirectory };
}

function gitObjectDigest(type, bytes, hexadecimalLength) {
  const algorithm = hexadecimalLength === 40 ? 'sha1' : 'sha256';
  const header = Buffer.from(`${type} ${bytes.length}\0`, 'utf8');
  return createHash(algorithm).update(header).update(bytes).digest('hex');
}

function validateObjectId(value, code) {
  if (!GIT_OBJECT_ID.test(value)) throw new Error(code);
  return value;
}

function collectChildStream(stream, {
  maximumBytes = Number.POSITIVE_INFINITY,
  boundCode = 'CHILD_STREAM_BOUND_EXCEEDED',
} = {}) {
  const chunks = [];
  return new Promise((resolveStream, rejectStream) => {
    let byteLength = 0;
    let settled = false;
    stream.on('data', (chunk) => {
      if (settled) return;
      const bytes = Buffer.from(chunk);
      byteLength += bytes.length;
      if (byteLength > maximumBytes) {
        settled = true;
        stream.destroy();
        rejectStream(new Error(boundCode));
        return;
      }
      chunks.push(bytes);
    });
    stream.once('end', () => {
      if (!settled) {
        settled = true;
        resolveStream(Buffer.concat(chunks));
      }
    });
    stream.once('error', (error) => {
      if (!settled) {
        settled = true;
        rejectStream(error);
      }
    });
  });
}

function childSpawned(child) {
  return new Promise((resolveSpawn, rejectSpawn) => {
    child.once('spawn', resolveSpawn);
    child.once('error', rejectSpawn);
  });
}

function childClosed(child) {
  return new Promise((resolveClose, rejectClose) => {
    child.once('close', (status, signal) => resolveClose({ status, signal }));
    child.once('error', rejectClose);
  });
}

async function runIsolatedGitObject(context, objectId) {
  validateObjectId(objectId, 'GIT_OBJECT_ID_INVALID');
  const pinnedExecutable = openPinnedRegularFile(
    context.gitExecutable,
    'GIT_CAT_FILE_EXECUTABLE',
  );
  let child;
  try {
    child = spawn(`/proc/self/fd/${pinnedExecutable.fd}`, [
      '--no-replace-objects',
      `--git-dir=${context.isolatedGitDirectory}`,
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      '-c', 'core.attributesFile=/dev/null',
      'cat-file', '--batch',
    ], {
      env: context.environment,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdoutPromise = collectChildStream(child.stdout, {
      maximumBytes: context.bounds.maxGitObjectBytes + 1024,
      boundCode: 'GIT_OBJECT_BOUND_EXCEEDED',
    });
    const stderrPromise = collectChildStream(child.stderr, {
      maximumBytes: 1024 * 1024,
      boundCode: 'GIT_STDERR_BOUND_EXCEEDED',
    });
    const closePromise = childClosed(child);
    await childSpawned(child);
    const runtimeEvidence = await waitForExpectedChildRuntime(
      child.pid,
      context.expectedGitRuntime,
      'GIT_RUNTIME',
    );
    child.stdin.end(`${objectId}\n`);
    const [{ status, signal }, stdout, stderr] = await Promise.all([
      closePromise,
      stdoutPromise,
      stderrPromise,
    ]);
    if (status !== 0 || signal) {
      const error = new Error('GIT_CAT_FILE_FAILED');
      error.commandResult = {
        status,
        signal,
        stdoutDigest: sha256(stdout),
        stderrDigest: sha256(stderr),
      };
      throw error;
    }
    const newline = stdout.indexOf(0x0a);
    if (newline === -1 || stdout.at(-1) !== 0x0a) throw new Error('GIT_BATCH_OUTPUT_INVALID');
    const header = stdout.subarray(0, newline).toString('ascii');
    const match = /^([0-9a-f]{40}|[0-9a-f]{64}) ([a-z]+) ([0-9]+)$/.exec(header);
    if (!match || match[1] !== objectId) throw new Error('GIT_BATCH_HEADER_INVALID');
    const byteLength = Number(match[3]);
    const bytes = stdout.subarray(newline + 1, -1);
    if (
      !Number.isSafeInteger(byteLength)
      || byteLength > context.bounds.maxGitObjectBytes
      || bytes.length !== byteLength
    ) {
      throw new Error('GIT_BATCH_LENGTH_INVALID');
    }
    context.gitExecutableEvidence = runtimeEvidence.executable;
    context.gitRuntimeEvidence.push(runtimeEvidence);
    return { type: match[2], bytes, runtimeEvidence };
  } catch (error) {
    if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    throw error;
  } finally {
    closePinned(pinnedExecutable);
  }
}

async function readVerifiedGitObject(context, type, objectId) {
  const result = await runIsolatedGitObject(context, objectId);
  if (result.type !== type) throw new Error('GIT_OBJECT_TYPE_MISMATCH');
  const observed = gitObjectDigest(type, result.bytes, objectId.length);
  if (observed !== objectId) throw new Error('GIT_OBJECT_CONTENT_DIGEST_MISMATCH');
  return result.bytes;
}

function parseCommitTree(commitBytes, objectIdLength) {
  const headerEnd = commitBytes.indexOf(Buffer.from('\n\n'));
  if (headerEnd === -1) throw new Error('COMMIT_OBJECT_INVALID');
  const headers = commitBytes.subarray(0, headerEnd).toString('utf8').split('\n');
  const tree = headers.find((line) => line.startsWith('tree '))?.slice(5) || '';
  if (tree.length !== objectIdLength || !GIT_OBJECT_ID.test(tree)) throw new Error('COMMIT_TREE_INVALID');
  return tree;
}

function parseTreeEntries(bytes, hexadecimalLength) {
  const rawObjectIdLength = hexadecimalLength / 2;
  const entries = [];
  let offset = 0;
  while (offset < bytes.length) {
    const space = bytes.indexOf(0x20, offset);
    const nul = bytes.indexOf(0x00, space + 1);
    if (space <= offset || nul <= space + 1 || nul + 1 + rawObjectIdLength > bytes.length) {
      throw new Error('TREE_OBJECT_INVALID');
    }
    const mode = bytes.subarray(offset, space).toString('ascii');
    const nameBytes = bytes.subarray(space + 1, nul);
    if (nameBytes.includes(0x2f)) throw new Error('TREE_ENTRY_NAME_INVALID');
    const name = nameBytes.toString('utf8');
    if (!name || Buffer.from(name, 'utf8').compare(nameBytes) !== 0) {
      throw new Error('TREE_ENTRY_NAME_NOT_STRICT_UTF8');
    }
    const objectId = bytes.subarray(nul + 1, nul + 1 + rawObjectIdLength).toString('hex');
    entries.push({ mode, name, objectId });
    offset = nul + 1 + rawObjectIdLength;
  }
  return entries;
}

function normalizeCompleteTreeBounds(bounds = {}) {
  if (!bounds || typeof bounds !== 'object' || Array.isArray(bounds)) {
    throw new Error('COMPLETE_TREE_BOUNDS_INVALID');
  }
  const unknown = Object.keys(bounds)
    .filter((name) => !(name in completeTreeBoundCeilings))
    .sort(utf8Compare);
  if (unknown.length > 0) throw new Error(`COMPLETE_TREE_BOUND_UNKNOWN_${unknown[0]}`);
  return Object.freeze(Object.fromEntries(Object.entries(completeTreeBoundCeilings).map(
    ([name, ceiling]) => {
      const value = bounds[name] ?? ceiling;
      if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) {
        throw new Error(`COMPLETE_TREE_BOUND_INVALID_${name}`);
      }
      return [name, value];
    },
  )));
}

function assertPathWithinBounds(path, bounds) {
  if (Buffer.byteLength(path, 'utf8') > bounds.maxPathBytes) {
    throw new Error('TRACKED_PATH_BYTE_BOUND_EXCEEDED');
  }
  if (path.split('/').length > bounds.maxDepth) {
    throw new Error('TRACKED_PATH_DEPTH_BOUND_EXCEEDED');
  }
}

async function walkTree(context, treeId, prefix, records, state, depth = 0) {
  if (depth > context.bounds.maxDepth) throw new Error('TRACKED_TREE_DEPTH_BOUND_EXCEEDED');
  const tree = await readVerifiedGitObject(context, 'tree', treeId);
  for (const entry of parseTreeEntries(tree, treeId.length)) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    assertPathWithinBounds(path, context.bounds);
    state.entryCount += 1;
    if (state.entryCount > context.bounds.maxTrackedPaths) {
      throw new Error('TRACKED_TREE_ENTRY_BOUND_EXCEEDED');
    }
    if (entry.mode === '40000' || entry.mode === '040000') {
      await walkTree(context, entry.objectId, path, records, state, depth + 1);
    } else {
      const type = entry.mode === '160000' ? 'commit' : 'blob';
      if (records.has(path)) throw new Error('TRACKED_TREE_DUPLICATE_PATH');
      records.set(path, { path, mode: entry.mode, objectId: entry.objectId, type });
    }
  }
}

function validateTrackedPath(path) {
  if (
    typeof path !== 'string'
    || path.length === 0
    || isAbsolute(path)
    || path.includes('\0')
    || path.includes('\\')
    || path.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw new Error('TRACKED_PATH_INVALID');
  }
  return path;
}

function readStrictDirectoryNames(directory) {
  const names = readdirSync(directory, { encoding: 'buffer' }).map((bytes) => {
    const name = bytes.toString('utf8');
    if (
      !name
      || name === '.'
      || name === '..'
      || name.includes('/')
      || name.includes('\0')
      || !Buffer.from(name, 'utf8').equals(bytes)
    ) {
      throw new Error('WORKTREE_ENTRY_NAME_NOT_STRICT_UTF8');
    }
    return name;
  }).sort(utf8Compare);
  if (new Set(names).size !== names.length) throw new Error('WORKTREE_ENTRY_NAMES_NOT_UNIQUE');
  return names;
}

function expectedDirectoryPaths(records) {
  const directories = new Set();
  for (const record of records) {
    const components = record.path.split('/');
    for (let index = 1; index < components.length; index += 1) {
      directories.add(components.slice(0, index).join('/'));
    }
  }
  return directories;
}

function captureWorktreeMirror({ repository, bounds }) {
  const files = [];
  const directories = [];
  let entryCount = 0;
  let totalBytes = 0;

  function walk(directory, prefix, depth) {
    if (depth > bounds.maxDepth) throw new Error('WORKTREE_DEPTH_BOUND_EXCEEDED');
    const beforeStat = lstatSync(directory, { bigint: true });
    if (!beforeStat.isDirectory() || beforeStat.isSymbolicLink()) {
      throw new Error('WORKTREE_DIRECTORY_IDENTITY_INVALID');
    }
    const beforeIdentity = identity(beforeStat);
    directories.push({ path: prefix, identity: beforeIdentity });
    const names = readStrictDirectoryNames(directory);
    for (const name of names) {
      const path = prefix ? `${prefix}/${name}` : name;
      const absolutePath = join(directory, name);
      const entryStat = lstatSync(absolutePath, { bigint: true });
      if (entryStat.isSymbolicLink()) throw new Error(`WORKTREE_SYMLINK_REFUSED_${path}`);
      if (!prefix && (name === '.git' || name === '.work')) {
        if (name === '.work' && !entryStat.isDirectory()) {
          throw new Error('WORKTREE_SESSION_AREA_NOT_DIRECTORY');
        }
        if (name === '.git' && !entryStat.isDirectory() && !entryStat.isFile()) {
          throw new Error('WORKTREE_GIT_AREA_NOT_EXACT');
        }
        continue;
      }
      assertPathWithinBounds(path, bounds);
      entryCount += 1;
      if (entryCount > bounds.maxTrackedPaths) {
        throw new Error('WORKTREE_ENTRY_BOUND_EXCEEDED');
      }
      if (entryStat.isDirectory()) {
        walk(absolutePath, path, depth + 1);
        continue;
      }
      if (!entryStat.isFile()) throw new Error(`WORKTREE_NON_REGULAR_ENTRY_${path}`);
      let pinned;
      try {
        pinned = openPinnedRegularFile(absolutePath, 'WORKTREE_COMPLETE_SOURCE');
        if (!identitiesEqual(identity(entryStat), pinned.identity)) {
          throw new Error(`WORKTREE_SOURCE_MOVED_BEFORE_READ_${path}`);
        }
        totalBytes += pinned.bytes.length;
        if (totalBytes > bounds.maxTotalBytes) {
          throw new Error('WORKTREE_TOTAL_BYTE_BOUND_EXCEEDED');
        }
        files.push({
          path,
          type: 'file',
          mode: Number(entryStat.mode & 0o111n) ? '100755' : '100644',
          byteLength: pinned.bytes.length,
          digest: pinned.digest,
          identity: pinned.identity,
        });
      } finally {
        closePinned(pinned);
      }
    }
    const afterNames = readStrictDirectoryNames(directory);
    const afterStat = lstatSync(directory, { bigint: true });
    if (
      canonicalJson(names) !== canonicalJson(afterNames)
      || !identitiesEqual(beforeIdentity, identity(afterStat))
    ) {
      throw new Error(`WORKTREE_DIRECTORY_MOVED_DURING_READ_${prefix || 'ROOT'}`);
    }
  }

  walk(repository, '', 0);
  return {
    files: files.sort((left, right) => utf8Compare(left.path, right.path)),
    directories: directories.sort((left, right) => utf8Compare(left.path, right.path)),
    totalBytes,
  };
}

function validateWorktreeCapture({ capture, records }) {
  const expectedFiles = new Map(records.map((record) => [record.path, record]));
  const observedFiles = new Map(capture.files.map((record) => [record.path, record]));
  const expectedDirectories = expectedDirectoryPaths(records);
  const observedDirectories = new Set(
    capture.directories.map(({ path }) => path).filter(Boolean),
  );
  const extraFile = [...observedFiles.keys()]
    .filter((path) => !expectedFiles.has(path))
    .sort(utf8Compare)[0];
  if (extraFile) throw new Error(`WORKTREE_UNLISTED_FILE_${extraFile}`);
  const missingFile = [...expectedFiles.keys()]
    .filter((path) => !observedFiles.has(path))
    .sort(utf8Compare)[0];
  if (missingFile) throw new Error(`WORKTREE_TRACKED_FILE_MISSING_${missingFile}`);
  const extraDirectory = [...observedDirectories]
    .filter((path) => !expectedDirectories.has(path))
    .sort(utf8Compare)[0];
  if (extraDirectory) throw new Error(`WORKTREE_UNLISTED_DIRECTORY_${extraDirectory}`);
  const missingDirectory = [...expectedDirectories]
    .filter((path) => !observedDirectories.has(path))
    .sort(utf8Compare)[0];
  if (missingDirectory) throw new Error(`WORKTREE_TRACKED_DIRECTORY_MISSING_${missingDirectory}`);
  for (const [path, expected] of expectedFiles) {
    const observed = observedFiles.get(path);
    if (
      observed.type !== 'file'
      || observed.mode !== expected.mode
      || observed.byteLength !== expected.byteLength
      || observed.digest !== expected.digest
    ) {
      throw new Error(`WORKTREE_TRACKED_FILE_MISMATCH_${path}`);
    }
  }
}

function readExactWorktreeMirror({ repository, records, bounds }) {
  const first = captureWorktreeMirror({ repository, bounds });
  validateWorktreeCapture({ capture: first, records });
  const second = captureWorktreeMirror({ repository, bounds });
  validateWorktreeCapture({ capture: second, records });
  if (
    canonicalJson(first.files) !== canonicalJson(second.files)
    || canonicalJson(first.directories) !== canonicalJson(second.directories)
  ) {
    throw new Error('WORKTREE_SOURCE_MOVED_DURING_COMPLETE_SNAPSHOT');
  }
  const publicRecords = first.files.map(({ identity: ignored, ...record }) => record);
  return {
    schemaVersion: 1,
    excludedRootEntries: ['.git', '.work'],
    exactPathSetVerified: true,
    sourceMovementChecked: true,
    recordCount: publicRecords.length,
    totalBytes: first.totalBytes,
    sourceSetDigest: sha256(canonicalJson(publicRecords)),
    sourceIdentitySetDigest: sha256(canonicalJson({
      directories: first.directories,
      files: first.files.map(({ path, identity }) => ({ path, identity })),
    })),
    records: publicRecords,
  };
}

export async function readTrackedTreeSnapshot({
  repository,
  commit,
  paths,
  allTrackedPaths = false,
  verifyWorktreeMirror = false,
  bounds: requestedBounds,
  gitExecutable = '/usr/bin/git',
  expectedGitRuntime,
}) {
  validateObjectId(commit, 'COMMIT_ID_INVALID');
  if (typeof allTrackedPaths !== 'boolean') throw new Error('ALL_TRACKED_PATHS_INVALID');
  if (typeof verifyWorktreeMirror !== 'boolean') throw new Error('VERIFY_WORKTREE_MIRROR_INVALID');
  if (verifyWorktreeMirror && !allTrackedPaths) {
    throw new Error('WORKTREE_MIRROR_REQUIRES_COMPLETE_TREE');
  }
  if (allTrackedPaths && paths !== undefined) {
    throw new Error('TRACKED_PATH_SELECTION_AMBIGUOUS');
  }
  if (!allTrackedPaths && (!Array.isArray(paths) || paths.length === 0)) {
    throw new Error('TRACKED_PATHS_REQUIRED');
  }
  const requestedPaths = allTrackedPaths
    ? null
    : [...new Set(paths.map(validateTrackedPath))].sort(utf8Compare);
  if (!allTrackedPaths && requestedPaths.length !== paths.length) {
    throw new Error('TRACKED_PATHS_NOT_UNIQUE');
  }
  const bounds = normalizeCompleteTreeBounds(requestedBounds);
  if (requestedPaths) requestedPaths.forEach((path) => assertPathWithinBounds(path, bounds));
  verifyExpectedRuntimeBeforeExecution(expectedGitRuntime, gitExecutable, 'GIT_RUNTIME');
  const source = resolveRepositoryObjectStore(repository);
  const isolated = createIsolatedObjectRepository(source.objectStore);
  const temporaryHome = mkdtempSync(join(tmpdir(), 'usf-hermetic-git-home-'));
  const context = {
    gitExecutable,
    isolatedGitDirectory: isolated.gitDirectory,
    expectedGitRuntime,
    gitRuntimeEvidence: [],
    bounds,
    environment: buildSanitizedExecutionEnvironment({
      homeDirectory: temporaryHome,
      includeGitControls: true,
    }),
  };
  try {
    const objectStoreBefore = identity(statSync(source.objectStore, { bigint: true }));
    if (!identitiesEqual(source.objectStoreIdentity, objectStoreBefore)) {
      throw new Error('OBJECT_STORE_CHANGED_BEFORE_READ');
    }
    const commitBytes = await readVerifiedGitObject(context, 'commit', commit);
    const treeId = parseCommitTree(commitBytes, commit.length);
    const treeRecords = new Map();
    await walkTree(context, treeId, '', treeRecords, { entryCount: 0 });
    const selectedPaths = allTrackedPaths
      ? [...treeRecords.keys()].sort(utf8Compare)
      : requestedPaths;
    const records = [];
    let totalBytes = 0;
    for (const path of selectedPaths) {
      const entry = treeRecords.get(path);
      if (!entry) throw new Error(`TRACKED_PATH_ABSENT_${path}`);
      if (entry.type !== 'blob' || !/^(?:100644|100755)$/.test(entry.mode)) {
        throw new Error(`TRACKED_PATH_NOT_REGULAR_BLOB_${path}`);
      }
      if (
        allTrackedPaths
        && (path === '.work' || path.startsWith('.work/') || path === '.git' || path.startsWith('.git/'))
      ) {
        throw new Error(`TRACKED_PATH_IN_RESERVED_AREA_${path}`);
      }
      const bytes = await readVerifiedGitObject(context, 'blob', entry.objectId);
      totalBytes += bytes.length;
      if (totalBytes > bounds.maxTotalBytes) throw new Error('TRACKED_TREE_TOTAL_BYTE_BOUND_EXCEEDED');
      const record = {
        ...entry,
        byteLength: bytes.length,
        digest: sha256(bytes),
      };
      records.push(allTrackedPaths ? { ...record, type: 'file' } : { ...record, bytes });
    }
    const worktreeMirror = verifyWorktreeMirror
      ? readExactWorktreeMirror({
        repository: source.worktree,
        records,
        bounds,
      })
      : null;
    const objectStoreAfter = identity(statSync(source.objectStore, { bigint: true }));
    if (!identitiesEqual(objectStoreBefore, objectStoreAfter)) {
      throw new Error('OBJECT_STORE_CHANGED_DURING_READ');
    }
    const recordEvidence = records.map(({ bytes, ...record }) => record);
    const sourceSetDigest = sha256(canonicalJson(recordEvidence));
    return {
      schemaVersion: 1,
      commit,
      tree: treeId,
      sourceSetDigest,
      records,
      evidence: {
        commit,
        tree: treeId,
        selection: allTrackedPaths ? 'ALL_TRACKED_PATHS' : 'EXACT_REQUESTED_PATHS',
        sourceSetDigest,
        recordCount: recordEvidence.length,
        totalBytes,
        bounds,
        records: recordEvidence,
        ...(worktreeMirror ? { worktreeMirror } : {}),
        repositoryObjectStore: {
          path: source.objectStore,
          ...objectStoreAfter,
        },
        gitExecution: {
          configurationSource: 'ISOLATED_GIT_DIR_WITH_SOURCE_OBJECT_ALTERNATE',
          executable: context.gitExecutableEvidence,
          runtime: context.gitRuntimeEvidence.at(-1),
          runtimeExecutions: context.gitRuntimeEvidence,
          originalLocalConfigLoaded: false,
          originalIndexLoaded: false,
          originalHooksLoaded: false,
          originalWorktreeLoaded: false,
          replaceObjectsDisabled: true,
          promptsDisabled: true,
        },
      },
    };
  } finally {
    rmSync(isolated.root, { recursive: true, force: true });
    rmSync(temporaryHome, { recursive: true, force: true });
  }
}

export function readCompleteTrackedTreeSnapshot(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new Error('COMPLETE_TREE_OPTIONS_REQUIRED');
  }
  if ('paths' in options || 'allTrackedPaths' in options) {
    throw new Error('COMPLETE_TREE_SELECTION_IS_FIXED');
  }
  return readTrackedTreeSnapshot({
    ...options,
    allTrackedPaths: true,
  });
}

export function compareWorktreeToSnapshot({ repository, snapshot }) {
  const root = exactDirectory(repository, 'REPOSITORY_NOT_EXACT_DIRECTORY');
  const results = snapshot.records.map((record) => {
    const path = join(root, ...record.path.split('/'));
    let pinned;
    try {
      pinned = openPinnedRegularFile(path, 'WORKTREE_SOURCE');
      const mode = Number(fstatSync(pinned.fd, { bigint: true }).mode & 0o111n) ? '100755' : '100644';
      return {
        path: record.path,
        expectedDigest: record.digest,
        observedDigest: pinned.digest,
        expectedMode: record.mode,
        observedMode: mode,
        matches: record.digest === pinned.digest && record.mode === mode,
      };
    } catch (error) {
      return {
        path: record.path,
        expectedDigest: record.digest,
        observedDigest: null,
        expectedMode: record.mode,
        observedMode: null,
        matches: false,
        error: error.code || error.message,
      };
    } finally {
      closePinned(pinned);
    }
  });
  return {
    matches: results.every((row) => row.matches),
    results,
  };
}

export function assertWorktreeMatchesSnapshot(options) {
  const result = compareWorktreeToSnapshot(options);
  if (!result.matches) {
    const error = new Error('WORKTREE_DOES_NOT_MATCH_COMMIT_SNAPSHOT');
    error.comparison = result;
    throw error;
  }
  return result;
}

const closureLoaderSource = `
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { relative, resolve as resolvePath, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
const digest = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export function installClosureHooks(root, records) {
  const manifest = new Map(records.map((record) => [record.path, record]));
  const within = (path) => path === root || path.startsWith(root + '/');
  const assertComponents = (path) => {
    const remainder = relative(root, resolvePath(path));
    if (remainder === '..' || remainder.startsWith('..' + sep)) {
      throw new Error('CLOSURE_COMPONENT_OUTSIDE_ROOT');
    }
    let current = root;
    if (lstatSync(current).isSymbolicLink()) throw new Error('CLOSURE_SYMLINK_COMPONENT');
    for (const component of remainder.split(sep).filter(Boolean)) {
      current = resolvePath(current, component);
      if (lstatSync(current).isSymbolicLink()) throw new Error('CLOSURE_SYMLINK_COMPONENT');
    }
  };
  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier.startsWith('node:')) return nextResolve(specifier, context);
      const resolved = nextResolve(specifier, context);
      if (!resolved.url.startsWith('file:')) throw new Error('CLOSURE_NON_FILE_IMPORT_REFUSED');
      const path = fileURLToPath(resolved.url);
      if (!within(path) || !manifest.has(path)) throw new Error('CLOSURE_IMPORT_OUTSIDE_MANIFEST');
      return resolved;
    },
    load(url, context, nextLoad) {
      if (url.startsWith('node:')) return nextLoad(url, context);
      if (!url.startsWith('file:')) throw new Error('CLOSURE_NON_FILE_LOAD_REFUSED');
      const path = fileURLToPath(url);
      const expected = manifest.get(path);
      if (!within(path) || !expected) throw new Error('CLOSURE_LOAD_OUTSIDE_MANIFEST');
      assertComponents(path);
      const before = lstatSync(path, { bigint: true });
      if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
        throw new Error('CLOSURE_LOAD_IDENTITY_INVALID');
      }
      const loaded = nextLoad(url, context);
      if (loaded.source === null || loaded.source === undefined) {
        throw new Error('CLOSURE_LOADER_SOURCE_UNAVAILABLE');
      }
      const bytes = Buffer.isBuffer(loaded.source) ? loaded.source : Buffer.from(loaded.source);
      if (digest(bytes) !== expected.digest || bytes.length !== expected.byteLength) {
        throw new Error('CLOSURE_LOADED_BYTES_MISMATCH');
      }
      const after = lstatSync(path, { bigint: true });
      assertComponents(path);
      if (
        before.dev !== after.dev
        || before.ino !== after.ino
        || before.ctimeNs !== after.ctimeNs
        || before.nlink !== after.nlink
        || before.size !== after.size
      ) throw new Error('CLOSURE_LOAD_IDENTITY_CHANGED');
      return loaded;
    },
  });
}
`;

function dataModule(source) {
  return `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
}

function validateSnapshotClosure(snapshot, closurePaths, entryPath) {
  if (
    !snapshot
    || snapshot.schemaVersion !== 1
    || !snapshot.evidence
    || !Array.isArray(snapshot.records)
    || !Array.isArray(closurePaths)
  ) {
    throw new Error('COMMITTED_CLOSURE_REQUIRED');
  }
  const expectedPaths = snapshot.records.map(({ path }) => path).sort(utf8Compare);
  const suppliedPaths = [...closurePaths].sort(utf8Compare);
  if (
    new Set(suppliedPaths).size !== suppliedPaths.length
    || canonicalJson(suppliedPaths) !== canonicalJson(expectedPaths)
  ) {
    throw new Error('CLOSURE_PATH_SET_MISMATCH');
  }
  validateTrackedPath(entryPath);
  if (!suppliedPaths.includes(entryPath)) throw new Error('CLOSURE_ENTRY_NOT_IN_SOURCE_SET');
  const evidenceRecords = snapshot.records.map(({ bytes, ...record }) => record);
  if (
    snapshot.evidence.recordCount !== evidenceRecords.length
    || canonicalJson(snapshot.evidence.records) !== canonicalJson(evidenceRecords)
    || sha256(canonicalJson(evidenceRecords)) !== snapshot.evidence.sourceSetDigest
  ) {
    throw new Error('CLOSURE_SOURCE_SET_BINDING_INVALID');
  }
  for (const record of snapshot.records) {
    if (
      !Buffer.isBuffer(record.bytes)
      || record.bytes.length !== record.byteLength
      || sha256(record.bytes) !== record.digest
      || !/^(?:100644|100755)$/.test(record.mode)
    ) {
      throw new Error(`CLOSURE_RECORD_INVALID_${record.path}`);
    }
  }
  return snapshot.records;
}

function createMaterializedClosure(snapshot, closurePaths, entryPath) {
  const records = validateSnapshotClosure(snapshot, closurePaths, entryPath);
  const root = mkdtempSync(join(tmpdir(), 'usf-committed-node-closure-'));
  const rootStat = lstatSync(root, { bigint: true });
  const rootAnchor = { device: rootStat.dev.toString(), inode: rootStat.ino.toString() };
  const directories = new Set([root]);
  const materialized = [];
  try {
    for (const record of records) {
      const components = record.path.split('/');
      let directory = root;
      for (const component of components.slice(0, -1)) {
        directory = join(directory, component);
        if (!existsSync(directory)) mkdirSync(directory, { mode: 0o700 });
        assertNoSymlinkComponents(directory, 'CLOSURE_DIRECTORY', root);
        directories.add(directory);
      }
      const path = join(root, ...components);
      writeFileSync(path, record.bytes, {
        flag: 'wx',
        mode: record.mode === '100755' ? 0o500 : 0o400,
      });
      const pinned = openPinnedRegularFile(path, 'CLOSURE_FILE');
      try {
        if (pinned.digest !== record.digest || pinned.bytes.length !== record.byteLength) {
          throw new Error('CLOSURE_MATERIALISATION_MISMATCH');
        }
        materialized.push({
          path: record.path,
          absolutePath: path,
          digest: record.digest,
          byteLength: record.byteLength,
          mode: record.mode,
          identity: pinned.identity,
        });
      } finally {
        closePinned(pinned);
      }
    }
    return {
      root,
      rootAnchor,
      entryPath: join(root, ...entryPath.split('/')),
      materialized,
      directories: [...directories].sort((left, right) => right.length - left.length),
    };
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

function verifyMaterializedClosure(closure) {
  for (const record of closure.materialized) {
    assertNoSymlinkComponents(record.absolutePath, 'CLOSURE_FILE', closure.root);
    const pinned = openPinnedRegularFile(record.absolutePath, 'CLOSURE_FILE');
    try {
      if (
        pinned.digest !== record.digest
        || pinned.bytes.length !== record.byteLength
        || !identitiesEqual(pinned.identity, record.identity)
      ) {
        throw new Error('CLOSURE_FILE_CHANGED');
      }
    } finally {
      closePinned(pinned);
    }
  }
}

function closeChildOnTimeout(child, timeout) {
  const timer = setTimeout(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }, timeout);
  timer.unref();
  return () => clearTimeout(timer);
}

function makePrivateDirectoryCleanupWritable(path) {
  try {
    const stat = lstatSync(path);
    if (stat.isDirectory() && !stat.isSymbolicLink()) chmodSync(path, 0o700);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

export async function runCommittedNodeClosure({
  snapshot,
  closurePaths,
  entryPath,
  expectedNodeRuntime,
  nodeExecutable = process.execPath,
  arguments: args = [],
  explicitEnvironment = {},
  allowedEnvironmentNames = [],
  timeout = 120_000,
  afterMaterialize,
  afterRuntimeBound,
}) {
  verifyExpectedRuntimeBeforeExecution(expectedNodeRuntime, nodeExecutable, 'NODE_RUNTIME');
  const closure = createMaterializedClosure(snapshot, closurePaths, entryPath);
  const home = join(closure.root, '.home');
  const xdg = join(home, '.config');
  mkdirSync(xdg, { recursive: true, mode: 0o700 });
  const environment = buildSanitizedExecutionEnvironment({
    homeDirectory: home,
    explicitEnvironment,
    allowedEnvironmentNames,
  });
  const loaderRecords = closure.materialized.map((record) => ({
    path: record.absolutePath,
    digest: record.digest,
    byteLength: record.byteLength,
  }));
  const registerSource = `${closureLoaderSource}
installClosureHooks(
  ${JSON.stringify(closure.root)},
  ${JSON.stringify(loaderRecords)}
);
`;
  const launcherSource = `
import { pathToFileURL } from 'node:url';
await import(pathToFileURL(${JSON.stringify(closure.entryPath)}).href);
`;
  let child;
  let pinnedExecutable;
  try {
    if (typeof afterMaterialize === 'function') await afterMaterialize(closure);
    verifyMaterializedClosure(closure);
    for (const directory of closure.directories) chmodSync(directory, 0o500);
    chmodSync(xdg, 0o500);
    chmodSync(home, 0o500);
    pinnedExecutable = openPinnedRegularFile(nodeExecutable, 'NODE_EXECUTABLE');
    child = spawn(`/proc/self/fd/${pinnedExecutable.fd}`, [
      '--no-addons',
      '--permission',
      `--allow-fs-read=${closure.root}`,
      `--import=${dataModule(registerSource)}`,
      '--input-type=module',
      '-',
      ...args,
    ], {
      cwd: closure.root,
      env: environment,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdoutPromise = collectChildStream(child.stdout);
    const stderrPromise = collectChildStream(child.stderr);
    const closePromise = childClosed(child);
    const cancelTimeout = closeChildOnTimeout(child, timeout);
    await childSpawned(child);
    const runtimeEvidence = await waitForExpectedChildRuntime(
      child.pid,
      expectedNodeRuntime,
      'NODE_RUNTIME',
    );
    if (typeof afterRuntimeBound === 'function') await afterRuntimeBound(closure, runtimeEvidence);
    child.stdin.end(launcherSource);
    const [{ status, signal }, stdout, stderr] = await Promise.all([
      closePromise,
      stdoutPromise,
      stderrPromise,
    ]);
    cancelTimeout();
    verifyExpectedRuntimeBeforeExecution(expectedNodeRuntime, nodeExecutable, 'NODE_RUNTIME_POST');
    verifyMaterializedClosure(closure);
    if (status !== 0 || signal) {
      const error = new Error('COMMITTED_NODE_CLOSURE_FAILED');
      error.commandResult = {
        status,
        signal,
        stdoutDigest: sha256(stdout),
        stderrDigest: sha256(stderr),
      };
      throw error;
    }
    return {
      status,
      stdout,
      stderr,
      runtimeEvidence,
      runtimeDescriptor: runtimeDescriptorFromEvidence(runtimeEvidence),
      executable: runtimeEvidence.executable,
      closure: {
        schemaVersion: 1,
        sourceSetDigest: snapshot.evidence.sourceSetDigest,
        entryPath,
        recordCount: closure.materialized.length,
        records: closure.materialized.map(({
          absolutePath,
          identity: fileIdentity,
          ...record
        }) => ({ ...record, identity: fileIdentity })),
        loaderDigest: sha256(closureLoaderSource),
        environmentAllowlist: [...allowedEnvironmentNames].sort(utf8Compare),
      },
    };
  } catch (error) {
    if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    throw error;
  } finally {
    closePinned(pinnedExecutable);
    let rootStable = false;
    try {
      const rootStat = lstatSync(closure.root, { bigint: true });
      rootStable = rootStat.isDirectory()
        && !rootStat.isSymbolicLink()
        && rootStat.dev.toString() === closure.rootAnchor.device
        && rootStat.ino.toString() === closure.rootAnchor.inode;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (rootStable) {
      makePrivateDirectoryCleanupWritable(closure.root);
      for (const directory of closure.directories) {
        makePrivateDirectoryCleanupWritable(directory);
      }
      makePrivateDirectoryCleanupWritable(home);
      makePrivateDirectoryCleanupWritable(xdg);
    }
    rmSync(closure.root, { recursive: true, force: true });
  }
}

export async function runPinnedNodeScript(options = {}) {
  if (!options.snapshot || !options.closurePaths || !options.entryPath) {
    throw new Error('COMPLETE_COMMITTED_CLOSURE_REQUIRED');
  }
  return runCommittedNodeClosure(options);
}

function decodeProcMapsPath(value) {
  return value.replace(/\\([0-7]{3})/g, (_, octal) => String.fromCharCode(Number.parseInt(octal, 8)));
}

export function collectProcessRuntimeClosure({ pid = process.pid } = {}) {
  if (!Number.isInteger(pid) || pid <= 0) throw new Error('PID_INVALID');
  const executablePath = realpathSync(`/proc/${pid}/exe`);
  const mappedPaths = new Set();
  for (const line of readFileSync(`/proc/${pid}/maps`, 'utf8').split('\n')) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 6 || !fields[5].startsWith('/')) continue;
    const mapped = decodeProcMapsPath(fields.slice(5).join(' '));
    if (mapped.endsWith(' (deleted)')) throw new Error('MAPPED_NATIVE_OBJECT_DELETED');
    mappedPaths.add(realpathSync(mapped));
  }
  mappedPaths.add(executablePath);
  const mappedNativeObjects = [...mappedPaths].sort(utf8Compare).map((path) => {
    const pinned = openPinnedRegularFile(path, 'MAPPED_NATIVE_OBJECT');
    try {
      return {
        path,
        digest: pinned.digest,
        ...pinned.identity,
      };
    } finally {
      closePinned(pinned);
    }
  });
  const executable = mappedNativeObjects.find(({ path }) => path === executablePath);
  if (!executable) throw new Error('NODE_EXECUTABLE_NOT_IN_RUNTIME_CLOSURE');
  return {
    schemaVersion: 1,
    pid,
    executable,
    mappedNativeObjectCount: mappedNativeObjects.length,
    mappedNativeObjectSetDigest: sha256(canonicalJson(mappedNativeObjects)),
    mappedNativeObjects,
  };
}

export function collectNodeRuntimeClosure(options = {}) {
  return collectProcessRuntimeClosure(options);
}

export function runtimeDescriptorFromEvidence(evidence) {
  if (!evidence || evidence.schemaVersion !== 1 || !Number.isInteger(evidence.pid)) {
    throw new Error('RUNTIME_EVIDENCE_INVALID');
  }
  return Object.freeze({
    schemaVersion: 1,
    executable: evidence.executable,
    mappedNativeObjectCount: evidence.mappedNativeObjectCount,
    mappedNativeObjectSetDigest: evidence.mappedNativeObjectSetDigest,
    mappedNativeObjects: evidence.mappedNativeObjects,
  });
}

function validateRuntimeDescriptor(descriptor, code) {
  if (
    !descriptor
    || descriptor.schemaVersion !== 1
    || !descriptor.executable
    || !Array.isArray(descriptor.mappedNativeObjects)
    || descriptor.mappedNativeObjectCount !== descriptor.mappedNativeObjects.length
    || !SHA256.test(descriptor.mappedNativeObjectSetDigest)
    || !SHA256.test(descriptor.executable.digest)
  ) {
    throw new Error(`${code}_INVALID`);
  }
  const paths = descriptor.mappedNativeObjects.map(({ path }) => path);
  if (
    new Set(paths).size !== paths.length
    || [...paths].sort(utf8Compare).some((path, index) => path !== paths[index])
    || !descriptor.mappedNativeObjects.some(({ path }) => path === descriptor.executable.path)
  ) {
    throw new Error(`${code}_OBJECT_SET_INVALID`);
  }
  const executableRecord = descriptor.mappedNativeObjects
    .find(({ path }) => path === descriptor.executable.path);
  if (canonicalJson(executableRecord) !== canonicalJson(descriptor.executable)) {
    throw new Error(`${code}_EXECUTABLE_RECORD_MISMATCH`);
  }
  if (sha256(canonicalJson(descriptor.mappedNativeObjects)) !== descriptor.mappedNativeObjectSetDigest) {
    throw new Error(`${code}_SET_DIGEST_MISMATCH`);
  }
  return descriptor;
}

function verifyExpectedRuntimeBeforeExecution(descriptor, executable, code) {
  validateRuntimeDescriptor(descriptor, code);
  const requestedExecutablePath = resolve(executable);
  assertNoSymlinkComponents(requestedExecutablePath, `${code}_EXECUTABLE`);
  const executablePath = realpathSync(requestedExecutablePath);
  if (requestedExecutablePath !== executablePath) throw new Error(`${code}_EXECUTABLE_NOT_EXACT`);
  if (descriptor.executable.path !== executablePath) throw new Error(`${code}_EXECUTABLE_PATH_MISMATCH`);
  for (const expected of descriptor.mappedNativeObjects) {
    const pinned = openPinnedRegularFile(expected.path, `${code}_EXPECTED_OBJECT`);
    try {
      const observed = {
        path: expected.path,
        digest: pinned.digest,
        ...pinned.identity,
      };
      if (canonicalJson(observed) !== canonicalJson(expected)) {
        throw new Error(`${code}_EXPECTED_OBJECT_CHANGED`);
      }
    } finally {
      closePinned(pinned);
    }
  }
  return descriptor;
}

function assertRuntimeMatchesExpected(evidence, expected, code) {
  const observed = runtimeDescriptorFromEvidence(evidence);
  if (canonicalJson(observed) !== canonicalJson(expected)) {
    throw new Error(`${code}_CHILD_RUNTIME_MISMATCH`);
  }
  return evidence;
}

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function waitForExpectedChildRuntime(pid, expected, code) {
  let lastError;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const evidence = collectProcessRuntimeClosure({ pid });
      return assertRuntimeMatchesExpected(evidence, expected, code);
    } catch (error) {
      lastError = error;
      if (error.code === 'ENOENT') break;
      await delay(5);
    }
  }
  const error = new Error(`${code}_CHILD_RUNTIME_NOT_ESTABLISHED`);
  error.cause = lastError;
  throw error;
}
