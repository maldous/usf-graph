import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import {
  isAbsolute,
  join,
  resolve,
} from 'node:path';

const GIT_OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const unsafeEnvironmentNames = /^(?:BASH_ENV|ENV|GIT_|LD_|NODE_|DYLD_|PYTHON)/;
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));

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

function exactDirectory(path, code) {
  const absolute = resolve(path);
  const canonicalPath = realpathSync(absolute);
  if (lstatSync(absolute).isSymbolicLink() || !statSync(canonicalPath).isDirectory()) {
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
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const beforeStat = fstatSync(fd, { bigint: true });
    if (!beforeStat.isFile()) throw new Error(`${code}_NOT_REGULAR`);
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

function pathnameIdentity(path) {
  try {
    const stat = lstatSync(path, { bigint: true });
    if (stat.isSymbolicLink() || !stat.isFile()) return null;
    return identity(stat);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

export function buildSanitizedExecutionEnvironment({
  homeDirectory,
  explicitEnvironment = {},
  includeGitControls = false,
} = {}) {
  if (!homeDirectory) throw new Error('HOME_DIRECTORY_REQUIRED');
  const home = exactDirectory(homeDirectory, 'HOME_NOT_EXACT_DIRECTORY');
  for (const name of Object.keys(explicitEnvironment)) {
    if (unsafeEnvironmentNames.test(name)) throw new Error(`UNSAFE_ENVIRONMENT_NAME_${name}`);
  }
  const environment = {
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    LANG: 'C',
    LC_ALL: 'C',
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
    const match = /^gitdir: ([^\0\r\n]+)\n?$/.exec(readFileSync(dotGit, 'utf8'));
    if (!match) throw new Error('GITDIR_POINTER_INVALID');
    gitDirectory = realpathSync(resolve(worktree, match[1]));
  } else {
    throw new Error('GITDIR_NOT_EXACT');
  }
  if (!statSync(gitDirectory).isDirectory()) throw new Error('GITDIR_NOT_DIRECTORY');
  const commonDirectoryFile = join(gitDirectory, 'commondir');
  let commonDirectory = gitDirectory;
  if (existsSync(commonDirectoryFile)) {
    const commondir = readFileSync(commonDirectoryFile, 'utf8').trim();
    if (!commondir || commondir.includes('\0')) throw new Error('COMMONDIR_POINTER_INVALID');
    commonDirectory = realpathSync(resolve(gitDirectory, commondir));
  }
  const objectStorePath = join(commonDirectory, 'objects');
  if (lstatSync(objectStorePath).isSymbolicLink()) throw new Error('OBJECT_STORE_SYMLINK_REFUSED');
  const objectStore = exactDirectory(objectStorePath, 'OBJECT_STORE_NOT_EXACT_DIRECTORY');
  const alternates = join(objectStore, 'info', 'alternates');
  if (existsSync(alternates) && readFileSync(alternates, 'utf8').trim()) {
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

function runPinnedExecutable({
  executable,
  arguments: args,
  cwd,
  environment,
  inputFd = null,
  timeout = 120_000,
  code,
}) {
  const executablePath = realpathSync(executable);
  const pinnedExecutable = openPinnedRegularFile(executablePath, `${code}_EXECUTABLE`);
  try {
    const result = spawnSync(`/proc/self/fd/${pinnedExecutable.fd}`, args, {
      cwd,
      env: environment,
      encoding: null,
      maxBuffer: 64 * 1024 * 1024,
      timeout,
      stdio: [
        inputFd === null ? 'ignore' : inputFd,
        'pipe',
        'pipe',
      ],
    });
    const executableAfter = fstatSync(pinnedExecutable.fd, { bigint: true });
    if (!identitiesEqual(pinnedExecutable.identity, identity(executableAfter))) {
      throw new Error(`${code}_EXECUTABLE_CHANGED`);
    }
    if (result.error || result.signal || result.status !== 0) {
      const error = new Error(`${code}_FAILED`);
      error.commandResult = {
        status: Number.isInteger(result.status) ? result.status : null,
        signal: result.signal || null,
        stdoutDigest: sha256(result.stdout || Buffer.alloc(0)),
        stderrDigest: sha256(result.stderr || Buffer.alloc(0)),
      };
      throw error;
    }
    return {
      stdout: Buffer.from(result.stdout || ''),
      stderr: Buffer.from(result.stderr || ''),
      status: result.status,
      executable: {
        path: executablePath,
        digest: pinnedExecutable.digest,
        ...pinnedExecutable.identity,
      },
    };
  } finally {
    closePinned(pinnedExecutable);
  }
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

function runIsolatedGit(context, args, code) {
  return runPinnedExecutable({
    executable: context.gitExecutable,
    arguments: [
      '--no-replace-objects',
      `--git-dir=${context.isolatedGitDirectory}`,
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      '-c', 'core.attributesFile=/dev/null',
      ...args,
    ],
    environment: context.environment,
    timeout: 120_000,
    code,
  });
}

function readVerifiedGitObject(context, type, objectId) {
  validateObjectId(objectId, 'GIT_OBJECT_ID_INVALID');
  const result = runIsolatedGit(context, ['cat-file', type, objectId], 'GIT_CAT_FILE');
  const observed = gitObjectDigest(type, result.stdout, objectId.length);
  if (observed !== objectId) throw new Error('GIT_OBJECT_CONTENT_DIGEST_MISMATCH');
  return result.stdout;
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

function walkTree(context, treeId, prefix, records) {
  const tree = readVerifiedGitObject(context, 'tree', treeId);
  for (const entry of parseTreeEntries(tree, treeId.length)) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.mode === '40000' || entry.mode === '040000') {
      walkTree(context, entry.objectId, path, records);
    } else {
      const type = entry.mode === '160000' ? 'commit' : 'blob';
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

export function readTrackedTreeSnapshot({
  repository,
  commit,
  paths,
  gitExecutable = '/usr/bin/git',
}) {
  validateObjectId(commit, 'COMMIT_ID_INVALID');
  if (!Array.isArray(paths) || paths.length === 0) throw new Error('TRACKED_PATHS_REQUIRED');
  const requestedPaths = [...new Set(paths.map(validateTrackedPath))].sort(utf8Compare);
  if (requestedPaths.length !== paths.length) throw new Error('TRACKED_PATHS_NOT_UNIQUE');
  const source = resolveRepositoryObjectStore(repository);
  const isolated = createIsolatedObjectRepository(source.objectStore);
  const temporaryHome = mkdtempSync(join(tmpdir(), 'usf-hermetic-git-home-'));
  const context = {
    gitExecutable,
    isolatedGitDirectory: isolated.gitDirectory,
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
    const commitBytes = readVerifiedGitObject(context, 'commit', commit);
    const treeId = parseCommitTree(commitBytes, commit.length);
    const treeRecords = new Map();
    walkTree(context, treeId, '', treeRecords);
    const records = requestedPaths.map((path) => {
      const entry = treeRecords.get(path);
      if (!entry) throw new Error(`TRACKED_PATH_ABSENT_${path}`);
      if (entry.type !== 'blob' || !/^(?:100644|100755)$/.test(entry.mode)) {
        throw new Error(`TRACKED_PATH_NOT_REGULAR_BLOB_${path}`);
      }
      const bytes = readVerifiedGitObject(context, 'blob', entry.objectId);
      return {
        ...entry,
        bytes,
        byteLength: bytes.length,
        digest: sha256(bytes),
      };
    });
    const objectStoreAfter = identity(statSync(source.objectStore, { bigint: true }));
    if (!identitiesEqual(objectStoreBefore, objectStoreAfter)) {
      throw new Error('OBJECT_STORE_CHANGED_DURING_READ');
    }
    const recordEvidence = records.map(({ bytes, ...record }) => record);
    return {
      schemaVersion: 1,
      commit,
      tree: treeId,
      records,
      evidence: {
        commit,
        tree: treeId,
        sourceSetDigest: sha256(canonicalJson(recordEvidence)),
        recordCount: recordEvidence.length,
        records: recordEvidence,
        repositoryObjectStore: {
          path: source.objectStore,
          ...objectStoreAfter,
        },
        gitExecution: {
          configurationSource: 'ISOLATED_GIT_DIR_WITH_SOURCE_OBJECT_ALTERNATE',
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

export function runPinnedNodeScript({
  scriptPath,
  expectedDigest,
  expectedByteLength = null,
  nodeExecutable = process.execPath,
  arguments: args = [],
  cwd,
  explicitEnvironment = {},
  timeout = 120_000,
  afterPin,
  requireStablePath = true,
}) {
  if (!SHA256.test(expectedDigest)) throw new Error('EXPECTED_SCRIPT_DIGEST_INVALID');
  const absoluteScript = resolve(scriptPath);
  const pathIdentityBefore = pathnameIdentity(absoluteScript);
  const temporaryHome = mkdtempSync(join(tmpdir(), 'usf-hermetic-node-home-'));
  let sourceScript;
  let pinnedScript;
  try {
    sourceScript = openPinnedRegularFile(absoluteScript, 'NODE_SCRIPT_SOURCE');
    if (sourceScript.digest !== expectedDigest) throw new Error('NODE_SCRIPT_COMMIT_DIGEST_MISMATCH');
    if (expectedByteLength !== null && sourceScript.bytes.length !== expectedByteLength) {
      throw new Error('NODE_SCRIPT_COMMIT_LENGTH_MISMATCH');
    }
    const snapshotPath = join(temporaryHome, 'committed-script.snapshot');
    writeFileSync(snapshotPath, sourceScript.bytes, { flag: 'wx', mode: 0o400 });
    pinnedScript = openPinnedRegularFile(snapshotPath, 'NODE_SCRIPT_SNAPSHOT');
    unlinkSync(snapshotPath);
    pinnedScript.identity = identity(fstatSync(pinnedScript.fd, { bigint: true }));
    closePinned(sourceScript);
    sourceScript = null;
    if (typeof afterPin === 'function') {
      afterPin(Object.freeze({
        digest: pinnedScript.digest,
        byteLength: pinnedScript.bytes.length,
        identity: pinnedScript.identity,
      }));
    }
    const result = runPinnedExecutable({
      executable: nodeExecutable,
      arguments: ['--input-type=module', '-', ...args],
      cwd: cwd ? exactDirectory(cwd, 'NODE_CWD_NOT_EXACT_DIRECTORY') : undefined,
      environment: buildSanitizedExecutionEnvironment({
        homeDirectory: temporaryHome,
        explicitEnvironment,
      }),
      inputFd: pinnedScript.fd,
      timeout,
      code: 'PINNED_NODE',
    });
    const pinnedAfter = identity(fstatSync(pinnedScript.fd, { bigint: true }));
    if (!identitiesEqual(pinnedScript.identity, pinnedAfter)) throw new Error('PINNED_NODE_SCRIPT_CHANGED');
    const pathIdentityAfter = pathnameIdentity(absoluteScript);
    const pathStable = pathIdentityBefore !== null
      && pathIdentityAfter !== null
      && identitiesEqual(pathIdentityBefore, pathIdentityAfter);
    if (requireStablePath && !pathStable) throw new Error('PINNED_NODE_SCRIPT_PATH_CHANGED');
    return {
      ...result,
      script: {
        path: absoluteScript,
        digest: pinnedScript.digest,
        byteLength: pinnedScript.bytes.length,
        ...pinnedScript.identity,
        pathStable,
      },
    };
  } finally {
    closePinned(sourceScript);
    closePinned(pinnedScript);
    rmSync(temporaryHome, { recursive: true, force: true });
  }
}

function decodeProcMapsPath(value) {
  return value.replace(/\\([0-7]{3})/g, (_, octal) => String.fromCharCode(Number.parseInt(octal, 8)));
}

export function collectNodeRuntimeClosure({ pid = process.pid } = {}) {
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
