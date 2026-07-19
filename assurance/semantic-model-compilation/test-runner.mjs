import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const TEST_SUFFIX = '.test.mjs';
const REQUIRED_NODE_VERSION = '22.23.1';
const REQUIRED_NODE_EXECUTABLE_DIGEST = 'sha256:93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068';
const SHA256 = /^sha256:[0-9a-f]{64}$/;
export const TEST_REJECTION_CODES = Object.freeze([
  'DIRECTORY_TARGET_PROHIBITED',
  'DUPLICATE_AUTHORISED_ROOT',
  'DUPLICATE_TEST_TARGET',
  'EMPTY_AUTHORISED_ROOTS',
  'EMPTY_TEST_INVENTORY',
  'EXTENSION_NOT_ALLOWED',
  'HARD_LINK_PROHIBITED',
  'INVALID_INVOCATION_MODE',
  'INVALID_AUTHORISED_ROOT',
  'INVENTORY_DIGEST_CHANGED',
  'MODULE_RESOLUTION_PROHIBITED',
  'NODE_VERSION_MISMATCH',
  'NON_REGULAR_TARGET_PROHIBITED',
  'PATH_ESCAPE',
  'SYMLINK_PROHIBITED',
  'TARGET_NOT_FOUND',
  'UNAUTHORISED_TEST_ROOT',
]);

export class TestInventoryError extends Error {
  constructor(reasonCode, detail) {
    super(`${reasonCode}: ${detail}`);
    this.name = 'TestInventoryError';
    this.reasonCode = reasonCode;
  }
}

const reject = (reasonCode, detail) => { throw new TestInventoryError(reasonCode, detail); };

export const TEST_PROFILES = Object.freeze({
  all: Object.freeze([
    'assurance',
    'capabilities',
    'configuration',
    'processes',
    'provider-bindings',
  ]),
  'semantic-assurance': Object.freeze([
    'assurance/semantic-model-compilation',
    'capabilities/semantic-model-compilation',
    'configuration/semantic-assurance',
    'processes/semantic-assurance',
    'provider-bindings/stardog',
  ]),
});

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const rejectionCodeVocabularyDigest = sha256(canonicalJson(TEST_REJECTION_CODES));
const comparePaths = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const portable = (path) => path.replaceAll('\\', '/').replace(/^\.\//, '');

const observedStatIdentity = (stat) => ({
  device: stat.dev.toString(),
  inode: stat.ino.toString(),
  links: stat.nlink.toString(),
  modifiedNanoseconds: (stat.mtimeNs ?? BigInt(Math.trunc(stat.mtimeMs * 1_000_000))).toString(),
  changedNanoseconds: (stat.ctimeNs ?? BigInt(Math.trunc(stat.ctimeMs * 1_000_000))).toString(),
  size: stat.size.toString(),
});

function readBoundRegularFile(path, { allowSymbolicLink = false, expectedStat } = {}) {
  const link = lstatSync(path);
  if (link.isSymbolicLink() && !allowSymbolicLink) reject('SYMLINK_PROHIBITED', `runtime input is a symbolic link: ${path}`);
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (allowSymbolicLink ? 0 : constants.O_NOFOLLOW));
  } catch (error) {
    if (!allowSymbolicLink && error?.code === 'ELOOP') reject('SYMLINK_PROHIBITED', `runtime input became a symbolic link: ${path}`);
    throw error;
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile()) reject('NON_REGULAR_TARGET_PROHIBITED', `runtime input is not a regular file: ${path}`);
    if (before.nlink !== 1n && !allowSymbolicLink) reject('HARD_LINK_PROHIBITED', `runtime input is hard-linked: ${path}`);
    if (expectedStat && canonicalJson(observedStatIdentity(before)) !== canonicalJson(observedStatIdentity(expectedStat))) {
      reject('INVENTORY_DIGEST_CHANGED', `runtime input identity changed before its bytes were bound: ${path}`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (canonicalJson(observedStatIdentity(before)) !== canonicalJson(observedStatIdentity(after))) {
      reject('INVENTORY_DIGEST_CHANGED', `runtime input changed while being observed: ${path}`);
    }
    return Object.freeze({
      binding: Object.freeze({
        path,
        device: after.dev.toString(),
        inode: after.ino.toString(),
        size: after.size.toString(),
        digest: sha256(bytes),
      }),
      bytes,
    });
  } finally {
    closeSync(descriptor);
  }
}

function bindRegularFile(path, options = {}) {
  return readBoundRegularFile(path, options).binding;
}

function openBoundExecutionFile(path) {
  const link = lstatSync(path);
  if (link.isSymbolicLink()) reject('SYMLINK_PROHIBITED', `execution image is a symbolic link: ${path}`);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile()) reject('NON_REGULAR_TARGET_PROHIBITED', `execution image is not a regular file: ${path}`);
    const bytes = readFileSync(`/proc/self/fd/${descriptor}`);
    const after = fstatSync(descriptor, { bigint: true });
    if (canonicalJson(observedStatIdentity(before)) !== canonicalJson(observedStatIdentity(after))) {
      reject('INVENTORY_DIGEST_CHANGED', `execution image changed while its descriptor was bound: ${path}`);
    }
    return Object.freeze({
      descriptor,
      binding: Object.freeze({
        path,
        device: after.dev.toString(),
        inode: after.ino.toString(),
        size: after.size.toString(),
        digest: sha256(bytes),
      }),
    });
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function runtimeInventory(nodeExecutable, nativeRuntimePaths, nodeVersion) {
  const unique = [...new Set(nativeRuntimePaths)].sort(comparePaths);
  const absolute = unique.filter((path) => path.startsWith('/'));
  const virtualSharedObjects = unique.filter((path) => !path.startsWith('/'));
  const core = {
    nodeVersion,
    node: bindRegularFile(nodeExecutable),
    nativeFiles: absolute.map((path) => bindRegularFile(path, { allowSymbolicLink: true })),
    virtualSharedObjects,
  };
  return Object.freeze({ ...core, runtimeSetDigest: sha256(canonicalJson(core)) });
}

function contained(root, target) {
  const path = relative(root, target);
  return path !== '' && path !== '..' && !path.startsWith(`..${sep}`);
}

function normaliseRoots(repositoryRoot, authorisedRoots) {
  if (!Array.isArray(authorisedRoots) || authorisedRoots.length === 0) {
    reject('EMPTY_AUTHORISED_ROOTS', 'at least one authorised test root is required');
  }
  const root = realpathSync(repositoryRoot);
  const roots = authorisedRoots.map((path) => {
    if (typeof path !== 'string' || path.length === 0 || path.includes('*')) {
      reject('INVALID_AUTHORISED_ROOT', `invalid authorised test root: ${path}`);
    }
    const relativePath = portable(path);
    const target = resolve(root, relativePath);
    let stat;
    try {
      stat = lstatSync(target);
    } catch (error) {
      if (error?.code === 'ENOENT') reject('TARGET_NOT_FOUND', `authorised test root does not exist: ${path}`);
      throw error;
    }
    if (!contained(root, target)) reject('PATH_ESCAPE', `authorised test root escapes the repository: ${path}`);
    if (stat.isSymbolicLink()) reject('SYMLINK_PROHIBITED', `authorised test root is a symbolic link: ${path}`);
    if (!stat.isDirectory()) reject('INVALID_AUTHORISED_ROOT', `authorised test root is not a directory: ${path}`);
    return { path: relativePath, target };
  });
  const identities = roots.map(({ target }) => target);
  if (new Set(identities).size !== identities.length) reject('DUPLICATE_AUTHORISED_ROOT', 'duplicate authorised test discovery root');
  return { root, roots };
}

function classifyTargetStat(stat, path) {
  if (stat.isSymbolicLink()) reject('SYMLINK_PROHIBITED', `test target is a symbolic link: ${path}`);
  if (stat.isDirectory()) reject('DIRECTORY_TARGET_PROHIBITED', `test target is a directory: ${path}`);
  if (!stat.isFile()) reject('NON_REGULAR_TARGET_PROHIBITED', `test target is not a regular file: ${path}`);
  if (stat.nlink !== 1) reject('HARD_LINK_PROHIBITED', `test target is hard-linked: ${path}`);
  return true;
}

function validateTestTargets({ repositoryRoot, authorisedRoots, targets }) {
  const { root, roots } = normaliseRoots(repositoryRoot, authorisedRoots);
  if (!Array.isArray(targets) || targets.length === 0) reject('EMPTY_TEST_INVENTORY', 'test discovery produced an empty test set');
  const portableTargets = targets.map(portable);
  const canonicalTargets = new Set();
  const records = portableTargets.map((path) => {
    const target = resolve(root, path);
    let stat;
    try {
      stat = lstatSync(target);
    } catch (error) {
      if (error?.code === 'ENOENT') reject('TARGET_NOT_FOUND', `test target does not exist: ${path}`);
      throw error;
    }
    if (!contained(root, target)) reject('PATH_ESCAPE', `test target escapes the repository: ${path}`);
    if (stat.isSymbolicLink()) reject('SYMLINK_PROHIBITED', `test target is a symbolic link: ${path}`);
    const canonicalTarget = realpathSync(target);
    if (!contained(root, canonicalTarget)) reject('PATH_ESCAPE', `canonical test target escapes the repository: ${path}`);
    classifyTargetStat(stat, path);
    const canonicalPath = portable(relative(root, canonicalTarget));
    if (!canonicalPath.endsWith(TEST_SUFFIX)) reject('EXTENSION_NOT_ALLOWED', `test target extension is not allowed: ${path}`);
    if (!roots.some(({ target: authorised }) => contained(authorised, canonicalTarget))) {
      reject('UNAUTHORISED_TEST_ROOT', `test target is outside authorised test roots: ${path}`);
    }
    if (canonicalTargets.has(canonicalTarget)) reject('DUPLICATE_TEST_TARGET', `canonical test target appears more than once: ${path}`);
    canonicalTargets.add(canonicalTarget);
    return { path: canonicalPath, digest: sha256(readFileSync(canonicalTarget)) };
  }).sort(({ path: left }, { path: right }) => comparePaths(left, right));
  return Object.freeze({
    records: Object.freeze(records),
    discoveredFileCount: records.length,
    testInventoryDigest: sha256(canonicalJson(records)),
    authorisedRoots: Object.freeze(roots.map(({ path }) => path).sort(comparePaths)),
    authorisedRootSetDigest: sha256(canonicalJson(roots.map(({ path }) => path).sort(comparePaths))),
  });
}

export function discoverTestInventory({
  repositoryRoot,
  authorisedRoots,
  readDirectory = readdirSync,
}) {
  const { root, roots } = normaliseRoots(repositoryRoot, authorisedRoots);
  const targets = [];
  const visit = (directory) => {
    const entries = [...readDirectory(directory, { withFileTypes: true })]
      .sort(({ name: left }, { name: right }) => comparePaths(left, right));
    for (const entry of entries) {
      const target = resolve(directory, entry.name);
      if (entry.isSymbolicLink()) reject('SYMLINK_PROHIBITED', `test discovery cannot traverse a symbolic link: ${portable(relative(root, target))}`);
      if (entry.isDirectory()) {
        visit(target);
      } else if (entry.isFile() && entry.name.includes('.test.')) {
        if (!entry.name.endsWith(TEST_SUFFIX)) reject('EXTENSION_NOT_ALLOWED', `unsupported test target extension: ${portable(relative(root, target))}`);
        targets.push(portable(relative(root, target)));
      }
    }
  };
  roots.forEach(({ target }) => visit(target));
  const inventory = validateTestTargets({ repositoryRoot: root, authorisedRoots: roots.map(({ path }) => path), targets });
  return Object.freeze({
    ...inventory,
    discoveryAlgorithmDigest: sha256(readFileSync(fileURLToPath(import.meta.url))),
    rejectionCodeVocabularyDigest,
  });
}

function parseLauncherInventory(output, expected, snapshotRecords, expectedBootstrapRecords, expectedRuntime) {
  const prefix = '# usf-test-inventory ';
  const records = output.split('\n').filter((line) => line.startsWith(prefix));
  if (records.length !== 1) reject('INVENTORY_DIGEST_CHANGED', `launcher emitted ${records.length} inventory records`);
  let observed;
  try {
    observed = JSON.parse(records[0].slice(prefix.length));
  } catch {
    reject('INVENTORY_DIGEST_CHANGED', 'launcher inventory record is not valid JSON');
  }
  if (observed?.fileCount !== expected.discoveredFileCount
      || observed?.observedInventoryDigest !== expected.testInventoryDigest
      || observed?.isolation !== 'none') {
    reject('INVENTORY_DIGEST_CHANGED', 'launcher-observed test inventory differs from the validated staged inventory');
  }
  const modulePrefix = '# usf-module-inventory ';
  const moduleLines = output.split('\n').filter((line) => line.startsWith(modulePrefix));
  if (moduleLines.length !== 1) reject('INVENTORY_DIGEST_CHANGED', `launcher emitted ${moduleLines.length} module inventory records`);
  let modules;
  try {
    modules = JSON.parse(moduleLines[0].slice(modulePrefix.length));
  } catch {
    reject('INVENTORY_DIGEST_CHANGED', 'launcher module inventory record is not valid JSON');
  }
  const allowed = new Map(snapshotRecords.map(({ path, digest }) => [path, digest]));
  const resolvedModuleRecords = Array.isArray(modules?.resolvedModuleRecords) ? modules.resolvedModuleRecords : [];
  const loadedModuleRecords = Array.isArray(modules?.loadedModuleRecords) ? modules.loadedModuleRecords : [];
  const bootstrapRecords = Array.isArray(modules?.bootstrapRecords) ? modules.bootstrapRecords : [];
  const exactModuleRecord = (record) => record && typeof record === 'object' && !Array.isArray(record)
    && canonicalJson(Object.keys(record).sort()) === canonicalJson(['digest', 'path'])
    && typeof record.path === 'string' && record.path.length > 0 && !record.path.startsWith('/')
    && !record.path.includes('\\') && !record.path.split('/').some((part) => part === '' || part === '.' || part === '..')
    && SHA256.test(record.digest || '');
  if (canonicalJson(Object.keys(modules || {}).sort()) !== canonicalJson([
    'bootstrapCount', 'bootstrapRecords', 'bootstrapSetDigest',
    'loadedModuleCount', 'loadedModuleRecords', 'loadedModuleSetDigest',
    'resolvedModuleCount', 'resolvedModuleRecords', 'resolvedModuleSetDigest',
  ])
      || loadedModuleRecords.length === 0 || modules.loadedModuleCount !== loadedModuleRecords.length
      || modules.loadedModuleSetDigest !== sha256(canonicalJson(loadedModuleRecords))
      || resolvedModuleRecords.length === 0 || modules.resolvedModuleCount !== resolvedModuleRecords.length
      || modules.resolvedModuleSetDigest !== sha256(canonicalJson(resolvedModuleRecords))
      || modules.bootstrapCount !== bootstrapRecords.length
      || modules.bootstrapSetDigest !== sha256(canonicalJson(bootstrapRecords))
      || canonicalJson(bootstrapRecords) !== canonicalJson(expectedBootstrapRecords)
      || loadedModuleRecords.some((record, index) => !exactModuleRecord(record)
        || allowed.get(record.path) !== record.digest
        || index > 0 && comparePaths(loadedModuleRecords[index - 1].path, record.path) >= 0)
      || resolvedModuleRecords.some((record, index) => !exactModuleRecord(record)
        || allowed.get(record.path) !== record.digest
        || index > 0 && comparePaths(resolvedModuleRecords[index - 1].path, record.path) >= 0)) {
    reject('INVENTORY_DIGEST_CHANGED', 'launcher-observed module inventories are not ordered subsets of the immutable snapshot');
  }
  if ([...expected.records, ...expectedBootstrapRecords].some(({ path, digest }) =>
    !loadedModuleRecords.some((record) => record.path === path && record.digest === digest))
      || loadedModuleRecords.some(({ path, digest }) =>
        !resolvedModuleRecords.some((record) => record.path === path && record.digest === digest))) {
    reject('INVENTORY_DIGEST_CHANGED', 'launcher-observed loaded inventory omits execution bytes or is not contained by resolution');
  }
  const runtimePrefix = '# usf-runtime-inventory ';
  const runtimeLines = output.split('\n').filter((line) => line.startsWith(runtimePrefix));
  if (runtimeLines.length !== 1) reject('INVENTORY_DIGEST_CHANGED', `launcher emitted ${runtimeLines.length} runtime inventory records`);
  let runtime;
  try {
    runtime = JSON.parse(runtimeLines[0].slice(runtimePrefix.length));
  } catch {
    reject('INVENTORY_DIGEST_CHANGED', 'launcher runtime inventory record is not valid JSON');
  }
  const runtimeCore = runtime && typeof runtime === 'object' && !Array.isArray(runtime) ? {
    nodeVersion: runtime.nodeVersion,
    node: runtime.node,
    nativeFiles: runtime.nativeFiles,
    virtualSharedObjects: runtime.virtualSharedObjects,
  } : null;
  if (canonicalJson(Object.keys(runtime || {}).sort()) !== canonicalJson([
    'nativeFiles', 'node', 'nodeVersion', 'runtimeSetDigest', 'virtualSharedObjects',
  ])
      || runtime.runtimeSetDigest !== sha256(canonicalJson(runtimeCore))
      || canonicalJson(runtime) !== canonicalJson(expectedRuntime)) {
    reject('INVENTORY_DIGEST_CHANGED', 'child-observed runtime inventory differs from the pre-execution binding');
  }
  const resultPrefix = '# usf-test-result ';
  const resultLines = output.split('\n').filter((line) => line.startsWith(resultPrefix));
  if (resultLines.length !== 1) reject('INVENTORY_DIGEST_CHANGED', `launcher emitted ${resultLines.length} structured test results`);
  let testResult;
  try {
    testResult = JSON.parse(resultLines[0].slice(resultPrefix.length));
  } catch {
    reject('INVENTORY_DIGEST_CHANGED', 'launcher structured test result is not valid JSON');
  }
  const countNames = ['cancelled', 'failed', 'passed', 'skipped', 'suites', 'tests', 'todo', 'topLevel'];
  if (canonicalJson(Object.keys(testResult || {}).sort()) !== canonicalJson(['counts', 'success'])
      || typeof testResult.success !== 'boolean'
      || canonicalJson(Object.keys(testResult.counts || {}).sort()) !== canonicalJson(countNames)
      || countNames.some((name) => !Number.isSafeInteger(testResult.counts[name]) || testResult.counts[name] < 0)
      || testResult.counts.tests < 1
      || testResult.counts.passed + testResult.counts.failed + testResult.counts.cancelled
        + testResult.counts.skipped + testResult.counts.todo !== testResult.counts.tests
      || testResult.success !== (testResult.counts.failed === 0 && testResult.counts.cancelled === 0)) {
    reject('INVENTORY_DIGEST_CHANGED', 'launcher structured test result is not exact');
  }
  return Object.freeze({
    ...observed,
    bootstrapRecords: Object.freeze(bootstrapRecords),
    bootstrapSetDigest: modules.bootstrapSetDigest,
    loadedModuleRecords: Object.freeze(loadedModuleRecords),
    loadedModuleSetDigest: modules.loadedModuleSetDigest,
    resolvedModuleRecords: Object.freeze(resolvedModuleRecords),
    resolvedModuleSetDigest: modules.resolvedModuleSetDigest,
    runtime: Object.freeze(runtime),
    testResult: Object.freeze(testResult),
  });
}

function enumerateSnapshot(snapshotRoot) {
  const records = [];
  const identities = new Set();
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort(({ name: left }, { name: right }) => comparePaths(left, right))) {
      const target = resolve(directory, entry.name);
      const path = portable(relative(snapshotRoot, target));
      const stat = lstatSync(target);
      if (stat.isSymbolicLink()) reject('SYMLINK_PROHIBITED', `execution snapshot contains a symbolic link: ${path}`);
      if (stat.isDirectory()) visit(target);
      else if (stat.isFile()) {
        const identity = `${stat.dev}:${stat.ino}`;
        if (stat.nlink !== 1 || identities.has(identity)) reject('HARD_LINK_PROHIBITED', `execution snapshot contains a hard link or alias: ${path}`);
        identities.add(identity);
        records.push({ path, digest: sha256(readFileSync(target)) });
      } else reject('NON_REGULAR_TARGET_PROHIBITED', `execution snapshot contains a non-regular entry: ${path}`);
    }
  };
  visit(snapshotRoot);
  return records.sort(({ path: left }, { path: right }) => comparePaths(left, right));
}

function verifySnapshot(snapshot, phase) {
  const records = enumerateSnapshot(snapshot.snapshotRoot);
  if (canonicalJson(records) !== canonicalJson(snapshot.snapshotRecords)
      || sha256(canonicalJson(records)) !== snapshot.snapshotManifestDigest) {
    reject('INVENTORY_DIGEST_CHANGED', `immutable execution snapshot changed ${phase}`);
  }
  const permissionsValid = snapshot.snapshotRecords.every(({ path }) => (lstatSync(resolve(snapshot.snapshotRoot, path)).mode & 0o777) === 0o400)
    && snapshot.directories.every((path) => (lstatSync(path).mode & 0o777) === 0o500);
  if (!permissionsValid) reject('INVENTORY_DIGEST_CHANGED', `execution snapshot permissions changed ${phase}`);
  return Object.freeze({ records: Object.freeze(records), permissionsValid });
}

function inspectNodeIdentity(nodeExecutable, binding = bindRegularFile(nodeExecutable)) {
  if (!SHA256.test(binding?.digest || '')) reject('NODE_VERSION_MISMATCH', 'Node executable bytes were not bound before the version probe');
  const version = execFileSync(nodeExecutable, ['--version'], {
    encoding: 'utf8', env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC' },
  }).trim().replace(/^v/u, '');
  return Object.freeze({ version, digest: binding.digest, binding });
}

export function snapshotModuleRecord(url, snapshotRoot) {
  if (typeof url !== 'string' || !url.startsWith('file:')) reject('MODULE_RESOLUTION_PROHIBITED', `module URL is not a snapshot file: ${url}`);
  const root = realpathSync(snapshotRoot);
  const requested = resolve(fileURLToPath(url));
  if (!contained(root, requested)) reject('MODULE_RESOLUTION_PROHIBITED', `module escapes the immutable snapshot: ${url}`);
  const stat = lstatSync(requested);
  if (stat.isSymbolicLink()) reject('SYMLINK_PROHIBITED', `module is a symbolic link: ${url}`);
  const target = realpathSync(requested);
  if (!contained(root, target)) reject('MODULE_RESOLUTION_PROHIBITED', `resolved module escapes the immutable snapshot: ${url}`);
  classifyTargetStat(stat, requested);
  return Object.freeze({ path: portable(relative(root, target)), digest: sha256(readFileSync(target)) });
}

export function snapshotLoadedModuleRecord(url, snapshotRoot, source) {
  const record = snapshotModuleRecord(url, snapshotRoot);
  let bytes;
  if (typeof source === 'string') bytes = Buffer.from(source);
  else if (Buffer.isBuffer(source)) bytes = source;
  else if (source instanceof ArrayBuffer) bytes = Buffer.from(source);
  else if (ArrayBuffer.isView(source)) bytes = Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  else reject('INVENTORY_DIGEST_CHANGED', `loaded source bytes are unavailable for ${record.path}`);
  const observedDigest = sha256(bytes);
  if (observedDigest !== record.digest) reject('INVENTORY_DIGEST_CHANGED', `loaded module bytes differ from snapshot bytes for ${record.path}`);
  return Object.freeze({ path: record.path, digest: observedDigest });
}

function snapshotExecutionBytes({
  repositoryRoot,
  inventory,
  snapshotPaths,
  snapshotExclusions = [],
  readSource = readBoundRegularFile,
}) {
  const root = realpathSync(repositoryRoot);
  const paths = [...new Set(snapshotPaths.map(portable))].sort(comparePaths);
  const exclusions = [...new Set(snapshotExclusions.map(portable))].sort(comparePaths);
  const sourceRecords = [];
  const sourceIdentities = new Set();
  const visit = (path) => {
    if (exclusions.some((excluded) => path === excluded || path.startsWith(`${excluded}/`))) return;
    const target = resolve(root, path);
    let stat;
    try {
      stat = lstatSync(target, { bigint: true });
    } catch (error) {
      if (error?.code === 'ENOENT') reject('TARGET_NOT_FOUND', `execution snapshot input does not exist: ${path}`);
      throw error;
    }
    if (!contained(root, target)) reject('PATH_ESCAPE', `execution snapshot input escapes the repository: ${path}`);
    if (stat.isSymbolicLink()) reject('SYMLINK_PROHIBITED', `execution snapshot input is a symbolic link: ${path}`);
    if (stat.isDirectory()) {
      for (const entry of readdirSync(target, { withFileTypes: true }).sort(({ name: left }, { name: right }) => comparePaths(left, right))) {
        visit(portable(join(path, entry.name)));
      }
    } else if (stat.isFile()) {
      const identity = `${stat.dev}:${stat.ino}`;
      if (stat.nlink !== 1n || sourceIdentities.has(identity)) reject('HARD_LINK_PROHIBITED', `execution snapshot input is hard-linked or aliased: ${path}`);
      sourceIdentities.add(identity);
      const observed = readSource(target, { expectedStat: stat });
      if (!observed?.binding || !Buffer.isBuffer(observed.bytes)
          || observed.binding.path !== target || observed.binding.digest !== sha256(observed.bytes)
          || observed.binding.device !== stat.dev.toString() || observed.binding.inode !== stat.ino.toString()
          || observed.binding.size !== stat.size.toString()) {
        reject('INVENTORY_DIGEST_CHANGED', `execution snapshot input was not read from its classified file identity: ${path}`);
      }
      sourceRecords.push({ path, digest: observed.binding.digest, bytes: observed.bytes });
    } else {
      reject('NON_REGULAR_TARGET_PROHIBITED', `execution snapshot input is not regular: ${path}`);
    }
  };
  paths.forEach(visit);
  const duplicate = sourceRecords.find(({ path }, index) => sourceRecords.findIndex((record) => record.path === path) !== index);
  if (duplicate) reject('DUPLICATE_TEST_TARGET', `execution snapshot contains a duplicate canonical path: ${duplicate.path}`);
  const container = mkdtempSync(join(tmpdir(), `usf-test-snapshot-${inventory.testInventoryDigest.slice(7, 23)}-`));
  try {
    const snapshotRoot = join(container, 'repository');
    mkdirSync(snapshotRoot, { mode: 0o700 });
    const snapshotRecords = sourceRecords.map(({ path, digest, bytes }) => {
      const target = resolve(snapshotRoot, path);
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      writeFileSync(target, bytes, { flag: 'wx', mode: 0o400 });
      const observed = sha256(readFileSync(target));
      if (observed !== digest) reject('INVENTORY_DIGEST_CHANGED', `execution snapshot copy changed: ${path}`);
      return { path, digest };
    }).sort(({ path: left }, { path: right }) => comparePaths(left, right));
    const directories = [];
    const collectDirectories = (directory) => {
      directories.push(directory);
      for (const entry of readdirSync(directory, { withFileTypes: true })) if (entry.isDirectory()) collectDirectories(join(directory, entry.name));
    };
    collectDirectories(snapshotRoot);
    directories.sort((left, right) => right.length - left.length).forEach((directory) => chmodSync(directory, 0o500));
    const snapshotManifestDigest = sha256(canonicalJson(snapshotRecords));
    const permissionRecords = [
      ...snapshotRecords.map(({ path }) => ({ path, mode: lstatSync(resolve(snapshotRoot, path)).mode & 0o777 })),
      ...directories.map((path) => ({ path: `${portable(relative(snapshotRoot, path)) || '.'}/`, mode: lstatSync(path).mode & 0o777 })),
    ].sort(({ path: left }, { path: right }) => comparePaths(left, right));
    if (permissionRecords.some(({ path, mode }) => path.endsWith('/') ? mode !== 0o500 : mode !== 0o400)) {
      reject('INVENTORY_DIGEST_CHANGED', 'execution snapshot permissions are not read-only');
    }
    const permissionsDigest = sha256(canonicalJson(permissionRecords));
    const snapshotRootDigest = sha256(canonicalJson({
      snapshotManifestDigest,
      permissionsDigest,
      exclusions,
    }));
    const executedTests = inventory.records.map(({ path }) => ({ path, digest: sha256(readFileSync(resolve(snapshotRoot, path))) }));
    const executedTestInventoryDigest = sha256(canonicalJson(executedTests));
    if (executedTestInventoryDigest !== inventory.testInventoryDigest) {
      reject('INVENTORY_DIGEST_CHANGED', 'staged test bytes differ from the discovered inventory');
    }
    const snapshot = {
      container,
      snapshotRoot,
      snapshotManifestDigest,
      snapshotRootDigest,
      snapshotRecords,
      permissionsDigest,
      executedTestInventoryDigest,
      directories,
      exclusions,
    };
    verifySnapshot(snapshot, 'after staging');
    return snapshot;
  } catch (error) {
    rmSync(container, { recursive: true, force: true });
    throw error;
  }
}

function removeSnapshot(snapshot) {
  if (!snapshot) return;
  snapshot.directories.forEach((directory) => chmodSync(directory, 0o700));
  rmSync(snapshot.container, { recursive: true, force: true });
}

export function executeTestInventory(inventory, {
  repositoryRoot,
  execute = execFileSync,
  nodeExecutable = process.execPath,
  expectedNodeExecutableDigest = REQUIRED_NODE_EXECUTABLE_DIGEST,
  nodeIdentityVerifier = inspectNodeIdentity,
  networkIsolator = '/usr/bin/unshare',
  nativeRuntimePaths = process.report.getReport().sharedObjects,
  snapshotPaths,
  snapshotExclusions,
  sourceReader = readBoundRegularFile,
  beforeExecute,
  launcherRelativePath = 'assurance/semantic-model-compilation/test-launcher.mjs',
  bootstrapRelativePaths = [launcherRelativePath, 'assurance/semantic-model-compilation/test-runner.mjs'],
  testInvocationMode = 'NODE_TEST_PROGRAMMATIC_EXACT_FILES',
} = {}) {
  if (!inventory || inventory.discoveredFileCount < 1 || inventory.records?.length !== inventory.discoveredFileCount
      || !SHA256.test(inventory.testInventoryDigest || '')
      || !Array.isArray(inventory.authorisedRoots) || inventory.authorisedRoots.length < 1
      || inventory.authorisedRootSetDigest !== sha256(canonicalJson(inventory.authorisedRoots))) {
    reject('EMPTY_TEST_INVENTORY', 'test runner requires a non-empty digest-bound inventory');
  }
  const root = realpathSync(repositoryRoot);
  const rebound = validateTestTargets({
    repositoryRoot: root,
    authorisedRoots: inventory.authorisedRoots,
    targets: inventory.records.map(({ path }) => path),
  });
  if (rebound.testInventoryDigest !== inventory.testInventoryDigest
      || rebound.authorisedRootSetDigest !== inventory.authorisedRootSetDigest
      || rebound.discoveredFileCount !== inventory.discoveredFileCount) {
    reject('INVENTORY_DIGEST_CHANGED', 'test inventory changed after validation and before execution');
  }
  const executionPaths = [...new Set([
    ...(snapshotPaths || rebound.records.map(({ path }) => path.split('/')[0])),
    'package-lock.json',
    'package.json',
  ])].sort(comparePaths);
  const invocationModes = {
    NODE_TEST_CLI_DEFAULT_ISOLATION: ['--frozen-intrinsics', '--permission', '--allow-fs-read=<SNAPSHOT_ROOT>', '--allow-fs-read=<RUNTIME_ROOT>', '--allow-fs-write=<RUNTIME_ROOT>', '--no-addons', '--test'],
    NODE_TEST_CLI_CHILD_PERMITTED: ['--frozen-intrinsics', '--permission', '--allow-fs-read=<SNAPSHOT_ROOT>', '--allow-fs-read=<RUNTIME_ROOT>', '--allow-fs-write=<RUNTIME_ROOT>', '--allow-child-process', '--no-addons', '--test'],
    NODE_TEST_PROGRAMMATIC_EXACT_FILES: ['--frozen-intrinsics', '--permission', '--allow-fs-read=<SNAPSHOT_ROOT>', '--allow-fs-read=<RUNTIME_ROOT>', '--allow-fs-write=<RUNTIME_ROOT>', '--no-addons', '<REPOSITORY_LOCAL_TEST_LAUNCHER>'],
  };
  const canonicalFlags = invocationModes[testInvocationMode];
  if (!canonicalFlags) reject('INVALID_INVOCATION_MODE', `unsupported test invocation mode: ${testInvocationMode}`);
  let snapshot;
  let runtimeRoot;
  let canonicalEnvironment;
  let launcherPath;
  let launcherDigest;
  let expectedBootstrapRecords;
  try {
    snapshot = snapshotExecutionBytes({
      repositoryRoot: root,
      inventory,
      snapshotPaths: executionPaths,
      snapshotExclusions,
      readSource: sourceReader,
    });
    runtimeRoot = mkdtempSync(join(tmpdir(), 'usf-test-runtime-'));
    canonicalEnvironment = {
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      TEMP: '<RUNTIME_ROOT>',
      TMP: '<RUNTIME_ROOT>',
      TMPDIR: '<RUNTIME_ROOT>',
      TZ: 'UTC',
      USF_HERMETIC_TEST_MODE: '1',
      USF_TEST_INVENTORY_DIGEST: inventory.testInventoryDigest,
    };
    launcherPath = resolve(snapshot.snapshotRoot, portable(launcherRelativePath));
    launcherDigest = sha256(readFileSync(launcherPath));
    const snapshotRecordByPath = new Map(snapshot.snapshotRecords.map((record) => [record.path, record]));
    expectedBootstrapRecords = [...new Set(bootstrapRelativePaths.map(portable))].sort(comparePaths).map((path) =>
      snapshotRecordByPath.get(path) || reject('INVENTORY_DIGEST_CHANGED', `immutable execution snapshot omits bootstrap module ${path}`));
  } catch (error) {
    removeSnapshot(snapshot);
    if (runtimeRoot) rmSync(runtimeRoot, { recursive: true, force: true });
    throw error;
  }
  let output;
  let executionError;
  let runtimeVerificationError;
  let verificationError;
  let postExecutionSnapshot;
  let preRuntime;
  let postRuntime;
  let preNetworkIsolator;
  let postNetworkIsolator;
  let nodeVersion;
  let evidenceNodeFlags;
  try {
    if (typeof beforeExecute === 'function') beforeExecute(Object.freeze({ snapshotRoot: snapshot.snapshotRoot, runtimeRoot }));
    verifySnapshot(snapshot, 'before Node started');
    const preNodeBinding = bindRegularFile(nodeExecutable);
    if (preNodeBinding.digest !== expectedNodeExecutableDigest || !SHA256.test(preNodeBinding.digest)) {
      reject('NODE_VERSION_MISMATCH', `test runner requires the accepted Node ${REQUIRED_NODE_VERSION} executable bytes`);
    }
    const nodeIdentity = nodeIdentityVerifier(nodeExecutable, preNodeBinding);
    if (nodeIdentity?.version !== REQUIRED_NODE_VERSION || nodeIdentity?.digest !== preNodeBinding.digest) {
      reject('NODE_VERSION_MISMATCH', `test runner requires the accepted Node ${REQUIRED_NODE_VERSION} executable bytes`);
    }
    nodeVersion = nodeIdentity.version;
    preRuntime = runtimeInventory(nodeExecutable, nativeRuntimePaths, nodeVersion);
    if (preRuntime.node.digest !== expectedNodeExecutableDigest) reject('NODE_VERSION_MISMATCH', 'Node runtime binding changed before execution');
    preNetworkIsolator = bindRegularFile(networkIsolator);
    const exactPaths = rebound.records.map(({ path }) => resolve(snapshot.snapshotRoot, path));
    const permissionArgs = [
      '--permission',
      `--allow-fs-read=${snapshot.snapshotRoot}`,
      `--allow-fs-read=${runtimeRoot}`,
      `--allow-fs-write=${runtimeRoot}`,
      '--allow-fs-read=/var/lib/usf-cas',
      `--allow-fs-read=${nodeExecutable}`,
      ...preRuntime.nativeFiles.map(({ path }) => `--allow-fs-read=${path}`),
    ];
    const nodeArgs = testInvocationMode === 'NODE_TEST_PROGRAMMATIC_EXACT_FILES'
      ? ['--frozen-intrinsics', ...permissionArgs, '--no-addons', launcherPath, ...exactPaths]
      : [
          '--frozen-intrinsics',
          ...permissionArgs,
          ...(testInvocationMode === 'NODE_TEST_CLI_CHILD_PERMITTED' ? ['--allow-child-process'] : []),
          '--no-addons',
          '--test',
          ...exactPaths,
        ];
    const relativeTestByAbsolute = new Map(exactPaths.map((path, index) => [path, rebound.records[index].path]));
    evidenceNodeFlags = nodeArgs.map((argument) => {
      if (argument === snapshot.snapshotRoot) return '<SNAPSHOT_ROOT>';
      if (argument === runtimeRoot) return '<RUNTIME_ROOT>';
      if (argument === launcherPath) return '<REPOSITORY_LOCAL_TEST_LAUNCHER>';
      if (relativeTestByAbsolute.has(argument)) return relativeTestByAbsolute.get(argument);
      return argument
        .replace(snapshot.snapshotRoot, '<SNAPSHOT_ROOT>')
        .replace(runtimeRoot, '<RUNTIME_ROOT>')
        .replace(nodeExecutable, '<NODE_EXECUTABLE>');
    });
    output = execute(networkIsolator, ['--net', '--', nodeExecutable, ...nodeArgs], {
      cwd: snapshot.snapshotRoot,
      encoding: 'utf8',
      env: {
        TZ: 'UTC',
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        TMPDIR: runtimeRoot,
        TMP: runtimeRoot,
        TEMP: runtimeRoot,
        USF_HERMETIC_TEST_MODE: '1',
        USF_TEST_INVENTORY_DIGEST: inventory.testInventoryDigest,
      },
    });
  } catch (error) {
    executionError = error;
  } finally {
    if (preRuntime) try {
      postRuntime = runtimeInventory(nodeExecutable, nativeRuntimePaths, nodeVersion);
      postNetworkIsolator = bindRegularFile(networkIsolator);
      if (canonicalJson(postRuntime) !== canonicalJson(preRuntime)
          || canonicalJson(postNetworkIsolator) !== canonicalJson(preNetworkIsolator)) {
        reject('INVENTORY_DIGEST_CHANGED', 'runtime or network-isolator bytes changed during execution');
      }
    } catch (error) {
      runtimeVerificationError = error;
    }
    try { postExecutionSnapshot = verifySnapshot(snapshot, 'during Node execution'); } catch (error) { verificationError = error; }
    removeSnapshot(snapshot);
    rmSync(runtimeRoot, { recursive: true, force: true });
  }
  if (runtimeVerificationError) throw runtimeVerificationError;
  if (verificationError) throw verificationError;
  if (executionError) throw executionError;
  const launcherObserved = parseLauncherInventory(output, inventory, snapshot.snapshotRecords, expectedBootstrapRecords, preRuntime);
  const deterministicResult = launcherObserved.testResult;
  const count = deterministicResult.counts.tests;
  return Object.freeze({
    passed: deterministicResult.success === true && count > 0
      && deterministicResult.counts.passed === count && deterministicResult.counts.failed === 0
      && deterministicResult.counts.cancelled === 0 && deterministicResult.counts.skipped === 0
      && deterministicResult.counts.todo === 0,
    count,
    outputDigest: sha256(canonicalJson(deterministicResult)),
    testSummary: deterministicResult,
    discoveredFileCount: inventory.discoveredFileCount,
    testInventoryDigest: inventory.testInventoryDigest,
    authorisedRoots: inventory.authorisedRoots,
    authorisedRootSetDigest: inventory.authorisedRootSetDigest,
    preExecutionReboundDigest: rebound.testInventoryDigest,
    stagedTestInventoryDigest: snapshot.executedTestInventoryDigest,
    executedTestInventoryDigest: launcherObserved.observedInventoryDigest,
    executedByteSetDigest: launcherObserved.loadedModuleSetDigest,
    launcherObservedTestInventoryDigest: launcherObserved.observedInventoryDigest,
    launcherObservedTestFileCount: launcherObserved.fileCount,
    loadedModuleSetDigest: launcherObserved.loadedModuleSetDigest,
    loadedModuleCount: launcherObserved.loadedModuleRecords.length,
    loadedModuleRecords: launcherObserved.loadedModuleRecords,
    resolvedModuleSetDigest: launcherObserved.resolvedModuleSetDigest,
    resolvedModuleCount: launcherObserved.resolvedModuleRecords.length,
    resolvedModuleRecords: launcherObserved.resolvedModuleRecords,
    authorisedExecutionByteSetDigest: snapshot.snapshotManifestDigest,
    snapshotManifestDigest: snapshot.snapshotManifestDigest,
    snapshotRootDigest: snapshot.snapshotRootDigest,
    snapshotPermissionsDigest: snapshot.permissionsDigest,
    snapshotFileCount: snapshot.snapshotRecords.length,
    stagedFileDigests: snapshot.snapshotRecords,
    snapshotPolicy: 'EPHEMERAL_DELETE_AFTER_EXECUTION',
    snapshotExclusions: snapshot.exclusions,
    snapshotReadOnlyVerified: postExecutionSnapshot?.permissionsValid === true,
    discoveryAlgorithmDigest: inventory.discoveryAlgorithmDigest,
    rejectionCodeVocabularyDigest: inventory.rejectionCodeVocabularyDigest,
    dependencyLockDigest: snapshot.snapshotRecords.find(({ path }) => path === 'package-lock.json')?.digest
      || reject('INVENTORY_DIGEST_CHANGED', 'immutable execution snapshot omits package-lock.json'),
    dependencyByteSetDigest: sha256(canonicalJson(snapshot.snapshotRecords.filter(({ path }) => path.startsWith('node_modules/')))),
    launcherDigest,
    bootstrapModuleRecords: launcherObserved.bootstrapRecords,
    bootstrapModuleSetDigest: launcherObserved.bootstrapSetDigest,
    nativeRuntimeBindings: preRuntime.nativeFiles,
    nativeRuntimeDigests: preRuntime.nativeFiles.map(({ path, digest }) => ({ path, digest })),
    nativeRuntimeSetDigest: sha256(canonicalJson(preRuntime.nativeFiles.map(({ path, digest }) => ({ path, digest })))),
    nativeRuntimePreBindingDigest: preRuntime.runtimeSetDigest,
    nativeRuntimeChildBindingDigest: launcherObserved.runtime.runtimeSetDigest,
    nativeRuntimePostBindingDigest: postRuntime.runtimeSetDigest,
    virtualSharedObjects: preRuntime.virtualSharedObjects,
    networkIsolation: 'LINUX_NETWORK_NAMESPACE',
    networkIsolatorBinding: preNetworkIsolator,
    networkIsolatorPostBinding: postNetworkIsolator,
    networkIsolatorDigest: preNetworkIsolator.digest,
    nodeExecutableBinding: preRuntime.node,
    nodeExecutableDigest: preRuntime.node.digest,
    nodeVersion,
    invocationMode: testInvocationMode,
    isolationMode: testInvocationMode === 'NODE_TEST_PROGRAMMATIC_EXACT_FILES' ? 'none' : 'process',
    expectedDenialCodes: Object.freeze({
      childProcess: 'ERR_ACCESS_DENIED',
      filesystemRead: 'ERR_ACCESS_DENIED',
      filesystemWrite: 'ERR_ACCESS_DENIED',
      network: Object.freeze(['EACCES', 'ENETDOWN', 'ENETUNREACH']),
      worker: 'ERR_ACCESS_DENIED',
    }),
    nodeFlags: evidenceNodeFlags,
    environment: canonicalEnvironment,
    invocationDigest: sha256(canonicalJson({
      nodeVersion,
      nodeExecutableBinding: preRuntime.node,
      launcherDigest,
      bootstrapModuleSetDigest: launcherObserved.bootstrapSetDigest,
      nativeRuntimeBindingDigest: preRuntime.runtimeSetDigest,
      networkIsolatorBinding: preNetworkIsolator,
      args: ['<NETWORK_ISOLATOR>', '--net', '--', '<NODE_EXECUTABLE>', ...evidenceNodeFlags],
      environment: canonicalEnvironment,
    })),
    output,
  });
}

export function runTestProfile(profile, options = {}) {
  const authorisedRoots = TEST_PROFILES[profile];
  if (!authorisedRoots) throw new Error(`unknown test profile: ${profile}`);
  const repositoryRoot = options.repositoryRoot || resolve(fileURLToPath(new URL('../..', import.meta.url)));
  const inventory = discoverTestInventory({ repositoryRoot, authorisedRoots });
  return executeTestInventory(inventory, {
    snapshotPaths: ['.github', 'assurance', 'capabilities', 'configuration', 'node_modules', 'package-lock.json', 'package.json', 'processes', 'provider-bindings', 'semantic-model'],
    snapshotExclusions: ['node_modules/.bin'],
    ...options,
    repositoryRoot,
  });
}

const invokedAsProgram = process.argv[1]
  && existsSync(process.argv[1])
  && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsProgram) {
  const profile = process.argv[2] || 'all';
  const result = runTestProfile(profile);
  process.stdout.write(result.output);
  process.stdout.write(`${JSON.stringify({
    passed: result.passed,
    tests: result.count,
    discoveredFileCount: result.discoveredFileCount,
    testInventoryDigest: result.testInventoryDigest,
    preExecutionReboundDigest: result.preExecutionReboundDigest,
    executedTestInventoryDigest: result.executedTestInventoryDigest,
    executedByteSetDigest: result.executedByteSetDigest,
    discoveryAlgorithmDigest: result.discoveryAlgorithmDigest,
    rejectionCodeVocabularyDigest: result.rejectionCodeVocabularyDigest,
    outputDigest: result.outputDigest,
    testSummary: result.testSummary,
    invocationDigest: result.invocationDigest,
    nodeVersion: result.nodeVersion,
  })}\n`);
  if (!result.passed) process.exitCode = 1;
}

export const testRunnerInternals = Object.freeze({
  REQUIRED_NODE_VERSION,
  REQUIRED_NODE_EXECUTABLE_DIGEST,
  bindRegularFile,
  readBoundRegularFile,
  canonicalJson,
  classifyTargetStat,
  enumerateSnapshot,
  inspectNodeIdentity,
  snapshotModuleRecord,
  snapshotLoadedModuleRecord,
  snapshotExecutionBytes,
  rejectionCodeVocabularyDigest,
  parseLauncherInventory,
  sha256,
  validateTestTargets,
});
