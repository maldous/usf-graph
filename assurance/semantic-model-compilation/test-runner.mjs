import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
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

function parseLauncherInventory(output, expected) {
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
  return Object.freeze(observed);
}

function snapshotExecutionBytes({ repositoryRoot, inventory, snapshotPaths, snapshotExclusions = [] }) {
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
      stat = lstatSync(target);
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
      if (stat.nlink !== 1 || sourceIdentities.has(identity)) reject('HARD_LINK_PROHIBITED', `execution snapshot input is hard-linked or aliased: ${path}`);
      sourceIdentities.add(identity);
      const bytes = readFileSync(target);
      sourceRecords.push({ path, digest: sha256(bytes), bytes });
    } else {
      reject('NON_REGULAR_TARGET_PROHIBITED', `execution snapshot input is not regular: ${path}`);
    }
  };
  paths.forEach(visit);
  const duplicate = sourceRecords.find(({ path }, index) => sourceRecords.findIndex((record) => record.path === path) !== index);
  if (duplicate) reject('DUPLICATE_TEST_TARGET', `execution snapshot contains a duplicate canonical path: ${duplicate.path}`);
  const container = mkdtempSync(join(tmpdir(), `usf-test-snapshot-${inventory.testInventoryDigest.slice(7, 23)}-`));
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
  return {
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
  nodeVersion = process.versions.node,
  networkIsolator = '/usr/bin/unshare',
  nativeRuntimePaths = process.report.getReport().sharedObjects.filter((path) => path.startsWith('/')),
  snapshotPaths,
  snapshotExclusions,
  beforeExecute,
  launcherRelativePath = 'assurance/semantic-model-compilation/test-launcher.mjs',
  testInvocationMode = 'NODE_TEST_PROGRAMMATIC_EXACT_FILES',
} = {}) {
  if (nodeVersion !== REQUIRED_NODE_VERSION) reject('NODE_VERSION_MISMATCH', `test runner requires Node ${REQUIRED_NODE_VERSION}, received ${nodeVersion}`);
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
  const executionPaths = snapshotPaths || [...new Set(rebound.records.map(({ path }) => path.split('/')[0]))];
  const snapshot = snapshotExecutionBytes({
    repositoryRoot: root,
    inventory,
    snapshotPaths: executionPaths,
    snapshotExclusions,
  });
  const runtimeRoot = mkdtempSync(join(tmpdir(), 'usf-test-runtime-'));
  const invocationModes = {
    NODE_TEST_CLI_DEFAULT_ISOLATION: ['--permission', '--allow-fs-read=<SNAPSHOT_ROOT>', '--allow-fs-read=<RUNTIME_ROOT>', '--allow-fs-write=<RUNTIME_ROOT>', '--no-addons', '--test'],
    NODE_TEST_CLI_CHILD_PERMITTED: ['--permission', '--allow-fs-read=<SNAPSHOT_ROOT>', '--allow-fs-read=<RUNTIME_ROOT>', '--allow-fs-write=<RUNTIME_ROOT>', '--allow-child-process', '--no-addons', '--test'],
    NODE_TEST_PROGRAMMATIC_EXACT_FILES: ['--permission', '--allow-fs-read=<SNAPSHOT_ROOT>', '--allow-fs-read=<RUNTIME_ROOT>', '--allow-fs-write=<RUNTIME_ROOT>', '--no-addons', '<REPOSITORY_LOCAL_TEST_LAUNCHER>'],
  };
  const canonicalFlags = invocationModes[testInvocationMode];
  if (!canonicalFlags) reject('INVALID_INVOCATION_MODE', `unsupported test invocation mode: ${testInvocationMode}`);
  const canonicalEnvironment = {
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    TEMP: '<RUNTIME_ROOT>',
    TMP: '<RUNTIME_ROOT>',
    TMPDIR: '<RUNTIME_ROOT>',
    TZ: 'UTC',
    USF_HERMETIC_TEST_MODE: '1',
    USF_TEST_INVENTORY_DIGEST: inventory.testInventoryDigest,
  };
  const launcherPath = resolve(snapshot.snapshotRoot, portable(launcherRelativePath));
  const launcherDigest = sha256(readFileSync(launcherPath));
  const nodeExecutableDigest = sha256(readFileSync(nodeExecutable));
  const networkIsolatorDigest = sha256(readFileSync(networkIsolator));
  const nativeRuntimeDigests = nativeRuntimePaths
    .map((path) => ({ path, digest: sha256(readFileSync(path)) }))
    .sort(({ path: left }, { path: right }) => comparePaths(left, right));
  let output;
  try {
    if (typeof beforeExecute === 'function') beforeExecute(Object.freeze({ snapshotRoot: snapshot.snapshotRoot }));
    const finalSnapshotRecords = snapshot.snapshotRecords.map(({ path }) => ({ path, digest: sha256(readFileSync(resolve(snapshot.snapshotRoot, path))) }));
    if (sha256(canonicalJson(finalSnapshotRecords)) !== snapshot.snapshotManifestDigest) {
      reject('INVENTORY_DIGEST_CHANGED', 'immutable execution snapshot changed before Node started');
    }
    const exactPaths = rebound.records.map(({ path }) => resolve(snapshot.snapshotRoot, path));
    const permissionArgs = [
      '--permission',
      `--allow-fs-read=${snapshot.snapshotRoot}`,
      `--allow-fs-read=${runtimeRoot}`,
      `--allow-fs-write=${runtimeRoot}`,
    ];
    const nodeArgs = testInvocationMode === 'NODE_TEST_PROGRAMMATIC_EXACT_FILES'
      ? [...permissionArgs, '--no-addons', launcherPath, ...exactPaths]
      : [
          ...permissionArgs,
          ...(testInvocationMode === 'NODE_TEST_CLI_CHILD_PERMITTED' ? ['--allow-child-process'] : []),
          '--no-addons',
          '--test',
          ...exactPaths,
        ];
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
  } finally {
    removeSnapshot(snapshot);
    rmSync(runtimeRoot, { recursive: true, force: true });
  }
  const launcherObserved = parseLauncherInventory(output, inventory);
  const count = Number(output.match(/# tests ([0-9]+)/)?.[1] || 0);
  const deterministicResult = {
    cases: output.split('\n').filter((line) => /^\s*(?:ok|not ok) [0-9]+ - /.test(line)).map((line) => line.trim()),
    tests: count,
    passed: Number(output.match(/# pass ([0-9]+)/)?.[1] || 0),
    failed: Number(output.match(/# fail ([0-9]+)/)?.[1] || 0),
    cancelled: Number(output.match(/# cancelled ([0-9]+)/)?.[1] || 0),
    skipped: Number(output.match(/# skipped ([0-9]+)/)?.[1] || 0),
    todo: Number(output.match(/# todo ([0-9]+)/)?.[1] || 0),
  };
  return Object.freeze({
    passed: count > 0 && deterministicResult.failed === 0 && deterministicResult.cancelled === 0 && deterministicResult.skipped === 0,
    count,
    outputDigest: sha256(canonicalJson(deterministicResult)),
    discoveredFileCount: inventory.discoveredFileCount,
    testInventoryDigest: inventory.testInventoryDigest,
    authorisedRoots: inventory.authorisedRoots,
    authorisedRootSetDigest: inventory.authorisedRootSetDigest,
    preExecutionReboundDigest: rebound.testInventoryDigest,
    stagedTestInventoryDigest: snapshot.executedTestInventoryDigest,
    executedTestInventoryDigest: launcherObserved.observedInventoryDigest,
    executedByteSetDigest: launcherObserved.observedInventoryDigest,
    launcherObservedTestInventoryDigest: launcherObserved.observedInventoryDigest,
    launcherObservedTestFileCount: launcherObserved.fileCount,
    authorisedExecutionByteSetDigest: snapshot.snapshotManifestDigest,
    snapshotManifestDigest: snapshot.snapshotManifestDigest,
    snapshotRootDigest: snapshot.snapshotRootDigest,
    snapshotPermissionsDigest: snapshot.permissionsDigest,
    snapshotFileCount: snapshot.snapshotRecords.length,
    stagedFileDigests: snapshot.snapshotRecords,
    snapshotPolicy: 'EPHEMERAL_DELETE_AFTER_EXECUTION',
    snapshotExclusions: snapshot.exclusions,
    snapshotReadOnlyVerified: true,
    discoveryAlgorithmDigest: inventory.discoveryAlgorithmDigest,
    rejectionCodeVocabularyDigest: inventory.rejectionCodeVocabularyDigest,
    dependencyLockDigest: sha256(readFileSync(resolve(root, 'package-lock.json'))),
    dependencyByteSetDigest: sha256(canonicalJson(snapshot.snapshotRecords.filter(({ path }) => path.startsWith('node_modules/')))),
    launcherDigest,
    nativeRuntimeDigests,
    networkIsolation: 'LINUX_NETWORK_NAMESPACE',
    networkIsolatorDigest,
    nodeExecutableDigest,
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
    nodeFlags: canonicalFlags,
    environment: canonicalEnvironment,
    invocationDigest: sha256(canonicalJson({
      nodeVersion,
      nodeExecutableDigest,
      launcherDigest,
      networkIsolatorDigest,
      args: [...canonicalFlags, ...inventory.records.map(({ path }) => path)],
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
    snapshotPaths: ['assurance', 'capabilities', 'configuration', 'node_modules', 'package-lock.json', 'package.json', 'processes', 'provider-bindings', 'semantic-model'],
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
    invocationDigest: result.invocationDigest,
    nodeVersion: result.nodeVersion,
  })}\n`);
  if (!result.passed) process.exitCode = 1;
}

export const testRunnerInternals = Object.freeze({
  REQUIRED_NODE_VERSION,
  classifyTargetStat,
  rejectionCodeVocabularyDigest,
  parseLauncherInventory,
  sha256,
  validateTestTargets,
});
