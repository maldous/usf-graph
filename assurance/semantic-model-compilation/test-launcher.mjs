import { createHash } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import Module, { isBuiltin, registerHooks, syncBuiltinESMExports } from 'node:module';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from 'node:test';
import { tap } from 'node:test/reporters';

import { snapshotLoadedModuleRecord, snapshotModuleRecord } from './test-runner.mjs';

const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const comparePaths = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const repositoryRoot = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
const files = process.argv.slice(2);
const resolvedModules = new Map();
const loadedModules = new Map();
const writeControl = process.stdout.write.bind(process.stdout);
const runtimeReportControl = process.report.getReport.bind(process.report);
const installModuleHooks = registerHooks;
const synchroniseBuiltinExports = syncBuiltinESMExports;

function bindRegularFile(path) {
  const descriptor = openSync(path, 'r');
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile()) throw new Error(`NON_REGULAR_TARGET_PROHIBITED: ${path}`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const identity = (stat) => ({ device: stat.dev.toString(), inode: stat.ino.toString(), size: stat.size.toString() });
    if (canonicalJson(identity(before)) !== canonicalJson(identity(after))) throw new Error(`INVENTORY_DIGEST_CHANGED: ${path}`);
    return { path, ...identity(after), digest: sha256(bytes) };
  } finally {
    closeSync(descriptor);
  }
}

function recordResolvedModule(url) {
  const record = snapshotModuleRecord(url, repositoryRoot);
  resolvedModules.set(record.path, record);
}

function recordLoadedModule(url, source) {
  const record = snapshotLoadedModuleRecord(url, repositoryRoot, source);
  loadedModules.set(record.path, record);
}

if (process.versions.node !== '22.23.1') throw new Error(`NODE_VERSION_MISMATCH: expected 22.23.1, received ${process.versions.node}`);
if (files.length === 0) throw new Error('EMPTY_TEST_INVENTORY: launcher requires exact test files');

const records = files.map((path) => {
  const target = resolve(path);
  const containment = relative(repositoryRoot, target);
  if (containment === '..' || containment.startsWith(`..${sep}`)) throw new Error(`PATH_ESCAPE: ${path}`);
  const stat = lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`NON_REGULAR_TARGET_PROHIBITED: ${path}`);
  return { path: containment.replaceAll('\\', '/'), digest: sha256(readFileSync(target)) };
}).sort(({ path: left }, { path: right }) => comparePaths(left, right));
const observedInventoryDigest = sha256(canonicalJson(records));
if (observedInventoryDigest !== process.env.USF_TEST_INVENTORY_DIGEST) {
  throw new Error(`INVENTORY_DIGEST_CHANGED: launcher observed ${observedInventoryDigest}`);
}

// Static imports execute before hooks can observe them. Bind those bootstrap
// bytes explicitly so the executed module set is complete rather than merely
// the post-registration import closure.
const bootstrapUrls = [import.meta.url, new URL('./test-runner.mjs', import.meta.url).href];
bootstrapUrls.forEach(recordResolvedModule);
const bootstrapRecords = bootstrapUrls.map((url) => snapshotModuleRecord(url, repositoryRoot))
  .sort(({ path: left }, { path: right }) => comparePaths(left, right));
for (const record of bootstrapRecords) loadedModules.set(record.path, record);

installModuleHooks({
  resolve(specifier, context, nextResolve) {
    if (isBuiltin(specifier)) return nextResolve(specifier, context);
    if (/^(?:data|https?):/u.test(specifier)) throw new Error(`MODULE_RESOLUTION_PROHIBITED: ${specifier}`);
    const result = nextResolve(specifier, context);
    recordResolvedModule(result.url);
    return result;
  },
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (!url.startsWith('node:')) recordLoadedModule(url, result.source);
    return result;
  },
});

// A test must not register a later hook that short-circuits this audit. Replace
// both hook-registration surfaces on the shared builtin object, then update
// named ESM exports from those locked properties.
const denyHookMutation = () => {
  const error = new Error('MODULE_RESOLUTION_PROHIBITED: module hook mutation is prohibited');
  error.code = 'MODULE_RESOLUTION_PROHIBITED';
  throw error;
};
for (const property of ['register', 'registerHooks', 'syncBuiltinESMExports']) {
  Object.defineProperty(Module, property, {
    configurable: false,
    enumerable: true,
    value: denyHookMutation,
    writable: false,
  });
}
synchroniseBuiltinExports();

writeControl(`# usf-test-inventory ${canonicalJson({
  fileCount: records.length,
  observedInventoryDigest,
  isolation: 'none',
})}\n`);
const stream = run({ files, isolation: 'none', concurrency: 1 });
const summaries = [];
stream.on('test:summary', (summary) => summaries.push(summary));
stream.on('test:fail', () => { process.exitCode = 1; });
const reporter = stream.compose(tap);
for await (const chunk of reporter) writeControl(chunk);
if (summaries.length !== 1) throw new Error(`INVENTORY_DIGEST_CHANGED: received ${summaries.length} test summaries`);
const summary = summaries[0];
const resultRecord = {
  success: summary?.success === true,
  counts: Object.fromEntries(['cancelled', 'failed', 'passed', 'skipped', 'suites', 'tests', 'todo', 'topLevel']
    .map((name) => [name, summary?.counts?.[name]])),
};
  if (Object.values(resultRecord.counts).some((value) => !Number.isSafeInteger(value) || value < 0)
    || resultRecord.counts.tests < 1) {
  throw new Error('INVENTORY_DIGEST_CHANGED: test summary is structurally invalid');
}
writeControl(`# usf-test-result ${canonicalJson(resultRecord)}\n`);
const sharedObjects = [...new Set(runtimeReportControl().sharedObjects)].sort(comparePaths);
const runtimeCore = {
  nodeVersion: process.versions.node,
  node: bindRegularFile(process.execPath),
  nativeFiles: sharedObjects.filter((path) => path.startsWith('/')).map(bindRegularFile),
  virtualSharedObjects: sharedObjects.filter((path) => !path.startsWith('/')),
};
writeControl(`# usf-runtime-inventory ${canonicalJson({ ...runtimeCore, runtimeSetDigest: sha256(canonicalJson(runtimeCore)) })}\n`);
const resolvedModuleRecords = [...resolvedModules.values()].sort(({ path: left }, { path: right }) => comparePaths(left, right));
const loadedModuleRecords = [...loadedModules.values()].sort(({ path: left }, { path: right }) => comparePaths(left, right));
writeControl(`# usf-module-inventory ${canonicalJson({
  bootstrapCount: bootstrapRecords.length,
  bootstrapRecords,
  bootstrapSetDigest: sha256(canonicalJson(bootstrapRecords)),
  loadedModuleCount: loadedModuleRecords.length,
  loadedModuleRecords,
  loadedModuleSetDigest: sha256(canonicalJson(loadedModuleRecords)),
  resolvedModuleCount: resolvedModuleRecords.length,
  resolvedModuleRecords,
  resolvedModuleSetDigest: sha256(canonicalJson(resolvedModuleRecords)),
})}\n`);
