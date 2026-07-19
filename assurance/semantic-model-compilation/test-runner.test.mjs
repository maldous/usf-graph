import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { Worker } from 'node:worker_threads';

import {
  discoverTestInventory,
  executeTestInventory,
  snapshotLoadedModuleRecord,
  snapshotModuleRecord,
  testRunnerInternals,
} from './test-runner.mjs';

const roots = [];

function fixture({ withTests = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'usf-test-inventory-'));
  mkdirSync(join(root, 'authorised', 'nested'), { recursive: true });
  mkdirSync(join(root, 'outside'), { recursive: true });
  writeFileSync(join(root, 'package.json'), '{"type":"module"}\n');
  writeFileSync(join(root, 'package-lock.json'), '{"lockfileVersion":3}\n');
  writeFileSync(join(root, 'authorised', 'fake-node'), 'node-binary-fixture\n');
  writeFileSync(join(root, 'authorised', 'fake-launcher.mjs'), 'export {};\n');
  if (withTests) {
    writeFileSync(join(root, 'authorised', 'alpha.test.mjs'), "import test from 'node:test'; test('alpha', () => {});\n");
    writeFileSync(join(root, 'authorised', 'nested', 'beta.test.mjs'), "import test from 'node:test'; test('beta', () => {});\n");
  }
  roots.push(root);
  return root;
}

test.after(() => roots.forEach((root) => rmSync(root, { recursive: true, force: true })));

const expectCode = (operation, reasonCode) => assert.throws(operation, (error) => {
  assert.equal(error.reasonCode, reasonCode);
  return true;
});

const fakeNodeOptions = (root) => {
  const nodeExecutable = join(root, 'authorised', 'fake-node');
  const digest = testRunnerInternals.sha256(readFileSync(nodeExecutable));
  return {
    bootstrapRelativePaths: ['authorised/fake-launcher.mjs'],
    nodeExecutable,
    expectedNodeExecutableDigest: digest,
    nodeIdentityVerifier: () => ({ version: '22.23.1', digest }),
  };
};

const successfulOutput = (args, options, { tests = 2, todo = 0, resolvedOnlyRecords = [] } = {}) => {
  const testRecords = args.filter((path) => path.endsWith('.test.mjs')).map((path) => ({
    path: relative(options.cwd, path).replaceAll('\\', '/'),
    digest: testRunnerInternals.sha256(readFileSync(path)),
  })).sort(({ path: left }, { path: right }) => left.localeCompare(right));
  const launcherPath = args.find((path) => path.endsWith('.mjs') && !path.endsWith('.test.mjs'));
  const bootstrapRecords = [{
    path: relative(options.cwd, launcherPath).replaceAll('\\', '/'),
    digest: testRunnerInternals.sha256(readFileSync(launcherPath)),
  }];
  const loadedRecords = [...bootstrapRecords, ...testRecords].sort(({ path: left }, { path: right }) => left.localeCompare(right));
  const resolvedRecords = [...loadedRecords, ...resolvedOnlyRecords].sort(({ path: left }, { path: right }) => left.localeCompare(right));
  const runtimeCore = {
    nodeVersion: '22.23.1',
    node: testRunnerInternals.bindRegularFile(args[2]),
    nativeFiles: [],
    virtualSharedObjects: [],
  };
  const runtimeRecord = `# usf-runtime-inventory ${JSON.stringify({
    ...runtimeCore,
    runtimeSetDigest: testRunnerInternals.sha256(testRunnerInternals.canonicalJson(runtimeCore)),
  })}\n`;
  const moduleRecord = `# usf-module-inventory ${JSON.stringify({
    bootstrapCount: bootstrapRecords.length,
    bootstrapRecords,
    bootstrapSetDigest: testRunnerInternals.sha256(testRunnerInternals.canonicalJson(bootstrapRecords)),
    loadedModuleCount: loadedRecords.length,
    loadedModuleRecords: loadedRecords,
    loadedModuleSetDigest: testRunnerInternals.sha256(testRunnerInternals.canonicalJson(loadedRecords)),
    resolvedModuleCount: resolvedRecords.length,
    resolvedModuleRecords: resolvedRecords,
    resolvedModuleSetDigest: testRunnerInternals.sha256(testRunnerInternals.canonicalJson(resolvedRecords)),
  })}\n`;
  const inventoryRecord = `# usf-test-inventory ${JSON.stringify({
    fileCount: tests, observedInventoryDigest: options.env.USF_TEST_INVENTORY_DIGEST, isolation: 'none',
  })}\n`;
  const resultRecord = `# usf-test-result ${JSON.stringify({
    counts: {
      cancelled: 0,
      failed: 0,
      passed: tests - todo,
      skipped: 0,
      suites: 0,
      tests,
      todo,
      topLevel: tests,
    },
    success: true,
  })}\n`;
  const cases = Array.from({ length: tests }, (_, index) => `ok ${index + 1} - case-${index + 1}`).join('\n');
  return `${inventoryRecord}${cases}\n# tests ${tests}\n# pass ${tests}\n# fail 0\n# cancelled 0\n# skipped 0\n# todo ${todo}\n${resultRecord}${runtimeRecord}${moduleRecord}`;
};

function rewriteControlRecord(output, prefix, mutate) {
  const lines = output.split('\n');
  const index = lines.findIndex((line) => line.startsWith(prefix));
  assert.ok(index >= 0, `missing control record ${prefix}`);
  const record = JSON.parse(lines[index].slice(prefix.length));
  mutate(record);
  lines[index] = `${prefix}${JSON.stringify(record)}`;
  return lines.join('\n');
}

test('discovers a canonical, digest-bound exact test inventory and invokes Node 22 without a shell', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  assert.deepEqual(inventory.records.map(({ path }) => path), [
    'authorised/alpha.test.mjs',
    'authorised/nested/beta.test.mjs',
  ]);
  assert.equal(inventory.discoveredFileCount, 2);
  assert.match(inventory.testInventoryDigest, /^sha256:[0-9a-f]{64}$/);
  let invocation;
  const result = executeTestInventory(inventory, {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
    execute: (executable, args, options) => {
      invocation = { executable, args, options };
      return successfulOutput(args, options);
    },
  });
  assert.equal(result.passed, true);
  assert.equal(result.discoveredFileCount, 2);
  assert.equal(result.testInventoryDigest, inventory.testInventoryDigest);
  assert.equal(result.executedTestInventoryDigest, inventory.testInventoryDigest);
  assert.equal(result.launcherObservedTestInventoryDigest, inventory.testInventoryDigest);
  assert.equal(result.executedByteSetDigest, result.loadedModuleSetDigest);
  assert.equal(result.launcherObservedTestFileCount, 2);
  assert.equal(result.authorisedRootSetDigest, inventory.authorisedRootSetDigest);
  assert.equal(invocation.args.includes('--net'), true);
  assert.equal(invocation.args.filter((value) => value.endsWith('.test.mjs')).length, 2);
  assert.equal(invocation.args.some((value) => /[*?\[\]]/.test(value)), false);
  assert.notEqual(invocation.options.cwd, root);
  assert.equal(invocation.args.filter((value) => value.endsWith('.test.mjs')).every((path) => path.startsWith(invocation.options.cwd)), true);
  assert.equal(result.nodeFlags.includes('--no-addons'), true);
  assert.equal(result.nodeFlags.includes('--frozen-intrinsics'), true);
  assert.equal(result.isolationMode, 'none');
  assert.equal(result.invocationMode, 'NODE_TEST_PROGRAMMATIC_EXACT_FILES');
  assert.match(result.nodeExecutableDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(result.snapshotRootDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.snapshotPolicy, 'EPHEMERAL_DELETE_AFTER_EXECUTION');
});

test('rejects each structurally invalid target with its exact reason code and precedence', () => {
  const root = fixture();
  writeFileSync(join(root, 'authorised', 'wrong.test.js'), 'export {};\n');
  writeFileSync(join(root, 'outside', 'outside.test.mjs'), 'export {};\n');
  mkdirSync(join(root, 'authorised', 'directory.test.mjs'));
  const escape = join(dirname(root), `${basename(root)}-escape.test.mjs`);
  writeFileSync(escape, 'export {};\n');
  roots.push(escape);
  const validate = (targets) => testRunnerInternals.validateTestTargets({ repositoryRoot: root, authorisedRoots: ['authorised'], targets });
  expectCode(() => validate(['authorised/nested']), 'DIRECTORY_TARGET_PROHIBITED');
  expectCode(() => validate(['authorised/directory.test.mjs']), 'DIRECTORY_TARGET_PROHIBITED');
  expectCode(() => validate(['authorised/wrong.test.js']), 'EXTENSION_NOT_ALLOWED');
  expectCode(() => validate(['outside/outside.test.mjs']), 'UNAUTHORISED_TEST_ROOT');
  expectCode(() => validate([`../${basename(escape)}`]), 'PATH_ESCAPE');
  expectCode(() => testRunnerInternals.classifyTargetStat({
    isSymbolicLink: () => true,
    isDirectory: () => false,
    isFile: () => false,
    nlink: 1,
  }, 'authorised/linked.test.mjs'), 'SYMLINK_PROHIBITED');
  expectCode(() => testRunnerInternals.classifyTargetStat({
    isSymbolicLink: () => false,
    isDirectory: () => false,
    isFile: () => true,
    nlink: 2,
  }, 'authorised/hard-linked.test.mjs'), 'HARD_LINK_PROHIBITED');
  expectCode(() => validate(['authorised/alpha.test.mjs', 'authorised/./alpha.test.mjs']), 'DUPLICATE_TEST_TARGET');
  expectCode(() => validate(['authorised/missing.test.mjs']), 'TARGET_NOT_FOUND');
  expectCode(() => discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] }), 'EXTENSION_NOT_ALLOWED');
});

test('rejects zero discovery and overlapping discovery roots', () => {
  const empty = fixture({ withTests: false });
  expectCode(() => discoverTestInventory({ repositoryRoot: empty, authorisedRoots: ['authorised'] }), 'EMPTY_TEST_INVENTORY');
  const root = fixture();
  expectCode(() => discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised', 'authorised'] }), 'DUPLICATE_AUTHORISED_ROOT');
});

test('canonical ordering and inventory digest are independent of directory enumeration order and shell globbing', () => {
  const root = fixture();
  const forward = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const reverse = discoverTestInventory({
    repositoryRoot: root,
    authorisedRoots: ['authorised'],
    readDirectory: (path, options) => readdirSync(path, options).reverse(),
  });
  assert.deepEqual(reverse, forward);
  const windowsStyle = testRunnerInternals.validateTestTargets({
    repositoryRoot: root,
    authorisedRoots: ['authorised'],
    targets: ['authorised\\nested\\beta.test.mjs', 'authorised\\alpha.test.mjs'],
  });
  assert.deepEqual(windowsStyle.records, forward.records);
  assert.equal(windowsStyle.testInventoryDigest, forward.testInventoryDigest);
  expectCode(() => testRunnerInternals.validateTestTargets({
    repositoryRoot: root,
    authorisedRoots: ['authorised'],
    targets: ['authorised/*.test.mjs'],
  }), 'TARGET_NOT_FOUND');
});

test('rejects inventory mutation after discovery and before execution', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  writeFileSync(join(root, 'authorised', 'alpha.test.mjs'), "import test from 'node:test'; test('changed', () => {});\n");
  let invoked = false;
  expectCode(() => executeTestInventory(inventory, {
    repositoryRoot: root,
    execute: () => { invoked = true; return ''; },
  }), 'INVENTORY_DIGEST_CHANGED');
  assert.equal(invoked, false);
});

test('rejects a non-test source swap between classification and byte binding before Node starts', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  let mutated = false;
  let invoked = false;
  expectCode(() => executeTestInventory(inventory, {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
    sourceReader: (path, options) => {
      if (!mutated && path.endsWith('package-lock.json')) {
        mutated = true;
        writeFileSync(path, '{"lockfileVersion":3,"swapped":true}\n');
      }
      return testRunnerInternals.readBoundRegularFile(path, options);
    },
    execute: () => { invoked = true; return ''; },
  }), 'INVENTORY_DIGEST_CHANGED');
  assert.equal(mutated, true);
  assert.equal(invoked, false);
});

test('removes staged state when a pre-execution bootstrap contract fails', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const snapshotNames = () => readdirSync(tmpdir()).filter((name) => name.startsWith(`usf-test-snapshot-${inventory.testInventoryDigest.slice(7, 23)}-`)).sort();
  const before = snapshotNames();
  expectCode(() => executeTestInventory(inventory, {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    bootstrapRelativePaths: ['authorised/missing-bootstrap.mjs'],
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
    execute: () => '',
  }), 'INVENTORY_DIGEST_CHANGED');
  assert.deepEqual(snapshotNames(), before);
});

test('executes immutable staged bytes when the workspace changes after staging', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  let observed;
  const result = executeTestInventory(inventory, {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
    beforeExecute: () => {
      writeFileSync(join(root, 'authorised', 'alpha.test.mjs'), "throw new Error('workspace mutation must not execute');\n");
      writeFileSync(join(root, 'package-lock.json'), '{"lockfileVersion":3,"workspaceMutation":true}\n');
    },
    execute: (_executable, args, options) => {
      const stagedAlpha = args.find((path) => path.endsWith('/authorised/alpha.test.mjs'));
      observed = readFileSync(stagedAlpha, 'utf8');
      return successfulOutput(args, options);
    },
  });
  assert.match(observed, /test\('alpha'/);
  assert.equal(result.testInventoryDigest, result.executedTestInventoryDigest);
  assert.equal(result.dependencyLockDigest, testRunnerInternals.sha256('{"lockfileVersion":3}\n'));
});

test('rejects undeclared or mutated staged bytes before and during execution', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const common = {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
  };
  let invoked = false;
  expectCode(() => executeTestInventory(inventory, {
    ...common,
    beforeExecute: ({ snapshotRoot }) => writeFileSync(join(snapshotRoot, 'undeclared.mjs'), 'export {};\n'),
    execute: () => { invoked = true; return ''; },
  }), 'INVENTORY_DIGEST_CHANGED');
  assert.equal(invoked, false);
  expectCode(() => executeTestInventory(inventory, {
    ...common,
    execute: (_executable, args, options) => {
      writeFileSync(args.find((path) => path.endsWith('/authorised/alpha.test.mjs')), 'export {};\n');
      return successfulOutput(args, options);
    },
  }), 'INVENTORY_DIGEST_CHANGED');
});

test('rejects missing, duplicate and mismatched launcher inventory records', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const common = {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
  };
  const tap = '# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
  expectCode(() => executeTestInventory(inventory, { ...common, execute: () => tap }), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) => {
    const valid = successfulOutput(args, options);
    const line = valid.split('\n').find((item) => item.startsWith('# usf-test-inventory '));
    return `${line}\n${line}\n${valid}`;
  } }), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) =>
    successfulOutput(args, options).replace(inventory.testInventoryDigest, testRunnerInternals.sha256('wrong')) }), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) =>
    successfulOutput(args, options).split('\n').filter((line) => !line.startsWith('# usf-module-inventory ')).join('\n') }), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) =>
    successfulOutput(args, options).split('\n').filter((line) => !line.startsWith('# usf-runtime-inventory ')).join('\n') }), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) =>
    successfulOutput(args, options).split('\n').filter((line) => !line.startsWith('# usf-test-result ')).join('\n') }), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) => {
    const valid = successfulOutput(args, options);
    const line = valid.split('\n').find((item) => item.startsWith('# usf-test-result '));
    return `${line}\n${valid}`;
  } }), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) =>
    successfulOutput(args, options).replace('"bootstrapCount":1', '"bootstrapCount":0') }), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) =>
    successfulOutput(args, options).replace('"nodeVersion":"22.23.1"', '"nodeVersion":"22.23.0"') }), 'INVENTORY_DIGEST_CHANGED');
  for (const moduleRecords of [[null], [{ path: 'authorised/alpha.test.mjs', digest: testRunnerInternals.sha256('wrong'), extra: true }]]) {
    expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) => {
      const output = successfulOutput(args, options).split('\n').filter((line) => !line.startsWith('# usf-module-inventory ')).join('\n');
      const moduleRecord = `# usf-module-inventory ${JSON.stringify({
        bootstrapCount: 0,
        bootstrapRecords: [],
        bootstrapSetDigest: testRunnerInternals.sha256(testRunnerInternals.canonicalJson([])),
        loadedModuleCount: moduleRecords.length,
        loadedModuleRecords: moduleRecords,
        loadedModuleSetDigest: testRunnerInternals.sha256(testRunnerInternals.canonicalJson(moduleRecords)),
        resolvedModuleCount: moduleRecords.length,
        resolvedModuleRecords: moduleRecords,
        resolvedModuleSetDigest: testRunnerInternals.sha256(testRunnerInternals.canonicalJson(moduleRecords)),
      })}`;
      return `${output}\n${moduleRecord}\n`;
    } }), 'INVENTORY_DIGEST_CHANGED');
  }
  const structuredDefects = [
    (record) => { record.extra = true; },
    (record) => { record.counts.failed = -1; },
    (record) => { record.counts.tests = Number.MAX_SAFE_INTEGER + 1; },
    (record) => { record.counts.failed = 1; },
    (record) => { record.success = false; },
  ];
  for (const mutate of structuredDefects) {
    expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) =>
      rewriteControlRecord(successfulOutput(args, options), '# usf-test-result ', mutate) }), 'INVENTORY_DIGEST_CHANGED');
  }
  const moduleDefects = [
    (record) => {
      record.loadedModuleRecords[0].digest = testRunnerInternals.sha256('substituted-loaded-source');
      record.loadedModuleSetDigest = testRunnerInternals.sha256(testRunnerInternals.canonicalJson(record.loadedModuleRecords));
    },
    (record) => {
      record.loadedModuleRecords = record.loadedModuleRecords.filter(({ path }) => !path.endsWith('alpha.test.mjs'));
      record.loadedModuleCount = record.loadedModuleRecords.length;
      record.loadedModuleSetDigest = testRunnerInternals.sha256(testRunnerInternals.canonicalJson(record.loadedModuleRecords));
    },
    (record) => {
      record.resolvedModuleRecords = record.resolvedModuleRecords.filter(({ path }) => !path.endsWith('alpha.test.mjs'));
      record.resolvedModuleCount = record.resolvedModuleRecords.length;
      record.resolvedModuleSetDigest = testRunnerInternals.sha256(testRunnerInternals.canonicalJson(record.resolvedModuleRecords));
    },
    (record) => {
      record.loadedModuleRecords.reverse();
      record.loadedModuleSetDigest = testRunnerInternals.sha256(testRunnerInternals.canonicalJson(record.loadedModuleRecords));
    },
  ];
  for (const mutate of moduleDefects) {
    expectCode(() => executeTestInventory(inventory, { ...common, execute: (_executable, args, options) =>
      rewriteControlRecord(successfulOutput(args, options), '# usf-module-inventory ', mutate) }), 'INVENTORY_DIGEST_CHANGED');
  }
});

test('structured core result, not TAP-shaped test output, determines the verdict', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const common = {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
  };
  const result = executeTestInventory(inventory, {
    ...common,
    execute: (_executable, args, options) => `${successfulOutput(args, options)}\n# tests 999\n# pass 0\n# fail 999\n`,
  });
  assert.equal(result.passed, true);
  assert.equal(result.count, 2);
});

test('runtime inputs are rebound before execution and after child completion', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const common = {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
  };
  let invoked = false;
  expectCode(() => executeTestInventory(inventory, {
    ...common,
    beforeExecute: () => writeFileSync(common.nodeExecutable, 'changed-before-execution\n'),
    execute: () => { invoked = true; return ''; },
  }), 'NODE_VERSION_MISMATCH');
  assert.equal(invoked, false);

  const secondRoot = fixture();
  const secondInventory = discoverTestInventory({ repositoryRoot: secondRoot, authorisedRoots: ['authorised'] });
  const second = {
    repositoryRoot: secondRoot,
    ...fakeNodeOptions(secondRoot),
    networkIsolator: join(secondRoot, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
  };
  expectCode(() => executeTestInventory(secondInventory, {
    ...second,
    execute: (_executable, args, options) => {
      const output = successfulOutput(args, options);
      writeFileSync(second.nodeExecutable, 'changed-after-child-observation\n');
      return output;
    },
  }), 'INVENTORY_DIGEST_CHANGED');
});

test('todo results and unverified Node identities fail closed', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const common = {
    repositoryRoot: root,
    ...fakeNodeOptions(root),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
  };
  const result = executeTestInventory(inventory, { ...common, execute: (_executable, args, options) => successfulOutput(args, options, { todo: 1 }) });
  assert.equal(result.passed, false);
  expectCode(() => executeTestInventory(inventory, {
    ...common,
    expectedNodeExecutableDigest: `sha256:${'0'.repeat(64)}`,
    execute: () => '',
  }), 'NODE_VERSION_MISMATCH');
});

test('module resolution permits only regular immutable snapshot files', () => {
  const root = fixture();
  const inside = join(root, 'authorised', 'alpha.test.mjs');
  const record = snapshotModuleRecord(pathToFileURL(inside).href, root);
  assert.equal(record.path, 'authorised/alpha.test.mjs');
  assert.match(record.digest, /^sha256:[0-9a-f]{64}$/);
  const sourceBytes = readFileSync(inside);
  assert.deepEqual(snapshotLoadedModuleRecord(pathToFileURL(inside).href, root, sourceBytes), record);
  assert.deepEqual(snapshotLoadedModuleRecord(pathToFileURL(inside).href, root, sourceBytes.toString('utf8')), record);
  const framed = Buffer.concat([Buffer.from('prefix'), sourceBytes, Buffer.from('suffix')]);
  const view = new Uint8Array(framed.buffer, framed.byteOffset + 6, sourceBytes.length);
  assert.deepEqual(snapshotLoadedModuleRecord(pathToFileURL(inside).href, root, view), record);
  expectCode(() => snapshotLoadedModuleRecord(pathToFileURL(inside).href, root, Buffer.from('different source')), 'INVENTORY_DIGEST_CHANGED');
  expectCode(() => snapshotLoadedModuleRecord(pathToFileURL(inside).href, root, null), 'INVENTORY_DIGEST_CHANGED');
  const outside = join(dirname(root), `${basename(root)}-ambient.mjs`);
  writeFileSync(outside, 'export {};\n');
  roots.push(outside);
  expectCode(() => snapshotModuleRecord(pathToFileURL(outside).href, root), 'MODULE_RESOLUTION_PROHIBITED');
  expectCode(() => snapshotModuleRecord('data:text/javascript,export{}', root), 'MODULE_RESOLUTION_PROHIBITED');
});

test('hermetic launcher denies ambient reads, writes, child processes, workers and network', {
  skip: process.env.USF_HERMETIC_TEST_MODE !== '1',
}, async () => {
  const denied = (operation) => assert.throws(operation, (error) => error?.code === 'ERR_ACCESS_DENIED');
  denied(() => readFileSync('/etc/hosts'));
  denied(() => writeFileSync('/tmp/usf-hermetic-denial-control', 'forbidden'));
  denied(() => execFileSync(process.execPath, ['-e', 'process.exit(0)']));
  denied(() => new Worker('export {};', { eval: true }));
  const networkCode = await new Promise((resolveCode, reject) => {
    const socket = net.connect({ host: '198.51.100.1', port: 9 });
    socket.once('connect', () => reject(new Error('network access unexpectedly succeeded')));
    socket.once('error', (error) => resolveCode(error.code));
    socket.setTimeout(1000, () => { socket.destroy(); reject(new Error('network isolation did not fail closed')); });
  });
  assert.ok(['EACCES', 'ENETDOWN', 'ENETUNREACH'].includes(networkCode), networkCode);
});

test('selects programmatic isolation none after evaluating the Node permission/isolation matrix', () => {
  if (process.env.USF_HERMETIC_TEST_MODE === '1') return;
  const root = fixture();
  mkdirSync(join(root, 'assurance', 'semantic-model-compilation'), { recursive: true });
  writeFileSync(
    join(root, 'assurance', 'semantic-model-compilation', 'test-launcher.mjs'),
    readFileSync(new URL('./test-launcher.mjs', import.meta.url)),
  );
  writeFileSync(
    join(root, 'assurance', 'semantic-model-compilation', 'test-runner.mjs'),
    readFileSync(new URL('./test-runner.mjs', import.meta.url)),
  );
  writeFileSync(join(root, 'authorised', 'resolved-only.mjs'), 'export const resolvedOnly = true;\n');
  writeFileSync(join(root, 'authorised', 'alpha.test.mjs'), `
import assert from 'node:assert/strict';
import Module, { createRequire, register, registerHooks } from 'node:module';
import test from 'node:test';
import.meta.resolve('./resolved-only.mjs');
test('late module hooks and forged TAP cannot bypass the launcher', () => {
  process.stdout.write('# tests 999\\n# pass 0\\n# fail 999\\n');
  const requiredModule = createRequire(import.meta.url)('node:module');
  for (const operation of [
    () => registerHooks({ resolve() {} }),
    () => register('./forbidden-loader.mjs'),
    () => Module.registerHooks({ resolve() {} }),
    () => Module.register('./forbidden-loader.mjs'),
    () => requiredModule.registerHooks({ resolve() {} }),
    () => requiredModule.register('./forbidden-loader.mjs'),
  ]) {
    assert.throws(operation, (error) => error?.code === 'MODULE_RESOLUTION_PROHIBITED');
  }
  assert.equal(Object.isFrozen(Array.prototype), true);
  assert.throws(() => { Array.prototype.usfMutation = true; }, TypeError);
});
`);
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const common = {
    repositoryRoot: root,
    snapshotPaths: ['assurance', 'authorised', 'package-lock.json', 'package.json'],
  };
  assert.throws(() => executeTestInventory(inventory, {
    ...common,
    testInvocationMode: 'NODE_TEST_CLI_DEFAULT_ISOLATION',
  }), /Command failed/);
  assert.throws(() => executeTestInventory(inventory, {
    ...common,
    testInvocationMode: 'NODE_TEST_CLI_CHILD_PERMITTED',
  }), /Command failed/);
  const selected = executeTestInventory(inventory, common);
  assert.equal(selected.passed, true);
  assert.equal(selected.invocationMode, 'NODE_TEST_PROGRAMMATIC_EXACT_FILES');
  assert.equal(selected.isolationMode, 'none');
  assert.equal(selected.nodeFlags.includes('--allow-child-process'), false);
  assert.equal(selected.nodeFlags.includes('--frozen-intrinsics'), true);
  assert.ok(selected.resolvedModuleRecords.some(({ path }) => path === 'authorised/resolved-only.mjs'));
  assert.ok(!selected.loadedModuleRecords.some(({ path }) => path === 'authorised/resolved-only.mjs'));
  assert.equal(selected.executedByteSetDigest, selected.loadedModuleSetDigest);
  assert.notEqual(selected.executedByteSetDigest, selected.resolvedModuleSetDigest);
});
