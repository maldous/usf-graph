import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { Worker } from 'node:worker_threads';

import { discoverTestInventory, executeTestInventory, testRunnerInternals } from './test-runner.mjs';

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
    nodeExecutable: join(root, 'authorised', 'fake-node'),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
    nodeVersion: '22.23.1',
    execute: (executable, args, options) => {
      invocation = { executable, args, options };
      return `# usf-test-inventory ${JSON.stringify({ fileCount: 2, observedInventoryDigest: options.env.USF_TEST_INVENTORY_DIGEST, isolation: 'none' })}\nok 1 - alpha\nok 2 - beta\n# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n`;
    },
  });
  assert.equal(result.passed, true);
  assert.equal(result.discoveredFileCount, 2);
  assert.equal(result.testInventoryDigest, inventory.testInventoryDigest);
  assert.equal(result.executedTestInventoryDigest, inventory.testInventoryDigest);
  assert.equal(result.launcherObservedTestInventoryDigest, inventory.testInventoryDigest);
  assert.equal(result.launcherObservedTestFileCount, 2);
  assert.equal(result.authorisedRootSetDigest, inventory.authorisedRootSetDigest);
  assert.equal(invocation.args.includes('--net'), true);
  assert.equal(invocation.args.filter((value) => value.endsWith('.test.mjs')).length, 2);
  assert.equal(invocation.args.some((value) => /[*?\[\]]/.test(value)), false);
  assert.notEqual(invocation.options.cwd, root);
  assert.equal(invocation.args.filter((value) => value.endsWith('.test.mjs')).every((path) => path.startsWith(invocation.options.cwd)), true);
  assert.equal(result.nodeFlags.includes('--no-addons'), true);
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
    nodeVersion: '22.23.1',
    execute: () => { invoked = true; return ''; },
  }), 'INVENTORY_DIGEST_CHANGED');
  assert.equal(invoked, false);
});

test('executes immutable staged bytes when the workspace changes after staging', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  let observed;
  const result = executeTestInventory(inventory, {
    repositoryRoot: root,
    nodeExecutable: join(root, 'authorised', 'fake-node'),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
    nodeVersion: '22.23.1',
    beforeExecute: () => writeFileSync(join(root, 'authorised', 'alpha.test.mjs'), "throw new Error('workspace mutation must not execute');\n"),
    execute: (_executable, args, options) => {
      const stagedAlpha = args.find((path) => path.endsWith('/authorised/alpha.test.mjs'));
      observed = readFileSync(stagedAlpha, 'utf8');
      return `# usf-test-inventory ${JSON.stringify({ fileCount: 2, observedInventoryDigest: options.env.USF_TEST_INVENTORY_DIGEST, isolation: 'none' })}\nok 1 - alpha\nok 2 - beta\n# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n`;
    },
  });
  assert.match(observed, /test\('alpha'/);
  assert.equal(result.testInventoryDigest, result.executedTestInventoryDigest);
});

test('rejects missing, duplicate and mismatched launcher inventory records', () => {
  const root = fixture();
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const common = {
    repositoryRoot: root,
    nodeExecutable: join(root, 'authorised', 'fake-node'),
    networkIsolator: join(root, 'authorised', 'fake-node'),
    nativeRuntimePaths: [],
    launcherRelativePath: 'authorised/fake-launcher.mjs',
    nodeVersion: '22.23.1',
  };
  const tap = '# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
  expectCode(() => executeTestInventory(inventory, { ...common, execute: () => tap }), 'INVENTORY_DIGEST_CHANGED');
  const line = `# usf-test-inventory ${JSON.stringify({ fileCount: 2, observedInventoryDigest: inventory.testInventoryDigest, isolation: 'none' })}\n`;
  expectCode(() => executeTestInventory(inventory, { ...common, execute: () => `${line}${line}${tap}` }), 'INVENTORY_DIGEST_CHANGED');
  const mismatch = `# usf-test-inventory ${JSON.stringify({ fileCount: 2, observedInventoryDigest: testRunnerInternals.sha256('wrong'), isolation: 'none' })}\n`;
  expectCode(() => executeTestInventory(inventory, { ...common, execute: () => `${mismatch}${tap}` }), 'INVENTORY_DIGEST_CHANGED');
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
  const inventory = discoverTestInventory({ repositoryRoot: root, authorisedRoots: ['authorised'] });
  const common = {
    repositoryRoot: root,
    snapshotPaths: ['assurance', 'authorised', 'package-lock.json', 'package.json'],
    nodeVersion: '22.23.1',
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
});
