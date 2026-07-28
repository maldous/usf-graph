import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import {
  assertWorktreeMatchesSnapshot,
  buildSanitizedExecutionEnvironment,
  collectNodeRuntimeClosure,
  collectProcessRuntimeClosure,
  compareWorktreeToSnapshot,
  readTrackedTreeSnapshot,
  runCommittedNodeClosure,
  runtimeDescriptorFromEvidence,
  sha256,
} from './authority-execution-hermeticity.mjs';

function git(repository, args, { allowFailure = false, replaceObjects = true } = {}) {
  const environment = {
    HOME: repository,
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
    GIT_AUTHOR_EMAIL: 'hermeticity@example.invalid',
    GIT_AUTHOR_NAME: 'Hermeticity Test',
    GIT_COMMITTER_EMAIL: 'hermeticity@example.invalid',
    GIT_COMMITTER_NAME: 'Hermeticity Test',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    ...(replaceObjects ? {} : { GIT_NO_REPLACE_OBJECTS: '1' }),
  };
  const result = spawnSync('/usr/bin/git', args, {
    cwd: repository,
    env: environment,
    encoding: null,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (!allowFailure && (result.error || result.signal || result.status !== 0)) {
    throw new Error(
      `git ${args.join(' ')} failed: ${Buffer.from(result.stderr || '').toString('utf8')}`,
    );
  }
  return result;
}

function makeRepository() {
  const repository = mkdtempSync(join(tmpdir(), 'usf-hermeticity-repository-'));
  git(repository, ['init', '--quiet']);
  writeFileSync(
    join(repository, 'script.mjs'),
    'import { value } from "./dependency.mjs";\nprocess.stdout.write(`${value}\\n`);\n',
    { mode: 0o755 },
  );
  writeFileSync(join(repository, 'dependency.mjs'), 'export const value = "ORIGINAL";\n');
  writeFileSync(join(repository, 'hidden.txt'), 'COMMITTED\n');
  writeFileSync(join(repository, 'package.json'), '{"private":true,"type":"module"}\n');
  mkdirSync(join(repository, 'nested'));
  writeFileSync(join(repository, 'nested', 'file.txt'), 'NESTED\n');
  git(repository, ['add', '.']);
  git(repository, ['commit', '--quiet', '-m', 'original']);
  const commit = git(repository, ['rev-parse', 'HEAD']).stdout.toString('utf8').trim();
  return { repository, commit };
}

function spawned(child) {
  return new Promise((resolveSpawn, rejectSpawn) => {
    child.once('spawn', resolveSpawn);
    child.once('error', rejectSpawn);
  });
}

function closed(child) {
  return new Promise((resolveClose) => {
    child.once('close', (status, signal) => resolveClose({ status, signal }));
  });
}

let expectedGitRuntimePromise;
async function expectedGitRuntime() {
  if (!expectedGitRuntimePromise) {
    expectedGitRuntimePromise = (async () => {
      const repository = mkdtempSync(join(tmpdir(), 'usf-hermeticity-git-runtime-'));
      git(repository, ['init', '--bare', '--quiet']);
      const child = spawn('/usr/bin/git', [`--git-dir=${repository}`, 'cat-file', '--batch'], {
        cwd: repository,
        env: {
          HOME: '/tmp',
          LANG: 'C',
          LC_ALL: 'C',
          PATH: '/usr/bin:/bin',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_NO_REPLACE_OBJECTS: '1',
          GIT_TERMINAL_PROMPT: '0',
        },
        stdio: ['pipe', 'ignore', 'ignore'],
      });
      const closePromise = closed(child);
      await spawned(child);
      let evidence;
      let lastError;
      for (let attempt = 0; attempt < 100; attempt += 1) {
        try {
          evidence = collectProcessRuntimeClosure({ pid: child.pid });
          break;
        } catch (error) {
          lastError = error;
          await new Promise((resolveDelay) => setTimeout(resolveDelay, 5));
        }
      }
      child.kill('SIGKILL');
      await closePromise;
      rmSync(repository, { recursive: true, force: true });
      if (!evidence) throw new Error(`TEST_GIT_RUNTIME_NOT_OBSERVED:${lastError?.message}`);
      return runtimeDescriptorFromEvidence(evidence);
    })();
  }
  return expectedGitRuntimePromise;
}

const expectedNodeRuntime = runtimeDescriptorFromEvidence(collectNodeRuntimeClosure());
const closurePaths = ['dependency.mjs', 'package.json', 'script.mjs'];

async function snapshotFor(fixture, paths = closurePaths) {
  return readTrackedTreeSnapshot({
    repository: fixture.repository,
    commit: fixture.commit,
    paths,
    expectedGitRuntime: await expectedGitRuntime(),
  });
}

test('commit snapshot ignores repo-local config, hooks, filters, and fsmonitor', async () => {
  const fixture = makeRepository();
  try {
    const hooks = join(fixture.repository, 'malicious-hooks');
    mkdirSync(hooks);
    writeFileSync(join(hooks, 'post-checkout'), '#!/bin/sh\nexit 91\n', { mode: 0o755 });
    git(fixture.repository, ['config', '--local', 'core.hooksPath', hooks]);
    git(fixture.repository, ['config', '--local', 'core.fsmonitor', '/bin/false']);
    git(fixture.repository, ['config', '--local', 'filter.hostile.smudge', '/bin/false']);
    git(fixture.repository, ['config', '--local', 'filter.hostile.clean', '/bin/false']);
    const snapshot = await snapshotFor(fixture, ['hidden.txt', 'script.mjs']);
    assert.equal(snapshot.records[0].bytes.toString('utf8'), 'COMMITTED\n');
    assert.match(snapshot.evidence.gitExecution.executable.digest, /^sha256:[0-9a-f]{64}$/);
    assert.notEqual(snapshot.evidence.gitExecution.runtime.pid, process.pid);
    assert.ok(snapshot.evidence.gitExecution.runtimeExecutions.length >= 3);
    const gitRuntime = await expectedGitRuntime();
    assert.ok(snapshot.evidence.gitExecution.runtimeExecutions.every((runtime) => (
      runtime.pid !== process.pid
      && runtimeDescriptorFromEvidence(runtime).mappedNativeObjectSetDigest
        === gitRuntime.mappedNativeObjectSetDigest
    )));
    assert.deepEqual(
      runtimeDescriptorFromEvidence(snapshot.evidence.gitExecution.runtime),
      await expectedGitRuntime(),
    );
    assert.equal(snapshot.evidence.gitExecution.originalLocalConfigLoaded, false);
    assert.equal(snapshot.evidence.gitExecution.originalIndexLoaded, false);
    assert.equal(snapshot.evidence.gitExecution.originalHooksLoaded, false);
    assert.equal(snapshot.evidence.gitExecution.replaceObjectsDisabled, true);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('replace refs cannot redirect the commit snapshot', async () => {
  const fixture = makeRepository();
  try {
    writeFileSync(join(fixture.repository, 'script.mjs'), 'process.stdout.write("REPLACED\\n");\n', { mode: 0o755 });
    git(fixture.repository, ['add', 'script.mjs']);
    git(fixture.repository, ['commit', '--quiet', '-m', 'replacement']);
    const replacement = git(fixture.repository, ['rev-parse', 'HEAD']).stdout.toString('utf8').trim();
    git(fixture.repository, ['replace', fixture.commit, replacement]);
    assert.equal(
      git(fixture.repository, ['show', `${fixture.commit}:script.mjs`]).stdout.toString('utf8'),
      'process.stdout.write("REPLACED\\n");\n',
    );
    const snapshot = await snapshotFor(fixture, ['script.mjs']);
    assert.match(snapshot.records[0].bytes.toString('utf8'), /dependency\.mjs/);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('skip-worktree and assume-unchanged cannot hide changed source bytes', async () => {
  const fixture = makeRepository();
  try {
    const snapshot = await snapshotFor(fixture, ['hidden.txt', 'script.mjs']);
    git(fixture.repository, ['update-index', '--assume-unchanged', 'hidden.txt']);
    git(fixture.repository, ['update-index', '--skip-worktree', 'script.mjs']);
    writeFileSync(join(fixture.repository, 'hidden.txt'), 'HIDDEN DIRTY\n');
    writeFileSync(join(fixture.repository, 'script.mjs'), 'process.stdout.write("HIDDEN DIRTY\\n");\n', { mode: 0o755 });
    assert.equal(git(fixture.repository, ['status', '--porcelain=v1']).stdout.toString('utf8'), '');
    const comparison = compareWorktreeToSnapshot({ repository: fixture.repository, snapshot });
    assert.equal(comparison.matches, false);
    assert.deepEqual(
      comparison.results.filter(({ matches }) => !matches).map(({ path }) => path),
      ['hidden.txt', 'script.mjs'],
    );
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('intermediate symlinks are refused even when target bytes match', async () => {
  const fixture = makeRepository();
  const external = mkdtempSync(join(tmpdir(), 'usf-hermeticity-external-'));
  try {
    const snapshot = await snapshotFor(fixture, ['nested/file.txt']);
    writeFileSync(join(external, 'file.txt'), 'NESTED\n');
    renameSync(join(fixture.repository, 'nested'), join(fixture.repository, 'nested.real'));
    symlinkSync(external, join(fixture.repository, 'nested'));
    const comparison = compareWorktreeToSnapshot({ repository: fixture.repository, snapshot });
    assert.equal(comparison.matches, false);
    assert.match(comparison.results[0].error, /SYMLINK_COMPONENT/);
    assert.throws(
      () => assertWorktreeMatchesSnapshot({ repository: fixture.repository, snapshot }),
      /WORKTREE_DOES_NOT_MATCH_COMMIT_SNAPSHOT/,
    );
  } finally {
    rmSync(external, { recursive: true, force: true });
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('hard-linked worktree source is refused', async () => {
  const fixture = makeRepository();
  try {
    const snapshot = await snapshotFor(fixture, ['hidden.txt']);
    linkSync(join(fixture.repository, 'hidden.txt'), join(fixture.repository, 'hidden.link'));
    const comparison = compareWorktreeToSnapshot({ repository: fixture.repository, snapshot });
    assert.equal(comparison.matches, false);
    assert.match(comparison.results[0].error, /LINK_COUNT_NOT_ONE/);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('complete committed dependency closure executes independently of mutable checkout', async () => {
  const fixture = makeRepository();
  try {
    const snapshot = await snapshotFor(fixture);
    writeFileSync(join(fixture.repository, 'dependency.mjs'), 'export const value = "SUBSTITUTED";\n');
    const result = await runCommittedNodeClosure({
      snapshot,
      closurePaths,
      entryPath: 'script.mjs',
      expectedNodeRuntime,
    });
    assert.equal(result.stdout.toString('utf8'), 'ORIGINAL\n');
    assert.equal(result.closure.recordCount, 3);
    assert.notEqual(result.runtimeEvidence.pid, process.pid);
    assert.deepEqual(result.runtimeDescriptor, expectedNodeRuntime);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('dependency substitution after child binding cannot execute', async () => {
  const fixture = makeRepository();
  try {
    const snapshot = await snapshotFor(fixture);
    await assert.rejects(runCommittedNodeClosure({
      snapshot,
      closurePaths,
      entryPath: 'script.mjs',
      expectedNodeRuntime,
      afterRuntimeBound(closure) {
        const dependency = join(closure.root, 'dependency.mjs');
        chmodSync(closure.root, 0o700);
        chmodSync(dependency, 0o600);
        writeFileSync(dependency, 'export const value = "SUBSTITUTED";\n');
      },
    }), /COMMITTED_NODE_CLOSURE_FAILED|CLOSURE_FILE_CHANGED/);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('caller cannot omit a committed dependency from the declared source set', async () => {
  const fixture = makeRepository();
  let materialized = false;
  try {
    const snapshot = await snapshotFor(fixture);
    await assert.rejects(runCommittedNodeClosure({
      snapshot,
      closurePaths: ['package.json', 'script.mjs'],
      entryPath: 'script.mjs',
      expectedNodeRuntime,
      afterMaterialize() {
        materialized = true;
      },
    }), /CLOSURE_PATH_SET_MISMATCH/);
    assert.equal(materialized, false);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('a snapshot that omits an imported dependency fails closed in the private root', async () => {
  const fixture = makeRepository();
  try {
    const snapshot = await snapshotFor(fixture, ['package.json', 'script.mjs']);
    await assert.rejects(runCommittedNodeClosure({
      snapshot,
      closurePaths: ['package.json', 'script.mjs'],
      entryPath: 'script.mjs',
      expectedNodeRuntime,
    }), /COMMITTED_NODE_CLOSURE_FAILED/);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('Node permission boundary refuses mutable dependencies outside the committed closure', async () => {
  const fixture = makeRepository();
  const external = mkdtempSync(join(tmpdir(), 'usf-hermeticity-external-module-'));
  const marker = join(external, 'executed.marker');
  try {
    writeFileSync(
      join(fixture.repository, 'script.mjs'),
      [
        'import { createRequire } from "node:module";',
        'const require = createRequire(import.meta.url);',
        'require(process.argv[2]);',
      ].join('\n'),
      { mode: 0o755 },
    );
    writeFileSync(
      join(external, 'mutable.cjs'),
      `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");\n`,
    );
    git(fixture.repository, ['add', 'script.mjs']);
    git(fixture.repository, ['commit', '--quiet', '-m', 'external dependency adversary']);
    fixture.commit = git(fixture.repository, ['rev-parse', 'HEAD']).stdout.toString('utf8').trim();
    const snapshot = await snapshotFor(fixture, ['package.json', 'script.mjs']);
    await assert.rejects(runCommittedNodeClosure({
      snapshot,
      closurePaths: ['package.json', 'script.mjs'],
      entryPath: 'script.mjs',
      expectedNodeRuntime,
      arguments: [join(external, 'mutable.cjs')],
    }), /COMMITTED_NODE_CLOSURE_FAILED/);
    assert.throws(() => readFileSync(marker), /ENOENT/);
  } finally {
    rmSync(external, { recursive: true, force: true });
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('environment allowlist cannot override helper-owned controls', () => {
  const home = mkdtempSync(join(tmpdir(), 'usf-hermeticity-home-'));
  try {
    for (const [name, value] of [
      ['HOME', '/hostile'],
      ['XDG_CONFIG_HOME', '/hostile'],
      ['PATH', '/hostile'],
      ['NODE_OPTIONS', '--require=/tmp/hostile.cjs'],
      ['NODE_PATH', '/hostile'],
      ['LD_PRELOAD', '/tmp/hostile.so'],
      ['OPENSSL_CONF', '/tmp/hostile.cnf'],
      ['LANG', 'hostile'],
      ['LC_ALL', 'hostile'],
      ['TZ', 'hostile'],
    ]) {
      assert.throws(() => buildSanitizedExecutionEnvironment({
        homeDirectory: home,
        allowedEnvironmentNames: [name],
        explicitEnvironment: { [name]: value },
      }), new RegExp(`RESERVED_ENVIRONMENT_NAME_${name}`));
    }
    assert.throws(() => buildSanitizedExecutionEnvironment({
      homeDirectory: home,
      explicitEnvironment: { USF_PUBLIC_INPUT: 'bounded' },
    }), /ENVIRONMENT_NAME_NOT_ALLOWLISTED_USF_PUBLIC_INPUT/);
    const environment = buildSanitizedExecutionEnvironment({
      homeDirectory: home,
      allowedEnvironmentNames: ['USF_PUBLIC_INPUT'],
      explicitEnvironment: { USF_PUBLIC_INPUT: 'bounded' },
    });
    assert.equal(environment.HOME, home);
    assert.equal(environment.XDG_CONFIG_HOME, join(home, '.config'));
    assert.equal(environment.PATH, '');
    assert.equal(environment.NODE_OPTIONS, '');
    assert.equal(environment.OPENSSL_CONF, '/dev/null');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('wrong expected Node runtime digest fails before materialisation or execution', async () => {
  const fixture = makeRepository();
  let materialized = false;
  try {
    const snapshot = await snapshotFor(fixture);
    const wrong = structuredClone(expectedNodeRuntime);
    wrong.executable.digest = sha256('wrong executable');
    const executableIndex = wrong.mappedNativeObjects
      .findIndex(({ path }) => path === wrong.executable.path);
    wrong.mappedNativeObjects[executableIndex] = wrong.executable;
    wrong.mappedNativeObjectSetDigest = sha256(JSON.stringify(wrong.mappedNativeObjects));
    await assert.rejects(runCommittedNodeClosure({
      snapshot,
      closurePaths,
      entryPath: 'script.mjs',
      expectedNodeRuntime: wrong,
      afterMaterialize() {
        materialized = true;
      },
    }), /NODE_RUNTIME_(?:SET_DIGEST_MISMATCH|EXPECTED_OBJECT_CHANGED)/);
    assert.equal(materialized, false);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('wrong expected Git runtime digest fails before repository execution', async () => {
  const fixture = makeRepository();
  try {
    const wrong = structuredClone(await expectedGitRuntime());
    wrong.executable.digest = sha256('wrong git executable');
    const executableIndex = wrong.mappedNativeObjects
      .findIndex(({ path }) => path === wrong.executable.path);
    wrong.mappedNativeObjects[executableIndex] = wrong.executable;
    wrong.mappedNativeObjectSetDigest = sha256(JSON.stringify(wrong.mappedNativeObjects));
    await assert.rejects(readTrackedTreeSnapshot({
      repository: fixture.repository,
      commit: fixture.commit,
      paths: ['script.mjs'],
      expectedGitRuntime: wrong,
    }), /GIT_RUNTIME_(?:SET_DIGEST_MISMATCH|EXPECTED_OBJECT_CHANGED)/);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('Node runtime evidence identifies the executed child and mapped objects', async () => {
  const fixture = makeRepository();
  try {
    const snapshot = await snapshotFor(fixture);
    const result = await runCommittedNodeClosure({
      snapshot,
      closurePaths,
      entryPath: 'script.mjs',
      expectedNodeRuntime,
    });
    assert.ok(Number.isInteger(result.runtimeEvidence.pid));
    assert.notEqual(result.runtimeEvidence.pid, process.pid);
    assert.equal(
      result.runtimeEvidence.mappedNativeObjectCount,
      result.runtimeEvidence.mappedNativeObjects.length,
    );
    assert.ok(result.runtimeEvidence.mappedNativeObjects.every((record) => (
      record.identity === undefined
      && record.path
      && record.digest
      && record.device
      && record.inode
      && record.linkCount === '1'
    )));
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('executable-mode drift is detected independently from content', async () => {
  const fixture = makeRepository();
  try {
    const snapshot = await snapshotFor(fixture, ['script.mjs']);
    chmodSync(join(fixture.repository, 'script.mjs'), 0o644);
    const comparison = compareWorktreeToSnapshot({ repository: fixture.repository, snapshot });
    assert.equal(comparison.matches, false);
    assert.equal(comparison.results[0].expectedDigest, comparison.results[0].observedDigest);
    assert.equal(comparison.results[0].expectedMode, '100755');
    assert.equal(comparison.results[0].observedMode, '100644');
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});
