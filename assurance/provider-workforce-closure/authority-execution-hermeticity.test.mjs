import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  assertWorktreeMatchesSnapshot,
  buildSanitizedExecutionEnvironment,
  collectNodeRuntimeClosure,
  compareWorktreeToSnapshot,
  readTrackedTreeSnapshot,
  runPinnedNodeScript,
  sha256,
} from './authority-execution-hermeticity.mjs';

function git(repository, args, { allowFailure = false, replaceObjects = true } = {}) {
  const environment = {
    HOME: repository,
    LANG: 'C',
    LC_ALL: 'C',
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
  writeFileSync(join(repository, 'script.mjs'), 'process.stdout.write("ORIGINAL\\n");\n', { mode: 0o755 });
  writeFileSync(join(repository, 'hidden.txt'), 'COMMITTED\n');
  git(repository, ['add', 'script.mjs', 'hidden.txt']);
  git(repository, ['commit', '--quiet', '-m', 'original']);
  const commit = git(repository, ['rev-parse', 'HEAD']).stdout.toString('utf8').trim();
  return { repository, commit };
}

test('commit snapshot is independent of repo-local config, hooks, filters, and fsmonitor', () => {
  const fixture = makeRepository();
  try {
    const hooks = join(fixture.repository, 'malicious-hooks');
    mkdirSync(hooks);
    writeFileSync(join(hooks, 'post-checkout'), '#!/bin/sh\nexit 91\n', { mode: 0o755 });
    git(fixture.repository, ['config', '--local', 'core.hooksPath', hooks]);
    git(fixture.repository, ['config', '--local', 'core.fsmonitor', '/bin/false']);
    git(fixture.repository, ['config', '--local', 'filter.hostile.smudge', '/bin/false']);
    git(fixture.repository, ['config', '--local', 'filter.hostile.clean', '/bin/false']);
    const snapshot = readTrackedTreeSnapshot({
      repository: fixture.repository,
      commit: fixture.commit,
      paths: ['script.mjs', 'hidden.txt'],
    });
    assert.equal(snapshot.records[0].bytes.toString('utf8'), 'COMMITTED\n');
    assert.equal(snapshot.records[1].bytes.toString('utf8'), 'process.stdout.write("ORIGINAL\\n");\n');
    assert.deepEqual({
      ...snapshot.evidence.gitExecution,
      executable: undefined,
    }, {
      configurationSource: 'ISOLATED_GIT_DIR_WITH_SOURCE_OBJECT_ALTERNATE',
      executable: undefined,
      originalLocalConfigLoaded: false,
      originalIndexLoaded: false,
      originalHooksLoaded: false,
      originalWorktreeLoaded: false,
      replaceObjectsDisabled: true,
      promptsDisabled: true,
    });
    assert.equal(snapshot.evidence.gitExecution.executable.path, '/usr/bin/git');
    assert.match(snapshot.evidence.gitExecution.executable.digest, /^sha256:[0-9a-f]{64}$/);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('replace refs cannot redirect the commit snapshot', () => {
  const fixture = makeRepository();
  try {
    writeFileSync(join(fixture.repository, 'script.mjs'), 'process.stdout.write("REPLACED\\n");\n', { mode: 0o755 });
    git(fixture.repository, ['add', 'script.mjs']);
    git(fixture.repository, ['commit', '--quiet', '-m', 'replacement']);
    const replacement = git(fixture.repository, ['rev-parse', 'HEAD']).stdout.toString('utf8').trim();
    git(fixture.repository, ['replace', fixture.commit, replacement]);
    const redirected = git(fixture.repository, ['show', `${fixture.commit}:script.mjs`])
      .stdout.toString('utf8');
    assert.equal(redirected, 'process.stdout.write("REPLACED\\n");\n');
    const snapshot = readTrackedTreeSnapshot({
      repository: fixture.repository,
      commit: fixture.commit,
      paths: ['script.mjs'],
    });
    assert.equal(snapshot.records[0].bytes.toString('utf8'), 'process.stdout.write("ORIGINAL\\n");\n');
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('skip-worktree and assume-unchanged cannot hide changed source from byte verification', () => {
  const fixture = makeRepository();
  try {
    const snapshot = readTrackedTreeSnapshot({
      repository: fixture.repository,
      commit: fixture.commit,
      paths: ['hidden.txt', 'script.mjs'],
    });
    git(fixture.repository, ['update-index', '--assume-unchanged', 'hidden.txt']);
    git(fixture.repository, ['update-index', '--skip-worktree', 'script.mjs']);
    writeFileSync(join(fixture.repository, 'hidden.txt'), 'HIDDEN DIRTY\n');
    writeFileSync(join(fixture.repository, 'script.mjs'), 'process.stdout.write("HIDDEN DIRTY\\n");\n', { mode: 0o755 });
    const status = git(fixture.repository, ['status', '--porcelain=v1']).stdout.toString('utf8');
    assert.equal(status, '');
    const comparison = compareWorktreeToSnapshot({
      repository: fixture.repository,
      snapshot,
    });
    assert.equal(comparison.matches, false);
    assert.deepEqual(
      comparison.results.filter(({ matches }) => !matches).map(({ path }) => path),
      ['hidden.txt', 'script.mjs'],
    );
    assert.throws(
      () => assertWorktreeMatchesSnapshot({ repository: fixture.repository, snapshot }),
      /WORKTREE_DOES_NOT_MATCH_COMMIT_SNAPSHOT/,
    );
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('pinned Node execution uses opened committed bytes during pathname substitution', () => {
  const fixture = makeRepository();
  try {
    const snapshot = readTrackedTreeSnapshot({
      repository: fixture.repository,
      commit: fixture.commit,
      paths: ['script.mjs'],
    });
    const record = snapshot.records[0];
    const path = join(fixture.repository, 'script.mjs');
    const displaced = join(fixture.repository, 'script.original.mjs');
    const result = runPinnedNodeScript({
      scriptPath: path,
      expectedDigest: record.digest,
      expectedByteLength: record.byteLength,
      requireStablePath: false,
      afterPin() {
        renameSync(path, displaced);
        writeFileSync(path, 'process.stdout.write("SUBSTITUTED\\n");\n', { mode: 0o755 });
      },
    });
    assert.equal(result.stdout.toString('utf8'), 'ORIGINAL\n');
    assert.equal(result.script.pathStable, false);
    assert.equal(readFileSync(path, 'utf8'), 'process.stdout.write("SUBSTITUTED\\n");\n');
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('stable-path enforcement fails closed after pathname substitution', () => {
  const fixture = makeRepository();
  try {
    const snapshot = readTrackedTreeSnapshot({
      repository: fixture.repository,
      commit: fixture.commit,
      paths: ['script.mjs'],
    });
    const record = snapshot.records[0];
    const path = join(fixture.repository, 'script.mjs');
    assert.throws(() => runPinnedNodeScript({
      scriptPath: path,
      expectedDigest: record.digest,
      expectedByteLength: record.byteLength,
      afterPin() {
        renameSync(path, join(fixture.repository, 'script.original.mjs'));
        writeFileSync(path, 'process.stdout.write("SUBSTITUTED\\n");\n', { mode: 0o755 });
      },
    }), /PINNED_NODE_SCRIPT_PATH_CHANGED/);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('Node execution rejects unexpected bytes before contact', () => {
  const fixture = makeRepository();
  try {
    assert.throws(() => runPinnedNodeScript({
      scriptPath: join(fixture.repository, 'script.mjs'),
      expectedDigest: sha256('different'),
    }), /NODE_SCRIPT_COMMIT_DIGEST_MISMATCH/);
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});

test('sanitized environments reject process-influencing variables', () => {
  const home = mkdtempSync(join(tmpdir(), 'usf-hermeticity-home-'));
  try {
    assert.throws(() => buildSanitizedExecutionEnvironment({
      homeDirectory: home,
      explicitEnvironment: { NODE_OPTIONS: '--require=/tmp/hostile.cjs' },
    }), /UNSAFE_ENVIRONMENT_NAME_NODE_OPTIONS/);
    const environment = buildSanitizedExecutionEnvironment({
      homeDirectory: home,
      includeGitControls: true,
      explicitEnvironment: { USF_PUBLIC_INPUT: 'bounded' },
    });
    assert.equal(environment.GIT_NO_REPLACE_OBJECTS, '1');
    assert.equal(environment.GIT_TERMINAL_PROMPT, '0');
    assert.equal(environment.USF_PUBLIC_INPUT, 'bounded');
    assert.equal('PATH' in environment, false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('Node runtime closure binds executable and every mapped native object', () => {
  const closure = collectNodeRuntimeClosure();
  assert.equal(closure.schemaVersion, 1);
  assert.match(closure.executable.digest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(closure.mappedNativeObjectCount > 0);
  assert.equal(closure.mappedNativeObjectCount, closure.mappedNativeObjects.length);
  assert.match(closure.mappedNativeObjectSetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(closure.mappedNativeObjects.every(({ digest }) => /^sha256:[0-9a-f]{64}$/.test(digest)));
});

test('executable-mode drift is detected independently from content', () => {
  const fixture = makeRepository();
  try {
    const snapshot = readTrackedTreeSnapshot({
      repository: fixture.repository,
      commit: fixture.commit,
      paths: ['script.mjs'],
    });
    chmodSync(join(fixture.repository, 'script.mjs'), 0o644);
    const comparison = compareWorktreeToSnapshot({
      repository: fixture.repository,
      snapshot,
    });
    assert.equal(comparison.matches, false);
    assert.equal(comparison.results[0].expectedDigest, comparison.results[0].observedDigest);
    assert.equal(comparison.results[0].expectedMode, '100755');
    assert.equal(comparison.results[0].observedMode, '100644');
  } finally {
    rmSync(fixture.repository, { recursive: true, force: true });
  }
});
