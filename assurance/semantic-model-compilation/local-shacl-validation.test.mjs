import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { validateLocalShaclRuntime } from './local-shacl-validation.mjs';

const roots = [];

function runtimeFixture() {
  const root = mkdtempSync(join(tmpdir(), 'local-shacl-runtime-'));
  const resolvedExecutablePath = join(root, 'python3.11');
  const executablePath = resolvedExecutablePath;
  writeFileSync(resolvedExecutablePath, '# deterministic local SHACL runtime fixture\n', { mode: 0o500 });
  const executableDigest = `sha256:${createHash('sha256').update(readFileSync(resolvedExecutablePath)).digest('hex')}`;
  roots.push(root);
  return { executablePath, resolvedExecutablePath, executableDigest };
}

test.after(() => roots.forEach((root) => rmSync(root, { recursive: true, force: true })));

test('accepts only an exact Python launcher, resolved executable and digest binding', () => {
  const runtime = runtimeFixture();
  assert.deepEqual(validateLocalShaclRuntime(runtime), runtime);
  assert.throws(() => validateLocalShaclRuntime(), /absolute launcher and resolved executable paths/);
  assert.throws(() => validateLocalShaclRuntime({ ...runtime, executableDigest: `sha256:${'0'.repeat(64)}` }), /digest mismatch/);
});

test('rejects a launcher whose resolved executable differs from its binding', () => {
  const runtime = runtimeFixture();
  const other = runtimeFixture();
  assert.throws(() => validateLocalShaclRuntime({
    ...runtime,
    resolvedExecutablePath: other.resolvedExecutablePath,
  }), /resolve to its declared executable/);
});
