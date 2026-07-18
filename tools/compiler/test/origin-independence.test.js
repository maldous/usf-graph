import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectOriginText } from '../src/origin-independence.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

test('origin independence rejects the isolated negative corpus', () => {
  const path = join(fixtures, 'defects', 'external-origin-dependency.fixture.js');
  const findings = inspectOriginText(readFileSync(path, 'utf8'), path);
  assert.ok(findings.length >= 6);
});

test('origin independence accepts semantic and integrity identifiers', () => {
  const path = join(fixtures, 'conforming', 'external-origin-independent.fixture.js');
  assert.deepEqual(inspectOriginText(readFileSync(path, 'utf8'), path), []);
});
