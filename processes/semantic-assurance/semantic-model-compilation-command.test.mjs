import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  SEMANTIC_MODEL_PATH,
  createSemanticModelCompilationCommand,
} from './semantic-model-compilation-command.mjs';

const authorityDigest = `sha256:${'a'.repeat(64)}`;
const repositories = [];

function repository() {
  const root = mkdtempSync(join(tmpdir(), 'usf-semantic-assurance-'));
  mkdirSync(join(root, SEMANTIC_MODEL_PATH));
  repositories.push(root);
  return root;
}

test.after(() => repositories.forEach((root) => rmSync(root, { recursive: true, force: true })));

function client() { return { connectivity: async () => 1 }; }

test('validates the canonical semantic model with an exact authority binding', async () => {
  const calls = [];
  const command = createSemanticModelCompilationCommand({
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    loadManifestFunction: (path) => ({ path }),
    compileFunction: async (input) => { calls.push(input); return { ok: true, commitOutcome: { state: 'validated-rolled-back' } }; },
  });
  const result = await command.execute({ expectedAuthorityDigest: authorityDigest });
  assert.equal(result.semanticModelPath, SEMANTIC_MODEL_PATH);
  assert.equal(result.evaluatedAuthorityDigest, authorityDigest);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].publicationMode, 'validate');
  assert.ok(calls[0].manifest.path.endsWith(`/${SEMANTIC_MODEL_PATH}`));
});

test('fails before loading or compiling when authority drift is observed', async () => {
  let loaded = false;
  const command = createSemanticModelCompilationCommand({
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: `sha256:${'b'.repeat(64)}` }),
    loadManifestFunction: () => { loaded = true; },
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({ expectedAuthorityDigest: authorityDigest }), /drifted before compilation/);
  assert.equal(loaded, false);
});

test('detects mutation during a validate-only transaction', async () => {
  let reads = 0;
  const command = createSemanticModelCompilationCommand({
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: reads++ === 0 ? authorityDigest : `sha256:${'c'.repeat(64)}` }),
    loadManifestFunction: () => ({}),
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({ expectedAuthorityDigest: authorityDigest }), /validate-only compilation changed/);
});

test('requires an explicit digest and the canonical non-symlink path', async () => {
  const command = createSemanticModelCompilationCommand({
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    loadManifestFunction: () => ({}),
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({}), /expected authority digest/);
});
