import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { readIndependentParserEvidence } from '../audit/parser-evidence.mjs';
import { canonicalJson } from '../src/canonical.mjs';
import { readParserEvidence, writeParserEvidence } from '../src/parser-evidence.mjs';

const records = [
  {
    universe: 'repository-output', path: 'a.json', contentDigest: 'a'.repeat(64), formatKind: 'structured-json', syntaxKind: 'structured-json',
    parserMode: 'structural', parserImplementation: 'test', parserVersion: '1', pathContext: 'ordinary', cacheKey: 'b'.repeat(64), structuralCoverage: 'complete', unsupportedStructures: [],
    confidence: { level: 'high', score: 0.98, reasons: ['structural-parser-evidence'] },
    declarations: [{ kind: 'mapping', identifier: 'root', attributes: { nested: { retained: ['all', 'evidence'] } } }],
    relationships: [{ relationshipType: 'references', target: 'urn:test:target', attributes: { exact: true } }], inventory: { nested: [{ value: 1 }] }
  },
  ...['v2-compiler-implementation', 'v2-graph-authority', 'v2-support-provisioning'].map((universe, index) => ({
    universe, path: `v2/example-${index}.txt`, contentDigest: String(index + 1).repeat(64), formatKind: 'plain-text', syntaxKind: 'plain-text',
    parserMode: 'bounded-text', parserImplementation: 'test', parserVersion: '1', pathContext: 'ordinary', cacheKey: String(index + 4).repeat(64), structuralCoverage: 'partial', unsupportedStructures: ['unparsed-free-text'],
    confidence: { level: 'medium', score: 0.7, reasons: ['bounded-parser-evidence'] }, declarations: [], relationships: [], inventory: null
  }))
];

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'usf-parser-evidence-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('parser evidence shards deterministically preserve complete nested records', async (t) => {
  const root = temporaryRoot(t);
  const first = writeParserEvidence(root, records);
  const firstBytes = Object.fromEntries(first.shards.map((shard) => [shard.path, fs.readFileSync(path.join(root, shard.path))]));
  const production = await readParserEvidence(root);
  const independent = await readIndependentParserEvidence(root);
  assert.deepEqual(production.records, records);
  assert.deepEqual(independent.records, records);
  assert.deepEqual(production.records[0].declarations[0].attributes.nested.retained, ['all', 'evidence']);
  assert.equal(first.aggregate.recordCount, records.length);
  const second = writeParserEvidence(root, records);
  assert.deepEqual(second, first);
  for (const shard of second.shards) assert.deepEqual(fs.readFileSync(path.join(root, shard.path)), firstBytes[shard.path]);
  assert.equal(fs.existsSync(path.join(root, 'parser-results.jsonl')), false);
});

test('parser evidence rejects corrupted compressed content', async (t) => {
  const root = temporaryRoot(t); const manifest = writeParserEvidence(root, records);
  const target = path.join(root, manifest.shards[0].path); const bytes = fs.readFileSync(target); bytes[Math.floor(bytes.length / 2)] ^= 0xff; fs.writeFileSync(target, bytes);
  await assert.rejects(readParserEvidence(root), /parser evidence|incorrect data check|invalid distance/i);
  await assert.rejects(readIndependentParserEvidence(root), /parser evidence|incorrect data check|invalid distance/i);
});

test('parser evidence rejects canonical manifest count tampering', async (t) => {
  const root = temporaryRoot(t); writeParserEvidence(root, records);
  const target = path.join(root, 'parser-results/manifest.json'); const manifest = JSON.parse(fs.readFileSync(target, 'utf8')); manifest.shards[0].recordCount += 1; fs.writeFileSync(target, canonicalJson(manifest));
  await assert.rejects(readParserEvidence(root), /shard manifest mismatch/);
  await assert.rejects(readIndependentParserEvidence(root), /shard verification failed/);
});

test('parser evidence rejects unexpected shards and legacy monoliths', async (t) => {
  const root = temporaryRoot(t); writeParserEvidence(root, records); fs.writeFileSync(path.join(root, 'parser-results/unregistered.jsonl.gz'), 'unexpected');
  await assert.rejects(readParserEvidence(root), /missing or unexpected files/);
  fs.rmSync(path.join(root, 'parser-results/unregistered.jsonl.gz')); fs.writeFileSync(path.join(root, 'parser-results.jsonl'), '{}\n');
  await assert.rejects(readParserEvidence(root), /legacy monolithic/);
  await assert.rejects(readIndependentParserEvidence(root), /legacy monolithic/);
});
