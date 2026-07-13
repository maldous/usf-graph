import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import zlib from 'node:zlib';
import { canonicalJson, canonicalLine, compareBy } from './canonical.mjs';

export const parserEvidenceDirectory = 'parser-results';
export const parserEvidenceManifestPath = `${parserEvidenceDirectory}/manifest.json`;
export const parserEvidenceUniverses = Object.freeze([
  'repository-output',
  'v2-compiler-implementation',
  'v2-graph-authority',
  'v2-support-provisioning'
]);

const digestPattern = /^[a-f0-9]{64}$/;
const manifestKeys = ['aggregate', 'encoding', 'formatVersion', 'order', 'shards'];
const aggregateKeys = ['recordCount', 'uncompressedBytes', 'uncompressedSha256'];
const shardKeys = ['compressedBytes', 'compressedSha256', 'firstPath', 'lastPath', 'path', 'recordCount', 'uncompressedBytes', 'uncompressedSha256', 'universe'];

function assertExactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${label} fields are not closed`);
}

function shardPath(universe) {
  return `${parserEvidenceDirectory}/${universe}.jsonl.gz`;
}

function hashBuffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function buildShard(universe, records) {
  const ordered = records.slice().sort(compareBy(['path']));
  const raw = Buffer.from(ordered.map(canonicalLine).join(''), 'utf8');
  const compressed = zlib.gzipSync(raw, { level: 9, mtime: 0 });
  return {
    descriptor: {
      universe,
      path: shardPath(universe),
      recordCount: ordered.length,
      uncompressedBytes: raw.length,
      uncompressedSha256: hashBuffer(raw),
      compressedBytes: compressed.length,
      compressedSha256: hashBuffer(compressed),
      firstPath: ordered[0]?.path ?? null,
      lastPath: ordered.at(-1)?.path ?? null
    },
    compressed,
    raw
  };
}

export function createParserEvidence(records) {
  const unknownUniverses = [...new Set(records.map((record) => record.universe).filter((universe) => !parserEvidenceUniverses.includes(universe)))];
  if (unknownUniverses.length) throw new Error(`parser evidence has unknown universes: ${unknownUniverses.join(',')}`);
  const shards = parserEvidenceUniverses.map((universe) => buildShard(universe, records.filter((record) => record.universe === universe)));
  const aggregateHash = crypto.createHash('sha256');
  let aggregateBytes = 0;
  for (const shard of shards) {
    aggregateHash.update(shard.raw);
    aggregateBytes += shard.raw.length;
  }
  const manifest = {
    formatVersion: 1,
    encoding: 'gzip-jsonl',
    order: ['universe', 'path'],
    aggregate: {
      recordCount: records.length,
      uncompressedBytes: aggregateBytes,
      uncompressedSha256: aggregateHash.digest('hex')
    },
    shards: shards.map((shard) => shard.descriptor)
  };
  return { manifest, shards };
}

export function writeParserEvidence(root, records) {
  const evidence = createParserEvidence(records);
  const directory = path.join(root, parserEvidenceDirectory);
  fs.mkdirSync(directory, { recursive: true });
  const expectedNames = new Set(['manifest.json', ...evidence.shards.map((shard) => path.basename(shard.descriptor.path))]);
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isFile() || !expectedNames.has(entry.name)) fs.rmSync(path.join(directory, entry.name), { recursive: true, force: true });
  }
  for (const shard of evidence.shards) {
    const target = path.join(root, shard.descriptor.path);
    const temporary = `${target}.writing`;
    fs.writeFileSync(temporary, shard.compressed);
    fs.renameSync(temporary, target);
  }
  const manifestTarget = path.join(root, parserEvidenceManifestPath);
  const manifestTemporary = `${manifestTarget}.writing`;
  fs.writeFileSync(manifestTemporary, canonicalJson(evidence.manifest));
  fs.renameSync(manifestTemporary, manifestTarget);
  const legacy = path.join(root, 'parser-results.jsonl');
  if (fs.existsSync(legacy)) fs.unlinkSync(legacy);
  return evidence.manifest;
}

function validateManifest(manifest) {
  assertExactKeys(manifest, manifestKeys, 'parser evidence manifest');
  assertExactKeys(manifest.aggregate, aggregateKeys, 'parser evidence aggregate');
  if (manifest.formatVersion !== 1 || manifest.encoding !== 'gzip-jsonl' || JSON.stringify(manifest.order) !== JSON.stringify(['universe', 'path'])) throw new Error('parser evidence manifest contract mismatch');
  if (!Number.isSafeInteger(manifest.aggregate.recordCount) || manifest.aggregate.recordCount < 0 || !Number.isSafeInteger(manifest.aggregate.uncompressedBytes) || manifest.aggregate.uncompressedBytes < 0 || !digestPattern.test(manifest.aggregate.uncompressedSha256)) throw new Error('parser evidence aggregate is invalid');
  if (!Array.isArray(manifest.shards) || manifest.shards.length !== parserEvidenceUniverses.length) throw new Error('parser evidence shard set is incomplete');
  manifest.shards.forEach((shard, index) => {
    assertExactKeys(shard, shardKeys, `parser evidence shard ${index}`);
    const universe = parserEvidenceUniverses[index];
    if (shard.universe !== universe || shard.path !== shardPath(universe)) throw new Error(`parser evidence shard order or path mismatch: ${shard.universe}`);
    for (const field of ['recordCount', 'uncompressedBytes', 'compressedBytes']) if (!Number.isSafeInteger(shard[field]) || shard[field] < 0) throw new Error(`parser evidence shard ${field} invalid: ${universe}`);
    for (const field of ['uncompressedSha256', 'compressedSha256']) if (!digestPattern.test(shard[field])) throw new Error(`parser evidence shard ${field} invalid: ${universe}`);
    if (shard.recordCount === 0 ? shard.firstPath !== null || shard.lastPath !== null : typeof shard.firstPath !== 'string' || typeof shard.lastPath !== 'string') throw new Error(`parser evidence shard path bounds invalid: ${universe}`);
  });
  return manifest;
}

async function readShard(root, descriptor, aggregateHash, onRecord) {
  const target = path.join(root, descriptor.path);
  const stat = await fs.promises.stat(target).catch(() => null);
  if (!stat?.isFile()) throw new Error(`parser evidence shard missing: ${descriptor.path}`);
  if (stat.size !== descriptor.compressedBytes) throw new Error(`parser evidence compressed size mismatch: ${descriptor.path}`);
  const compressedHash = crypto.createHash('sha256');
  const uncompressedHash = crypto.createHash('sha256');
  const input = fs.createReadStream(target);
  input.on('data', (chunk) => compressedHash.update(chunk));
  const gunzip = zlib.createGunzip();
  input.pipe(gunzip);
  const lines = readline.createInterface({ input: gunzip, crlfDelay: Infinity });
  const records = [];
  let count = 0;
  let uncompressedBytes = 0;
  let previousPath = null;
  let firstPath = null;
  let lastPath = null;
  for await (const line of lines) {
    if (line.length === 0) throw new Error(`parser evidence contains a blank record: ${descriptor.path}`);
    const framed = Buffer.from(`${line}\n`, 'utf8');
    uncompressedHash.update(framed);
    aggregateHash.update(framed);
    uncompressedBytes += framed.length;
    let record;
    try { record = JSON.parse(line); } catch { throw new Error(`parser evidence JSON is invalid: ${descriptor.path}:${count + 1}`); }
    if (canonicalLine(record) !== `${line}\n`) throw new Error(`parser evidence record is not canonical: ${descriptor.path}:${count + 1}`);
    if (record.universe !== descriptor.universe) throw new Error(`parser evidence universe mismatch: ${record.path}`);
    if (typeof record.path !== 'string' || (previousPath !== null && previousPath.localeCompare(record.path) >= 0)) throw new Error(`parser evidence order or duplicate mismatch: ${record.path}`);
    firstPath ??= record.path;
    lastPath = record.path;
    previousPath = record.path;
    count += 1;
    records.push(record);
    if (onRecord) await onRecord(record);
  }
  if (compressedHash.digest('hex') !== descriptor.compressedSha256) throw new Error(`parser evidence compressed digest mismatch: ${descriptor.path}`);
  if (uncompressedHash.digest('hex') !== descriptor.uncompressedSha256) throw new Error(`parser evidence uncompressed digest mismatch: ${descriptor.path}`);
  if (count !== descriptor.recordCount || uncompressedBytes !== descriptor.uncompressedBytes || firstPath !== descriptor.firstPath || lastPath !== descriptor.lastPath) throw new Error(`parser evidence shard manifest mismatch: ${descriptor.path}`);
  return { records, count, uncompressedBytes };
}

export async function readParserEvidence(root, { onRecord } = {}) {
  const legacy = path.join(root, 'parser-results.jsonl');
  if (fs.existsSync(legacy)) throw new Error('legacy monolithic parser-results.jsonl is prohibited');
  const manifestTarget = path.join(root, parserEvidenceManifestPath);
  const manifestText = await fs.promises.readFile(manifestTarget, 'utf8').catch(() => null);
  if (manifestText === null) throw new Error('parser evidence manifest missing');
  let manifest;
  try { manifest = validateManifest(JSON.parse(manifestText)); } catch (error) { throw new Error(`parser evidence manifest invalid: ${error.message}`, { cause: error }); }
  if (manifestText !== canonicalJson(manifest)) throw new Error('parser evidence manifest is not canonical JSON');
  const directoryEntries = (await fs.promises.readdir(path.join(root, parserEvidenceDirectory), { withFileTypes: true })).filter((entry) => entry.isFile()).map((entry) => entry.name).sort();
  const expectedEntries = ['manifest.json', ...manifest.shards.map((shard) => path.basename(shard.path))].sort();
  if (JSON.stringify(directoryEntries) !== JSON.stringify(expectedEntries)) throw new Error('parser evidence directory contains missing or unexpected files');
  const aggregateHash = crypto.createHash('sha256');
  const records = [];
  let recordCount = 0;
  let uncompressedBytes = 0;
  for (const descriptor of manifest.shards) {
    const shard = await readShard(root, descriptor, aggregateHash, onRecord);
    records.push(...shard.records);
    recordCount += shard.count;
    uncompressedBytes += shard.uncompressedBytes;
  }
  if (recordCount !== manifest.aggregate.recordCount || uncompressedBytes !== manifest.aggregate.uncompressedBytes || aggregateHash.digest('hex') !== manifest.aggregate.uncompressedSha256) throw new Error('parser evidence aggregate manifest mismatch');
  return { manifest, records };
}

export function parserEvidenceMismatches(root, records) {
  const expected = createParserEvidence(records);
  const mismatches = [];
  const manifestTarget = path.join(root, parserEvidenceManifestPath);
  if (!fs.existsSync(manifestTarget) || fs.readFileSync(manifestTarget, 'utf8') !== canonicalJson(expected.manifest)) mismatches.push(parserEvidenceManifestPath);
  for (const shard of expected.shards) {
    const target = path.join(root, shard.descriptor.path);
    if (!fs.existsSync(target) || !fs.readFileSync(target).equals(shard.compressed)) mismatches.push(shard.descriptor.path);
  }
  if (fs.existsSync(path.join(root, 'parser-results.jsonl'))) mismatches.push('parser-results.jsonl');
  return mismatches.sort();
}
