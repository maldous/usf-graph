import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import zlib from 'node:zlib';

const universes = ['repository-output', 'v2-compiler-implementation', 'v2-graph-authority', 'v2-support-provisioning'];
const digestPattern = /^[a-f0-9]{64}$/;

function canonicalise(value) {
  if (Array.isArray(value)) return value.map(canonicalise);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalise(value[key])]));
  return value;
}

function canonicalJson(value) { return `${JSON.stringify(canonicalise(value), null, 2)}\n`; }
function canonicalLine(value) { return `${JSON.stringify(canonicalise(value))}\n`; }
function exactKeys(value, keys) { return value && typeof value === 'object' && !Array.isArray(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()); }

function validateManifest(manifest) {
  if (!exactKeys(manifest, ['aggregate', 'encoding', 'formatVersion', 'order', 'shards']) || !exactKeys(manifest.aggregate, ['recordCount', 'uncompressedBytes', 'uncompressedSha256'])) throw new Error('independent parser evidence manifest fields invalid');
  if (manifest.formatVersion !== 1 || manifest.encoding !== 'gzip-jsonl' || JSON.stringify(manifest.order) !== JSON.stringify(['universe', 'path']) || !Array.isArray(manifest.shards) || manifest.shards.length !== universes.length) throw new Error('independent parser evidence manifest contract mismatch');
  if (!Number.isSafeInteger(manifest.aggregate.recordCount) || manifest.aggregate.recordCount < 0 || !Number.isSafeInteger(manifest.aggregate.uncompressedBytes) || manifest.aggregate.uncompressedBytes < 0 || !digestPattern.test(manifest.aggregate.uncompressedSha256)) throw new Error('independent parser evidence aggregate invalid');
  for (let index = 0; index < universes.length; index += 1) {
    const shard = manifest.shards[index]; const universe = universes[index];
    if (!exactKeys(shard, ['compressedBytes', 'compressedSha256', 'firstPath', 'lastPath', 'path', 'recordCount', 'uncompressedBytes', 'uncompressedSha256', 'universe'])) throw new Error(`independent parser evidence shard fields invalid: ${universe}`);
    if (shard.universe !== universe || shard.path !== `parser-results/${universe}.jsonl.gz`) throw new Error(`independent parser evidence shard identity invalid: ${universe}`);
    for (const field of ['recordCount', 'uncompressedBytes', 'compressedBytes']) if (!Number.isSafeInteger(shard[field]) || shard[field] < 0) throw new Error(`independent parser evidence shard count invalid: ${universe}`);
    if (!digestPattern.test(shard.uncompressedSha256) || !digestPattern.test(shard.compressedSha256)) throw new Error(`independent parser evidence shard digest invalid: ${universe}`);
  }
}

async function readShard(root, descriptor, aggregateHash) {
  const target = path.join(root, descriptor.path);
  const stat = await fs.promises.stat(target).catch(() => null);
  if (!stat?.isFile() || stat.size !== descriptor.compressedBytes) throw new Error(`independent parser evidence shard missing or wrong size: ${descriptor.path}`);
  const compressedHash = crypto.createHash('sha256'); const uncompressedHash = crypto.createHash('sha256');
  const input = fs.createReadStream(target); input.on('data', (chunk) => compressedHash.update(chunk));
  const gunzip = zlib.createGunzip(); input.pipe(gunzip);
  const lines = readline.createInterface({ input: gunzip, crlfDelay: Infinity });
  const records = []; let count = 0; let bytes = 0; let previous = null; let first = null; let last = null;
  for await (const line of lines) {
    if (!line) throw new Error(`independent parser evidence blank record: ${descriptor.path}`);
    const framed = Buffer.from(`${line}\n`); uncompressedHash.update(framed); aggregateHash.update(framed); bytes += framed.length;
    let record; try { record = JSON.parse(line); } catch { throw new Error(`independent parser evidence invalid JSON: ${descriptor.path}:${count + 1}`); }
    if (canonicalLine(record) !== `${line}\n` || record.universe !== descriptor.universe || typeof record.path !== 'string' || (previous !== null && previous.localeCompare(record.path) >= 0)) throw new Error(`independent parser evidence canonical order mismatch: ${descriptor.path}:${count + 1}`);
    first ??= record.path; last = record.path; previous = record.path; count += 1; records.push(record);
  }
  if (compressedHash.digest('hex') !== descriptor.compressedSha256 || uncompressedHash.digest('hex') !== descriptor.uncompressedSha256 || count !== descriptor.recordCount || bytes !== descriptor.uncompressedBytes || first !== descriptor.firstPath || last !== descriptor.lastPath) throw new Error(`independent parser evidence shard verification failed: ${descriptor.path}`);
  return { records, count, bytes };
}

export async function readIndependentParserEvidence(root) {
  if (fs.existsSync(path.join(root, 'parser-results.jsonl'))) throw new Error('independent audit rejects legacy monolithic parser evidence');
  const manifestPath = path.join(root, 'parser-results/manifest.json');
  const text = await fs.promises.readFile(manifestPath, 'utf8').catch(() => null);
  if (text === null) throw new Error('independent parser evidence manifest missing');
  let manifest; try { manifest = JSON.parse(text); validateManifest(manifest); } catch (error) { throw new Error(`independent parser evidence manifest invalid: ${error.message}`, { cause: error }); }
  if (text !== canonicalJson(manifest)) throw new Error('independent parser evidence manifest is noncanonical');
  const entries = (await fs.promises.readdir(path.join(root, 'parser-results'), { withFileTypes: true })).filter((entry) => entry.isFile()).map((entry) => entry.name).sort();
  const expected = ['manifest.json', ...manifest.shards.map((shard) => path.basename(shard.path))].sort();
  if (JSON.stringify(entries) !== JSON.stringify(expected)) throw new Error('independent parser evidence shard set has missing or unexpected files');
  const aggregateHash = crypto.createHash('sha256'); const records = []; let count = 0; let bytes = 0;
  for (const descriptor of manifest.shards) { const shard = await readShard(root, descriptor, aggregateHash); records.push(...shard.records); count += shard.count; bytes += shard.bytes; }
  if (count !== manifest.aggregate.recordCount || bytes !== manifest.aggregate.uncompressedBytes || aggregateHash.digest('hex') !== manifest.aggregate.uncompressedSha256) throw new Error('independent parser evidence aggregate verification failed');
  return { manifest, records };
}
