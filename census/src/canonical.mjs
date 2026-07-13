import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export function canonicalise(value) {
  if (Array.isArray(value)) return value.map(canonicalise);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalise(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalise(value), null, 2)}\n`;
}

export function canonicalLine(value) {
  return `${JSON.stringify(canonicalise(value))}\n`;
}

export function sortUnique(values) {
  return [...new Set(values)].sort((a, b) => String(a).localeCompare(String(b)));
}

export function compareBy(keys) {
  return (left, right) => {
    for (const key of keys) {
      const order = String(left[key] ?? '').localeCompare(String(right[key] ?? ''));
      if (order !== 0) return order;
    }
    return 0;
  };
}

export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function framedDigest(records, fields) {
  const hash = crypto.createHash('sha256');
  for (const record of records) {
    for (const field of fields) {
      const value = Buffer.from(String(record[field] ?? ''), 'utf8');
      const size = Buffer.alloc(8);
      size.writeBigUInt64BE(BigInt(value.length));
      hash.update(size);
      hash.update(value);
    }
  }
  return hash.digest('hex');
}

export function writeJsonAtomic(target, value) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.writing`;
  fs.writeFileSync(temporary, canonicalJson(value));
  fs.renameSync(temporary, target);
}

export function writeJsonlAtomic(target, records) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.writing`;
  fs.writeFileSync(temporary, records.map(canonicalLine).join(''));
  fs.renameSync(temporary, target);
}

export function readJsonl(target) {
  const text = fs.readFileSync(target, 'utf8');
  if (text.length > 0 && !text.endsWith('\n')) throw new Error(`${target} lacks final newline`);
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line));
}
