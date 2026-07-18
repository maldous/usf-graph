import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from 'node:test';
import { tap } from 'node:test/reporters';

const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const comparePaths = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const repositoryRoot = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
const files = process.argv.slice(2);

if (process.versions.node !== '22.23.1') throw new Error(`NODE_VERSION_MISMATCH: expected 22.23.1, received ${process.versions.node}`);
if (files.length === 0) throw new Error('EMPTY_TEST_INVENTORY: launcher requires exact test files');

const records = files.map((path) => {
  const target = resolve(path);
  const containment = relative(repositoryRoot, target);
  if (containment === '..' || containment.startsWith(`..${sep}`)) throw new Error(`PATH_ESCAPE: ${path}`);
  const stat = lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`NON_REGULAR_TARGET_PROHIBITED: ${path}`);
  return { path: containment.replaceAll('\\', '/'), digest: sha256(readFileSync(target)) };
}).sort(({ path: left }, { path: right }) => comparePaths(left, right));
const observedInventoryDigest = sha256(canonicalJson(records));
if (observedInventoryDigest !== process.env.USF_TEST_INVENTORY_DIGEST) {
  throw new Error(`INVENTORY_DIGEST_CHANGED: launcher observed ${observedInventoryDigest}`);
}

process.stdout.write(`# usf-test-inventory ${canonicalJson({
  fileCount: records.length,
  observedInventoryDigest,
  isolation: 'none',
})}\n`);
const stream = run({ files, isolation: 'none', concurrency: 1 });
stream.on('test:fail', () => { process.exitCode = 1; });
stream.compose(tap).pipe(process.stdout);
