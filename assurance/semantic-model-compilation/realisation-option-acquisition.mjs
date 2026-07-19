import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])])) : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

function requiredArgument(name) {
  const prefix = `--${name}=`;
  const matches = process.argv.filter((value) => value.startsWith(prefix));
  if (matches.length !== 1 || matches[0].length === prefix.length) throw new Error(`exactly one explicit ${prefix}<value> is required`);
  return matches[0].slice(prefix.length);
}

function validateTimestamp(value, label) {
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${label} must be an ISO timestamp`);
  return value;
}

const sourcePathAbsolute = realpathSync(fileURLToPath(import.meta.url));
const repositoryRoot = realpathSync(resolve(dirname(sourcePathAbsolute), '../..'));
const sourcePath = relative(repositoryRoot, sourcePathAbsolute);
if (sourcePath !== 'assurance/semantic-model-compilation/realisation-option-acquisition.mjs') {
  throw new Error(`collector must execute from its authorised repository path: ${sourcePath}`);
}
const authorityDigest = requiredArgument('authority-digest');
const collectedAt = validateTimestamp(requiredArgument('collected-at'), 'collected-at');
const validUntil = validateTimestamp(requiredArgument('valid-until'), 'valid-until');
const stardogVersion = requiredArgument('stardog-version');
const stardogEdition = requiredArgument('stardog-edition');
const stardogLicenceType = requiredArgument('stardog-licence-type');
if (!SHA256.test(authorityDigest)) throw new Error('authority digest must be exact');
if (Date.parse(validUntil) <= Date.parse(collectedAt)) throw new Error('valid-until must follow collected-at');
if (!/^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/.test(stardogVersion)) throw new Error('Stardog version must be exact');
if (!stardogEdition.trim() || !stardogLicenceType.trim()) throw new Error('Stardog edition and licence type are required');
const casRoot = realpathSync(requiredArgument('cas-root'));

function writeCas(bytes) {
  const digest = sha256(bytes);
  const hexadecimal = digest.slice(7);
  const directory = join(casRoot, 'sha256', hexadecimal.slice(0, 2));
  const path = join(directory, hexadecimal);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  try { writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 }); } catch (error) {
    if (error.code !== 'EEXIST' || sha256(readFileSync(path)) !== digest) throw error;
  }
  if (sha256(readFileSync(path)) !== digest) throw new Error(`CAS round-trip failed for ${digest}`);
  return { digest, path, byteSize: bytes.length };
}

function exactRegularFile(path) {
  const canonical = realpathSync(path);
  if (!statSync(canonical).isFile()) throw new Error(`required regular file missing: ${path}`);
  return canonical;
}

const collectorDigest = sha256(readFileSync(sourcePathAbsolute));
const lockPath = exactRegularFile(join(repositoryRoot, 'package-lock.json'));
const lockBytes = readFileSync(lockPath);
const lock = JSON.parse(lockBytes);
const packageLockDigest = sha256(lockBytes);
const dependencyRecords = Object.entries(lock.packages).map(([path, value]) => ({
  path,
  version: value.version || null,
  integrity: value.integrity || null,
})).sort((left, right) => utf8Compare(left.path, right.path));
const transitiveDependencySetDigest = sha256(canonicalJson(dependencyRecords));
function packageDependencyClosure(name) {
  const pending = [`node_modules/${name}`];
  const visited = new Set();
  while (pending.length) {
    const path = pending.shift();
    if (visited.has(path)) continue;
    const record = lock.packages[path];
    if (!record) throw new Error(`locked dependency path missing: ${path}`);
    visited.add(path);
    for (const dependency of Object.keys(record.dependencies || {}).sort(utf8Compare)) {
      const dependencyPath = `node_modules/${dependency}`;
      if (!lock.packages[dependencyPath]) throw new Error(`locked transitive dependency path missing: ${dependencyPath}`);
      pending.push(dependencyPath);
    }
  }
  const records = [...visited].sort(utf8Compare).map((path) => {
    const record = lock.packages[path];
    return { path, version: record.version, integrity: record.integrity || null };
  });
  return { dependencyCount: records.length, dependencySetDigest: sha256(canonicalJson(records)) };
}
const packages = ['n3', 'rdf-canonize', 'stardog', 'yaml'].map((name) => {
  const record = lock.packages[`node_modules/${name}`];
  if (!record?.version || !record?.integrity || !record?.license) throw new Error(`locked package identity incomplete: ${name}`);
  return { name, version: record.version, integrity: record.integrity, licence: record.license, ...packageDependencyClosure(name) };
});
const nodePath = exactRegularFile(process.execPath);
const nodeLicencePath = exactRegularFile(join(dirname(nodePath), '..', 'LICENSE'));
const nodeLicencePayload = writeCas(readFileSync(nodeLicencePath));
const npmVersionResult = spawnSync(process.execPath, [join(dirname(nodePath), '..', 'lib/node_modules/npm/bin/npm-cli.js'), '--version'], {
  cwd: repositoryRoot,
  encoding: 'utf8',
  env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PATH: `${dirname(nodePath)}:/usr/bin:/bin`, TZ: 'UTC' },
  timeout: 30_000,
});
if (npmVersionResult.status !== 0 || npmVersionResult.signal || npmVersionResult.error) throw new Error('locked npm version observation failed');
const npmVersion = npmVersionResult.stdout.trim();
if (!/^\d+(?:\.\d+){2,3}$/.test(npmVersion)) throw new Error('npm version observation is not exact');

const nodeReleaseUrl = 'https://nodejs.org/dist/index.json';
const releaseResponse = await fetch(nodeReleaseUrl, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(30_000) });
if (!releaseResponse.ok) throw new Error(`Node release acquisition failed (${releaseResponse.status})`);
const releaseBytes = Buffer.from(await releaseResponse.arrayBuffer());
const releaseRecords = JSON.parse(releaseBytes);
const nodeRelease = releaseRecords.find(({ version }) => version === process.version);
if (!nodeRelease) throw new Error(`official Node release metadata missing ${process.version}`);
const nodeReleasePayload = writeCas(releaseBytes);
const nodeReleaseNotesUrl = `https://nodejs.org/en/blog/release/v${process.version.slice(1)}/`;

const npmCli = exactRegularFile(join(dirname(nodePath), '..', 'lib/node_modules/npm/bin/npm-cli.js'));
const auditResult = spawnSync(process.execPath, [npmCli, 'audit', '--json', '--package-lock-only', '--ignore-scripts'], {
  cwd: repositoryRoot,
  encoding: 'utf8',
  env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PATH: `${dirname(nodePath)}:/usr/bin:/bin`, TZ: 'UTC' },
  maxBuffer: 32 * 1024 * 1024,
  timeout: 120_000,
});
if (auditResult.error || auditResult.signal || ![0, 1].includes(auditResult.status)) throw new Error('npm advisory acquisition failed');
const npmAudit = JSON.parse(auditResult.stdout);
if (!npmAudit.metadata?.vulnerabilities) throw new Error('npm advisory response lacks vulnerability metadata');
const npmAuditBytes = Buffer.from(`${canonicalJson(npmAudit)}\n`);
const npmAuditPayload = writeCas(npmAuditBytes);

async function acquireDeclaredSource(url, requiredPatterns, label) {
  const response = await fetch(url, { headers: { accept: 'text/html,application/xhtml+xml' }, signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`${label} acquisition failed (${response.status})`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const text = bytes.toString('utf8');
  if (!requiredPatterns.every((pattern) => pattern.test(text))) throw new Error(`${label} does not contain the required declared subject`);
  const payload = writeCas(bytes);
  return { sourceDigest: payload.digest, sourceUrl: url };
}
const [nodeReleaseNotes, stardogReleaseNotes, stardogSecurityStatement, stardogLicenceTerms] = await Promise.all([
  acquireDeclaredSource(nodeReleaseNotesUrl, [new RegExp(process.version.replaceAll('.', '\\.'), 'i'), /security release/i], 'Node release security notes'),
  acquireDeclaredSource('https://docs.stardog.com/release-notes/stardog-platform', [/12\.1\.0/i], 'Stardog release notes'),
  acquireDeclaredSource('https://support.stardog.com/support/solutions/articles/151000205373-security-vulnerability-faq', [/vulnerabilit/i, /scan/i], 'Stardog security statement'),
  acquireDeclaredSource('https://www.stardog.com/legal/stardog-enterprise-agreement/', [/enterprise/i, /license/i], 'Stardog licence terms'),
]);

const localObservations = {
  nodeExecutableDigest: sha256(readFileSync(nodePath)),
  nodeLicenceDigest: sha256(readFileSync(nodeLicencePath)),
  nodeLicenceSourceDigest: nodeLicencePayload.digest,
  npmVersion,
  packageLockDigest,
  packages,
  transitiveDependencySetDigest,
};
const externalObservations = {
  nodeRelease: {
    version: nodeRelease.version,
    date: nodeRelease.date,
    files: [...nodeRelease.files].sort(utf8Compare),
    lts: nodeRelease.lts,
    npm: nodeRelease.npm,
    openssl: nodeRelease.openssl,
    sourceDigest: nodeReleasePayload.digest,
    sourceUrl: nodeReleaseUrl,
  },
  nodeReleaseNotes: { version: nodeRelease.version, ...nodeReleaseNotes },
  npmAudit,
  npmAuditSourceDigest: npmAuditPayload.digest,
  npmAuditSource: 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',
  stardogReleaseNotes: { version: stardogVersion, ...stardogReleaseNotes },
  stardogSecurityStatement,
  stardogLicenceTerms: { licenceType: stardogLicenceType, ...stardogLicenceTerms },
};
const declaredProviderCore = {
  product: 'Stardog Server',
  version: stardogVersion,
  edition: stardogEdition,
  licenceType: stardogLicenceType,
  declaredAuthorityDigest: authorityDigest,
  sourceKind: 'DECLARED_REALISATION_CONSTRAINT',
};
const declaredProviderObservations = {
  stardog: { ...declaredProviderCore, metadataDigest: sha256(canonicalJson(declaredProviderCore)) },
};

function manifest(scope, observations) {
  const observationDigest = sha256(canonicalJson(observations));
  const descriptorDigest = sha256(canonicalJson({
    authorityDigest, collectedAt, collectorDigest, observationDigest, scope, validUntil,
  }));
  const core = { scope, authorityDigest, collectedAt, validUntil, collectorDigest, descriptorDigest, observations };
  return { ...core, manifestDigest: sha256(canonicalJson(core)) };
}

const manifests = [
  manifest('HERMETIC_LOCAL_RAW', localObservations),
  manifest('EXTERNAL_STATIC_RAW', externalObservations),
  manifest('DECLARED_PROVIDER_METADATA_RAW', declaredProviderObservations),
].sort((left, right) => utf8Compare(left.scope, right.scope));
const manifestRecords = manifests.map(({ scope, manifestDigest, collectorDigest: digest, descriptorDigest, collectedAt: observedAt, validUntil: freshUntil }) => ({
  scope, digest: manifestDigest, collectorDigest: digest, descriptorDigest, collectedAt: observedAt, validUntil: freshUntil,
}));
const acquisitionSetDigest = sha256(canonicalJson(manifestRecords));
const payload = { recordKind: 'USF_RAW_ACQUISITION_SET', schemaVersion: 1, authorityDigest, acquisitionSetDigest, manifests };
const record = writeCas(Buffer.from(`${canonicalJson(payload)}\n`));
process.stdout.write(`${canonicalJson({ acquisitionInputDigest: record.digest, acquisitionSetDigest, byteSize: record.byteSize, casPath: record.path, collectorDigest })}\n`);
