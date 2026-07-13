import fs from 'node:fs';
import path from 'node:path';
import { framedDigest, sha256 } from './canonical.mjs';
import { DEFAULT_REPOSITORY_ROOT, trackedEntries } from './universe.mjs';

const lockKinds = Object.freeze({
  'package-lock.json': { packageManager: 'npm', manifest: 'package.json', installCommand: 'npm ci', materialisedPath: 'node_modules' },
  'pnpm-lock.yaml': { packageManager: 'pnpm', manifest: 'package.json', installCommand: 'pnpm install --frozen-lockfile', materialisedPath: 'node_modules' },
  'yarn.lock': { packageManager: 'yarn', manifest: 'package.json', installCommand: 'yarn install --frozen-lockfile', materialisedPath: 'node_modules' },
  'poetry.lock': { packageManager: 'poetry', manifest: 'pyproject.toml', installCommand: 'poetry install --no-interaction', materialisedPath: '.venv' },
  'uv.lock': { packageManager: 'uv', manifest: 'pyproject.toml', installCommand: 'uv sync --frozen', materialisedPath: '.venv' }
});

function relativeJoin(directory, name) {
  return directory === '.' ? name : path.posix.join(directory, name);
}

function runtimeConstraint(repositoryRoot, manifestPath) {
  if (path.posix.basename(manifestPath) === 'package.json') {
    const manifest = JSON.parse(fs.readFileSync(path.join(repositoryRoot, manifestPath), 'utf8'));
    return manifest.engines?.node ?? null;
  }
  const text = fs.readFileSync(path.join(repositoryRoot, manifestPath), 'utf8');
  return /^requires-python\s*=\s*["']([^"']+)["']/m.exec(text)?.[1] ?? null;
}

export function createMaterialisationContract({
  repositoryRoot,
  key,
  kind = 'package-manager',
  sourceRoot,
  packageManager,
  runtimeConstraint: requiredRuntime = null,
  manifestPaths,
  lockPaths,
  installCommand,
  materialisedPaths,
  integrityPolicy = 'frozen-lockfile-with-recorded-integrity',
  nativeBuildPolicy = 'package-manager-declared-builds-only'
}) {
  if (!repositoryRoot || !key || !sourceRoot || !packageManager || !installCommand) throw new Error('incomplete materialisation contract');
  if (!Array.isArray(manifestPaths) || manifestPaths.length === 0 || !Array.isArray(lockPaths) || lockPaths.length === 0) throw new Error(`materialisation source inputs required: ${key}`);
  if (!Array.isArray(materialisedPaths) || materialisedPaths.length === 0) throw new Error(`materialisation observation paths required: ${key}`);
  const sourceInputs = [...manifestPaths, ...lockPaths].sort();
  const digestRows = sourceInputs.map((repoPath) => ({
    path: repoPath,
    contentDigest: sha256(fs.readFileSync(path.join(repositoryRoot, repoPath)))
  }));
  const observed = materialisedPaths.map((repoPath) => fs.existsSync(path.join(repositoryRoot, repoPath)));
  const presentCount = observed.filter(Boolean).length;
  const currentStatus = presentCount === materialisedPaths.length ? 'observed-present' : 'observed-absent';
  return {
    key,
    kind,
    sourceRoot,
    packageManager,
    runtimeConstraint: requiredRuntime,
    manifestPaths: [...manifestPaths].sort(),
    lockPaths: [...lockPaths].sort(),
    installCommand,
    integrityPolicy,
    nativeBuildPolicy,
    expectedClosureDigest: framedDigest(digestRows, ['path', 'contentDigest']),
    currentStatus,
    canonicalDigestInput: false,
    verification: {
      materialisedPaths: [...materialisedPaths].sort(),
      observedPathCount: presentCount,
      expectedPathCount: materialisedPaths.length,
      observationOnly: true,
      sourceIdentityUnaffected: true
    }
  };
}

export function discoverMaterialisationContracts({ repositoryRoot = DEFAULT_REPOSITORY_ROOT, entries = trackedEntries(repositoryRoot) } = {}) {
  const trackedPaths = new Set(entries.keys());
  const contracts = [];
  for (const lockPath of [...trackedPaths].sort()) {
    const lockName = path.posix.basename(lockPath);
    const definition = lockKinds[lockName];
    if (!definition) continue;
    const sourceRoot = path.posix.dirname(lockPath);
    const manifestPath = relativeJoin(sourceRoot, definition.manifest);
    if (!trackedPaths.has(manifestPath)) throw new Error(`materialisation lock lacks tracked manifest: ${lockPath}`);
    contracts.push(createMaterialisationContract({
      repositoryRoot,
      key: `${definition.packageManager}:${sourceRoot}`,
      sourceRoot,
      packageManager: definition.packageManager,
      runtimeConstraint: runtimeConstraint(repositoryRoot, manifestPath),
      manifestPaths: [manifestPath],
      lockPaths: [lockPath],
      installCommand: definition.installCommand,
      materialisedPaths: [relativeJoin(sourceRoot, definition.materialisedPath)]
    }));
  }
  return contracts.sort((left, right) => left.key.localeCompare(right.key));
}

export const materialisationContracts = discoverMaterialisationContracts;
