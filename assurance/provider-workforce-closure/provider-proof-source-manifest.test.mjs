import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

import {
  CANONICAL_PUBLICATION_SOURCE_PATHS,
  PROVIDER_PROOF_ALGORITHM_ENTRYPOINT_PATHS,
  PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
  PROVIDER_PROOF_SOURCE_CLASSIFICATIONS,
  PROVIDER_PROOF_SOURCE_MANIFEST,
  verifyProviderProofSourceManifest,
} from './provider-proof-source-manifest.mjs';

const repositoryRoot = resolve(import.meta.dirname, '..', '..');
const utf8Compare = (left, right) => Buffer.compare(
  Buffer.from(String(left), 'utf8'),
  Buffer.from(String(right), 'utf8'),
);
const sorted = (values) => [...values].sort(utf8Compare);

function cloneManifest(overrides = {}) {
  return {
    entrypoints: [...PROVIDER_PROOF_SOURCE_MANIFEST.entrypoints],
    schemaVersion: PROVIDER_PROOF_SOURCE_MANIFEST.schemaVersion,
    sources: [...PROVIDER_PROOF_SOURCE_MANIFEST.sources],
    subsets: Object.fromEntries(
      Object.entries(PROVIDER_PROOF_SOURCE_MANIFEST.subsets)
        .map(([key, value]) => [key, [...value]]),
    ),
    ...overrides,
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'usf-provider-proof-source-manifest-'));
  for (const path of PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS) {
    const destination = join(root, path);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(repositoryRoot, path), destination);
  }
  return {
    cleanup: () => rmSync(root, { force: true, recursive: true }),
    root,
    trackedSourcePaths: [...PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS],
  };
}

function expectCode(callback, code) {
  assert.throws(callback, (error) => {
    assert.equal(error.message.startsWith(code), true, error.message);
    return true;
  });
}

test('frozen manifest is UTF-8 sorted, disjoint, complete, and test-free', () => {
  assert.equal(Object.isFrozen(PROVIDER_PROOF_SOURCE_MANIFEST), true);
  assert.equal(Object.isFrozen(PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS), true);
  assert.deepEqual(
    PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
    sorted(PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS),
  );
  assert.deepEqual(
    PROVIDER_PROOF_ALGORITHM_ENTRYPOINT_PATHS,
    sorted(PROVIDER_PROOF_ALGORITHM_ENTRYPOINT_PATHS),
  );
  assert.equal(PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS.length, 20);
  assert.equal(CANONICAL_PUBLICATION_SOURCE_PATHS.length, 9);
  assert.equal(
    new Set(Object.values(PROVIDER_PROOF_SOURCE_CLASSIFICATIONS).flat()).size,
    PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS.length,
  );
  assert.equal(PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS.some((path) => path.includes('.test.')), false);
});

test('candidate source set has the exact recursive first-party import closure', () => {
  const tracked = execFileSync(
    '/usr/bin/git',
    ['-C', repositoryRoot, 'ls-tree', '-rz', '--name-only', 'HEAD'],
  ).toString('utf8').split('\0').filter(Boolean);
  const manifestPath =
    'assurance/provider-workforce-closure/provider-proof-source-manifest.mjs';
  if (!tracked.includes(manifestPath)) tracked.push(manifestPath);
  tracked.sort(utf8Compare);
  const result = verifyProviderProofSourceManifest({
    repositoryRoot,
    trackedSourcePaths: tracked,
  });
  assert.equal(result.sourceCount, 20);
  assert.equal(result.publicationSourceCount, 9);
  assert.deepEqual(
    result.publicationSourceRecords.map(({ path }) => path),
    CANONICAL_PUBLICATION_SOURCE_PATHS,
  );
  assert.match(result.sourceSetDigest, /^sha256:[0-9a-f]{64}$/u);
  assert.match(result.publicationSourceSetDigest, /^sha256:[0-9a-f]{64}$/u);
  assert.match(result.importClosureDigest, /^sha256:[0-9a-f]{64}$/u);
});

test('every direct source omission is rejected', async (context) => {
  for (const omitted of PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS) {
    await context.test(omitted, () => {
      const sources = PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS.filter((path) => path !== omitted);
      expectCode(
        () => verifyProviderProofSourceManifest({
          manifest: cloneManifest({ sources }),
          repositoryRoot,
          trackedSourcePaths: PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
        }),
        'PROVIDER_PROOF_SOURCE_MANIFEST_SOURCE_SET_MISMATCH',
      );
    });
  }
});

test('every direct source substitution is rejected', async (context) => {
  for (const [index, replaced] of PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS.entries()) {
    await context.test(replaced, () => {
      const replacement = `assurance/provider-workforce-closure/substitute-${index}.mjs`;
      const sources = [...PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS];
      sources[index] = replacement;
      sources.sort(utf8Compare);
      expectCode(
        () => verifyProviderProofSourceManifest({
          manifest: cloneManifest({ sources }),
          repositoryRoot,
          trackedSourcePaths: sorted([...PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS, replacement]),
        }),
        'PROVIDER_PROOF_SOURCE_MANIFEST_SOURCE_SET_MISMATCH',
      );
    });
  }
});

test('a new relative import in every direct source requires a manifest update', async (context) => {
  for (const [index, path] of PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS.entries()) {
    await context.test(path, () => {
      const state = fixture();
      try {
        const source = join(state.root, path);
        const unlisted = `./unlisted-proof-source-${index}.mjs`;
        writeFileSync(source, `${readSource(source)}\nimport '${unlisted}';\n`, 'utf8');
        expectCode(
          () => verifyProviderProofSourceManifest({
            repositoryRoot: state.root,
            trackedSourcePaths: state.trackedSourcePaths,
          }),
          'PROVIDER_PROOF_RELATIVE_IMPORT_NOT_DECLARED',
        );
      } finally {
        state.cleanup();
      }
    });
  }
});

test('every duplicate direct source is rejected before file access', async (context) => {
  for (const duplicated of PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS) {
    await context.test(duplicated, () => {
      const sources = sorted([...PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS, duplicated]);
      expectCode(
        () => verifyProviderProofSourceManifest({
          manifest: cloneManifest({ sources }),
          repositoryRoot,
          trackedSourcePaths: PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
        }),
        'PROVIDER_PROOF_SOURCE_MANIFEST_SOURCES_INVALID:DUPLICATE',
      );
    });
  }
});

test('path traversal is rejected before repository access', () => {
  const sources = [...PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS];
  sources[0] = '../outside.mjs';
  sources.sort(utf8Compare);
  expectCode(
    () => verifyProviderProofSourceManifest({
      manifest: cloneManifest({ sources }),
      repositoryRoot,
      trackedSourcePaths: PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
    }),
    'PROVIDER_PROOF_SOURCE_MANIFEST_SOURCES_INVALID',
  );
});

test('missing, untracked, symlink, and special source paths fail closed', async (context) => {
  const target = PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS[0];
  await context.test('missing', () => {
    const state = fixture();
    try {
      unlinkSync(join(state.root, target));
      expectCode(
        () => verifyProviderProofSourceManifest({
          repositoryRoot: state.root,
          trackedSourcePaths: state.trackedSourcePaths,
        }),
        'PROVIDER_PROOF_SOURCE_MISSING',
      );
    } finally {
      state.cleanup();
    }
  });
  await context.test('untracked', () => {
    const state = fixture();
    try {
      expectCode(
        () => verifyProviderProofSourceManifest({
          repositoryRoot: state.root,
          trackedSourcePaths: state.trackedSourcePaths.filter((path) => path !== target),
        }),
        'PROVIDER_PROOF_SOURCE_UNTRACKED',
      );
    } finally {
      state.cleanup();
    }
  });
  await context.test('symlink', () => {
    const state = fixture();
    try {
      const targetPath = join(state.root, target);
      unlinkSync(targetPath);
      symlinkSync('/dev/null', targetPath);
      expectCode(
        () => verifyProviderProofSourceManifest({
          repositoryRoot: state.root,
          trackedSourcePaths: state.trackedSourcePaths,
        }),
        'PROVIDER_PROOF_SOURCE_SYMLINK_REFUSED',
      );
    } finally {
      state.cleanup();
    }
  });
  await context.test('special', () => {
    const state = fixture();
    try {
      const targetPath = join(state.root, target);
      unlinkSync(targetPath);
      mkdirSync(targetPath);
      expectCode(
        () => verifyProviderProofSourceManifest({
          repositoryRoot: state.root,
          trackedSourcePaths: state.trackedSourcePaths,
        }),
        'PROVIDER_PROOF_SOURCE_NOT_REGULAR',
      );
    } finally {
      state.cleanup();
    }
  });
});

test('extra source and altered publication subset are rejected', () => {
  const extra = 'assurance/provider-workforce-closure/extra-proof-source.mjs';
  expectCode(
    () => verifyProviderProofSourceManifest({
      manifest: cloneManifest({
        sources: sorted([...PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS, extra]),
      }),
      repositoryRoot,
      trackedSourcePaths: sorted([...PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS, extra]),
    }),
    'PROVIDER_PROOF_SOURCE_MANIFEST_SOURCE_SET_MISMATCH',
  );
  const subsets = cloneManifest().subsets;
  subsets.canonicalPublication = subsets.canonicalPublication.slice(1);
  expectCode(
    () => verifyProviderProofSourceManifest({
      manifest: cloneManifest({ subsets }),
      repositoryRoot,
      trackedSourcePaths: PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
    }),
    'PROVIDER_PROOF_SOURCE_SUBSET_MISMATCH:canonicalPublication',
  );
});

function readSource(path) {
  return readFileSync(path, 'utf8');
}
