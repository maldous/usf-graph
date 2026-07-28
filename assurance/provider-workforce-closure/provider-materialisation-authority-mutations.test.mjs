import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import {
  bindProviderMaterialisationAuthorityMutationRuntime,
  PROVIDER_MATERIALISATION_MUTATION_CASES,
  PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS,
  providerMaterialisationAuthorityMutationInternals,
  verifyProviderMaterialisationAuthorityMutationEvidence,
  verifyProviderProofNodeDependencyEvidence,
} from './provider-materialisation-authority-mutations.mjs';
import { localShaclRuntimeInternals } from '../semantic-model-compilation/local-shacl-validation.mjs';

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const digestByte = (value) => (value % 256).toString(16).padStart(2, '0').repeat(32);

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${canonicalJson(value)}\n`);
}

function createNodeDependencyFixture() {
  const root = mkdtempSync(join(tmpdir(), 'usf-node-runtime-closure-'));
  const definitions = {
    n3: { version: '1.0.0', dependencies: {} },
    stardog: { version: '2.0.0', dependencies: { lodash: '1.0.0' } },
    lodash: { version: '1.0.0', dependencies: {} },
  };
  const rootDependencies = { n3: '1.0.0', stardog: '2.0.0' };
  writeJson(join(root, 'package.json'), {
    name: 'node-runtime-fixture',
    private: true,
    dependencies: rootDependencies,
  });
  const packages = { '': { dependencies: rootDependencies } };
  for (const [name, definition] of Object.entries(definitions)) {
    const packageRoot = join(root, 'node_modules', name);
    writeJson(join(packageRoot, 'package.json'), {
      name,
      version: definition.version,
      dependencies: definition.dependencies,
    });
    writeFileSync(join(packageRoot, 'index.js'), `export const identity = ${JSON.stringify(name)};\n`);
    packages[`node_modules/${name}`] = {
      version: definition.version,
      dependencies: definition.dependencies,
    };
  }
  writeJson(join(root, 'package-lock.json'), {
    name: 'node-runtime-fixture',
    lockfileVersion: 3,
    packages,
  });
  return {
    root,
    inspect(overrides = {}) {
      return providerMaterialisationAuthorityMutationInternals.inspectNodeDependencyEvidence({
        repositoryRoot: root,
        rootPackages: ['n3', 'stardog'],
        resolvePackageJson: (name) => join(root, 'node_modules', name, 'package.json'),
        procMapsText: '',
        ...overrides,
      });
    },
  };
}

function nativeMappingEvidence(checkpoints) {
  const records = localShaclRuntimeInternals.expectedPythonMappedSystemObjects;
  const snapshots = checkpoints.map((checkpoint) => ({
    schemaVersion: 1,
    checkpoint,
    records,
    recordCount: records.length,
    recordSetDigest: sha256(canonicalJson(records)),
  }));
  return {
    schemaVersion: 1,
    checkpoints: snapshots,
    checkpointSetDigest: sha256(canonicalJson(snapshots)),
  };
}

function unboundMutationCore() {
  const sourceRecords = PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS.map((path, index) => ({
    path,
    digest: `sha256:${digestByte(index + 37)}`,
  }));
  const cases = PROVIDER_MATERIALISATION_MUTATION_CASES.map((expected, index) => ({
    ...expected,
    observedShaclCodeDigest: `sha256:${digestByte(index + 71)}`,
    observedIntegrityCodeDigest: `sha256:${digestByte(index + 113)}`,
    shaclMatched: true,
    integrityMatched: true,
  }));
  const mappingEvidence = nativeMappingEvidence([
    'PRE_WORKLOAD',
    'POST_BASELINE_LOAD',
    'POST_WORKLOAD',
  ]);
  const finalSnapshot = mappingEvidence.checkpoints.at(-1);
  return {
    schemaVersion: 3,
    evidenceScope: 'HERMETIC_UNPUBLISHED_MUTATION_FIXTURE',
    caseCount: cases.length,
    passedCaseCount: cases.length,
    baselineIntegrityRowCount: 0,
    baselineIntegrityDigest: sha256(canonicalJson([])),
    sourceRecords,
    sourceSetDigest: sha256(canonicalJson(sourceRecords)),
    pythonDependencyByteSets:
      providerMaterialisationAuthorityMutationInternals.expectedPythonDependencyByteSets,
    pythonDependencyByteSetDigest:
      providerMaterialisationAuthorityMutationInternals.expectedPythonDependencyByteSetDigest,
    mappedSystemObjectCount: finalSnapshot.recordCount,
    mappedSystemObjectSetDigest: finalSnapshot.recordSetDigest,
    nativeMappingEvidence: mappingEvidence,
    siteCustomizationLoaded: false,
    cases,
    caseSetDigest: sha256(canonicalJson(cases)),
  };
}

test('Node native mapping inspection fails closed on deleted and unresolved file-backed entries', () => {
  const inspect = providerMaterialisationAuthorityMutationInternals.inspectMappedNativeObjectRecords;
  assert.throws(
    () => inspect({
      procMapsText: '1000-2000 r--p 00000000 00:00 0 /tmp/native-fixture.so (deleted)\n',
      executablePath: '/usr/bin/node',
    }),
    /NODE_MAPPED_RUNTIME_OBJECT_DELETED_/,
  );
  assert.throws(
    () => inspect({
      procMapsText: '1000-2000 r--p 00000000 00:00 0 /tmp/native-fixture.so\n',
      executablePath: '/usr/bin/node',
      resolvePath: () => {
        throw Object.assign(new Error('gone'), { code: 'ENOENT' });
      },
    }),
    /NODE_MAPPED_RUNTIME_OBJECT_UNRESOLVED_.*_ENOENT/,
  );
});

test('Node dependency evidence binds the exact approved native object records', () => {
  const valid = providerMaterialisationAuthorityMutationInternals.expectedNodeDependencyEvidence;
  assert.equal(valid.schemaVersion, 3);
  assert.deepEqual(valid.rootPackages, ['n3', 'stardog']);
  assert.equal(valid.rootClosures.length, 2);
  valid.rootClosures.forEach((closure) => {
    assert.equal(closure.packageNameSetDigest, sha256(canonicalJson(closure.packageNames)));
    assert.equal(
      closure.packageByteSetDigest,
      sha256(canonicalJson(
        closure.packageNames.map((name) => valid.packages.find((record) => record.name === name)),
      )),
    );
  });
  assert.equal(valid.packageByteSetDigest, sha256(canonicalJson(valid.packages)));
  assert.equal(valid.mappedSystemObjectCount, valid.mappedSystemObjects.length);
  assert.equal(
    valid.mappedSystemObjectSetDigest,
    sha256(canonicalJson(valid.mappedSystemObjects)),
  );
  const { evidenceDigest, ...core } = valid;
  assert.equal(evidenceDigest, sha256(canonicalJson(core)));
  assert.equal(verifyProviderProofNodeDependencyEvidence(valid), valid);

  const mappedSystemObjects = [
    ...valid.mappedSystemObjects,
    {
      path: '/tmp/injected-native-object.so',
      digest: `sha256:${'1'.repeat(64)}`,
      byteSize: 1,
    },
  ];
  const injected = {
    ...valid,
    mappedSystemObjects,
    mappedSystemObjectCount: mappedSystemObjects.length,
    mappedSystemObjectSetDigest: sha256(canonicalJson(mappedSystemObjects)),
  };
  assert.throws(
    () => verifyProviderProofNodeDependencyEvidence(injected),
    /NODE_DEPENDENCY_EVIDENCE_MISMATCH/,
  );
});

test('Node root closures bind stardog and lodash bytes independently of n3', () => {
  const fixture = createNodeDependencyFixture();
  try {
    const before = fixture.inspect();
    const n3Before = before.rootClosures.find(({ rootPackage }) => rootPackage === 'n3');
    const stardogBefore = before.rootClosures.find(({ rootPackage }) => rootPackage === 'stardog');

    writeFileSync(
      join(fixture.root, 'node_modules', 'stardog', 'index.js'),
      'export const identity = "stardog-mutated";\n',
    );
    const afterStardog = fixture.inspect();
    assert.equal(
      afterStardog.rootClosures.find(({ rootPackage }) => rootPackage === 'n3')
        .packageByteSetDigest,
      n3Before.packageByteSetDigest,
    );
    assert.notEqual(
      afterStardog.rootClosures.find(({ rootPackage }) => rootPackage === 'stardog')
        .packageByteSetDigest,
      stardogBefore.packageByteSetDigest,
    );
    assert.notEqual(afterStardog.packageByteSetDigest, before.packageByteSetDigest);

    writeFileSync(
      join(fixture.root, 'node_modules', 'lodash', 'index.js'),
      'export const identity = "lodash-mutated";\n',
    );
    const afterLodash = fixture.inspect();
    assert.notEqual(
      afterLodash.packages.find(({ name }) => name === 'lodash').byteSetDigest,
      afterStardog.packages.find(({ name }) => name === 'lodash').byteSetDigest,
    );
    assert.notEqual(
      afterLodash.rootClosures.find(({ rootPackage }) => rootPackage === 'stardog')
        .packageByteSetDigest,
      afterStardog.rootClosures.find(({ rootPackage }) => rootPackage === 'stardog')
        .packageByteSetDigest,
    );
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('Node dependency closure rejects missing and extra lock dependencies', () => {
  const missing = createNodeDependencyFixture();
  try {
    const stardogManifestPath = join(missing.root, 'node_modules', 'stardog', 'package.json');
    const stardogManifest = JSON.parse(readFileSync(stardogManifestPath, 'utf8'));
    stardogManifest.dependencies.missing = '1.0.0';
    writeJson(stardogManifestPath, stardogManifest);
    const lockPath = join(missing.root, 'package-lock.json');
    const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
    lock.packages['node_modules/stardog'].dependencies.missing = '1.0.0';
    writeJson(lockPath, lock);
    assert.throws(() => missing.inspect(), /NODE_DEPENDENCY_RESOLUTION_FAILED_missing_ENOENT/);
  } finally {
    rmSync(missing.root, { recursive: true, force: true });
  }

  const extra = createNodeDependencyFixture();
  try {
    const lockPath = join(extra.root, 'package-lock.json');
    const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
    lock.packages['node_modules/stardog'].dependencies.extra = '1.0.0';
    writeJson(lockPath, lock);
    assert.throws(
      () => extra.inspect(),
      /NODE_DEPENDENCY_LOCK_RUNTIME_MISMATCH_stardog/,
    );
  } finally {
    rmSync(extra.root, { recursive: true, force: true });
  }
});

test('Node dependency resolution rejects outside and duplicate-version package roots', () => {
  const fixture = createNodeDependencyFixture();
  const outside = mkdtempSync(join(tmpdir(), 'usf-node-runtime-outside-'));
  try {
    writeJson(join(outside, 'package.json'), {
      name: 'lodash',
      version: '1.0.0',
      dependencies: {},
    });
    assert.throws(
      () => fixture.inspect({
        resolvePackageJson: (name) => name === 'lodash'
          ? join(outside, 'package.json')
          : join(fixture.root, 'node_modules', name, 'package.json'),
      }),
      /NODE_DEPENDENCY_OUTSIDE_REPOSITORY_lodash/,
    );

    const duplicate = join(
      fixture.root,
      'node_modules',
      'stardog',
      'node_modules',
      'lodash',
    );
    writeJson(join(duplicate, 'package.json'), {
      name: 'lodash',
      version: '2.0.0',
      dependencies: {},
    });
    writeFileSync(join(duplicate, 'index.js'), 'export const identity = "duplicate";\n');
    assert.throws(
      () => fixture.inspect({
        resolvePackageJson: (name) => name === 'lodash'
          ? join(duplicate, 'package.json')
          : join(fixture.root, 'node_modules', name, 'package.json'),
      }),
      /NODE_DEPENDENCY_DUPLICATE_VERSION_lodash/,
    );
  } finally {
    rmSync(outside, { recursive: true, force: true });
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('Node dependency resolution rejects package-root symlinks and root-set drift', () => {
  const fixture = createNodeDependencyFixture();
  try {
    const valid = providerMaterialisationAuthorityMutationInternals.expectedNodeDependencyEvidence;
    const drifted = structuredClone(valid);
    drifted.rootPackages = ['n3'];
    drifted.rootClosures = drifted.rootClosures.filter(({ rootPackage }) => rootPackage === 'n3');
    const { evidenceDigest: _oldDigest, ...driftedCore } = drifted;
    drifted.evidenceDigest = sha256(canonicalJson(driftedCore));
    assert.throws(
      () => verifyProviderProofNodeDependencyEvidence(drifted),
      /NODE_DEPENDENCY_EVIDENCE_MISMATCH/,
    );
    assert.throws(
      () => fixture.inspect({ rootPackages: ['stardog', 'n3'] }),
      /NODE_ROOT_PACKAGE_SET_INVALID/,
    );

    const realLodash = join(fixture.root, 'node_modules', 'lodash-real');
    const lodash = join(fixture.root, 'node_modules', 'lodash');
    writeJson(join(realLodash, 'package.json'), {
      name: 'lodash',
      version: '1.0.0',
      dependencies: {},
    });
    writeFileSync(join(realLodash, 'index.js'), 'export const identity = "lodash";\n');
    rmSync(lodash, { recursive: true, force: true });
    symlinkSync(realLodash, lodash, 'dir');
    assert.throws(
      () => fixture.inspect(),
      /NODE_DEPENDENCY_SYMLINK_OR_SPECIAL_ROOT_lodash/,
    );
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('mutation evidence digest binds the exact runtime and rejects post-hoc substitution', () => {
  const runtime = {
    executablePath: '/fixture/venv/bin/python',
    resolvedExecutablePath: '/usr/bin/python3.11',
    executableDigest: `sha256:${'e1'.repeat(32)}`,
  };
  const evidence = bindProviderMaterialisationAuthorityMutationRuntime(
    unboundMutationCore(),
    runtime,
  );
  assert.equal(verifyProviderMaterialisationAuthorityMutationEvidence(evidence), evidence);
  assert.equal(
    evidence.evidenceDigestScope,
    'MATERIALISATION_MUTATION_EVIDENCE_WITH_RUNTIME_V1',
  );

  const substituted = structuredClone(evidence);
  substituted.runtime.executableDigest = `sha256:${'e2'.repeat(32)}`;
  assert.throws(
    () => verifyProviderMaterialisationAuthorityMutationEvidence(substituted),
    /MATERIALISATION_MUTATION_EVIDENCE_DIGEST_MISMATCH/,
  );
  assert.notEqual(
    bindProviderMaterialisationAuthorityMutationRuntime(
      unboundMutationCore(),
      substituted.runtime,
    ).evidenceDigest,
    evidence.evidenceDigest,
  );
});
