import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
  assert.equal(valid.schemaVersion, 2);
  assert.equal(valid.systemObjectCount, valid.systemObjects.length);
  assert.equal(valid.systemObjectSetDigest, sha256(canonicalJson(valid.systemObjects)));
  assert.equal(verifyProviderProofNodeDependencyEvidence(valid), valid);

  const systemObjects = [
    ...valid.systemObjects,
    {
      path: '/tmp/injected-native-object.so',
      digest: `sha256:${'1'.repeat(64)}`,
      byteSize: 1,
    },
  ];
  const injected = {
    ...valid,
    systemObjects,
    systemObjectCount: systemObjects.length,
    systemObjectSetDigest: sha256(canonicalJson(systemObjects)),
  };
  assert.throws(
    () => verifyProviderProofNodeDependencyEvidence(injected),
    /NODE_DEPENDENCY_EVIDENCE_MISMATCH/,
  );
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
