import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { compilerProofInternals, evaluateCompilerSemanticEnforcement } from './compiler-proof.mjs';

const authorityDigest = `sha256:${'a'.repeat(64)}`;
const roots = [];

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'usf-compiler-proof-'));
  const casRoot = join(root, 'cas');
  mkdirSync(join(root, 'semantic-model'));
  mkdirSync(casRoot);
  writeFileSync(join(root, 'source.mjs'), 'export const value = true;\n');
  writeFileSync(join(root, 'proof.mjs'), 'export const proof = true;\n');
  writeFileSync(join(root, 'tests.mjs'), 'export const tests = true;\n');
  writeFileSync(join(root, 'substitute.mjs'), 'export const substitute = true;\n');
  roots.push(root);
  return { root, casRoot };
}

function focusedResult(root, passed = true) {
  const tests = compilerProofInternals.sourceSet(root, ['tests.mjs']);
  const stagedFileDigests = tests.records;
  return {
    passed,
    count: 7,
    discoveredFileCount: 1,
    testInventoryDigest: tests.digest,
    preExecutionReboundDigest: tests.digest,
    stagedTestInventoryDigest: tests.digest,
    executedTestInventoryDigest: tests.digest,
    executedByteSetDigest: tests.digest,
    launcherObservedTestInventoryDigest: tests.digest,
    launcherObservedTestFileCount: 1,
    snapshotManifestDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(stagedFileDigests)),
    authorisedExecutionByteSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(stagedFileDigests)),
    authorisedRoots: ['.'],
    authorisedRootSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(['.'])),
    snapshotRootDigest: compilerProofInternals.sha256('snapshot-root'),
    snapshotPermissionsDigest: compilerProofInternals.sha256('permissions'),
    snapshotReadOnlyVerified: true,
    snapshotPolicy: 'EPHEMERAL_DELETE_AFTER_EXECUTION',
    snapshotExclusions: [],
    snapshotFileCount: stagedFileDigests.length,
    stagedFileDigests,
    discoveryAlgorithmDigest: compilerProofInternals.sha256('discovery'),
    rejectionCodeVocabularyDigest: compilerProofInternals.sha256('rejections'),
    dependencyLockDigest: compilerProofInternals.sha256('lock'),
    dependencyByteSetDigest: compilerProofInternals.sha256('dependencies'),
    launcherDigest: compilerProofInternals.sha256('launcher'),
    nodeExecutableDigest: compilerProofInternals.sha256('node'),
    nativeRuntimeDigests: [],
    networkIsolation: 'LINUX_NETWORK_NAMESPACE',
    networkIsolatorDigest: compilerProofInternals.sha256('unshare'),
    nodeFlags: ['--permission', '--no-addons', '<REPOSITORY_LOCAL_TEST_LAUNCHER>'],
    nodeVersion: '22.23.1',
    invocationMode: 'NODE_TEST_PROGRAMMATIC_EXACT_FILES',
    isolationMode: 'none',
    invocationDigest: compilerProofInternals.sha256('invocation'),
    expectedDenialCodes: { filesystemRead: 'ERR_ACCESS_DENIED' },
    environment: { TZ: 'UTC' },
    outputDigest: compilerProofInternals.sha256(passed ? 'tests' : 'failed'),
  };
}

function localShaclResult(overrides = {}) {
  const classifier = [
    'via-service-predicate', 'managed-service-token', 'service-string-literal', 'service-comment',
    'service-variable-name', 'service-iri', 'service-clause',
  ].map((id) => ({ id, expectedLiveDependent: id === 'service-clause', actualLiveDependent: id === 'service-clause' }));
  const evidence = {
    schemaVersion: 1,
    evidenceScope: 'HERMETIC_SUBSTITUTE',
    validationScope: 'LOCAL_PYSHACL_COMPATIBLE_AFFECTED_CLOSURE',
    localCompatibleConforms: true,
    registeredSparqlConstraintCount: 79,
    locallyEvaluatedConstraintCount: 79,
    actualServiceAlgebraNodeCount: 0,
    liveServiceConstraintCount: 0,
    liveServiceConstraintSetDigest: compilerProofInternals.EMPTY_SET_DIGEST,
    substringBasedExclusionCount: 0,
    unexpectedExclusionCount: 0,
    candidateViolationCount: 0,
    serviceConstraintsCountedAsLocalPass: 0,
    prefixInjectionDeterministic: true,
    prefixSemanticsEquivalent: true,
    prefixSemanticEquivalenceCount: 79,
    pyshaclServiceDetectionMode: 'PARSED_SPARQL_ALGEBRA',
    transitiveFocusGap: 0,
    focusRootCount: 11,
    focusRootDigest: compilerProofInternals.EXPECTED_FOCUS_ROOT_DIGEST,
    focusNodeCount: 162,
    focusNodeDigest: compilerProofInternals.sha256('focus-nodes'),
    serviceClassifierSelfTestCount: 7,
    serviceClassifierSelfTests: classifier,
    pyshaclVersion: '0.40.0',
    rdflibVersion: '7.6.0',
    pyyamlVersion: '6.0.3',
    validationPhaseResults: [
      { phase: 'AFFECTED_AUTHORED', conforms: true, violationCount: 0, resultDigest: compilerProofInternals.sha256('phase-results') },
      { phase: 'AFFECTED_REGISTERED_DERIVED_SNAPSHOT', conforms: true, violationCount: 0, resultDigest: compilerProofInternals.sha256('phase-results') },
    ],
    candidateSourceSetDigest: compilerProofInternals.sha256('candidate-source'),
    compatibleConstraintSetDigest: compilerProofInternals.sha256('constraint-set'),
    registeredConstraintSetDigest: compilerProofInternals.sha256('constraint-set'),
    dataSourceSetDigest: compilerProofInternals.sha256('data-sources'),
    dependencySpecificationDigest: compilerProofInternals.sha256('dependency-specification'),
    focusClosureAlgorithmDigest: compilerProofInternals.sha256('closure-algorithm'),
    focusClosureWitnessDigest: compilerProofInternals.sha256('closure-witness'),
    focusPredicatePolicyDigest: compilerProofInternals.sha256('predicate-policy'),
    harnessSourceDigest: compilerProofInternals.sha256('harness'),
    originalQuerySetDigest: compilerProofInternals.sha256('original-queries'),
    prefixContextSetDigest: compilerProofInternals.sha256('prefix-contexts'),
    prefixInjectionAlgorithmDigest: compilerProofInternals.sha256('prefix-algorithm'),
    pythonDependencyByteSetDigest: compilerProofInternals.sha256('python-dependencies'),
    pythonExecutableDigest: compilerProofInternals.sha256('python'),
    representativeEquivalenceDigest: compilerProofInternals.sha256('representative-equivalence'),
    semanticManifestDigest: compilerProofInternals.sha256('semantic-manifest'),
    serviceClassificationAlgorithmDigest: compilerProofInternals.sha256('service-classifier'),
    serviceClassifierSelfTestDigest: compilerProofInternals.sha256('service-self-tests'),
    shapeSourceSetDigest: compilerProofInternals.sha256('shape-sources'),
    transformedQuerySetDigest: compilerProofInternals.sha256('transformed-queries'),
    ...overrides,
  };
  evidence.validationPhaseResultDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(evidence.validationPhaseResults));
  evidence.evidenceDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(evidence));
  const output = `${compilerProofInternals.canonicalJson(evidence)}\n`;
  const digest = compilerProofInternals.sha256(output);
  return {
    deterministicRegenerationCount: 2,
    deterministicOutputDigest: digest,
    firstOutputDigest: digest,
    secondOutputDigest: digest,
    evidence,
  };
}

test.after(() => roots.forEach((root) => rmSync(root, { recursive: true, force: true })));

test('emits digest-bound evidence and a verified deterministic integrity envelope', async () => {
  const { root, casRoot } = fixture();
  const inputs = {
    authorityDigest,
    evaluatedAt: '2026-07-18T13:30:00Z',
    repositoryRoot: root,
    casRoot,
    createLiveClient: async () => ({}),
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    sourcePaths: ['proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => focusedResult(root),
    runLocalCompatibleShacl: async () => localShaclResult(),
    createCommand: () => ({ execute: async () => ({
      evaluatedAuthorityDigest: authorityDigest,
      semanticModelPath: 'semantic-model',
      contaminationCount: 0,
      commitOutcome: { state: 'validated-rolled-back', exactCandidateStateVerified: true, candidateDigest: `sha256:${'b'.repeat(64)}` },
    }) }),
  };
  const result = await evaluateCompilerSemanticEnforcement(inputs);
  const secondCasRoot = join(root, 'cas-second');
  mkdirSync(secondCasRoot);
  const regenerated = await evaluateCompilerSemanticEnforcement({ ...inputs, casRoot: secondCasRoot });
  assert.deepEqual(regenerated, result);
  assert.equal(result.ok, true);
  assert.equal(result.failureCount, 0);
  assert.equal(result.caseCount, 8);
  assert.ok(result.evidenceManifests.hermetic.locator.startsWith('cas://sha256/'));
  assert.ok(result.evidenceManifests.authorityControl.locator.startsWith('cas://sha256/'));
  assert.ok(result.evidenceAttestations.hermetic.locator.startsWith('cas://sha256/'));
  assert.ok(result.evidenceAttestations.authorityControl.locator.startsWith('cas://sha256/'));
  assert.ok(result.proofAttestation.locator.startsWith('cas://sha256/'));
  const manifest = (descriptor) => JSON.parse(readFileSync(join(casRoot, 'sha256', descriptor.digest.slice(7, 9), descriptor.digest.slice(7)), 'utf8'));
  const hermetic = manifest(result.evidenceManifests.hermetic);
  const authorityControl = manifest(result.evidenceManifests.authorityControl);
  assert.equal(hermetic.providerMode, 'urn:usf:providermode:deterministictestsubstitute');
  assert.equal(hermetic.evidenceScope, 'HERMETIC_SUBSTITUTE');
  assert.equal(hermetic.liveAuthorityDependency, false);
  assert.equal(hermetic.providerIdentity, 'urn:usf:provider:compilerfocusedtestsubstitute');
  assert.match(hermetic.substituteImplementationDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(hermetic.environmentClass, 'urn:usf:environmentclass:hermetic');
  assert.deepEqual(hermetic.supportedEvidenceKinds, [
    'urn:usf:evidencekind:runtimeproofevidence',
    'urn:usf:evidencekind:validationevidence',
  ]);
  assert.equal(authorityControl.providerMode, 'urn:usf:providermode:liveauthoritycontrol');
  assert.equal(authorityControl.evidenceScope, 'LIVE_AUTHORITY_CONTROL');
  assert.equal(authorityControl.providerIdentity, 'urn:usf:provider:livestardogsemanticauthority');
  assert.equal(authorityControl.evaluatedAuthorityDigest, authorityDigest);
  assert.equal(authorityControl.transactionMode, 'validate-and-rollback');
  assert.equal(authorityControl.postTransactionAuthorityDrift, 'ZERO');
  assert.equal(authorityControl.environmentClass, 'urn:usf:environmentclass:authoritycontrol');
  assert.deepEqual(authorityControl.supportedEvidenceKinds, ['urn:usf:evidencekind:validationevidence']);
  assert.equal(hermetic.cases.length, 2);
  assert.equal(authorityControl.cases.length, 6);
  assert.equal(hermetic.localShaclRegisteredConstraintCount, 79);
  assert.equal(hermetic.localShaclActualServiceAlgebraNodeCount, 0);
  assert.equal(hermetic.localShaclValidationPhaseResultDigest, localShaclResult().evidence.validationPhaseResultDigest);
  assert.equal(authorityControl.liveServiceConstraintCount, 0);
  assert.equal(authorityControl.liveServiceConstraintSetDigest, hermetic.localShaclLiveServiceConstraintSetDigest);
  assert.equal(Object.hasOwn(authorityControl, 'snapshotManifestDigest'), false);
  for (const scoped of [hermetic, authorityControl]) {
    const { evidenceDigest, ...claims } = scoped;
    assert.equal(evidenceDigest, compilerProofInternals.sha256(compilerProofInternals.canonicalJson(claims)));
  }
});

test('fails closed on a stale authority or failed focused tests', async () => {
  const { root, casRoot } = fixture();
  const base = {
    authorityDigest,
    evaluatedAt: '2026-07-18T13:30:00Z',
    repositoryRoot: root,
    casRoot,
    createLiveClient: async () => ({}),
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    sourcePaths: ['proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runLocalCompatibleShacl: async () => localShaclResult(),
    createCommand: () => ({ execute: async () => ({ evaluatedAuthorityDigest: `sha256:${'c'.repeat(64)}` }) }),
  };
  const focused = (passed) => ({ ...focusedResult(root, passed), count: 1 });
  await assert.rejects(() => evaluateCompilerSemanticEnforcement({ ...base, runFocusedTests: async () => focused(false) }), /did not produce valid passing evidence/);
  await assert.rejects(() => evaluateCompilerSemanticEnforcement({ ...base, runFocusedTests: async () => focused(true) }), /proof cases failed/);
});

test('rejects invalid local SHACL evidence before creating a live authority client', async () => {
  const { root, casRoot } = fixture();
  let liveClientCreated = false;
  await assert.rejects(() => evaluateCompilerSemanticEnforcement({
    authorityDigest,
    evaluatedAt: '2026-07-18T13:30:00Z',
    repositoryRoot: root,
    casRoot,
    createLiveClient: async () => { liveClientCreated = true; return {}; },
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    sourcePaths: ['proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => focusedResult(root),
    runLocalCompatibleShacl: async () => localShaclResult({ candidateViolationCount: 1 }),
  }), /does not close the exact compatible affected constraint scope/);
  assert.equal(liveClientCreated, false);
});

test('rejects incomplete or broadened local SHACL validation phases before live access', async () => {
  const { root, casRoot } = fixture();
  let liveClientCreated = false;
  const invalidPhases = [{ phase: 'FULL_AUTHORED', conforms: true, violationCount: 0, resultDigest: compilerProofInternals.sha256('phase-results') }];
  await assert.rejects(() => evaluateCompilerSemanticEnforcement({
    authorityDigest,
    evaluatedAt: '2026-07-18T13:30:00Z',
    repositoryRoot: root,
    casRoot,
    createLiveClient: async () => { liveClientCreated = true; return {}; },
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    sourcePaths: ['proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => focusedResult(root),
    runLocalCompatibleShacl: async () => localShaclResult({ validationPhaseResults: invalidPhases }),
  }), /does not close the exact compatible affected constraint scope/);
  assert.equal(liveClientCreated, false);
});

test('rejects mixed, mislabeled, live-claiming and self-referential evidence', () => {
  const common = {
    schemaVersion: 2,
    evaluatedAt: '2026-07-18T13:30:00Z',
    providerIdentity: 'urn:usf:provider:compilerfocusedtestsubstitute',
    liveAuthorityDependency: false,
    implementationSourceDigest: compilerProofInternals.sha256('implementation'),
    substituteImplementationDigest: compilerProofInternals.sha256('substitute'),
    proofAlgorithmDigest: compilerProofInternals.sha256('algorithm'),
    testSetDigest: compilerProofInternals.sha256('test-inventory'),
    testInventoryDigest: compilerProofInternals.sha256('test-inventory'),
    preExecutionReboundDigest: compilerProofInternals.sha256('test-inventory'),
    stagedTestInventoryDigest: compilerProofInternals.sha256('test-inventory'),
    executedTestInventoryDigest: compilerProofInternals.sha256('test-inventory'),
    executedByteSetDigest: compilerProofInternals.sha256('test-inventory'),
    launcherObservedTestInventoryDigest: compilerProofInternals.sha256('test-inventory'),
    launcherObservedTestFileCount: 1,
    snapshotManifestDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson([{ path: 'tests.mjs', digest: compilerProofInternals.sha256('test') }])),
    authorisedExecutionByteSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson([{ path: 'tests.mjs', digest: compilerProofInternals.sha256('test') }])),
    authorisedRoots: ['.'],
    authorisedRootSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(['.'])),
    snapshotRootDigest: compilerProofInternals.sha256('snapshot-root'),
    snapshotPermissionsDigest: compilerProofInternals.sha256('permissions'),
    snapshotReadOnlyVerified: true,
    snapshotPolicy: 'EPHEMERAL_DELETE_AFTER_EXECUTION',
    snapshotExclusions: [],
    snapshotFileCount: 1,
    stagedFileDigests: [{ path: 'tests.mjs', digest: compilerProofInternals.sha256('test') }],
    discoveryAlgorithmDigest: compilerProofInternals.sha256('discovery'),
    rejectionCodeVocabularyDigest: compilerProofInternals.sha256('rejections'),
    dependencyLockDigest: compilerProofInternals.sha256('lock'),
    dependencyByteSetDigest: compilerProofInternals.sha256('dependencies'),
    launcherDigest: compilerProofInternals.sha256('launcher'),
    nodeExecutableDigest: compilerProofInternals.sha256('node'),
    nativeRuntimeDigests: [],
    networkIsolation: 'LINUX_NETWORK_NAMESPACE',
    networkIsolatorDigest: compilerProofInternals.sha256('unshare'),
    nodeFlags: ['--permission', '--no-addons', '<REPOSITORY_LOCAL_TEST_LAUNCHER>'],
    invocationMode: 'NODE_TEST_PROGRAMMATIC_EXACT_FILES',
    isolationMode: 'none',
    invocationDigest: compilerProofInternals.sha256('invocation'),
    localShaclActualServiceAlgebraNodeCount: 0,
    localShaclCandidateSourceSetDigest: compilerProofInternals.sha256('candidate-source'),
    localShaclCandidateViolationCount: 0,
    localShaclCompatibleConstraintSetDigest: compilerProofInternals.sha256('constraint-set'),
    localShaclDeterministicOutputDigest: compilerProofInternals.sha256('local-output'),
    localShaclEvidenceDigest: compilerProofInternals.sha256('local-evidence'),
    localShaclFocusNodeDigest: compilerProofInternals.sha256('focus-nodes'),
    localShaclFocusRootDigest: compilerProofInternals.EXPECTED_FOCUS_ROOT_DIGEST,
    localShaclHarnessSourceDigest: compilerProofInternals.sha256('harness'),
    localShaclLiveServiceConstraintSetDigest: compilerProofInternals.EMPTY_SET_DIGEST,
    localShaclLocallyEvaluatedConstraintCount: 79,
    localShaclPrefixInjectionAlgorithmDigest: compilerProofInternals.sha256('prefix-algorithm'),
    localShaclPythonDependencyByteSetDigest: compilerProofInternals.sha256('python-dependencies'),
    localShaclRegisteredConstraintSetDigest: compilerProofInternals.sha256('constraint-set'),
    localShaclRegisteredConstraintCount: 79,
    localShaclServiceClassificationAlgorithmDigest: compilerProofInternals.sha256('service-classifier'),
    localShaclSubstringBasedExclusionCount: 0,
    localShaclUnexpectedExclusionCount: 0,
    localShaclValidationPhaseResultDigest: compilerProofInternals.sha256('validation-phases'),
    testFileCount: 1,
    testRuntime: 'node@22.23.1',
    testOutputDigest: compilerProofInternals.sha256('test-output'),
    environmentClass: 'urn:usf:environmentclass:hermetic',
    providerMode: 'urn:usf:providermode:deterministictestsubstitute',
    supportedEvidenceKinds: ['urn:usf:evidencekind:validationevidence'],
    evidenceStages: ['emitted'],
    cases: [{ id: 'focused-tests-passed', passed: true }],
    nonclaims: [],
  };
  const hermetic = compilerProofInternals.evidenceManifest({ ...common, evidenceScope: compilerProofInternals.HERMETIC_SCOPE });
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...common }), /unsupported evidence scope/);
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...common, evidenceScope: [compilerProofInternals.HERMETIC_SCOPE, compilerProofInternals.AUTHORITY_SCOPE] }), /unsupported evidence scope/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    providerIdentity: 'urn:usf:provider:livestardogsemanticauthority',
  }), /cannot contain live authority-control claims/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    cases: [{ id: 'candidate-transaction-rolled-back', passed: true }],
  }), /cannot contain live authority-control claims/);
  assert.throws(() => compilerProofInternals.validateCompositeScopes([hermetic, hermetic]), /silently merge/);
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...common, evidenceScope: compilerProofInternals.AUTHORITY_SCOPE }), /live authority-control evidence manifest requires/);
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...common, evidenceScope: compilerProofInternals.HERMETIC_SCOPE, descriptorDigest: compilerProofInternals.sha256('self') }), /derived outputs/);
});

test('rejects proof and evidence outputs from the implementation source digest', () => {
  const { root } = fixture();
  assert.throws(() => compilerProofInternals.sourceSet(root, ['.work/proof-result.json']), /generated proof output/);
  assert.throws(() => compilerProofInternals.sourceSet(root, ['semantic-model/assurance/evidence.trig']), /generated proof output/);
});
