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
  writeFileSync(join(root, 'dependency.mjs'), 'export const dependency = true;\n');
  writeFileSync(join(root, 'tests.mjs'), "import { dependency } from './dependency.mjs'; export const tests = dependency;\n");
  writeFileSync(join(root, 'substitute.mjs'), 'export const substitute = true;\n');
  writeFileSync(join(root, 'package-lock.json'), '{"lockfileVersion":3}\n');
  roots.push(root);
  return { root, casRoot };
}

function focusedResult(root, passed = true) {
  const tests = compilerProofInternals.sourceSet(root, ['tests.mjs']);
  const stagedFileDigests = compilerProofInternals.sourceSet(root, [
    'dependency.mjs', 'package-lock.json', 'proof.mjs', 'source.mjs', 'tests.mjs',
  ]).records;
  const resolvedModuleRecords = stagedFileDigests.filter(({ path }) => path !== 'package-lock.json');
  const resolvedModuleSetDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(resolvedModuleRecords));
  const loadedModuleRecords = resolvedModuleRecords;
  const loadedModuleSetDigest = resolvedModuleSetDigest;
  const bootstrapModuleRecords = resolvedModuleRecords.filter(({ path }) => ['proof.mjs', 'source.mjs'].includes(path));
  const bootstrapModuleSetDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(bootstrapModuleRecords));
  const fileBinding = (path, digest, inode) => ({ device: '1', digest, inode: String(inode), path, size: '1' });
  const nodeExecutableBinding = fileBinding('/runtime/node', compilerProofInternals.sha256('node'), 1);
  const nativeRuntimeBindings = [fileBinding('/runtime/libnode.so', compilerProofInternals.sha256('native-runtime'), 2)];
  const nativeRuntimeDigests = [{ path: '/runtime/libnode.so', digest: compilerProofInternals.sha256('native-runtime') }];
  const virtualSharedObjects = [];
  const runtimeCore = {
    nodeVersion: '22.23.1',
    node: nodeExecutableBinding,
    nativeFiles: nativeRuntimeBindings,
    virtualSharedObjects,
  };
  const nativeRuntimeBindingDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(runtimeCore));
  const networkIsolatorBinding = fileBinding('/usr/bin/unshare', compilerProofInternals.sha256('unshare'), 3);
  const environment = {
    LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TEMP: '<RUNTIME_ROOT>', TMP: '<RUNTIME_ROOT>', TMPDIR: '<RUNTIME_ROOT>',
    TZ: 'UTC', USF_HERMETIC_TEST_MODE: '1', USF_TEST_INVENTORY_DIGEST: tests.digest,
  };
  const nodeFlags = [
    '--frozen-intrinsics', '--permission', '--allow-fs-read=<SNAPSHOT_ROOT>', '--allow-fs-read=<RUNTIME_ROOT>', '--allow-fs-write=<RUNTIME_ROOT>',
    '--allow-fs-read=/var/lib/usf-cas', '--allow-fs-read=<NODE_EXECUTABLE>', '--allow-fs-read=/runtime/libnode.so', '--no-addons',
    '<REPOSITORY_LOCAL_TEST_LAUNCHER>', 'tests.mjs',
  ];
  const launcherDigest = bootstrapModuleRecords.find(({ path }) => path === 'proof.mjs').digest;
  const discoveryAlgorithmDigest = bootstrapModuleRecords.find(({ path }) => path === 'source.mjs').digest;
  const invocationDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson({
    nodeVersion: '22.23.1', nodeExecutableBinding, launcherDigest, bootstrapModuleSetDigest,
    nativeRuntimeBindingDigest, networkIsolatorBinding,
    args: ['<NETWORK_ISOLATOR>', '--net', '--', '<NODE_EXECUTABLE>', ...nodeFlags], environment,
  }));
  const snapshotManifestDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(stagedFileDigests));
  const snapshotPermissionsDigest = compilerProofInternals.sha256('permissions');
  const snapshotExclusions = [];
  const testSummary = {
    counts: { cancelled: 0, failed: passed ? 0 : 1, passed: passed ? 7 : 6, skipped: 0, suites: 0, tests: 7, todo: 0, topLevel: 1 },
    success: passed,
  };
  return {
    passed,
    count: 7,
    discoveredFileCount: 1,
    testInventoryDigest: tests.digest,
    preExecutionReboundDigest: tests.digest,
    stagedTestInventoryDigest: tests.digest,
    executedTestInventoryDigest: tests.digest,
    executedByteSetDigest: loadedModuleSetDigest,
    launcherObservedTestInventoryDigest: tests.digest,
    launcherObservedTestFileCount: 1,
    loadedModuleCount: loadedModuleRecords.length,
    loadedModuleRecords,
    loadedModuleSetDigest,
    resolvedModuleCount: resolvedModuleRecords.length,
    resolvedModuleRecords,
    resolvedModuleSetDigest,
    snapshotManifestDigest,
    authorisedExecutionByteSetDigest: snapshotManifestDigest,
    authorisedRoots: ['.'],
    authorisedRootSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(['.'])),
    snapshotRootDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson({
      snapshotManifestDigest, permissionsDigest: snapshotPermissionsDigest, exclusions: snapshotExclusions,
    })),
    snapshotPermissionsDigest,
    snapshotReadOnlyVerified: true,
    snapshotPolicy: 'EPHEMERAL_DELETE_AFTER_EXECUTION',
    snapshotExclusions,
    snapshotFileCount: stagedFileDigests.length,
    stagedFileDigests,
    discoveryAlgorithmDigest,
    rejectionCodeVocabularyDigest: compilerProofInternals.sha256('rejections'),
    dependencyLockDigest: stagedFileDigests.find(({ path }) => path === 'package-lock.json').digest,
    dependencyByteSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson([])),
    launcherDigest,
    bootstrapModuleRecords,
    bootstrapModuleSetDigest,
    nodeExecutableBinding,
    nodeExecutableDigest: nodeExecutableBinding.digest,
    nativeRuntimeBindings,
    nativeRuntimeDigests,
    nativeRuntimeSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(nativeRuntimeDigests)),
    nativeRuntimePreBindingDigest: nativeRuntimeBindingDigest,
    nativeRuntimeChildBindingDigest: nativeRuntimeBindingDigest,
    nativeRuntimePostBindingDigest: nativeRuntimeBindingDigest,
    virtualSharedObjects,
    networkIsolation: 'LINUX_NETWORK_NAMESPACE',
    networkIsolatorBinding,
    networkIsolatorPostBinding: networkIsolatorBinding,
    networkIsolatorDigest: networkIsolatorBinding.digest,
    nodeFlags,
    nodeVersion: '22.23.1',
    invocationMode: 'NODE_TEST_PROGRAMMATIC_EXACT_FILES',
    isolationMode: 'none',
    invocationDigest,
    expectedDenialCodes: {
      childProcess: 'ERR_ACCESS_DENIED', filesystemRead: 'ERR_ACCESS_DENIED', filesystemWrite: 'ERR_ACCESS_DENIED',
      network: ['EACCES', 'ENETDOWN', 'ENETUNREACH'], worker: 'ERR_ACCESS_DENIED',
    },
    environment,
    testSummary,
    outputDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(testSummary)),
  };
}

function optionClosureResult() {
  const gateCounters = Object.fromEntries(compilerProofInternals.GATE_COUNTER_NAMES.map((name) => [name, 0]));
  const closureStates = ['repositoryarchitectureandnaming', 'semanticmodelcompilationrealisation', 'semanticauthoritycontrolselection']
    .map((decision) => ({ decision: `urn:usf:realisationdecision:${decision}`, state: 'COMPLETE' }));
  const resultCore = {
    schemaVersion: 1,
    gate: 'REALISATION_OPTION_EVALUATION_CLOSURE',
    acceptedDecisionCount: 3,
    criterionCount: 31,
    findings: [],
    gateCounters,
    closureStates,
    reasonCodeVocabularyDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(compilerProofInternals.REASON_PRECEDENCE)),
  };
  const evaluated = {
    ...resultCore,
    ok: true,
    resultDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(resultCore)),
    evaluatedAuthorityDigest: authorityDigest,
    evaluationEvidenceDigest: compilerProofInternals.sha256('option-evaluation-evidence'),
    evaluationDependencySetDigest: compilerProofInternals.sha256('option-evaluation-dependencies'),
    evaluationImplementationSourceDigest: compilerProofInternals.sha256('option-evaluation-implementation'),
    sourceSetDigest: compilerProofInternals.sha256('option-evaluation-source-set'),
    sourceFileCount: 46,
  };
  return { ...evaluated, evidenceDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(evaluated)) };
}

function rebindOptionClosure(overrides = {}, omitted = []) {
  const candidate = { ...optionClosureResult(), ...overrides };
  const resultCore = {
    schemaVersion: candidate.schemaVersion,
    gate: candidate.gate,
    acceptedDecisionCount: candidate.acceptedDecisionCount,
    criterionCount: candidate.criterionCount,
    findings: candidate.findings,
    gateCounters: candidate.gateCounters,
    closureStates: candidate.closureStates,
    reasonCodeVocabularyDigest: candidate.reasonCodeVocabularyDigest,
  };
  candidate.resultDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(resultCore));
  delete candidate.evidenceDigest;
  for (const field of omitted) delete candidate[field];
  candidate.evidenceDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(candidate));
  return candidate;
}

function plantedFixtureEvidence(overrides = {}) {
  const cases = [
    ['candidate-authorisation-prohibited', 'UNIVERSAL_CANDIDATE_AUTHORISATION_PROHIBITED'],
    ['candidate-datatype-endpoint-absent', 'UNIVERSAL_CANDIDATE_ENDPOINT_MODE_INVALID'],
    ['candidate-form-component-conflict', 'UNIVERSAL_CANDIDATE_FORM_COMPONENT_CONFLICT'],
    ['candidate-kind-absent', 'UNIVERSAL_CANDIDATE_KIND_ABSENT'],
    ['candidate-missing-subject', 'UNIVERSAL_CANDIDATE_SUBJECT_ABSENT'],
    ['candidate-object-endpoint-conflict', 'UNIVERSAL_CANDIDATE_ENDPOINT_MODE_INVALID'],
    ['candidate-warranted-with-gaps', 'UNIVERSAL_CANDIDATE_WARRANTED_WITH_GAPS'],
    ['mismatched-family-components', 'PERMUTATION_FAMILY_SIGNATURE_COMPONENT_MISMATCH'],
    ['missing-family-subject', 'PERMUTATION_FAMILY_SIGNATURE_SUBJECT_ABSENT'],
    ['missing-reviewed-term', 'UNIVERSAL_REVIEW_TERM_ABSENT'],
    ['missing-term-algorithm', 'PERMUTATION_REVIEW_TERM_ALGORITHM_ABSENT'],
    ['positive-datatype-candidate', null],
    ['positive-family-candidate', null],
    ['positive-family-review', null],
    ['positive-object-candidate', null],
    ['positive-relationship-review', null],
    ['positive-review-coverage', null],
    ['positive-term-review', null],
    ['relationship-review-authorisation-prohibited', 'PERMUTATION_RELATIONSHIP_REVIEW_AUTHORISATION_PROHIBITED'],
    ['relationship-review-signature-absent', 'PERMUTATION_RELATIONSHIP_REVIEW_SIGNATURE_ABSENT'],
    ['semantic-review-algorithm-absent', 'PERMUTATION_SEMANTIC_REVIEW_ALGORITHM_ABSENT'],
    ['semantic-review-disposition-absent', 'PERMUTATION_SEMANTIC_REVIEW_DISPOSITION_ABSENT'],
    ['semantic-review-evidence-absent', 'PERMUTATION_SEMANTIC_REVIEW_EVIDENCE_ABSENT'],
    ['semantic-review-rationale-absent', 'PERMUTATION_SEMANTIC_REVIEW_RATIONALE_ABSENT'],
    ['term-set-mismatch', 'PERMUTATION_REVIEW_TERM_SET_MISMATCH'],
  ];
  const catalogue = cases.map(([id, code]) => ({
    id,
    focusNode: `urn:usf:fixture:permutation-review:${id.replaceAll('-', '')}`,
    expectedResult: code ? 'REJECTED' : 'ACCEPTED',
    expectedReasonCodes: code ? [code] : [],
  }));
  const resultRecords = catalogue.map((record) => ({
    id: record.id,
    focusNode: record.focusNode,
    expectedResult: record.expectedResult,
    actualResult: record.expectedResult,
    expectedReasonCodes: record.expectedReasonCodes,
    actualReasonCodes: record.expectedReasonCodes,
    resultCount: record.expectedReasonCodes.length,
  }));
  const reasonCodeSet = [...new Set(catalogue.flatMap(({ expectedReasonCodes }) => expectedReasonCodes))].sort();
  const core = {
    schemaVersion: 1,
    validationScope: 'PLANTED_PERMUTATION_REVIEW_FIXTURES',
    fixtureIsolation: 'IN_MEMORY_UNPUBLISHED_CANDIDATE',
    caseCount: catalogue.length,
    positiveControlCount: 7,
    negativeControlCount: 18,
    catalogue,
    catalogueDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(catalogue)),
    focusNodeSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(catalogue.map(({ focusNode }) => focusNode).sort())),
    fixtureTripleCount: 96,
    fixtureGraphDigest: compilerProofInternals.sha256('fixture-graph'),
    rawValidationConforms: false,
    resultRecords,
    resultDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(resultRecords)),
    reasonCodeSet,
    reasonCodeSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(reasonCodeSet)),
    missingExpectedCount: 0,
    unexpectedCodeCount: 0,
    multipleCodeCount: 0,
    unrecognisedResultCount: 0,
    contractConforms: true,
    ...overrides,
  };
  return { ...core, evidenceDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(core)) };
}

function localShaclResult(overrides = {}) {
  const focusRootDigest = compilerProofInternals.sha256('focus-roots');
  const classifier = [
    'via-service-predicate', 'managed-service-token', 'service-string-literal', 'service-comment',
    'service-variable-name', 'service-iri', 'service-clause',
  ].map((id) => ({ id, expectedLiveDependent: id === 'service-clause', actualLiveDependent: id === 'service-clause' }));
  const plantedFixtures = plantedFixtureEvidence();
  const evidence = {
    schemaVersion: 1,
    evidenceScope: 'HERMETIC_SUBSTITUTE',
    validationScope: 'LOCAL_PYSHACL_COMPATIBLE_AFFECTED_CLOSURE',
    localCompatibleConforms: true,
    registeredSparqlConstraintCount: 125,
    locallyEvaluatedConstraintCount: 125,
    actualServiceAlgebraNodeCount: 0,
    liveServiceConstraintCount: 0,
    liveServiceConstraintSetDigest: compilerProofInternals.EMPTY_SET_DIGEST,
    substringBasedExclusionCount: 0,
    unexpectedExclusionCount: 0,
    candidateViolationCount: 0,
    serviceConstraintsCountedAsLocalPass: 0,
    prefixInjectionDeterministic: true,
    prefixSemanticsEquivalent: true,
    prefixSemanticEquivalenceCount: 125,
    pyshaclServiceDetectionMode: 'PARSED_SPARQL_ALGEBRA',
    transitiveFocusGap: 0,
    focusRootCount: 336,
    focusRootDigest,
    focusNodeCount: 557,
    focusNodeDigest: compilerProofInternals.sha256('focus-nodes'),
    serviceClassifierSelfTestCount: 7,
    serviceClassifierSelfTests: classifier,
    plantedFixtureEvidence: plantedFixtures,
    plantedFixtureEvidenceDigest: plantedFixtures.evidenceDigest,
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
    expectedScope: {
      registeredSparqlConstraintCount: evidence.registeredSparqlConstraintCount,
      registeredConstraintSetDigest: evidence.registeredConstraintSetDigest,
      shapeSourceFileCount: 11,
      shapeSourceSetDigest: evidence.shapeSourceSetDigest,
      focusRootCount: evidence.focusRootCount,
      focusRootDigest: evidence.focusRootDigest,
    },
  };
}

function liveValidationResult(local = localShaclResult()) {
  const makeReceipt = (phase) => {
    const core = {
      conforms: true,
      validatedDocumentCount: local.expectedScope.shapeSourceFileCount,
      validatedDocumentSetDigest: local.expectedScope.shapeSourceSetDigest,
      observationSetDigest: compilerProofInternals.sha256(phase),
    };
    return { ...core, receiptDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(core)) };
  };
  const core = {
    authored: makeReceipt('authored-live-validation'),
    derived: makeReceipt('derived-live-validation'),
    validatedDocumentCount: local.expectedScope.shapeSourceFileCount,
    validatedDocumentSetDigest: local.expectedScope.shapeSourceSetDigest,
  };
  return { ...core, receiptDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(core)) };
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
    sourcePaths: ['dependency.mjs', 'package-lock.json', 'proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => focusedResult(root),
    runLocalCompatibleShacl: async () => localShaclResult(),
    realisationOptionClosure: optionClosureResult(),
    createCommand: () => ({ execute: async () => ({
      evaluatedAuthorityDigest: authorityDigest,
      semanticModelPath: 'semantic-model',
      contaminationCount: 0,
      commitOutcome: { state: 'validated-rolled-back', exactCandidateStateVerified: true, candidateDigest: `sha256:${'b'.repeat(64)}` },
      liveValidation: liveValidationResult(),
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
  assert.equal(hermetic.localShaclRegisteredConstraintCount, 125);
  assert.equal(hermetic.localShaclActualServiceAlgebraNodeCount, 0);
  assert.equal(hermetic.localShaclValidationPhaseResultDigest, localShaclResult().evidence.validationPhaseResultDigest);
  assert.equal(hermetic.localShaclPlantedFixtureCaseCount, 25);
  assert.equal(hermetic.localShaclPlantedFixtureNegativeControlCount, 18);
  assert.equal(hermetic.localShaclPlantedFixturePositiveControlCount, 7);
  assert.equal(hermetic.localShaclPlantedFixtureEvidenceDigest, localShaclResult().evidence.plantedFixtureEvidence.evidenceDigest);
  assert.equal(authorityControl.liveServiceConstraintCount, 0);
  assert.equal(authorityControl.liveServiceConstraintSetDigest, hermetic.localShaclLiveServiceConstraintSetDigest);
  assert.equal(Object.hasOwn(authorityControl, 'snapshotManifestDigest'), false);
  for (const scoped of [hermetic, authorityControl]) {
    const { evidenceDigest, ...claims } = scoped;
    assert.equal(evidenceDigest, compilerProofInternals.sha256(compilerProofInternals.canonicalJson(claims)));
  }
  const { evidenceDigest: _authorityEvidenceDigest, ...authorityCore } = authorityControl;
  const substitutedAuthority = compilerProofInternals.evidenceManifest({
    ...authorityCore,
    implementationSourceDigest: compilerProofInternals.sha256('cross-scope-substitution'),
  });
  assert.throws(() => compilerProofInternals.validateCompositeScopes([hermetic, substitutedAuthority]), /exact cross-scope constraint boundaries/);
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
    sourcePaths: ['dependency.mjs', 'package-lock.json', 'proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runLocalCompatibleShacl: async () => localShaclResult(),
    realisationOptionClosure: optionClosureResult(),
    createCommand: () => ({ execute: async () => ({
      evaluatedAuthorityDigest: `sha256:${'c'.repeat(64)}`,
      liveValidation: liveValidationResult(),
    }) }),
  };
  const focused = (passed) => focusedResult(root, passed);
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
    sourcePaths: ['dependency.mjs', 'package-lock.json', 'proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => focusedResult(root),
    runLocalCompatibleShacl: async () => localShaclResult({ candidateViolationCount: 1 }),
    realisationOptionClosure: optionClosureResult(),
  }), /does not close the exact compatible affected constraint scope/);
  assert.equal(liveClientCreated, false);

  const mismatchedScope = localShaclResult();
  mismatchedScope.expectedScope = {
    ...mismatchedScope.expectedScope,
    focusRootDigest: compilerProofInternals.sha256('wrong-focus-root-set'),
  };
  await assert.rejects(() => evaluateCompilerSemanticEnforcement({
    authorityDigest,
    evaluatedAt: '2026-07-18T13:30:00Z',
    repositoryRoot: root,
    casRoot,
    createLiveClient: async () => { liveClientCreated = true; return {}; },
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    sourcePaths: ['dependency.mjs', 'package-lock.json', 'proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => focusedResult(root),
    runLocalCompatibleShacl: async () => mismatchedScope,
    realisationOptionClosure: optionClosureResult(),
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
    sourcePaths: ['dependency.mjs', 'package-lock.json', 'proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => focusedResult(root),
    runLocalCompatibleShacl: async () => localShaclResult({ validationPhaseResults: invalidPhases }),
    realisationOptionClosure: optionClosureResult(),
  }), /does not close the exact compatible affected constraint scope/);
  assert.equal(liveClientCreated, false);
});

test('rejects malformed planted-fixture evidence with exact outer digest bindings', () => {
  for (const mutation of [
    { caseCount: 24 },
    { positiveControlCount: 6 },
    { negativeControlCount: 17 },
    { unexpectedCodeCount: 1, contractConforms: false },
    { missingExpectedCount: 1, contractConforms: false },
    { multipleCodeCount: 1, contractConforms: false },
    { unrecognisedResultCount: 1, contractConforms: false },
  ]) {
    const planted = plantedFixtureEvidence(mutation);
    const local = localShaclResult({
      plantedFixtureEvidence: planted,
      plantedFixtureEvidenceDigest: planted.evidenceDigest,
    });
    assert.throws(
      () => compilerProofInternals.validateLocalShaclEvidence(local),
      /planted-fixture evidence does not close exact reason-code precedence/,
    );
  }

  const valid = plantedFixtureEvidence();
  const alteredResults = valid.resultRecords.map((record, index) => index === 0
    ? { ...record, actualReasonCodes: [], actualResult: 'ACCEPTED', resultCount: 0 }
    : record);
  const substituted = plantedFixtureEvidence({
    resultRecords: alteredResults,
    resultDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(alteredResults)),
  });
  const substitutedLocal = localShaclResult({
    plantedFixtureEvidence: substituted,
    plantedFixtureEvidenceDigest: substituted.evidenceDigest,
  });
  assert.throws(
    () => compilerProofInternals.validateLocalShaclEvidence(substitutedLocal),
    /result does not match its exact expected branch/,
  );
});

test('rejects incomplete realisation-option closure before focused tests or live access', async () => {
  const { root, casRoot } = fixture();
  let focusedTestsStarted = false;
  let liveClientCreated = false;
  await assert.rejects(() => evaluateCompilerSemanticEnforcement({
    authorityDigest,
    evaluatedAt: '2026-07-18T13:30:00Z',
    repositoryRoot: root,
    casRoot,
    createLiveClient: async () => { liveClientCreated = true; return {}; },
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    sourcePaths: ['dependency.mjs', 'package-lock.json', 'proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => { focusedTestsStarted = true; return focusedResult(root); },
    runLocalCompatibleShacl: async () => localShaclResult(),
    realisationOptionClosure: {
      ...optionClosureResult(),
      ok: false,
      gateCounters: { acceptedDecisionsWithoutEvaluationClosure: 1 },
    },
  }), /realisation option evaluation closure is incomplete or stale/);
  assert.equal(focusedTestsStarted, false);
  assert.equal(liveClientCreated, false);
});

test('rejects every malformed option-closure binding and resolved-module substitution locally', async () => {
  const valid = optionClosureResult();
  const invalidClosures = [
    undefined,
    rebindOptionClosure({ gate: 'WRONG_GATE' }),
    rebindOptionClosure({ evaluatedAuthorityDigest: `sha256:${'b'.repeat(64)}` }),
    rebindOptionClosure({ gateCounters: {} }),
    rebindOptionClosure({ gateCounters: { ...valid.gateCounters, unknownCounter: 0 } }),
    rebindOptionClosure({ gateCounters: { ...valid.gateCounters, [compilerProofInternals.GATE_COUNTER_NAMES[0]]: 1 } }),
    rebindOptionClosure({ acceptedDecisionCount: 0, closureStates: [] }),
    rebindOptionClosure({ closureStates: [null, valid.closureStates[1], valid.closureStates[2]] }),
    rebindOptionClosure({ closureStates: [valid.closureStates[0], valid.closureStates[0], valid.closureStates[2]] }),
    rebindOptionClosure({ closureStates: valid.closureStates.map((item, index) => index === 0 ? { ...item, state: 'INCOMPLETE' } : item) }),
    ...['resultDigest', 'evaluationEvidenceDigest', 'evaluationDependencySetDigest', 'evaluationImplementationSourceDigest', 'sourceSetDigest']
      .map((field) => rebindOptionClosure({}, [field])),
  ];
  for (const candidate of invalidClosures) {
    assert.throws(() => compilerProofInternals.validateRealisationOptionClosure(candidate, authorityDigest), /incomplete or stale|digest is invalid/);
  }

  const { root, casRoot } = fixture();
  let localShaclStarted = false;
  let liveClientCreated = false;
  const invalidFocused = focusedResult(root);
  invalidFocused.loadedModuleRecords = [{ path: 'ambient.mjs', digest: compilerProofInternals.sha256('ambient') }];
  invalidFocused.loadedModuleCount = 1;
  invalidFocused.loadedModuleSetDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(invalidFocused.loadedModuleRecords));
  invalidFocused.executedByteSetDigest = invalidFocused.loadedModuleSetDigest;
  await assert.rejects(() => evaluateCompilerSemanticEnforcement({
    authorityDigest,
    evaluatedAt: '2026-07-18T13:30:00Z',
    repositoryRoot: root,
    casRoot,
    createLiveClient: async () => { liveClientCreated = true; return {}; },
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    sourcePaths: ['dependency.mjs', 'package-lock.json', 'proof.mjs', 'source.mjs', 'substitute.mjs', 'tests.mjs'],
    proofAlgorithmPath: 'proof.mjs',
    testPaths: ['tests.mjs'],
    substituteSourcePaths: ['substitute.mjs'],
    runFocusedTests: async () => invalidFocused,
    runLocalCompatibleShacl: async () => { localShaclStarted = true; return localShaclResult(); },
    realisationOptionClosure: valid,
  }), /exact resolved and loaded modules with locked runtime inputs/);
  assert.equal(localShaclStarted, false);
  assert.equal(liveClientCreated, false);
});

test('rejects mixed, mislabeled, live-claiming and self-referential evidence', () => {
  const testInventory = [{ path: 'tests.mjs', digest: compilerProofInternals.sha256('test') }];
  const testInventoryDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(testInventory));
  const substituteImplementationSources = [{ path: 'substitute.mjs', digest: compilerProofInternals.sha256('substitute') }];
  const bootstrapModuleRecords = [
    { path: 'proof.mjs', digest: compilerProofInternals.sha256('launcher') },
    { path: 'source.mjs', digest: compilerProofInternals.sha256('discovery') },
  ];
  const bootstrapModuleSetDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(bootstrapModuleRecords));
  const implementationSources = [...bootstrapModuleRecords, ...substituteImplementationSources, ...testInventory]
    .sort(({ path: left }, { path: right }) => left.localeCompare(right));
  const packageLock = { path: 'package-lock.json', digest: compilerProofInternals.sha256('lock') };
  const stagedFileDigests = [packageLock, ...bootstrapModuleRecords, ...substituteImplementationSources, ...testInventory]
    .sort(({ path: left }, { path: right }) => left.localeCompare(right));
  const snapshotManifestDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(stagedFileDigests));
  const resolvedModuleRecords = [...bootstrapModuleRecords, ...substituteImplementationSources, ...testInventory]
    .sort(({ path: left }, { path: right }) => left.localeCompare(right));
  const resolvedModuleSetDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(resolvedModuleRecords));
  const loadedModuleRecords = [...bootstrapModuleRecords, ...testInventory]
    .sort(({ path: left }, { path: right }) => left.localeCompare(right));
  const loadedModuleSetDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(loadedModuleRecords));
  const binding = (path, digest, inode) => ({ device: '1', digest, inode: String(inode), path, size: '1' });
  const nodeExecutableBinding = binding('/runtime/node', compilerProofInternals.sha256('node'), 1);
  const nativeRuntimeBindings = [binding('/runtime/libnode.so', compilerProofInternals.sha256('native-runtime'), 2)];
  const nativeRuntimeDigests = [{ path: '/runtime/libnode.so', digest: compilerProofInternals.sha256('native-runtime') }];
  const virtualSharedObjects = [];
  const runtimeCore = { nodeVersion: '22.23.1', node: nodeExecutableBinding, nativeFiles: nativeRuntimeBindings, virtualSharedObjects };
  const runtimeBindingDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson(runtimeCore));
  const networkIsolatorBinding = binding('/usr/bin/unshare', compilerProofInternals.sha256('unshare'), 3);
  const environment = {
    LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TEMP: '<RUNTIME_ROOT>', TMP: '<RUNTIME_ROOT>', TMPDIR: '<RUNTIME_ROOT>',
    TZ: 'UTC', USF_HERMETIC_TEST_MODE: '1', USF_TEST_INVENTORY_DIGEST: testInventoryDigest,
  };
  const nodeFlags = [
    '--frozen-intrinsics', '--permission', '--allow-fs-read=<SNAPSHOT_ROOT>', '--allow-fs-read=<RUNTIME_ROOT>', '--allow-fs-write=<RUNTIME_ROOT>',
    '--allow-fs-read=/var/lib/usf-cas', '--allow-fs-read=<NODE_EXECUTABLE>', '--allow-fs-read=/runtime/libnode.so', '--no-addons',
    '<REPOSITORY_LOCAL_TEST_LAUNCHER>', 'tests.mjs',
  ];
  const invocationDigest = compilerProofInternals.sha256(compilerProofInternals.canonicalJson({
    nodeVersion: '22.23.1', nodeExecutableBinding, launcherDigest: bootstrapModuleRecords[0].digest,
    bootstrapModuleSetDigest, nativeRuntimeBindingDigest: runtimeBindingDigest, networkIsolatorBinding,
    args: ['<NETWORK_ISOLATOR>', '--net', '--', '<NODE_EXECUTABLE>', ...nodeFlags], environment,
  }));
  const snapshotPermissionsDigest = compilerProofInternals.sha256('permissions');
  const snapshotExclusions = [];
  const testSummary = {
    counts: { cancelled: 0, failed: 0, passed: 1, skipped: 0, suites: 0, tests: 1, todo: 0, topLevel: 1 },
    success: true,
  };
  const common = {
    schemaVersion: 2,
    evaluatedAt: '2026-07-18T13:30:00Z',
    providerIdentity: 'urn:usf:provider:compilerfocusedtestsubstitute',
    liveAuthorityDependency: false,
    implementationSourceDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(implementationSources)),
    implementationSources,
    substituteImplementationDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(substituteImplementationSources)),
    substituteImplementationSources,
    proofAlgorithmDigest: bootstrapModuleRecords[0].digest,
    realisationOptionClosureEvidenceDigest: compilerProofInternals.sha256('option-closure-evidence'),
    realisationOptionClosureResultDigest: compilerProofInternals.sha256('option-closure-result'),
    realisationOptionEvaluationDependencyDigest: compilerProofInternals.sha256('option-evaluation-dependencies'),
    realisationOptionEvaluationEvidenceDigest: compilerProofInternals.sha256('option-evaluation-evidence'),
    realisationOptionEvaluationImplementationSourceDigest: compilerProofInternals.sha256('option-evaluation-implementation'),
    realisationOptionEvaluationSourceSetDigest: compilerProofInternals.sha256('option-evaluation-source-set'),
    testSetDigest: testInventoryDigest,
    testInventoryDigest,
    preExecutionReboundDigest: testInventoryDigest,
    stagedTestInventoryDigest: testInventoryDigest,
    executedTestInventoryDigest: testInventoryDigest,
    executedByteSetDigest: loadedModuleSetDigest,
    launcherObservedTestInventoryDigest: testInventoryDigest,
    launcherObservedTestFileCount: 1,
    loadedModuleCount: loadedModuleRecords.length,
    loadedModuleRecords,
    loadedModuleSetDigest,
    resolvedModuleCount: resolvedModuleRecords.length,
    resolvedModuleRecords,
    resolvedModuleSetDigest,
    snapshotManifestDigest,
    authorisedExecutionByteSetDigest: snapshotManifestDigest,
    authorisedRoots: ['.'],
    authorisedRootSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(['.'])),
    snapshotRootDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson({
      snapshotManifestDigest, permissionsDigest: snapshotPermissionsDigest, exclusions: snapshotExclusions,
    })),
    snapshotPermissionsDigest,
    snapshotReadOnlyVerified: true,
    snapshotPolicy: 'EPHEMERAL_DELETE_AFTER_EXECUTION',
    snapshotExclusions,
    snapshotFileCount: stagedFileDigests.length,
    stagedFileDigests,
    testInventory,
    discoveryAlgorithmDigest: bootstrapModuleRecords[1].digest,
    rejectionCodeVocabularyDigest: compilerProofInternals.sha256('rejections'),
    dependencyLockDigest: packageLock.digest,
    dependencyByteSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson([])),
    launcherDigest: bootstrapModuleRecords[0].digest,
    bootstrapModuleRecords,
    bootstrapModuleSetDigest,
    nodeExecutableBinding,
    nodeExecutableDigest: nodeExecutableBinding.digest,
    nodeVersion: '22.23.1',
    nativeRuntimeBindings,
    nativeRuntimeDigests,
    nativeRuntimeSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(nativeRuntimeDigests)),
    nativeRuntimePreBindingDigest: runtimeBindingDigest,
    nativeRuntimeChildBindingDigest: runtimeBindingDigest,
    nativeRuntimePostBindingDigest: runtimeBindingDigest,
    virtualSharedObjects,
    networkIsolation: 'LINUX_NETWORK_NAMESPACE',
    networkIsolatorBinding,
    networkIsolatorPostBinding: networkIsolatorBinding,
    networkIsolatorDigest: networkIsolatorBinding.digest,
    nodeFlags,
    expectedDenialCodes: {
      childProcess: 'ERR_ACCESS_DENIED', filesystemRead: 'ERR_ACCESS_DENIED', filesystemWrite: 'ERR_ACCESS_DENIED',
      network: ['EACCES', 'ENETDOWN', 'ENETUNREACH'], worker: 'ERR_ACCESS_DENIED',
    },
    environment,
    invocationMode: 'NODE_TEST_PROGRAMMATIC_EXACT_FILES',
    isolationMode: 'none',
    invocationDigest,
    localShaclActualServiceAlgebraNodeCount: 0,
    localShaclCandidateSourceSetDigest: compilerProofInternals.sha256('candidate-source'),
    localShaclCandidateViolationCount: 0,
    localShaclCompatibleConstraintSetDigest: compilerProofInternals.sha256('constraint-set'),
    localShaclDeterministicOutputDigest: compilerProofInternals.sha256('local-output'),
    localShaclEvidenceDigest: compilerProofInternals.sha256('local-evidence'),
    localShaclExpectedFocusRootCount: 336,
    localShaclExpectedFocusRootDigest: compilerProofInternals.sha256('focus-roots'),
    localShaclExpectedRegisteredConstraintCount: 125,
    localShaclExpectedRegisteredConstraintSetDigest: compilerProofInternals.sha256('constraint-set'),
    localShaclExpectedShapeSourceFileCount: 11,
    localShaclExpectedShapeSourceSetDigest: compilerProofInternals.sha256('shape-sources'),
    localShaclFocusNodeCount: 557,
    localShaclFocusNodeDigest: compilerProofInternals.sha256('focus-nodes'),
    localShaclFocusRootCount: 336,
    localShaclFocusRootDigest: compilerProofInternals.sha256('focus-roots'),
    localShaclHarnessSourceDigest: compilerProofInternals.sha256('harness'),
    localShaclLiveServiceConstraintSetDigest: compilerProofInternals.EMPTY_SET_DIGEST,
    localShaclLocallyEvaluatedConstraintCount: 125,
    localShaclPlantedFixtureCatalogueDigest: compilerProofInternals.sha256('fixture-catalogue'),
    localShaclPlantedFixtureCaseCount: 25,
    localShaclPlantedFixtureEvidenceDigest: compilerProofInternals.sha256('fixture-evidence'),
    localShaclPlantedFixtureFixtureGraphDigest: compilerProofInternals.sha256('fixture-graph'),
    localShaclPlantedFixtureFocusNodeSetDigest: compilerProofInternals.sha256('fixture-focus'),
    localShaclPlantedFixtureMissingExpectedCount: 0,
    localShaclPlantedFixtureMultipleCodeCount: 0,
    localShaclPlantedFixtureNegativeControlCount: 18,
    localShaclPlantedFixturePositiveControlCount: 7,
    localShaclPlantedFixtureReasonCodeSetDigest: compilerProofInternals.sha256('fixture-codes'),
    localShaclPlantedFixtureResultDigest: compilerProofInternals.sha256('fixture-results'),
    localShaclPlantedFixtureUnexpectedCodeCount: 0,
    localShaclPlantedFixtureUnrecognisedResultCount: 0,
    localShaclPrefixInjectionAlgorithmDigest: compilerProofInternals.sha256('prefix-algorithm'),
    localShaclPythonDependencyByteSetDigest: compilerProofInternals.sha256('python-dependencies'),
    localShaclRegisteredConstraintSetDigest: compilerProofInternals.sha256('constraint-set'),
    localShaclRegisteredConstraintCount: 125,
    localShaclShapeSourceSetDigest: compilerProofInternals.sha256('shape-sources'),
    localShaclServiceClassificationAlgorithmDigest: compilerProofInternals.sha256('service-classifier'),
    localShaclSubstringBasedExclusionCount: 0,
    localShaclUnexpectedExclusionCount: 0,
    localShaclValidationPhaseResultDigest: compilerProofInternals.sha256('validation-phases'),
    testFileCount: 1,
    testCount: 1,
    testRuntime: 'node@22.23.1',
    testSummary,
    testOutputDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(testSummary)),
    environmentClass: 'urn:usf:environmentclass:hermetic',
    providerMode: 'urn:usf:providermode:deterministictestsubstitute',
    supportedEvidenceKinds: ['urn:usf:evidencekind:runtimeproofevidence', 'urn:usf:evidencekind:validationevidence'],
    evidenceStages: ['emitted', 'collected', 'normalised', 'ingested', 'signed', 'integrityverified'],
    cases: [{ id: 'focused-tests-passed', passed: true }, { id: 'local-compatible-shacl-passed', passed: true }],
    nonclaims: [],
  };
  const hermetic = compilerProofInternals.evidenceManifest({ ...common, evidenceScope: compilerProofInternals.HERMETIC_SCOPE });
  assert.equal(hermetic.executedByteSetDigest, hermetic.loadedModuleSetDigest);
  assert.notEqual(hermetic.executedByteSetDigest, hermetic.resolvedModuleSetDigest);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    cases: [{ id: 'focused-tests-passed', passed: true }],
  }), /complete canonical scope contract/);
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...common }), /structurally mixed evidence scope/);
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...common, evidenceScope: [compilerProofInternals.HERMETIC_SCOPE, compilerProofInternals.AUTHORITY_SCOPE] }), /structurally mixed evidence scope/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    providerIdentity: 'urn:usf:provider:livestardogsemanticauthority',
  }), /cannot contain live authority-control claims/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    candidateAuthorityDigest: compilerProofInternals.sha256('live-candidate'),
  }), /structurally mixed evidence scope/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    cases: [{ id: 'candidate-transaction-rolled-back', passed: true }],
  }), /cannot contain live authority-control claims/);
  assert.throws(() => compilerProofInternals.validateCompositeScopes([hermetic, hermetic]), /silently merge/);
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...common, evidenceScope: compilerProofInternals.AUTHORITY_SCOPE }), /structurally mixed evidence scope/);
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...common, evidenceScope: compilerProofInternals.HERMETIC_SCOPE, descriptorDigest: compilerProofInternals.sha256('self') }), /derived outputs/);
  const { bootstrapModuleRecords: _omittedBootstrap, ...missingBootstrap } = common;
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...missingBootstrap, evidenceScope: compilerProofInternals.HERMETIC_SCOPE }), /structurally mixed evidence scope/);
  const { loadedModuleRecords: _omittedLoaded, ...missingLoaded } = common;
  assert.throws(() => compilerProofInternals.evidenceManifest({ ...missingLoaded, evidenceScope: compilerProofInternals.HERMETIC_SCOPE }), /structurally mixed evidence scope/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    executedByteSetDigest: resolvedModuleSetDigest,
  }), /exact resolved and loaded modules/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    testOutputDigest: compilerProofInternals.sha256('forged-summary'),
  }), /structured test summary/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    nodeFlags: common.nodeFlags.filter((flag) => flag !== '--frozen-intrinsics'),
  }), /locked runtime inputs/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    nodeFlags: common.nodeFlags.filter((flag) => flag !== '--allow-fs-read=/var/lib/usf-cas'),
  }), /execution source, dependency, snapshot or invocation closure/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    nodeFlags: common.nodeFlags.map((flag) => flag === '--allow-fs-read=/var/lib/usf-cas'
      ? '--allow-fs-read=/var/lib/usf-cas-substitute'
      : flag),
  }), /execution source, dependency, snapshot or invocation closure/);
  const substitutedBootstrap = [{ path: 'proof.mjs', digest: compilerProofInternals.sha256('substituted-launcher') }, bootstrapModuleRecords[1]];
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    bootstrapModuleRecords: substitutedBootstrap,
    bootstrapModuleSetDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(substitutedBootstrap)),
  }), /exact resolved and loaded modules/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    nativeRuntimePostBindingDigest: compilerProofInternals.sha256('post-runtime-substitution'),
  }), /equal pre-child-post bindings/);
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    networkIsolatorPostBinding: { ...networkIsolatorBinding, digest: compilerProofInternals.sha256('post-isolator-substitution') },
  }), /execution source, dependency, snapshot or invocation closure/);
  const generatedImplementationSources = implementationSources.map((record) => record.path === 'source.mjs'
    ? { ...record, path: 'proof-result.json' } : record).sort(({ path: left }, { path: right }) => left.localeCompare(right));
  assert.throws(() => compilerProofInternals.evidenceManifest({
    ...common,
    evidenceScope: compilerProofInternals.HERMETIC_SCOPE,
    implementationSources: generatedImplementationSources,
    implementationSourceDigest: compilerProofInternals.sha256(compilerProofInternals.canonicalJson(generatedImplementationSources)),
  }), /execution source, dependency, snapshot or invocation closure/);
});

test('rejects proof outputs, noncanonical paths, symlinks and aliases from the implementation source digest', () => {
  const { root } = fixture();
  assert.throws(() => compilerProofInternals.sourceSet(root, ['.work/proof-result.json']), /generated proof output/);
  assert.throws(() => compilerProofInternals.sourceSet(root, ['semantic-model/assurance/evidence.trig']), /generated proof output/);
  assert.throws(() => compilerProofInternals.sourceSet(root, ['./source.mjs']), /not canonical repository-relative identity/);
  assert.throws(() => compilerProofInternals.sourceSet(root, ['source.mjs', 'source.mjs']), /duplicated/);
  const virtualFileSystem = (stat) => ({
    exists: () => true,
    lstat: () => stat,
    read: () => Buffer.from('unreachable fixture bytes'),
    realpath: (path) => path,
  });
  assert.throws(() => compilerProofInternals.sourceSet(root, ['source-link.mjs'], virtualFileSystem({
    dev: 1, ino: 2, nlink: 1, isFile: () => true, isSymbolicLink: () => true,
  })), /canonical regular repository file/);
  assert.throws(() => compilerProofInternals.sourceSet(root, ['source-hard-link.mjs'], virtualFileSystem({
    dev: 1, ino: 3, nlink: 2, isFile: () => true, isSymbolicLink: () => false,
  })), /canonical regular repository file/);
  const localCas = join(root, 'cas-output');
  mkdirSync(localCas, { recursive: true });
  writeFileSync(join(localCas, 'prior-proof.mjs'), 'generated proof bytes\n');
  assert.throws(() => compilerProofInternals.sourceSet(root, ['cas-output/prior-proof.mjs'], {}, [localCas]), /generated output or CAS root/);
});
