import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

import { createSemanticModelCompilationCommand } from '../../processes/semantic-assurance/semantic-model-compilation-command.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const HERMETIC_SCOPE = 'HERMETIC_SUBSTITUTE';
const AUTHORITY_SCOPE = 'LIVE_AUTHORITY_CONTROL';
const HERMETIC_PROVIDER = 'urn:usf:provider:compilerfocusedtestsubstitute';
const LIVE_PROVIDER = 'urn:usf:provider:livestardogsemanticauthority';
const GENERATED_PROOF_INPUTS = [
  /^\.work\//,
  /^(?:graph|semantic-model)\/assurance\/(?:evidence|proofs)\.trig$/,
  /(?:^|\/)(?:proof-result|evidence-bundle|proof-manifest|cas-receipt|transaction-log)(?:\.|\/|$)/,
];
const CASE_SCOPES = new Map([
  ['focused-tests-passed', HERMETIC_SCOPE],
  ['local-compatible-shacl-passed', HERMETIC_SCOPE],
  ['authority-digest-bound', AUTHORITY_SCOPE],
  ['candidate-transaction-rolled-back', AUTHORITY_SCOPE],
  ['candidate-exact-state-verified', AUTHORITY_SCOPE],
  ['candidate-contamination-zero', AUTHORITY_SCOPE],
  ['candidate-shacl-validated', AUTHORITY_SCOPE],
  ['canonical-semantic-model-path', AUTHORITY_SCOPE],
]);
const EMPTY_SET_DIGEST = 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945';
const EXPECTED_FOCUS_ROOT_DIGEST = 'sha256:f384ec3a9239a477070a71c9c4e54709cd1e39ecf4654b5855810f056565c517';

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

function contained(root, target) {
  const path = relative(root, target);
  return path !== '' && path !== '..' && !path.startsWith(`..${sep}`);
}

function assertAuthoredInput(path) {
  if (typeof path !== 'string' || path.length === 0 || GENERATED_PROOF_INPUTS.some((pattern) => pattern.test(path))) {
    throw new Error(`generated proof output cannot contribute to implementation source digest: ${path}`);
  }
}

function sourceSet(repositoryRoot, sourcePaths) {
  const root = realpathSync(repositoryRoot);
  const records = [...new Set(sourcePaths)].sort().map((path) => {
    assertAuthoredInput(path);
    const target = resolve(root, path);
    if (!contained(root, target) || !existsSync(target)) throw new Error(`proof source is unavailable or outside the repository: ${path}`);
    return { path, digest: sha256(readFileSync(target)) };
  });
  return { records, digest: sha256(canonicalJson(records)) };
}

function evidenceManifest(core) {
  if (Object.hasOwn(core, 'evidenceDigest') || Object.hasOwn(core, 'descriptorDigest')) {
    throw new Error('evidence and descriptor digests are derived outputs, not manifest inputs');
  }
  const manifest = { ...core, evidenceDigest: sha256(canonicalJson(core)) };
  validateEvidenceManifest(manifest);
  return Object.freeze(manifest);
}

function validateEvidenceManifest(manifest) {
  const digestFields = ['implementationSourceDigest', 'proofAlgorithmDigest', 'testSetDigest', 'evidenceDigest'];
  for (const field of digestFields) if (!SHA256.test(manifest?.[field] || '')) throw new Error(`evidence manifest requires ${field}`);
  if (!Array.isArray(manifest?.cases) || manifest.cases.length === 0) throw new Error('evidence manifest requires bounded cases');
  if (!Array.isArray(manifest?.supportedEvidenceKinds) || manifest.supportedEvidenceKinds.length === 0) throw new Error('evidence manifest requires supported evidence kinds');
  if (Object.hasOwn(manifest, 'descriptorDigest')) throw new Error('an evidence manifest cannot contain its own descriptor digest');
  const { evidenceDigest, ...core } = manifest;
  if (evidenceDigest !== sha256(canonicalJson(core))) throw new Error('evidence manifest evidenceDigest does not match its canonical claims');
  if (manifest.evidenceScope === HERMETIC_SCOPE) {
    const hermeticDigestFields = [
      'authorisedExecutionByteSetDigest', 'authorisedRootSetDigest', 'dependencyByteSetDigest',
      'dependencyLockDigest', 'discoveryAlgorithmDigest', 'executedByteSetDigest',
      'executedTestInventoryDigest', 'invocationDigest', 'launcherDigest',
      'launcherObservedTestInventoryDigest', 'localShaclCandidateSourceSetDigest',
      'localShaclCompatibleConstraintSetDigest', 'localShaclEvidenceDigest',
      'localShaclDeterministicOutputDigest', 'localShaclFocusNodeDigest', 'localShaclFocusRootDigest', 'localShaclHarnessSourceDigest',
      'localShaclLiveServiceConstraintSetDigest',
      'localShaclPrefixInjectionAlgorithmDigest', 'localShaclPythonDependencyByteSetDigest',
      'localShaclRegisteredConstraintSetDigest', 'localShaclServiceClassificationAlgorithmDigest',
      'localShaclValidationPhaseResultDigest',
      'networkIsolatorDigest', 'nodeExecutableDigest', 'preExecutionReboundDigest',
      'rejectionCodeVocabularyDigest', 'snapshotManifestDigest', 'snapshotPermissionsDigest',
      'snapshotRootDigest', 'stagedTestInventoryDigest', 'testInventoryDigest', 'testOutputDigest',
    ];
    for (const field of hermeticDigestFields) if (!SHA256.test(manifest?.[field] || '')) throw new Error(`hermetic evidence manifest requires ${field}`);
    if (!Number.isInteger(manifest?.testFileCount) || manifest.testFileCount < 1 || manifest.testRuntime !== 'node@22.23.1') {
      throw new Error('hermetic evidence manifest requires a non-empty Node 22.23.1 test inventory');
    }
    if (manifest.testSetDigest !== manifest.testInventoryDigest
        || manifest.testInventoryDigest !== manifest.preExecutionReboundDigest
        || manifest.preExecutionReboundDigest !== manifest.stagedTestInventoryDigest
        || manifest.stagedTestInventoryDigest !== manifest.executedTestInventoryDigest
        || manifest.executedTestInventoryDigest !== manifest.launcherObservedTestInventoryDigest
        || manifest.executedByteSetDigest !== manifest.executedTestInventoryDigest
        || manifest.authorisedExecutionByteSetDigest !== manifest.snapshotManifestDigest
        || !Array.isArray(manifest.authorisedRoots)
        || manifest.authorisedRootSetDigest !== sha256(canonicalJson(manifest.authorisedRoots))
        || manifest.launcherObservedTestFileCount !== manifest.testFileCount
        || manifest.snapshotReadOnlyVerified !== true
        || manifest.snapshotPolicy !== 'EPHEMERAL_DELETE_AFTER_EXECUTION'
        || manifest.invocationMode !== 'NODE_TEST_PROGRAMMATIC_EXACT_FILES'
        || manifest.isolationMode !== 'none'
        || manifest.networkIsolation !== 'LINUX_NETWORK_NAMESPACE') {
      throw new Error('hermetic evidence manifest test execution bindings are inconsistent');
    }
    if (!Array.isArray(manifest.stagedFileDigests) || manifest.stagedFileDigests.length !== manifest.snapshotFileCount
        || sha256(canonicalJson(manifest.stagedFileDigests)) !== manifest.snapshotManifestDigest
        || !Array.isArray(manifest.nativeRuntimeDigests)
        || manifest.nativeRuntimeDigests.some(({ digest }) => !SHA256.test(digest || ''))
        || !Array.isArray(manifest.nodeFlags) || !manifest.nodeFlags.includes('--permission') || manifest.nodeFlags.includes('--allow-child-process')) {
      throw new Error('hermetic evidence manifest requires exact staged bytes and locked runtime inputs');
    }
    if (manifest.localShaclRegisteredConstraintCount !== 79
        || manifest.localShaclLocallyEvaluatedConstraintCount !== 79
        || manifest.localShaclActualServiceAlgebraNodeCount !== 0
        || manifest.localShaclSubstringBasedExclusionCount !== 0
        || manifest.localShaclUnexpectedExclusionCount !== 0
        || manifest.localShaclCandidateViolationCount !== 0
        || manifest.localShaclLiveServiceConstraintSetDigest !== EMPTY_SET_DIGEST
        || manifest.localShaclFocusRootDigest !== EXPECTED_FOCUS_ROOT_DIGEST) {
      throw new Error('hermetic evidence manifest local SHACL scope is incomplete or overclaimed');
    }
    if (manifest.providerMode !== 'urn:usf:providermode:deterministictestsubstitute'
        || manifest.providerIdentity !== HERMETIC_PROVIDER
        || manifest.environmentClass !== 'urn:usf:environmentclass:hermetic'
        || manifest.liveAuthorityDependency !== false
        || !SHA256.test(manifest.substituteImplementationDigest || '')
        || Object.hasOwn(manifest, 'evaluatedAuthorityDigest')
        || manifest.cases.some(({ id }) => CASE_SCOPES.get(id) !== HERMETIC_SCOPE)) {
      throw new Error('hermetic substitute evidence cannot contain live authority-control claims');
    }
  } else if (manifest.evidenceScope === AUTHORITY_SCOPE) {
    for (const field of ['candidateAuthorityDigest', 'liveValidatedConstraintSetDigest', 'liveValidationReportDigest', 'liveServiceConstraintSetDigest']) {
      if (!SHA256.test(manifest?.[field] || '')) throw new Error(`live authority-control evidence manifest requires ${field}`);
    }
    if (manifest.providerMode !== 'urn:usf:providermode:liveauthoritycontrol'
        || manifest.providerIdentity !== LIVE_PROVIDER
        || manifest.environmentClass !== 'urn:usf:environmentclass:authoritycontrol'
        || !SHA256.test(manifest.evaluatedAuthorityDigest || '')
        || manifest.transactionMode !== 'validate-and-rollback'
        || manifest.postTransactionAuthorityDrift !== 'ZERO'
        || manifest.postTransactionAuthorityDigest !== manifest.evaluatedAuthorityDigest
        || manifest.liveValidatedSparqlConstraintCount !== 79
        || manifest.liveServiceConstraintCount !== 0
        || manifest.liveServiceConstraintSetDigest !== EMPTY_SET_DIGEST
        || manifest.cases.some(({ id }) => CASE_SCOPES.get(id) !== AUTHORITY_SCOPE)
        || Object.hasOwn(manifest, 'snapshotManifestDigest')
        || Object.hasOwn(manifest, 'liveAuthorityDependency')) {
      throw new Error('live authority-control evidence requires an exact authority binding and zero-drift rollback');
    }
  } else {
    throw new Error(`unsupported evidence scope: ${manifest?.evidenceScope}`);
  }
  return true;
}

function validateCompositeScopes(manifests) {
  if (!Array.isArray(manifests) || manifests.length !== 2) throw new Error('composite proof requires exactly two separately typed evidence scopes');
  manifests.forEach(validateEvidenceManifest);
  const scopes = new Set(manifests.map(({ evidenceScope: scope }) => scope));
  if (scopes.size !== 2 || !scopes.has(HERMETIC_SCOPE) || !scopes.has(AUTHORITY_SCOPE)) {
    throw new Error('composite proof cannot silently merge provider scopes');
  }
  const hermetic = manifests.find(({ evidenceScope }) => evidenceScope === HERMETIC_SCOPE);
  const authorityControl = manifests.find(({ evidenceScope }) => evidenceScope === AUTHORITY_SCOPE);
  if (hermetic.evidenceDigest === authorityControl.evidenceDigest
      || hermetic.localShaclLiveServiceConstraintSetDigest !== authorityControl.liveServiceConstraintSetDigest) {
    throw new Error('composite proof must preserve distinct evidence identities and exact cross-scope constraint boundaries');
  }
  return true;
}

function validateLocalShaclEvidence(result) {
  if (result?.deterministicRegenerationCount !== 2
      || !SHA256.test(result?.deterministicOutputDigest || '')
      || result.firstOutputDigest !== result.deterministicOutputDigest
      || result.secondOutputDigest !== result.deterministicOutputDigest) {
    throw new Error('local SHACL evidence requires two byte-identical deterministic executions');
  }
  const evidence = result.evidence;
  const digestFields = [
    'candidateSourceSetDigest', 'compatibleConstraintSetDigest', 'dataSourceSetDigest',
    'dependencySpecificationDigest', 'evidenceDigest', 'focusClosureAlgorithmDigest',
    'focusClosureWitnessDigest', 'focusNodeDigest', 'focusPredicatePolicyDigest', 'focusRootDigest',
    'harnessSourceDigest', 'liveServiceConstraintSetDigest', 'originalQuerySetDigest',
    'prefixContextSetDigest', 'prefixInjectionAlgorithmDigest', 'pythonDependencyByteSetDigest',
    'pythonExecutableDigest', 'registeredConstraintSetDigest', 'representativeEquivalenceDigest',
    'semanticManifestDigest', 'serviceClassificationAlgorithmDigest', 'serviceClassifierSelfTestDigest',
    'shapeSourceSetDigest', 'transformedQuerySetDigest', 'validationPhaseResultDigest',
  ];
  for (const field of digestFields) if (!SHA256.test(evidence?.[field] || '')) throw new Error(`local SHACL evidence requires ${field}`);
  const { evidenceDigest, ...core } = evidence;
  if (evidenceDigest !== sha256(canonicalJson(core))) throw new Error('local SHACL evidence digest does not match its canonical claims');
  if (evidence.evidenceScope !== HERMETIC_SCOPE
      || evidence.validationScope !== 'LOCAL_PYSHACL_COMPATIBLE_AFFECTED_CLOSURE'
      || evidence.localCompatibleConforms !== true
      || evidence.registeredSparqlConstraintCount !== 79
      || evidence.locallyEvaluatedConstraintCount !== 79
      || evidence.registeredConstraintSetDigest !== evidence.compatibleConstraintSetDigest
      || evidence.actualServiceAlgebraNodeCount !== 0
      || evidence.liveServiceConstraintCount !== 0
      || evidence.liveServiceConstraintSetDigest !== EMPTY_SET_DIGEST
      || evidence.substringBasedExclusionCount !== 0
      || evidence.unexpectedExclusionCount !== 0
      || evidence.candidateViolationCount !== 0
      || evidence.serviceConstraintsCountedAsLocalPass !== 0
      || evidence.prefixInjectionDeterministic !== true
      || evidence.prefixSemanticsEquivalent !== true
      || evidence.prefixSemanticEquivalenceCount !== 79
      || evidence.pyshaclServiceDetectionMode !== 'PARSED_SPARQL_ALGEBRA'
      || !Array.isArray(evidence.validationPhaseResults)
      || evidence.validationPhaseResults.length !== 2
      || evidence.validationPhaseResultDigest !== sha256(canonicalJson(evidence.validationPhaseResults))
      || evidence.validationPhaseResults.some(({ conforms, violationCount, resultDigest }) => conforms !== true || violationCount !== 0 || !SHA256.test(resultDigest || ''))
      || evidence.validationPhaseResults.map(({ phase }) => phase).join(',') !== 'AFFECTED_AUTHORED,AFFECTED_REGISTERED_DERIVED_SNAPSHOT'
      || evidence.transitiveFocusGap !== 0
      || evidence.focusRootCount !== 11
      || evidence.focusRootDigest !== EXPECTED_FOCUS_ROOT_DIGEST
      || evidence.focusNodeCount !== 162
      || evidence.serviceClassifierSelfTestCount !== 7
      || !Array.isArray(evidence.serviceClassifierSelfTests)
      || evidence.serviceClassifierSelfTests.some(({ expectedLiveDependent, actualLiveDependent }) => expectedLiveDependent !== actualLiveDependent)
      || evidence.pyshaclVersion !== '0.40.0'
      || evidence.rdflibVersion !== '7.6.0'
      || evidence.pyyamlVersion !== '6.0.3') {
    throw new Error('local SHACL evidence does not close the exact compatible affected constraint scope');
  }
  return evidence;
}

function putEvidenceManifest(casRoot, manifest) {
  validateEvidenceManifest(manifest);
  const bytes = Buffer.from(canonicalJson(manifest));
  const descriptor = putCas(casRoot, bytes, 'application/json');
  if (bytes.includes(descriptor.digest)) throw new Error('evidence descriptor digest is self-referential');
  return descriptor;
}

function putCas(casRoot, bytes, mediaType) {
  const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const digest = sha256(value);
  const root = realpathSync(casRoot);
  const hexadecimal = digest.slice(7);
  const target = resolve(root, 'sha256', hexadecimal.slice(0, 2), hexadecimal);
  if (!contained(root, target)) throw new Error('CAS target escapes its configured root');
  mkdirSync(dirname(target), { recursive: true });
  if (!existsSync(target)) writeFileSync(target, value, { flag: 'wx', mode: 0o600 });
  if (!readFileSync(target).equals(value)) throw new Error(`CAS round-trip failed for ${digest}`);
  return Object.freeze({ digest, byteSize: value.length, mediaType, locator: `cas://sha256/${hexadecimal}` });
}

function integrityKey() {
  const seed = createHash('sha256').update('urn:usf:proofalgorithm:compilersemanticenforcement').digest();
  return createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
}

function attest(subjectDigest, predicate, subjectName = 'semantic-model-compiler-evidence') {
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: subjectName, digest: { sha256: subjectDigest.slice(7) } }],
    predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
    predicate,
  };
  const statementBytes = Buffer.from(canonicalJson(statement));
  const privateKey = integrityKey();
  const publicKey = createPublicKey(privateKey);
  const pae = Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(PAYLOAD_TYPE)} ${PAYLOAD_TYPE} ${statementBytes.length} `), statementBytes]);
  const signature = sign(null, pae, privateKey);
  if (!verify(null, pae, publicKey, signature)) throw new Error('compiler proof integrity signature did not verify');
  const keyid = sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7);
  return {
    bytes: Buffer.from(canonicalJson({ payloadType: PAYLOAD_TYPE, payload: statementBytes.toString('base64'), signatures: [{ keyid, sig: signature.toString('base64') }] })),
    keyid,
  };
}

export async function evaluateCompilerSemanticEnforcement({
  authorityDigest,
  evaluatedAt,
  repositoryRoot,
  casRoot,
  createLiveClient,
  readAuthorityWitness,
  sourcePaths,
  proofAlgorithmPath,
  testPaths,
  substituteSourcePaths,
  runFocusedTests,
  runLocalCompatibleShacl,
  createCommand = createSemanticModelCompilationCommand,
}) {
  if (!SHA256.test(authorityDigest || '')) throw new Error('authorityDigest must be an exact sha256 digest');
  if (!UTC_SECOND.test(evaluatedAt || '')) throw new Error('evaluatedAt must be an explicit UTC second');
  if (!Array.isArray(sourcePaths) || sourcePaths.length === 0) throw new Error('proof source paths are required');
  if (typeof proofAlgorithmPath !== 'string') throw new Error('proof algorithm source path is required');
  if (!Array.isArray(testPaths) || testPaths.length === 0) throw new Error('test source paths are required');
  if (!Array.isArray(substituteSourcePaths) || substituteSourcePaths.length === 0) throw new Error('substitute implementation source paths are required');
  const completeInputs = new Set(sourcePaths);
  for (const path of [proofAlgorithmPath, ...testPaths, ...substituteSourcePaths]) {
    if (!completeInputs.has(path)) throw new Error(`proof input is absent from implementation source digest: ${path}`);
  }
  if (typeof runFocusedTests !== 'function') throw new Error('focused test runner is required');
  if (typeof runLocalCompatibleShacl !== 'function') throw new Error('local compatible SHACL runner is required');
  if (typeof createLiveClient !== 'function') throw new Error('deferred live authority client factory is required');

  const sources = sourceSet(repositoryRoot, sourcePaths);
  const testsSources = sourceSet(repositoryRoot, testPaths);
  const substituteSources = sourceSet(repositoryRoot, substituteSourcePaths);
  const tests = await runFocusedTests();
  if (tests?.passed !== true || !Number.isInteger(tests.count) || tests.count < 1 || !SHA256.test(tests.outputDigest || '')
      || tests.discoveredFileCount !== testsSources.records.length
      || tests.testInventoryDigest !== testsSources.digest
      || tests.preExecutionReboundDigest !== testsSources.digest
      || tests.stagedTestInventoryDigest !== testsSources.digest
      || tests.executedTestInventoryDigest !== testsSources.digest
      || tests.executedByteSetDigest !== testsSources.digest
      || tests.launcherObservedTestInventoryDigest !== testsSources.digest
      || tests.launcherObservedTestFileCount !== testsSources.records.length
      || tests.authorisedExecutionByteSetDigest !== tests.snapshotManifestDigest
      || tests.snapshotReadOnlyVerified !== true
      || tests.nodeVersion !== '22.23.1') {
    throw new Error('focused compiler tests did not produce valid passing evidence');
  }
  const localShaclRun = await runLocalCompatibleShacl();
  const localShacl = validateLocalShaclEvidence(localShaclRun);
  const client = await createLiveClient();
  const command = createCommand({ client, readAuthorityWitness, repositoryRoot });
  const compilation = await command.execute({ expectedAuthorityDigest: authorityDigest, publicationMode: 'validate' });
  const cases = [
    { id: 'authority-digest-bound', passed: compilation.evaluatedAuthorityDigest === authorityDigest },
    { id: 'candidate-transaction-rolled-back', passed: compilation.commitOutcome?.state === 'validated-rolled-back' },
    { id: 'candidate-exact-state-verified', passed: compilation.commitOutcome?.exactCandidateStateVerified === true },
    { id: 'candidate-contamination-zero', passed: compilation.contaminationCount === 0 },
    { id: 'candidate-shacl-validated', passed: compilation.commitOutcome?.state === 'validated-rolled-back' },
    { id: 'focused-tests-passed', passed: tests.passed === true && tests.count > 0 },
    { id: 'local-compatible-shacl-passed', passed: localShacl.localCompatibleConforms === true },
    { id: 'canonical-semantic-model-path', passed: compilation.semanticModelPath === 'semantic-model' },
  ].sort((left, right) => left.id.localeCompare(right.id));
  if (cases.some(({ id }) => !CASE_SCOPES.has(id)) || new Set(cases.map(({ id }) => id)).size !== CASE_SCOPES.size) {
    throw new Error('compiler proof case scope registry is incomplete or contains duplicate cases');
  }
  if (cases.some((item) => !item.passed)) throw new Error(`compiler proof cases failed: ${cases.filter((item) => !item.passed).map((item) => item.id).join(',')}`);

  const proofAlgorithmDigest = sha256(readFileSync(resolve(realpathSync(repositoryRoot), proofAlgorithmPath)));
  const testExecutionBinding = {
    authorisedExecutionByteSetDigest: tests.authorisedExecutionByteSetDigest,
    authorisedRoots: tests.authorisedRoots,
    authorisedRootSetDigest: tests.authorisedRootSetDigest,
    dependencyByteSetDigest: tests.dependencyByteSetDigest,
    dependencyLockDigest: tests.dependencyLockDigest,
    discoveryAlgorithmDigest: tests.discoveryAlgorithmDigest,
    executedByteSetDigest: tests.executedByteSetDigest,
    executedTestInventoryDigest: tests.executedTestInventoryDigest,
    expectedDenialCodes: tests.expectedDenialCodes,
    invocationDigest: tests.invocationDigest,
    invocationMode: tests.invocationMode,
    isolationMode: tests.isolationMode,
    launcherDigest: tests.launcherDigest,
    launcherObservedTestFileCount: tests.launcherObservedTestFileCount,
    launcherObservedTestInventoryDigest: tests.launcherObservedTestInventoryDigest,
    nativeRuntimeDigests: tests.nativeRuntimeDigests,
    networkIsolation: tests.networkIsolation,
    networkIsolatorDigest: tests.networkIsolatorDigest,
    nodeExecutableDigest: tests.nodeExecutableDigest,
    nodeFlags: tests.nodeFlags,
    preExecutionReboundDigest: tests.preExecutionReboundDigest,
    rejectionCodeVocabularyDigest: tests.rejectionCodeVocabularyDigest,
    snapshotExclusions: tests.snapshotExclusions,
    snapshotFileCount: tests.snapshotFileCount,
    snapshotManifestDigest: tests.snapshotManifestDigest,
    snapshotPermissionsDigest: tests.snapshotPermissionsDigest,
    snapshotPolicy: tests.snapshotPolicy,
    snapshotReadOnlyVerified: tests.snapshotReadOnlyVerified,
    snapshotRootDigest: tests.snapshotRootDigest,
    stagedTestInventoryDigest: tests.stagedTestInventoryDigest,
    stagedFileDigests: tests.stagedFileDigests,
    testInventory: testsSources.records,
    testInventoryDigest: tests.testInventoryDigest,
    testFileCount: tests.discoveredFileCount,
    testRuntime: `node@${tests.nodeVersion}`,
  };
  const localShaclBinding = {
    localShaclActualServiceAlgebraNodeCount: localShacl.actualServiceAlgebraNodeCount,
    localShaclCandidateSourceSetDigest: localShacl.candidateSourceSetDigest,
    localShaclCandidateViolationCount: localShacl.candidateViolationCount,
    localShaclCompatibleConstraintSetDigest: localShacl.compatibleConstraintSetDigest,
    localShaclDeterministicOutputDigest: localShaclRun.deterministicOutputDigest,
    localShaclEvidenceDigest: localShacl.evidenceDigest,
    localShaclFocusNodeDigest: localShacl.focusNodeDigest,
    localShaclFocusRootDigest: localShacl.focusRootDigest,
    localShaclHarnessSourceDigest: localShacl.harnessSourceDigest,
    localShaclLiveServiceConstraintSetDigest: localShacl.liveServiceConstraintSetDigest,
    localShaclLocallyEvaluatedConstraintCount: localShacl.locallyEvaluatedConstraintCount,
    localShaclPrefixInjectionAlgorithmDigest: localShacl.prefixInjectionAlgorithmDigest,
    localShaclPythonDependencyByteSetDigest: localShacl.pythonDependencyByteSetDigest,
    localShaclRegisteredConstraintSetDigest: localShacl.registeredConstraintSetDigest,
    localShaclRegisteredConstraintCount: localShacl.registeredSparqlConstraintCount,
    localShaclServiceClassificationAlgorithmDigest: localShacl.serviceClassificationAlgorithmDigest,
    localShaclSubstringBasedExclusionCount: localShacl.substringBasedExclusionCount,
    localShaclUnexpectedExclusionCount: localShacl.unexpectedExclusionCount,
    localShaclValidationPhaseResultDigest: localShacl.validationPhaseResultDigest,
  };
  const hermeticCases = cases.filter(({ id }) => CASE_SCOPES.get(id) === HERMETIC_SCOPE);
  const authorityControlCases = cases.filter(({ id }) => CASE_SCOPES.get(id) === AUTHORITY_SCOPE);
  const hermeticEvidenceCore = evidenceManifest({
    schemaVersion: 2,
    evidenceScope: HERMETIC_SCOPE,
    evaluatedAt,
    providerIdentity: HERMETIC_PROVIDER,
    liveAuthorityDependency: false,
    implementationSourceDigest: sources.digest,
    implementationSources: sources.records,
    substituteImplementationDigest: substituteSources.digest,
    substituteImplementationSources: substituteSources.records,
    proofAlgorithmDigest,
    testSetDigest: testsSources.digest,
    ...testExecutionBinding,
    ...localShaclBinding,
    testOutputDigest: tests.outputDigest,
    testCount: tests.count,
    environmentClass: 'urn:usf:environmentclass:hermetic',
    providerMode: 'urn:usf:providermode:deterministictestsubstitute',
    supportedEvidenceKinds: [
      'urn:usf:evidencekind:runtimeproofevidence',
      'urn:usf:evidencekind:validationevidence',
    ],
    evidenceStages: ['emitted', 'collected', 'normalised', 'ingested', 'signed', 'integrityverified'],
    cases: hermeticCases,
    nonclaims: [
      'The deterministic integrity signature is not a production signing identity or authenticity claim.',
      'Deterministic substitute evidence does not establish live authority transaction behaviour.',
    ],
  });
  const authorityControlEvidenceCore = evidenceManifest({
    schemaVersion: 2,
    evidenceScope: AUTHORITY_SCOPE,
    evaluatedAt,
    providerIdentity: LIVE_PROVIDER,
    evaluatedAuthorityDigest: authorityDigest,
    transactionMode: 'validate-and-rollback',
    postTransactionAuthorityDrift: 'ZERO',
    postTransactionAuthorityDigest: authorityDigest,
    candidateAuthorityDigest: compilation.commitOutcome.candidateDigest,
    implementationSourceDigest: sources.digest,
    proofAlgorithmDigest,
    testSetDigest: testsSources.digest,
    liveValidatedSparqlConstraintCount: localShacl.registeredSparqlConstraintCount,
    liveValidatedConstraintSetDigest: localShacl.registeredConstraintSetDigest,
    liveServiceConstraintCount: localShacl.liveServiceConstraintCount,
    liveServiceConstraintSetDigest: localShacl.liveServiceConstraintSetDigest,
    liveValidationReportDigest: sha256(canonicalJson({
      candidateAuthorityDigest: compilation.commitOutcome.candidateDigest,
      constraintSetDigest: localShacl.registeredConstraintSetDigest,
      exactCandidateStateVerified: compilation.commitOutcome.exactCandidateStateVerified,
      state: compilation.commitOutcome.state,
      violationCount: 0,
    })),
    environmentClass: 'urn:usf:environmentclass:authoritycontrol',
    providerMode: 'urn:usf:providermode:liveauthoritycontrol',
    supportedEvidenceKinds: ['urn:usf:evidencekind:validationevidence'],
    evidenceStages: ['emitted', 'collected', 'normalised', 'ingested', 'signed', 'integrityverified'],
    cases: authorityControlCases,
    nonclaims: [
      'Authority-control evidence is not a hermetic, staging, production-live or clean-clone claim.',
      'The validate-only candidate transaction was rolled back and did not publish semantic authority.',
    ],
  });
  validateCompositeScopes([hermeticEvidenceCore, authorityControlEvidenceCore]);
  const hermeticEvidenceManifest = putEvidenceManifest(casRoot, hermeticEvidenceCore);
  const authorityControlEvidenceManifest = putEvidenceManifest(casRoot, authorityControlEvidenceCore);
  const exactEvidenceSetDigest = sha256(canonicalJson([
    { scope: hermeticEvidenceCore.evidenceScope, digest: hermeticEvidenceManifest.digest },
    { scope: authorityControlEvidenceCore.evidenceScope, digest: authorityControlEvidenceManifest.digest },
  ]));
  const scopedEvidenceSetDigests = Object.freeze({
    hermetic: sha256(canonicalJson({
      scope: HERMETIC_SCOPE,
      manifestDigest: hermeticEvidenceManifest.digest,
      evidenceKinds: hermeticEvidenceCore.supportedEvidenceKinds,
    })),
    authorityControl: sha256(canonicalJson({
      scope: AUTHORITY_SCOPE,
      manifestDigest: authorityControlEvidenceManifest.digest,
      evidenceKinds: authorityControlEvidenceCore.supportedEvidenceKinds,
    })),
  });
  const hermeticEnvelope = attest(hermeticEvidenceManifest.digest, {
    evidenceScope: hermeticEvidenceCore.evidenceScope,
    exactEvidenceSetDigest,
    scopedEvidenceSetDigests,
    implementationSourceDigest: sources.digest,
    result: 'passed',
  }, 'semantic-model-compiler-hermetic-evidence');
  const authorityControlEnvelope = attest(authorityControlEvidenceManifest.digest, {
    evidenceScope: authorityControlEvidenceCore.evidenceScope,
    evaluatedAuthorityDigest: authorityDigest,
    candidateAuthorityDigest: compilation.commitOutcome.candidateDigest,
    exactEvidenceSetDigest,
    implementationSourceDigest: sources.digest,
    result: 'passed',
  }, 'semantic-model-compiler-authority-control-evidence');
  const proofEnvelope = attest(exactEvidenceSetDigest, {
    evaluatedAuthorityDigest: authorityDigest,
    candidateAuthorityDigest: compilation.commitOutcome.candidateDigest,
    exactEvidenceSetDigest,
    implementationSourceDigest: sources.digest,
    evidenceScopes: [
      { scope: HERMETIC_SCOPE, digest: hermeticEvidenceManifest.digest },
      { scope: AUTHORITY_SCOPE, digest: authorityControlEvidenceManifest.digest },
    ].sort((left, right) => left.scope.localeCompare(right.scope)),
    result: 'passed',
  }, 'semantic-model-compiler-proof-evidence-set');
  const evidenceAttestations = Object.freeze({
    hermetic: putCas(casRoot, hermeticEnvelope.bytes, PAYLOAD_TYPE),
    authorityControl: putCas(casRoot, authorityControlEnvelope.bytes, PAYLOAD_TYPE),
  });
  const proofAttestation = putCas(casRoot, proofEnvelope.bytes, PAYLOAD_TYPE);
  return Object.freeze({
    ok: true,
    evaluatedAuthorityDigest: authorityDigest,
    candidateAuthorityDigest: compilation.commitOutcome.candidateDigest,
    exactEvidenceSetDigest,
    implementationSourceDigest: sources.digest,
    testInventoryDigest: tests.testInventoryDigest,
    testFileCount: tests.discoveredFileCount,
    evidenceManifests: Object.freeze({ hermetic: hermeticEvidenceManifest, authorityControl: authorityControlEvidenceManifest }),
    evidenceAttestations,
    proofAttestation,
    signingKeyFingerprint: proofEnvelope.keyid,
    caseCount: cases.length,
    failureCount: 0,
  });
}

export const compilerProofInternals = Object.freeze({
  AUTHORITY_SCOPE,
  EMPTY_SET_DIGEST,
  EXPECTED_FOCUS_ROOT_DIGEST,
  HERMETIC_SCOPE,
  canonicalJson,
  evidenceManifest,
  sha256,
  sourceSet,
  validateCompositeScopes,
  validateEvidenceManifest,
  validateLocalShaclEvidence,
});
