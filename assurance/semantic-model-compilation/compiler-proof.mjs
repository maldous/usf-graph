import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

import { createSemanticModelCompilationCommand } from '../../processes/semantic-assurance/semantic-model-compilation-command.mjs';
import { GATE_COUNTER_NAMES, REASON_PRECEDENCE } from './realisation-option-evaluation.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const HERMETIC_SCOPE = 'HERMETIC_SUBSTITUTE';
const AUTHORITY_SCOPE = 'LIVE_AUTHORITY_CONTROL';
const HERMETIC_PROVIDER = 'urn:usf:provider:compilerfocusedtestsubstitute';
const LIVE_PROVIDER = 'urn:usf:provider:livestardogsemanticauthority';
const COMMON_MANIFEST_FIELDS = [
  'cases', 'environmentClass', 'evaluatedAt', 'evidenceDigest', 'evidenceScope', 'evidenceStages',
  'implementationSourceDigest', 'nonclaims', 'proofAlgorithmDigest', 'providerIdentity', 'providerMode',
  'realisationOptionClosureEvidenceDigest', 'realisationOptionClosureResultDigest',
  'realisationOptionEvaluationDependencyDigest', 'realisationOptionEvaluationEvidenceDigest',
  'realisationOptionEvaluationImplementationSourceDigest', 'realisationOptionEvaluationSourceSetDigest',
  'schemaVersion', 'supportedEvidenceKinds', 'testSetDigest',
];
const HERMETIC_MANIFEST_FIELDS = [
  ...COMMON_MANIFEST_FIELDS,
  'authorisedExecutionByteSetDigest', 'authorisedRootSetDigest', 'authorisedRoots',
  'bootstrapModuleRecords', 'bootstrapModuleSetDigest', 'dependencyByteSetDigest', 'dependencyLockDigest',
  'discoveryAlgorithmDigest', 'environment', 'executedByteSetDigest',
  'executedTestInventoryDigest', 'expectedDenialCodes', 'implementationSources', 'invocationDigest',
  'invocationMode', 'isolationMode', 'launcherDigest', 'launcherObservedTestFileCount',
  'launcherObservedTestInventoryDigest', 'liveAuthorityDependency', 'localShaclActualServiceAlgebraNodeCount',
  'localShaclCandidateSourceSetDigest', 'localShaclCandidateViolationCount',
  'localShaclCompatibleConstraintSetDigest', 'localShaclDeterministicOutputDigest', 'localShaclEvidenceDigest',
  'localShaclExpectedFocusRootCount', 'localShaclExpectedFocusRootDigest',
  'localShaclExpectedRegisteredConstraintCount', 'localShaclExpectedRegisteredConstraintSetDigest',
  'localShaclExpectedShapeSourceFileCount', 'localShaclExpectedShapeSourceSetDigest',
  'localShaclFocusNodeCount', 'localShaclFocusNodeDigest', 'localShaclFocusRootCount',
  'localShaclFocusRootDigest', 'localShaclHarnessSourceDigest',
  'localShaclLiveServiceConstraintSetDigest', 'localShaclLocallyEvaluatedConstraintCount',
  'localShaclPlantedFixtureCatalogueDigest', 'localShaclPlantedFixtureCaseCount',
  'localShaclPlantedFixtureEvidenceDigest', 'localShaclPlantedFixtureFixtureGraphDigest',
  'localShaclPlantedFixtureFocusNodeSetDigest', 'localShaclPlantedFixtureMissingExpectedCount',
  'localShaclPlantedFixtureMultipleCodeCount', 'localShaclPlantedFixtureNegativeControlCount',
  'localShaclPlantedFixturePositiveControlCount', 'localShaclPlantedFixtureReasonCodeSetDigest',
  'localShaclPlantedFixtureResultDigest', 'localShaclPlantedFixtureUnexpectedCodeCount',
  'localShaclPlantedFixtureUnrecognisedResultCount',
  'localShaclPrefixInjectionAlgorithmDigest', 'localShaclPythonDependencyByteSetDigest',
  'localShaclRegisteredConstraintCount', 'localShaclRegisteredConstraintSetDigest',
  'localShaclShapeSourceSetDigest',
  'localShaclServiceClassificationAlgorithmDigest', 'localShaclSubstringBasedExclusionCount',
  'localShaclUnexpectedExclusionCount', 'localShaclValidationPhaseResultDigest', 'nativeRuntimeBindings',
  'nativeRuntimeChildBindingDigest', 'nativeRuntimeDigests', 'nativeRuntimePostBindingDigest',
  'nativeRuntimePreBindingDigest', 'nativeRuntimeSetDigest', 'networkIsolation', 'networkIsolatorBinding',
  'networkIsolatorDigest', 'networkIsolatorPostBinding', 'nodeExecutableBinding', 'nodeExecutableDigest',
  'nodeFlags', 'nodeVersion',
  'preExecutionReboundDigest', 'rejectionCodeVocabularyDigest', 'resolvedModuleCount',
  'resolvedModuleRecords', 'resolvedModuleSetDigest', 'loadedModuleCount', 'loadedModuleRecords',
  'loadedModuleSetDigest', 'snapshotExclusions', 'snapshotFileCount',
  'snapshotManifestDigest', 'snapshotPermissionsDigest', 'snapshotPolicy', 'snapshotReadOnlyVerified',
  'snapshotRootDigest', 'stagedFileDigests', 'stagedTestInventoryDigest', 'substituteImplementationDigest',
  'substituteImplementationSources', 'testCount', 'testFileCount', 'testInventory', 'testInventoryDigest',
  'testOutputDigest', 'testRuntime', 'testSummary', 'virtualSharedObjects',
];
const AUTHORITY_MANIFEST_FIELDS = [
  ...COMMON_MANIFEST_FIELDS,
  'candidateAuthorityDigest', 'evaluatedAuthorityDigest', 'liveServiceConstraintCount',
  'liveServiceConstraintSetDigest', 'liveValidatedConstraintSetDigest',
  'liveValidatedSparqlConstraintCount', 'liveValidatedShapeSourceFileCount',
  'liveValidatedShapeSourceSetDigest', 'liveAuthoredValidationReceiptDigest',
  'liveDerivedValidationReceiptDigest', 'liveValidationReportDigest', 'postTransactionAuthorityDigest',
  'postTransactionAuthorityDrift', 'transactionMode',
];
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
const EVIDENCE_STAGES = Object.freeze(['emitted', 'collected', 'normalised', 'ingested', 'signed', 'integrityverified']);
const SCOPE_REQUIREMENTS = Object.freeze({
  [HERMETIC_SCOPE]: Object.freeze({
    caseIds: Object.freeze([...CASE_SCOPES].filter(([, scope]) => scope === HERMETIC_SCOPE).map(([id]) => id).sort()),
    evidenceKinds: Object.freeze(['urn:usf:evidencekind:runtimeproofevidence', 'urn:usf:evidencekind:validationevidence']),
  }),
  [AUTHORITY_SCOPE]: Object.freeze({
    caseIds: Object.freeze([...CASE_SCOPES].filter(([, scope]) => scope === AUTHORITY_SCOPE).map(([id]) => id).sort()),
    evidenceKinds: Object.freeze(['urn:usf:evidencekind:validationevidence']),
  }),
});
const EMPTY_SET_DIGEST = 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945';

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const compareStrings = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function contained(root, target) {
  const path = relative(root, target);
  return path !== '' && path !== '..' && !path.startsWith(`..${sep}`);
}

function assertAuthoredInput(path) {
  if (typeof path !== 'string' || path.length === 0 || GENERATED_PROOF_INPUTS.some((pattern) => pattern.test(path))) {
    throw new Error(`generated proof output cannot contribute to implementation source digest: ${path}`);
  }
}

function sourceSet(repositoryRoot, sourcePaths, fileSystem = {}, excludedRoots = []) {
  const inspect = {
    exists: fileSystem.exists || existsSync,
    lstat: fileSystem.lstat || lstatSync,
    read: fileSystem.read || readFileSync,
    realpath: fileSystem.realpath || realpathSync,
  };
  const root = inspect.realpath(repositoryRoot);
  const exclusions = excludedRoots.map((path) => resolve(path));
  if (!Array.isArray(sourcePaths) || sourcePaths.length === 0) throw new Error('proof source paths are required');
  const identities = new Set();
  const paths = new Set();
  const records = sourcePaths.map((path) => {
    assertAuthoredInput(path);
    if (path.startsWith('/') || path.includes('\\') || path.split('/').some((part) => part === '' || part === '.' || part === '..')) {
      throw new Error(`proof source path is not canonical repository-relative identity: ${path}`);
    }
    const target = resolve(root, path);
    if (!contained(root, target) || !inspect.exists(target)) throw new Error(`proof source is unavailable or outside the repository: ${path}`);
    if (exclusions.some((excluded) => target === excluded || contained(excluded, target))) {
      throw new Error(`proof source is inside a generated output or CAS root: ${path}`);
    }
    const stat = inspect.lstat(target);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || inspect.realpath(target) !== target) {
      throw new Error(`proof source must be one canonical regular repository file: ${path}`);
    }
    const identity = `${stat.dev}:${stat.ino}`;
    if (paths.has(path) || identities.has(identity)) throw new Error(`proof source path or file identity is duplicated: ${path}`);
    paths.add(path);
    identities.add(identity);
    return { path, digest: sha256(inspect.read(target)) };
  }).sort(({ path: left }, { path: right }) => compareStrings(left, right));
  return { records, digest: sha256(canonicalJson(records)) };
}

function sourceSubset(complete, paths) {
  if (!complete || !Array.isArray(complete.records) || !Array.isArray(paths) || paths.length < 1) throw new Error('proof source subset requires complete observed sources and paths');
  const byPath = new Map(complete.records.map((record) => [record.path, record]));
  const records = paths.map((path) => {
    const record = byPath.get(path);
    if (!record) throw new Error(`proof source subset is absent from the complete observation: ${path}`);
    return record;
  })
    .sort(({ path: left }, { path: right }) => compareStrings(left, right));
  if (new Set(records.map(({ path }) => path)).size !== records.length) throw new Error('proof source subset contains duplicate paths');
  return { records, digest: sha256(canonicalJson(records)) };
}

function exactDigestRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)
      || canonicalJson(Object.keys(record).sort()) !== canonicalJson(['digest', 'path'])
      || typeof record.path !== 'string' || record.path.length === 0
      || record.path.startsWith('/') || record.path.includes('\\')
      || record.path.split('/').some((part) => part === '' || part === '.' || part === '..')
      || !SHA256.test(record.digest || '')) {
    return false;
  }
  return true;
}

function validDigestRecordSet(records, digest) {
  return Array.isArray(records) && records.length > 0 && SHA256.test(digest || '')
    && records.every((record, index) => exactDigestRecord(record)
      && (index === 0 || records[index - 1].path < record.path))
    && sha256(canonicalJson(records)) === digest;
}

function validateModuleBinding({
  authorisedExecutionByteSetDigest,
  bootstrapModuleRecords,
  executedByteSetDigest,
  loadedModuleCount,
  loadedModuleRecords,
  loadedModuleSetDigest,
  resolvedModuleCount,
  resolvedModuleRecords,
  resolvedModuleSetDigest,
  snapshotManifestDigest,
  stagedFileDigests,
  testInventory,
}) {
  if (!Number.isInteger(loadedModuleCount) || loadedModuleCount < 1
      || !Array.isArray(loadedModuleRecords) || loadedModuleRecords.length !== loadedModuleCount
      || !Number.isInteger(resolvedModuleCount) || resolvedModuleCount < 1
      || !Array.isArray(resolvedModuleRecords) || resolvedModuleRecords.length !== resolvedModuleCount
      || !Array.isArray(stagedFileDigests) || !Array.isArray(testInventory) || !Array.isArray(bootstrapModuleRecords)
      || !SHA256.test(loadedModuleSetDigest || '') || !SHA256.test(resolvedModuleSetDigest || '')
      || executedByteSetDigest !== loadedModuleSetDigest
      || !validDigestRecordSet(stagedFileDigests, snapshotManifestDigest)
      || authorisedExecutionByteSetDigest !== snapshotManifestDigest
      || !validDigestRecordSet(loadedModuleRecords, loadedModuleSetDigest)
      || !validDigestRecordSet(resolvedModuleRecords, resolvedModuleSetDigest)
      || stagedFileDigests.some((record) => !exactDigestRecord(record))
      || testInventory.some((record) => !exactDigestRecord(record))
      || resolvedModuleRecords.some(({ path, digest }) =>
        !stagedFileDigests.some((record) => record.path === path && record.digest === digest))
      || loadedModuleRecords.some(({ path, digest }) =>
        !resolvedModuleRecords.some((record) => record.path === path && record.digest === digest))
      || testInventory.some(({ path, digest }) =>
        !loadedModuleRecords.some((record) => record.path === path && record.digest === digest))
      || bootstrapModuleRecords.some(({ path, digest }) =>
        !loadedModuleRecords.some((record) => record.path === path && record.digest === digest))) {
    throw new Error('hermetic evidence manifest requires exact resolved and loaded modules with locked runtime inputs');
  }
  return true;
}

function validateTestSummary({ testSummary, testOutputDigest, testCount }) {
  const countNames = ['cancelled', 'failed', 'passed', 'skipped', 'suites', 'tests', 'todo', 'topLevel'];
  if (!testSummary || typeof testSummary !== 'object' || Array.isArray(testSummary)
      || canonicalJson(Object.keys(testSummary).sort()) !== canonicalJson(['counts', 'success'])
      || testSummary.success !== true
      || canonicalJson(Object.keys(testSummary.counts || {}).sort()) !== canonicalJson(countNames)
      || countNames.some((name) => !Number.isSafeInteger(testSummary.counts[name]) || testSummary.counts[name] < 0)
      || testSummary.counts.tests < 1 || testSummary.counts.tests !== testCount
      || testSummary.counts.passed + testSummary.counts.failed + testSummary.counts.cancelled
        + testSummary.counts.skipped + testSummary.counts.todo !== testSummary.counts.tests
      || testSummary.counts.passed !== testCount || testSummary.counts.failed !== 0
      || testSummary.counts.cancelled !== 0 || testSummary.counts.skipped !== 0 || testSummary.counts.todo !== 0
      || testOutputDigest !== sha256(canonicalJson(testSummary))) {
    throw new Error('hermetic evidence manifest requires one exact passing structured test summary');
  }
  return true;
}

function exactFileBinding(record) {
  return Boolean(record) && typeof record === 'object' && !Array.isArray(record)
    && canonicalJson(Object.keys(record).sort()) === canonicalJson(['device', 'digest', 'inode', 'path', 'size'])
    && typeof record.path === 'string' && record.path.startsWith('/') && !record.path.includes('\\')
    && /^[0-9]+$/.test(record.device || '') && /^[0-9]+$/.test(record.inode || '')
    && /^[0-9]+$/.test(record.size || '') && SHA256.test(record.digest || '');
}

function validateNativeRuntimeBinding(manifest) {
  const {
    nativeRuntimeBindings,
    nativeRuntimeDigests,
    nativeRuntimeSetDigest,
    nativeRuntimePreBindingDigest,
    nativeRuntimeChildBindingDigest,
    nativeRuntimePostBindingDigest,
    nodeExecutableBinding,
    nodeExecutableDigest,
    nodeVersion,
    virtualSharedObjects,
  } = manifest;
  const projected = Array.isArray(nativeRuntimeBindings)
    ? nativeRuntimeBindings.map(({ path, digest }) => ({ path, digest })) : null;
  const runtimeCore = {
    nodeVersion,
    node: nodeExecutableBinding,
    nativeFiles: nativeRuntimeBindings,
    virtualSharedObjects,
  };
  const runtimeDigest = sha256(canonicalJson(runtimeCore));
  if (!Array.isArray(nativeRuntimeBindings) || nativeRuntimeBindings.length < 1
      || nativeRuntimeBindings.some((record, index) => !exactFileBinding(record)
        || index > 0 && nativeRuntimeBindings[index - 1].path >= record.path)
      || !exactFileBinding(nodeExecutableBinding) || nodeExecutableBinding.digest !== nodeExecutableDigest
      || nodeVersion !== '22.23.1'
      || !Array.isArray(virtualSharedObjects)
      || virtualSharedObjects.some((value, index) => typeof value !== 'string' || value.length === 0
        || value.startsWith('/') || index > 0 && virtualSharedObjects[index - 1] >= value)
      || new Set(virtualSharedObjects).size !== virtualSharedObjects.length
      || canonicalJson(nativeRuntimeDigests) !== canonicalJson(projected)
      || sha256(canonicalJson(projected)) !== nativeRuntimeSetDigest
      || ![nativeRuntimePreBindingDigest, nativeRuntimeChildBindingDigest, nativeRuntimePostBindingDigest]
        .every((digest) => digest === runtimeDigest)) {
    throw new Error('hermetic evidence manifest requires exact native runtime inputs and equal pre-child-post bindings');
  }
  return true;
}

function validateExecutionSourceClosure(manifest) {
  const includes = (records, expected) => records.some(({ path, digest }) => path === expected.path && digest === expected.digest);
  const dependencyRecords = manifest.stagedFileDigests.filter(({ path }) => path.startsWith('node_modules/'));
  const dependencyLock = manifest.stagedFileDigests.find(({ path }) => path === 'package-lock.json');
  const expectedEnvironment = {
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    TEMP: '<RUNTIME_ROOT>',
    TMP: '<RUNTIME_ROOT>',
    TMPDIR: '<RUNTIME_ROOT>',
    TZ: 'UTC',
    USF_HERMETIC_TEST_MODE: '1',
    USF_TEST_INVENTORY_DIGEST: manifest.testInventoryDigest,
  };
  const expectedFlags = [
    '--frozen-intrinsics',
    '--permission',
    '--allow-fs-read=<SNAPSHOT_ROOT>',
    '--allow-fs-read=<RUNTIME_ROOT>',
    '--allow-fs-write=<RUNTIME_ROOT>',
    '--allow-fs-read=<NODE_EXECUTABLE>',
    ...manifest.nativeRuntimeBindings.map(({ path }) => `--allow-fs-read=${path}`),
    '--no-addons',
    '<REPOSITORY_LOCAL_TEST_LAUNCHER>',
    ...manifest.testInventory.map(({ path }) => path),
  ];
  const expectedDenialCodes = {
    childProcess: 'ERR_ACCESS_DENIED',
    filesystemRead: 'ERR_ACCESS_DENIED',
    filesystemWrite: 'ERR_ACCESS_DENIED',
    network: ['EACCES', 'ENETDOWN', 'ENETUNREACH'],
    worker: 'ERR_ACCESS_DENIED',
  };
  const expectedInvocationDigest = sha256(canonicalJson({
    nodeVersion: manifest.nodeVersion,
    nodeExecutableBinding: manifest.nodeExecutableBinding,
    launcherDigest: manifest.launcherDigest,
    bootstrapModuleSetDigest: manifest.bootstrapModuleSetDigest,
    nativeRuntimeBindingDigest: manifest.nativeRuntimePreBindingDigest,
    networkIsolatorBinding: manifest.networkIsolatorBinding,
    args: ['<NETWORK_ISOLATOR>', '--net', '--', '<NODE_EXECUTABLE>', ...expectedFlags],
    environment: expectedEnvironment,
  }));
  const implementationRecords = manifest.implementationSources;
  const repositoryResolved = manifest.resolvedModuleRecords.filter(({ path }) => !path.startsWith('node_modules/'));
  if (!validDigestRecordSet(manifest.bootstrapModuleRecords, manifest.bootstrapModuleSetDigest)
      || !manifest.bootstrapModuleRecords.some(({ digest }) => digest === manifest.launcherDigest)
      || !manifest.bootstrapModuleRecords.some(({ digest }) => digest === manifest.discoveryAlgorithmDigest)
      || manifest.bootstrapModuleRecords.some((record) => !includes(manifest.loadedModuleRecords, record)
        || !includes(manifest.stagedFileDigests, record) || !includes(implementationRecords, record))
      || repositoryResolved.some((record) => !includes(implementationRecords, record))
      || manifest.testInventory.some((record) => !includes(implementationRecords, record))
      || manifest.substituteImplementationSources.some((record) => !includes(implementationRecords, record))
      || implementationRecords.some(({ path }) => {
        try { assertAuthoredInput(path); return false; } catch { return true; }
      })
      || !dependencyLock || dependencyLock.digest !== manifest.dependencyLockDigest
      || sha256(canonicalJson(dependencyRecords)) !== manifest.dependencyByteSetDigest
      || manifest.snapshotRootDigest !== sha256(canonicalJson({
        snapshotManifestDigest: manifest.snapshotManifestDigest,
        permissionsDigest: manifest.snapshotPermissionsDigest,
        exclusions: manifest.snapshotExclusions,
      }))
      || canonicalJson(manifest.environment) !== canonicalJson(expectedEnvironment)
      || canonicalJson(manifest.expectedDenialCodes) !== canonicalJson(expectedDenialCodes)
      || canonicalJson(manifest.nodeFlags) !== canonicalJson(expectedFlags)
      || !exactFileBinding(manifest.networkIsolatorBinding)
      || !exactFileBinding(manifest.networkIsolatorPostBinding)
      || canonicalJson(manifest.networkIsolatorBinding) !== canonicalJson(manifest.networkIsolatorPostBinding)
      || manifest.networkIsolatorBinding.digest !== manifest.networkIsolatorDigest
      || manifest.invocationDigest !== expectedInvocationDigest) {
    throw new Error('hermetic evidence manifest execution source, dependency, snapshot or invocation closure is invalid');
  }
  return true;
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
  const digestFields = [
    'implementationSourceDigest', 'proofAlgorithmDigest', 'testSetDigest', 'evidenceDigest',
    'realisationOptionClosureEvidenceDigest', 'realisationOptionClosureResultDigest',
    'realisationOptionEvaluationDependencyDigest', 'realisationOptionEvaluationEvidenceDigest',
    'realisationOptionEvaluationImplementationSourceDigest', 'realisationOptionEvaluationSourceSetDigest',
  ];
  for (const field of digestFields) if (!SHA256.test(manifest?.[field] || '')) throw new Error(`evidence manifest requires ${field}`);
  if (manifest?.schemaVersion !== 2 || !UTC_SECOND.test(manifest?.evaluatedAt || '')) throw new Error('evidence manifest requires schema version 2 and an explicit UTC second');
  const allowedFields = manifest.evidenceScope === HERMETIC_SCOPE ? HERMETIC_MANIFEST_FIELDS
    : manifest.evidenceScope === AUTHORITY_SCOPE ? AUTHORITY_MANIFEST_FIELDS : null;
  if (!allowedFields || canonicalJson(Object.keys(manifest).sort()) !== canonicalJson([...allowedFields].sort())) {
    const observedFields = Object.keys(manifest || {});
    const missing = (allowedFields || []).filter((field) => !observedFields.includes(field));
    const unexpected = observedFields.filter((field) => !(allowedFields || []).includes(field));
    throw new Error(`unsupported or structurally mixed evidence scope: ${manifest?.evidenceScope}; missing=${missing.join(',')}; unexpected=${unexpected.join(',')}`);
  }
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0
      || manifest.cases.some((item) => !item || typeof item !== 'object' || Array.isArray(item)
        || canonicalJson(Object.keys(item).sort()) !== canonicalJson(['id', 'passed'])
        || typeof item.id !== 'string' || item.passed !== true)
      || new Set(manifest.cases.map(({ id }) => id)).size !== manifest.cases.length) {
    throw new Error('evidence manifest requires distinct bounded passing cases');
  }
  const supportedEvidenceVocabulary = new Set([
    'urn:usf:evidencekind:runtimeproofevidence',
    'urn:usf:evidencekind:validationevidence',
  ]);
  if (!Array.isArray(manifest.supportedEvidenceKinds) || manifest.supportedEvidenceKinds.length === 0
      || new Set(manifest.supportedEvidenceKinds).size !== manifest.supportedEvidenceKinds.length
      || manifest.supportedEvidenceKinds.some((value) => !supportedEvidenceVocabulary.has(value))
      || !Array.isArray(manifest.evidenceStages) || manifest.evidenceStages.length === 0
      || manifest.evidenceStages.some((value) => !['emitted', 'collected', 'normalised', 'ingested', 'signed', 'integrityverified'].includes(value))
      || !Array.isArray(manifest.nonclaims) || manifest.nonclaims.some((value) => typeof value !== 'string' || value.length === 0)) {
    throw new Error('evidence manifest requires closed evidence kinds, lifecycle stages and nonclaims');
  }
  if (Object.hasOwn(manifest, 'descriptorDigest')) throw new Error('an evidence manifest cannot contain its own descriptor digest');
  const { evidenceDigest, ...core } = manifest;
  if (evidenceDigest !== sha256(canonicalJson(core))) throw new Error('evidence manifest evidenceDigest does not match its canonical claims');
  if (manifest.evidenceScope === HERMETIC_SCOPE
      && (manifest.providerMode !== 'urn:usf:providermode:deterministictestsubstitute'
        || manifest.providerIdentity !== HERMETIC_PROVIDER
        || manifest.environmentClass !== 'urn:usf:environmentclass:hermetic'
        || manifest.liveAuthorityDependency !== false
        || Object.hasOwn(manifest, 'evaluatedAuthorityDigest')
        || manifest.cases.some(({ id }) => CASE_SCOPES.get(id) === AUTHORITY_SCOPE))) {
    throw new Error('hermetic substitute evidence cannot contain live authority-control claims');
  }
  const scopeRequirements = SCOPE_REQUIREMENTS[manifest.evidenceScope];
  if (!scopeRequirements
      || canonicalJson(manifest.supportedEvidenceKinds) !== canonicalJson(scopeRequirements.evidenceKinds)
      || canonicalJson(manifest.evidenceStages) !== canonicalJson(EVIDENCE_STAGES)
      || canonicalJson(manifest.cases.map(({ id }) => id)) !== canonicalJson(scopeRequirements.caseIds)) {
    throw new Error('evidence manifest scope claims must equal the complete canonical scope contract');
  }
  if (manifest.evidenceScope === HERMETIC_SCOPE) {
    const hermeticDigestFields = [
      'authorisedExecutionByteSetDigest', 'authorisedRootSetDigest', 'bootstrapModuleSetDigest', 'dependencyByteSetDigest',
      'dependencyLockDigest', 'discoveryAlgorithmDigest', 'executedByteSetDigest',
      'executedTestInventoryDigest', 'invocationDigest', 'launcherDigest',
      'launcherObservedTestInventoryDigest', 'localShaclCandidateSourceSetDigest',
      'localShaclCompatibleConstraintSetDigest', 'localShaclEvidenceDigest',
      'localShaclDeterministicOutputDigest', 'localShaclExpectedFocusRootDigest',
      'localShaclExpectedRegisteredConstraintSetDigest',
      'localShaclExpectedShapeSourceSetDigest',
      'localShaclFocusNodeDigest', 'localShaclFocusRootDigest', 'localShaclHarnessSourceDigest',
      'localShaclLiveServiceConstraintSetDigest',
      'localShaclPlantedFixtureCatalogueDigest', 'localShaclPlantedFixtureEvidenceDigest',
      'localShaclPlantedFixtureFixtureGraphDigest', 'localShaclPlantedFixtureFocusNodeSetDigest',
      'localShaclPlantedFixtureReasonCodeSetDigest', 'localShaclPlantedFixtureResultDigest',
      'localShaclPrefixInjectionAlgorithmDigest', 'localShaclPythonDependencyByteSetDigest',
      'localShaclRegisteredConstraintSetDigest', 'localShaclServiceClassificationAlgorithmDigest',
      'localShaclShapeSourceSetDigest',
      'localShaclValidationPhaseResultDigest',
      'nativeRuntimeChildBindingDigest', 'nativeRuntimePostBindingDigest', 'nativeRuntimePreBindingDigest',
      'nativeRuntimeSetDigest', 'networkIsolatorDigest', 'nodeExecutableDigest', 'preExecutionReboundDigest',
      'rejectionCodeVocabularyDigest', 'loadedModuleSetDigest', 'resolvedModuleSetDigest', 'snapshotManifestDigest', 'snapshotPermissionsDigest',
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
        || manifest.authorisedExecutionByteSetDigest !== manifest.snapshotManifestDigest
        || !Array.isArray(manifest.authorisedRoots)
        || manifest.authorisedRootSetDigest !== sha256(canonicalJson(manifest.authorisedRoots))
        || manifest.launcherObservedTestFileCount !== manifest.testFileCount
        || manifest.snapshotReadOnlyVerified !== true
        || manifest.snapshotPolicy !== 'EPHEMERAL_DELETE_AFTER_EXECUTION'
        || manifest.invocationMode !== 'NODE_TEST_PROGRAMMATIC_EXACT_FILES'
        || manifest.isolationMode !== 'none'
        || manifest.networkIsolation !== 'LINUX_NETWORK_NAMESPACE'
        || manifest.localShaclPlantedFixtureCaseCount !== 25
        || manifest.localShaclPlantedFixturePositiveControlCount !== 7
        || manifest.localShaclPlantedFixtureNegativeControlCount !== 18
        || manifest.localShaclPlantedFixtureMissingExpectedCount !== 0
        || manifest.localShaclPlantedFixtureUnexpectedCodeCount !== 0
        || manifest.localShaclPlantedFixtureMultipleCodeCount !== 0
        || manifest.localShaclPlantedFixtureUnrecognisedResultCount !== 0) {
      throw new Error('hermetic evidence manifest test execution bindings are inconsistent');
    }
    if (!Array.isArray(manifest.stagedFileDigests) || manifest.stagedFileDigests.length !== manifest.snapshotFileCount
        || sha256(canonicalJson(manifest.stagedFileDigests)) !== manifest.snapshotManifestDigest
        || !validDigestRecordSet(manifest.testInventory, manifest.testInventoryDigest)
        || !validDigestRecordSet(manifest.implementationSources, manifest.implementationSourceDigest)
        || !validDigestRecordSet(manifest.substituteImplementationSources, manifest.substituteImplementationDigest)
        || !Array.isArray(manifest.nodeFlags) || !manifest.nodeFlags.includes('--permission')
        || !manifest.nodeFlags.includes('--frozen-intrinsics') || manifest.nodeFlags.includes('--allow-child-process')) {
      throw new Error('hermetic evidence manifest requires exact staged bytes and locked runtime inputs');
    }
    validateModuleBinding(manifest);
    validateTestSummary(manifest);
    validateNativeRuntimeBinding(manifest);
    validateExecutionSourceClosure(manifest);
    if (!Number.isInteger(manifest.localShaclExpectedRegisteredConstraintCount)
        || manifest.localShaclExpectedRegisteredConstraintCount < 1
        || manifest.localShaclRegisteredConstraintCount !== manifest.localShaclExpectedRegisteredConstraintCount
        || manifest.localShaclLocallyEvaluatedConstraintCount !== manifest.localShaclExpectedRegisteredConstraintCount
        || manifest.localShaclRegisteredConstraintSetDigest !== manifest.localShaclExpectedRegisteredConstraintSetDigest
        || manifest.localShaclCompatibleConstraintSetDigest !== manifest.localShaclExpectedRegisteredConstraintSetDigest
        || !Number.isInteger(manifest.localShaclExpectedShapeSourceFileCount)
        || manifest.localShaclExpectedShapeSourceFileCount < 1
        || manifest.localShaclShapeSourceSetDigest !== manifest.localShaclExpectedShapeSourceSetDigest
        || manifest.localShaclActualServiceAlgebraNodeCount !== 0
        || manifest.localShaclSubstringBasedExclusionCount !== 0
        || manifest.localShaclUnexpectedExclusionCount !== 0
        || manifest.localShaclCandidateViolationCount !== 0
        || manifest.localShaclLiveServiceConstraintSetDigest !== EMPTY_SET_DIGEST
        || !Number.isInteger(manifest.localShaclExpectedFocusRootCount)
        || manifest.localShaclExpectedFocusRootCount < 1
        || manifest.localShaclFocusRootCount !== manifest.localShaclExpectedFocusRootCount
        || manifest.localShaclFocusRootDigest !== manifest.localShaclExpectedFocusRootDigest
        || !Number.isInteger(manifest.localShaclFocusNodeCount)
        || manifest.localShaclFocusNodeCount < manifest.localShaclFocusRootCount) {
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
    for (const field of ['candidateAuthorityDigest', 'liveValidatedConstraintSetDigest', 'liveValidatedShapeSourceSetDigest',
      'liveAuthoredValidationReceiptDigest', 'liveDerivedValidationReceiptDigest', 'liveValidationReportDigest', 'liveServiceConstraintSetDigest']) {
      if (!SHA256.test(manifest?.[field] || '')) throw new Error(`live authority-control evidence manifest requires ${field}`);
    }
    if (manifest.providerMode !== 'urn:usf:providermode:liveauthoritycontrol'
        || manifest.providerIdentity !== LIVE_PROVIDER
        || manifest.environmentClass !== 'urn:usf:environmentclass:authoritycontrol'
        || !SHA256.test(manifest.evaluatedAuthorityDigest || '')
        || manifest.transactionMode !== 'validate-and-rollback'
        || manifest.postTransactionAuthorityDrift !== 'ZERO'
        || manifest.postTransactionAuthorityDigest !== manifest.evaluatedAuthorityDigest
        || !Number.isInteger(manifest.liveValidatedSparqlConstraintCount) || manifest.liveValidatedSparqlConstraintCount < 1
        || !Number.isInteger(manifest.liveValidatedShapeSourceFileCount) || manifest.liveValidatedShapeSourceFileCount < 1
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

function validateRealisationOptionClosure(result, authorityDigest) {
  const exactFields = [
    'acceptedDecisionCount', 'closureStates', 'criterionCount', 'evaluatedAuthorityDigest',
    'evaluationDependencySetDigest', 'evaluationEvidenceDigest', 'evaluationImplementationSourceDigest',
    'evidenceDigest', 'findings', 'gate', 'gateCounters', 'ok', 'reasonCodeVocabularyDigest',
    'resultDigest', 'schemaVersion', 'sourceFileCount', 'sourceSetDigest',
  ];
  const digests = [
    'evidenceDigest', 'resultDigest', 'evaluationEvidenceDigest', 'evaluationDependencySetDigest',
    'evaluationImplementationSourceDigest', 'sourceSetDigest',
  ];
  const counterNames = result?.gateCounters && typeof result.gateCounters === 'object' && !Array.isArray(result.gateCounters)
    ? Object.keys(result.gateCounters).sort() : [];
  const decisions = Array.isArray(result?.closureStates)
    ? result.closureStates.map((item) => item && typeof item === 'object' && !Array.isArray(item) ? item.decision : null)
    : [];
  if (!result || typeof result !== 'object' || Array.isArray(result)
      || canonicalJson(Object.keys(result).sort()) !== canonicalJson(exactFields.sort())
      || result.schemaVersion !== 1 || result.ok !== true || result.gate !== 'REALISATION_OPTION_EVALUATION_CLOSURE'
      || result.evaluatedAuthorityDigest !== authorityDigest
      || !Number.isInteger(result.acceptedDecisionCount) || result.acceptedDecisionCount < 1
      || !Number.isInteger(result.criterionCount) || result.criterionCount < 1
      || !Number.isInteger(result.sourceFileCount) || result.sourceFileCount < 1
      || canonicalJson(counterNames) !== canonicalJson([...GATE_COUNTER_NAMES].sort())
      || Object.values(result.gateCounters).some((value) => !Number.isInteger(value) || value !== 0)
      || !Array.isArray(result.findings) || result.findings.length !== 0
      || !Array.isArray(result.closureStates) || result.closureStates.length !== result.acceptedDecisionCount
      || result.closureStates.some((item) => !item || typeof item !== 'object' || Array.isArray(item)
        || canonicalJson(Object.keys(item).sort()) !== canonicalJson(['decision', 'state'])
        || typeof item.decision !== 'string' || item.decision.length === 0 || item.state !== 'COMPLETE')
      || new Set(decisions).size !== decisions.length
      || result.reasonCodeVocabularyDigest !== sha256(canonicalJson(REASON_PRECEDENCE))
      || digests.some((field) => !SHA256.test(result[field] || ''))) {
    throw new Error('realisation option evaluation closure is incomplete or stale');
  }
  const resultCore = {
    schemaVersion: result.schemaVersion,
    gate: result.gate,
    acceptedDecisionCount: result.acceptedDecisionCount,
    criterionCount: result.criterionCount,
    findings: result.findings,
    gateCounters: result.gateCounters,
    closureStates: result.closureStates,
    reasonCodeVocabularyDigest: result.reasonCodeVocabularyDigest,
  };
  if (result.resultDigest !== sha256(canonicalJson(resultCore))) throw new Error('realisation option evaluation closure result digest is invalid');
  const { evidenceDigest, ...evidenceCore } = result;
  if (evidenceDigest !== sha256(canonicalJson(evidenceCore))) throw new Error('realisation option evaluation closure evidence digest is invalid');
  return result;
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
  const sharedBindings = [
    'evaluatedAt',
    'implementationSourceDigest', 'proofAlgorithmDigest', 'testSetDigest',
    'realisationOptionClosureEvidenceDigest', 'realisationOptionClosureResultDigest',
    'realisationOptionEvaluationDependencyDigest', 'realisationOptionEvaluationEvidenceDigest',
    'realisationOptionEvaluationImplementationSourceDigest', 'realisationOptionEvaluationSourceSetDigest',
  ];
  if (hermetic.evidenceDigest === authorityControl.evidenceDigest
      || sharedBindings.some((field) => hermetic[field] !== authorityControl[field])
      || hermetic.localShaclExpectedRegisteredConstraintCount !== authorityControl.liveValidatedSparqlConstraintCount
      || hermetic.localShaclExpectedRegisteredConstraintSetDigest !== authorityControl.liveValidatedConstraintSetDigest
      || hermetic.localShaclRegisteredConstraintSetDigest !== authorityControl.liveValidatedConstraintSetDigest
      || hermetic.localShaclExpectedShapeSourceFileCount !== authorityControl.liveValidatedShapeSourceFileCount
      || hermetic.localShaclExpectedShapeSourceSetDigest !== authorityControl.liveValidatedShapeSourceSetDigest
      || hermetic.localShaclShapeSourceSetDigest !== authorityControl.liveValidatedShapeSourceSetDigest
      || hermetic.localShaclLiveServiceConstraintSetDigest !== authorityControl.liveServiceConstraintSetDigest) {
    throw new Error('composite proof must preserve distinct evidence identities and exact cross-scope constraint boundaries');
  }
  return true;
}

function validatePlantedFixtureEvidence(evidence) {
  const expectedCodes = [
    'PERMUTATION_FAMILY_SIGNATURE_COMPONENT_MISMATCH',
    'PERMUTATION_FAMILY_SIGNATURE_SUBJECT_ABSENT',
    'PERMUTATION_RELATIONSHIP_REVIEW_AUTHORISATION_PROHIBITED',
    'PERMUTATION_RELATIONSHIP_REVIEW_SIGNATURE_ABSENT',
    'PERMUTATION_REVIEW_TERM_ALGORITHM_ABSENT',
    'PERMUTATION_REVIEW_TERM_SET_MISMATCH',
    'PERMUTATION_SEMANTIC_REVIEW_ALGORITHM_ABSENT',
    'PERMUTATION_SEMANTIC_REVIEW_DISPOSITION_ABSENT',
    'PERMUTATION_SEMANTIC_REVIEW_EVIDENCE_ABSENT',
    'PERMUTATION_SEMANTIC_REVIEW_RATIONALE_ABSENT',
    'UNIVERSAL_CANDIDATE_AUTHORISATION_PROHIBITED',
    'UNIVERSAL_CANDIDATE_ENDPOINT_MODE_INVALID',
    'UNIVERSAL_CANDIDATE_FORM_COMPONENT_CONFLICT',
    'UNIVERSAL_CANDIDATE_KIND_ABSENT',
    'UNIVERSAL_CANDIDATE_SUBJECT_ABSENT',
    'UNIVERSAL_CANDIDATE_WARRANTED_WITH_GAPS',
    'UNIVERSAL_REVIEW_TERM_ABSENT',
  ];
  const fields = [
    'caseCount', 'catalogue', 'catalogueDigest', 'contractConforms', 'evidenceDigest',
    'fixtureGraphDigest', 'fixtureIsolation', 'fixtureTripleCount', 'focusNodeSetDigest',
    'missingExpectedCount', 'multipleCodeCount', 'negativeControlCount', 'positiveControlCount',
    'rawValidationConforms', 'reasonCodeSet', 'reasonCodeSetDigest', 'resultDigest',
    'resultRecords', 'schemaVersion', 'unexpectedCodeCount', 'unrecognisedResultCount',
    'validationScope',
  ];
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)
      || canonicalJson(Object.keys(evidence).sort()) !== canonicalJson(fields)
      || evidence.schemaVersion !== 1
      || evidence.validationScope !== 'PLANTED_PERMUTATION_REVIEW_FIXTURES'
      || evidence.fixtureIsolation !== 'IN_MEMORY_UNPUBLISHED_CANDIDATE'
      || evidence.caseCount !== 25
      || evidence.positiveControlCount !== 7
      || evidence.negativeControlCount !== 18
      || !Array.isArray(evidence.catalogue)
      || !Array.isArray(evidence.resultRecords)
      || !Array.isArray(evidence.reasonCodeSet)
      || evidence.catalogue.length !== evidence.caseCount
      || evidence.resultRecords.length !== evidence.caseCount
      || canonicalJson(evidence.reasonCodeSet) !== canonicalJson(expectedCodes)
      || evidence.catalogueDigest !== sha256(canonicalJson(evidence.catalogue))
      || evidence.resultDigest !== sha256(canonicalJson(evidence.resultRecords))
      || evidence.reasonCodeSetDigest !== sha256(canonicalJson(evidence.reasonCodeSet))
      || !SHA256.test(evidence.fixtureGraphDigest || '')
      || !SHA256.test(evidence.focusNodeSetDigest || '')
      || !Number.isInteger(evidence.fixtureTripleCount) || evidence.fixtureTripleCount < 1
      || evidence.rawValidationConforms !== false
      || evidence.missingExpectedCount !== 0
      || evidence.unexpectedCodeCount !== 0
      || evidence.multipleCodeCount !== 0
      || evidence.unrecognisedResultCount !== 0
      || evidence.contractConforms !== true) {
    throw new Error('local SHACL planted-fixture evidence does not close exact reason-code precedence');
  }
  const { evidenceDigest, ...core } = evidence;
  if (!SHA256.test(evidenceDigest || '') || evidenceDigest !== sha256(canonicalJson(core))) {
    throw new Error('local SHACL planted-fixture evidence digest mismatch');
  }
  const catalogueById = new Map();
  const focusNodes = [];
  let positiveCount = 0;
  let negativeCount = 0;
  for (const record of evidence.catalogue) {
    if (!record || typeof record !== 'object' || Array.isArray(record)
        || canonicalJson(Object.keys(record).sort()) !== canonicalJson(['expectedReasonCodes', 'expectedResult', 'focusNode', 'id'])
        || typeof record.id !== 'string' || record.id.length < 1
        || typeof record.focusNode !== 'string' || !record.focusNode.startsWith('urn:usf:fixture:permutation-review:')
        || !Array.isArray(record.expectedReasonCodes)
        || !['ACCEPTED', 'REJECTED'].includes(record.expectedResult)
        || (record.expectedResult === 'ACCEPTED' && record.expectedReasonCodes.length !== 0)
        || (record.expectedResult === 'REJECTED' && record.expectedReasonCodes.length !== 1)
        || record.expectedReasonCodes.some((code) => !expectedCodes.includes(code))
        || catalogueById.has(record.id)) {
      throw new Error('local SHACL planted-fixture catalogue is not exact');
    }
    catalogueById.set(record.id, record);
    focusNodes.push(record.focusNode);
    if (record.expectedResult === 'ACCEPTED') positiveCount += 1;
    else negativeCount += 1;
  }
  if (new Set(focusNodes).size !== focusNodes.length
      || evidence.focusNodeSetDigest !== sha256(canonicalJson([...focusNodes].sort()))
      || positiveCount !== evidence.positiveControlCount
      || negativeCount !== evidence.negativeControlCount) {
    throw new Error('local SHACL planted-fixture inventory is not exact');
  }
  const resultIds = new Set();
  for (const record of evidence.resultRecords) {
    const expected = catalogueById.get(record?.id);
    if (!expected || resultIds.has(record.id)
        || canonicalJson(Object.keys(record).sort()) !== canonicalJson(['actualReasonCodes', 'actualResult', 'expectedReasonCodes', 'expectedResult', 'focusNode', 'id', 'resultCount'])
        || record.focusNode !== expected.focusNode
        || record.expectedResult !== expected.expectedResult
        || canonicalJson(record.expectedReasonCodes) !== canonicalJson(expected.expectedReasonCodes)
        || canonicalJson(record.actualReasonCodes) !== canonicalJson(expected.expectedReasonCodes)
        || record.actualResult !== expected.expectedResult
        || record.resultCount !== expected.expectedReasonCodes.length) {
      throw new Error('local SHACL planted-fixture result does not match its exact expected branch');
    }
    resultIds.add(record.id);
  }
  if (resultIds.size !== catalogueById.size) throw new Error('local SHACL planted-fixture results are incomplete');
  return evidence;
}

function validateLocalShaclEvidence(result) {
  if (result?.deterministicRegenerationCount !== 2
      || !SHA256.test(result?.deterministicOutputDigest || '')
      || result.firstOutputDigest !== result.deterministicOutputDigest
      || result.secondOutputDigest !== result.deterministicOutputDigest) {
    throw new Error('local SHACL evidence requires two byte-identical deterministic executions');
  }
  const expectedScope = result.expectedScope;
  if (!expectedScope || typeof expectedScope !== 'object' || Array.isArray(expectedScope)
      || canonicalJson(Object.keys(expectedScope).sort()) !== canonicalJson(['focusRootCount', 'focusRootDigest', 'registeredConstraintSetDigest', 'registeredSparqlConstraintCount', 'shapeSourceFileCount', 'shapeSourceSetDigest'])
      || !Number.isInteger(expectedScope.registeredSparqlConstraintCount) || expectedScope.registeredSparqlConstraintCount < 1
      || !Number.isInteger(expectedScope.focusRootCount) || expectedScope.focusRootCount < 1
      || !SHA256.test(expectedScope.focusRootDigest || '')
      || !SHA256.test(expectedScope.registeredConstraintSetDigest || '')
      || !Number.isInteger(expectedScope.shapeSourceFileCount) || expectedScope.shapeSourceFileCount < 1
      || !SHA256.test(expectedScope.shapeSourceSetDigest || '')) {
    throw new Error('local SHACL evidence requires an independently derived exact scope');
  }
  const evidence = result.evidence;
  const digestFields = [
    'candidateSourceSetDigest', 'compatibleConstraintSetDigest', 'dataSourceSetDigest',
    'dependencySpecificationDigest', 'evidenceDigest', 'focusClosureAlgorithmDigest',
    'focusClosureWitnessDigest', 'focusNodeDigest', 'focusPredicatePolicyDigest', 'focusRootDigest',
    'harnessSourceDigest', 'liveServiceConstraintSetDigest', 'originalQuerySetDigest',
    'prefixContextSetDigest', 'prefixInjectionAlgorithmDigest', 'pythonDependencyByteSetDigest',
    'pythonExecutableDigest', 'registeredConstraintSetDigest', 'representativeEquivalenceDigest',
    'plantedFixtureEvidenceDigest', 'semanticManifestDigest', 'serviceClassificationAlgorithmDigest', 'serviceClassifierSelfTestDigest',
    'shapeSourceSetDigest', 'transformedQuerySetDigest', 'validationPhaseResultDigest',
  ];
  for (const field of digestFields) if (!SHA256.test(evidence?.[field] || '')) throw new Error(`local SHACL evidence requires ${field}`);
  const { evidenceDigest, ...core } = evidence;
  if (evidenceDigest !== sha256(canonicalJson(core))) throw new Error('local SHACL evidence digest does not match its canonical claims');
  const plantedFixtureEvidence = validatePlantedFixtureEvidence(evidence.plantedFixtureEvidence);
  if (evidence.evidenceScope !== HERMETIC_SCOPE
      || evidence.validationScope !== 'LOCAL_PYSHACL_COMPATIBLE_AFFECTED_CLOSURE'
      || evidence.localCompatibleConforms !== true
      || evidence.registeredSparqlConstraintCount !== expectedScope.registeredSparqlConstraintCount
      || evidence.locallyEvaluatedConstraintCount !== expectedScope.registeredSparqlConstraintCount
      || evidence.registeredConstraintSetDigest !== expectedScope.registeredConstraintSetDigest
      || evidence.shapeSourceSetDigest !== expectedScope.shapeSourceSetDigest
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
      || evidence.prefixSemanticEquivalenceCount !== expectedScope.registeredSparqlConstraintCount
      || evidence.pyshaclServiceDetectionMode !== 'PARSED_SPARQL_ALGEBRA'
      || !Array.isArray(evidence.validationPhaseResults)
      || evidence.validationPhaseResults.length !== 2
      || evidence.validationPhaseResultDigest !== sha256(canonicalJson(evidence.validationPhaseResults))
      || evidence.validationPhaseResults.some(({ conforms, violationCount, resultDigest }) => conforms !== true || violationCount !== 0 || !SHA256.test(resultDigest || ''))
      || evidence.validationPhaseResults.map(({ phase }) => phase).join(',') !== 'AFFECTED_AUTHORED,AFFECTED_REGISTERED_DERIVED_SNAPSHOT'
      || evidence.transitiveFocusGap !== 0
      || evidence.focusRootCount !== expectedScope.focusRootCount
      || evidence.focusRootDigest !== expectedScope.focusRootDigest
      || !Number.isInteger(evidence.focusNodeCount) || evidence.focusNodeCount < evidence.focusRootCount
      || evidence.serviceClassifierSelfTestCount !== 7
      || !Array.isArray(evidence.serviceClassifierSelfTests)
      || evidence.serviceClassifierSelfTests.some(({ expectedLiveDependent, actualLiveDependent }) => expectedLiveDependent !== actualLiveDependent)
      || evidence.plantedFixtureEvidenceDigest !== plantedFixtureEvidence.evidenceDigest
      || evidence.pyshaclVersion !== '0.40.0'
      || evidence.rdflibVersion !== '7.6.0'
      || evidence.pyyamlVersion !== '6.0.3') {
    throw new Error('local SHACL evidence does not close the exact compatible affected constraint scope');
  }
  return Object.freeze({ ...evidence, expectedScope: Object.freeze({ ...expectedScope }) });
}

function validateLiveValidationEvidence(result, localShacl) {
  const topFields = ['authored', 'derived', 'receiptDigest', 'validatedDocumentCount', 'validatedDocumentSetDigest'];
  const receiptFields = ['conforms', 'observationSetDigest', 'receiptDigest', 'validatedDocumentCount', 'validatedDocumentSetDigest'];
  if (!result || typeof result !== 'object' || Array.isArray(result)
      || canonicalJson(Object.keys(result).sort()) !== canonicalJson(topFields)
      || result.validatedDocumentCount !== localShacl.expectedScope.shapeSourceFileCount
      || result.validatedDocumentSetDigest !== localShacl.expectedScope.shapeSourceSetDigest
      || result.validatedDocumentSetDigest !== localShacl.shapeSourceSetDigest) {
    throw new Error('live SHACL validation evidence does not bind the exact locally validated shape sources');
  }
  for (const receipt of [result.authored, result.derived]) {
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)
        || canonicalJson(Object.keys(receipt).sort()) !== canonicalJson(receiptFields)
        || receipt.conforms !== true
        || receipt.validatedDocumentCount !== result.validatedDocumentCount
        || receipt.validatedDocumentSetDigest !== result.validatedDocumentSetDigest
        || !SHA256.test(receipt.observationSetDigest || '')) {
      throw new Error('live SHACL validation receipt is incomplete or bound to different inputs');
    }
    const { receiptDigest, ...core } = receipt;
    if (receiptDigest !== sha256(canonicalJson(core))) throw new Error('live SHACL validation receipt digest is invalid');
  }
  const { receiptDigest, ...core } = result;
  if (receiptDigest !== sha256(canonicalJson(core))) throw new Error('combined live SHACL validation receipt digest is invalid');
  return Object.freeze(result);
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
  realisationOptionClosure,
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
  const optionClosure = validateRealisationOptionClosure(realisationOptionClosure, authorityDigest);

  const sources = sourceSet(repositoryRoot, sourcePaths, {}, [casRoot]);
  const testsSources = sourceSubset(sources, testPaths);
  const substituteSources = sourceSubset(sources, substituteSourcePaths);
  const tests = await runFocusedTests();
  if (tests?.passed !== true || !Number.isInteger(tests.count) || tests.count < 1 || !SHA256.test(tests.outputDigest || '')
      || tests.discoveredFileCount !== testsSources.records.length
      || tests.testInventoryDigest !== testsSources.digest
      || tests.preExecutionReboundDigest !== testsSources.digest
      || tests.stagedTestInventoryDigest !== testsSources.digest
      || tests.executedTestInventoryDigest !== testsSources.digest
      || tests.launcherObservedTestInventoryDigest !== testsSources.digest
      || tests.launcherObservedTestFileCount !== testsSources.records.length
      || tests.authorisedExecutionByteSetDigest !== tests.snapshotManifestDigest
      || tests.snapshotReadOnlyVerified !== true
      || tests.nodeVersion !== '22.23.1') {
    throw new Error('focused compiler tests did not produce valid passing evidence');
  }
  validateModuleBinding({ ...tests, testInventory: testsSources.records });
  validateTestSummary({ ...tests, testSummary: tests.testSummary, testOutputDigest: tests.outputDigest, testCount: tests.count });
  validateNativeRuntimeBinding(tests);
  validateExecutionSourceClosure({
    ...tests,
    implementationSources: sources.records,
    substituteImplementationSources: substituteSources.records,
    testInventory: testsSources.records,
  });
  const localShaclRun = await runLocalCompatibleShacl();
  const localShacl = validateLocalShaclEvidence(localShaclRun);
  const client = await createLiveClient();
  const command = createCommand({ client, readAuthorityWitness, repositoryRoot });
  const compilation = await command.execute({ expectedAuthorityDigest: authorityDigest, publicationMode: 'validate' });
  const liveValidation = validateLiveValidationEvidence(compilation.liveValidation, localShacl);
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

  const proofAlgorithmDigest = sources.records.find(({ path }) => path === proofAlgorithmPath)?.digest;
  if (!proofAlgorithmDigest) throw new Error('proof algorithm is absent from the complete immutable source observation');
  const testExecutionBinding = {
    authorisedExecutionByteSetDigest: tests.authorisedExecutionByteSetDigest,
    authorisedRoots: tests.authorisedRoots,
    authorisedRootSetDigest: tests.authorisedRootSetDigest,
    bootstrapModuleRecords: tests.bootstrapModuleRecords,
    bootstrapModuleSetDigest: tests.bootstrapModuleSetDigest,
    dependencyByteSetDigest: tests.dependencyByteSetDigest,
    dependencyLockDigest: tests.dependencyLockDigest,
    discoveryAlgorithmDigest: tests.discoveryAlgorithmDigest,
    executedByteSetDigest: tests.executedByteSetDigest,
    executedTestInventoryDigest: tests.executedTestInventoryDigest,
    expectedDenialCodes: tests.expectedDenialCodes,
    environment: tests.environment,
    invocationDigest: tests.invocationDigest,
    invocationMode: tests.invocationMode,
    isolationMode: tests.isolationMode,
    launcherDigest: tests.launcherDigest,
    launcherObservedTestFileCount: tests.launcherObservedTestFileCount,
    launcherObservedTestInventoryDigest: tests.launcherObservedTestInventoryDigest,
    loadedModuleCount: tests.loadedModuleCount,
    loadedModuleRecords: tests.loadedModuleRecords,
    loadedModuleSetDigest: tests.loadedModuleSetDigest,
    resolvedModuleCount: tests.resolvedModuleCount,
    resolvedModuleRecords: tests.resolvedModuleRecords,
    resolvedModuleSetDigest: tests.resolvedModuleSetDigest,
    nativeRuntimeBindings: tests.nativeRuntimeBindings,
    nativeRuntimeChildBindingDigest: tests.nativeRuntimeChildBindingDigest,
    nativeRuntimeDigests: tests.nativeRuntimeDigests,
    nativeRuntimePostBindingDigest: tests.nativeRuntimePostBindingDigest,
    nativeRuntimePreBindingDigest: tests.nativeRuntimePreBindingDigest,
    nativeRuntimeSetDigest: tests.nativeRuntimeSetDigest,
    networkIsolation: tests.networkIsolation,
    networkIsolatorBinding: tests.networkIsolatorBinding,
    networkIsolatorDigest: tests.networkIsolatorDigest,
    networkIsolatorPostBinding: tests.networkIsolatorPostBinding,
    nodeExecutableBinding: tests.nodeExecutableBinding,
    nodeExecutableDigest: tests.nodeExecutableDigest,
    nodeFlags: tests.nodeFlags,
    nodeVersion: tests.nodeVersion,
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
    testSummary: tests.testSummary,
    virtualSharedObjects: tests.virtualSharedObjects,
  };
  const localShaclBinding = {
    localShaclActualServiceAlgebraNodeCount: localShacl.actualServiceAlgebraNodeCount,
    localShaclCandidateSourceSetDigest: localShacl.candidateSourceSetDigest,
    localShaclCandidateViolationCount: localShacl.candidateViolationCount,
    localShaclCompatibleConstraintSetDigest: localShacl.compatibleConstraintSetDigest,
    localShaclDeterministicOutputDigest: localShaclRun.deterministicOutputDigest,
    localShaclEvidenceDigest: localShacl.evidenceDigest,
    localShaclExpectedFocusRootCount: localShacl.expectedScope.focusRootCount,
    localShaclExpectedFocusRootDigest: localShacl.expectedScope.focusRootDigest,
    localShaclExpectedRegisteredConstraintCount: localShacl.expectedScope.registeredSparqlConstraintCount,
    localShaclExpectedRegisteredConstraintSetDigest: localShacl.expectedScope.registeredConstraintSetDigest,
    localShaclExpectedShapeSourceFileCount: localShacl.expectedScope.shapeSourceFileCount,
    localShaclExpectedShapeSourceSetDigest: localShacl.expectedScope.shapeSourceSetDigest,
    localShaclFocusNodeCount: localShacl.focusNodeCount,
    localShaclFocusNodeDigest: localShacl.focusNodeDigest,
    localShaclFocusRootCount: localShacl.focusRootCount,
    localShaclFocusRootDigest: localShacl.focusRootDigest,
    localShaclHarnessSourceDigest: localShacl.harnessSourceDigest,
    localShaclLiveServiceConstraintSetDigest: localShacl.liveServiceConstraintSetDigest,
    localShaclLocallyEvaluatedConstraintCount: localShacl.locallyEvaluatedConstraintCount,
    localShaclPlantedFixtureCatalogueDigest: localShacl.plantedFixtureEvidence.catalogueDigest,
    localShaclPlantedFixtureCaseCount: localShacl.plantedFixtureEvidence.caseCount,
    localShaclPlantedFixtureEvidenceDigest: localShacl.plantedFixtureEvidence.evidenceDigest,
    localShaclPlantedFixtureFixtureGraphDigest: localShacl.plantedFixtureEvidence.fixtureGraphDigest,
    localShaclPlantedFixtureFocusNodeSetDigest: localShacl.plantedFixtureEvidence.focusNodeSetDigest,
    localShaclPlantedFixtureMissingExpectedCount: localShacl.plantedFixtureEvidence.missingExpectedCount,
    localShaclPlantedFixtureMultipleCodeCount: localShacl.plantedFixtureEvidence.multipleCodeCount,
    localShaclPlantedFixtureNegativeControlCount: localShacl.plantedFixtureEvidence.negativeControlCount,
    localShaclPlantedFixturePositiveControlCount: localShacl.plantedFixtureEvidence.positiveControlCount,
    localShaclPlantedFixtureReasonCodeSetDigest: localShacl.plantedFixtureEvidence.reasonCodeSetDigest,
    localShaclPlantedFixtureResultDigest: localShacl.plantedFixtureEvidence.resultDigest,
    localShaclPlantedFixtureUnexpectedCodeCount: localShacl.plantedFixtureEvidence.unexpectedCodeCount,
    localShaclPlantedFixtureUnrecognisedResultCount: localShacl.plantedFixtureEvidence.unrecognisedResultCount,
    localShaclPrefixInjectionAlgorithmDigest: localShacl.prefixInjectionAlgorithmDigest,
    localShaclPythonDependencyByteSetDigest: localShacl.pythonDependencyByteSetDigest,
    localShaclRegisteredConstraintSetDigest: localShacl.registeredConstraintSetDigest,
    localShaclRegisteredConstraintCount: localShacl.registeredSparqlConstraintCount,
    localShaclShapeSourceSetDigest: localShacl.shapeSourceSetDigest,
    localShaclServiceClassificationAlgorithmDigest: localShacl.serviceClassificationAlgorithmDigest,
    localShaclSubstringBasedExclusionCount: localShacl.substringBasedExclusionCount,
    localShaclUnexpectedExclusionCount: localShacl.unexpectedExclusionCount,
    localShaclValidationPhaseResultDigest: localShacl.validationPhaseResultDigest,
  };
  const hermeticCases = cases.filter(({ id }) => CASE_SCOPES.get(id) === HERMETIC_SCOPE);
  const authorityControlCases = cases.filter(({ id }) => CASE_SCOPES.get(id) === AUTHORITY_SCOPE);
  const optionClosureBinding = {
    realisationOptionClosureEvidenceDigest: optionClosure.evidenceDigest,
    realisationOptionClosureResultDigest: optionClosure.resultDigest,
    realisationOptionEvaluationDependencyDigest: optionClosure.evaluationDependencySetDigest,
    realisationOptionEvaluationEvidenceDigest: optionClosure.evaluationEvidenceDigest,
    realisationOptionEvaluationImplementationSourceDigest: optionClosure.evaluationImplementationSourceDigest,
    realisationOptionEvaluationSourceSetDigest: optionClosure.sourceSetDigest,
  };
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
    ...optionClosureBinding,
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
    ...optionClosureBinding,
    liveValidatedSparqlConstraintCount: localShacl.registeredSparqlConstraintCount,
    liveValidatedConstraintSetDigest: localShacl.registeredConstraintSetDigest,
    liveValidatedShapeSourceFileCount: liveValidation.validatedDocumentCount,
    liveValidatedShapeSourceSetDigest: liveValidation.validatedDocumentSetDigest,
    liveAuthoredValidationReceiptDigest: liveValidation.authored.receiptDigest,
    liveDerivedValidationReceiptDigest: liveValidation.derived.receiptDigest,
    liveServiceConstraintCount: localShacl.liveServiceConstraintCount,
    liveServiceConstraintSetDigest: localShacl.liveServiceConstraintSetDigest,
    liveValidationReportDigest: liveValidation.receiptDigest,
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
    realisationOptionClosureEvidenceDigest: optionClosure.evidenceDigest,
    result: 'passed',
  }, 'semantic-model-compiler-hermetic-evidence');
  const authorityControlEnvelope = attest(authorityControlEvidenceManifest.digest, {
    evidenceScope: authorityControlEvidenceCore.evidenceScope,
    evaluatedAuthorityDigest: authorityDigest,
    candidateAuthorityDigest: compilation.commitOutcome.candidateDigest,
    exactEvidenceSetDigest,
    implementationSourceDigest: sources.digest,
    realisationOptionClosureEvidenceDigest: optionClosure.evidenceDigest,
    result: 'passed',
  }, 'semantic-model-compiler-authority-control-evidence');
  const proofEnvelope = attest(exactEvidenceSetDigest, {
    evaluatedAuthorityDigest: authorityDigest,
    candidateAuthorityDigest: compilation.commitOutcome.candidateDigest,
    exactEvidenceSetDigest,
    implementationSourceDigest: sources.digest,
    realisationOptionClosureEvidenceDigest: optionClosure.evidenceDigest,
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
    realisationOptionClosureEvidenceDigest: optionClosure.evidenceDigest,
    realisationOptionClosureResultDigest: optionClosure.resultDigest,
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
  GATE_COUNTER_NAMES,
  HERMETIC_SCOPE,
  REASON_PRECEDENCE,
  canonicalJson,
  evidenceManifest,
  sha256,
  sourceSet,
  validateCompositeScopes,
  validateEvidenceManifest,
  validateLocalShaclEvidence,
  validateRealisationOptionClosure,
});
