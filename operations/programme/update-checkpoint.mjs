import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  renameSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { dirname, join } from 'node:path';

const repositoryRoot = process.cwd();
const stateRoot = join(repositoryRoot, '.work', 'programme');
const checkpointPath = join(stateRoot, 'checkpoint.json');
const legacyCheckpointPath = join(repositoryRoot, '.work', 'materialisation', 'goal', 'goal-state.json');

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortValue(value[key])]));
  }
  return value;
}

function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(sortValue(value), null, 2)}\n`);
}

function gitBuffer(args) {
  return execFileSync('git', args, { cwd: repositoryRoot, maxBuffer: 1024 * 1024 * 1024 });
}

function gitText(args) {
  return gitBuffer(args).toString('utf8').trim();
}

function atomicWrite(path, bytes) {
  mkdirSync(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  const descriptor = openSync(temporaryPath, 'w', 0o600);
  try {
    writeSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporaryPath, path);
  chmodSync(path, 0o600);
  const actual = readFileSync(path);
  if (!actual.equals(bytes)) throw new Error(`atomic checkpoint verification failed: ${path}`);
  return sha256(actual);
}

function digestAt(revision, path) {
  try {
    return sha256(gitBuffer(['show', `${revision}:${path}`]));
  } catch {
    return null;
  }
}

function digestWorkingPath(path) {
  const absolutePath = join(repositoryRoot, path);
  if (!existsSync(absolutePath)) return null;
  const stat = lstatSync(absolutePath);
  if (stat.isSymbolicLink()) return sha256(Buffer.from(readlinkSync(absolutePath)));
  if (!stat.isFile()) return null;
  return sha256(readFileSync(absolutePath));
}

function readContentAddressedJson(path) {
  const fileDigest = digestWorkingPath(path);
  if (!fileDigest) throw new Error(`current wave artefact is absent or not a regular file: ${path}`);
  const match = path.match(/-([0-9a-f]{64})\.json$/u);
  if (!match || fileDigest !== `sha256:${match[1]}`) {
    throw new Error(`current wave artefact path is not bound to its byte digest: ${path}`);
  }
  return {
    fileDigest,
    path,
    record: JSON.parse(readFileSync(join(repositoryRoot, path), 'utf8')),
  };
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, observed ${actual}`);
}

function trackedInventory() {
  const records = gitBuffer(['ls-files', '-s', '-z']).toString('utf8').split('\0').filter(Boolean);
  return records.map((record) => {
    const tab = record.indexOf('\t');
    const [mode, gitObject, stage] = record.slice(0, tab).split(' ');
    const path = record.slice(tab + 1);
    return {
      contentDigest: digestWorkingPath(path),
      gitObject,
      mode,
      path,
      stage: Number(stage),
    };
  }).sort((left, right) => left.path.localeCompare(right.path, 'en'));
}

function workingChanges() {
  const fields = gitBuffer(['diff', '--name-status', '-z', '-M', 'HEAD'])
    .toString('utf8').split('\0').filter(Boolean);
  const changes = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    const renamed = status.startsWith('R') || status.startsWith('C');
    const previousPath = fields[index++];
    const currentPath = renamed ? fields[index++] : previousPath;
    changes.push({
      currentContentDigest: status.startsWith('D') ? null : digestWorkingPath(currentPath),
      currentPath: status.startsWith('D') ? null : currentPath,
      previousContentDigest: status.startsWith('A') ? null : digestAt('HEAD', previousPath),
      previousPath: status.startsWith('A') ? null : previousPath,
      status,
    });
  }
  return changes.sort((left, right) => (left.currentPath ?? left.previousPath)
    .localeCompare(right.currentPath ?? right.previousPath, 'en'));
}

function repositoryProcesses() {
  const lines = execFileSync('ps', ['-eo', 'pid=,ppid=,comm='], { encoding: 'utf8' })
    .split('\n').map((line) => line.trim()).filter(Boolean);
  const records = [];
  for (const line of lines) {
    const match = line.match(/^(\d+)\s+(\d+)\s+(.+)$/);
    if (!match) continue;
    const [, pidText, parentPidText, executable] = match;
    const pid = Number(pidText);
    if (pid === process.pid) continue;
    let cwd;
    try {
      cwd = readlinkSync(`/proc/${pid}/cwd`);
    } catch {
      continue;
    }
    if (cwd !== repositoryRoot) continue;
    records.push({
      cwd,
      executable,
      ownership: 'OBSERVED_REPOSITORY_CWD_NO_MUTATION_ATTRIBUTED',
      parentProcessId: Number(parentPidText),
      processId: pid,
    });
  }
  return records.sort((left, right) => left.processId - right.processId);
}

const recordedAt = new Date().toISOString();
const priorCheckpointBytes = existsSync(checkpointPath)
  ? readFileSync(checkpointPath)
  : existsSync(legacyCheckpointPath)
    ? readFileSync(legacyCheckpointPath)
    : null;
const priorCheckpointDigest = priorCheckpointBytes ? sha256(priorCheckpointBytes) : null;
if (existsSync(checkpointPath) && priorCheckpointBytes) {
  atomicWrite(join(stateRoot, 'history', `${priorCheckpointDigest.slice(7)}.json`), priorCheckpointBytes);
}
const head = gitText(['rev-parse', 'HEAD']);
const upstream = gitText(['rev-parse', '@{upstream}']);
const goalDigest = sha256(readFileSync(join(repositoryRoot, 'GOAL.md')));
const tracked = trackedInventory();
const changes = workingChanges();
const statusBytes = gitBuffer(['status', '--porcelain=v1', '-z']);
const unstagedPatch = gitBuffer(['diff', '--binary', '--no-ext-diff']);
const stagedPatch = gitBuffer(['diff', '--cached', '--binary', '--no-ext-diff']);
const untrackedPaths = gitBuffer(['ls-files', '--others', '--exclude-standard', '-z']).toString('utf8').split('\0').filter(Boolean).sort();
for (const path of untrackedPaths) {
  changes.push({
    currentContentDigest: digestWorkingPath(path),
    currentPath: path,
    previousContentDigest: null,
    previousPath: null,
    status: '??',
  });
}
changes.sort((left, right) => (left.currentPath ?? left.previousPath).localeCompare(right.currentPath ?? right.previousPath, 'en'));
// GOAL.md digest this generator was last reconciled against (GOAL Section 2).
// A changed GOAL.md reopens DIRECTIVE_AND_CHECKPOINT_RECONCILIATION so an
// older checkpoint can never bypass the current directive.
const reconciledGoalDigest = 'sha256:8d06ec86a9b96ff2f61698fa3d06e503bc92537fb3b22cfb7a55e6617ccea66f';
const directiveReconciled = goalDigest === reconciledGoalDigest;
const optionAcquisition = {
  acquisitionInputDigest: 'sha256:7d5f9939c26e1524a5d38e6eecd46d26a8bb476f69e8ad1859f459150db59a3d',
  acquisitionSetDigest: 'sha256:be26125ea7f9ba92a44e05f711678c97b0769b75c102f0efb14875eea37623c0',
  authorityDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd',
  byteSize: 5526,
  casPath: '/var/lib/usf-cas/sha256/7d/7d5f9939c26e1524a5d38e6eecd46d26a8bb476f69e8ad1859f459150db59a3d',
  collectedAt: '2026-07-20T02:00:39Z',
  collectorDigest: 'sha256:315cb068463808d958d621840c715ce66f93a1a14c1777bc1bd498ec06ad1c69',
  state: 'VERIFIED_LOCAL_ACQUISITION_PENDING_SIGNED_EVIDENCE',
  validUntil: '2027-07-15T02:00:39Z',
};
const optionAcquisitionBytes = readFileSync(optionAcquisition.casPath);
if (sha256(optionAcquisitionBytes) !== optionAcquisition.acquisitionInputDigest) {
  throw new Error('realisation-option acquisition CAS bytes do not match the recorded digest');
}
const optionAcquisitionRecord = JSON.parse(optionAcquisitionBytes);
if (optionAcquisitionRecord.authorityDigest !== optionAcquisition.authorityDigest
  || optionAcquisitionRecord.acquisitionSetDigest !== optionAcquisition.acquisitionSetDigest) {
  throw new Error('realisation-option acquisition CAS record does not match its authority or set binding');
}

const currentWavePaths = {
  foundationAssessment: '.work/generated/foundation-domain-closure-assessment-8243a59f8b66008523a7a1350ddcba00c13b7f5b37e5a6d9ddef84bd70481f61.json',
  foundationProof: '.work/generated/foundation-domain-closure-proof-d506796d4ae5002e5694fd34a70505013b2b6aca9321de2fd748e61a71da87b8.json',
  localShaclEvidence: '.work/generated/local-shacl-relationship-review-wave-bf7c02bcd827ef20cf4d66e402e6c2ec744191c89cd5a7c0dc66d15895b04bf3.json',
  universalAnalysis: '.work/generated/universal-family-completeness-analysis-d4b298ec651d4929cf5ef06c83cc29037132c5b12db8cb8984eb345d0802e4d4.json',
  universalInventory: '.work/generated/universal-semantic-inventory-8d1fd6a44f6c2ebab8384e7d7b0ccd882b07c29b2098a12d7b3a59eab2c774d2.json',
  universalProof: '.work/generated/universal-semantic-coverage-proof-db86340a264cedcf17b17bab333d4b966b93cda64fbc2d9db14e120d009065e4.json',
  universalRegistry: '.work/generated/universal-family-registry-48a591a52d84a4522b8b7ba0bf29b96f7c12fdff13a38482b8d01ec3c7f876ff.json',
  universalReviewProjection: '.work/generated/universal-review-projection-51d7e1e32ad74afc7fdf46951eac55c9550d3e61ee83489d6398b79603e07fb1.json',
};
const currentWaveArtifacts = Object.fromEntries(Object.entries(currentWavePaths)
  .map(([key, path]) => [key, readContentAddressedJson(path)]));
const foundationAssessmentRecord = currentWaveArtifacts.foundationAssessment.record;
const foundationProofRecord = currentWaveArtifacts.foundationProof.record;
const localShaclEvidenceRecord = currentWaveArtifacts.localShaclEvidence.record;
const universalAnalysisRecord = currentWaveArtifacts.universalAnalysis.record;
const universalInventoryRecord = currentWaveArtifacts.universalInventory.record;
const universalProofRecord = currentWaveArtifacts.universalProof.record;
const universalRegistryRecord = currentWaveArtifacts.universalRegistry.record;
const universalReviewProjectionRecord = currentWaveArtifacts.universalReviewProjection.record;

requireEqual(foundationProofRecord.assessmentDigest, foundationAssessmentRecord.assessmentDigest, 'foundation proof assessment binding');
requireEqual(universalAnalysisRecord.foundationAssessmentDigest, foundationAssessmentRecord.assessmentDigest, 'universal analysis foundation assessment binding');
requireEqual(universalAnalysisRecord.foundationProofDigest, foundationProofRecord.proofDigest, 'universal analysis foundation proof binding');
requireEqual(universalAnalysisRecord.inventoryDigest, universalInventoryRecord.inventoryDigest, 'universal analysis inventory binding');
requireEqual(universalAnalysisRecord.registryDigest, universalRegistryRecord.registryDigest, 'universal analysis registry binding');
requireEqual(universalAnalysisRecord.reviewProjectionDigest, universalReviewProjectionRecord.reviewProjectionDigest, 'universal analysis review projection binding');
requireEqual(universalProofRecord.analysisDigest, universalAnalysisRecord.analysisDigest, 'universal proof analysis binding');
requireEqual(universalProofRecord.inventoryDigest, universalInventoryRecord.inventoryDigest, 'universal proof inventory binding');
requireEqual(universalProofRecord.registryDigest, universalRegistryRecord.registryDigest, 'universal proof registry binding');
requireEqual(universalProofRecord.reviewProjectionDigest, universalReviewProjectionRecord.reviewProjectionDigest, 'universal proof review projection binding');
requireEqual(universalProofRecord.authorityBinding.authorityDigest, optionAcquisition.authorityDigest, 'universal proof authority binding');
requireEqual(universalInventoryRecord.authorityBinding.authorityDigest, optionAcquisition.authorityDigest, 'universal inventory authority binding');
requireEqual(universalAnalysisRecord.authorityDigest, optionAcquisition.authorityDigest, 'universal analysis authority binding');

const universalProofMismatchFields = [
  'analysisReconstructionMismatchCount',
  'familyReconstructionMismatchCount',
  'inventoryReconstructionMismatchCount',
  'reviewProjectionReconstructionMismatchCount',
  'reviewSourceReconstructionMismatchCount',
];
const universalReconstructionMismatchCount = universalProofMismatchFields
  .reduce((sum, field) => sum + universalProofRecord.results[field], 0);

const nextExactAction = directiveReconciled ? {
  action: 'Inspect the largest residual subject-local review gap groups through the analysis path recorded by the verified checkpoint, then resolve the first evidence-backed group without inventing semantic decisions.',
  authorityDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd',
  command: "analysis_path=$(jq -er '.permutationClosure.universalFamilyModel.analysisPath' .work/programme/checkpoint.json) && jq -er '{verdict, gapCount, relationshipSignatureDispositionPartition, atomicCandidateCount, gapGroups:(.gaps | group_by(.code) | map({code:.[0].code,count:length}) | sort_by(-.count,.code))}' \"$analysis_path\"",
  preconditions: [
    'authority digest and authority packet/projection byte digests remain exact',
    'no authority mutation transaction or modifying worker is active',
    'foundation-domain closure assessment and independent proof remain current',
    'the current universal independent reconstruction has zero inventory, family, review, analysis, and source mismatches',
    'the relationship-review and candidate-projection focused and integrated local gates are current',
    'the local SHACL evidence evaluates every compatible registered constraint with zero violations and zero exclusions',
    'candidate reviews remain unpublished and cannot establish semantic truth',
  ],
  semanticIdentifiers: [
    'OPERATIONAL_PERMUTATION_AND_AUTHORISATION_CLOSURE',
    'UNIVERSAL_FAMILY_MODEL_REVIEW_CLOSURE',
  ],
} : {
  action: 'Read the changed GOAL.md completely, update this tracked checkpoint generator and any directive validators to the current dependency order, then regenerate the checkpoint before trusting any generated next action.',
  authorityDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd',
  command: 'node operations/programme/update-checkpoint.mjs',
  preconditions: [
    'the checked-out HEAD includes the latest GOAL.md from the programme remote',
  ],
  semanticIdentifiers: [
    'DIRECTIVE_AND_CHECKPOINT_RECONCILIATION',
  ],
};

const dependencyNodes = [
  { blockerCode: 'EXTERNAL_SIGNING_CREDENTIAL_REQUIRED', id: 'REALISATION_OPTION_EVALUATION_CLOSURE', prerequisites: [], state: 'EXTERNAL_OR_HUMAN_BLOCKED_KEY_ABSENT_USER_AUTHORISED_USE' },
  { blockerCode: 'STALE_OPTION_EVALUATION_EVIDENCE', id: 'CANONICAL_COMPILER_DEPENDENCY_CLOSURE', prerequisites: ['REALISATION_OPTION_EVALUATION_CLOSURE'], state: 'PARTIALLY_DELIVERED_REOPENED_EVIDENCE_BINDING' },
  { blockerCode: 'NONE', id: 'CANONICAL_COMPILER_ENTRYPOINT_CUTOVER', prerequisites: ['CANONICAL_COMPILER_DEPENDENCY_CLOSURE'], state: 'COMPLETE' },
  { blockerCode: 'NONE', id: 'DUPLICATE_COMPILER_RETIREMENT', prerequisites: ['CANONICAL_COMPILER_ENTRYPOINT_CUTOVER'], state: 'COMPLETE' },
  {
    blockerCode: directiveReconciled ? 'NONE' : 'DIRECTIVE_DIGEST_CHANGED',
    id: 'DIRECTIVE_AND_CHECKPOINT_RECONCILIATION',
    prerequisites: [],
    state: directiveReconciled ? 'COMPLETE' : 'REOPENED_GOAL_DIGEST_CHANGED',
  },
  {
    blockerCode: 'NONE',
    id: 'FOUNDATION_DOMAIN_CLOSURE',
    prerequisites: ['DIRECTIVE_AND_CHECKPOINT_RECONCILIATION'],
    state: directiveReconciled ? 'COMPLETE' : 'BLOCKED_BY_RECONCILIATION',
  },
  { blockerCode: 'LOCAL_SEMANTIC_REVIEW_AND_IMPLEMENTATION', id: 'UNIVERSAL_FAMILY_MODEL_REVIEW_CLOSURE', prerequisites: ['FOUNDATION_DOMAIN_CLOSURE'], state: directiveReconciled ? 'UNBLOCKED' : 'BLOCKED_BY_RECONCILIATION' },
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'CAPABILITY_CLASSIFICATION_AND_FOUNDATION_APPLICATION', prerequisites: ['UNIVERSAL_FAMILY_MODEL_REVIEW_CLOSURE'], state: 'BLOCKED_BY_UNIVERSAL_FAMILY_MODEL_REVIEW' },
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'SERVICE_FUNCTION_AND_OPERATION_CLOSURE', prerequisites: ['CAPABILITY_CLASSIFICATION_AND_FOUNDATION_APPLICATION'], state: 'BLOCKED_BY_CAPABILITY_CLASSIFICATION' },
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'IDENTITY_RESOURCE_AUTHORISATION_CLOSURE', prerequisites: ['SERVICE_FUNCTION_AND_OPERATION_CLOSURE'], state: 'BLOCKED_BY_SERVICE_FUNCTION_CLOSURE' },
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'DATA_VERSION_LIFECYCLE_AND_INTERACTION_CLOSURE', prerequisites: ['IDENTITY_RESOURCE_AUTHORISATION_CLOSURE'], state: 'BLOCKED_BY_IDENTITY_RESOURCE_CLOSURE' },
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'SERVICE_REQUIREMENT_AND_PRODUCTION_PROFILE_CLOSURE', prerequisites: ['DATA_VERSION_LIFECYCLE_AND_INTERACTION_CLOSURE'], state: 'BLOCKED_BY_CAPABILITY_SEMANTICS' },
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'CAPABILITY_PERMUTATION_CLOSURE', prerequisites: ['SERVICE_REQUIREMENT_AND_PRODUCTION_PROFILE_CLOSURE'], state: 'BLOCKED_BY_CAPABILITY_SEMANTICS' },
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'OPERATIONAL_PERMISSION_AND_TOKEN_CLOSURE', prerequisites: ['CAPABILITY_PERMUTATION_CLOSURE'], state: 'BLOCKED_BY_CAPABILITY_PERMUTATION_CLOSURE' },
  { blockerCode: 'LOCAL_VALIDATION_THEN_AUTHORITY_PUBLICATION_REQUIRED', id: 'CAPABILITY_EVIDENCE_PROOF_AND_PUBLICATION_CLOSURE', prerequisites: ['OPERATIONAL_PERMISSION_AND_TOKEN_CLOSURE'], state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { blockerCode: 'LOCAL_PROOF_REFRESH', id: 'COMPILER_GENERATOR_AND_PROOF_REFRESH', prerequisites: ['CAPABILITY_EVIDENCE_PROOF_AND_PUBLICATION_CLOSURE'], state: 'BLOCKED_BY_CAPABILITY_PROOF_CLOSURE' },
  { blockerCode: 'LOCAL_IMPLEMENTATION', id: 'EXECUTABLE_ENVIRONMENT_DELIVERY', prerequisites: ['COMPILER_GENERATOR_AND_PROOF_REFRESH'], state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { blockerCode: 'LOCAL_VALIDATION', id: 'BIDIRECTIONAL_TRACEABILITY_CLOSURE', prerequisites: ['EXECUTABLE_ENVIRONMENT_DELIVERY'], state: 'BLOCKED_BY_DELIVERY' },
  { blockerCode: 'LOCAL_VALIDATION_THEN_AUTHORITY_PUBLICATION_REQUIRED', id: 'FINAL_HERMETIC_SYSTEM_GATES', prerequisites: ['BIDIRECTIONAL_TRACEABILITY_CLOSURE'], state: 'BLOCKED_BY_DELIVERY' },
];

const currentItem = directiveReconciled
  ? { id: 'UNIVERSAL_FAMILY_MODEL_REVIEW_CLOSURE', state: 'UNBLOCKED' }
  : { id: 'DIRECTIVE_AND_CHECKPOINT_RECONCILIATION', state: 'REOPENED_GOAL_DIGEST_CHANGED' };
const currentPhase = 'OPERATIONAL_PERMUTATION_AND_AUTHORISATION_CLOSURE';

const stateClassifications = {
  EXTERNAL_OR_HUMAN_BLOCKED: ['REALISATION_OPTION_EVALUATION_EVIDENCE_SIGNING_KEY'],
  PARTIALLY_DELIVERED: ['COMPILER_PROOF_PREVIOUS_IMPLEMENTATION_BINDING', 'HERMETIC_EXECUTABLE_SUITE'],
  REMAINING_ACTIONABLE: dependencyNodes.filter(({ state }) => state !== 'COMPLETE'
    && !state.startsWith('EXTERNAL_OR_HUMAN_BLOCKED')).map(({ id }) => id),
  REOPENED_BY_DIRECTIVE: [
    'OPERATION_UNIVERSE_SEMANTIC_ADEQUACY',
    'PERMISSION_AND_TOKEN_SCOPE_CLOSURE',
    'OPERATION_CATALOGUE_COMPLETENESS',
  ],
  SUPERSEDED_OR_INVALIDATED: ['REJECTED_EXECUTABLE_REALISATION', 'STALE_MIXED_SCOPE_COMPILER_PROOF', 'REFERENCE_OR_HISTORICAL_SOURCE_COMPLETION'],
  VERIFIED_CURRENT: ['SEMANTIC_ADEQUACY_AND_CONTAMINATION_WITHIN_UNCHANGED_DEPENDENCY_SCOPE', 'DELIVERABLE_AND_LAYOUT_AUTHORITY', 'MILESTONE_GIT_PUBLICATION', 'CANONICAL_COMPILER_SOLE_PATH', 'FOUNDATION_DOMAIN_CLOSURE', 'UNIVERSAL_SEMANTIC_GAP_RECONSTRUCTION'],
};

const gateSummary = [
  { id: 'DIRECTIVE_AND_CHECKPOINT_RECONCILIATION', state: directiveReconciled ? 'VERIFIED_CURRENT' : 'REOPENED_GOAL_DIGEST_CHANGED' },
  { id: 'SEMANTIC_ADEQUACY', state: 'VERIFIED_CURRENT_EXCEPT_REOPENED_OPERATION_UNIVERSE_SCOPE' },
  { id: 'DELIVERABLE_AND_LAYOUT_AUTHORITY', state: 'VERIFIED_CURRENT' },
  { id: 'REALISATION_OPTION_EVALUATION_CLOSURE', state: 'PARTIALLY_DELIVERED_RAW_ACQUISITION_CURRENT_SIGNED_EVIDENCE_PENDING' },
  { id: 'FOUNDATION_DOMAIN_CLOSURE', state: 'VERIFIED_CURRENT_LOCAL_CANDIDATE' },
  { id: 'UNIVERSAL_FAMILY_MODEL_REVIEW_CLOSURE', state: 'REMAINING_ACTIONABLE' },
  { id: 'CAPABILITY_SEMANTIC_APPLICATION_AND_CLASSIFICATION', state: 'BLOCKED_BY_UNIVERSAL_FAMILY_MODEL_REVIEW' },
  { id: 'SERVICE_FUNCTION_IDENTITY_RESOURCE_DATA_AND_INTERACTION_CLOSURE', state: 'BLOCKED_BY_CAPABILITY_SEMANTIC_APPLICATION' },
  { id: 'SERVICE_REQUIREMENT_AND_PRODUCTION_PROFILE_CLOSURE', state: 'BLOCKED_BY_CAPABILITY_SEMANTICS' },
  { id: 'CAPABILITY_PERMUTATION_CLOSURE', state: 'BLOCKED_BY_CAPABILITY_SEMANTICS' },
  { id: 'COMPILER_PROOF_ADMISSION', state: 'PARTIALLY_DELIVERED_REOPENED_IMPLEMENTATION_BINDING' },
  { id: 'CANONICAL_COMPILER_SOLE_PATH', state: 'VERIFIED_CURRENT' },
  { id: 'EXECUTABLE_ENVIRONMENTS', state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { id: 'FINAL_HERMETIC_CLOSURE', state: 'REMAINING_ACTIONABLE' },
];

const permutationClosure = {
  foundationDomain: {
    assessmentDigest: foundationAssessmentRecord.assessmentDigest,
    assessmentFileDigest: currentWaveArtifacts.foundationAssessment.fileDigest,
    assessmentPath: currentWaveArtifacts.foundationAssessment.path,
    dimensionBindingOccurrenceCount: foundationAssessmentRecord.dimensionBindingOccurrenceCount,
    emptyDomainCount: foundationProofRecord.results.emptyDomainCount,
    familyCount: foundationAssessmentRecord.familyCount,
    fixtureCombinationCount: foundationAssessmentRecord.totalCombinationCount,
    proofDigest: foundationProofRecord.proofDigest,
    proofFileDigest: currentWaveArtifacts.foundationProof.fileDigest,
    proofPath: currentWaveArtifacts.foundationProof.path,
    proofReconstructionMismatchCount: foundationProofRecord.results.reconstructionMismatchCount,
    proofVerdict: foundationProofRecord.verdict,
    uniqueDimensionCount: foundationAssessmentRecord.uniqueDimensionCount,
    verdict: foundationAssessmentRecord.foundationVerdict,
  },
  supersededProjectionBindings: {
    familyCount34: 'SUPERSEDED',
    familyReviewCount2176: 'SUPERSEDED',
    candidateUniverseCount9899563: 'SUPERSEDED',
    segmentCount990: 'SUPERSEDED',
    finiteDomainGapCount371: 'SUPERSEDED',
  },
  universalFamilyModel: {
    analysisDigest: universalAnalysisRecord.analysisDigest,
    analysisFileDigest: currentWaveArtifacts.universalAnalysis.fileDigest,
    analysisPath: currentWaveArtifacts.universalAnalysis.path,
    atomicCandidateCount: universalAnalysisRecord.atomicCandidateCount,
    atomicCandidateProjectionCurrentCount: universalAnalysisRecord.atomicCandidateProjection.currentCount,
    atomicCandidateProjectionDuplicateCount: universalAnalysisRecord.atomicCandidateProjection.duplicateCount,
    atomicCandidateProjectionMissingCount: universalAnalysisRecord.atomicCandidateProjection.missingCount,
    atomicCandidateProjectionOrphanCount: universalAnalysisRecord.atomicCandidateProjection.orphanCount,
    atomicCandidateProjectionStaleOrInvalidCount: universalAnalysisRecord.atomicCandidateProjection.staleOrInvalidCount,
    atomicEndpointAmbiguityCount: universalProofRecord.results.atomicEndpointAmbiguityCount,
    authorityReviewRequiredTermCount: universalProofRecord.results.unresolvedSemanticTermCount,
    classCount: universalInventoryRecord.classCount,
    familyCount: universalRegistryRecord.familyCount,
    gapCount: universalAnalysisRecord.gapCount,
    independentProofDigest: universalProofRecord.proofDigest,
    independentProofFileDigest: currentWaveArtifacts.universalProof.fileDigest,
    independentProofPath: currentWaveArtifacts.universalProof.path,
    independentProofReconstructionMismatchCount: universalReconstructionMismatchCount,
    independentProofVerdict: universalProofRecord.verdict,
    individualCount: universalInventoryRecord.individualCount,
    inventoryDigest: universalInventoryRecord.inventoryDigest,
    inventoryFileDigest: currentWaveArtifacts.universalInventory.fileDigest,
    inventoryPath: currentWaveArtifacts.universalInventory.path,
    missingFamilyReviewCount: universalAnalysisRecord.registeredFamilyModelReview.missingReviewCount,
    projectedFamilyCandidateCount: universalReviewProjectionRecord.familyCandidateCount,
    projectedRelationshipSignatureReviewCount: universalReviewProjectionRecord.relationshipSignatureReviewCount,
    propertyCount: universalInventoryRecord.propertyCount,
    registryDigest: universalRegistryRecord.registryDigest,
    registryFileDigest: currentWaveArtifacts.universalRegistry.fileDigest,
    registryPath: currentWaveArtifacts.universalRegistry.path,
    relationshipCategoryCount: universalInventoryRecord.relationshipCategoryCount,
    relationshipSignatureCount: universalInventoryRecord.relationshipSignatureCount,
    relationshipSignatureDispositionPartition: universalAnalysisRecord.relationshipSignatureDispositionPartition,
    relationshipSignatureReviewCurrentCount: universalProofRecord.results.relationshipSignatureReviewCurrentCount,
    relationshipSignatureReviewDuplicateCount: universalProofRecord.results.relationshipSignatureReviewDuplicateCount,
    relationshipSignatureReviewMissingCount: universalProofRecord.results.relationshipSignatureReviewMissingCount,
    relationshipSignatureReviewOrphanCount: universalProofRecord.results.relationshipSignatureReviewOrphanCount,
    relationshipSignatureReviewStaleOrInvalidCount: universalProofRecord.results.relationshipSignatureReviewStaleOrInvalidCount,
    reviewProjectionDigest: universalReviewProjectionRecord.reviewProjectionDigest,
    reviewProjectionFileDigest: currentWaveArtifacts.universalReviewProjection.fileDigest,
    reviewProjectionPath: currentWaveArtifacts.universalReviewProjection.path,
    semanticTermCount: universalInventoryRecord.termCount,
    termDispositionPartition: universalAnalysisRecord.termDispositionPartition,
    unresolvedRelationshipSignatureCount: universalProofRecord.results.unresolvedRelationshipSignatureCount,
    validatorDependencyUnresolvedTermCount: universalProofRecord.results.validatorDependencyUnresolvedTermCount,
    verdict: universalAnalysisRecord.verdict,
    witnessCount: universalAnalysisRecord.witnessCount,
    witnessIndexDigest: universalAnalysisRecord.witnessIndexDigest,
  },
  verdict: 'PERMUTATION_CLOSURE_INCOMPLETE',
  verdictKind: 'INTERMEDIATE_NEVER_OVERALL_TERMINAL',
};

requireEqual(universalProofRecord.familyCount, permutationClosure.universalFamilyModel.familyCount, 'universal proof family count');
requireEqual(universalProofRecord.gapCount, permutationClosure.universalFamilyModel.gapCount, 'universal proof gap count');
requireEqual(universalProofRecord.results.atomicCandidateProjectionMissingCount, permutationClosure.universalFamilyModel.atomicCandidateProjectionMissingCount, 'universal proof missing atomic candidate count');
requireEqual(universalProofRecord.results.relationshipSignatureReviewMissingCount, permutationClosure.universalFamilyModel.relationshipSignatureReviewMissingCount, 'universal proof missing relationship review count');
requireEqual(universalProofRecord.candidateVerdict, permutationClosure.universalFamilyModel.verdict, 'universal proof candidate verdict');

const currentWaveArtifactBindings = [
  { fileDigest: permutationClosure.foundationDomain.assessmentFileDigest, internalDigest: permutationClosure.foundationDomain.assessmentDigest, internalField: 'assessmentDigest', path: permutationClosure.foundationDomain.assessmentPath },
  { fileDigest: permutationClosure.foundationDomain.proofFileDigest, internalDigest: permutationClosure.foundationDomain.proofDigest, internalField: 'proofDigest', path: permutationClosure.foundationDomain.proofPath },
  { fileDigest: permutationClosure.universalFamilyModel.inventoryFileDigest, internalDigest: permutationClosure.universalFamilyModel.inventoryDigest, internalField: 'inventoryDigest', path: permutationClosure.universalFamilyModel.inventoryPath },
  { fileDigest: permutationClosure.universalFamilyModel.registryFileDigest, internalDigest: permutationClosure.universalFamilyModel.registryDigest, internalField: 'registryDigest', path: permutationClosure.universalFamilyModel.registryPath },
  { fileDigest: permutationClosure.universalFamilyModel.reviewProjectionFileDigest, internalDigest: permutationClosure.universalFamilyModel.reviewProjectionDigest, internalField: 'reviewProjectionDigest', path: permutationClosure.universalFamilyModel.reviewProjectionPath },
  { fileDigest: permutationClosure.universalFamilyModel.analysisFileDigest, internalDigest: permutationClosure.universalFamilyModel.analysisDigest, internalField: 'analysisDigest', path: permutationClosure.universalFamilyModel.analysisPath },
  { fileDigest: permutationClosure.universalFamilyModel.independentProofFileDigest, internalDigest: permutationClosure.universalFamilyModel.independentProofDigest, internalField: 'proofDigest', path: permutationClosure.universalFamilyModel.independentProofPath },
  { fileDigest: currentWaveArtifacts.localShaclEvidence.fileDigest, internalDigest: localShaclEvidenceRecord.evidenceDigest, internalField: 'evidenceDigest', path: currentWaveArtifacts.localShaclEvidence.path },
  { fileDigest: 'sha256:2b557090632299e1b28feef07f4f770cdd1b9229019a4586824cc06a9fdb4739', internalDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd', internalField: 'authorityDigest', path: '.work/generated/permutation-authority-packet-2b557090632299e1b28feef07f4f770cdd1b9229019a4586824cc06a9fdb4739.json' },
  { fileDigest: 'sha256:886abdaedb6bb18f82bb90a218a525d64bd1027b999f49f0dc11e001df4e1c16', internalDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd', internalField: 'authorityDigest', path: '.work/generated/permutation-authority-projection-886abdaedb6bb18f82bb90a218a525d64bd1027b999f49f0dc11e001df4e1c16.json' },
];
for (const binding of currentWaveArtifactBindings) {
  const observedFileDigest = digestWorkingPath(binding.path);
  if (observedFileDigest !== binding.fileDigest) throw new Error(`current wave artefact byte digest mismatch: ${binding.path}`);
  const record = JSON.parse(readFileSync(join(repositoryRoot, binding.path), 'utf8'));
  if (record[binding.internalField] !== binding.internalDigest) throw new Error(`current wave artefact internal digest mismatch: ${binding.path}:${binding.internalField}`);
}
const authorityProjectionRecord = JSON.parse(readFileSync(join(repositoryRoot, '.work/generated/permutation-authority-projection-886abdaedb6bb18f82bb90a218a525d64bd1027b999f49f0dc11e001df4e1c16.json'), 'utf8'));
if (authorityProjectionRecord.basePacketDigest !== 'sha256:2b557090632299e1b28feef07f4f770cdd1b9229019a4586824cc06a9fdb4739') {
  throw new Error('current authority projection does not bind the verified authority packet');
}

const dependencyReviewPath = join(stateRoot, 'compiler-cutover-dependency-review.json');
const dependencyReviewDigest = existsSync(dependencyReviewPath) ? sha256(readFileSync(dependencyReviewPath)) : null;
if (dependencyReviewDigest) {
  atomicWrite(
    `${dependencyReviewPath}.sha256`,
    Buffer.from(`${dependencyReviewDigest.slice(7)}  compiler-cutover-dependency-review.json\n`),
  );
}
const observedProcesses = repositoryProcesses();

const changedPathsRecord = {
  baseCommit: head,
  changedPathCount: changes.length,
  changes,
  head,
  recordKind: 'USF_WORKING_TREE_CHANGED_PATHS',
  schemaVersion: 1,
};
const changedPathsDigest = atomicWrite(join(stateRoot, 'changed-paths.json'), canonicalBytes(changedPathsRecord));

const ledger = {
  authority: {
    currentDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd',
    inputPacketDigest: 'sha256:2b557090632299e1b28feef07f4f770cdd1b9229019a4586824cc06a9fdb4739',
    inputProjectionDigest: 'sha256:886abdaedb6bb18f82bb90a218a525d64bd1027b999f49f0dc11e001df4e1c16',
    localCandidateState: 'UNPUBLISHED_NOT_SEMANTIC_AUTHORITY',
    sourceLiveDrift: 'NOT_ASSERTED_FOR_UNPUBLISHED_CANDIDATE',
    tripleCount: 86536,
  },
  completedBoundaries: [
    'REJECTED_REALISATION_REMOVED_AND_INVALIDATED',
    'LEGACY_CONTAMINATION_REVIEW_ACCEPTED_6458_ITEMS',
    'DELIVERABLE_INVENTORY_ACCEPTED_452_ITEMS',
    'FOUNDATIONAL_LAYOUT_MATERIALISED',
    'REPOSITORY_MATERIALISATION_CONTRACT_PROVEN',
    'COMPILER_PROOF_SCOPES_SEPARATED_AND_ADMITTED',
    'COMPILER_CONTRACT_ACTIVE_REALISATION_IMPLEMENTABLE',
    'MILESTONE_COMMITTED_AND_PUSHED',
    'FOUNDATION_DOMAIN_CLOSURE_COMPLETE',
    'UNIVERSAL_SEMANTIC_GAP_RECONSTRUCTION_PASS',
  ],
  dependencyNodes,
  gateSummary,
  currentItem,
  currentPhase,
  permutationClosure,
  goalDigest,
  git: {
    branch: gitText(['branch', '--show-current']),
    head,
    pushedCommitMatchesUpstream: head === upstream,
    upstream,
  },
  nextDependencyNodes: dependencyNodes.filter(({ state }) => state === 'UNBLOCKED' || state === 'PARTIALLY_UNBLOCKED').map(({ id }) => id),
  nextExactAction,
  realisationOptionEvaluation: {
    acquisition: optionAcquisition,
    evidenceSigningKey: {
      operatorAuthorisation: 'CURRENT_USER_AUTHORISED_USE_WHEN_KEY_AVAILABLE',
      path: '.work/programme/realisation-option-evaluation-signing-key.pk8',
      state: 'ABSENT_OPERATOR_SUPPLIED_SECRET_REQUIRED',
    },
  },
  recordKind: 'USF_PROGRAMME_LEDGER',
  recordedAt,
  schemaVersion: 2,
  stateClassifications,
  userReportedExecutionMetric: {
    sessions: 1,
    source: 'USER_REPORTED_NOT_SYSTEM_VERIFIED',
    tokens: 500000000,
  },
};
const ledgerDigest = atomicWrite(join(stateRoot, 'programme-ledger.json'), canonicalBytes(ledger));
const statusRecheckBytes = gitBuffer(['status', '--porcelain=v1', '-z']);
const statusStableBeforeCheckpoint = statusBytes.equals(statusRecheckBytes);
if (!statusStableBeforeCheckpoint) {
  throw new Error('working tree changed while programme state was being reconciled');
}

const checkpoint = {
  activeWorkPackets: [],
  authority: {
    currentDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd',
    inputPacket: {
      digest: 'sha256:2b557090632299e1b28feef07f4f770cdd1b9229019a4586824cc06a9fdb4739',
      path: '.work/generated/permutation-authority-packet-2b557090632299e1b28feef07f4f770cdd1b9229019a4586824cc06a9fdb4739.json',
    },
    inputProjection: {
      digest: 'sha256:886abdaedb6bb18f82bb90a218a525d64bd1027b999f49f0dc11e001df4e1c16',
      path: '.work/generated/permutation-authority-projection-886abdaedb6bb18f82bb90a218a525d64bd1027b999f49f0dc11e001df4e1c16.json',
      scope: 'BOUNDED_USF_MCP_SELECT_NOT_FULL_TERM_PARITY',
    },
    localCandidateState: 'UNPUBLISHED_NOT_SEMANTIC_AUTHORITY',
    sourceLiveDrift: 'NOT_ASSERTED_FOR_UNPUBLISHED_CANDIDATE',
    tripleCount: 86536,
  },
  cas: {
    descriptors: [
      { byteSize: 221897, digest: 'sha256:ac5490b46604ca6eb25d739248eb9fb6a188dd7d587edf6215c61b1a593f787c', kind: 'HERMETIC_EVIDENCE_MANIFEST', mediaType: 'application/json', state: 'VERIFIED_ADMITTED' },
      { byteSize: 2138, digest: 'sha256:164c0f372063fe1b0addd39127a5380bcf15e3db5014283a9a62a671f41aff55', kind: 'LIVE_AUTHORITY_CONTROL_EVIDENCE_MANIFEST', mediaType: 'application/json', state: 'VERIFIED_ADMITTED' },
      { byteSize: 1236, digest: 'sha256:02282b4d1a1b06a4b95e5c78b5bcb62e08e87789c4a471f800f76e249f811905', kind: 'HERMETIC_EVIDENCE_ATTESTATION', mediaType: 'application/vnd.in-toto+json', state: 'VERIFIED_ADMITTED' },
      { byteSize: 1244, digest: 'sha256:40ed3c107149dde345f075d98d08c7afd4d206c77fef60b53bdcf6a7f6e0282e', kind: 'LIVE_AUTHORITY_CONTROL_ATTESTATION', mediaType: 'application/vnd.in-toto+json', state: 'VERIFIED_ADMITTED' },
      { byteSize: 1516, digest: 'sha256:a7148e9b618f5dda16b588e45739742e0aa6ea0ae34dd5639daa41a6eed8224d', kind: 'COMPILER_PROOF_ATTESTATION', mediaType: 'application/vnd.in-toto+json', state: 'VERIFIED_ADMITTED' },
      { byteSize: 10802, digest: 'sha256:c976ca68a8656dba2aec13b703a44378997996e11cbfd52ad8382f50254be9cc', kind: 'STALE_MIXED_SCOPE_EVIDENCE', mediaType: 'application/json', state: 'INVALIDATED_HISTORICAL_ONLY' },
      { byteSize: 1168, digest: 'sha256:dac9ecbd1c3c20a35bb6e2008275a904baaf0d24ab2de9cd7de86ef0727a274f', kind: 'STALE_MIXED_SCOPE_ATTESTATION', mediaType: 'application/vnd.in-toto+json', state: 'INVALIDATED_HISTORICAL_ONLY' },
      { byteSize: optionAcquisition.byteSize, digest: optionAcquisition.acquisitionInputDigest, kind: 'REALISATION_OPTION_RAW_ACQUISITION', mediaType: 'application/json', state: optionAcquisition.state },
    ],
    root: '/var/lib/usf-cas',
  },
  changedPaths: {
    count: changes.length,
    digest: changedPathsDigest,
    path: '.work/programme/changed-paths.json',
  },
  checkoutObservation: {
    statusDigest: sha256(statusBytes),
    statusStableBeforeCheckpoint,
  },
  completedUnintegratedPackets: [],
  currentEnvironmentState: {
    development: 'NOT_DELIVERED',
    deterministicTest: 'NOT_DELIVERED',
    evidenceSigningKey: 'AUTHORISED_FOR_USE_BUT_SECRET_BYTES_ABSENT',
    productionShapedStaging: 'NOT_DELIVERED',
  },
  currentItem,
  git: {
    branch: gitText(['branch', '--show-current']),
    changedPathCountFromHead: changes.length,
    clean: statusBytes.length === 0,
    head,
    indexPatchDigest: sha256(stagedPatch),
    patchDigest: sha256(unstagedPatch),
    pushedCommitMatchesUpstream: head === upstream,
    remote: 'origin',
    stashDigest: sha256(gitBuffer(['stash', 'list'])),
    stashState: gitText(['stash', 'list']) || 'EMPTY',
    statusDigest: sha256(statusBytes),
    trackedFileCount: tracked.length,
    untrackedPaths,
    upstream,
    workingTreeDigest: sha256(canonicalBytes(tracked)),
    worktrees: gitText(['worktree', 'list', '--porcelain']),
  },
  goalDigest,
  gateSummary,
  inventories: {
    foundationDomain: permutationClosure.foundationDomain,
    universalSemanticCoverage: permutationClosure.universalFamilyModel,
    contamination: {
      independentReviewFileDigest: 'sha256:081b775881fac9c72fd0eb3bef6e7a8bdc23e2bbd009c6ad60d888dcdf4b7427',
      internalDigest: 'sha256:8008ce6eebb6f854543df7dbf4833eb8d067be11d80581bd3bab5f9e627f19e2',
      inventoryFileDigest: 'sha256:0bf10686bc1c93058091ab27c705ece083f9c2309bd00686bfb175d36bc07892',
      recordCount: 6458,
      state: 'ACCEPTED',
    },
    deliverable: {
      independentReviewDigest: 'sha256:953cf68731cde48b1246bd096edc2ea19faa72d8688ab07ae09fe01729d712c4',
      independentReviewFileDigest: 'sha256:496c669a90665ee292ad3f48a437affd65197b0b78e60d3be945af1b8dc5c860',
      internalDigest: 'sha256:de3b112fdb7fcad7fdcbc9ba3bf4d656b3b0551e7137b07d2971b2fab7ba13a4',
      inventoryFileDigest: 'sha256:b8146982fc99b9ff343cc5e6ed6fc097fe1578e33eda52720826999fb450b3cc',
      recordCount: 452,
      state: 'ACCEPTED_ALL_BOUNDARY_COUNTERS_ZERO',
      validatedCandidateDigest: 'sha256:b48ae957b826076187f97e07d0c39d351f984872436e947f85092ce82f7c09a2',
    },
  },
  materialisationPlans: [
    { digest: 'sha256:f2a1c37ab71ecee0136db640a45d89068e2ae4f52a8b80e311ccd2c1b28bb481', state: 'VALIDATED_AND_MATERIALISED', type: 'FOUNDATIONAL_LAYOUT' },
    { digest: 'sha256:b37a2e69bf3e2c9bd223566343f849eb0d8504988edcef54b48644b1217c0962', state: 'VALIDATED_AND_APPLIED', type: 'REJECTED_REALISATION_REMOVAL' },
    { digest: 'sha256:a18d85957abcd1c9abf9e888e5f750248fa729cdd821774c5466a0d19994c273', state: 'VALIDATED_AND_MATERIALISED', type: 'CANONICAL_COMPILER_UTILITY_CUTOVER' },
    { digest: 'sha256:0661bf511774f9c8d88ef7264000fedf7a14588947b32cbe360c629eabcd892a', state: 'VALIDATED_AND_MATERIALISED', type: 'LOCAL_SHACL_ASSURANCE_CONTAINMENT' },
  ],
  nextExactAction,
  ownedQueries: [],
  ownedTransactions: [],
  permutationClosure,
  phase: currentPhase,
  previousCheckpointDigest: priorCheckpointDigest,
  programmeLedger: {
    digest: ledgerDigest,
    path: '.work/programme/programme-ledger.json',
  },
  realisationOptionEvaluation: {
    acquisition: optionAcquisition,
    evidenceSigningKey: {
      operatorAuthorisation: 'CURRENT_USER_AUTHORISED_USE_WHEN_KEY_AVAILABLE',
      path: '.work/programme/realisation-option-evaluation-signing-key.pk8',
      state: 'ABSENT_OPERATOR_SUPPLIED_SECRET_REQUIRED',
    },
  },
  reopenedIdentifiers: [
    {
      cause: 'IMPLEMENTATION_SOURCE_CHANGED_BY_AUTHORITY_BOUND_CANONICAL_COMPILER_CUTOVER',
      changedPaths: [
        'assurance/semantic-model-compilation/local-shacl-dependencies.json',
        'assurance/semantic-model-compilation/local-shacl-validation.mjs',
        'assurance/semantic-model-compilation/local-shacl-validation.test.mjs',
        'processes/semantic-assurance/compiler-proof-command.mjs',
        'processes/semantic-assurance/compiler-proof-command.test.mjs',
        'processes/semantic-assurance/semantic-authority-gateway.mjs',
        'processes/semantic-assurance/semantic-authority-gateway.test.mjs',
      ],
      id: 'COMPILER_PROOF_ADMISSION',
      previousImplementationSourceDigest: 'sha256:05323e8c4b7e6b21d16e5e679c30cd80154b0bbb12907dcf05944b4cc2c00e4a',
      state: 'REOPENED_PENDING_COHERENT_LOCAL_CUTOVER_AND_PROOF_REFRESH',
    },
  ],
  runningProcesses: {
    mutationObserved: false,
    observed: observedProcesses,
    ownedAuthorityMutationProcessIds: [],
  },
  sidecars: [
    ...currentWaveArtifactBindings.map(({ fileDigest, path }) => ({
      digest: fileDigest,
      path,
      schema: 'DIGEST_BOUND_CURRENT_WAVE_ARTIFACT',
    })),
    ...(dependencyReviewDigest ? [{
      digest: dependencyReviewDigest,
      path: '.work/programme/compiler-cutover-dependency-review.json',
      schema: 'USF_COMPILER_CUTOVER_DEPENDENCY_REVIEW/v1',
    }] : []),
    {
      digest: changedPathsDigest,
      path: '.work/programme/changed-paths.json',
      schema: 'USF_WORKING_TREE_CHANGED_PATHS/v1',
    },
  ],
  proofState: {
    compiler: {
      state: 'ADMITTED_FOR_PREVIOUS_IMPLEMENTATION_BINDING_REOPENED_BY_CURRENT_LOCAL_SOURCE_CHANGE',
    },
    foundationDomain: {
      proofDigest: permutationClosure.foundationDomain.proofDigest,
      state: 'CURRENT_LOCAL_INDEPENDENT_PROOF_NOT_PUBLISHED',
      verdict: permutationClosure.foundationDomain.proofVerdict,
    },
    universalSemanticCoverage: {
      atomicCandidateProjectionMissingCount: permutationClosure.universalFamilyModel.atomicCandidateProjectionMissingCount,
      atomicEndpointAmbiguityCount: permutationClosure.universalFamilyModel.atomicEndpointAmbiguityCount,
      proofDigest: permutationClosure.universalFamilyModel.independentProofDigest,
      reconstructionMismatchCount: permutationClosure.universalFamilyModel.independentProofReconstructionMismatchCount,
      relationshipSignatureReviewMissingCount: permutationClosure.universalFamilyModel.relationshipSignatureReviewMissingCount,
      state: 'CURRENT_LOCAL_INDEPENDENT_RECONSTRUCTION_NOT_CLOSURE_PROOF',
      unresolvedFamilyReviewCount: universalProofRecord.results.unresolvedFamilyReviewCount,
      unresolvedAtomicCandidateCount: universalProofRecord.results.unresolvedAtomicCandidateCount,
      unresolvedRelationshipSignatureCount: universalProofRecord.results.unresolvedRelationshipSignatureCount,
      unresolvedSemanticTermCount: universalProofRecord.results.unresolvedSemanticTermCount,
      validatorDependencyUnresolvedTermCount: universalProofRecord.results.validatorDependencyUnresolvedTermCount,
      verdict: permutationClosure.universalFamilyModel.independentProofVerdict,
    },
  },
  publishedSemanticResources: [
    'urn:usf:evidenceresult:compilerhermeticsubstituteruntime',
    'urn:usf:evidenceresult:compilerhermeticsubstitutevalidation',
    'urn:usf:evidenceresult:compilerliveauthorityruntime',
    'urn:usf:evidenceresult:compilerliveauthoritytransactionvalidation',
    'urn:usf:proofresult:compilercontractbehaviour',
    'urn:usf:proofresult:compilerhermeticsubstitute',
    'urn:usf:proofresult:compilerliveauthoritycontrol',
    'urn:usf:realisationdecision:semanticmodelcompilationrealisation',
  ],
  publication: {
    currentWave: {
      allowed: false,
      authorityMutation: 'CLOSED_NONE_OWNED',
      mutationOutcomeAmbiguous: false,
      reason: 'UNIVERSAL_FAMILY_MODEL_INCOMPLETE',
      state: 'PROHIBITED_NOT_ATTEMPTED',
    },
    historicalCompilerPublication: {
      state: 'PRESERVED_HISTORICAL_BINDING_NOT_CURRENT_WAVE_AUTHORITY',
    },
  },
  recordKind: 'USF_RECOVERY_CHECKPOINT',
  recordedAt,
  schemaVersion: 2,
  stateClassifications,
  transactionState: {
    authorityMutation: 'CLOSED_NONE_OWNED',
    lastKnownPublicationOutcome: 'CURRENT_WAVE_NOT_ATTEMPTED',
    mutationOutcomeAmbiguous: false,
    queryOwnership: 'NONE_OWNED',
  },
  unresolvedFindings: dependencyNodes.filter(({ state }) => state !== 'COMPLETE')
    .map(({ blockerCode, id, state }) => ({ blockerCode, id, state })),
  userReportedExecutionMetric: {
    sessions: 1,
    source: 'USER_REPORTED_NOT_SYSTEM_VERIFIED',
    tokens: 500000000,
  },
  validation: {
    compilerSuite: { failed: 0, focusedPassed: 14, state: 'FOCUSED_CURRENT_FULL_INTEGRATED_GATE_PENDING' },
    localShacl: {
      actualServiceAlgebraNodes: localShaclEvidenceRecord.actualServiceAlgebraNodeCount,
      candidateViolations: localShaclEvidenceRecord.candidateViolationCount,
      evaluatedConstraints: localShaclEvidenceRecord.locallyEvaluatedConstraintCount,
      evidenceDigest: localShaclEvidenceRecord.evidenceDigest,
      evidenceFileDigest: currentWaveArtifacts.localShaclEvidence.fileDigest,
      evidencePath: currentWaveArtifacts.localShaclEvidence.path,
      harnessSourceDigest: localShaclEvidenceRecord.harnessSourceDigest,
      plantedFixtureEvidenceDigest: localShaclEvidenceRecord.plantedFixtureEvidenceDigest,
      plantedFixtures: {
        cases: localShaclEvidenceRecord.plantedFixtureEvidence.caseCount,
        missingCodes: localShaclEvidenceRecord.plantedFixtureEvidence.missingExpectedCount,
        multipleCodes: localShaclEvidenceRecord.plantedFixtureEvidence.multipleCodeCount,
        negative: localShaclEvidenceRecord.plantedFixtureEvidence.negativeControlCount,
        positive: localShaclEvidenceRecord.plantedFixtureEvidence.positiveControlCount,
        unexpectedCodes: localShaclEvidenceRecord.plantedFixtureEvidence.unexpectedCodeCount,
      },
      registeredConstraints: localShaclEvidenceRecord.registeredSparqlConstraintCount,
      substringExclusions: localShaclEvidenceRecord.substringBasedExclusionCount,
      unexpectedExclusions: localShaclEvidenceRecord.unexpectedExclusionCount,
    },
    narrowPermutationAndUniversal: {
      familyModelAndLocalShacl: { failed: 0, passed: 27 },
      relationshipReviewAndIndependentProof: { failed: 0, passed: 17 },
      state: 'CURRENT_FOCUSED_PASS',
    },
    integratedPermutationAndUniversal: {
      command: 'node --test assurance/permutation-closure/*.test.mjs assurance/semantic-model-compilation/local-shacl-validation.test.mjs',
      failed: 0,
      passed: 101,
      state: 'CURRENT_COHERENT_WAVE_PASS',
    },
    rootSuite: {
      discoveredFileCount: 19,
      inventoryDigest: 'sha256:5e74513d538d9a0e3d7dbd32cceb3e5c908eaf9a4535a989f4e4a7897d15c72a',
      reasonCodes: [
        'DEPENDENCY_SET_DIGEST_MISMATCH',
        'DETERMINISTIC_EVALUATION_SCOPE_INVALID',
        'IMPLEMENTATION_SOURCE_DIGEST_MISMATCH',
        'REPOSITORY_SECURITY_SCAN_INVALID',
        'SOURCE_RECORD_DRIFT',
      ],
      state: 'STALE_RELATIONSHIP_REVIEW_CANDIDATE_SOURCE_WAVE_REQUIRES_FINAL_SOURCE_FREEZE',
    },
    semanticCheck: { state: 'CURRENT_LOCAL_SHACL_AND_INTEGRATED_WAVE_PASS' },
    sourceLiveDrift: 'NOT_ASSERTED_FOR_UNPUBLISHED_CANDIDATE',
  },
};

const checkpointDigest = atomicWrite(checkpointPath, canonicalBytes(checkpoint));
atomicWrite(join(stateRoot, 'changed-paths.json.sha256'), Buffer.from(`${changedPathsDigest.slice(7)}  changed-paths.json\n`));
atomicWrite(join(stateRoot, 'programme-ledger.json.sha256'), Buffer.from(`${ledgerDigest.slice(7)}  programme-ledger.json\n`));
atomicWrite(join(stateRoot, 'checkpoint.json.sha256'), Buffer.from(`${checkpointDigest.slice(7)}  checkpoint.json\n`));

process.stdout.write(`${JSON.stringify({
  changedPathCount: changes.length,
  changedPathsDigest,
  checkpointDigest,
  clean: statusBytes.length === 0,
  goalDigest,
  head,
  ledgerDigest,
  pushedCommitMatchesUpstream: head === upstream,
})}\n`);
