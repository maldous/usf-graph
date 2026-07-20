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
const reconciledGoalDigest = 'sha256:3e6aaebdb730dbed3a6506bb53bbf008c96a00acfd41a7445beb2e8a74c4b2e3';
const directiveReconciled = goalDigest === reconciledGoalDigest;

const nextExactAction = directiveReconciled ? {
  action: 'Run the one pending integrated local permutation and universal-semantic wave gate against the committed candidate before regenerating stale option-evaluation evidence or entering family-model review closure.',
  authorityDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd',
  command: 'node --test assurance/permutation-closure/family-census.test.mjs assurance/permutation-closure/family-model.test.mjs assurance/permutation-closure/foundation-domain-closure.test.mjs assurance/permutation-closure/universal-semantic-coverage.test.mjs assurance/permutation-closure/universe-generator.test.mjs assurance/semantic-model-compilation/compiler-proof.test.mjs assurance/semantic-model-compilation/local-shacl-validation.test.mjs',
  preconditions: [
    'authority digest and authority packet/projection byte digests remain exact',
    'no authority mutation transaction or modifying worker is active',
    'foundation-domain closure assessment and independent proof remain current',
    'narrow family-census and universal-semantic gates remain current at 15/15 and 9/9',
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
  { blockerCode: 'NONE', id: 'REALISATION_OPTION_EVALUATION_CLOSURE', prerequisites: [], state: 'COMPLETE' },
  { blockerCode: 'NONE', id: 'CANONICAL_COMPILER_DEPENDENCY_CLOSURE', prerequisites: ['REALISATION_OPTION_EVALUATION_CLOSURE'], state: 'COMPLETE' },
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
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'CAPABILITY_PERMUTATION_CLOSURE', prerequisites: ['UNIVERSAL_FAMILY_MODEL_REVIEW_CLOSURE'], state: 'BLOCKED_BY_UNIVERSAL_FAMILY_MODEL_REVIEW' },
  { blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION', id: 'OPERATIONAL_PERMISSION_AND_TOKEN_CLOSURE', prerequisites: ['CAPABILITY_PERMUTATION_CLOSURE'], state: 'BLOCKED_BY_CAPABILITY_PERMUTATION_CLOSURE' },
  { blockerCode: 'LOCAL_PROOF_REFRESH', id: 'COMPILER_GENERATOR_AND_PROOF_REFRESH', prerequisites: ['OPERATIONAL_PERMISSION_AND_TOKEN_CLOSURE'], state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { blockerCode: 'LOCAL_IMPLEMENTATION', id: 'EXECUTABLE_ENVIRONMENT_DELIVERY', prerequisites: ['COMPILER_GENERATOR_AND_PROOF_REFRESH'], state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { blockerCode: 'LOCAL_VALIDATION', id: 'BIDIRECTIONAL_TRACEABILITY_CLOSURE', prerequisites: ['EXECUTABLE_ENVIRONMENT_DELIVERY'], state: 'BLOCKED_BY_DELIVERY' },
  { blockerCode: 'LOCAL_VALIDATION_THEN_AUTHORITY_PUBLICATION_REQUIRED', id: 'FINAL_HERMETIC_SYSTEM_GATES', prerequisites: ['BIDIRECTIONAL_TRACEABILITY_CLOSURE'], state: 'BLOCKED_BY_DELIVERY' },
];

const currentItem = directiveReconciled
  ? { id: 'UNIVERSAL_FAMILY_MODEL_REVIEW_CLOSURE', state: 'UNBLOCKED' }
  : { id: 'DIRECTIVE_AND_CHECKPOINT_RECONCILIATION', state: 'REOPENED_GOAL_DIGEST_CHANGED' };
const currentPhase = 'OPERATIONAL_PERMUTATION_AND_AUTHORISATION_CLOSURE';

const stateClassifications = {
  EXTERNAL_OR_HUMAN_BLOCKED: [],
  PARTIALLY_DELIVERED: ['COMPILER_PROOF_PREVIOUS_IMPLEMENTATION_BINDING', 'HERMETIC_EXECUTABLE_SUITE'],
  REMAINING_ACTIONABLE: dependencyNodes.filter(({ state }) => state !== 'COMPLETE').map(({ id }) => id),
  REOPENED_BY_DIRECTIVE: [
    'OPERATION_UNIVERSE_SEMANTIC_ADEQUACY',
    'PERMISSION_AND_TOKEN_SCOPE_CLOSURE',
    'OPERATION_CATALOGUE_COMPLETENESS',
  ],
  SUPERSEDED_OR_INVALIDATED: ['REJECTED_EXECUTABLE_REALISATION', 'STALE_MIXED_SCOPE_COMPILER_PROOF', 'REFERENCE_OR_HISTORICAL_SOURCE_COMPLETION'],
  VERIFIED_CURRENT: ['SEMANTIC_ADEQUACY_AND_CONTAMINATION_WITHIN_UNCHANGED_DEPENDENCY_SCOPE', 'DELIVERABLE_AND_LAYOUT_AUTHORITY', 'MILESTONE_GIT_PUBLICATION', 'REALISATION_OPTION_EVALUATION_CLOSURE', 'CANONICAL_COMPILER_SOLE_PATH', 'FOUNDATION_DOMAIN_CLOSURE', 'UNIVERSAL_SEMANTIC_GAP_RECONSTRUCTION'],
};

const gateSummary = [
  { id: 'DIRECTIVE_AND_CHECKPOINT_RECONCILIATION', state: directiveReconciled ? 'VERIFIED_CURRENT' : 'REOPENED_GOAL_DIGEST_CHANGED' },
  { id: 'SEMANTIC_ADEQUACY', state: 'VERIFIED_CURRENT_EXCEPT_REOPENED_OPERATION_UNIVERSE_SCOPE' },
  { id: 'DELIVERABLE_AND_LAYOUT_AUTHORITY', state: 'VERIFIED_CURRENT' },
  { id: 'REALISATION_OPTION_EVALUATION_CLOSURE', state: 'VERIFIED_CURRENT' },
  { id: 'FOUNDATION_DOMAIN_CLOSURE', state: 'VERIFIED_CURRENT_LOCAL_CANDIDATE' },
  { id: 'UNIVERSAL_FAMILY_MODEL_REVIEW_CLOSURE', state: 'REMAINING_ACTIONABLE' },
  { id: 'CAPABILITY_PERMUTATION_CLOSURE', state: 'BLOCKED_BY_UNIVERSAL_FAMILY_MODEL_REVIEW' },
  { id: 'COMPILER_PROOF_ADMISSION', state: 'PARTIALLY_DELIVERED_REOPENED_IMPLEMENTATION_BINDING' },
  { id: 'CANONICAL_COMPILER_SOLE_PATH', state: 'VERIFIED_CURRENT' },
  { id: 'EXECUTABLE_ENVIRONMENTS', state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { id: 'FINAL_HERMETIC_CLOSURE', state: 'REMAINING_ACTIONABLE' },
];

const permutationClosure = {
  foundationDomain: {
    assessmentDigest: 'sha256:9261fccdbf0f4e4a70338ea3167e0ed968be8c67780915e7d2ce92724a40def0',
    assessmentFileDigest: 'sha256:0088a03a961ef6f4b2a35f32e18b27367bbdab21cb1aac8c9fe7882c11c9bdc9',
    assessmentPath: '.work/generated/foundation-domain-closure-assessment-0088a03a961ef6f4b2a35f32e18b27367bbdab21cb1aac8c9fe7882c11c9bdc9.json',
    dimensionBindingOccurrenceCount: 304,
    emptyDomainCount: 0,
    familyCount: 108,
    fixtureCombinationCount: 80911,
    proofDigest: 'sha256:3af4cb5a377a6001207d5bf9495f8bc0cd0decf1b8744898f064166bd0330df9',
    proofFileDigest: 'sha256:743677482dbca73d9538b3a07d4e51aa440b4d277993c80bc59195422046ff3a',
    proofPath: '.work/generated/foundation-domain-closure-proof-743677482dbca73d9538b3a07d4e51aa440b4d277993c80bc59195422046ff3a.json',
    proofVerdict: 'FOUNDATION_DOMAIN_CLOSURE_PROOF_PASS',
    uniqueDimensionCount: 245,
    verdict: 'FOUNDATION_DOMAIN_CLOSURE_COMPLETE',
  },
  supersededProjectionBindings: {
    familyCount34: 'SUPERSEDED',
    familyReviewCount2176: 'SUPERSEDED',
    candidateUniverseCount9899563: 'SUPERSEDED',
    segmentCount990: 'SUPERSEDED',
    finiteDomainGapCount371: 'SUPERSEDED',
  },
  universalFamilyModel: {
    analysisDigest: 'sha256:73d21ad9c5be29fd9419bf5728a7162136e1695b4329ea24949caff9ed35455a',
    analysisFileDigest: 'sha256:dc6ba08e7e4146e7ae88485bbdb93e2f51a19f4a89a07c3249250cf6845acb42',
    analysisPath: '.work/generated/universal-family-completeness-analysis-dc6ba08e7e4146e7ae88485bbdb93e2f51a19f4a89a07c3249250cf6845acb42.json',
    atomicCandidateCount: 1555,
    authorityReviewRequiredTermCount: 8519,
    familyCount: 108,
    gapCount: 29424,
    independentProofDigest: 'sha256:c697729ba1561c5625bf05961a701fc9dc7815c6abdc925ae536e5ae402eab5a',
    independentProofFileDigest: 'sha256:8f19e116af820aebe20205eda5323687dc6cde355ea3621d76987c7d0c462601',
    independentProofPath: '.work/generated/universal-semantic-coverage-proof-8f19e116af820aebe20205eda5323687dc6cde355ea3621d76987c7d0c462601.json',
    independentProofVerdict: 'UNIVERSAL_SEMANTIC_GAP_AND_CROSS_PRODUCT_RECONSTRUCTION_PASS',
    inventoryDigest: 'sha256:502165e6a717d859ffa981903b6b712f782041885f3dfdcf6ae18d7dd358068d',
    inventoryFileDigest: 'sha256:e6bf9c5b8459eaa863b4048165291aa1c43d3b0bbf79aa0399bd2375d553040c',
    inventoryPath: '.work/generated/universal-semantic-inventory-e6bf9c5b8459eaa863b4048165291aa1c43d3b0bbf79aa0399bd2375d553040c.json',
    missingFamilyReviewCount: 108,
    registryDigest: 'sha256:a33f4aa299d5a988ee8ac264e33e448532d429b2af5dd0996620c096689d612b',
    registryFileDigest: 'sha256:c6550a6355a56687d1854eaf18ac002d951b43fc8a8155df831a3cd05d0471df',
    registryPath: '.work/generated/universal-family-registry-c6550a6355a56687d1854eaf18ac002d951b43fc8a8155df831a3cd05d0471df.json',
    relationshipSignatureReviewRequiredCount: 2025,
    reviewProjectionDigest: 'sha256:daf768ce098a4689e6a8efb476f03f0b7a3c8be1cfb597e87f7673b80654e53c',
    reviewProjectionFileDigest: 'sha256:29b6c68a0c231989444274e4dc834a60d5b4bbb2e73c0550295d949db5c85e22',
    reviewProjectionPath: '.work/generated/universal-review-projection-29b6c68a0c231989444274e4dc834a60d5b4bbb2e73c0550295d949db5c85e22.json',
    verdict: 'UNIVERSAL_FAMILY_MODEL_INCOMPLETE',
  },
  verdict: 'PERMUTATION_CLOSURE_INCOMPLETE',
  verdictKind: 'INTERMEDIATE_NEVER_OVERALL_TERMINAL',
};

const currentWaveArtifactBindings = [
  { fileDigest: permutationClosure.foundationDomain.assessmentFileDigest, internalDigest: permutationClosure.foundationDomain.assessmentDigest, internalField: 'assessmentDigest', path: permutationClosure.foundationDomain.assessmentPath },
  { fileDigest: permutationClosure.foundationDomain.proofFileDigest, internalDigest: permutationClosure.foundationDomain.proofDigest, internalField: 'proofDigest', path: permutationClosure.foundationDomain.proofPath },
  { fileDigest: permutationClosure.universalFamilyModel.inventoryFileDigest, internalDigest: permutationClosure.universalFamilyModel.inventoryDigest, internalField: 'inventoryDigest', path: permutationClosure.universalFamilyModel.inventoryPath },
  { fileDigest: permutationClosure.universalFamilyModel.registryFileDigest, internalDigest: permutationClosure.universalFamilyModel.registryDigest, internalField: 'registryDigest', path: permutationClosure.universalFamilyModel.registryPath },
  { fileDigest: permutationClosure.universalFamilyModel.reviewProjectionFileDigest, internalDigest: permutationClosure.universalFamilyModel.reviewProjectionDigest, internalField: 'reviewProjectionDigest', path: permutationClosure.universalFamilyModel.reviewProjectionPath },
  { fileDigest: permutationClosure.universalFamilyModel.analysisFileDigest, internalDigest: permutationClosure.universalFamilyModel.analysisDigest, internalField: 'analysisDigest', path: permutationClosure.universalFamilyModel.analysisPath },
  { fileDigest: permutationClosure.universalFamilyModel.independentProofFileDigest, internalDigest: permutationClosure.universalFamilyModel.independentProofDigest, internalField: 'proofDigest', path: permutationClosure.universalFamilyModel.independentProofPath },
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
      proofDigest: permutationClosure.universalFamilyModel.independentProofDigest,
      reconstructionMismatchCount: 0,
      state: 'CURRENT_LOCAL_INDEPENDENT_RECONSTRUCTION_NOT_CLOSURE_PROOF',
      unresolvedFamilyReviewCount: 108,
      unresolvedSemanticTermCount: 8519,
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
      actualServiceAlgebraNodes: 0,
      candidateViolations: 0,
      evaluatedConstraints: 228,
      evidenceDigest: 'sha256:7e8e7c176fc0fc2c61721bfb4f2828d0d038fe7b730c4ba53f9e1abd30d79272',
      harnessSourceDigest: 'sha256:52db9580c0878d698439f4d680120e282de6f824caa8f8b01c914648e088ed85',
      plantedFixtureEvidenceDigest: 'sha256:f16f512282fa44474d2e0aaf8c32262526efdf7c05d30e24853b6191beae1164',
      plantedFixtures: { cases: 12, negative: 8, positive: 4, unexpectedCodes: 0, missingCodes: 0, multipleCodes: 0 },
      registeredConstraints: 228,
      substringExclusions: 0,
      unexpectedExclusions: 0,
    },
    narrowPermutationAndUniversal: {
      familyCensus: { failed: 0, passed: 15 },
      universalSemanticCoverage: { failed: 0, passed: 9 },
      state: 'CURRENT_FOCUSED_PASS',
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
      state: 'STALE_OPTION_EVALUATION_EVIDENCE_REGENERATION_REQUIRED_AFTER_SOURCE_FREEZE',
    },
    semanticCheck: { state: 'CURRENT_LOCAL_SHACL_PASS_FULL_INTEGRATED_GATE_PENDING' },
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
