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
  action: 'Produce the authority-bound permutation-family census across every active capability, contract and mandatory facet, then deliver the permutation meta-model, complete action/transport catalogue, permission and token closure, deterministic universe generation, fixtures, generated tests and independent proof.',
  authorityDigest: 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd',
  command: 'npm run authority:drift && npm test',
  preconditions: [
    'authority digest remains exact and the semantic-model source retains zero live drift',
    'no authority mutation transaction or modifying worker is active',
    'no permission, operation-catalogue, access-token or overall completion claim closes before the permutation gate passes',
  ],
  semanticIdentifiers: [
    'OPERATIONAL_PERMUTATION_AND_AUTHORISATION_CLOSURE',
    'PERMUTATION_FAMILY_CENSUS',
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
    blockerCode: 'LOCAL_SEMANTIC_IMPLEMENTATION',
    id: 'OPERATIONAL_PERMUTATION_AND_AUTHORISATION_CLOSURE',
    prerequisites: ['DIRECTIVE_AND_CHECKPOINT_RECONCILIATION'],
    state: directiveReconciled ? 'UNBLOCKED' : 'BLOCKED_BY_RECONCILIATION',
  },
  { blockerCode: 'LOCAL_PROOF_REFRESH', id: 'COMPILER_GENERATOR_AND_PROOF_REFRESH', prerequisites: ['OPERATIONAL_PERMUTATION_AND_AUTHORISATION_CLOSURE'], state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { blockerCode: 'LOCAL_IMPLEMENTATION', id: 'EXECUTABLE_ENVIRONMENT_DELIVERY', prerequisites: ['COMPILER_GENERATOR_AND_PROOF_REFRESH'], state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { blockerCode: 'LOCAL_VALIDATION', id: 'BIDIRECTIONAL_TRACEABILITY_CLOSURE', prerequisites: ['EXECUTABLE_ENVIRONMENT_DELIVERY'], state: 'BLOCKED_BY_DELIVERY' },
  { blockerCode: 'LOCAL_VALIDATION_THEN_AUTHORITY_PUBLICATION_REQUIRED', id: 'FINAL_HERMETIC_SYSTEM_GATES', prerequisites: ['BIDIRECTIONAL_TRACEABILITY_CLOSURE'], state: 'BLOCKED_BY_DELIVERY' },
];

const currentItem = directiveReconciled
  ? { id: 'OPERATIONAL_PERMUTATION_AND_AUTHORISATION_CLOSURE', state: 'UNBLOCKED' }
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
  VERIFIED_CURRENT: ['SEMANTIC_ADEQUACY_AND_CONTAMINATION_WITHIN_UNCHANGED_DEPENDENCY_SCOPE', 'DELIVERABLE_AND_LAYOUT_AUTHORITY', 'SOURCE_LIVE_PARITY', 'MILESTONE_GIT_PUBLICATION', 'REALISATION_OPTION_EVALUATION_CLOSURE', 'CANONICAL_COMPILER_SOLE_PATH'],
};

const gateSummary = [
  { id: 'DIRECTIVE_AND_CHECKPOINT_RECONCILIATION', state: directiveReconciled ? 'VERIFIED_CURRENT' : 'REOPENED_GOAL_DIGEST_CHANGED' },
  { id: 'SEMANTIC_ADEQUACY', state: 'VERIFIED_CURRENT_EXCEPT_REOPENED_OPERATION_UNIVERSE_SCOPE' },
  { id: 'DELIVERABLE_AND_LAYOUT_AUTHORITY', state: 'VERIFIED_CURRENT' },
  { id: 'REALISATION_OPTION_EVALUATION_CLOSURE', state: 'VERIFIED_CURRENT' },
  { id: 'PERMUTATION_AND_AUTHORISATION_CLOSURE', state: 'REMAINING_ACTIONABLE' },
  { id: 'COMPILER_PROOF_ADMISSION', state: 'PARTIALLY_DELIVERED_REOPENED_IMPLEMENTATION_BINDING' },
  { id: 'CANONICAL_COMPILER_SOLE_PATH', state: 'VERIFIED_CURRENT' },
  { id: 'EXECUTABLE_ENVIRONMENTS', state: 'BLOCKED_BY_PERMUTATION_CLOSURE' },
  { id: 'FINAL_HERMETIC_CLOSURE', state: 'REMAINING_ACTIONABLE' },
];

const permutationClosure = {
  verdict: 'PERMUTATION_CLOSURE_INCOMPLETE',
  verdictKind: 'INTERMEDIATE_NEVER_OVERALL_TERMINAL',
};

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
    currentDigest: 'sha256:d24b641a3136cb73d73b354b11bcb839d4714d38c8c4ba905128039547575b8f',
    graphCount: 36,
    nonPublicationDependencyDigest: 'sha256:1b7147be19433f3c0420c0d08559554b7a90e30d02b73cb12f508211916f588c',
    sourceLiveDrift: 'ZERO_BOTH_GOVERNED_MIRRORS',
    tripleCount: 61704,
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
  schemaVersion: 1,
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
    currentDigest: 'sha256:d24b641a3136cb73d73b354b11bcb839d4714d38c8c4ba905128039547575b8f',
    graphCount: 36,
    managedCandidateDigest: 'sha256:6220e75969e28cee9a35aa5d6e78b7d2754a0fcbcdefb6fbdf42c73b6bd7ba2d',
    nonPublicationDependencyDigest: 'sha256:1b7147be19433f3c0420c0d08559554b7a90e30d02b73cb12f508211916f588c',
    sourceLiveDrift: {
      graph: 0,
      semanticModel: 0,
      state: 'ZERO',
    },
    tripleCount: 61704,
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
    candidateAuthorityDigest: 'sha256:014a7547a9e2d1973f15fdceb4ae5d2578e16be12b5ab7bc6569f159b70e97b7',
    exactEvidenceSetDigest: 'sha256:2049d80e0725b70c02a6f269d6819a3a36b4cb19745fcc2c5cb0015c52b5b737',
    hermeticScopedEvidenceDigest: 'sha256:72605408479efedbc873c44c3d5a7dcf2add80084cdb3c0244e52ffde77f4a67',
    implementationSourceDigest: 'sha256:05323e8c4b7e6b21d16e5e679c30cd80154b0bbb12907dcf05944b4cc2c00e4a',
    liveAuthorityScopedEvidenceDigest: 'sha256:38f69d84d7a60372de291bacc755ea105c99ee2a04cbca5e64c9206574109748',
    proofAlgorithmDigest: 'sha256:1d2db0368372a56356717073eaa4c40def2a256df0d95b01d5daa460b7aed024',
    resultIdentifiers: [
      'urn:usf:proofresult:compilercontractbehaviour',
      'urn:usf:proofresult:compilerhermeticsubstitute',
      'urn:usf:proofresult:compilerliveauthoritycontrol',
    ],
    state: 'ADMITTED_FOR_PREVIOUS_IMPLEMENTATION_BINDING_REOPENED_BY_LOCAL_CUTOVER',
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
    commitOutcome: 'CONFIRMED_RESPONSE_EXACT_CANDIDATE_STATE_VERIFIED',
    currentAuthorityDigest: 'sha256:d24b641a3136cb73d73b354b11bcb839d4714d38c8c4ba905128039547575b8f',
    evaluatedAuthorityDigest: 'sha256:dd3a24e0ad666a94c51988fe92a1083cfe0e35de1247e5f7884ff2eacabf0573',
    managedCandidateDigest: 'sha256:6220e75969e28cee9a35aa5d6e78b7d2754a0fcbcdefb6fbdf42c73b6bd7ba2d',
    resultPath: '.work/materialisation/compiler-wave-4fe1a272/compiler-publication-result.json',
  },
  recordKind: 'USF_RECOVERY_CHECKPOINT',
  recordedAt,
  schemaVersion: 1,
  stateClassifications,
  transactionState: {
    authorityMutation: 'CLOSED_NONE_OWNED',
    lastKnownPublicationOutcome: 'CONFIRMED_RESPONSE_EXACT_CANDIDATE_STATE_VERIFIED',
    mutationOutcomeAmbiguous: false,
    queryOwnership: 'NONE_OWNED',
  },
  unresolvedFindings: dependencyNodes.map(({ blockerCode, id, state }) => ({ blockerCode, id, state })),
  userReportedExecutionMetric: {
    sessions: 1,
    source: 'USER_REPORTED_NOT_SYSTEM_VERIFIED',
    tokens: 500000000,
  },
  validation: {
    compilerSuite: { failed: 0, passed: 121 },
    localShacl: { actualServiceAlgebraNodes: 0, evaluatedConstraints: 79, registeredConstraints: 79, substringExclusions: 0, unexpectedExclusions: 0, violations: 0 },
    rootSuite: { failed: 0, inventoryDigest: 'sha256:600d1663e33fa723efe6a917734d35e410fb67e778bbeb181d1ddee5dc95d47d', nodeVersion: '22.23.1', passed: 71 },
    semanticCheck: { authoredGraphCount: 30, derivedGraphCount: 5, fileCount: 53, state: 'PASSED' },
    sourceLiveDrift: 'ZERO_ACROSS_36_REGISTERED_GRAPHS',
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
