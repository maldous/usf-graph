#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import {
  existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const FINGERPRINT = /^[0-9A-F]{40}$/;
const REQUIRED_NODE_VERSION = 'v22.23.1';
const REQUIRED_NODE_DIGEST = 'sha256:93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068';
const REQUIRED_PACKAGE_LOCK_DIGEST = 'sha256:e0f320742ed96b54765a39ccac219c05d72b61c4b8805b42e57b7e9e14cecde5';
const REQUIRED_PACKAGES = Object.freeze({ n3: '2.1.1', 'rdf-canonize': '5.0.0', stardog: '10.0.1', yaml: '2.9.0' });
const GIT_EXECUTABLE = '/usr/bin/git';
const GPG_EXECUTABLE = '/usr/bin/gpg';
const failureContext = { commands: [] };

const stable = (value) => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

class EvidenceProducerError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) { throw new EvidenceProducerError(code); }

process.on('uncaughtException', (error) => {
  const receipt = {
    schemaVersion: 1,
    recordKind: 'USF_VALIDATION_EVIDENCE_CANDIDATE',
    passed: false,
    eligibleForAdmission: false,
    authorityClaims: [],
    failureCodes: [error?.code || 'VALIDATION_EVIDENCE_PRODUCER_FAILED'],
    ...failureContext,
  };
  process.stdout.write(`${canonicalJson(receipt)}\n`);
  process.exitCode = 1;
});

function requiredEnvironment(name, pattern, failureCode) {
  const value = process.env[name] || '';
  if (!pattern.test(value)) fail(failureCode);
  return value;
}

function exactRegularFile(path, failureCode) {
  let canonical;
  try {
    if (lstatSync(path).isSymbolicLink()) fail(failureCode);
    canonical = realpathSync(path);
    if (!lstatSync(canonical).isFile()) fail(failureCode);
  } catch (error) {
    if (error instanceof EvidenceProducerError) throw error;
    fail(failureCode);
  }
  return canonical;
}

function executableBinding(path, version) {
  const canonical = exactRegularFile(path, 'EXECUTABLE_NOT_REGULAR');
  return { path: canonical, version, digest: sha256(readFileSync(canonical)) };
}

function runBoundCommand(id, executable, args, { cwd, env, timeout = 120_000, allowFailure = false } = {}) {
  const result = spawnSync(executable, args, {
    cwd,
    env,
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    timeout,
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
  const record = {
    id,
    executable,
    arguments: [...args],
    exitStatus: Number.isInteger(result.status) ? result.status : null,
    signal: result.signal || null,
    stdoutDigest: sha256(stdout),
    stderrDigest: sha256(stderr),
  };
  failureContext.commands.push(record);
  if (!allowFailure && (result.error || result.signal || result.status !== 0)) fail(`COMMAND_FAILED_${id.toUpperCase().replaceAll('-', '_')}`);
  return { record, stdout, stderr };
}

function bindProducerPreflight(repo) {
  const graphCommit = requiredEnvironment('USF_GRAPH_COMMIT', COMMIT, 'GRAPH_COMMIT_REQUIRED');
  const expectedGraphTree = requiredEnvironment('USF_EXPECTED_GRAPH_TREE', COMMIT, 'GRAPH_TREE_REQUIRED');
  const expectedSignerFingerprint = requiredEnvironment('USF_EXPECTED_SIGNER_FINGERPRINT', FINGERPRINT, 'SIGNER_FINGERPRINT_REQUIRED');
  const expectedKeyringDigest = requiredEnvironment('USF_EXPECTED_KEYRING_DIGEST', SHA256, 'KEYRING_DIGEST_REQUIRED');
  failureContext.graphCommit = graphCommit;
  failureContext.expectedGraphTree = expectedGraphTree;
  failureContext.expectedSignerFingerprint = expectedSignerFingerprint;
  failureContext.expectedKeyringDigest = expectedKeyringDigest;
  let gnupgHome;
  try { gnupgHome = realpathSync(process.env.USF_GNUPGHOME || ''); }
  catch { fail('GNUPGHOME_MISSING'); }
  if (!lstatSync(gnupgHome).isDirectory() || (lstatSync(gnupgHome).mode & 0o077) !== 0) fail('GNUPGHOME_NOT_PRIVATE');
  const pubringPath = exactRegularFile(join(gnupgHome, 'pubring.kbx'), 'PUBLIC_KEYRING_MISSING');
  const pubringDigest = sha256(readFileSync(pubringPath));
  if (pubringDigest !== expectedKeyringDigest) fail('PUBLIC_KEYRING_DIGEST_MISMATCH');

  const commandEnvironment = {
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    HOME: '/nonexistent',
    GNUPGHOME: gnupgHome,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
  };
  const repositoryGitArguments = ['--no-replace-objects', '-c', `safe.directory=${repo}`, '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null'];
  const head = runBoundCommand('git-head', GIT_EXECUTABLE, [...repositoryGitArguments, 'rev-parse', 'HEAD'], { cwd: repo, env: commandEnvironment }).stdout.toString('utf8').trim();
  if (head !== graphCommit) fail('GRAPH_HEAD_MISMATCH');
  const tree = runBoundCommand('git-tree', GIT_EXECUTABLE, [...repositoryGitArguments, 'rev-parse', 'HEAD^{tree}'], { cwd: repo, env: commandEnvironment }).stdout.toString('utf8').trim();
  if (tree !== expectedGraphTree) fail('GRAPH_TREE_MISMATCH');
  const status = runBoundCommand('git-status', GIT_EXECUTABLE, [...repositoryGitArguments, 'status', '--porcelain=v1', '--untracked-files=all'], { cwd: repo, env: commandEnvironment }).stdout;
  if (status.length !== 0) fail('GRAPH_WORKTREE_NOT_CLEAN');
  const verification = runBoundCommand(
    'git-verify-commit',
    GIT_EXECUTABLE,
    [...repositoryGitArguments, '-c', 'gpg.format=openpgp', '-c', `gpg.program=${GPG_EXECUTABLE}`, 'verify-commit', '--raw', graphCommit],
    { cwd: repo, env: commandEnvironment },
  );
  const signatureStatus = verification.stderr.toString('utf8').split('\n');
  const validSignatures = signatureStatus
    .map((line) => line.match(/^\[GNUPG:\] VALIDSIG (.+)$/u)?.[1].trim().split(/\s+/u))
    .filter(Boolean);
  const goodSignatures = signatureStatus
    .map((line) => line.match(/^\[GNUPG:\] GOODSIG ([0-9A-F]{16})\s+(.+)$/u))
    .filter(Boolean);
  if (validSignatures.length !== 1 || validSignatures[0].length !== 10) fail('GRAPH_VALIDSIG_RECORD_INVALID');
  const signingKeyFingerprint = validSignatures[0][0];
  const primaryKeyFingerprint = validSignatures[0][9];
  if (!FINGERPRINT.test(signingKeyFingerprint) || !FINGERPRINT.test(primaryKeyFingerprint)) fail('GRAPH_VALIDSIG_RECORD_INVALID');
  if (goodSignatures.length !== 1 || goodSignatures[0][1] !== signingKeyFingerprint.slice(-16)) fail('GRAPH_GOODSIG_SIGNING_KEY_MISMATCH');
  if (primaryKeyFingerprint !== expectedSignerFingerprint) fail('GRAPH_PRIMARY_FINGERPRINT_MISMATCH');

  const runnerSourcePath = 'assurance/semantic-model-compilation/materialisation-proof.mjs';
  const runnerSource = exactRegularFile(join(repo, runnerSourcePath), 'RUNNER_SOURCE_MISSING');
  if (realpathSync(import.meta.filename) !== runnerSource) fail('RUNNER_SOURCE_OUTSIDE_GRAPH_BYTES');
  const committedRunner = runBoundCommand(
    'git-runner-source',
    GIT_EXECUTABLE,
    [...repositoryGitArguments, 'show', `${graphCommit}:${runnerSourcePath}`],
    { cwd: repo, env: commandEnvironment },
  ).stdout;
  const runnerSourceDigest = sha256(readFileSync(runnerSource));
  if (sha256(committedRunner) !== runnerSourceDigest) fail('RUNNER_SOURCE_COMMIT_MISMATCH');

  const nodeBinding = executableBinding(process.execPath, process.version);
  if (nodeBinding.version !== REQUIRED_NODE_VERSION) fail('NODE_VERSION_MISMATCH');
  if (nodeBinding.digest !== REQUIRED_NODE_DIGEST) fail('NODE_EXECUTABLE_DIGEST_MISMATCH');
  const packageLockPath = exactRegularFile(join(repo, 'package-lock.json'), 'PACKAGE_LOCK_MISSING');
  const packageLockDigest = sha256(readFileSync(packageLockPath));
  if (packageLockDigest !== REQUIRED_PACKAGE_LOCK_DIGEST) fail('PACKAGE_LOCK_DIGEST_MISMATCH');
  const lock = JSON.parse(readFileSync(packageLockPath, 'utf8'));
  const packages = Object.fromEntries(Object.entries(REQUIRED_PACKAGES).map(([name, expectedVersion]) => {
    const record = lock.packages?.[`node_modules/${name}`];
    if (record?.version !== expectedVersion || typeof record.integrity !== 'string') fail('PACKAGE_IDENTITY_MISMATCH');
    return [name, { version: record.version, integrity: record.integrity }];
  }));
  const gitVersion = runBoundCommand('git-version', GIT_EXECUTABLE, ['--version'], { cwd: repo, env: commandEnvironment }).stdout.toString('utf8').trim();
  const gpgVersion = runBoundCommand('gpg-version', GPG_EXECUTABLE, ['--version'], { cwd: repo, env: commandEnvironment }).stdout.toString('utf8').split('\n')[0].trim();
  const gitExecutionPolicy = {
    globalArguments: [...repositoryGitArguments],
    environment: {
      GIT_CONFIG_GLOBAL: commandEnvironment.GIT_CONFIG_GLOBAL,
      GIT_CONFIG_NOSYSTEM: commandEnvironment.GIT_CONFIG_NOSYSTEM,
      GIT_NO_REPLACE_OBJECTS: commandEnvironment.GIT_NO_REPLACE_OBJECTS,
      GIT_OPTIONAL_LOCKS: commandEnvironment.GIT_OPTIONAL_LOCKS,
    },
  };
  const toolchain = {
    node: nodeBinding,
    git: { ...executableBinding(GIT_EXECUTABLE, gitVersion), executionPolicy: gitExecutionPolicy },
    gpg: executableBinding(GPG_EXECUTABLE, gpgVersion),
    packageLockDigest,
    packages,
  };
  return Object.freeze({
    graphCommit,
    graphTree: tree,
    signatureVerification: {
      state: 'verified',
      signingKeyFingerprint,
      primaryKeyFingerprint,
      goodSignatureKeyId: goodSignatures[0][1],
      gnupgHome,
      publicKeyringPath: pubringPath,
      publicKeyringDigest: pubringDigest,
    },
    runner: {
      sourcePath: runnerSourcePath,
      sourceDigest: runnerSourceDigest,
      executable: nodeBinding,
    },
    toolchain,
    toolchainDigest: sha256(canonicalJson(toolchain)),
  });
}

const repo = realpathSync(resolve(process.env.USF_REPO || resolve(import.meta.dirname, '../..')));
const evaluatedAuthorityDigest = process.env.USF_AUTHORITY_DIGEST || '';
const evaluatedAt = process.env.USF_EVALUATED_AT || '';
const expectedDependencySetDigest = process.env.USF_EXPECTED_DEPENDENCY_SET_DIGEST || null;
const casRoot = resolve(process.env.USF_CAS_ROOT || '/var/lib/usf-cas');
const outputRoot = resolve(process.env.USF_PROOF_OUTPUT || '/tmp/usf-materialisation-control-plane-proof');
if (!/^sha256:[0-9a-f]{64}$/.test(evaluatedAuthorityDigest)) throw new Error('USF_AUTHORITY_DIGEST is required');
if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(evaluatedAt)) throw new Error('USF_EVALUATED_AT is required');
if (expectedDependencySetDigest && !/^sha256:[0-9a-f]{64}$/.test(expectedDependencySetDigest)) throw new Error('invalid USF_EXPECTED_DEPENDENCY_SET_DIGEST');
if (!outputRoot.startsWith('/tmp/usf-materialisation-control-plane-proof')) throw new Error('proof output must use the bounded temporary proof root');

const producerPreflight = bindProducerPreflight(repo);
failureContext.graphCommit = producerPreflight.graphCommit;
failureContext.graphTree = producerPreflight.graphTree;
failureContext.evaluatedAuthorityDigest = evaluatedAuthorityDigest;
failureContext.signatureVerification = producerPreflight.signatureVerification;
failureContext.runner = producerPreflight.runner;
failureContext.toolchain = producerPreflight.toolchain;
failureContext.toolchainDigest = producerPreflight.toolchainDigest;
if (process.argv.includes('--test-preflight-only')) {
  process.stdout.write(`${canonicalJson({
    schemaVersion: 1,
    recordKind: 'USF_TEST_ONLY_VALIDATION_PREFLIGHT',
    preflightPassed: true,
    realisationValidationPassed: false,
    eligibleForAdmission: false,
    authorityClaims: [],
    evaluatedAuthorityDigest,
    ...producerPreflight,
    commands: failureContext.commands,
  })}\n`);
  process.exit(0);
}

const require = createRequire(join(repo, 'package.json'));
const canonicalModule = (path) => pathToFileURL(join(repo, path));
const semanticModelDirectory = join(repo, 'semantic-model');
const authorityBindingModule = canonicalModule('capabilities/semantic-model-compilation/authority-binding.mjs');
if (process.argv.includes('--test-authority-loading-only')) {
  const { authorityDependencySetDigest: dependencyDigest } = await import(authorityBindingModule);
  const semanticManifestPath = exactRegularFile(join(semanticModelDirectory, 'manifest.yaml'), 'SEMANTIC_MANIFEST_MISSING');
  process.stdout.write(`${canonicalJson({
    schemaVersion: 1,
    recordKind: 'USF_TEST_ONLY_AUTHORITY_LOADING',
    preflightPassed: true,
    authorityBindingModuleLoaded: typeof dependencyDigest === 'function',
    semanticManifestPath,
    semanticManifestDigest: sha256(readFileSync(semanticManifestPath)),
    realisationValidationPassed: false,
    eligibleForAdmission: false,
    authorityClaims: [],
    evaluatedAuthorityDigest,
    ...producerPreflight,
    commands: failureContext.commands,
  })}\n`);
  process.exit(0);
}
const { DataFactory } = require('n3');
const { authorityWitness } = await import(canonicalModule('processes/semantic-assurance/semantic-bootstrap-packet.mjs'));
const { loadConfig } = await import(canonicalModule('configuration/semantic-assurance/stardog-connection.mjs'));
const { compile, checkLocal } = await import(canonicalModule('capabilities/semantic-model-compilation/compiler.mjs'));
const { loadAuthorityDataset } = await import(canonicalModule('processes/semantic-assurance/authority-dataset.mjs'));
const { loadManifest } = await import(canonicalModule('capabilities/semantic-model-compilation/manifest.mjs'));
const { createClient } = await import(canonicalModule('provider-bindings/stardog/stardog-read-gateway.mjs'));
const { readSemanticAuthorityWitness } = await import(canonicalModule('processes/semantic-assurance/semantic-authority-gateway.mjs'));
const {
  digest, jcs, layoutContext, projectContract,
} = await import(canonicalModule('processes/semantic-assurance/repository-materialisation-gateway.mjs'));
const materialisationCapability = await import(pathToFileURL(join(repo, 'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs')));
const {
  createMaterialisationPlan,
  materialisePlan,
  validateMaterialisationPlan,
} = materialisationCapability;
const {
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  SELF_PUBLICATION_RULE,
  authorityDependencySetDigest,
} = await import(authorityBindingModule);

const contract = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const proofResult = 'urn:usf:proofresult:repositorymaterialisationcontrolplane';
const decision = 'urn:usf:realisationdecision:repositoryarchitectureandnaming';
const realisation = 'urn:usf:realisation:repositoryarchitectureandnaming';
const ACTIVE = 'urn:usf:contractactivationstate:active';
const PROOF_BLOCKED = 'urn:usf:contractactivationstate:proofblocked';
const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
const ACCEPTED = 'urn:usf:decisionstate:accepted';
const { namedNode } = DataFactory;
const cases = [];

function record(id, expected, observed, { negative = false, detail = null } = {}) {
  const passed = expected === observed;
  cases.push({ id, expected, observed, passed, negative, ...(detail ? { detail } : {}) });
  if (!passed) throw new Error(`${id}: expected ${expected}, observed ${observed}`);
}

function sourceSetDigest(paths) {
  const records = paths.slice().sort().map((path) => ({ path, digest: sha256(readFileSync(join(repo, path))) }));
  return { records, digest: digest(jcs(records)) };
}

function putCas(bytes, mediaType) {
  const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const contentDigest = sha256(value);
  const hex = contentDigest.slice(7);
  const path = join(casRoot, 'sha256', hex.slice(0, 2), hex);
  mkdirSync(dirname(path), { recursive: true });
  if (!existsSync(path)) writeFileSync(path, value, { flag: 'wx', mode: 0o600 });
  if (!readFileSync(path).equals(value)) throw new Error(`CAS round-trip failed for ${contentDigest}`);
  return { digest: contentDigest, byteSize: value.length, mediaType, locator: `cas://sha256/${hex}` };
}

function oneObject(store, subject, predicate) {
  const values = store.getObjects(namedNode(subject), namedNode(predicate), null).map((term) => term.value);
  if (values.length !== 1) throw new Error(`${subject} must have exactly one ${predicate}`);
  return values[0];
}

function binding(value) { return { value }; }

const config = loadConfig();
const client = createClient(config);
const live = { client, config };
const liveWitness = await authorityWitness(client);
record('live-authority-digest', evaluatedAuthorityDigest, `sha256:${liveWitness.digest}`);
const current = await layoutContext(live, { contract });
record('live-contract-active', ACTIVE, current.contract.activationState);
record('live-proof-result-successful', SUCCESSFUL, current.contract.proofResultState);
record('accepted-layout-decision-count', 1, current.acceptedDecisionCount);
record('accepted-layout-decision', decision, current.contract.decision);

const livePacket = await projectContract(live, { contract, objective: 'Refresh current materialisation control-plane evidence after an implementation or authority dependency change.' });
record('active-packet-authorises-actions', true, livePacket.authorisedActions.length > 0);
record('active-packet-authorises-paths', true, livePacket.authorisedPaths.length > 0);

const manifest = loadManifest(semanticModelDirectory);
checkLocal(manifest);
const candidateDataset = loadAuthorityDataset(manifest);
record('candidate-contract-active', ACTIVE, oneObject(candidateDataset.store, contract, 'urn:usf:ontology:hasActivationState'));
record('candidate-contract-relies-on-current-proof', proofResult, oneObject(candidateDataset.store, contract, 'urn:usf:ontology:reliesOnProofResult'));
record('candidate-realisation-implementable', 'urn:usf:realisationstate:implementable', oneObject(candidateDataset.store, realisation, 'urn:usf:ontology:realisationState'));

const publicationAuthorityWitness = await readSemanticAuthorityWitness(client);
let candidate;
try {
  candidate = await compile({
    authorityWitness: publicationAuthorityWitness,
    client,
    manifest,
    publicationBudgetPolicy: manifest.publicationBudget,
    publicationMode: 'validate',
  });
} catch (error) {
  failureContext.commands.push({
    id: 'semantic-compiler-validate-rollback',
    executable: 'repository-local:capabilities/semantic-model-compilation/compiler.mjs',
    arguments: ['publicationMode=validate'],
    exitStatus: 1,
    signal: null,
    stdoutDigest: sha256(''),
    stderrDigest: sha256(error?.name || 'Error'),
  });
  fail('SEMANTIC_COMPILER_VALIDATION_FAILED');
}
failureContext.commands.push({
  id: 'semantic-compiler-validate-rollback',
  executable: 'repository-local:capabilities/semantic-model-compilation/compiler.mjs',
  arguments: ['publicationMode=validate'],
  exitStatus: 0,
  signal: null,
  stdoutDigest: sha256(canonicalJson(candidate?.commitOutcome || null)),
  stderrDigest: sha256(''),
});
record('candidate-transaction-rolled-back', 'validated-rolled-back', candidate.commitOutcome.state);
record('candidate-exact-state-verified', true, candidate.commitOutcome.exactCandidateStateVerified);
const candidateGraphInventory = candidate.commitOutcome.candidateGraphs;
const candidateDependencySetDigest = authorityDependencySetDigest(candidateGraphInventory);
if (expectedDependencySetDigest) record('candidate-dependency-set-digest', expectedDependencySetDigest, candidateDependencySetDigest);

const activeContext = current;
const blockedContext = {
  ...activeContext,
  contract: {
    ...activeContext.contract,
    activationState: PROOF_BLOCKED,
    proofResult: null,
    proofResultState: null,
  },
};
record('current-authority-context-active', ACTIVE, activeContext.contract.activationState);

const selectedRule = activeContext.rules.find((rule) => rule.family === 'urn:usf:artefactfamily:assurancesource'
  && rule.pathRole === 'urn:usf:pathrole:assurancesource'
  && rule.representationFormat === 'urn:usf:representationformat:ecmascriptmodule2024');
if (!selectedRule) throw new Error('current authority has no assurance ECMAScript materialisation rule');
const content = 'export const materialisationControlPlaneFixture = true;\n';
const operation = {
  action: 'write-file', artefactFamily: selectedRule.family, content,
  contentDigest: digest(content), contentEncoding: 'utf8', fileMode: '0644', index: 0,
  path: 'assurance/materialisation-control-plane.fixture.mjs', pathRole: selectedRule.pathRole,
  representationFormat: selectedRule.representationFormat,
};
const unsignedLivePlan = { schemaVersion: 1, authorityDigest: current.authorityDigest, contract, operations: [operation] };
const livePlan = { ...unsignedLivePlan, planDigest: digest(jcs(unsignedLivePlan)) };
const blockedValidation = validateMaterialisationPlan(blockedContext, livePlan);
record('pre-activation-plan-fails-closed', true, blockedValidation.failures.some((item) => item.code === 'contract-not-active'), { negative: true });

const firstPlan = createMaterialisationPlan(activeContext, [operation], contract);
const secondPlan = createMaterialisationPlan(activeContext, [operation], contract);
record('plan-determinism', firstPlan.planDigest, secondPlan.planDigest);
record('plan-bounded', true, Buffer.byteLength(jcs(firstPlan)) <= 65_536);
record('plan-validation', true, validateMaterialisationPlan(activeContext, firstPlan).ok);

const applyRoot = mkdtempSync(join(tmpdir(), 'materialisation-apply-proof-'));
try {
  record('materialisation-dry-run', true, materialisePlan({ authority: activeContext, plan: firstPlan, repositoryRoot: applyRoot }).dryRun);
  record('materialisation-first-apply', true, materialisePlan({ authority: activeContext, plan: firstPlan, repositoryRoot: applyRoot, apply: true }).applied);
  const repeated = materialisePlan({ authority: activeContext, plan: firstPlan, repositoryRoot: applyRoot, apply: true });
  record('materialisation-idempotence', 'already-applied', repeated.operations[0].state);
} finally {
  rmSync(applyRoot, { recursive: true, force: true });
}

const rollbackRoot = mkdtempSync(join(tmpdir(), 'materialisation-rollback-proof-'));
try {
  mkdirSync(join(rollbackRoot, 'assurance'), { recursive: true });
  const existing = join(rollbackRoot, 'assurance/existing.fixture.mjs');
  writeFileSync(existing, 'prior\n');
  const rollbackPlan = createMaterialisationPlan(activeContext, [
    { ...operation, path: 'assurance/transient.fixture.mjs' },
    { ...operation, index: 1, path: 'assurance/existing.fixture.mjs', sourceDigest: digest('prior\n') },
  ], contract);
  writeFileSync(existing, 'concurrent-change\n');
  let rollbackState = 'accepted';
  try { materialisePlan({ authority: activeContext, plan: rollbackPlan, repositoryRoot: rollbackRoot, apply: true }); }
  catch { rollbackState = existsSync(join(rollbackRoot, 'assurance/transient.fixture.mjs')) ? 'partial' : 'rolled-back'; }
  record('materialisation-rollback', 'rolled-back', rollbackState, { negative: true });
} finally {
  rmSync(rollbackRoot, { recursive: true, force: true });
}

const outsideRoot = mkdtempSync(join(tmpdir(), 'materialisation-outside-proof-'));
const symlinkRoot = mkdtempSync(join(tmpdir(), 'materialisation-symlink-proof-'));
try {
  symlinkSync(outsideRoot, join(symlinkRoot, 'assurance'), 'dir');
  let traversal = 'accepted';
  try { materialisePlan({ authority: activeContext, plan: firstPlan, repositoryRoot: symlinkRoot, apply: true }); }
  catch { traversal = 'rejected'; }
  record('symbolic-link-traversal', 'rejected', traversal, { negative: true });
  record('symbolic-link-outside-write', false, existsSync(join(outsideRoot, 'materialisation-control-plane.fixture.mjs')), { negative: true });
} finally {
  rmSync(symlinkRoot, { recursive: true, force: true });
  rmSync(outsideRoot, { recursive: true, force: true });
}

const stalePlan = structuredClone(firstPlan);
stalePlan.authorityDigest = `sha256:${'0'.repeat(64)}`;
delete stalePlan.planDigest;
stalePlan.planDigest = digest(jcs(stalePlan));
record('stale-authority-plan', true, validateMaterialisationPlan(activeContext, stalePlan).failures.some((item) => item.code === 'plan-authority-digest'), { negative: true });
const tamperedPlan = structuredClone(firstPlan);
tamperedPlan.operations[0].content = 'tampered\n';
delete tamperedPlan.planDigest;
tamperedPlan.planDigest = digest(jcs(tamperedPlan));
record('tampered-content-plan', true, validateMaterialisationPlan(activeContext, tamperedPlan).failures.some((item) => item.code === 'operation-content-mismatch'), { negative: true });

const focusedTestArguments = ['--test',
  'capabilities/repository-external-artefact-materialisation/materialisation-plan.test.mjs',
  'configuration/semantic-assurance/semantic-authority.test.mjs',
  'provider-bindings/stardog/semantic-authority.test.mjs',
  'processes/semantic-assurance/repository-materialisation-command.test.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.test.mjs',
  'processes/semantic-assurance/repository-materialisation-gateway.test.mjs',
  'processes/semantic-assurance/semantic-authority-mcp.test.mjs',
];
const focusedTests = runBoundCommand('focused-control-plane-tests', process.execPath, focusedTestArguments, {
  cwd: repo,
  env: {
    HOME: '/nonexistent',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    PATH: '/usr/bin:/bin',
    TZ: 'UTC',
  },
  timeout: 300_000,
}).stdout.toString('utf8');
const focusedTestCount = Number(focusedTests.match(/# tests ([0-9]+)/)?.[1] || 0);
record('focused-control-plane-tests', 'passed', focusedTestCount > 0 && /# fail 0/.test(focusedTests) ? 'passed' : 'failed');

const implementationSources = sourceSetDigest([
  'assurance/semantic-model-compilation/materialisation-proof.hostile-test.mjs',
  'capabilities/semantic-model-compilation/authority-binding.mjs',
  'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
  'capabilities/repository-external-artefact-materialisation/materialisation-plan.test.mjs',
  'configuration/semantic-assurance/semantic-authority.mjs',
  'configuration/semantic-assurance/semantic-authority.test.mjs',
  'provider-bindings/stardog/semantic-authority.mjs',
  'provider-bindings/stardog/semantic-authority.test.mjs',
  'processes/semantic-assurance/repository-materialisation-command.mjs',
  'processes/semantic-assurance/repository-materialisation-command.test.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.test.mjs',
  'processes/semantic-assurance/authority-dataset.mjs',
  'processes/semantic-assurance/semantic-bootstrap-packet.mjs',
  'processes/semantic-assurance/repository-materialisation-gateway.mjs',
  'processes/semantic-assurance/semantic-authority-mcp.mjs',
  'processes/semantic-assurance/repository-materialisation-gateway.test.mjs',
  'processes/semantic-assurance/semantic-authority-mcp.test.mjs',
]);
const proofAlgorithmSourceDigest = sha256(readFileSync(import.meta.filename));
cases.sort((left, right) => left.id.localeCompare(right.id));
const evidenceCore = {
  schemaVersion: 3,
  recordKind: 'USF_VALIDATION_EVIDENCE_CANDIDATE',
  passed: cases.every((item) => item.passed),
  eligibleForAdmission: false,
  authorityClaims: [],
  evaluatedAt,
  evaluatedAuthorityDigest,
  graphCommit: producerPreflight.graphCommit,
  graphTree: producerPreflight.graphTree,
  signatureVerification: producerPreflight.signatureVerification,
  runner: producerPreflight.runner,
  toolchain: producerPreflight.toolchain,
  toolchainDigest: producerPreflight.toolchainDigest,
  validationCommands: [
    {
      executable: GIT_EXECUTABLE,
      arguments: [
        '--no-replace-objects', '-c', `safe.directory=${repo}`, '-c', 'core.fsmonitor=false',
        '-c', 'core.hooksPath=/dev/null', '-c', 'gpg.format=openpgp',
        '-c', `gpg.program=${GPG_EXECUTABLE}`, 'verify-commit', '--raw', producerPreflight.graphCommit,
      ],
    },
    { executable: process.execPath, arguments: focusedTestArguments },
    {
      executable: 'repository-local:capabilities/semantic-model-compilation/compiler.mjs',
      arguments: ['publicationMode=validate'],
    },
  ],
  commandResults: failureContext.commands,
  candidateDependencySetDigest,
  dependencyDigestAlgorithm: AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  authorityBindingRule: SELF_PUBLICATION_RULE,
  excludedAuthorityGraphs: SELF_PUBLICATION_EXCLUDED_GRAPHS,
  implementationSourceDigest: implementationSources.digest,
  implementationSources: implementationSources.records,
  proofAlgorithmSourceDigest,
  environmentClass: 'urn:usf:environmentclass:hermetic',
  providerMode: 'urn:usf:providermode:deterministictestsubstitute',
  cases,
  measurements: {
    candidateGraphCount: candidateGraphInventory.length,
    focusedTestCount,
    materialisationRuleCount: activeContext.rules.length,
    pathRoleCount: activeContext.pathRoles.length,
  },
  nonclaims: [
    'This producer emits candidate evidence only; it does not admit evidence, establish integrity or freshness state, establish proof, activate a validation obligation, or mutate semantic authority.',
    'The lifecycle substitute proves the post-activation control path; it does not itself mutate live contract state.',
    'The deterministic test signature is integrity evidence, not production identity or authenticity.',
    'This control-plane proof does not satisfy final clean-clone, staging, live-provider or whole-suite readiness obligations.',
  ],
};
const exactEvidenceSetDigest = digest(jcs(evidenceCore));
const evidenceManifest = { ...evidenceCore, exactEvidenceSetDigest };
const evidenceManifestBytes = Buffer.from(jcs(evidenceManifest));
const evidenceManifestDescriptor = putCas(evidenceManifestBytes, 'application/json');

const seed = createHash('sha256').update('repository-materialisation-control-plane-integrity-key').digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const payloadType = 'application/vnd.in-toto+json';
const statement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'repository-materialisation-control-plane-evidence', digest: { sha256: evidenceManifestDescriptor.digest.slice(7) } }],
  predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
  predicate: {
    evaluatedAuthorityDigest, candidateDependencySetDigest, exactEvidenceSetDigest,
    implementationSourceDigest: implementationSources.digest, proofAlgorithmSourceDigest, result: 'passed',
  },
};
const statementBytes = Buffer.from(jcs(statement));
const pae = Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `), statementBytes]);
const signature = sign(null, pae, privateKey);
if (!verify(null, pae, publicKey, signature)) throw new Error('proof attestation signature verification failed');
const envelope = {
  payloadType,
  payload: statementBytes.toString('base64'),
  signatures: [{ keyid: sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7), sig: signature.toString('base64') }],
};
const proofAttestationBytes = Buffer.from(jcs(envelope));
const proofAttestationDescriptor = putCas(proofAttestationBytes, 'application/vnd.in-toto+json');

rmSync(outputRoot, { recursive: true, force: true });
mkdirSync(outputRoot, { recursive: true });
writeFileSync(join(outputRoot, 'evidence-manifest.json'), evidenceManifestBytes, { mode: 0o600 });
writeFileSync(join(outputRoot, 'proof-attestation.dsse.json'), proofAttestationBytes, { mode: 0o600 });

process.stdout.write(`${JSON.stringify({
  schemaVersion: 1,
  recordKind: 'USF_VALIDATION_EVIDENCE_CANDIDATE_RECEIPT',
  ok: cases.every((item) => item.passed),
  passed: cases.every((item) => item.passed),
  eligibleForAdmission: false,
  authorityClaims: [],
  evaluatedAuthorityDigest,
  graphCommit: producerPreflight.graphCommit,
  graphTree: producerPreflight.graphTree,
  signatureVerification: producerPreflight.signatureVerification,
  runner: producerPreflight.runner,
  toolchainDigest: producerPreflight.toolchainDigest,
  commandResults: failureContext.commands,
  candidateAuthorityDigest: candidate.commitOutcome.candidateDigest,
  candidateDependencySetDigest,
  exactEvidenceSetDigest,
  implementationSourceDigest: implementationSources.digest,
  proofAlgorithmSourceDigest,
  evidenceManifest: evidenceManifestDescriptor,
  proofAttestation: proofAttestationDescriptor,
  signingKeyFingerprint: envelope.signatures[0].keyid,
  caseCount: cases.length,
  negativeCaseCount: cases.filter((item) => item.negative).length,
  failureCount: cases.filter((item) => !item.passed).length,
  outputRoot,
}, null, 2)}\n`);
