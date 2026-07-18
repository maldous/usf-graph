#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const repo = resolve(process.env.USF_REPO || resolve(import.meta.dirname, '../..'));
const evaluatedAuthorityDigest = process.env.USF_AUTHORITY_DIGEST || '';
const evaluatedAt = process.env.USF_EVALUATED_AT || '';
const expectedDependencySetDigest = process.env.USF_EXPECTED_DEPENDENCY_SET_DIGEST || null;
const casRoot = resolve(process.env.USF_CAS_ROOT || '/var/lib/usf-cas');
const outputRoot = resolve(process.env.USF_PROOF_OUTPUT || '/tmp/usf-materialisation-control-plane-proof');
if (!/^sha256:[0-9a-f]{64}$/.test(evaluatedAuthorityDigest)) throw new Error('USF_AUTHORITY_DIGEST is required');
if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(evaluatedAt)) throw new Error('USF_EVALUATED_AT is required');
if (expectedDependencySetDigest && !/^sha256:[0-9a-f]{64}$/.test(expectedDependencySetDigest)) throw new Error('invalid USF_EXPECTED_DEPENDENCY_SET_DIGEST');
if (!outputRoot.startsWith('/tmp/usf-materialisation-control-plane-proof')) throw new Error('proof output must use the bounded temporary proof root');

const require = createRequire(join(repo, 'tools/compiler/package.json'));
const { DataFactory } = require('n3');
const compilerModule = (name) => pathToFileURL(join(repo, `tools/compiler/src/${name}`));
const { authorityWitness } = await import(compilerModule('bootstrap.js'));
const { loadConfig } = await import(compilerModule('config.js'));
const { compile, checkLocal } = await import(compilerModule('compiler.js'));
const { loadAuthorityDataset } = await import(compilerModule('authority-dataset.js'));
const { loadManifest } = await import(compilerModule('manifest.js'));
const { createClient } = await import(compilerModule('stardog.js'));
const {
  digest, jcs, layoutContext, projectContract,
} = await import(compilerModule('materialisation.js'));
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
} = await import(compilerModule('authority-binding.js'));

const contract = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const proofResult = 'urn:usf:proofresult:repositorymaterialisationcontrolplane';
const decision = 'urn:usf:realisationdecision:repositoryarchitectureandnaming';
const realisation = 'urn:usf:realisation:repositoryarchitectureandnaming';
const ACTIVE = 'urn:usf:contractactivationstate:active';
const PROOF_BLOCKED = 'urn:usf:contractactivationstate:proofblocked';
const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
const ACCEPTED = 'urn:usf:decisionstate:accepted';
const { namedNode } = DataFactory;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
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

const manifest = loadManifest(join(repo, 'graph'));
checkLocal(manifest);
const candidateDataset = loadAuthorityDataset(manifest);
record('candidate-contract-active', ACTIVE, oneObject(candidateDataset.store, contract, 'urn:usf:ontology:hasActivationState'));
record('candidate-contract-relies-on-current-proof', proofResult, oneObject(candidateDataset.store, contract, 'urn:usf:ontology:reliesOnProofResult'));
record('candidate-realisation-implementable', 'urn:usf:realisationstate:implementable', oneObject(candidateDataset.store, realisation, 'urn:usf:ontology:realisationState'));

const candidate = await compile({ manifest, client, publicationMode: 'validate' });
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

const focusedTests = execFileSync('node', ['--test',
  'capabilities/repository-external-artefact-materialisation/materialisation-plan.test.mjs',
  'configuration/semantic-assurance/semantic-authority.test.mjs',
  'provider-bindings/stardog/semantic-authority.test.mjs',
  'processes/semantic-assurance/repository-materialisation-command.test.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.test.mjs',
  'tools/compiler/test/materialisation.test.js',
  'tools/compiler/test/mcp.test.js',
], {
  cwd: repo, encoding: 'utf8', env: { ...process.env, TZ: 'UTC', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' },
});
const focusedTestCount = Number(focusedTests.match(/# tests ([0-9]+)/)?.[1] || 0);
record('focused-control-plane-tests', 'passed', focusedTestCount > 0 && /# fail 0/.test(focusedTests) ? 'passed' : 'failed');

const implementationSources = sourceSetDigest([
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
  'tools/compiler/src/authority-binding.js',
  'tools/compiler/src/bootstrap.js',
  'tools/compiler/src/materialisation.js',
  'tools/compiler/src/mcp.js',
  'tools/compiler/test/materialisation.test.js',
  'tools/compiler/test/mcp.test.js',
]);
const proofAlgorithmSourceDigest = sha256(readFileSync(import.meta.filename));
cases.sort((left, right) => left.id.localeCompare(right.id));
const evidenceCore = {
  schemaVersion: 2,
  evaluatedAt,
  evaluatedAuthorityDigest,
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
  ok: cases.every((item) => item.passed),
  evaluatedAuthorityDigest,
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
