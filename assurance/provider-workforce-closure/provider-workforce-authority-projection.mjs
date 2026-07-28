#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify,
} from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  authorityDependencySetDigest,
} from '../../capabilities/semantic-model-compilation/authority-binding.mjs';
import {
  PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS,
  PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS,
  PROVIDER_WORKFORCE_PROOF_INPUT_PATHS,
  prepareExactSessionOutputRoot,
  verifyProviderMaterialisationAuthorityMutationEvidence,
  verifyProviderProofNodeDependencyEvidence,
} from './provider-materialisation-authority-mutations.mjs';
import {
  spawnPinnedLocalShaclRuntime,
  verifyPinnedPythonRuntimeEvidence,
} from '../semantic-model-compilation/local-shacl-validation.mjs';
import { assertSupportedPublicationReceipt } from '../../processes/semantic-assurance/publication-receipt.mjs';
import {
  MATERIALISATION_IMPLEMENTATION_SOURCE_PATHS,
  MATERIALISATION_PROOF_RUNNER_PATH,
  verifyMaterialisationProofAttestation,
} from './materialisation-proof-attestation-verifier.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const PROVIDER_PROOF_PATH = 'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs';
const PROVIDER_MUTATION_PATH = 'assurance/provider-workforce-closure/provider-materialisation-authority-mutations.mjs';
const PROVIDER_PROOF_SOURCE_PATHS = Object.freeze([
  PROVIDER_PROOF_PATH,
  PROVIDER_MUTATION_PATH,
  'assurance/provider-workforce-closure/materialisation-proof-attestation-verifier.mjs',
  'assurance/provider-workforce-closure/provider-workforce-authority-projection.mjs',
  'assurance/semantic-model-compilation/local-shacl-validation.mjs',
  'capabilities/semantic-model-compilation/authority-binding.mjs',
  'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
]);
const EVIDENCE_START = '# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE';
const EVIDENCE_END = '# END GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE';
const PROOF_START = '# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF';
const PROOF_END = '# END GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF';
const EVIDENCE_RESOURCE = '<urn:usf:externalpayloaddescriptor:providerworkforceauthorityevidence>';
const PROOF_RESOURCE = '<urn:usf:proofalgorithm:providerworkforceauthority>';
const APPLICATION_BINDINGS = new WeakMap();
const APPLICATION_ROLLBACKS = new WeakMap();
const PROJECTION_MATERIALISATION_ATTESTATIONS = new WeakMap();
export const PROVIDER_WORKFORCE_REQUIRED_CLAIMS = Object.freeze([
  'provider-secrets-remain-outside-git-and-semantic-authority',
  'environment-inspection-exposes-names-and-presence-only',
  'unknown-token-variables-are-not-loaded',
  'provider-calls-require-current-run-authorization',
  'zero-paid-budget-denies-paid-api-inference',
  'claude-codex-antigravity-subscription-transports-remain-distinct-from-paid-api-access',
  'openrouter-requires-explicit-free-zero-cost-identity-verified-routes',
  'ollama-is-operator-excluded-not-unavailable',
  'requested-and-actual-provider-and-model-identities-are-distinct-facts',
  'quota-and-rate-limit-outcomes-are-durable-availability-facts',
  'provider-failures-do-not-suppress-unrelated-providers',
  'model-specific-failures-remain-model-scoped',
  'missing-credentials-classify-token-required',
  'disabled-providers-remain-inventoried',
  'research-only-and-unbound-commands-cannot-contact-providers',
  'effective-policy-is-one-immutable-intersection',
  'eligible-assessment-population-drains-to-zero-unaccounted',
  'credential-values-do-not-enter-proof-output',
  'provider-materialisation-exact-files-and-directory-prefixes-are-disjoint',
  'provider-materialisation-authorises-write-file-only',
  'provider-materialisation-families-resolve-to-exact-format-role-naming-and-storage-rules',
  'provider-materialisation-permission-digest-binds-filename-acceptance',
  'provider-materialisation-scope-mode-is-contract-exact',
  'provider-materialisation-effective-decision-is-exact',
  'provider-materialisation-repository-and-directory-set-are-exact',
  'provider-materialisation-family-rule-tuples-are-exact',
  'provider-materialisation-hostile-mutations-fail-shacl-and-integrity',
  'legacy-materialisation-contracts-retain-unscoped-behaviour',
]);
export const PROVIDER_WORKFORCE_REQUIRED_CASES = Object.freeze([
  'factory-commit-exact',
  'factory-tree-exact',
  'factory-worktree-clean',
  'secrets-outside-git',
  'environment-file-ignored',
  'environment-names-only',
  'unknown-token-not-loaded',
  'run-authorization-at-provider-call',
  'zero-paid-budget-denial',
  'subscription-api-distinction',
  'openrouter-free-fail-closed',
  'ollama-operator-exclusion',
  'actual-identities-recorded',
  'model-quota-scope-preserved',
  'disabled-providers-inventoried',
  'research-command-unbound',
  'one-effective-policy-intersection',
  'fair-queue-complete-drain',
  'terminal-model-at-most-once',
  'missing-credential-token-required',
  'model-specific-terminal-scope',
  'availability-facts-durable',
  'provider-failure-isolated',
  'materialisation-exact-path-and-directory-prefix-disjoint',
  'materialisation-action-and-family-fail-closed',
  'materialisation-permission-digest-binds-naming',
  'provider-materialisation-semantic-scope-exact',
  'provider-materialisation-family-rules-exact',
  'legacy-materialisation-contracts-remain-unscoped',
  'provider-materialisation-hostile-mutations',
  'focused-pytest-runtime-closure-stable',
  'focused-deterministic-tests',
  'focused-deterministic-test-count',
  'focused-pytest-workload-runtime',
  'credential-values-absent-from-proof-output',
]);
const CONTRACTS = Object.freeze([
  Object.freeze({
    name: 'providerconfigurationplane',
    obligation: 'urn:usf:proofobligation:p7515b7117898c8bf9cedd38642fd544b19bd241c7e53cf392161edda5065843f',
    requirement: 'urn:usf:evidencerequirement:e8c6928a56f67bd7f0f379b43c026dc28acb991e045faceaae1160d13b2513050',
  }),
  Object.freeze({
    name: 'providerenvironmentclassification',
    obligation: 'urn:usf:proofobligation:p6fdcab8c78bc4d0a1ae49ebd9f1fae6d3ea03eb61c4226889f14d8e05a32ef03',
    requirement: 'urn:usf:evidencerequirement:e6bc2d48a0f6eae6eb793d4d7e026ad38589542c1d9973bd21823196da9d38371',
  }),
  Object.freeze({
    name: 'servicecatalogandproviderintegrationmodel',
    obligation: 'urn:usf:proofobligation:p3d210ec339c9c829e5b031b079ff8a95257db4b539185d8dc88ff58d726a5ecf',
    requirement: 'urn:usf:evidencerequirement:e81267ee8b57d047d9f92772d4899a060dde3e01480d51c3f26c5ba2f86a7e11d',
  }),
]);
const EVALUATION_CRITERIA = Object.freeze([
  'acquisitionandtotalcost',
  'availabilityandrecovery',
  'backupandrestore',
  'behaviourcoverage',
  'continuityandreplacement',
  'dataownershipandtransactions',
  'environmentcompatibility',
  'evidenceandprooffeasibility',
  'hermeticsubstitutefeasibility',
  'identitypermissiontenancyandprivacy',
  'licencecompatibility',
  'maintenanceburden',
  'negativeerrorandrecoverybehaviour',
  'observability',
  'operationalcomplexity',
  'performanceandresourceuse',
  'portability',
  'productionshapedstagingfeasibility',
  'providercompatibility',
  'reliabilityandfailurehandling',
  'scalability',
  'securityarchitecture',
  'semanticcontractfit',
  'semanticderivation',
  'supplychainrisk',
  'testability',
  'updateandpatchpolicy',
  'upgradeandrollback',
  'vendorlockinandexit',
  'versionstability',
  'vulnerabilityexposure',
]);

const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const HERMETIC_GIT_ENV = Object.freeze({
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  PATH: '/usr/bin:/bin',
  TZ: 'UTC',
  XDG_CONFIG_HOME: '/nonexistent',
});
const GIT_RUNTIME = Object.freeze({
  executablePath: '/usr/bin/git',
  resolvedExecutablePath: realpathSync('/usr/bin/git'),
  executableDigest: 'sha256:2540879925a6881e3877ff7e3330746ba3027b04edf16a3a12dccd1644c4f32d',
});
const GIT_RUNTIME_EVIDENCE = Object.freeze({
  schemaVersion: 1,
  executableDigest: GIT_RUNTIME.executableDigest,
  nativeObjectCount: 4,
  nativeObjectSetDigest: 'sha256:e94726f2d63131c39a6ef652c5368a50fca66686e1baf7ffbffd13f6ac86bc2e',
});
const q = (value) => JSON.stringify(String(value));
const iri = (value) => `<${value}>`;
const assert = (condition, code) => {
  if (!condition) throw new Error(code);
};
const exactDigest = (value, code) => {
  assert(typeof value === 'string' && SHA256.test(value), code);
  return value;
};
const exactCommit = (value, code) => {
  assert(typeof value === 'string' && COMMIT.test(value), code);
  return value;
};

function verifyGitRuntimeEvidence(evidence) {
  exactObjectKeys(evidence, [
    'schemaVersion',
    'executableDigest',
    'nativeObjectCount',
    'nativeObjectSetDigest',
  ], 'GIT_RUNTIME_EVIDENCE_FIELDS_INVALID');
  assert(canonicalJson(evidence) === canonicalJson(GIT_RUNTIME_EVIDENCE),
    'GIT_RUNTIME_EVIDENCE_INVALID');
  assert(sha256(readFileSync(GIT_RUNTIME.resolvedExecutablePath)) === GIT_RUNTIME.executableDigest,
    'GIT_EXECUTABLE_DIGEST_MISMATCH');
  const records = [
    '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
    '/usr/lib/x86_64-linux-gnu/libc.so.6',
    '/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2',
    '/usr/lib/x86_64-linux-gnu/libz.so.1.2.13',
  ].map((path) => {
    const resolvedPath = realpathSync(path);
    return {
      path: resolvedPath,
      digest: sha256(readFileSync(resolvedPath)),
      byteSize: lstatSync(resolvedPath).size,
    };
  });
  assert(sha256(canonicalJson(records)) === evidence.nativeObjectSetDigest,
    'GIT_NATIVE_OBJECT_SET_DIGEST_MISMATCH');
  return evidence;
}
const exactDateTime = (value, code) => {
  assert(typeof value === 'string' && DATE_TIME.test(value) && Number.isFinite(Date.parse(value)), code);
  return value;
};
const exactStringSet = (actual, expected, code) => {
  assert(Array.isArray(actual)
    && actual.length === expected.length
    && new Set(actual).size === actual.length
    && canonicalJson([...actual].sort(utf8Compare)) === canonicalJson([...expected].sort(utf8Compare)), code);
};
const exactObjectKeys = (value, expected, code) => {
  assert(value && typeof value === 'object' && !Array.isArray(value)
    && canonicalJson(Object.keys(value).sort(utf8Compare))
      === canonicalJson([...expected].sort(utf8Compare)), code);
};
const exactSafeCount = (value, code) => {
  assert(Number.isSafeInteger(value) && value >= 0, code);
  return value;
};
const allowedObjectKeys = (value, required, optional, code) => {
  const keys = value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value) : [];
  assert(required.every((key) => keys.includes(key))
    && keys.every((key) => required.includes(key) || optional.includes(key)), code);
};
function parseCanonicalJson(bytes, label) {
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`${label}_JSON_INVALID`);
  }
  assert(Buffer.from(canonicalJson(value)).equals(bytes), `${label}_NOT_CANONICAL_JSON`);
  return value;
}

const CANDIDATE_INVENTORY_ALGORITHM = 'sha256-rdfc10-managed-graph-inventory-v1';
const RAW_SHA256 = /^[0-9a-f]{64}$/;

export function verifyCandidatePublicationReceipt({
  receipt,
  receiptBytes,
  expectedAuthorityDigest = null,
}) {
  assert(Buffer.isBuffer(receiptBytes), 'CANDIDATE_PUBLICATION_RECEIPT_BYTES_REQUIRED');
  assert(receiptBytes.equals(Buffer.from(`${JSON.stringify(receipt)}\n`)),
    'CANDIDATE_PUBLICATION_RECEIPT_BYTES_NONCANONICAL');
  exactObjectKeys(receipt, [
    'receiptSchemaVersion',
    'mode',
    'ok',
    'commitOutcome',
    'contaminationCount',
    'graphsCleared',
    'authoredLoaded',
    'shapesLoaded',
    'authorityWitness',
  ], 'CANDIDATE_PUBLICATION_RECEIPT_FIELDS_INVALID');
  assert(receipt.receiptSchemaVersion === 2,
    'CANDIDATE_PUBLICATION_RECEIPT_SCHEMA_INVALID');
  assert(receipt.contaminationCount === 0,
    'CANDIDATE_PUBLICATION_CONTAMINATION_INVALID');
  exactSafeCount(receipt.graphsCleared, 'CANDIDATE_PUBLICATION_GRAPHS_CLEARED_INVALID');
  exactSafeCount(receipt.authoredLoaded, 'CANDIDATE_PUBLICATION_AUTHORED_LOADED_INVALID');
  exactSafeCount(receipt.shapesLoaded, 'CANDIDATE_PUBLICATION_SHAPES_LOADED_INVALID');
  exactObjectKeys(receipt.authorityWitness, [
    'algorithm',
    'totalSource',
    'expected',
    'evaluated',
    'beforePublication',
    'afterPublication',
    'settled',
  ], 'CANDIDATE_PUBLICATION_AUTHORITY_WITNESS_FIELDS_INVALID');
  for (const phase of ['beforePublication', 'afterPublication']) {
    exactObjectKeys(receipt.authorityWitness[phase], [
      'digest',
      'graphCount',
      'triples',
    ], `CANDIDATE_PUBLICATION_${phase.toUpperCase()}_FIELDS_INVALID`);
    exactSafeCount(receipt.authorityWitness[phase].graphCount,
      `CANDIDATE_PUBLICATION_${phase.toUpperCase()}_GRAPH_COUNT_INVALID`);
    exactSafeCount(receipt.authorityWitness[phase].triples,
      `CANDIDATE_PUBLICATION_${phase.toUpperCase()}_TRIPLES_INVALID`);
  }
  exactObjectKeys(receipt.authorityWitness.settled, [
    'digest',
    'graphCount',
    'triples',
    'stable',
  ], 'CANDIDATE_PUBLICATION_SETTLED_FIELDS_INVALID');
  exactSafeCount(receipt.authorityWitness.settled.graphCount,
    'CANDIDATE_PUBLICATION_SETTLED_GRAPH_COUNT_INVALID');
  exactSafeCount(receipt.authorityWitness.settled.triples,
    'CANDIDATE_PUBLICATION_SETTLED_TRIPLES_INVALID');
  assert(receipt.authorityWitness.settled.stable === true,
    'CANDIDATE_PUBLICATION_SETTLED_STABILITY_INVALID');
  assertSupportedPublicationReceipt(receipt);
  assert(receipt.mode === 'validate' && receipt.ok === true,
    'CANDIDATE_PUBLICATION_RECEIPT_NOT_SUCCESSFUL_VALIDATE');
  if (expectedAuthorityDigest !== null) {
    exactDigest(expectedAuthorityDigest, 'CANDIDATE_PUBLICATION_EXPECTED_AUTHORITY_INVALID');
    assert(receipt.authorityWitness.expected === expectedAuthorityDigest
      && receipt.authorityWitness.evaluated === expectedAuthorityDigest
      && receipt.authorityWitness.beforePublication.digest === expectedAuthorityDigest,
    'CANDIDATE_PUBLICATION_AUTHORITY_BINDING_MISMATCH');
  }
  const outcome = receipt.commitOutcome;
  exactObjectKeys(outcome, [
    'state',
    'exactCandidateStateVerified',
    'candidateDigest',
    'candidateGraphs',
    'publicationBudget',
  ], 'CANDIDATE_PUBLICATION_OUTCOME_FIELDS_INVALID');
  assert(outcome.state === 'validated-rolled-back'
    && outcome.exactCandidateStateVerified === true,
  'CANDIDATE_PUBLICATION_OUTCOME_INVALID');
  exactDigest(outcome.candidateDigest, 'CANDIDATE_PUBLICATION_DIGEST_INVALID');
  assert(Array.isArray(outcome.candidateGraphs) && outcome.candidateGraphs.length > 0,
    'CANDIDATE_PUBLICATION_GRAPH_INVENTORY_EMPTY');
  const seen = new Set();
  let previous = null;
  let candidateStatementCount = 0;
  const candidateGraphs = outcome.candidateGraphs.map((record) => {
    exactObjectKeys(record, ['graph', 'algorithm', 'digestAlgorithm', 'sha256', 'triples'],
      'CANDIDATE_PUBLICATION_GRAPH_FIELDS_INVALID');
    assert(typeof record.graph === 'string' && record.graph.startsWith('urn:usf:graph:'),
      'CANDIDATE_PUBLICATION_GRAPH_IRI_INVALID');
    assert(previous === null || utf8Compare(previous, record.graph) < 0,
      'CANDIDATE_PUBLICATION_GRAPH_ORDER_INVALID');
    assert(!seen.has(record.graph), 'CANDIDATE_PUBLICATION_GRAPH_DUPLICATE');
    assert(typeof record.sha256 === 'string' && RAW_SHA256.test(record.sha256),
      'CANDIDATE_PUBLICATION_GRAPH_DIGEST_INVALID');
    assert(record.algorithm === 'RDFC-1.0' && record.digestAlgorithm === 'sha256',
      'CANDIDATE_PUBLICATION_GRAPH_ALGORITHM_INVALID');
    assert(Number.isSafeInteger(record.triples) && record.triples >= 0,
      'CANDIDATE_PUBLICATION_GRAPH_TRIPLES_INVALID');
    seen.add(record.graph);
    previous = record.graph;
    candidateStatementCount += record.triples;
    assert(Number.isSafeInteger(candidateStatementCount),
      'CANDIDATE_PUBLICATION_STATEMENT_ARITHMETIC_INVALID');
    return Object.freeze({
      graph: record.graph,
      algorithm: record.algorithm,
      digestAlgorithm: record.digestAlgorithm,
      sha256: record.sha256,
      triples: record.triples,
    });
  });
  const candidateInventoryDigest = sha256(candidateGraphs
    .map(({ graph, sha256: graphDigest, triples }) => `${graph}=${graphDigest}:${triples}`)
    .join('\n'));
  assert(candidateInventoryDigest === outcome.candidateDigest,
    'CANDIDATE_PUBLICATION_INVENTORY_DIGEST_MISMATCH');
  for (const graph of SELF_PUBLICATION_EXCLUDED_GRAPHS) {
    assert(seen.has(graph), `CANDIDATE_PUBLICATION_EXCLUDED_GRAPH_ABSENT_${graph}`);
  }
  const budget = outcome.publicationBudget;
  exactObjectKeys(budget, [
    'authorityDigest',
    'baselineStatementCount',
    'candidateGraphWitnessDigest',
    'candidateStatementCount',
    'conservativeNoReplacementCredit',
    'hardStatementLimit',
    'maximumProjectedStatementCount',
    'policyDigest',
    'policyIri',
    'projectedStatementUpperBound',
    'provider',
    'reserveStatementCount',
    'budgetDigest',
    'result',
  ], 'CANDIDATE_PUBLICATION_BUDGET_FIELDS_INVALID');
  exactDigest(budget.authorityDigest, 'CANDIDATE_PUBLICATION_BUDGET_AUTHORITY_INVALID');
  exactDigest(budget.candidateGraphWitnessDigest, 'CANDIDATE_PUBLICATION_BUDGET_CANDIDATE_INVALID');
  exactDigest(budget.policyDigest, 'CANDIDATE_PUBLICATION_BUDGET_POLICY_DIGEST_INVALID');
  exactDigest(budget.budgetDigest, 'CANDIDATE_PUBLICATION_BUDGET_DIGEST_INVALID');
  assert(budget.authorityDigest === receipt.authorityWitness.expected
    && budget.baselineStatementCount === receipt.authorityWitness.beforePublication.triples
    && budget.candidateGraphWitnessDigest === candidateInventoryDigest
    && budget.candidateStatementCount === candidateStatementCount
    && budget.conservativeNoReplacementCredit === true
    && budget.provider === 'stardogcloudfree'
    && budget.hardStatementLimit === 1_000_000
    && Number.isSafeInteger(budget.reserveStatementCount)
    && budget.reserveStatementCount >= 1
    && budget.maximumProjectedStatementCount
      === budget.hardStatementLimit - budget.reserveStatementCount
    && typeof budget.policyIri === 'string'
    && budget.policyIri.startsWith('urn:usf:permutationpublicationbudget:')
    && budget.projectedStatementUpperBound
      === budget.baselineStatementCount + budget.candidateStatementCount
    && budget.projectedStatementUpperBound <= budget.maximumProjectedStatementCount
    && budget.result === 'PASS',
  'CANDIDATE_PUBLICATION_BUDGET_INVALID');
  const policyCore = {
    hardStatementLimit: budget.hardStatementLimit,
    maximumProjectedStatementCount: budget.maximumProjectedStatementCount,
    policyIri: budget.policyIri,
    provider: budget.provider,
    reserveStatementCount: budget.reserveStatementCount,
  };
  assert(budget.policyDigest === sha256(canonicalJson(policyCore)),
    'CANDIDATE_PUBLICATION_BUDGET_POLICY_DIGEST_MISMATCH');
  const { budgetDigest, result, ...budgetCore } = budget;
  assert(budgetDigest === sha256(canonicalJson(budgetCore)),
    'CANDIDATE_PUBLICATION_BUDGET_DIGEST_MISMATCH');
  return Object.freeze({
    candidateGraphs: Object.freeze(candidateGraphs),
    candidateInventoryAlgorithm: CANDIDATE_INVENTORY_ALGORITHM,
    candidateInventoryDigest,
    candidatePublicationReceiptDigest: sha256(receiptBytes),
    expectedAuthorityDigest: receipt.authorityWitness.expected,
  });
}

function deterministicIntegrityPublicKey() {
  const seed = createHash('sha256').update('provider-workforce-authority-integrity-key-v1').digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(privateKey);
}

function descriptor(receipt, field, bytes, mediaType) {
  const label = field.replace(/[A-Z]/g, (value) => `_${value}`).toUpperCase();
  const value = receipt[field];
  exactObjectKeys(value, ['digest', 'byteSize', 'mediaType', 'locator'], `${label}_DESCRIPTOR_FIELDS_INVALID`);
  const digest = exactDigest(value.digest, `${label}_DIGEST_INVALID`);
  assert(digest === sha256(bytes), `${label}_DIGEST_MISMATCH`);
  assert(value.byteSize === bytes.length, `${label}_BYTE_SIZE_MISMATCH`);
  assert(value.mediaType === mediaType, `${label}_MEDIA_TYPE_MISMATCH`);
  assert(value.locator === `cas://sha256/${digest.slice(7)}`, `${label}_LOCATOR_MISMATCH`);
  return Object.freeze({ digest, byteSize: bytes.length, mediaType, locator: value.locator });
}

function verifyEvidence(receipt, evidenceBytes) {
  const evidence = parseCanonicalJson(evidenceBytes, 'EVIDENCE');
  exactObjectKeys(evidence, [
    'schemaVersion',
    'recordKind',
    'passed',
    'eligibleForAdmission',
    'authorityClaims',
    'evaluatedAt',
    'validUntil',
    'evaluatedAuthorityDigest',
    'factoryCommit',
    'factoryTree',
    'implementationSourceDigest',
    'implementationSources',
    'proofInputSourceDigest',
    'proofInputSources',
    'proofAlgorithmSourceDigest',
    'proofAlgorithmSourceSetDigest',
    'proofAlgorithmSources',
    'runtimeDependencyEvidence',
    'runtimeDependencyEvidenceDigest',
    'materialisationAuthorityMutationEvidence',
    'environmentClass',
    'providerMode',
    'commands',
    'cases',
    'policyDigest',
    'populationDigest',
    'closureDigest',
    'nonclaims',
    'exactEvidenceSetDigest',
  ], 'EVIDENCE_FIELDS_INVALID');
  assert(evidence.schemaVersion === 3, 'EVIDENCE_SCHEMA_UNSUPPORTED');
  assert(evidence.recordKind === 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_CANDIDATE', 'EVIDENCE_KIND_INVALID');
  assert(evidence.passed === true && evidence.eligibleForAdmission === true, 'EVIDENCE_NOT_ELIGIBLE');
  exactStringSet(evidence.authorityClaims, PROVIDER_WORKFORCE_REQUIRED_CLAIMS, 'EVIDENCE_AUTHORITY_CLAIM_SET_MISMATCH');
  assert(canonicalJson(receipt.authorityClaims) === canonicalJson(evidence.authorityClaims),
    'RECEIPT_AUTHORITY_CLAIMS_MISMATCH');
  assert(Array.isArray(evidence.cases), 'EVIDENCE_CASES_INVALID');
  assert(evidence.cases.every((item) => {
    allowedObjectKeys(item, ['id', 'expected', 'observed', 'passed'], ['detail'], 'EVIDENCE_CASE_FIELDS_INVALID');
    return item.passed === true && typeof item.id === 'string';
  }), 'EVIDENCE_CASE_FAILED');
  exactStringSet(evidence.cases.map(({ id }) => id), PROVIDER_WORKFORCE_REQUIRED_CASES, 'EVIDENCE_CASE_SET_MISMATCH');
  assert(receipt.caseCount === evidence.cases.length, 'RECEIPT_CASE_COUNT_MISMATCH');
  verifyProviderMaterialisationAuthorityMutationEvidence(evidence.materialisationAuthorityMutationEvidence);
  exactObjectKeys(evidence.runtimeDependencyEvidence, ['git', 'node', 'python'],
    'RUNTIME_DEPENDENCY_EVIDENCE_FIELDS_INVALID');
  verifyGitRuntimeEvidence(evidence.runtimeDependencyEvidence.git);
  verifyProviderProofNodeDependencyEvidence(evidence.runtimeDependencyEvidence.node);
  verifyPinnedPythonRuntimeEvidence(evidence.runtimeDependencyEvidence.python);
  exactDigest(evidence.runtimeDependencyEvidenceDigest, 'RUNTIME_DEPENDENCY_EVIDENCE_DIGEST_INVALID');
  assert(evidence.runtimeDependencyEvidenceDigest === sha256(canonicalJson(evidence.runtimeDependencyEvidence)),
    'RUNTIME_DEPENDENCY_EVIDENCE_DIGEST_MISMATCH');
  const exactEvidenceSetDigest = exactDigest(evidence.exactEvidenceSetDigest, 'EVIDENCE_SET_DIGEST_INVALID');
  const { exactEvidenceSetDigest: omitted, ...evidenceCore } = evidence;
  assert(exactEvidenceSetDigest === sha256(canonicalJson(evidenceCore)), 'EVIDENCE_SET_DIGEST_MISMATCH');
  assert(receipt.exactEvidenceSetDigest === exactEvidenceSetDigest, 'RECEIPT_EVIDENCE_SET_DIGEST_MISMATCH');
  for (const key of [
    'evaluatedAuthorityDigest',
    'implementationSourceDigest',
    'proofInputSourceDigest',
    'proofAlgorithmSourceDigest',
    'proofAlgorithmSourceSetDigest',
    'runtimeDependencyEvidenceDigest',
    'policyDigest',
    'populationDigest',
    'closureDigest',
  ]) {
    exactDigest(evidence[key], `EVIDENCE_${key.toUpperCase()}_INVALID`);
    assert(receipt[key] === evidence[key], `RECEIPT_${key.toUpperCase()}_MISMATCH`);
  }
  exactCommit(evidence.factoryCommit, 'FACTORY_COMMIT_INVALID');
  exactCommit(evidence.factoryTree, 'FACTORY_TREE_INVALID');
  assert(receipt.factoryCommit === evidence.factoryCommit, 'RECEIPT_FACTORY_COMMIT_MISMATCH');
  assert(receipt.factoryTree === evidence.factoryTree, 'RECEIPT_FACTORY_TREE_MISMATCH');
  exactDateTime(evidence.evaluatedAt, 'EVIDENCE_EVALUATED_AT_INVALID');
  exactDateTime(evidence.validUntil, 'EVIDENCE_VALID_UNTIL_INVALID');
  assert(receipt.evaluatedAt === evidence.evaluatedAt, 'RECEIPT_EVALUATED_AT_MISMATCH');
  assert(receipt.validUntil === evidence.validUntil, 'RECEIPT_VALID_UNTIL_MISMATCH');
  assert(Date.parse(evidence.validUntil) > Date.parse(evidence.evaluatedAt), 'EVIDENCE_VALIDITY_INTERVAL_INVALID');
  assert(evidence.environmentClass === 'urn:usf:environmentclass:hermetic', 'EVIDENCE_ENVIRONMENT_INVALID');
  assert(evidence.providerMode === 'urn:usf:providermode:deterministictestsubstitute', 'EVIDENCE_PROVIDER_MODE_INVALID');
  assert(Array.isArray(evidence.implementationSources) && evidence.implementationSources.length > 0, 'IMPLEMENTATION_SOURCES_EMPTY');
  assert(evidence.implementationSources.every((record) => {
    exactObjectKeys(record, ['path', 'digest', 'byteSize'], 'IMPLEMENTATION_SOURCE_FIELDS_INVALID');
    const { path, digest, byteSize } = record;
    return typeof path === 'string'
      && path.length > 0
      && !path.startsWith('/')
      && !path.includes('\\')
      && path.split('/').every((segment) => segment.length > 0 && segment !== '.' && segment !== '..')
      && SHA256.test(digest) && Number.isInteger(byteSize) && byteSize >= 0;
  }), 'IMPLEMENTATION_SOURCE_RECORD_INVALID');
  assert(new Set(evidence.implementationSources.map(({ path }) => path)).size === evidence.implementationSources.length,
    'IMPLEMENTATION_SOURCE_PATH_DUPLICATE');
  assert(sha256(canonicalJson(evidence.implementationSources)) === evidence.implementationSourceDigest,
    'IMPLEMENTATION_SOURCE_SET_DIGEST_MISMATCH');
  assert(Array.isArray(evidence.proofInputSources) && evidence.proofInputSources.length > 0,
    'PROOF_INPUT_SOURCES_EMPTY');
  assert(evidence.proofInputSources.every((record) => {
    exactObjectKeys(record, ['path', 'digest', 'byteSize'], 'PROOF_INPUT_SOURCE_FIELDS_INVALID');
    const { path, digest, byteSize } = record;
    return typeof path === 'string'
      && path.length > 0
      && !path.startsWith('/')
      && !path.includes('\\')
      && path.split('/').every((segment) => segment.length > 0 && segment !== '.' && segment !== '..')
      && SHA256.test(digest) && Number.isInteger(byteSize) && byteSize >= 0;
  }), 'PROOF_INPUT_SOURCE_RECORD_INVALID');
  exactStringSet(evidence.proofInputSources.map(({ path }) => path), PROVIDER_WORKFORCE_PROOF_INPUT_PATHS,
    'PROOF_INPUT_SOURCE_SET_INVALID');
  assert(sha256(canonicalJson(evidence.proofInputSources)) === evidence.proofInputSourceDigest,
    'PROOF_INPUT_SOURCE_SET_DIGEST_MISMATCH');
  assert(Array.isArray(evidence.proofAlgorithmSources) && evidence.proofAlgorithmSources.length > 0, 'PROOF_ALGORITHM_SOURCES_EMPTY');
  assert(evidence.proofAlgorithmSources.every((record) => {
    exactObjectKeys(record, ['path', 'digest'], 'PROOF_ALGORITHM_SOURCE_FIELDS_INVALID');
    const { path, digest } = record;
    return typeof path === 'string'
      && path.length > 0
      && !path.startsWith('/')
      && !path.includes('\\')
      && path.split('/').every((segment) => segment.length > 0 && segment !== '.' && segment !== '..')
      && SHA256.test(digest);
  }), 'PROOF_ALGORITHM_SOURCE_RECORD_INVALID');
  exactStringSet(evidence.proofAlgorithmSources.map(({ path }) => path), PROVIDER_PROOF_SOURCE_PATHS,
    'PROOF_ALGORITHM_SOURCE_SET_INVALID');
  assert(sha256(canonicalJson(evidence.proofAlgorithmSources))
    === evidence.proofAlgorithmSourceSetDigest,
    'PROOF_ALGORITHM_SOURCE_SET_DIGEST_MISMATCH');
  const primaryAlgorithmSource = evidence.proofAlgorithmSources
    .find(({ path }) => path === PROVIDER_PROOF_PATH);
  assert(primaryAlgorithmSource?.digest === evidence.proofAlgorithmSourceDigest,
    'PROOF_ALGORITHM_PRIMARY_SOURCE_DIGEST_MISMATCH');
  return Object.freeze(evidence);
}

function verifyAttestation(receipt, evidence, evidenceDescriptor, attestationBytes) {
  const envelope = parseCanonicalJson(attestationBytes, 'ATTESTATION');
  exactObjectKeys(envelope, ['payloadType', 'payload', 'signatures'], 'ATTESTATION_FIELDS_INVALID');
  assert(envelope.payloadType === 'application/vnd.in-toto+json', 'ATTESTATION_PAYLOAD_TYPE_INVALID');
  assert(typeof envelope.payload === 'string', 'ATTESTATION_PAYLOAD_MISSING');
  assert(Array.isArray(envelope.signatures) && envelope.signatures.length === 1, 'ATTESTATION_SIGNATURE_COUNT_INVALID');
  const signature = envelope.signatures[0];
  exactObjectKeys(signature, ['keyid', 'sig'], 'ATTESTATION_SIGNATURE_FIELDS_INVALID');
  assert(typeof signature.keyid === 'string' && typeof signature.sig === 'string', 'ATTESTATION_SIGNATURE_INVALID');
  const publicKey = deterministicIntegrityPublicKey();
  const keyid = sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7);
  assert(signature.keyid === keyid && receipt.signingKeyFingerprint === keyid, 'ATTESTATION_KEY_ID_MISMATCH');
  const statementBytes = Buffer.from(envelope.payload, 'base64');
  const statement = parseCanonicalJson(statementBytes, 'ATTESTATION_STATEMENT');
  const payloadType = envelope.payloadType;
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `),
    statementBytes,
  ]);
  assert(verify(null, pae, publicKey, Buffer.from(signature.sig, 'base64')), 'ATTESTATION_SIGNATURE_VERIFICATION_FAILED');
  exactObjectKeys(statement, ['_type', 'subject', 'predicateType', 'predicate'], 'ATTESTATION_STATEMENT_FIELDS_INVALID');
  assert(statement._type === 'https://in-toto.io/Statement/v1', 'ATTESTATION_STATEMENT_TYPE_INVALID');
  assert(statement.predicateType === 'https://in-toto.io/attestation/test-result/v0.1',
    'ATTESTATION_PREDICATE_TYPE_INVALID');
  assert(Array.isArray(statement.subject) && statement.subject.length === 1, 'ATTESTATION_SUBJECT_COUNT_INVALID');
  exactObjectKeys(statement.subject[0], ['name', 'digest'], 'ATTESTATION_SUBJECT_FIELDS_INVALID');
  exactObjectKeys(statement.subject[0].digest, ['sha256'], 'ATTESTATION_SUBJECT_DIGEST_FIELDS_INVALID');
  assert(statement.subject[0]?.name === 'provider-workforce-authority-evidence', 'ATTESTATION_SUBJECT_NAME_INVALID');
  assert(statement.subject[0]?.digest?.sha256 === evidenceDescriptor.digest.slice(7), 'ATTESTATION_SUBJECT_DIGEST_MISMATCH');
  assert(statement.predicate?.evaluatedAuthorityDigest === evidence.evaluatedAuthorityDigest,
    'ATTESTATION_AUTHORITY_DIGEST_MISMATCH');
  assert(statement.predicate?.exactEvidenceSetDigest === evidence.exactEvidenceSetDigest,
    'ATTESTATION_EVIDENCE_SET_DIGEST_MISMATCH');
  assert(statement.predicate?.implementationSourceDigest === evidence.implementationSourceDigest,
    'ATTESTATION_IMPLEMENTATION_DIGEST_MISMATCH');
  assert(statement.predicate?.proofAlgorithmSourceDigest === evidence.proofAlgorithmSourceDigest,
    'ATTESTATION_ALGORITHM_DIGEST_MISMATCH');
  assert(statement.predicate?.proofAlgorithmSourceSetDigest === evidence.proofAlgorithmSourceSetDigest,
    'ATTESTATION_ALGORITHM_SOURCE_SET_DIGEST_MISMATCH');
  assert(statement.predicate?.proofInputSourceDigest === evidence.proofInputSourceDigest,
    'ATTESTATION_PROOF_INPUT_DIGEST_MISMATCH');
  assert(statement.predicate?.runtimeDependencyEvidenceDigest === evidence.runtimeDependencyEvidenceDigest,
    'ATTESTATION_RUNTIME_DEPENDENCY_DIGEST_MISMATCH');
  exactObjectKeys(statement.predicate, [
    'evaluatedAuthorityDigest',
    'exactEvidenceSetDigest',
    'implementationSourceDigest',
    'proofInputSourceDigest',
    'proofAlgorithmSourceDigest',
    'proofAlgorithmSourceSetDigest',
    'runtimeDependencyEvidenceDigest',
    'result',
  ], 'ATTESTATION_PREDICATE_FIELDS_INVALID');
  assert(statement.predicate?.result === 'passed', 'ATTESTATION_RESULT_NOT_PASSED');
  return Object.freeze({ envelope, signature, statement });
}

function scopeManifest({ evidence, evidenceDescriptor, classification }) {
  const deterministic = classification === 'deterministicevaluation';
  const core = deterministic ? {
    classification,
    evidenceDigest: evidenceDescriptor.digest,
    proofInputSourceDigest: evidence.proofInputSourceDigest,
    proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
    proofAlgorithmSourceSetDigest: evidence.proofAlgorithmSourceSetDigest,
    runtimeDependencyEvidenceDigest: evidence.runtimeDependencyEvidenceDigest,
    authorityClaims: [...evidence.authorityClaims].sort(utf8Compare),
    caseIds: evidence.cases.map(({ id }) => id).sort(utf8Compare),
  } : {
    classification,
    evidenceDigest: evidenceDescriptor.digest,
    implementationSourceDigest: evidence.implementationSourceDigest,
    proofInputSourceDigest: evidence.proofInputSourceDigest,
    runtimeDependencyEvidenceDigest: evidence.runtimeDependencyEvidenceDigest,
    factoryCommit: evidence.factoryCommit,
    factoryTree: evidence.factoryTree,
    implementationSources: evidence.implementationSources,
  };
  return Object.freeze({
    classification,
    digest: sha256(canonicalJson(core)),
    providerIdentity: deterministic
      ? 'urn:usf:provideridentity:repositorylocalevaluator'
      : 'urn:usf:provideridentity:repositorylocalacquisition',
    claimBoundary: deterministic
      ? `Deterministic reference algorithms and ${evidence.cases.length} passing fail-closed boundary cases.`
      : `Exact clean factory commit and tree with ${evidence.implementationSources.length} digest-bound implementation sources.`,
    prohibitedClaim: deterministic
      ? 'Does not establish provider availability, authenticate an account, validate a future factory implementation, or establish production readiness.'
      : 'Does not admit mutable quota state, credentials, provider responses, external model identity or production validation.',
  });
}

function evidenceProjection({ receipt, evidence, evidenceDescriptor, attestationDescriptor, attestation }) {
  const contracts = CONTRACTS.map(({ name }) => iri(`urn:usf:semanticcontract:${name}`)).join(', ');
  const obligations = CONTRACTS.map(({ obligation }) => iri(obligation)).join(', ');
  const collections = CONTRACTS.map(({ name }) => iri(`urn:usf:evidencecollection:providerworkforceauthority${name}`)).join(', ');
  const criteria = EVALUATION_CRITERIA.map((name) => iri(`urn:usf:evaluationcriterion:${name}`)).join(', ');
  const deterministic = scopeManifest({ evidence, evidenceDescriptor, classification: 'deterministicevaluation' });
  const hermetic = scopeManifest({ evidence, evidenceDescriptor, classification: 'hermeticlocal' });
  const lines = [];
  lines.push(`${EVIDENCE_RESOURCE} a usf:ExternalPayloadDescriptor;`);
  lines.push('  usf:canonicalName "providerworkforceauthorityevidence";');
  lines.push('  usf:descriptorArtefactFamily <urn:usf:artefactfamily:evidencepayload>;');
  lines.push('  usf:descriptorRepresentationFormat <urn:usf:representationformat:jsondata8259>;');
  lines.push(`  usf:descriptorMediaType ${q(evidenceDescriptor.mediaType)};`);
  lines.push(`  usf:descriptorDigest ${q(evidenceDescriptor.digest)};`);
  lines.push(`  usf:descriptorByteSize ${evidenceDescriptor.byteSize};`);
  lines.push(`  usf:descriptorLocator ${q(evidenceDescriptor.locator)}^^xsd:anyURI;`);
  lines.push('  usf:descriptorArtefactType "urn:usf:artefacttype:providerworkforceauthorityevidence"^^xsd:anyURI;');
  lines.push('  usf:descriptorStorageClass <urn:usf:storageclass:contentaddressedobjectstorage>.');
  lines.push('<urn:usf:externalpayloaddescriptor:providerworkforceauthorityattestation> a usf:ExternalPayloadDescriptor;');
  lines.push('  usf:canonicalName "providerworkforceauthorityattestation";');
  lines.push('  usf:descriptorArtefactFamily <urn:usf:artefactfamily:proofexecutionattestation>;');
  lines.push('  usf:descriptorRepresentationFormat <urn:usf:representationformat:intotostatementjson>;');
  lines.push(`  usf:descriptorMediaType ${q(attestationDescriptor.mediaType)};`);
  lines.push(`  usf:descriptorDigest ${q(attestationDescriptor.digest)};`);
  lines.push(`  usf:descriptorByteSize ${attestationDescriptor.byteSize};`);
  lines.push(`  usf:descriptorLocator ${q(attestationDescriptor.locator)}^^xsd:anyURI;`);
  lines.push('  usf:descriptorArtefactType "urn:usf:artefacttype:providerworkforceauthorityattestation"^^xsd:anyURI;');
  lines.push('  usf:descriptorStorageClass <urn:usf:storageclass:contentaddressedobjectstorage>.');
  lines.push('<urn:usf:signingidentity:providerworkforceauthorityintegrity> a usf:SigningIdentity;');
  lines.push('  usf:canonicalName "providerworkforceauthorityintegrity";');
  lines.push(`  usf:signingKeyFingerprint ${q(receipt.signingKeyFingerprint)}.`);
  lines.push('<urn:usf:signature:providerworkforceauthorityattestation> a usf:Signature;');
  lines.push('  usf:canonicalName "providerworkforceauthorityattestation";');
  lines.push('  usf:artefactKind <urn:usf:artefactkind:signature>;');
  lines.push(`  usf:canonicalPath ${q(`${attestationDescriptor.locator}#signature`)};`);
  lines.push('  usf:governedByPathRule <urn:usf:pathrule:contentaddressedsignature>;');
  lines.push('  usf:signatureMethod <urn:usf:signaturemethod:enveloped>;');
  lines.push('  usf:signingPolicy <urn:usf:policy:hermeticevidenceattestation>;');
  lines.push('  usf:signedBy <urn:usf:signingidentity:providerworkforceauthorityintegrity>;');
  lines.push(`  usf:signatureValue ${q(attestation.signature.sig)}.`);
  lines.push('<urn:usf:checksum:providerworkforceauthorityevidence> a usf:Checksum;');
  lines.push('  usf:canonicalName "providerworkforceauthorityevidence";');
  lines.push('  usf:checksumAlgorithm <urn:usf:checksumalgorithm:sha256>;');
  lines.push(`  usf:checksumValue ${q(evidenceDescriptor.digest.slice(7))}.`);
  for (const [name, scope] of [['providerworkforcedeterministicevaluation', deterministic], ['providerworkforcehermeticlocal', hermetic]]) {
    lines.push(`<urn:usf:evidencescopemanifest:${name}> a usf:EvidenceScopeManifest;`);
    lines.push(`  usf:canonicalName ${q(name)};`);
    lines.push(`  usf:evidenceScopeClassification <urn:usf:evidencescopeclassification:${scope.classification}>;`);
    lines.push(`  usf:scopeProviderIdentity <${scope.providerIdentity}>;`);
    lines.push(`  usf:scopeManifestDigest ${q(scope.digest)};`);
    lines.push(`  usf:scopeDescriptorDigest ${q(evidenceDescriptor.digest)};`);
    lines.push(`  usf:scopeCollectorDigest ${q(evidence.proofAlgorithmSourceDigest)};`);
    lines.push(`  usf:scopeClaimBoundary ${q(scope.claimBoundary)};`);
    lines.push(`  usf:scopeProhibitedClaim ${q(scope.prohibitedClaim)};`);
    lines.push(`  usf:scopeSupportsCriterion ${criteria}.`);
  }
  lines.push('<urn:usf:validatorrule:validateproviderworkforceauthority> a usf:ValidatorRule;');
  lines.push('  usf:canonicalName "validateproviderworkforceauthority";');
  lines.push('  usf:resultCode "providerworkforceauthorityclosure";');
  lines.push('  usf:targetsGraph <urn:usf:namedgraph:capabilities>, <urn:usf:namedgraph:evidence>, <urn:usf:namedgraph:bindings>, <urn:usf:namedgraph:proofs>;');
  lines.push('  usf:validatorSeverity <urn:usf:severity:blocking>.');
  lines.push('evr:providerworkforceauthority a usf:EvidenceResult;');
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push('  usf:evidenceKind evk:runtimeproofevidence;');
  lines.push('  usf:hasFreshness fresh:fresh;');
  lines.push(`  usf:evidenceForContract ${contracts};`);
  lines.push(`  usf:evidenceFor ${contracts};`);
  lines.push(`  usf:contentDigest ${q(evidenceDescriptor.digest)};`);
  lines.push(`  usf:evaluatedAuthorityDigest ${q(evidence.evaluatedAuthorityDigest)};`);
  lines.push(`  usf:evidenceProducerDigest ${q(evidence.proofAlgorithmSourceDigest)};`);
  lines.push(`  usf:mediaType ${q(evidenceDescriptor.mediaType)};`);
  lines.push(`  usf:byteSize ${evidenceDescriptor.byteSize};`);
  lines.push(`  usf:storageLocator ${q(evidenceDescriptor.locator)}^^xsd:anyURI;`);
  lines.push('  usf:wasProducedBy <urn:usf:validatorrule:validateproviderworkforceauthority>;');
  lines.push(`  usf:collectedAt ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
  lines.push(`  usf:validUntil ${q(evidence.validUntil)}^^xsd:dateTime;`);
  lines.push('  usf:hasFreshnessPolicy <urn:usf:evidencefreshnesspolicy:providerworkforcethirtydays>;');
  lines.push('  usf:hasAdmissionState admission:admitted;');
  lines.push('  usf:hasFreshnessState freshnessstate:fresh;');
  lines.push('  usf:hasIntegrityState integritystate:valid;');
  lines.push('  usf:evidenceStage <urn:usf:evidencestage:emitted>, <urn:usf:evidencestage:collected>, <urn:usf:evidencestage:normalised>, <urn:usf:evidencestage:ingested>, <urn:usf:evidencestage:signed>, <urn:usf:evidencestage:integrityverified>;');
  lines.push('  usf:usesProviderMode pmode:deterministictestsubstitute;');
  lines.push('  usf:inEnvironment env:hermetic;');
  lines.push(`  usf:collectedBy ${collections};`);
  lines.push('  usf:normalisedBy <urn:usf:evidencenormalisation:providerworkforceauthority>;');
  lines.push('  usf:ingestedBy <urn:usf:evidenceingestion:providerworkforceauthority>;');
  lines.push('  usf:evidenceSignature <urn:usf:signature:providerworkforceauthorityattestation>;');
  lines.push('  usf:evidenceChecksum <urn:usf:checksum:providerworkforceauthorityevidence>;');
  lines.push('  usf:integrityVerification <urn:usf:integrityverification:providerworkforceauthority>;');
  lines.push(`  usf:applicableToObligation ${obligations};`);
  lines.push('  usf:withinValidityScope true.');
  lines.push('evr:providerworkforcedecisionevaluation a usf:EvidenceResult, usf:CompositeEvidenceResult;');
  lines.push('  usf:canonicalName "providerworkforcedecisionevaluation";');
  lines.push('  usf:evidenceKind evk:attestation;');
  lines.push('  usf:hasFreshness fresh:fresh;');
  lines.push(`  usf:evidenceForContract ${contracts};`);
  lines.push(`  usf:evidenceFor ${contracts};`);
  lines.push(`  usf:contentDigest ${q(evidenceDescriptor.digest)};`);
  lines.push(`  usf:evaluatedAuthorityDigest ${q(evidence.evaluatedAuthorityDigest)};`);
  lines.push(`  usf:evidenceProducerDigest ${q(evidence.proofAlgorithmSourceDigest)};`);
  lines.push(`  usf:mediaType ${q(evidenceDescriptor.mediaType)};`);
  lines.push(`  usf:byteSize ${evidenceDescriptor.byteSize};`);
  lines.push(`  usf:storageLocator ${q(evidenceDescriptor.locator)}^^xsd:anyURI;`);
  lines.push('  usf:wasProducedBy <urn:usf:validatorrule:validateproviderworkforceauthority>;');
  lines.push(`  usf:collectedAt ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
  lines.push(`  usf:validUntil ${q(evidence.validUntil)}^^xsd:dateTime;`);
  lines.push('  usf:hasFreshnessPolicy <urn:usf:evidencefreshnesspolicy:providerworkforcethirtydays>;');
  lines.push('  usf:hasAdmissionState admission:admitted;');
  lines.push('  usf:hasFreshnessState freshnessstate:fresh;');
  lines.push('  usf:hasIntegrityState integritystate:valid;');
  lines.push('  usf:evidenceStage <urn:usf:evidencestage:emitted>, <urn:usf:evidencestage:collected>, <urn:usf:evidencestage:normalised>, <urn:usf:evidencestage:ingested>, <urn:usf:evidencestage:signed>, <urn:usf:evidencestage:integrityverified>;');
  lines.push('  usf:collectedBy <urn:usf:evidencecollection:providerworkforcedecisionevaluation>;');
  lines.push('  usf:normalisedBy <urn:usf:evidencenormalisation:providerworkforceauthority>;');
  lines.push('  usf:ingestedBy <urn:usf:evidenceingestion:providerworkforceauthority>;');
  lines.push('  usf:evidenceSignature <urn:usf:signature:providerworkforceauthorityattestation>;');
  lines.push('  usf:evidenceChecksum <urn:usf:checksum:providerworkforceauthorityevidence>;');
  lines.push('  usf:integrityVerification <urn:usf:integrityverification:providerworkforcedecisionevaluation>;');
  lines.push('  usf:hasSupportingEvidenceManifest <urn:usf:evidencescopemanifest:providerworkforcedeterministicevaluation>, <urn:usf:evidencescopemanifest:providerworkforcehermeticlocal>;');
  lines.push('  usf:withinValidityScope true.');
  lines.push('<urn:usf:evidencefreshnesspolicy:providerworkforcethirtydays> a usf:EvidenceRetentionPolicy;');
  lines.push('  usf:canonicalName "providerworkforcethirtydays".');
  for (const name of ['providerworkforceauthority', 'providerworkforcedecisionevaluation']) {
    lines.push(`<urn:usf:evidenceadmission:${name}> a usf:EvidenceAdmission;`);
    lines.push(`  usf:canonicalName ${q(name)};`);
    lines.push(`  usf:admissionForEvidence evr:${name};`);
    lines.push('  usf:admissionDecidedByValidator <urn:usf:validatorrule:validateproviderworkforceauthority>.');
  }
  for (const { name, requirement } of CONTRACTS) {
    const collection = `providerworkforceauthority${name}`;
    lines.push(`<urn:usf:evidencecollection:${collection}> a usf:EvidenceCollection;`);
    lines.push(`  usf:canonicalName ${q(collection)};`);
    lines.push(`  usf:collectionForRequirement <${requirement}>;`);
    lines.push('  usf:collectedEvidence evr:providerworkforceauthority;');
    lines.push('  usf:collectsEvidence evr:providerworkforceauthority;');
    lines.push(`  usf:collectedOn ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
    lines.push(`  usf:sourceDigest ${q(receipt.dependencySetDigest)}.`);
  }
  lines.push('<urn:usf:evidencecollection:providerworkforcedecisionevaluation> a usf:EvidenceCollection;');
  lines.push('  usf:canonicalName "providerworkforcedecisionevaluation";');
  lines.push('  usf:collectedEvidence evr:providerworkforcedecisionevaluation;');
  lines.push('  usf:collectsEvidence evr:providerworkforcedecisionevaluation;');
  lines.push(`  usf:collectedOn ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
  lines.push(`  usf:sourceDigest ${q(receipt.dependencySetDigest)}.`);
  lines.push('<urn:usf:evidencenormalisation:providerworkforceauthority> a usf:EvidenceNormalisation;');
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push('  usf:normalisesEvidence evr:providerworkforceauthority, evr:providerworkforcedecisionevaluation.');
  lines.push('<urn:usf:evidenceingestion:providerworkforceauthority> a usf:EvidenceIngestion;');
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push('  usf:ingestsEvidence evr:providerworkforceauthority, evr:providerworkforcedecisionevaluation.');
  for (const name of ['providerworkforceauthority', 'providerworkforcedecisionevaluation']) {
    lines.push(`<urn:usf:integrityverification:${name}> a usf:IntegrityVerification;`);
    lines.push(`  usf:canonicalName ${q(name)};`);
    lines.push(`  usf:verifiesEvidence evr:${name};`);
    lines.push('  usf:verificationState <urn:usf:resultstate:passed>.');
  }
  return `${lines.join('\n')}\n`;
}

function proofProjection({
  evidence,
  evidenceDescriptor,
  attestationDescriptor,
  dependencySetDigest,
  dependencyDigestAlgorithm,
  proofProducerCommit,
  proofProducerTree,
  algorithmVersion,
  reevaluationState,
  settledAuthorityDigest,
  reevaluatedAt,
}) {
  const algorithmVersionIri =
    `urn:usf:proofalgorithmversion:providerworkforceauthority${evidence.proofAlgorithmSourceSetDigest.slice(7)}`;
  const primaryAlgorithmSourceDigest = evidence.proofAlgorithmSources
    .find(({ path }) => path === PROVIDER_PROOF_PATH).digest;
  const contracts = CONTRACTS.map(({ name }) => iri(`urn:usf:semanticcontract:${name}`)).join(', ');
  const excluded = SELF_PUBLICATION_EXCLUDED_GRAPHS.map((value) => `${q(value)}^^xsd:anyURI`).join(', ');
  const lines = [];
  lines.push('<urn:usf:nonclaim:providerworkforceproofisfactoryvalidation> a usf:NonClaim;');
  lines.push('  usf:canonicalName "providerworkforceproofisfactoryvalidation".');
  lines.push('<urn:usf:nonclaim:providerworkforceproofisproductionreadiness> a usf:NonClaim;');
  lines.push('  usf:canonicalName "providerworkforceproofisproductionreadiness".');
  lines.push(`${PROOF_RESOURCE} a usf:ProofAlgorithm;`);
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push(`  usf:proofAlgorithmSourcePath ${q(PROVIDER_PROOF_PATH)};`);
  lines.push(`  usf:proofAlgorithmSourceDigest ${q(primaryAlgorithmSourceDigest)};`);
  lines.push(`  usf:proofAlgorithmSourceSetDigest ${q(evidence.proofAlgorithmSourceSetDigest)};`);
  lines.push(`  usf:currentAlgorithmVersion <${algorithmVersionIri}>;`);
  lines.push(`  usf:currentAlgorithmSourceDigest ${q(primaryAlgorithmSourceDigest)};`);
  lines.push(`  usf:currentAlgorithmSourceSetDigest ${q(evidence.proofAlgorithmSourceSetDigest)};`);
  lines.push(`  usf:currentImplementationSourceSetDigest ${q(evidence.implementationSourceDigest)};`);
  lines.push(`  usf:currentDependencySetDigest ${q(dependencySetDigest)};`);
  lines.push(`  usf:currentDependencyDigestAlgorithm ${q(dependencyDigestAlgorithm)};`);
  lines.push('  usf:requiresGraphSourceBinding true.');
  lines.push(`<${algorithmVersionIri}> a usf:ProofAlgorithmVersion;`);
  lines.push(`  usf:canonicalName ${q(`providerworkforceauthority${evidence.proofAlgorithmSourceSetDigest.slice(7)}`)};`);
  lines.push('  usf:proofAlgorithmVersionOf <urn:usf:proofalgorithm:providerworkforceauthority>;');
  lines.push(`  usf:proofAlgorithmVersionSourceSetDigest ${q(evidence.proofAlgorithmSourceSetDigest)};`);
  lines.push(`  usf:proofAlgorithmVersionIdentifier ${q(algorithmVersion)}.`);
  lines.push('<urn:usf:proof:providerworkforceauthority> a usf:Proof;');
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push('  usf:atRung rung:behaviour;');
  lines.push('  usf:usesProviderMode pmode:deterministictestsubstitute;');
  lines.push('  usf:inEnvironment env:hermetic;');
  lines.push(`  usf:exercises ${contracts};`);
  lines.push(`  usf:provesSubject ${contracts}.`);
  for (const { name, obligation } of CONTRACTS) {
    const suffix = `providerworkforceauthority${name}`;
    const resultIri = `urn:usf:proofresult:${suffix}`;
    const bindingIri = `urn:usf:proofauthoritybinding:${suffix}`;
    lines.push(`<urn:usf:proofexecution:${suffix}> a usf:ProofExecution;`);
    lines.push(`  usf:canonicalName ${q(suffix)};`);
    lines.push('  usf:executesProof <urn:usf:proof:providerworkforceauthority>;');
    lines.push(`  usf:producesResult <${resultIri}>.`);
    lines.push(`<urn:usf:proofevaluation:${suffix}> a usf:ProofEvaluation;`);
    lines.push(`  usf:canonicalName ${q(suffix)};`);
    lines.push(`  usf:evaluatesObligation <${obligation}>;`);
    lines.push(`  usf:producesProofResult <${resultIri}>.`);
    lines.push(`<${resultIri}> a usf:ProofResult;`);
    lines.push(`  usf:canonicalName ${q(suffix)};`);
    lines.push('  usf:resultState rs:passed;');
    lines.push('  usf:resultForProof <urn:usf:proof:providerworkforceauthority>;');
    lines.push('  usf:claimedRung rung:behaviour;');
    lines.push('  usf:observedRung rung:behaviour;');
    lines.push('  usf:hasFreshness fresh:fresh;');
    lines.push('  usf:usesProviderMode pmode:deterministictestsubstitute;');
    lines.push('  usf:inEnvironment env:hermetic;');
    lines.push('  usf:hasProofResultState <urn:usf:proofresultstate:successful>;');
    lines.push(`  usf:proofResultForObligation <${obligation}>;`);
    lines.push('  usf:usesAdmittedEvidence <urn:usf:evidenceresult:providerworkforceauthority>;');
    lines.push(`  usf:evidenceSetDigest ${q(evidence.exactEvidenceSetDigest)};`);
    lines.push('  usf:usesProofAlgorithm <urn:usf:proofalgorithm:providerworkforceauthority>;');
    lines.push(`  usf:usesAlgorithmVersion <${algorithmVersionIri}>;`);
    lines.push(`  usf:algorithmSourceSetDigest ${q(evidence.proofAlgorithmSourceSetDigest)};`);
    lines.push(`  usf:implementationSourceSetDigest ${q(evidence.implementationSourceDigest)};`);
    lines.push(`  usf:dependencySetDigest ${q(dependencySetDigest)};`);
    lines.push(`  usf:dependencyDigestAlgorithm ${q(dependencyDigestAlgorithm)};`);
    lines.push(`  usf:proofProducerCommit ${q(proofProducerCommit)};`);
    lines.push(`  usf:proofProducerTree ${q(proofProducerTree)};`);
    lines.push('  usf:evaluatedByValidator <urn:usf:validatorrule:validateproviderworkforceauthority>;');
    lines.push('  usf:proofExecutionEnvironment env:hermetic;');
    lines.push('  usf:hasConfidenceState <urn:usf:proofconfidencestate:warranted>;');
    lines.push('  usf:confidenceBasis <urn:usf:evidenceresult:providerworkforceauthority>;');
    lines.push(`  usf:uncertaintyStatement ${q(`This result proves only the bounded provider-workforce authority claims observed at factory commit ${evidence.factoryCommit}; it does not validate the future provider expansion implementation or establish provider or production availability.`)};`);
    lines.push('  usf:proofNonclaim <urn:usf:nonclaim:providerworkforceproofisfactoryvalidation>, <urn:usf:nonclaim:providerworkforceproofisproductionreadiness>;');
    lines.push(`  usf:evaluatedAt ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
    lines.push(`  usf:hasAuthorityBinding <${bindingIri}>;`);
    lines.push('  usf:hasInvalidationCondition <urn:usf:proofinvalidationcondition:evidenceinvalidated>, <urn:usf:proofinvalidationcondition:evidencestale>, <urn:usf:proofinvalidationcondition:authoritydigestchanged>.');
    lines.push(`<${bindingIri}> a usf:ProofAuthorityBinding;`);
    lines.push(`  usf:canonicalName ${q(suffix)};`);
    lines.push(`  usf:bindingEvaluatedAuthorityDigest ${q(evidence.evaluatedAuthorityDigest)};`);
    lines.push(`  usf:bindingDependencySetDigest ${q(dependencySetDigest)};`);
    lines.push(`  usf:bindingDependencyDigestAlgorithm ${q(dependencyDigestAlgorithm)};`);
    lines.push('  usf:usesAuthorityBindingRule <urn:usf:authoritybindingrule:selfpublicationclosure>;');
    lines.push('  usf:requiresPostPublicationReevaluation true;');
    lines.push(`  usf:authorityBindingEvidenceDigest ${q(attestationDescriptor.digest)};`);
    lines.push(`  usf:hasPostPublicationReevaluationState <urn:usf:proofreevaluationstate:${reevaluationState}>;`);
    if (reevaluationState === 'successful') {
      lines.push(`  usf:reevaluationSettledAuthorityDigest ${q(settledAuthorityDigest)};`);
      lines.push(`  usf:reevaluationDependencySetDigest ${q(dependencySetDigest)};`);
      lines.push(`  usf:reevaluationEvidenceDigest ${q(attestationDescriptor.digest)};`);
      lines.push(`  usf:reevaluatedAt ${q(reevaluatedAt)}^^xsd:dateTime;`);
    }
    lines.push(`  usf:excludedAuthorityGraphIri ${excluded}.`);
  }
  return `${lines.join('\n')}\n`;
}

export function projectProviderWorkforceAuthorityReceipt({
  receipt,
  evidenceBytes,
  attestationBytes,
  materialisationReceipt,
  materialisationReceiptBytes,
  materialisationEvidenceBytes,
  materialisationAttestationBytes,
  candidatePublicationReceipt,
  candidatePublicationReceiptBytes,
  proofProducerCommit,
  proofProducerTree,
  algorithmVersion,
  observedAt,
  reevaluationState = 'pending',
  settledAuthorityDigest = null,
  reevaluatedAt = null,
}) {
  exactObjectKeys(receipt, [
    'schemaVersion',
    'recordKind',
    'ok',
    'passed',
    'eligibleForAdmission',
    'authorityClaims',
    'evaluatedAuthorityDigest',
    'evaluatedAt',
    'validUntil',
    'factoryCommit',
    'factoryTree',
    'implementationSourceDigest',
    'proofInputSourceDigest',
    'proofAlgorithmSourceDigest',
    'proofAlgorithmSourceSetDigest',
    'runtimeDependencyEvidenceDigest',
    'exactEvidenceSetDigest',
    'policyDigest',
    'populationDigest',
    'closureDigest',
    'caseCount',
    'evidenceManifest',
    'proofAttestation',
    'signingKeyFingerprint',
    'outputRoot',
  ], 'RECEIPT_FIELDS_INVALID');
  assert(receipt.schemaVersion === 3, 'RECEIPT_SCHEMA_UNSUPPORTED');
  assert(receipt.recordKind === 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_RECEIPT', 'RECEIPT_KIND_INVALID');
  assert(receipt.ok === true && receipt.passed === true && receipt.eligibleForAdmission === true, 'RECEIPT_NOT_ELIGIBLE');
  assert(receipt.outputRoot === 'SESSION_TRANSIENT_OUTPUT_ROOT',
    'RECEIPT_OUTPUT_ROOT_SENTINEL_INVALID');
  exactCommit(proofProducerCommit, 'PROOF_PRODUCER_COMMIT_INVALID');
  exactCommit(proofProducerTree, 'PROOF_PRODUCER_TREE_INVALID');
  assert(typeof algorithmVersion === 'string' && /^\d+\.\d+\.\d+$/.test(algorithmVersion), 'ALGORITHM_VERSION_INVALID');
  exactDateTime(observedAt, 'OBSERVED_AT_INVALID');
  assert(reevaluationState === 'pending' || reevaluationState === 'successful', 'REEVALUATION_STATE_INVALID');
  if (reevaluationState === 'successful') {
    exactDigest(settledAuthorityDigest, 'SETTLED_AUTHORITY_DIGEST_INVALID');
    exactDateTime(reevaluatedAt, 'REEVALUATED_AT_INVALID');
    assert(settledAuthorityDigest === receipt.evaluatedAuthorityDigest, 'SETTLED_AUTHORITY_DIGEST_MISMATCH');
  } else {
    assert(settledAuthorityDigest === null && reevaluatedAt === null, 'PENDING_REEVALUATION_HAS_SETTLED_FIELDS');
  }
  const evidenceDescriptor = descriptor(receipt, 'evidenceManifest', evidenceBytes, 'application/json');
  const attestationDescriptor = descriptor(receipt, 'proofAttestation', attestationBytes, 'application/vnd.in-toto+json');
  const evidence = verifyEvidence(receipt, evidenceBytes);
  const materialisation = verifyMaterialisationProofAttestation({
    receipt: materialisationReceipt,
    receiptBytes: materialisationReceiptBytes,
    evidenceBytes: materialisationEvidenceBytes,
    attestationBytes: materialisationAttestationBytes,
  });
  const candidatePublication = verifyCandidatePublicationReceipt({
    receipt: candidatePublicationReceipt,
    receiptBytes: candidatePublicationReceiptBytes,
    expectedAuthorityDigest: evidence.evaluatedAuthorityDigest,
  });
  const dependencySetDigest = authorityDependencySetDigest(candidatePublication.candidateGraphs);
  const dependencyDigestAlgorithm = AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM;
  assert(materialisation.evidence.evaluatedAuthorityDigest === evidence.evaluatedAuthorityDigest,
    'MATERIALISATION_PROVIDER_AUTHORITY_BINDING_MISMATCH');
  assert(materialisation.evidence.graphCommit === proofProducerCommit,
    'MATERIALISATION_PROOF_PRODUCER_COMMIT_MISMATCH');
  assert(materialisation.evidence.graphTree === proofProducerTree,
    'MATERIALISATION_PROOF_PRODUCER_TREE_MISMATCH');
  assert(materialisation.candidateGraphInventoryAlgorithm
    === candidatePublication.candidateInventoryAlgorithm,
  'MATERIALISATION_CANDIDATE_INVENTORY_ALGORITHM_MISMATCH');
  assert(canonicalJson(materialisation.candidateGraphs)
    === canonicalJson(candidatePublication.candidateGraphs),
  'MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_MISMATCH');
  assert(materialisation.candidateAuthorityDigest === candidatePublication.candidateInventoryDigest,
    'MATERIALISATION_CANDIDATE_AUTHORITY_DIGEST_MISMATCH');
  assert(materialisation.candidateDependencySetDigest === dependencySetDigest,
    'MATERIALISATION_CANDIDATE_DEPENDENCY_DIGEST_MISMATCH');
  assert(Date.parse(evidence.evaluatedAt) <= Date.parse(observedAt), 'EVIDENCE_NOT_YET_VALID');
  assert(Date.parse(observedAt) < Date.parse(evidence.validUntil), 'EVIDENCE_EXPIRED');
  if (reevaluationState === 'successful') {
    assert(Date.parse(reevaluatedAt) >= Date.parse(evidence.evaluatedAt)
      && Date.parse(reevaluatedAt) <= Date.parse(observedAt), 'REEVALUATED_AT_OUTSIDE_OBSERVATION');
  }
  const primaryAlgorithmSourceDigest = evidence.proofAlgorithmSourceDigest;
  const attestation = verifyAttestation(receipt, evidence, evidenceDescriptor, attestationBytes);
  const enrichedReceipt = Object.freeze({ ...receipt, dependencySetDigest });
  const evidenceTurtle = evidenceProjection({
    receipt: enrichedReceipt,
    evidence,
    evidenceDescriptor,
    attestationDescriptor,
    attestation,
  });
  const proofsTurtle = proofProjection({
    evidence,
    evidenceDescriptor,
    attestationDescriptor,
    dependencySetDigest,
    dependencyDigestAlgorithm,
    proofProducerCommit,
    proofProducerTree,
    algorithmVersion,
    reevaluationState,
    settledAuthorityDigest,
    reevaluatedAt,
  });
  const metadataCore = {
    schemaVersion: 3,
    recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_RDF_PROJECTION',
    evidenceDigest: evidenceDescriptor.digest,
    attestationDigest: attestationDescriptor.digest,
    exactEvidenceSetDigest: evidence.exactEvidenceSetDigest,
    evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
    dependencySetDigest,
    dependencyDigestAlgorithm,
    candidatePublicationReceiptDigest: candidatePublication.candidatePublicationReceiptDigest,
    candidateAuthorityDigest: candidatePublication.candidateInventoryDigest,
    candidateInventoryAlgorithm: candidatePublication.candidateInventoryAlgorithm,
    excludedAuthorityGraphs: SELF_PUBLICATION_EXCLUDED_GRAPHS,
    implementationSourceDigest: evidence.implementationSourceDigest,
    proofInputSourceDigest: evidence.proofInputSourceDigest,
    proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
    proofAlgorithmSourceSetDigest: evidence.proofAlgorithmSourceSetDigest,
    runtimeDependencyEvidenceDigest: evidence.runtimeDependencyEvidenceDigest,
    primaryAlgorithmSourceDigest,
    materialisationProofReceiptDigest: sha256(materialisationReceiptBytes),
    materialisationProofEvidenceDigest: materialisation.evidenceDescriptor.digest,
    materialisationProofAttestationDigest: materialisation.attestationDescriptor.digest,
    materialisationProofExactEvidenceSetDigest: materialisation.evidence.exactEvidenceSetDigest,
    materialisationProofImplementationSourceDigest:
      materialisation.evidence.implementationSourceDigest,
    materialisationProofAlgorithmSourceDigest:
      materialisation.evidence.proofAlgorithmSourceDigest,
    materialisationProofGraphCommit: materialisation.evidence.graphCommit,
    materialisationProofGraphTree: materialisation.evidence.graphTree,
    materialisationProofSigningKeyFingerprint: materialisation.signingKeyFingerprint,
    proofProducerCommit,
    proofProducerTree,
    algorithmVersion,
    observedAt,
    reevaluationState,
    settledAuthorityDigest,
    reevaluatedAt,
    evidenceProjectionDigest: sha256(evidenceTurtle),
    proofProjectionDigest: sha256(proofsTurtle),
  };
  const projection = Object.freeze({
    evidenceTurtle,
    proofsTurtle,
    metadata: Object.freeze({ ...metadataCore, projectionDigest: sha256(canonicalJson(metadataCore)) }),
  });
  PROJECTION_MATERIALISATION_ATTESTATIONS.set(projection, materialisation);
  return projection;
}

function replaceExactBlock(source, start, end, replacement, label) {
  const startIndex = source.indexOf(start);
  const secondStart = startIndex < 0 ? -1 : source.indexOf(start, startIndex + start.length);
  const endIndex = source.indexOf(end, startIndex + start.length);
  const secondEnd = endIndex < 0 ? -1 : source.indexOf(end, endIndex + end.length);
  assert(startIndex >= 0 && secondStart < 0 && endIndex > startIndex && secondEnd < 0, `${label}_MARKERS_INVALID`);
  return `${source.slice(0, startIndex).trimEnd()}\n\n${start}\n${replacement.trim()}\n${end}${source.slice(endIndex + end.length)}`;
}

const DEFAULT_FILE_OPERATIONS = Object.freeze({ renameSync, rmSync, writeFileSync });

function stageFile(path, bytes, mode, label, operations) {
  const staged = `${path}.provider-projection-${process.pid}-${label}`;
  operations.writeFileSync(staged, bytes, { flag: 'wx', mode });
  return staged;
}

export function replaceProviderWorkforceAuthorityProjection(
  repositoryRoot,
  projection,
  applicationBinding,
  operations = DEFAULT_FILE_OPERATIONS,
) {
  const root = realpathSync(repositoryRoot);
  const admittedBinding = applicationBinding && typeof applicationBinding === 'object'
    ? APPLICATION_BINDINGS.get(applicationBinding)
    : null;
  assert(admittedBinding
    && admittedBinding.repositoryRoot === root
    && admittedBinding.exactEvidenceSetDigest === projection?.metadata?.exactEvidenceSetDigest
    && admittedBinding.projectionDigest === projection?.metadata?.projectionDigest,
  'PROJECTION_APPLICATION_BINDING_INVALID');
  const refreshedRepositories = verifyProjectionRepositoryBinding(admittedBinding.verificationArguments);
  assert(refreshedRepositories.repositoryRoot === admittedBinding.repositoryRoot
    && refreshedRepositories.factoryRepositoryRoot === admittedBinding.factoryRepositoryRoot,
  'PROJECTION_APPLICATION_REPOSITORY_MOVED');
  const evidencePath = join(root, 'semantic-model/assurance/evidence.trig');
  const proofsPath = join(root, 'semantic-model/assurance/proofs.trig');
  const stats = [];
  for (const path of [evidencePath, proofsPath]) {
    const stat = lstatSync(path);
    assert(!stat.isSymbolicLink() && stat.isFile() && stat.nlink === 1, 'PROJECTION_TARGET_NOT_EXACT_FILE');
    stats.push(stat);
  }
  const evidenceSource = readFileSync(evidencePath, 'utf8');
  const proofsSource = readFileSync(proofsPath, 'utf8');
  const nextEvidence = replaceExactBlock(
    evidenceSource,
    EVIDENCE_START,
    EVIDENCE_END,
    projection.evidenceTurtle,
    'EVIDENCE',
  );
  const nextProofs = replaceExactBlock(
    proofsSource,
    PROOF_START,
    PROOF_END,
    projection.proofsTurtle,
    'PROOF',
  );
  const evidenceStage = stageFile(evidencePath, nextEvidence, stats[0].mode & 0o777, 'evidence', operations);
  const proofStage = stageFile(proofsPath, nextProofs, stats[1].mode & 0o777, 'proof', operations);
  let evidenceReplaced = false;
  let proofReplaced = false;
  try {
    assert(sha256(readFileSync(evidencePath)) === sha256(evidenceSource), 'EVIDENCE_TARGET_MOVED_BEFORE_APPLY');
    assert(sha256(readFileSync(proofsPath)) === sha256(proofsSource), 'PROOF_TARGET_MOVED_BEFORE_APPLY');
    operations.renameSync(evidenceStage, evidencePath);
    evidenceReplaced = true;
    operations.renameSync(proofStage, proofsPath);
    proofReplaced = true;
    assert(sha256(readFileSync(evidencePath)) === sha256(nextEvidence), 'EVIDENCE_REPLACEMENT_VERIFICATION_FAILED');
    assert(sha256(readFileSync(proofsPath)) === sha256(nextProofs), 'PROOF_REPLACEMENT_VERIFICATION_FAILED');
  } catch (error) {
    const rollbackErrors = [];
    for (const [replaced, path, source, mode, label] of [
      [proofReplaced, proofsPath, proofsSource, stats[1].mode & 0o777, 'proof-rollback'],
      [evidenceReplaced, evidencePath, evidenceSource, stats[0].mode & 0o777, 'evidence-rollback'],
    ]) {
      if (!replaced) continue;
      let rollbackStage = null;
      try {
        rollbackStage = stageFile(path, source, mode, label, operations);
        operations.renameSync(rollbackStage, path);
        rollbackStage = null;
        assert(sha256(readFileSync(path)) === sha256(source), `${label.toUpperCase()}_VERIFICATION_FAILED`);
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      } finally {
        if (rollbackStage !== null) {
          try {
            operations.rmSync(rollbackStage, { force: true });
          } catch {
            // Preserve the primary rollback outcome.
          }
        }
      }
    }
    if (rollbackErrors.length) throw new AggregateError([error, ...rollbackErrors], 'PROJECTION_REPLACEMENT_AND_ROLLBACK_FAILED');
    throw error;
  } finally {
    for (const path of [evidenceStage, proofStage]) {
      try {
        operations.rmSync(path, { force: true });
      } catch {
        // A retained stage is inert and cannot replace a source without an
        // explicit later rename; do not mask the authoritative result.
      }
    }
  }
  const result = Object.freeze({
    evidencePath,
    proofsPath,
    evidenceSourceDigest: sha256(nextEvidence),
    proofSourceDigest: sha256(nextProofs),
  });
  APPLICATION_ROLLBACKS.set(result, Object.freeze({
    evidencePath,
    proofsPath,
    evidenceSource,
    proofsSource,
    evidenceAppliedDigest: result.evidenceSourceDigest,
    proofAppliedDigest: result.proofSourceDigest,
    evidenceMode: stats[0].mode & 0o777,
    proofMode: stats[1].mode & 0o777,
  }));
  return result;
}

export function rollbackProviderWorkforceAuthorityProjection(
  applied,
  operations = DEFAULT_FILE_OPERATIONS,
) {
  const rollback = applied && typeof applied === 'object'
    ? APPLICATION_ROLLBACKS.get(applied)
    : null;
  assert(rollback, 'PROJECTION_ROLLBACK_BINDING_INVALID');
  for (const [path, expectedDigest, label] of [
    [rollback.evidencePath, rollback.evidenceAppliedDigest, 'EVIDENCE'],
    [rollback.proofsPath, rollback.proofAppliedDigest, 'PROOF'],
  ]) {
    const stat = lstatSync(path);
    assert(!stat.isSymbolicLink() && stat.isFile() && stat.nlink === 1,
      `${label}_ROLLBACK_TARGET_NOT_EXACT_FILE`);
    assert(sha256(readFileSync(path)) === expectedDigest,
      `${label}_ROLLBACK_TARGET_MOVED`);
  }
  const stages = [];
  const errors = [];
  try {
    stages.push(stageFile(
      rollback.evidencePath,
      rollback.evidenceSource,
      rollback.evidenceMode,
      'evidence-post-closure-rollback',
      operations,
    ));
    stages.push(stageFile(
      rollback.proofsPath,
      rollback.proofsSource,
      rollback.proofMode,
      'proof-post-closure-rollback',
      operations,
    ));
    for (const [index, [path, source, label]] of [
      [rollback.evidencePath, rollback.evidenceSource, 'EVIDENCE'],
      [rollback.proofsPath, rollback.proofsSource, 'PROOF'],
    ].entries()) {
      try {
        operations.renameSync(stages[index], path);
        assert(sha256(readFileSync(path)) === sha256(source),
          `${label}_POST_CLOSURE_ROLLBACK_VERIFICATION_FAILED`);
      } catch (error) {
        errors.push(error);
      }
    }
  } finally {
    for (const path of stages) {
      try {
        operations.rmSync(path, { force: true });
      } catch {
        // Preserve the authoritative rollback outcome.
      }
    }
  }
  if (errors.length) {
    throw new AggregateError(errors, 'PROJECTION_POST_CLOSURE_ROLLBACK_FAILED');
  }
  APPLICATION_ROLLBACKS.delete(applied);
  return Object.freeze({
    evidencePath: rollback.evidencePath,
    proofsPath: rollback.proofsPath,
    evidenceSourceDigest: sha256(rollback.evidenceSource),
    proofSourceDigest: sha256(rollback.proofsSource),
  });
}

function finalizeProviderWorkforceAuthorityProjection(applied) {
  assert(applied && APPLICATION_ROLLBACKS.has(applied),
    'PROJECTION_FINALIZATION_BINDING_INVALID');
  APPLICATION_ROLLBACKS.delete(applied);
}

export function applyProviderWorkforceProjectionWithClosure({
  applyProjection,
  verifyPostApplyClosure,
  rollbackProjection,
  finalizeProjection = () => {},
}) {
  assert(typeof applyProjection === 'function'
    && typeof verifyPostApplyClosure === 'function'
    && typeof rollbackProjection === 'function'
    && typeof finalizeProjection === 'function',
  'PROJECTION_CLOSURE_OPERATION_INVALID');
  let applied = null;
  try {
    applied = applyProjection();
    const postProjectionClosure = verifyPostApplyClosure(applied);
    finalizeProjection(applied);
    return Object.freeze({ applied, postProjectionClosure });
  } catch (error) {
    if (applied !== null) {
      try {
        rollbackProjection(applied);
      } catch (rollbackError) {
        throw new AggregateError(
          [error, rollbackError],
          'PROJECTION_POST_CLOSURE_AND_ROLLBACK_FAILED',
        );
      }
    }
    throw error;
  }
}

function parseArguments(argv) {
  const values = {};
  const flags = new Set();
  for (const argument of argv) {
    if (argument === '--apply') {
      flags.add('apply');
      continue;
    }
    const match = /^--([a-z0-9-]+)=(.*)$/.exec(argument);
    assert(match, `ARGUMENT_INVALID_${argument}`);
    assert(!(match[1] in values), `ARGUMENT_DUPLICATE_${match[1]}`);
    values[match[1]] = match[2];
  }
  return { values, flags };
}

function exactInputFile(path, label) {
  assert(typeof path === 'string' && path.length > 0, `${label}_PATH_REQUIRED`);
  const absolutePath = resolve(path);
  const stat = lstatSync(absolutePath);
  assert(!stat.isSymbolicLink() && stat.isFile() && stat.nlink === 1,
    `${label}_NOT_EXACT_FILE`);
  assert(realpathSync(absolutePath) === absolutePath, `${label}_PATH_NOT_EXACT`);
  return readFileSync(absolutePath);
}

export function prepareProjectionOutputRoot(repositoryRoot, requestedOutputRoot) {
  const outputRoot = prepareExactSessionOutputRoot({
    repositoryRoot: realpathSync(repositoryRoot),
    requestedOutputRoot: resolve(requestedOutputRoot),
    clear: false,
  });
  for (const child of readdirSync(outputRoot)) {
    const path = join(outputRoot, child);
    const stat = lstatSync(path);
    assert(!stat.isSymbolicLink() && stat.isFile() && stat.nlink === 1,
      'PROJECTION_OUTPUT_CHILD_NOT_EXACT_FILE');
  }
  return outputRoot;
}

function writeProjectionOutputFile(outputRoot, name, bytes) {
  const path = join(outputRoot, name);
  if (existsSync(path)) {
    const stat = lstatSync(path);
    assert(!stat.isSymbolicLink() && stat.isFile() && stat.nlink === 1,
      'PROJECTION_OUTPUT_LEAF_NOT_EXACT_FILE');
  }
  const staged = stageFile(path, bytes, 0o600, 'output', DEFAULT_FILE_OPERATIONS);
  try {
    renameSync(staged, path);
  } finally {
    try {
      rmSync(staged, { force: true });
    } catch {
      // A retained stage cannot become authoritative without a later rename.
    }
  }
}

function gitValue(repositoryRoot, args, label) {
  const result = spawnPinnedLocalShaclRuntime(GIT_RUNTIME, ['-C', repositoryRoot, ...args], {
      encoding: 'utf8',
      env: HERMETIC_GIT_ENV,
      maxBuffer: 16 * 1024,
      timeout: 120_000,
  });
  if (result.error || result.signal || result.status !== 0) throw new Error(`${label}_GIT_READ_FAILED`);
  return result.stdout.trim();
}

function gitBytes(repositoryRoot, args, label) {
  const result = spawnPinnedLocalShaclRuntime(GIT_RUNTIME, ['-C', repositoryRoot, ...args], {
      encoding: 'buffer',
      env: HERMETIC_GIT_ENV,
      maxBuffer: 16 * 1024 * 1024,
      timeout: 120_000,
  });
  if (result.error || result.signal || result.status !== 0) throw new Error(`${label}_GIT_READ_FAILED`);
  return result.stdout;
}

function verifyTrackedSource(repositoryRoot, record, label) {
  assert(record && typeof record === 'object' && !Array.isArray(record), `${label}_RECORD_INVALID`);
  assert(typeof record.path === 'string' && record.path.length > 0, `${label}_PATH_INVALID`);
  exactDigest(record.digest, `${label}_DIGEST_INVALID`);
  const sourcePath = join(repositoryRoot, record.path);
  assert(!lstatSync(sourcePath).isSymbolicLink() && statSync(sourcePath).isFile(), `${label}_NOT_EXACT_FILE`);
  const resolvedSource = realpathSync(sourcePath);
  assert(resolvedSource.startsWith(`${repositoryRoot}/`), `${label}_OUTSIDE_REPOSITORY`);
  const checkoutBytes = readFileSync(resolvedSource);
  const committedBytes = gitBytes(repositoryRoot, ['show', `HEAD:${record.path}`], label);
  assert(sha256(checkoutBytes) === record.digest, `${label}_CHECKOUT_DIGEST_MISMATCH`);
  assert(sha256(committedBytes) === record.digest, `${label}_COMMIT_DIGEST_MISMATCH`);
  if ('byteSize' in record) {
    assert(record.byteSize === checkoutBytes.length && record.byteSize === committedBytes.length,
      `${label}_BYTE_SIZE_MISMATCH`);
  }
}

function verifyGitRepository({
  repositoryRoot,
  expectedCommit,
  expectedTree,
  label,
}) {
  assert(typeof repositoryRoot === 'string' && repositoryRoot.length > 0, `${label}_ROOT_REQUIRED`);
  assert(!lstatSync(repositoryRoot).isSymbolicLink(), `${label}_ROOT_SYMLINK_REFUSED`);
  const root = realpathSync(repositoryRoot);
  assert(realpathSync(gitValue(root, ['rev-parse', '--show-toplevel'], `${label}_ROOT`)) === root,
    `${label}_ROOT_NOT_GIT_TOP_LEVEL`);
  assert(gitValue(root, ['rev-parse', 'HEAD'], `${label}_COMMIT`) === expectedCommit,
    `${label}_COMMIT_NOT_CHECKOUT_HEAD`);
  assert(gitValue(root, ['rev-parse', 'HEAD^{tree}'], `${label}_TREE`) === expectedTree,
    `${label}_TREE_NOT_CHECKOUT_TREE`);
  assert(gitValue(root, ['status', '--porcelain=v1', '--untracked-files=all'], `${label}_STATUS`) === '',
    `${label}_WORKTREE_NOT_CLEAN`);
  return root;
}

export function verifyProjectionRepositoryBinding({
  repositoryRoot,
  factoryRepositoryRoot,
  proofProducerCommit,
  proofProducerTree,
  evidence,
  materialisation,
}) {
  const root = verifyGitRepository({
    repositoryRoot,
    expectedCommit: proofProducerCommit,
    expectedTree: proofProducerTree,
    label: 'PROOF_PRODUCER',
  });
  const factoryRoot = verifyGitRepository({
    repositoryRoot: factoryRepositoryRoot,
    expectedCommit: evidence?.factoryCommit,
    expectedTree: evidence?.factoryTree,
    label: 'FACTORY_PRODUCER',
  });
  assert(root !== factoryRoot, 'PROOF_AND_FACTORY_REPOSITORIES_NOT_DISTINCT');
  exactStringSet(evidence?.proofAlgorithmSources?.map(({ path }) => path), PROVIDER_PROOF_SOURCE_PATHS,
    'PROOF_ALGORITHM_SOURCE_SET_INVALID');
  evidence.proofAlgorithmSources.forEach((record, index) => {
    verifyTrackedSource(root, record, `PROOF_ALGORITHM_SOURCE_${index}`);
  });
  assert(sha256(canonicalJson(evidence.proofAlgorithmSources))
    === evidence.proofAlgorithmSourceSetDigest,
    'PROOF_ALGORITHM_SOURCE_SET_DIGEST_MISMATCH');
  assert(evidence.proofAlgorithmSources
    .find(({ path }) => path === PROVIDER_PROOF_PATH)?.digest
      === evidence.proofAlgorithmSourceDigest,
  'PROOF_ALGORITHM_PRIMARY_SOURCE_DIGEST_MISMATCH');
  assert(materialisation && typeof materialisation === 'object',
    'MATERIALISATION_PROOF_ATTESTATION_BINDING_REQUIRED');
  assert(materialisation.evidence?.graphCommit === proofProducerCommit
    && materialisation.evidence?.graphTree === proofProducerTree,
  'MATERIALISATION_PROOF_CHECKOUT_BINDING_MISMATCH');
  exactStringSet(
    materialisation.evidence?.implementationSources?.map(({ path }) => path),
    MATERIALISATION_IMPLEMENTATION_SOURCE_PATHS,
    'MATERIALISATION_IMPLEMENTATION_SOURCE_SET_INVALID',
  );
  materialisation.evidence.implementationSources.forEach((record, index) => {
    verifyTrackedSource(root, record, `MATERIALISATION_IMPLEMENTATION_SOURCE_${index}`);
  });
  assert(sha256(canonicalJson(materialisation.evidence.implementationSources))
    === materialisation.evidence.implementationSourceDigest,
  'MATERIALISATION_IMPLEMENTATION_SOURCE_SET_DIGEST_MISMATCH');
  assert(materialisation.evidence?.runner?.sourcePath === MATERIALISATION_PROOF_RUNNER_PATH,
    'MATERIALISATION_PROOF_RUNNER_PATH_INVALID');
  verifyTrackedSource(root, {
    path: materialisation.evidence.runner.sourcePath,
    digest: materialisation.evidence.runner.sourceDigest,
  }, 'MATERIALISATION_PROOF_RUNNER');
  verifyProviderMaterialisationAuthorityMutationEvidence(
    evidence.materialisationAuthorityMutationEvidence,
    { repositoryRoot: root },
  );
  exactStringSet(
    evidence.materialisationAuthorityMutationEvidence.sourceRecords.map(({ path }) => path),
    PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS,
    'MATERIALISATION_MUTATION_SOURCE_SET_INVALID',
  );
  evidence.materialisationAuthorityMutationEvidence.sourceRecords.forEach((record, index) => {
    verifyTrackedSource(root, record, `MATERIALISATION_MUTATION_SOURCE_${index}`);
  });
  assert(Array.isArray(evidence.implementationSources) && evidence.implementationSources.length > 0,
    'IMPLEMENTATION_SOURCES_EMPTY');
  exactStringSet(
    evidence.implementationSources.map(({ path }) => path),
    PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS,
    'IMPLEMENTATION_SOURCE_PATH_SET_INVALID',
  );
  evidence.implementationSources.forEach((record, index) => {
    verifyTrackedSource(factoryRoot, record, `IMPLEMENTATION_SOURCE_${index}`);
  });
  assert(sha256(canonicalJson(evidence.implementationSources)) === evidence.implementationSourceDigest,
    'IMPLEMENTATION_SOURCE_SET_DIGEST_MISMATCH');
  exactStringSet(
    evidence.proofInputSources.map(({ path }) => path),
    PROVIDER_WORKFORCE_PROOF_INPUT_PATHS,
    'PROOF_INPUT_SOURCE_PATH_SET_INVALID',
  );
  evidence.proofInputSources.forEach((record, index) => {
    verifyTrackedSource(factoryRoot, record, `PROOF_INPUT_SOURCE_${index}`);
  });
  assert(sha256(canonicalJson(evidence.proofInputSources)) === evidence.proofInputSourceDigest,
    'PROOF_INPUT_SOURCE_SET_DIGEST_MISMATCH');
  return Object.freeze({ repositoryRoot: root, factoryRepositoryRoot: factoryRoot });
}

function reproduceProviderWorkforceEvidence({
  repositories,
  evidence,
  evidenceBytes,
  attestationBytes,
  receipt,
  mutationRuntime,
}) {
  const casRoot = prepareExactSessionOutputRoot({
    repositoryRoot: repositories.repositoryRoot,
    requestedOutputRoot: join(repositories.repositoryRoot, '.work', 'provider-proof-reproduction-cas'),
    clear: true,
  });
  const outputRoot = prepareExactSessionOutputRoot({
    repositoryRoot: repositories.repositoryRoot,
    requestedOutputRoot: join(repositories.repositoryRoot, '.work', 'provider-proof-reproduction'),
    clear: true,
  });
  let receiptBytes;
  try {
    receiptBytes = execFileSync(process.execPath, [
      join(repositories.repositoryRoot, PROVIDER_PROOF_PATH),
    ], {
      cwd: repositories.repositoryRoot,
      encoding: 'buffer',
      maxBuffer: 64 * 1024 * 1024,
      timeout: 3_600_000,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        PATH: '/usr/bin:/bin',
        TZ: 'UTC',
        USF_AUTHORITY_DIGEST: evidence.evaluatedAuthorityDigest,
        USF_EVALUATED_AT: evidence.evaluatedAt,
        USF_CAS_ROOT: casRoot,
        USF_FACTORY_REPO: repositories.factoryRepositoryRoot,
        USF_FACTORY_COMMIT: evidence.factoryCommit,
        USF_EXPECTED_FACTORY_TREE: evidence.factoryTree,
        USF_OUTPUT_ROOT: outputRoot,
        USF_PYTHON: mutationRuntime.executablePath,
      },
    });
  } catch {
    throw new Error('PROVIDER_WORKFORCE_EVIDENCE_REPRODUCTION_FAILED');
  }
  assert(receipt.outputRoot === 'SESSION_TRANSIENT_OUTPUT_ROOT',
    'RECEIPT_OUTPUT_ROOT_SENTINEL_INVALID');
  assert(receiptBytes.equals(Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`)),
    'PROVIDER_WORKFORCE_RECEIPT_REPRODUCTION_MISMATCH');
  assert(readFileSync(join(outputRoot, 'evidence-manifest.json')).equals(evidenceBytes),
    'PROVIDER_WORKFORCE_EVIDENCE_REPRODUCTION_MISMATCH');
  assert(readFileSync(join(outputRoot, 'proof-attestation.dsse.json')).equals(attestationBytes),
    'PROVIDER_WORKFORCE_ATTESTATION_REPRODUCTION_MISMATCH');
}

function exactExecutionSourceIdentitySnapshot({
  repositories,
  evidence,
  materialisation,
}) {
  const paths = [
    ...evidence.proofAlgorithmSources.map(({ path }) => join(repositories.repositoryRoot, path)),
    ...evidence.materialisationAuthorityMutationEvidence.sourceRecords
      .map(({ path }) => join(repositories.repositoryRoot, path)),
    ...evidence.implementationSources.map(({ path }) => join(repositories.factoryRepositoryRoot, path)),
    ...evidence.proofInputSources.map(({ path }) => join(repositories.factoryRepositoryRoot, path)),
    ...materialisation.evidence.implementationSources
      .map(({ path }) => join(repositories.repositoryRoot, path)),
    join(repositories.repositoryRoot, materialisation.evidence.runner.sourcePath),
  ];
  return [...new Set(paths)].sort(utf8Compare).map((path) => {
    const stat = statSync(path, { bigint: true });
    return {
      path,
      device: stat.dev.toString(),
      inode: stat.ino.toString(),
      ctimeNanoseconds: stat.ctimeNs.toString(),
      mode: stat.mode.toString(),
      linkCount: stat.nlink.toString(),
      size: stat.size.toString(),
      digest: sha256(readFileSync(path)),
    };
  });
}

export const providerWorkforceAuthorityProjectionInternals = Object.freeze({
  exactExecutionSourceIdentitySnapshot,
});

function createProjectionApplicationBinding(arguments_) {
  const materialisation = PROJECTION_MATERIALISATION_ATTESTATIONS.get(arguments_.projection);
  assert(materialisation, 'PROJECTION_MATERIALISATION_ATTESTATION_BINDING_INVALID');
  const repositories = verifyProjectionRepositoryBinding({
    ...arguments_,
    materialisation,
  });
  assert(canonicalJson(arguments_.mutationRuntime)
    === canonicalJson(arguments_.evidence.materialisationAuthorityMutationEvidence.runtime),
  'MATERIALISATION_MUTATION_RUNTIME_BINDING_MISMATCH');
  const executionSourceIdentityBefore = exactExecutionSourceIdentitySnapshot({
    repositories,
    evidence: arguments_.evidence,
    materialisation,
  });
  reproduceProviderWorkforceEvidence({
    repositories,
    evidence: arguments_.evidence,
    evidenceBytes: arguments_.evidenceBytes,
    attestationBytes: arguments_.attestationBytes,
    receipt: arguments_.receipt,
    mutationRuntime: arguments_.mutationRuntime,
  });
  const executionSourceIdentityAfter = exactExecutionSourceIdentitySnapshot({
    repositories,
    evidence: arguments_.evidence,
    materialisation,
  });
  assert(canonicalJson(executionSourceIdentityAfter) === canonicalJson(executionSourceIdentityBefore),
    'PROVIDER_WORKFORCE_EXECUTION_SOURCE_IDENTITY_MOVED');
  verifyProviderProofNodeDependencyEvidence(
    arguments_.evidence.runtimeDependencyEvidence.node,
    { repositoryRoot: repositories.repositoryRoot },
  );
  const binding = Object.freeze({
    ...repositories,
    exactEvidenceSetDigest: arguments_.evidence.exactEvidenceSetDigest,
  });
  APPLICATION_BINDINGS.set(binding, Object.freeze({
    repositoryRoot: repositories.repositoryRoot,
    factoryRepositoryRoot: repositories.factoryRepositoryRoot,
    exactEvidenceSetDigest: arguments_.evidence.exactEvidenceSetDigest,
    projectionDigest: arguments_.projection.metadata.projectionDigest,
    verificationArguments: Object.freeze({
      repositoryRoot: arguments_.repositoryRoot,
      factoryRepositoryRoot: arguments_.factoryRepositoryRoot,
      proofProducerCommit: arguments_.proofProducerCommit,
      proofProducerTree: arguments_.proofProducerTree,
      evidence: arguments_.evidence,
      materialisation,
    }),
  }));
  return binding;
}

function canonicalValidateCandidate({
  repositoryRoot,
  expectedAuthorityDigest,
}) {
  const authorityEnvironment = {
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    PATH: '/usr/bin:/bin',
    STARDOG_DATABASE: process.env.STARDOG_DATABASE,
    STARDOG_SERVER: process.env.STARDOG_SERVER,
    STARDOG_TOKEN: process.env.STARDOG_TOKEN,
    TZ: 'UTC',
  };
  assert(authorityEnvironment.STARDOG_DATABASE
    && authorityEnvironment.STARDOG_SERVER
    && authorityEnvironment.STARDOG_TOKEN,
  'CANONICAL_VALIDATE_AUTHORITY_ENVIRONMENT_REQUIRED');
  let bytes;
  try {
    bytes = execFileSync(process.execPath, [
      join(repositoryRoot, 'processes/semantic-assurance/semantic-authority-publication.mjs'),
      '--mode=validate',
      `--authority-digest=${expectedAuthorityDigest}`,
    ], {
      cwd: repositoryRoot,
      encoding: 'buffer',
      env: authorityEnvironment,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 3_600_000,
    });
  } catch {
    throw new Error('CANONICAL_VALIDATE_PUBLICATION_FAILED');
  }
  let receipt;
  try {
    receipt = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('CANONICAL_VALIDATE_PUBLICATION_RECEIPT_JSON_INVALID');
  }
  return Object.freeze({
    bytes,
    receipt,
    verified: verifyCandidatePublicationReceipt({
      receipt,
      receiptBytes: bytes,
      expectedAuthorityDigest,
    }),
  });
}

export function assertSameCanonicalCandidate(supplied, reproduced) {
  assert(Buffer.isBuffer(supplied?.bytes) && Buffer.isBuffer(reproduced?.bytes),
    'CANDIDATE_PUBLICATION_RECEIPT_PROVENANCE_BYTES_REQUIRED');
  assert(supplied.bytes.equals(reproduced.bytes),
    'CANDIDATE_PUBLICATION_RECEIPT_PROVENANCE_MISMATCH');
  assert(supplied.verified.candidateInventoryDigest === reproduced.verified.candidateInventoryDigest
    && canonicalJson(supplied.verified.candidateGraphs)
      === canonicalJson(reproduced.verified.candidateGraphs),
  'CANDIDATE_PUBLICATION_INVENTORY_PROVENANCE_MISMATCH');
}

export function assertPostProjectionCandidateClosure(before, after) {
  const beforeByGraph = new Map(before.verified.candidateGraphs.map((record) => [record.graph, record]));
  const afterByGraph = new Map(after.verified.candidateGraphs.map((record) => [record.graph, record]));
  exactStringSet([...afterByGraph.keys()], [...beforeByGraph.keys()],
    'POST_PROJECTION_GRAPH_SET_MISMATCH');
  const excluded = new Set(SELF_PUBLICATION_EXCLUDED_GRAPHS);
  for (const [graph, beforeRecord] of beforeByGraph) {
    if (!excluded.has(graph) || graph === 'urn:usf:graph:capabilities') {
      assert(canonicalJson(afterByGraph.get(graph)) === canonicalJson(beforeRecord),
        `POST_PROJECTION_NONEXCLUDED_GRAPH_MOVED_${graph}`);
    }
  }
  const beforeDependency = authorityDependencySetDigest(before.verified.candidateGraphs);
  const afterDependency = authorityDependencySetDigest(after.verified.candidateGraphs);
  assert(afterDependency === beforeDependency, 'POST_PROJECTION_DEPENDENCY_SET_MOVED');
  return Object.freeze({
    beforeCandidateAuthorityDigest: before.verified.candidateInventoryDigest,
    afterCandidateAuthorityDigest: after.verified.candidateInventoryDigest,
    dependencySetDigest: afterDependency,
    postProjectionPublicationReceiptDigest: after.verified.candidatePublicationReceiptDigest,
  });
}

function runCli() {
  const { values, flags } = parseArguments(process.argv.slice(2));
  const expectedArguments = [
    'algorithm-version',
    'attestation',
    'candidate-publication-receipt',
    'evidence',
    'factory-repository-root',
    'local-shacl-python',
    'materialisation-attestation',
    'materialisation-evidence',
    'materialisation-receipt',
    'observed-at',
    'output-root',
    'proof-producer-commit',
    'proof-producer-tree',
    'receipt',
    'reevaluation-state',
    'repository-root',
    ...(values['reevaluation-state'] === 'successful'
      ? ['reevaluated-at', 'settled-authority-digest'] : []),
  ];
  exactStringSet(Object.keys(values), expectedArguments, 'CLI_ARGUMENT_SET_INVALID');
  const receiptBytes = exactInputFile(values.receipt, 'RECEIPT');
  let receipt;
  try {
    receipt = JSON.parse(receiptBytes.toString('utf8'));
  } catch {
    throw new Error('RECEIPT_JSON_INVALID');
  }
  assert(receiptBytes.equals(Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`)),
    'RECEIPT_BYTES_NONCANONICAL');
  assert(receipt.outputRoot === 'SESSION_TRANSIENT_OUTPUT_ROOT',
    'RECEIPT_OUTPUT_ROOT_SENTINEL_INVALID');
  const evidenceBytes = exactInputFile(values.evidence, 'EVIDENCE');
  const evidence = parseCanonicalJson(evidenceBytes, 'EVIDENCE');
  const mutationExecutablePath = values['local-shacl-python'];
  assert(typeof mutationExecutablePath === 'string' && mutationExecutablePath.length > 0,
    'LOCAL_SHACL_PYTHON_REQUIRED');
  const mutationResolvedExecutablePath = realpathSync(mutationExecutablePath);
  const mutationRuntime = Object.freeze({
    executablePath: mutationExecutablePath,
    resolvedExecutablePath: mutationResolvedExecutablePath,
    executableDigest: sha256(readFileSync(mutationResolvedExecutablePath)),
  });
  const attestationBytes = exactInputFile(values.attestation, 'ATTESTATION');
  const materialisationReceiptBytes = exactInputFile(
    values['materialisation-receipt'],
    'MATERIALISATION_RECEIPT',
  );
  let materialisationReceipt;
  try {
    materialisationReceipt = JSON.parse(materialisationReceiptBytes.toString('utf8'));
  } catch {
    throw new Error('MATERIALISATION_RECEIPT_JSON_INVALID');
  }
  const materialisationEvidenceBytes = exactInputFile(
    values['materialisation-evidence'],
    'MATERIALISATION_EVIDENCE',
  );
  const materialisationAttestationBytes = exactInputFile(
    values['materialisation-attestation'],
    'MATERIALISATION_ATTESTATION',
  );
  const candidatePublicationReceiptBytes = exactInputFile(
    values['candidate-publication-receipt'],
    'CANDIDATE_PUBLICATION_RECEIPT',
  );
  let candidatePublicationReceipt;
  try {
    candidatePublicationReceipt = JSON.parse(candidatePublicationReceiptBytes.toString('utf8'));
  } catch {
    throw new Error('CANDIDATE_PUBLICATION_RECEIPT_JSON_INVALID');
  }
  const projection = projectProviderWorkforceAuthorityReceipt({
    receipt,
    evidenceBytes,
    attestationBytes,
    materialisationReceipt,
    materialisationReceiptBytes,
    materialisationEvidenceBytes,
    materialisationAttestationBytes,
    candidatePublicationReceipt,
    candidatePublicationReceiptBytes,
    proofProducerCommit: values['proof-producer-commit'],
    proofProducerTree: values['proof-producer-tree'],
    algorithmVersion: values['algorithm-version'],
    observedAt: values['observed-at'],
    reevaluationState: values['reevaluation-state'],
    settledAuthorityDigest: values['settled-authority-digest'] || null,
    reevaluatedAt: values['reevaluated-at'] || null,
  });
  const applicationBinding = createProjectionApplicationBinding({
    repositoryRoot: values['repository-root'],
    factoryRepositoryRoot: values['factory-repository-root'],
    proofProducerCommit: values['proof-producer-commit'],
    proofProducerTree: values['proof-producer-tree'],
    evidence,
    evidenceBytes,
    attestationBytes,
    receipt,
    mutationRuntime,
    projection,
  });
  const root = applicationBinding.repositoryRoot;
  const suppliedCandidate = Object.freeze({
    bytes: candidatePublicationReceiptBytes,
    receipt: candidatePublicationReceipt,
    verified: verifyCandidatePublicationReceipt({
      receipt: candidatePublicationReceipt,
      receiptBytes: candidatePublicationReceiptBytes,
      expectedAuthorityDigest: evidence.evaluatedAuthorityDigest,
    }),
  });
  const reproducedCandidate = canonicalValidateCandidate({
    repositoryRoot: root,
    expectedAuthorityDigest: evidence.evaluatedAuthorityDigest,
  });
  assertSameCanonicalCandidate(suppliedCandidate, reproducedCandidate);
  verifyProjectionRepositoryBinding({
    repositoryRoot: values['repository-root'],
    factoryRepositoryRoot: values['factory-repository-root'],
    proofProducerCommit: values['proof-producer-commit'],
    proofProducerTree: values['proof-producer-tree'],
    evidence,
    materialisation: PROJECTION_MATERIALISATION_ATTESTATIONS.get(projection),
  });
  const exactOutputRoot = prepareProjectionOutputRoot(root, values['output-root']);
  writeProjectionOutputFile(
    exactOutputRoot,
    'provider-workforce-authority-evidence-projection.ttl',
    projection.evidenceTurtle,
  );
  writeProjectionOutputFile(
    exactOutputRoot,
    'provider-workforce-authority-proof-projection.ttl',
    projection.proofsTurtle,
  );
  writeProjectionOutputFile(
    exactOutputRoot,
    'provider-workforce-authority-projection.json',
    `${canonicalJson(projection.metadata)}\n`,
  );
  let applied = null;
  let postProjectionClosure = null;
  if (flags.has('apply')) {
    ({ applied, postProjectionClosure } = applyProviderWorkforceProjectionWithClosure({
      applyProjection: () => replaceProviderWorkforceAuthorityProjection(
        root,
        projection,
        applicationBinding,
      ),
      verifyPostApplyClosure: () => {
        const postProjectionCandidate = canonicalValidateCandidate({
          repositoryRoot: root,
          expectedAuthorityDigest: evidence.evaluatedAuthorityDigest,
        });
        const closure = assertPostProjectionCandidateClosure(
          reproducedCandidate,
          postProjectionCandidate,
        );
        writeProjectionOutputFile(
          exactOutputRoot,
          'post-projection-candidate-publication-receipt.json',
          postProjectionCandidate.bytes,
        );
        return closure;
      },
      rollbackProjection: (appliedProjection) => {
        rollbackProviderWorkforceAuthorityProjection(appliedProjection);
      },
      finalizeProjection: (appliedProjection) => {
        finalizeProviderWorkforceAuthorityProjection(appliedProjection);
      },
    }));
  }
  process.stdout.write(`${canonicalJson({ ...projection.metadata, applied, postProjectionClosure })}\n`);
}

const mainPath = process.argv[1] ? realpathSync(process.argv[1]) : null;
if (mainPath === fileURLToPath(import.meta.url)) {
  try {
    runCli();
  } catch (error) {
    process.stderr.write(`${error.name}:${error.message}\n`);
    process.exitCode = 1;
  }
}
