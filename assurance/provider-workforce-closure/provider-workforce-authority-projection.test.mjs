import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from 'node:crypto';
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { Parser } from 'n3';

import {
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  SELF_PUBLICATION_RULE,
  authorityDependencySetDigest,
} from '../../capabilities/semantic-model-compilation/authority-binding.mjs';
import {
  localShaclRuntimeInternals,
} from '../semantic-model-compilation/local-shacl-validation.mjs';
import {
  PROVIDER_MATERIALISATION_MUTATION_CASES,
  PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS,
  PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS,
  PROVIDER_WORKFORCE_PROOF_INPUT_PATHS,
  normaliseDeterministicPytestOutput,
  providerMaterialisationAuthorityMutationInternals,
  prepareExactSessionOutputRoot,
  verifyProviderMaterialisationAuthorityMutationEvidence,
} from './provider-materialisation-authority-mutations.mjs';
import {
  MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM,
  MATERIALISATION_EVIDENCE_SCHEMA_VERSION,
  MATERIALISATION_IMPLEMENTATION_SOURCE_PATHS,
  MATERIALISATION_PROOF_RUNNER_PATH,
  MATERIALISATION_RECEIPT_SCHEMA_VERSION,
  candidateDependencyDigestFromGraphs,
  canonicalMaterialisationJson,
  canonicalMaterialisationReceiptBytes,
} from './materialisation-proof-attestation-verifier.mjs';
import {
  PROVIDER_WORKFORCE_REQUIRED_CASES,
  PROVIDER_WORKFORCE_REQUIRED_CLAIMS,
  applyProviderWorkforceProjectionWithClosure,
  assertPostProjectionCandidateClosure,
  assertSameCanonicalCandidate,
  projectProviderWorkforceAuthorityReceipt,
  prepareProjectionOutputRoot,
  providerWorkforceAuthorityProjectionInternals,
  replaceProviderWorkforceAuthorityProjection,
  verifyCandidatePublicationReceipt,
  verifyProjectionRepositoryBinding,
} from './provider-workforce-authority-projection.mjs';

const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const PROJECTOR_PATH = fileURLToPath(
  new URL('./provider-workforce-authority-projection.mjs', import.meta.url),
);
const digestByte = (index) => (index % 256).toString(16).padStart(2, '0').repeat(32);
const pythonNativeMappingEvidence = (checkpoints) => {
  const records = localShaclRuntimeInternals.expectedPythonMappedSystemObjects;
  const snapshots = checkpoints.map((checkpoint) => ({
    schemaVersion: 1,
    checkpoint,
    records,
    recordCount: records.length,
    recordSetDigest: sha256(canonicalJson(records)),
  }));
  return {
    schemaVersion: 1,
    checkpoints: snapshots,
    checkpointSetDigest: sha256(canonicalJson(snapshots)),
  };
};

const AUTHORITY_GRAPH_INVENTORY = Object.freeze([
  'urn:usf:graph:capabilities',
  'urn:usf:graph:derived:coverage',
  'urn:usf:graph:derived:evidence',
  'urn:usf:graph:derived:obligations',
  'urn:usf:graph:derived:readiness',
  'urn:usf:graph:derived:surfaces',
  'urn:usf:graph:evidence',
  'urn:usf:graph:proofs',
  'urn:usf:graph:ontology',
].sort().map((graph, index) => Object.freeze({
  graph,
  algorithm: 'RDFC-1.0',
  digestAlgorithm: 'sha256',
  sha256: digestByte(index + 1),
  triples: index + 10,
})));
const DEPENDENCY_SET_DIGEST = authorityDependencySetDigest(AUTHORITY_GRAPH_INVENTORY);
const EVALUATED_AUTHORITY_DIGEST = `sha256:${'88'.repeat(32)}`;
const CANDIDATE_AUTHORITY_DIGEST = sha256(AUTHORITY_GRAPH_INVENTORY
  .map(({ graph, sha256: graphDigest, triples }) => `${graph}=${graphDigest}:${triples}`)
  .join('\n'));
const CANDIDATE_STATEMENT_COUNT = AUTHORITY_GRAPH_INVENTORY
  .reduce((total, { triples }) => total + triples, 0);
const PUBLICATION_BUDGET_POLICY = Object.freeze({
  hardStatementLimit: 1_000_000,
  maximumProjectedStatementCount: 900_000,
  policyIri: 'urn:usf:permutationpublicationbudget:stardogcloudfree',
  provider: 'stardogcloudfree',
  reserveStatementCount: 100_000,
});
const PUBLICATION_BUDGET_CORE = Object.freeze({
  authorityDigest: EVALUATED_AUTHORITY_DIGEST,
  baselineStatementCount: 107_219,
  candidateGraphWitnessDigest: CANDIDATE_AUTHORITY_DIGEST,
  candidateStatementCount: CANDIDATE_STATEMENT_COUNT,
  conservativeNoReplacementCredit: true,
  hardStatementLimit: PUBLICATION_BUDGET_POLICY.hardStatementLimit,
  maximumProjectedStatementCount: PUBLICATION_BUDGET_POLICY.maximumProjectedStatementCount,
  policyDigest: sha256(canonicalJson(PUBLICATION_BUDGET_POLICY)),
  policyIri: PUBLICATION_BUDGET_POLICY.policyIri,
  projectedStatementUpperBound: 107_219 + CANDIDATE_STATEMENT_COUNT,
  provider: PUBLICATION_BUDGET_POLICY.provider,
  reserveStatementCount: PUBLICATION_BUDGET_POLICY.reserveStatementCount,
});
const CANDIDATE_PUBLICATION_RECEIPT = Object.freeze({
  receiptSchemaVersion: 2,
  mode: 'validate',
  ok: true,
  contaminationCount: 0,
  graphsCleared: 40,
  authoredLoaded: 20,
  shapesLoaded: 8,
  commitOutcome: {
    state: 'validated-rolled-back',
    exactCandidateStateVerified: true,
    candidateDigest: CANDIDATE_AUTHORITY_DIGEST,
    candidateGraphs: AUTHORITY_GRAPH_INVENTORY,
    publicationBudget: {
      ...PUBLICATION_BUDGET_CORE,
      budgetDigest: sha256(canonicalJson(PUBLICATION_BUDGET_CORE)),
      result: 'PASS',
    },
  },
  authorityWitness: {
    algorithm: 'sha256-rdfc10-graph-inventory-v2',
    totalSource: 'canonical-graph-inventory',
    expected: EVALUATED_AUTHORITY_DIGEST,
    evaluated: EVALUATED_AUTHORITY_DIGEST,
    beforePublication: {
      digest: EVALUATED_AUTHORITY_DIGEST,
      graphCount: 40,
      triples: 107_219,
    },
    afterPublication: {
      digest: EVALUATED_AUTHORITY_DIGEST,
      graphCount: 40,
      triples: 107_219,
    },
    settled: {
      digest: EVALUATED_AUTHORITY_DIGEST,
      graphCount: 40,
      triples: 107_219,
      stable: true,
    },
  },
});
const OPTIONS = Object.freeze({
  candidatePublicationReceipt: CANDIDATE_PUBLICATION_RECEIPT,
  candidatePublicationReceiptBytes: Buffer.from(`${JSON.stringify(CANDIDATE_PUBLICATION_RECEIPT)}\n`),
  proofProducerCommit: '11'.repeat(20),
  proofProducerTree: '22'.repeat(20),
  algorithmVersion: '2.0.0',
  observedAt: '2026-07-28T07:30:00Z',
  reevaluationState: 'pending',
});

function candidateReceiptOptions(receipt) {
  return {
    candidatePublicationReceipt: receipt,
    candidatePublicationReceiptBytes: Buffer.from(`${JSON.stringify(receipt)}\n`),
    ...materialisationFixture({
      candidateGraphs: receipt.commitOutcome.candidateGraphs,
      evaluatedAuthorityDigest: receipt.authorityWitness.expected,
    }),
  };
}

function verifiedCandidate(receipt) {
  const bytes = Buffer.from(`${JSON.stringify(receipt)}\n`);
  return Object.freeze({
    bytes,
    receipt,
    verified: verifyCandidatePublicationReceipt({
      receipt,
      receiptBytes: bytes,
      expectedAuthorityDigest: EVALUATED_AUTHORITY_DIGEST,
    }),
  });
}

function rebindCandidateReceipt(receipt) {
  const graphs = receipt.commitOutcome.candidateGraphs;
  const candidateDigest = sha256(graphs
    .map(({ graph, sha256: graphDigest, triples }) => `${graph}=${graphDigest}:${triples}`)
    .join('\n'));
  const candidateStatementCount = graphs.reduce((total, { triples }) => total + triples, 0);
  const budget = receipt.commitOutcome.publicationBudget;
  const budgetCore = {
    ...budget,
    candidateGraphWitnessDigest: candidateDigest,
    candidateStatementCount,
    projectedStatementUpperBound: budget.baselineStatementCount + candidateStatementCount,
  };
  delete budgetCore.budgetDigest;
  delete budgetCore.result;
  receipt.commitOutcome.candidateDigest = candidateDigest;
  receipt.commitOutcome.publicationBudget = {
    ...budgetCore,
    budgetDigest: sha256(canonicalJson(budgetCore)),
    result: 'PASS',
  };
  return receipt;
}

function mutationEvidence({
  passedCaseCount = 26,
  sourceRecords = PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS.map((path, index) => ({
    path,
    digest: `sha256:${digestByte(index + 77)}`,
  })),
} = {}) {
  const cases = PROVIDER_MATERIALISATION_MUTATION_CASES.map((expected, index) => ({
    ...expected,
    observedShaclCodeDigest: `sha256:${digestByte(index + 11)}`,
    observedIntegrityCodeDigest: `sha256:${digestByte(index + 37)}`,
    shaclMatched: true,
    integrityMatched: true,
  }));
  const nativeMappingEvidence = pythonNativeMappingEvidence([
    'PRE_WORKLOAD',
    'POST_BASELINE_LOAD',
    'POST_WORKLOAD',
  ]);
  const core = {
    schemaVersion: 3,
    evidenceScope: 'HERMETIC_UNPUBLISHED_MUTATION_FIXTURE',
    caseCount: 26,
    passedCaseCount,
    baselineIntegrityRowCount: 0,
    baselineIntegrityDigest: sha256(canonicalJson([])),
    sourceRecords,
    sourceSetDigest: sha256(canonicalJson(sourceRecords)),
    pythonDependencyByteSets: providerMaterialisationAuthorityMutationInternals.expectedPythonDependencyByteSets,
    pythonDependencyByteSetDigest:
      providerMaterialisationAuthorityMutationInternals.expectedPythonDependencyByteSetDigest,
    mappedSystemObjectCount: 23,
    mappedSystemObjectSetDigest: 'sha256:2aa149da8aefbaaa71c1f887620b75d2f47b9dea26f57663fa92eda8da92755f',
    nativeMappingEvidence,
    siteCustomizationLoaded: false,
    cases,
    caseSetDigest: sha256(canonicalJson(cases)),
    evidenceDigestScope: 'MATERIALISATION_MUTATION_EVIDENCE_WITH_RUNTIME_V1',
    runtime: {
      executablePath: '/fixture/python',
      resolvedExecutablePath: '/fixture/python',
      executableDigest: `sha256:${'ee'.repeat(32)}`,
    },
  };
  return {
    ...core,
    evidenceDigest: sha256(canonicalJson(core)),
  };
}

function deterministicMaterialisationPrivateKey() {
  const seed = createHash('sha256')
    .update('repository-materialisation-control-plane-integrity-key')
    .digest();
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      seed,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
}

function materialisationFixture({
  candidateGraphs = AUTHORITY_GRAPH_INVENTORY,
  evaluatedAuthorityDigest = EVALUATED_AUTHORITY_DIGEST,
  graphCommit = OPTIONS.proofProducerCommit,
  graphTree = OPTIONS.proofProducerTree,
  implementationSourceRecords = null,
  mutateEvidenceCore = null,
  mutateStatement = null,
  mutateReceipt = null,
} = {}) {
  const graphs = structuredClone(candidateGraphs);
  const inventory = candidateDependencyDigestFromGraphs(graphs);
  const signatureVerification = {
    state: 'verified',
    signingKeyFingerprint: 'A'.repeat(40),
    primaryKeyFingerprint: 'B'.repeat(40),
  };
  const proofAlgorithmSourceDigest = `sha256:${'8'.repeat(64)}`;
  const runner = {
    sourcePath: MATERIALISATION_PROOF_RUNNER_PATH,
    sourceDigest: proofAlgorithmSourceDigest,
  };
  const implementationSources = implementationSourceRecords
    ?? MATERIALISATION_IMPLEMENTATION_SOURCE_PATHS.map((path, index) => ({
      path,
      digest: sha256(`materialisation-source-${index}`),
    }));
  const commandResults = [{
    id: 'fixture-command',
    executable: '/usr/bin/true',
    arguments: [],
    exitStatus: 0,
    signal: null,
    stdoutDigest: sha256(''),
    stderrDigest: sha256(''),
  }];
  const cases = [{
    id: 'positive-case',
    expected: true,
    observed: true,
    passed: true,
    negative: false,
  }, {
    id: 'negative-case',
    expected: 'rejected',
    observed: 'rejected',
    passed: true,
    negative: true,
  }];
  const evidenceCore = {
    schemaVersion: MATERIALISATION_EVIDENCE_SCHEMA_VERSION,
    recordKind: 'USF_VALIDATION_EVIDENCE_CANDIDATE',
    passed: true,
    eligibleForAdmission: false,
    authorityClaims: [],
    evaluatedAt: '2026-07-28T06:55:00Z',
    evaluatedAuthorityDigest,
    graphCommit,
    graphTree,
    signatureVerification,
    runner,
    toolchain: { node: { version: 'v22.23.1' } },
    toolchainDigest: `sha256:${'5'.repeat(64)}`,
    validationCommands: [{ executable: '/usr/bin/true', arguments: [] }],
    commandResults,
    candidateGraphInventoryAlgorithm:
      MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM,
    candidateGraphs: graphs,
    candidateAuthorityDigest: inventory.candidateAuthorityDigest,
    candidateDependencySetDigest: inventory.candidateDependencySetDigest,
    dependencyDigestAlgorithm: AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
    authorityBindingRule: SELF_PUBLICATION_RULE,
    excludedAuthorityGraphs: [...SELF_PUBLICATION_EXCLUDED_GRAPHS],
    implementationSourceDigest: sha256(canonicalMaterialisationJson(implementationSources)),
    implementationSources,
    proofAlgorithmSourceDigest,
    environmentClass: 'urn:usf:environmentclass:hermetic',
    providerMode: 'urn:usf:providermode:deterministictestsubstitute',
    cases,
    measurements: {
      candidateGraphCount: graphs.length,
      focusedTestCount: 1,
      materialisationRuleCount: 1,
      pathRoleCount: 1,
    },
    nonclaims: ['Fixture evidence is not semantic authority.'],
  };
  if (mutateEvidenceCore) mutateEvidenceCore(evidenceCore);
  const exactEvidenceSetDigest = sha256(canonicalMaterialisationJson(evidenceCore));
  const evidence = { ...evidenceCore, exactEvidenceSetDigest };
  const evidenceBytes = Buffer.from(canonicalMaterialisationJson(evidence));
  const descriptor = (bytes, mediaType) => {
    const digest = sha256(bytes);
    return {
      digest,
      byteSize: bytes.length,
      mediaType,
      locator: `cas://sha256/${digest.slice(7)}`,
    };
  };
  const evidenceManifest = descriptor(evidenceBytes, 'application/json');
  const privateKey = deterministicMaterialisationPrivateKey();
  const publicKey = createPublicKey(privateKey);
  const keyid = sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7);
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{
      name: 'repository-materialisation-control-plane-evidence',
      digest: { sha256: evidenceManifest.digest.slice(7) },
    }],
    predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
    predicate: {
      evidenceSchemaVersion: evidence.schemaVersion,
      evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
      candidateGraphInventoryAlgorithm: evidence.candidateGraphInventoryAlgorithm,
      candidateAuthorityDigest: evidence.candidateAuthorityDigest,
      candidateDependencySetDigest: evidence.candidateDependencySetDigest,
      exactEvidenceSetDigest: evidence.exactEvidenceSetDigest,
      implementationSourceDigest: evidence.implementationSourceDigest,
      proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
      result: 'passed',
    },
  };
  if (mutateStatement) mutateStatement(statement);
  const payloadType = 'application/vnd.in-toto+json';
  const statementBytes = Buffer.from(canonicalMaterialisationJson(statement));
  const pae = Buffer.concat([
    Buffer.from(
      `DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `,
    ),
    statementBytes,
  ]);
  const envelope = {
    payloadType,
    payload: statementBytes.toString('base64'),
    signatures: [{
      keyid,
      sig: sign(null, pae, privateKey).toString('base64'),
    }],
  };
  const attestationBytes = Buffer.from(canonicalMaterialisationJson(envelope));
  const proofAttestation = descriptor(attestationBytes, 'application/vnd.in-toto+json');
  const receipt = {
    schemaVersion: MATERIALISATION_RECEIPT_SCHEMA_VERSION,
    recordKind: 'USF_VALIDATION_EVIDENCE_CANDIDATE_RECEIPT',
    ok: true,
    passed: true,
    eligibleForAdmission: false,
    authorityClaims: [],
    evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
    graphCommit: evidence.graphCommit,
    graphTree: evidence.graphTree,
    signatureVerification,
    runner,
    toolchainDigest: evidence.toolchainDigest,
    commandResults,
    candidateGraphInventoryAlgorithm: evidence.candidateGraphInventoryAlgorithm,
    candidateAuthorityDigest: evidence.candidateAuthorityDigest,
    candidateDependencySetDigest: evidence.candidateDependencySetDigest,
    exactEvidenceSetDigest: evidence.exactEvidenceSetDigest,
    implementationSourceDigest: evidence.implementationSourceDigest,
    proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
    evidenceManifest,
    proofAttestation,
    signingKeyFingerprint: keyid,
    caseCount: evidence.cases.length,
    negativeCaseCount: evidence.cases.filter(({ negative }) => negative).length,
    failureCount: 0,
    outputRoot: 'SESSION_TRANSIENT_OUTPUT_ROOT',
  };
  if (mutateReceipt) mutateReceipt(receipt);
  return {
    materialisationReceipt: receipt,
    materialisationReceiptBytes: canonicalMaterialisationReceiptBytes(receipt),
    materialisationEvidenceBytes: evidenceBytes,
    materialisationAttestationBytes: attestationBytes,
    materialisationEvidence: evidence,
  };
}

function rebindMaterialisationBytes(input, field, bytes) {
  const descriptorField = field === 'materialisationEvidenceBytes'
    ? 'evidenceManifest'
    : 'proofAttestation';
  const mediaType = field === 'materialisationEvidenceBytes'
    ? 'application/json'
    : 'application/vnd.in-toto+json';
  const digest = sha256(bytes);
  input[field] = bytes;
  input.materialisationReceipt[descriptorField] = {
    digest,
    byteSize: bytes.length,
    mediaType,
    locator: `cas://sha256/${digest.slice(7)}`,
  };
  input.materialisationReceiptBytes =
    canonicalMaterialisationReceiptBytes(input.materialisationReceipt);
  return input;
}

function fixture({
  primaryProofPath = 'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs',
  claims = PROVIDER_WORKFORCE_REQUIRED_CLAIMS,
  caseIds = PROVIDER_WORKFORCE_REQUIRED_CASES,
  mutationPassedCaseCount = 26,
  evaluatedAt = '2026-07-28T07:00:00Z',
  implementationSourcePaths = ['src/usf_factory/providers/registry.py'],
  evidenceExtensions = {},
  proofAlgorithmSourcePaths = [
    primaryProofPath,
    'assurance/provider-workforce-closure/provider-materialisation-authority-mutations.mjs',
    'assurance/provider-workforce-closure/materialisation-proof-attestation-verifier.mjs',
    'assurance/provider-workforce-closure/provider-workforce-authority-projection.mjs',
    'assurance/semantic-model-compilation/local-shacl-validation.mjs',
    'capabilities/semantic-model-compilation/authority-binding.mjs',
    'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
  ],
} = {}) {
  const implementationSources = implementationSourcePaths.map((path, index) => ({
    path,
    digest: `sha256:${digestByte(index + 55)}`,
    byteSize: 81 + index,
  }));
  const proofAlgorithmSources = proofAlgorithmSourcePaths.map((path, index) => ({
    path,
    digest: `sha256:${digestByte(index + 66)}`,
  }));
  const proofAlgorithmSourceDigest = proofAlgorithmSources
    .find(({ path }) => path === primaryProofPath)?.digest ?? proofAlgorithmSources[0]?.digest;
  const proofAlgorithmSourceSetDigest = sha256(canonicalJson(proofAlgorithmSources));
  const proofInputSources = PROVIDER_WORKFORCE_PROOF_INPUT_PATHS.map((path, index) => ({
    path,
    digest: `sha256:${digestByte(index + 88)}`,
    byteSize: 101 + index,
  }));
  const pythonRuntimeCore = {
    schemaVersion: 3,
    executionMode: 'FD_PINNED_PROC_SELF_FD_WITH_LOGICAL_VENV_ARGV0_ISOLATED_NO_SITE',
    pythonVersion: '3.11.2',
    resolvedExecutableDigest: 'sha256:c6e1f1ef67ab331cbb83bfbd5bbb9b766fbb2228ce848b038141cb7d2cad3158',
    venvPrefix: '/fixture/venv',
    pyvenvConfigurationDigest: `sha256:${'fe'.repeat(32)}`,
    includeSystemSitePackages: false,
    distributionCount: 56,
    distributionSetDigest: 'sha256:8d8c40b038b21aaed0fc0d944912a2e0d6fea79add7463672abb1f1d38c65668',
    stdlibFileCount: 723,
    stdlibByteSetDigest: 'sha256:a789ca9789eb7ed46ef7d6733bfafea0f079ebe17f20c8a4b32dbf9bc3943b36',
    mappedSystemObjectCount: 23,
    mappedSystemObjectSetDigest: 'sha256:2aa149da8aefbaaa71c1f887620b75d2f47b9dea26f57663fa92eda8da92755f',
    nativeMappingEvidence: pythonNativeMappingEvidence(['RUNTIME_INSPECTOR_STEADY_STATE']),
    siteCustomizationLoaded: false,
  };
  const pythonRuntimeEvidence = {
    ...pythonRuntimeCore,
    evidenceDigest: sha256(canonicalJson(pythonRuntimeCore)),
  };
  const runtimeDependencyEvidence = {
    git: {
      schemaVersion: 1,
      executableDigest: 'sha256:2540879925a6881e3877ff7e3330746ba3027b04edf16a3a12dccd1644c4f32d',
      nativeObjectCount: 4,
      nativeObjectSetDigest: 'sha256:e94726f2d63131c39a6ef652c5368a50fca66686e1baf7ffbffd13f6ac86bc2e',
    },
    node: providerMaterialisationAuthorityMutationInternals.expectedNodeDependencyEvidence,
    python: pythonRuntimeEvidence,
  };
  const evidenceCore = {
    schemaVersion: 3,
    recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_CANDIDATE',
    passed: true,
    eligibleForAdmission: true,
    authorityClaims: [...claims],
    evaluatedAt,
    validUntil: '2026-08-27T07:00:00Z',
    evaluatedAuthorityDigest: EVALUATED_AUTHORITY_DIGEST,
    factoryCommit: '33'.repeat(20),
    factoryTree: '44'.repeat(20),
    implementationSourceDigest: sha256(canonicalJson(implementationSources)),
    implementationSources,
    proofInputSourceDigest: sha256(canonicalJson(proofInputSources)),
    proofInputSources,
    proofAlgorithmSourceDigest,
    proofAlgorithmSourceSetDigest,
    proofAlgorithmSources,
    runtimeDependencyEvidence,
    runtimeDependencyEvidenceDigest: sha256(canonicalJson(runtimeDependencyEvidence)),
    materialisationAuthorityMutationEvidence: mutationEvidence({
      passedCaseCount: mutationPassedCaseCount,
    }),
    environmentClass: 'urn:usf:environmentclass:hermetic',
    providerMode: 'urn:usf:providermode:deterministictestsubstitute',
    commands: [],
    cases: caseIds.map((id) => ({
      id, expected: true, observed: true, passed: true,
    })),
    policyDigest: `sha256:${'99'.repeat(32)}`,
    populationDigest: `sha256:${'aa'.repeat(32)}`,
    closureDigest: `sha256:${'bb'.repeat(32)}`,
    nonclaims: ['No production readiness claim.'],
    ...evidenceExtensions,
  };
  const exactEvidenceSetDigest = sha256(canonicalJson(evidenceCore));
  const evidence = { ...evidenceCore, exactEvidenceSetDigest };
  const evidenceBytes = Buffer.from(canonicalJson(evidence));
  const seed = createHash('sha256').update('provider-workforce-authority-integrity-key-v1').digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'provider-workforce-authority-evidence', digest: { sha256: sha256(evidenceBytes).slice(7) } }],
    predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
    predicate: {
      evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
      exactEvidenceSetDigest,
      implementationSourceDigest: evidence.implementationSourceDigest,
      proofInputSourceDigest: evidence.proofInputSourceDigest,
      proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
      proofAlgorithmSourceSetDigest: evidence.proofAlgorithmSourceSetDigest,
      runtimeDependencyEvidenceDigest: evidence.runtimeDependencyEvidenceDigest,
      result: 'passed',
    },
  };
  const payloadType = 'application/vnd.in-toto+json';
  const statementBytes = Buffer.from(canonicalJson(statement));
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `),
    statementBytes,
  ]);
  const signature = sign(null, pae, privateKey);
  const envelope = {
    payloadType,
    payload: statementBytes.toString('base64'),
    signatures: [{
      keyid: sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7),
      sig: signature.toString('base64'),
    }],
  };
  const attestationBytes = Buffer.from(canonicalJson(envelope));
  const descriptor = (bytes, mediaType) => ({
    digest: sha256(bytes),
    byteSize: bytes.length,
    mediaType,
    locator: `cas://sha256/${sha256(bytes).slice(7)}`,
  });
  const receipt = {
    schemaVersion: 3,
    recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_RECEIPT',
    ok: true,
    passed: true,
    eligibleForAdmission: true,
    authorityClaims: evidence.authorityClaims,
    evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
    evaluatedAt: evidence.evaluatedAt,
    validUntil: evidence.validUntil,
    factoryCommit: evidence.factoryCommit,
    factoryTree: evidence.factoryTree,
    implementationSourceDigest: evidence.implementationSourceDigest,
    proofInputSourceDigest: evidence.proofInputSourceDigest,
    proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
    proofAlgorithmSourceSetDigest: evidence.proofAlgorithmSourceSetDigest,
    runtimeDependencyEvidenceDigest: evidence.runtimeDependencyEvidenceDigest,
    exactEvidenceSetDigest,
    policyDigest: evidence.policyDigest,
    populationDigest: evidence.populationDigest,
    closureDigest: evidence.closureDigest,
    caseCount: evidence.cases.length,
    evidenceManifest: descriptor(evidenceBytes, 'application/json'),
    proofAttestation: descriptor(attestationBytes, 'application/vnd.in-toto+json'),
    signingKeyFingerprint: envelope.signatures[0].keyid,
    outputRoot: 'SESSION_TRANSIENT_OUTPUT_ROOT',
  };
  return {
    receipt,
    evidenceBytes,
    attestationBytes,
    ...materialisationFixture(),
  };
}

function project(input = fixture(), options = {}) {
  return projectProviderWorkforceAuthorityReceipt({
    ...input,
    ...OPTIONS,
    ...options,
  });
}

const prefixes = `
@prefix admission: <urn:usf:evidenceadmissionstate:>.
@prefix env: <urn:usf:environment:>.
@prefix evk: <urn:usf:evidencekind:>.
@prefix evr: <urn:usf:evidenceresult:>.
@prefix fresh: <urn:usf:freshness:>.
@prefix freshnessstate: <urn:usf:evidencefreshnessstate:>.
@prefix integritystate: <urn:usf:evidenceintegritystate:>.
@prefix pmode: <urn:usf:providermode:>.
@prefix rs: <urn:usf:resultstate:>.
@prefix rung: <urn:usf:proofrung:>.
@prefix usf: <urn:usf:ontology:>.
@prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
`;

test('accepts only a canonical successful validate-and-rollback candidate publication receipt', () => {
  const accepted = verifyCandidatePublicationReceipt({
    receipt: CANDIDATE_PUBLICATION_RECEIPT,
    receiptBytes: OPTIONS.candidatePublicationReceiptBytes,
    expectedAuthorityDigest: EVALUATED_AUTHORITY_DIGEST,
  });
  assert.equal(accepted.candidateInventoryDigest, CANDIDATE_AUTHORITY_DIGEST);
  assert.equal(accepted.candidateInventoryAlgorithm, 'sha256-rdfc10-managed-graph-inventory-v1');
  assert.equal(accepted.candidateGraphs.length, AUTHORITY_GRAPH_INVENTORY.length);

  for (const [mutate, pattern] of [
    [(receipt) => { receipt.receiptSchemaVersion = 1; }, /SCHEMA_INVALID|schema is unsupported/],
    [(receipt) => { receipt.mode = 'commit'; }, /NOT_SUCCESSFUL_VALIDATE/],
    [(receipt) => { receipt.ok = false; }, /NOT_SUCCESSFUL_VALIDATE/],
    [(receipt) => { receipt.commitOutcome.state = 'confirmed-response'; }, /OUTCOME_INVALID/],
    [(receipt) => { receipt.commitOutcome.exactCandidateStateVerified = false; }, /OUTCOME_INVALID/],
    [(receipt) => { receipt.commitOutcome.candidateGraphs = []; }, /GRAPH_INVENTORY_EMPTY/],
    [(receipt) => { receipt.commitOutcome.candidateGraphs[0].algorithm = 'URDNA2015'; }, /GRAPH_ALGORITHM_INVALID/],
    [(receipt) => { receipt.commitOutcome.candidateGraphs[0].digestAlgorithm = 'sha1'; }, /GRAPH_ALGORITHM_INVALID/],
    [(receipt) => { receipt.commitOutcome.candidateGraphs[0].sha256 = 'AA'.repeat(32); }, /GRAPH_DIGEST_INVALID/],
    [(receipt) => { receipt.commitOutcome.candidateGraphs[0].triples = -1; }, /GRAPH_TRIPLES_INVALID/],
    [(receipt) => { receipt.commitOutcome.candidateDigest = `sha256:${'01'.repeat(32)}`; }, /INVENTORY_DIGEST_MISMATCH/],
    [(receipt) => { receipt.commitOutcome.publicationBudget.result = 'REJECTED'; }, /BUDGET_INVALID/],
    [(receipt) => { receipt.commitOutcome.publicationBudget.candidateStatementCount += 1; }, /BUDGET_INVALID/],
    [(receipt) => { receipt.commitOutcome.publicationBudget.budgetDigest = `sha256:${'02'.repeat(32)}`; }, /BUDGET_DIGEST_MISMATCH/],
  ]) {
    const receipt = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
    mutate(receipt);
    assert.throws(() => verifyCandidatePublicationReceipt({
      receipt,
      receiptBytes: Buffer.from(`${JSON.stringify(receipt)}\n`),
      expectedAuthorityDigest: EVALUATED_AUTHORITY_DIGEST,
    }), pattern);
  }
  assert.throws(() => verifyCandidatePublicationReceipt({
    receipt: CANDIDATE_PUBLICATION_RECEIPT,
    receiptBytes: Buffer.from(` ${JSON.stringify(CANDIDATE_PUBLICATION_RECEIPT)}\n`),
    expectedAuthorityDigest: EVALUATED_AUTHORITY_DIGEST,
  }), /BYTES_NONCANONICAL/);
  assert.throws(() => verifyCandidatePublicationReceipt({
    receipt: CANDIDATE_PUBLICATION_RECEIPT,
    receiptBytes: OPTIONS.candidatePublicationReceiptBytes,
    expectedAuthorityDigest: `sha256:${'03'.repeat(32)}`,
  }), /AUTHORITY_BINDING_MISMATCH/);
});

test('candidate publication receipt binds the exact real schema, count types and policy core', () => {
  for (const [mutate, pattern] of [
    [(receipt) => { delete receipt.contaminationCount; }, /RECEIPT_FIELDS_INVALID/],
    [(receipt) => { receipt.contaminationCount = '0'; }, /CONTAMINATION_INVALID/],
    [(receipt) => { receipt.graphsCleared = 1.5; }, /GRAPHS_CLEARED_INVALID/],
    [(receipt) => { receipt.authoredLoaded = '20'; }, /AUTHORED_LOADED_INVALID/],
    [(receipt) => { receipt.shapesLoaded = -1; }, /SHAPES_LOADED_INVALID/],
    [(receipt) => { receipt.authorityWitness.extra = true; }, /AUTHORITY_WITNESS_FIELDS_INVALID/],
    [(receipt) => { delete receipt.authorityWitness.beforePublication.triples; },
      /BEFOREPUBLICATION_FIELDS_INVALID/],
    [(receipt) => { receipt.authorityWitness.settled.stable = 'true'; },
      /SETTLED_STABILITY_INVALID/],
  ]) {
    const receipt = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
    mutate(receipt);
    assert.throws(() => verifyCandidatePublicationReceipt({
      receipt,
      receiptBytes: Buffer.from(`${JSON.stringify(receipt)}\n`),
      expectedAuthorityDigest: EVALUATED_AUTHORITY_DIGEST,
    }), pattern);
  }

  const forgedPolicy = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  forgedPolicy.commitOutcome.publicationBudget.policyDigest = `sha256:${'ab'.repeat(32)}`;
  const { budgetDigest, result, ...budgetCore } = forgedPolicy.commitOutcome.publicationBudget;
  forgedPolicy.commitOutcome.publicationBudget.budgetDigest = sha256(canonicalJson(budgetCore));
  assert.throws(() => verifyCandidatePublicationReceipt({
    receipt: forgedPolicy,
    receiptBytes: Buffer.from(`${JSON.stringify(forgedPolicy)}\n`),
    expectedAuthorityDigest: EVALUATED_AUTHORITY_DIGEST,
  }), /BUDGET_POLICY_DIGEST_MISMATCH/);
});

test('candidate publication provenance requires exact canonical rerun bytes including key order', () => {
  const canonical = verifiedCandidate(structuredClone(CANDIDATE_PUBLICATION_RECEIPT));
  const source = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  const reordered = {
    authorityWitness: source.authorityWitness,
    shapesLoaded: source.shapesLoaded,
    authoredLoaded: source.authoredLoaded,
    graphsCleared: source.graphsCleared,
    contaminationCount: source.contaminationCount,
    commitOutcome: source.commitOutcome,
    ok: source.ok,
    mode: source.mode,
    receiptSchemaVersion: source.receiptSchemaVersion,
  };
  const reorderedCandidate = verifiedCandidate(reordered);
  assert.throws(
    () => assertSameCanonicalCandidate(reorderedCandidate, canonical),
    /RECEIPT_PROVENANCE_MISMATCH/,
  );

  const differentCandidateReceipt = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  differentCandidateReceipt.commitOutcome.candidateGraphs
    .find(({ graph }) => graph === 'urn:usf:graph:evidence').sha256 = 'fe'.repeat(32);
  rebindCandidateReceipt(differentCandidateReceipt);
  const differentCandidate = verifiedCandidate(differentCandidateReceipt);
  assert.throws(
    () => assertSameCanonicalCandidate(differentCandidate, canonical),
    /RECEIPT_PROVENANCE_MISMATCH/,
  );
});

test('candidate publication inventory rejects duplicate, unsorted and missing excluded graphs', () => {
  const duplicate = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  duplicate.commitOutcome.candidateGraphs.splice(1, 0,
    structuredClone(duplicate.commitOutcome.candidateGraphs[0]));
  assert.throws(() => verifyCandidatePublicationReceipt({
    receipt: duplicate,
    receiptBytes: Buffer.from(`${JSON.stringify(duplicate)}\n`),
  }), /GRAPH_ORDER_INVALID|GRAPH_DUPLICATE/);

  const unsorted = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  [unsorted.commitOutcome.candidateGraphs[0], unsorted.commitOutcome.candidateGraphs[1]]
    = [unsorted.commitOutcome.candidateGraphs[1], unsorted.commitOutcome.candidateGraphs[0]];
  assert.throws(() => verifyCandidatePublicationReceipt({
    receipt: unsorted,
    receiptBytes: Buffer.from(`${JSON.stringify(unsorted)}\n`),
  }), /GRAPH_ORDER_INVALID/);

  const missing = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  missing.commitOutcome.candidateGraphs = missing.commitOutcome.candidateGraphs
    .filter(({ graph }) => graph !== SELF_PUBLICATION_EXCLUDED_GRAPHS[0]);
  rebindCandidateReceipt(missing);
  assert.throws(() => verifyCandidatePublicationReceipt({
    receipt: missing,
    receiptBytes: Buffer.from(`${JSON.stringify(missing)}\n`),
  }), /EXCLUDED_GRAPH_ABSENT/);
});

test('materialisation artifacts are mandatory for direct projection callers and canonical byte exactness is enforced', () => {
  for (const field of [
    'materialisationReceipt',
    'materialisationReceiptBytes',
    'materialisationEvidenceBytes',
    'materialisationAttestationBytes',
  ]) {
    const input = fixture();
    delete input[field];
    assert.throws(() => project(input));
  }

  const receiptWhitespace = fixture();
  receiptWhitespace.materialisationReceiptBytes = Buffer.from(
    ` ${receiptWhitespace.materialisationReceiptBytes}`,
  );
  assert.throws(() => project(receiptWhitespace),
    /MATERIALISATION_RECEIPT_(?:JSON_INVALID|BYTES_NONCANONICAL)/);

  const evidenceWhitespace = fixture();
  rebindMaterialisationBytes(
    evidenceWhitespace,
    'materialisationEvidenceBytes',
    Buffer.concat([evidenceWhitespace.materialisationEvidenceBytes, Buffer.from('\n')]),
  );
  assert.throws(() => project(evidenceWhitespace),
    /MATERIALISATION_EVIDENCE_NOT_CANONICAL_JSON/);

  const attestationWhitespace = fixture();
  rebindMaterialisationBytes(
    attestationWhitespace,
    'materialisationAttestationBytes',
    Buffer.concat([attestationWhitespace.materialisationAttestationBytes, Buffer.from('\n')]),
  );
  assert.throws(() => project(attestationWhitespace),
    /MATERIALISATION_ATTESTATION_NOT_CANONICAL_JSON/);
});

test('CLI requires three exact materialisation files and rejects duplicates, non-files, symlinks and noncanonical bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-projector-materialisation-cli-'));
  try {
    const input = fixture();
    const paths = {
      receipt: join(root, 'provider-receipt.json'),
      evidence: join(root, 'provider-evidence.json'),
      attestation: join(root, 'provider-attestation.json'),
      candidate: join(root, 'candidate.json'),
      materialisationReceipt: join(root, 'materialisation-receipt.json'),
      materialisationEvidence: join(root, 'materialisation-evidence.json'),
      materialisationAttestation: join(root, 'materialisation-attestation.json'),
    };
    writeFileSync(paths.receipt, `${JSON.stringify(input.receipt, null, 2)}\n`);
    writeFileSync(paths.evidence, input.evidenceBytes);
    writeFileSync(paths.attestation, input.attestationBytes);
    writeFileSync(paths.candidate, OPTIONS.candidatePublicationReceiptBytes);
    writeFileSync(paths.materialisationReceipt, input.materialisationReceiptBytes);
    writeFileSync(paths.materialisationEvidence, input.materialisationEvidenceBytes);
    writeFileSync(paths.materialisationAttestation, input.materialisationAttestationBytes);
    const baseArguments = {
      'algorithm-version': OPTIONS.algorithmVersion,
      attestation: paths.attestation,
      'candidate-publication-receipt': paths.candidate,
      evidence: paths.evidence,
      'factory-repository-root': root,
      'local-shacl-python': process.execPath,
      'materialisation-attestation': paths.materialisationAttestation,
      'materialisation-evidence': paths.materialisationEvidence,
      'materialisation-receipt': paths.materialisationReceipt,
      'observed-at': OPTIONS.observedAt,
      'output-root': join(root, 'output'),
      'proof-producer-commit': OPTIONS.proofProducerCommit,
      'proof-producer-tree': OPTIONS.proofProducerTree,
      receipt: paths.receipt,
      'reevaluation-state': 'pending',
      'repository-root': root,
    };
    const cliArguments = (values) => Object.entries(values)
      .map(([name, value]) => `--${name}=${value}`);
    const expectFailure = (arguments_, pattern) => {
      assert.throws(
        () => execFileSync(process.execPath, [PROJECTOR_PATH, ...arguments_], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        }),
        (error) => pattern.test(String(error.stderr)),
      );
    };

    for (const name of [
      'materialisation-receipt',
      'materialisation-evidence',
      'materialisation-attestation',
    ]) {
      const missing = { ...baseArguments };
      delete missing[name];
      expectFailure(cliArguments(missing), /CLI_ARGUMENT_SET_INVALID/);
      expectFailure([
        ...cliArguments(baseArguments),
        `--${name}=${baseArguments[name]}`,
      ], new RegExp(`ARGUMENT_DUPLICATE_${name}`));

      const directory = join(root, `${name}-directory`);
      mkdirSync(directory);
      expectFailure(cliArguments({ ...baseArguments, [name]: directory }),
        new RegExp(`${name.replaceAll('-', '_').toUpperCase()}_NOT_EXACT_FILE`));

      const symlink = join(root, `${name}-symlink`);
      symlinkSync(baseArguments[name], symlink);
      expectFailure(cliArguments({ ...baseArguments, [name]: symlink }),
        new RegExp(`${name.replaceAll('-', '_').toUpperCase()}_NOT_EXACT_FILE`));
    }
    const linkedDirectory = join(root, 'linked-directory');
    const linkedDirectoryTarget = join(root, 'linked-directory-target');
    mkdirSync(linkedDirectoryTarget);
    writeFileSync(
      join(linkedDirectoryTarget, 'materialisation-receipt.json'),
      input.materialisationReceiptBytes,
    );
    symlinkSync(linkedDirectoryTarget, linkedDirectory);
    expectFailure(cliArguments({
      ...baseArguments,
      'materialisation-receipt':
        join(linkedDirectory, 'materialisation-receipt.json'),
    }), /MATERIALISATION_RECEIPT_PATH_NOT_EXACT/);
    const hardlinkedReceipt = join(root, 'materialisation-receipt-hardlink.json');
    linkSync(paths.materialisationReceipt, hardlinkedReceipt);
    expectFailure(cliArguments({
      ...baseArguments,
      'materialisation-receipt': hardlinkedReceipt,
    }), /MATERIALISATION_RECEIPT_NOT_EXACT_FILE/);
    rmSync(hardlinkedReceipt);

    writeFileSync(paths.materialisationReceipt,
      JSON.stringify(input.materialisationReceipt));
    expectFailure(cliArguments(baseArguments),
      /MATERIALISATION_RECEIPT_BYTES_NONCANONICAL/);

    writeFileSync(paths.materialisationReceipt, input.materialisationReceiptBytes);
    const evidenceWhitespace = Buffer.concat([
      input.materialisationEvidenceBytes,
      Buffer.from('\n'),
    ]);
    rebindMaterialisationBytes(input, 'materialisationEvidenceBytes', evidenceWhitespace);
    writeFileSync(paths.materialisationReceipt, input.materialisationReceiptBytes);
    writeFileSync(paths.materialisationEvidence, evidenceWhitespace);
    expectFailure(cliArguments(baseArguments),
      /MATERIALISATION_EVIDENCE_NOT_CANONICAL_JSON/);

    const attestationInput = fixture();
    const attestationWhitespace = Buffer.concat([
      attestationInput.materialisationAttestationBytes,
      Buffer.from('\n'),
    ]);
    rebindMaterialisationBytes(
      attestationInput,
      'materialisationAttestationBytes',
      attestationWhitespace,
    );
    writeFileSync(paths.materialisationReceipt,
      attestationInput.materialisationReceiptBytes);
    writeFileSync(paths.materialisationEvidence,
      attestationInput.materialisationEvidenceBytes);
    writeFileSync(paths.materialisationAttestation, attestationWhitespace);
    expectFailure(cliArguments(baseArguments),
      /MATERIALISATION_ATTESTATION_NOT_CANONICAL_JSON/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('materialisation receipt, manifest and DSSE cannot be paired across runs or rebound without a valid signature', () => {
  const left = fixture();
  const right = fixture();
  const rightEvidence = JSON.parse(right.materialisationEvidenceBytes);
  rightEvidence.evaluatedAt = '2026-07-28T06:56:00Z';
  const rightBytes = Buffer.from(canonicalMaterialisationJson(rightEvidence));
  assert.throws(() => project({
    ...left,
    materialisationEvidenceBytes: rightBytes,
  }), /MATERIALISATION_EVIDENCE_DIGEST_MISMATCH/);

  const invalidSignature = fixture();
  const envelope = JSON.parse(invalidSignature.materialisationAttestationBytes);
  const signature = Buffer.from(envelope.signatures[0].sig, 'base64');
  signature[0] ^= 1;
  envelope.signatures[0].sig = signature.toString('base64');
  rebindMaterialisationBytes(
    invalidSignature,
    'materialisationAttestationBytes',
    Buffer.from(canonicalMaterialisationJson(envelope)),
  );
  assert.throws(() => project(invalidSignature),
    /MATERIALISATION_ATTESTATION_SIGNATURE_VERIFICATION_FAILED/);
});

test('materialisation authority, graph commit and graph tree are cross-bound before projection', () => {
  for (const [override, pattern] of [
    [{
      ...materialisationFixture({
        evaluatedAuthorityDigest: `sha256:${'7'.repeat(64)}`,
      }),
    }, /MATERIALISATION_PROVIDER_AUTHORITY_BINDING_MISMATCH/],
    [{
      ...materialisationFixture({ graphCommit: '7'.repeat(40) }),
    }, /MATERIALISATION_PROOF_PRODUCER_COMMIT_MISMATCH/],
    [{
      ...materialisationFixture({ graphTree: '8'.repeat(40) }),
    }, /MATERIALISATION_PROOF_PRODUCER_TREE_MISMATCH/],
  ]) {
    assert.throws(() => project(fixture(), override), pattern);
  }
});

test('materialisation inventory is an exact full pre-projection candidate, not merely the same dependency set', () => {
  const changedExcludedGraphs = structuredClone(AUTHORITY_GRAPH_INVENTORY);
  changedExcludedGraphs
    .find(({ graph }) => graph === 'urn:usf:graph:evidence').sha256 = 'ef'.repeat(32);
  const changedMaterialisation = materialisationFixture({
    candidateGraphs: changedExcludedGraphs,
  });
  assert.equal(
    candidateDependencyDigestFromGraphs(changedExcludedGraphs).candidateDependencySetDigest,
    DEPENDENCY_SET_DIGEST,
  );
  assert.throws(() => project(fixture(), changedMaterialisation),
    /MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_MISMATCH/);
  const postCandidateWithPreAttestation =
    rebindCandidateReceipt(structuredClone(CANDIDATE_PUBLICATION_RECEIPT));
  postCandidateWithPreAttestation.commitOutcome.candidateGraphs
    .find(({ graph }) => graph === 'urn:usf:graph:evidence').sha256 = 'ce'.repeat(32);
  rebindCandidateReceipt(postCandidateWithPreAttestation);
  assert.throws(() => project(fixture(), {
    candidatePublicationReceipt: postCandidateWithPreAttestation,
    candidatePublicationReceiptBytes:
      Buffer.from(`${JSON.stringify(postCandidateWithPreAttestation)}\n`),
  }), /MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_MISMATCH/);

  const changedNonExcludedGraphs = structuredClone(AUTHORITY_GRAPH_INVENTORY);
  changedNonExcludedGraphs
    .find(({ graph }) => graph === 'urn:usf:graph:ontology').triples += 1;
  assert.throws(() => project(fixture(), materialisationFixture({
    candidateGraphs: changedNonExcludedGraphs,
  })), /MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_MISMATCH/);
});

test('materialisation cross-binding failure occurs before any projection apply callback', () => {
  let applyCount = 0;
  const changedGraphs = structuredClone(AUTHORITY_GRAPH_INVENTORY);
  changedGraphs
    .find(({ graph }) => graph === 'urn:usf:graph:evidence').sha256 = 'bc'.repeat(32);
  assert.throws(() => {
    const projection = project(fixture(), materialisationFixture({
      candidateGraphs: changedGraphs,
    }));
    applyProviderWorkforceProjectionWithClosure({
      applyProjection() {
        applyCount += 1;
        return projection;
      },
      verifyPostApplyClosure: () => Object.freeze({}),
      rollbackProjection: () => {},
    });
  }, /MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_MISMATCH/);
  assert.equal(applyCount, 0);
});

test('materialisation implementation-source and runner sets reject fully rebound substitutions', () => {
  const missingImplementation = materialisationFixture({
    mutateEvidenceCore(evidence) {
      evidence.implementationSources.pop();
      evidence.implementationSourceDigest =
        sha256(canonicalMaterialisationJson(evidence.implementationSources));
    },
  });
  assert.throws(() => project(fixture(), missingImplementation),
    /MATERIALISATION_EVIDENCE_IMPLEMENTATION_SOURCE_PATH_SET_INVALID/);

  const reorderedImplementation = materialisationFixture({
    mutateEvidenceCore(evidence) {
      [evidence.implementationSources[0], evidence.implementationSources[1]]
        = [evidence.implementationSources[1], evidence.implementationSources[0]];
      evidence.implementationSourceDigest =
        sha256(canonicalMaterialisationJson(evidence.implementationSources));
    },
  });
  assert.throws(() => project(fixture(), reorderedImplementation),
    /MATERIALISATION_EVIDENCE_IMPLEMENTATION_SOURCE_PATH_SET_INVALID/);

  const changedRunner = materialisationFixture({
    mutateEvidenceCore(evidence) {
      evidence.runner.sourcePath = 'assurance/semantic-model-compilation/alternate-runner.mjs';
    },
  });
  assert.throws(() => project(fixture(), changedRunner),
    /MATERIALISATION_EVIDENCE_RUNNER_PATH_INVALID/);
});

test('projection metadata uses only verifier-derived materialisation descriptors and bindings', () => {
  const input = fixture();
  const projected = project(input);
  assert.equal(
    projected.metadata.materialisationProofReceiptDigest,
    sha256(input.materialisationReceiptBytes),
  );
  assert.equal(
    projected.metadata.materialisationProofEvidenceDigest,
    input.materialisationReceipt.evidenceManifest.digest,
  );
  assert.equal(
    projected.metadata.materialisationProofAttestationDigest,
    input.materialisationReceipt.proofAttestation.digest,
  );
  assert.equal(
    projected.metadata.materialisationProofExactEvidenceSetDigest,
    input.materialisationReceipt.exactEvidenceSetDigest,
  );
  assert.equal(
    projected.metadata.materialisationProofSigningKeyFingerprint,
    input.materialisationReceipt.signingKeyFingerprint,
  );
  assert.equal(projected.metadata.candidateAuthorityDigest, CANDIDATE_AUTHORITY_DIGEST);
  assert.equal(projected.metadata.dependencySetDigest, DEPENDENCY_SET_DIGEST);
});

test('proof evidence schema v3 binds distinct primary and aggregate algorithm source digests', () => {
  const input = fixture();
  const evidence = JSON.parse(input.evidenceBytes);
  assert.equal(evidence.schemaVersion, 3);
  assert.equal(evidence.proofAlgorithmSourceDigest, evidence.proofAlgorithmSources[0].digest);
  assert.equal(
    evidence.proofAlgorithmSourceSetDigest,
    sha256(canonicalJson(evidence.proofAlgorithmSources)),
  );
  assert(evidence.proofAlgorithmSources.some(
    ({ path }) => path
      === 'assurance/provider-workforce-closure/materialisation-proof-attestation-verifier.mjs',
  ));

  const aggregateMismatch = fixture({
    evidenceExtensions: { proofAlgorithmSourceSetDigest: `sha256:${'0'.repeat(64)}` },
  });
  assert.throws(() => project(aggregateMismatch),
    /PROOF_ALGORITHM_SOURCE_SET_DIGEST_MISMATCH/);

  const primaryMismatch = fixture({
    evidenceExtensions: { proofAlgorithmSourceDigest: `sha256:${'1'.repeat(64)}` },
  });
  assert.throws(() => project(primaryMismatch),
    /PROOF_ALGORITHM_PRIMARY_SOURCE_DIGEST_MISMATCH/);
});

test('projects a verified receipt deterministically into parseable evidence and proof RDF', () => {
  const first = project();
  const second = project();
  assert.deepEqual(second, first);
  assert.doesNotThrow(() => new Parser({ format: 'text/turtle' }).parse(`${prefixes}\n${first.evidenceTurtle}`));
  assert.doesNotThrow(() => new Parser({ format: 'text/turtle' }).parse(`${prefixes}\n${first.proofsTurtle}`));
  assert.match(first.evidenceTurtle, /providerworkforceauthorityevidence/);
  assert.match(first.proofsTurtle, /proofreevaluationstate:pending/);
  assert.doesNotMatch(first.proofsTurtle, /reevaluationSettledAuthorityDigest/);
  assert.match(first.proofsTurtle, new RegExp(DEPENDENCY_SET_DIGEST));
  assert.match(first.proofsTurtle, new RegExp(`sha256:${digestByte(66)}`));
  assert.equal(first.metadata.primaryAlgorithmSourceDigest, `sha256:${digestByte(66)}`);
  assert.equal(first.metadata.proofAlgorithmSourceDigest, `sha256:${digestByte(66)}`);
  assert.equal(
    first.metadata.proofAlgorithmSourceSetDigest,
    JSON.parse(fixture().evidenceBytes).proofAlgorithmSourceSetDigest,
  );
  assert.match(first.proofsTurtle, /usf:proofAlgorithmSourceSetDigest/);
  assert.match(first.proofsTurtle, /usf:currentAlgorithmSourceSetDigest/);
  assert.match(first.proofsTurtle, /usf:proofAlgorithmVersionSourceSetDigest/);
  assert.match(first.proofsTurtle, /usf:algorithmSourceSetDigest/);
  assert.equal(first.metadata.materialisationProofGraphCommit, OPTIONS.proofProducerCommit);
  assert.equal(first.metadata.materialisationProofGraphTree, OPTIONS.proofProducerTree);
  assert.match(first.proofsTurtle, /provider-materialisation-authority-mutations[.]mjs|providerworkforceauthority/);
  assert.match(first.metadata.projectionDigest, /^sha256:[0-9a-f]{64}$/);
});

test('successful post-publication projection requires and records an exact settled binding', () => {
  const input = fixture();
  const result = project(input, {
    reevaluationState: 'successful',
    settledAuthorityDigest: input.receipt.evaluatedAuthorityDigest,
    reevaluatedAt: '2026-07-28T07:20:00Z',
  });
  assert.match(result.proofsTurtle, /proofreevaluationstate:successful/);
  assert.match(result.proofsTurtle, /reevaluationSettledAuthorityDigest/);
  assert.match(result.proofsTurtle, /reevaluationDependencySetDigest/);
  assert.match(result.proofsTurtle, /reevaluationEvidenceDigest/);
  assert.throws(() => project(input, {
    reevaluationState: 'successful',
    settledAuthorityDigest: `sha256:${'cc'.repeat(32)}`,
    reevaluatedAt: '2026-07-28T07:20:00Z',
  }), /SETTLED_AUTHORITY_DIGEST_MISMATCH/);
});

test('rejects a changed evidence payload instead of projecting receipt assertions', () => {
  const input = fixture();
  const changed = Buffer.from(input.evidenceBytes);
  changed[changed.length - 2] ^= 1;
  assert.throws(() => project({ ...input, evidenceBytes: changed }), /EVIDENCE_MANIFEST_DIGEST_MISMATCH/);
});

test('rejects an invalid DSSE signature even when the descriptor is recomputed', () => {
  const input = fixture();
  const envelope = JSON.parse(input.attestationBytes.toString('utf8'));
  const signature = Buffer.from(envelope.signatures[0].sig, 'base64');
  signature[0] ^= 1;
  envelope.signatures[0].sig = signature.toString('base64');
  const attestationBytes = Buffer.from(canonicalJson(envelope));
  const digest = sha256(attestationBytes);
  input.receipt.proofAttestation = {
    ...input.receipt.proofAttestation,
    digest,
    byteSize: attestationBytes.length,
    locator: `cas://sha256/${digest.slice(7)}`,
  };
  assert.throws(() => project({ ...input, attestationBytes }), /ATTESTATION_SIGNATURE_VERIFICATION_FAILED/);
});

test('rejects receipt-to-evidence binding drift', () => {
  const input = fixture();
  input.receipt.caseCount += 1;
  assert.throws(() => project(input), /RECEIPT_CASE_COUNT_MISMATCH/);
  const other = fixture();
  other.receipt.policyDigest = `sha256:${'cc'.repeat(32)}`;
  assert.throws(() => project(other), /RECEIPT_POLICYDIGEST_MISMATCH/);
  const wrongOutputRoot = fixture();
  wrongOutputRoot.receipt.outputRoot = '/tmp/forged-output';
  assert.throws(() => project(wrongOutputRoot), /RECEIPT_OUTPUT_ROOT_SENTINEL_INVALID/);
});

test('rejects unrecognised receipt, evidence and DSSE envelope fields', () => {
  const receiptInput = fixture();
  receiptInput.receipt.unrecognised = true;
  assert.throws(() => project(receiptInput), /RECEIPT_FIELDS_INVALID/);
  assert.throws(() => project(fixture({
    evidenceExtensions: { unrecognised: true },
  })), /EVIDENCE_FIELDS_INVALID/);
  const envelopeInput = fixture();
  const envelope = JSON.parse(envelopeInput.attestationBytes.toString('utf8'));
  envelope.unrecognised = true;
  const attestationBytes = Buffer.from(canonicalJson(envelope));
  const digest = sha256(attestationBytes);
  envelopeInput.receipt.proofAttestation = {
    ...envelopeInput.receipt.proofAttestation,
    digest,
    byteSize: attestationBytes.length,
    locator: `cas://sha256/${digest.slice(7)}`,
  };
  assert.throws(() => project({ ...envelopeInput, attestationBytes }), /ATTESTATION_FIELDS_INVALID/);
});

test('does not promote an incomplete claim, case, or hostile-mutation set', () => {
  assert.throws(() => project(fixture({
    claims: PROVIDER_WORKFORCE_REQUIRED_CLAIMS.slice(0, -1),
  })), /EVIDENCE_AUTHORITY_CLAIM_SET_MISMATCH/);
  assert.throws(() => project(fixture({
    caseIds: PROVIDER_WORKFORCE_REQUIRED_CASES.slice(0, -1),
  })), /EVIDENCE_CASE_SET_MISMATCH/);
  assert.throws(() => project(fixture({
    mutationPassedCaseCount: 20,
  })), /MATERIALISATION_MUTATION_EVIDENCE_HEADER_INVALID/);
});

test('binds every nested hostile-mutation case, source and digest', () => {
  assert.deepEqual(providerMaterialisationAuthorityMutationInternals.pythonArgumentPrefix, ['-I', '-S', '-']);
  assert.equal(providerMaterialisationAuthorityMutationInternals.pythonWorkingDirectory, '/');
  const valid = mutationEvidence();
  assert.equal(verifyProviderMaterialisationAuthorityMutationEvidence(valid), valid);
  const changedCase = structuredClone(valid);
  changedCase.cases[0].id = 'invented-case';
  assert.throws(
    () => verifyProviderMaterialisationAuthorityMutationEvidence(changedCase),
    /MATERIALISATION_MUTATION_CASE_INVALID_scope-mode-provider-flip/,
  );
  const changedSource = structuredClone(valid);
  changedSource.sourceRecords[0].path = 'semantic-model/shapes/invented.ttl';
  assert.throws(
    () => verifyProviderMaterialisationAuthorityMutationEvidence(changedSource),
    new RegExp(`MATERIALISATION_MUTATION_SOURCE_INVALID_${PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS[0]}`),
  );
  const changedCaseDigest = structuredClone(valid);
  changedCaseDigest.caseSetDigest = `sha256:${'01'.repeat(32)}`;
  assert.throws(
    () => verifyProviderMaterialisationAuthorityMutationEvidence(changedCaseDigest),
    /MATERIALISATION_MUTATION_CASE_SET_DIGEST_MISMATCH/,
  );
  const changedSourceDigest = structuredClone(valid);
  changedSourceDigest.sourceSetDigest = `sha256:${'02'.repeat(32)}`;
  assert.throws(
    () => verifyProviderMaterialisationAuthorityMutationEvidence(changedSourceDigest),
    /MATERIALISATION_MUTATION_SOURCE_SET_DIGEST_MISMATCH/,
  );
  const changedEvidenceDigest = structuredClone(valid);
  changedEvidenceDigest.evidenceDigest = `sha256:${'03'.repeat(32)}`;
  assert.throws(
    () => verifyProviderMaterialisationAuthorityMutationEvidence(changedEvidenceDigest),
    /MATERIALISATION_MUTATION_EVIDENCE_DIGEST_MISMATCH/,
  );
});

test('requires exact proof algorithm sources and safe unique implementation source paths', () => {
  const proofPath = 'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs';
  const mutationPath = 'assurance/provider-workforce-closure/provider-materialisation-authority-mutations.mjs';
  const materialisationVerifierPath =
    'assurance/provider-workforce-closure/materialisation-proof-attestation-verifier.mjs';
  const projectionPath =
    'assurance/provider-workforce-closure/provider-workforce-authority-projection.mjs';
  const localShaclPath = 'assurance/semantic-model-compilation/local-shacl-validation.mjs';
  const authorityBindingPath = 'capabilities/semantic-model-compilation/authority-binding.mjs';
  const materialisationPlanPath =
    'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';
  const exactProofPaths = [
    proofPath,
    mutationPath,
    materialisationVerifierPath,
    projectionPath,
    localShaclPath,
    authorityBindingPath,
    materialisationPlanPath,
  ];
  assert.throws(() => project(fixture({
    proofAlgorithmSourcePaths: exactProofPaths.slice(0, -1),
  })), /PROOF_ALGORITHM_SOURCE_SET_INVALID/);
  assert.throws(() => project(fixture({
    proofAlgorithmSourcePaths: [...exactProofPaths, 'assurance/provider-workforce-closure/extra.mjs'],
  })), /PROOF_ALGORITHM_SOURCE_SET_INVALID/);
  assert.throws(() => project(fixture({
    proofAlgorithmSourcePaths: [...exactProofPaths, mutationPath],
  })), /PROOF_ALGORITHM_SOURCE_SET_INVALID/);
  for (const implementationSourcePaths of [
    ['/tmp/factory.py'],
    ['src/usf_factory/../credentials.py'],
    ['src/usf_factory/providers/registry.py', 'src/usf_factory/providers/registry.py'],
  ]) {
    assert.throws(() => project(fixture({ implementationSourcePaths })),
      /IMPLEMENTATION_SOURCE_(?:RECORD_INVALID|PATH_DUPLICATE)/);
  }
});

test('binds proof and mutation source digests to the exact clean Git checkout', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-provider-projection-binding-'));
  const factoryRoot = mkdtempSync(join(tmpdir(), 'usf-factory-projection-binding-'));
  try {
    const paths = [
      'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs',
      'assurance/provider-workforce-closure/provider-materialisation-authority-mutations.mjs',
      'assurance/provider-workforce-closure/materialisation-proof-attestation-verifier.mjs',
      'assurance/provider-workforce-closure/provider-workforce-authority-projection.mjs',
      'assurance/semantic-model-compilation/local-shacl-validation.mjs',
      'capabilities/semantic-model-compilation/authority-binding.mjs',
      'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
      ...PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS,
      ...MATERIALISATION_IMPLEMENTATION_SOURCE_PATHS,
      MATERIALISATION_PROOF_RUNNER_PATH,
    ];
    for (const [index, path] of [...new Set(paths)].entries()) {
      mkdirSync(join(root, path, '..'), { recursive: true });
      writeFileSync(join(root, path), `fixture-${index}\n`);
    }
    for (const [index, path] of PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS.entries()) {
      mkdirSync(join(factoryRoot, path, '..'), { recursive: true });
      writeFileSync(join(factoryRoot, path), `factory-fixture-${index}\n`);
    }
    for (const [index, path] of PROVIDER_WORKFORCE_PROOF_INPUT_PATHS.entries()) {
      mkdirSync(join(factoryRoot, path, '..'), { recursive: true });
      writeFileSync(join(factoryRoot, path), `factory-proof-input-${index}\n`);
    }
    for (const repository of [root, factoryRoot]) {
      execFileSync('/usr/bin/git', ['init', '-q', repository]);
      execFileSync('/usr/bin/git', ['-C', repository, 'config', 'user.name', 'USF Test']);
      execFileSync('/usr/bin/git', ['-C', repository, 'config', 'user.email', 'usf-test@example.invalid']);
      execFileSync('/usr/bin/git', ['-C', repository, 'add', '.']);
      execFileSync('/usr/bin/git', ['-C', repository, 'commit', '-q', '-m', 'fixture']);
    }
    const commit = execFileSync('/usr/bin/git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const tree = execFileSync('/usr/bin/git', ['-C', root, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim();
    const factoryCommit = execFileSync('/usr/bin/git', ['-C', factoryRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const factoryTree = execFileSync('/usr/bin/git', ['-C', factoryRoot, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim();
    const proofAlgorithmSources = paths.slice(0, 7).map((path) => ({
      path,
      digest: sha256(readFileSync(join(root, path))),
    }));
    const sourceRecords = PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS.map((path) => ({
      path,
      digest: sha256(readFileSync(join(root, path))),
    }));
    const implementationSources = PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS.map((path) => ({
      path,
      digest: sha256(readFileSync(join(factoryRoot, path))),
      byteSize: readFileSync(join(factoryRoot, path)).length,
    }));
    const proofInputSources = PROVIDER_WORKFORCE_PROOF_INPUT_PATHS.map((path) => ({
      path,
      digest: sha256(readFileSync(join(factoryRoot, path))),
      byteSize: readFileSync(join(factoryRoot, path)).length,
    }));
    const evidence = {
      factoryCommit,
      factoryTree,
      implementationSources,
      implementationSourceDigest: sha256(canonicalJson(implementationSources)),
      proofInputSources,
      proofInputSourceDigest: sha256(canonicalJson(proofInputSources)),
      proofAlgorithmSources,
      proofAlgorithmSourceDigest: proofAlgorithmSources[0].digest,
      proofAlgorithmSourceSetDigest: sha256(canonicalJson(proofAlgorithmSources)),
      materialisationAuthorityMutationEvidence: mutationEvidence({ sourceRecords }),
    };
    const materialisationImplementationSources = MATERIALISATION_IMPLEMENTATION_SOURCE_PATHS
      .map((path) => ({
        path,
        digest: sha256(readFileSync(join(root, path))),
      }));
    const materialisation = {
      evidence: {
        graphCommit: commit,
        graphTree: tree,
        implementationSources: materialisationImplementationSources,
        implementationSourceDigest: sha256(canonicalJson(materialisationImplementationSources)),
        runner: {
          sourcePath: MATERIALISATION_PROOF_RUNNER_PATH,
          sourceDigest: sha256(readFileSync(join(root, MATERIALISATION_PROOF_RUNNER_PATH))),
        },
      },
    };
    const repositories = { repositoryRoot: root, factoryRepositoryRoot: factoryRoot };
    const executionIdentityBefore =
      providerWorkforceAuthorityProjectionInternals.exactExecutionSourceIdentitySnapshot({
        repositories,
        evidence,
        materialisation,
      });
    const swappedPath = join(
      root,
      'assurance/provider-workforce-closure/materialisation-proof-attestation-verifier.mjs',
    );
    const swappedBytes = readFileSync(swappedPath);
    writeFileSync(swappedPath, 'transient source substitution\n');
    writeFileSync(swappedPath, swappedBytes);
    const executionIdentityAfter =
      providerWorkforceAuthorityProjectionInternals.exactExecutionSourceIdentitySnapshot({
        repositories,
        evidence,
        materialisation,
      });
    assert.notDeepEqual(executionIdentityAfter, executionIdentityBefore);
    assert.deepEqual(verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: tree,
      evidence,
      materialisation,
    }), { repositoryRoot: root, factoryRepositoryRoot: factoryRoot });
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: tree,
      evidence,
    }), /MATERIALISATION_PROOF_ATTESTATION_BINDING_REQUIRED/);
    const changedMaterialisationSource = structuredClone(materialisation);
    changedMaterialisationSource.evidence.implementationSources[0].digest =
      `sha256:${'06'.repeat(32)}`;
    changedMaterialisationSource.evidence.implementationSourceDigest = sha256(
      canonicalJson(changedMaterialisationSource.evidence.implementationSources),
    );
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: tree,
      evidence,
      materialisation: changedMaterialisationSource,
    }), /MATERIALISATION_IMPLEMENTATION_SOURCE_0_CHECKOUT_DIGEST_MISMATCH/);
    const changedMaterialisationRunner = structuredClone(materialisation);
    changedMaterialisationRunner.evidence.runner.sourceDigest = `sha256:${'07'.repeat(32)}`;
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: tree,
      evidence,
      materialisation: changedMaterialisationRunner,
    }), /MATERIALISATION_PROOF_RUNNER_CHECKOUT_DIGEST_MISMATCH/);
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: '00'.repeat(20),
      proofProducerTree: tree,
      evidence,
      materialisation,
    }), /PROOF_PRODUCER_COMMIT_NOT_CHECKOUT_HEAD/);
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: '00'.repeat(20),
      evidence,
      materialisation,
    }), /PROOF_PRODUCER_TREE_NOT_CHECKOUT_TREE/);
    const changed = structuredClone(evidence);
    changed.proofAlgorithmSources[0].digest = `sha256:${'04'.repeat(32)}`;
    changed.proofAlgorithmSourceDigest = changed.proofAlgorithmSources[0].digest;
    changed.proofAlgorithmSourceSetDigest = sha256(canonicalJson(changed.proofAlgorithmSources));
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: tree,
      evidence: changed,
      materialisation,
    }), /PROOF_ALGORITHM_SOURCE_0_CHECKOUT_DIGEST_MISMATCH/);
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: tree,
      evidence: { ...evidence, factoryCommit: '00'.repeat(20) },
      materialisation,
    }), /FACTORY_PRODUCER_COMMIT_NOT_CHECKOUT_HEAD/);
    const changedFactory = structuredClone(evidence);
    changedFactory.implementationSources[0].digest = `sha256:${'05'.repeat(32)}`;
    changedFactory.implementationSourceDigest = sha256(canonicalJson(changedFactory.implementationSources));
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: tree,
      evidence: changedFactory,
      materialisation,
    }), /IMPLEMENTATION_SOURCE_0_CHECKOUT_DIGEST_MISMATCH/);
    writeFileSync(join(root, paths[0]), 'dirty\n');
    assert.throws(() => verifyProjectionRepositoryBinding({
      repositoryRoot: root,
      factoryRepositoryRoot: factoryRoot,
      proofProducerCommit: commit,
      proofProducerTree: tree,
      evidence,
      materialisation,
    }), /PROOF_PRODUCER_WORKTREE_NOT_CLEAN/);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(factoryRoot, { recursive: true, force: true });
  }
});

test('rejects a parseable but non-canonical evidence timestamp', () => {
  assert.throws(() => project(fixture({
    evaluatedAt: '2026-07-28T17:00:00+10:00',
  })), /EVIDENCE_EVALUATED_AT_INVALID/);
});

test('pending projection rejects invented settled re-evaluation facts', () => {
  const input = fixture();
  assert.throws(() => project(input, {
    settledAuthorityDigest: input.receipt.evaluatedAuthorityDigest,
  }), /PENDING_REEVALUATION_HAS_SETTLED_FIELDS/);
});

test('derives the dependency-set digest from the exact authority graph inventory', () => {
  assert.equal(project().metadata.dependencySetDigest, DEPENDENCY_SET_DIGEST);
  const changed = rebindCandidateReceipt(structuredClone(CANDIDATE_PUBLICATION_RECEIPT));
  changed.commitOutcome.candidateGraphs
    .find(({ graph }) => graph === 'urn:usf:graph:ontology').sha256 = 'cc'.repeat(32);
  rebindCandidateReceipt(changed);
  assert.notEqual(project(fixture(), candidateReceiptOptions(changed)).metadata.dependencySetDigest,
    DEPENDENCY_SET_DIGEST);
  const missing = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  missing.commitOutcome.candidateGraphs = missing.commitOutcome.candidateGraphs
    .filter(({ graph }) => graph !== 'urn:usf:graph:proofs');
  rebindCandidateReceipt(missing);
  assert.throws(() => project(fixture(), candidateReceiptOptions(missing)),
    /(?:CANDIDATE_PUBLICATION|MATERIALISATION_CANDIDATE)_EXCLUDED_GRAPH_ABSENT/);
});

test('requires the evidence validity window to contain the canonical observation time', () => {
  assert.throws(() => project(fixture(), {
    observedAt: '2026-07-28T06:59:59Z',
  }), /EVIDENCE_NOT_YET_VALID/);
  assert.throws(() => project(fixture(), {
    observedAt: '2026-08-27T07:00:00Z',
  }), /EVIDENCE_EXPIRED/);
});

test('rejects session-specific absolute proof source paths', () => {
  const input = fixture({
    primaryProofPath: '/tmp/worktree/assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs',
  });
  assert.throws(() => project(input), /PROOF_ALGORITHM_SOURCE_RECORD_INVALID/);
});

test('session output preparation rejects symlink escape before creation or deletion', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-provider-output-root-'));
  const outside = mkdtempSync(join(tmpdir(), 'usf-provider-output-outside-'));
  try {
    mkdirSync(join(root, '.work'));
    writeFileSync(join(outside, 'sentinel'), 'keep\n');
    symlinkSync(outside, join(root, '.work', 'link'));
    assert.throws(() => prepareProjectionOutputRoot(
      root,
      join(root, '.work', 'link', 'created'),
    ), /OUTPUT_ROOT_NOT_DIRECT_SESSION_CHILD/);
    assert.equal(existsSync(join(outside, 'created')), false);
    assert.throws(() => prepareExactSessionOutputRoot({
      repositoryRoot: root,
      requestedOutputRoot: join(root, '.work', 'link'),
      clear: true,
    }), /OUTPUT_ROOT_NOT_EXACT_DIRECTORY/);
    assert.equal(readFileSync(join(outside, 'sentinel'), 'utf8'), 'keep\n');

    const outputRoot = prepareProjectionOutputRoot(root, join(root, '.work', 'projection'));
    symlinkSync(join(outside, 'sentinel'), join(outputRoot, 'symlink-leaf'));
    assert.throws(
      () => prepareProjectionOutputRoot(root, outputRoot),
      /PROJECTION_OUTPUT_CHILD_NOT_EXACT_FILE/,
    );
    rmSync(join(outputRoot, 'symlink-leaf'));

    linkSync(join(outside, 'sentinel'), join(outputRoot, 'hardlink-leaf'));
    assert.throws(
      () => prepareProjectionOutputRoot(root, outputRoot),
      /PROJECTION_OUTPUT_CHILD_NOT_EXACT_FILE/,
    );
    rmSync(join(outputRoot, 'hardlink-leaf'));

    mkdirSync(join(outputRoot, 'directory-leaf'));
    assert.throws(
      () => prepareProjectionOutputRoot(root, outputRoot),
      /PROJECTION_OUTPUT_CHILD_NOT_EXACT_FILE/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('post-projection closure rejects graph drift, additions and removals but permits exact excluded changes', () => {
  const before = verifiedCandidate(structuredClone(CANDIDATE_PUBLICATION_RECEIPT));

  const allowed = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  allowed.commitOutcome.candidateGraphs
    .find(({ graph }) => graph === 'urn:usf:graph:evidence').sha256 = 'ed'.repeat(32);
  rebindCandidateReceipt(allowed);
  assert.doesNotThrow(() => assertPostProjectionCandidateClosure(
    before,
    verifiedCandidate(allowed),
  ));

  const drifted = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  drifted.commitOutcome.candidateGraphs
    .find(({ graph }) => graph === 'urn:usf:graph:ontology').sha256 = 'dc'.repeat(32);
  rebindCandidateReceipt(drifted);
  assert.throws(() => assertPostProjectionCandidateClosure(
    before,
    verifiedCandidate(drifted),
  ), /POST_PROJECTION_NONEXCLUDED_GRAPH_MOVED/);

  const added = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  added.commitOutcome.candidateGraphs.push({
    graph: 'urn:usf:graph:z-added',
    algorithm: 'RDFC-1.0',
    digestAlgorithm: 'sha256',
    sha256: 'ad'.repeat(32),
    triples: 1,
  });
  rebindCandidateReceipt(added);
  assert.throws(() => assertPostProjectionCandidateClosure(
    before,
    verifiedCandidate(added),
  ), /POST_PROJECTION_GRAPH_SET_MISMATCH/);

  const removed = structuredClone(CANDIDATE_PUBLICATION_RECEIPT);
  removed.commitOutcome.candidateGraphs = removed.commitOutcome.candidateGraphs
    .filter(({ graph }) => graph !== 'urn:usf:graph:ontology');
  rebindCandidateReceipt(removed);
  assert.throws(() => assertPostProjectionCandidateClosure(
    before,
    verifiedCandidate(removed),
  ), /POST_PROJECTION_GRAPH_SET_MISMATCH/);
});

test('post-apply closure failure invokes rollback for both projection sources', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-post-closure-rollback-'));
  const evidencePath = join(root, 'evidence.trig');
  const proofsPath = join(root, 'proofs.trig');
  const evidenceBefore = Buffer.from('before-evidence\n');
  const proofsBefore = Buffer.from('before-proofs\n');
  try {
    writeFileSync(evidencePath, evidenceBefore);
    writeFileSync(proofsPath, proofsBefore);
    assert.throws(() => applyProviderWorkforceProjectionWithClosure({
      applyProjection() {
        writeFileSync(evidencePath, 'projected-evidence\n');
        writeFileSync(proofsPath, 'projected-proofs\n');
        return Object.freeze({ evidencePath, proofsPath });
      },
      verifyPostApplyClosure() {
        assert.equal(readFileSync(evidencePath, 'utf8'), 'projected-evidence\n');
        assert.equal(readFileSync(proofsPath, 'utf8'), 'projected-proofs\n');
        throw new Error('POST_PROJECTION_NONEXCLUDED_GRAPH_MOVED');
      },
      rollbackProjection() {
        writeFileSync(evidencePath, evidenceBefore);
        writeFileSync(proofsPath, proofsBefore);
      },
    }), /POST_PROJECTION_NONEXCLUDED_GRAPH_MOVED/);
    assert(readFileSync(evidencePath).equals(evidenceBefore));
    assert(readFileSync(proofsPath).equals(proofsBefore));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }

  assert.throws(() => applyProviderWorkforceProjectionWithClosure({
    applyProjection: () => Object.freeze({ id: 'applied' }),
    verifyPostApplyClosure() {
      throw new Error('POST_PROJECTION_GRAPH_SET_MISMATCH');
    },
    rollbackProjection() {
      throw new Error('PROOF_POST_CLOSURE_ROLLBACK_VERIFICATION_FAILED');
    },
  }), (error) => error instanceof AggregateError
    && error.message === 'PROJECTION_POST_CLOSURE_AND_ROLLBACK_FAILED'
    && error.errors.length === 2);
});

test('projection application is impossible without the private reproduced-evidence binding', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-provider-projection-'));
  try {
    const assurance = join(root, 'semantic-model/assurance');
    mkdirSync(assurance, { recursive: true });
    const evidencePath = join(assurance, 'evidence.trig');
    const proofPath = join(assurance, 'proofs.trig');
    const evidenceBefore = '@prefix usf: <urn:usf:ontology:>.\n# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE\n<urn:old:evidence> a usf:Policy.\n# END GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE\n';
    const proofBefore = '@prefix usf: <urn:usf:ontology:>.\n# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF\n<urn:old:proof> a usf:Policy.\n# END GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF\n}\n';
    writeFileSync(evidencePath, evidenceBefore);
    writeFileSync(proofPath, proofBefore);
    let renameCount = 0;
    const operations = {
      writeFileSync,
      rmSync,
      renameSync(source, target) {
        renameCount += 1;
        renameSync(source, target);
      },
    };
    assert.throws(() => replaceProviderWorkforceAuthorityProjection(root, project(), null, operations),
      /PROJECTION_APPLICATION_BINDING_INVALID/);
    const forgedBinding = new Proxy({}, {
      get(_target, property) {
        if (typeof property === 'symbol') return true;
        if (property === 'repositoryRoot') return root;
        return undefined;
      },
    });
    assert.throws(() => replaceProviderWorkforceAuthorityProjection(root, project(), forgedBinding, operations),
      /PROJECTION_APPLICATION_BINDING_INVALID/);
    assert.equal(renameCount, 0);
    assert.equal(readFileSync(evidencePath, 'utf8'), evidenceBefore);
    assert.equal(readFileSync(proofPath, 'utf8'), proofBefore);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('pytest command evidence removes only volatile summaries and preserves exact progress', () => {
  const left = normaliseDeterministicPytestOutput(
    '........................................................................ [ 97%]\n..                                                                       [100%]\n74 passed in 1.23s\n',
  );
  const right = normaliseDeterministicPytestOutput(
    '........................................................................ [ 97%]\n..                                                                       [100%]\n74 passed in 9.87s\n',
  );
  assert.deepEqual(left, right);
  assert.notDeepEqual(
    left,
    normaliseDeterministicPytestOutput(
      '....................................................................... [ 96%]\n...                                                                      [100%]\n74 passed in 1.23s\n',
    ),
  );
  assert.throws(
    () => normaliseDeterministicPytestOutput('..F [100%]\n'),
    /PYTEST_PROGRESS_OUTPUT_INVALID/,
  );
});

test('node dependency evidence changes when an executed package byte changes', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-provider-node-dependencies-'));
  try {
    const parent = join(root, 'node_modules', 'root-package');
    const child = join(root, 'node_modules', 'child-package');
    mkdirSync(parent, { recursive: true });
    mkdirSync(child, { recursive: true });
    writeFileSync(join(root, 'package.json'), canonicalJson({
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { 'root-package': '1.0.0' },
    }));
    writeFileSync(join(root, 'package-lock.json'), canonicalJson({
      name: 'fixture-root',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'fixture-root',
          version: '1.0.0',
          dependencies: { 'root-package': '1.0.0' },
        },
        'node_modules/root-package': {
          version: '1.0.0',
          dependencies: { 'child-package': '1.0.0' },
        },
        'node_modules/child-package': {
          version: '1.0.0',
        },
      },
    }));
    writeFileSync(join(parent, 'package.json'), canonicalJson({
      name: 'root-package',
      version: '1.0.0',
      dependencies: { 'child-package': '1.0.0' },
    }));
    writeFileSync(join(parent, 'index.js'), 'export const value = 1;\n');
    writeFileSync(join(child, 'package.json'), canonicalJson({
      name: 'child-package',
      version: '1.0.0',
    }));
    writeFileSync(join(child, 'index.js'), 'export const child = 1;\n');
    const resolvePackageJson = (name) => join(root, 'node_modules', name, 'package.json');
    const before = providerMaterialisationAuthorityMutationInternals.inspectNodeDependencyEvidence({
      repositoryRoot: root,
      rootPackages: ['root-package'],
      resolvePackageJson,
    });
    writeFileSync(join(child, 'index.js'), 'export const child = 2;\n');
    const after = providerMaterialisationAuthorityMutationInternals.inspectNodeDependencyEvidence({
      repositoryRoot: root,
      rootPackages: ['root-package'],
      resolvePackageJson,
    });
    assert.notEqual(before.packageByteSetDigest, after.packageByteSetDigest);
    assert.notEqual(
      before.packages.find(({ name }) => name === 'child-package')?.byteSetDigest,
      after.packages.find(({ name }) => name === 'child-package')?.byteSetDigest,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
