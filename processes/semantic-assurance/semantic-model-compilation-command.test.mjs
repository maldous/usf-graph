import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DataFactory, Parser, Writer } from 'n3';

import {
  SEMANTIC_MODEL_PATH,
  createSemanticModelCompilationCommand,
  handoverD1ReconciliationReceiptDigest,
  semanticModelCompilationCommandInternals,
} from './semantic-model-compilation-command.mjs';
import {
  materializeAggregateCompilerAuthorityCandidateV2,
} from '../../assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.mjs';
import { semanticAuthorityInventoryDigest } from './semantic-authority-gateway.mjs';
import {
  createCasEvidenceStore,
  createGraphNativeSuccessorStoreV2,
} from './semantic-authority-publication.mjs';
import {
  canonicalGraphDigest,
  canonicalInventoryGraphDigest,
} from '../../capabilities/semantic-model-compilation/compiler.mjs';

const authorityDigest = `sha256:${'a'.repeat(64)}`;
const repositories = [];
const requiredHistoryMode = ['lin', 'ear'].join('');
const oneParentHistoryShape = ['one-parent-lin', 'ear'].join('');

function repository() {
  const root = mkdtempSync(join(tmpdir(), 'usf-semantic-assurance-'));
  mkdirSync(join(root, SEMANTIC_MODEL_PATH));
  repositories.push(root);
  return root;
}

// The publication lane is an explicit dependency with no host-path default, so
// each test roots the V1 retirement interlock in its own isolated directory
// rather than in whatever the host happens to have at /var/lib/usf-programme.
// Same rule for the terminal-ownership floor: an empty floor must mean "no
// terminal generation in THIS root", never "no root was configured".
function isolatedNativeGraphStore() {
  const root = mkdtempSync(join(tmpdir(), 'usf-native-floor-'));
  repositories.push(root);
  const casRoot = mkdtempSync(join(tmpdir(), 'usf-native-floor-cas-'));
  repositories.push(casRoot);
  return createGraphNativeSuccessorStoreV2({
    nativeRoot: root,
    casStore: createCasEvidenceStore(casRoot),
  });
}

function publicationLane() {
  const root = mkdtempSync(join(tmpdir(), 'usf-publication-lane-'));
  repositories.push(root);
  return semanticModelCompilationCommandInternals.createSemanticPublicationLaneV2(root);
}

function rootedPublicationLane() {
  const root = mkdtempSync(join(tmpdir(), 'usf-publication-lane-'));
  repositories.push(root);
  return {
    lane: semanticModelCompilationCommandInternals.createSemanticPublicationLaneV2(root),
    root,
  };
}

test.after(() => repositories.forEach((root) => rmSync(root, { recursive: true, force: true })));

test('candidate transaction snapshots require one self-consistent opening authority state', () => {
  const graph = 'urn:usf:graph:authority';
  const inventory = [{ graph, sha256: `sha256:${'1'.repeat(64)}`, triples: 1 }];
  const openingFold = semanticAuthorityInventoryDigest(inventory, 1);
  const snapshot = { digest: openingFold, observedGraphs: [graph] };
  const assertSnapshot = semanticModelCompilationCommandInternals
    .assertTransactionSnapshotMatchesWitness;

  assert.doesNotThrow(() => assertSnapshot(snapshot, {
    digest: openingFold,
    inventory,
  }));
  assert.throws(() => assertSnapshot(snapshot, {
    digest: `sha256:${'2'.repeat(64)}`,
    inventory,
  }), /opening authority witness digest does not match its graph inventory/);
  assert.throws(() => assertSnapshot({
    ...snapshot,
    observedGraphs: [graph, 'urn:usf:graph:unexpected'],
  }, {
    digest: openingFold,
    inventory,
  }), /transaction authority graph set differs from the opening witness/);
  assert.throws(() => assertSnapshot({
    ...snapshot,
    digest: `sha256:${'3'.repeat(64)}`,
  }, {
    digest: openingFold,
    inventory,
  }), /transaction authority state differs from the opening witness/);
});

test('implementation work grant delta is derived from exact reviewed CAS artifacts and rejects substitution', () => {
  const allowedActions = [
    'candidate_existing_file_edit', 'candidate_signing_and_protection', 'cas_closure',
    'compilation_and_build', 'evidence_generation', 'independent_review',
    'isolated_read_only_rehearsal', 'tests',
  ];
  const deniedEffects = [
    'a0_capture', 'authority_mutation', 'business_semantic_scope_expansion', 'deployment',
    'implicit_path_widening', 'learned_execution', 'production_write', 'provider_contact',
    'pruning', 'semantic_publication', 'v2_activation',
  ];
  const scopes = [
    {
      predecessor_commit: '1'.repeat(40), predecessor_tree: '2'.repeat(40), repository: 'maldous/usf-factory',
      source_paths: ['src/usf_factory/activation.py'],
      source_scope_digest: contentDigest(Buffer.from(stableJson(['src/usf_factory/activation.py']))),
    },
    {
      predecessor_commit: '3'.repeat(40), predecessor_tree: '4'.repeat(40), repository: 'maldous/usf-graph',
      source_paths: ['processes/semantic-assurance/semantic-proof-v2.mjs'],
      source_scope_digest: contentDigest(Buffer.from(stableJson(['processes/semantic-assurance/semantic-proof-v2.mjs']))),
    },
  ];
  const decision = {
    allowed_actions: allowedActions, authority_pre_digest: authorityDigest, decision_state: 'accepted',
    denied_effects: deniedEffects, expires_at: '2026-08-20T00:00:00Z', issued_at: '2026-08-16T00:00:00Z',
    nonpublication_dependency_set_digest: contentDigest(Buffer.from('non-publication dependency')),
    purpose: 'V2_NATIVE_HANDOVER implementation only', repositories: scopes,
    schema_version: 'usf-implementation-work-grant-decision-v1',
  };
  const decisionBytes = canonicalArtifactBytes(decision);
  const review = {
    authority_pre_digest: authorityDigest, candidate_derivation_participation: false,
    decision_digest: contentDigest(decisionBytes), governance_independent_review_satisfied: true,
    review_state: 'accepted', schema_version: 'usf-implementation-work-grant-review-v1',
  };
  const reviewBytes = canonicalArtifactBytes(review);
  const validation = {
    authority_pre_digest: authorityDigest, decision_digest: contentDigest(decisionBytes),
    review_digest: contentDigest(reviewBytes), schema_version: 'usf-implementation-work-grant-validation-v1',
    validation_state: 'passed',
  };
  const validationBytes = canonicalArtifactBytes(validation);
  const evidenceDigests = [contentDigest(decisionBytes), contentDigest(reviewBytes), contentDigest(validationBytes)].sort();
  const payload = {
    algorithm: 'openpgp', allowed_actions: allowedActions, authority_pre_digest: authorityDigest,
    claim_type: 'implementation_work_grant', denied_effects: deniedEffects,
    evidence_set_digest: contentDigest(Buffer.from(stableJson(evidenceDigests))),
    expires_at: decision.expires_at, fingerprint: 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D',
    issued_at: decision.issued_at, nonce: '00000000-0000-4000-8000-000000000009',
    nonpublication_dependency_set_digest: decision.nonpublication_dependency_set_digest,
    principal: 'urn:usf:principal:matthewaldous', protocol: 'semantic-proof-v1',
    purpose: decision.purpose, repositories: scopes, schema_version: 'usf-implementation-work-grant-v1',
    signing_identity: 'urn:usf:signingidentity:matthewaldoussemanticproofv1', single_use: true,
  };
  const grant = { payload, signature: '-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n' };
  const grantBytes = canonicalArtifactBytes(grant);
  const candidateDigest = contentDigest(Buffer.from(stableJson(payload)));
  const artifacts = [
    { bytes: decisionBytes, role: 'decision' }, { bytes: grantBytes, role: 'grant' },
    { bytes: reviewBytes, role: 'review' }, { bytes: validationBytes, role: 'validation' },
  ];
  const verifier = (envelope, options) => {
    assert.deepEqual(envelope, grant);
    assert.deepEqual(options.evidenceDigests, evidenceDigests);
    return { ...payload, candidate_digest: candidateDigest, envelope_digest: contentDigest(Buffer.from(stableJson(grant))) };
  };
  const packageValue = semanticModelCompilationCommandInternals.createImplementationWorkGrantDeltaPackage({
    artifacts, authorityDigest, now: new Date('2026-08-16T01:00:00Z'), verifyImplementationWorkGrant: verifier,
  });
  const store = new Map(artifacts.map(({ bytes }) => [contentDigest(bytes), bytes]));
  const evidenceStore = {
    read: (digest) => store.get(digest),
    verify: (digest) => ({ digest, size: store.get(digest)?.length }),
  };
  const asserted = semanticModelCompilationCommandInternals.assertImplementationWorkGrantDelta({
    value: packageValue, expectedAuthorityDigest: authorityDigest, evidenceStore,
    allowedGraphs: new Set(['urn:usf:graph:evidence', 'urn:usf:graph:proofs']),
    now: new Date('2026-08-16T01:00:00Z'), verifyImplementationWorkGrant: verifier,
  });
  assert.equal(asserted.grantCandidateDigest, candidateDigest);
  assert.equal(asserted.patchDigest, packageValue.patchDigest);
  for (const predicate of ['descriptorArtefactFamily', 'descriptorRepresentationFormat', 'descriptorArtefactType']) {
    assert.equal(packageValue.permittedOperations.filter((operation) => operation.includes(predicate)).length, 4);
  }
  assert.ok(packageValue.permittedOperations.some((operation) => operation.includes(
    'urn:usf:implementationworkrepositoryscope:usffactory',
  )));
  assert.ok(packageValue.permittedOperations.some((operation) => operation.includes(
    'urn:usf:implementationworkrepositoryscope:usfgraph',
  )));
  assert.equal(packageValue.permittedOperations.some((operation) => operation.includes(
    'urn:usf:implementationworkrepositoryscope:usf-',
  )), false);
  assert.throws(() => semanticModelCompilationCommandInternals.assertImplementationWorkGrantDelta({
    value: { ...packageValue, grantCandidateDigest: contentDigest(Buffer.from('wrong')) },
    expectedAuthorityDigest: authorityDigest, evidenceStore,
    allowedGraphs: new Set(['urn:usf:graph:evidence', 'urn:usf:graph:proofs']),
    now: new Date('2026-08-16T01:00:00Z'), verifyImplementationWorkGrant: verifier,
  }), /candidate|derived closed operation set/);
});

function client() { return { connectivity: async () => 1 }; }

test('validates the canonical semantic model with an exact authority binding', async () => {
  const calls = [];
  const command = createSemanticModelCompilationCommand({
    publicationLane: publicationLane(),
    nativeGraphStore: isolatedNativeGraphStore(),
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    loadManifestFunction: (path) => ({ path }),
    compileFunction: async (input) => { calls.push(input); return { ok: true, commitOutcome: { state: 'validated-rolled-back' } }; },
  });
  const result = await command.execute({ expectedAuthorityDigest: authorityDigest });
  assert.equal(result.semanticModelPath, SEMANTIC_MODEL_PATH);
  assert.equal(result.evaluatedAuthorityDigest, authorityDigest);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].publicationMode, 'validate');
  assert.equal(calls[0].authorityWitness.digest, authorityDigest);
  assert.ok(calls[0].manifest.path.endsWith(`/${SEMANTIC_MODEL_PATH}`));
});

test('fails before loading or compiling when authority drift is observed', async () => {
  let loaded = false;
  const command = createSemanticModelCompilationCommand({
    publicationLane: publicationLane(),
    nativeGraphStore: isolatedNativeGraphStore(),
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: `sha256:${'b'.repeat(64)}` }),
    loadManifestFunction: () => { loaded = true; },
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({ expectedAuthorityDigest: authorityDigest }), /drifted before compilation/);
  assert.equal(loaded, false);
});

test('detects mutation during a validate-only transaction', async () => {
  let reads = 0;
  const command = createSemanticModelCompilationCommand({
    publicationLane: publicationLane(),
    nativeGraphStore: isolatedNativeGraphStore(),
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: reads++ === 0 ? authorityDigest : `sha256:${'c'.repeat(64)}` }),
    loadManifestFunction: () => ({}),
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({ expectedAuthorityDigest: authorityDigest }), /validate-only compilation changed/);
});

test('requires an explicit digest and the canonical non-symlink path', async () => {
  const command = createSemanticModelCompilationCommand({
    publicationLane: publicationLane(),
    nativeGraphStore: isolatedNativeGraphStore(),
    client: client(),
    repositoryRoot: repository(),
    readAuthorityWitness: async () => ({ digest: authorityDigest }),
    loadManifestFunction: () => ({}),
    compileFunction: async () => ({ ok: true }),
  });
  await assert.rejects(() => command.execute({}), /expected authority digest/);
});

const stableJson = (value) => JSON.stringify(
  value && typeof value === 'object' && !Array.isArray(value)
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [
      key,
      Array.isArray(value[key])
        ? value[key].map((item) => item && typeof item === 'object' && !Array.isArray(item)
          ? JSON.parse(stableJson(item))
          : item)
        : value[key] && typeof value[key] === 'object'
          ? JSON.parse(stableJson(value[key]))
          : value[key],
    ]))
    : value,
);
const canonicalArtifactBytes = (value) => Buffer.from(`${JSON.stringify(JSON.parse(stableJson(value)), null, 2)}\n`);
const contentDigest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const jcsDigest = (value) => contentDigest(Buffer.from(stableJson(value)));

function externalAuthorityFixture({
  contentLocator = false,
  decisionState = 'ACCEPTED',
  proofState = 'PASSED',
  reviewVerdict = 'ACCEPTED',
  validUntil = '2026-08-12T00:00:00Z',
} = {}) {
  const repositoryId = 'maldous/usf-graph';
  const predecessorHead = 'c'.repeat(40);
  const predecessorTree = 'd'.repeat(40);
  const successorTree = 'e'.repeat(40);
  const sourcePaths = ['processes/semantic-assurance/semantic-model-compilation-command.mjs'];
  const scopeDigest = contentDigest(Buffer.from(stableJson(sourcePaths)));
  const sourceBytes = Buffer.from('predecessor\n');
  const successor = 'successor\n';
  const operationContentDigest = contentDigest(Buffer.from(successor));
  const operationsValue = [{
    action: 'write-file',
    artefactFamily: 'urn:usf:artefactfamily:processsource',
    ...(contentLocator ? {} : { content: successor }),
    contentDigest: operationContentDigest,
    ...(contentLocator
      ? { contentLocator: contentLocator === true
        ? `cas://sha256/${operationContentDigest.slice(7)}` : contentLocator }
      : { contentEncoding: 'utf8' }),
    index: 0,
    path: sourcePaths[0],
    pathRole: 'urn:usf:pathrole:processsource',
    representationFormat: 'urn:usf:representationformat:ecmascriptmodule2024',
    sourceDigest: contentDigest(sourceBytes),
  }];
  const operationsBytes = canonicalArtifactBytes(operationsValue);
  const operationDigest = contentDigest(Buffer.from(stableJson({
    operations: operationsValue,
    repository: repositoryId,
    schemaVersion: 1,
  })));
  const obligations = ['urn:usf:validationobligation:operationexpectedoutcomeerrorclass'];
  const inventoryValue = {
    authority: { digest: authorityDigest, graph_count: 1, triple_count: 1 },
    candidate_source: {
      added_path_count: 0,
      changed_path_count: 1,
      deleted_path_count: 0,
      focused_verification: { failed: 0, passed: 1 },
      history_shape: oneParentHistoryShape,
      predecessor_commit: predecessorHead,
      predecessor_tree: predecessorTree,
      repository: repositoryId,
      source_records: [{
        mode: '100644',
        path: sourcePaths[0],
        predecessor_digest: operationsValue[0].sourceDigest,
        successor_digest: operationsValue[0].contentDigest,
      }],
      staged_deletions: 1,
      staged_insertions: 1,
      staged_successor_tree: successorTree,
    },
    corrections: [{
      candidate: {},
      defect: 'exact defect',
      obligation: obligations[0],
      owner_authored_paths: sourcePaths,
      status: 'REFERENCE_ONLY_CANDIDATE',
    }],
    current_execution_boundary: {
      action_state: 'PROCEED',
      execution_scope_digest: contentDigest(Buffer.from('scope')),
      execution_scope_iri: 'urn:usf:contractexecutionscope:fixture',
      execution_scope_projection_digest: contentDigest(Buffer.from('projection')),
      maximum_repository_writes: 0,
      mode: 'readonlysemanticvalidation',
      permitted_effect: 'urn:usf:executioneffect:validationevidencecandidate',
      repository_mutation_permitted: false,
      status: 'CONFLICT_RESOLUTION_AND_VALIDATION_CLOSURE_REQUIRED_FAIL_CLOSED',
      unresolved_validation_obligations: obligations,
      validation_satisfied: false,
      write_paths: [],
    },
    nonclaims: [],
    owner_precedent: {},
    predecessor_request: {},
    proof_preflight: {},
    protected_graph_source: {
      commit: predecessorHead,
      parent: 'b'.repeat(40),
      required_history: requiredHistoryMode,
      tree: predecessorTree,
    },
    required_authority_actions: [],
    required_validation_invariants: [],
    schema: 'usf-repository-materialisation-semantic-correction-authority-request-v3',
    source_scope: {
      authority_projection_additions: {},
      current_path_count: 1,
      current_scope_digest: scopeDigest,
      successor_path_count: 1,
      successor_scope_digest: scopeDigest,
    },
    status: 'REFERENCE_ONLY_VALIDATION_EVIDENCE_CANDIDATE_AWAITING_EXACT_CONFLICT_RESOLUTION',
    supporting_integrity_corrections: {},
  };
  const inventoryBytes = canonicalArtifactBytes(inventoryValue);
  const inventoryDigest = contentDigest(inventoryBytes);
  const reviewValue = {
    authorshipIndependence: {
      candidateDerivationParticipation: false,
      priorReviewConclusionsUsed: false,
      reviewDerivation: 'independent exact recomputation',
      reviewerRole: 'independent-usf-semantic-reviewer',
    },
    candidateSource: {
      baseCommit: predecessorHead,
      baseParent: 'b'.repeat(40),
      baseTree: predecessorTree,
      changedPaths: sourcePaths,
      sourceRecordCount: 1,
      sourceRecordsExact: true,
      sourceRecordsJcsSha256: jcsDigest(inventoryValue.candidate_source.source_records),
      stagedDeletions: 1,
      stagedInsertions: 1,
      stagedSuccessorTree: successorTree,
      trackedDeltaExact: true,
      trackedPathAdditions: 0,
      trackedPathDeletions: 0,
    },
    currentExecutionBoundary: {},
    governanceIndependentReviewSatisfied: true,
    liveAuthority: {
      digest: authorityDigest,
      digestAlgorithm: 'sha256-rdfc10-graph-inventory-v2',
      graphCount: 1,
      stableAcrossReview: true,
      tripleCount: 1,
    },
    nonclaims: [],
    obligations: {
      currentValidationResultCounts: { [obligations[0]]: 0 },
      requiredAuthorityActionCount: 1,
      requiredValidationInvariantCount: 1,
      targetValidationObligations: obligations,
    },
    publicationReadiness: 'NOT_READY_REFERENCE_ONLY_AWAITING_OWNER_DECISION_PROOF_AND_V1_PUBLICATION',
    request: {
      byteCount: inventoryBytes.length,
      jcsSha256: jcsDigest(inventoryValue),
      path: '.work/request.json',
      rawSha256: inventoryDigest,
      schema: inventoryValue.schema,
      status: inventoryValue.status,
      terminalLf: true,
    },
    reviewArtifactStorageClass: 'session-transient-gitignored',
    schema: 'usf-semantic-adequacy-review-core-v1',
    sourceOrAuthorityMutationPerformed: false,
    verdict: reviewVerdict,
    verification: {},
  };
  const reviewBytes = canonicalArtifactBytes(reviewValue);
  const inputDescriptors = {
    inventory: {
      byteSize: inventoryBytes.length,
      digest: inventoryDigest,
      jcsDigest: jcsDigest(inventoryValue),
    },
    operations: {
      byteSize: operationsBytes.length,
      digest: contentDigest(operationsBytes),
      jcsDigest: jcsDigest(operationsValue),
    },
    review: {
      byteSize: reviewBytes.length,
      digest: contentDigest(reviewBytes),
      jcsDigest: jcsDigest(reviewValue),
    },
  };
  const ownerAssignmentIri = 'urn:usf:ownerassignment:semanticmodelcompilation:matthewaldous';
  const conflictBinding = {
    conflictingAuthorities: [
      'urn:usf:semanticcontract:compilersemanticenforcement',
      'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation',
    ],
    operationDigest,
    requestedActions: ['write-file'],
    requestedEffects: ['urn:usf:obligationeffect:blocking'],
    requestedFormats: ['urn:usf:representationformat:ecmascriptmodule2024'],
    requestedPaths: sourcePaths,
    sourcePaths,
    sourceScopeDigest: scopeDigest,
    successorSourceTree: successorTree,
    validationObligations: obligations,
  };
  const proofValue = {
    artifacts: inputDescriptors,
    authorityDigest,
    candidateDigest: inventoryDigest,
    conflict: {
      authorities: conflictBinding.conflictingAuthorities,
      operationDigest,
      requestedActions: conflictBinding.requestedActions,
      requestedEffects: conflictBinding.requestedEffects,
      requestedFormats: conflictBinding.requestedFormats,
      requestedPaths: conflictBinding.requestedPaths,
      validationObligations: obligations,
    },
    decision: {
      ownerAssignmentIri,
      rationale: 'Approve only this exact reviewed correction and no unrelated effect.',
      state: decisionState,
    },
    evidenceSetDigest: contentDigest(Buffer.from(stableJson(inputDescriptors))),
    nonclaims: [
      'NO_FACTORY_MUTATION',
      'NO_PRODUCTION_PRUNING',
      'NO_PROVIDER_CONTACT',
      'NO_V2_ACTIVATION',
      'NO_DEPLOYMENT',
    ],
    proof: {
      algorithmIri: 'urn:usf:proofalgorithm:compilersemanticenforcementaggregate',
      algorithmVersionIri: 'urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210',
      evaluatedAt: '2026-08-11T00:00:00Z',
      obligationIri: 'urn:usf:proofobligation:compilersemanticenforcementaggregate',
      resultState: 'SUCCESSFUL',
      state: proofState,
      subjectCandidateDigest: inventoryDigest,
      validUntil,
    },
    repository: repositoryId,
    review: {
      defectCount: 0,
      digest: inputDescriptors.review.digest,
      independent: true,
      state: 'ACCEPTED',
    },
    schema: 'usf-authority-conflict-proof-decision-v1',
    source: {
      predecessorHead,
      predecessorTree,
      sourcePaths,
      sourceScopeDigest: scopeDigest,
      successorTree,
    },
  };
  const proofBytes = canonicalArtifactBytes(proofValue);
  const proofDigest = contentDigest(proofBytes);
  const proofApprovalEnvelope = {
    payload: { candidate_digest: proofDigest },
    signature: 'fixture-owner-signature',
  };
  const verifiedApproval = () => ({
    authority_domain: 'urn:usf:capabilityowner:semanticmodelcompilation',
    authority_pre_digest: authorityDigest,
    candidate_digest: proofDigest,
    claim_type: 'candidate_approval',
    expires_at: '2026-08-12T00:00:00Z',
    fingerprint: 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D',
    principal: 'urn:usf:principal:matthewaldous',
    repository: repositoryId,
    signing_identity: 'urn:usf:signingidentity:matthewaldoussemanticproofv1',
    single_use: false,
    source_scope_digest: scopeDigest,
  });
  const artifactBytes = new Map([
    ['inventory', inventoryBytes],
    ['operations', operationsBytes],
    ['proof', proofBytes],
    ['review', reviewBytes],
  ]);
  const operationContentStore = {
    read: (digest) => digest === operationContentDigest ? Buffer.from(successor) : undefined,
    verify: (digest) => digest === operationContentDigest
      ? { digest, size: Buffer.byteLength(successor) } : undefined,
  };
  const packageValue = semanticModelCompilationCommandInternals.createExternalAuthorityDeltaPackage({
    artifacts: [...artifactBytes].map(([role, bytes]) => ({ bytes, role })),
    authorityDigest,
    conflictBinding,
    correctionCandidateDigest: inventoryDigest,
    now: new Date('2026-08-11T00:00:01Z'),
    ownerAssignmentIri,
    predecessorSourceHead: predecessorHead,
    predecessorSourceTree: predecessorTree,
    operationContentStore,
    proofApprovalEnvelope,
    repository: repositoryId,
    verifyProofApprovalEnvelope: verifiedApproval,
  });
  const evidenceStore = {
    read: (digest) => digest === operationContentDigest
      ? Buffer.from(successor)
      : Buffer.from([...artifactBytes.values()].find((bytes) => contentDigest(bytes) === digest)),
    verify: (digest) => {
      if (digest === operationContentDigest) return { digest, size: Buffer.byteLength(successor) };
      const bytes = [...artifactBytes.values()].find((item) => contentDigest(item) === digest);
      return { digest, size: bytes.length };
    },
  };
  return {
    artifactBytes,
    conflictBinding,
    evidenceStore,
    inventoryDigest,
    operationContentDigest,
    ownerAssignmentIri,
    packageValue,
    proofApprovalEnvelope,
    source: { head: predecessorHead, repository: repositoryId, tree: predecessorTree },
    verifiedApproval,
  };
}

test('admits only canonical owner-approved evidence-backed conflict resolution', () => {
  const fixture = externalAuthorityFixture();
  const options = {
    allowedGraphs: new Set(['urn:usf:graph:evidence', 'urn:usf:graph:proofs']),
    evidenceStore: fixture.evidenceStore,
    expectedAuthorityDigest: authorityDigest,
    expectedSource: fixture.source,
    now: new Date('2026-08-11T00:00:01Z'),
    value: fixture.packageValue,
    verifyProofApprovalEnvelope: fixture.verifiedApproval,
  };
  const accepted = semanticModelCompilationCommandInternals.assertExternalAuthorityDelta(options);
  assert.equal(accepted.patchDigest, fixture.packageValue.patchDigest);
  assert.equal(accepted.correctionCandidateDigest, fixture.inventoryDigest);
  const patchText = Buffer.from(fixture.packageValue.patchBytesBase64, 'base64').toString('utf8');
  assert.match(patchText, /semanticadequacyoperations/);
  assert.match(patchText, /<urn:usf:ontology:evidenceFor> <urn:usf:authorityconflict:/);
  const mutatePatch = (mutator) => {
    const lines = patchText.trimEnd().split('\n');
    const header = lines.shift();
    const permittedOperations = mutator(lines).sort();
    const bytes = Buffer.from([header, ...permittedOperations, ''].join('\n'));
    return {
      ...fixture.packageValue,
      patchBytesBase64: bytes.toString('base64'),
      patchDigest: contentDigest(bytes),
      permittedOperations,
    };
  };
  assert.throws(() => semanticModelCompilationCommandInternals.assertExternalAuthorityDelta({
    ...options,
    value: mutatePatch((lines) => lines.map((line) => line.includes('<urn:usf:ontology:evidenceFor>')
      ? line.replace(`<${fixture.packageValue.conflictIri}>`, '<urn:usf:authorityconflict:substituted>')
      : line)),
  }), /evidence subject is not exact|missing exact evidence subject/);

  assert.throws(() => semanticModelCompilationCommandInternals.assertExternalAuthorityDelta({
    ...options,
    evidenceStore: {
      ...fixture.evidenceStore,
      read: (digest) => digest === fixture.packageValue.artifactDescriptors
        .find(({ role }) => role === 'proof').digest
        ? Buffer.from('not-json')
        : fixture.evidenceStore.read(digest),
    },
  }), /CAS verifier returned an invalid receipt|not canonical UTF-8 JSON/);

  assert.throws(() => semanticModelCompilationCommandInternals.assertExternalAuthorityDelta({
    ...options,
    verifyProofApprovalEnvelope: () => { throw new Error('bad signature'); },
  }), /owner approval is invalid/);

  assert.throws(() => semanticModelCompilationCommandInternals.createExternalAuthorityDeltaPackage({
    artifacts: [...fixture.artifactBytes].map(([role, bytes]) => ({ bytes, role })),
    authorityDigest,
    conflictBinding: {
      ...fixture.conflictBinding,
      sourceScopeDigest: `sha256:${'7'.repeat(64)}`,
    },
    correctionCandidateDigest: fixture.inventoryDigest,
    now: new Date('2026-08-11T00:00:01Z'),
    ownerAssignmentIri: fixture.ownerAssignmentIri,
    predecessorSourceHead: fixture.source.head,
    predecessorSourceTree: fixture.source.tree,
    proofApprovalEnvelope: fixture.proofApprovalEnvelope,
    repository: fixture.source.repository,
    verifyProofApprovalEnvelope: fixture.verifiedApproval,
  }), /source-scope digest was not derived/);

  assert.throws(() => semanticModelCompilationCommandInternals.createExternalAuthorityDeltaPackage({
    artifacts: [...fixture.artifactBytes].map(([role, bytes]) => ({ bytes, role })),
    authorityDigest,
    conflictBinding: {
      ...fixture.conflictBinding,
      operationDigest: `sha256:${'8'.repeat(64)}`,
    },
    correctionCandidateDigest: fixture.inventoryDigest,
    now: new Date('2026-08-11T00:00:01Z'),
    ownerAssignmentIri: fixture.ownerAssignmentIri,
    predecessorSourceHead: fixture.source.head,
    predecessorSourceTree: fixture.source.tree,
    proofApprovalEnvelope: fixture.proofApprovalEnvelope,
    repository: fixture.source.repository,
    verifyProofApprovalEnvelope: fixture.verifiedApproval,
  }), /operation or source-scope digest was not derived/);

  assert.throws(() => externalAuthorityFixture({ reviewVerdict: 'REJECTED' }),
    /review is not exact, independent and accepted/);
  assert.throws(() => externalAuthorityFixture({ proofState: 'FAILED' }),
    /proof\/decision is not exact, current and owner-authored/);
  assert.throws(() => externalAuthorityFixture({ decisionState: 'REJECTED' }),
    /proof\/decision is not exact, current and owner-authored/);
  assert.throws(() => externalAuthorityFixture({ validUntil: '2026-08-11T00:00:00Z' }),
    /proof\/decision is not exact, current and owner-authored/);

  const unrelated = '<urn:usf:semanticcontract:compilersemanticenforcement> <http://www.w3.org/2000/01/rdf-schema#comment> "UNRELATED" <urn:usf:graph:proofs> .';
  const lines = Buffer.from(fixture.packageValue.patchBytesBase64, 'base64').toString('utf8').trimEnd().split('\n');
  const header = lines.shift();
  const permittedOperations = [...lines, `A ${unrelated}`].sort();
  const patchBytes = Buffer.from([header, ...permittedOperations, ''].join('\n'));
  assert.throws(() => semanticModelCompilationCommandInternals.assertExternalAuthorityDelta({
    ...options,
    value: {
      ...fixture.packageValue,
      patchBytesBase64: patchBytes.toString('base64'),
      patchDigest: contentDigest(patchBytes),
      permittedOperations,
    },
  }), /contains an unrelated semantic operation/);
});

test('external authority operations accept exact immutable CAS content and reject locator substitution', () => {
  const fixture = externalAuthorityFixture({ contentLocator: true });
  const options = {
    allowedGraphs: new Set(['urn:usf:graph:evidence', 'urn:usf:graph:proofs']),
    evidenceStore: fixture.evidenceStore,
    expectedAuthorityDigest: authorityDigest,
    expectedSource: fixture.source,
    now: new Date('2026-08-11T00:00:01Z'),
    value: fixture.packageValue,
    verifyProofApprovalEnvelope: fixture.verifiedApproval,
  };
  assert.equal(
    semanticModelCompilationCommandInternals.assertExternalAuthorityDelta(options).patchDigest,
    fixture.packageValue.patchDigest,
  );
  assert.throws(() => externalAuthorityFixture({ contentLocator: 'substituted' }),
    /external authority write operation is not exact and preimage-bound/);
  assert.throws(() => semanticModelCompilationCommandInternals.assertExternalAuthorityDelta({
    ...options,
    evidenceStore: {
      ...fixture.evidenceStore,
      read: (digest) => digest === fixture.operationContentDigest
        ? Buffer.from('substituted') : fixture.evidenceStore.read(digest),
    },
  }), /external authority write operation is not exact and preimage-bound/);
});
test('composes and applies exact D0 stage1 and D1 stage2 source-plus-generated deltas', async () => {
  const root = repository();
  const graph = 'urn:test:graph';
  const unmanagedGraph = 'urn:test:unmanaged-live-graph';
  const proofsGraph = 'urn:usf:graph:proofs';
  const bindingsGraph = 'urn:usf:graph:bindings';
  const evidenceGraph = 'urn:usf:graph:evidence';
  const dependencyDigests = [
    '1', '2', '3', '4', '5', '6', '7',
  ].map((character) => `sha256:${character.repeat(64)}`).sort();
  const binding = 'urn:usf:validationselfpublicationbinding:compilersemanticenforcementaggregate';
  const bindingPredicates = [
    'validationBindingEvaluationReceiptDigest',
    'validationBindingExecutionReceiptDigest',
    'validationBindingSourceScopeDigest',
    'validationNonPublicationDependencySetDigest',
  ];
  const bindingFacts = bindingPredicates.map((predicate, index) => (
    `<${binding}> <urn:usf:ontology:${predicate}> "${dependencyDigests[index]}" .`
  )).join('\n') + '\n';
  const evidenceFacts = [
    'compilersemanticenforcementaggregateevaluation',
    'compilersemanticenforcementaggregateexecution',
    'compilersemanticenforcementcompilervalidation',
  ].map((name, index) => (
    `<urn:usf:validationevidence:${name}> <urn:usf:ontology:contentDigest> "${dependencyDigests[index + 4]}" .`
  )).join('\n') + '\n';
  const shapesPath = join(root, SEMANTIC_MODEL_PATH, 'shapes.ttl');
  writeFileSync(shapesPath, '@prefix sh: <http://www.w3.org/ns/shacl#> .\n');
  let live = new Map([
    [graph, '<urn:test:s> <urn:test:p> "d0" .\n'],
    [unmanagedGraph, '<urn:test:retained> <urn:test:state> "unchanged" .\n'],
    [bindingsGraph, bindingFacts],
    [evidenceGraph, evidenceFacts],
  ]);
  let authority = null;
  const snapshots = new Map();
  const addedPayloads = [];
  let next = 0;
  const fakeClient = {
    async connectivity() { return 1; },
    async begin() { const id = `tx-${next += 1}`; snapshots.set(id, new Map(live)); return id; },
    async rollback(id) { snapshots.delete(id); },
    async commit(id) {
      live = snapshots.get(id);
      snapshots.delete(id);
      authority = (await readCommandWitness()).digest;
    },
    async constructInTransaction(id, query) {
      const name = /GRAPH <([^>]+)>/.exec(query)?.[1];
      return snapshots.get(id).get(name) || '';
    },
    async clearGraphs(id, graphs) { for (const name of graphs) snapshots.get(id).set(name, ''); },
    async addData(id, content, _type, target) {
      addedPayloads.push({ content, target, type: _type });
      const parsed = new Parser({ format: target ? 'text/turtle' : 'application/n-quads' }).parse(content);
      const byGraph = new Map();
      for (const item of parsed) {
        const name = target || item.graph.value;
        if (!byGraph.has(name)) byGraph.set(name, []);
        byGraph.get(name).push(DataFactory.quad(item.subject, item.predicate, item.object));
      }
      for (const [name, items] of byGraph) {
        const value = await new Promise((resolveText, reject) => {
          const writer = new Writer({ format: 'N-Triples' });
          writer.addQuads(items);
          writer.end((error, output) => error ? reject(error) : resolveText(output));
        });
        snapshots.get(id).set(name, value);
      }
    },
    async validateInTransactionWithReceipt() { return { conforms: true, receiptDigest: `sha256:${'e'.repeat(64)}` }; },
    async reportInTransaction() { return []; },
    async selectInTransaction(id, query) {
      if (/SELECT DISTINCT \?g WHERE \{ GRAPH \?g \{ \?s \?p \?o \} \}/.test(query)) {
        return [...snapshots.get(id)]
          .filter(([, content]) => content.trim().length > 0)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([name]) => ({ g: DataFactory.namedNode(name) }));
      }
      return [];
    },
  };
  const manifest = {
    authored: [], definitions: [
      { file: 'authority.ttl', graph },
      { file: 'proofs.ttl', graph: proofsGraph },
      { file: 'bindings.ttl', graph: bindingsGraph },
      { file: 'evidence.ttl', graph: evidenceGraph },
    ], derived: [], reviews: [], rules: [],
    shapes: [{ file: 'shapes.ttl', graph: 'urn:usf:graph:shapes', liveValidation: true, path: shapesPath }],
    publicationBudget: { maximumProjectedStatementCount: 999999 },
  };
  let sourceValue = 'source';
  const sourceCompiler = async ({ client: transactionClient, publicationMode }) => {
    assert.equal(publicationMode, 'validate');
    const tx = await transactionClient.begin();
    await transactionClient.clearGraphs(tx, [graph]);
    await transactionClient.addData(tx, `<urn:test:s> <urn:test:p> "${sourceValue}" .\n<urn:test:boolean> <urn:test:p> true .\n`, 'text/turtle', graph);
    const liveValidation = await transactionClient.validateInTransactionWithReceipt(tx, []);
    await transactionClient.rollback(tx);
    return { ok: true, liveValidation };
  };
  const readCommandWitness = async (witnessDigest = null) => {
    const inventory = [];
    let triples = 0;
    for (const [name, content] of [...live].sort(([left], [right]) => left.localeCompare(right))) {
      const [record, dependencyRecord] = await Promise.all([
        canonicalGraphDigest(content),
        canonicalInventoryGraphDigest(name, content),
      ]);
      if (record.triples > 0) {
        inventory.push({
          graph: name,
          sha256: record.sha256,
          dependencySha256: dependencyRecord.sha256,
          triples: record.triples,
        });
        triples += record.triples;
      }
    }
    return {
      digest: witnessDigest ?? semanticAuthorityInventoryDigest(inventory, triples),
      inventory,
      triples,
    };
  };
  authority = (await readCommandWitness()).digest;
  const command = createSemanticModelCompilationCommand({
    publicationLane: publicationLane(),
    nativeGraphStore: isolatedNativeGraphStore(),
    checkLocalFunction: () => {}, client: Object.freeze(fakeClient), compileFunction: sourceCompiler,
    loadManifestFunction: () => manifest,
    readAuthorityWitness: () => readCommandWitness(),
    repositoryRoot: root,
  });
  const candidate = (label) => {
    const bytes = Buffer.from(`# semantic-proof-v1 canonical-rdf-patch-v1 stage1\nA <urn:test:blank> <urn:test:p> _:${label} <${graph}> .\n`);
    return { bytes, digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}` };
  };
  const canonicalBlankNode = candidate('c14n0');
  assert.equal((await command.inspectCandidateState({
    candidateBytes: canonicalBlankNode.bytes,
    candidateDigest: canonicalBlankNode.digest,
  })).state, 'pre');
  const nonCanonicalBlankNode = candidate('sourceBlank');
  await assert.rejects(() => command.inspectCandidateState({
    candidateBytes: nonCanonicalBlankNode.bytes,
    candidateDigest: nonCanonicalBlankNode.digest,
  }), /canonical quad/);
  const originalLive = live;
  live = new Map([[graph, '<urn:test:blank> <urn:test:p> _:source .\n']]);
  const deletionBytes = Buffer.from(`# semantic-proof-v1 canonical-rdf-patch-v1 stage1\nD <urn:test:blank> <urn:test:p> _:c14n0 <${graph}> .\n`);
  assert.equal((await command.inspectCandidateState({
    candidateBytes: deletionBytes,
    candidateDigest: `sha256:${createHash('sha256').update(deletionBytes).digest('hex')}`,
  })).state, 'pre');
  live = originalLive;
  const generated = (stage, from, to) => Buffer.from(`# semantic-proof-v1 canonical-rdf-patch-v1 ${stage}\nD <urn:test:s> <urn:test:p> "${from}" <${graph}> .\nA <urn:test:s> <urn:test:p> "${to}" <${graph}> .\n`);
  const stage1 = await command.composeCandidate({ generatedCandidateBytes: generated('stage1', 'source', 'd1'), expectedAuthorityDigest: authority });
  const rewritten = addedPayloads.find(({ type }) => type === 'application/n-triples');
  assert.ok(rewritten);
  assert.match(rewritten.content, / "true"\^\^<http:\/\/www\.w3\.org\/2001\/XMLSchema#boolean> \.\n/);
  assert.doesNotMatch(rewritten.content, / true\.\n/);
  assert.equal((await command.inspectCandidateState({ candidateBytes: stage1.bytes, candidateDigest: stage1.digest })).state, 'pre');
  const shadowStage2Bytes = generated('stage2', 'd1', 'final');
  const shadowStage2Digest = `sha256:${createHash('sha256').update(shadowStage2Bytes).digest('hex')}`;
  const shadow = await command.previewPublicationSequence({
    d1CandidateBytes: stage1.bytes,
    d1CandidateDigest: stage1.digest,
    d2CandidateBytes: shadowStage2Bytes,
    d2CandidateDigest: shadowStage2Digest,
    expectedD0AuthorityDigest: authority,
  });
  assert.equal(shadow.d0AuthorityDigest, authority);
  assert.equal(shadow.d1.candidateDigest, stage1.digest);
  assert.equal(shadow.d2.candidateDigest, shadowStage2Digest);
  assert.equal(shadow.d2.evaluationInputAuthorityDigest, shadow.d1.authorityDigest);
  assert.notEqual(shadow.d1.authorityDigest, shadow.d2.authorityDigest);
  assert.equal(shadow.productionWriteOperations, 0);
  assert.equal(shadow.transactionBeginCount, 1);
  assert.equal(shadow.transactionRollbackCount, 1);
  assert.match(live.get(graph), /"d0"/);
  const releaseSubjectDigest = `sha256:${'1'.repeat(64)}`;
  const frozenV2Input = {
    protocol: 'semantic-proof-v2',
    release_subject_digest: releaseSubjectDigest,
    d0_authority_digest: authority,
    source_identities: [
      {
        authored_tree: '1'.repeat(40),
        repository: 'maldous/usf-factory',
        source_scope_digest: `sha256:${'2'.repeat(64)}`,
      },
      {
        authored_tree: '2'.repeat(40),
        repository: 'maldous/usf-graph',
        source_scope_digest: `sha256:${'3'.repeat(64)}`,
      },
    ],
    external_attestation_identities: [
      ['implementation_evidence', '4'],
      ['option_evaluation', '5'],
      ['owner_approval', '6'],
      ['proof', '7'],
    ].map(([attestation_type, character]) => ({
      attestation_digest: `sha256:${character.repeat(64)}`,
      attestation_type,
      release_subject_digest: releaseSubjectDigest,
    })),
    evidence_dependency_digests: [`sha256:${'8'.repeat(64)}`],
    compiler_identity: {
      algorithm_digest: `sha256:${'9'.repeat(64)}`,
      algorithm_version: 'aggregate-compiler-v2.0.0',
      command_digest: `sha256:${'a'.repeat(64)}`,
      implementation_source_digest: `sha256:${'b'.repeat(64)}`,
    },
  };
  const writesBeforeTwoStep = addedPayloads.length;
  const firstTwoStep = await command.previewV2PublicationFromFrozenInputs({
    frozenInputs: frozenV2Input,
    expectedD0AuthorityDigest: authority,
  });
  const secondTwoStep = await command.previewV2PublicationFromFrozenInputs({
    frozenInputs: structuredClone(frozenV2Input),
    expectedD0AuthorityDigest: authority,
  });
  assert.deepEqual(firstTwoStep, secondTwoStep);
  for (const candidate of [firstTwoStep.candidates.c1, firstTwoStep.candidates.c2]) {
    assert.ok(Buffer.isBuffer(candidate.bytes));
    assert.ok(Buffer.isBuffer(candidate.identityBytes));
    assert.equal(candidate.candidateDigest,
      `sha256:${createHash('sha256').update(candidate.bytes).digest('hex')}`);
  }
  assert.equal(firstTwoStep.candidateBindings.releaseSubjectDigest,
    frozenV2Input.release_subject_digest);
  assert.equal(firstTwoStep.candidateBindings.externalAttestationSetRootDigest,
    firstTwoStep.candidates.external_attestation_set_root_digest);
  assert.equal(firstTwoStep.candidateBindings.candidateGeneratorImplementationDigest,
    frozenV2Input.compiler_identity.implementation_source_digest);
  assert.equal(firstTwoStep.candidateBindings.candidateCommandDigest,
    frozenV2Input.compiler_identity.command_digest);
  assert.deepEqual(firstTwoStep.d1.dependencyIdentityDigests, dependencyDigests);
  assert.deepEqual(
    firstTwoStep.candidateBindings.c2D1DependencyIdentityDigests,
    dependencyDigests,
  );
  assert.equal(firstTwoStep.candidateBindings.c2D1AuthorityDigest,
    firstTwoStep.d1.authorityDigest);
  assert.equal(firstTwoStep.d2.evaluationInputAuthorityDigest,
    firstTwoStep.d1.authorityDigest);
  assert.equal(firstTwoStep.productionWriteOperations, 0);
  assert.equal(firstTwoStep.productionCasWriteOperations, 0);
  assert.equal(firstTwoStep.productionJournalWriteOperations, 0);
  assert.equal(firstTwoStep.authorizationIssued, 0);
  assert.equal(firstTwoStep.publicationPerformed, 0);
  assert.equal(firstTwoStep.transactionBeginCount, 1);
  assert.equal(firstTwoStep.transactionRollbackCount, 1);
  assert.equal(addedPayloads.length, writesBeforeTwoStep);
  assert.match(live.get(graph), /"d0"/);
  assert.equal(firstTwoStep.d1.inventory.some(({ graph: name }) => name === unmanagedGraph), true);
  assert.equal(firstTwoStep.d2.inventory.some(({ graph: name }) => name === unmanagedGraph), true);
  assert.equal(live.get(unmanagedGraph), '<urn:test:retained> <urn:test:state> "unchanged" .\n');
  let driftingShadowWitnessReads = 0;
  const driftingShadowCommand = createSemanticModelCompilationCommand({
    publicationLane: publicationLane(),
    nativeGraphStore: isolatedNativeGraphStore(),
    checkLocalFunction: () => {},
    client: Object.freeze(fakeClient),
    compileFunction: sourceCompiler,
    loadManifestFunction: () => manifest,
    readAuthorityWitness: () => readCommandWitness(
      driftingShadowWitnessReads++ === 0 ? authority : `sha256:${'f'.repeat(64)}`,
    ),
    repositoryRoot: root,
  });
  await assert.rejects(driftingShadowCommand.previewV2PublicationFromFrozenInputs({
    frozenInputs: structuredClone(frozenV2Input),
    expectedD0AuthorityDigest: authority,
  }), /V2 publication shadow changed semantic authority/);
  assert.equal(addedPayloads.length, writesBeforeTwoStep);
  assert.match(live.get(graph), /"d0"/);
  const v2c1 = materializeAggregateCompilerAuthorityCandidateV2({
    ...frozenV2Input,
    d1_binding: null,
    stage: 'C1',
  });
  const d1Inventory = await command.previewCandidateInventory({
    candidateBytes: v2c1.bytes,
    candidateDigest: v2c1.candidateDigest,
    expectedAuthorityDigest: authority,
  });
  assert.equal(d1Inventory.dependencyInventory.length, d1Inventory.inventory.length);
  assert.deepEqual(
    d1Inventory.dependencyInventory.map(({ graph, triples }) => ({ graph, triples })),
    d1Inventory.inventory.map(({ graph, triples }) => ({ graph, triples })),
  );
  assert.equal(d1Inventory.inventory.some((record, index) => (
    record.sha256 !== d1Inventory.dependencyInventory[index].sha256
  )), true);
  const nonemptyD1Inventory = d1Inventory.inventory.filter((item) => item.triples > 0);
  const predictedD1 = semanticAuthorityInventoryDigest(
    nonemptyD1Inventory,
    nonemptyD1Inventory.reduce((sum, item) => sum + item.triples, 0),
  );
  const v2c2 = materializeAggregateCompilerAuthorityCandidateV2({
    ...frozenV2Input,
    d1_binding: {
      authority_digest: predictedD1,
      c1_candidate_digest: v2c1.candidateDigest,
      dependency_identity_digests: dependencyDigests,
    },
    stage: 'C2',
  });
  const v2Shadow = await command.previewPublicationSequence({
    d1CandidateBytes: v2c1.bytes,
    d1CandidateDigest: v2c1.candidateDigest,
    d1CandidateIdentityBytes: v2c1.identityBytes,
    d2CandidateBytes: v2c2.bytes,
    d2CandidateDigest: v2c2.candidateDigest,
    d2CandidateIdentityBytes: v2c2.identityBytes,
    expectedD0AuthorityDigest: authority,
  });
  assert.equal(v2Shadow.d2.evaluationInputAuthorityDigest, v2Shadow.d1.authorityDigest);
  assert.equal(v2Shadow.candidateBindings.c2D1AuthorityDigest, v2Shadow.d1.authorityDigest);
  assert.equal(v2Shadow.d1.inventory.some(({ graph: name }) => name === unmanagedGraph), true);
  assert.equal(v2Shadow.d2.inventory.some(({ graph: name }) => name === unmanagedGraph), true);
  assert.equal(live.get(unmanagedGraph), '<urn:test:retained> <urn:test:state> "unchanged" .\n');
  // The production publisher's grant reservation compares the approved plan against
  // `result.d1.dependencyIdentityDigests` from THIS producer, so the candidate-bytes path must
  // report the live-derived set on `d1` exactly as previewV2PublicationFromFrozenInputs does.
  // While it was exposed only under candidateBindings, that comparison read undefined, and
  // canonicalJson(undefined) is undefined rather than a canonical string -- so no plan could
  // ever match and the reservation was unreachable.
  assert.deepEqual([...v2Shadow.d1.dependencyIdentityDigests], dependencyDigests);
  assert.deepEqual(
    [...v2Shadow.d1.dependencyIdentityDigests],
    [...v2Shadow.candidateBindings.c2D1DependencyIdentityDigests],
  );
  assert.equal(v2Shadow.candidateBindings.externalAttestationSetRootDigest,
    v2c1.externalAttestationSetRootDigest);
  assert.match(live.get(graph), /"d0"/);
  const staleD1C2 = materializeAggregateCompilerAuthorityCandidateV2({
    ...frozenV2Input,
    d1_binding: {
      authority_digest: `sha256:${'f'.repeat(64)}`,
      c1_candidate_digest: v2c1.candidateDigest,
      dependency_identity_digests: dependencyDigests,
    },
    stage: 'C2',
  });
  await assert.rejects(command.previewPublicationSequence({
    d1CandidateBytes: v2c1.bytes,
    d1CandidateDigest: v2c1.candidateDigest,
    d1CandidateIdentityBytes: v2c1.identityBytes,
    d2CandidateBytes: staleD1C2.bytes,
    d2CandidateDigest: staleD1C2.candidateDigest,
    d2CandidateIdentityBytes: staleD1C2.identityBytes,
    expectedD0AuthorityDigest: authority,
  }), /does not bind the exact C1-produced D1 authority and dependencies/);
  const substitutedDependenciesC2 = materializeAggregateCompilerAuthorityCandidateV2({
    ...frozenV2Input,
    d1_binding: {
      authority_digest: predictedD1,
      c1_candidate_digest: v2c1.candidateDigest,
      dependency_identity_digests: [
        ...dependencyDigests.slice(0, -1),
        `sha256:${'f'.repeat(64)}`,
      ].sort(),
    },
    stage: 'C2',
  });
  await assert.rejects(command.previewPublicationSequence({
    d1CandidateBytes: v2c1.bytes,
    d1CandidateDigest: v2c1.candidateDigest,
    d1CandidateIdentityBytes: v2c1.identityBytes,
    d2CandidateBytes: substitutedDependenciesC2.bytes,
    d2CandidateDigest: substitutedDependenciesC2.candidateDigest,
    d2CandidateIdentityBytes: substitutedDependenciesC2.identityBytes,
    expectedD0AuthorityDigest: authority,
  }), /does not bind the exact C1-produced D1 authority and dependencies/);
  await assert.rejects(command.execute({
    candidateBytes: v2c1.bytes,
    candidateDigest: v2c1.candidateDigest,
    expectedAuthorityDigest: authority,
    publicationMode: 'commit',
  }), /V2 production candidate commits remain disabled/);
  const validatedV2 = await command.executeV2Candidate({
    candidateBytes: v2c1.bytes,
    candidateDigest: v2c1.candidateDigest,
    candidateIdentityBytes: v2c1.identityBytes,
    expectedD0AuthorityDigest: authority,
    expectedAuthorityDigest: authority,
    expectedPostAuthorityDigest: predictedD1,
    publicationMode: 'validate',
    stage: 'C1',
  });
  assert.equal(validatedV2.protocol, 'semantic-proof-v2');
  assert.equal(validatedV2.stage, 'C1');
  assert.equal(validatedV2.commitOutcome.state, 'VALIDATED_ROLLBACK');
  assert.match(live.get(graph), /"d0"/);
  await assert.rejects(command.executeV2Candidate({
    candidateBytes: v2c1.bytes,
    candidateDigest: v2c1.candidateDigest,
    candidateIdentityBytes: v2c2.identityBytes,
    expectedD0AuthorityDigest: authority,
    expectedAuthorityDigest: authority,
    expectedPostAuthorityDigest: predictedD1,
    publicationMode: 'validate',
    stage: 'C1',
  }), /descriptor\/core binding is not exact/u);
  await assert.rejects(command.composeCandidate({
    generatedCandidateBytes: v2c1.bytes,
    expectedAuthorityDigest: authority,
  }), /V2 candidate cannot enter the V1 source-composition path/);
  await assert.rejects(command.previewPublicationSequence({
    d1CandidateBytes: shadowStage2Bytes,
    d1CandidateDigest: shadowStage2Digest,
    d2CandidateBytes: stage1.bytes,
    d2CandidateDigest: stage1.digest,
    expectedD0AuthorityDigest: authority,
  }), /V1 stage1\/stage2 or V2 C1\/C2/);
  await command.execute({ candidateBytes: stage1.bytes, candidateDigest: stage1.digest, expectedAuthorityDigest: authority, publicationMode: 'commit' });
  assert.match(live.get(graph), /"d1"/);
  const d1 = authority;
  const stage2 = await command.composeCandidate({ generatedCandidateBytes: generated('stage2', 'source', 'final'), expectedAuthorityDigest: d1 });
  assert.equal((await command.inspectCandidateState({ candidateBytes: stage2.bytes, candidateDigest: stage2.digest })).state, 'pre');
  await command.execute({ candidateBytes: stage2.bytes, candidateDigest: stage2.digest, expectedAuthorityDigest: d1, publicationMode: 'commit' });
  assert.match(live.get(graph), /"final"/);
});

// A reservation is singular and immutable, so a generation that proves unusable would otherwise
// wedge the lane forever: a corrected plan has a different digest and reserving it is a fork.
// Retirement is therefore a governed, append-only act, admissible ONLY while the reservation has
// produced nothing durable, and the retired reservation's own bytes are preserved verbatim.
const RESERVATION_A = Object.freeze({
  d0_authority_digest: `sha256:${'a'.repeat(64)}`,
  handover_generation_digest: `sha256:${'b'.repeat(64)}`,
  prospective_publication_plan_digest: `sha256:${'c'.repeat(64)}`,
  schema: 'usf-v2-native-handover-reservation-v1',
});
const RESERVATION_B = Object.freeze({
  ...RESERVATION_A,
  handover_generation_digest: `sha256:${'d'.repeat(64)}`,
  prospective_publication_plan_digest: `sha256:${'e'.repeat(64)}`,
});
const ZERO_EFFECT = Object.freeze({
  conflicting_publication_present: false,
  d1_authority_present: false,
  d2_authority_present: false,
  grant_consumed: false,
  observed_authority_digest: RESERVATION_A.d0_authority_digest,
  successors_root_present: false,
  terminal_receipt_present: false,
});
const RETIRED_AT = '2026-08-21T09:00:00Z';

test('a zero-effect reservation retires, stays auditable, and frees exactly one new reservation', async () => {
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  assert.deepEqual(lane.readReservation(), RESERVATION_A);

  const record = await lane.supersede(ZERO_EFFECT, RETIRED_AT, 'DEFECTIVE');
  // The retired reservation survives verbatim, so nothing is erased by retiring it.
  assert.deepEqual(record.superseded_reservation, RESERVATION_A);
  assert.equal(record.retired_at, RETIRED_AT);
  assert.deepEqual(
    lane.readSupersession(RESERVATION_A.handover_generation_digest).superseded_reservation,
    RESERVATION_A,
  );
  // ...and it is no longer live, so there is never more than one live reservation.
  assert.equal(lane.readReservation(), null);

  // The retired generation can never come back, even though its plan digest is known.
  await assert.rejects(
    lane.reserve(RESERVATION_A, async () => {}),
    /superseded and cannot reserve/u,
  );
  // Exactly one corrected generation may now reserve.
  await lane.reserve(RESERVATION_B, async () => {});
  assert.deepEqual(lane.readReservation(), RESERVATION_B);
});

test('retirement is idempotent for the same act and refuses a divergent one', async () => {
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  const first = await lane.supersede(ZERO_EFFECT, RETIRED_AT, 'DEFECTIVE');
  await lane.reserve(RESERVATION_B, async () => {});
  // Re-retiring the same generation is refused because it is no longer the live reservation;
  // the record itself is unchanged and still readable.
  assert.deepEqual(
    lane.readSupersession(RESERVATION_A.handover_generation_digest),
    first,
  );
});

// A RESOLVED semantic fence: the recovery may release coordination state only when authority
// itself no longer fences current V1 publication.
const D1_RESOLVED_FENCE = Object.freeze({
  authority_digest_at_observation: `sha256:${'9'.repeat(64)}`,
  current_v1_publication_state: 'urn:usf:v1publicationstate:current',
  fence_content_digest: `sha256:${'0'.repeat(64)}`,
  generation_digest: RESERVATION_A.handover_generation_digest,
  installed: false,
  ownership_state: 'urn:usf:v2ownershipstate:none',
  row_cardinality: 0,
  successor_binding_cardinality: 0,
  terminal_floor_terminal: false,
});
const D1_EFFECT = Object.freeze({
  activation_present: false,
  d1_journal_boundary_present: false,
  d2_authority_present: false,
  graph_semantic_fence: D1_RESOLVED_FENCE,
  journal_states: Object.freeze(['PLANNED', 'RESERVED']),
  observed_post_d1_authority_digest: `sha256:${'9'.repeat(64)}`,
  pre_d1_authority_digest: RESERVATION_A.d0_authority_digest,
  successors_root_present: false,
  terminal_receipt_present: false,
});
const RECOVERED_AT = '2026-08-23T04:00:00Z';

// The exact current D1 identities from the independently observed Graph and Factory projections.
// They exercise the generic receipt with the incident bindings without making the implementation
// depend on one job or recovery order.
const CURRENT_D1_RESERVATION = Object.freeze({
  d0_authority_digest: 'sha256:9ac4626f471ef05c3d89ef4ba66c28bbb322867d89275b1dc7200d38d7e48b5a',
  handover_generation_digest:
    'sha256:d939e2bafe8e54e99c2e1f4955ba10112b5c1b390f2471040288c748fe6ee603',
  prospective_publication_plan_digest:
    'sha256:1f84e021e15e04b8db191349b5e9774a014ecbe33864762378234f41042ae43e',
  schema: 'usf-v2-native-handover-reservation-v1',
});
const CURRENT_D1_AUTHORITY =
  'sha256:a38ff9c34bb2c6051c6be37d1c2ac71ed56d88c687b432a96b45e92d6fc97b13';
const CURRENT_D1_EFFECT = Object.freeze({
  ...D1_EFFECT,
  graph_semantic_fence: Object.freeze({
    ...D1_RESOLVED_FENCE,
    authority_digest_at_observation: CURRENT_D1_AUTHORITY,
    generation_digest: CURRENT_D1_RESERVATION.handover_generation_digest,
  }),
  observed_post_d1_authority_digest: CURRENT_D1_AUTHORITY,
  pre_d1_authority_digest: CURRENT_D1_RESERVATION.d0_authority_digest,
});
const CURRENT_FACTORY_RECONCILIATION = Object.freeze({
  candidate_digest:
    'sha256:ffd7bb4b699dbdd60abceda4cb8e256552716bbb3ef00ba43186d0ff60184da9',
  generation_id: CURRENT_D1_RESERVATION.handover_generation_digest,
  graph_publication_receipt_keys: Object.freeze([]),
  journal_states: Object.freeze(['PLANNED', 'RESERVED']),
  plan_digest: CURRENT_D1_RESERVATION.prospective_publication_plan_digest,
  projection_digest:
    'sha256:e9c2064b3e3834780aa8bffbddf749d4c1f0bcd6a55d92ff8aba690c7e31919e',
  terminal_receipt_keys: Object.freeze([]),
  transaction_id:
    'sha256:dc0d9482c8a7d0292636dc0ff8250b5c915f5e17d45260c1bc04746a9aa2bb6c',
});
const CURRENT_FACTORY_PREPARE =
  'sha256:6bbcb5153178cb82f28b5c1826200a7d052fbccd75f286989411560ba5c9a559';
const RECONCILED_AT = '2026-08-25T20:23:57Z';
const canonicalTestDigest = (value) => `sha256:${createHash('sha256')
  .update(Buffer.from(stableJson(value), 'utf8')).digest('hex')}`;

function currentJournaledD1Evidence(prepareBinding = null) {
  const digest = canonicalTestDigest;
  const releaseSubject = `sha256:${'4'.repeat(64)}`;
  const coordination = `sha256:${'3'.repeat(64)}`;
  const grants = [];
  const dependencies = [`sha256:${'2'.repeat(64)}`];
  const commitReceipt = {
    authority_digest: CURRENT_D1_AUTHORITY,
    candidate_digest: CURRENT_FACTORY_RECONCILIATION.candidate_digest,
    explicit_authorization_grant_digests: grants,
    graph_count: 40,
    prospective_publication_plan_digest: CURRENT_D1_RESERVATION
      .prospective_publication_plan_digest,
    protocol: 'semantic-proof-v2',
    release_subject_digest: releaseSubject,
    schema: 'usf-graph-d1-commit-receipt-v2',
    triples: 122_645,
  };
  const observationReceipt = {
    authority_digest: CURRENT_D1_AUTHORITY,
    dependency_identity_digests: dependencies,
    explicit_authorization_grant_digests: grants,
    prospective_publication_plan_digest: CURRENT_D1_RESERVATION
      .prospective_publication_plan_digest,
    protocol: 'semantic-proof-v2',
    release_subject_digest: releaseSubject,
    schema: 'usf-graph-d1-observation-receipt-v2',
  };
  const commitDigest = digest(commitReceipt);
  const observationDigest = digest(observationReceipt);
  const reservationReceipt = `sha256:${'1'.repeat(64)}`;
  const common = [
    CURRENT_D1_RESERVATION.prospective_publication_plan_digest,
    `sha256:${'5'.repeat(64)}`,
    `sha256:${'6'.repeat(64)}`,
  ].sort();
  const entries = [];
  const receiptSets = [
    common,
    [...common, reservationReceipt].sort(),
    [...common, commitDigest].sort(),
    [...common, observationDigest, ...dependencies].sort(),
  ];
  for (const [index, state] of [
    'PLANNED', 'RESERVED', 'D1_COMMITTED', 'D1_DEPENDENCIES_OBSERVED',
  ].entries()) {
    entries.push({
      coordination_identity_digest: coordination,
      d0_authority_digest: CURRENT_D1_RESERVATION.d0_authority_digest,
      d1_authority_digest: index >= 2 ? CURRENT_D1_AUTHORITY : null,
      d2_authority_digest: null,
      previous_entry_digest: index === 0 ? null : digest(entries[index - 1]),
      prospective_publication_plan_digest: CURRENT_D1_RESERVATION
        .prospective_publication_plan_digest,
      receipt_digests: receiptSets[index],
      release_subject_digest: releaseSubject,
      schema: 'usf-semantic-publication-journal-v2',
      state,
      transaction_id: CURRENT_FACTORY_RECONCILIATION.transaction_id,
      trusted_at: `2026-08-25T20:0${index}:00Z`,
    });
  }
  const journal = {
    boundary_receipts: {
      d1_commit: commitDigest,
      d1_observation: observationDigest,
      grant_reservation: reservationReceipt,
    },
    entries,
    grant_consumed: false,
    publication_state: null,
    schema: 'usf-hermetic-semantic-proof-v2-journal',
    terminal_receipt: null,
    terminal_receipt_digest: null,
  };
  const factoryProjection = {
    ...CURRENT_FACTORY_RECONCILIATION,
    graph_terminal_required: true,
  };
  const later = {
    activation_present: false,
    d2_authority_present: false,
    observed_authority_digest: CURRENT_D1_AUTHORITY,
    successors_root_present: false,
    terminal_receipt_present: false,
  };
  const evidence = {
    captured_at: '2026-08-25T20:05:00Z',
    factory_projection: factoryProjection,
    factory_projection_digest: digest(factoryProjection),
    graph_d1_commit_receipt: commitReceipt,
    graph_d1_commit_receipt_digest: commitDigest,
    graph_d1_observation_receipt: observationReceipt,
    graph_d1_observation_receipt_digest: observationDigest,
    graph_journal: journal,
    graph_journal_digest: digest(journal),
    handover_generation_digest: CURRENT_D1_RESERVATION.handover_generation_digest,
    later_boundary_observation: later,
    later_boundary_observation_digest: digest(later),
    observed_post_d1_authority_digest: CURRENT_D1_AUTHORITY,
    pre_d1_authority_digest: CURRENT_D1_RESERVATION.d0_authority_digest,
    prospective_publication_plan_digest: CURRENT_D1_RESERVATION
      .prospective_publication_plan_digest,
    recovery_reason: 'DEFECTIVE_AFTER_D1',
    schema: 'usf-v2-native-handover-journaled-d1-recovery-evidence-v1',
    superseded_prepare_binding: prepareBinding ?? {
      factory_prepare_receipt_digest: CURRENT_FACTORY_PREPARE,
      handover_generation_digest: CURRENT_D1_RESERVATION.handover_generation_digest,
      prospective_publication_plan_digest: CURRENT_D1_RESERVATION
        .prospective_publication_plan_digest,
      reservation_digest: digest(CURRENT_D1_RESERVATION),
      schema: 'usf-v2-native-handover-factory-prepare-binding-v1',
    },
    superseded_reservation: CURRENT_D1_RESERVATION,
    transaction_id: CURRENT_FACTORY_RECONCILIATION.transaction_id,
  };
  return evidence;
}

async function currentD1RecoveredLane(rooted = false) {
  const context = rooted ? rootedPublicationLane() : { lane: publicationLane() };
  await context.lane.reserve(CURRENT_D1_RESERVATION, async () => {});
  context.lane.bindFactoryPrepare(CURRENT_FACTORY_PREPARE);
  await context.lane.recoverAfterD1(CURRENT_D1_EFFECT, RECOVERED_AT);
  return context;
}

test('a committed-but-unrecorded D1 recovers without pretending it was zero-effect', async () => {
  // The stranded condition: D1 COMMITTED (authority moved) but the journal never recorded the
  // boundary, and a Factory PREPARE is bound. The zero-effect supersession path cannot serve
  // this and must not -- it would deny a real authority transition, and it refuses once a
  // PREPARE is bound because discarding a committed coordination step silently is worse than
  // being stuck. Before this capability existed the lane was permanently wedged.
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  lane.bindFactoryPrepare(`sha256:${'a'.repeat(64)}`);

  // The zero-effect path is correctly closed in this state.
  await assert.rejects(
    lane.supersede(ZERO_EFFECT, RETIRED_AT, 'DEFECTIVE'),
    /already bound a Factory prepare/u,
  );

  const record = await lane.recoverAfterD1(D1_EFFECT, RECOVERED_AT);
  assert.equal(record.recovery_reason, 'DEFECTIVE_AFTER_D1');
  // The real authority transition is RECORDED, not denied.
  assert.equal(record.d1_effect.pre_d1_authority_digest, RESERVATION_A.d0_authority_digest);
  assert.equal(record.d1_effect.observed_post_d1_authority_digest, `sha256:${'9'.repeat(64)}`);
  // Inputs preserved verbatim.
  assert.deepEqual(record.superseded_reservation, RESERVATION_A);
  assert.equal(
    record.superseded_prepare_binding.factory_prepare_receipt_digest, `sha256:${'a'.repeat(64)}`);
  // The lane is genuinely available and the PREPARE is unbound.
  assert.equal(lane.readReservation(), null);
  assert.equal(lane.readFactoryPrepareBinding(), null);
  // The record is durable and rereadable.
  assert.deepEqual(lane.readD1Recovery(RESERVATION_A.handover_generation_digest), record);
  // A corrected generation may now reserve.
  await lane.reserve(RESERVATION_B, async () => {});
  assert.deepEqual(lane.readReservation(), RESERVATION_B);
});

test('a canonical transaction-bound D1 receipt permanently excludes its generation and plan', async () => {
  const { lane } = await currentD1RecoveredLane();
  const receipt = await lane.recordD1Reconciliation(
    CURRENT_FACTORY_RECONCILIATION, RECONCILED_AT,
  );
  assert.deepEqual(receipt, {
    d1_recovery_record_digest: receipt.d1_recovery_record_digest,
    disposition: 'DEFECTIVE_AFTER_D1',
    factory_graph_publication_receipt_keys: [],
    factory_journal_states: ['PLANNED', 'RESERVED'],
    factory_projection_digest: CURRENT_FACTORY_RECONCILIATION.projection_digest,
    factory_terminal_receipt_keys: [],
    graph_d1_candidate_digest: CURRENT_FACTORY_RECONCILIATION.candidate_digest,
    handover_generation_digest: CURRENT_FACTORY_RECONCILIATION.generation_id,
    observed_post_d1_authority_digest: CURRENT_D1_AUTHORITY,
    pre_d1_authority_digest: CURRENT_D1_RESERVATION.d0_authority_digest,
    prospective_publication_plan_digest: CURRENT_FACTORY_RECONCILIATION.plan_digest,
    reconciled_at: RECONCILED_AT,
    schema: 'usf-v2-native-handover-d1-reconciliation-receipt-v1',
    selection_state: 'PERMANENTLY_EXCLUDED',
    transaction_id: CURRENT_FACTORY_RECONCILIATION.transaction_id,
  });
  assert.match(receipt.d1_recovery_record_digest, /^sha256:[0-9a-f]{64}$/u);
  assert.match(handoverD1ReconciliationReceiptDigest(receipt), /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(lane.readD1Reconciliation(receipt.transaction_id), receipt);
  assert.deepEqual(
    await lane.recordD1Reconciliation(CURRENT_FACTORY_RECONCILIATION, RECONCILED_AT),
    receipt,
    'the exact transaction receipt is idempotent',
  );

  await assert.rejects(
    lane.reserve({
      ...CURRENT_D1_RESERVATION,
      prospective_publication_plan_digest: `sha256:${'7'.repeat(64)}`,
    }, async () => {}),
    /V2_HANDOVER_DEFECTIVE_GENERATION_OR_PLAN_PERMANENTLY_EXCLUDED/u,
    'the generation is permanently excluded even with another plan',
  );
  await assert.rejects(
    lane.reserve({
      ...CURRENT_D1_RESERVATION,
      d0_authority_digest: CURRENT_D1_AUTHORITY,
      handover_generation_digest: `sha256:${'8'.repeat(64)}`,
    }, async () => {}),
    /V2_HANDOVER_DEFECTIVE_GENERATION_OR_PLAN_PERMANENTLY_EXCLUDED/u,
    'the plan is permanently excluded even under another generation',
  );
  const corrected = {
    ...CURRENT_D1_RESERVATION,
    d0_authority_digest: CURRENT_D1_AUTHORITY,
    handover_generation_digest: `sha256:${'8'.repeat(64)}`,
    prospective_publication_plan_digest: `sha256:${'7'.repeat(64)}`,
  };
  await lane.reserve(corrected, async () => {});
  assert.deepEqual(lane.readReservation(), corrected);
});

test('journaled D1 recovery persists reconciliation before releasing reservation and PREPARE', async () => {
  const lane = publicationLane();
  await lane.reserve(CURRENT_D1_RESERVATION, async () => {});
  const prepare = lane.bindFactoryPrepare(CURRENT_FACTORY_PREPARE);
  const evidence = currentJournaledD1Evidence(prepare);

  const result = await lane.recoverJournaledAfterD1(evidence, RECONCILED_AT, async () => {});
  assert.deepEqual(result.recovery_record, evidence);
  assert.equal(result.reconciliation_receipt.selection_state, 'PERMANENTLY_EXCLUDED');
  assert.equal(result.reconciliation_receipt.factory_projection_digest,
    CURRENT_FACTORY_RECONCILIATION.projection_digest);
  assert.deepEqual(lane.readD1Recovery(CURRENT_D1_RESERVATION.handover_generation_digest), evidence);
  assert.deepEqual(lane.readD1Reconciliation(CURRENT_FACTORY_RECONCILIATION.transaction_id),
    result.reconciliation_receipt);
  assert.deepEqual(await lane.recordD1Reconciliation(
    CURRENT_FACTORY_RECONCILIATION, RECONCILED_AT), result.reconciliation_receipt,
    'the existing reconciliation API reads the journaled recovery form idempotently');
  assert.equal(lane.readReservation(), null);
  assert.equal(lane.readFactoryPrepareBinding(), null);
  await assert.rejects(
    lane.reserve(CURRENT_D1_RESERVATION, async () => {}),
    /V2_HANDOVER_DEFECTIVE_GENERATION_OR_PLAN_PERMANENTLY_EXCLUDED/u,
  );
  assert.deepEqual(await lane.recoverJournaledAfterD1(
    evidence, RECONCILED_AT, async () => {}), result,
    'an exact replay is idempotent after both coordination pointers are released');
});

test('journaled D1 recovery refuses candidate substitution and every claimed later boundary', async () => {
  const fresh = async () => {
    const lane = publicationLane();
    await lane.reserve(CURRENT_D1_RESERVATION, async () => {});
    const prepare = lane.bindFactoryPrepare(CURRENT_FACTORY_PREPARE);
    return { lane, evidence: currentJournaledD1Evidence(prepare) };
  };

  let context = await fresh();
  const substitutedFactory = {
    ...context.evidence.factory_projection,
    candidate_digest: `sha256:${'7'.repeat(64)}`,
  };
  await assert.rejects(
    context.lane.recoverJournaledAfterD1({
      ...context.evidence,
      factory_projection: substitutedFactory,
      factory_projection_digest: canonicalTestDigest(substitutedFactory),
    }, RECONCILED_AT, async () => {}),
    /Factory projection is not the exact RESERVED transaction/u,
  );
  assert.notEqual(context.lane.readReservation(), null);
  assert.notEqual(context.lane.readFactoryPrepareBinding(), null);

  for (const boundary of [
    'activation_present', 'd2_authority_present', 'successors_root_present',
    'terminal_receipt_present',
  ]) {
    context = await fresh();
    const later = { ...context.evidence.later_boundary_observation, [boundary]: true };
    await assert.rejects(
      context.lane.recoverJournaledAfterD1({
        ...context.evidence,
        later_boundary_observation: later,
        later_boundary_observation_digest: canonicalTestDigest(later),
      }, RECONCILED_AT, async () => {}),
      /records a later boundary/u,
    );
    assert.notEqual(context.lane.readReservation(), null, `${boundary} must release nothing`);
    assert.notEqual(context.lane.readFactoryPrepareBinding(), null);
  }

  context = await fresh();
  const entries = context.evidence.graph_journal.entries.map((entry, index) => index === 3
    ? { ...entry, d2_authority_digest: `sha256:${'8'.repeat(64)}` } : entry);
  const journal = { ...context.evidence.graph_journal, entries };
  await assert.rejects(
    context.lane.recoverJournaledAfterD1({
      ...context.evidence,
      graph_journal: journal,
      graph_journal_digest: canonicalTestDigest(journal),
    }, RECONCILED_AT, async () => {}),
    /publication journal drifted from its exact D1 prefix/u,
  );
  assert.notEqual(context.lane.readReservation(), null);
  assert.notEqual(context.lane.readFactoryPrepareBinding(), null);
});

test('journaled D1 recovery requires a fresh in-lock state check before persistence', async () => {
  const lane = publicationLane();
  await lane.reserve(CURRENT_D1_RESERVATION, async () => {});
  const prepare = lane.bindFactoryPrepare(CURRENT_FACTORY_PREPARE);
  const evidence = currentJournaledD1Evidence(prepare);

  await assert.rejects(
    lane.recoverJournaledAfterD1(evidence, RECONCILED_AT),
    /requires in-lock current-state validation/u,
  );
  await assert.rejects(
    lane.recoverJournaledAfterD1(evidence, RECONCILED_AT, async () => {
      throw new Error('D2 appeared during recovery');
    }),
    /D2 appeared during recovery/u,
  );
  assert.equal(lane.readD1Recovery(CURRENT_D1_RESERVATION.handover_generation_digest), null);
  assert.equal(lane.readD1Reconciliation(CURRENT_FACTORY_RECONCILIATION.transaction_id), null);
  assert.deepEqual(lane.readReservation(), CURRENT_D1_RESERVATION);
  assert.deepEqual(lane.readFactoryPrepareBinding(), prepare);
});

test('D1 reconciliation is fail-closed, immutable, and fences ordinary execution', async () => {
  const rooted = await currentD1RecoveredLane(true);
  const receipt = await rooted.lane.recordD1Reconciliation(
    CURRENT_FACTORY_RECONCILIATION, RECONCILED_AT,
  );

  await assert.rejects(
    rooted.lane.recordD1Reconciliation({
      ...CURRENT_FACTORY_RECONCILIATION,
      transaction_id: `sha256:${'6'.repeat(64)}`,
    }, RECONCILED_AT),
    /subject fork rejected/u,
    'another transaction cannot reconcile the same defective subject',
  );
  for (const [change, pattern] of [
    [{ candidate_digest: 'not-a-digest' }, /candidate_digest is not exact/u],
    [{ graph_publication_receipt_keys: ['unexpected'] }, /not stranded at RESERVED/u],
    [{ journal_states: ['PLANNED', 'RESERVED', 'D1_COMMITTED'] }, /not stranded at RESERVED/u],
    [{ terminal_receipt_keys: ['unexpected'] }, /not stranded at RESERVED/u],
  ]) {
    const context = await currentD1RecoveredLane();
    await assert.rejects(
      context.lane.recordD1Reconciliation(
        { ...CURRENT_FACTORY_RECONCILIATION, ...change }, RECONCILED_AT,
      ),
      pattern,
    );
  }
  const inexactTime = await currentD1RecoveredLane();
  await assert.rejects(
    inexactTime.lane.recordD1Reconciliation(CURRENT_FACTORY_RECONCILIATION,
      '2026-08-25T20:23:57.799Z'),
    /time is not exact/u,
  );
  await assert.rejects(
    publicationLane().recordD1Reconciliation(CURRENT_FACTORY_RECONCILIATION, RECONCILED_AT),
    /requires its recovery record/u,
  );

  // Simulate a stale/tampered live pointer that predates the receipt. Selection and the next
  // execution boundary both fail closed against the durable receipt; neither can advance it.
  writeFileSync(
    join(rooted.root, 'v2-native-handover-reservation.json'),
    stableJson(CURRENT_D1_RESERVATION),
  );
  assert.throws(
    () => rooted.lane.readReservation(),
    /V2_HANDOVER_DEFECTIVE_GENERATION_OR_PLAN_PERMANENTLY_EXCLUDED/u,
  );
  assert.throws(
    () => rooted.lane.bindFactoryPrepare(`sha256:${'5'.repeat(64)}`),
    /V2_HANDOVER_DEFECTIVE_GENERATION_OR_PLAN_PERMANENTLY_EXCLUDED/u,
  );
  assert.equal(receipt.selection_state, 'PERMANENTLY_EXCLUDED');
});

test('D1 recovery refuses anything that is not the exact stranded condition', async () => {
  const fresh = async () => {
    const lane = publicationLane();
    await lane.reserve(RESERVATION_A, async () => {});
    lane.bindFactoryPrepare(`sha256:${'a'.repeat(64)}`);
    return lane;
  };

  // No authority transition => this is a zero-effect supersession wearing the wrong name. The
  // fence observation moves with it, so the refusal proves THIS property and not the
  // fence-consistency check that would otherwise fire first.
  let lane = await fresh();
  await assert.rejects(
    lane.recoverAfterD1({
      ...D1_EFFECT,
      graph_semantic_fence: {
        ...D1_RESOLVED_FENCE,
        authority_digest_at_observation: RESERVATION_A.d0_authority_digest,
      },
      observed_post_d1_authority_digest: RESERVATION_A.d0_authority_digest,
    }, RECOVERED_AT),
    /observed no authority transition/u,
  );
  assert.notEqual(lane.readReservation(), null, 'a refused recovery must release nothing');

  // A fence observed at a DIFFERENT authority than the one the recovery claims cannot speak for
  // that authority at all.
  lane = await fresh();
  await assert.rejects(
    lane.recoverAfterD1({
      ...D1_EFFECT,
      graph_semantic_fence: {
        ...D1_RESOLVED_FENCE, authority_digest_at_observation: `sha256:${'4'.repeat(64)}`,
      },
    }, RECOVERED_AT),
    /fence observation authority differs from the observed post-D1 authority/u,
  );
  assert.notEqual(lane.readReservation(), null);

  // The incident itself: an UNRESOLVED fence still retiring V1 publication must refuse, however
  // clean local coordination state looks.
  for (const [field, value, pattern] of [
    ['installed', true, /unresolved Graph semantic handover fence is installed/u],
    ['row_cardinality', 12, /fence row_cardinality is not 0/u],
    ['successor_binding_cardinality', 2, /fence successor_binding_cardinality is not 0/u],
    ['terminal_floor_terminal', true, /durable terminal ownership exists/u],
  ]) {
    lane = await fresh();
    await assert.rejects(
      lane.recoverAfterD1({
        ...D1_EFFECT, graph_semantic_fence: { ...D1_RESOLVED_FENCE, [field]: value },
      }, RECOVERED_AT),
      pattern,
    );
    assert.notEqual(lane.readReservation(), null, `${field} refusal must release nothing`);
    assert.notEqual(lane.readFactoryPrepareBinding(), null);
  }

  // A v1-shaped effect can no longer be WRITTEN: the fence observation is mandatory.
  lane = await fresh();
  const { graph_semantic_fence: _omitted, ...legacyShaped } = D1_EFFECT;
  await assert.rejects(
    lane.recoverAfterD1(legacyShaped, RECOVERED_AT),
    /invalid closed schema/u,
  );
  assert.notEqual(lane.readReservation(), null, 'a refused recovery must release nothing');
  assert.notEqual(lane.readFactoryPrepareBinding(), null);

  // Any LATER boundary present means this is not stranded-at-D1.
  for (const flag of ['d1_journal_boundary_present', 'd2_authority_present',
    'successors_root_present', 'terminal_receipt_present', 'activation_present']) {
    lane = await fresh();
    await assert.rejects(
      lane.recoverAfterD1({ ...D1_EFFECT, [flag]: true }, RECOVERED_AT),
      new RegExp(`D1 recovery refused: ${flag}`, 'u'),
    );
    assert.notEqual(lane.readReservation(), null);
  }

  // A journal beyond RESERVED is not this condition either.
  lane = await fresh();
  await assert.rejects(
    lane.recoverAfterD1({ ...D1_EFFECT, journal_states: ['PLANNED', 'RESERVED', 'D1_COMMITTED'] },
      RECOVERED_AT),
    /not stranded at RESERVED/u,
  );

  // An inexact recovery time is refused.
  lane = await fresh();
  await assert.rejects(
    lane.recoverAfterD1(D1_EFFECT, '2026-08-23T04:00:00'),
    /recovery time is not exact/u,
  );
  assert.notEqual(lane.readReservation(), null);
});

test('a sequencing retirement leaves the re-reserved generation retirable again', async () => {
  // SEQUENCING deliberately permits the SAME plan to reserve again. When retirement was a single
  // record per generation, that second reservation could never be released: supersede() could
  // only write a record that collided with the first, so the live pointer wedged permanently and
  // no plan -- corrected or original -- could ever reserve again. Retirement is therefore an
  // append-only history whose latest record governs.
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  const first = await lane.supersede(ZERO_EFFECT, RETIRED_AT, 'SEQUENCING');
  assert.equal(lane.readReservation(), null);

  // The same plan lawfully reserves again under a sequencing retirement...
  await lane.reserve(RESERVATION_A, async () => {});
  assert.deepEqual(lane.readReservation(), RESERVATION_A);

  // ...and that second reservation can itself be retired, on its own proof, at its own time.
  const second = await lane.supersede(ZERO_EFFECT, '2026-08-21T22:38:40Z', 'DEFECTIVE');
  assert.equal(lane.readReservation(), null);
  assert.equal(second.retirement_reason, 'DEFECTIVE');

  // Both retirements survive: the history is append-only and the first is not rewritten.
  const history = lane.readSupersessionHistory(RESERVATION_A.handover_generation_digest);
  assert.deepEqual(history, [first, second]);
  // The latest record governs, so the generation is now barred forever.
  assert.deepEqual(lane.readSupersession(RESERVATION_A.handover_generation_digest), second);
  await assert.rejects(
    lane.reserve(RESERVATION_A, async () => {}),
    /superseded and cannot reserve/u,
  );
  // A corrected generation is still free to reserve.
  await lane.reserve(RESERVATION_B, async () => {});
  assert.deepEqual(lane.readReservation(), RESERVATION_B);
});

test('a byte-identical retirement retry appends nothing', async () => {
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  const first = await lane.supersede(ZERO_EFFECT, RETIRED_AT, 'SEQUENCING');
  await lane.reserve(RESERVATION_A, async () => {});
  // Same reservation, same proof, same time, same reason: one governed act, retried.
  const retry = await lane.supersede(ZERO_EFFECT, RETIRED_AT, 'SEQUENCING');
  assert.deepEqual(retry, first);
  assert.deepEqual(
    lane.readSupersessionHistory(RESERVATION_A.handover_generation_digest),
    [first],
  );
  assert.equal(lane.readReservation(), null);
});

test('retirement is refused unless zero durable effect is proven', async () => {
  for (const [field, value] of [
    ['grant_consumed', true],
    ['d1_authority_present', true],
    ['d2_authority_present', true],
    ['terminal_receipt_present', true],
    ['successors_root_present', true],
    ['conflicting_publication_present', true],
  ]) {
    const lane = publicationLane();
    await lane.reserve(RESERVATION_A, async () => {});
    await assert.rejects(
      lane.supersede({ ...ZERO_EFFECT, [field]: value }, RETIRED_AT, 'DEFECTIVE'),
      new RegExp(`supersession refused: ${field}`, 'u'),
    );
    // The reservation must still be live after a refused retirement.
    assert.deepEqual(lane.readReservation(), RESERVATION_A);
  }
});

test('retirement is refused when authority moved, when nothing is reserved, and when a prepare bound', async () => {
  const moved = publicationLane();
  await moved.reserve(RESERVATION_A, async () => {});
  await assert.rejects(
    moved.supersede(
      { ...ZERO_EFFECT, observed_authority_digest: `sha256:${'f'.repeat(64)}` },
      RETIRED_AT, 'DEFECTIVE',
    ),
    /observed a different authority/u,
  );
  assert.deepEqual(moved.readReservation(), RESERVATION_A);

  const empty = publicationLane();
  await assert.rejects(empty.supersede(ZERO_EFFECT, RETIRED_AT), /no reservation to supersede/u);

  const bound = publicationLane();
  await bound.reserve(RESERVATION_A, async () => {});
  bound.bindFactoryPrepare(`sha256:${'9'.repeat(64)}`);
  await assert.rejects(
    bound.supersede(ZERO_EFFECT, RETIRED_AT),
    /already bound a Factory prepare/u,
  );
  assert.deepEqual(bound.readReservation(), RESERVATION_A);
});

test('a retirement record must be exact', async () => {
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  await assert.rejects(lane.supersede(ZERO_EFFECT, '2026-08-21T09:00:00', 'DEFECTIVE'), /retirement time/u);
  const { grant_consumed: _dropped, ...incomplete } = ZERO_EFFECT;
  await assert.rejects(lane.supersede(incomplete, RETIRED_AT, 'DEFECTIVE'), /zero-effect proof/u);
  assert.deepEqual(lane.readReservation(), RESERVATION_A);
});


test('a sequencing retirement lets the same generation reserve again', async () => {
  // The generation digest is deterministic from authority and source, so a GOOD generation
  // retired only to re-establish an ordering requirement has no alternative digest to reserve
  // at the same authority. Barring it made retiring a sound plan a dead end.
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  const record = await lane.supersede(ZERO_EFFECT, RETIRED_AT, 'SEQUENCING');
  assert.equal(record.retirement_reason, 'SEQUENCING');
  assert.equal(lane.readReservation(), null);
  await lane.reserve(RESERVATION_A, async () => {});
  assert.deepEqual(lane.readReservation(), RESERVATION_A);
  // ...but only that exact plan: a different plan wearing the same generation digest is refused.
  await lane.supersede(ZERO_EFFECT, RETIRED_AT, 'SEQUENCING');
  await assert.rejects(
    lane.reserve(
      { ...RESERVATION_A, prospective_publication_plan_digest: `sha256:${'9'.repeat(64)}` },
      async () => {},
    ),
    /superseded under a different plan/u,
  );
});

test('a defective retirement still bars the generation forever', async () => {
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  await lane.supersede(ZERO_EFFECT, RETIRED_AT, 'DEFECTIVE');
  await assert.rejects(
    lane.reserve(RESERVATION_A, async () => {}),
    /superseded and cannot reserve/u,
  );
});

test('a retirement reason outside the closed set is refused', async () => {
  const lane = publicationLane();
  await lane.reserve(RESERVATION_A, async () => {});
  await assert.rejects(
    lane.supersede(ZERO_EFFECT, RETIRED_AT, 'BECAUSE_I_SAID_SO'),
    /retirement reason must be DEFECTIVE or SEQUENCING/u,
  );
  assert.deepEqual(lane.readReservation(), RESERVATION_A);
});
