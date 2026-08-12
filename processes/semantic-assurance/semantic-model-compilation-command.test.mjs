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
  semanticModelCompilationCommandInternals,
} from './semantic-model-compilation-command.mjs';

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

test.after(() => repositories.forEach((root) => rmSync(root, { recursive: true, force: true })));

function client() { return { connectivity: async () => 1 }; }

test('validates the canonical semantic model with an exact authority binding', async () => {
  const calls = [];
  const command = createSemanticModelCompilationCommand({
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
  const operationsValue = [{
    action: 'write-file',
    artefactFamily: 'urn:usf:artefactfamily:processsource',
    content: successor,
    contentDigest: contentDigest(Buffer.from(successor)),
    contentEncoding: 'utf8',
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
  const packageValue = semanticModelCompilationCommandInternals.createExternalAuthorityDeltaPackage({
    artifacts: [...artifactBytes].map(([role, bytes]) => ({ bytes, role })),
    authorityDigest,
    conflictBinding,
    correctionCandidateDigest: inventoryDigest,
    now: new Date('2026-08-11T00:00:01Z'),
    ownerAssignmentIri,
    predecessorSourceHead: predecessorHead,
    predecessorSourceTree: predecessorTree,
    proofApprovalEnvelope,
    repository: repositoryId,
    verifyProofApprovalEnvelope: verifiedApproval,
  });
  const evidenceStore = {
    read: (digest) => Buffer.from([...artifactBytes.values()].find((bytes) => contentDigest(bytes) === digest)),
    verify: (digest) => {
      const bytes = [...artifactBytes.values()].find((item) => contentDigest(item) === digest);
      return { digest, size: bytes.length };
    },
  };
  return {
    artifactBytes,
    conflictBinding,
    evidenceStore,
    inventoryDigest,
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
test('composes and applies exact D0 stage1 and D1 stage2 source-plus-generated deltas', async () => {
  const root = repository();
  const graph = 'urn:test:graph';
  const shapesPath = join(root, SEMANTIC_MODEL_PATH, 'shapes.ttl');
  writeFileSync(shapesPath, '@prefix sh: <http://www.w3.org/ns/shacl#> .\n');
  let live = new Map([[graph, '<urn:test:s> <urn:test:p> "d0" .\n']]);
  let authority = `sha256:${'d'.repeat(64)}`;
  const snapshots = new Map();
  const addedPayloads = [];
  let next = 0;
  const fakeClient = {
    async connectivity() { return 1; },
    async begin() { const id = `tx-${next += 1}`; snapshots.set(id, new Map(live)); return id; },
    async rollback(id) { snapshots.delete(id); },
    async commit(id) { live = snapshots.get(id); snapshots.delete(id); authority = `sha256:${String(next).padStart(64, '0')}`; },
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
    async selectInTransaction() { return []; },
  };
  const manifest = {
    authored: [], definitions: [{ file: 'authority.ttl', graph }], derived: [], reviews: [], rules: [],
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
  const command = createSemanticModelCompilationCommand({
    checkLocalFunction: () => {}, client: Object.freeze(fakeClient), compileFunction: sourceCompiler,
    loadManifestFunction: () => manifest,
    readAuthorityWitness: async () => ({ digest: authority, inventory: [], triples: 1 }),
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
  await command.execute({ candidateBytes: stage1.bytes, candidateDigest: stage1.digest, expectedAuthorityDigest: authority, publicationMode: 'commit' });
  assert.match(live.get(graph), /"d1"/);
  const d1 = authority;
  const stage2 = await command.composeCandidate({ generatedCandidateBytes: generated('stage2', 'source', 'final'), expectedAuthorityDigest: d1 });
  assert.equal((await command.inspectCandidateState({ candidateBytes: stage2.bytes, candidateDigest: stage2.digest })).state, 'pre');
  await command.execute({ candidateBytes: stage2.bytes, candidateDigest: stage2.digest, expectedAuthorityDigest: d1, publicationMode: 'commit' });
  assert.match(live.get(graph), /"final"/);
});
