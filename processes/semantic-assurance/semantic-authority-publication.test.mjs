import assert from 'node:assert/strict';
import test from 'node:test';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  canonicalTerminalReceipt,
  fixture as provenFixture,
  preparedReceipts,
} from './native-handover-fixture-v2.mjs';

import {
  assertAcceptedCompilerResult,
  createCasEvidenceStore,
  createGraphNativeSuccessorStoreV2,
  createGraphProductionAdapterV2,
  createReadOnlyStardogShadowClientV2,
  DEFAULT_PROTOCOL_JOURNAL,
  readImplementationWorkGrantAuthorityStateV1,
  observeGraphRuntimeOwnershipV2,
  readAdmittedClosureExecutorIdentityV2,
  readAdmittedEvidenceAdmissionProducerIdentityV2,
  readAdmittedPublisherIdentityV2,
  runPublication,
} from './semantic-authority-publication.mjs';
import {
  createSemanticModelCompilationCommand,
  SEMANTIC_MODEL_PATH,
  semanticModelCompilationCommandInternals,
} from './semantic-model-compilation-command.mjs';
import {
  consumeGrantNonce,
  canonicalJson,
  envelopeDigest,
  IMPLEMENTATION_WORK_GRANT_ALLOWED_ACTIONS,
  IMPLEMENTATION_WORK_GRANT_DENIED_EFFECTS,
  implementationWorkGrantCandidateDigest,
  implementationWorkGrantEvidenceSetDigest,
  publicationReceiptDigest,
  sha256,
  sourceScopeDigest,
} from './semantic-proof-v1.mjs';
import {
  canonicalDigestV2,
  DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
  graphPublicationReceiptDigestV2,
  IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST,
  prospectivePublicationPlanDigestV2,
} from './semantic-proof-v2.mjs';

function recursivelyStable(value) {
  if (Array.isArray(value)) return value.map(recursivelyStable);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, recursivelyStable(value[key])]));
}

const canonicalArtifactBytes = (value) => Buffer.from(`${JSON.stringify(recursivelyStable(value), null, 2)}\n`);


// The publication lane is an explicit dependency with no host-path default, so
// each test roots the V1 retirement interlock in an isolated directory instead
// of whatever the host happens to have at /var/lib/usf-programme.
// The terminal-ownership floor is an explicit dependency too: an empty floor
// must mean "this root holds no terminal generation", never "no root was
// configured", so each test roots it in its own directory.
function isolatedNativeGraphStore() {
  return createGraphNativeSuccessorStoreV2({
    nativeRoot: mkdtempSync(join(tmpdir(), 'usf-native-floor-')),
    casStore: createCasEvidenceStore(mkdtempSync(join(tmpdir(), 'usf-native-floor-cas-'))),
  });
}

function isolatedPublicationLane() {
  const root = mkdtempSync(join(tmpdir(), 'usf-publication-lane-'));
  return semanticModelCompilationCommandInternals.createSemanticPublicationLaneV2(root);
}

test('V2 Graph production shadow exposes reads and rollback while refusing every write surface', async () => {
  const calls = [];
  const client = Object.fromEntries([
    'begin',
    'rollback',
    'connectivity',
    'construct',
    'select',
    'constructInTransaction',
    'selectInTransaction',
  ].map((operation) => [operation, async (...args) => {
    calls.push([operation, ...args]);
    return operation === 'begin' ? 'tx-1' : [];
  }]));
  client.expectedAuthorityDigest = `sha256:${'a'.repeat(64)}`;
  const shadow = createReadOnlyStardogShadowClientV2(client);
  assert.equal(await shadow.begin(), 'tx-1');
  await shadow.select('SELECT * WHERE {}');
  await shadow.rollback('tx-1');
  assert.deepEqual(calls.map(([operation]) => operation), ['begin', 'select', 'rollback']);
  for (const operation of [
    'commit', 'clearGraphs', 'addData', 'validateInTransaction',
    'validateInTransactionWithReceipt',
  ]) {
    await assert.rejects(shadow[operation](), /V2_GRAPH_PRODUCTION_WRITES_DISABLED/);
  }
});

test('implementation work grant live readback requires one exact two-repository closed grant', async () => {
  const binding = (value) => ({ value });
  const authorityDigest = `sha256:${'a'.repeat(64)}`;
  const nonPublicationDependencySetDigest = `sha256:${'d'.repeat(64)}`;
  const scopes = [
    {
      predecessor_commit: '2'.repeat(40), predecessor_tree: '3'.repeat(40),
      repository: 'maldous/usf-factory', source_paths: ['src/usf_factory/activation.py'],
      source_scope_digest: sourceScopeDigest(['src/usf_factory/activation.py']),
    },
    {
      predecessor_commit: '4'.repeat(40), predecessor_tree: '5'.repeat(40),
      repository: 'maldous/usf-graph', source_paths: ['processes/semantic-assurance/semantic-proof-v2.mjs'],
      source_scope_digest: sourceScopeDigest(['processes/semantic-assurance/semantic-proof-v2.mjs']),
    },
  ];
  const decision = {
    allowed_actions: IMPLEMENTATION_WORK_GRANT_ALLOWED_ACTIONS,
    authority_pre_digest: authorityDigest,
    decision_state: 'accepted',
    denied_effects: IMPLEMENTATION_WORK_GRANT_DENIED_EFFECTS,
    expires_at: '2026-08-20T00:00:00Z',
    issued_at: '2026-08-16T00:00:00Z',
    nonpublication_dependency_set_digest: nonPublicationDependencySetDigest,
    purpose: 'V2_NATIVE_HANDOVER implementation only',
    repositories: scopes,
    schema_version: 'usf-implementation-work-grant-decision-v1',
  };
  const decisionBytes = canonicalArtifactBytes(decision);
  const review = {
    authority_pre_digest: authorityDigest, candidate_derivation_participation: false,
    decision_digest: sha256(decisionBytes), governance_independent_review_satisfied: true,
    review_state: 'accepted', schema_version: 'usf-implementation-work-grant-review-v1',
  };
  const reviewBytes = canonicalArtifactBytes(review);
  const validation = {
    authority_pre_digest: authorityDigest, decision_digest: sha256(decisionBytes),
    review_digest: sha256(reviewBytes), schema_version: 'usf-implementation-work-grant-validation-v1',
    validation_state: 'passed',
  };
  const validationBytes = canonicalArtifactBytes(validation);
  const evidenceDigests = [sha256(decisionBytes), sha256(reviewBytes), sha256(validationBytes)].sort();
  const payload = {
    algorithm: 'openpgp', allowed_actions: IMPLEMENTATION_WORK_GRANT_ALLOWED_ACTIONS,
    authority_pre_digest: authorityDigest, claim_type: 'implementation_work_grant',
    denied_effects: IMPLEMENTATION_WORK_GRANT_DENIED_EFFECTS,
    evidence_set_digest: implementationWorkGrantEvidenceSetDigest(evidenceDigests),
    expires_at: decision.expires_at, fingerprint: 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D',
    issued_at: decision.issued_at, nonce: '00000000-0000-4000-8000-000000000009',
    nonpublication_dependency_set_digest: nonPublicationDependencySetDigest,
    principal: 'urn:usf:principal:matthewaldous', protocol: 'semantic-proof-v1',
    purpose: decision.purpose, repositories: scopes, schema_version: 'usf-implementation-work-grant-v1',
    signing_identity: 'urn:usf:signingidentity:matthewaldoussemanticproofv1', single_use: true,
  };
  const candidateDigest = implementationWorkGrantCandidateDigest(payload);
  const grant = { payload, signature: '-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n' };
  const grantBytes = canonicalArtifactBytes(grant);
  const grantIri = `urn:usf:implementationworkgrant:${candidateDigest.slice(7)}`;
  const artifacts = new Map([
    ['decision', decisionBytes], ['grant', grantBytes], ['review', reviewBytes], ['validation', validationBytes],
  ]);
  const roles = ['decision', 'grant', 'review', 'validation'];
  const descriptors = roles.map((role) => {
    const bytes = artifacts.get(role);
    const digest = sha256(bytes);
    return {
      artefactType: binding(`urn:usf:artefacttype:implementationworkgrant${role}`),
      byteSize: binding(String(bytes.length)), descriptor: binding(`urn:descriptor:${role}`),
      digest: binding(digest), family: binding('urn:usf:artefactfamily:evidencepayload'),
      format: binding('urn:usf:representationformat:jsondata8259'),
      locator: binding(`cas://sha256/${digest.slice(7)}`), mediaType: binding('application/json'),
      storage: binding('urn:usf:storageclass:contentaddressedobjectstorage'),
    };
  });
  const allowed = IMPLEMENTATION_WORK_GRANT_ALLOWED_ACTIONS
    .map((slug) => `urn:usf:implementationworkaction:${slug.replaceAll('_', '')}`).sort();
  const denied = IMPLEMENTATION_WORK_GRANT_DENIED_EFFECTS
    .map((slug) => `urn:usf:implementationworkeffect:${slug.replaceAll('_', '')}`).sort();
  const rows = [
    [{
      authorityDigest: binding(authorityDigest), candidateDigest: binding(candidateDigest),
      envelopeDigest: binding(envelopeDigest(grant)), evidenceSetDigest: binding(payload.evidence_set_digest),
      expiresAt: binding('2026-08-20T00:00:00Z'), issuedAt: binding('2026-08-16T00:00:00Z'),
      nonce: binding('00000000-0000-4000-8000-000000000009'),
      nonPublicationDependencySetDigest: binding(nonPublicationDependencySetDigest),
      purpose: binding('urn:usf:implementationworkpurpose:v2nativehandover'),
      state: binding('urn:usf:implementationworkgrantstate:reserved'),
    }],
    [
      ...allowed.map((item) => ({ kind: binding('allow'), item: binding(item) })),
      ...denied.map((item) => ({ kind: binding('deny'), item: binding(item) })),
      ...roles.map((role) => ({ kind: binding('evidence'), item: binding(`urn:descriptor:${role}`) })),
    ],
    scopes.map((scope, index) => ({
      scope: binding(`urn:scope:${index}`), repository: binding(scope.repository), path: binding(scope.source_paths[0]),
      predecessorCommit: binding(scope.predecessor_commit), predecessorTree: binding(scope.predecessor_tree),
      sourceScopeDigest: binding(scope.source_scope_digest),
    })),
    descriptors,
  ];
  let call = 0;
  const client = { select: async () => rows[call++] };
  const evidenceStore = { read: (digest) => [...artifacts.values()].find((bytes) => sha256(bytes) === digest) };
  const verifyImplementationWorkGrant = () => ({
    ...payload, candidate_digest: candidateDigest, envelope_digest: envelopeDigest(grant), repositories: scopes,
  });
  const result = await readImplementationWorkGrantAuthorityStateV1(client, grantIri, {
    evidenceStore, now: new Date('2026-08-16T01:00:00Z'), verifyImplementationWorkGrant,
  });
  assert.equal(result.repositories.length, 2);
  assert.deepEqual(result.allowedActions, allowed);
  assert.deepEqual(result.deniedEffects, denied);
  assert.equal(call, 4);
  call = 0;
  let observedCasRoot = null;
  const nullRootResult = await readImplementationWorkGrantAuthorityStateV1(client, grantIri, {
    casRoot: null,
    createEvidenceStore: (root) => {
      observedCasRoot = root;
      return evidenceStore;
    },
    now: new Date('2026-08-16T01:00:00Z'),
    verifyImplementationWorkGrant,
  });
  assert.equal(observedCasRoot, '/var/lib/usf-cas');
  assert.equal(nullRootResult.grantIri, grantIri);
  assert.equal(call, 4);
  call = 0;
  const exactNonce = rows[0][0].nonce;
  rows[0][0].nonce = binding('------------------------------------');
  await assert.rejects(() => readImplementationWorkGrantAuthorityStateV1(client, grantIri, {
    evidenceStore, now: new Date('2026-08-16T01:00:00Z'), verifyImplementationWorkGrant,
  }), /scalar closure is invalid/);
  rows[0][0].nonce = exactNonce;
  call = 0;
  rows[1] = rows[1].filter((row) => row.item.value !== denied[0]);
  await assert.rejects(() => readImplementationWorkGrantAuthorityStateV1(client, grantIri, {
    evidenceStore, now: new Date('2026-08-16T01:00:00Z'), verifyImplementationWorkGrant,
  }), /ALLOW, DENY or evidence closure/);
});

function productionAdapterFixture() {
  // Consumes the SHARED canonical builder. A divergent local copy is exactly
  // how this test went stale and ended up skipped.
  const valueDigest = (character) => `sha256:${character.repeat(64)}`;
  const d1Bytes = Buffer.from('exact C1 candidate');
  const d2Bytes = Buffer.from('exact C2 candidate');
  const built = provenFixture({
    graphD1CandidateDigest: sha256(d1Bytes),
    graphD2CandidateDigest: sha256(d2Bytes),
  });
  return {
    ...built,
    d1Bytes,
    d2Bytes,
    valueDigest,
    planDigest: prospectivePublicationPlanDigestV2(built.plan),
  };
}

test('V2 Graph production adapter commits exact C1/C2 once and recovers each durable boundary', async () => {
  const fixture = productionAdapterFixture();
  let authority = fixture.d0;
  const calls = { C1: 0, C2: 0 };
  const receipts = new Map();
  const command = {
    async reserveV2HandoverGeneration({
      d0AuthorityDigest, handoverGenerationDigest, prospectivePublicationPlanDigest,
    }) {
      return {
        d0_authority_digest: d0AuthorityDigest,
        handover_generation_digest: handoverGenerationDigest,
        prospective_publication_plan_digest: prospectivePublicationPlanDigest,
      };
    },
    bindV2FactoryPrepare({ factoryPrepareReceiptDigest }) {
      return {
        factory_prepare_receipt_digest: factoryPrepareReceiptDigest,
        handover_generation_digest: fixture.plan.handover_generation_digest,
        prospective_publication_plan_digest: fixture.planDigest,
      };
    },
    async previewPublicationSequence() {
      return {
        d0AuthorityDigest: fixture.d0,
        d1: {
          authorityDigest: fixture.d1,
          dependencyIdentityDigests: fixture.dependencies,
        },
        d2: {
          authorityDigest: fixture.d2,
          evaluationInputAuthorityDigest: fixture.d1,
        },
        candidateBindings: {
          releaseSubjectDigest: fixture.plan.release_subject_digest,
          externalAttestationSetRootDigest: fixture.plan.external_attestation_set_root_digest,
          candidateGeneratorImplementationDigest:
            fixture.plan.candidate_generator_implementation_digest,
          candidateCommandDigest: fixture.plan.candidate_command_digest,
        },
      };
    },
    async inspectCandidateState({ candidateDigest }) {
      if (candidateDigest === fixture.plan.graph_d1_candidate_digest) {
        return { state: authority === fixture.d0 ? 'pre' : 'post' };
      }
      return { state: authority === fixture.d1 ? 'pre' : 'post' };
    },
    async executeV2Candidate({ stage }) {
      calls[stage] += 1;
      authority = stage === 'C1' ? fixture.d1 : fixture.d2;
      return { ok: true };
    },
    async observeV2D1Dependencies() {
      return {
        authorityDigest: authority,
        dependencyIdentityDigests: fixture.dependencies,
      };
    },
  };
  const receiptStore = {
    persist(receipt, expectedDigest = sha256(canonicalJson(receipt))) {
      const observed = sha256(canonicalJson(receipt));
      assert.equal(observed, expectedDigest);
      assert.equal(receipts.get(observed) || canonicalJson(receipt), canonicalJson(receipt));
      receipts.set(observed, canonicalJson(receipt));
      return { digest: observed, path: `/receipts/${observed}.json` };
    },
  };
  const nativeGraphStore = createGraphNativeSuccessorStoreV2({
    nativeRoot: mkdtempSync(join(tmpdir(), 'usf-adapter-native-')),
    casStore: createCasEvidenceStore(mkdtempSync(join(tmpdir(), 'usf-adapter-cas-'))),
  });
  const adapter = createGraphProductionAdapterV2({
    command,
    nativeGraphStore,
    trustedTime: async () => '2026-08-01T12:00:00Z',
    readAuthorityWitness: async () => ({
      digest: authority,
      inventory: [{ graph: 'urn:test:graph', sha256: fixture.valueDigest('f'), triples: 1 }],
      triples: 1,
    }),
    readGraphOwnedConsumers: async () => [],
    d1CandidateBytes: fixture.d1Bytes,
    d1CandidateIdentityBytes: Buffer.from('{}'),
    d2CandidateBytes: fixture.d2Bytes,
    d2CandidateIdentityBytes: Buffer.from('{}'),
    graphCommit: fixture.plan.graph_protected_commit,
    graphTree: fixture.plan.graph_protected_tree,
    publisherImplementationDigest: fixture.valueDigest('f'),
    publisherCommandDigest: fixture.valueDigest('0'),
    receiptStore,
  });
  const inputs = {
    plan: fixture.plan,
    // Both receipts come from the shared canonical builder, which computes them
    // with the real digest functions -- no hand-rolled literal to go stale.
    graph_reservation_receipt: preparedReceipts(fixture.plan).graphReservationReceipt,
    factory_prepare_receipt: preparedReceipts(fixture.plan).factoryPrepareReceipt,
    factory_commit: fixture.plan.factory_deployment_commit,
    factory_tree: fixture.plan.factory_deployment_tree,
    graph_commit: fixture.plan.graph_protected_commit,
    graph_tree: fixture.plan.graph_protected_tree,
    publisher_implementation_digest: fixture.valueDigest('f'),
    publisher_command_digest: fixture.valueDigest('0'),
    // coordinationIdentity binds the Factory executor and command alongside the
    // publisher's, plus the predicted terminal receipt time.
    factory_executor_implementation_digest: fixture.valueDigest('1'),
    factory_closure_command_digest: fixture.valueDigest('2'),
    terminal_receipt_at: '2026-08-01T12:00:00Z',
    factory_closure_receipt: fixture.closure,
  };
  assert.match((await adapter.reserveGrant(inputs)).digest, /^sha256:/u);
  const d1First = await adapter.commitD1(inputs);
  const d1Recovered = await adapter.commitD1(inputs);
  assert.deepEqual(d1Recovered, d1First);
  assert.equal(calls.C1, 1);
  const observation = await adapter.observeD1(inputs);
  assert.deepEqual(observation.dependency_identity_digests, fixture.dependencies);
  const d2First = await adapter.commitD2(inputs);
  const d2Recovered = await adapter.commitD2(inputs);
  assert.deepEqual(d2Recovered, d2First);
  assert.equal(calls.C2, 1);
  // Production consumes the one-shot grant BEFORE importing the terminal
  // receipt, so a crash between them leaves a consumed grant and no activation
  // rather than an activation over a replayable grant. consumeGrant is also what
  // persists the durable Factory closure the terminal receipt then requires, and
  // it takes the CLOSURE receipt -- the previous order (and argument) could
  // never have run.
  const consumed = await adapter.consumeGrant(fixture.closure, inputs);
  assert.match(consumed.digest, /^sha256:/u);

  // The canonical 16-field receipt, from the production builder. The previous
  // 4-field literal (with a lowercase publication_outcome) is exactly the drift
  // that got this test skipped.
  const terminal = canonicalTerminalReceipt(
    inputs,
    fixture.closure,
    '2026-08-01T12:00:00Z',
    consumed.digest,
  );

  const persisted = await adapter.persistTerminalReceipt(terminal, inputs);
  assert.equal(persisted.digest, graphPublicationReceiptDigestV2(terminal));
  const drifted = structuredClone(inputs);
  drifted.graph_tree = 'd'.repeat(40);
  await assert.rejects(adapter.reserveGrant(drifted), /exact admitted release/u);
});

test('canonical source candidate generation cannot cross the strict no-write production shadow', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-graph-shadow-source-'));
  try {
    mkdirSync(join(root, SEMANTIC_MODEL_PATH));
    const graph = 'urn:test:graph';
    const observedWrites = { add: 0, clear: 0, commit: 0 };
    const raw = {
      expectedAuthorityDigest: `sha256:${'a'.repeat(64)}`,
      async connectivity() { return 1; },
      async begin() { return 'tx-1'; },
      async rollback() {},
      async construct() { return '<urn:test:s> <urn:test:p> "d0" .\n'; },
      async select() { return []; },
      async constructInTransaction() { return '<urn:test:s> <urn:test:p> "d0" .\n'; },
      async selectInTransaction() { return []; },
      async clearGraphs() { observedWrites.clear += 1; },
      async addData() { observedWrites.add += 1; },
      async commit() { observedWrites.commit += 1; },
    };
    const shadow = createReadOnlyStardogShadowClientV2(raw);
    const command = createSemanticModelCompilationCommand({
    publicationLane: isolatedPublicationLane(),
    nativeGraphStore: isolatedNativeGraphStore(),
      client: shadow,
      repositoryRoot: root,
      readAuthorityWitness: async () => ({ digest: raw.expectedAuthorityDigest }),
      checkLocalFunction: () => {},
      loadManifestFunction: () => ({
        authored: [],
        definitions: [{ file: 'authority.ttl', graph }],
        derived: [],
        reviews: [],
        rules: [],
        shapes: [{
          file: 'shapes.ttl',
          graph: 'urn:usf:graph:shapes',
          liveValidation: true,
          path: join(root, SEMANTIC_MODEL_PATH, 'shapes.ttl'),
        }],
        publicationBudget: { maximumProjectedStatementCount: 100 },
      }),
      compileFunction: async ({ client }) => {
        const transaction = await client.begin();
        await client.clearGraphs(transaction, [graph]);
        await client.addData(transaction, '<urn:test:s> <urn:test:p> "source" .\n', 'text/turtle', graph);
        await client.rollback(transaction);
        return { ok: true };
      },
    });
    await assert.rejects(
      command.prepareSourceDelta({ expectedAuthorityDigest: raw.expectedAuthorityDigest }),
      /V2_GRAPH_PRODUCTION_WRITES_DISABLED/,
    );
    assert.deepEqual(observedWrites, { add: 0, clear: 0, commit: 0 });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('canonical CAS persistence is immutable and repairs exact pre-existing private object and directory modes', () => {
  const root = mkdtempSync(join(tmpdir(), 'semantic-publisher-cas-'));
  try {
    const store = createCasEvidenceStore(root);
    const bytes = Buffer.from('exact evidence bytes');
    const first = store.persist(bytes);
    assert.equal(statSync(first.path).mode & 0o777, 0o444);
    chmodSync(first.path, 0o600);
    chmodSync(dirname(first.path), 0o700);
    chmodSync(dirname(dirname(first.path)), 0o700);
    const second = store.persist(bytes);
    assert.equal(second.digest, first.digest);
    assert.equal(second.path, first.path);
    assert.equal(statSync(dirname(dirname(second.path))).mode & 0o777, 0o755);
    assert.equal(statSync(dirname(second.path)).mode & 0o777, 0o755);
    assert.equal(statSync(second.path).mode & 0o777, 0o444);
    assert.deepEqual(store.read(first.digest), bytes);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('option acquisition and evaluation collectors use the one canonical CAS store', () => {
  for (const path of [
    'assurance/semantic-model-compilation/realisation-option-acquisition.mjs',
    'assurance/semantic-model-compilation/realisation-option-evaluation-evidence.mjs',
  ]) {
    const source = readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
    assert.match(source, /createCasEvidenceStore\(casRoot\)/u);
    assert.match(source, /casEvidenceStore\.persist\(bytes\)/u);
    assert.doesNotMatch(source, /mode:\s*0o600/u);
  }
});

const PRE = `sha256:${'1'.repeat(64)}`;
const INITIAL_BYTES = Buffer.from('# semantic-proof-v1 canonical-rdf-patch-v1 stage1\nD <urn:test:s> <urn:test:p> "old" <urn:test:graph> .\nA <urn:test:s> <urn:test:p> "new" <urn:test:graph> .\n');
const INITIAL_CANDIDATE = sha256(INITIAL_BYTES);
const STAGE_ONE = `sha256:${'3'.repeat(64)}`;
const FINAL = `sha256:${'4'.repeat(64)}`;
const REEVALUATION_BYTES = Buffer.from('# semantic-proof-v1 canonical-rdf-patch-v1 stage2\nD <urn:test:s> <urn:test:p> "new" <urn:test:graph> .\nA <urn:test:s> <urn:test:p> "final" <urn:test:graph> .\n');
const REEVALUATION_CANDIDATE = sha256(REEVALUATION_BYTES);
const EXECUTION_BYTES = Buffer.from('{"schema":"execution"}');
const EVALUATION_BYTES = Buffer.from('{"schema":"evaluation"}');
const EXECUTION = sha256(EXECUTION_BYTES);
const EVALUATION = sha256(EVALUATION_BYTES);
const OBSERVATION = `sha256:${'8'.repeat(64)}`;
const DOMAIN = 'urn:usf:capabilityowner:semanticmodelcompilation';
const REPOSITORY = 'maldous/usf-graph';
const PATHS = ['processes/semantic-assurance/semantic-proof-v1.mjs'];
const PROVIDER_PATHS = ['usf_factory/provider_catalogue.py'];
const REPOSITORY_EXTERNAL_PATHS = [
  'assurance/semantic-model-compilation/aggregate-compiler-proof-command.mjs',
  'processes/semantic-assurance/semantic-authority-publication.mjs',
  'processes/semantic-assurance/semantic-proof-v1.mjs',
];
const PROVIDER_V3_PATHS = ['src/usf_factory/v3_events.py'];
const INITIAL_NONCE = '00000000-0000-4000-8000-000000000001';
const REEVALUATION_NONCE = '00000000-0000-4000-8000-000000000002';
const PUBLISHED_AT = '2026-08-01T12:00:00Z';

const ownerAssignment = { payload: { claim: 'owner' }, signature: 'owner' };
const candidateApproval = { payload: { claim: 'approval' }, signature: 'approval' };
const witness = (digest) => ({ algorithm: 'sha256-rdfc10', digest, inventory: [], triples: 0 });
const compilerResult = (state, candidateDigest) => ({
  ok: true,
  commitOutcome: { candidateDigest, exactCandidateStateVerified: true, state },
});

function grantEnvelope(authorityPreDigest, candidateDigest, nonce) {
  return {
    payload: {
      authority_pre_digest: authorityPreDigest,
      candidate_digest: candidateDigest,
      claim_type: 'publication_grant',
      nonce,
    },
    signature: 'grant',
  };
}

function verifiedGrant(envelope) {
  return Object.freeze({
    ...envelope.payload,
    envelope_digest: envelopeDigest(envelope),
    single_use: true,
  });
}

const initialEnvelope = grantEnvelope(PRE, INITIAL_CANDIDATE, INITIAL_NONCE);
const reevaluationEnvelope = grantEnvelope(STAGE_ONE, REEVALUATION_CANDIDATE, REEVALUATION_NONCE);
const initialGrant = verifiedGrant(initialEnvelope);
const reevaluationGrant = verifiedGrant(reevaluationEnvelope);

function command(candidateDigest, {
  validate = compilerResult('VALIDATED_ROLLBACK', candidateDigest),
  commit = compilerResult('COMMITTED', candidateDigest),
  throwAfterCommit,
} = {}) {
  const evidenceBytes = Buffer.from(`${canonicalJson({ candidateDigest, conforms: true })}\n`);
  const withEvidence = (result) => ({
    ...result,
    validationEvidence: { bytes: evidenceBytes, digest: sha256(evidenceBytes) },
  });
  return {
    calls: [],
    state: 'pre',
    async inspectCandidateState() { return { candidateDigest, state: this.state }; },
    async execute(input) {
      this.calls.push({ expectedAuthorityDigest: input.expectedAuthorityDigest, publicationMode: input.publicationMode });
      if (input.publicationMode !== 'commit') return withEvidence(validate);
      this.state = 'post';
      if (throwAfterCommit) throw new Error(throwAfterCommit);
      return withEvidence(commit);
    },
    async composeCandidate({ generatedCandidateBytes }) {
      return { bytes: generatedCandidateBytes, digest: sha256(generatedCandidateBytes) };
    },
  };
}

function memoryEvidenceStore() {
  const values = new Map([[EXECUTION, EXECUTION_BYTES], [EVALUATION, EVALUATION_BYTES]]);
  return Object.freeze({
    persist(bytes) { const digest = sha256(bytes); values.set(digest, Buffer.from(bytes)); return { digest, size: bytes.length }; },
    read(digest) { if (!values.has(digest)) throw new Error(`missing CAS object ${digest}`); return Buffer.from(values.get(digest)); },
    verify(digest) { const bytes = this.read(digest); assert.equal(sha256(bytes), digest); return { digest, size: bytes.length }; },
  });
}

const ownerAssignments = Object.freeze([
  Object.freeze({ authorityDomain: DOMAIN, repository: REPOSITORY, sourcePaths: PATHS, envelope: ownerAssignment }),
  Object.freeze({
    authorityDomain: 'urn:usf:capabilityowner:repositoryexternalartefactmaterialisation',
    repository: 'maldous/usf-graph', sourcePaths: REPOSITORY_EXTERNAL_PATHS,
    envelope: { payload: { claim: 'repository-external-owner' }, signature: 'repository-external-owner' },
  }),
  Object.freeze({
    authorityDomain: 'urn:usf:capabilityowner:providerconfigurationplane',
    repository: 'maldous/usf-factory', sourcePaths: PROVIDER_PATHS,
    envelope: { payload: { claim: 'provider-owner' }, signature: 'provider-owner' },
  }),
  Object.freeze({
    authorityDomain: 'urn:usf:capabilityowner:factoryproviderdurablecontrolplane',
    repository: 'maldous/usf-factory', sourcePaths: PROVIDER_V3_PATHS,
    envelope: { payload: { claim: 'provider-v3-owner' }, signature: 'provider-v3-owner' },
  }),
]);

function witnessReader(digests) {
  const values = [...digests];
  return async () => {
    if (values.length === 0) throw new Error('unexpected authority witness read');
    return witness(values.shift());
  };
}

function timeReader(values = [PUBLISHED_AT]) {
  const times = [...values];
  let last = times.at(-1);
  return async () => {
    if (times.length > 0) last = times.shift();
    return last;
  };
}

const settle = async (_read, first) => first;
const observation = (overrides = {}) => ({
  actionState: 'UNRESOLVED_FAIL_CLOSED',
  authorityDigest: STAGE_ONE,
  currentProofResults: 0,
  directProvisionalAggregateSelections: 1,
  observationReceiptDigest: OBSERVATION,
  ok: true,
  operation: 'observe_initial',
  proofCurrentness: 'PENDING',
  selectedProvisionalAggregateResult: 'urn:usf:proofresult:provisionalaggregatecompilerproof',
  ...overrides,
});
const preparation = (overrides = {}) => ({
  candidateDigest: INITIAL_CANDIDATE,
  evaluatedAuthorityDigest: STAGE_ONE,
  evaluationReceiptDigest: EVALUATION,
  executionReceiptDigest: EXECUTION,
  ok: true,
  operation: 'produce_initial',
  protocol: 'semantic-proof-v1',
  state: 'REEVALUATION_CANDIDATE_PREPARED',
  ...overrides,
});
const terminal = (overrides = {}) => ({
  actionState: 'PROCEED',
  authorityAfterDigest: FINAL,
  currentProofResults: 1,
  evaluatedAuthorityDigest: STAGE_ONE,
  evaluationReceiptDigest: EVALUATION,
  executionReceiptDigest: EXECUTION,
  ok: true,
  operation: 'verify_reevaluation',
  proofCurrentness: 'CURRENT',
  selectedAggregateResult: 'urn:usf:proofresult:aggregatecompilerproof',
  ...overrides,
});

function producer({ observe = observation, produce = preparation, verify = terminal, calls = [] } = {}) {
  return async (request) => {
    calls.push(request.operation);
    if (request.operation === 'observe_initial') return observe();
    if (request.operation === 'produce_initial') return produce();
    if (request.operation === 'verify_reevaluation') return verify();
    throw new Error(`unexpected producer operation ${request.operation}`);
  };
}

const permissionJournals = new Map();

function memoryProtocolJournal(ledger) {
  const clone = (value) => JSON.parse(canonicalJson(value));
  const current = (grant) => ledger.nonces[grant.nonce];
  const update = (grant, transform) => {
    const next = transform(current(grant));
    ledger.nonces[grant.nonce] = next;
    return Object.freeze({ nonce: grant.nonce, ...clone(next) });
  };
  return Object.freeze({
    reserveGrantNonce(grant, { observedAt, publicationPhase }) {
      return update(grant, (record) => {
        if (record) throw new Error('publication grant nonce was replayed or already entered the transaction journal');
        return {
          authority_pre_digest: grant.authority_pre_digest,
          candidate_digest: grant.candidate_digest,
          grant_envelope_digest: grant.envelope_digest,
          publication_outcome: 'pending', publication_phase: publicationPhase,
          reserved_at: observedAt, state: 'reserved',
        };
      });
    },
    readPublicationTransaction(grant) { return current(grant) ? Object.freeze(clone(current(grant))) : null; },
    readPublicationTransactionForEnvelope(envelope) {
      const record = ledger.nonces[envelope?.payload?.nonce];
      return record ? Object.freeze(clone(record)) : null;
    },
    recordPublicationOutcome(grant, {
      authorityPublicationDigest, committedCandidateState, observedAt, publishedAt,
    }) {
      return update(grant, (record) => ({
        ...record, authority_publication_digest: authorityPublicationDigest,
        committed_at: observedAt, committed_candidate_state: committedCandidateState,
        publication_outcome: 'committed', published_at: publishedAt,
        state: 'published_pending_reevaluation',
      }));
    },
    recordInitialProjectionObservation(grant, observation, { observedAt }) {
      return update(grant, (record) => ({
        ...record,
        initial_projection_observation: {
          package: clone(observation), package_digest: sha256(canonicalJson(observation)), recorded_at: observedAt,
        },
      }));
    },
    recordInitialReevaluationPreparation(grant, preparationValue, { observedAt }) {
      return update(grant, (record) => ({
        ...record,
        reevaluation_preparation: {
          package: clone(preparationValue), package_digest: sha256(canonicalJson(preparationValue)), recorded_at: observedAt,
        },
      }));
    },
    assertReevaluationPredecessor({ priorReceipt, preparation: preparationValue, authorityPreDigest }) {
      const prior = ledger.nonces[priorReceipt.grant_nonce];
      if (!prior || prior.state !== 'consumed' || prior.publication_phase !== 'initial'
          || priorReceipt.publication_phase !== 'initial' || priorReceipt.terminal_state !== 'PENDING'
          || priorReceipt.authority_after_digest !== authorityPreDigest
          || preparationValue.evaluatedAuthorityDigest !== authorityPreDigest
          || preparationValue.candidateDigest !== priorReceipt.candidate_digest
          || prior.final_receipt_digest !== publicationReceiptDigest(priorReceipt)
          || prior.reevaluation_preparation?.package_digest !== sha256(canonicalJson(preparationValue))
          || canonicalJson(prior.reevaluation_preparation?.package) !== canonicalJson(preparationValue)) {
        throw new Error('reevaluation publication has no durable stage-1 transaction linkage');
      }
      return Object.freeze({ prior: clone(prior), preparation: clone(preparationValue) });
    },
    recordPostPublicationReevaluation(grant, reevaluation, { observedAt }) {
      return update(grant, (record) => ({
        ...record, action_state: reevaluation.actionState,
        authority_after_digest: reevaluation.authorityAfterDigest,
        current_proof_results: reevaluation.currentProofResults,
        proof_currentness: reevaluation.proofCurrentness, reevaluated_at: observedAt,
        reevaluation_evaluation_receipt_digest: reevaluation.evaluationReceiptDigest,
        reevaluation_execution_receipt_digest: reevaluation.executionReceiptDigest,
        selected_aggregate_result: reevaluation.selectedAggregateResult,
        state: 'reevaluated_pending_receipt',
      }));
    },
    consumeGrantNonce(grant, { receipt, observedAt }) {
      return update(grant, (record) => ({
        ...record, consumed_at: observedAt, final_receipt: clone(receipt),
        final_receipt_digest: publicationReceiptDigest(receipt),
        publication_outcome: receipt.publication_outcome,
        published_at: receipt.published_at, state: 'consumed',
      }));
    },
    failGrantNonce(grant, { stage, observedAt }) {
      return update(grant, (record) => ({
        ...record, failed_at: observedAt, failure_stage: stage,
        previous_state: record.state, state: 'failed',
      }));
    },
  });
}

function journal() {
  if (process.permission) {
    const ledgerPath = `memory:semantic-publisher-test-${permissionJournals.size + 1}`;
    const ledger = { nonces: {}, protocol: 'semantic-proof-v1' };
    const protocolJournal = memoryProtocolJournal(ledger);
    permissionJournals.set(ledgerPath, protocolJournal);
    return {
      ledgerPath,
      protocolJournal,
      read: () => JSON.parse(canonicalJson(ledger)),
      remove: () => permissionJournals.delete(ledgerPath),
    };
  }
  const directory = mkdtempSync(join(tmpdir(), 'semantic-publisher-test-'));
  const ledgerPath = join(directory, 'ledger.json');
  writeFileSync(ledgerPath, '{"nonces":{},"protocol":"semantic-proof-v1"}\n', { mode: 0o600 });
  return {
    ledgerPath,
    read: () => JSON.parse(readFileSync(ledgerPath, 'utf8')),
    remove: () => { unlinkSync(ledgerPath); rmdirSync(directory); },
  };
}

function invocation({
  publicationPhase = 'initial',
  expectedAuthorityDigest = PRE,
  expectedCandidateDigest = INITIAL_CANDIDATE,
  publicationGrant = initialEnvelope,
  grant = initialGrant,
  commandInstance = command(expectedCandidateDigest),
  readAuthorityWitness = witnessReader([expectedAuthorityDigest, expectedAuthorityDigest]),
  ...overrides
} = {}) {
  const invocationValue = {
    authorityDomain: DOMAIN,
    candidateApproval,
    candidateBytes: expectedCandidateDigest === REEVALUATION_CANDIDATE ? REEVALUATION_BYTES : INITIAL_BYTES,
    command: commandInstance,
    expectedAuthorityDigest,
    expectedCandidateDigest,
    ownerAssignments,
    publicationGrant,
    publicationPhase,
    readAuthorityWitness,
    repository: REPOSITORY,
    sourcePaths: PATHS,
    trustedTime: timeReader(),
    evidenceStore: memoryEvidenceStore(),
    trustAnchor: { principal: 'urn:usf:principal:matthewaldous' },
    verifyBundle: () => ({ assignment: {}, approval: {}, grant }),
    verifyOwnerAssignment: () => ({}),
    ...overrides,
  };
  if (!invocationValue.protocolJournal && permissionJournals.has(invocationValue.ledgerPath)) {
    invocationValue.protocolJournal = permissionJournals.get(invocationValue.ledgerPath);
  }
  return invocationValue;
}

async function publishInitial(state, overrides = {}) {
  let persistedReceipt;
  const compiler = overrides.commandInstance || command(INITIAL_CANDIDATE);
  const output = await runPublication(invocation({
    mode: 'commit',
    commandInstance: compiler,
    ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE, STAGE_ONE, STAGE_ONE, STAGE_ONE]),
    settle,
    postPublicationReevaluate: producer(),
    persist: (receipt) => {
      persistedReceipt = receipt;
      return { digest: publicationReceiptDigest(receipt), path: '/proof/initial.json' };
    },
    ...overrides,
  }));
  return { compiler, output, preparation: output.reevaluationPreparation, receipt: persistedReceipt };
}

test('prepare is read-only and derives the canonical candidate without authority claims', async () => {
  const compiler = command(INITIAL_CANDIDATE);
  const prepared = await runPublication({
    mode: 'prepare', publicationPhase: 'initial', expectedAuthorityDigest: PRE,
    candidateBytes: INITIAL_BYTES, command: compiler, readAuthorityWitness: witnessReader([PRE, PRE]),
    evidenceStore: memoryEvidenceStore(),
  });
  assert.equal(prepared.canonicalCandidateDigest, INITIAL_CANDIDATE);
  assert.deepEqual(Buffer.from(prepared.canonicalCandidateBytes, 'base64'), INITIAL_BYTES);
  assert.deepEqual(compiler.calls, [{ expectedAuthorityDigest: PRE, publicationMode: 'validate' }]);
});

test('all independently scoped owner assignments are verified before validation and CAS bytes round-trip', async () => {
  const calls = [];
  const store = memoryEvidenceStore();
  const result = await runPublication(invocation({
    mode: 'validate', evidenceStore: store,
    verifyOwnerAssignment: (_envelope, options) => { calls.push([options.authorityDomain, options.repository]); return {}; },
  }));
  assert.deepEqual(calls, [
    [DOMAIN, REPOSITORY],
    ['urn:usf:capabilityowner:repositoryexternalartefactmaterialisation', 'maldous/usf-graph'],
    ['urn:usf:capabilityowner:providerconfigurationplane', 'maldous/usf-factory'],
    ['urn:usf:capabilityowner:factoryproviderdurablecontrolplane', 'maldous/usf-factory'],
  ]);
  assert.equal(sha256(store.read(result.validationEvidence.digest)), result.validationEvidence.digest);
});

test('current predecessor owner scope remains admissible only as the exact three-domain set', async () => {
  const currentOwnerAssignments = ownerAssignments.filter((assignment) =>
    assignment.authorityDomain !== 'urn:usf:capabilityowner:repositoryexternalartefactmaterialisation');
  const calls = [];
  await runPublication(invocation({
    mode: 'validate',
    ownerAssignments: currentOwnerAssignments,
    verifyOwnerAssignment: (_envelope, options) => { calls.push(options.authorityDomain); return {}; },
  }));
  assert.deepEqual(calls.sort(), [
    DOMAIN,
    'urn:usf:capabilityowner:providerconfigurationplane',
    'urn:usf:capabilityowner:factoryproviderdurablecontrolplane',
  ].sort());
  await assert.rejects(runPublication(invocation({
    mode: 'validate',
    ownerAssignments: ownerAssignments.slice(0, 3),
  })), /exact current or final V1 governed scope set/);
});

test('actual RDF Patch compiler adapter validates and commits the identical canonical bytes', async () => {
  const graph = 'urn:test:graph';
  let value = 'old';
  const transaction = () => ({ value });
  const client = {
    async connectivity() { return 1; },
    async begin() { return transaction(); },
    async rollback() {},
    async commit(tx) { value = tx.value; },
    async constructInTransaction(tx) {
      return `<urn:test:s> <urn:test:p> "${tx.value}" .\n`;
    },
    async clearGraphs(tx) { tx.value = null; },
    async addData(tx, content) {
      const match = /<urn:test:s>\s+<urn:test:p>\s+"([^"]+)"/.exec(content);
      tx.value = match?.[1] ?? null;
    },
    async validateInTransactionWithReceipt() { return { conforms: true }; },
    async reportInTransaction() { return []; },
    async selectInTransaction() { return []; },
  };
  const manifest = {
    authored: [], definitions: [{ file: 'authority.ttl', graph }], derived: [], reviews: [], rules: [],
    shapes: [{
      file: 'shapes.ttl', graph: 'urn:usf:graph:shapes', liveValidation: true,
      path: join(import.meta.dirname, '../../semantic-model/shapes.ttl'),
    }],
    publicationBudget: { maximumProjectedStatementCount: 999999 },
  };
  const compiler = createSemanticModelCompilationCommand({
    publicationLane: isolatedPublicationLane(),
    nativeGraphStore: isolatedNativeGraphStore(),
    checkLocalFunction: () => {}, client,
    loadManifestFunction: () => manifest,
    readAuthorityWitness: async () => witness(value === 'old' ? PRE : FINAL),
    repositoryRoot: join(import.meta.dirname, '../..'),
  });
  const validation = await compiler.execute({
    candidateBytes: INITIAL_BYTES, candidateDigest: INITIAL_CANDIDATE,
    expectedAuthorityDigest: PRE, publicationMode: 'validate',
  });
  assert.equal(validation.commitOutcome.candidateDigest, INITIAL_CANDIDATE);
  assert.equal(validation.commitOutcome.state, 'VALIDATED_ROLLBACK');
  assert.equal(value, 'old');
  const committed = await compiler.execute({
    candidateBytes: INITIAL_BYTES, candidateDigest: INITIAL_CANDIDATE,
    expectedAuthorityDigest: PRE, publicationMode: 'commit',
  });
  assert.equal(committed.commitOutcome.candidateDigest, validation.commitOutcome.candidateDigest);
  assert.equal(committed.commitOutcome.state, 'COMMITTED');
  assert.equal(value, 'new');
  assert.equal((await compiler.inspectCandidateState({
    candidateBytes: INITIAL_BYTES, candidateDigest: INITIAL_CANDIDATE,
  })).state, 'post');
});

test('trusted Stardog time absence fails closed before signed validation', async () => {
  await assert.rejects(runPublication(invocation({
    mode: 'validate', trustedTime: undefined,
  })), /trusted-time reader/);
});

test('fractional Stardog publication time is canonicalized before envelope verification', async () => {
  let verifiedAt;
  const result = await runPublication(invocation({
    mode: 'validate',
    trustedTime: async () => '2026-08-01T11:00:00.577Z',
    verifyBundle: ({ now }) => {
      verifiedAt = now.toISOString();
      return { assignment: {}, approval: {}, grant: initialGrant };
    },
  }));
  assert.equal(result.mode, 'validate');
  assert.equal(verifiedAt, '2026-08-01T11:00:00.000Z');
});

test('crash after atomic commit recovers from exact post-state without republishing', async () => {
  const state = journal();
  const compiler = command(INITIAL_CANDIDATE, { throwAfterCommit: 'process interrupted after commit' });
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE]), settle,
    postPublicationReevaluate: producer(),
  })), /process interrupted after commit/);
  assert.equal(state.read().nonces[INITIAL_NONCE].state, 'reserved');
  const recovered = await runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([FINAL, FINAL, FINAL]), settle,
    postPublicationReevaluate: producer({
      observe: () => observation({ authorityDigest: FINAL }),
      produce: () => preparation({ evaluatedAuthorityDigest: FINAL }),
    }),
    persist: (receipt) => ({ digest: publicationReceiptDigest(receipt), path: '/proof/recovered.json' }),
  }));
  assert.equal(recovered.recovered, true);
  assert.equal(compiler.calls.filter(({ publicationMode }) => publicationMode === 'commit').length, 1);
  state.remove();
});

test('new and merely reserved publications still require exact candidate bytes', async () => {
  const empty = journal();
  await assert.rejects(runPublication(invocation({
    mode: 'commit', ledgerPath: empty.ledgerPath, candidateBytes: undefined,
    postPublicationReevaluate: producer(),
  })), /requires exact canonical candidate bytes/);
  empty.remove();

  const reserved = journal();
  const interrupted = command(INITIAL_CANDIDATE, { throwAfterCommit: 'process interrupted after commit' });
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: interrupted, ledgerPath: reserved.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE]), settle,
    postPublicationReevaluate: producer(),
  })), /process interrupted after commit/);
  assert.equal(reserved.read().nonces[INITIAL_NONCE].state, 'reserved');
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: interrupted, ledgerPath: reserved.ledgerPath,
    candidateBytes: undefined,
    readAuthorityWitness: witnessReader([FINAL]), settle,
    postPublicationReevaluate: producer(),
  })), /reserved publication recovery requires exact canonical candidate bytes/);
  reserved.remove();
});

test('compiler failure, unaccepted state, inexact candidate, and digest mismatch fail closed', async () => {
  for (const [bad, pattern] of [
    [{ ...compilerResult('VALIDATED_ROLLBACK', INITIAL_CANDIDATE), ok: false }, /not an exact accepted/],
    [compilerResult('COMMITTED', INITIAL_CANDIDATE), /not an exact accepted/],
    [{ ...compilerResult('VALIDATED_ROLLBACK', INITIAL_CANDIDATE), commitOutcome: { ...compilerResult('VALIDATED_ROLLBACK', INITIAL_CANDIDATE).commitOutcome, exactCandidateStateVerified: false } }, /not an exact accepted/],
    [compilerResult('VALIDATED_ROLLBACK', sha256('wrong')), /differs from the expected/],
  ]) await assert.rejects(runPublication(invocation({
    mode: 'validate', commandInstance: command(INITIAL_CANDIDATE, { validate: bad }),
    readAuthorityWitness: witnessReader([PRE, PRE]),
  })), pattern);
  assert.throws(() => assertAcceptedCompilerResult(compilerResult('FAILED', INITIAL_CANDIDATE), {
    phase: 'commit', expectedCandidateDigest: INITIAL_CANDIDATE,
  }), /not an exact accepted/);
});

test('both commit phases require the injected producer callback', async () => {
  await assert.rejects(runPublication(invocation({ mode: 'commit' })), /requires an injected mandatory/);
  await assert.rejects(runPublication(invocation({
    mode: 'commit', publicationPhase: 'reevaluation', expectedAuthorityDigest: STAGE_ONE,
    expectedCandidateDigest: REEVALUATION_CANDIDATE, publicationGrant: reevaluationEnvelope,
    grant: reevaluationGrant,
  })), /requires an injected mandatory/);
});

test('stage-1 state comes from observe_initial and produce_initial runs only after durable consumption', async () => {
  const state = journal();
  const calls = [];
  let stateAtProduce;
  const stage = await publishInitial(state, {
    postPublicationReevaluate: producer({
      calls,
      produce: () => {
        stateAtProduce = state.read().nonces[INITIAL_NONCE].state;
        return preparation();
      },
    }),
  });
  assert.deepEqual(calls, ['observe_initial', 'produce_initial']);
  assert.equal(stateAtProduce, 'consumed');
  assert.equal(stage.output.direct_provisional_aggregate_selections, 1);
  assert.equal(stage.output.current_proof_results, 0);
  assert.equal(stage.output.proof_currentness, 'PENDING');
  assert.equal(stage.output.action_state, 'UNRESOLVED_FAIL_CLOSED');
  assert.equal(stage.output.selected_provisional_aggregate_result, 'urn:usf:proofresult:provisionalaggregatecompilerproof');
  assert.equal(state.read().nonces[INITIAL_NONCE].published_at, PUBLISHED_AT);
  state.remove();
});

test('stage-1 projection mismatch is rejected without a false receipt or generic permanent failure', async () => {
  const state = journal();
  await assert.rejects(runPublication(invocation({
    mode: 'commit', ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE, STAGE_ONE, STAGE_ONE]), settle,
    postPublicationReevaluate: producer({ observe: () => observation({ directProvisionalAggregateSelections: 0 }) }),
    persist: () => { throw new Error('receipt must not persist'); },
  })), /exactly one provisional aggregate/);
  const record = state.read().nonces[INITIAL_NONCE];
  assert.equal(record.state, 'published_pending_reevaluation');
  assert.equal(record.final_receipt, undefined);
  state.remove();
});

test('reevaluation requires exact full preparation package and durable predecessor equality', async () => {
  const state = journal();
  const stageOne = await publishInitial(state);
  const stageTwo = {
    mode: 'validate', publicationPhase: 'reevaluation', ledgerPath: state.ledgerPath,
    expectedAuthorityDigest: STAGE_ONE, expectedCandidateDigest: REEVALUATION_CANDIDATE,
    publicationGrant: reevaluationEnvelope, grant: reevaluationGrant,
    commandInstance: command(REEVALUATION_CANDIDATE),
    priorPublicationReceipt: stageOne.receipt,
  };
  await assert.rejects(runPublication(invocation({
    ...stageTwo, readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]),
    reevaluationPreparation: { ...stageOne.preparation, executionReceiptDigest: sha256('substituted') },
  })), /no durable stage-1 transaction linkage/);
  await assert.rejects(runPublication(invocation({
    ...stageTwo, readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]),
    priorPublicationReceipt: { ...stageOne.receipt, candidate_digest: REEVALUATION_CANDIDATE },
    reevaluationPreparation: { ...stageOne.preparation, candidateDigest: REEVALUATION_CANDIDATE },
  })), /no durable stage-1 transaction linkage/);
  const accepted = await runPublication(invocation({
    ...stageTwo, readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]),
    reevaluationPreparation: stageOne.preparation,
  }));
  assert.equal(accepted.canonicalCandidateDigest, REEVALUATION_CANDIDATE);
  assert.equal(stageOne.preparation.candidateDigest, INITIAL_CANDIDATE);
  assert.equal(state.read().nonces[INITIAL_NONCE].reevaluation_preparation.package_digest,
    stageOne.output.reevaluationPreparationDigest);
  state.remove();
});

test('expiry during validation is rechecked immediately before commit', async () => {
  const state = journal();
  const compiler = command(INITIAL_CANDIDATE);
  const expires = Date.parse('2026-08-01T12:00:00Z');
  const verifyBundle = ({ now }) => {
    if (now.getTime() >= expires) throw new Error('signed envelope is not current at trusted time');
    return { assignment: {}, approval: {}, grant: initialGrant };
  };
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE]), settle,
    trustedTime: timeReader(['2026-08-01T11:00:00Z', '2026-08-01T11:59:59Z', '2026-08-01T12:00:00Z']),
    verifyBundle, postPublicationReevaluate: producer(),
  })), /not current at trusted time/);
  assert.deepEqual(compiler.calls, [{ expectedAuthorityDigest: PRE, publicationMode: 'validate' }]);
  assert.equal(state.read().nonces[INITIAL_NONCE].state, 'failed');
  state.remove();
});

test('consume failure remains recoverable after grant expiry without republishing', async () => {
  const state = journal();
  const compiler = command(INITIAL_CANDIDATE);
  let consumeAttempts = 0;
  const verificationTimes = [];
  const verifyBundle = ({ now }) => {
    verificationTimes.push(now.toISOString());
    if (now.getTime() >= Date.parse('2026-08-01T13:00:00Z')) {
      throw new Error('signed envelope is not current at trusted time');
    }
    return { assignment: {}, approval: {}, grant: initialGrant };
  };
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE, STAGE_ONE, STAGE_ONE]), settle,
    verifyBundle,
    postPublicationReevaluate: producer(),
    protocolJournal: {
      ...(state.protocolJournal || DEFAULT_PROTOCOL_JOURNAL),
      consumeGrantNonce: () => { consumeAttempts += 1; throw new Error('journal write interrupted'); },
    },
  })), /journal write interrupted/);
  assert.equal(state.read().nonces[INITIAL_NONCE].state, 'published_pending_reevaluation');
  const reportBytes = Buffer.from(canonicalJson({
    authorityDigest: PRE,
    candidateDigest: INITIAL_CANDIDATE,
    providerValidationReceipt: { conforms: true },
    schema: 'semantic-authority-compiler-validation-report-v1',
  }));
  const pendingPackage = {
    aggregateResult: { evaluation: { sourceBindingDigest: OBSERVATION } },
    evaluatedAuthorityDigest: PRE,
  };
  const recovered = await runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    candidateBytes: undefined,
    pendingPackage,
    readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]), settle,
    trustedTime: timeReader(['2026-08-01T14:00:00Z']),
    verifyBundle,
    recoveryValidationEvidence: { bytes: reportBytes, digest: sha256(reportBytes) },
    postPublicationReevaluate: producer(),
    persist: (receipt) => ({ digest: publicationReceiptDigest(receipt), path: '/proof/recovered.json' }),
  }));
  assert.equal(recovered.recovered, true);
  assert.equal(recovered.compilerValidation.receipt.authorityBeforeDigest, PRE);
  assert.equal(recovered.compilerValidation.receipt.authorityAfterDigest, STAGE_ONE);
  assert.equal(recovered.compilerValidation.receipt.sourceBindingDigest, OBSERVATION);
  assert.equal(consumeAttempts, 1);
  assert.deepEqual(verificationTimes, [
    '2026-08-01T12:00:00.000Z',
    '2026-08-01T12:00:00.000Z',
    '2026-08-01T12:00:00.000Z',
  ]);
  assert.deepEqual(compiler.calls, [
    { expectedAuthorityDigest: PRE, publicationMode: 'validate' },
    { expectedAuthorityDigest: PRE, publicationMode: 'commit' },
  ]);
  state.remove();
});

test('recovery validation evidence cannot enter a new or non-initial publication', async () => {
  const evidenceBytes = Buffer.from('{}');
  await assert.rejects(runPublication(invocation({
    mode: 'validate',
    recoveryValidationEvidence: { bytes: evidenceBytes, digest: sha256(evidenceBytes) },
  })), /restricted to initial publication recovery/);
  const state = journal();
  await assert.rejects(runPublication(invocation({
    mode: 'commit',
    ledgerPath: state.ledgerPath,
    recoveryValidationEvidence: { bytes: evidenceBytes, digest: sha256(evidenceBytes) },
    postPublicationReevaluate: producer(),
  })), /requires an existing durable publication outcome/);
  state.remove();
});

test('persist failure leaves a full consumed receipt and recovery resumes producer without republishing', async () => {
  const state = journal();
  const compiler = command(INITIAL_CANDIDATE);
  let produceCalls = 0;
  const callback = producer({ produce: () => { produceCalls += 1; return preparation(); } });
  await assert.rejects(runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([PRE, PRE, STAGE_ONE, STAGE_ONE]), settle,
    postPublicationReevaluate: callback,
    persist: () => { throw new Error('receipt store interrupted'); },
  })), /receipt store interrupted/);
  const interrupted = state.read().nonces[INITIAL_NONCE];
  assert.equal(interrupted.state, 'consumed');
  assert.equal(interrupted.final_receipt.grant_consumed, true);
  assert.equal(interrupted.final_receipt_digest, publicationReceiptDigest(interrupted.final_receipt));
  const recovered = await runPublication(invocation({
    mode: 'commit', commandInstance: compiler, ledgerPath: state.ledgerPath,
    readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE]), settle,
    postPublicationReevaluate: callback,
    persist: (receipt) => ({ digest: publicationReceiptDigest(receipt), path: '/proof/recovered.json' }),
  }));
  assert.equal(recovered.recovered, true);
  assert.equal(produceCalls, 1);
  assert.equal(state.read().nonces[INITIAL_NONCE].reevaluation_preparation.package.candidateDigest, INITIAL_CANDIDATE);
  assert.equal(compiler.calls.filter((call) => call.publicationMode === 'commit').length, 1);
  state.remove();
});

test('reevaluation terminal verification resumes after post-commit process failure without republishing', async () => {
  const state = journal();
  const stageOne = await publishInitial(state);
  const compiler = command(REEVALUATION_CANDIDATE);
  let terminalAttempts = 0;
  const second = invocation({
    mode: 'commit', publicationPhase: 'reevaluation', ledgerPath: state.ledgerPath,
    expectedAuthorityDigest: STAGE_ONE, expectedCandidateDigest: REEVALUATION_CANDIDATE,
    publicationGrant: reevaluationEnvelope, grant: reevaluationGrant, commandInstance: compiler,
    readAuthorityWitness: witnessReader([STAGE_ONE, STAGE_ONE, FINAL, FINAL]), settle,
    priorPublicationReceipt: stageOne.receipt, reevaluationPreparation: stageOne.preparation,
    postPublicationReevaluate: producer({ verify: () => {
      terminalAttempts += 1;
      if (terminalAttempts === 1) throw new Error('projector interrupted');
      return terminal();
    } }),
    persist: (receipt) => ({ digest: publicationReceiptDigest(receipt), path: '/proof/final.json' }),
  });
  await assert.rejects(runPublication(second), /projector interrupted/);
  assert.equal(state.read().nonces[REEVALUATION_NONCE].state, 'published_pending_reevaluation');
  const recovered = await runPublication({
    ...second,
    readAuthorityWitness: witnessReader([FINAL]),
  });
  assert.equal(recovered.proof_currentness, 'CURRENT');
  assert.equal(recovered.action_state, 'PROCEED');
  assert.equal(terminalAttempts, 2);
  assert.equal(compiler.calls.filter((call) => call.publicationMode === 'commit').length, 1);
  state.remove();
});


test('terminal V2 is irreversible: deleting the fence quad does not resurrect V1', async () => {
  // The fence quad is a RUNTIME marker. Terminal ownership derives from durable
  // admitted state, so removing the fence must fail closed -- never fall back to
  // V1_OWNER. This is the difference between a fence and a barrier.
  const nativeRoot = mkdtempSync(join(tmpdir(), 'usf-terminal-floor-'));
  const casRoot = mkdtempSync(join(tmpdir(), 'usf-terminal-floor-cas-'));
  const store = createGraphNativeSuccessorStoreV2({
    nativeRoot,
    casStore: createCasEvidenceStore(casRoot),
  });

  // No durable generation yet: an absent fence is genuinely pre-handover V1.
  assert.equal(store.readTerminalOwnershipFloor().terminal, false);

  const witness = { digest: `sha256:${'a'.repeat(64)}`, inventory: [], triples: 0 };
  const readAuthorityWitness = async () => witness;
  const client = { select: async () => [] };

  const preTerminal = await observeGraphRuntimeOwnershipV2({
    client,
    expectedAuthorityDigest: witness.digest,
    readAuthorityWitness,
    nativeGraphStore: store,
  });
  assert.equal(preTerminal.ownership_state, 'V1_OWNER');

  // Admit durable terminal state, then delete the fence (the client returns no
  // fence rows at all, which is exactly the "quad deleted" case).
  const generation = 'b'.repeat(64);
  mkdirSync(join(nativeRoot, generation), { recursive: true });
  writeFileSync(join(nativeRoot, generation, 'terminal-receipt.json'), '{}\n');

  const floor = store.readTerminalOwnershipFloor();
  assert.equal(floor.terminal, true);
  assert.deepEqual(floor.generations, [`sha256:${generation}`]);

  await assert.rejects(
    () => observeGraphRuntimeOwnershipV2({
      client,
      expectedAuthorityDigest: witness.digest,
      readAuthorityWitness,
      nativeGraphStore: store,
    }),
    /V2_GRAPH_TERMINAL_OWNERSHIP_FENCE_MISSING/,
    'a deleted fence over durable terminal state must fail closed, not report V1',
  );
});

// (4) No caller-supplied or fallback identity can satisfy the V2 publisher binding. The
// identity is resolved from live authority only: an absent, duplicated, or malformed
// declaration refuses the publication instead of letting the caller assert its own digests
// into the coordination identity and the terminal receipt.
test('the V2 publisher identity is resolved from authority and never supplied by the caller', async () => {
  const admitted = Object.freeze({
    canonicalName: { value: 'nativev2publisher' },
    commandDigest: { value: `sha256:${'a'.repeat(64)}` },
    publisher: { value: 'urn:usf:publisherimplementation:nativev2publisher' },
    setDigest: { value: `sha256:${'b'.repeat(64)}` },
    sourcePath: { value: 'processes/semantic-assurance/semantic-authority-publication.mjs' },
  });
  const clientReturning = (rows) => ({ select: async () => rows });

  const resolved = await readAdmittedPublisherIdentityV2(clientReturning([admitted]));
  assert.equal(resolved.commandDigest, admitted.commandDigest.value);
  assert.equal(resolved.implementationSourceSetDigest, admitted.setDigest.value);
  assert.equal(resolved.sourcePath, admitted.sourcePath.value);

  // No declaration must not degrade to a caller-supplied or default identity.
  await assert.rejects(
    () => readAdmittedPublisherIdentityV2(clientReturning([])),
    /V2_PUBLISHER_IDENTITY_NOT_EXACTLY_ONE/u,
  );
  // An ambiguous declaration must refuse rather than pick one.
  await assert.rejects(
    () => readAdmittedPublisherIdentityV2(clientReturning([admitted, admitted])),
    /V2_PUBLISHER_IDENTITY_NOT_EXACTLY_ONE/u,
  );
  // An assurance path here would mean the identity had drifted out of its processes scope.
  await assert.rejects(
    () => readAdmittedPublisherIdentityV2(clientReturning([{
      ...admitted,
      sourcePath: { value: 'assurance/semantic-model-compilation/aggregate-compiler-proof.mjs' },
    }])),
    /V2_PUBLISHER_IDENTITY_SOURCE_PATH_INVALID/u,
  );
  // A non-exact digest must refuse rather than be recorded.
  await assert.rejects(
    () => readAdmittedPublisherIdentityV2(clientReturning([{
      ...admitted, commandDigest: { value: 'sha256:not-a-digest' },
    }])),
    /V2_PUBLISHER_IDENTITY_DIGEST_INVALID/u,
  );
  // There is no query surface to fall back to.
  await assert.rejects(
    () => readAdmittedPublisherIdentityV2({}),
    /V2_PUBLISHER_IDENTITY_CLIENT_REQUIRED/u,
  );
});

test('the live V2 production configuration overrides any caller-supplied publisher identity', () => {
  const source = readFileSync(
    new URL('./semantic-authority-publication.mjs', import.meta.url), 'utf8',
  );
  // The caller's publisher digests are destructured away and replaced by the authority
  // values, so `exactGraphProductionInputsV2` compares the v2-inputs file against authority
  // rather than against the caller's own assertion.
  assert.match(source, /publisherImplementationDigest: _callerPublisherImplementationDigest/u);
  assert.match(source, /publisherCommandDigest: _callerPublisherCommandDigest/u);
  assert.match(
    source,
    /publisherImplementationDigest: admittedPublisher\.implementationSourceSetDigest/u,
  );
  assert.match(source, /publisherCommandDigest: admittedPublisher\.commandDigest/u);
});

// The Factory-side closure executor identity is authority-resolved and fail-closed. Absent,
// ambiguous, malformed, wrong-repository, wrong-path, wrong-source-set and wrong-command
// declarations must all refuse, and the caller must never be able to substitute its own.
test('the V2 closure executor identity is resolved from authority and fails closed', async () => {
  const admitted = Object.freeze({
    canonicalName: { value: 'factorynativev2closureexecutor' },
    commandDigest: { value: `sha256:${'1'.repeat(64)}` },
    commandPath: { value: 'src/usf_factory/cli.py' },
    commit: { value: 'a'.repeat(40) },
    executor: { value: 'urn:usf:closureexecutorimplementation:factorynativev2closureexecutor' },
    repository: { value: 'maldous/usf-factory' },
    setDigest: { value: `sha256:${'2'.repeat(64)}` },
    tree: { value: 'b'.repeat(40) },
  });
  const clientReturning = (rows) => ({ select: async () => rows });

  const resolved = await readAdmittedClosureExecutorIdentityV2(clientReturning([admitted]));
  assert.equal(resolved.repository, 'maldous/usf-factory');
  assert.equal(resolved.commandPath, 'src/usf_factory/cli.py');
  assert.equal(resolved.commandDigest, admitted.commandDigest.value);
  assert.equal(resolved.implementationSourceSetDigest, admitted.setDigest.value);
  assert.equal(resolved.commit, admitted.commit.value);
  assert.equal(resolved.tree, admitted.tree.value);

  for (const [rows, pattern, label] of [
    [[], /V2_CLOSURE_EXECUTOR_IDENTITY_NOT_EXACTLY_ONE/u, 'absent'],
    [[admitted, admitted], /V2_CLOSURE_EXECUTOR_IDENTITY_NOT_EXACTLY_ONE/u, 'ambiguous'],
    [[{ ...admitted, repository: { value: 'maldous/usf-graph' } }],
      /V2_CLOSURE_EXECUTOR_IDENTITY_REPOSITORY_INVALID/u, 'wrong repository'],
    [[{ ...admitted, commandPath: { value: 'processes/semantic-assurance/x.mjs' } }],
      /V2_CLOSURE_EXECUTOR_IDENTITY_COMMAND_PATH_INVALID/u, 'wrong path space'],
    [[{ ...admitted, commandDigest: { value: 'sha256:not-a-digest' } }],
      /V2_CLOSURE_EXECUTOR_IDENTITY_DIGEST_INVALID/u, 'malformed command digest'],
    [[{ ...admitted, setDigest: { value: 'nope' } }],
      /V2_CLOSURE_EXECUTOR_IDENTITY_DIGEST_INVALID/u, 'malformed source set digest'],
    [[{ ...admitted, commit: { value: 'short' } }],
      /V2_CLOSURE_EXECUTOR_IDENTITY_SOURCE_INVALID/u, 'malformed commit'],
  ]) {
    await assert.rejects(() => readAdmittedClosureExecutorIdentityV2(clientReturning(rows)),
      pattern, label);
  }
  await assert.rejects(() => readAdmittedClosureExecutorIdentityV2({}),
    /V2_CLOSURE_EXECUTOR_IDENTITY_CLIENT_REQUIRED/u, 'no query surface to fall back to');
});

test('the V2 evidence-admission producer identity is resolved from authority and fails closed', async () => {
  const admitted = Object.freeze({
    admissionPath: { value: 'urn:usf:evidenceadmissionpath:compilersemanticenforcementaggregate' },
    canonicalName: { value: 'compilersemanticenforcementaggregateevidenceadmissionproducer' },
    identity: { value: 'urn:usf:evidenceadmissionproduceridentity:x' },
    producer: { value: 'urn:usf:validationproducer:compilersemanticenforcementaggregate' },
    repository: { value: 'maldous/usf-graph' },
    scopeDigest: { value: `sha256:${'3'.repeat(64)}` },
    setDigest: { value: `sha256:${'4'.repeat(64)}` },
  });
  const clientReturning = (rows) => ({ select: async () => rows });

  const resolved =
    await readAdmittedEvidenceAdmissionProducerIdentityV2(clientReturning([admitted]));
  // The identity digest is the producer's implementation source set digest, NOT its source
  // scope digest: a source scope is shared with other subjects and does not identify a producer.
  assert.equal(resolved.identityDigest, admitted.setDigest.value);
  assert.notEqual(resolved.identityDigest, resolved.sourceScopeDigest);
  assert.equal(resolved.validationProducerIri, admitted.producer.value);
  assert.equal(resolved.evidenceAdmissionPathIri, admitted.admissionPath.value);

  for (const [rows, pattern, label] of [
    [[], /V2_ADMISSION_PRODUCER_IDENTITY_NOT_EXACTLY_ONE/u, 'absent'],
    [[admitted, admitted], /V2_ADMISSION_PRODUCER_IDENTITY_NOT_EXACTLY_ONE/u, 'ambiguous'],
    [[{ ...admitted, producer: { value: 'urn:usf:validationobligation:x' } }],
      /V2_ADMISSION_PRODUCER_IDENTITY_BINDING_INVALID/u, 'wrong producer kind'],
    [[{ ...admitted, admissionPath: { value: 'urn:usf:evidenceresult:x' } }],
      /V2_ADMISSION_PRODUCER_IDENTITY_BINDING_INVALID/u, 'wrong admission path kind'],
    [[{ ...admitted, repository: { value: 'maldous/usf-factory' } }],
      /V2_ADMISSION_PRODUCER_IDENTITY_REPOSITORY_INVALID/u, 'wrong repository'],
    [[{ ...admitted, setDigest: { value: 'sha256:nope' } }],
      /V2_ADMISSION_PRODUCER_IDENTITY_DIGEST_INVALID/u, 'malformed identity digest'],
  ]) {
    await assert.rejects(
      () => readAdmittedEvidenceAdmissionProducerIdentityV2(clientReturning(rows)),
      pattern, label);
  }
  await assert.rejects(() => readAdmittedEvidenceAdmissionProducerIdentityV2({}),
    /V2_ADMISSION_PRODUCER_IDENTITY_CLIENT_REQUIRED/u, 'no query surface to fall back to');
});

test('live V2 production discards caller-selected executor and producer identities', () => {
  const source = readFileSync(
    new URL('./semantic-authority-publication.mjs', import.meta.url), 'utf8',
  );
  // Caller-supplied Factory identities are destructured away and replaced by authority's.
  assert.match(source, /factoryExecutorImplementationDigest: _callerFactoryExecutorImplementationDigest/u);
  assert.match(source, /factoryClosureCommandDigest: _callerFactoryClosureCommandDigest/u);
  assert.match(source,
    /factoryExecutorImplementationDigest: admittedClosureExecutor\.implementationSourceSetDigest/u);
  assert.match(source, /factoryClosureCommandDigest: admittedClosureExecutor\.commandDigest/u);
  // A stale executor cannot satisfy a current plan, and the renewal rule must name the
  // admitted producer.
  assert.match(source, /V2_CLOSURE_EXECUTOR_IDENTITY_IS_NOT_THE_PLANNED_FACTORY_SOURCE/u);
  assert.match(source, /V2_ADMISSION_PRODUCER_IDENTITY_IS_NOT_THE_ADMITTED_PRODUCER/u);
  // And the publish path must pass authority's values, never the inputs file's.
  assert.match(source,
    /factory_executor_implementation_digest: executor\.implementationSourceSetDigest/u);
  assert.match(source, /factory_closure_command_digest: executor\.commandDigest/u);
});
