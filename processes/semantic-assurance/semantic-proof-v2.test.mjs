import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  advanceDurableSemanticProofV2Publication,
  advanceSemanticProofV2Publication,
  canonicalDigestV2,
  closureTransactionIdV2,
  DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
  factoryClosureReceiptDigestV2,
  graphPublicationReceiptDigestV2,
  HermeticSemanticProofV2Journal,
  IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST,
  prospectivePublicationPlanDigestV2,
  SemanticProofV2JournalState,
} from './semantic-proof-v2.mjs';

const digest = (character) => `sha256:${character.repeat(64)}`;
const KINDS = Object.freeze([
  'contract_projection',
  'execution_scope_projection',
  'factory_graph_witness_binding',
  'owner_envelope_successor',
  'run_authorization',
  'validation_currentness_binding',
  'workforce_policy_compatibility_binding',
]);

// Node's permission model deliberately disables fsync even for a permitted
// writable directory.  V1 owns and separately tests the real fsync+rename
// implementation; these coordinator tests inject only the byte sink so the
// hermetic semantic gate exercises the V2 state/receipt composition rather
// than an API that its runner explicitly forbids.
const HERMETIC_DURABLE_JOURNAL_IO = Object.freeze({
  write(path, contents) {
    writeFileSync(path, contents, { mode: 0o600 });
    chmodSync(path, 0o600);
  },
});

function fixture() {
  const releaseSubject = digest('1');
  const d0 = digest('2');
  const d1 = digest('3');
  const d2 = digest('4');
  const dependencies = Object.freeze([digest('5'), digest('6')]);
  const semanticCharacters = ['a', 'b', 'c', 'd', 'e', 'f', '9'];
  const predecessorCharacters = ['8', '7', '6', '5', '4', '3', '2'];
  const materialisationCharacters = ['1', '2', '3', '4', '5', '6', '7'];
  const currentMaterialisationCharacters = ['0', '1', '2', '3', '4', '5', '6'];
  const consumers = KINDS.map((kind, index) => {
    const semanticScope = digest(semanticCharacters[index]);
    const predecessor = digest(predecessorCharacters[index]);
    const materialisation = digest(materialisationCharacters[index]);
    const successor = {
      authority_digest: d2,
      consumer_iri: `urn:usf:derivedconsumer:v2:${kind.replaceAll('_', '-')}`,
      consumer_kind: kind,
      consumer_schema_version: 2,
      current_policy_compatibility_digest: kind === 'workforce_policy_compatibility_binding'
        ? digest('e') : null,
      historical_policy_identity_digest: kind === 'workforce_policy_compatibility_binding'
        ? digest('f') : null,
      materialisation_digest: materialisation,
      predecessor_identity_digest: predecessor,
      producer_iri: `urn:usf:producer:${kind.replaceAll('_', '-')}:v2`,
      record_iri: `urn:usf:derivedconsumersuccessor:v2:${kind}:${index}`,
      registry_digest: DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
      release_subject_digest: releaseSubject,
      repository_category: kind === 'factory_graph_witness_binding'
        ? 'maldous/usf-factory' : null,
      schema: 'usf-derived-consumer-successor-v2',
      semantic_scope_digest: semanticScope,
      transition_cause: 'PUBLICATION_DERIVED_MATERIALISATION',
      validation_input_authority_digest: kind === 'validation_currentness_binding'
        ? d1 : null,
      validation_input_identity_digests: kind === 'validation_currentness_binding'
        ? dependencies : [],
      verification_algorithm_iri: `urn:usf:algorithm:verify-${kind.replaceAll('_', '-')}:v2`,
      verification_algorithm_version: '2.0.0',
    };
    return Object.freeze({
      block_reason: null,
      consumer_iri: successor.consumer_iri,
      consumer_kind: kind,
      current_materialisation_digest: digest(currentMaterialisationCharacters[index]),
      current_semantic_scope_digest: semanticScope,
      decision: 'COMPATIBLE_SUCCESSOR',
      expected_successor: Object.freeze(successor),
      expected_successor_digest: canonicalDigestV2(successor),
      mandatory: true,
      predecessor_identity_digest: predecessor,
      predecessor_record_digest: digest(materialisationCharacters[index]),
      predicted_d1_authority_digest: d1,
      predicted_d2_authority_digest: d2,
      prospective_materialisation_digest: materialisation,
      prospective_semantic_scope_digest: semanticScope,
    });
  });
  const plan = Object.freeze({
    d0_authority_digest: d0,
    d1_dependency_identity_digests: dependencies,
    d2_evaluation_input_authority_digest: d1,
    derived_consumer_registry_digest: DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
    derived_consumers: Object.freeze(consumers),
    factory_deployment_tree: 'a'.repeat(40),
    graph_protected_tree: 'b'.repeat(40),
    identity_dependency_graph_digest: IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST,
    outcome: 'PROCEED',
    predicted_d1_authority_digest: d1,
    predicted_d2_authority_digest: d2,
    release_subject_digest: releaseSubject,
    required_cas_object_digests: Object.freeze([digest('7'), digest('8')]),
    schema: 'usf-prospective-publication-plan-v2',
  });
  const current = consumers.map((item) => item.expected_successor_digest).sort();
  const closure = Object.freeze({
    schema: 'usf-derived-consumer-closure-receipt-v2',
    transaction_id: closureTransactionIdV2(plan),
    release_subject_digest: plan.release_subject_digest,
    prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(plan),
    derived_consumer_registry_digest: plan.derived_consumer_registry_digest,
    d1_authority_digest: d1,
    d2_authority_digest: d2,
    successor_identity_digests: Object.freeze([...current]),
    mandatory_consumer_identity_digests: Object.freeze([...current]),
    explicit_authorization_grant_digests: Object.freeze([]),
    graph_d1_commit_receipt_digest: digest('a'),
    graph_d1_observation_receipt_digest: digest('b'),
    graph_d2_commit_receipt_digest: digest('c'),
    terminal_result: 'VERIFIED',
  });
  return { closure, plan };
}

function adapter(plan, {
  throwAfterD1 = false,
  throwAfterD2 = false,
  throwAfterTerminal = false,
  throwAfterConsume = false,
} = {}) {
  const state = {
    reservationCount: 0,
    d1CommitCount: 0,
    d2CommitCount: 0,
    terminalCount: 0,
    consumeCount: 0,
    d1: null,
    d2: null,
    terminal: null,
    consumed: false,
    threwD1: false,
    threwD2: false,
    threwTerminal: false,
    threwConsume: false,
  };
  return Object.freeze({
    state,
    async reserveGrant() {
      if (state.reservationCount === 0) state.reservationCount += 1;
      return { digest: digest('9') };
    },
    async commitD1() {
      if (state.d1 === null) {
        state.d1 = plan.predicted_d1_authority_digest;
        state.d1CommitCount += 1;
        if (throwAfterD1 && !state.threwD1) {
          state.threwD1 = true;
          throw new Error('simulated death after physical D1 commit');
        }
      }
      return { authority_digest: state.d1, receipt_digest: digest('a') };
    },
    async observeD1() {
      return {
        authority_digest: state.d1,
        dependency_identity_digests: plan.d1_dependency_identity_digests,
        receipt_digest: digest('b'),
      };
    },
    async commitD2() {
      if (state.d2 === null) {
        state.d2 = plan.predicted_d2_authority_digest;
        state.d2CommitCount += 1;
        if (throwAfterD2 && !state.threwD2) {
          state.threwD2 = true;
          throw new Error('simulated death after physical D2 commit');
        }
      }
      return {
        authority_digest: state.d2,
        evaluated_authority_digest: plan.predicted_d1_authority_digest,
        receipt_digest: digest('c'),
      };
    },
    async persistTerminalReceipt(receipt) {
      const observed = graphPublicationReceiptDigestV2(receipt);
      if (state.terminal !== null && state.terminal !== observed) {
        throw new Error('terminal receipt fork');
      }
      if (state.terminal === null) {
        state.terminal = observed;
        state.terminalCount += 1;
        if (throwAfterTerminal && !state.threwTerminal) {
          state.threwTerminal = true;
          throw new Error('simulated death after terminal receipt persistence');
        }
      }
      return { digest: observed };
    },
    async consumeGrant(receipt) {
      assert.equal(graphPublicationReceiptDigestV2(receipt), state.terminal);
      if (!state.consumed) {
        state.consumed = true;
        state.consumeCount += 1;
        if (throwAfterConsume && !state.threwConsume) {
          state.threwConsume = true;
          throw new Error('simulated death after grant consumption');
        }
      }
      return { digest: digest('d') };
    },
  });
}

function inputs(plan, journal, graphAdapter, closure) {
  return {
    plan,
    journal,
    graph_adapter: graphAdapter,
    factory_closure_receipt: closure,
    trusted_at: '2026-08-10T07:00:00Z',
    terminal_receipt_at: '2026-08-10T07:00:30Z',
    factory_commit: 'c'.repeat(40),
    factory_tree: plan.factory_deployment_tree,
    graph_commit: 'd'.repeat(40),
    graph_tree: plan.graph_protected_tree,
    publisher_implementation_digest: digest('e'),
    factory_executor_implementation_digest: digest('f'),
    publisher_command_digest: digest('0'),
    factory_closure_command_digest: digest('1'),
  };
}

async function complete(values) {
  let result;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    result = await advanceSemanticProofV2Publication(values);
    if (result.terminal) return result;
  }
  throw new Error('V2 transaction did not reach terminal state');
}

test('V2 canonical publisher withholds terminal acceptance until exact Factory closure', async () => {
  const { closure, plan } = fixture();
  const journal = new HermeticSemanticProofV2Journal();
  const graphAdapter = adapter(plan);
  const values = inputs(plan, journal, graphAdapter, undefined);
  for (let index = 0; index < 5; index += 1) {
    await advanceSemanticProofV2Publication(values);
  }
  assert.equal(journal.state(), SemanticProofV2JournalState.D2_COMMITTED);
  assert.equal(journal.publicationState, 'COMMITTED_PENDING_DERIVED_CLOSURE');
  const pending = await advanceSemanticProofV2Publication(values);
  assert.equal(pending.terminal, false);
  assert.equal(journal.state(), SemanticProofV2JournalState.D2_COMMITTED);
  assert.equal(graphAdapter.state.terminalCount, 0);
  assert.equal(graphAdapter.state.consumeCount, 0);

  values.factory_closure_receipt = closure;
  const result = await complete(values);
  assert.equal(result.state, SemanticProofV2JournalState.CONSUMED);
  assert.equal(result.receipt.publication_outcome, 'accepted');
  assert.equal(result.receipt.factory_closure_receipt_digest,
    factoryClosureReceiptDigestV2(closure, plan));
  assert.equal(journal.publicationState, 'ACCEPTED');
  assert.deepEqual(graphAdapter.state, {
    reservationCount: 1,
    d1CommitCount: 1,
    d2CommitCount: 1,
    terminalCount: 1,
    consumeCount: 1,
    d1: plan.predicted_d1_authority_digest,
    d2: plan.predicted_d2_authority_digest,
    terminal: graphPublicationReceiptDigestV2(result.receipt),
    consumed: true,
    threwD1: false,
    threwD2: false,
    threwTerminal: false,
    threwConsume: false,
  });
});

test('V2 publication recovers exactly from every durable journal boundary', async () => {
  const { closure, plan } = fixture();
  for (const crashState of Object.values(SemanticProofV2JournalState).slice(0, -1)) {
    let journal = new HermeticSemanticProofV2Journal();
    const graphAdapter = adapter(plan);
    let values = inputs(plan, journal, graphAdapter, closure);
    while (journal.state() !== crashState) await advanceSemanticProofV2Publication(values);
    journal = new HermeticSemanticProofV2Journal(journal.snapshotBytes());
    values = inputs(plan, journal, graphAdapter, closure);
    const result = await complete(values);
    assert.equal(result.state, SemanticProofV2JournalState.CONSUMED);
    assert.equal(graphAdapter.state.d1CommitCount, 1);
    assert.equal(graphAdapter.state.d2CommitCount, 1);
    assert.equal(graphAdapter.state.terminalCount, 1);
    assert.equal(graphAdapter.state.consumeCount, 1);
  }
});

test('V2 durable journal atomically resumes through canonical publisher boundaries', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-semantic-proof-v2-'));
  try {
    const journalPath = join(root, 'journal', 'publication.json');
    const { closure, plan } = fixture();
    const graphAdapter = adapter(plan);
    let result;
    const values = inputs(plan, new HermeticSemanticProofV2Journal(), graphAdapter, closure);
    for (let attempt = 0; attempt < 20; attempt += 1) {
      result = await advanceDurableSemanticProofV2Publication(values, {
        journalPath,
        journalIo: HERMETIC_DURABLE_JOURNAL_IO,
      });
      if (result.terminal) break;
    }
    assert.equal(result.state, SemanticProofV2JournalState.CONSUMED);
    assert.match(result.journalDigest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(graphAdapter.state.d1CommitCount, 1);
    assert.equal(graphAdapter.state.d2CommitCount, 1);
    assert.equal(graphAdapter.state.terminalCount, 1);
    assert.equal(graphAdapter.state.consumeCount, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('V2 durable journal rejects a broadened persisted mode', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-semantic-proof-v2-mode-'));
  try {
    const journalPath = join(root, 'journal', 'publication.json');
    const { closure, plan } = fixture();
    const graphAdapter = adapter(plan);
    const values = inputs(plan, new HermeticSemanticProofV2Journal(), graphAdapter, closure);
    await advanceDurableSemanticProofV2Publication(values, {
      journalPath,
      journalIo: HERMETIC_DURABLE_JOURNAL_IO,
    });
    chmodSync(journalPath, 0o644);
    await assert.rejects(
      advanceDurableSemanticProofV2Publication(values, {
        journalPath,
        journalIo: HERMETIC_DURABLE_JOURNAL_IO,
      }),
      /owner-only regular file/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

for (const boundary of ['D1', 'D2']) {
  test(`V2 recovery observes exact physical ${boundary} after interruption`, async () => {
    const { closure, plan } = fixture();
    let journal = new HermeticSemanticProofV2Journal();
    const graphAdapter = adapter(plan, {
      throwAfterD1: boundary === 'D1',
      throwAfterD2: boundary === 'D2',
    });
    let values = inputs(plan, journal, graphAdapter, closure);
    await assert.rejects(complete(values), new RegExp(`physical ${boundary} commit`));
    journal = new HermeticSemanticProofV2Journal(journal.snapshotBytes());
    values = inputs(plan, journal, graphAdapter, closure);
    const result = await complete(values);
    assert.equal(result.state, SemanticProofV2JournalState.CONSUMED);
    assert.equal(graphAdapter.state.d1CommitCount, 1);
    assert.equal(graphAdapter.state.d2CommitCount, 1);
  });
}

for (const boundary of ['terminal receipt persistence', 'grant consumption']) {
  test(`V2 recovery observes exact ${boundary} after interruption`, async () => {
    const { closure, plan } = fixture();
    let journal = new HermeticSemanticProofV2Journal();
    const graphAdapter = adapter(plan, {
      throwAfterTerminal: boundary === 'terminal receipt persistence',
      throwAfterConsume: boundary === 'grant consumption',
    });
    let values = inputs(plan, journal, graphAdapter, closure);
    await assert.rejects(complete(values), new RegExp(boundary));
    journal = new HermeticSemanticProofV2Journal(journal.snapshotBytes());
    values = {
      ...inputs(plan, journal, graphAdapter, closure),
      trusted_at: '2026-08-10T07:01:00Z',
    };
    const result = await complete(values);
    assert.equal(result.state, SemanticProofV2JournalState.CONSUMED);
    assert.equal(graphAdapter.state.terminalCount, 1);
    assert.equal(graphAdapter.state.consumeCount, 1);
  });
}

test('V2 Graph independently rejects substituted closure and coordination inputs', async () => {
  const { closure, plan } = fixture();
  const badClosure = { ...closure, d2_authority_digest: digest('9') };
  assert.throws(
    () => factoryClosureReceiptDigestV2(badClosure, plan),
    /differs from the approved prospective plan/,
  );

  const journal = new HermeticSemanticProofV2Journal();
  const graphAdapter = adapter(plan);
  const values = inputs(plan, journal, graphAdapter, closure);
  await advanceSemanticProofV2Publication(values);
  const changedCommand = { ...values, publisher_command_digest: digest('2') };
  await assert.rejects(
    advanceSemanticProofV2Publication(changedCommand),
    /journal drifted from the approved coordination contract/,
  );
  const changedPlan = {
    ...plan,
    derived_consumers: plan.derived_consumers.map((item, index) => index === 0
      ? { ...item, prospective_semantic_scope_digest: digest('9') }
      : item),
  };
  assert.throws(() => prospectivePublicationPlanDigestV2(changedPlan), /successor prediction drifted/);
});

test('V2 journal recovery rejects unknown fields and terminal-receipt substitution', async () => {
  const { closure, plan } = fixture();
  const journal = new HermeticSemanticProofV2Journal();
  const graphAdapter = adapter(plan);
  const values = inputs(plan, journal, graphAdapter, closure);
  const result = await complete(values);
  assert.equal(result.state, SemanticProofV2JournalState.CONSUMED);

  const unknown = JSON.parse(journal.snapshotBytes().toString('utf8'));
  unknown.unreviewed = true;
  assert.throws(
    () => new HermeticSemanticProofV2Journal(Buffer.from(JSON.stringify(unknown))),
    /fields are not the closed protocol shape/,
  );

  const substituted = JSON.parse(journal.snapshotBytes().toString('utf8'));
  substituted.terminal_receipt.d2_authority_digest = digest('9');
  const recovered = new HermeticSemanticProofV2Journal(Buffer.from(JSON.stringify(substituted)));
  await assert.rejects(
    advanceSemanticProofV2Publication(inputs(plan, recovered, graphAdapter, closure)),
    /terminal receipt drifted from its approved transaction/,
  );
});

test('canonical Graph publisher exports the separately versioned V2 coordinator', async () => {
  const publisher = await import('./semantic-authority-publication.mjs');
  assert.equal(publisher.advanceSemanticProofV2Publication, advanceSemanticProofV2Publication);
  assert.equal(
    publisher.advanceDurableSemanticProofV2Publication,
    advanceDurableSemanticProofV2Publication,
  );
  assert.equal(publisher.HermeticSemanticProofV2Journal, HermeticSemanticProofV2Journal);
});
