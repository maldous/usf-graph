import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  advanceDurableSemanticProofV2Publication,
  advanceSemanticProofV2Publication,
  assertGraphProductionShadowPlanBindingV2,
  canonicalGraphOwnedConsumerObservationBytesV2,
  canonicalGraphOwnedConsumerRecordBytesV2,
  canonicalGraphProductionShadowReceiptBytesV2,
  captureGraphOwnedConsumerObservationV2,
  captureGraphProductionShadowV2,
  canonicalJsonV2,
  canonicalDigestV2,
  closureTransactionIdV2,
  createReadOnlyGraphProductionAdapterV2,
  DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
  factoryClosureReceiptDigestV2,
  graphOwnedConsumerObservationDigestV2,
  graphOwnedConsumerRecordDigestV2,
  graphPublicationReceiptDigestV2,
  graphProductionShadowReceiptDigestV2,
  HermeticSemanticProofV2Journal,
  IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST,
  prospectivePublicationPlanDigestV2,
  SemanticProofV2JournalState,
} from './semantic-proof-v2.mjs';
import { semanticAuthorityInventoryDigest } from './semantic-authority-gateway.mjs';

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

function graphOwnedConsumerInputs() {
  const statement = (subject, value) => Object.freeze({
    subject,
    predicate: 'urn:usf:ontology:canonicalName',
    object: Object.freeze({ term_type: 'literal', value, datatype: null, language: null }),
  });
  return Object.freeze([
    Object.freeze({
      consumer_kind: 'owner_envelope_successor',
      consumer_iri: 'urn:usf:derivedconsumer:v2:owner-envelope-successor',
      predecessor_record_iri: 'urn:usf:ownerassignment:semanticmodelcompilation:matthewaldous',
      semantic_scope: Object.freeze({
        authority_domain: 'urn:usf:capabilityowner:semanticmodelcompilation',
        principal: 'urn:usf:authorityprincipal:matthewaldous',
        repository: 'maldous/usf-graph',
        signing_identity: 'urn:usf:authoritysigningidentity:semanticproofv1',
        source_paths: Object.freeze(['processes/semantic-assurance/semantic-proof-v2.mjs']),
        source_scope_digest: digest('1'),
      }),
      materialisation: Object.freeze([statement(
        'urn:usf:ownerassignment:semanticmodelcompilation:matthewaldous', 'owner',
      )]),
      validation_input_authority_digest: null,
      validation_input_identity_digests: Object.freeze([]),
    }),
    Object.freeze({
      consumer_kind: 'validation_currentness_binding',
      consumer_iri: 'urn:usf:derivedconsumer:v2:validation-currentness-binding',
      predecessor_record_iri: 'urn:usf:validationselfpublicationbinding:compilersemanticenforcementaggregate',
      semantic_scope: Object.freeze({
        authority_binding_rule: 'urn:usf:authoritybindingrule:validationnonpublicationdependencyclosure',
        validation_obligation: 'urn:usf:validationobligation:compilersemanticenforcement',
      }),
      materialisation: Object.freeze([statement(
        'urn:usf:validationselfpublicationbinding:compilersemanticenforcementaggregate', 'validation',
      )]),
      validation_input_authority_digest: digest('2'),
      validation_input_identity_digests: Object.freeze([digest('3'), digest('4')]),
    }),
  ]);
}

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
    graph_d1_candidate_digest: digest('9'),
    graph_d2_candidate_digest: digest('a'),
    graph_production_shadow_receipt_digest: digest('b'),
    external_attestation_set_root_digest: digest('c'),
    candidate_generator_implementation_digest: digest('d'),
    candidate_command_digest: digest('e'),
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

function graphWitness(character = 'a') {
  const inventory = Object.freeze([Object.freeze({
    graph: 'urn:test:graph',
    sha256: digest(character),
    triples: 1,
  })]);
  return Object.freeze({
    digest: semanticAuthorityInventoryDigest(inventory, 1),
    inventory,
    triples: 1,
  });
}

function graphShadowCandidateBindings({
  releaseSubjectDigest,
  externalAttestationSetRootDigest,
  candidateGeneratorImplementationDigest,
  candidateCommandDigest,
  predictedD1AuthorityDigest,
}) {
  return Object.freeze({
    releaseSubjectDigest,
    externalAttestationSetRootDigest,
    candidateGeneratorImplementationDigest,
    candidateCommandDigest,
    c2D1AuthorityDigest: predictedD1AuthorityDigest,
    c2D1DependencyIdentityDigests: Object.freeze([digest('1')]),
  });
}

test('Graph production shadow predicts exact D1/D2 while every publisher mutation is disabled', async () => {
  const d0 = graphWitness('a');
  const d1CandidateBytes = Buffer.from('d1');
  const d1CandidateIdentityBytes = Buffer.from('d1-identity');
  const d2CandidateBytes = Buffer.from('d2');
  const d2CandidateIdentityBytes = Buffer.from('d2-identity');
  const d1CandidateDigest = canonicalDigestV2('d1-candidate');
  const d2CandidateDigest = canonicalDigestV2('d2-candidate');
  const releaseSubjectDigest = digest('d');
  const externalAttestationSetRootDigest = digest('e');
  const candidateGeneratorImplementationDigest = digest('f');
  const candidateCommandDigest = digest('0');
  const command = {
    async previewPublicationSequence(input) {
      assert.equal(input.expectedD0AuthorityDigest, d0.digest);
      assert.equal(input.d1CandidateDigest, d1CandidateDigest);
      assert.equal(input.d2CandidateDigest, d2CandidateDigest);
      assert.equal(input.d1CandidateIdentityBytes, d1CandidateIdentityBytes);
      assert.equal(input.d2CandidateIdentityBytes, d2CandidateIdentityBytes);
      return {
        d0AuthorityDigest: d0.digest,
        d1: { authorityDigest: digest('b'), candidateDigest: d1CandidateDigest },
        d2: {
          authorityDigest: digest('c'),
          candidateDigest: d2CandidateDigest,
          evaluationInputAuthorityDigest: digest('b'),
        },
        candidateBindings: graphShadowCandidateBindings({
          releaseSubjectDigest,
          externalAttestationSetRootDigest,
          candidateGeneratorImplementationDigest,
          candidateCommandDigest,
          predictedD1AuthorityDigest: digest('b'),
        }),
        productionWriteOperations: 0,
        transactionBeginCount: 1,
        transactionRollbackCount: 1,
      };
    },
  };
  const adapter = createReadOnlyGraphProductionAdapterV2({
    command,
    readAuthorityWitness: async () => d0,
    readGraphOwnedConsumers: async () => graphOwnedConsumerInputs(),
  });
  const capture = () => captureGraphProductionShadowV2({
    adapter,
    expectedD0AuthorityDigest: d0.digest,
    d1CandidateBytes,
    d1CandidateDigest,
    d1CandidateIdentityBytes,
    d2CandidateBytes,
    d2CandidateDigest,
    d2CandidateIdentityBytes,
    releaseSubjectDigest,
    externalAttestationSetRootDigest,
    candidateGeneratorImplementationDigest,
    candidateCommandDigest,
    graphCommit: '1'.repeat(40),
    graphTree: '2'.repeat(40),
  });
  const first = await capture();
  const second = await capture();
  assert.equal(canonicalJsonV2(first), canonicalJsonV2(second));
  assert.deepEqual(
    canonicalGraphProductionShadowReceiptBytesV2(first),
    canonicalGraphProductionShadowReceiptBytesV2(second),
  );
  assert.equal(graphProductionShadowReceiptDigestV2(first), canonicalDigestV2(first));
  assert.throws(
    () => graphProductionShadowReceiptDigestV2({ ...first, unplanned_field: true }),
    /closed protocol shape/,
  );
  assert.deepEqual(first.authority_before, first.authority_after);
  assert.equal(first.predicted_d1_authority_digest, digest('b'));
  assert.equal(first.predicted_d2_authority_digest, digest('c'));
  assert.deepEqual(first.graph_owned_consumers.map((record) => record.consumer_kind),
    ['owner_envelope_successor', 'validation_currentness_binding']);
  assert.equal(first.production_stardog_write_operations, 0);
  assert.equal(first.production_cas_write_operations, 0);
  assert.equal(first.production_journal_write_operations, 0);
  assert.equal(first.authorization_issued, 0);
  assert.equal(first.publication_performed, 0);
  for (const [field, value] of [
    ['externalAttestationSetRootDigest', digest('1')],
    ['candidateGeneratorImplementationDigest', digest('2')],
    ['candidateCommandDigest', digest('3')],
  ]) {
    await assert.rejects(captureGraphProductionShadowV2({
      adapter,
      expectedD0AuthorityDigest: d0.digest,
      d1CandidateBytes,
      d1CandidateDigest,
      d1CandidateIdentityBytes,
      d2CandidateBytes,
      d2CandidateDigest,
      d2CandidateIdentityBytes,
      releaseSubjectDigest,
      externalAttestationSetRootDigest,
      candidateGeneratorImplementationDigest,
      candidateCommandDigest,
      [field]: value,
      graphCommit: '1'.repeat(40),
      graphTree: '2'.repeat(40),
    }), /prediction is not exact and read-only/);
  }
  for (const operation of [
    'reserveGrant', 'commitD1', 'observeD1', 'commitD2', 'persistTerminalReceipt', 'consumeGrant',
  ]) {
    await assert.rejects(adapter[operation](), /V2_GRAPH_PRODUCTION_WRITES_DISABLED/);
  }
});

test('Graph production shadow fails closed on authority drift and absent exact D2 bytes', async () => {
  const d0 = graphWitness('a');
  const drift = graphWitness('b');
  const d1CandidateBytes = Buffer.from('d1');
  const d1CandidateIdentityBytes = Buffer.from('d1-identity');
  const d2CandidateBytes = Buffer.from('d2');
  const d2CandidateIdentityBytes = Buffer.from('d2-identity');
  const d1CandidateDigest = canonicalDigestV2('d1-candidate');
  const d2CandidateDigest = canonicalDigestV2('d2-candidate');
  let reads = 0;
  const adapter = createReadOnlyGraphProductionAdapterV2({
    readAuthorityWitness: async () => reads++ === 0 ? d0 : drift,
    readGraphOwnedConsumers: async () => graphOwnedConsumerInputs(),
    command: {
      async previewPublicationSequence() {
        return {
          d0AuthorityDigest: d0.digest,
          d1: { authorityDigest: digest('c'), candidateDigest: d1CandidateDigest },
          d2: {
            authorityDigest: digest('d'), candidateDigest: d2CandidateDigest,
            evaluationInputAuthorityDigest: digest('c'),
          },
          candidateBindings: graphShadowCandidateBindings({
            releaseSubjectDigest: digest('d'),
            externalAttestationSetRootDigest: digest('e'),
            candidateGeneratorImplementationDigest: digest('f'),
            candidateCommandDigest: digest('0'),
            predictedD1AuthorityDigest: digest('c'),
          }),
          productionWriteOperations: 0,
          transactionBeginCount: 1,
          transactionRollbackCount: 1,
        };
      },
    },
  });
  const common = {
    adapter,
    expectedD0AuthorityDigest: d0.digest,
    d1CandidateBytes,
    d1CandidateDigest,
    d1CandidateIdentityBytes,
    d2CandidateBytes,
    d2CandidateDigest,
    d2CandidateIdentityBytes,
    releaseSubjectDigest: digest('d'),
    externalAttestationSetRootDigest: digest('e'),
    candidateGeneratorImplementationDigest: digest('f'),
    candidateCommandDigest: digest('0'),
    graphCommit: '1'.repeat(40),
    graphTree: '2'.repeat(40),
  };
  await assert.rejects(captureGraphProductionShadowV2(common), /changed during observation/);
  const stableAdapter = createReadOnlyGraphProductionAdapterV2({
    command: {
      async previewPublicationSequence() {
        throw new Error('exact candidates must be rejected before planning');
      },
    },
    readAuthorityWitness: async () => d0,
    readGraphOwnedConsumers: async () => graphOwnedConsumerInputs(),
  });
  await assert.rejects(captureGraphProductionShadowV2({
    ...common,
    adapter: stableAdapter,
    d2CandidateBytes: undefined,
  }), /EXACT_D1_D2_CANDIDATES_REQUIRED/);
});

test('Graph shadow receipt is an exact executable binding of the prospective plan', async () => {
  const base = fixture().plan;
  const d0 = graphWitness('f');
  const d1CandidateBytes = Buffer.from('bound-d1');
  const d1CandidateIdentityBytes = Buffer.from('bound-d1-identity');
  const d2CandidateBytes = Buffer.from('bound-d2');
  const d2CandidateIdentityBytes = Buffer.from('bound-d2-identity');
  const d1CandidateDigest = canonicalDigestV2('bound-d1-candidate');
  const d2CandidateDigest = canonicalDigestV2('bound-d2-candidate');
  const graphTree = base.graph_protected_tree;
  const adapter = createReadOnlyGraphProductionAdapterV2({
    readAuthorityWitness: async () => d0,
    readGraphOwnedConsumers: async () => graphOwnedConsumerInputs(),
    command: {
      async previewPublicationSequence() {
        return {
          d0AuthorityDigest: d0.digest,
          d1: {
            authorityDigest: base.predicted_d1_authority_digest,
            candidateDigest: d1CandidateDigest,
          },
          d2: {
            authorityDigest: base.predicted_d2_authority_digest,
            candidateDigest: d2CandidateDigest,
            evaluationInputAuthorityDigest: base.predicted_d1_authority_digest,
          },
          candidateBindings: graphShadowCandidateBindings({
            releaseSubjectDigest: base.release_subject_digest,
            externalAttestationSetRootDigest: base.external_attestation_set_root_digest,
            candidateGeneratorImplementationDigest:
              base.candidate_generator_implementation_digest,
            candidateCommandDigest: base.candidate_command_digest,
            predictedD1AuthorityDigest: base.predicted_d1_authority_digest,
          }),
          productionWriteOperations: 0,
          transactionBeginCount: 1,
          transactionRollbackCount: 1,
        };
      },
    },
  });
  const receipt = await captureGraphProductionShadowV2({
    adapter,
    expectedD0AuthorityDigest: d0.digest,
    d1CandidateBytes,
    d1CandidateDigest,
    d1CandidateIdentityBytes,
    d2CandidateBytes,
    d2CandidateDigest,
    d2CandidateIdentityBytes,
    releaseSubjectDigest: base.release_subject_digest,
    externalAttestationSetRootDigest: base.external_attestation_set_root_digest,
    candidateGeneratorImplementationDigest: base.candidate_generator_implementation_digest,
    candidateCommandDigest: base.candidate_command_digest,
    graphCommit: '1'.repeat(40),
    graphTree,
  });
  const plan = Object.freeze({
    ...base,
    d0_authority_digest: d0.digest,
    graph_d1_candidate_digest: d1CandidateDigest,
    graph_d2_candidate_digest: d2CandidateDigest,
    graph_production_shadow_receipt_digest: graphProductionShadowReceiptDigestV2(receipt),
  });
  assert.equal(assertGraphProductionShadowPlanBindingV2(receipt, plan), receipt);
  assert.throws(() => assertGraphProductionShadowPlanBindingV2({
    ...receipt, candidate_command_digest: digest('9'),
  }, plan), /prospective plan/);
});

test('Graph-owned consumers are canonically observed inside one immutable authority boundary', async () => {
  const d0 = graphWitness('a');
  const adapter = createReadOnlyGraphProductionAdapterV2({
    readAuthorityWitness: async () => d0,
    readGraphOwnedConsumers: async () => graphOwnedConsumerInputs(),
    command: { async previewPublicationSequence() { throw new Error('unused'); } },
  });
  const first = await captureGraphOwnedConsumerObservationV2({
    adapter, expectedAuthorityDigest: d0.digest,
  });
  const second = await captureGraphOwnedConsumerObservationV2({
    adapter, expectedAuthorityDigest: d0.digest,
  });
  assert.deepEqual(first, second);
  assert.deepEqual(canonicalGraphOwnedConsumerObservationBytesV2(first),
    canonicalGraphOwnedConsumerObservationBytesV2(second));
  assert.equal(graphOwnedConsumerObservationDigestV2(first), first.observation_digest);
  assert.equal(first.production_write_operations, 0);
  for (const record of first.consumers) {
    assert.equal(graphOwnedConsumerRecordDigestV2(record), canonicalDigestV2(record));
    assert.deepEqual(canonicalGraphOwnedConsumerRecordBytesV2(record),
      Buffer.from(canonicalJsonV2(record)));
    assert.equal(record.authority_digest, d0.digest);
  }
  assert.equal(first.consumers[1].validation_input_authority_digest, digest('2'));
  assert.deepEqual(first.consumers[1].validation_input_identity_digests,
    [digest('3'), digest('4')]);
});

test('Graph-owned consumer materialisation is canonical-byte ordered and duplicate-free', async () => {
  const d0 = graphWitness('a');
  const statement = (subject, value) => Object.freeze({
    subject,
    predicate: 'urn:usf:ontology:canonicalName',
    object: Object.freeze({ term_type: 'literal', value, datatype: null, language: null }),
  });
  const records = graphOwnedConsumerInputs();
  const later = statement('urn:usf:z', 'later');
  const earlier = statement('urn:usf:a', 'earlier');
  const observe = async (materialisation) => captureGraphOwnedConsumerObservationV2({
    adapter: createReadOnlyGraphProductionAdapterV2({
      readAuthorityWitness: async () => d0,
      readGraphOwnedConsumers: async () => records.map((record, index) => index === 0
        ? { ...record, materialisation } : record),
      command: { async previewPublicationSequence() { throw new Error('unused'); } },
    }),
    expectedAuthorityDigest: d0.digest,
  });
  const forward = await observe([later, earlier]);
  const reverse = await observe([earlier, later]);
  assert.deepEqual(forward, reverse);
  assert.deepEqual(forward.consumers[0].materialisation, [earlier, later]);
  await assert.rejects(observe([earlier, earlier]), /duplicate statements/);
});

test('Graph-owned consumer observation fails closed on drift, cardinality, schema and stale D0 input', async () => {
  const d0 = graphWitness('a');
  const drift = graphWitness('b');
  let reads = 0;
  const drifting = createReadOnlyGraphProductionAdapterV2({
    readAuthorityWitness: async () => reads++ === 0 ? d0 : drift,
    readGraphOwnedConsumers: async () => graphOwnedConsumerInputs(),
    command: { async previewPublicationSequence() { throw new Error('unused'); } },
  });
  await assert.rejects(captureGraphOwnedConsumerObservationV2({
    adapter: drifting, expectedAuthorityDigest: d0.digest,
  }), /changed during observation/);
  for (const mutate of [
    (records) => records.slice(0, 1),
    (records) => records.map((record, index) => index === 0
      ? { ...record, consumer_kind: 'unknown_consumer' } : record),
    (records) => records.map((record, index) => index === 1
      ? { ...record, validation_input_authority_digest: 'stale' } : record),
  ]) {
    const adapter = createReadOnlyGraphProductionAdapterV2({
      readAuthorityWitness: async () => d0,
      readGraphOwnedConsumers: async () => mutate(graphOwnedConsumerInputs()),
      command: { async previewPublicationSequence() { throw new Error('unused'); } },
    });
    await assert.rejects(captureGraphOwnedConsumerObservationV2({
      adapter, expectedAuthorityDigest: d0.digest,
    }), /Graph-owned consumer|validation D0 input/);
  }
});

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

  const unknownTopLevel = { ...plan, publication_timestamp: '2026-08-10T07:00:00Z' };
  assert.throws(() => prospectivePublicationPlanDigestV2(unknownTopLevel),
    /prospective publication plan fields are not the closed protocol shape/);
  const unknownConsumer = {
    ...plan,
    derived_consumers: plan.derived_consumers.map((item, index) => index === 0
      ? { ...item, observation_timestamp: '2026-08-10T07:00:00Z' }
      : item),
  };
  assert.throws(() => prospectivePublicationPlanDigestV2(unknownConsumer),
    /planned derived consumer fields are not the closed protocol shape/);
  const unknownSuccessor = {
    ...plan,
    derived_consumers: plan.derived_consumers.map((item, index) => index === 0
      ? {
        ...item,
        expected_successor: {
          ...item.expected_successor,
          projection_observed_at: '2026-08-10T07:00:00Z',
        },
      }
      : item),
  };
  assert.throws(() => prospectivePublicationPlanDigestV2(unknownSuccessor),
    /derived consumer successor fields are not the closed protocol shape/);
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
