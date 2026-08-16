import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  advanceDurableSemanticProofV2Publication,
  advanceSemanticProofV2Publication,
  assertValidationCurrentnessDescendantV2,
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
  factoryPrepareReceiptDigestV2,
  graphOwnedNativeObservationDigestV2,
  graphOwnedConsumerObservationDigestV2,
  graphOwnedConsumerRecordDigestV2,
  graphPublicationReceiptDigestV2,
  graphReservationReceiptDigestV2,
  graphProductionShadowReceiptDigestV2,
  HermeticSemanticProofV2Journal,
  IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST,
  nativeHandoverGenerationDigestV2,
  nativeReadbackSetDigestV2,
  nativeSuccessorReadbackDigestV2,
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
const PREPARED = new WeakMap();

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

function fixture({ d0Override = null } = {}) {
  const releaseSubject = digest('1');
  const d0 = d0Override || digest('2');
  const d1 = digest('3');
  const d2 = digest('4');
  const dependencies = Object.freeze([digest('5'), digest('6')]);
  const predecessorCharacters = ['8', '7', '6', '5', '4', '3', '2'];
  const currentMaterialisationCharacters = ['0', '1', '2', '3', '4', '5', '6'];
  const graphCommit = 'd'.repeat(40);
  const factoryCommit = 'c'.repeat(40);
  const planCore = {
    d0_authority_digest: d0,
    derived_consumer_registry_digest: DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
    external_attestation_set_root_digest: digest('c'),
    factory_deployment_commit: factoryCommit,
    factory_deployment_tree: 'a'.repeat(40),
    graph_protected_commit: graphCommit,
    graph_protected_tree: 'b'.repeat(40),
    release_subject_digest: releaseSubject,
  };
  const generation = nativeHandoverGenerationDigestV2(planCore);
  const factoryNativeState = (kind) => {
    if (kind === 'run_authorization') return Object.freeze({
      schema_version: 2,
      permitted_actions: Object.freeze([]),
      validation_lifecycle_scope: Object.freeze({ trusted_time_authority_digest: d2 }),
    });
    if (kind === 'execution_scope_projection') return Object.freeze({
      schema: 'usf-execution-scope-projection-v2', authority_digest: d2,
      contract_execution_scope_iri: 'urn:test:execution-scope',
      contract_execution_scope_digest: digest('a'),
      contract_execution_scope_projection_ref: `cas://sha256/${'b'.repeat(64)}`,
      contract_execution_scope_projection_digest: digest('b'),
      validation_lifecycle_scope: Object.freeze({ trusted_time_authority_digest: d2 }),
    });
    if (kind === 'contract_projection') return Object.freeze({
      schema: 'usf-contract-projection-v2', authority_digest: d2,
      snapshot_contract_iri: 'urn:test:contract', semantic_contract_root_digest: digest('c'),
      contract_projection_ref: `cas://sha256/${'d'.repeat(64)}`,
      contract_projection_digest: digest('d'),
    });
    if (kind === 'factory_graph_witness_binding') return Object.freeze({
      schema: 'usf-factory-graph-witness-binding-v2', authority_digest: d2,
      repository_id: 'maldous/usf-factory', repository_head: factoryCommit,
      repository_tree: planCore.factory_deployment_tree, source_manifest_digest: digest('e'),
      registry_digest: DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
      materialisation_contract_identity: digest('f'), programme_state_digest: digest('0'),
      environment_id: 'production', service_name: 'usf-factory',
    });
    const policy = (name) => Object.freeze({ schema: `usf-${name}-policy-v2`, mode: 'CURRENT_ONLY' });
    const workforce = policy('workforce');
    const roster = policy('roster');
    const provider = policy('provider');
    const market = policy('model-market');
    const catalogue = policy('catalogue');
    return Object.freeze({
      schema: 'usf-workforce-policy-compatibility-binding-v2', authority_digest: d2,
      workforce_policy: workforce, workforce_policy_digest: canonicalDigestV2(workforce),
      qualification_policy_digest: digest('1'), admission_policy_digest: digest('2'),
      roster_policy: roster, roster_policy_digest: canonicalDigestV2(roster),
      provider_policy: provider, provider_policy_digest: canonicalDigestV2(provider),
      model_market_policy: market, model_market_policy_digest: canonicalDigestV2(market),
      catalogue_policy: catalogue, catalogue_policy_digest: canonicalDigestV2(catalogue),
    });
  };
  const graphNativeState = (kind, semanticScope, semanticScopeDigest) => kind === 'owner_envelope_successor'
    ? Object.freeze({
      schema: 'usf-owner-envelope-successor-v2', authority_digest: d2,
      handover_generation_digest: generation,
      predecessor_owner_assignment_iri:
        'urn:usf:ownerassignment:semanticmodelcompilation:matthewaldous',
      semantic_scope: semanticScope, semantic_scope_digest: semanticScopeDigest,
      owner_identity_digest: digest('a'), owner_envelope_digest: digest('b'),
      owner_signing_fingerprint: 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D',
      predecessor_lineage_digest: digest('c'),
    })
    : Object.freeze({
      schema: 'usf-validation-currentness-root-v2', authority_digest: d2,
      handover_generation_digest: generation,
      predecessor_validation_binding_iri:
        'urn:usf:validationselfpublicationbinding:compilersemanticenforcementaggregate',
      semantic_scope: semanticScope, semantic_scope_digest: semanticScopeDigest,
      predecessor_validation_input_authority_digest: d1,
      predecessor_validation_input_identity_digests: dependencies,
      handover_currentness: Object.freeze({
        schema: 'usf-v2-native-validation-currentness-genesis-v1',
        validation_input_authority_digest: d1,
        validation_input_identity_digests: dependencies,
        evidence_set_digest: digest('3'), proof_result_digest: digest('4'),
        admission_receipt_digest: digest('5'), owner_identity_digest: digest('a'),
        proof_state: 'SUCCESSFUL', evaluated_at: '2026-01-01T00:00:00Z',
        admitted_at: '2026-01-01T00:00:00Z',
        valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z',
      }),
      renewal_rule: Object.freeze({
        schema: 'usf-validation-currentness-renewal-rule-v2',
        allowed_transition: 'MATERIALISATION_CURRENTNESS',
        descendant_schema: 'usf-v2-native-validation-currentness-descendant-v1',
        evidence_admission_producer_identity_digest: digest('6'),
        proof_algorithm_digest: digest('7'),
        evidence_admission_path_iri: semanticScope.evidence_admission_path,
        external_verifier_iri: semanticScope.external_verifier,
        validation_envelope_verification_iri: semanticScope.envelope_verification,
        validation_producer_iri: semanticScope.producer,
        verification_cas_descriptor_iri: semanticScope.verification_cas_descriptor,
        requires_exact_predecessor: true, requires_single_head: true,
        requires_trusted_now: true,
      }),
    });
  const consumers = KINDS.map((kind, index) => {
    const predecessor = digest(predecessorCharacters[index]);
    const storageOwner = ['owner_envelope_successor', 'validation_currentness_binding']
      .includes(kind) ? 'GRAPH' : 'FACTORY';
    const semanticScopeValue = kind === 'validation_currentness_binding'
      ? Object.freeze({
        authority_binding_rule: 'urn:usf:authoritybindingrule:test',
        evidence_admission_path: 'urn:usf:evidenceadmissionpath:test',
        envelope_verification: 'urn:usf:semanticproofverification:test',
        external_verifier: 'urn:usf:semanticproofverifier:semanticproofv1',
        producer: 'urn:usf:validationproducer:test',
        repository: 'maldous/usf-graph',
        requires_postpublication_reevaluation: true,
        source_paths: ['processes/semantic-assurance/semantic-proof-v2.mjs'],
        source_scope_digest: digest('6'),
        validation_obligation: 'urn:usf:validationobligation:test',
        verification_cas_descriptor: 'urn:usf:semanticproofcasdescriptor:test',
      })
      : Object.freeze({ capability: `urn:test:${kind}` });
    const semanticScopePreimage = storageOwner === 'GRAPH' ? Object.freeze({
      schema: 'usf-graph-owned-consumer-semantic-scope-v2',
      consumer_kind: kind,
      semantic_scope: semanticScopeValue,
    }) : Object.freeze({ schema: 'usf-factory-consumer-semantic-scope-v2', consumer_kind: kind });
    const semanticScope = canonicalDigestV2(semanticScopePreimage);
    const nativeState = storageOwner === 'GRAPH'
      ? graphNativeState(kind, semanticScopeValue, semanticScope)
      : factoryNativeState(kind);
    const materialisation = canonicalDigestV2(nativeState);
    const payloadPreimage = Object.freeze({
      schema: 'usf-v2-native-successor-payload-v1',
      handover_generation_digest: generation,
      consumer_kind: kind,
      consumer_iri: `urn:usf:derivedconsumer:v2:${kind.replaceAll('_', '-')}`,
      storage_owner: storageOwner,
      authority_digest: d2,
      predecessor_identity_digest: predecessor,
      semantic_scope_digest: semanticScope,
      materialisation_digest: materialisation,
      native_state: nativeState,
    });
    const payloadBytes = Buffer.from(canonicalJsonV2(payloadPreimage));
    const payloadDigest = canonicalDigestV2(payloadPreimage);
    const successor = {
      authority_digest: d2,
      consumer_iri: `urn:usf:derivedconsumer:v2:${kind.replaceAll('_', '-')}`,
      consumer_kind: kind,
      consumer_schema_version: 2,
      current_policy_compatibility_digest: kind === 'workforce_policy_compatibility_binding'
        ? digest('e') : null,
      historical_policy_identity_digest: kind === 'workforce_policy_compatibility_binding'
        ? digest('f') : null,
      handover_generation_digest: generation,
      materialisation_digest: materialisation,
      materialisation_preimage: nativeState,
      predecessor_identity_digest: predecessor,
      payload_cas_uri: `cas://sha256/${payloadDigest.slice(7)}`,
      payload_digest: payloadDigest,
      payload_preimage: payloadPreimage,
      payload_schema: 'usf-v2-native-successor-payload-v1',
      payload_size: payloadBytes.length,
      producer_iri: `urn:usf:producer:${kind.replaceAll('_', '-')}:v2`,
      record_iri: `urn:usf:derivedconsumersuccessor:v2:${kind}:${index}`,
      registry_digest: DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
      release_subject_digest: releaseSubject,
      repository_category: kind === 'factory_graph_witness_binding'
        ? 'maldous/usf-factory' : null,
      schema: 'usf-derived-consumer-successor-v2',
      semantic_scope_digest: semanticScope,
      semantic_scope_preimage: semanticScopePreimage,
      storage_owner: storageOwner,
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
      predecessor_record_digest: digest(currentMaterialisationCharacters[index]),
      predicted_d1_authority_digest: d1,
      predicted_d2_authority_digest: d2,
      prospective_materialisation_digest: materialisation,
      prospective_semantic_scope_digest: semanticScope,
    });
  });
  const requiredCas = consumers.flatMap((item) => [
    item.expected_successor_digest, item.expected_successor.payload_digest,
  ]).sort();
  const plan = Object.freeze({
    d0_authority_digest: d0,
    d1_dependency_identity_digests: dependencies,
    d2_evaluation_input_authority_digest: d1,
    derived_consumer_registry_digest: DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
    derived_consumers: Object.freeze(consumers),
    factory_deployment_tree: 'a'.repeat(40),
    factory_deployment_commit: factoryCommit,
    graph_d1_candidate_digest: digest('9'),
    graph_d2_candidate_digest: digest('a'),
    graph_production_shadow_receipt_digest: digest('b'),
    external_attestation_set_root_digest: digest('c'),
    candidate_generator_implementation_digest: digest('d'),
    candidate_command_digest: digest('e'),
    graph_protected_tree: 'b'.repeat(40),
    graph_protected_commit: graphCommit,
    handover_generation_digest: generation,
    identity_dependency_graph_digest: IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST,
    outcome: 'PROCEED',
    predicted_d1_authority_digest: d1,
    predicted_d2_authority_digest: d2,
    release_subject_digest: releaseSubject,
    required_cas_object_digests: Object.freeze(requiredCas),
    schema: 'usf-prospective-publication-plan-v2',
  });
  const current = consumers.map((item) => item.expected_successor_digest).sort();
  const reader = Object.freeze({
    contract_projection: 'urn:usf:productionreader:factory:contract-projection:v2',
    execution_scope_projection:
      'urn:usf:productionreader:factory:execution-scope-projection:v2',
    factory_graph_witness_binding:
      'urn:usf:productionreader:factory:repository-witness:v2',
    owner_envelope_successor: 'urn:usf:productionreader:graph:owner-envelope-successor:v2',
    run_authorization: 'urn:usf:productionreader:factory:run-authorization:v2',
    validation_currentness_binding:
      'urn:usf:productionreader:graph:validation-currentness-binding:v2',
    workforce_policy_compatibility_binding:
      'urn:usf:productionreader:factory:workforce-policy:v2',
  });
  const readbacks = Object.freeze(consumers.map((item) => {
    const successor = item.expected_successor;
    const core = Object.freeze({
      schema: 'usf-v2-native-successor-readback-v1', consumer_kind: item.consumer_kind,
      successor_record_digest: item.expected_successor_digest,
      handover_generation_digest: generation, storage_owner: successor.storage_owner,
      production_reader: reader[item.consumer_kind],
      native_payload_digest: successor.payload_digest,
      native_payload_cas_uri: successor.payload_cas_uri,
      native_payload_size: successor.payload_size, observation_state: 'EXACT',
    });
    return Object.freeze({ ...core, observation_digest: canonicalDigestV2(core) });
  }));
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
    handover_generation_digest: generation,
    native_successor_readbacks: readbacks,
    native_readback_set_digest: nativeReadbackSetDigestV2(generation, readbacks),
    graph_owned_observation_digest: graphOwnedNativeObservationDigestV2(generation, readbacks),
    terminal_result: 'NATIVE_STATE_REREAD_EXACT',
  });
  const graphReservationReceipt = Object.freeze({
    schema: 'usf-graph-grant-reservation-receipt-v2', protocol: 'semantic-proof-v2',
    release_subject_digest: releaseSubject,
    prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(plan),
    explicit_authorization_grant_digests: Object.freeze([]), d0_authority_digest: d0,
    graph_commit: graphCommit, graph_tree: plan.graph_protected_tree,
    handover_generation_digest: generation,
    lane_reservation_digest: canonicalDigestV2({
      schema: 'usf-v2-native-handover-reservation-v1', d0_authority_digest: d0,
      handover_generation_digest: generation,
      prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(plan),
    }),
    lane_reservation_schema: 'usf-v2-native-handover-reservation-v1',
    reservation_state: 'V2_HANDOVER_RESERVED',
  });
  const graphReservationReceiptDigest = graphReservationReceiptDigestV2(
    graphReservationReceipt, plan, { graphCommit, graphTree: plan.graph_protected_tree },
  );
  const generationRecordDigest = digest('7');
  const factoryPrepareReceipt = Object.freeze({
    schema: 'usf-v2-native-handover-prepare-receipt-v1',
    handover_generation_digest: generation,
    prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(plan),
    d0_authority_digest: d0, factory_commit: factoryCommit,
    factory_tree: plan.factory_deployment_tree,
    generation_record_digest: generationRecordDigest,
    generation_record_cas_uri: `cas://sha256/${generationRecordDigest.slice(7)}`,
    graph_reservation_receipt_digest: graphReservationReceiptDigest,
    successor_record_digests: Object.freeze(consumers.map(
      (item) => item.expected_successor_digest,
    ).sort()),
    native_payload_digests: Object.freeze(consumers.map(
      (item) => item.expected_successor.payload_digest,
    ).sort()),
    cas_closure_digests: Object.freeze([
      prospectivePublicationPlanDigestV2(plan), generationRecordDigest,
      graphReservationReceiptDigest, ...requiredCas,
    ].sort()),
    coordinator_fence_name: 'v2-native-handover', coordinator_fencing_token: 1,
    prepare_state: 'DURABLE_PENDING',
  });
  factoryPrepareReceiptDigestV2(factoryPrepareReceipt, plan, {
    factoryCommit, factoryTree: plan.factory_deployment_tree,
  });
  PREPARED.set(plan, Object.freeze({ factoryPrepareReceipt, graphReservationReceipt }));
  return { closure, factoryPrepareReceipt, graphReservationReceipt, plan };
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
      const receipt = PREPARED.get(plan).graphReservationReceipt;
      return {
        digest: graphReservationReceiptDigestV2(receipt, plan, {
          graphCommit: 'd'.repeat(40), graphTree: plan.graph_protected_tree,
        }),
        receipt,
      };
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
      assert.equal(factoryClosureReceiptDigestV2(receipt, plan),
        factoryClosureReceiptDigestV2(receipt, plan));
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
    async verifyTerminalOwnership(receipt) {
      return {
        authority_digest: plan.predicted_d2_authority_digest,
        handover_generation_digest: plan.handover_generation_digest,
        ownership_state: 'V2_TERMINAL_OWNER',
        terminal_receipt_digest: graphPublicationReceiptDigestV2(receipt),
      };
    },
  });
}

function inputs(plan, journal, graphAdapter, closure) {
  const prepared = PREPARED.get(plan);
  return {
    plan,
    journal,
    graph_adapter: graphAdapter,
    factory_closure_receipt: closure,
    factory_prepare_receipt: prepared?.factoryPrepareReceipt,
    graph_reservation_receipt: prepared?.graphReservationReceipt,
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
  const d0 = graphWitness('f');
  const base = fixture({ d0Override: d0.digest }).plan;
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
    graphCommit: base.graph_protected_commit,
    graphTree,
  });
  const plan = Object.freeze({
    ...base,
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
  assert.equal(result.receipt.publication_outcome, 'ACCEPTED');
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

test('V2 validation currentness descendants are exact, admitted, linear and time-current', () => {
  const values = fixture();
  const validation = values.plan.derived_consumers.find(
    (item) => item.consumer_kind === 'validation_currentness_binding',
  ).expected_successor;
  const owner = values.plan.derived_consumers.find(
    (item) => item.consumer_kind === 'owner_envelope_successor',
  ).expected_successor.payload_preimage.native_state;
  const evidence = Object.freeze([digest('e')]);
  const claimPayload = Object.freeze({
    schema: 'usf-v2-native-validation-currentness-descendant-v1',
    authority_digest: values.plan.predicted_d2_authority_digest,
    handover_generation_digest: values.plan.handover_generation_digest,
    validation_root_payload_digest: validation.payload_digest,
    predecessor_descendant_digest: validation.payload_digest,
    semantic_scope_digest: validation.semantic_scope_digest,
    transition: 'MATERIALISATION_CURRENTNESS',
    evidence_identity_digests: evidence,
    evidence_set_digest: canonicalDigestV2({
      schema: 'usf-v2-native-validation-currentness-evidence-set-v1',
      evidence_identity_digests: evidence,
    }),
    proof_result_digest: digest('f'),
    proof_state: 'SUCCESSFUL', proof_evaluated_at: '2026-06-01T00:00:00Z',
    validation_candidate_digest: digest('d'),
    valid_from: '2026-06-01T00:00:00Z', valid_until: '2026-07-01T00:00:00Z',
    trusted_time_authority_digest: values.plan.predicted_d2_authority_digest,
    renewal_nonce: '00000000-0000-4000-8000-000000000001',
  });
  const currentnessClaimDigest = canonicalDigestV2({
    schema: 'usf-v2-native-validation-currentness-claim-v1', payload: claimPayload,
  });
  const admission = Object.freeze({
    schema: 'usf-v2-native-validation-currentness-admission-v1',
    admission_state: 'ADMITTED', admitted_at: '2026-06-01T00:00:01Z',
    authority_digest: values.plan.predicted_d2_authority_digest,
    currentness_claim_digest: currentnessClaimDigest,
    evidence_set_digest: claimPayload.evidence_set_digest,
    handover_generation_digest: values.plan.handover_generation_digest,
    owner_identity_digest: owner.owner_identity_digest,
    proof_result_digest: claimPayload.proof_result_digest,
  });
  const envelope = Object.freeze({
    schema: 'usf-v2-native-validation-currentness-descendant-envelope-v1',
    payload: Object.freeze({
      ...claimPayload, admission_receipt_digest: canonicalDigestV2(admission),
    }),
    admission_receipt: admission,
    signature: 'signed-validation-currentness-envelope'.repeat(2),
  });
  const options = {
    authorityDigest: values.plan.predicted_d2_authority_digest,
    handoverGenerationDigest: values.plan.handover_generation_digest,
    ownerIdentityDigest: owner.owner_identity_digest,
    predecessorDigest: validation.payload_digest,
    semanticScopeDigest: validation.semantic_scope_digest,
    validationRootPayloadDigest: validation.payload_digest,
    trustedNow: '2026-06-15T00:00:00Z',
    verifySignature: () => true,
  };
  const verified = assertValidationCurrentnessDescendantV2(envelope, options);
  assert.equal(verified.digest, canonicalDigestV2(envelope));
  assert.throws(() => assertValidationCurrentnessDescendantV2({
    ...envelope, payload: { ...envelope.payload, admission_receipt_digest: digest('1') },
  }, options), /exact admission/);
  assert.throws(() => assertValidationCurrentnessDescendantV2(envelope, {
    ...options, predecessorDigest: digest('2'),
  }), /binding is not exact/);
  assert.throws(() => assertValidationCurrentnessDescendantV2(envelope, {
    ...options, trustedNow: '2026-07-01T00:00:00Z',
  }), /STALE/);
  assert.throws(() => assertValidationCurrentnessDescendantV2(envelope, {
    ...options, verifySignature: () => false,
  }), /signature is invalid/);
});
