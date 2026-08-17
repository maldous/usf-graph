// Canonical native V2 handover fixture builder.
//
// Extracted from semantic-proof-v2.test.mjs so the Graph production-adapter
// test and the semantic-proof tests consume ONE builder. A divergent copy is
// exactly how the C1/C2 adapter test went stale and ended up skipped: the
// closed schemas moved and only one copy was updated.
//
// This is a fixture builder, not production code. It is a non-test module so
// importing it does not re-run another file's test suite.

import {
  canonicalDigestV2,
  canonicalJsonV2,
  DERIVED_CONSUMER_REGISTRY_V2_DIGEST,
  factoryPrepareReceiptDigestV2,
  graphReservationReceiptDigestV2,
  IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST,
  nativeHandoverGenerationDigestV2,
  nativeReadbackSetDigestV2,
  prospectivePublicationPlanDigestV2,
  closureTransactionIdV2,
  graphOwnedNativeObservationDigestV2,
} from './semantic-proof-v2.mjs';

const digest = (character) => `sha256:${character.repeat(64)}`;

const PREPARED = new WeakMap();

// The prepared receipts are keyed by plan identity. Exported so consumers read
// the SAME map the builder populates -- two WeakMaps would silently miss.
export function preparedReceipts(plan) {
  const prepared = PREPARED.get(plan);
  if (!prepared) throw new Error('native handover fixture plan was not prepared');
  return prepared;
}

export const KINDS = Object.freeze([
  'contract_projection',
  'execution_scope_projection',
  'factory_graph_witness_binding',
  'owner_envelope_successor',
  'run_authorization',
  'validation_currentness_binding',
  'workforce_policy_compatibility_binding',
]);

export function fixture({
  d0Override = null,
  graphD1CandidateDigest = null,
  graphD2CandidateDigest = null,
} = {}) {
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
    graph_d1_candidate_digest: graphD1CandidateDigest || digest('9'),
    graph_d2_candidate_digest: graphD2CandidateDigest || digest('a'),
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
  return { closure, consumers, d0, d1, d2, dependencies, factoryPrepareReceipt, generation,
    graphReservationReceipt, plan, readbacks };
}
