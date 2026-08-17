import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute } from 'node:path';

import { REAL_JOURNAL_IO } from './semantic-proof-v1.mjs';
import { semanticAuthorityInventoryDigest } from './semantic-authority-gateway.mjs';

export const SEMANTIC_PROOF_V2 = 'semantic-proof-v2';
export const PROSPECTIVE_PUBLICATION_PLAN_V2 = 'usf-prospective-publication-plan-v2';
export const DERIVED_CLOSURE_RECEIPT_V2 = 'usf-derived-consumer-closure-receipt-v2';
export const GRAPH_PUBLICATION_RECEIPT_V2 = 'usf-semantic-publication-receipt-v2';
export const GRAPH_PUBLICATION_JOURNAL_V2 = 'usf-semantic-publication-journal-v2';
export const GRAPH_PRODUCTION_SHADOW_RECEIPT_V2 =
  'usf-graph-production-shadow-receipt-v2';
export const GRAPH_OWNED_CONSUMER_RECORD_V2 =
  'usf-graph-owned-derived-consumer-record-v2';
export const GRAPH_OWNED_CONSUMER_OBSERVATION_V2 =
  'usf-graph-owned-derived-consumer-observation-v2';
export const DERIVED_CONSUMER_REGISTRY_V2_DIGEST =
  'sha256:de62d7097cd1b2a6eb5954bd0859eb4759188bf37d0175b288e5d0b8225d4231';
export const IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST =
  'sha256:cb244fb857bb87abf183f195a131d8550f6b1187b10153c08a6a05c7d2d77fdd';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_IDENTITY = /^[0-9a-f]{40}$/;
const UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const REQUIRED_CONSUMER_KINDS = Object.freeze([
  'contract_projection',
  'execution_scope_projection',
  'factory_graph_witness_binding',
  'owner_envelope_successor',
  'run_authorization',
  'validation_currentness_binding',
  'workforce_policy_compatibility_binding',
]);
const GRAPH_OWNED_CONSUMER_KINDS = Object.freeze([
  'owner_envelope_successor',
  'validation_currentness_binding',
]);
const NATIVE_SUCCESSOR_STORAGE_OWNER = Object.freeze(Object.fromEntries(
  REQUIRED_CONSUMER_KINDS.map((kind) => [
    kind, GRAPH_OWNED_CONSUMER_KINDS.includes(kind) ? 'GRAPH' : 'FACTORY',
  ]),
));
const NATIVE_SUCCESSOR_PRODUCTION_READERS = Object.freeze({
  contract_projection: 'urn:usf:productionreader:factory:contract-projection:v2',
  execution_scope_projection: 'urn:usf:productionreader:factory:execution-scope-projection:v2',
  factory_graph_witness_binding: 'urn:usf:productionreader:factory:repository-witness:v2',
  owner_envelope_successor: 'urn:usf:productionreader:graph:owner-envelope-successor:v2',
  run_authorization: 'urn:usf:productionreader:factory:run-authorization:v2',
  validation_currentness_binding: 'urn:usf:productionreader:graph:validation-currentness-binding:v2',
  workforce_policy_compatibility_binding: 'urn:usf:productionreader:factory:workforce-policy:v2',
});
const SUCCESSOR_DECISIONS = new Set([
  'COMPATIBLE_SUCCESSOR',
  'EXPLICITLY_AUTHORIZED_SUCCESSOR',
]);
const GRAPH_PRODUCTION_SHADOW_FIELDS = Object.freeze([
  'authorization_issued',
  'authority_after',
  'authority_before',
  'boundary_observation_digest',
  'd0_authority_digest',
  'd1_candidate_digest',
  'd2_candidate_digest',
  'd2_evaluation_input_authority_digest',
  'external_attestation_set_root_digest',
  'candidate_command_digest',
  'candidate_generator_implementation_digest',
  'graph_commit',
  'graph_owned_consumers',
  'graph_tree',
  'predicted_d1_authority_digest',
  'predicted_d2_authority_digest',
  'production_cas_write_operations',
  'production_journal_write_operations',
  'production_stardog_write_operations',
  'protocol',
  'publication_performed',
  'release_subject_digest',
  'schema',
].sort());
const GRAPH_OWNED_CONSUMER_RECORD_FIELDS = Object.freeze([
  'authority_digest',
  'consumer_iri',
  'consumer_kind',
  'materialisation',
  'materialisation_digest',
  'predecessor_record_iri',
  'schema',
  'semantic_scope',
  'semantic_scope_digest',
  'validation_input_authority_digest',
  'validation_input_identity_digests',
].sort());
const GRAPH_OWNED_CONSUMER_OBSERVATION_FIELDS = Object.freeze([
  'authority_after',
  'authority_before',
  'consumers',
  'observation_digest',
  'production_write_operations',
  'protocol',
  'schema',
].sort());
const PROSPECTIVE_PUBLICATION_PLAN_FIELDS = Object.freeze([
  'candidate_command_digest',
  'candidate_generator_implementation_digest',
  'd0_authority_digest',
  'd1_dependency_identity_digests',
  'd2_evaluation_input_authority_digest',
  'derived_consumer_registry_digest',
  'derived_consumers',
  'external_attestation_set_root_digest',
  'factory_deployment_commit',
  'factory_deployment_tree',
  'graph_d1_candidate_digest',
  'graph_d2_candidate_digest',
  'graph_production_shadow_receipt_digest',
  'graph_protected_commit',
  'graph_protected_tree',
  'handover_generation_digest',
  'identity_dependency_graph_digest',
  'outcome',
  'predicted_d1_authority_digest',
  'predicted_d2_authority_digest',
  'release_subject_digest',
  'required_cas_object_digests',
  'schema',
].sort());
const PLANNED_DERIVED_CONSUMER_FIELDS = Object.freeze([
  'block_reason',
  'consumer_iri',
  'consumer_kind',
  'current_materialisation_digest',
  'current_semantic_scope_digest',
  'decision',
  'expected_successor',
  'expected_successor_digest',
  'mandatory',
  'predecessor_identity_digest',
  'predecessor_record_digest',
  'predicted_d1_authority_digest',
  'predicted_d2_authority_digest',
  'prospective_materialisation_digest',
  'prospective_semantic_scope_digest',
].sort());
const DERIVED_CONSUMER_SUCCESSOR_FIELDS = Object.freeze([
  'authority_digest',
  'consumer_iri',
  'consumer_kind',
  'consumer_schema_version',
  'current_policy_compatibility_digest',
  'historical_policy_identity_digest',
  'handover_generation_digest',
  'materialisation_digest',
  'materialisation_preimage',
  'predecessor_identity_digest',
  'producer_iri',
  'payload_cas_uri',
  'payload_digest',
  'payload_preimage',
  'payload_schema',
  'payload_size',
  'record_iri',
  'registry_digest',
  'release_subject_digest',
  'repository_category',
  'schema',
  'semantic_scope_digest',
  'semantic_scope_preimage',
  'storage_owner',
  'transition_cause',
  'validation_input_authority_digest',
  'validation_input_identity_digests',
  'verification_algorithm_iri',
  'verification_algorithm_version',
].sort());
const NATIVE_SUCCESSOR_READBACK_FIELDS = Object.freeze([
  'consumer_kind',
  'handover_generation_digest',
  'native_payload_cas_uri',
  'native_payload_digest',
  'native_payload_size',
  'observation_digest',
  'observation_state',
  'production_reader',
  'schema',
  'storage_owner',
  'successor_record_digest',
].sort());
const FACTORY_PREPARE_RECEIPT_FIELDS = Object.freeze([
  'cas_closure_digests', 'coordinator_fence_name', 'coordinator_fencing_token',
  'd0_authority_digest', 'factory_commit', 'factory_tree', 'generation_record_cas_uri',
  'generation_record_digest', 'graph_reservation_receipt_digest',
  'handover_generation_digest', 'native_payload_digests',
  'prepare_state', 'prospective_publication_plan_digest', 'schema',
  'successor_record_digests',
].sort());
const GRAPH_RESERVATION_RECEIPT_FIELDS = Object.freeze([
  'd0_authority_digest', 'explicit_authorization_grant_digests', 'graph_commit',
  'graph_tree', 'handover_generation_digest', 'lane_reservation_digest',
  'lane_reservation_schema', 'prospective_publication_plan_digest', 'protocol',
  'release_subject_digest', 'reservation_state', 'schema',
].sort());
const FACTORY_CLOSURE_RECEIPT_FIELDS = Object.freeze([
  'd1_authority_digest',
  'd2_authority_digest',
  'derived_consumer_registry_digest',
  'explicit_authorization_grant_digests',
  'graph_d1_commit_receipt_digest',
  'graph_d1_observation_receipt_digest',
  'graph_d2_commit_receipt_digest',
  'graph_owned_observation_digest',
  'handover_generation_digest',
  'mandatory_consumer_identity_digests',
  'native_readback_set_digest',
  'native_successor_readbacks',
  'prospective_publication_plan_digest',
  'release_subject_digest',
  'schema',
  'successor_identity_digests',
  'terminal_result',
  'transaction_id',
].sort());
const GRAPH_TERMINAL_RECEIPT_FIELDS = Object.freeze([
  'accepted_at',
  'coordination_identity_digest',
  'current_v1_publication_state',
  'd0_authority_digest',
  'd1_authority_digest',
  'd2_authority_digest',
  'derived_consumer_registry_digest',
  'explicit_authorization_grant_digests',
  'factory_closure_receipt_digest',
  'factory_prepare_receipt_digest',
  'factory_commit',
  'factory_tree',
  'graph_commit',
  'graph_owned_observation_digest',
  'graph_tree',
  'grant_consumption_receipt_digest',
  'handover_generation_digest',
  'mandatory_consumer_identity_digests',
  'native_readback_set_digest',
  'native_successor_readback_digests',
  'ownership_state',
  'prospective_publication_plan_digest',
  'protocol',
  'publication_outcome',
  'release_subject_digest',
  'schema',
  'transaction_id',
].sort());
const GRAPH_NATIVE_OWNERSHIP_OBSERVATION_FIELDS = Object.freeze([
  'authority_digest',
  'authority_observation_digest',
  'current_v1_publication_state',
  'currentness_observation_digest',
  'd2_fence_state',
  'execution_state',
  'factory_closure_receipt_cas_uri',
  'factory_closure_receipt_digest',
  'grant_consumption_receipt_cas_uri',
  'grant_consumption_receipt_digest',
  'graph_commit',
  'graph_native_successor_readbacks',
  'graph_native_successors',
  'graph_owned_observation_digest',
  'graph_reservation_digest',
  'graph_tree',
  'handover_generation_digest',
  'observation_identity_digest',
  'ownership_state',
  'ownership_identity_digest',
  'schema',
  'terminal_receipt_cas_uri',
  'terminal_receipt_digest',
  'validation_currentness',
].sort());
const GRAPH_NATIVE_WORK_PLAN_FIELDS = Object.freeze([
  'action', 'authority_digest', 'current_v1_publication_state',
  'currentness_observation_digest', 'handover_generation_digest',
  'observation_identity_digest', 'ownership_identity_digest', 'reason', 'schema',
  'terminal_receipt_digest', 'trusted_now', 'valid_until',
  'validation_currentness_digest', 'validation_currentness_root_payload_digest',
  'validation_currentness_state',
].sort());
const VALIDATION_CURRENTNESS_GENESIS_FIELDS = Object.freeze([
  'admission_receipt_digest', 'admitted_at', 'evaluated_at', 'evidence_set_digest',
  'owner_identity_digest', 'proof_result_digest', 'proof_state', 'schema',
  'valid_from', 'valid_until', 'validation_input_authority_digest',
  'validation_input_identity_digests',
].sort());
const VALIDATION_CURRENTNESS_DESCENDANT_PAYLOAD_FIELDS = Object.freeze([
  'admission_receipt_digest', 'authority_digest', 'evidence_identity_digests',
  'evidence_set_digest', 'handover_generation_digest', 'predecessor_descendant_digest',
  'proof_evaluated_at', 'proof_result_digest',
  'proof_state', 'renewal_nonce', 'schema',
  'semantic_scope_digest', 'transition', 'trusted_time_authority_digest', 'valid_from',
  'valid_until', 'validation_candidate_digest', 'validation_root_payload_digest',
].sort());
const VALIDATION_CURRENTNESS_ADMISSION_FIELDS = Object.freeze([
  'admission_state', 'admitted_at', 'authority_digest', 'currentness_claim_digest',
  'evidence_set_digest', 'handover_generation_digest',
  'owner_identity_digest', 'proof_result_digest', 'schema',
].sort());
const VALIDATION_CURRENTNESS_DESCENDANT_FIELDS = Object.freeze([
  'admission_receipt', 'payload', 'schema', 'signature',
].sort());

export const SemanticProofV2JournalState = Object.freeze({
  PLANNED: 'PLANNED',
  RESERVED: 'RESERVED',
  D1_COMMITTED: 'D1_COMMITTED',
  D1_DEPENDENCIES_OBSERVED: 'D1_DEPENDENCIES_OBSERVED',
  D2_COMMITTED: 'D2_COMMITTED',
  DERIVED_CLOSURE_VERIFIED: 'DERIVED_CLOSURE_VERIFIED',
  TERMINAL_RECEIPT_COMMITTED: 'TERMINAL_RECEIPT_COMMITTED',
  CONSUMED: 'CONSUMED',
});
const JOURNAL_ORDER = Object.freeze(Object.values(SemanticProofV2JournalState));
const JOURNAL_SNAPSHOT_FIELDS = Object.freeze([
  'boundary_receipts',
  'entries',
  'grant_consumed',
  'publication_state',
  'schema',
  'terminal_receipt',
  'terminal_receipt_digest',
]);
const JOURNAL_ENTRY_FIELDS = Object.freeze([
  'coordination_identity_digest',
  'd0_authority_digest',
  'd1_authority_digest',
  'd2_authority_digest',
  'previous_entry_digest',
  'prospective_publication_plan_digest',
  'receipt_digests',
  'release_subject_digest',
  'schema',
  'state',
  'transaction_id',
  'trusted_at',
]);

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;

export const canonicalJsonV2 = (value) => JSON.stringify(stable(value));
export const sha256V2 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
export const canonicalDigestV2 = (value) => sha256V2(canonicalJsonV2(value));

function canonicalGraphWitnessV2(witness) {
  if (!witness || !Array.isArray(witness.inventory) || witness.inventory.length === 0
      || !Number.isSafeInteger(witness.triples) || witness.triples < 0) {
    throw new Error('Graph production shadow requires one complete authority inventory witness');
  }
  const inventory = witness.inventory.map((record) => Object.freeze({
    graph: record.graph,
    sha256: /^[0-9a-f]{64}$/.test(record.sha256 || '')
      ? `sha256:${record.sha256}` : record.sha256,
    triples: record.triples,
  })).sort((left, right) => left.graph.localeCompare(right.graph));
  if (inventory.some((record) => typeof record.graph !== 'string'
      || !SHA256.test(record.sha256 || '')
      || !Number.isSafeInteger(record.triples) || record.triples < 0)
      || new Set(inventory.map((record) => record.graph)).size !== inventory.length
      || inventory.reduce((total, record) => total + record.triples, 0) !== witness.triples) {
    throw new Error('Graph production shadow authority inventory is not canonical');
  }
  const digest = semanticAuthorityInventoryDigest(inventory, witness.triples);
  if (digest !== witness.digest) {
    throw new Error('Graph production shadow authority digest does not match its inventory');
  }
  const value = Object.freeze({ digest, inventory: Object.freeze(inventory), triples: witness.triples });
  return Object.freeze({ ...value, observationDigest: canonicalDigestV2(value) });
}

function exactClosedFields(value, fields, label) {
  if (!value || canonicalJsonV2(Object.keys(value).sort()) !== canonicalJsonV2(fields)) {
    throw new Error(`${label} fields are not the closed protocol shape`);
  }
}

function exactGraphOwnedConsumerRecordV2(input, authorityDigest) {
  if (!input || !['owner_envelope_successor', 'validation_currentness_binding']
    .includes(input.consumer_kind)) {
    throw new Error('Graph-owned consumer kind is not registered');
  }
  exactDigest(authorityDigest, 'Graph-owned consumer authority');
  if (typeof input.consumer_iri !== 'string' || !input.consumer_iri.startsWith('urn:usf:derivedconsumer:v2:')
      || typeof input.predecessor_record_iri !== 'string' || !input.predecessor_record_iri.startsWith('urn:usf:')) {
    throw new Error('Graph-owned consumer identities are not exact IRIs');
  }
  if (!input.semantic_scope || typeof input.semantic_scope !== 'object'
      || Array.isArray(input.semantic_scope)
      || !Array.isArray(input.materialisation) || input.materialisation.length === 0) {
    throw new Error('Graph-owned consumer semantic scope/materialisation is incomplete');
  }
  const materialisationEntries = input.materialisation.map((statement) => {
    const record = Object.freeze({
      subject: statement.subject,
      predicate: statement.predicate,
      object: Object.freeze({ ...statement.object }),
    });
    return Object.freeze({
      bytes: Buffer.from(canonicalJsonV2(record), 'utf8'),
      record,
    });
  }).sort((left, right) => Buffer.compare(left.bytes, right.bytes));
  for (let index = 1; index < materialisationEntries.length; index += 1) {
    if (materialisationEntries[index - 1].bytes.equals(materialisationEntries[index].bytes)) {
      throw new Error('Graph-owned consumer materialisation contains duplicate statements');
    }
  }
  const materialisation = Object.freeze(materialisationEntries.map(({ record }) => record));
  const semanticScope = Object.freeze(stable(input.semantic_scope));
  const validationInputAuthorityDigest = input.consumer_kind === 'validation_currentness_binding'
    ? exactDigest(input.validation_input_authority_digest, 'validation D0 input authority')
    : null;
  const validationInputIdentityDigests = input.consumer_kind === 'validation_currentness_binding'
    ? sortedUniqueDigests(input.validation_input_identity_digests,
      'validation D0 input identities', { nonempty: true })
    : Object.freeze([]);
  const record = Object.freeze({
    schema: GRAPH_OWNED_CONSUMER_RECORD_V2,
    consumer_kind: input.consumer_kind,
    consumer_iri: input.consumer_iri,
    predecessor_record_iri: input.predecessor_record_iri,
    authority_digest: authorityDigest,
    semantic_scope: semanticScope,
    semantic_scope_digest: canonicalDigestV2({
      schema: 'usf-graph-owned-consumer-semantic-scope-v2',
      consumer_kind: input.consumer_kind,
      semantic_scope: semanticScope,
    }),
    materialisation,
    materialisation_digest: canonicalDigestV2({
      schema: 'usf-graph-owned-consumer-materialisation-v2',
      consumer_kind: input.consumer_kind,
      materialisation,
    }),
    validation_input_authority_digest: validationInputAuthorityDigest,
    validation_input_identity_digests: validationInputIdentityDigests,
  });
  exactClosedFields(record, GRAPH_OWNED_CONSUMER_RECORD_FIELDS, 'Graph-owned consumer record');
  return record;
}

export function graphOwnedConsumerRecordDigestV2(record) {
  exactClosedFields(record, GRAPH_OWNED_CONSUMER_RECORD_FIELDS, 'Graph-owned consumer record');
  if (record.schema !== GRAPH_OWNED_CONSUMER_RECORD_V2) {
    throw new Error('Graph-owned consumer record schema is unknown');
  }
  return canonicalDigestV2(record);
}

export function canonicalGraphOwnedConsumerRecordBytesV2(record) {
  graphOwnedConsumerRecordDigestV2(record);
  return Buffer.from(canonicalJsonV2(record), 'utf8');
}

function canonicalGraphOwnedConsumersV2(inputs, authorityDigest) {
  if (!Array.isArray(inputs) || inputs.length !== 2) {
    throw new Error('Graph production shadow requires exactly two Graph-owned consumers');
  }
  const consumers = inputs.map((input) => exactGraphOwnedConsumerRecordV2(input, authorityDigest))
    .sort((left, right) => left.consumer_kind.localeCompare(right.consumer_kind));
  const expectedKinds = ['owner_envelope_successor', 'validation_currentness_binding'];
  if (canonicalJsonV2(consumers.map((record) => record.consumer_kind))
      !== canonicalJsonV2(expectedKinds)) {
    throw new Error('Graph-owned consumer cardinality is not exact');
  }
  return Object.freeze(consumers);
}

export function createReadOnlyGraphProductionAdapterV2({
  command, readAuthorityWitness, readGraphOwnedConsumers,
} = {}) {
  if (!command || typeof command.previewPublicationSequence !== 'function') {
    throw new Error('Graph production shadow requires the canonical sequence preview command');
  }
  if (typeof readAuthorityWitness !== 'function') {
    throw new Error('Graph production shadow requires the canonical authority witness reader');
  }
  if (typeof readGraphOwnedConsumers !== 'function') {
    throw new Error('Graph production shadow requires the canonical Graph-owned consumer reader');
  }
  const refuse = async () => {
    throw new Error('V2_GRAPH_PRODUCTION_WRITES_DISABLED');
  };
  return Object.freeze({
    mode: 'production-shadow-read-only-v2',
    observe: async () => canonicalGraphWitnessV2(await readAuthorityWitness()),
    readGraphOwnedConsumers: async (authorityDigest) => canonicalGraphOwnedConsumersV2(
      await readGraphOwnedConsumers({ authorityDigest }), authorityDigest,
    ),
    previewPublication: (input) => command.previewPublicationSequence(input),
    reserveGrant: refuse,
    commitD1: refuse,
    observeD1: refuse,
    commitD2: refuse,
    persistTerminalReceipt: refuse,
    consumeGrant: refuse,
    verifyTerminalOwnership: refuse,
  });
}

export async function captureGraphOwnedConsumerObservationV2({
  adapter, expectedAuthorityDigest,
} = {}) {
  if (!adapter || adapter.mode !== 'production-shadow-read-only-v2'
      || typeof adapter.observe !== 'function'
      || typeof adapter.readGraphOwnedConsumers !== 'function') {
    throw new Error('Graph-owned consumer observation requires the complete production adapter');
  }
  exactDigest(expectedAuthorityDigest, 'expected Graph-owned consumer authority');
  const before = await adapter.observe();
  if (before.digest !== expectedAuthorityDigest) {
    throw new Error('Graph-owned consumer authority drifted before observation');
  }
  const consumers = await adapter.readGraphOwnedConsumers(before.digest);
  const after = await adapter.observe();
  if (after.observationDigest !== before.observationDigest) {
    throw new Error('Graph-owned consumer authority changed during observation');
  }
  const authorityBefore = Object.freeze({
    digest: before.digest, inventory: before.inventory, triples: before.triples,
  });
  const authorityAfter = Object.freeze({
    digest: after.digest, inventory: after.inventory, triples: after.triples,
  });
  const observationCore = Object.freeze({
    schema: GRAPH_OWNED_CONSUMER_OBSERVATION_V2,
    protocol: SEMANTIC_PROOF_V2,
    authority_before: authorityBefore,
    authority_after: authorityAfter,
    consumers,
    production_write_operations: 0,
  });
  return Object.freeze({
    ...observationCore,
    observation_digest: canonicalDigestV2(observationCore),
  });
}

export function graphOwnedConsumerObservationDigestV2(observation) {
  exactClosedFields(observation, GRAPH_OWNED_CONSUMER_OBSERVATION_FIELDS,
    'Graph-owned consumer observation');
  if (observation.schema !== GRAPH_OWNED_CONSUMER_OBSERVATION_V2
      || observation.protocol !== SEMANTIC_PROOF_V2
      || observation.production_write_operations !== 0) {
    throw new Error('Graph-owned consumer observation is not exact and read-only');
  }
  const before = canonicalGraphWitnessV2(observation.authority_before);
  const after = canonicalGraphWitnessV2(observation.authority_after);
  const consumers = canonicalGraphOwnedConsumersV2(observation.consumers, before.digest);
  if (before.observationDigest !== after.observationDigest
      || canonicalJsonV2(consumers) !== canonicalJsonV2(observation.consumers)) {
    throw new Error('Graph-owned consumer observation drifted');
  }
  const { observation_digest: observedDigest, ...core } = observation;
  const expectedDigest = canonicalDigestV2(core);
  if (observedDigest !== expectedDigest) {
    throw new Error('Graph-owned consumer observation digest drifted');
  }
  return expectedDigest;
}

export function canonicalGraphOwnedConsumerObservationBytesV2(observation) {
  graphOwnedConsumerObservationDigestV2(observation);
  return Buffer.from(canonicalJsonV2(observation), 'utf8');
}

export async function captureGraphProductionShadowV2({
  adapter,
  expectedD0AuthorityDigest,
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
  graphCommit,
  graphTree,
} = {}) {
  if (!adapter || adapter.mode !== 'production-shadow-read-only-v2'
      || typeof adapter.observe !== 'function'
      || typeof adapter.previewPublication !== 'function') {
    throw new Error('Graph production shadow requires the complete read-only production adapter');
  }
  exactDigest(expectedD0AuthorityDigest, 'expected Graph D0 authority');
  exactGitIdentity(graphCommit, 'Graph production shadow commit');
  exactGitIdentity(graphTree, 'Graph production shadow tree');
  if (!Buffer.isBuffer(d1CandidateBytes) || d1CandidateBytes.length === 0
      || !Buffer.isBuffer(d1CandidateIdentityBytes) || d1CandidateIdentityBytes.length === 0
      || !Buffer.isBuffer(d2CandidateBytes) || d2CandidateBytes.length === 0
      || !Buffer.isBuffer(d2CandidateIdentityBytes) || d2CandidateIdentityBytes.length === 0) {
    throw new Error('V2_GRAPH_SHADOW_EXACT_D1_D2_CANDIDATES_REQUIRED');
  }
  exactDigest(d1CandidateDigest, 'D1 candidate');
  exactDigest(d2CandidateDigest, 'D2 candidate');
  exactDigest(releaseSubjectDigest, 'Graph shadow release subject');
  exactDigest(externalAttestationSetRootDigest, 'Graph shadow external attestation set root');
  exactDigest(candidateGeneratorImplementationDigest, 'Graph shadow candidate generator');
  exactDigest(candidateCommandDigest, 'Graph shadow candidate command');
  const before = await adapter.observe();
  if (before.digest !== expectedD0AuthorityDigest) {
    throw new Error('Graph production shadow D0 authority drifted before observation');
  }
  const graphOwnedConsumers = await adapter.readGraphOwnedConsumers(before.digest);
  const prediction = await adapter.previewPublication({
    d1CandidateBytes,
    d1CandidateDigest,
    d1CandidateIdentityBytes,
    d2CandidateBytes,
    d2CandidateDigest,
    d2CandidateIdentityBytes,
    expectedD0AuthorityDigest,
  });
  const after = await adapter.observe();
  if (after.observationDigest !== before.observationDigest) {
    throw new Error('Graph production shadow authority changed during observation');
  }
  if (prediction?.d0AuthorityDigest !== before.digest
      || prediction?.d1?.candidateDigest !== d1CandidateDigest
      || prediction?.d2?.candidateDigest !== d2CandidateDigest
      || prediction?.d2?.evaluationInputAuthorityDigest !== prediction?.d1?.authorityDigest
      || prediction?.candidateBindings?.releaseSubjectDigest !== releaseSubjectDigest
      || prediction?.candidateBindings?.externalAttestationSetRootDigest
        !== externalAttestationSetRootDigest
      || prediction?.candidateBindings?.candidateGeneratorImplementationDigest
        !== candidateGeneratorImplementationDigest
      || prediction?.candidateBindings?.candidateCommandDigest !== candidateCommandDigest
      || prediction?.candidateBindings?.c2D1AuthorityDigest !== prediction?.d1?.authorityDigest
      || prediction?.productionWriteOperations !== 0
      || prediction?.transactionBeginCount !== 1
      || prediction?.transactionRollbackCount !== 1) {
    throw new Error('Graph production shadow prediction is not exact and read-only');
  }
  exactDigest(prediction.d1.authorityDigest, 'predicted Graph D1 authority');
  exactDigest(prediction.d2.authorityDigest, 'predicted Graph D2 authority');
  const authorityBefore = Object.freeze({
    digest: before.digest,
    inventory: before.inventory,
    triples: before.triples,
  });
  const authorityAfter = Object.freeze({
    digest: after.digest,
    inventory: after.inventory,
    triples: after.triples,
  });
  const boundaryObservationDigest = canonicalDigestV2({
    schema: 'usf-graph-production-shadow-observation-boundary-v2',
    authority_before: authorityBefore,
    authority_after: authorityAfter,
  });
  return Object.freeze({
    schema: GRAPH_PRODUCTION_SHADOW_RECEIPT_V2,
    protocol: SEMANTIC_PROOF_V2,
    graph_commit: graphCommit,
    graph_tree: graphTree,
    release_subject_digest: releaseSubjectDigest,
    external_attestation_set_root_digest: externalAttestationSetRootDigest,
    candidate_generator_implementation_digest: candidateGeneratorImplementationDigest,
    candidate_command_digest: candidateCommandDigest,
    graph_owned_consumers: graphOwnedConsumers,
    boundary_observation_digest: boundaryObservationDigest,
    authority_before: authorityBefore,
    authority_after: authorityAfter,
    d0_authority_digest: before.digest,
    d1_candidate_digest: d1CandidateDigest,
    predicted_d1_authority_digest: prediction.d1.authorityDigest,
    d2_candidate_digest: d2CandidateDigest,
    d2_evaluation_input_authority_digest: prediction.d2.evaluationInputAuthorityDigest,
    predicted_d2_authority_digest: prediction.d2.authorityDigest,
    production_stardog_write_operations: 0,
    production_cas_write_operations: 0,
    production_journal_write_operations: 0,
    authorization_issued: 0,
    publication_performed: 0,
  });
}

export function graphProductionShadowReceiptDigestV2(receipt) {
  if (!receipt || receipt.schema !== GRAPH_PRODUCTION_SHADOW_RECEIPT_V2
      || receipt.protocol !== SEMANTIC_PROOF_V2) {
    throw new Error('invalid V2 Graph production shadow receipt');
  }
  if (canonicalJsonV2(Object.keys(receipt).sort())
      !== canonicalJsonV2(GRAPH_PRODUCTION_SHADOW_FIELDS)) {
    throw new Error(`V2 Graph production shadow receipt fields are not the closed protocol shape: ${canonicalJsonV2(Object.keys(receipt).sort())}`);
  }
  for (const [field, label] of [
    ['boundary_observation_digest', 'Graph shadow observation boundary'],
    ['d0_authority_digest', 'Graph shadow D0 authority'],
    ['d1_candidate_digest', 'Graph shadow D1 candidate'],
    ['predicted_d1_authority_digest', 'Graph shadow predicted D1 authority'],
    ['d2_candidate_digest', 'Graph shadow D2 candidate'],
    ['d2_evaluation_input_authority_digest', 'Graph shadow D2 evaluation input'],
    ['predicted_d2_authority_digest', 'Graph shadow predicted D2 authority'],
    ['release_subject_digest', 'Graph shadow release subject'],
    ['external_attestation_set_root_digest', 'Graph shadow external attestation set root'],
    ['candidate_generator_implementation_digest', 'Graph shadow candidate generator'],
    ['candidate_command_digest', 'Graph shadow candidate command'],
  ]) exactDigest(receipt[field], label);
  exactGitIdentity(receipt.graph_commit, 'Graph shadow commit');
  exactGitIdentity(receipt.graph_tree, 'Graph shadow tree');
  const authorityBefore = canonicalGraphWitnessV2(receipt.authority_before);
  const authorityAfter = canonicalGraphWitnessV2(receipt.authority_after);
  const graphOwnedConsumers = canonicalGraphOwnedConsumersV2(
    receipt.graph_owned_consumers, authorityBefore.digest,
  );
  if (receipt.d2_evaluation_input_authority_digest !== receipt.predicted_d1_authority_digest
      || canonicalDigestV2({
        schema: 'usf-graph-production-shadow-observation-boundary-v2',
        authority_before: {
          digest: authorityBefore.digest,
          inventory: authorityBefore.inventory,
          triples: authorityBefore.triples,
        },
        authority_after: {
          digest: authorityAfter.digest,
          inventory: authorityAfter.inventory,
          triples: authorityAfter.triples,
        },
      }) !== receipt.boundary_observation_digest
      || authorityBefore.observationDigest !== authorityAfter.observationDigest
      || authorityBefore.digest !== receipt.d0_authority_digest
      || canonicalJsonV2(graphOwnedConsumers) !== canonicalJsonV2(receipt.graph_owned_consumers)
      || receipt.production_stardog_write_operations !== 0
      || receipt.production_cas_write_operations !== 0
      || receipt.production_journal_write_operations !== 0
      || receipt.authorization_issued !== 0
      || receipt.publication_performed !== 0) {
    throw new Error('V2 Graph production shadow receipt is not exact and read-only');
  }
  return canonicalDigestV2(receipt);
}

export function canonicalGraphProductionShadowReceiptBytesV2(receipt) {
  graphProductionShadowReceiptDigestV2(receipt);
  return Buffer.from(canonicalJsonV2(receipt), 'utf8');
}

export function assertGraphProductionShadowPlanBindingV2(receipt, plan) {
  assertProspectivePublicationPlanV2(plan);
  const receiptDigest = graphProductionShadowReceiptDigestV2(receipt);
  if (receiptDigest !== plan.graph_production_shadow_receipt_digest
      || receipt.release_subject_digest !== plan.release_subject_digest
      || receipt.d0_authority_digest !== plan.d0_authority_digest
      || receipt.d1_candidate_digest !== plan.graph_d1_candidate_digest
      || receipt.predicted_d1_authority_digest !== plan.predicted_d1_authority_digest
      || receipt.d2_candidate_digest !== plan.graph_d2_candidate_digest
      || receipt.d2_evaluation_input_authority_digest
        !== plan.d2_evaluation_input_authority_digest
      || receipt.predicted_d2_authority_digest !== plan.predicted_d2_authority_digest
      || receipt.external_attestation_set_root_digest
        !== plan.external_attestation_set_root_digest
      || receipt.candidate_generator_implementation_digest
        !== plan.candidate_generator_implementation_digest
      || receipt.candidate_command_digest !== plan.candidate_command_digest
      || receipt.graph_commit !== plan.graph_protected_commit
      || receipt.graph_tree !== plan.graph_protected_tree) {
    throw new Error('Graph production shadow receipt differs from the prospective plan');
  }
  return Object.freeze(receipt);
}

function exactDigest(value, label) {
  if (!SHA256.test(value || '')) throw new Error(`${label} must be an exact sha256 digest`);
  return value;
}

function exactGitIdentity(value, label) {
  if (!GIT_IDENTITY.test(value || '')) throw new Error(`${label} must be an exact Git identity`);
  return value;
}

function exactUtcSecond(value, label) {
  if (!UTC_SECOND.test(value || '') || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be exact UTC seconds`);
  }
  return value;
}

export function nativeHandoverGenerationDigestV2(plan) {
  return canonicalDigestV2({
    schema: 'usf-v2-native-handover-generation-v1',
    release_subject_digest: plan.release_subject_digest,
    d0_authority_digest: plan.d0_authority_digest,
    derived_consumer_registry_digest: plan.derived_consumer_registry_digest,
    graph_protected_tree: plan.graph_protected_tree,
    factory_deployment_tree: plan.factory_deployment_tree,
    external_attestation_set_root_digest: plan.external_attestation_set_root_digest,
  });
}

function assertCanonicalPreimage(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length === 0) {
    throw new Error(`${label} must be one non-empty canonical object`);
  }
  return Object.freeze(stable(value));
}

function assertGraphNativeStateV2(successor, nativeState, semanticScopePreimage) {
  if (successor.storage_owner !== 'GRAPH') return;
  exactClosedFields(semanticScopePreimage,
    ['consumer_kind', 'schema', 'semantic_scope'], 'Graph native semantic-scope preimage');
  if (semanticScopePreimage.schema !== 'usf-graph-owned-consumer-semantic-scope-v2'
      || semanticScopePreimage.consumer_kind !== successor.consumer_kind
      || canonicalJsonV2(semanticScopePreimage.semantic_scope)
        !== canonicalJsonV2(nativeState.semantic_scope)) {
    throw new Error('Graph native successor semantic scope differs from its exact preimage');
  }
  const ownerFields = [
    'authority_digest', 'handover_generation_digest', 'owner_envelope_digest',
    'owner_identity_digest', 'owner_signing_fingerprint', 'predecessor_lineage_digest',
    'predecessor_owner_assignment_iri', 'schema', 'semantic_scope', 'semantic_scope_digest',
  ].sort();
  const validationFields = [
    'authority_digest', 'handover_generation_digest',
    'handover_currentness',
    'predecessor_validation_binding_iri', 'predecessor_validation_input_authority_digest',
    'predecessor_validation_input_identity_digests', 'renewal_rule', 'schema',
    'semantic_scope', 'semantic_scope_digest',
  ].sort();
  if (successor.consumer_kind === 'owner_envelope_successor') {
    exactClosedFields(nativeState, ownerFields, 'Graph owner-envelope native state');
    if (nativeState.schema !== 'usf-owner-envelope-successor-v2'
        || nativeState.authority_digest !== successor.authority_digest
        || nativeState.handover_generation_digest !== successor.handover_generation_digest
        || typeof nativeState.predecessor_owner_assignment_iri !== 'string'
        || !nativeState.predecessor_owner_assignment_iri.startsWith('urn:usf:ownerassignment:')
        || !nativeState.semantic_scope || typeof nativeState.semantic_scope !== 'object'
        || Array.isArray(nativeState.semantic_scope)
        || nativeState.semantic_scope_digest !== successor.semantic_scope_digest
        || !/^[0-9A-F]{40}$/.test(nativeState.owner_signing_fingerprint || '')) {
      throw new Error('Graph owner-envelope successor is not a complete native V2 state');
    }
    for (const [value, label] of [
      [nativeState.owner_identity_digest, 'Graph owner identity'],
      [nativeState.owner_envelope_digest, 'Graph owner envelope'],
      [nativeState.predecessor_lineage_digest, 'Graph owner predecessor lineage'],
    ]) exactDigest(value, label);
    return;
  }
  if (successor.consumer_kind !== 'validation_currentness_binding') {
    throw new Error('Graph native successor kind is not registered');
  }
  exactClosedFields(nativeState, validationFields, 'Graph validation-currentness native state');
  const renewalFields = [
    'allowed_transition', 'descendant_schema', 'requires_exact_predecessor',
    'evidence_admission_path_iri', 'evidence_admission_producer_identity_digest',
    'external_verifier_iri', 'proof_algorithm_digest',
    'requires_single_head', 'requires_trusted_now', 'schema',
    'validation_envelope_verification_iri', 'validation_producer_iri',
    'verification_cas_descriptor_iri',
  ].sort();
  exactClosedFields(nativeState.renewal_rule, renewalFields,
    'Graph validation-currentness renewal rule');
  if (nativeState.schema !== 'usf-validation-currentness-root-v2'
      || nativeState.authority_digest !== successor.authority_digest
      || nativeState.handover_generation_digest !== successor.handover_generation_digest
      || typeof nativeState.predecessor_validation_binding_iri !== 'string'
      || !nativeState.predecessor_validation_binding_iri
        .startsWith('urn:usf:validationselfpublicationbinding:')
      || !nativeState.semantic_scope || typeof nativeState.semantic_scope !== 'object'
      || Array.isArray(nativeState.semantic_scope)
      || nativeState.semantic_scope_digest !== successor.semantic_scope_digest
      || nativeState.predecessor_validation_input_authority_digest
        !== successor.validation_input_authority_digest
      || canonicalJsonV2(nativeState.predecessor_validation_input_identity_digests)
        !== canonicalJsonV2(successor.validation_input_identity_digests)
      || nativeState.renewal_rule.schema !== 'usf-validation-currentness-renewal-rule-v2'
      || nativeState.renewal_rule.allowed_transition !== 'MATERIALISATION_CURRENTNESS'
      || nativeState.renewal_rule.descendant_schema
        !== 'usf-v2-native-validation-currentness-descendant-v1'
      || nativeState.renewal_rule.requires_exact_predecessor !== true
      || nativeState.renewal_rule.requires_single_head !== true
      || nativeState.renewal_rule.requires_trusted_now !== true) {
    throw new Error('Graph validation-currentness successor is not a complete native V2 state');
  }
  exactDigest(nativeState.renewal_rule.evidence_admission_producer_identity_digest,
    'Graph validation-currentness evidence producer');
  exactDigest(nativeState.renewal_rule.proof_algorithm_digest,
    'Graph validation-currentness proof algorithm');
  for (const [field, scopeField] of [
    ['evidence_admission_path_iri', 'evidence_admission_path'],
    ['external_verifier_iri', 'external_verifier'],
    ['validation_envelope_verification_iri', 'envelope_verification'],
    ['validation_producer_iri', 'producer'],
    ['verification_cas_descriptor_iri', 'verification_cas_descriptor'],
  ]) {
    if (typeof nativeState.renewal_rule[field] !== 'string'
        || !nativeState.renewal_rule[field].startsWith('urn:usf:')
        || nativeState.renewal_rule[field] !== nativeState.semantic_scope[scopeField]) {
      throw new Error(`Graph validation-currentness ${field} is not the admitted V1 binding`);
    }
  }
  exactDigest(nativeState.predecessor_validation_input_authority_digest,
    'Graph validation-currentness input authority');
  sortedUniqueDigests(nativeState.predecessor_validation_input_identity_digests,
    'Graph validation-currentness input identities', { nonempty: true });
  exactClosedFields(nativeState.handover_currentness,
    VALIDATION_CURRENTNESS_GENESIS_FIELDS, 'Graph validation-currentness genesis');
  const genesis = nativeState.handover_currentness;
  if (genesis.schema !== 'usf-v2-native-validation-currentness-genesis-v1'
      || genesis.validation_input_authority_digest
        !== nativeState.predecessor_validation_input_authority_digest
      || canonicalJsonV2(genesis.validation_input_identity_digests)
        !== canonicalJsonV2(nativeState.predecessor_validation_input_identity_digests)
      || genesis.proof_state !== 'SUCCESSFUL') {
    throw new Error('Graph validation-currentness genesis is not exact');
  }
  for (const [field, label] of [
    ['admission_receipt_digest', 'validation genesis admission'],
    ['evidence_set_digest', 'validation genesis evidence set'],
    ['owner_identity_digest', 'validation genesis owner identity'],
    ['proof_result_digest', 'validation genesis proof result'],
    ['validation_input_authority_digest', 'validation genesis input authority'],
  ]) exactDigest(genesis[field], label);
  sortedUniqueDigests(genesis.validation_input_identity_digests,
    'validation genesis input identities', { nonempty: true });
  const evaluatedAt = Date.parse(exactUtcSecond(genesis.evaluated_at,
    'validation genesis evaluation time'));
  const validFrom = Date.parse(exactUtcSecond(genesis.valid_from,
    'validation genesis validity start'));
  const validUntil = Date.parse(exactUtcSecond(genesis.valid_until,
    'validation genesis validity end'));
  const admittedAt = Date.parse(exactUtcSecond(genesis.admitted_at,
    'validation genesis admission time'));
  if (evaluatedAt < validFrom || evaluatedAt >= validUntil
      || admittedAt < evaluatedAt || admittedAt >= validUntil) {
    throw new Error('Graph validation-currentness genesis validity window is invalid');
  }
}

export function assertValidationCurrentnessDescendantV2(envelope, {
  authorityDigest,
  handoverGenerationDigest,
  ownerIdentityDigest,
  predecessorDigest,
  semanticScopeDigest,
  validationRootPayloadDigest,
  trustedNow,
  verifySignature,
} = {}) {
  exactClosedFields(envelope, VALIDATION_CURRENTNESS_DESCENDANT_FIELDS,
    'V2 validation-currentness descendant envelope');
  if (envelope.schema !== 'usf-v2-native-validation-currentness-descendant-envelope-v1'
      || typeof envelope.signature !== 'string' || envelope.signature.length < 32) {
    throw new Error('V2 validation-currentness descendant envelope is invalid');
  }
  const payload = envelope.payload;
  const admission = envelope.admission_receipt;
  exactClosedFields(payload, VALIDATION_CURRENTNESS_DESCENDANT_PAYLOAD_FIELDS,
    'V2 validation-currentness descendant payload');
  exactClosedFields(admission, VALIDATION_CURRENTNESS_ADMISSION_FIELDS,
    'V2 validation-currentness admission receipt');
  if (payload.schema !== 'usf-v2-native-validation-currentness-descendant-v1'
      || payload.authority_digest !== authorityDigest
      || payload.handover_generation_digest !== handoverGenerationDigest
      || payload.validation_root_payload_digest !== validationRootPayloadDigest
      || payload.predecessor_descendant_digest !== predecessorDigest
      || payload.semantic_scope_digest !== semanticScopeDigest
      || payload.transition !== 'MATERIALISATION_CURRENTNESS'
      || payload.trusted_time_authority_digest !== authorityDigest
      || payload.proof_state !== 'SUCCESSFUL'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        payload.renewal_nonce || '',
      )) {
    throw new Error('V2 validation-currentness descendant binding is not exact');
  }
  for (const [field, label] of [
    ['admission_receipt_digest', 'validation descendant admission'],
    ['authority_digest', 'validation descendant authority'],
    ['evidence_set_digest', 'validation descendant evidence set'],
    ['handover_generation_digest', 'validation descendant generation'],
    ['predecessor_descendant_digest', 'validation descendant predecessor'],
    ['proof_result_digest', 'validation descendant proof result'],
    ['semantic_scope_digest', 'validation descendant semantic scope'],
    ['trusted_time_authority_digest', 'validation descendant trusted time authority'],
    ['validation_candidate_digest', 'validation descendant validated candidate'],
    ['validation_root_payload_digest', 'validation descendant root'],
  ]) exactDigest(payload[field], label);
  sortedUniqueDigests(payload.evidence_identity_digests,
    'validation descendant evidence identities', { nonempty: true });
  if (canonicalDigestV2({
    schema: 'usf-v2-native-validation-currentness-evidence-set-v1',
    evidence_identity_digests: payload.evidence_identity_digests,
  }) !== payload.evidence_set_digest) {
    throw new Error('V2 validation-currentness evidence-set identity is not exact');
  }
  const evaluatedAt = Date.parse(exactUtcSecond(payload.proof_evaluated_at,
    'validation descendant proof time'));
  const validFrom = Date.parse(exactUtcSecond(payload.valid_from,
    'validation descendant validity start'));
  const validUntil = Date.parse(exactUtcSecond(payload.valid_until,
    'validation descendant validity end'));
  if (evaluatedAt < validFrom || evaluatedAt >= validUntil) {
    throw new Error('V2 validation-currentness descendant validity window is invalid');
  }
  const { admission_receipt_digest: _admissionDigest, ...claimPayload } = payload;
  const currentnessClaimDigest = canonicalDigestV2({
    schema: 'usf-v2-native-validation-currentness-claim-v1',
    payload: claimPayload,
  });
  if (admission.schema !== 'usf-v2-native-validation-currentness-admission-v1'
      || admission.admission_state !== 'ADMITTED'
      || admission.authority_digest !== authorityDigest
      || admission.handover_generation_digest !== handoverGenerationDigest
      || admission.currentness_claim_digest !== currentnessClaimDigest
      || admission.evidence_set_digest !== payload.evidence_set_digest
      || admission.proof_result_digest !== payload.proof_result_digest
      || admission.owner_identity_digest !== ownerIdentityDigest) {
    throw new Error('V2 validation-currentness admission is not exact');
  }
  const admittedAt = Date.parse(exactUtcSecond(
    admission.admitted_at, 'validation descendant admission time',
  ));
  if (admittedAt < evaluatedAt || admittedAt >= validUntil) {
    throw new Error('V2 validation-currentness admission chronology is invalid');
  }
  for (const [field, label] of [
    ['authority_digest', 'validation admission authority'],
    ['currentness_claim_digest', 'validation admission subject'],
    ['evidence_set_digest', 'validation admission evidence set'],
    ['handover_generation_digest', 'validation admission generation'],
    ['owner_identity_digest', 'validation admission owner'],
    ['proof_result_digest', 'validation admission proof'],
  ]) exactDigest(admission[field], label);
  if (payload.admission_receipt_digest !== canonicalDigestV2(admission)) {
    throw new Error('V2 validation-currentness payload does not bind its exact admission');
  }
  const signedSubject = Buffer.from(canonicalJsonV2({
    schema: 'usf-v2-native-validation-currentness-signed-subject-v1',
    admission_receipt: admission,
    payload,
  }), 'utf8');
  if (typeof verifySignature !== 'function'
      || verifySignature(signedSubject, envelope.signature) !== true) {
    throw new Error('V2 validation-currentness descendant signature is invalid');
  }
  if (trustedNow !== undefined && trustedNow !== null) {
    const now = trustedNow instanceof Date ? trustedNow.getTime() : Date.parse(trustedNow);
    if (!Number.isFinite(now) || now < validFrom || now >= validUntil || admittedAt > now) {
      throw new Error('V2_VALIDATION_CURRENTNESS_STALE');
    }
  }
  return Object.freeze({
    admission_receipt_digest: canonicalDigestV2(admission),
    currentness_claim_digest: currentnessClaimDigest,
    digest: canonicalDigestV2(envelope),
    envelope: Object.freeze(envelope),
    payload: Object.freeze(payload),
  });
}

function assertFactoryNativeStateV2(successor, nativeState) {
  if (successor.storage_owner !== 'FACTORY') return;
  const closed = (fields, schema, label) => {
    exactClosedFields(nativeState, fields.slice().sort(), label);
    if (nativeState.schema !== schema || nativeState.authority_digest !== successor.authority_digest) {
      throw new Error(`${label} authority/schema binding is not exact`);
    }
  };
  if (successor.consumer_kind === 'run_authorization') {
    const protectedActions = new Set(['push_pr', 'main_integration', 'stardog_publication']);
    const requiresProtectedScope = Array.isArray(nativeState.permitted_actions)
      && nativeState.permitted_actions.some((action) => protectedActions.has(action));
    if (nativeState.schema_version !== 2
        || (requiresProtectedScope
          && nativeState.protected_delivery_scope?.authority_digest !== successor.authority_digest)
        || nativeState.validation_lifecycle_scope === null
        || nativeState.validation_lifecycle_scope === undefined
        || nativeState.validation_lifecycle_scope.trusted_time_authority_digest
          !== successor.authority_digest) {
      throw new Error('native V2 RunAuthorization is not current and D2-bound');
    }
    return;
  }
  if (successor.consumer_kind === 'execution_scope_projection') {
    closed([
      'authority_digest', 'contract_execution_scope_digest', 'contract_execution_scope_iri',
      'contract_execution_scope_projection_digest', 'contract_execution_scope_projection_ref',
      'schema', 'validation_lifecycle_scope',
    ], 'usf-execution-scope-projection-v2', 'native execution-scope projection');
  } else if (successor.consumer_kind === 'contract_projection') {
    closed([
      'authority_digest', 'contract_projection_digest', 'contract_projection_ref', 'schema',
      'semantic_contract_root_digest', 'snapshot_contract_iri',
    ], 'usf-contract-projection-v2', 'native contract projection');
  } else if (successor.consumer_kind === 'factory_graph_witness_binding') {
    closed([
      'authority_digest', 'environment_id', 'materialisation_contract_identity',
      'programme_state_digest', 'registry_digest', 'repository_head', 'repository_id',
      'repository_tree', 'schema', 'service_name', 'source_manifest_digest',
    ], 'usf-factory-graph-witness-binding-v2', 'native Factory repository witness');
    exactGitIdentity(nativeState.repository_head, 'native Factory witness commit');
    exactGitIdentity(nativeState.repository_tree, 'native Factory witness tree');
  } else if (successor.consumer_kind === 'workforce_policy_compatibility_binding') {
    closed([
      'admission_policy_digest', 'authority_digest', 'catalogue_policy',
      'catalogue_policy_digest', 'model_market_policy', 'model_market_policy_digest',
      'provider_policy', 'provider_policy_digest', 'qualification_policy_digest',
      'roster_policy', 'roster_policy_digest', 'schema', 'workforce_policy',
      'workforce_policy_digest',
    ], 'usf-workforce-policy-compatibility-binding-v2', 'native workforce policy');
    for (const [valueField, digestField] of [
      ['workforce_policy', 'workforce_policy_digest'],
      ['roster_policy', 'roster_policy_digest'],
      ['provider_policy', 'provider_policy_digest'],
      ['model_market_policy', 'model_market_policy_digest'],
      ['catalogue_policy', 'catalogue_policy_digest'],
    ]) {
      if (!nativeState[valueField] || typeof nativeState[valueField] !== 'object'
          || Array.isArray(nativeState[valueField])
          || canonicalDigestV2(nativeState[valueField]) !== nativeState[digestField]) {
        throw new Error(`native workforce ${valueField} binding is invalid`);
      }
    }
  } else {
    throw new Error('Factory native successor kind is not registered');
  }
  for (const [key, value] of Object.entries(nativeState)) {
    if (key.endsWith('_digest')) exactDigest(value, `native ${successor.consumer_kind} ${key}`);
    if (key.endsWith('_iri') && (typeof value !== 'string' || !value.startsWith('urn:'))) {
      throw new Error(`native ${successor.consumer_kind} ${key} is not an exact IRI`);
    }
    if (key.endsWith('_ref')) {
      const digestField = `${key.slice(0, -4)}_digest`;
      if (nativeState[digestField]
          && value !== `cas://sha256/${nativeState[digestField].slice(7)}`) {
        throw new Error(`native ${successor.consumer_kind} ${key} CAS binding is invalid`);
      }
    }
  }
}

function assertNativeSuccessorPayloadV2(successor) {
  if (successor.handover_generation_digest === undefined
      || successor.storage_owner !== NATIVE_SUCCESSOR_STORAGE_OWNER[successor.consumer_kind]
      || successor.payload_schema !== 'usf-v2-native-successor-payload-v1') {
    throw new Error('derived consumer native successor owner/schema binding is invalid');
  }
  exactDigest(successor.handover_generation_digest, 'native handover generation');
  const semanticScopePreimage = assertCanonicalPreimage(
    successor.semantic_scope_preimage, 'native successor semantic scope preimage',
  );
  const materialisationPreimage = assertCanonicalPreimage(
    successor.materialisation_preimage, 'native successor materialisation preimage',
  );
  if (canonicalJsonV2(semanticScopePreimage) !== canonicalJsonV2(successor.semantic_scope_preimage)
      || canonicalJsonV2(materialisationPreimage)
        !== canonicalJsonV2(successor.materialisation_preimage)) {
    throw new Error('native successor preimages are not canonical');
  }
  if (canonicalDigestV2(semanticScopePreimage) !== successor.semantic_scope_digest
      || canonicalDigestV2(materialisationPreimage) !== successor.materialisation_digest) {
    throw new Error('native successor preimage digest binding is invalid');
  }
  const payload = assertCanonicalPreimage(successor.payload_preimage, 'native successor payload');
  const payloadFields = [
    'authority_digest', 'consumer_iri', 'consumer_kind', 'handover_generation_digest',
    'materialisation_digest', 'native_state', 'predecessor_identity_digest', 'schema',
    'semantic_scope_digest', 'storage_owner',
  ].sort();
  exactClosedFields(payload, payloadFields, 'native successor payload');
  if (payload.schema !== successor.payload_schema
      || payload.handover_generation_digest !== successor.handover_generation_digest
      || payload.consumer_kind !== successor.consumer_kind
      || payload.consumer_iri !== successor.consumer_iri
      || payload.storage_owner !== successor.storage_owner
      || payload.authority_digest !== successor.authority_digest
      || payload.predecessor_identity_digest !== successor.predecessor_identity_digest
      || payload.semantic_scope_digest !== successor.semantic_scope_digest
      || payload.materialisation_digest !== successor.materialisation_digest
      || !payload.native_state || typeof payload.native_state !== 'object'
      || Array.isArray(payload.native_state) || Object.keys(payload.native_state).length === 0) {
    throw new Error('native successor payload differs from its successor identity');
  }
  if (canonicalJsonV2(materialisationPreimage) !== canonicalJsonV2(payload.native_state)) {
    throw new Error('native successor materialisation must be its exact owner-native state');
  }
  assertGraphNativeStateV2(successor, payload.native_state, semanticScopePreimage);
  assertFactoryNativeStateV2(successor, payload.native_state);
  const bytes = Buffer.from(canonicalJsonV2(payload), 'utf8');
  const payloadDigest = sha256V2(bytes);
  if (successor.payload_digest !== payloadDigest
      || successor.payload_cas_uri !== `cas://sha256/${payloadDigest.slice(7)}`
      || successor.payload_size !== bytes.length) {
    throw new Error('native successor payload CAS binding is invalid');
  }
  return successor;
}

export function nativeSuccessorReadbackDigestV2(readback) {
  exactClosedFields(readback, NATIVE_SUCCESSOR_READBACK_FIELDS,
    'native successor production readback');
  if (readback.schema !== 'usf-v2-native-successor-readback-v1'
      || !REQUIRED_CONSUMER_KINDS.includes(readback.consumer_kind)
      || readback.storage_owner !== NATIVE_SUCCESSOR_STORAGE_OWNER[readback.consumer_kind]
      || readback.production_reader !== NATIVE_SUCCESSOR_PRODUCTION_READERS[readback.consumer_kind]
      || readback.observation_state !== 'EXACT') {
    throw new Error('native successor production readback is not exact');
  }
  for (const [field, label] of [
    ['successor_record_digest', 'native successor record'],
    ['handover_generation_digest', 'native handover generation'],
    ['native_payload_digest', 'native payload'],
  ]) exactDigest(readback[field], label);
  if (readback.native_payload_cas_uri
        !== `cas://sha256/${readback.native_payload_digest.slice(7)}`
      || !Number.isSafeInteger(readback.native_payload_size)
      || readback.native_payload_size < 1) {
    throw new Error('native successor readback CAS binding is invalid');
  }
  const { observation_digest: observed, ...core } = readback;
  const expected = canonicalDigestV2(core);
  if (observed !== expected) throw new Error('native successor readback digest drifted');
  return expected;
}

export function nativeReadbackSetDigestV2(generationDigest, readbacks) {
  exactDigest(generationDigest, 'native handover generation');
  const observationDigests = readbacks.map(nativeSuccessorReadbackDigestV2);
  return canonicalDigestV2({
    schema: 'usf-v2-native-successor-readback-set-v1',
    handover_generation_digest: generationDigest,
    observation_digests: observationDigests,
  });
}

export function assertFactoryPrepareReceiptV2(receipt, plan, {
  factoryCommit,
  factoryTree,
} = {}) {
  assertProspectivePublicationPlanV2(plan);
  exactClosedFields(receipt, FACTORY_PREPARE_RECEIPT_FIELDS, 'Factory native prepare receipt');
  if (receipt.schema !== 'usf-v2-native-handover-prepare-receipt-v1'
      || receipt.prepare_state !== 'DURABLE_PENDING'
      || receipt.handover_generation_digest !== plan.handover_generation_digest
      || receipt.prospective_publication_plan_digest !== prospectivePublicationPlanDigestV2(plan)
      || receipt.d0_authority_digest !== plan.d0_authority_digest
      || receipt.factory_commit !== factoryCommit
      || receipt.factory_tree !== factoryTree
      || receipt.factory_tree !== plan.factory_deployment_tree
      || typeof receipt.coordinator_fence_name !== 'string'
      || receipt.coordinator_fence_name.length === 0
      || !Number.isSafeInteger(receipt.coordinator_fencing_token)
      || receipt.coordinator_fencing_token < 1) {
    throw new Error('Factory native prepare receipt differs from the exact fenced release');
  }
  exactGitIdentity(receipt.factory_commit, 'Factory prepare commit');
  exactGitIdentity(receipt.factory_tree, 'Factory prepare tree');
  exactDigest(receipt.generation_record_digest, 'Factory native generation record');
  exactDigest(receipt.graph_reservation_receipt_digest,
    'Factory native Graph reservation receipt');
  if (receipt.generation_record_cas_uri
      !== `cas://sha256/${receipt.generation_record_digest.slice(7)}`) {
    throw new Error('Factory native generation record CAS binding is invalid');
  }
  const records = plan.derived_consumers.map((item) => item.expected_successor_digest).sort();
  const payloads = plan.derived_consumers.map(
    (item) => item.expected_successor.payload_digest,
  ).sort();
  const closure = [
    prospectivePublicationPlanDigestV2(plan), receipt.generation_record_digest,
    receipt.graph_reservation_receipt_digest,
    ...records, ...payloads,
  ].sort();
  for (const [values, expected, label] of [
    [receipt.successor_record_digests, records, 'Factory prepared successor records'],
    [receipt.native_payload_digests, payloads, 'Factory prepared native payloads'],
    [receipt.cas_closure_digests, closure, 'Factory prepared CAS closure'],
  ]) {
    sortedUniqueDigests(values, label, { nonempty: true });
    if (canonicalJsonV2(values) !== canonicalJsonV2(expected)) {
      throw new Error(`${label} differ from the prospective plan`);
    }
  }
  if (receipt.cas_closure_digests.length !== 17) {
    throw new Error('Factory native prepare CAS closure cardinality is not 17');
  }
  return Object.freeze(receipt);
}

export function graphReservationReceiptDigestV2(receipt, plan, {
  graphCommit,
  graphTree,
} = {}) {
  assertProspectivePublicationPlanV2(plan);
  exactClosedFields(receipt, GRAPH_RESERVATION_RECEIPT_FIELDS,
    'Graph native handover reservation receipt');
  const explicitGrantDigests = plan.derived_consumers
    .map((item) => item.explicit_authorization_grant_digest)
    .filter((value) => value !== null && value !== undefined)
    .sort();
  const laneReservationDigest = canonicalDigestV2({
    schema: 'usf-v2-native-handover-reservation-v1',
    d0_authority_digest: plan.d0_authority_digest,
    handover_generation_digest: plan.handover_generation_digest,
    prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(plan),
  });
  if (receipt.schema !== 'usf-graph-grant-reservation-receipt-v2'
      || receipt.protocol !== SEMANTIC_PROOF_V2
      || receipt.release_subject_digest !== plan.release_subject_digest
      || receipt.prospective_publication_plan_digest
        !== prospectivePublicationPlanDigestV2(plan)
      || canonicalJsonV2(receipt.explicit_authorization_grant_digests)
        !== canonicalJsonV2(explicitGrantDigests)
      || receipt.d0_authority_digest !== plan.d0_authority_digest
      || receipt.graph_commit !== graphCommit
      || receipt.graph_tree !== graphTree
      || receipt.graph_tree !== plan.graph_protected_tree
      || receipt.handover_generation_digest !== plan.handover_generation_digest
      || receipt.lane_reservation_digest !== laneReservationDigest
      || receipt.lane_reservation_schema !== 'usf-v2-native-handover-reservation-v1'
      || receipt.reservation_state !== 'V2_HANDOVER_RESERVED') {
    throw new Error('Graph native handover reservation receipt is not exact');
  }
  exactGitIdentity(receipt.graph_commit, 'Graph reservation commit');
  exactGitIdentity(receipt.graph_tree, 'Graph reservation tree');
  sortedUniqueDigests(receipt.explicit_authorization_grant_digests,
    'Graph reservation explicit grants');
  exactDigest(receipt.lane_reservation_digest, 'Graph lane reservation');
  return canonicalDigestV2(receipt);
}

export function factoryPrepareReceiptDigestV2(receipt, plan, sources) {
  assertFactoryPrepareReceiptV2(receipt, plan, sources);
  return canonicalDigestV2(receipt);
}

export function graphOwnedNativeObservationDigestV2(generationDigest, readbacks) {
  exactDigest(generationDigest, 'native handover generation');
  const graphReadbacks = readbacks.filter((readback) => readback.storage_owner === 'GRAPH');
  if (graphReadbacks.length !== 2
      || canonicalJsonV2(graphReadbacks.map((item) => item.consumer_kind))
        !== canonicalJsonV2(GRAPH_OWNED_CONSUMER_KINDS)) {
    throw new Error('Graph native successor observation requires the exact Graph-owned pair');
  }
  return canonicalDigestV2({
    schema: 'usf-v2-graph-native-successor-observation-v1',
    handover_generation_digest: generationDigest,
    observation_digests: graphReadbacks.map(nativeSuccessorReadbackDigestV2),
  });
}

function sortedUniqueDigests(values, label, { nonempty = false } = {}) {
  if (!Array.isArray(values) || (nonempty && values.length === 0)) {
    throw new Error(`${label} must be a${nonempty ? ' non-empty' : ''} digest array`);
  }
  values.forEach((value) => exactDigest(value, label));
  const canonical = [...new Set(values)].sort();
  if (canonical.length !== values.length || canonical.some((value, index) => value !== values[index])) {
    throw new Error(`${label} must be sorted and unique`);
  }
  return Object.freeze(canonical);
}

export function prospectivePublicationPlanDigestV2(plan) {
  assertProspectivePublicationPlanV2(plan);
  return canonicalDigestV2(plan);
}

export function closureTransactionIdV2(plan) {
  return canonicalDigestV2({
    schema: 'usf-derived-consumer-closure-transaction-id-v2',
    releaseSubjectDigest: plan.release_subject_digest,
    prospectivePublicationPlanDigest: prospectivePublicationPlanDigestV2(plan),
  });
}

export function assertProspectivePublicationPlanV2(plan) {
  if (!plan || typeof plan !== 'object' || plan.schema !== PROSPECTIVE_PUBLICATION_PLAN_V2) {
    throw new Error('V2 publisher requires one exact prospective publication plan');
  }
  exactClosedFields(plan, PROSPECTIVE_PUBLICATION_PLAN_FIELDS,
    'prospective publication plan');
  for (const [field, label] of [
    ['release_subject_digest', 'release subject'],
    ['derived_consumer_registry_digest', 'derived consumer registry'],
    ['identity_dependency_graph_digest', 'identity dependency graph'],
    ['d0_authority_digest', 'D0 authority'],
    ['predicted_d1_authority_digest', 'predicted D1 authority'],
    ['d2_evaluation_input_authority_digest', 'D2 evaluation input'],
    ['predicted_d2_authority_digest', 'predicted D2 authority'],
    ['graph_d1_candidate_digest', 'Graph D1 candidate'],
    ['graph_d2_candidate_digest', 'Graph D2 candidate'],
    ['graph_production_shadow_receipt_digest', 'Graph production shadow receipt'],
    ['external_attestation_set_root_digest', 'external attestation set root'],
    ['candidate_generator_implementation_digest', 'candidate generator implementation'],
    ['candidate_command_digest', 'candidate command'],
  ]) exactDigest(plan[field], label);
  if (plan.derived_consumer_registry_digest !== DERIVED_CONSUMER_REGISTRY_V2_DIGEST) {
    throw new Error('prospective plan registry differs from the exact V2 registry');
  }
  if (plan.identity_dependency_graph_digest !== IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST) {
    throw new Error('prospective plan dependency graph differs from the exact V2 graph');
  }
  if (plan.handover_generation_digest !== nativeHandoverGenerationDigestV2(plan)) {
    throw new Error('prospective plan native handover generation is not exact');
  }
  if (plan.d2_evaluation_input_authority_digest !== plan.predicted_d1_authority_digest) {
    throw new Error('V2 D2 evaluation must consume the exact predicted D1 authority');
  }
  if (plan.outcome !== 'PROCEED') throw new Error('blocked prospective plan is not publishable');
  exactGitIdentity(plan.factory_deployment_tree, 'Factory deployment tree');
  exactGitIdentity(plan.factory_deployment_commit, 'Factory deployment commit');
  exactGitIdentity(plan.graph_protected_tree, 'Graph protected tree');
  exactGitIdentity(plan.graph_protected_commit, 'Graph protected commit');
  sortedUniqueDigests(plan.d1_dependency_identity_digests, 'D1 dependency identities', {
    nonempty: true,
  });
  sortedUniqueDigests(plan.required_cas_object_digests, 'required CAS objects', {
    nonempty: true,
  });
  if (!Array.isArray(plan.derived_consumers) || plan.derived_consumers.length !== 7) {
    throw new Error('prospective plan must close exactly seven mandatory consumers');
  }
  const kinds = plan.derived_consumers.map((item) => item.consumer_kind);
  if (canonicalJsonV2(kinds) !== canonicalJsonV2(REQUIRED_CONSUMER_KINDS)) {
    throw new Error('prospective plan mandatory consumer set is not canonical');
  }
  const predecessorIdentities = [];
  for (const item of plan.derived_consumers) {
    const plannedFields = item?.decision === 'EXPLICITLY_AUTHORIZED_SUCCESSOR'
      ? [...PLANNED_DERIVED_CONSUMER_FIELDS, 'explicit_authorization_grant_digest'].sort()
      : PLANNED_DERIVED_CONSUMER_FIELDS;
    exactClosedFields(item, plannedFields, 'planned derived consumer');
    if (item.mandatory !== true || item.predicted_d1_authority_digest !== plan.predicted_d1_authority_digest
        || item.predicted_d2_authority_digest !== plan.predicted_d2_authority_digest) {
      throw new Error('prospective consumer authority binding differs from the plan');
    }
    predecessorIdentities.push(exactDigest(
      item.predecessor_identity_digest,
      'derived consumer predecessor',
    ));
    exactDigest(item.predecessor_record_digest, 'derived consumer predecessor record');
    exactDigest(item.current_semantic_scope_digest, 'current consumer semantic scope');
    exactDigest(item.prospective_semantic_scope_digest, 'prospective consumer semantic scope');
    exactDigest(item.current_materialisation_digest, 'current consumer materialisation');
    exactDigest(item.prospective_materialisation_digest, 'prospective consumer materialisation');
    if (item.decision === 'BLOCK') throw new Error('blocked mandatory consumer reached V2 publisher');
    if (item.decision === 'UNCHANGED') {
      throw new Error('native V2 handover requires a distinct successor for every consumer');
    }
    if (!SUCCESSOR_DECISIONS.has(item.decision) || !item.expected_successor) {
      throw new Error('mandatory consumer has an unsupported transition decision');
    }
    const successorFields = item.decision === 'EXPLICITLY_AUTHORIZED_SUCCESSOR'
      ? [...DERIVED_CONSUMER_SUCCESSOR_FIELDS, 'explicit_authorization_grant_digest'].sort()
      : DERIVED_CONSUMER_SUCCESSOR_FIELDS;
    exactClosedFields(item.expected_successor, successorFields, 'derived consumer successor');
    if (item.expected_successor.schema !== 'usf-derived-consumer-successor-v2') {
      throw new Error('derived consumer successor schema is unknown');
    }
    if (canonicalDigestV2(item.expected_successor) !== item.expected_successor_digest
        || item.expected_successor.predecessor_identity_digest !== item.predecessor_identity_digest
        || item.expected_successor.semantic_scope_digest !== item.prospective_semantic_scope_digest
        || item.expected_successor.materialisation_digest !== item.prospective_materialisation_digest
        || item.expected_successor.authority_digest !== plan.predicted_d2_authority_digest
        || item.expected_successor.release_subject_digest !== plan.release_subject_digest
        || item.expected_successor.registry_digest !== plan.derived_consumer_registry_digest) {
      throw new Error('prospective plan exact successor prediction drifted');
    }
    assertNativeSuccessorPayloadV2(item.expected_successor);
    if (item.expected_successor.handover_generation_digest
        !== plan.handover_generation_digest) {
      throw new Error('native successor belongs to another handover generation');
    }
    if (item.decision === 'COMPATIBLE_SUCCESSOR') {
      if (item.current_semantic_scope_digest !== item.prospective_semantic_scope_digest
          || item.explicit_authorization_grant_digest !== undefined
          || item.expected_successor.transition_cause !== 'PUBLICATION_DERIVED_MATERIALISATION') {
        throw new Error('compatible successor attempted a semantic authorization change');
      }
    } else if (item.current_semantic_scope_digest === item.prospective_semantic_scope_digest
        || !SHA256.test(item.explicit_authorization_grant_digest || '')
        || item.expected_successor.explicit_authorization_grant_digest
          !== item.explicit_authorization_grant_digest
        || item.expected_successor.transition_cause !== 'EXPLICIT_SEMANTIC_AUTHORIZATION') {
      throw new Error('explicit successor lacks one exact semantic authorization grant');
    }
    if (item.consumer_kind === 'validation_currentness_binding'
        && (item.expected_successor.validation_input_authority_digest
          !== plan.predicted_d1_authority_digest
          || canonicalJsonV2(item.expected_successor.validation_input_identity_digests)
            !== canonicalJsonV2(plan.d1_dependency_identity_digests))) {
      throw new Error('validation currentness does not consume exact D1 identities');
    }
  }
  if (new Set(predecessorIdentities).size !== predecessorIdentities.length) {
    throw new Error('prospective consumer predecessors must be unique');
  }
  const nativePayloadDigests = plan.derived_consumers
    .map((item) => item.expected_successor.payload_digest)
    .sort();
  const nativeRecordDigests = plan.derived_consumers
    .map((item) => item.expected_successor_digest)
    .sort();
  if ([...nativePayloadDigests, ...nativeRecordDigests]
    .some((value) => !plan.required_cas_object_digests.includes(value))) {
    throw new Error('prospective plan CAS closure omits a native successor record or payload');
  }
  return Object.freeze(plan);
}

function expectedClosure(plan) {
  const successorDigests = plan.derived_consumers
    .filter((item) => SUCCESSOR_DECISIONS.has(item.decision))
    .map((item) => item.expected_successor_digest)
    .sort();
  const currentDigests = plan.derived_consumers.map((item) => (
    SUCCESSOR_DECISIONS.has(item.decision)
      ? item.expected_successor_digest
      : item.predecessor_identity_digest
  )).sort();
  const explicitGrantDigests = plan.derived_consumers
    .map((item) => item.explicit_authorization_grant_digest)
    .filter(Boolean)
    .sort();
  return Object.freeze({ successorDigests, currentDigests, explicitGrantDigests });
}

export function assertFactoryClosureReceiptV2(receipt, plan) {
  assertProspectivePublicationPlanV2(plan);
  if (!receipt || receipt.schema !== DERIVED_CLOSURE_RECEIPT_V2
      || receipt.terminal_result !== 'NATIVE_STATE_REREAD_EXACT') {
    throw new Error('Graph requires exact native-state production reread closure');
  }
  exactClosedFields(receipt, FACTORY_CLOSURE_RECEIPT_FIELDS, 'Factory closure receipt');
  const expected = expectedClosure(plan);
  if (receipt.transaction_id !== closureTransactionIdV2(plan)
      || receipt.release_subject_digest !== plan.release_subject_digest
      || receipt.prospective_publication_plan_digest !== prospectivePublicationPlanDigestV2(plan)
      || receipt.derived_consumer_registry_digest !== plan.derived_consumer_registry_digest
      || receipt.d1_authority_digest !== plan.predicted_d1_authority_digest
      || receipt.d2_authority_digest !== plan.predicted_d2_authority_digest
      || receipt.handover_generation_digest !== plan.handover_generation_digest
      || canonicalJsonV2(receipt.successor_identity_digests) !== canonicalJsonV2(expected.successorDigests)
      || canonicalJsonV2(receipt.mandatory_consumer_identity_digests)
        !== canonicalJsonV2(expected.currentDigests)
      || canonicalJsonV2(receipt.explicit_authorization_grant_digests)
        !== canonicalJsonV2(expected.explicitGrantDigests)) {
    throw new Error('Factory closure receipt differs from the approved prospective plan');
  }
  sortedUniqueDigests(receipt.successor_identity_digests, 'Factory closure successors');
  sortedUniqueDigests(
    receipt.mandatory_consumer_identity_digests,
    'Factory closure mandatory consumers',
    { nonempty: true },
  );
  sortedUniqueDigests(receipt.explicit_authorization_grant_digests, 'explicit grants');
  for (const [field, label] of [
    ['graph_d1_commit_receipt_digest', 'Factory closure D1 commit receipt'],
    ['graph_d1_observation_receipt_digest', 'Factory closure D1 observation receipt'],
    ['graph_d2_commit_receipt_digest', 'Factory closure D2 commit receipt'],
  ]) exactDigest(receipt[field], label);
  if (!Array.isArray(receipt.native_successor_readbacks)
      || receipt.native_successor_readbacks.length !== 7
      || canonicalJsonV2(receipt.native_successor_readbacks.map((item) => item.consumer_kind))
        !== canonicalJsonV2(REQUIRED_CONSUMER_KINDS)) {
    throw new Error('Factory closure does not carry exactly seven native production readbacks');
  }
  const readbackByKind = new Map(receipt.native_successor_readbacks.map((readback) => [
    readback.consumer_kind, readback,
  ]));
  for (const item of plan.derived_consumers) {
    const readback = readbackByKind.get(item.consumer_kind);
    nativeSuccessorReadbackDigestV2(readback);
    if (readback.successor_record_digest !== item.expected_successor_digest
        || readback.handover_generation_digest !== plan.handover_generation_digest
        || readback.native_payload_digest !== item.expected_successor.payload_digest
        || readback.native_payload_cas_uri !== item.expected_successor.payload_cas_uri
        || readback.native_payload_size !== item.expected_successor.payload_size) {
      throw new Error('Factory closure native readback differs from the exact successor plan');
    }
  }
  if (receipt.native_readback_set_digest
        !== nativeReadbackSetDigestV2(plan.handover_generation_digest,
          receipt.native_successor_readbacks)
      || receipt.graph_owned_observation_digest
        !== graphOwnedNativeObservationDigestV2(plan.handover_generation_digest,
          receipt.native_successor_readbacks)) {
    throw new Error('Factory closure native observation set digest is invalid');
  }
  return Object.freeze(receipt);
}

export function factoryClosureReceiptDigestV2(receipt, plan) {
  assertFactoryClosureReceiptV2(receipt, plan);
  return canonicalDigestV2(receipt);
}

function coordinationIdentity(inputs) {
  for (const [field, label] of [
    ['publisher_implementation_digest', 'publisher implementation'],
    ['factory_executor_implementation_digest', 'Factory closure executor'],
    ['publisher_command_digest', 'publisher command'],
    ['factory_closure_command_digest', 'Factory closure command'],
  ]) exactDigest(inputs[field], label);
  exactGitIdentity(inputs.factory_commit, 'Factory commit');
  exactGitIdentity(inputs.factory_tree, 'Factory tree');
  exactGitIdentity(inputs.graph_commit, 'Graph commit');
  exactGitIdentity(inputs.graph_tree, 'Graph tree');
  exactUtcSecond(inputs.terminal_receipt_at, 'predicted terminal receipt time');
  if (inputs.factory_tree !== inputs.plan.factory_deployment_tree
      || inputs.graph_tree !== inputs.plan.graph_protected_tree) {
    throw new Error('coordination source identities differ from the prospective plan');
  }
  const factoryWitness = inputs.plan.derived_consumers.find(
    (item) => item.consumer_kind === 'factory_graph_witness_binding',
  )?.expected_successor?.payload_preimage?.native_state;
  if (!factoryWitness
      || factoryWitness.repository_id !== 'maldous/usf-factory'
      || factoryWitness.repository_head !== inputs.factory_commit
      || factoryWitness.repository_tree !== inputs.factory_tree) {
    throw new Error('Factory native repository witness differs from the admitted source');
  }
  return canonicalDigestV2({
    schema: 'usf-semantic-proof-v2-coordination-identity',
    transaction_id: closureTransactionIdV2(inputs.plan),
    release_subject_digest: inputs.plan.release_subject_digest,
    prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(inputs.plan),
    derived_consumer_registry_digest: inputs.plan.derived_consumer_registry_digest,
    d0_authority_digest: inputs.plan.d0_authority_digest,
    predicted_d1_authority_digest: inputs.plan.predicted_d1_authority_digest,
    predicted_d2_authority_digest: inputs.plan.predicted_d2_authority_digest,
    factory_commit: inputs.factory_commit,
    factory_tree: inputs.factory_tree,
    graph_commit: inputs.graph_commit,
    graph_tree: inputs.graph_tree,
    publisher_implementation_digest: inputs.publisher_implementation_digest,
    factory_executor_implementation_digest: inputs.factory_executor_implementation_digest,
    publisher_command_digest: inputs.publisher_command_digest,
    factory_closure_command_digest: inputs.factory_closure_command_digest,
    terminal_receipt_at: inputs.terminal_receipt_at,
  });
}

// Exported so fixtures build the canonical 16-field terminal receipt through
// this one definition instead of hand-rolling a literal that goes stale.
export function terminalReceipt(
  inputs, closureReceipt, acceptedAt, grantConsumptionReceiptDigest,
) {
  return Object.freeze({
    schema: GRAPH_PUBLICATION_RECEIPT_V2,
    protocol: SEMANTIC_PROOF_V2,
    transaction_id: closureTransactionIdV2(inputs.plan),
    coordination_identity_digest: coordinationIdentity(inputs),
    release_subject_digest: inputs.plan.release_subject_digest,
    prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(inputs.plan),
    derived_consumer_registry_digest: inputs.plan.derived_consumer_registry_digest,
    handover_generation_digest: inputs.plan.handover_generation_digest,
    d0_authority_digest: inputs.plan.d0_authority_digest,
    d1_authority_digest: inputs.plan.predicted_d1_authority_digest,
    d2_authority_digest: inputs.plan.predicted_d2_authority_digest,
    factory_closure_receipt_digest: factoryClosureReceiptDigestV2(
      closureReceipt,
      inputs.plan,
    ),
    factory_prepare_receipt_digest: factoryPrepareReceiptDigestV2(
      inputs.factory_prepare_receipt,
      inputs.plan,
      { factoryCommit: inputs.factory_commit, factoryTree: inputs.factory_tree },
    ),
    mandatory_consumer_identity_digests: Object.freeze([
      ...closureReceipt.mandatory_consumer_identity_digests,
    ]),
    explicit_authorization_grant_digests: Object.freeze([
      ...closureReceipt.explicit_authorization_grant_digests,
    ]),
    native_readback_set_digest: closureReceipt.native_readback_set_digest,
    native_successor_readback_digests: Object.freeze(
      closureReceipt.native_successor_readbacks.map(nativeSuccessorReadbackDigestV2).sort(),
    ),
    graph_owned_observation_digest: closureReceipt.graph_owned_observation_digest,
    grant_consumption_receipt_digest: exactDigest(
      grantConsumptionReceiptDigest, 'V2 grant consumption receipt',
    ),
    graph_commit: inputs.graph_commit,
    graph_tree: inputs.graph_tree,
    factory_commit: inputs.factory_commit,
    factory_tree: inputs.factory_tree,
    ownership_state: 'V2_TERMINAL_OWNER',
    current_v1_publication_state: 'RETIRED',
    publication_outcome: 'ACCEPTED',
    accepted_at: exactUtcSecond(acceptedAt, 'V2 publication acceptance time'),
  });
}

export function graphPublicationReceiptDigestV2(receipt) {
  if (!receipt || receipt.schema !== GRAPH_PUBLICATION_RECEIPT_V2
      || receipt.protocol !== SEMANTIC_PROOF_V2 || receipt.publication_outcome !== 'ACCEPTED') {
    throw new Error('invalid V2 Graph terminal publication receipt');
  }
  exactClosedFields(receipt, GRAPH_TERMINAL_RECEIPT_FIELDS, 'Graph terminal receipt');
  for (const [field, label] of [
    ['transaction_id', 'terminal transaction'],
    ['coordination_identity_digest', 'terminal coordination'],
    ['release_subject_digest', 'terminal release subject'],
    ['prospective_publication_plan_digest', 'terminal plan'],
    ['derived_consumer_registry_digest', 'terminal registry'],
    ['handover_generation_digest', 'terminal handover generation'],
    ['d0_authority_digest', 'terminal D0'],
    ['d1_authority_digest', 'terminal D1'],
    ['d2_authority_digest', 'terminal D2'],
    ['factory_closure_receipt_digest', 'terminal Factory closure'],
    ['factory_prepare_receipt_digest', 'terminal Factory prepare'],
    ['native_readback_set_digest', 'terminal native readback set'],
    ['graph_owned_observation_digest', 'terminal Graph observation'],
    ['grant_consumption_receipt_digest', 'terminal grant consumption'],
  ]) exactDigest(receipt[field], label);
  exactGitIdentity(receipt.graph_commit, 'terminal Graph commit');
  exactGitIdentity(receipt.graph_tree, 'terminal Graph tree');
  exactGitIdentity(receipt.factory_commit, 'terminal Factory commit');
  exactGitIdentity(receipt.factory_tree, 'terminal Factory tree');
  exactUtcSecond(receipt.accepted_at, 'terminal accepted time');
  sortedUniqueDigests(receipt.mandatory_consumer_identity_digests,
    'terminal mandatory consumers', { nonempty: true });
  sortedUniqueDigests(receipt.explicit_authorization_grant_digests,
    'terminal explicit authorization grants');
  sortedUniqueDigests(receipt.native_successor_readback_digests,
    'terminal native successor readbacks', { nonempty: true });
  if (receipt.mandatory_consumer_identity_digests.length !== 7
      || receipt.native_successor_readback_digests.length !== 7
      || receipt.ownership_state !== 'V2_TERMINAL_OWNER'
      || receipt.current_v1_publication_state !== 'RETIRED') {
    throw new Error('Graph terminal receipt does not establish exact native V2 ownership');
  }
  return canonicalDigestV2(receipt);
}

export function assertGraphNativeOwnershipObservationV2(observation, plan = null) {
  exactClosedFields(observation, GRAPH_NATIVE_OWNERSHIP_OBSERVATION_FIELDS,
    'Graph native ownership observation');
  if (observation.schema !== 'usf-graph-native-ownership-observation-v2'
      || observation.ownership_state !== 'V2_TERMINAL_OWNER'
      || observation.current_v1_publication_state !== 'RETIRED'
      || observation.d2_fence_state !== 'V2_HANDOVER_PENDING') {
    throw new Error('Graph native ownership observation state is not terminal V2');
  }
  exactClosedFields(observation.validation_currentness, [
    'admission_receipt_digest', 'digest', 'evidence_set_digest',
    'handover_generation_digest', 'lineage_length', 'proof_result_digest',
    'semantic_scope_digest', 'source', 'state', 'trusted_now', 'valid_from', 'valid_until',
    'validation_root_payload_digest',
  ].sort(), 'Graph native validation-currentness observation');
  const currentness = observation.validation_currentness;
  for (const [field, label] of [
    ['admission_receipt_digest', 'native currentness admission'],
    ['digest', 'native currentness identity'],
    ['evidence_set_digest', 'native currentness evidence set'],
    ['handover_generation_digest', 'native currentness generation'],
    ['proof_result_digest', 'native currentness proof'],
    ['semantic_scope_digest', 'native currentness semantic scope'],
    ['validation_root_payload_digest', 'native currentness root'],
  ]) exactDigest(currentness[field], label);
  exactUtcSecond(currentness.trusted_now, 'native currentness trusted now');
  exactUtcSecond(currentness.valid_from, 'native currentness validity start');
  exactUtcSecond(currentness.valid_until, 'native currentness validity end');
  if (!Number.isSafeInteger(currentness.lineage_length) || currentness.lineage_length < 0
      || !['HANDOVER_GENESIS', 'V2_MATERIALISATION_CURRENTNESS_DESCENDANT']
        .includes(currentness.source)
      || !['CURRENT', 'STALE'].includes(currentness.state)
      || (currentness.state === 'CURRENT'
        ? observation.execution_state !== 'EXECUTION_PERMITTED'
        : observation.execution_state !== 'BLOCKED_VALIDATION_CURRENTNESS')) {
    throw new Error('Graph native validation-currentness execution state is invalid');
  }
  if (canonicalDigestV2(currentness) !== observation.currentness_observation_digest) {
    throw new Error('Graph native dynamic currentness observation digest is invalid');
  }
  for (const [field, label] of [
    ['authority_digest', 'Graph native observed authority'],
    ['authority_observation_digest', 'Graph native authority observation'],
    ['factory_closure_receipt_digest', 'Graph native Factory closure'],
    ['grant_consumption_receipt_digest', 'Graph native grant consumption'],
    ['graph_owned_observation_digest', 'Graph native Graph-owned observation'],
    ['graph_reservation_digest', 'Graph native publication reservation'],
    ['handover_generation_digest', 'Graph native handover generation'],
    ['terminal_receipt_digest', 'Graph native terminal receipt'],
  ]) exactDigest(observation[field], label);
  exactGitIdentity(observation.graph_commit, 'Graph native running commit');
  exactGitIdentity(observation.graph_tree, 'Graph native running tree');
  for (const [digestField, uriField, label] of [
    ['factory_closure_receipt_digest', 'factory_closure_receipt_cas_uri', 'Factory closure'],
    ['grant_consumption_receipt_digest', 'grant_consumption_receipt_cas_uri', 'grant consumption'],
    ['terminal_receipt_digest', 'terminal_receipt_cas_uri', 'terminal receipt'],
  ]) {
    if (observation[uriField] !== `cas://sha256/${observation[digestField].slice(7)}`) {
      throw new Error(`Graph native ${label} CAS binding is invalid`);
    }
  }
  if (!Array.isArray(observation.graph_native_successors)
      || !Array.isArray(observation.graph_native_successor_readbacks)
      || observation.graph_native_successors.length !== 2
      || observation.graph_native_successor_readbacks.length !== 2) {
    throw new Error('Graph native ownership observation requires two exact native successors');
  }
  const successorKinds = observation.graph_native_successors.map((item) => item.consumer_kind);
  const readbackKinds = observation.graph_native_successor_readbacks
    .map((item) => item.consumer_kind);
  if (canonicalJsonV2(successorKinds) !== canonicalJsonV2(GRAPH_OWNED_CONSUMER_KINDS)
      || canonicalJsonV2(readbackKinds) !== canonicalJsonV2(GRAPH_OWNED_CONSUMER_KINDS)) {
    throw new Error('Graph native ownership successor ordering/set is not canonical');
  }
  const expectedByKind = plan === null ? null : new Map(
    plan.derived_consumers
      .filter((item) => item.expected_successor.storage_owner === 'GRAPH')
      .map((item) => [item.consumer_kind, item.expected_successor]),
  );
  if (plan !== null) {
    assertProspectivePublicationPlanV2(plan);
    if (observation.authority_digest !== plan.predicted_d2_authority_digest
        || observation.handover_generation_digest !== plan.handover_generation_digest
        || observation.graph_commit !== plan.graph_protected_commit
        || observation.graph_tree !== plan.graph_protected_tree) {
      throw new Error('Graph native ownership observation differs from the exact plan');
    }
  }
  for (let index = 0; index < observation.graph_native_successors.length; index += 1) {
    const successor = observation.graph_native_successors[index];
    exactClosedFields(successor, successor.explicit_authorization_grant_digest === undefined
      ? DERIVED_CONSUMER_SUCCESSOR_FIELDS
      : [...DERIVED_CONSUMER_SUCCESSOR_FIELDS, 'explicit_authorization_grant_digest'].sort(),
    'Graph native observed successor');
    assertNativeSuccessorPayloadV2(successor);
    const readback = observation.graph_native_successor_readbacks[index];
    nativeSuccessorReadbackDigestV2(readback);
    if (successor.storage_owner !== 'GRAPH'
        || successor.handover_generation_digest !== observation.handover_generation_digest
        || readback.successor_record_digest !== canonicalDigestV2(successor)
        || readback.handover_generation_digest !== observation.handover_generation_digest
        || readback.native_payload_digest !== successor.payload_digest
        || readback.native_payload_cas_uri !== successor.payload_cas_uri
        || readback.native_payload_size !== successor.payload_size
        || (expectedByKind !== null
          && canonicalJsonV2(successor) !== canonicalJsonV2(expectedByKind.get(successor.consumer_kind)))) {
      throw new Error('Graph native ownership successor/readback binding is not exact');
    }
  }
  if (graphOwnedNativeObservationDigestV2(
    observation.handover_generation_digest,
    observation.graph_native_successor_readbacks,
  ) !== observation.graph_owned_observation_digest) {
    throw new Error('Graph native ownership observation digest differs from production readbacks');
  }
  const {
    currentness_observation_digest: _currentnessDigest,
    execution_state: _executionState,
    observation_identity_digest: observedDigest,
    ownership_identity_digest: observedOwnershipDigest,
    validation_currentness: _validationCurrentness,
    ...stableCore
  } = observation;
  const expectedOwnershipDigest = canonicalDigestV2(stableCore);
  if (observedOwnershipDigest !== expectedOwnershipDigest) {
    throw new Error('Graph native stable ownership identity differs from exact terminal state');
  }
  const expectedDigest = canonicalDigestV2({
    ...stableCore,
    currentness_observation_digest: observation.currentness_observation_digest,
    execution_state: observation.execution_state,
    ownership_identity_digest: observedOwnershipDigest,
    validation_currentness: observation.validation_currentness,
  });
  if (observedDigest !== expectedDigest) {
    throw new Error('Graph native ownership self identity differs from exact observation');
  }
  return Object.freeze(observation);
}

export function graphNativeOwnershipObservationDigestV2(observation, plan = null) {
  assertGraphNativeOwnershipObservationV2(observation, plan);
  return observation.observation_identity_digest;
}

export function graphNativeWorkPlanDigestV2(observation) {
  exactClosedFields(observation, GRAPH_NATIVE_WORK_PLAN_FIELDS,
    'Graph native V2 work-plan observation');
  if (observation.schema !== 'usf-graph-native-work-plan-v2'
      || observation.current_v1_publication_state !== 'RETIRED'
      || !['CURRENT', 'STALE'].includes(observation.validation_currentness_state)
      || (observation.validation_currentness_state === 'CURRENT'
        ? observation.action !== 'PROCEED'
          || observation.reason !== 'V2_NATIVE_VALIDATION_CURRENT'
        : observation.action !== 'BLOCK'
          || observation.reason !== 'V2_NATIVE_VALIDATION_CURRENTNESS_STALE')) {
    throw new Error('Graph native V2 work-plan decision is invalid');
  }
  for (const [field, label] of [
    ['authority_digest', 'native work-plan authority'],
    ['currentness_observation_digest', 'native work-plan currentness observation'],
    ['handover_generation_digest', 'native work-plan generation'],
    ['ownership_identity_digest', 'native work-plan ownership'],
    ['terminal_receipt_digest', 'native work-plan terminal receipt'],
    ['validation_currentness_digest', 'native work-plan currentness'],
    ['validation_currentness_root_payload_digest', 'native work-plan validation root'],
  ]) exactDigest(observation[field], label);
  exactUtcSecond(observation.trusted_now, 'native work-plan trusted now');
  exactUtcSecond(observation.valid_until, 'native work-plan validity end');
  const { observation_identity_digest: observed, ...core } = observation;
  const expected = canonicalDigestV2(core);
  if (observed !== expected) {
    throw new Error('Graph native V2 work-plan observation identity is invalid');
  }
  return expected;
}

export class HermeticSemanticProofV2Journal {
  constructor(snapshot) {
    this.entries = [];
    this.publicationState = null;
    this.terminalReceipt = null;
    this.terminalReceiptDigest = null;
    this.grantConsumed = false;
    this.boundaryReceipts = {};
    if (snapshot !== undefined) this.#load(snapshot);
  }

  #load(snapshotBytes) {
    const value = JSON.parse(Buffer.from(snapshotBytes).toString('utf8'));
    if (value.schema !== 'usf-hermetic-semantic-proof-v2-journal') {
      throw new Error('V2 journal snapshot schema mismatch');
    }
    if (canonicalJsonV2(Object.keys(value).sort()) !== canonicalJsonV2(JOURNAL_SNAPSHOT_FIELDS)) {
      throw new Error('V2 journal snapshot fields are not the closed protocol shape');
    }
    if (!Array.isArray(value.entries) || !value.boundary_receipts
        || typeof value.boundary_receipts !== 'object' || Array.isArray(value.boundary_receipts)
        || typeof value.grant_consumed !== 'boolean') {
      throw new Error('V2 journal snapshot structure is invalid');
    }
    this.entries = value.entries;
    this.publicationState = value.publication_state;
    this.terminalReceipt = value.terminal_receipt;
    this.terminalReceiptDigest = value.terminal_receipt_digest;
    this.grantConsumed = value.grant_consumed;
    this.boundaryReceipts = value.boundary_receipts;
  }

  snapshotBytes() {
    return Buffer.from(canonicalJsonV2({
      schema: 'usf-hermetic-semantic-proof-v2-journal',
      entries: this.entries,
      publication_state: this.publicationState,
      terminal_receipt: this.terminalReceipt,
      terminal_receipt_digest: this.terminalReceiptDigest,
      grant_consumed: this.grantConsumed,
      boundary_receipts: this.boundaryReceipts,
    }));
  }

  state() {
    return this.entries.at(-1)?.state ?? null;
  }

  append(state, inputs, trustedAt, receipts = []) {
    if (JOURNAL_ORDER[this.entries.length] !== state) {
      throw new Error('V2 publication journal state transition is not canonical');
    }
    const entry = Object.freeze({
      schema: GRAPH_PUBLICATION_JOURNAL_V2,
      state,
      transaction_id: closureTransactionIdV2(inputs.plan),
      coordination_identity_digest: coordinationIdentity(inputs),
      release_subject_digest: inputs.plan.release_subject_digest,
      prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(inputs.plan),
      d0_authority_digest: inputs.plan.d0_authority_digest,
      d1_authority_digest: JOURNAL_ORDER.indexOf(state) >= JOURNAL_ORDER.indexOf('D1_COMMITTED')
        ? inputs.plan.predicted_d1_authority_digest : null,
      d2_authority_digest: JOURNAL_ORDER.indexOf(state) >= JOURNAL_ORDER.indexOf('D2_COMMITTED')
        ? inputs.plan.predicted_d2_authority_digest : null,
      receipt_digests: Object.freeze([...new Set(receipts)].sort()),
      previous_entry_digest: this.entries.length
        ? canonicalDigestV2(this.entries.at(-1)) : null,
      trusted_at: exactUtcSecond(trustedAt, 'V2 journal trusted time'),
    });
    this.entries.push(entry);
    return entry;
  }
}

function readDurableSemanticProofV2Journal(journalPath) {
  if (!existsSync(journalPath)) return new HermeticSemanticProofV2Journal();
  const stat = lstatSync(journalPath);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600) {
    throw new Error('V2 publication journal must be an owner-only regular file');
  }
  return new HermeticSemanticProofV2Journal(readFileSync(journalPath));
}

// Node disables the fsync API outright under --permission, so a process inside
// the permission model cannot take a storage durability barrier at all. This is
// observed from the process rather than declared by a caller or an env var; the
// write remains atomic (open wx -> write -> link -> byte readback) either way.
const DURABILITY_BARRIER = process.permission === undefined
  ? 'FSYNC'
  : 'UNAVAILABLE_UNDER_NODE_PERMISSION_MODEL';

function durabilityBarrierSync(descriptor) {
  if (DURABILITY_BARRIER === 'FSYNC') fsyncSync(descriptor);
}

function publicationJournalProcessIdentity(pid = process.pid) {
  let processStat;
  try { processStat = readFileSync(`/proc/${pid}/stat`, 'utf8'); } catch { return null; }
  const close = processStat.lastIndexOf(')');
  const fields = close < 0 ? [] : processStat.slice(close + 2).trim().split(/\s+/);
  const bootId = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
  if (!/^\d+$/.test(fields[19] || '') || !/^[0-9a-f-]{36}$/.test(bootId)) return null;
  return Object.freeze({
    schema: 'usf-semantic-publication-journal-lock-v2',
    boot_id: bootId,
    pid,
    process_start_ticks: fields[19],
  });
}

// Liveness probing needs /proc, which the Node permission model does not grant.
// Losing it must make the lock STRONGER, not weaker: a holder whose liveness
// nobody can verify still gets exclusion through the exclusive link, and no
// holder may be evicted as stale unless its death is positively provable.
const JOURNAL_LOCK_LIVENESS_SCHEMA = 'usf-semantic-publication-journal-lock-v2';
const JOURNAL_LOCK_UNVERIFIABLE_SCHEMA =
  'usf-semantic-publication-journal-lock-v2-unverifiable-liveness';

function publicationJournalHolderIdentity() {
  const identity = publicationJournalProcessIdentity();
  if (identity !== null) return identity;
  return Object.freeze({
    schema: JOURNAL_LOCK_UNVERIFIABLE_SCHEMA,
    boot_id: null,
    pid: process.pid,
    process_start_ticks: null,
  });
}

function publicationJournalHolderIsProvablyGone(observed) {
  // Only the strong schema records enough to disprove liveness, and only a
  // successful probe of the recorded pid counts as a disproof. An unreadable
  // /proc yields null, which means "unknown" -- never "gone".
  if (observed?.schema !== JOURNAL_LOCK_LIVENESS_SCHEMA) return false;
  const live = publicationJournalProcessIdentity(observed.pid);
  if (live === null) return false;
  return canonicalJsonV2(live) !== canonicalJsonV2(observed);
}

function acquirePublicationJournalLock(lockPath) {
  const identity = publicationJournalHolderIdentity();
  const bytes = Buffer.from(canonicalJsonV2(identity), 'utf8');
  const temporary = `${lockPath}.${process.pid}.${sha256V2(bytes).slice(7)}.tmp`;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (existsSync(temporary)) {
      const stat = lstatSync(temporary);
      if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(temporary) !== temporary) {
        throw new Error('V2 publication journal temporary lock is unsafe');
      }
      unlinkSync(temporary);
    }
    let descriptor;
    try {
      descriptor = openSync(temporary, 'wx', 0o600);
      writeFileSync(descriptor, bytes);
      durabilityBarrierSync(descriptor);
      closeSync(descriptor);
      descriptor = undefined;
      try { linkSync(temporary, lockPath); } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
      try { unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    const lockStat = lstatSync(lockPath);
    if (!lockStat.isFile() || lockStat.isSymbolicLink() || realpathSync(lockPath) !== lockPath) {
      throw new Error('V2 publication journal lock is unsafe');
    }
    const observedBytes = readFileSync(lockPath);
    if (observedBytes.equals(bytes)) {
      const directory = openSync(dirname(lockPath), 'r');
      try { durabilityBarrierSync(directory); } finally { closeSync(directory); }
      let released = false;
      return () => {
        if (released) return;
        if (!readFileSync(lockPath).equals(bytes)) {
          throw new Error('V2 publication journal lock ownership changed');
        }
        unlinkSync(lockPath);
        const directoryDescriptor = openSync(dirname(lockPath), 'r');
        try { durabilityBarrierSync(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
        released = true;
      };
    }
    let observed;
    try { observed = JSON.parse(observedBytes.toString('utf8')); } catch {
      throw new Error('V2 publication journal lock is not recoverable canonical JSON');
    }
    if (!publicationJournalHolderIsProvablyGone(observed)) {
      throw new Error('V2_PUBLICATION_JOURNAL_BUSY');
    }
    if (!readFileSync(lockPath).equals(observedBytes)) {
      throw new Error('V2 publication journal stale lock changed during recovery');
    }
    unlinkSync(lockPath);
  }
  throw new Error('V2 publication journal lock did not settle');
}

export async function advanceDurableSemanticProofV2Publication(inputs, {
  journalPath,
  journalIo = REAL_JOURNAL_IO,
} = {}) {
  if (typeof journalPath !== 'string' || !isAbsolute(journalPath)) {
    throw new Error('V2 publication journal path must be exact and absolute');
  }
  const journalDirectory = dirname(journalPath);
  mkdirSync(journalDirectory, { recursive: true, mode: 0o700 });
  const directoryStat = lstatSync(journalDirectory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error('V2 publication journal directory is unsafe');
  }
  chmodSync(journalDirectory, 0o700);
  const lockPath = `${journalPath}.lock`;
  let releaseLock;
  try {
    releaseLock = acquirePublicationJournalLock(lockPath);
    const journal = readDurableSemanticProofV2Journal(journalPath);
    const result = await advanceSemanticProofV2Publication({ ...inputs, journal });
    if (journalIo === REAL_JOURNAL_IO && existsSync(`${journalPath}.tmp`)) {
      const temporary = `${journalPath}.tmp`;
      const stat = lstatSync(temporary);
      if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(temporary) !== temporary) {
        throw new Error('V2 publication journal recovery temporary is unsafe');
      }
      unlinkSync(temporary);
    }
    journalIo.write(journalPath, journal.snapshotBytes());
    chmodSync(journalPath, 0o600);
    const observed = readDurableSemanticProofV2Journal(journalPath);
    if (canonicalJsonV2(JSON.parse(observed.snapshotBytes().toString('utf8')))
        !== canonicalJsonV2(JSON.parse(journal.snapshotBytes().toString('utf8')))) {
      throw new Error('V2 publication journal atomic read-back differs');
    }
    return Object.freeze({
      ...result,
      journalDigest: sha256V2(journal.snapshotBytes()),
      journalPath,
    });
  } finally {
    if (releaseLock !== undefined) releaseLock();
  }
}

function validateJournal(journal, inputs, trustedAt) {
  if (!(journal instanceof HermeticSemanticProofV2Journal)) {
    throw new Error('V2 publisher requires an exact durable journal adapter');
  }
  const expectedCoordination = coordinationIdentity(inputs);
  const immutableReceiptDigests = [
    prospectivePublicationPlanDigestV2(inputs.plan),
    inputs.plan.derived_consumer_registry_digest,
    inputs.plan.identity_dependency_graph_digest,
  ];
  if (journal.entries.length > JOURNAL_ORDER.length
      || journal.entries.some((entry, index) => entry.state !== JOURNAL_ORDER[index]
        || entry.schema !== GRAPH_PUBLICATION_JOURNAL_V2
        || canonicalJsonV2(Object.keys(entry).sort()) !== canonicalJsonV2(JOURNAL_ENTRY_FIELDS)
        || entry.coordination_identity_digest !== expectedCoordination
        || entry.transaction_id !== closureTransactionIdV2(inputs.plan)
        || entry.release_subject_digest !== inputs.plan.release_subject_digest
        || entry.prospective_publication_plan_digest
          !== prospectivePublicationPlanDigestV2(inputs.plan)
        || entry.d0_authority_digest !== inputs.plan.d0_authority_digest
        || entry.d1_authority_digest !== (index >= JOURNAL_ORDER.indexOf('D1_COMMITTED')
          ? inputs.plan.predicted_d1_authority_digest : null)
        || entry.d2_authority_digest !== (index >= JOURNAL_ORDER.indexOf('D2_COMMITTED')
          ? inputs.plan.predicted_d2_authority_digest : null)
        || canonicalJsonV2(entry.receipt_digests)
          !== canonicalJsonV2([...new Set(entry.receipt_digests || [])].sort())
        || (entry.receipt_digests || []).some((digest) => !SHA256.test(digest))
        || immutableReceiptDigests.some((digest) => !entry.receipt_digests?.includes(digest))
        || entry.previous_entry_digest !== (index
          ? canonicalDigestV2(journal.entries[index - 1]) : null)
        || !UTC_SECOND.test(entry.trusted_at || '')
        || (index > 0 && entry.trusted_at < journal.entries[index - 1].trusted_at))) {
    throw new Error('V2 publication journal drifted from the approved coordination contract');
  }
  if (journal.entries.length && trustedAt < journal.entries.at(-1).trusted_at) {
    throw new Error('V2 publication trusted time moved backwards');
  }
  const state = journal.state();
  const expectedBoundaryKeys = [
    ['RESERVED', 'grant_reservation'],
    ['D1_COMMITTED', 'd1_commit'],
    ['D1_DEPENDENCIES_OBSERVED', 'd1_observation'],
    ['D2_COMMITTED', 'd2_commit'],
    ['TERMINAL_RECEIPT_COMMITTED', 'grant_consumption'],
  ].filter(([boundary]) => state
    && JOURNAL_ORDER.indexOf(state) >= JOURNAL_ORDER.indexOf(boundary))
    .map(([, key]) => key);
  if (canonicalJsonV2(Object.keys(journal.boundaryReceipts).sort())
      !== canonicalJsonV2(expectedBoundaryKeys.sort())) {
    throw new Error('V2 publication boundary receipt set differs from its journal state');
  }
  Object.values(journal.boundaryReceipts).forEach((receipt) => {
    exactDigest(receipt, 'V2 publication boundary receipt');
  });
  if (state && JOURNAL_ORDER.indexOf(state) >= JOURNAL_ORDER.indexOf('D2_COMMITTED')) {
    const expectedState = state === 'CONSUMED' ? 'ACCEPTED' : 'COMMITTED_PENDING_DERIVED_CLOSURE';
    if (journal.publicationState !== expectedState) {
      throw new Error('D2 actionability state differs from the V2 journal');
    }
  } else if (journal.publicationState !== null) {
    throw new Error('V2 publication state exists before D2');
  }
  const terminalReached = state
    && JOURNAL_ORDER.indexOf(state) >= JOURNAL_ORDER.indexOf('TERMINAL_RECEIPT_COMMITTED');
  if (journal.grantConsumed !== Boolean(terminalReached)) {
    throw new Error('V2 durable grant consumption ordering differs from terminal closure');
  }
  if (terminalReached) {
    if (!journal.terminalReceipt || journal.terminalReceiptDigest
        !== graphPublicationReceiptDigestV2(journal.terminalReceipt)
        || journal.terminalReceipt.coordination_identity_digest !== expectedCoordination
        || journal.terminalReceipt.release_subject_digest !== inputs.plan.release_subject_digest
        || journal.terminalReceipt.prospective_publication_plan_digest
          !== prospectivePublicationPlanDigestV2(inputs.plan)
        || journal.terminalReceipt.derived_consumer_registry_digest
          !== inputs.plan.derived_consumer_registry_digest
        || journal.terminalReceipt.handover_generation_digest
          !== inputs.plan.handover_generation_digest
        || journal.terminalReceipt.d0_authority_digest !== inputs.plan.d0_authority_digest
        || journal.terminalReceipt.d1_authority_digest
          !== inputs.plan.predicted_d1_authority_digest
        || journal.terminalReceipt.d2_authority_digest
          !== inputs.plan.predicted_d2_authority_digest
        || journal.terminalReceipt.accepted_at !== inputs.terminal_receipt_at
        || journal.terminalReceipt.graph_commit !== inputs.graph_commit
        || journal.terminalReceipt.graph_tree !== inputs.graph_tree
        || journal.terminalReceipt.factory_commit !== inputs.factory_commit
        || journal.terminalReceipt.factory_tree !== inputs.factory_tree
        || journal.terminalReceipt.factory_prepare_receipt_digest
          !== factoryPrepareReceiptDigestV2(
            inputs.factory_prepare_receipt,
            inputs.plan,
            { factoryCommit: inputs.factory_commit, factoryTree: inputs.factory_tree },
          )
        || journal.terminalReceipt.grant_consumption_receipt_digest
          !== journal.boundaryReceipts.grant_consumption
        || journal.terminalReceipt.ownership_state !== 'V2_TERMINAL_OWNER'
        || journal.terminalReceipt.current_v1_publication_state !== 'RETIRED'
        || canonicalJsonV2(journal.terminalReceipt.mandatory_consumer_identity_digests)
          !== canonicalJsonV2(expectedClosure(inputs.plan).currentDigests)
        || canonicalJsonV2(journal.terminalReceipt.explicit_authorization_grant_digests)
          !== canonicalJsonV2(expectedClosure(inputs.plan).explicitGrantDigests)
        || journal.terminalReceipt.native_readback_set_digest
          !== inputs.factory_closure_receipt?.native_readback_set_digest
        || journal.terminalReceipt.graph_owned_observation_digest
          !== inputs.factory_closure_receipt?.graph_owned_observation_digest
        || canonicalJsonV2(journal.terminalReceipt.native_successor_readback_digests)
          !== canonicalJsonV2(inputs.factory_closure_receipt?.native_successor_readbacks
            ?.map(nativeSuccessorReadbackDigestV2).sort())
        || !inputs.factory_closure_receipt
        || journal.terminalReceipt.factory_closure_receipt_digest
          !== factoryClosureReceiptDigestV2(inputs.factory_closure_receipt, inputs.plan)) {
      throw new Error('V2 terminal receipt drifted from its approved transaction');
    }
  } else if (journal.terminalReceipt !== null || journal.terminalReceiptDigest !== null) {
    throw new Error('V2 terminal receipt exists before its durable journal boundary');
  }
  if (state === 'CONSUMED' && (!journal.grantConsumed || !journal.terminalReceipt)) {
    throw new Error('consumed V2 publication lacks terminal evidence');
  }
}

function recordBoundaryReceipt(journal, boundary, digest) {
  exactDigest(digest, `V2 ${boundary} receipt`);
  const existing = journal.boundaryReceipts[boundary];
  if (existing !== undefined && existing !== digest) {
    throw new Error(`V2 ${boundary} receipt fork rejected`);
  }
  journal.boundaryReceipts[boundary] = digest;
}

function requireAdapter(adapter) {
  const operations = [
    'reserveGrant',
    'commitD1',
    'observeD1',
    'commitD2',
    'persistTerminalReceipt',
    'consumeGrant',
    'verifyTerminalOwnership',
  ];
  if (!adapter || operations.some((operation) => typeof adapter[operation] !== 'function')) {
    throw new Error('V2 publisher requires the complete canonical Graph adapter');
  }
  return adapter;
}

export async function advanceSemanticProofV2Publication(inputs) {
  assertProspectivePublicationPlanV2(inputs.plan);
  const trustedAt = exactUtcSecond(inputs.trusted_at, 'V2 publication trusted time');
  const adapter = requireAdapter(inputs.graph_adapter);
  validateJournal(inputs.journal, inputs, trustedAt);
  const state = inputs.journal.state();
  const planDigest = prospectivePublicationPlanDigestV2(inputs.plan);
  const commonReceipts = [
    planDigest,
    inputs.plan.derived_consumer_registry_digest,
    inputs.plan.identity_dependency_graph_digest,
  ];

  if (state === null) {
    inputs.journal.append('PLANNED', inputs, trustedAt, commonReceipts);
    return Object.freeze({ state: 'PLANNED', terminal: false });
  }
  if (state === 'PLANNED') {
    const reservation = await adapter.reserveGrant(inputs);
    exactDigest(reservation?.digest, 'V2 grant reservation receipt');
    recordBoundaryReceipt(inputs.journal, 'grant_reservation', reservation.digest);
    inputs.journal.append('RESERVED', inputs, trustedAt, [...commonReceipts, reservation.digest]);
    return Object.freeze({
      graph_reservation_receipt: reservation.receipt,
      graph_reservation_receipt_digest: reservation.digest,
      state: 'RESERVED',
      terminal: false,
    });
  }
  if (state === 'RESERVED') {
    const graphReservationReceiptDigest = graphReservationReceiptDigestV2(
      inputs.graph_reservation_receipt,
      inputs.plan,
      { graphCommit: inputs.graph_commit, graphTree: inputs.graph_tree },
    );
    assertFactoryPrepareReceiptV2(inputs.factory_prepare_receipt, inputs.plan, {
      factoryCommit: inputs.factory_commit,
      factoryTree: inputs.factory_tree,
    });
    if (graphReservationReceiptDigest !== inputs.journal.boundaryReceipts.grant_reservation
        || inputs.factory_prepare_receipt.graph_reservation_receipt_digest
          !== graphReservationReceiptDigest) {
      throw new Error('Factory PREPARE does not consume the exact Graph reservation receipt');
    }
    const d1 = await adapter.commitD1(inputs);
    if (d1?.authority_digest !== inputs.plan.predicted_d1_authority_digest) {
      throw new Error('committed D1 differs from the prospective plan');
    }
    exactDigest(d1.receipt_digest, 'D1 commit receipt');
    recordBoundaryReceipt(inputs.journal, 'd1_commit', d1.receipt_digest);
    inputs.journal.append('D1_COMMITTED', inputs, trustedAt, [...commonReceipts, d1.receipt_digest]);
    return Object.freeze({ state: 'D1_COMMITTED', terminal: false });
  }
  if (state === 'D1_COMMITTED') {
    const observation = await adapter.observeD1(inputs);
    if (observation?.authority_digest !== inputs.plan.predicted_d1_authority_digest
        || canonicalJsonV2(observation.dependency_identity_digests)
          !== canonicalJsonV2(inputs.plan.d1_dependency_identity_digests)) {
      throw new Error('D1 observation differs from the prospective plan');
    }
    exactDigest(observation.receipt_digest, 'D1 observation receipt');
    recordBoundaryReceipt(inputs.journal, 'd1_observation', observation.receipt_digest);
    inputs.journal.append('D1_DEPENDENCIES_OBSERVED', inputs, trustedAt, [
      ...commonReceipts,
      observation.receipt_digest,
      ...inputs.plan.d1_dependency_identity_digests,
    ]);
    return Object.freeze({ state: 'D1_DEPENDENCIES_OBSERVED', terminal: false });
  }
  if (state === 'D1_DEPENDENCIES_OBSERVED') {
    const d2 = await adapter.commitD2(inputs);
    if (d2?.authority_digest !== inputs.plan.predicted_d2_authority_digest
        || d2.evaluated_authority_digest !== inputs.plan.predicted_d1_authority_digest) {
      throw new Error('committed D2 differs from the exact D1-bound prospective plan');
    }
    exactDigest(d2.receipt_digest, 'D2 commit receipt');
    recordBoundaryReceipt(inputs.journal, 'd2_commit', d2.receipt_digest);
    inputs.journal.publicationState = 'COMMITTED_PENDING_DERIVED_CLOSURE';
    inputs.journal.append('D2_COMMITTED', inputs, trustedAt, [...commonReceipts, d2.receipt_digest]);
    return Object.freeze({
      state: 'D2_COMMITTED',
      publicationState: inputs.journal.publicationState,
      terminal: false,
    });
  }
  if (state === 'D2_COMMITTED') {
    if (inputs.factory_closure_receipt === undefined) {
      return Object.freeze({
        state,
        publicationState: inputs.journal.publicationState,
        terminal: false,
      });
    }
    const closure = assertFactoryClosureReceiptV2(inputs.factory_closure_receipt, inputs.plan);
    if (closure.graph_d1_commit_receipt_digest !== inputs.journal.boundaryReceipts.d1_commit
        || closure.graph_d1_observation_receipt_digest
          !== inputs.journal.boundaryReceipts.d1_observation
        || closure.graph_d2_commit_receipt_digest !== inputs.journal.boundaryReceipts.d2_commit) {
      throw new Error('Factory closure receipt is not bound to exact Graph D1/D2 receipts');
    }
    const closureDigest = factoryClosureReceiptDigestV2(closure, inputs.plan);
    inputs.journal.append('DERIVED_CLOSURE_VERIFIED', inputs, trustedAt, [
      ...commonReceipts,
      closureDigest,
      ...closure.mandatory_consumer_identity_digests,
    ]);
    return Object.freeze({ state: 'DERIVED_CLOSURE_VERIFIED', terminal: false });
  }
  if (state === 'DERIVED_CLOSURE_VERIFIED') {
    const closure = assertFactoryClosureReceiptV2(inputs.factory_closure_receipt, inputs.plan);
    if (closure.graph_d1_commit_receipt_digest !== inputs.journal.boundaryReceipts.d1_commit
        || closure.graph_d1_observation_receipt_digest
          !== inputs.journal.boundaryReceipts.d1_observation
        || closure.graph_d2_commit_receipt_digest !== inputs.journal.boundaryReceipts.d2_commit) {
      throw new Error('Factory closure receipt is not bound to exact Graph D1/D2 receipts');
    }
    const consumed = await adapter.consumeGrant(closure, inputs);
    exactDigest(consumed?.digest, 'V2 grant consumption receipt');
    const receipt = terminalReceipt(
      inputs, closure, inputs.terminal_receipt_at, consumed.digest,
    );
    const expectedDigest = graphPublicationReceiptDigestV2(receipt);
    const persisted = await adapter.persistTerminalReceipt(receipt, inputs);
    if (persisted?.digest !== expectedDigest) {
      throw new Error('persisted Graph terminal receipt differs from exact predicted bytes');
    }
    const ownership = await adapter.verifyTerminalOwnership(receipt, inputs);
    if (ownership?.ownership_state !== 'V2_TERMINAL_OWNER'
        || ownership.terminal_receipt_digest !== expectedDigest
        || ownership.handover_generation_digest !== inputs.plan.handover_generation_digest
        || ownership.authority_digest !== inputs.plan.predicted_d2_authority_digest) {
      throw new Error('Graph terminal ownership production reread is not exact');
    }
    recordBoundaryReceipt(inputs.journal, 'grant_consumption', consumed.digest);
    if (inputs.journal.terminalReceiptDigest
        && inputs.journal.terminalReceiptDigest !== expectedDigest) {
      throw new Error('Graph terminal publication receipt fork rejected');
    }
    inputs.journal.terminalReceipt = receipt;
    inputs.journal.terminalReceiptDigest = expectedDigest;
    inputs.journal.append('TERMINAL_RECEIPT_COMMITTED', inputs, trustedAt, [
      ...commonReceipts,
      expectedDigest,
      receipt.factory_closure_receipt_digest,
      consumed.digest,
    ]);
    inputs.journal.grantConsumed = true;
    return Object.freeze({ state: 'TERMINAL_RECEIPT_COMMITTED', terminal: false, receipt });
  }
  if (state === 'TERMINAL_RECEIPT_COMMITTED') {
    const receipt = inputs.journal.terminalReceipt;
    const ownership = await adapter.verifyTerminalOwnership(receipt, inputs);
    if (ownership?.ownership_state !== 'V2_TERMINAL_OWNER'
        || ownership.terminal_receipt_digest !== inputs.journal.terminalReceiptDigest) {
      throw new Error('V2 terminal ownership must reread before grant consumption');
    }
    if (!inputs.journal.grantConsumed
        || receipt.grant_consumption_receipt_digest
          !== inputs.journal.boundaryReceipts.grant_consumption) {
      throw new Error('V2 terminal ownership lacks durable prior grant consumption');
    }
    inputs.journal.publicationState = 'ACCEPTED';
    inputs.journal.append('CONSUMED', inputs, trustedAt, [
      ...commonReceipts,
      inputs.journal.terminalReceiptDigest,
      receipt.grant_consumption_receipt_digest,
    ]);
    return Object.freeze({ state: 'CONSUMED', terminal: true, receipt });
  }
  if (state === 'CONSUMED') {
    const ownership = await adapter.verifyTerminalOwnership(
      inputs.journal.terminalReceipt, inputs,
    );
    if (ownership?.ownership_state !== 'V2_TERMINAL_OWNER'
        || ownership.terminal_receipt_digest !== inputs.journal.terminalReceiptDigest
        || ownership.handover_generation_digest !== inputs.plan.handover_generation_digest) {
      throw new Error('V2 terminal journal cannot substitute for native ownership state');
    }
    return Object.freeze({
      state,
      terminal: true,
      receipt: Object.freeze(inputs.journal.terminalReceipt),
      ownership: Object.freeze(ownership),
    });
  }
  throw new Error('unsupported semantic-proof-v2 publication state');
}
