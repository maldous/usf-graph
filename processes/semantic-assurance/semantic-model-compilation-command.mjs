import { createHash } from 'node:crypto';
import {
  closeSync, existsSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync,
  readdirSync,
  realpathSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { DataFactory, Parser, Store, Writer } from 'n3';

import {
  canonicalGraphDigest,
  canonicalInventoryGraphDigest,
  canonicalNQuads,
  checkLocal,
  compile,
  CompilerError,
  shapeConstraints,
} from '../../capabilities/semantic-model-compilation/compiler.mjs';
import {
  integrityRules,
  loadManifest,
  managedGraphs,
} from '../../capabilities/semantic-model-compilation/manifest.mjs';
import {
  materializeAggregateCompilerAuthorityCandidateV2,
  parseAggregateCompilerAuthorityCandidateV2IdentityBytes,
} from '../../assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.mjs';
import {
  prepareAggregateCompilerAuthorityCandidatesV2,
} from '../../assurance/semantic-model-compilation/aggregate-compiler-proof-command.mjs';
import {
  readSemanticAuthorityWitness, semanticAuthorityInventoryDigest,
} from './semantic-authority-gateway.mjs';

export const SEMANTIC_MODEL_PATH = 'semantic-model';
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const V1_PATCH_HEADER = /^# (semantic-proof-v1) canonical-rdf-patch-v1 (base|stage1|stage2)$/;
const V2_PATCH_HEADER = /^# (semantic-proof-v2) canonical-rdf-patch-v1 (C1|C2)$/;
const EXTERNAL_AUTHORITY_DELTA_SCHEMA = 'usf-external-authority-conflict-resolution-delta-v1';
const IMPLEMENTATION_WORK_GRANT_DELTA_SCHEMA = 'usf-external-implementation-work-grant-delta-v1';
const IMPLEMENTATION_WORK_GRANT_ARTIFACT_ROLES = Object.freeze(['decision', 'grant', 'review', 'validation']);
const IMPLEMENTATION_WORK_GRANT_PURPOSE = 'V2_NATIVE_HANDOVER implementation only';
const IMPLEMENTATION_WORK_GRANT_ALLOWED_ACTIONS = Object.freeze([
  'candidate_existing_file_edit', 'candidate_signing_and_protection', 'cas_closure',
  'compilation_and_build', 'evidence_generation', 'independent_review',
  'isolated_read_only_rehearsal', 'tests',
]);
const IMPLEMENTATION_WORK_GRANT_DENIED_EFFECTS = Object.freeze([
  'a0_capture', 'authority_mutation', 'business_semantic_scope_expansion', 'deployment',
  'implicit_path_widening', 'learned_execution', 'production_write', 'provider_contact',
  'pruning', 'semantic_publication', 'v2_activation',
]);
const EXTERNAL_AUTHORITY_PROOF_SCHEMA = 'usf-authority-conflict-proof-decision-v1';
const EXTERNAL_AUTHORITY_DOMAIN = 'urn:usf:capabilityowner:semanticmodelcompilation';
const AUTHORITY_FINGERPRINT = 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D';
const AUTHORITY_PRINCIPAL = 'urn:usf:principal:matthewaldous';
const AUTHORITY_SIGNING_IDENTITY = 'urn:usf:signingidentity:matthewaldoussemanticproofv1';
const EXTERNAL_AUTHORITY_ARTIFACT_ROLES = Object.freeze(['inventory', 'operations', 'proof', 'review']);
const EXTERNAL_AUTHORITY_EVIDENCE_ROLES = Object.freeze(['inventory', 'operations', 'review']);
const EXTERNAL_AUTHORITY_NONCLAIMS = Object.freeze([
  'NO_FACTORY_MUTATION',
  'NO_PRODUCTION_PRUNING',
  'NO_PROVIDER_CONTACT',
  'NO_V2_ACTIVATION',
  'NO_DEPLOYMENT',
]);
const REQUIRED_HISTORY_MODE = ['lin', 'ear'].join('');
const ONE_PARENT_HISTORY_SHAPE = ['one-parent-lin', 'ear'].join('');
const NQUADS = 'application/n-quads';
const NTRIPLES = 'application/n-triples';
const TURTLE = 'text/turtle';
const USF_ONTOLOGY = 'urn:usf:ontology:';
const V2_D1_VALIDATION_BINDING =
  'urn:usf:validationselfpublicationbinding:compilersemanticenforcementaggregate';
const V2_D1_VALIDATION_EVIDENCE = Object.freeze([
  'urn:usf:validationevidence:compilersemanticenforcementaggregateevaluation',
  'urn:usf:validationevidence:compilersemanticenforcementaggregateexecution',
  'urn:usf:validationevidence:compilersemanticenforcementcompilervalidation',
]);
const V2_D1_BINDING_DEPENDENCY_PREDICATES = Object.freeze([
  'validationBindingEvaluationReceiptDigest',
  'validationBindingExecutionReceiptDigest',
  'validationBindingSourceScopeDigest',
  'validationNonPublicationDependencySetDigest',
]);
const V2_NATIVE_HANDOVER_FENCE = 'urn:usf:v2nativehandoverfence:current';
const V2_NATIVE_HANDOVER_FENCE_CLASS = `${USF_ONTOLOGY}V2NativeHandoverFence`;
const V2_HANDOVER_RESERVATION_SCHEMA = 'usf-v2-native-handover-reservation-v1';
const V2_HANDOVER_SUPERSESSION_SCHEMA = 'usf-v2-native-handover-supersession-v1';
// v1 records exist durably and are IMMUTABLE history: the first recovery was written before the
// fence observation was required. They stay readable verbatim; only new records may be written,
// and only under v2, which demands the complete effect inventory including the semantic fence.
const V2_HANDOVER_D1_RECOVERY_SCHEMA_LEGACY = 'usf-v2-native-handover-d1-recovery-v1';
const V2_HANDOVER_D1_RECOVERY_SCHEMA = 'usf-v2-native-handover-d1-recovery-v2';
const V2_HANDOVER_JOURNALED_D1_RECOVERY_EVIDENCE_SCHEMA =
  'usf-v2-native-handover-journaled-d1-recovery-evidence-v1';
const V2_HANDOVER_D1_RECONCILIATION_SCHEMA =
  'usf-v2-native-handover-d1-reconciliation-receipt-v1';
const V2_HANDOVER_FACTORY_PREPARE_BINDING_SCHEMA =
  'usf-v2-native-handover-factory-prepare-binding-v1';
const PUBLICATION_LANE_LOCK_SCHEMA = 'usf-semantic-publication-lane-lock-v1';
const PUBLICATION_LANE_UNVERIFIABLE_LOCK_SCHEMA =
  'usf-semantic-publication-lane-lock-v1-unverifiable-liveness';
const { defaultGraph, literal, namedNode, quad } = DataFactory;

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object' && !Buffer.isBuffer(value)
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function handoverD1ReconciliationReceiptDigest(receipt) {
  return sha256(Buffer.from(canonicalJson(receipt), 'utf8'));
}

// The lane root is always supplied by the caller. Reading process.env here, or
// defaulting to the host path, made the V1 retirement interlock depend on an
// ambient directory: an entrypoint could be pointed elsewhere, and any caller
// without that directory could not even ask whether V1 was reserved. Each
// entrypoint now resolves the root from its own explicit env argument.
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

// Atomic, immutable, durability-barriered publication of one exact byte sequence.
//
// Module scope because the abandonment journal needs the SAME primitive as the publication
// lane. Duplicating a durability/immutability primitive is how two subtly different
// definitions of "durable" come to exist in one system, so there is exactly one.
function publishImmutableFile(path, bytes, mode = 0o600) {
  const suffix = sha256(bytes).slice(7);
  const temporary = `${path}.${suffix}.tmp`;
  if (existsSync(temporary)) {
    const stat = lstatSync(temporary);
    if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(temporary) !== temporary) {
      throw new CompilerError('immutable semantic publication temporary is unsafe', {
        phase: 'candidate:publication-lane',
      });
    }
    unlinkSync(temporary);
  }
  let descriptor;
  let created = false;
  try {
    descriptor = openSync(temporary, 'wx', mode);
    writeFileSync(descriptor, bytes);
    durabilityBarrierSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    try { linkSync(temporary, path); created = true; } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    try { unlinkSync(temporary); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  if (!readFileSync(path).equals(bytes)) {
    throw new CompilerError('immutable semantic publication state fork rejected', {
      phase: 'candidate:publication-lane',
    });
  }
  const directory = openSync(dirname(path), 'r');
  try { durabilityBarrierSync(directory); } finally { closeSync(directory); }
  return created;
}

function createSemanticPublicationLaneV2(programmeRoot) {
  if (typeof programmeRoot !== 'string' || !isAbsolute(programmeRoot)) {
    throw new CompilerError('semantic publication lane root must be an exact absolute path', {
      phase: 'candidate:publication-lane',
    });
  }
  const requestedRoot = resolve(programmeRoot);
  const root = () => {
    if (!existsSync(requestedRoot)) {
      throw new CompilerError('semantic publication lane root is missing', {
        phase: 'candidate:publication-lane',
      });
    }
    const observed = realpathSync(requestedRoot);
    const stat = lstatSync(observed);
    if (observed !== requestedRoot || !stat.isDirectory() || stat.isSymbolicLink()) {
      throw new CompilerError('semantic publication lane root is unsafe', {
        phase: 'candidate:publication-lane',
      });
    }
    return observed;
  };
  const lockPath = () => `${root()}/semantic-publication-lane-v2.lock`;
  const reservationPath = () => `${root()}/v2-native-handover-reservation.json`;
  const prepareBindingPath = () => `${root()}/v2-native-handover-factory-prepare.json`;
  const supersessionDirectory = () => `${root()}/v2-native-handover-superseded`;
  // A generation's retirements are an append-only history, not one record. A SEQUENCING
  // retirement deliberately permits the same plan to reserve again, so that second reservation
  // must be retirable too -- otherwise the live pointer could never be released and the lane
  // would wedge permanently. Ordinal 1 keeps the original filename so existing records stay
  // exactly where they are.
  const supersessionPath = (generationDigest, ordinal = 1) => (
    ordinal <= 1
      ? `${supersessionDirectory()}/${generationDigest.slice(7)}.json`
      : `${supersessionDirectory()}/${generationDigest.slice(7)}.${ordinal}.json`
  );
  const d1RecoveryPath = (generationDigest) => (
    `${supersessionDirectory()}/${generationDigest.slice(7)}.d1-recovery.json`
  );
  const d1ReconciliationPath = (transactionId) => (
    `${supersessionDirectory()}/${transactionId.slice(7)}.d1-reconciliation.json`
  );
  const supersessionHistory = (generationDigest) => {
    const records = [];
    for (let ordinal = 1; ; ordinal += 1) {
      const path = supersessionPath(generationDigest, ordinal);
      if (!existsSync(path)) break;
      records.push(Object.freeze({
        ordinal,
        path,
        record: validateSupersession(readCanonicalFile(path)),
      }));
    }
    return records;
  };
  const readCanonicalFile = (path) => {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path) {
      throw new CompilerError('semantic publication reservation is unsafe', {
        phase: 'candidate:publication-lane',
      });
    }
    const bytes = readFileSync(path);
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); } catch {
      throw new CompilerError('semantic publication reservation is not JSON', {
        phase: 'candidate:publication-lane',
      });
    }
    if (!bytes.equals(Buffer.from(canonicalJson(value), 'utf8'))) {
      throw new CompilerError('semantic publication reservation is not canonical', {
        phase: 'candidate:publication-lane',
      });
    }
    return Object.freeze(value);
  };
  const readReservation = () => {
    const path = reservationPath();
    return existsSync(path) ? readCanonicalFile(path) : null;
  };
  const validateReservation = (value) => {
    exactObjectKeys(value, [
      'd0_authority_digest', 'handover_generation_digest',
      'prospective_publication_plan_digest', 'schema',
    ], 'V2 handover publication reservation');
    if (value.schema !== V2_HANDOVER_RESERVATION_SCHEMA
        || !SHA256.test(value.d0_authority_digest || '')
        || !SHA256.test(value.handover_generation_digest || '')
        || !SHA256.test(value.prospective_publication_plan_digest || '')) {
      throw new CompilerError('V2 handover publication reservation is invalid', {
        phase: 'candidate:publication-lane',
      });
    }
    return Object.freeze(value);
  };
  // A generation whose D1 committed but whose journal never recorded it. Unlike a supersession
  // this does NOT claim zero effect: it records the real authority transition, and is admitted
  // only when every LATER boundary is provably absent.
  const validateD1Recovery = (value) => {
    if (value?.schema === V2_HANDOVER_JOURNALED_D1_RECOVERY_EVIDENCE_SCHEMA) {
      validateJournaledD1RecoveryEvidence(value);
      return Object.freeze(value);
    }
    exactObjectKeys(value, [
      'd1_effect', 'recovered_at', 'recovery_reason', 'schema',
      'superseded_prepare_binding', 'superseded_reservation',
    ], 'V2 handover D1 recovery');
    const legacy = value.schema === V2_HANDOVER_D1_RECOVERY_SCHEMA_LEGACY;
    if (!legacy && value.schema !== V2_HANDOVER_D1_RECOVERY_SCHEMA) {
      throw new CompilerError('V2 handover D1 recovery schema is invalid', {
        phase: 'candidate:publication-lane',
      });
    }
    if (value.recovery_reason !== 'DEFECTIVE_AFTER_D1') {
      throw new CompilerError('V2 handover D1 recovery reason must be DEFECTIVE_AFTER_D1', {
        phase: 'candidate:publication-lane',
      });
    }
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.recovered_at || '')) {
      throw new CompilerError('V2 handover D1 recovery time is not exact', {
        phase: 'candidate:publication-lane',
      });
    }
    validateReservation(value.superseded_reservation);
    validatePrepareBinding(value.superseded_prepare_binding);
    const effect = value.d1_effect;
    // The SEMANTIC FENCE is part of the effect inventory, not an afterthought. The first version
    // of this record observed only later FACTORY boundaries (D2, successors, terminal receipt,
    // activation) and concluded the generation was cleanly recoverable -- while the D1 commit had
    // installed a handover-pending fence into semantic authority that retired V1 publication.
    // Local lane availability is not semantic-authority availability, and a recovery that cannot
    // see the fence cannot know what it is releasing.
    exactObjectKeys(effect, legacy ? [
      'activation_present', 'd1_journal_boundary_present', 'd2_authority_present',
      'journal_states', 'observed_post_d1_authority_digest', 'pre_d1_authority_digest',
      'successors_root_present', 'terminal_receipt_present',
    ] : [
      'activation_present', 'd1_journal_boundary_present', 'd2_authority_present',
      'graph_semantic_fence', 'journal_states', 'observed_post_d1_authority_digest',
      'pre_d1_authority_digest', 'successors_root_present', 'terminal_receipt_present',
    ], 'V2 handover D1 recovery effect');
    if (legacy) {
      // Readable, never writable, and never a basis for releasing anything again.
      return Object.freeze(value);
    }
    const fence = effect.graph_semantic_fence;
    exactObjectKeys(fence, [
      'authority_digest_at_observation', 'current_v1_publication_state', 'fence_content_digest',
      'generation_digest', 'installed', 'ownership_state', 'row_cardinality',
      'successor_binding_cardinality', 'terminal_floor_terminal',
    ], 'V2 handover D1 recovery fence observation');
    if (fence.authority_digest_at_observation !== effect.observed_post_d1_authority_digest) {
      throw new CompilerError('fence observation authority differs from the observed post-D1 authority', {
        phase: 'candidate:publication-lane',
      });
    }
    // An UNRESOLVED semantic fence must refuse. Releasing coordination state while authority
    // still retires V1 publication is what stranded the previous generation: the lane looked
    // clean and the system was still fenced.
    if (fence.installed !== false) {
      throw new CompilerError(
        'V2 handover D1 recovery refused: an unresolved Graph semantic handover fence is installed',
        { phase: 'candidate:publication-lane' },
      );
    }
    for (const [field, expected] of [['row_cardinality', 0], ['successor_binding_cardinality', 0]]) {
      if (fence[field] !== expected) {
        throw new CompilerError(`V2 handover D1 recovery refused: fence ${field} is not ${expected}`, {
          phase: 'candidate:publication-lane',
        });
      }
    }
    if (fence.terminal_floor_terminal !== false) {
      throw new CompilerError('V2 handover D1 recovery refused: durable terminal ownership exists', {
        phase: 'candidate:publication-lane',
      });
    }
    for (const field of ['pre_d1_authority_digest', 'observed_post_d1_authority_digest']) {
      if (!SHA256.test(effect[field] || '')) {
        throw new CompilerError(`V2 handover D1 recovery ${field} is not exact`, {
          phase: 'candidate:publication-lane',
        });
      }
    }
    // The whole point: authority MUST have moved. A recovery that claims no transition is a
    // supersession wearing the wrong name and belongs on the zero-effect path instead.
    if (effect.pre_d1_authority_digest === effect.observed_post_d1_authority_digest) {
      throw new CompilerError('V2 handover D1 recovery observed no authority transition', {
        phase: 'candidate:publication-lane',
      });
    }
    // Every LATER boundary must be absent, or this is not the stranded-at-D1 condition.
    for (const flag of ['d1_journal_boundary_present', 'd2_authority_present',
      'successors_root_present', 'terminal_receipt_present', 'activation_present']) {
      if (effect[flag] !== false) {
        throw new CompilerError(`V2 handover D1 recovery refused: ${flag}`, {
          phase: 'candidate:publication-lane',
        });
      }
    }
    if (!Array.isArray(effect.journal_states)
        || canonicalJson(effect.journal_states) !== canonicalJson(['PLANNED', 'RESERVED'])) {
      throw new CompilerError('V2 handover D1 recovery journal is not stranded at RESERVED', {
        phase: 'candidate:publication-lane',
      });
    }
    return Object.freeze(value);
  };

  // A reconciliation receipt records the exact Factory transaction that produced the Graph D1
  // candidate and binds it to Graph's already-durable D1 recovery record. It is deliberately a
  // receipt, not a lifecycle transition: recording it changes neither authority nor Factory.
  const validateD1Reconciliation = (value) => {
    exactObjectKeys(value, [
      'd1_recovery_record_digest', 'disposition', 'factory_graph_publication_receipt_keys',
      'factory_journal_states', 'factory_projection_digest', 'factory_terminal_receipt_keys',
      'graph_d1_candidate_digest', 'handover_generation_digest',
      'observed_post_d1_authority_digest', 'pre_d1_authority_digest',
      'prospective_publication_plan_digest', 'reconciled_at', 'schema', 'selection_state',
      'transaction_id',
    ], 'V2 handover D1 reconciliation receipt');
    if (value.schema !== V2_HANDOVER_D1_RECONCILIATION_SCHEMA) {
      throw new CompilerError('V2 handover D1 reconciliation receipt schema is invalid', {
        phase: 'candidate:publication-lane',
      });
    }
    for (const field of [
      'd1_recovery_record_digest', 'factory_projection_digest', 'graph_d1_candidate_digest',
      'handover_generation_digest', 'observed_post_d1_authority_digest',
      'pre_d1_authority_digest', 'prospective_publication_plan_digest', 'transaction_id',
    ]) {
      if (!SHA256.test(value[field] || '')) {
        throw new CompilerError(`V2 handover D1 reconciliation ${field} is not exact`, {
          phase: 'candidate:publication-lane',
        });
      }
    }
    if (value.disposition !== 'DEFECTIVE_AFTER_D1'
        || value.selection_state !== 'PERMANENTLY_EXCLUDED') {
      throw new CompilerError('V2 handover D1 reconciliation disposition is invalid', {
        phase: 'candidate:publication-lane',
      });
    }
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.reconciled_at || '')) {
      throw new CompilerError('V2 handover D1 reconciliation time is not exact', {
        phase: 'candidate:publication-lane',
      });
    }
    if (canonicalJson(value.factory_journal_states) !== canonicalJson(['PLANNED', 'RESERVED'])
        || canonicalJson(value.factory_graph_publication_receipt_keys) !== canonicalJson([])
        || canonicalJson(value.factory_terminal_receipt_keys) !== canonicalJson([])) {
      throw new CompilerError('V2 handover D1 reconciliation Factory boundary is not stranded', {
        phase: 'candidate:publication-lane',
      });
    }
    if (value.pre_d1_authority_digest === value.observed_post_d1_authority_digest) {
      throw new CompilerError('V2 handover D1 reconciliation observed no authority transition', {
        phase: 'candidate:publication-lane',
      });
    }
    return Object.freeze(value);
  };

  const d1Reconciliations = () => {
    const directory = supersessionDirectory();
    if (!existsSync(directory)) return [];
    return readdirSync(directory)
      .filter((name) => /^[0-9a-f]{64}\.d1-reconciliation\.json$/.test(name))
      .sort()
      .map((name) => validateD1Reconciliation(readCanonicalFile(`${directory}/${name}`)));
  };

  const assertNotD1Reconciled = (reservation) => {
    const receipt = d1Reconciliations().find((candidate) => (
      candidate.handover_generation_digest === reservation.handover_generation_digest
      || candidate.prospective_publication_plan_digest
        === reservation.prospective_publication_plan_digest
    ));
    if (receipt !== undefined) {
      throw new CompilerError(
        'V2_HANDOVER_DEFECTIVE_GENERATION_OR_PLAN_PERMANENTLY_EXCLUDED', {
          phase: 'candidate:publication-lane',
          reconciliation_receipt_digest: handoverD1ReconciliationReceiptDigest(receipt),
          transaction_id: receipt.transaction_id,
        },
      );
    }
  };

  const validateFactoryD1ReconciliationEvidence = (factoryEvidence) => {
    exactObjectKeys(factoryEvidence, [
      'candidate_digest', 'generation_id', 'graph_publication_receipt_keys',
      'journal_states', 'plan_digest', 'projection_digest', 'terminal_receipt_keys',
      'transaction_id',
    ], 'Factory D1 reconciliation evidence');
    for (const field of [
      'candidate_digest', 'generation_id', 'plan_digest', 'projection_digest', 'transaction_id',
    ]) {
      if (!SHA256.test(factoryEvidence[field] || '')) {
        throw new CompilerError(`Factory D1 reconciliation ${field} is not exact`, {
          phase: 'candidate:publication-lane',
        });
      }
    }
    if (canonicalJson(factoryEvidence.journal_states) !== canonicalJson(['PLANNED', 'RESERVED'])
        || canonicalJson(factoryEvidence.graph_publication_receipt_keys) !== canonicalJson([])
        || canonicalJson(factoryEvidence.terminal_receipt_keys) !== canonicalJson([])) {
      throw new CompilerError('Factory D1 reconciliation evidence is not stranded at RESERVED', {
        phase: 'candidate:publication-lane',
      });
    }
    return Object.freeze(factoryEvidence);
  };

  const persistD1Reconciliation = (recoveryValue, factoryEvidenceValue, reconciledAt) => {
    const factoryEvidence = validateFactoryD1ReconciliationEvidence(factoryEvidenceValue);
    const recovery = validateD1Recovery(recoveryValue);
    const normalized = normalizeHandoverAbandonmentD1Evidence(recovery);
    const reservation = recovery.superseded_reservation;
    if (reservation.handover_generation_digest !== factoryEvidence.generation_id
        || reservation.prospective_publication_plan_digest !== factoryEvidence.plan_digest) {
      throw new CompilerError('Factory D1 reconciliation differs from the recovered reservation', {
        phase: 'candidate:publication-lane',
      });
    }
    const recoveredFactoryStates = recovery.schema
        === V2_HANDOVER_JOURNALED_D1_RECOVERY_EVIDENCE_SCHEMA
      ? recovery.factory_projection.journal_states
      : recovery.d1_effect.journal_states;
    if (canonicalJson(recoveredFactoryStates) !== canonicalJson(factoryEvidence.journal_states)) {
      throw new CompilerError('Factory D1 reconciliation journal differs from Graph recovery', {
        phase: 'candidate:publication-lane',
      });
    }
    if (recovery.schema === V2_HANDOVER_JOURNALED_D1_RECOVERY_EVIDENCE_SCHEMA) {
      const { graph_terminal_required: _required, ...recordedFactory } = recovery.factory_projection;
      if (canonicalJson(recordedFactory) !== canonicalJson(factoryEvidence)
          || recovery.graph_d1_commit_receipt.candidate_digest
            !== factoryEvidence.candidate_digest) {
        throw new CompilerError(
          'Factory D1 reconciliation differs from the journaled D1 Factory projection', {
            phase: 'candidate:publication-lane',
          },
        );
      }
    }
    const receipt = validateD1Reconciliation({
      d1_recovery_record_digest: canonicalObjectDigest(recovery),
      disposition: 'DEFECTIVE_AFTER_D1',
      factory_graph_publication_receipt_keys: factoryEvidence.graph_publication_receipt_keys,
      factory_journal_states: factoryEvidence.journal_states,
      factory_projection_digest: factoryEvidence.projection_digest,
      factory_terminal_receipt_keys: factoryEvidence.terminal_receipt_keys,
      graph_d1_candidate_digest: factoryEvidence.candidate_digest,
      handover_generation_digest: factoryEvidence.generation_id,
      observed_post_d1_authority_digest:
        normalized.recoveryEffect.observed_post_d1_authority_digest,
      pre_d1_authority_digest: normalized.recoveryEffect.pre_d1_authority_digest,
      prospective_publication_plan_digest: factoryEvidence.plan_digest,
      reconciled_at: reconciledAt,
      schema: V2_HANDOVER_D1_RECONCILIATION_SCHEMA,
      selection_state: 'PERMANENTLY_EXCLUDED',
      transaction_id: factoryEvidence.transaction_id,
    });
    const conflicting = d1Reconciliations().find((candidate) => (
      candidate.handover_generation_digest === receipt.handover_generation_digest
      || candidate.prospective_publication_plan_digest
        === receipt.prospective_publication_plan_digest
    ));
    if (conflicting !== undefined && canonicalJson(conflicting) !== canonicalJson(receipt)) {
      throw new CompilerError('V2 handover D1 reconciliation subject fork rejected', {
        phase: 'candidate:publication-lane',
      });
    }
    const path = d1ReconciliationPath(receipt.transaction_id);
    if (!existsSync(path)) {
      publishImmutable(path, Buffer.from(canonicalJson(receipt), 'utf8'), 0o444);
    }
    const persisted = validateD1Reconciliation(readCanonicalFile(path));
    if (canonicalJson(persisted) !== canonicalJson(receipt)) {
      throw new CompilerError('V2 handover D1 reconciliation fork rejected', {
        phase: 'candidate:publication-lane',
      });
    }
    return persisted;
  };

  const validateSupersession = (value) => {
    exactObjectKeys(value, [
      'retired_at', 'retirement_reason', 'schema', 'superseded_reservation', 'zero_effect_proof',
    ], 'V2 handover reservation supersession');
    // DEFECTIVE bars the generation forever: its plan was proven unusable. SEQUENCING records
    // that the plan was sound and the retirement was only needed to re-establish an ordering
    // requirement, so the same generation may be reserved again. Barring both made retiring a
    // GOOD generation a dead end, because the generation digest is deterministic from authority
    // and source -- there is no different digest to reserve at the same authority.
    if (!['DEFECTIVE', 'SEQUENCING'].includes(value.retirement_reason)) {
      throw new CompilerError('V2 handover retirement reason must be DEFECTIVE or SEQUENCING', {
        phase: 'candidate:publication-lane',
      });
    }
    if (value.schema !== V2_HANDOVER_SUPERSESSION_SCHEMA) {
      throw new CompilerError('V2 handover reservation supersession is invalid', {
        phase: 'candidate:publication-lane',
      });
    }
    validateReservation(value.superseded_reservation);
    const proof = value.zero_effect_proof;
    // A reservation may only be retired while it demonstrably produced NOTHING durable. Each
    // flag is an observation the caller had to make against production state; all of them must
    // be present and false/absent, and the observed authority must still be the reservation's
    // own D0, or the reservation is not zero-effect and must never be retired.
    exactObjectKeys(proof, [
      'conflicting_publication_present', 'd1_authority_present', 'd2_authority_present',
      'grant_consumed', 'observed_authority_digest', 'successors_root_present',
      'terminal_receipt_present',
    ], 'V2 handover reservation zero-effect proof');
    if (proof.observed_authority_digest !== value.superseded_reservation.d0_authority_digest) {
      throw new CompilerError('V2 handover supersession observed a different authority', {
        phase: 'candidate:publication-lane',
      });
    }
    for (const flag of ['conflicting_publication_present', 'd1_authority_present',
      'd2_authority_present', 'grant_consumed', 'successors_root_present',
      'terminal_receipt_present']) {
      if (proof[flag] !== false) {
        throw new CompilerError(`V2 handover supersession refused: ${flag}`, {
          phase: 'candidate:publication-lane',
        });
      }
    }
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.retired_at || '')) {
      throw new CompilerError('V2 handover supersession retirement time is not exact', {
        phase: 'candidate:publication-lane',
      });
    }
    return Object.freeze(value);
  };
  const validatePrepareBinding = (value) => {
    exactObjectKeys(value, [
      'factory_prepare_receipt_digest', 'handover_generation_digest',
      'prospective_publication_plan_digest', 'reservation_digest', 'schema',
    ], 'V2 handover Factory prepare binding');
    if (value.schema !== V2_HANDOVER_FACTORY_PREPARE_BINDING_SCHEMA
        || !SHA256.test(value.factory_prepare_receipt_digest || '')
        || !SHA256.test(value.handover_generation_digest || '')
        || !SHA256.test(value.prospective_publication_plan_digest || '')
        || !SHA256.test(value.reservation_digest || '')) {
      throw new CompilerError('V2 handover Factory prepare binding is invalid', {
        phase: 'candidate:publication-lane',
      });
    }
    return Object.freeze(value);
  };
  const processIdentity = (pid = process.pid) => {
    let stat;
    try { stat = readFileSync(`/proc/${pid}/stat`, 'utf8'); } catch { return null; }
    const close = stat.lastIndexOf(')');
    const fields = close < 0 ? [] : stat.slice(close + 2).trim().split(/\s+/);
    const bootId = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
    if (!/^\d+$/.test(fields[19] || '')
        || !/^[0-9a-f-]{36}$/.test(bootId)) return null;
    return Object.freeze({
      boot_id: bootId,
      pid,
      process_start_ticks: fields[19],
      schema: PUBLICATION_LANE_LOCK_SCHEMA,
    });
  };
  const validateLock = (value) => {
    exactObjectKeys(value, ['boot_id', 'pid', 'process_start_ticks', 'schema'],
      'semantic publication lane lock');
    const unverifiable = value.schema === PUBLICATION_LANE_UNVERIFIABLE_LOCK_SCHEMA;
    if ((value.schema !== PUBLICATION_LANE_LOCK_SCHEMA && !unverifiable)
        || !Number.isSafeInteger(value.pid) || value.pid < 1
        || (unverifiable
          ? value.process_start_ticks !== null || value.boot_id !== null
          : !/^\d+$/.test(value.process_start_ticks || '')
            || !/^[0-9a-f-]{36}$/.test(value.boot_id || ''))) {
      throw new CompilerError('semantic publication lane lock is invalid', {
        phase: 'candidate:publication-lane',
      });
    }
    return Object.freeze(value);
  };
  // A holder that could not read /proc records that fact instead of failing to
  // take the lane at all. Its liveness can never be disproved, so it is never
  // evicted as stale -- the unverifiable case is strictly more conservative.
  const holderIdentity = () => processIdentity() ?? Object.freeze({
    boot_id: null,
    pid: process.pid,
    process_start_ticks: null,
    schema: PUBLICATION_LANE_UNVERIFIABLE_LOCK_SCHEMA,
  });
  const holderIsProvablyGone = (observed) => {
    if (observed.schema !== PUBLICATION_LANE_LOCK_SCHEMA) return false;
    const live = processIdentity(observed.pid);
    return live !== null && canonicalJson(live) !== canonicalJson(observed);
  };
  const publishImmutable = publishImmutableFile;
  const acquire = () => {
    const path = lockPath();
    const bytes = Buffer.from(canonicalJson(holderIdentity()), 'utf8');
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        if (publishImmutable(path, bytes)) break;
        const observedBytes = readFileSync(path);
        const observed = validateLock(readCanonicalFile(path));
        if (!holderIsProvablyGone(observed)) {
          throw new CompilerError('SEMANTIC_PUBLICATION_LANE_BUSY', {
            phase: 'candidate:publication-lane',
          });
        }
        if (!readFileSync(path).equals(observedBytes)) {
          throw new CompilerError('semantic publication stale lock changed during recovery', {
            phase: 'candidate:publication-lane',
          });
        }
        unlinkSync(path);
      } catch (error) {
        if (error instanceof CompilerError) throw error;
        throw new CompilerError(`semantic publication lane acquisition failed: ${error.message}`, {
          phase: 'candidate:publication-lane',
        });
      }
    }
    if (!existsSync(path) || !readFileSync(path).equals(bytes)) {
      throw new CompilerError('semantic publication lane acquisition did not settle', {
        phase: 'candidate:publication-lane',
      });
    }
    let released = false;
    return () => {
      if (released) return;
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path) {
        throw new CompilerError('semantic publication lane lock was substituted', {
          phase: 'candidate:publication-lane',
        });
      }
      if (!readFileSync(path).equals(bytes)) {
        throw new CompilerError('semantic publication lane ownership changed', {
          phase: 'candidate:publication-lane',
        });
      }
      unlinkSync(path);
      const directory = openSync(dirname(path), 'r');
      try { durabilityBarrierSync(directory); } finally { closeSync(directory); }
      released = true;
    };
  };
  return Object.freeze({
    acquire,
    assertCurrentV1Unreserved() {
      const value = readReservation();
      if (value !== null) {
        validateReservation(value);
        throw new CompilerError('REJECTED_V2_HANDOVER_RESERVED_CURRENT_V1_PUBLICATION_RETIRED', {
          phase: 'candidate:v1-retirement-interlock',
          handoverGenerationDigest: value.handover_generation_digest,
        });
      }
    },
    readReservation() {
      const value = readReservation();
      if (value === null) return null;
      const reservation = validateReservation(value);
      assertNotD1Reconciled(reservation);
      return reservation;
    },
    readFactoryPrepareBinding() {
      const path = prepareBindingPath();
      return existsSync(path) ? validatePrepareBinding(readCanonicalFile(path)) : null;
    },
    async reserve(value, validateBeforePersist) {
      const reservation = validateReservation(value);
      const release = acquire();
      try {
        const path = reservationPath();
        // A reconciliation receipt is a permanent selection fence for BOTH identities. Checking
        // the plan as well as the generation prevents the same defective transaction from being
        // reintroduced under a freshly-derived generation digest.
        assertNotD1Reconciled(reservation);
        // A retired generation can never come back. Without this, superseding a reservation and
        // then re-reserving the same generation would resurrect a plan that was proven unusable.
        const history = supersessionHistory(reservation.handover_generation_digest);
        const retirement = history.length === 0
          ? null
          : history[history.length - 1].record;
        if (retirement !== null && retirement.retirement_reason === 'DEFECTIVE') {
          throw new CompilerError('V2 handover generation was superseded and cannot reserve', {
            phase: 'candidate:publication-lane',
          });
        }
        if (retirement !== null
            && retirement.superseded_reservation.prospective_publication_plan_digest
              !== reservation.prospective_publication_plan_digest) {
          // A sequencing retirement permits the SAME plan to reserve again, never a different
          // one wearing the same generation digest.
          throw new CompilerError('V2 handover generation was superseded under a different plan', {
            phase: 'candidate:publication-lane',
          });
        }
        if (existsSync(path)) {
          const observed = validateReservation(readCanonicalFile(path));
          if (canonicalJson(observed) !== canonicalJson(reservation)) {
            throw new CompilerError('V2 handover publication reservation fork rejected', {
              phase: 'candidate:publication-lane',
            });
          }
          return observed;
        }
        if (typeof validateBeforePersist !== 'function') {
          throw new CompilerError('V2 handover reservation requires an in-lock precondition', {
            phase: 'candidate:publication-lane',
          });
        }
        await validateBeforePersist();
        const bytes = Buffer.from(canonicalJson(reservation), 'utf8');
        publishImmutable(path, bytes, 0o444);
        const observed = validateReservation(readCanonicalFile(path));
        if (canonicalJson(observed) !== canonicalJson(reservation)) {
          throw new CompilerError('V2 handover publication reservation fork rejected', {
            phase: 'candidate:publication-lane',
          });
        }
        return observed;
      } finally {
        release();
      }
    },
    readD1Recovery(generationDigest) {
      const path = d1RecoveryPath(generationDigest);
      return existsSync(path) ? validateD1Recovery(readCanonicalFile(path)) : null;
    },
    readD1Reconciliation(transactionId) {
      if (!SHA256.test(transactionId || '')) {
        throw new CompilerError('exact D1 reconciliation transaction id is required', {
          phase: 'candidate:publication-lane',
        });
      }
      const path = d1ReconciliationPath(transactionId);
      return existsSync(path) ? validateD1Reconciliation(readCanonicalFile(path)) : null;
    },
    // Persist the minimum transaction-bound receipt only after Graph's immutable D1 recovery
    // record exists and every Factory boundary independently says the transaction stopped at
    // RESERVED. The receipt is idempotent for identical evidence and rejects every fork.
    async recordD1Reconciliation(factoryEvidence, reconciledAt) {
      validateFactoryD1ReconciliationEvidence(factoryEvidence);
      const release = acquire();
      try {
        const recoveryPath = d1RecoveryPath(factoryEvidence.generation_id);
        if (!existsSync(recoveryPath)) {
          throw new CompilerError('V2 handover D1 reconciliation requires its recovery record', {
            phase: 'candidate:publication-lane',
          });
        }
        const recovery = validateD1Recovery(readCanonicalFile(recoveryPath));
        return persistD1Reconciliation(recovery, factoryEvidence, reconciledAt);
      } finally {
        release();
      }
    },
    // A correctly journaled D1 is a different recovery state from the older crash window. Its
    // exact journal and both boundary receipts already exist, so this operation records those
    // facts, creates the permanent generation/plan exclusion, reads both records back, and only
    // then releases the active reservation and PREPARE under the same publication-lane lock.
    async recoverJournaledAfterD1(evidence, reconciledAt, validateBeforePersist) {
      const record = validateD1Recovery(evidence);
      if (record.schema !== V2_HANDOVER_JOURNALED_D1_RECOVERY_EVIDENCE_SCHEMA) {
        throw new CompilerError('journaled D1 recovery requires its exact evidence schema', {
          phase: 'candidate:publication-lane',
        });
      }
      if (typeof validateBeforePersist !== 'function') {
        throw new CompilerError('journaled D1 recovery requires in-lock current-state validation', {
          phase: 'candidate:publication-lane',
        });
      }
      const release = acquire();
      try {
        const recoveryPath = d1RecoveryPath(record.handover_generation_digest);
        const hadRecovery = existsSync(recoveryPath);
        if (hadRecovery) {
          const observed = validateD1Recovery(readCanonicalFile(recoveryPath));
          if (canonicalJson(observed) !== canonicalJson(record)) {
            throw new CompilerError('V2 handover journaled D1 recovery fork rejected', {
              phase: 'candidate:publication-lane',
            });
          }
        }
        const expectedPointers = [
          [reservationPath(), validateReservation, record.superseded_reservation, 'reservation'],
          [prepareBindingPath(), validatePrepareBinding, record.superseded_prepare_binding,
            'prepare binding'],
        ];
        for (const [path, validate, expected, label] of expectedPointers) {
          if (!existsSync(path)) {
            if (!hadRecovery) {
              throw new CompilerError(`journaled D1 recovery requires its active ${label}`, {
                phase: 'candidate:publication-lane',
              });
            }
            continue;
          }
          const observed = validate(readCanonicalFile(path));
          if (canonicalJson(observed) !== canonicalJson(expected)) {
            throw new CompilerError(`journaled D1 recovery ${label} differs from its evidence`, {
              phase: 'candidate:publication-lane',
            });
          }
        }
        // The evidence was assembled before this lock was acquired. Re-observe the exact
        // authority, journal and durable later-boundary state while no publication-lane actor can
        // advance the pointers, immediately before the first immutable recovery write. A stale
        // observation must leave both pointers intact and create no recovery/exclusion record.
        await validateBeforePersist();
        if (!hadRecovery) {
          mkdirSync(supersessionDirectory(), { recursive: true, mode: 0o700 });
          publishImmutable(recoveryPath, Buffer.from(canonicalJson(record), 'utf8'), 0o444);
        }
        const persistedRecovery = validateD1Recovery(readCanonicalFile(recoveryPath));
        if (canonicalJson(persistedRecovery) !== canonicalJson(record)) {
          throw new CompilerError('V2 handover journaled D1 recovery read-back differs', {
            phase: 'candidate:publication-lane',
          });
        }
        const { graph_terminal_required: _required, ...factoryEvidence } =
          record.factory_projection;
        const reconciliation = persistD1Reconciliation(
          persistedRecovery, factoryEvidence, reconciledAt,
        );
        for (const [path, _validate, _expected, label] of expectedPointers.reverse()) {
          if (!existsSync(path)) continue;
          unlinkSync(path);
          const directory = openSync(dirname(path), 'r');
          try { durabilityBarrierSync(directory); } finally { closeSync(directory); }
          if (existsSync(path)) {
            throw new CompilerError(`journaled D1 recovery could not release the ${label}`, {
              phase: 'candidate:publication-lane',
            });
          }
        }
        return Object.freeze({
          recovery_record: persistedRecovery,
          reconciliation_receipt: reconciliation,
        });
      } finally {
        release();
      }
    },
    // Recover a generation whose D1 COMMITTED but whose D1 journal boundary did not.
    //
    // The ordinary supersession path cannot serve this state, and must not: it requires a
    // zero-effect proof, and here the D1 authority transition is REAL. It also refuses once a
    // Factory PREPARE is bound, which is correct -- discarding a committed coordination step
    // silently would be worse than being stuck.
    //
    // So this records the effect rather than denying it. The record is immutable and names the
    // exact pre-D1 authority, the exact observed post-D1 authority, the reservation, the bound
    // PREPARE and the journal states, and it is admitted ONLY when every later boundary is
    // provably absent. Only after the record is durably readable does it unbind the PREPARE and
    // release the lane.
    async recoverAfterD1(evidence, recoveredAt) {
      const release = acquire();
      try {
        const reservation = validateReservation(readCanonicalFile(reservationPath()));
        const prepare = validatePrepareBinding(readCanonicalFile(prepareBindingPath()));
        if (prepare.handover_generation_digest !== reservation.handover_generation_digest) {
          throw new CompilerError('bound PREPARE names a different generation', {
            phase: 'candidate:publication-lane',
          });
        }
        const record = validateD1Recovery({
          schema: V2_HANDOVER_D1_RECOVERY_SCHEMA,
          recovered_at: recoveredAt,
          recovery_reason: 'DEFECTIVE_AFTER_D1',
          superseded_reservation: reservation,
          superseded_prepare_binding: prepare,
          d1_effect: evidence,
        });
        const path = d1RecoveryPath(reservation.handover_generation_digest);
        if (existsSync(path)) {
          const observed = validateD1Recovery(readCanonicalFile(path));
          if (canonicalJson(observed) !== canonicalJson(record)) {
            throw new CompilerError('V2 handover D1 recovery fork rejected', {
              phase: 'candidate:publication-lane',
            });
          }
        } else {
          mkdirSync(supersessionDirectory(), { recursive: true, mode: 0o700 });
          publishImmutable(path, Buffer.from(canonicalJson(record), 'utf8'), 0o444);
        }
        // Read the durable record back BEFORE releasing anything, so a crash in between leaves
        // the reservation and PREPARE intact rather than the generation unaccounted for.
        const persisted = validateD1Recovery(readCanonicalFile(path));
        if (canonicalJson(persisted.superseded_reservation) !== canonicalJson(reservation)
            || canonicalJson(persisted.superseded_prepare_binding) !== canonicalJson(prepare)) {
          throw new CompilerError('V2 handover D1 recovery did not preserve its inputs', {
            phase: 'candidate:publication-lane',
          });
        }
        for (const [target, label] of [
          [prepareBindingPath(), 'prepare binding'],
          [reservationPath(), 'reservation'],
        ]) {
          unlinkSync(target);
          const directory = openSync(dirname(target), 'r');
          try { durabilityBarrierSync(directory); } finally { closeSync(directory); }
          if (existsSync(target)) {
            throw new CompilerError(`V2 handover D1 recovery could not release the ${label}`, {
              phase: 'candidate:publication-lane',
            });
          }
        }
        return persisted;
      } finally {
        release();
      }
    },
    readSupersession(generationDigest) {
      const history = supersessionHistory(generationDigest);
      return history.length === 0 ? null : history[history.length - 1].record;
    },
    readSupersessionHistory(generationDigest) {
      return supersessionHistory(generationDigest).map((entry) => entry.record);
    },
    async supersede(zeroEffectProof, retiredAt, retirementReason) {
      const release = acquire();
      try {
        const path = reservationPath();
        if (!existsSync(path)) {
          throw new CompilerError('V2 handover has no reservation to supersede', {
            phase: 'candidate:publication-lane',
          });
        }
        const reservation = validateReservation(readCanonicalFile(path));
        // Retiring a reservation that already bound a Factory prepare would discard a
        // committed coordination step, so that is refused outright.
        if (existsSync(prepareBindingPath())) {
          throw new CompilerError('V2 handover reservation already bound a Factory prepare', {
            phase: 'candidate:publication-lane',
          });
        }
        const record = validateSupersession({
          retired_at: retiredAt,
          retirement_reason: retirementReason,
          schema: V2_HANDOVER_SUPERSESSION_SCHEMA,
          superseded_reservation: reservation,
          zero_effect_proof: zeroEffectProof,
        });
        const history = supersessionHistory(reservation.handover_generation_digest);
        const latest = history.length === 0 ? null : history[history.length - 1];
        if (latest !== null && latest.record.retirement_reason === 'DEFECTIVE') {
          // Unreachable through reserve(), which refuses a DEFECTIVE generation outright. Assert
          // it anyway so a defective retirement can never be followed by anything.
          throw new CompilerError('V2 handover generation was retired as defective', {
            phase: 'candidate:publication-lane',
          });
        }
        let recordPath;
        if (latest !== null && canonicalJson(latest.record) === canonicalJson(record)) {
          // Idempotent: a byte-identical retirement is a retry of the same governed act.
          recordPath = latest.path;
        } else {
          // A genuinely new retirement of a lawfully re-reserved generation appends to the
          // history; it never overwrites or contradicts a record already written.
          recordPath = supersessionPath(
            reservation.handover_generation_digest,
            history.length + 1,
          );
          mkdirSync(supersessionDirectory(), { recursive: true, mode: 0o700 });
          publishImmutable(recordPath, Buffer.from(canonicalJson(record), 'utf8'), 0o444);
        }
        // The retired reservation's own bytes are now preserved inside the durable, immutable
        // supersession record, so releasing the live pointer destroys no history. Only after
        // that record is readable back is the pointer released, so a crash in between leaves the
        // reservation live rather than the generation unaccounted for.
        const persisted = validateSupersession(readCanonicalFile(recordPath));
        if (canonicalJson(persisted.superseded_reservation) !== canonicalJson(reservation)) {
          throw new CompilerError('V2 handover supersession did not preserve the reservation', {
            phase: 'candidate:publication-lane',
          });
        }
        unlinkSync(path);
        const directory = openSync(dirname(path), 'r');
        try { durabilityBarrierSync(directory); } finally { closeSync(directory); }
        return persisted;
      } finally {
        release();
      }
    },
    bindFactoryPrepare(factoryPrepareReceiptDigest) {
      if (!SHA256.test(factoryPrepareReceiptDigest || '')) {
        throw new CompilerError('exact Factory prepare receipt digest is required', {
          phase: 'candidate:publication-lane',
        });
      }
      const release = acquire();
      try {
        const reservation = readReservation();
        if (!reservation) {
          throw new CompilerError('Factory PREPARE cannot precede the Graph reservation', {
            phase: 'candidate:publication-lane',
          });
        }
        assertNotD1Reconciled(reservation);
        const binding = validatePrepareBinding(Object.freeze({
          schema: V2_HANDOVER_FACTORY_PREPARE_BINDING_SCHEMA,
          factory_prepare_receipt_digest: factoryPrepareReceiptDigest,
          handover_generation_digest: reservation.handover_generation_digest,
          prospective_publication_plan_digest: reservation.prospective_publication_plan_digest,
          reservation_digest: sha256(Buffer.from(canonicalJson(reservation), 'utf8')),
        }));
        const path = prepareBindingPath();
        if (!existsSync(path)) {
          publishImmutable(path, Buffer.from(canonicalJson(binding), 'utf8'), 0o444);
        }
        const observed = validatePrepareBinding(readCanonicalFile(path));
        if (canonicalJson(observed) !== canonicalJson(binding)) {
          throw new CompilerError('V2 Factory prepare binding fork rejected', {
            phase: 'candidate:publication-lane',
          });
        }
        return observed;
      } finally {
        release();
      }
    },
  });
}

function exactCandidateBytes(value, expectedDigest) {
  if (!Buffer.isBuffer(value) || value.length === 0) {
    throw new CompilerError('canonical RDF Patch candidate bytes are required', { phase: 'candidate:configuration' });
  }
  const observedDigest = sha256(value);
  if (expectedDigest !== undefined && observedDigest !== expectedDigest) {
    throw new CompilerError('canonical RDF Patch bytes do not match the accepted candidate digest', {
      phase: 'candidate:digest', expectedCandidateDigest: expectedDigest, observedCandidateDigest: observedDigest,
    });
  }
  return Object.freeze({ bytes: Buffer.from(value), digest: observedDigest });
}

function parseCanonicalPatch(
  value,
  expectedDigest,
  allowedGraphs,
  allowedStages = new Set(['base', 'stage1', 'stage2', 'C1', 'C2']),
) {
  const candidate = exactCandidateBytes(value, expectedDigest);
  const text = candidate.bytes.toString('utf8');
  if (!candidate.bytes.equals(Buffer.from(text, 'utf8')) || text.includes('\r') || !text.endsWith('\n')) {
    throw new CompilerError('candidate is not canonical UTF-8 RDF Patch', { phase: 'candidate:parse' });
  }
  const lines = text.split('\n');
  const header = lines.shift();
  const headerMatch = V1_PATCH_HEADER.exec(header || '') || V2_PATCH_HEADER.exec(header || '');
  if (!headerMatch || !allowedStages.has(headerMatch[2])
      || lines.pop() !== '' || lines.length === 0) {
    throw new CompilerError('candidate does not use canonical-rdf-patch-v1', { phase: 'candidate:parse' });
  }
  const operations = lines.map((line) => {
    const match = /^([AD]) (.+)$/.exec(line);
    if (!match) throw new CompilerError('candidate contains a malformed RDF Patch operation', { phase: 'candidate:parse' });
    let parsed;
    try {
      parsed = new Parser({ format: NQUADS, blankNodePrefix: '' }).parse(`${match[2]}\n`);
    } catch (error) {
      throw new CompilerError(`candidate contains invalid N-Quads: ${error.message}`, { phase: 'candidate:parse' });
    }
    if (parsed.length !== 1 || parsed[0].graph.termType !== 'NamedNode'
        || [parsed[0].subject, parsed[0].object].some((term) => term.termType === 'BlankNode'
          && !/^c14n[0-9]+$/.test(term.value))
        || !allowedGraphs.has(parsed[0].graph.value)) {
      throw new CompilerError('candidate operation must be one canonical quad in a managed named graph', { phase: 'candidate:scope' });
    }
    return Object.freeze({ action: match[1], line: match[2], value: parsed[0] });
  });
  const deletions = operations.filter(({ action }) => action === 'D');
  const additions = operations.filter(({ action }) => action === 'A');
  const canonicalLines = [
    header,
    ...deletions.map(({ line }) => `D ${line}`).sort(),
    ...additions.map(({ line }) => `A ${line}`).sort(),
    '',
  ];
  if (canonicalLines.join('\n') !== text
      || new Set(operations.map(({ action, line }) => `${action} ${line}`)).size !== operations.length
      || deletions.some(({ line }) => additions.some((entry) => entry.line === line))) {
    throw new CompilerError('candidate RDF Patch is not canonical, unique and contradiction-free', { phase: 'candidate:canonicality' });
  }
  return Object.freeze({
    ...candidate,
    additions,
    deletions,
    operations,
    protocol: headerMatch[1],
    stage: headerMatch[2],
  });
}

function v2CandidateInputFromCore(core) {
  return {
    protocol: core.protocol,
    stage: core.stage,
    release_subject_digest: core.release_subject_digest,
    d0_authority_digest: core.d0_authority_digest,
    source_identities: core.source_identities,
    external_attestation_identities: core.external_attestation_identities,
    evidence_dependency_digests: core.evidence_dependency_digests,
    compiler_identity: core.compiler_identity,
    d1_binding: core.d1_binding === null ? null : {
      authority_digest: core.d1_binding.authority_digest,
      c1_candidate_digest: core.d1_binding.c1_candidate_digest,
      dependency_identity_digests: core.d1_binding.dependency_identity_digests,
    },
  };
}

function exactV2CandidateCoreBinding(patch, identityBytes, expectedStage) {
  if (!Buffer.isBuffer(identityBytes) || identityBytes.length === 0) {
    throw new CompilerError('V2 candidate identity bytes are required', {
      phase: 'candidate:v2-identity',
    });
  }
  let core;
  try {
    core = parseAggregateCompilerAuthorityCandidateV2IdentityBytes(identityBytes);
  } catch (error) {
    throw new CompilerError(error.message, { phase: 'candidate:v2-identity' });
  }
  const regenerated = materializeAggregateCompilerAuthorityCandidateV2(
    v2CandidateInputFromCore(core),
  );
  if (core.stage !== expectedStage
      || regenerated.candidateDigest !== patch.digest
      || !regenerated.bytes.equals(patch.bytes)
      || !regenerated.identityBytes.equals(identityBytes)) {
    throw new CompilerError('V2 candidate descriptor/core binding is not exact', {
      phase: 'candidate:v2-identity',
    });
  }
  return core;
}

function v2ManagedGraphSet(manifest) {
  // The exact V2 candidate is independently regenerated from its frozen
  // identity before execution.  Its ownership fence is constitutionally
  // rooted in the authority graph even in minimal production-shadow
  // manifests that omit that empty graph at D0.
  return new Set([...managedGraphs(manifest), 'urn:usf:graph:authority']);
}

function frozenV2CandidateCore(core) {
  return {
    release_subject_digest: core.release_subject_digest,
    d0_authority_digest: core.d0_authority_digest,
    source_identities: core.source_identities,
    external_attestation_identities: core.external_attestation_identities,
    external_attestation_set_root_digest: core.external_attestation_set_root_digest,
    handover_generation_digest: core.handover_generation_digest,
    evidence_dependency_digests: core.evidence_dependency_digests,
    compiler_identity: core.compiler_identity,
  };
}

async function assertCurrentV1PublicationUnfenced(client, transaction, nativeGraphStore) {
  // The fence triple is a RUNTIME marker. Deleting it must not re-open V1
  // publication, so the durable terminal floor is consulted FIRST -- the same
  // barrier observeGraphRuntimeOwnershipV2 applies to ownership observation.
  // Without this, fence deletion failed closed for observation but open here,
  // which is the one path that actually writes V1 authority.
  //
  // The floor reader is always supplied. Constructing one here would have
  // rooted the barrier at an ambient host directory, so a caller with a
  // different root -- or none -- would read an empty floor and conclude V1 was
  // still open. An absent reader fails closed instead.
  const floor = nativeGraphStore;
  if (!floor || typeof floor.readTerminalOwnershipFloor !== 'function') {
    throw new CompilerError('V2_GRAPH_TERMINAL_OWNERSHIP_FLOOR_READER_REQUIRED', {
      phase: 'candidate:v1-retirement-interlock',
    });
  }
  if (floor.readTerminalOwnershipFloor().terminal) {
    throw new CompilerError('REJECTED_V2_TERMINAL_CURRENT_V1_PUBLICATION_RETIRED', {
      phase: 'candidate:v1-retirement-interlock',
    });
  }
  const rows = await client.selectInTransaction(transaction, `SELECT ?fence ?state ?generation WHERE {
    GRAPH ?graph {
      ?fence a <${V2_NATIVE_HANDOVER_FENCE_CLASS}> .
      OPTIONAL { ?fence <${USF_ONTOLOGY}handoverOwnershipState> ?state }
      OPTIONAL { ?fence <${USF_ONTOLOGY}handoverGenerationDigest> ?generation }
    }
  } ORDER BY ?fence ?state ?generation`);
  if (!Array.isArray(rows)) {
    throw new CompilerError('V2 native handover fence observation is invalid', {
      phase: 'candidate:v1-retirement-interlock',
    });
  }
  if (rows.length > 0) {
    const exact = rows.length === 1
      && rows[0].fence?.value === V2_NATIVE_HANDOVER_FENCE
      && rows[0].state?.value === 'urn:usf:v2ownershipstate:handoverpending'
      && SHA256.test(rows[0].generation?.value || '');
    throw new CompilerError(
      exact
        ? 'REJECTED_V2_HANDOVER_PENDING_CURRENT_V1_PUBLICATION_RETIRED'
        : 'REJECTED_AMBIGUOUS_V2_HANDOVER_STATE_CURRENT_V1_PUBLICATION_RETIRED',
      {
        phase: 'candidate:v1-retirement-interlock',
        fenceCount: rows.length,
      },
    );
  }
}

async function assertExactNativeV2HandoverFence(client, handoverGenerationDigest) {
  if (!SHA256.test(handoverGenerationDigest || '')) {
    throw new CompilerError('native V2 validation requires one exact handover generation', {
      phase: 'candidate:v2-currentness',
    });
  }
  const rows = await client.select(`SELECT ?fence ?state ?generation ?v1state WHERE {
    GRAPH ?graph {
      ?fence a <${V2_NATIVE_HANDOVER_FENCE_CLASS}> ;
        <${USF_ONTOLOGY}handoverOwnershipState> ?state ;
        <${USF_ONTOLOGY}handoverGenerationDigest> ?generation ;
        <${USF_ONTOLOGY}handoverCurrentV1PublicationState> ?v1state .
    }
  } ORDER BY ?fence ?state ?generation ?v1state`);
  if (!Array.isArray(rows) || rows.length !== 1
      || rows[0].fence?.value !== V2_NATIVE_HANDOVER_FENCE
      || rows[0].state?.value !== 'urn:usf:v2ownershipstate:handoverpending'
      || rows[0].generation?.value !== handoverGenerationDigest
      || rows[0].v1state?.value !== 'urn:usf:v1publicationstate:fenced') {
    throw new CompilerError('native V2 validation does not observe the exact terminal handover fence', {
      phase: 'candidate:v2-currentness',
    });
  }
}

function createCurrentV1PublicationInterlockedClient(client, publicationLane, {
  commitMode = false,
  nativeGraphStore = null,
} = {}) {
  if (!publicationLane || typeof publicationLane.acquire !== 'function'
      || typeof publicationLane.assertCurrentV1Unreserved !== 'function') {
    throw new CompilerError('current V1 publication requires the shared publication lane', {
      phase: 'candidate:v1-retirement-interlock',
    });
  }
  const releases = new Map();
  const releaseFor = (transaction) => {
    const release = releases.get(transaction);
    if (release) {
      releases.delete(transaction);
      release();
    }
  };
  const overrides = {
    async begin() {
      let release = null;
      let transaction = null;
      try {
        if (commitMode) release = publicationLane.acquire();
        publicationLane.assertCurrentV1Unreserved();
        transaction = await client.begin();
        if (release) releases.set(transaction, release);
        await assertCurrentV1PublicationUnfenced(client, transaction, nativeGraphStore);
        return transaction;
      } catch (error) {
        if (transaction) {
          try { await client.rollback(transaction); } catch { /* preserve interlock failure */ }
          releases.delete(transaction);
        }
        if (release) release();
        throw error;
      }
    },
    async commit(transaction) {
      try { return await client.commit(transaction); } finally { releaseFor(transaction); }
    },
    async rollback(transaction) {
      try { return await client.rollback(transaction); } finally { releaseFor(transaction); }
    },
  };
  return new Proxy(Object.create(null), {
    get(_target, property) {
      if (Object.hasOwn(overrides, property)) return overrides[property];
      const value = Reflect.get(client, property, client);
      return typeof value === 'function' ? value.bind(client) : value;
    },
    set() {
      throw new CompilerError('current V1 publication interlock client is immutable', {
        phase: 'candidate:v1-retirement-interlock',
      });
    },
  });
}

function exactObjectKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    throw new CompilerError(`${label} has an invalid closed schema`, { phase: 'candidate:external-authority-delta' });
  }
}

function exactSortedUniqueStrings(value, pattern, label, { minimum = 1 } = {}) {
  if (!Array.isArray(value) || value.length < minimum || value.some((item) => typeof item !== 'string' || !pattern.test(item))
      || canonicalJson(value) !== canonicalJson([...new Set(value)].sort())) {
    throw new CompilerError(`${label} must be an exact sorted unique set`, { phase: 'candidate:external-authority-delta' });
  }
  return Object.freeze([...value]);
}

function exactCanonicalRepositoryPaths(value, label, { minimum = 1 } = {}) {
  const paths = exactSortedUniqueStrings(value, /^[A-Za-z0-9._/-]+$/, label, { minimum });
  if (paths.some((path) => path.startsWith('/')
      || path.split('/').some((part) => part === '' || part === '.' || part === '..'))) {
    throw new CompilerError(`${label} contains a non-canonical repository-relative path`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  return paths;
}

function externalAuthoritySourceScopeDigest(paths) {
  const canonicalPaths = exactCanonicalRepositoryPaths(paths, 'external authority source paths');
  return sha256(Buffer.from(canonicalJson(canonicalPaths), 'utf8'));
}

function missingExternalAuthorityProofVerifier() {
  throw new CompilerError('external authority proof approval verifier is required', {
    phase: 'candidate:external-authority-delta',
  });
}

async function resolveExternalAuthorityTrustedNow(operationTrustedNow, configuredTrustedNow) {
  let observed = operationTrustedNow ?? configuredTrustedNow;
  if (observed === null || observed === undefined) {
    throw new CompilerError('external authority proof validation requires trusted current time', {
      phase: 'candidate:external-authority-delta',
    });
  }
  if (typeof observed === 'function') observed = await observed();
  const date = observed instanceof Date ? new Date(observed.getTime()) : new Date(observed);
  if (!Number.isFinite(date.getTime())) {
    throw new CompilerError('external authority proof trusted current time is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return date;
}

function parseCanonicalJsonArtifact(bytes, label) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2) {
    throw new CompilerError(`${label} bytes are required`, { phase: 'candidate:external-authority-delta' });
  }
  const text = bytes.toString('utf8');
  if (!bytes.equals(Buffer.from(text, 'utf8')) || text.includes('\r') || !text.endsWith('\n')) {
    throw new CompilerError(`${label} is not canonical UTF-8 JSON with terminal LF`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new CompilerError(`${label} is not JSON: ${error.message}`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  const canonicalBytes = Buffer.from(`${JSON.stringify(stable(value), null, 2)}\n`, 'utf8');
  if (!canonicalBytes.equals(bytes)) {
    throw new CompilerError(`${label} is not stable-key canonical JSON`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  return Object.freeze({
    byteSize: bytes.length,
    bytes: Buffer.from(bytes),
    digest: sha256(bytes),
    jcsDigest: sha256(Buffer.from(canonicalJson(value), 'utf8')),
    value,
  });
}

function exactArtifactDescriptor(value, observed, label) {
  exactObjectKeys(value, ['byteSize', 'digest', 'jcsDigest'], label);
  if (value.byteSize !== observed.byteSize || value.digest !== observed.digest
      || value.jcsDigest !== observed.jcsDigest) {
    throw new CompilerError(`${label} does not bind the exact canonical artifact bytes`, {
      phase: 'candidate:external-authority-delta',
    });
  }
}

function validateExternalAuthorityOperations(artifact, repository, contentStore = null) {
  const operations = artifact.value;
  if (!Array.isArray(operations) || operations.length < 1 || operations.length > 256) {
    throw new CompilerError('external authority operations must be a bounded canonical array', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const paths = [];
  for (const [index, operation] of operations.entries()) {
    const inline = Object.hasOwn(operation, 'content') || Object.hasOwn(operation, 'contentEncoding');
    const located = Object.hasOwn(operation, 'contentLocator');
    exactObjectKeys(operation, inline && !located ? [
      'action', 'artefactFamily', 'content', 'contentDigest', 'contentEncoding', 'index',
      'path', 'pathRole', 'representationFormat', 'sourceDigest',
    ] : !inline && located ? [
      'action', 'artefactFamily', 'contentDigest', 'contentLocator', 'index',
      'path', 'pathRole', 'representationFormat', 'sourceDigest',
    ] : [], 'external authority write operation');
    let contentBytes;
    if (inline && !located && operation.contentEncoding === 'utf8'
        && typeof operation.content === 'string' && operation.content.length > 0) {
      contentBytes = Buffer.from(operation.content, 'utf8');
    } else if (!inline && located && SHA256.test(operation.contentDigest || '')
        && operation.contentLocator === `cas://sha256/${operation.contentDigest.slice(7)}`
        && contentStore && typeof contentStore.read === 'function' && typeof contentStore.verify === 'function') {
      const receipt = contentStore.verify(operation.contentDigest);
      const read = contentStore.read(operation.contentDigest);
      if (receipt?.digest === operation.contentDigest && Number.isSafeInteger(receipt.size)
          && Buffer.isBuffer(read) && read.length > 0 && read.length === receipt.size
          && sha256(read) === operation.contentDigest) contentBytes = read;
    }
    if (operation.action !== 'write-file' || operation.index !== index
        || !Buffer.isBuffer(contentBytes)
        || typeof operation.path !== 'string'
        || !/^[A-Za-z0-9._/-]+$/.test(operation.path)
        || operation.path.startsWith('/')
        || operation.path.split('/').some((part) => part === '' || part === '.' || part === '..')
        || !SHA256.test(operation.sourceDigest || '')
        || sha256(contentBytes) !== operation.contentDigest
        || !/^urn:usf:artefactfamily:[a-z0-9]+$/.test(operation.artefactFamily || '')
        || !/^urn:usf:pathrole:[a-z0-9]+$/.test(operation.pathRole || '')
        || !/^urn:usf:representationformat:[a-z0-9]+$/.test(operation.representationFormat || '')) {
      throw new CompilerError('external authority write operation is not exact and preimage-bound', {
        phase: 'candidate:external-authority-delta', index,
      });
    }
    paths.push(operation.path);
  }
  if (canonicalJson(paths) !== canonicalJson([...new Set(paths)].sort())) {
    throw new CompilerError('external authority operation paths must be sorted and unique', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const requestedFormats = [...new Set(operations.map(({ representationFormat }) => representationFormat))].sort();
  const operationDigest = sha256(Buffer.from(canonicalJson({
    operations: stable(operations), repository, schemaVersion: 1,
  }), 'utf8'));
  return Object.freeze({
    operationDigest,
    operations: Object.freeze(operations.map((operation) => Object.freeze({ ...operation }))),
    requestedActions: Object.freeze(['write-file']),
    requestedFormats: Object.freeze(requestedFormats),
    requestedPaths: Object.freeze(paths),
  });
}

function validateExternalAuthorityInventory(artifact, {
  authorityDigest,
  conflictBinding,
  correctionCandidateDigest,
  operations,
  predecessorSourceHead,
  predecessorSourceTree,
  repository,
}) {
  const inventory = artifact.value;
  exactObjectKeys(inventory, [
    'authority', 'candidate_source', 'corrections', 'current_execution_boundary', 'nonclaims',
    'owner_precedent', 'predecessor_request', 'proof_preflight', 'protected_graph_source',
    'required_authority_actions', 'required_validation_invariants', 'schema', 'source_scope',
    'status', 'supporting_integrity_corrections',
  ], 'external authority inventory');
  if (inventory.schema !== 'usf-repository-materialisation-semantic-correction-authority-request-v3'
      || inventory.status !== 'REFERENCE_ONLY_VALIDATION_EVIDENCE_CANDIDATE_AWAITING_EXACT_CONFLICT_RESOLUTION'
      || artifact.digest !== correctionCandidateDigest) {
    throw new CompilerError('external authority inventory identity or status is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  exactObjectKeys(inventory.authority, ['digest', 'graph_count', 'triple_count'], 'external authority inventory authority');
  exactObjectKeys(inventory.protected_graph_source, ['commit', 'parent', 'required_history', 'tree'],
    'external authority inventory protected source');
  exactObjectKeys(inventory.candidate_source, [
    'added_path_count', 'changed_path_count', 'deleted_path_count', 'focused_verification',
    'history_shape', 'predecessor_commit', 'predecessor_tree', 'repository', 'source_records',
    'staged_deletions', 'staged_insertions', 'staged_successor_tree',
  ], 'external authority inventory candidate source');
  exactObjectKeys(inventory.source_scope, [
    'authority_projection_additions', 'current_path_count', 'current_scope_digest',
    'successor_path_count', 'successor_scope_digest',
  ], 'external authority inventory source scope');
  exactObjectKeys(inventory.current_execution_boundary, [
    'action_state', 'execution_scope_digest', 'execution_scope_iri', 'execution_scope_projection_digest',
    'maximum_repository_writes', 'mode', 'permitted_effect', 'repository_mutation_permitted',
    'status', 'unresolved_validation_obligations', 'validation_satisfied', 'write_paths',
  ], 'external authority inventory execution boundary');
  const sourceRecords = inventory.candidate_source.source_records;
  if (!Array.isArray(sourceRecords) || sourceRecords.length !== operations.operations.length) {
    throw new CompilerError('external authority inventory source-record cardinality is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const [index, record] of sourceRecords.entries()) {
    exactObjectKeys(record, ['mode', 'path', 'predecessor_digest', 'successor_digest'],
      'external authority inventory source record');
    const operation = operations.operations[index];
    if (record.mode !== '100644' || record.path !== operation.path
        || record.predecessor_digest !== operation.sourceDigest
        || record.successor_digest !== operation.contentDigest) {
      throw new CompilerError('external authority inventory source record differs from the exact operation', {
        phase: 'candidate:external-authority-delta', index,
      });
    }
  }
  const obligations = inventory.corrections.map((correction) => {
    if (!correction || typeof correction !== 'object' || Array.isArray(correction)
        || correction.status !== 'REFERENCE_ONLY_CANDIDATE'
        || !/^urn:usf:validationobligation:[a-z0-9]+$/.test(correction.obligation || '')) {
      throw new CompilerError('external authority inventory correction is not reference-only and obligation-bound', {
        phase: 'candidate:external-authority-delta',
      });
    }
    return correction.obligation;
  }).sort();
  if (inventory.authority.digest !== authorityDigest
      || inventory.protected_graph_source.commit !== predecessorSourceHead
      || inventory.protected_graph_source.tree !== predecessorSourceTree
      || inventory.protected_graph_source.required_history !== REQUIRED_HISTORY_MODE
      || inventory.candidate_source.predecessor_commit !== predecessorSourceHead
      || inventory.candidate_source.predecessor_tree !== predecessorSourceTree
      || inventory.candidate_source.repository !== repository
      || inventory.candidate_source.staged_successor_tree !== conflictBinding.successorSourceTree
      || inventory.candidate_source.added_path_count !== 0
      || inventory.candidate_source.deleted_path_count !== 0
      || inventory.candidate_source.changed_path_count !== operations.operations.length
      || inventory.candidate_source.history_shape !== ONE_PARENT_HISTORY_SHAPE
      || inventory.source_scope.successor_scope_digest !== conflictBinding.sourceScopeDigest
      || inventory.source_scope.successor_path_count !== conflictBinding.sourcePaths.length
      || inventory.current_execution_boundary.repository_mutation_permitted !== false
      || inventory.current_execution_boundary.maximum_repository_writes !== 0
      || inventory.current_execution_boundary.validation_satisfied !== false
      || inventory.current_execution_boundary.write_paths.length !== 0
      || canonicalJson(obligations) !== canonicalJson(conflictBinding.validationObligations)
      || canonicalJson(inventory.current_execution_boundary.unresolved_validation_obligations)
        !== canonicalJson(conflictBinding.validationObligations)) {
    throw new CompilerError('external authority inventory does not bind the exact fail-closed correction boundary', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return inventory;
}

function validateExternalAuthorityReview(artifact, inventoryArtifact, {
  authorityDigest,
  conflictBinding,
  operations,
  predecessorSourceHead,
  predecessorSourceTree,
}) {
  const review = artifact.value;
  exactObjectKeys(review, [
    'authorshipIndependence', 'candidateSource', 'currentExecutionBoundary',
    'governanceIndependentReviewSatisfied', 'liveAuthority', 'nonclaims', 'obligations',
    'publicationReadiness', 'request', 'reviewArtifactStorageClass', 'schema',
    'sourceOrAuthorityMutationPerformed', 'verdict', 'verification',
  ], 'external authority independent review');
  exactObjectKeys(review.liveAuthority, ['digest', 'digestAlgorithm', 'graphCount', 'stableAcrossReview', 'tripleCount'],
    'external authority review live authority');
  exactObjectKeys(review.authorshipIndependence, [
    'candidateDerivationParticipation', 'priorReviewConclusionsUsed', 'reviewDerivation', 'reviewerRole',
  ], 'external authority review independence');
  exactObjectKeys(review.request, ['byteCount', 'jcsSha256', 'path', 'rawSha256', 'schema', 'status', 'terminalLf'],
    'external authority review request binding');
  exactObjectKeys(review.candidateSource, [
    'baseCommit', 'baseParent', 'baseTree', 'changedPaths', 'sourceRecordCount',
    'sourceRecordsExact', 'sourceRecordsJcsSha256', 'stagedDeletions', 'stagedInsertions',
    'stagedSuccessorTree', 'trackedDeltaExact', 'trackedPathAdditions', 'trackedPathDeletions',
  ], 'external authority review candidate source');
  exactObjectKeys(review.obligations, [
    'currentValidationResultCounts', 'requiredAuthorityActionCount',
    'requiredValidationInvariantCount', 'targetValidationObligations',
  ], 'external authority review obligations');
  const zeroCounts = Object.fromEntries(conflictBinding.validationObligations.map((iri) => [iri, 0]));
  if (review.schema !== 'usf-semantic-adequacy-review-core-v1'
      || review.verdict !== 'ACCEPTED'
      || review.governanceIndependentReviewSatisfied !== true
      || review.sourceOrAuthorityMutationPerformed !== false
      || review.liveAuthority.digest !== authorityDigest
      || review.liveAuthority.stableAcrossReview !== true
      || review.authorshipIndependence.candidateDerivationParticipation !== false
      || review.authorshipIndependence.priorReviewConclusionsUsed !== false
      || review.authorshipIndependence.reviewerRole !== 'independent-usf-semantic-reviewer'
      || review.request.rawSha256 !== inventoryArtifact.digest
      || review.request.jcsSha256 !== inventoryArtifact.jcsDigest
      || review.request.byteCount !== inventoryArtifact.byteSize
      || review.request.terminalLf !== true
      || review.candidateSource.baseCommit !== predecessorSourceHead
      || review.candidateSource.baseTree !== predecessorSourceTree
      || review.candidateSource.stagedSuccessorTree !== conflictBinding.successorSourceTree
      || review.candidateSource.sourceRecordCount !== operations.operations.length
      || review.candidateSource.sourceRecordsExact !== true
      || review.candidateSource.trackedDeltaExact !== true
      || review.candidateSource.trackedPathAdditions !== 0
      || review.candidateSource.trackedPathDeletions !== 0
      || canonicalJson(review.candidateSource.changedPaths) !== canonicalJson(operations.requestedPaths)
      || canonicalJson(review.obligations.targetValidationObligations)
        !== canonicalJson(conflictBinding.validationObligations)
      || canonicalJson(review.obligations.currentValidationResultCounts) !== canonicalJson(zeroCounts)
      || review.publicationReadiness
        !== 'NOT_READY_REFERENCE_ONLY_AWAITING_OWNER_DECISION_PROOF_AND_V1_PUBLICATION') {
    throw new CompilerError('external authority review is not exact, independent and accepted', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return review;
}

function validateExternalAuthorityProof(artifact, inputs, {
  authorityDigest,
  conflictBinding,
  correctionCandidateDigest,
  now,
  ownerAssignmentIri,
  predecessorSourceHead,
  predecessorSourceTree,
  repository,
}) {
  const value = artifact.value;
  exactObjectKeys(value, [
    'artifacts', 'authorityDigest', 'candidateDigest', 'conflict', 'decision',
    'evidenceSetDigest', 'nonclaims', 'proof', 'repository', 'review', 'schema', 'source',
  ], 'external authority proof decision');
  exactObjectKeys(value.artifacts, EXTERNAL_AUTHORITY_EVIDENCE_ROLES,
    'external authority proof input artifacts');
  exactObjectKeys(value.source, [
    'predecessorHead', 'predecessorTree', 'sourcePaths', 'sourceScopeDigest', 'successorTree',
  ], 'external authority proof source');
  exactObjectKeys(value.conflict, [
    'authorities', 'operationDigest', 'requestedActions', 'requestedEffects',
    'requestedFormats', 'requestedPaths', 'validationObligations',
  ], 'external authority proof conflict');
  exactObjectKeys(value.review, ['defectCount', 'digest', 'independent', 'state'],
    'external authority proof review conclusion');
  exactObjectKeys(value.proof, [
    'algorithmIri', 'algorithmVersionIri', 'evaluatedAt', 'obligationIri', 'resultState',
    'state', 'subjectCandidateDigest', 'validUntil',
  ], 'external authority proof result');
  exactObjectKeys(value.decision, ['ownerAssignmentIri', 'rationale', 'state'],
    'external authority owner decision');
  for (const role of EXTERNAL_AUTHORITY_EVIDENCE_ROLES) {
    exactArtifactDescriptor(value.artifacts[role], inputs.get(role),
      `external authority proof ${role} descriptor`);
  }
  const evidenceSetDigest = sha256(Buffer.from(canonicalJson(value.artifacts), 'utf8'));
  const observedNow = now instanceof Date ? now.getTime() : Date.parse(now);
  const evaluated = Date.parse(value.proof.evaluatedAt);
  const validUntil = Date.parse(value.proof.validUntil);
  if (value.schema !== EXTERNAL_AUTHORITY_PROOF_SCHEMA
      || value.authorityDigest !== authorityDigest
      || value.repository !== repository
      || value.candidateDigest !== correctionCandidateDigest
      || value.source.predecessorHead !== predecessorSourceHead
      || value.source.predecessorTree !== predecessorSourceTree
      || value.source.successorTree !== conflictBinding.successorSourceTree
      || value.source.sourceScopeDigest !== conflictBinding.sourceScopeDigest
      || canonicalJson(value.source.sourcePaths) !== canonicalJson(conflictBinding.sourcePaths)
      || canonicalJson(value.conflict.authorities) !== canonicalJson(conflictBinding.conflictingAuthorities)
      || value.conflict.operationDigest !== conflictBinding.operationDigest
      || canonicalJson(value.conflict.requestedActions) !== canonicalJson(conflictBinding.requestedActions)
      || canonicalJson(value.conflict.requestedEffects) !== canonicalJson(conflictBinding.requestedEffects)
      || canonicalJson(value.conflict.requestedFormats) !== canonicalJson(conflictBinding.requestedFormats)
      || canonicalJson(value.conflict.requestedPaths) !== canonicalJson(conflictBinding.requestedPaths)
      || canonicalJson(value.conflict.validationObligations)
        !== canonicalJson(conflictBinding.validationObligations)
      || value.evidenceSetDigest !== evidenceSetDigest
      || value.review.digest !== inputs.get('review').digest
      || value.review.state !== 'ACCEPTED'
      || value.review.independent !== true
      || value.review.defectCount !== 0
      || value.proof.state !== 'PASSED'
      || value.proof.resultState !== 'SUCCESSFUL'
      || value.proof.subjectCandidateDigest !== correctionCandidateDigest
      || value.proof.obligationIri !== 'urn:usf:proofobligation:compilersemanticenforcementaggregate'
      || value.proof.algorithmIri !== 'urn:usf:proofalgorithm:compilersemanticenforcementaggregate'
      || value.proof.algorithmVersionIri !== 'urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210'
      || !Number.isFinite(observedNow) || !Number.isFinite(evaluated) || !Number.isFinite(validUntil)
      || evaluated > observedNow || validUntil <= observedNow || validUntil <= evaluated
      || value.decision.state !== 'ACCEPTED'
      || value.decision.ownerAssignmentIri !== ownerAssignmentIri
      || typeof value.decision.rationale !== 'string' || value.decision.rationale.length < 1
      || canonicalJson(value.nonclaims) !== canonicalJson(EXTERNAL_AUTHORITY_NONCLAIMS)) {
    throw new CompilerError('external authority proof/decision is not exact, current and owner-authored', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return Object.freeze({ evidenceSetDigest, evaluatedAt: value.proof.evaluatedAt, validUntil: value.proof.validUntil, value });
}

function validateExternalAuthorityArtifacts({
  artifacts,
  authorityDigest,
  conflictBinding,
  correctionCandidateDigest,
  now,
  ownerAssignmentIri,
  predecessorSourceHead,
  predecessorSourceTree,
  proofApprovalEnvelope,
  repository,
  operationContentStore = null,
  trustAnchor,
  verifyProofApprovalEnvelope = missingExternalAuthorityProofVerifier,
}) {
  if (!(artifacts instanceof Map)
      || canonicalJson([...artifacts.keys()].sort()) !== canonicalJson(EXTERNAL_AUTHORITY_ARTIFACT_ROLES)) {
    throw new CompilerError('external authority artifact role set is incomplete', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const parsed = new Map([...artifacts].map(([role, bytes]) => [
    role, parseCanonicalJsonArtifact(bytes, `external authority ${role} artifact`),
  ]));
  const operations = validateExternalAuthorityOperations(parsed.get('operations'), repository, operationContentStore);
  if (operations.operationDigest !== conflictBinding.operationDigest
      || canonicalJson(operations.requestedActions) !== canonicalJson(conflictBinding.requestedActions)
      || canonicalJson(operations.requestedFormats) !== canonicalJson(conflictBinding.requestedFormats)
      || canonicalJson(operations.requestedPaths) !== canonicalJson(conflictBinding.requestedPaths)
      || externalAuthoritySourceScopeDigest(conflictBinding.sourcePaths) !== conflictBinding.sourceScopeDigest) {
    throw new CompilerError('external authority operation or source-scope digest was not derived from canonical bytes', {
      phase: 'candidate:external-authority-delta',
    });
  }
  validateExternalAuthorityInventory(parsed.get('inventory'), {
    authorityDigest, conflictBinding, correctionCandidateDigest, operations,
    predecessorSourceHead, predecessorSourceTree, repository,
  });
  validateExternalAuthorityReview(parsed.get('review'), parsed.get('inventory'), {
    authorityDigest, conflictBinding, operations, predecessorSourceHead, predecessorSourceTree,
  });
  const proof = validateExternalAuthorityProof(parsed.get('proof'), parsed, {
    authorityDigest, conflictBinding, correctionCandidateDigest, now, ownerAssignmentIri,
    predecessorSourceHead, predecessorSourceTree, repository,
  });
  let verifiedApproval;
  try {
    verifiedApproval = verifyProofApprovalEnvelope(proofApprovalEnvelope, {
      authorityDomain: EXTERNAL_AUTHORITY_DOMAIN,
      authorityPreDigest: authorityDigest,
      candidateDigest: parsed.get('proof').digest,
      claimType: 'candidate_approval',
      expectedSingleUse: false,
      now,
      repository,
      sourcePaths: conflictBinding.sourcePaths,
      ...(trustAnchor === undefined ? {} : { trustAnchor }),
    });
  } catch (error) {
    throw new CompilerError(`external authority proof owner approval is invalid: ${error.message}`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  const approvalExpiresAt = Date.parse(verifiedApproval.expires_at);
  if (verifiedApproval.fingerprint !== AUTHORITY_FINGERPRINT
      || verifiedApproval.principal !== AUTHORITY_PRINCIPAL
      || verifiedApproval.signing_identity !== AUTHORITY_SIGNING_IDENTITY
      || verifiedApproval.claim_type !== 'candidate_approval'
      || verifiedApproval.authority_domain !== EXTERNAL_AUTHORITY_DOMAIN
      || verifiedApproval.authority_pre_digest !== authorityDigest
      || verifiedApproval.repository !== repository
      || verifiedApproval.source_scope_digest !== conflictBinding.sourceScopeDigest
      || verifiedApproval.candidate_digest !== parsed.get('proof').digest
      || verifiedApproval.single_use !== false
      || !Number.isFinite(approvalExpiresAt)
      || approvalExpiresAt < Date.parse(proof.validUntil)) {
    throw new CompilerError('external authority proof owner approval does not bind the proof lifetime and identity', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return Object.freeze({ artifacts: parsed, operations, proof, verifiedApproval });
}

function conflictBindingFromProofDocument(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !value.conflict || !value.source || !value.decision) {
    throw new CompilerError('external authority proof does not contain a conflict/source/decision binding', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return Object.freeze({
    conflictingAuthorities: value.conflict.authorities,
    operationDigest: value.conflict.operationDigest,
    requestedActions: value.conflict.requestedActions,
    requestedEffects: value.conflict.requestedEffects,
    requestedFormats: value.conflict.requestedFormats,
    requestedPaths: value.conflict.requestedPaths,
    sourcePaths: value.source.sourcePaths,
    sourceScopeDigest: value.source.sourceScopeDigest,
    successorSourceTree: value.source.successorTree,
    validationObligations: value.conflict.validationObligations,
  });
}

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const USF = 'urn:usf:ontology:';

function patchHas(patch, subject, predicate, object) {
  return patch.additions.some(({ value }) => value.subject.value === subject
    && value.predicate.value === predicate && value.object.value === object);
}

function requirePatchTriple(patch, subject, predicate, object, label) {
  if (!patchHas(patch, subject, predicate, object)) {
    throw new CompilerError(`external authority delta is missing exact ${label}`, {
      phase: 'candidate:external-authority-delta', subject, predicate, object,
    });
  }
}

const EXTERNAL_AUTHORITY_ROLE_PREDICATES = Object.freeze({
  conflict: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}conflictAuthorityDigest`,
    `${USF}conflictingAuthority`, `${USF}conflictRepository`, `${USF}conflictOperationDigest`,
    `${USF}conflictCandidateDigest`, `${USF}conflictPredecessorSourceHead`,
    `${USF}conflictPredecessorSourceTree`, `${USF}conflictSuccessorSourceTree`,
    `${USF}conflictSourceScopeDigest`, `${USF}conflictSourcePath`,
    `${USF}conflictRequestedAction`, `${USF}conflictRequestedPath`,
    `${USF}conflictRequestedRepresentationFormat`, `${USF}conflictRequestedEffect`,
    `${USF}conflictBlockedByValidationObligation`,
  ]),
  review: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}hasSemanticAdequacyReviewState`,
    `${USF}reviewedAuthorityDigest`, `${USF}reviewedInventoryDigest`, `${USF}reviewedItemCount`,
    `${USF}usesDispositionInventoryDescriptor`, `${USF}usesIndependentReviewDescriptor`,
    `${USF}usesSemanticAdequacyProofDescriptor`,
  ]),
  resolution: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}decisionRationale`,
    `${USF}semanticCorrectionDecisionState`, `${USF}decisionBasedOnSemanticAdequacyReview`,
    `${USF}warrantedBySemanticAdequacyProof`, `${USF}resolvesAuthorityConflict`,
    `${USF}authorityConflictResolutionOwnerAssignment`,
  ]),
  proof: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}atRung`, `${USF}exercises`,
    `${USF}inEnvironment`, `${USF}provesSubject`, `${USF}usesProviderMode`,
  ]),
  proofResult: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}claimedRung`, `${USF}observedRung`,
    `${USF}hasFreshness`, `${USF}hasProofResultState`, `${USF}inEnvironment`,
    `${USF}resultState`, `${USF}resultForProof`, `${USF}usesProviderMode`,
    `${USF}proofExecutionEnvironment`, `${USF}evidenceSetDigest`, `${USF}evaluatedAt`,
    `${USF}uncertaintyStatement`, `${USF}hasInvalidationCondition`,
    `${USF}proofResultForObligation`, `${USF}usesAdmittedEvidence`,
    `${USF}usesProofAlgorithm`, `${USF}usesAlgorithmVersion`,
    `${USF}evaluatedByValidator`, `${USF}hasConfidenceState`, `${USF}confidenceBasis`,
  ]),
  descriptor: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}descriptorArtefactFamily`,
    `${USF}descriptorRepresentationFormat`, `${USF}descriptorMediaType`,
    `${USF}descriptorDigest`, `${USF}descriptorByteSize`, `${USF}descriptorLocator`,
    `${USF}descriptorArtefactType`, `${USF}descriptorStorageClass`,
  ]),
  disposition: new Set([
    `${USF}reviewedInSemanticAdequacyReview`, `${USF}semanticAdequacyDisposition`,
    `${USF}authorisedBySemanticCorrectionDecision`, `${USF}sourceItemDigest`,
    `${USF}finalCanonicalSemanticItem`,
  ]),
  evidence: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}evidenceKind`, `${USF}usesProviderMode`,
    `${USF}inEnvironment`, `${USF}hasFreshness`, `${USF}evidenceFor`, `${USF}evidenceForContract`,
    `${USF}contentDigest`, `${USF}mediaType`, `${USF}byteSize`,
    `${USF}storageLocator`, `${USF}wasProducedBy`, `${USF}collectedAt`, `${USF}validUntil`,
    `${USF}hasFreshnessPolicy`, `${USF}hasAdmissionState`, `${USF}hasFreshnessState`,
    `${USF}hasIntegrityState`, `${USF}concernsSemanticSubject`, `${USF}evidenceStage`,
    `${USF}collectedBy`, `${USF}normalisedBy`, `${USF}ingestedBy`, `${USF}evidenceSignature`,
    `${USF}evidenceChecksum`, `${USF}integrityVerification`, `${USF}applicableToObligation`,
    `${USF}withinValidityScope`,
  ]),
  collection: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}collectionForRequirement`,
    `${USF}collectedEvidence`, `${USF}collectsEvidence`, `${USF}collectedOn`, `${USF}sourceDigest`,
  ]),
  normalisation: new Set([RDF_TYPE, `${USF}canonicalName`, `${USF}normalisesEvidence`]),
  ingestion: new Set([RDF_TYPE, `${USF}canonicalName`, `${USF}ingestsEvidence`]),
  integrity: new Set([RDF_TYPE, `${USF}canonicalName`, `${USF}verifiesEvidence`, `${USF}verificationState`]),
  checksum: new Set([RDF_TYPE, `${USF}canonicalName`, `${USF}checksumAlgorithm`, `${USF}checksumValue`]),
  signature: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}artefactKind`, `${USF}canonicalPath`,
    `${USF}governedByPathRule`, `${USF}signatureMethod`, `${USF}signingPolicy`,
    `${USF}signedBy`, `${USF}signatureValue`,
  ]),
});

const EXTERNAL_AUTHORITY_MULTI_PREDICATES = Object.freeze({
  conflict: new Set([
    `${USF}conflictingAuthority`, `${USF}conflictSourcePath`, `${USF}conflictRequestedAction`,
    `${USF}conflictRequestedPath`, `${USF}conflictRequestedRepresentationFormat`,
    `${USF}conflictRequestedEffect`, `${USF}conflictBlockedByValidationObligation`,
  ]),
  proof: new Set([`${USF}exercises`]),
  proofResult: new Set([
    `${USF}hasInvalidationCondition`, `${USF}usesAdmittedEvidence`, `${USF}confidenceBasis`,
  ]),
  evidence: new Set([`${USF}evidenceForContract`, `${USF}evidenceStage`]),
});

function exactPatchObjects(patch, subject, predicate) {
  return patch.additions
    .filter(({ value: item }) => item.subject.value === subject && item.predicate.value === predicate)
    .map(({ value: item }) => item.object.value);
}

function assertExternalAuthorityClosedShape(patch, value, verifiedArtifacts, artifactValidation) {
  const roots = [...verifiedArtifacts.keys()].sort();
  const proofLinks = exactPatchObjects(patch, value.proofResultIri, `${USF}resultForProof`);
  if (proofLinks.length !== 1 || !/^urn:usf:proof:[a-z0-9]+$/.test(proofLinks[0])) {
    throw new CompilerError('external authority delta proof identity is not exact', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const proofIri = proofLinks[0];
  const descriptorSubjects = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}descriptorDigest`
      && roots.includes(item.object.value))
    .map(({ value: item }) => item.subject.value))].sort();
  if (descriptorSubjects.length !== roots.length
      || descriptorSubjects.some((item) => !/^urn:usf:externalpayloaddescriptor:[a-z0-9]+$/.test(item))) {
    throw new CompilerError('external authority delta descriptor identities are not one-to-one with CAS roots', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const dispositionSubjects = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}reviewedInSemanticAdequacyReview`
      && item.object.value === value.reviewIri)
    .map(({ value: item }) => item.subject.value))].sort();
  if (dispositionSubjects.some((item) => !/^urn:usf:historicalitem:[0-9a-f]{64}$/.test(item))) {
    throw new CompilerError('external authority delta review disposition identity is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const evidenceSubjects = [...new Set(exactPatchObjects(
    patch,
    value.proofResultIri,
    `${USF}usesAdmittedEvidence`,
  ))].sort();
  if (evidenceSubjects.length !== 3
      || evidenceSubjects.some((item) => !/^urn:usf:evidenceresult:[a-z0-9]+$/.test(item))) {
    throw new CompilerError('external authority delta requires exactly three admitted proof evidence subjects', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const linkedSubjects = (predicate, pattern, label) => {
    const subjects = [...new Set(evidenceSubjects.flatMap((evidence) => exactPatchObjects(
      patch,
      evidence,
      predicate,
    )))].sort();
    if (subjects.length === 0 || subjects.some((item) => !pattern.test(item))) {
      throw new CompilerError(`external authority delta ${label} identity is invalid`, {
        phase: 'candidate:external-authority-delta',
      });
    }
    return subjects;
  };
  const collectionSubjects = linkedSubjects(`${USF}collectedBy`, /^urn:usf:evidencecollection:[a-z0-9]+$/, 'collection');
  const normalisationSubjects = linkedSubjects(`${USF}normalisedBy`, /^urn:usf:evidencenormalisation:[a-z0-9]+$/, 'normalisation');
  const ingestionSubjects = linkedSubjects(`${USF}ingestedBy`, /^urn:usf:evidenceingestion:[a-z0-9]+$/, 'ingestion');
  const integritySubjects = linkedSubjects(`${USF}integrityVerification`, /^urn:usf:integrityverification:[a-z0-9]+$/, 'integrity verification');
  const checksumSubjects = linkedSubjects(`${USF}evidenceChecksum`, /^urn:usf:checksum:[a-z0-9]+$/, 'checksum');
  const signatureSubjects = linkedSubjects(`${USF}evidenceSignature`, /^urn:usf:signature:[a-z0-9]+$/, 'signature');
  if ([collectionSubjects, normalisationSubjects, ingestionSubjects, integritySubjects, checksumSubjects]
    .some((subjects) => subjects.length !== evidenceSubjects.length)
      || signatureSubjects.length !== 1) {
    throw new CompilerError('external authority delta evidence lifecycle is not one-to-one with one shared signature', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const roleBySubject = new Map([
    [value.conflictIri, 'conflict'], [value.reviewIri, 'review'],
    [value.resolutionIri, 'resolution'], [value.proofResultIri, 'proofResult'], [proofIri, 'proof'],
    ...descriptorSubjects.map((item) => [item, 'descriptor']),
    ...dispositionSubjects.map((item) => [item, 'disposition']),
    ...evidenceSubjects.map((item) => [item, 'evidence']),
    ...collectionSubjects.map((item) => [item, 'collection']),
    ...normalisationSubjects.map((item) => [item, 'normalisation']),
    ...ingestionSubjects.map((item) => [item, 'ingestion']),
    ...integritySubjects.map((item) => [item, 'integrity']),
    ...checksumSubjects.map((item) => [item, 'checksum']),
    ...signatureSubjects.map((item) => [item, 'signature']),
  ]);
  const expectedRoleCount = 5 + descriptorSubjects.length + dispositionSubjects.length
    + evidenceSubjects.length + collectionSubjects.length + normalisationSubjects.length
    + ingestionSubjects.length + integritySubjects.length + checksumSubjects.length
    + signatureSubjects.length;
  if (roleBySubject.size !== expectedRoleCount) {
    throw new CompilerError('external authority delta semantic roles overlap', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const cardinality = new Map();
  const observedPredicates = new Map();
  for (const { value: item } of patch.additions) {
    const role = roleBySubject.get(item.subject.value);
    if (!role || !EXTERNAL_AUTHORITY_ROLE_PREDICATES[role].has(item.predicate.value)) {
      throw new CompilerError('external authority delta contains an unrelated semantic operation', {
        phase: 'candidate:external-authority-delta',
        predicate: item.predicate.value,
        subject: item.subject.value,
      });
    }
    const key = `${item.subject.value}\u0000${item.predicate.value}`;
    if (!observedPredicates.has(item.subject.value)) observedPredicates.set(item.subject.value, new Set());
    observedPredicates.get(item.subject.value).add(item.predicate.value);
    cardinality.set(key, (cardinality.get(key) || 0) + 1);
    if (!EXTERNAL_AUTHORITY_MULTI_PREDICATES[role]?.has(item.predicate.value)
        && cardinality.get(key) > 1) {
      throw new CompilerError('external authority delta contains an ambiguous singleton property', {
        phase: 'candidate:external-authority-delta',
        predicate: item.predicate.value,
        subject: item.subject.value,
      });
    }
  }
  for (const [subject, role] of roleBySubject) {
    const expected = [...EXTERNAL_AUTHORITY_ROLE_PREDICATES[role]].sort();
    const observed = [...(observedPredicates.get(subject) || [])].sort();
    if (canonicalJson(observed) !== canonicalJson(expected)) {
      throw new CompilerError('external authority delta semantic role is incomplete', {
        phase: 'candidate:external-authority-delta', expected, observed, role, subject,
      });
    }
  }
  const requireExactObjects = (subject, predicate, expected, label) => {
    const observed = exactPatchObjects(patch, subject, predicate).sort();
    const values = [...expected].sort();
    if (canonicalJson(observed) !== canonicalJson(values)) {
      throw new CompilerError(`external authority delta ${label} is not exact`, {
        phase: 'candidate:external-authority-delta', expected: values, observed, predicate, subject,
      });
    }
  };
  requireExactObjects(proofIri, RDF_TYPE, [`${USF}Proof`], 'proof type');
  requireExactObjects(proofIri, `${USF}atRung`, ['urn:usf:proofrung:behaviour'], 'proof rung');
  requireExactObjects(proofIri, `${USF}usesProviderMode`, ['urn:usf:providermode:deterministictestsubstitute'], 'proof provider mode');
  requireExactObjects(proofIri, `${USF}inEnvironment`, ['urn:usf:environment:hermetic'], 'proof environment');
  requireExactObjects(proofIri, `${USF}exercises`, ['urn:usf:semanticcontract:compilersemanticenforcement'], 'proof contract');
  requireExactObjects(value.proofResultIri, RDF_TYPE, [`${USF}ProofResult`], 'proof-result type');
  for (const [predicate, expected, label] of [
    [`${USF}resultState`, 'urn:usf:resultstate:passed', 'proof result state'],
    [`${USF}hasProofResultState`, 'urn:usf:proofresultstate:successful', 'proof success state'],
    [`${USF}claimedRung`, 'urn:usf:proofrung:behaviour', 'claimed rung'],
    [`${USF}observedRung`, 'urn:usf:proofrung:behaviour', 'observed rung'],
    [`${USF}hasFreshness`, 'urn:usf:freshness:fresh', 'proof freshness'],
    [`${USF}usesProviderMode`, 'urn:usf:providermode:deterministictestsubstitute', 'proof-result provider mode'],
    [`${USF}inEnvironment`, 'urn:usf:environment:hermetic', 'proof-result environment'],
    [`${USF}proofExecutionEnvironment`, 'urn:usf:environment:hermetic', 'proof execution environment'],
    [`${USF}proofResultForObligation`, 'urn:usf:proofobligation:compilersemanticenforcementaggregate', 'proof obligation'],
    [`${USF}usesProofAlgorithm`, 'urn:usf:proofalgorithm:compilersemanticenforcementaggregate', 'proof algorithm'],
    [`${USF}usesAlgorithmVersion`, 'urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210', 'proof algorithm version'],
    [`${USF}evaluatedByValidator`, 'urn:usf:validatorrule:validateassuranceconformance', 'proof validator'],
    [`${USF}hasConfidenceState`, 'urn:usf:proofconfidencestate:warranted', 'proof confidence'],
  ]) requireExactObjects(value.proofResultIri, predicate, [expected], label);
  for (const subject of descriptorSubjects) {
    const digests = exactPatchObjects(patch, subject, `${USF}descriptorDigest`);
    if (digests.length !== 1 || !roots.includes(digests[0])) {
      throw new CompilerError('external authority delta descriptor root is ambiguous', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
    const byteSizes = exactPatchObjects(patch, subject, `${USF}descriptorByteSize`);
    const locators = exactPatchObjects(patch, subject, `${USF}descriptorLocator`);
    if (byteSizes.length !== 1 || Number(byteSizes[0]) !== verifiedArtifacts.get(digests[0]).byteSize
        || locators.length !== 1 || locators[0] !== `cas://sha256/${digests[0].slice(7)}`) {
      throw new CompilerError('external authority delta descriptor does not bind exact CAS bytes', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
    for (const [predicate, expected, label] of [
      [RDF_TYPE, `${USF}ExternalPayloadDescriptor`, 'descriptor type'],
      [`${USF}descriptorArtefactFamily`, 'urn:usf:artefactfamily:evidencepayload', 'descriptor family'],
      [`${USF}descriptorRepresentationFormat`, 'urn:usf:representationformat:jsondata8259', 'descriptor format'],
      [`${USF}descriptorMediaType`, 'application/json', 'descriptor media type'],
      [`${USF}descriptorStorageClass`, 'urn:usf:storageclass:contentaddressedobjectstorage', 'descriptor storage class'],
    ]) requireExactObjects(subject, predicate, [expected], label);
  }
  const reviewDescriptorSubjects = [
    `${USF}usesDispositionInventoryDescriptor`, `${USF}usesIndependentReviewDescriptor`,
    `${USF}usesSemanticAdequacyProofDescriptor`,
  ].flatMap((predicate) => exactPatchObjects(patch, value.reviewIri, predicate)).sort();
  const reviewedRoles = new Set(['inventory', 'proof', 'review']);
  const expectedReviewDescriptorSubjects = descriptorSubjects.filter((subject) => {
    const digest = exactPatchObjects(patch, subject, `${USF}descriptorDigest`)[0];
    return reviewedRoles.has(verifiedArtifacts.get(digest).role);
  }).sort();
  if (canonicalJson(reviewDescriptorSubjects) !== canonicalJson(expectedReviewDescriptorSubjects)) {
    throw new CompilerError('external authority delta review does not bind its exact inventory/review/proof descriptors', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const descriptorByDigest = new Map(descriptorSubjects.map((subject) => {
    const digests = exactPatchObjects(patch, subject, `${USF}descriptorDigest`);
    return [digests[0], subject];
  }));
  const evidenceDigests = evidenceSubjects.map((subject) => {
    const digests = exactPatchObjects(patch, subject, `${USF}contentDigest`);
    if (digests.length !== 1 || !descriptorByDigest.has(digests[0])) {
      throw new CompilerError('external authority delta evidence does not bind one review descriptor digest', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
    const concerns = exactPatchObjects(patch, subject, `${USF}concernsSemanticSubject`);
    const stages = exactPatchObjects(patch, subject, `${USF}evidenceStage`).sort();
    const requiredStages = [
      'collected', 'emitted', 'ingested', 'integrityverified', 'normalised', 'signed',
    ].map((name) => `urn:usf:evidencestage:${name}`).sort();
    if (concerns.length !== 1 || concerns[0] !== value.reviewIri
        || canonicalJson(stages) !== canonicalJson(requiredStages)) {
      throw new CompilerError('external authority delta evidence review binding or lifecycle stages are incomplete', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
    return digests[0];
  }).sort();
  const expectedEvidenceDigests = roots.filter((root) => EXTERNAL_AUTHORITY_EVIDENCE_ROLES
    .includes(verifiedArtifacts.get(root).role)).sort();
  if (canonicalJson(evidenceDigests) !== canonicalJson(expectedEvidenceDigests)) {
    throw new CompilerError('external authority delta proof evidence is not the exact inventory/operations/review set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const confidenceBasis = exactPatchObjects(patch, value.proofResultIri, `${USF}confidenceBasis`).sort();
  if (canonicalJson(confidenceBasis) !== canonicalJson(evidenceSubjects)) {
    throw new CompilerError('external authority delta proof confidence is not bound to its exact evidence set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const evidenceSetDigests = exactPatchObjects(patch, value.proofResultIri, `${USF}evidenceSetDigest`);
  if (evidenceSetDigests.length !== 1
      || evidenceSetDigests[0] !== artifactValidation.proof.evidenceSetDigest) {
    throw new CompilerError('external authority delta proof evidence-set digest is not exact', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const evidence of evidenceSubjects) {
    const contentDigest = exactPatchObjects(patch, evidence, `${USF}contentDigest`)[0];
    const byteSizes = exactPatchObjects(patch, evidence, `${USF}byteSize`);
    const locators = exactPatchObjects(patch, evidence, `${USF}storageLocator`);
    const checksum = exactPatchObjects(patch, evidence, `${USF}evidenceChecksum`)[0];
    const checksumValue = exactPatchObjects(patch, checksum, `${USF}checksumValue`);
    if (byteSizes.length !== 1 || Number(byteSizes[0]) !== verifiedArtifacts.get(contentDigest).byteSize
        || locators.length !== 1 || locators[0] !== `cas://sha256/${contentDigest.slice(7)}`
        || checksumValue.length !== 1 || checksumValue[0] !== contentDigest.slice(7)) {
      throw new CompilerError('external authority delta evidence checksum does not match its content digest', {
        phase: 'candidate:external-authority-delta', evidence,
      });
    }
    for (const [predicate, expected, label] of [
      [RDF_TYPE, `${USF}EvidenceResult`, 'evidence type'],
      [`${USF}evidenceKind`, 'urn:usf:evidencekind:semanticreviewevidence', 'evidence kind'],
      [`${USF}usesProviderMode`, 'urn:usf:providermode:deterministictestsubstitute', 'evidence provider mode'],
      [`${USF}inEnvironment`, 'urn:usf:environment:hermetic', 'evidence environment'],
      [`${USF}hasFreshness`, 'urn:usf:freshness:fresh', 'evidence freshness'],
      [`${USF}evidenceFor`, value.conflictIri, 'evidence subject'],
      [`${USF}evidenceForContract`, 'urn:usf:semanticcontract:compilersemanticenforcement', 'evidence contract'],
      [`${USF}mediaType`, 'application/json', 'evidence media type'],
      [`${USF}wasProducedBy`, 'urn:usf:validatorrule:validateassuranceconformance', 'evidence validator'],
      [`${USF}hasFreshnessPolicy`, 'urn:usf:evidencefreshnesspolicy:semanticadequacyreviewauthoritybound', 'evidence freshness policy'],
      [`${USF}hasAdmissionState`, 'urn:usf:evidenceadmissionstate:admitted', 'evidence admission state'],
      [`${USF}hasFreshnessState`, 'urn:usf:evidencefreshnessstate:fresh', 'evidence freshness state'],
      [`${USF}hasIntegrityState`, 'urn:usf:evidenceintegritystate:valid', 'evidence integrity state'],
      [`${USF}applicableToObligation`, 'urn:usf:proofobligation:compilersemanticenforcementaggregate', 'evidence obligation'],
      [`${USF}withinValidityScope`, 'true', 'evidence validity scope'],
    ]) requireExactObjects(evidence, predicate, [expected], label);
    for (const [predicate, rolePredicate] of [
      [`${USF}collectedBy`, `${USF}collectedEvidence`],
      [`${USF}normalisedBy`, `${USF}normalisesEvidence`],
      [`${USF}ingestedBy`, `${USF}ingestsEvidence`],
      [`${USF}integrityVerification`, `${USF}verifiesEvidence`],
    ]) {
      const lifecycle = exactPatchObjects(patch, evidence, predicate);
      if (lifecycle.length !== 1 || !patchHas(patch, lifecycle[0], rolePredicate, evidence)) {
        throw new CompilerError('external authority delta evidence lifecycle does not point back to its evidence', {
          phase: 'candidate:external-authority-delta', evidence, predicate,
        });
      }
    }
  }
  for (const subject of collectionSubjects) {
    requireExactObjects(subject, RDF_TYPE, [`${USF}EvidenceCollection`], 'collection type');
    requireExactObjects(subject, `${USF}collectionForRequirement`, ['urn:usf:evidencerequirement:compilersemanticvalidation'], 'collection requirement');
  }
  for (const subject of normalisationSubjects) requireExactObjects(subject, RDF_TYPE, [`${USF}EvidenceNormalisation`], 'normalisation type');
  for (const subject of ingestionSubjects) requireExactObjects(subject, RDF_TYPE, [`${USF}EvidenceIngestion`], 'ingestion type');
  for (const subject of integritySubjects) {
    requireExactObjects(subject, RDF_TYPE, [`${USF}IntegrityVerification`], 'integrity type');
    requireExactObjects(subject, `${USF}verificationState`, ['urn:usf:resultstate:passed'], 'integrity state');
  }
  for (const subject of checksumSubjects) {
    requireExactObjects(subject, RDF_TYPE, [`${USF}Checksum`], 'checksum type');
    requireExactObjects(subject, `${USF}checksumAlgorithm`, ['urn:usf:checksumalgorithm:sha256'], 'checksum algorithm');
  }
  const signature = signatureSubjects[0];
  for (const [predicate, expected, label] of [
    [RDF_TYPE, `${USF}Signature`, 'signature type'],
    [`${USF}artefactKind`, 'urn:usf:artefactkind:signature', 'signature artefact kind'],
    [`${USF}governedByPathRule`, 'urn:usf:pathrule:contentaddressedsignature', 'signature path rule'],
    [`${USF}signatureMethod`, 'urn:usf:signaturemethod:detached', 'signature method'],
    [`${USF}signingPolicy`, 'urn:usf:policy:hermeticevidenceattestation', 'signature policy'],
  ]) requireExactObjects(signature, predicate, [expected], label);
  const signedBy = exactPatchObjects(patch, signature, `${USF}signedBy`);
  const signatureValue = exactPatchObjects(patch, signature, `${USF}signatureValue`);
  if (signedBy.length !== 1 || signedBy[0] !== AUTHORITY_SIGNING_IDENTITY
      || signatureValue.length !== 1
      || signatureValue[0] !== artifactValidation.proofApprovalEnvelope.signature) {
    throw new CompilerError('external authority delta signature identity or value is invalid', {
      phase: 'candidate:external-authority-delta', signature,
    });
  }
  const proofDescriptor = exactPatchObjects(patch, value.reviewIri, `${USF}usesSemanticAdequacyProofDescriptor`);
  const proofRoot = proofDescriptor.length === 1
    ? exactPatchObjects(patch, proofDescriptor[0], `${USF}descriptorDigest`)
    : [];
  requireExactObjects(signature, `${USF}canonicalPath`, proofRoot.length === 1
    ? [`cas://sha256/${proofRoot[0].slice(7)}#signature`]
    : [], 'signature canonical path');
  const reviewCounts = exactPatchObjects(patch, value.reviewIri, `${USF}reviewedItemCount`);
  if (reviewCounts.length > 0
      && (reviewCounts.length !== 1 || Number(reviewCounts[0]) !== dispositionSubjects.length)) {
    throw new CompilerError('external authority delta review item count is not exact', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const subject of dispositionSubjects) {
    const suffix = subject.slice('urn:usf:historicalitem:'.length);
    const sourceDigests = exactPatchObjects(patch, subject, `${USF}sourceItemDigest`);
    const decisions = exactPatchObjects(patch, subject, `${USF}authorisedBySemanticCorrectionDecision`);
    if (sourceDigests.length !== 1 || sourceDigests[0] !== `sha256:${suffix}`
        || decisions.length !== 1 || decisions[0] !== value.resolutionIri) {
      throw new CompilerError('external authority delta review disposition is not decision-bound', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
  }
  return proofIri;
}

function assertExternalAuthorityDelta({
  value,
  expectedAuthorityDigest,
  expectedSource,
  evidenceStore,
  allowedGraphs,
  now = null,
  trustAnchor,
  verifyProofApprovalEnvelope = missingExternalAuthorityProofVerifier,
}) {
  exactObjectKeys(value, [
    'artifactDescriptors', 'authorityDigest', 'casRootDigests', 'conflictIri', 'correctionCandidateDigest',
    'ownerAssignmentIri', 'patchBytesBase64', 'patchDigest', 'predecessorSourceHead',
    'predecessorSourceTree', 'proofApprovalEnvelope', 'proofResultIri', 'repository', 'resolutionIri', 'reviewIri',
    'schema', 'permittedOperations',
  ], 'external authority delta');
  if (value.schema !== EXTERNAL_AUTHORITY_DELTA_SCHEMA || value.authorityDigest !== expectedAuthorityDigest
      || !expectedSource || value.repository !== expectedSource.repository
      || value.predecessorSourceHead !== expectedSource.head
      || value.predecessorSourceTree !== expectedSource.tree
      || !GIT_OBJECT.test(value.predecessorSourceHead || '') || !GIT_OBJECT.test(value.predecessorSourceTree || '')
      || !SHA256.test(value.correctionCandidateDigest || '')
      || !SHA256.test(value.patchDigest || '')) {
    throw new CompilerError('external authority delta does not bind the exact authority and source predecessor', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const [name, iri] of Object.entries({
    conflict: value.conflictIri,
    owner: value.ownerAssignmentIri,
    proof: value.proofResultIri,
    resolution: value.resolutionIri,
    review: value.reviewIri,
  })) {
    const pattern = name === 'owner'
      ? /^urn:usf:ownerassignment:[a-z0-9:]+$/
      : /^urn:usf:[a-z0-9]+:[a-z0-9]+$/;
    if (typeof iri !== 'string' || !pattern.test(iri)) {
      throw new CompilerError(`external authority delta ${name} IRI is invalid`, {
        phase: 'candidate:external-authority-delta',
      });
    }
  }
  let bytes;
  try {
    bytes = Buffer.from(value.patchBytesBase64, 'base64');
  } catch {
    throw new CompilerError('external authority delta patch is not base64', { phase: 'candidate:external-authority-delta' });
  }
  if (bytes.toString('base64') !== value.patchBytesBase64 || sha256(bytes) !== value.patchDigest) {
    throw new CompilerError('external authority delta patch bytes or digest are not canonical', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const patch = parseCanonicalPatch(bytes, value.patchDigest, allowedGraphs, new Set(['base']));
  if (patch.deletions.length !== 0) {
    throw new CompilerError('external authority delta must be additive', { phase: 'candidate:external-authority-delta' });
  }
  const permittedOperations = exactSortedUniqueStrings(
    value.permittedOperations,
    /^[AD] .+$/,
    'external authority delta permitted operations',
  );
  const observedOperations = patch.operations.map(({ action, line }) => `${action} ${line}`).sort();
  if (canonicalJson(permittedOperations) !== canonicalJson(observedOperations)) {
    throw new CompilerError('external authority delta exceeds its exact permitted operation set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const roots = exactSortedUniqueStrings(value.casRootDigests, SHA256, 'external authority delta CAS roots', { minimum: 3 });
  if (!evidenceStore || typeof evidenceStore.verify !== 'function' || typeof evidenceStore.read !== 'function') {
    throw new CompilerError('external authority delta requires the canonical CAS reader and verifier', {
      phase: 'candidate:external-authority-delta',
    });
  }
  if (!Array.isArray(value.artifactDescriptors)
      || value.artifactDescriptors.length !== EXTERNAL_AUTHORITY_ARTIFACT_ROLES.length) {
    throw new CompilerError('external authority delta artifact descriptor set is incomplete', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const descriptorByRole = new Map();
  for (const descriptor of value.artifactDescriptors) {
    exactObjectKeys(descriptor, ['byteSize', 'digest', 'jcsDigest', 'role'],
      'external authority delta artifact descriptor');
    if (!EXTERNAL_AUTHORITY_ARTIFACT_ROLES.includes(descriptor.role)
        || descriptorByRole.has(descriptor.role)
        || !SHA256.test(descriptor.digest || '') || !SHA256.test(descriptor.jcsDigest || '')
        || !Number.isSafeInteger(descriptor.byteSize) || descriptor.byteSize < 1) {
      throw new CompilerError('external authority delta artifact descriptor is invalid', {
        phase: 'candidate:external-authority-delta',
      });
    }
    descriptorByRole.set(descriptor.role, descriptor);
  }
  if (canonicalJson([...descriptorByRole.keys()].sort()) !== canonicalJson(EXTERNAL_AUTHORITY_ARTIFACT_ROLES)
      || canonicalJson([...descriptorByRole.values()].map(({ digest: item }) => item).sort())
        !== canonicalJson(roots)) {
    throw new CompilerError('external authority delta artifact descriptors do not equal the CAS root set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const verifiedArtifacts = new Map();
  const artifactBytes = new Map();
  for (const role of EXTERNAL_AUTHORITY_ARTIFACT_ROLES) {
    const descriptor = descriptorByRole.get(role);
    const verified = evidenceStore.verify(descriptor.digest);
    const read = evidenceStore.read(descriptor.digest);
    if (!verified || verified.digest !== descriptor.digest || !Number.isSafeInteger(verified.size)
        || verified.size !== descriptor.byteSize || !Buffer.isBuffer(read)
        || read.length !== descriptor.byteSize || sha256(read) !== descriptor.digest) {
      throw new CompilerError('external authority delta CAS verifier returned an invalid receipt', {
        phase: 'candidate:external-authority-delta', root: descriptor.digest,
      });
    }
    const parsed = parseCanonicalJsonArtifact(read, `external authority ${role} CAS artifact`);
    if (parsed.jcsDigest !== descriptor.jcsDigest) {
      throw new CompilerError('external authority delta CAS artifact JCS digest is invalid', {
        phase: 'candidate:external-authority-delta', root: descriptor.digest,
      });
    }
    verifiedArtifacts.set(descriptor.digest, Object.freeze({ byteSize: descriptor.byteSize, role }));
    artifactBytes.set(role, read);
  }
  const proofDocument = parseCanonicalJsonArtifact(artifactBytes.get('proof'),
    'external authority proof CAS artifact').value;
  const conflictBinding = conflictBindingFromProofDocument(proofDocument);
  const artifactValidation = validateExternalAuthorityArtifacts({
    artifacts: artifactBytes,
    authorityDigest: expectedAuthorityDigest,
    conflictBinding,
    correctionCandidateDigest: value.correctionCandidateDigest,
    now,
    ownerAssignmentIri: value.ownerAssignmentIri,
    predecessorSourceHead: expectedSource.head,
    predecessorSourceTree: expectedSource.tree,
    proofApprovalEnvelope: value.proofApprovalEnvelope,
    repository: expectedSource.repository,
    operationContentStore: evidenceStore,
    trustAnchor,
    verifyProofApprovalEnvelope,
  });
  const descriptorRoots = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}descriptorDigest` && SHA256.test(item.object.value))
    .map(({ value: item }) => item.object.value))].sort();
  if (canonicalJson(descriptorRoots) !== canonicalJson(roots)) {
    throw new CompilerError('external authority delta CAS roots do not equal its descriptor closure', {
      phase: 'candidate:external-authority-delta',
    });
  }

  const closedProofIri = assertExternalAuthorityClosedShape(
    patch,
    value,
    verifiedArtifacts,
    Object.freeze({ ...artifactValidation, proofApprovalEnvelope: value.proofApprovalEnvelope }),
  );

  requirePatchTriple(patch, value.conflictIri, RDF_TYPE, `${USF}AssuranceFinding`, 'authority-conflict type');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictAuthorityDigest`, expectedAuthorityDigest, 'authority digest');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictCandidateDigest`, value.correctionCandidateDigest, 'correction candidate digest');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictRepository`, value.repository, 'repository');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictPredecessorSourceHead`, expectedSource.head, 'predecessor head');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictPredecessorSourceTree`, expectedSource.tree, 'predecessor tree');
  requirePatchTriple(patch, value.reviewIri, RDF_TYPE, `${USF}SemanticAdequacyReview`, 'review type');
  requirePatchTriple(patch, value.reviewIri, `${USF}hasSemanticAdequacyReviewState`, 'urn:usf:semanticadequacyreviewstate:accepted', 'accepted review');
  requirePatchTriple(patch, value.reviewIri, `${USF}reviewedAuthorityDigest`, expectedAuthorityDigest, 'review authority');
  requirePatchTriple(patch, value.reviewIri, `${USF}reviewedInventoryDigest`, value.correctionCandidateDigest, 'review candidate');
  requirePatchTriple(patch, value.proofResultIri, RDF_TYPE, `${USF}ProofResult`, 'proof-result type');
  requirePatchTriple(patch, value.proofResultIri, `${USF}hasProofResultState`, 'urn:usf:proofresultstate:successful', 'successful proof');
  if (!patchHas(patch, closedProofIri, `${USF}provesSubject`, value.conflictIri)) {
    throw new CompilerError('external authority delta proof does not prove the exact conflict', {
      phase: 'candidate:external-authority-delta',
    });
  }
  requirePatchTriple(patch, value.resolutionIri, RDF_TYPE, `${USF}SemanticCorrectionDecision`, 'resolution type');
  requirePatchTriple(patch, value.resolutionIri, `${USF}resolvesAuthorityConflict`, value.conflictIri, 'resolved conflict');
  requirePatchTriple(patch, value.resolutionIri, `${USF}semanticCorrectionDecisionState`, 'urn:usf:semanticcorrectiondecisionstate:accepted', 'accepted resolution');
  requirePatchTriple(patch, value.resolutionIri, `${USF}decisionBasedOnSemanticAdequacyReview`, value.reviewIri, 'resolution review');
  requirePatchTriple(patch, value.resolutionIri, `${USF}warrantedBySemanticAdequacyProof`, value.proofResultIri, 'resolution proof');
  requirePatchTriple(patch, value.resolutionIri, `${USF}authorityConflictResolutionOwnerAssignment`, value.ownerAssignmentIri, 'resolution owner');
  return Object.freeze({
    casRootDigests: roots,
    conflictIri: value.conflictIri,
    correctionCandidateDigest: value.correctionCandidateDigest,
    patch,
    patchDigest: value.patchDigest,
    resolutionIri: value.resolutionIri,
    reviewIri: value.reviewIri,
    proofResultIri: value.proofResultIri,
    kind: 'authority_conflict',
  });
}

function createExternalAuthorityDeltaPackage({
  artifacts,
  authorityDigest,
  conflictBinding,
  correctionCandidateDigest,
  now = null,
  ownerAssignmentIri,
  predecessorSourceHead,
  predecessorSourceTree,
  proofApprovalEnvelope,
  repository,
  operationContentStore = null,
  trustAnchor,
  verifyProofApprovalEnvelope = missingExternalAuthorityProofVerifier,
}) {
  if (!SHA256.test(authorityDigest || '') || !SHA256.test(correctionCandidateDigest || '')
      || !GIT_OBJECT.test(predecessorSourceHead || '') || !GIT_OBJECT.test(predecessorSourceTree || '')
      || typeof repository !== 'string' || repository.length === 0
      || !/^urn:usf:ownerassignment:[a-z0-9:]+$/.test(ownerAssignmentIri || '')) {
    throw new CompilerError('external authority package inputs are not canonical', {
      phase: 'candidate:external-authority-delta',
    });
  }
  exactObjectKeys(conflictBinding, [
    'conflictingAuthorities', 'operationDigest', 'requestedActions', 'requestedEffects',
    'requestedFormats', 'requestedPaths', 'sourcePaths', 'sourceScopeDigest',
    'successorSourceTree', 'validationObligations',
  ], 'external authority conflict binding');
  const authorities = exactSortedUniqueStrings(
    conflictBinding.conflictingAuthorities,
    /^urn:usf:semanticcontract:[a-z0-9]+$/,
    'external authority conflicting authorities',
    { minimum: 2 },
  );
  const requestedActions = exactSortedUniqueStrings(
    conflictBinding.requestedActions,
    /^(create-directory|write-file|move-path|delete-path)$/,
    'external authority requested actions',
  );
  const requestedEffects = exactSortedUniqueStrings(
    conflictBinding.requestedEffects,
    /^urn:usf:obligationeffect:[a-z0-9]+$/,
    'external authority requested effects',
  );
  const requestedFormats = exactSortedUniqueStrings(
    conflictBinding.requestedFormats,
    /^urn:usf:representationformat:[a-z0-9]+$/,
    'external authority requested formats',
  );
  const requestedPaths = exactCanonicalRepositoryPaths(
    conflictBinding.requestedPaths,
    'external authority requested paths',
  );
  const sourcePaths = exactCanonicalRepositoryPaths(
    conflictBinding.sourcePaths,
    'external authority source paths',
  );
  const validationObligations = exactSortedUniqueStrings(
    conflictBinding.validationObligations,
    /^urn:usf:validationobligation:[a-z0-9]+$/,
    'external authority validation obligations',
  );
  if (!SHA256.test(conflictBinding.operationDigest || '')
      || !SHA256.test(conflictBinding.sourceScopeDigest || '')
      || !GIT_OBJECT.test(conflictBinding.successorSourceTree || '')) {
    throw new CompilerError('external authority conflict digest binding is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const expectedRoles = EXTERNAL_AUTHORITY_ARTIFACT_ROLES;
  if (!Array.isArray(artifacts) || artifacts.length !== expectedRoles.length) {
    throw new CompilerError('external authority package requires inventory, operations, review and proof artifacts', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const artifactByRole = new Map();
  for (const artifact of artifacts) {
    exactObjectKeys(artifact, ['bytes', 'role'], 'external authority artifact');
    if (!expectedRoles.includes(artifact.role) || artifactByRole.has(artifact.role)
        || !Buffer.isBuffer(artifact.bytes) || artifact.bytes.length < 2) {
      throw new CompilerError('external authority artifact identity is invalid', {
        phase: 'candidate:external-authority-delta',
      });
    }
    artifactByRole.set(artifact.role, Buffer.from(artifact.bytes));
  }
  if (canonicalJson([...artifactByRole.keys()].sort()) !== canonicalJson(expectedRoles)) {
    throw new CompilerError('external authority artifact role set is incomplete', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const artifactValidation = validateExternalAuthorityArtifacts({
    artifacts: artifactByRole,
    authorityDigest,
    conflictBinding,
    correctionCandidateDigest,
    now,
    ownerAssignmentIri,
    predecessorSourceHead,
    predecessorSourceTree,
    proofApprovalEnvelope,
    repository,
    operationContentStore,
    trustAnchor,
    verifyProofApprovalEnvelope,
  });
  const artifactRecords = new Map([...artifactValidation.artifacts].map(([role, artifact]) => [
    role,
    Object.freeze({ byteSize: artifact.byteSize, digest: artifact.digest, jcsDigest: artifact.jcsDigest, role }),
  ]));
  const roots = [...artifactRecords.values()].map(({ digest: item }) => item).sort();
  if (new Set(roots).size !== roots.length) {
    throw new CompilerError('external authority artifacts must have distinct content identities', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const suffix = correctionCandidateDigest.slice(7);
  const slug = `repositorymaterialisationvalidationcorrection${suffix}`;
  const conflictIri = `urn:usf:authorityconflict:${slug}`;
  const resolutionIri = `urn:usf:semanticcorrectiondecision:${slug}`;
  const reviewIri = `urn:usf:semanticadequacyreview:${slug}`;
  const proofIri = `urn:usf:proof:${slug}`;
  const proofResultIri = `urn:usf:proofresult:${slug}`;
  const signatureIri = `urn:usf:signature:${slug}`;
  const proofArtifact = artifactRecords.get('proof');
  const evaluatedAt = artifactValidation.proof.evaluatedAt;
  const validUntil = artifactValidation.proof.validUntil;
  const signatureValue = proofApprovalEnvelope.signature;
  const proofsGraph = 'urn:usf:graph:proofs';
  const evidenceGraph = 'urn:usf:graph:evidence';
  const literal = (item) => JSON.stringify(item);
  const iri = (item) => `<${item}>`;
  const line = (subject, predicate, object, graph) => `${iri(subject)} ${iri(predicate)} ${object} ${iri(graph)} .`;
  const type = (subject, object, graph) => line(subject, RDF_TYPE, iri(object), graph);
  const quads = [];
  const add = (subject, predicate, object, graph = proofsGraph) => quads.push(line(subject, predicate, object, graph));
  quads.push(type(conflictIri, `${USF}AssuranceFinding`, proofsGraph));
  add(conflictIri, `${USF}canonicalName`, literal(slug));
  add(conflictIri, `${USF}conflictAuthorityDigest`, literal(authorityDigest));
  for (const item of authorities) add(conflictIri, `${USF}conflictingAuthority`, iri(item));
  add(conflictIri, `${USF}conflictRepository`, literal(repository));
  add(conflictIri, `${USF}conflictOperationDigest`, literal(conflictBinding.operationDigest));
  add(conflictIri, `${USF}conflictCandidateDigest`, literal(correctionCandidateDigest));
  add(conflictIri, `${USF}conflictPredecessorSourceHead`, literal(predecessorSourceHead));
  add(conflictIri, `${USF}conflictPredecessorSourceTree`, literal(predecessorSourceTree));
  add(conflictIri, `${USF}conflictSuccessorSourceTree`, literal(conflictBinding.successorSourceTree));
  add(conflictIri, `${USF}conflictSourceScopeDigest`, literal(conflictBinding.sourceScopeDigest));
  for (const item of sourcePaths) add(conflictIri, `${USF}conflictSourcePath`, literal(item));
  for (const item of requestedActions) add(conflictIri, `${USF}conflictRequestedAction`, literal(item));
  for (const item of requestedPaths) add(conflictIri, `${USF}conflictRequestedPath`, literal(item));
  for (const item of requestedFormats) add(conflictIri, `${USF}conflictRequestedRepresentationFormat`, iri(item));
  for (const item of requestedEffects) add(conflictIri, `${USF}conflictRequestedEffect`, iri(item));
  for (const item of validationObligations) add(conflictIri, `${USF}conflictBlockedByValidationObligation`, iri(item));

  const descriptorFor = (role) => {
    const artifact = artifactRecords.get(role);
    return `urn:usf:externalpayloaddescriptor:${role}${artifact.digest.slice(7)}`;
  };
  quads.push(type(reviewIri, `${USF}SemanticAdequacyReview`, proofsGraph));
  add(reviewIri, `${USF}canonicalName`, literal(slug));
  add(reviewIri, `${USF}reviewedAuthorityDigest`, literal(authorityDigest));
  add(reviewIri, `${USF}reviewedInventoryDigest`, literal(correctionCandidateDigest));
  add(reviewIri, `${USF}reviewedItemCount`, '"1"^^<http://www.w3.org/2001/XMLSchema#integer>');
  add(reviewIri, `${USF}hasSemanticAdequacyReviewState`, iri('urn:usf:semanticadequacyreviewstate:accepted'));
  add(reviewIri, `${USF}usesDispositionInventoryDescriptor`, iri(descriptorFor('inventory')));
  add(reviewIri, `${USF}usesIndependentReviewDescriptor`, iri(descriptorFor('review')));
  add(reviewIri, `${USF}usesSemanticAdequacyProofDescriptor`, iri(descriptorFor('proof')));

  quads.push(type(proofIri, `${USF}Proof`, proofsGraph));
  add(proofIri, `${USF}canonicalName`, literal(slug));
  add(proofIri, `${USF}atRung`, iri('urn:usf:proofrung:behaviour'));
  add(proofIri, `${USF}usesProviderMode`, iri('urn:usf:providermode:deterministictestsubstitute'));
  add(proofIri, `${USF}inEnvironment`, iri('urn:usf:environment:hermetic'));
  add(proofIri, `${USF}exercises`, iri('urn:usf:semanticcontract:compilersemanticenforcement'));
  add(proofIri, `${USF}provesSubject`, iri(conflictIri));

  quads.push(type(proofResultIri, `${USF}ProofResult`, proofsGraph));
  add(proofResultIri, `${USF}canonicalName`, literal(slug));
  add(proofResultIri, `${USF}resultState`, iri('urn:usf:resultstate:passed'));
  add(proofResultIri, `${USF}resultForProof`, iri(proofIri));
  add(proofResultIri, `${USF}claimedRung`, iri('urn:usf:proofrung:behaviour'));
  add(proofResultIri, `${USF}observedRung`, iri('urn:usf:proofrung:behaviour'));
  add(proofResultIri, `${USF}hasFreshness`, iri('urn:usf:freshness:fresh'));
  add(proofResultIri, `${USF}usesProviderMode`, iri('urn:usf:providermode:deterministictestsubstitute'));
  add(proofResultIri, `${USF}inEnvironment`, iri('urn:usf:environment:hermetic'));
  add(proofResultIri, `${USF}hasProofResultState`, iri('urn:usf:proofresultstate:successful'));
  add(proofResultIri, `${USF}proofResultForObligation`, iri('urn:usf:proofobligation:compilersemanticenforcementaggregate'));
  add(proofResultIri, `${USF}evidenceSetDigest`, literal(artifactValidation.proof.evidenceSetDigest));
  add(proofResultIri, `${USF}usesProofAlgorithm`, iri('urn:usf:proofalgorithm:compilersemanticenforcementaggregate'));
  add(proofResultIri, `${USF}usesAlgorithmVersion`, iri('urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210'));
  add(proofResultIri, `${USF}evaluatedByValidator`, iri('urn:usf:validatorrule:validateassuranceconformance'));
  add(proofResultIri, `${USF}proofExecutionEnvironment`, iri('urn:usf:environment:hermetic'));
  add(proofResultIri, `${USF}hasConfidenceState`, iri('urn:usf:proofconfidencestate:warranted'));
  add(proofResultIri, `${USF}uncertaintyStatement`, literal('This proof is bounded to the exact authority-conflict request, accepted independent review, canonical proof receipt and prospective source identity. It does not authorize pruning, Factory mutation, V2 activation, deployment or provider contact.'));
  add(proofResultIri, `${USF}evaluatedAt`, `"${evaluatedAt}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`);
  for (const item of ['authoritydigestchanged', 'evidenceinvalidated', 'evidencestale']) {
    add(proofResultIri, `${USF}hasInvalidationCondition`, iri(`urn:usf:proofinvalidationcondition:${item}`));
  }

  for (const role of expectedRoles) {
    const artifact = artifactRecords.get(role);
    const hex = artifact.digest.slice(7);
    const descriptor = descriptorFor(role);
    const evidence = `urn:usf:evidenceresult:${role}${hex}`;
    const collection = `urn:usf:evidencecollection:${role}${hex}`;
    const normalisation = `urn:usf:evidencenormalisation:${role}${hex}`;
    const ingestion = `urn:usf:evidenceingestion:${role}${hex}`;
    const integrity = `urn:usf:integrityverification:${role}${hex}`;
    const checksum = `urn:usf:checksum:${role}${hex}`;
    quads.push(type(descriptor, `${USF}ExternalPayloadDescriptor`, evidenceGraph));
    add(descriptor, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(descriptor, `${USF}descriptorArtefactFamily`, iri('urn:usf:artefactfamily:evidencepayload'), evidenceGraph);
    add(descriptor, `${USF}descriptorRepresentationFormat`, iri('urn:usf:representationformat:jsondata8259'), evidenceGraph);
    add(descriptor, `${USF}descriptorMediaType`, literal('application/json'), evidenceGraph);
    add(descriptor, `${USF}descriptorDigest`, literal(artifact.digest), evidenceGraph);
    add(descriptor, `${USF}descriptorByteSize`, `"${artifact.byteSize}"^^<http://www.w3.org/2001/XMLSchema#integer>`, evidenceGraph);
    add(descriptor, `${USF}descriptorLocator`, `"cas://sha256/${hex}"^^<http://www.w3.org/2001/XMLSchema#anyURI>`, evidenceGraph);
    add(descriptor, `${USF}descriptorArtefactType`, `"urn:usf:artefacttype:semanticadequacy${role}"^^<http://www.w3.org/2001/XMLSchema#anyURI>`, evidenceGraph);
    add(descriptor, `${USF}descriptorStorageClass`, iri('urn:usf:storageclass:contentaddressedobjectstorage'), evidenceGraph);
    if (!EXTERNAL_AUTHORITY_EVIDENCE_ROLES.includes(role)) continue;
    add(proofResultIri, `${USF}usesAdmittedEvidence`, iri(evidence));
    add(proofResultIri, `${USF}confidenceBasis`, iri(evidence));
    quads.push(type(evidence, `${USF}EvidenceResult`, evidenceGraph));
    add(evidence, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(evidence, `${USF}evidenceKind`, iri('urn:usf:evidencekind:semanticreviewevidence'), evidenceGraph);
    add(evidence, `${USF}usesProviderMode`, iri('urn:usf:providermode:deterministictestsubstitute'), evidenceGraph);
    add(evidence, `${USF}inEnvironment`, iri('urn:usf:environment:hermetic'), evidenceGraph);
    add(evidence, `${USF}hasFreshness`, iri('urn:usf:freshness:fresh'), evidenceGraph);
    add(evidence, `${USF}evidenceFor`, iri(conflictIri), evidenceGraph);
    add(evidence, `${USF}evidenceForContract`, iri('urn:usf:semanticcontract:compilersemanticenforcement'), evidenceGraph);
    add(evidence, `${USF}contentDigest`, literal(artifact.digest), evidenceGraph);
    add(evidence, `${USF}mediaType`, literal('application/json'), evidenceGraph);
    add(evidence, `${USF}byteSize`, `"${artifact.byteSize}"^^<http://www.w3.org/2001/XMLSchema#integer>`, evidenceGraph);
    add(evidence, `${USF}storageLocator`, `"cas://sha256/${hex}"^^<http://www.w3.org/2001/XMLSchema#anyURI>`, evidenceGraph);
    add(evidence, `${USF}wasProducedBy`, iri('urn:usf:validatorrule:validateassuranceconformance'), evidenceGraph);
    add(evidence, `${USF}collectedAt`, `"${evaluatedAt}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`, evidenceGraph);
    add(evidence, `${USF}validUntil`, `"${validUntil}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`, evidenceGraph);
    add(evidence, `${USF}hasFreshnessPolicy`, iri('urn:usf:evidencefreshnesspolicy:semanticadequacyreviewauthoritybound'), evidenceGraph);
    add(evidence, `${USF}hasAdmissionState`, iri('urn:usf:evidenceadmissionstate:admitted'), evidenceGraph);
    add(evidence, `${USF}hasFreshnessState`, iri('urn:usf:evidencefreshnessstate:fresh'), evidenceGraph);
    add(evidence, `${USF}hasIntegrityState`, iri('urn:usf:evidenceintegritystate:valid'), evidenceGraph);
    add(evidence, `${USF}concernsSemanticSubject`, iri(reviewIri), evidenceGraph);
    for (const stage of ['emitted', 'collected', 'normalised', 'ingested', 'signed', 'integrityverified']) {
      add(evidence, `${USF}evidenceStage`, iri(`urn:usf:evidencestage:${stage}`), evidenceGraph);
    }
    add(evidence, `${USF}collectedBy`, iri(collection), evidenceGraph);
    add(evidence, `${USF}normalisedBy`, iri(normalisation), evidenceGraph);
    add(evidence, `${USF}ingestedBy`, iri(ingestion), evidenceGraph);
    add(evidence, `${USF}evidenceSignature`, iri(signatureIri), evidenceGraph);
    add(evidence, `${USF}evidenceChecksum`, iri(checksum), evidenceGraph);
    add(evidence, `${USF}integrityVerification`, iri(integrity), evidenceGraph);
    add(evidence, `${USF}applicableToObligation`, iri('urn:usf:proofobligation:compilersemanticenforcementaggregate'), evidenceGraph);
    add(evidence, `${USF}withinValidityScope`, '"true"^^<http://www.w3.org/2001/XMLSchema#boolean>', evidenceGraph);
    quads.push(type(collection, `${USF}EvidenceCollection`, evidenceGraph));
    add(collection, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(collection, `${USF}collectionForRequirement`, iri('urn:usf:evidencerequirement:compilersemanticvalidation'), evidenceGraph);
    add(collection, `${USF}collectedEvidence`, iri(evidence), evidenceGraph);
    add(collection, `${USF}collectsEvidence`, iri(evidence), evidenceGraph);
    add(collection, `${USF}collectedOn`, `"${evaluatedAt}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`, evidenceGraph);
    add(collection, `${USF}sourceDigest`, literal(artifact.digest), evidenceGraph);
    quads.push(type(normalisation, `${USF}EvidenceNormalisation`, evidenceGraph));
    add(normalisation, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(normalisation, `${USF}normalisesEvidence`, iri(evidence), evidenceGraph);
    quads.push(type(ingestion, `${USF}EvidenceIngestion`, evidenceGraph));
    add(ingestion, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(ingestion, `${USF}ingestsEvidence`, iri(evidence), evidenceGraph);
    quads.push(type(integrity, `${USF}IntegrityVerification`, evidenceGraph));
    add(integrity, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(integrity, `${USF}verifiesEvidence`, iri(evidence), evidenceGraph);
    add(integrity, `${USF}verificationState`, iri('urn:usf:resultstate:passed'), evidenceGraph);
    quads.push(type(checksum, `${USF}Checksum`, evidenceGraph));
    add(checksum, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(checksum, `${USF}checksumAlgorithm`, iri('urn:usf:checksumalgorithm:sha256'), evidenceGraph);
    add(checksum, `${USF}checksumValue`, literal(hex), evidenceGraph);
  }
  quads.push(type(signatureIri, `${USF}Signature`, evidenceGraph));
  add(signatureIri, `${USF}canonicalName`, literal(slug), evidenceGraph);
  add(signatureIri, `${USF}artefactKind`, iri('urn:usf:artefactkind:signature'), evidenceGraph);
  add(signatureIri, `${USF}canonicalPath`, literal(`cas://sha256/${proofArtifact.digest.slice(7)}#signature`), evidenceGraph);
  add(signatureIri, `${USF}governedByPathRule`, iri('urn:usf:pathrule:contentaddressedsignature'), evidenceGraph);
  add(signatureIri, `${USF}signatureMethod`, iri('urn:usf:signaturemethod:detached'), evidenceGraph);
  add(signatureIri, `${USF}signingPolicy`, iri('urn:usf:policy:hermeticevidenceattestation'), evidenceGraph);
  add(signatureIri, `${USF}signedBy`, iri(AUTHORITY_SIGNING_IDENTITY), evidenceGraph);
  add(signatureIri, `${USF}signatureValue`, literal(signatureValue), evidenceGraph);

  quads.push(type(resolutionIri, `${USF}SemanticCorrectionDecision`, proofsGraph));
  add(resolutionIri, `${USF}canonicalName`, literal(slug));
  add(resolutionIri, `${USF}decisionRationale`, literal(artifactValidation.proof.value.decision.rationale));
  add(resolutionIri, `${USF}semanticCorrectionDecisionState`, iri('urn:usf:semanticcorrectiondecisionstate:accepted'));
  add(resolutionIri, `${USF}decisionBasedOnSemanticAdequacyReview`, iri(reviewIri));
  add(resolutionIri, `${USF}warrantedBySemanticAdequacyProof`, iri(proofResultIri));
  add(resolutionIri, `${USF}resolvesAuthorityConflict`, iri(conflictIri));
  add(resolutionIri, `${USF}authorityConflictResolutionOwnerAssignment`, iri(ownerAssignmentIri));

  const historical = `urn:usf:historicalitem:${suffix}`;
  add(historical, `${USF}sourceItemDigest`, literal(correctionCandidateDigest));
  add(historical, `${USF}reviewedInSemanticAdequacyReview`, iri(reviewIri));
  add(historical, `${USF}semanticAdequacyDisposition`, iri('urn:usf:semanticadequacydisposition:independentlywarrantedretained'));
  add(historical, `${USF}authorisedBySemanticCorrectionDecision`, iri(resolutionIri));
  add(historical, `${USF}finalCanonicalSemanticItem`, iri(conflictIri));

  const sortedQuads = [...new Set(quads)].sort();
  if (sortedQuads.length !== quads.length) {
    throw new CompilerError('external authority package contains duplicate semantic operations', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const patchBytes = Buffer.from([
    '# semantic-proof-v1 canonical-rdf-patch-v1 base',
    ...sortedQuads.map((item) => `A ${item}`),
    '',
  ].join('\n'));
  return Object.freeze({
    artifactDescriptors: Object.freeze([...artifactRecords.values()]
      .map((descriptor) => Object.freeze({ ...descriptor })).sort((left, right) => left.role.localeCompare(right.role))),
    authorityDigest,
    casRootDigests: Object.freeze(roots),
    conflictIri,
    correctionCandidateDigest,
    ownerAssignmentIri,
    patchBytesBase64: patchBytes.toString('base64'),
    patchDigest: sha256(patchBytes),
    permittedOperations: Object.freeze(sortedQuads.map((item) => `A ${item}`)),
    predecessorSourceHead,
    predecessorSourceTree,
    proofApprovalEnvelope,
    proofResultIri,
    repository,
    resolutionIri,
    reviewIri,
    schema: EXTERNAL_AUTHORITY_DELTA_SCHEMA,
  });
}

function missingImplementationWorkGrantVerifier() {
  throw new CompilerError('implementation work grant envelope verifier is required', {
    phase: 'candidate:implementation-work-grant',
  });
}

function validateImplementationWorkGrantArtifacts({
  artifacts,
  authorityDigest,
  now,
  verifyImplementationWorkGrant = missingImplementationWorkGrantVerifier,
}) {
  if (!(artifacts instanceof Map)
      || canonicalJson([...artifacts.keys()].sort()) !== canonicalJson(IMPLEMENTATION_WORK_GRANT_ARTIFACT_ROLES)) {
    throw new CompilerError('implementation work grant artifact role set is incomplete', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  const parsed = new Map([...artifacts].map(([role, bytes]) => [
    role, parseCanonicalJsonArtifact(bytes, `implementation work grant ${role} artifact`),
  ]));
  const decision = parsed.get('decision').value;
  const review = parsed.get('review').value;
  const validation = parsed.get('validation').value;
  const envelope = parsed.get('grant').value;
  exactObjectKeys(decision, [
    'allowed_actions', 'authority_pre_digest', 'decision_state', 'denied_effects',
    'expires_at', 'issued_at', 'nonpublication_dependency_set_digest', 'purpose',
    'repositories', 'schema_version',
  ], 'implementation work grant decision');
  exactObjectKeys(review, [
    'authority_pre_digest', 'candidate_derivation_participation', 'decision_digest',
    'governance_independent_review_satisfied', 'review_state', 'schema_version',
  ], 'implementation work grant review');
  exactObjectKeys(validation, [
    'authority_pre_digest', 'decision_digest', 'review_digest', 'schema_version', 'validation_state',
  ], 'implementation work grant validation');
  if (decision.schema_version !== 'usf-implementation-work-grant-decision-v1'
      || decision.authority_pre_digest !== authorityDigest
      || decision.purpose !== IMPLEMENTATION_WORK_GRANT_PURPOSE
      || decision.decision_state !== 'accepted'
      || !SHA256.test(decision.nonpublication_dependency_set_digest || '')
      || canonicalJson(decision.allowed_actions) !== canonicalJson(IMPLEMENTATION_WORK_GRANT_ALLOWED_ACTIONS)
      || canonicalJson(decision.denied_effects) !== canonicalJson(IMPLEMENTATION_WORK_GRANT_DENIED_EFFECTS)
      || review.schema_version !== 'usf-implementation-work-grant-review-v1'
      || review.authority_pre_digest !== authorityDigest
      || review.review_state !== 'accepted'
      || review.candidate_derivation_participation !== false
      || review.governance_independent_review_satisfied !== true
      || validation.schema_version !== 'usf-implementation-work-grant-validation-v1'
      || validation.authority_pre_digest !== authorityDigest
      || validation.validation_state !== 'passed') {
    throw new CompilerError('implementation work grant decision, review or validation is not exact and accepted', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  const evidenceDigests = ['decision', 'review', 'validation'].map((role) => parsed.get(role).digest).sort();
  let verified;
  try {
    verified = verifyImplementationWorkGrant(envelope, {
      authorityPreDigest: authorityDigest,
      evidenceDigests,
      now,
      repositories: decision.repositories,
    });
  } catch (error) {
    throw new CompilerError(`implementation work grant envelope is invalid: ${error.message}`, {
      phase: 'candidate:implementation-work-grant',
    });
  }
  if (verified.authority_pre_digest !== authorityDigest
      || verified.purpose !== IMPLEMENTATION_WORK_GRANT_PURPOSE
      || canonicalJson(verified.repositories) !== canonicalJson(decision.repositories)
      || canonicalJson(verified.allowed_actions) !== canonicalJson(decision.allowed_actions)
      || canonicalJson(verified.denied_effects) !== canonicalJson(decision.denied_effects)
      || verified.nonpublication_dependency_set_digest !== decision.nonpublication_dependency_set_digest
      || review.decision_digest !== parsed.get('decision').digest
      || validation.decision_digest !== parsed.get('decision').digest
      || validation.review_digest !== parsed.get('review').digest
      || decision.issued_at !== verified.issued_at || decision.expires_at !== verified.expires_at) {
    throw new CompilerError('implementation work grant artifacts do not bind one exact candidate', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  return Object.freeze({ decision, evidenceDigests, envelope, parsed, review, validation, verified });
}

function implementationWorkGrantPatch(validation) {
  const { parsed, verified } = validation;
  const suffix = verified.candidate_digest.slice(7);
  const grantIri = `urn:usf:implementationworkgrant:${suffix}`;
  const graph = 'urn:usf:graph:proofs';
  const evidenceGraph = 'urn:usf:graph:evidence';
  const iri = (value) => `<${value}>`;
  const literal = (value) => JSON.stringify(value);
  const line = (subject, predicate, object, target = graph) => `${iri(subject)} ${iri(predicate)} ${object} ${iri(target)} .`;
  const quads = [];
  const add = (subject, predicate, object, target = graph) => quads.push(line(subject, predicate, object, target));
  add(grantIri, RDF_TYPE, iri(`${USF}ImplementationWorkGrant`));
  add(grantIri, `${USF}canonicalName`, literal(suffix));
  add(grantIri, `${USF}implementationWorkGrantAuthorityDigest`, literal(verified.authority_pre_digest));
  add(grantIri, `${USF}implementationWorkGrantPurpose`, iri('urn:usf:implementationworkpurpose:v2nativehandover'));
  add(grantIri, `${USF}implementationWorkGrantState`, iri('urn:usf:implementationworkgrantstate:reserved'));
  add(grantIri, `${USF}implementationWorkGrantNonce`, literal(verified.nonce));
  add(grantIri, `${USF}implementationWorkGrantEvidenceSetDigest`, literal(verified.evidence_set_digest));
  add(grantIri, `${USF}implementationWorkGrantNonPublicationDependencySetDigest`,
    literal(verified.nonpublication_dependency_set_digest));
  add(grantIri, `${USF}implementationWorkGrantCandidateDigest`, literal(verified.candidate_digest));
  add(grantIri, `${USF}implementationWorkGrantEnvelopeDigest`, literal(verified.envelope_digest));
  add(grantIri, `${USF}implementationWorkGrantIssuedAt`, `"${verified.issued_at}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`);
  add(grantIri, `${USF}implementationWorkGrantExpiresAt`, `"${verified.expires_at}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`);
  for (const action of verified.allowed_actions) {
    add(grantIri, `${USF}implementationWorkGrantAllows`, iri(`urn:usf:implementationworkaction:${action.replaceAll('_', '')}`));
  }
  for (const effect of verified.denied_effects) {
    add(grantIri, `${USF}implementationWorkGrantDenies`, iri(`urn:usf:implementationworkeffect:${effect.replaceAll('_', '')}`));
  }
  for (const scope of verified.repositories) {
    const repositoryToken = scope.repository === 'maldous/usf-factory' ? 'usffactory' : 'usfgraph';
    const scopeIri = `urn:usf:implementationworkrepositoryscope:${repositoryToken}${scope.source_scope_digest.slice(7)}`;
    add(grantIri, `${USF}implementationWorkGrantRepositoryScope`, iri(scopeIri));
    add(scopeIri, RDF_TYPE, iri(`${USF}ImplementationWorkRepositoryScope`));
    add(scopeIri, `${USF}implementationWorkRepository`, literal(scope.repository));
    add(scopeIri, `${USF}implementationWorkPredecessorCommit`, literal(scope.predecessor_commit));
    add(scopeIri, `${USF}implementationWorkPredecessorTree`, literal(scope.predecessor_tree));
    add(scopeIri, `${USF}implementationWorkSourceScopeDigest`, literal(scope.source_scope_digest));
    for (const path of scope.source_paths) add(scopeIri, `${USF}implementationWorkSourcePath`, literal(path));
  }
  for (const role of IMPLEMENTATION_WORK_GRANT_ARTIFACT_ROLES) {
    const artifact = parsed.get(role);
    const descriptor = `urn:usf:externalpayloaddescriptor:implementationworkgrant${role}${artifact.digest.slice(7)}`;
    add(grantIri, `${USF}implementationWorkGrantEvidenceDescriptor`, iri(descriptor));
    add(descriptor, RDF_TYPE, iri(`${USF}ExternalPayloadDescriptor`), evidenceGraph);
    add(descriptor, `${USF}canonicalName`, literal(`implementationworkgrant${role}${artifact.digest.slice(7)}`), evidenceGraph);
    add(descriptor, `${USF}descriptorArtefactFamily`, iri('urn:usf:artefactfamily:evidencepayload'), evidenceGraph);
    add(descriptor, `${USF}descriptorRepresentationFormat`, iri('urn:usf:representationformat:jsondata8259'), evidenceGraph);
    add(descriptor, `${USF}descriptorMediaType`, literal('application/json'), evidenceGraph);
    add(descriptor, `${USF}descriptorDigest`, literal(artifact.digest), evidenceGraph);
    add(descriptor, `${USF}descriptorByteSize`, `"${artifact.byteSize}"^^<http://www.w3.org/2001/XMLSchema#integer>`, evidenceGraph);
    add(descriptor, `${USF}descriptorLocator`, `"cas://sha256/${artifact.digest.slice(7)}"^^<http://www.w3.org/2001/XMLSchema#anyURI>`, evidenceGraph);
    add(descriptor, `${USF}descriptorArtefactType`, `"urn:usf:artefacttype:implementationworkgrant${role}"^^<http://www.w3.org/2001/XMLSchema#anyURI>`, evidenceGraph);
    add(descriptor, `${USF}descriptorStorageClass`, iri('urn:usf:storageclass:contentaddressedobjectstorage'), evidenceGraph);
  }
  const sorted = [...new Set(quads)].sort();
  if (sorted.length !== quads.length) {
    throw new CompilerError('implementation work grant contains duplicate semantic operations', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  const bytes = Buffer.from(['# semantic-proof-v1 canonical-rdf-patch-v1 base', ...sorted.map((value) => `A ${value}`), ''].join('\n'));
  return Object.freeze({ bytes, digest: sha256(bytes), grantIri, permittedOperations: Object.freeze(sorted.map((value) => `A ${value}`)) });
}

function createImplementationWorkGrantDeltaPackage({
  artifacts,
  authorityDigest,
  now,
  verifyImplementationWorkGrant = missingImplementationWorkGrantVerifier,
}) {
  if (!SHA256.test(authorityDigest || '') || !Array.isArray(artifacts)
      || artifacts.length !== IMPLEMENTATION_WORK_GRANT_ARTIFACT_ROLES.length) {
    throw new CompilerError('implementation work grant package inputs are invalid', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  const artifactMap = new Map();
  for (const artifact of artifacts) {
    exactObjectKeys(artifact, ['bytes', 'role'], 'implementation work grant artifact');
    if (!IMPLEMENTATION_WORK_GRANT_ARTIFACT_ROLES.includes(artifact.role)
        || artifactMap.has(artifact.role) || !Buffer.isBuffer(artifact.bytes)) {
      throw new CompilerError('implementation work grant artifact identity is invalid', {
        phase: 'candidate:implementation-work-grant',
      });
    }
    artifactMap.set(artifact.role, Buffer.from(artifact.bytes));
  }
  const validation = validateImplementationWorkGrantArtifacts({
    artifacts: artifactMap, authorityDigest, now, verifyImplementationWorkGrant,
  });
  const patch = implementationWorkGrantPatch(validation);
  const descriptors = [...validation.parsed].map(([role, artifact]) => Object.freeze({
    byteSize: artifact.byteSize, digest: artifact.digest, jcsDigest: artifact.jcsDigest, role,
  })).sort((left, right) => left.role.localeCompare(right.role));
  return Object.freeze({
    artifactDescriptors: Object.freeze(descriptors),
    authorityDigest,
    casRootDigests: Object.freeze(descriptors.map(({ digest: value }) => value).sort()),
    grantCandidateDigest: validation.verified.candidate_digest,
    grantIri: patch.grantIri,
    patchBytesBase64: patch.bytes.toString('base64'),
    patchDigest: patch.digest,
    permittedOperations: patch.permittedOperations,
    schema: IMPLEMENTATION_WORK_GRANT_DELTA_SCHEMA,
  });
}

function assertImplementationWorkGrantDelta({
  value,
  expectedAuthorityDigest,
  evidenceStore,
  allowedGraphs,
  now,
  verifyImplementationWorkGrant = missingImplementationWorkGrantVerifier,
}) {
  exactObjectKeys(value, [
    'artifactDescriptors', 'authorityDigest', 'casRootDigests', 'grantCandidateDigest', 'grantIri',
    'patchBytesBase64', 'patchDigest', 'permittedOperations', 'schema',
  ], 'implementation work grant delta');
  if (value.schema !== IMPLEMENTATION_WORK_GRANT_DELTA_SCHEMA
      || value.authorityDigest !== expectedAuthorityDigest
      || !SHA256.test(value.grantCandidateDigest || '') || !SHA256.test(value.patchDigest || '')
      || value.grantIri !== `urn:usf:implementationworkgrant:${value.grantCandidateDigest.slice(7)}`) {
    throw new CompilerError('implementation work grant delta does not bind exact authority and candidate', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  if (!evidenceStore || typeof evidenceStore.verify !== 'function' || typeof evidenceStore.read !== 'function') {
    throw new CompilerError('implementation work grant delta requires canonical CAS read and verification', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  if (!Array.isArray(value.artifactDescriptors)
      || value.artifactDescriptors.length !== IMPLEMENTATION_WORK_GRANT_ARTIFACT_ROLES.length) {
    throw new CompilerError('implementation work grant descriptor set is incomplete', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  const artifacts = new Map();
  for (const descriptor of value.artifactDescriptors) {
    exactObjectKeys(descriptor, ['byteSize', 'digest', 'jcsDigest', 'role'], 'implementation work grant descriptor');
    if (!IMPLEMENTATION_WORK_GRANT_ARTIFACT_ROLES.includes(descriptor.role) || artifacts.has(descriptor.role)
        || !SHA256.test(descriptor.digest || '') || !SHA256.test(descriptor.jcsDigest || '')
        || !Number.isSafeInteger(descriptor.byteSize) || descriptor.byteSize < 2) {
      throw new CompilerError('implementation work grant descriptor is invalid', {
        phase: 'candidate:implementation-work-grant',
      });
    }
    const receipt = evidenceStore.verify(descriptor.digest);
    const bytes = evidenceStore.read(descriptor.digest);
    if (receipt?.digest !== descriptor.digest || receipt?.size !== descriptor.byteSize
        || !Buffer.isBuffer(bytes) || bytes.length !== descriptor.byteSize || sha256(bytes) !== descriptor.digest) {
      throw new CompilerError('implementation work grant CAS readback failed', {
        phase: 'candidate:implementation-work-grant',
      });
    }
    const parsed = parseCanonicalJsonArtifact(bytes, `implementation work grant ${descriptor.role} CAS artifact`);
    if (parsed.jcsDigest !== descriptor.jcsDigest) {
      throw new CompilerError('implementation work grant CAS JCS digest mismatch', {
        phase: 'candidate:implementation-work-grant',
      });
    }
    artifacts.set(descriptor.role, bytes);
  }
  const roots = exactSortedUniqueStrings(value.casRootDigests, SHA256, 'implementation work grant CAS roots', { minimum: 4 });
  if (canonicalJson(roots) !== canonicalJson(value.artifactDescriptors.map(({ digest: item }) => item).sort())) {
    throw new CompilerError('implementation work grant descriptors do not equal exact CAS roots', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  const validation = validateImplementationWorkGrantArtifacts({
    artifacts, authorityDigest: expectedAuthorityDigest, now, verifyImplementationWorkGrant,
  });
  if (validation.verified.candidate_digest !== value.grantCandidateDigest) {
    throw new CompilerError('implementation work grant candidate digest substitution was rejected', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  const expected = implementationWorkGrantPatch(validation);
  const bytes = Buffer.from(value.patchBytesBase64 || '', 'base64');
  if (bytes.toString('base64') !== value.patchBytesBase64 || !bytes.equals(expected.bytes)
      || value.patchDigest !== expected.digest
      || canonicalJson(value.permittedOperations) !== canonicalJson(expected.permittedOperations)) {
    throw new CompilerError('implementation work grant patch is not the exact derived closed operation set', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  const patch = parseCanonicalPatch(bytes, value.patchDigest, allowedGraphs, new Set(['base']));
  if (patch.deletions.length !== 0 || !patchHas(patch, value.grantIri, RDF_TYPE, `${USF}ImplementationWorkGrant`)
      || !patchHas(patch, value.grantIri, `${USF}implementationWorkGrantState`, 'urn:usf:implementationworkgrantstate:reserved')) {
    throw new CompilerError('implementation work grant patch is not an exact reserved grant', {
      phase: 'candidate:implementation-work-grant',
    });
  }
  return Object.freeze({
    casRootDigests: roots,
    grantCandidateDigest: value.grantCandidateDigest,
    grantIri: value.grantIri,
    patch,
    patchDigest: value.patchDigest,
    kind: 'implementation_work_grant',
  });
}

function triple(item) {
  return quad(item.subject, item.predicate, item.object, defaultGraph());
}

async function graphText(store) {
  return new Promise((resolveText, reject) => {
    const writer = new Writer({ format: 'N-Triples' });
    writer.addQuads(store.getQuads(null, null, null, null));
    writer.end((error, output) => error ? reject(error) : resolveText(output));
  });
}

async function nquadsText(quads) {
  return new Promise((resolveText, reject) => {
    const writer = new Writer({ format: 'N-Quads' });
    writer.addQuads(quads);
    writer.end((error, output) => error ? reject(error) : resolveText(output));
  });
}

async function readCanonicalStores(client, transaction, graphs) {
  const graphNames = [...new Set(graphs)].sort();
  const dataset = [];
  for (const graph of graphNames) {
    const content = await client.constructInTransaction(
      transaction,
      `CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`,
    );
    let values;
    try {
      values = new Parser({ format: TURTLE, baseIRI: 'urn:usf:' }).parse(content || '');
    } catch (error) {
      throw new CompilerError(`managed graph could not be isolated for candidate application: ${error.message}`, {
        phase: 'candidate:isolation', graph,
      });
    }
    dataset.push(...values.map((item) => quad(item.subject, item.predicate, item.object, namedNode(graph))));
  }
  const canonical = await canonicalNQuads(await nquadsText(dataset));
  const stores = new Map(graphNames.map((graph) => [graph, new Store()]));
  for (const item of new Parser({ format: NQUADS, blankNodePrefix: '' }).parse(canonical)) {
    stores.get(item.graph.value).addQuad(triple(item));
  }
  return Object.freeze({ canonical, stores });
}

async function readAffectedStores(client, transaction, patch) {
  return (await readCanonicalStores(
    client,
    transaction,
    patch.operations.map(({ value }) => value.graph.value),
  )).stores;
}

async function replaceStores(client, transaction, stores) {
  const graphs = [...stores.keys()].sort();
  await client.clearGraphs(transaction, graphs);
  for (const graph of graphs) {
    const content = await graphText(stores.get(graph));
    if (content.trim()) await client.addData(transaction, content, NTRIPLES, graph);
  }
}

async function applyDesiredPatch(client, transaction, patch) {
  const stores = await readAffectedStores(client, transaction, patch);
  for (const { value } of patch.deletions) stores.get(value.graph.value).removeQuad(triple(value));
  for (const { value } of patch.additions) stores.get(value.graph.value).addQuad(triple(value));
  await replaceStores(client, transaction, stores);
}

function canonicalCombinedPatch(stage, before, after) {
  const prior = new Set(before.split('\n').filter(Boolean));
  const target = new Set(after.split('\n').filter(Boolean));
  const deletions = [...prior].filter((line) => !target.has(line)).sort();
  const additions = [...target].filter((line) => !prior.has(line)).sort();
  if (deletions.length + additions.length === 0) {
    throw new CompilerError('combined semantic candidate contains no authority transition', { phase: 'candidate:source-delta' });
  }
  if (!['base', 'stage1', 'stage2'].includes(stage)) {
    throw new CompilerError('combined semantic candidate stage is invalid', { phase: 'candidate:source-delta' });
  }
  return Buffer.from([
    `# semantic-proof-v1 canonical-rdf-patch-v1 ${stage}`,
    ...deletions.map((line) => `D ${line}`),
    ...additions.map((line) => `A ${line}`),
    '',
  ].join('\n'), 'utf8');
}

async function composeSourceCandidate({
  client,
  manifest,
  generatedPatch = null,
  preservedPatch = null,
  validationContextPatch = null,
  authorityWitness,
  compileFunction,
  stage,
}) {
  const graphs = [...managedGraphs(manifest)].sort();
  let beforeDataset;
  let targetDataset;
  let generatedApplied = false;
  let validationContextBaseline = null;
  const overrides = {
    async begin() {
      const transaction = await client.begin();
      beforeDataset = await readCanonicalStores(client, transaction, graphs);
      return transaction;
    },
    async validateInTransactionWithReceipt(transaction, shapes) {
      if (!generatedApplied) {
        if (preservedPatch) await applyDesiredPatch(client, transaction, preservedPatch);
        if (generatedPatch) await applyDesiredPatch(client, transaction, generatedPatch);
        if (validationContextPatch) {
          validationContextBaseline = await readAffectedStores(client, transaction, validationContextPatch);
          await applyDesiredPatch(client, transaction, validationContextPatch);
        }
        generatedApplied = true;
      }
      return client.validateInTransactionWithReceipt(transaction, shapes);
    },
    async rollback(transaction) {
      if (generatedApplied && !targetDataset) {
        if (validationContextBaseline) await replaceStores(client, transaction, validationContextBaseline);
        targetDataset = await readCanonicalStores(client, transaction, graphs);
      }
      return client.rollback(transaction);
    },
    async commit() {
      throw new CompilerError('source candidate composition must never commit', { phase: 'candidate:source-delta' });
    },
  };
  const compositionClient = new Proxy(Object.create(null), {
    get(_target, property) {
      if (Object.hasOwn(overrides, property)) return overrides[property];
      const value = Reflect.get(client, property, client);
      return typeof value === 'function' ? value.bind(client) : value;
    },
    set() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
    defineProperty() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
    deleteProperty() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
  });
  const sourceValidation = await compileFunction({
    authorityWitness,
    client: compositionClient,
    manifest,
    publicationBudgetPolicy: manifest.publicationBudget,
    publicationMode: 'validate',
  });
  if (!beforeDataset || !targetDataset || generatedApplied !== true || sourceValidation?.ok !== true) {
    throw new CompilerError('full source candidate could not be constructed and validated', { phase: 'candidate:source-delta' });
  }
  const candidateStage = stage
    || V1_PATCH_HEADER.exec(generatedPatch?.bytes.toString('utf8').split('\n', 1)[0])?.[2];
  const bytes = canonicalCombinedPatch(candidateStage, beforeDataset.canonical, targetDataset.canonical);
  const combined = candidateStage === 'base'
    ? Object.freeze({ bytes, digest: sha256(bytes) })
    : parseCanonicalPatch(bytes, undefined, new Set(graphs));
  for (const operation of [...(preservedPatch?.operations || []), ...(generatedPatch?.operations || [])]) {
    const targetStore = targetDataset.stores.get(operation.value.graph.value);
    const present = targetStore?.has(
      operation.value.subject, operation.value.predicate, operation.value.object, null,
    ) === true;
    if ((operation.action === 'A') !== present) {
      const operationLabel = `${operation.action} ${operation.line}`;
      throw new CompilerError(`generated aggregate intent was not preserved by full source composition: ${operationLabel}`, {
        phase: 'candidate:source-delta', operation: operationLabel,
      });
    }
  }
  return Object.freeze({
    bytes: combined.bytes,
    digest: combined.digest,
    sourceValidation: Object.freeze(sourceValidation.liveValidation || {}),
  });
}

function patchState(stores, patch) {
  const storeFor = ({ value }) => stores.get(value.graph.value) || new Store();
  const present = (entry) => storeFor(entry).has(
    entry.value.subject, entry.value.predicate, entry.value.object, null,
  );
  const pre = patch.deletions.every(present) && patch.additions.every((entry) => !present(entry));
  const post = patch.deletions.every((entry) => !present(entry)) && patch.additions.every(present);
  return pre && !post ? 'pre' : post && !pre ? 'post' : 'mixed';
}

function applyPatchToStores(stores, patch, label) {
  if (patchState(stores, patch) !== 'pre') {
    throw new CompilerError(`${label} candidate does not match its exact prospective pre-state`, {
      phase: 'candidate:precondition',
    });
  }
  for (const { value } of patch.deletions) stores.get(value.graph.value).removeQuad(triple(value));
  for (const { value } of patch.additions) {
    if (!stores.has(value.graph.value)) stores.set(value.graph.value, new Store());
    stores.get(value.graph.value).addQuad(triple(value));
  }
  if (patchState(stores, patch) !== 'post') {
    throw new CompilerError(`${label} candidate could not construct its exact prospective state`, {
      phase: 'candidate:postcondition',
    });
  }
}

async function prospectiveInventory(stores) {
  const inventory = [];
  for (const [graph, store] of [...stores.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const content = await graphText(store);
    // `semanticAuthorityInventoryDigest` folds record.sha256 per graph, and
    // readSemanticAuthorityWitness populates that field from canonicalGraphDigest while this
    // predictor populated it from canonicalInventoryGraphDigest. Two different digest functions
    // for the same field meant the predicted authority digest could NEVER equal the digest a
    // commit produces -- provably so: the prediction differed even for graphs the patch never
    // touches. The D1 postcondition was therefore unsatisfiable, and because the commit runs
    // before the check, every attempt advanced authority irreversibly and then failed.
    //
    // Both digests are now derived exactly as the witness derives them, so prediction and
    // observation are one meaning of the same state rather than two.
    // The RECORD SHAPE is closed downstream (aggregate-compiler-authority-candidate's exactKeys
    // rejects any extra key with CANDIDATE_CURRENTNESS_BINDING_INVALID), so only the digest
    // FUNCTION changes here -- which is the entire defect. dependencySha256 is deliberately not
    // added: the witness carries it for its own consumers, this prospective record must not.
    const record = await canonicalGraphDigest(content);
    // Match readSemanticAuthorityWitness exactly: Stardog's graph inventory
    // contains only named graphs with at least one triple.
    if (record.triples > 0) {
      inventory.push(Object.freeze({ graph, sha256: `sha256:${record.sha256}`, triples: record.triples }));
    }
  }
  const triples = inventory.reduce((total, record) => total + record.triples, 0);
  return Object.freeze({
    authorityDigest: semanticAuthorityInventoryDigest(inventory, triples),
    inventory: Object.freeze(inventory),
    triples,
  });
}

function exactProspectiveDigest(stores, subjectIri, predicateIri, label) {
  const matches = [...stores.entries()].flatMap(([graph, store]) => store
    .getQuads(namedNode(subjectIri), namedNode(predicateIri), null, null)
    .map((item) => Object.freeze({ graph, object: item.object })));
  if (matches.length !== 1
      || matches[0].object.termType !== 'Literal'
      || !SHA256.test(matches[0].object.value)) {
    throw new CompilerError(`prospective D1 ${label} is not one exact digest`, {
      phase: 'candidate:d1-dependencies',
      cardinality: matches.length,
      subject: subjectIri,
      predicate: predicateIri,
    });
  }
  return matches[0].object.value;
}

function prospectiveD1DependencyIdentityDigests(stores) {
  const bindingDigests = V2_D1_BINDING_DEPENDENCY_PREDICATES.map((predicate) => (
    exactProspectiveDigest(
      stores,
      V2_D1_VALIDATION_BINDING,
      `${USF_ONTOLOGY}${predicate}`,
      predicate,
    )
  ));
  const evidenceDigests = V2_D1_VALIDATION_EVIDENCE.map((evidenceIri) => (
    exactProspectiveDigest(
      stores,
      evidenceIri,
      `${USF_ONTOLOGY}contentDigest`,
      `validation evidence ${evidenceIri}`,
    )
  ));
  const identities = [...bindingDigests, ...evidenceDigests].sort();
  if (identities.length !== 7 || new Set(identities).size !== identities.length) {
    throw new CompilerError('prospective D1 dependency identity set is not exact and unique', {
      phase: 'candidate:d1-dependencies',
      cardinality: identities.length,
    });
  }
  return Object.freeze(identities);
}

async function inspectPatchState(client, patch) {
  let transaction;
  try {
    transaction = await client.begin();
    const stores = await readAffectedStores(client, transaction, patch);
    const state = patchState(stores, patch);
    await client.rollback(transaction);
    transaction = null;
    return state;
  } finally {
    if (transaction) await client.rollback(transaction);
  }
}

// ---------------------------------------------------------------------------------------------
// Governed abandonment of ONE fenced, uncompletable handover generation.
//
// This exists because the lifecycle had no terminal edge for the state a failed D1 leaves behind:
// authority fenced (V1 publication retired), no D2, no successors, no terminal receipt, and a
// generation whose plan can never match live authority. Forward was impossible and backward was
// impossible, so the system was permanently stuck.
//
// It is NOT a "clear fence" primitive and must never become one. The only reachable effect is
// bounded by an owner-signed one-shot grant whose signature covers the exact authority, the exact
// fence contents, the exact generation, the exact recovery evidence and the exact effect digest.
//
// It also fixes the commit-ordering defect that caused the incident: the predicted post-authority
// is derived INSIDE the transaction, from the staged candidate, using the same canonical
// inventory semantics as the live witness. Commit happens only after the prediction is known and
// consistent, so nothing after commit can turn a committed success into an apparent no-effect.
const HANDOVER_ABANDONMENT_INTENT_SCHEMA = 'usf-v2-handover-abandonment-intent-v1';
const HANDOVER_ABANDONMENT_RECORD_CLASS = `${USF_ONTOLOGY}V2NativeHandoverAbandonment`;
const OWL_CLASS = 'http://www.w3.org/2002/07/owl#Class';

// The exact fence predicates this transition may remove. Enumerated rather than "delete whatever
// is attached to the fence subject", so an unexpected predicate fails closed instead of being
// silently swept away.
const V2_HANDOVER_FENCE_PREDICATES = Object.freeze([
  'canonicalName',
  'handoverCurrentV1PublicationState',
  'handoverD0AuthorityDigest',
  'handoverDerivedConsumerRegistryDigest',
  'handoverExpectedTerminalReceiptSchema',
  'handoverExternalAttestationSetRootDigest',
  'handoverFactorySourceTree',
  'handoverGenerationDigest',
  'handoverGraphSourceTree',
  'handoverOwnershipState',
  'handoverReleaseSubjectDigest',
]);

// The fence's exact content, including WHICH subject in WHICH graph carries it. Folding only
// predicate/object would give two differently-named fences the same digest, and a grant bound to
// that digest would transfer between them -- exactly the substitution this digest exists to stop.
export function canonicalHandoverFenceDigest(rows) {
  const body = [...rows]
    .map((row) => {
      const term = row.objectTerm ?? { type: 'literal', value: row.object };
      const suffix = term.type === 'uri' ? '<>'
        : `"${term.datatype ?? ''}"${term.language ?? ''}`;
      return `${row.graph} ${row.fence} ${row.predicate} ${term.value} ${suffix}`;
    })
    .sort()
    .join('\n');
  return `sha256:${createHash('sha256').update(`${body}\n`, 'utf8').digest('hex')}`;
}

async function readHandoverFenceRows(client, transaction) {
  const rows = await client.selectInTransaction(transaction, `SELECT ?fence ?p ?o ?g WHERE {
    GRAPH ?g {
      ?fence a <${V2_NATIVE_HANDOVER_FENCE_CLASS}> .
      ?fence ?p ?o
    }
  } ORDER BY ?fence ?p ?o`);
  if (!Array.isArray(rows)) {
    throw new CompilerError('handover fence observation is invalid', {
      phase: 'candidate:handover-abandonment',
    });
  }
  const value = (term) => (term && typeof term === 'object' ? term.value : term);
  // The exact RDF term, not its lexical form. `sha256:...` reads as a plausible IRI and is
  // stored as a literal; guessing from the string shape made the staged deletion miss the quad
  // it was supposed to remove, so term identity is carried through explicitly.
  const objectTerm = (term) => {
    if (!term || typeof term !== 'object') return Object.freeze({ type: 'literal', value: String(term) });
    if (term.type === 'uri') return Object.freeze({ type: 'uri', value: term.value });
    if (term.type === 'literal') {
      return Object.freeze({
        type: 'literal',
        value: term.value,
        ...(term.datatype ? { datatype: term.datatype } : {}),
        ...(term['xml:lang'] ? { language: term['xml:lang'] } : {}),
      });
    }
    throw new CompilerError('handover abandonment refused: the fence carries a non-ground term', {
      phase: 'candidate:handover-abandonment', termType: term.type,
    });
  };
  const observed = rows.map((row) => Object.freeze({
    fence: value(row.fence),
    predicate: value(row.p),
    object: value(row.o),
    objectTerm: objectTerm(row.o),
    graph: value(row.g),
  }));
  const subjects = new Set(observed.map((row) => row.fence));
  const graphs = new Set(observed.map((row) => row.graph));
  if (observed.length === 0) {
    throw new CompilerError('handover abandonment refused: no semantic handover fence exists', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (subjects.size !== 1 || graphs.size !== 1) {
    throw new CompilerError('handover abandonment refused: fence is duplicated or ambiguous', {
      phase: 'candidate:handover-abandonment',
    });
  }
  // The runtime V2 classes are declared as owl:Class in the AUTHORITY graph itself, alongside the
  // instances they type -- not in the ontology source. The abandonment record's class belongs in
  // exactly the same place, so the reader observes whether it is already declared and the effect
  // adds the declaration only when it is absent.
  const declared = await client.selectInTransaction(transaction, `SELECT ?graph WHERE {
    GRAPH ?graph { <${HANDOVER_ABANDONMENT_RECORD_CLASS}> a <${OWL_CLASS}> }
  }`);
  if (!Array.isArray(declared)) {
    throw new CompilerError('handover abandonment vocabulary observation is invalid', {
      phase: 'candidate:handover-abandonment',
    });
  }
  return Object.freeze({
    rows: Object.freeze(observed),
    fence: [...subjects][0],
    graph: [...graphs][0],
    recordClassDeclared: declared.length > 0,
    contentDigest: canonicalHandoverFenceDigest(observed),
  });
}

function fenceField(observation, predicate) {
  const matches = observation.rows.filter(
    (row) => row.predicate === `${USF_ONTOLOGY}${predicate}`,
  );
  if (matches.length !== 1) {
    throw new CompilerError(`handover abandonment refused: fence ${predicate} is not exact`, {
      phase: 'candidate:handover-abandonment',
    });
  }
  return matches[0].object;
}

export function handoverAbandonmentEffectDigest(effect) {
  return `sha256:${createHash('sha256').update(canonicalJson(effect), 'utf8').digest('hex')}`;
}

// The exact proposed authority delta, derived from observed state alone. Deterministic, so the
// grant can be signed over its digest before the transition ever runs.
export function buildHandoverAbandonmentEffect(observation, {
  generationDigest, preD1AuthorityDigest, observedPostD1AuthorityDigest,
  d1RecoveryRecordDigest, recoveredAt,
}) {
  const unexpected = observation.rows.filter((row) => row.predicate !== `${RDF_TYPE}`
    && !V2_HANDOVER_FENCE_PREDICATES.includes(row.predicate.replace(USF_ONTOLOGY, '')));
  if (unexpected.length > 0) {
    throw new CompilerError('handover abandonment refused: fence carries unexpected predicates', {
      phase: 'candidate:handover-abandonment',
      predicates: unexpected.map((row) => row.predicate),
    });
  }
  const record = `${observation.fence}:abandoned`;
  const iri = (value) => Object.freeze({ type: 'uri', value });
  const text = (value) => Object.freeze({ type: 'literal', value });
  return Object.freeze({
    schema: 'usf-v2-handover-abandonment-effect-v2',
    // Remove ONLY the pending fence representation, so current-state queries deterministically
    // resolve to the unfenced state. Each deletion names the EXACT observed term.
    deletions: Object.freeze([...observation.rows]
      .map((row) => Object.freeze({
        graph: row.graph,
        subject: row.fence,
        predicate: row.predicate,
        object: row.object,
        objectTerm: row.objectTerm ?? text(row.object),
      }))
      .sort((left, right) => (left.predicate + left.object).localeCompare(right.predicate + right.object))),
    // Preserve the abandonment as HISTORY. It deliberately asserts no ownership state, no
    // successor, no terminal receipt and no activation.
    additions: Object.freeze([
      [RDF_TYPE, iri(HANDOVER_ABANDONMENT_RECORD_CLASS)],
      [`${USF_ONTOLOGY}abandonedHandoverGenerationDigest`, text(generationDigest)],
      [`${USF_ONTOLOGY}abandonedHandoverFenceContentDigest`, text(observation.contentDigest)],
      [`${USF_ONTOLOGY}abandonedHandoverPreD1AuthorityDigest`, text(preD1AuthorityDigest)],
      [`${USF_ONTOLOGY}abandonedHandoverObservedD1AuthorityDigest`, text(observedPostD1AuthorityDigest)],
      [`${USF_ONTOLOGY}abandonedHandoverRecoveryRecordDigest`, text(d1RecoveryRecordDigest)],
      [`${USF_ONTOLOGY}abandonedHandoverReason`, text('DEFECTIVE_AFTER_D1_UNCOMPLETABLE')],
      [`${USF_ONTOLOGY}abandonedHandoverRecoveredAt`, text(recoveredAt)],
    ].map(([predicate, objectTerm]) => Object.freeze({
      graph: observation.graph,
      subject: record,
      predicate,
      object: objectTerm.value,
      objectTerm,
    })).concat(observation.recordClassDeclared === true ? [] : [Object.freeze({
      // The record's own class, declared where V2NativeHandoverFence and
      // V2NativeGraphSuccessorBinding are declared. Semantic authority refuses an instance of an
      // undeclared urn:usf:ontology: class, and it is right to: a record nothing can interpret is
      // not history, it is residue.
      graph: observation.graph,
      subject: HANDOVER_ABANDONMENT_RECORD_CLASS,
      predicate: RDF_TYPE,
      object: OWL_CLASS,
      objectTerm: iri(OWL_CLASS),
    })]).sort((left, right) => (left.subject + left.predicate + left.object)
      .localeCompare(right.subject + right.predicate + right.object))),
  });
}

// ---------------------------------------------------------------------------
// Governed ABANDON of one fenced, uncompletable V2 native handover.
// ---------------------------------------------------------------------------
//
// A handover whose D1 committed but which can never reach its terminal receipt leaves semantic
// authority permanently fenced: V1 publication is retired and V2 never arrives. That is not a
// state any amount of retrying escapes, so the protocol needs one lawful terminal edge out of it.
//
// This is that edge, and it is deliberately the narrowest possible one. It is NOT a patch
// facility, NOT a fence-clearing utility, and NOT reachable without an owner-signed grant bound
// to this exact authority, fence, generation, recovery record and mutation. No generic entry
// point is exported: the only way in is to present a grant that already names everything.
//
// It also fixes the ordering defect that produced the incident it exists to resolve. Previously a
// prediction was computed OUTSIDE the transaction and compared to authority AFTER commit, so a
// prediction computed with the wrong digest function turned a committed success into an apparent
// failure and invited a replay. Here the prediction is derived INSIDE the transaction from the
// staged candidate using the same canonical inventory semantics as the live witness, is made
// durable BEFORE commit, and everything after commit is classification only.
const HANDOVER_ABANDONMENT_JOURNAL_SCHEMA = 'usf-v2-handover-abandonment-journal-v1';
const HANDOVER_ABANDONMENT_INTENT_FIELDS = Object.freeze([
  'action', 'authority_pre_digest', 'created_at', 'd1_recovery_record_digest',
  'fence_content_digest', 'grant_digest', 'handover_generation_digest', 'implementation_identity',
  'nonce', 'operation_id', 'permitted_effect_digest', 'schema', 'state',
]);
const HANDOVER_ABANDONMENT_READY_FIELDS = Object.freeze([
  'operation_id', 'predicted_post_authority', 'schema', 'state',
  'transaction_preimage_digest', 'validated_candidate_inventory_digest',
]);
const HANDOVER_ABANDONMENT_CLASSIFICATION_FIELDS = Object.freeze([
  'classification', 'classified_at', 'observed_authority_digest', 'operation_id',
  'reached_commit', 'schema', 'state',
]);
const HANDOVER_ABANDONMENT_ACTION = 'abandon-fenced-handover';
const PRE_STATE = 'PRE_STATE';
const PREDICTED_POST_STATE = 'PREDICTED_POST_STATE';
const UNEXPECTED_THIRD_STATE = 'UNEXPECTED_THIRD_STATE';

// A two-stage, append-only, immutable journal. INTENT_PREPARED records that an attempt is about
// to be made; READY_TO_COMMIT records that every precondition passed and the exact predicted
// outcome is known. Commit may be called only once READY_TO_COMMIT is durable, so the presence of
// READY_TO_COMMIT without a classification is precisely the ambiguous-commit condition.
//
// Attempts are ordinal because a proven no-effect attempt must be retryable while a committed one
// must never be. Every file is written once, 0444, atomically, behind a durability barrier.
function createHandoverAbandonmentJournal(programmeRoot) {
  if (typeof programmeRoot !== 'string' || !isAbsolute(programmeRoot)) {
    throw new CompilerError('handover abandonment journal root must be an exact absolute path', {
      phase: 'candidate:handover-abandonment',
    });
  }
  const root = resolve(programmeRoot);
  const directory = () => {
    const path = `${root}${sep}v2-native-handover-abandonment`;
    mkdirSync(path, { recursive: true, mode: 0o700 });
    return path;
  };
  const operationPath = (operationId, suffix) =>
    `${directory()}${sep}${operationId}.attempt-${suffix}.json`;
  const noncePath = (nonce, suffix) => `${directory()}${sep}nonce-${nonce}.${suffix}.json`;

  const readExact = (path) => {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(path) !== path) {
      throw new CompilerError('handover abandonment journal entry is unsafe', {
        phase: 'candidate:handover-abandonment', path,
      });
    }
    const bytes = readFileSync(path);
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); } catch {
      throw new CompilerError('handover abandonment journal entry is not JSON', {
        phase: 'candidate:handover-abandonment', path,
      });
    }
    if (!bytes.equals(Buffer.from(canonicalJson(value), 'utf8'))) {
      throw new CompilerError('handover abandonment journal entry is not canonical', {
        phase: 'candidate:handover-abandonment', path,
      });
    }
    return Object.freeze(value);
  };
  const readOptional = (path) => (existsSync(path) ? readExact(path) : null);
  const write = (path, value) => {
    publishImmutableFile(path, Buffer.from(canonicalJson(value), 'utf8'), 0o444);
    return readExact(path);
  };

  const readAttempt = (operationId, ordinal) => {
    const intent = readOptional(operationPath(operationId, `${ordinal}.intent-prepared`));
    if (intent === null) return null;
    exactObjectKeys(intent, HANDOVER_ABANDONMENT_INTENT_FIELDS, 'handover abandonment intent');
    const ready = readOptional(operationPath(operationId, `${ordinal}.ready-to-commit`));
    if (ready !== null) {
      exactObjectKeys(ready, HANDOVER_ABANDONMENT_READY_FIELDS, 'handover abandonment readiness');
    }
    const classification = readOptional(operationPath(operationId, `${ordinal}.classification`));
    if (classification !== null) {
      exactObjectKeys(classification, HANDOVER_ABANDONMENT_CLASSIFICATION_FIELDS,
        'handover abandonment classification');
    }
    return Object.freeze({
      ordinal,
      intent,
      ready,
      classification,
      state: classification !== null ? 'CLASSIFIED'
        : ready !== null ? 'READY_TO_COMMIT' : 'INTENT_PREPARED',
    });
  };

  const readOperation = (operationId) => {
    const attempts = [];
    for (let ordinal = 0; ordinal < 64; ordinal += 1) {
      const attempt = readAttempt(operationId, ordinal);
      if (attempt === null) break;
      attempts.push(attempt);
    }
    return Object.freeze({
      operation_id: operationId,
      attempts: Object.freeze(attempts),
      open: attempts.find((attempt) => attempt.classification === null) ?? null,
      committed: attempts.find(
        (attempt) => attempt.classification?.classification === PREDICTED_POST_STATE) ?? null,
    });
  };

  return Object.freeze({
    readOperation,
    // Which operation, if any, has already used this one-shot nonce.
    nonceOwner(nonce) {
      const claim = readOptional(noncePath(nonce, 'claim'));
      return claim === null ? null : claim.operation_id;
    },
    nonceCommitted(nonce) {
      return readOptional(noncePath(nonce, 'committed')) !== null;
    },
    beginAttempt(intent) {
      exactObjectKeys(intent, HANDOVER_ABANDONMENT_INTENT_FIELDS, 'handover abandonment intent');
      const operation = readOperation(intent.operation_id);
      if (operation.committed !== null) {
        throw new CompilerError(
          'handover abandonment refused: this operation already committed', {
            phase: 'candidate:handover-abandonment', operation_id: intent.operation_id,
          });
      }
      if (operation.open !== null) {
        throw new CompilerError(
          'handover abandonment refused: an earlier attempt is unclassified and must be recovered first',
          {
            phase: 'candidate:handover-abandonment',
            operation_id: intent.operation_id,
            attempt: operation.open.ordinal,
            attempt_state: operation.open.state,
          });
      }
      // The one-shot nonce is claimed for exactly one operation, first writer wins. A divergent
      // reuse -- same nonce, different authority/fence/generation/effect -- is refused here.
      const claim = { operation_id: intent.operation_id, schema: HANDOVER_ABANDONMENT_JOURNAL_SCHEMA };
      publishImmutableFile(noncePath(intent.nonce, 'claim'),
        Buffer.from(canonicalJson(claim), 'utf8'), 0o444);
      const owner = readExact(noncePath(intent.nonce, 'claim')).operation_id;
      if (owner !== intent.operation_id) {
        throw new CompilerError(
          'handover abandonment refused: this one-shot nonce is already bound to a different operation',
          {
            phase: 'candidate:handover-abandonment',
            nonce: intent.nonce, bound_operation_id: owner,
          });
      }
      const ordinal = operation.attempts.length;
      write(operationPath(intent.operation_id, `${ordinal}.intent-prepared`), intent);
      return readAttempt(intent.operation_id, ordinal);
    },
    markReadyToCommit(operationId, ordinal, fields) {
      const record = {
        ...fields,
        operation_id: operationId,
        schema: HANDOVER_ABANDONMENT_JOURNAL_SCHEMA,
        state: 'READY_TO_COMMIT',
      };
      exactObjectKeys(record, HANDOVER_ABANDONMENT_READY_FIELDS, 'handover abandonment readiness');
      write(operationPath(operationId, `${ordinal}.ready-to-commit`), record);
      return readAttempt(operationId, ordinal);
    },
    classify(operationId, ordinal, fields) {
      const record = {
        ...fields,
        operation_id: operationId,
        schema: HANDOVER_ABANDONMENT_JOURNAL_SCHEMA,
        state: 'CLASSIFIED',
      };
      exactObjectKeys(record, HANDOVER_ABANDONMENT_CLASSIFICATION_FIELDS,
        'handover abandonment classification');
      write(operationPath(operationId, `${ordinal}.classification`), record);
      const attempt = readAttempt(operationId, ordinal);
      // A committed success makes the nonce permanently unusable. A proven no-effect attempt
      // deliberately does NOT consume it: refusing a lawful retry forever is its own failure.
      if (record.classification === PREDICTED_POST_STATE) {
        publishImmutableFile(
          noncePath(attempt.intent.nonce, 'committed'),
          Buffer.from(canonicalJson({
            operation_id: operationId,
            attempt: ordinal,
            schema: HANDOVER_ABANDONMENT_JOURNAL_SCHEMA,
          }), 'utf8'),
          0o444,
        );
      }
      return attempt;
    },
  });
}

// The in-transaction mirror of readSemanticAuthorityWitness. Same graph enumeration, same
// per-graph RDFC-10 canonicalisation, same empty-graph exclusion, same fold. If these two ever
// disagree the prediction is worthless, so this deliberately reuses the witness's own fold rather
// than reimplementing it.
async function readTransactionAuthorityInventory(client, transaction, additionalGraphs = []) {
  const rows = await client.selectInTransaction(
    transaction, 'SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } } ORDER BY ?g');
  if (!Array.isArray(rows)) {
    throw new CompilerError('transaction authority inventory response is invalid', {
      phase: 'candidate:handover-abandonment',
    });
  }
  const graphs = rows.map((row) => (row.g && typeof row.g === 'object' ? row.g.value : row.g));
  if (graphs.some((graph) => typeof graph !== 'string' || graph.length === 0)
      || new Set(graphs).size !== graphs.length) {
    throw new CompilerError('transaction authority graph inventory is invalid', {
      phase: 'candidate:handover-abandonment',
    });
  }
  graphs.sort();
  const allowed = [...new Set(additionalGraphs)];
  if (allowed.some((graph) => typeof graph !== 'string' || graph.length === 0)) {
    throw new CompilerError('additional transaction authority graph set is invalid', {
      phase: 'candidate:transaction-inventory',
    });
  }
  const { stores } = await readCanonicalStores(client, transaction, [...graphs, ...allowed]);
  const prospective = await prospectiveInventory(stores);
  return Object.freeze({
    digest: prospective.authorityDigest,
    inventory: prospective.inventory,
    observedGraphs: Object.freeze(graphs),
    stores,
    triples: prospective.triples,
  });
}

function canonicalWitnessInventory(witness) {
  if (!Array.isArray(witness?.inventory)) {
    throw new CompilerError('opening authority witness has no graph inventory', {
      phase: 'candidate:transaction-inventory',
    });
  }
  const observed = new Set();
  const inventory = witness.inventory.map((record) => {
    const raw = record?.sha256;
    const sha256Value = /^[0-9a-f]{64}$/.test(raw || '') ? `sha256:${raw}` : raw;
    if (typeof record?.graph !== 'string' || record.graph.length === 0
        || observed.has(record.graph) || !SHA256.test(sha256Value || '')
        || !Number.isSafeInteger(record.triples) || record.triples <= 0) {
      throw new CompilerError('opening authority witness graph inventory is invalid', {
        phase: 'candidate:transaction-inventory',
      });
    }
    observed.add(record.graph);
    return Object.freeze({ graph: record.graph, sha256: sha256Value, triples: record.triples });
  }).sort((left, right) => left.graph.localeCompare(right.graph));
  return Object.freeze(inventory);
}

function assertTransactionSnapshotMatchesWitness(snapshot, witness) {
  const openingInventory = canonicalWitnessInventory(witness);
  const openingGraphs = openingInventory.map(({ graph }) => graph);
  if (canonicalJson(snapshot.observedGraphs) !== canonicalJson(openingGraphs)) {
    throw new CompilerError('transaction authority graph set differs from the opening witness', {
      phase: 'candidate:transaction-inventory',
    });
  }
  const openingTriples = openingInventory.reduce((total, record) => total + record.triples, 0);
  const openingFold = semanticAuthorityInventoryDigest(openingInventory, openingTriples);
  if (digest(witness) !== openingFold) {
    throw new CompilerError('opening authority witness digest does not match its graph inventory', {
      phase: 'candidate:transaction-inventory',
    });
  }
  if (snapshot.digest !== openingFold) {
    throw new CompilerError('transaction authority state differs from the opening witness', {
      phase: 'candidate:transaction-inventory',
    });
  }
}

// Every later-boundary absence, re-derived from authority inside the transaction. None of these
// are taken from the recovery record: a record asserting absence is a claim, and this transition
// requires observation.
async function assertAbandonmentPreconditionsInTransaction(client, transaction, {
  generationDigest, nativeGraphStore,
}) {
  const count = async (label, sparql) => {
    const rows = await client.selectInTransaction(transaction, sparql);
    if (!Array.isArray(rows)) {
      throw new CompilerError(`handover abandonment ${label} observation is invalid`, {
        phase: 'candidate:handover-abandonment',
      });
    }
    return rows;
  };
  const successors = await count('successor binding', `SELECT ?binding WHERE {
    GRAPH ?g { ?binding a <${USF_ONTOLOGY}V2NativeGraphSuccessorBinding> }
  } ORDER BY ?binding`);
  if (successors.length !== 0) {
    throw new CompilerError('handover abandonment refused: a V2 native successor binding exists', {
      phase: 'candidate:handover-abandonment', cardinality: successors.length,
    });
  }
  const links = await count('successor link', `SELECT ?fence WHERE {
    GRAPH ?g { ?fence <${USF_ONTOLOGY}handoverGraphNativeSuccessorBinding> ?binding }
  } ORDER BY ?fence`);
  if (links.length !== 0) {
    throw new CompilerError('handover abandonment refused: the fence already binds a successor', {
      phase: 'candidate:handover-abandonment', cardinality: links.length,
    });
  }
  const owners = await count('storage owner', `SELECT ?subject WHERE {
    GRAPH ?g { ?subject <${USF_ONTOLOGY}handoverStorageOwner> ?owner }
  } ORDER BY ?subject`);
  if (owners.length !== 0) {
    throw new CompilerError('handover abandonment refused: terminal V2 storage ownership exists', {
      phase: 'candidate:handover-abandonment', cardinality: owners.length,
    });
  }
  const generations = await count('generation', `SELECT DISTINCT ?generation WHERE {
    GRAPH ?g { ?subject <${USF_ONTOLOGY}handoverGenerationDigest> ?generation }
  } ORDER BY ?generation`);
  const distinct = generations.map(
    (row) => (row.generation && typeof row.generation === 'object'
      ? row.generation.value : row.generation));
  if (distinct.length !== 1 || distinct[0] !== generationDigest) {
    throw new CompilerError(
      'handover abandonment refused: authority does not hold exactly this one live generation', {
        phase: 'candidate:handover-abandonment', generations: distinct,
      });
  }
  const abandonments = await count('abandonment', `SELECT ?record WHERE {
    GRAPH ?g { ?record a <${HANDOVER_ABANDONMENT_RECORD_CLASS}> }
  } ORDER BY ?record`);
  if (abandonments.length !== 0) {
    throw new CompilerError(
      'handover abandonment refused: an abandonment record already exists', {
        phase: 'candidate:handover-abandonment', cardinality: abandonments.length,
      });
  }
  // Terminal receipt, successor root and activation are DURABLE artefacts, not authority
  // triples. An absent reader fails closed rather than reading an empty floor and concluding
  // the handover never got that far -- the same fail-closed rule the V1 interlock uses.
  if (!nativeGraphStore || typeof nativeGraphStore.readTerminalOwnershipFloor !== 'function'
      || typeof nativeGraphStore.loadGeneration !== 'function') {
    throw new CompilerError('V2_GRAPH_TERMINAL_OWNERSHIP_FLOOR_READER_REQUIRED', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (nativeGraphStore.readTerminalOwnershipFloor().terminal) {
    throw new CompilerError('handover abandonment refused: durable terminal ownership exists', {
      phase: 'candidate:handover-abandonment',
    });
  }
  const durable = nativeGraphStore.loadGeneration(generationDigest);
  if (durable?.terminal_receipt) {
    throw new CompilerError('handover abandonment refused: a terminal receipt exists', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (durable?.successor_root || durable?.activation) {
    throw new CompilerError(
      'handover abandonment refused: successor root or activation evidence exists', {
        phase: 'candidate:handover-abandonment',
      });
  }
}

// Stage the exact permitted effect onto the isolated stores. Deliberately not a patch API: it
// accepts only the deterministic effect this module builds, and refuses if the observed
// pre-state is not exactly what that effect was derived from.
function stageHandoverAbandonmentEffect(stores, effect) {
  // The effect names exact RDF terms, so nothing here infers a term kind from a lexical form.
  const term = (entry) => {
    const observed = entry.objectTerm;
    if (!observed || typeof observed !== 'object') {
      throw new CompilerError('handover abandonment effect entry has no exact object term', {
        phase: 'candidate:handover-abandonment', predicate: entry.predicate,
      });
    }
    if (observed.type === 'uri') return namedNode(observed.value);
    if (observed.type !== 'literal') {
      throw new CompilerError('handover abandonment effect names a non-ground object term', {
        phase: 'candidate:handover-abandonment', termType: observed.type,
      });
    }
    if (observed.language) return literal(observed.value, observed.language);
    if (observed.datatype) return literal(observed.value, namedNode(observed.datatype));
    return literal(observed.value);
  };
  const quads = (entries) => entries.map((entry) => ({
    graph: entry.graph,
    quad: quad(namedNode(entry.subject), namedNode(entry.predicate), term(entry),
      defaultGraph()),
  }));
  const deletions = quads(effect.deletions);
  const additions = quads(effect.additions);
  const store = (graph) => {
    if (!stores.has(graph)) {
      throw new CompilerError('handover abandonment effect names an unisolated graph', {
        phase: 'candidate:handover-abandonment', graph,
      });
    }
    return stores.get(graph);
  };
  const present = (entry) => store(entry.graph).has(
    entry.quad.subject, entry.quad.predicate, entry.quad.object, null);
  if (!deletions.every(present) || additions.some(present)) {
    throw new CompilerError(
      'handover abandonment refused: authority is not in the exact pre-state the effect was derived from',
      { phase: 'candidate:handover-abandonment' });
  }
  for (const entry of deletions) store(entry.graph).removeQuad(entry.quad);
  for (const entry of additions) store(entry.graph).addQuad(entry.quad);
  if (deletions.some(present) || !additions.every(present)) {
    throw new CompilerError(
      'handover abandonment could not construct its exact post-state', {
        phase: 'candidate:handover-abandonment',
      });
  }
}

// Read authority independently of any transaction. Post-commit classification must never look at
// the transaction it is classifying.
async function readIndependentAuthorityDigest(client) {
  const witness = await readSemanticAuthorityWitness(client);
  const digest = typeof witness?.digest === 'string' ? witness.digest : null;
  if (digest === null || !SHA256.test(digest)) {
    throw new CompilerError('independent authority observation is not one exact digest', {
      phase: 'candidate:handover-abandonment',
    });
  }
  return digest;
}

function classifyObservedAuthority(observed, { authorityPreDigest, predictedPostAuthority }) {
  if (predictedPostAuthority !== null && observed === predictedPostAuthority) {
    return PREDICTED_POST_STATE;
  }
  if (observed === authorityPreDigest) return PRE_STATE;
  return UNEXPECTED_THIRD_STATE;
}

export function handoverAbandonmentOperationId({
  nonce, authorityPreDigest, fenceContentDigest, handoverGenerationDigest,
  d1RecoveryRecordDigest, permittedEffectDigest,
}) {
  return createHash('sha256').update(canonicalJson({
    action: HANDOVER_ABANDONMENT_ACTION,
    authority_pre_digest: authorityPreDigest,
    d1_recovery_record_digest: d1RecoveryRecordDigest,
    fence_content_digest: fenceContentDigest,
    handover_generation_digest: handoverGenerationDigest,
    nonce,
    permitted_effect_digest: permittedEffectDigest,
  }), 'utf8').digest('hex');
}

// Classification-only recovery. It never opens a transaction, never stages anything and never
// commits. Its entire job is to turn an interrupted attempt into one of three exact statements
// about authority, and to say whether a lawful retry is permitted.
export async function recoverHandoverAbandonment({
  client, journal, operationId, readAuthorityDigest = null, now,
}) {
  const operation = journal.readOperation(operationId);
  if (operation.attempts.length === 0) {
    throw new CompilerError('handover abandonment recovery found no durable intent', {
      phase: 'candidate:handover-abandonment', operation_id: operationId,
    });
  }
  if (operation.open === null) {
    const last = operation.attempts[operation.attempts.length - 1];
    return Object.freeze({
      outcome: 'ALREADY_CLASSIFIED',
      classification: last.classification.classification,
      attempt: last.ordinal,
      mutated: false,
      retry_permitted: last.classification.classification === PRE_STATE,
      record: last.classification,
    });
  }
  const attempt = operation.open;
  const observed = await (readAuthorityDigest ?? (() => readIndependentAuthorityDigest(client)))();
  // INTENT_PREPARED proves commit was never reached: READY_TO_COMMIT is made durable first, and
  // commit is called only after that. So there is no prediction to compare against, and any
  // authority other than the pre-state is somebody else's change, not this attempt's.
  const predicted = attempt.state === 'READY_TO_COMMIT'
    ? attempt.ready.predicted_post_authority : null;
  const classification = classifyObservedAuthority(observed, {
    authorityPreDigest: attempt.intent.authority_pre_digest,
    predictedPostAuthority: predicted,
  });
  const record = journal.classify(operationId, attempt.ordinal, {
    classification,
    classified_at: now,
    observed_authority_digest: observed,
    reached_commit: attempt.state === 'READY_TO_COMMIT',
  });
  return Object.freeze({
    outcome: 'CLASSIFIED',
    classification,
    attempt: attempt.ordinal,
    // A committed effect is a mutation this operation caused; anything else is not.
    mutated: classification === PREDICTED_POST_STATE,
    // Only a proven no-effect attempt may be retried, and only through this path.
    retry_permitted: classification === PRE_STATE,
    record: record.classification,
  });
}

function canonicalObjectDigest(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function validateJournaledD1RecoveryEvidence(value) {
  const phase = 'candidate:handover-abandonment';
  const refuse = (message) => {
    throw new CompilerError(`handover abandonment refused: ${message}`, { phase });
  };
  const exactDigest = (candidate, label) => {
    if (!SHA256.test(candidate || '')) refuse(`${label} is not exact`);
  };
  const exactTime = (candidate, label) => {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(candidate || '')
        || Number.isNaN(Date.parse(candidate))) refuse(`${label} is not exact`);
  };
  const exactDigestSet = (candidate, label, minimum = 1) => {
    if (!Array.isArray(candidate) || candidate.length < minimum
        || candidate.some((item) => !SHA256.test(item || ''))
        || canonicalJson(candidate) !== canonicalJson([...new Set(candidate)].sort())) {
      refuse(`${label} is not an exact sorted digest set`);
    }
  };
  const assertDigestBinding = (candidate, expected, label) => {
    exactDigest(expected, `${label} digest`);
    if (canonicalObjectDigest(candidate) !== expected) refuse(`${label} digest does not match its bytes`);
  };

  exactObjectKeys(value, [
    'captured_at', 'factory_projection', 'factory_projection_digest',
    'graph_d1_commit_receipt', 'graph_d1_commit_receipt_digest',
    'graph_d1_observation_receipt', 'graph_d1_observation_receipt_digest',
    'graph_journal', 'graph_journal_digest', 'handover_generation_digest',
    'later_boundary_observation', 'later_boundary_observation_digest',
    'observed_post_d1_authority_digest', 'pre_d1_authority_digest',
    'prospective_publication_plan_digest', 'recovery_reason', 'schema',
    'superseded_prepare_binding', 'superseded_reservation', 'transaction_id',
  ], 'journaled D1 recovery evidence');
  if (value.schema !== V2_HANDOVER_JOURNALED_D1_RECOVERY_EVIDENCE_SCHEMA
      || value.recovery_reason !== 'DEFECTIVE_AFTER_D1') {
    refuse('journaled D1 recovery evidence identity is invalid');
  }
  exactTime(value.captured_at, 'journaled D1 evidence capture time');
  for (const [field, label] of [
    ['transaction_id', 'transaction'],
    ['handover_generation_digest', 'generation'],
    ['prospective_publication_plan_digest', 'plan'],
    ['pre_d1_authority_digest', 'pre-D1 authority'],
    ['observed_post_d1_authority_digest', 'post-D1 authority'],
  ]) exactDigest(value[field], `journaled D1 ${label}`);
  if (value.pre_d1_authority_digest === value.observed_post_d1_authority_digest) {
    refuse('journaled D1 evidence records no authority transition');
  }

  const commit = value.graph_d1_commit_receipt;
  exactObjectKeys(commit, [
    'authority_digest', 'candidate_digest', 'explicit_authorization_grant_digests',
    'graph_count', 'prospective_publication_plan_digest', 'protocol',
    'release_subject_digest', 'schema', 'triples',
  ], 'journaled D1 commit receipt');
  if (commit.schema !== 'usf-graph-d1-commit-receipt-v2'
      || commit.protocol !== 'semantic-proof-v2'
      || commit.authority_digest !== value.observed_post_d1_authority_digest
      || commit.prospective_publication_plan_digest
        !== value.prospective_publication_plan_digest
      || !Number.isSafeInteger(commit.graph_count) || commit.graph_count < 1
      || !Number.isSafeInteger(commit.triples) || commit.triples < 1) {
    refuse('journaled D1 commit receipt differs from the exact D1 transition');
  }
  exactDigest(commit.candidate_digest, 'journaled D1 candidate');
  exactDigest(commit.release_subject_digest, 'journaled D1 release subject');
  exactDigestSet(commit.explicit_authorization_grant_digests,
    'journaled D1 authorization grants', 0);
  assertDigestBinding(commit, value.graph_d1_commit_receipt_digest, 'journaled D1 commit receipt');

  const observation = value.graph_d1_observation_receipt;
  exactObjectKeys(observation, [
    'authority_digest', 'dependency_identity_digests',
    'explicit_authorization_grant_digests', 'prospective_publication_plan_digest',
    'protocol', 'release_subject_digest', 'schema',
  ], 'journaled D1 observation receipt');
  if (observation.schema !== 'usf-graph-d1-observation-receipt-v2'
      || observation.protocol !== 'semantic-proof-v2'
      || observation.authority_digest !== value.observed_post_d1_authority_digest
      || observation.prospective_publication_plan_digest
        !== value.prospective_publication_plan_digest
      || observation.release_subject_digest !== commit.release_subject_digest
      || canonicalJson(observation.explicit_authorization_grant_digests)
        !== canonicalJson(commit.explicit_authorization_grant_digests)) {
    refuse('journaled D1 observation receipt differs from the exact D1 transition');
  }
  exactDigestSet(observation.dependency_identity_digests,
    'journaled D1 dependency identities');
  exactDigestSet(observation.explicit_authorization_grant_digests,
    'journaled D1 observation authorization grants', 0);
  assertDigestBinding(observation, value.graph_d1_observation_receipt_digest,
    'journaled D1 observation receipt');

  const journal = value.graph_journal;
  exactObjectKeys(journal, [
    'boundary_receipts', 'entries', 'grant_consumed', 'publication_state', 'schema',
    'terminal_receipt', 'terminal_receipt_digest',
  ], 'journaled D1 publication journal');
  if (journal.schema !== 'usf-hermetic-semantic-proof-v2-journal'
      || journal.grant_consumed !== false || journal.publication_state !== null
      || journal.terminal_receipt !== null || journal.terminal_receipt_digest !== null) {
    refuse('journaled D1 publication journal records a later boundary');
  }
  exactObjectKeys(journal.boundary_receipts,
    ['d1_commit', 'd1_observation', 'grant_reservation'],
    'journaled D1 boundary receipts');
  if (journal.boundary_receipts.d1_commit !== value.graph_d1_commit_receipt_digest
      || journal.boundary_receipts.d1_observation
        !== value.graph_d1_observation_receipt_digest) {
    refuse('journaled D1 boundary receipts do not bind the exact D1 receipts');
  }
  exactDigest(journal.boundary_receipts.grant_reservation,
    'journaled D1 grant reservation receipt');
  const states = ['PLANNED', 'RESERVED', 'D1_COMMITTED', 'D1_DEPENDENCIES_OBSERVED'];
  if (!Array.isArray(journal.entries) || journal.entries.length !== states.length) {
    refuse('journaled D1 publication journal is not the exact current D1 prefix');
  }
  let coordinationIdentity = null;
  let releaseSubject = null;
  let trustedAt = null;
  let commonReceipts = null;
  for (const [index, entry] of journal.entries.entries()) {
    exactObjectKeys(entry, [
      'coordination_identity_digest', 'd0_authority_digest', 'd1_authority_digest',
      'd2_authority_digest', 'previous_entry_digest',
      'prospective_publication_plan_digest', 'receipt_digests', 'release_subject_digest',
      'schema', 'state', 'transaction_id', 'trusted_at',
    ], 'journaled D1 publication journal entry');
    exactDigest(entry.coordination_identity_digest, 'journaled D1 coordination identity');
    exactDigest(entry.release_subject_digest, 'journaled D1 journal release subject');
    exactTime(entry.trusted_at, 'journaled D1 journal trusted time');
    exactDigestSet(entry.receipt_digests, 'journaled D1 journal receipts');
    if (entry.schema !== 'usf-semantic-publication-journal-v2'
        || entry.state !== states[index]
        || entry.transaction_id !== value.transaction_id
        || entry.prospective_publication_plan_digest
          !== value.prospective_publication_plan_digest
        || entry.d0_authority_digest !== value.pre_d1_authority_digest
        || entry.d1_authority_digest !== (index >= 2
          ? value.observed_post_d1_authority_digest : null)
        || entry.d2_authority_digest !== null
        || entry.previous_entry_digest !== (index === 0
          ? null : canonicalObjectDigest(journal.entries[index - 1]))
        || !entry.receipt_digests.includes(value.prospective_publication_plan_digest)
        || (trustedAt !== null && entry.trusted_at < trustedAt)) {
      refuse('journaled D1 publication journal drifted from its exact D1 prefix');
    }
    coordinationIdentity ??= entry.coordination_identity_digest;
    releaseSubject ??= entry.release_subject_digest;
    if (entry.coordination_identity_digest !== coordinationIdentity
        || entry.release_subject_digest !== releaseSubject) {
      refuse('journaled D1 publication journal changed coordination identity');
    }
    trustedAt = entry.trusted_at;
    if (index === 0) commonReceipts = entry.receipt_digests;
  }
  const expectedReceiptSets = [
    commonReceipts,
    [...commonReceipts, journal.boundary_receipts.grant_reservation].sort(),
    [...commonReceipts, value.graph_d1_commit_receipt_digest].sort(),
    [...commonReceipts, value.graph_d1_observation_receipt_digest,
      ...observation.dependency_identity_digests].sort(),
  ].map((items) => [...new Set(items)].sort());
  if (expectedReceiptSets.some((expected, index) =>
    canonicalJson(journal.entries[index].receipt_digests) !== canonicalJson(expected))
      || releaseSubject !== commit.release_subject_digest
      || value.captured_at < trustedAt) {
    refuse('journaled D1 publication journal receipt chain is invalid');
  }
  assertDigestBinding(journal, value.graph_journal_digest, 'journaled D1 publication journal');

  const factory = value.factory_projection;
  exactObjectKeys(factory, [
    'candidate_digest', 'generation_id', 'graph_publication_receipt_keys',
    'graph_terminal_required', 'journal_states', 'plan_digest', 'projection_digest',
    'terminal_receipt_keys', 'transaction_id',
  ], 'journaled D1 Factory projection');
  if (factory.transaction_id !== value.transaction_id
      || factory.generation_id !== value.handover_generation_digest
      || factory.plan_digest !== value.prospective_publication_plan_digest
      || factory.candidate_digest !== commit.candidate_digest
      || canonicalJson(factory.journal_states) !== canonicalJson(['PLANNED', 'RESERVED'])
      || factory.graph_terminal_required !== true
      || canonicalJson(factory.graph_publication_receipt_keys) !== canonicalJson([])
      || canonicalJson(factory.terminal_receipt_keys) !== canonicalJson([])) {
    refuse('journaled D1 Factory projection is not the exact RESERVED transaction');
  }
  exactDigest(factory.projection_digest, 'journaled D1 source Factory projection');
  assertDigestBinding(factory, value.factory_projection_digest,
    'journaled D1 Factory projection');

  const reservation = value.superseded_reservation;
  exactObjectKeys(reservation, [
    'd0_authority_digest', 'handover_generation_digest',
    'prospective_publication_plan_digest', 'schema',
  ], 'journaled D1 superseded reservation');
  if (reservation.schema !== V2_HANDOVER_RESERVATION_SCHEMA
      || reservation.d0_authority_digest !== value.pre_d1_authority_digest
      || reservation.handover_generation_digest !== value.handover_generation_digest
      || reservation.prospective_publication_plan_digest
        !== value.prospective_publication_plan_digest) {
    refuse('journaled D1 superseded reservation differs from the exact transaction');
  }
  const prepare = value.superseded_prepare_binding;
  exactObjectKeys(prepare, [
    'factory_prepare_receipt_digest', 'handover_generation_digest',
    'prospective_publication_plan_digest', 'reservation_digest', 'schema',
  ], 'journaled D1 superseded PREPARE binding');
  if (prepare.schema !== V2_HANDOVER_FACTORY_PREPARE_BINDING_SCHEMA
      || prepare.handover_generation_digest !== value.handover_generation_digest
      || prepare.prospective_publication_plan_digest
        !== value.prospective_publication_plan_digest
      || prepare.reservation_digest !== canonicalObjectDigest(reservation)) {
    refuse('journaled D1 superseded PREPARE differs from the exact transaction');
  }
  exactDigest(prepare.factory_prepare_receipt_digest,
    'journaled D1 Factory PREPARE receipt');

  const later = value.later_boundary_observation;
  exactObjectKeys(later, [
    'activation_present', 'd2_authority_present', 'observed_authority_digest',
    'successors_root_present', 'terminal_receipt_present',
  ], 'journaled D1 later-boundary observation');
  if (later.observed_authority_digest !== value.observed_post_d1_authority_digest
      || later.d2_authority_present !== false || later.successors_root_present !== false
      || later.terminal_receipt_present !== false || later.activation_present !== false) {
    refuse('journaled D1 evidence records a later boundary');
  }
  assertDigestBinding(later, value.later_boundary_observation_digest,
    'journaled D1 later-boundary observation');

  return Object.freeze({
    generationDigest: value.handover_generation_digest,
    recoveryEffect: Object.freeze({
      activation_present: later.activation_present,
      d2_authority_present: later.d2_authority_present,
      observed_post_d1_authority_digest: value.observed_post_d1_authority_digest,
      pre_d1_authority_digest: value.pre_d1_authority_digest,
      successors_root_present: later.successors_root_present,
      terminal_receipt_present: later.terminal_receipt_present,
    }),
  });
}

function normalizeHandoverAbandonmentD1Evidence(value) {
  if (value?.schema === V2_HANDOVER_JOURNALED_D1_RECOVERY_EVIDENCE_SCHEMA) {
    return validateJournaledD1RecoveryEvidence(value);
  }
  const recoveryEffect = value?.d1_effect;
  if (!recoveryEffect || !SHA256.test(recoveryEffect.pre_d1_authority_digest || '')
      || !SHA256.test(recoveryEffect.observed_post_d1_authority_digest || '')) {
    throw new CompilerError('handover abandonment D1 recovery evidence is not exact', {
      phase: 'candidate:handover-abandonment',
    });
  }
  return Object.freeze({
    generationDigest: value.superseded_reservation?.handover_generation_digest ?? null,
    recoveryEffect,
  });
}

// The governed abandonment transition. There is no parameter that widens what it may do: the
// grant names the authority, the fence, the generation, the recovery record and the exact
// mutation, and every one of those is re-observed inside the transaction before commit.
export async function abandonFencedHandover({
  client,
  manifest,
  grantEnvelope,
  verifyGrant,
  journal,
  nativeGraphStore,
  d1RecoveryRecord,
  d1RecoveryRecordDigest,
  implementationIdentity,
  now,
  readText = readFileSync,
  failpoint = async () => {},
}) {
  if (!client || typeof client.begin !== 'function' || typeof client.commit !== 'function') {
    throw new CompilerError('handover abandonment requires a transactional authority client', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (typeof verifyGrant !== 'function') {
    throw new CompilerError('handover abandonment requires the owner grant verifier', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(now || '')) {
    throw new CompilerError('handover abandonment time is not exact', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (!SHA256.test(d1RecoveryRecordDigest || '')) {
    throw new CompilerError('handover abandonment D1 recovery record digest is not exact', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (!SHA256.test(implementationIdentity || '')) {
    throw new CompilerError('handover abandonment implementation identity is not exact', {
      phase: 'candidate:handover-abandonment',
    });
  }

  // --- Stage A: authenticate, identify, then observe. Read-only; nothing durable yet. -----
  //
  // The grant is authenticated BEFORE anything is observed, because the grant is what identifies
  // the operation. After a committed success the fence no longer exists, so an operation identity
  // derived from observation could not be computed at all -- and an exact replay must still be
  // able to find its own immutable result rather than failing on a precondition.
  const declared = verifyGrant(grantEnvelope, { now: new Date(now) });
  const operationId = handoverAbandonmentOperationId({
    nonce: declared.nonce,
    authorityPreDigest: declared.authority_pre_digest,
    fenceContentDigest: declared.fence_content_digest,
    handoverGenerationDigest: declared.handover_generation_digest,
    d1RecoveryRecordDigest: declared.d1_recovery_record_digest,
    permittedEffectDigest: declared.permitted_effect_digest,
  });

  // An EXACT replay after confirmed success returns the immutable result and mutates nothing.
  const existing = journal.readOperation(operationId);
  if (existing.committed !== null) {
    return Object.freeze({
      outcome: 'ALREADY_COMMITTED',
      classification: PREDICTED_POST_STATE,
      operation_id: operationId,
      attempt: existing.committed.ordinal,
      authority_pre_digest: existing.committed.intent.authority_pre_digest,
      predicted_post_authority: existing.committed.ready.predicted_post_authority,
      observed_authority_digest: existing.committed.classification.observed_authority_digest,
      mutated: false,
      replayed: true,
    });
  }
  // A DIVERGENT use of the same one-shot nonce is refused: the nonce belongs to one operation.
  if (journal.nonceCommitted(declared.nonce)) {
    throw new CompilerError('handover abandonment refused: this one-shot nonce already committed a mutation', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (declared.d1_recovery_record_digest !== d1RecoveryRecordDigest) {
    throw new CompilerError('handover abandonment refused: the grant names a different D1 recovery record', {
      phase: 'candidate:handover-abandonment',
    });
  }

  // The D1 recovery record is EVIDENCE of a recorded recovery, never a source of absence claims:
  // every absence this transition depends on is re-observed from authority below. That is why a
  // legacy v1 record is usable here as evidence while remaining unable to release anything -- the
  // two capabilities are different, and only one of them ever trusted the record's own claims.
  const normalizedRecovery = normalizeHandoverAbandonmentD1Evidence(d1RecoveryRecord);
  const recoveryEffect = normalizedRecovery.recoveryEffect;
  if (`sha256:${createHash('sha256').update(
    Buffer.from(canonicalJson(d1RecoveryRecord), 'utf8')).digest('hex')}` !== d1RecoveryRecordDigest) {
    throw new CompilerError('handover abandonment D1 recovery record digest does not match its bytes', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (recoveryEffect.pre_d1_authority_digest
      === recoveryEffect.observed_post_d1_authority_digest) {
    throw new CompilerError('handover abandonment refused: the recovery record observed no D1 authority transition', {
      phase: 'candidate:handover-abandonment',
    });
  }
  // The record's absence claims are never TRUSTED, but a record that claims a LATER boundary DID
  // happen contradicts the very condition this transition exists for. Evidence that disagrees
  // with observation fails closed rather than being quietly ignored, because one of the two is
  // wrong and neither may be assumed.
  for (const boundary of ['activation_present', 'd2_authority_present', 'successors_root_present',
    'terminal_receipt_present']) {
    if (recoveryEffect[boundary] === true) {
      throw new CompilerError(
        `handover abandonment refused: the recovery record records ${boundary}`, {
          phase: 'candidate:handover-abandonment',
        });
    }
  }

  const observedAuthority = await readIndependentAuthorityDigest(client);
  if (recoveryEffect.observed_post_d1_authority_digest !== observedAuthority) {
    throw new CompilerError('handover abandonment refused: the recovered D1 authority is not the current authority', {
      phase: 'candidate:handover-abandonment',
    });
  }

  let preObservation;
  {
    const transaction = await client.begin();
    try {
      preObservation = await readHandoverFenceRows(client, transaction);
    } finally {
      try { await client.rollback(transaction); } catch { /* observation only */ }
    }
  }
  const generationDigest = fenceField(preObservation, 'handoverGenerationDigest');
  if (!SHA256.test(generationDigest || '')
      || generationDigest !== normalizedRecovery.generationDigest) {
    throw new CompilerError('handover abandonment refused: the fence generation is not the recovered generation', {
      phase: 'candidate:handover-abandonment',
      fence_generation: generationDigest,
      recovered_generation: normalizedRecovery.generationDigest,
    });
  }
  const effect = buildHandoverAbandonmentEffect(preObservation, {
    generationDigest,
    preD1AuthorityDigest: recoveryEffect.pre_d1_authority_digest,
    observedPostD1AuthorityDigest: recoveryEffect.observed_post_d1_authority_digest,
    d1RecoveryRecordDigest,
    recoveredAt: now,
  });
  const permittedEffectDigest = handoverAbandonmentEffectDigest(effect);

  // Now re-verify the SAME grant against everything actually observed. The first verification
  // proved authenticity; this one proves the grant describes THIS world.
  const grant = verifyGrant(grantEnvelope, {
    authorityPreDigest: observedAuthority,
    fenceContentDigest: preObservation.contentDigest,
    handoverGenerationDigest: generationDigest,
    d1RecoveryRecordDigest,
    permittedEffectDigest,
    now: new Date(now),
  });
  if (grant.envelope_digest !== declared.envelope_digest) {
    throw new CompilerError('handover abandonment refused: the grant is not the one that identified this operation', {
      phase: 'candidate:handover-abandonment',
    });
  }
  if (grant.pre_d1_authority_digest !== recoveryEffect.pre_d1_authority_digest
      || grant.observed_post_d1_authority_digest
        !== recoveryEffect.observed_post_d1_authority_digest) {
    throw new CompilerError('handover abandonment refused: the grant does not describe the recovered D1 transition', {
      phase: 'candidate:handover-abandonment',
    });
  }
  const admitted = grant.repositories.some(
    (repository) => repository.source_scope_digest === implementationIdentity);
  if (!admitted) {
    throw new CompilerError('handover abandonment refused: this implementation identity is not admitted by the grant', {
      phase: 'candidate:handover-abandonment', implementation_identity: implementationIdentity,
    });
  }

  await failpoint('before-intent-prepared');
  const attempt = journal.beginAttempt({
    action: HANDOVER_ABANDONMENT_ACTION,
    authority_pre_digest: observedAuthority,
    created_at: now,
    d1_recovery_record_digest: d1RecoveryRecordDigest,
    fence_content_digest: preObservation.contentDigest,
    grant_digest: grant.envelope_digest,
    handover_generation_digest: generationDigest,
    implementation_identity: implementationIdentity,
    nonce: grant.nonce,
    operation_id: operationId,
    permitted_effect_digest: permittedEffectDigest,
    schema: HANDOVER_ABANDONMENT_JOURNAL_SCHEMA,
    state: 'INTENT_PREPARED',
  });
  await failpoint('after-intent-prepared');

  // --- Stage B: the authority transaction. ------------------------------------------------
  let committed = false;
  let predictedPostAuthority = null;
  let transaction;
  try {
    await failpoint('before-transaction-open');
    transaction = await client.begin();
    await failpoint('after-transaction-open');

    // Re-read authority and every precondition INSIDE the transaction. The values observed in
    // stage A are treated as a proposal, never as fact.
    const inTransactionBefore = await readTransactionAuthorityInventory(client, transaction);
    if (inTransactionBefore.digest !== observedAuthority) {
      throw new CompilerError('handover abandonment refused: authority changed before the transaction opened', {
        phase: 'candidate:handover-abandonment',
        expected: observedAuthority, observed: inTransactionBefore.digest,
      });
    }
    await failpoint('after-authority-read');

    const observation = await readHandoverFenceRows(client, transaction);
    if (observation.contentDigest !== preObservation.contentDigest) {
      throw new CompilerError('handover abandonment refused: the fence changed before the transaction opened', {
        phase: 'candidate:handover-abandonment',
      });
    }
    if (fenceField(observation, 'handoverGenerationDigest') !== generationDigest) {
      throw new CompilerError('handover abandonment refused: the fence generation changed', {
        phase: 'candidate:handover-abandonment',
      });
    }
    if (fenceField(observation, 'handoverOwnershipState')
        !== 'urn:usf:v2ownershipstate:handoverpending') {
      throw new CompilerError('handover abandonment refused: ownership state is not handover-pending', {
        phase: 'candidate:handover-abandonment',
      });
    }
    if (fenceField(observation, 'handoverCurrentV1PublicationState')
        !== 'urn:usf:v1publicationstate:fenced') {
      throw new CompilerError('handover abandonment refused: current V1 publication is not fenced', {
        phase: 'candidate:handover-abandonment',
      });
    }
    if (fenceField(observation, 'handoverD0AuthorityDigest')
        !== recoveryEffect.pre_d1_authority_digest) {
      throw new CompilerError('handover abandonment refused: the fence D0 authority is not the recovered pre-D1 authority', {
        phase: 'candidate:handover-abandonment',
      });
    }
    await assertAbandonmentPreconditionsInTransaction(client, transaction, {
      generationDigest, nativeGraphStore,
    });
    await failpoint('after-fence-validation');

    // Re-verify the grant against the TRANSACTION-VIEW values, not stage A's.
    const transactionGrant = verifyGrant(grantEnvelope, {
      authorityPreDigest: inTransactionBefore.digest,
      fenceContentDigest: observation.contentDigest,
      handoverGenerationDigest: generationDigest,
      d1RecoveryRecordDigest,
      permittedEffectDigest,
      now: new Date(now),
    });
    if (transactionGrant.envelope_digest !== grant.envelope_digest
        || transactionGrant.nonce !== grant.nonce) {
      throw new CompilerError('handover abandonment refused: the grant is not the one the intent recorded', {
        phase: 'candidate:handover-abandonment',
      });
    }
    await failpoint('after-grant-verification');

    // Stage the exact permitted effect and nothing else.
    const { stores } = await readCanonicalStores(
      client, transaction, [...v2ManagedGraphSet(manifest), observation.graph]);
    stageHandoverAbandonmentEffect(stores, effect);
    await replaceStores(client, transaction, stores);
    await failpoint('after-mutation-staging');

    const shapes = shapeConstraints(manifest);
    const validation = await client.validateInTransactionWithReceipt(transaction, shapes);
    if (validation?.conforms !== true) {
      const report = await client.reportInTransaction(transaction, shapes);
      throw new CompilerError('handover abandonment candidate failed live SHACL validation', {
        phase: 'candidate:handover-abandonment', report,
      });
    }
    for (const rule of integrityRules(manifest)) {
      const violations = await client.selectInTransaction(
        transaction, readText(rule.path, 'utf8'));
      if (violations.length > 0) {
        throw new CompilerError('handover abandonment candidate failed semantic integrity validation', {
          phase: 'candidate:handover-abandonment',
          integrityRule: rule.file, violations: violations.slice(0, 20),
        });
      }
    }
    await failpoint('after-shacl-validation');

    // The fence must be gone and the history record present, observed through authority itself.
    const remaining = await client.selectInTransaction(transaction, `SELECT ?fence WHERE {
      GRAPH ?g { ?fence a <${V2_NATIVE_HANDOVER_FENCE_CLASS}> }
    }`);
    if (!Array.isArray(remaining) || remaining.length !== 0) {
      throw new CompilerError('handover abandonment did not resolve the fence in transaction view', {
        phase: 'candidate:handover-abandonment',
      });
    }
    const history = await client.selectInTransaction(transaction, `SELECT ?record WHERE {
      GRAPH ?g { ?record a <${HANDOVER_ABANDONMENT_RECORD_CLASS}> }
    }`);
    if (!Array.isArray(history) || history.length !== 1) {
      throw new CompilerError('handover abandonment did not install exactly one history record', {
        phase: 'candidate:handover-abandonment',
      });
    }

    const candidate = await readTransactionAuthorityInventory(client, transaction);
    await failpoint('after-candidate-inventory');
    predictedPostAuthority = candidate.digest;
    if (!SHA256.test(predictedPostAuthority)
        || predictedPostAuthority === inTransactionBefore.digest) {
      throw new CompilerError('handover abandonment produced no distinct authority transition', {
        phase: 'candidate:handover-abandonment',
      });
    }
    // The prediction must be internally consistent: recomputing the fold from the same inventory
    // must reproduce it exactly, and the only graph that may have moved is the fence's.
    if (semanticAuthorityInventoryDigest(candidate.inventory, candidate.triples)
        !== predictedPostAuthority) {
      throw new CompilerError('handover abandonment prediction is not internally consistent', {
        phase: 'candidate:handover-abandonment',
      });
    }
    const before = new Map(inTransactionBefore.inventory.map((r) => [r.graph, r.sha256]));
    const after = new Map(candidate.inventory.map((r) => [r.graph, r.sha256]));
    const moved = [...new Set([...before.keys(), ...after.keys()])]
      .filter((graph) => before.get(graph) !== after.get(graph));
    if (moved.length !== 1 || moved[0] !== observation.graph) {
      throw new CompilerError('handover abandonment moved a graph outside the fence graph', {
        phase: 'candidate:handover-abandonment', moved,
      });
    }
    await failpoint('after-prediction');

    await failpoint('before-ready-to-commit');
    journal.markReadyToCommit(operationId, attempt.ordinal, {
      predicted_post_authority: predictedPostAuthority,
      transaction_preimage_digest: `sha256:${createHash('sha256').update(canonicalJson({
        authority_pre_digest: inTransactionBefore.digest,
        effect,
        permitted_effect_digest: permittedEffectDigest,
      }), 'utf8').digest('hex')}`,
      validated_candidate_inventory_digest: `sha256:${createHash('sha256')
        .update(canonicalJson(candidate.inventory), 'utf8').digest('hex')}`,
    });
    await failpoint('after-ready-to-commit');

    await failpoint('immediately-before-commit');
    committed = true;
    await client.commit(transaction);
  } catch (error) {
    // Only a transaction that never reached commit may be rolled back. Once commit has been
    // ATTEMPTED the outcome is a question for read-back, never for another write.
    if (!committed && transaction !== undefined) {
      try { await client.rollback(transaction); } catch { /* already gone */ }
    }
    throw error;
  }
  await failpoint('commit-success-before-readback');

  // --- Stage C: classification only. ------------------------------------------------------
  //
  // Nothing below may turn a committed transition into an apparent failure. A failed read-back
  // leaves the attempt at READY_TO_COMMIT, which is exactly the ambiguous-commit condition the
  // recovery path exists to classify -- it never triggers a second commit.
  const observedAfter = await readIndependentAuthorityDigest(client);
  const classification = classifyObservedAuthority(observedAfter, {
    authorityPreDigest: observedAuthority,
    predictedPostAuthority,
  });
  let journalError = null;
  try {
    journal.classify(operationId, attempt.ordinal, {
      classification,
      classified_at: now,
      observed_authority_digest: observedAfter,
      reached_commit: true,
    });
  } catch (error) {
    // Local bookkeeping failed AFTER a semantic commit. The commit is not undone by that, and
    // must not be reported as a failure. Semantic state, not this file, is the authority; the
    // recovery path reclassifies from read-back if this is ever revisited.
    journalError = error.message;
  }
  return Object.freeze({
    outcome: 'COMMITTED',
    classification,
    operation_id: operationId,
    attempt: attempt.ordinal,
    authority_pre_digest: observedAuthority,
    predicted_post_authority: predictedPostAuthority,
    observed_authority_digest: observedAfter,
    mutated: classification === PREDICTED_POST_STATE,
    replayed: false,
    journal_error: journalError,
  });
}

async function compilePatch({ client, manifest, patch, publicationMode, readText = readFileSync }) {
  let transaction;
  try {
    transaction = await client.begin();
    const stores = await readAffectedStores(client, transaction, patch);
    if (patchState(stores, patch) !== 'pre') {
      throw new CompilerError('candidate does not match the exact live pre-state', { phase: 'candidate:precondition' });
    }
    for (const { value } of patch.deletions) stores.get(value.graph.value).removeQuad(triple(value));
    for (const { value } of patch.additions) stores.get(value.graph.value).addQuad(triple(value));
    if (patchState(stores, patch) !== 'post') {
      throw new CompilerError('candidate post-state could not be constructed exactly', { phase: 'candidate:postcondition' });
    }
    await replaceStores(client, transaction, stores);
    const shapes = shapeConstraints(manifest);
    const validation = await client.validateInTransactionWithReceipt(transaction, shapes);
    if (validation?.conforms !== true) {
      const report = await client.reportInTransaction(transaction, shapes);
      throw new CompilerError('RDF Patch candidate failed live SHACL validation', {
        phase: 'candidate:shacl', report,
      });
    }
    for (const rule of integrityRules(manifest)) {
      const violations = await client.selectInTransaction(transaction, readText(rule.path, 'utf8'));
      if (violations.length > 0) {
        throw new CompilerError('RDF Patch candidate failed semantic integrity validation', {
          phase: 'candidate:integrity', integrityRule: rule.file, violations: violations.slice(0, 20),
        });
      }
    }
    const projectedStatements = Number.isSafeInteger(manifest.publicationBudget?.maximumProjectedStatementCount)
      ? manifest.publicationBudget.maximumProjectedStatementCount
      : null;
    if (projectedStatements === null) {
      throw new CompilerError('candidate publication budget policy is unavailable', { phase: 'candidate:budget' });
    }
    if (publicationMode === 'validate') {
      await client.rollback(transaction);
      transaction = null;
      return Object.freeze({
        ok: true,
        liveValidation: Object.freeze(validation),
        commitOutcome: Object.freeze({
          candidateDigest: patch.digest,
          exactCandidateStateVerified: true,
          state: 'VALIDATED_ROLLBACK',
        }),
      });
    }
    await client.commit(transaction);
    transaction = null;
    return Object.freeze({
      ok: true,
      liveValidation: Object.freeze(validation),
      commitOutcome: Object.freeze({
        candidateDigest: patch.digest,
        exactCandidateStateVerified: true,
        state: 'COMMITTED',
      }),
    });
  } catch (error) {
    if (transaction) {
      try { await client.rollback(transaction); } catch { /* preserve the primary failure */ }
    }
    if (error instanceof CompilerError) throw error;
    // Keep the originating failure attached: this boundary wraps every
    // transaction fault into one message, and without the cause the
    // authoritative blocker is unrecoverable from the test output alone.
    throw new CompilerError(error.message, { phase: 'candidate:transaction', cause: error });
  }
}

function digest(value) {
  const observed = value?.digest || value?.authorityDigest;
  if (typeof observed !== 'string') throw new CompilerError('authority witness is missing its digest', { phase: 'authority:witness' });
  return observed.startsWith('sha256:') ? observed : `sha256:${observed}`;
}

function semanticModelDirectory(repositoryRoot) {
  const root = realpathSync(repositoryRoot);
  const candidate = resolve(root, SEMANTIC_MODEL_PATH);
  const repositoryRelative = relative(root, candidate);
  if (repositoryRelative !== SEMANTIC_MODEL_PATH || repositoryRelative.startsWith(`..${sep}`)) {
    throw new CompilerError('semantic model path escapes the repository', { phase: 'compile:configuration' });
  }
  if (lstatSync(candidate).isSymbolicLink()) throw new CompilerError('semantic model path must not be a symbolic link', { phase: 'compile:configuration' });
  const canonical = realpathSync(candidate);
  if (relative(root, canonical) !== SEMANTIC_MODEL_PATH) throw new CompilerError('semantic model path resolves outside its canonical repository role', { phase: 'compile:configuration' });
  return canonical;
}

function validationEvidence(result, authorityDigest, candidateDigest) {
  if (!result?.liveValidation || result.liveValidation.conforms !== true) {
    throw new CompilerError('candidate validation returned no conforming provider receipt', { phase: 'candidate:validation-receipt' });
  }
  const record = Object.freeze({
    authorityDigest,
    candidateDigest,
    providerValidationReceipt: result.liveValidation,
    schema: 'semantic-authority-compiler-validation-report-v1',
    state: result.commitOutcome.state,
  });
  const bytes = Buffer.from(`${canonicalJson(record)}\n`, 'utf8');
  return Object.freeze({ bytes, digest: sha256(bytes), record });
}

function sourceValidationEvidence(sourceValidation, authorityDigest, candidateDigest) {
  if (!sourceValidation || sourceValidation.derived?.conforms !== true) {
    throw new CompilerError('base source preparation returned no real derived validation receipt', {
      phase: 'candidate:validation-receipt',
    });
  }
  const record = Object.freeze({
    authorityDigest,
    candidateDigest,
    providerValidationReceipt: sourceValidation,
    schema: 'semantic-authority-compiler-source-validation-report-v1',
    state: 'VALIDATED_ROLLBACK',
  });
  const bytes = Buffer.from(canonicalJson(record), 'utf8');
  return Object.freeze({ bytes, digest: sha256(bytes), record });
}

export function createSemanticModelCompilationCommand({
  client,
  readAuthorityWitness,
  repositoryRoot,
  loadManifestFunction = loadManifest,
  compileFunction = compile,
  checkLocalFunction = checkLocal,
  externalAuthorityTrustAnchor,
  trustedNow = null,
  verifyExternalAuthorityProofApproval = missingExternalAuthorityProofVerifier,
  verifyImplementationWorkGrantEnvelope = missingImplementationWorkGrantVerifier,
  publicationLane,
  nativeGraphStore,
}) {
  if (!client || typeof client.connectivity !== 'function') throw new TypeError('semantic authority client is required');
  if (typeof readAuthorityWitness !== 'function') throw new TypeError('authority witness reader is required');
  if (typeof repositoryRoot !== 'string') throw new TypeError('repository root is required');
  if (!publicationLane || typeof publicationLane.reserve !== 'function'
      || typeof publicationLane.readReservation !== 'function'
      || typeof publicationLane.bindFactoryPrepare !== 'function'
      || typeof publicationLane.readFactoryPrepareBinding !== 'function') {
    throw new TypeError('semantic publication lane is required');
  }

  return Object.freeze({
    requiresCandidateBytes: true,

    async validateExternalAuthorityDelta({
      expectedAuthorityDigest,
      evidenceStore,
      expectedSource,
      externalAuthorityDelta,
      trustedNow: operationTrustedNow = null,
    }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) {
        throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      }
      const before = digest(await readAuthorityWitness(client));
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before external delta validation', { phase: 'authority:drift' });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const observedNow = await resolveExternalAuthorityTrustedNow(operationTrustedNow, trustedNow);
      const external = externalAuthorityDelta?.schema === IMPLEMENTATION_WORK_GRANT_DELTA_SCHEMA
        ? assertImplementationWorkGrantDelta({
          value: externalAuthorityDelta,
          expectedAuthorityDigest,
          evidenceStore,
          allowedGraphs: new Set(managedGraphs(manifest)),
          now: observedNow,
          verifyImplementationWorkGrant: verifyImplementationWorkGrantEnvelope,
        })
        : assertExternalAuthorityDelta({
          value: externalAuthorityDelta,
          expectedAuthorityDigest,
          expectedSource,
          evidenceStore,
          allowedGraphs: new Set(managedGraphs(manifest)),
          now: observedNow,
          trustAnchor: externalAuthorityTrustAnchor,
          verifyProofApprovalEnvelope: verifyExternalAuthorityProofApproval,
        });
      if (await inspectPatchState(client, external.patch) !== 'pre') {
        throw new CompilerError('external authority delta is not an unused exact live pre-state', {
          phase: 'candidate:external-authority-delta-replay',
        });
      }
      if (digest(await readAuthorityWitness(client)) !== before) {
        throw new CompilerError('external delta validation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      return Object.freeze(external.kind === 'implementation_work_grant' ? {
        casRootDigests: external.casRootDigests,
        grantCandidateDigest: external.grantCandidateDigest,
        grantIri: external.grantIri,
        patchDigest: external.patchDigest,
      } : {
        casRootDigests: external.casRootDigests,
        conflictIri: external.conflictIri,
        correctionCandidateDigest: external.correctionCandidateDigest,
        patchDigest: external.patchDigest,
        proofResultIri: external.proofResultIri,
        resolutionIri: external.resolutionIri,
        reviewIri: external.reviewIri,
      });
    },

    async prepareSourceDelta({
      expectedAuthorityDigest,
      evidenceStore = null,
      expectedSource = null,
      externalAuthorityDelta = null,
      validationAuthorityContext = null,
      trustedNow: operationTrustedNow = null,
    }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) throw new CompilerError('semantic authority drifted before base source preparation', { phase: 'authority:drift' });
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const observedNow = externalAuthorityDelta === null
        ? null
        : await resolveExternalAuthorityTrustedNow(operationTrustedNow, trustedNow);
      const external = externalAuthorityDelta === null ? null
        : externalAuthorityDelta?.schema === IMPLEMENTATION_WORK_GRANT_DELTA_SCHEMA
          ? assertImplementationWorkGrantDelta({
            value: externalAuthorityDelta,
            expectedAuthorityDigest,
            evidenceStore,
            allowedGraphs: new Set(managedGraphs(manifest)),
            now: observedNow,
            verifyImplementationWorkGrant: verifyImplementationWorkGrantEnvelope,
          })
          : assertExternalAuthorityDelta({
            value: externalAuthorityDelta,
            expectedAuthorityDigest,
            expectedSource,
            evidenceStore,
            allowedGraphs: new Set(managedGraphs(manifest)),
            now: observedNow,
            trustAnchor: externalAuthorityTrustAnchor,
            verifyProofApprovalEnvelope: verifyExternalAuthorityProofApproval,
          });
      if (external !== null && await inspectPatchState(client, external.patch) !== 'pre') {
        throw new CompilerError('external authority delta is not an unused exact live pre-state', {
          phase: 'candidate:external-authority-delta-replay',
        });
      }
      let validationContextPatch = null;
      if (validationAuthorityContext !== null) {
        exactObjectKeys(validationAuthorityContext, ['bytesBase64', 'digest'], 'validation authority context');
        const contextBytes = Buffer.from(validationAuthorityContext.bytesBase64, 'base64');
        if (contextBytes.toString('base64') !== validationAuthorityContext.bytesBase64) {
          throw new CompilerError('validation authority context bytes are not canonical base64', {
            phase: 'candidate:source-delta',
          });
        }
        validationContextPatch = parseCanonicalPatch(
          contextBytes, validationAuthorityContext.digest, new Set(managedGraphs(manifest)), new Set(['base']),
        );
        if (validationContextPatch.deletions.length !== 0) {
          throw new CompilerError('validation authority context must remain additive', {
            phase: 'candidate:source-delta',
          });
        }
      }
      const prepared = await composeSourceCandidate({
        client,
        manifest,
        generatedPatch: external?.patch || null,
        validationContextPatch,
        authorityWitness: beforeWitness,
        compileFunction,
        stage: 'base',
      });
      if (digest(await readAuthorityWitness(client)) !== before) {
        throw new CompilerError('base source preparation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      const validation = sourceValidationEvidence(prepared.sourceValidation, before, prepared.digest);
      return Object.freeze({
        baseSemanticDelta: Object.freeze({
          authorityPreDigest: before,
          bytesBase64: prepared.bytes.toString('base64'),
          candidateDigest: prepared.digest,
          exactCandidateStateVerified: true,
          mediaType: 'application/rdf-patch',
          state: 'VALIDATED_ROLLBACK',
          validationReceiptDigest: validation.digest,
        }),
        externalAuthorityDelta: external === null ? null : Object.freeze(
          external.kind === 'implementation_work_grant' ? {
            casRootDigests: external.casRootDigests,
            grantCandidateDigest: external.grantCandidateDigest,
            grantIri: external.grantIri,
            kind: external.kind,
            patchDigest: external.patchDigest,
          } : {
            casRootDigests: external.casRootDigests,
            conflictIri: external.conflictIri,
            correctionCandidateDigest: external.correctionCandidateDigest,
            patchDigest: external.patchDigest,
            proofResultIri: external.proofResultIri,
            resolutionIri: external.resolutionIri,
            reviewIri: external.reviewIri,
          },
        ),
        preservedAuthorityDelta: external === null ? null : Object.freeze({
          bytesBase64: external.patch.bytes.toString('base64'),
          digest: external.patch.digest,
        }),
        validationEvidence: validation,
      });
    },

    async composeCandidate({ generatedCandidateBytes, expectedAuthorityDigest, preservedAuthorityDelta = null }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before source candidate composition', {
          phase: 'authority:drift', expectedAuthorityDigest, observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const v2 = Buffer.isBuffer(generatedCandidateBytes)
        && generatedCandidateBytes.toString('utf8').startsWith('# semantic-proof-v2 ');
      const allowedGraphs = v2
        ? v2ManagedGraphSet(manifest) : new Set(managedGraphs(manifest));
      const generatedPatch = parseCanonicalPatch(generatedCandidateBytes, undefined, allowedGraphs);
      if (generatedPatch.protocol !== 'semantic-proof-v1') {
        throw new CompilerError('V2 candidate cannot enter the V1 source-composition path', {
          phase: 'candidate:protocol',
        });
      }
      let preservedPatch = null;
      if (preservedAuthorityDelta !== null) {
        exactObjectKeys(preservedAuthorityDelta, ['bytesBase64', 'digest'], 'preserved authority delta');
        const preservedBytes = Buffer.from(preservedAuthorityDelta.bytesBase64, 'base64');
        if (preservedBytes.toString('base64') !== preservedAuthorityDelta.bytesBase64) {
          throw new CompilerError('preserved authority delta bytes are not canonical base64', {
            phase: 'candidate:external-authority-delta',
          });
        }
        preservedPatch = parseCanonicalPatch(
          preservedBytes,
          preservedAuthorityDelta.digest,
          allowedGraphs,
          new Set(['base']),
        );
        if (preservedPatch.deletions.length !== 0) {
          throw new CompilerError('preserved authority delta must remain additive', {
            phase: 'candidate:external-authority-delta',
          });
        }
      }
      const combined = await composeSourceCandidate({
        client, manifest, generatedPatch, preservedPatch, authorityWitness: beforeWitness, compileFunction,
      });
      const after = digest(await readAuthorityWitness(client));
      if (after !== before) throw new CompilerError('source candidate composition changed semantic authority', { phase: 'authority:validate-drift' });
      return combined;
    },

    async previewCandidateInventory({ candidateBytes, candidateDigest, expectedAuthorityDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const openingWitness = await readAuthorityWitness(client);
      const before = digest(openingWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before candidate preview', { phase: 'authority:drift' });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const v2 = Buffer.isBuffer(candidateBytes)
        && candidateBytes.toString('utf8').startsWith('# semantic-proof-v2 ');
      const graphSet = v2 ? v2ManagedGraphSet(manifest) : new Set(managedGraphs(manifest));
      const patch = parseCanonicalPatch(candidateBytes, candidateDigest, graphSet);
      let transaction;
      try {
        transaction = await client.begin();
        const current = await readTransactionAuthorityInventory(client, transaction, graphSet);
        assertTransactionSnapshotMatchesWitness(current, openingWitness);
        if (patchState(current.stores, patch) !== 'pre') {
          throw new CompilerError('candidate preview does not match the exact live pre-state', { phase: 'candidate:precondition' });
        }
        for (const { value } of patch.deletions) current.stores.get(value.graph.value).removeQuad(triple(value));
        for (const { value } of patch.additions) {
          if (!current.stores.has(value.graph.value)) {
            current.stores.set(value.graph.value, new Store());
          }
          current.stores.get(value.graph.value).addQuad(triple(value));
        }
        if (patchState(current.stores, patch) !== 'post') {
          throw new CompilerError('candidate preview could not construct the exact target state', { phase: 'candidate:postcondition' });
        }
        const inventory = [];
        const dependencyInventory = [];
        for (const [graph, store] of [...current.stores.entries()].sort(([left], [right]) => left.localeCompare(right))) {
          // Same correction as prospectiveInventory: the inventory's sha256 must be the digest
          // readSemanticAuthorityWitness reports, or a predicted inventory cannot be compared
          // against a committed one.
          const content = await graphText(store);
          const [record, dependencyRecord] = await Promise.all([
            canonicalGraphDigest(content), canonicalInventoryGraphDigest(graph, content),
          ]);
          if (record.triples !== dependencyRecord.triples) {
            throw new CompilerError('candidate preview graph inventories disagree on triple count', {
              phase: 'authority:inventory', graph,
            });
          }
          // Empty named graphs are not part of the live witness and therefore
          // cannot contribute to either prospective identity.
          if (record.triples > 0) {
            inventory.push(Object.freeze({
              graph, sha256: `sha256:${record.sha256}`, triples: record.triples,
            }));
            dependencyInventory.push(Object.freeze({
              graph, sha256: `sha256:${dependencyRecord.sha256}`, triples: record.triples,
            }));
          }
        }
        await client.rollback(transaction);
        transaction = null;
        const after = digest(await readAuthorityWitness(client));
        if (after !== before) {
          throw new CompilerError('candidate preview changed semantic authority', {
            phase: 'authority:validate-drift',
            beforeAuthorityDigest: before,
            afterAuthorityDigest: after,
          });
        }
        return Object.freeze({
          candidateDigest: patch.digest,
          dependencyInventory: Object.freeze(dependencyInventory),
          inventory: Object.freeze(inventory),
        });
      } finally {
        if (transaction) await client.rollback(transaction);
      }
    },

    // Generate and preview the V2 publication in its only lawful order. C1 is
    // first materialised from frozen pre-D1 identities, then applied only to
    // the transaction-local canonical stores.  The exact D1 authority and
    // validation dependency set observed from that state generate C2.  D2 is
    // derived in the same transaction and the transaction is always rolled
    // back.  No publication claim, grant, clock, CAS writer or commit surface
    // is available to this coordinator.
    async previewV2PublicationFromFrozenInputs({
      frozenInputs,
      expectedD0AuthorityDigest,
    }) {
      if (!SHA256.test(expectedD0AuthorityDigest || '')
          || frozenInputs?.protocol !== 'semantic-proof-v2'
          || frozenInputs?.d0_authority_digest !== expectedD0AuthorityDigest) {
        throw new CompilerError('V2 frozen publication input does not bind exact D0', {
          phase: 'candidate:configuration',
        });
      }
      const openingWitness = await readAuthorityWitness(client);
      const before = digest(openingWitness);
      if (before !== expectedD0AuthorityDigest) {
        throw new CompilerError('semantic authority drifted before V2 publication shadow', {
          phase: 'authority:drift',
          expectedAuthorityDigest: expectedD0AuthorityDigest,
          observedAuthorityDigest: before,
        });
      }
      const preliminaryC1 = materializeAggregateCompilerAuthorityCandidateV2({
        ...frozenInputs,
        d1_binding: null,
        stage: 'C1',
      });
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const allowedGraphs = v2ManagedGraphSet(manifest);
      const c1Patch = parseCanonicalPatch(
        preliminaryC1.bytes,
        preliminaryC1.candidateDigest,
        allowedGraphs,
      );
      exactV2CandidateCoreBinding(c1Patch, preliminaryC1.identityBytes, 'C1');
      let transaction;
      try {
        transaction = await client.begin();
        const current = await readTransactionAuthorityInventory(client, transaction, allowedGraphs);
        assertTransactionSnapshotMatchesWitness(current, openingWitness);
        applyPatchToStores(current.stores, c1Patch, 'D1');
        const d1 = await prospectiveInventory(current.stores);
        const dependencyIdentityDigests = prospectiveD1DependencyIdentityDigests(
          current.stores,
        );
        const candidates = prepareAggregateCompilerAuthorityCandidatesV2({
          frozen_inputs: frozenInputs,
          d1_observation: {
            authority_digest: d1.authorityDigest,
            dependency_identity_digests: dependencyIdentityDigests,
          },
        });
        if (!candidates.c1.bytes.equals(preliminaryC1.bytes)
            || !candidates.c1.identityBytes.equals(preliminaryC1.identityBytes)
            || candidates.c1.candidateDigest !== preliminaryC1.candidateDigest) {
          throw new CompilerError('canonical V2 producer regenerated a different C1', {
            phase: 'candidate:v2-identity',
          });
        }
        const c2Patch = parseCanonicalPatch(
          candidates.c2.bytes,
          candidates.c2.candidateDigest,
          allowedGraphs,
        );
        const c2Core = exactV2CandidateCoreBinding(
          c2Patch,
          candidates.c2.identityBytes,
          'C2',
        );
        if (c2Core.d1_binding?.authority_digest !== d1.authorityDigest
            || c2Core.d1_binding?.c1_candidate_digest !== c1Patch.digest
            || canonicalJson(c2Core.d1_binding?.dependency_identity_digests)
              !== canonicalJson(dependencyIdentityDigests)) {
          throw new CompilerError('V2 C2 does not bind the exact observed D1 closure', {
            phase: 'candidate:d1-binding',
          });
        }
        applyPatchToStores(current.stores, c2Patch, 'D2');
        const d2 = await prospectiveInventory(current.stores);
        await client.rollback(transaction);
        transaction = null;
        const after = digest(await readAuthorityWitness(client));
        if (after !== before) {
          throw new CompilerError('V2 publication shadow changed semantic authority', {
            phase: 'authority:validate-drift',
            beforeAuthorityDigest: before,
            afterAuthorityDigest: after,
          });
        }
        return Object.freeze({
          schema: 'usf-v2-two-step-production-shadow-v1',
          protocol: 'semantic-proof-v2',
          d0AuthorityDigest: before,
          d1: Object.freeze({
            ...d1,
            candidateDigest: candidates.c1.candidateDigest,
            dependencyIdentityDigests,
            dependencySetDigest: candidates.d1_dependency_set_digest,
          }),
          d2: Object.freeze({
            ...d2,
            candidateDigest: candidates.c2.candidateDigest,
            evaluationInputAuthorityDigest: d1.authorityDigest,
          }),
          candidates,
          candidateBindings: Object.freeze({
            releaseSubjectDigest: candidates.release_subject_digest,
            externalAttestationSetRootDigest:
              candidates.external_attestation_set_root_digest,
            candidateGeneratorImplementationDigest:
              candidates.candidate_generator_implementation_digest,
            candidateCommandDigest: candidates.candidate_command_digest,
            c2D1AuthorityDigest: candidates.d1_authority_digest,
            c2D1DependencyIdentityDigests:
              candidates.d1_dependency_identity_digests,
            c2D1DependencySetDigest: candidates.d1_dependency_set_digest,
          }),
          productionWriteOperations: 0,
          productionCasWriteOperations: 0,
          productionJournalWriteOperations: 0,
          authorizationIssued: 0,
          publicationPerformed: 0,
          transactionBeginCount: 1,
          transactionRollbackCount: 1,
        });
      } finally {
        if (transaction) await client.rollback(transaction);
      }
    },

    // Predict both publication authorities without ever applying a database
    // mutation.  D2 is evaluated against the exact in-memory D1 state in the
    // same rolled-back transaction; it is never previewed against live D0 and
    // never selected by time or "latest" ordering.
    async previewPublicationSequence({
      d1CandidateBytes,
      d1CandidateDigest,
      d1CandidateIdentityBytes,
      d2CandidateBytes,
      d2CandidateDigest,
      d2CandidateIdentityBytes,
      expectedD0AuthorityDigest,
    }) {
      if (!SHA256.test(expectedD0AuthorityDigest || '')) {
        throw new CompilerError('expected D0 authority digest is required', {
          phase: 'authority:configuration',
        });
      }
      const openingWitness = await readAuthorityWitness(client);
      const before = digest(openingWitness);
      if (before !== expectedD0AuthorityDigest) {
        throw new CompilerError('semantic authority drifted before publication shadow', {
          phase: 'authority:drift',
          expectedAuthorityDigest: expectedD0AuthorityDigest,
          observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const v2Bytes = Buffer.isBuffer(d1CandidateBytes)
        && d1CandidateBytes.toString('utf8').startsWith('# semantic-proof-v2 ');
      const allowedGraphs = v2Bytes
        ? v2ManagedGraphSet(manifest) : new Set(managedGraphs(manifest));
      const d1Patch = parseCanonicalPatch(d1CandidateBytes, d1CandidateDigest, allowedGraphs);
      const d2Patch = parseCanonicalPatch(d2CandidateBytes, d2CandidateDigest, allowedGraphs);
      const exactSequence = (
        d1Patch.protocol === 'semantic-proof-v1'
        && d1Patch.stage === 'stage1'
        && d2Patch.protocol === 'semantic-proof-v1'
        && d2Patch.stage === 'stage2'
      ) || (
        d1Patch.protocol === 'semantic-proof-v2'
        && d1Patch.stage === 'C1'
        && d2Patch.protocol === 'semantic-proof-v2'
        && d2Patch.stage === 'C2'
      );
      if (!exactSequence) {
        throw new CompilerError('publication shadow requires exact V1 stage1/stage2 or V2 C1/C2 candidates', {
          phase: 'candidate:sequence',
        });
      }
      let v2CandidateCores = null;
      if (d1Patch.protocol === 'semantic-proof-v2') {
        const c1 = exactV2CandidateCoreBinding(d1Patch, d1CandidateIdentityBytes, 'C1');
        const c2 = exactV2CandidateCoreBinding(d2Patch, d2CandidateIdentityBytes, 'C2');
        if (canonicalJson(frozenV2CandidateCore(c1))
              !== canonicalJson(frozenV2CandidateCore(c2))
            || c1.d0_authority_digest !== expectedD0AuthorityDigest
            || c2.d1_binding?.c1_candidate_digest !== d1Patch.digest) {
          throw new CompilerError('V2 C1/C2 frozen identity binding differs', {
            phase: 'candidate:v2-identity',
          });
        }
        v2CandidateCores = Object.freeze({ c1, c2 });
      } else if (d1CandidateIdentityBytes !== undefined
          || d2CandidateIdentityBytes !== undefined) {
        throw new CompilerError('V2 identity bytes cannot enter the V1 publication preview', {
          phase: 'candidate:protocol',
        });
      }
      let transaction;
      try {
        transaction = await client.begin();
        const current = await readTransactionAuthorityInventory(client, transaction, allowedGraphs);
        assertTransactionSnapshotMatchesWitness(current, openingWitness);
        applyPatchToStores(current.stores, d1Patch, 'D1');
        const d1 = await prospectiveInventory(current.stores);
        // The D1 dependency identity set is live-derived inside this shadow transaction, and it
        // is the value the production publisher compares against the approved plan. It must
        // therefore reach the caller on `d1`, exactly as previewV2PublicationFromFrozenInputs
        // reports it. Exposing it only under `candidateBindings` left
        // `d1.dependencyIdentityDigests` permanently undefined, and canonicalJson(undefined) is
        // undefined rather than a canonical string, so the grant reservation's comparison could
        // never hold for ANY plan -- empty dependency set included.
        const dependencyIdentityDigests = v2CandidateCores
          ? prospectiveD1DependencyIdentityDigests(current.stores)
          : null;
        if (v2CandidateCores) {
          if (v2CandidateCores.c2.d1_binding.authority_digest !== d1.authorityDigest
              || canonicalJson(
                v2CandidateCores.c2.d1_binding.dependency_identity_digests,
              ) !== canonicalJson(dependencyIdentityDigests)) {
            throw new CompilerError(
              'V2 C2 does not bind the exact C1-produced D1 authority and dependencies',
              {
                phase: 'candidate:d1-binding',
                actualD1AuthorityDigest: d1.authorityDigest,
                c2D1AuthorityDigest: v2CandidateCores.c2.d1_binding.authority_digest,
              },
            );
          }
        }
        applyPatchToStores(current.stores, d2Patch, 'D2');
        const d2 = await prospectiveInventory(current.stores);
        await client.rollback(transaction);
        transaction = null;
        const after = digest(await readAuthorityWitness(client));
        if (after !== before) {
          throw new CompilerError('publication shadow changed semantic authority', {
            phase: 'authority:validate-drift',
            beforeAuthorityDigest: before,
            afterAuthorityDigest: after,
          });
        }
        return Object.freeze({
          d0AuthorityDigest: before,
          d1: Object.freeze({
            ...d1,
            candidateDigest: d1Patch.digest,
            ...(dependencyIdentityDigests === null ? {} : {
              dependencyIdentityDigests: Object.freeze([...dependencyIdentityDigests]),
            }),
          }),
          d2: Object.freeze({
            ...d2,
            candidateDigest: d2Patch.digest,
            evaluationInputAuthorityDigest: d1.authorityDigest,
          }),
          candidateBindings: v2CandidateCores ? Object.freeze({
            releaseSubjectDigest: v2CandidateCores.c1.release_subject_digest,
            externalAttestationSetRootDigest:
              v2CandidateCores.c1.external_attestation_set_root_digest,
            candidateGeneratorImplementationDigest:
              v2CandidateCores.c1.compiler_identity.implementation_source_digest,
            candidateCommandDigest: v2CandidateCores.c1.compiler_identity.command_digest,
            c2D1AuthorityDigest: v2CandidateCores.c2.d1_binding.authority_digest,
            c2D1DependencyIdentityDigests: Object.freeze([
              ...v2CandidateCores.c2.d1_binding.dependency_identity_digests,
            ]),
          }) : null,
          productionWriteOperations: 0,
          transactionBeginCount: 1,
          transactionRollbackCount: 1,
        });
      } finally {
        if (transaction) await client.rollback(transaction);
      }
    },

    // V2 publication is deliberately exposed through a protocol-specific
    // entrypoint.  The generic V1 execute() path below continues to reject V2
    // candidates, so a V1 envelope can never be used to commit a V2 patch.
    async reserveV2HandoverGeneration({
      d0AuthorityDigest,
      handoverGenerationDigest,
      prospectivePublicationPlanDigest,
      recoveryAuthorityDigests = [],
    }) {
      if (!Array.isArray(recoveryAuthorityDigests)
          || recoveryAuthorityDigests.length !== 2
          || recoveryAuthorityDigests.some((value) => !SHA256.test(value || ''))
          || new Set(recoveryAuthorityDigests).size !== 2) {
        throw new CompilerError('V2 handover recovery authority set is not exact', {
          phase: 'candidate:publication-lane',
        });
      }
      const reservation = Object.freeze({
        schema: V2_HANDOVER_RESERVATION_SCHEMA,
        d0_authority_digest: d0AuthorityDigest,
        handover_generation_digest: handoverGenerationDigest,
        prospective_publication_plan_digest: prospectivePublicationPlanDigest,
      });
      return publicationLane.reserve(reservation, async () => {
        const observed = digest(await readAuthorityWitness(client));
        if (observed === d0AuthorityDigest) return;
        if (!recoveryAuthorityDigests.includes(observed)) {
          throw new CompilerError('V2 handover reservation no longer observes exact D0', {
            phase: 'candidate:publication-lane',
            expectedAuthorityDigest: d0AuthorityDigest,
            observedAuthorityDigest: observed,
          });
        }
        const rows = await client.select(`SELECT ?fence ?generation ?state ?v1state WHERE {
          GRAPH ?graph {
            ?fence a <${V2_NATIVE_HANDOVER_FENCE_CLASS}>;
              <${USF_ONTOLOGY}handoverGenerationDigest> ?generation;
              <${USF_ONTOLOGY}handoverOwnershipState> ?state;
              <${USF_ONTOLOGY}handoverCurrentV1PublicationState> ?v1state .
          }
        } ORDER BY ?fence ?generation ?state ?v1state`);
        if (!Array.isArray(rows) || rows.length !== 1
            || rows[0].fence?.value !== V2_NATIVE_HANDOVER_FENCE
            || rows[0].generation?.value !== handoverGenerationDigest
            || rows[0].state?.value !== 'urn:usf:v2ownershipstate:handoverpending'
            || rows[0].v1state?.value !== 'urn:usf:v1publicationstate:fenced') {
          throw new CompilerError('V2 handover reservation recovery fence is not exact', {
            phase: 'candidate:publication-lane',
          });
        }
      });
    },

    bindV2FactoryPrepare({ factoryPrepareReceiptDigest }) {
      return publicationLane.bindFactoryPrepare(factoryPrepareReceiptDigest);
    },

    async executeV2Candidate({
      candidateBytes,
      candidateDigest,
      candidateIdentityBytes,
      expectedD0AuthorityDigest,
      expectedAuthorityDigest,
      expectedPostAuthorityDigest,
      prospectivePublicationPlanDigest,
      factoryPrepareReceiptDigest,
      publicationMode = 'validate',
      stage,
    }) {
      if (!['C1', 'C2'].includes(stage)
          || !['validate', 'commit'].includes(publicationMode)
          || !SHA256.test(expectedD0AuthorityDigest || '')
          || !SHA256.test(expectedAuthorityDigest || '')
          || !SHA256.test(expectedPostAuthorityDigest || '')
          || (publicationMode === 'commit'
            && (!SHA256.test(prospectivePublicationPlanDigest || '')
              || !SHA256.test(factoryPrepareReceiptDigest || '')))) {
        throw new CompilerError('V2 production candidate configuration is incomplete', {
          phase: 'candidate:v2-configuration',
        });
      }
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before V2 compilation', {
          phase: 'authority:drift',
          expectedAuthorityDigest,
          observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const patch = parseCanonicalPatch(
        candidateBytes,
        candidateDigest,
        v2ManagedGraphSet(manifest),
      );
      const core = exactV2CandidateCoreBinding(patch, candidateIdentityBytes, stage);
      if (core.d0_authority_digest !== expectedD0AuthorityDigest
          || (stage === 'C1' && expectedD0AuthorityDigest !== expectedAuthorityDigest)
          || (stage === 'C1' && core.d1_binding !== null)
          || (stage === 'C2'
            && core.d1_binding?.authority_digest !== expectedAuthorityDigest)) {
        throw new CompilerError('V2 production candidate authority binding is stale', {
          phase: 'candidate:v2-authority-binding',
        });
      }
      if (publicationMode === 'commit') {
        const reservation = publicationLane.readReservation();
        const prepareBinding = publicationLane.readFactoryPrepareBinding();
        if (!reservation
            || reservation.d0_authority_digest !== expectedD0AuthorityDigest
            || reservation.handover_generation_digest !== core.handover_generation_digest
            || reservation.prospective_publication_plan_digest
              !== prospectivePublicationPlanDigest
            || !prepareBinding
            || prepareBinding.factory_prepare_receipt_digest !== factoryPrepareReceiptDigest
            || prepareBinding.handover_generation_digest !== core.handover_generation_digest
            || prepareBinding.prospective_publication_plan_digest
              !== prospectivePublicationPlanDigest
            || prepareBinding.reservation_digest
              !== sha256(Buffer.from(canonicalJson(reservation), 'utf8'))) {
          throw new CompilerError('V2 candidate is not the reserved handover generation', {
            phase: 'candidate:publication-lane',
          });
        }
      }
      let release = null;
      try {
        if (publicationMode === 'commit') release = publicationLane.acquire();
        const result = await compilePatch({ client, manifest, patch, publicationMode });
        const after = digest(await readAuthorityWitness(client));
        if (publicationMode === 'validate' && after !== before) {
          throw new CompilerError('validate-only V2 candidate changed semantic authority', {
            phase: 'authority:validate-drift',
          });
        }
        if (publicationMode === 'commit' && after !== expectedPostAuthorityDigest) {
          throw new CompilerError('V2 candidate committed an unexpected authority digest', {
            phase: 'authority:postcondition',
            expectedAuthorityDigest: expectedPostAuthorityDigest,
            observedAuthorityDigest: after,
          });
        }
        return Object.freeze({
          ...result,
          evaluatedAuthorityDigest: before,
          protocol: 'semantic-proof-v2',
          stage,
        });
      } finally {
        if (release) release();
      }
    },

    async observeV2D1Dependencies({ expectedAuthorityDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) {
        throw new CompilerError('expected V2 D1 authority digest is required', {
          phase: 'candidate:v2-configuration',
        });
      }
      const before = digest(await readAuthorityWitness(client));
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before V2 D1 observation', {
          phase: 'authority:drift',
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      let transaction;
      try {
        transaction = await client.begin();
        const current = await readCanonicalStores(
          client,
          transaction,
          managedGraphs(manifest),
        );
        const dependencyIdentityDigests = prospectiveD1DependencyIdentityDigests(
          current.stores,
        );
        await client.rollback(transaction);
        transaction = null;
        const after = digest(await readAuthorityWitness(client));
        if (after !== before) {
          throw new CompilerError('V2 D1 observation changed semantic authority', {
            phase: 'authority:validate-drift',
          });
        }
        return Object.freeze({
          authorityDigest: before,
          dependencyIdentityDigests,
        });
      } finally {
        if (transaction) await client.rollback(transaction);
      }
    },

    async inspectCandidateState({ candidateBytes, candidateDigest }) {
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const v2 = Buffer.isBuffer(candidateBytes)
        && candidateBytes.toString('utf8').startsWith('# semantic-proof-v2 ');
      const patch = parseCanonicalPatch(candidateBytes, candidateDigest,
        v2 ? v2ManagedGraphSet(manifest) : new Set(managedGraphs(manifest)));
      return Object.freeze({ candidateDigest: patch.digest, state: await inspectPatchState(client, patch) });
    },

    async validateNativeV2Currentness({ expectedAuthorityDigest, handoverGenerationDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) {
        throw new CompilerError('native V2 validation requires exact current authority', {
          phase: 'candidate:v2-currentness',
        });
      }
      const reservation = publicationLane.readReservation();
      if (!reservation
          || reservation.handover_generation_digest !== handoverGenerationDigest) {
        throw new CompilerError('native V2 validation requires the durable publication reservation', {
          phase: 'candidate:v2-currentness',
        });
      }
      const beforeWitness = await readAuthorityWitness(client);
      if (digest(beforeWitness) !== expectedAuthorityDigest) {
        throw new CompilerError('native V2 validation authority drifted before evaluation', {
          phase: 'authority:drift',
        });
      }
      await assertExactNativeV2HandoverFence(client, handoverGenerationDigest);
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const result = await compileFunction({
        authorityWitness: beforeWitness,
        client,
        manifest,
        publicationBudgetPolicy: manifest.publicationBudget,
        publicationMode: 'validate',
      });
      const after = digest(await readAuthorityWitness(client));
      if (after !== expectedAuthorityDigest) {
        throw new CompilerError('native V2 validation changed semantic authority', {
          phase: 'authority:validate-drift',
        });
      }
      return Object.freeze({
        ...result,
        evaluatedAuthorityDigest: expectedAuthorityDigest,
        semanticModelPath: SEMANTIC_MODEL_PATH,
        validationEvidence: validationEvidence(
          result, expectedAuthorityDigest, result.commitOutcome.candidateDigest,
        ),
      });
    },

    async execute({ expectedAuthorityDigest, publicationMode = 'validate', candidateBytes, candidateDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before compilation', {
          phase: 'authority:drift',
          expectedAuthorityDigest,
          observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      if (candidateBytes !== undefined || candidateDigest !== undefined) {
        checkLocalFunction(manifest);
        const v2 = Buffer.isBuffer(candidateBytes)
          && candidateBytes.toString('utf8').startsWith('# semantic-proof-v2 ');
        const patch = parseCanonicalPatch(candidateBytes, candidateDigest,
          v2 ? v2ManagedGraphSet(manifest) : new Set(managedGraphs(manifest)));
        if (patch.protocol !== 'semantic-proof-v1') {
          throw new CompilerError('V2 production candidate commits remain disabled', {
            phase: 'candidate:protocol',
          });
        }
        const result = await compilePatch({
          client: createCurrentV1PublicationInterlockedClient(client, publicationLane, {
            commitMode: publicationMode === 'commit',
            nativeGraphStore,
          }), manifest, patch, publicationMode,
        });
        if (publicationMode === 'validate') {
          const after = digest(await readAuthorityWitness(client));
          if (after !== before) throw new CompilerError('validate-only RDF Patch changed semantic authority', { phase: 'authority:validate-drift' });
        }
        return Object.freeze({
          ...result,
          evaluatedAuthorityDigest: before,
          semanticModelPath: SEMANTIC_MODEL_PATH,
          validationEvidence: validationEvidence(result, before, patch.digest),
        });
      }
      const result = await compileFunction({
        authorityWitness: beforeWitness,
        client: createCurrentV1PublicationInterlockedClient(client, publicationLane, {
          commitMode: publicationMode === 'commit',
          nativeGraphStore,
        }),
        manifest,
        publicationBudgetPolicy: manifest.publicationBudget,
        publicationMode,
      });
      if (publicationMode === 'validate') {
        const after = digest(await readAuthorityWitness(client));
        if (after !== before) throw new CompilerError('validate-only compilation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      return Object.freeze({
        ...result,
        evaluatedAuthorityDigest: before,
        semanticModelPath: SEMANTIC_MODEL_PATH,
      });
    },
  });
}

export const semanticModelCompilationCommandInternals = Object.freeze({
  createHandoverAbandonmentJournal,
  readHandoverFenceRows,
  readTransactionAuthorityInventory,
  assertTransactionSnapshotMatchesWitness,
  stageHandoverAbandonmentEffect,
  assertAbandonmentPreconditionsInTransaction,
  HANDOVER_ABANDONMENT_RECORD_CLASS,
  V2_HANDOVER_FENCE_PREDICATES,
  assertImplementationWorkGrantDelta,
  assertExternalAuthorityDelta,
  createImplementationWorkGrantDeltaPackage,
  createExternalAuthorityDeltaPackage,
  digest,
  exactCandidateBytes,
  canonicalCombinedPatch,
  composeSourceCandidate,
  parseCanonicalPatch,
  patchState,
  semanticModelDirectory,
  assertCurrentV1PublicationUnfenced,
  createCurrentV1PublicationInterlockedClient,
  createSemanticPublicationLaneV2,
  validateImplementationWorkGrantArtifacts,
});
