import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
} from 'node:fs';
import { dirname, isAbsolute } from 'node:path';

import { REAL_JOURNAL_IO } from './semantic-proof-v1.mjs';

export const SEMANTIC_PROOF_V2 = 'semantic-proof-v2';
export const PROSPECTIVE_PUBLICATION_PLAN_V2 = 'usf-prospective-publication-plan-v2';
export const DERIVED_CLOSURE_RECEIPT_V2 = 'usf-derived-consumer-closure-receipt-v2';
export const GRAPH_PUBLICATION_RECEIPT_V2 = 'usf-semantic-publication-receipt-v2';
export const GRAPH_PUBLICATION_JOURNAL_V2 = 'usf-semantic-publication-journal-v2';
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
const SUCCESSOR_DECISIONS = new Set([
  'COMPATIBLE_SUCCESSOR',
  'EXPLICITLY_AUTHORIZED_SUCCESSOR',
]);

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
  for (const [field, label] of [
    ['release_subject_digest', 'release subject'],
    ['derived_consumer_registry_digest', 'derived consumer registry'],
    ['identity_dependency_graph_digest', 'identity dependency graph'],
    ['d0_authority_digest', 'D0 authority'],
    ['predicted_d1_authority_digest', 'predicted D1 authority'],
    ['d2_evaluation_input_authority_digest', 'D2 evaluation input'],
    ['predicted_d2_authority_digest', 'predicted D2 authority'],
  ]) exactDigest(plan[field], label);
  if (plan.derived_consumer_registry_digest !== DERIVED_CONSUMER_REGISTRY_V2_DIGEST) {
    throw new Error('prospective plan registry differs from the exact V2 registry');
  }
  if (plan.identity_dependency_graph_digest !== IDENTITY_DEPENDENCY_GRAPH_V2_DIGEST) {
    throw new Error('prospective plan dependency graph differs from the exact V2 graph');
  }
  if (plan.d2_evaluation_input_authority_digest !== plan.predicted_d1_authority_digest) {
    throw new Error('V2 D2 evaluation must consume the exact predicted D1 authority');
  }
  if (plan.outcome !== 'PROCEED') throw new Error('blocked prospective plan is not publishable');
  exactGitIdentity(plan.factory_deployment_tree, 'Factory deployment tree');
  exactGitIdentity(plan.graph_protected_tree, 'Graph protected tree');
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
      if (item.expected_successor !== null || item.expected_successor_digest !== null
          || item.explicit_authorization_grant_digest !== undefined) {
        throw new Error('unchanged consumer cannot carry successor state');
      }
      continue;
    }
    if (!SUCCESSOR_DECISIONS.has(item.decision) || !item.expected_successor) {
      throw new Error('mandatory consumer has an unsupported transition decision');
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
      || receipt.terminal_result !== 'VERIFIED') {
    throw new Error('Graph requires an exact Factory VERIFIED closure receipt');
  }
  const expected = expectedClosure(plan);
  if (receipt.transaction_id !== closureTransactionIdV2(plan)
      || receipt.release_subject_digest !== plan.release_subject_digest
      || receipt.prospective_publication_plan_digest !== prospectivePublicationPlanDigestV2(plan)
      || receipt.derived_consumer_registry_digest !== plan.derived_consumer_registry_digest
      || receipt.d1_authority_digest !== plan.predicted_d1_authority_digest
      || receipt.d2_authority_digest !== plan.predicted_d2_authority_digest
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

function terminalReceipt(inputs, closureReceipt, acceptedAt) {
  return Object.freeze({
    schema: GRAPH_PUBLICATION_RECEIPT_V2,
    protocol: SEMANTIC_PROOF_V2,
    transaction_id: closureTransactionIdV2(inputs.plan),
    coordination_identity_digest: coordinationIdentity(inputs),
    release_subject_digest: inputs.plan.release_subject_digest,
    prospective_publication_plan_digest: prospectivePublicationPlanDigestV2(inputs.plan),
    derived_consumer_registry_digest: inputs.plan.derived_consumer_registry_digest,
    d0_authority_digest: inputs.plan.d0_authority_digest,
    d1_authority_digest: inputs.plan.predicted_d1_authority_digest,
    d2_authority_digest: inputs.plan.predicted_d2_authority_digest,
    factory_closure_receipt_digest: factoryClosureReceiptDigestV2(
      closureReceipt,
      inputs.plan,
    ),
    mandatory_consumer_identity_digests: Object.freeze([
      ...closureReceipt.mandatory_consumer_identity_digests,
    ]),
    explicit_authorization_grant_digests: Object.freeze([
      ...closureReceipt.explicit_authorization_grant_digests,
    ]),
    publication_outcome: 'accepted',
    accepted_at: exactUtcSecond(acceptedAt, 'V2 publication acceptance time'),
  });
}

export function graphPublicationReceiptDigestV2(receipt) {
  if (!receipt || receipt.schema !== GRAPH_PUBLICATION_RECEIPT_V2
      || receipt.protocol !== SEMANTIC_PROOF_V2 || receipt.publication_outcome !== 'accepted') {
    throw new Error('invalid V2 Graph terminal publication receipt');
  }
  return canonicalDigestV2(receipt);
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
  let lockDescriptor;
  try {
    lockDescriptor = openSync(lockPath, 'wx', 0o600);
    const journal = readDurableSemanticProofV2Journal(journalPath);
    const result = await advanceSemanticProofV2Publication({ ...inputs, journal });
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
    if (lockDescriptor !== undefined) {
      closeSync(lockDescriptor);
      try { unlinkSync(lockPath); } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
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
  if (state !== 'CONSUMED' && journal.grantConsumed) {
    throw new Error('V2 grant was consumed before terminal publication closure');
  }
  const terminalReached = state
    && JOURNAL_ORDER.indexOf(state) >= JOURNAL_ORDER.indexOf('TERMINAL_RECEIPT_COMMITTED');
  if (terminalReached) {
    if (!journal.terminalReceipt || journal.terminalReceiptDigest
        !== graphPublicationReceiptDigestV2(journal.terminalReceipt)
        || journal.terminalReceipt.coordination_identity_digest !== expectedCoordination
        || journal.terminalReceipt.release_subject_digest !== inputs.plan.release_subject_digest
        || journal.terminalReceipt.prospective_publication_plan_digest
          !== prospectivePublicationPlanDigestV2(inputs.plan)
        || journal.terminalReceipt.derived_consumer_registry_digest
          !== inputs.plan.derived_consumer_registry_digest
        || journal.terminalReceipt.d0_authority_digest !== inputs.plan.d0_authority_digest
        || journal.terminalReceipt.d1_authority_digest
          !== inputs.plan.predicted_d1_authority_digest
        || journal.terminalReceipt.d2_authority_digest
          !== inputs.plan.predicted_d2_authority_digest
        || journal.terminalReceipt.accepted_at !== inputs.terminal_receipt_at
        || canonicalJsonV2(journal.terminalReceipt.mandatory_consumer_identity_digests)
          !== canonicalJsonV2(expectedClosure(inputs.plan).currentDigests)
        || canonicalJsonV2(journal.terminalReceipt.explicit_authorization_grant_digests)
          !== canonicalJsonV2(expectedClosure(inputs.plan).explicitGrantDigests)
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
    return Object.freeze({ state: 'RESERVED', terminal: false });
  }
  if (state === 'RESERVED') {
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
    const receipt = terminalReceipt(inputs, closure, inputs.terminal_receipt_at);
    const expectedDigest = graphPublicationReceiptDigestV2(receipt);
    const persisted = await adapter.persistTerminalReceipt(receipt, inputs);
    if (persisted?.digest !== expectedDigest) {
      throw new Error('persisted Graph terminal receipt differs from exact predicted bytes');
    }
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
    ]);
    return Object.freeze({ state: 'TERMINAL_RECEIPT_COMMITTED', terminal: false, receipt });
  }
  if (state === 'TERMINAL_RECEIPT_COMMITTED') {
    const receipt = inputs.journal.terminalReceipt;
    const consumed = await adapter.consumeGrant(receipt, inputs);
    exactDigest(consumed?.digest, 'V2 grant consumption receipt');
    inputs.journal.grantConsumed = true;
    inputs.journal.publicationState = 'ACCEPTED';
    inputs.journal.append('CONSUMED', inputs, trustedAt, [
      ...commonReceipts,
      inputs.journal.terminalReceiptDigest,
      consumed.digest,
    ]);
    return Object.freeze({ state: 'CONSUMED', terminal: true, receipt });
  }
  if (state === 'CONSUMED') {
    return Object.freeze({
      state,
      terminal: true,
      receipt: Object.freeze(inputs.journal.terminalReceipt),
    });
  }
  throw new Error('unsupported semantic-proof-v2 publication state');
}
