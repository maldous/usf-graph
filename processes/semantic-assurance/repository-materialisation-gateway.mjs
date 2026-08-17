import { createHash } from 'node:crypto';
import { createReadStream, existsSync, lstatSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import {
  NATIVE_VALIDATION_CURRENT,
  OWNERSHIP,
  authorityWitness,
  resolveOwnerBoundary,
  validContractRef,
} from './semantic-bootstrap-packet.mjs';
import {
  PROOF_CURRENTNESS,
  PROOF_CURRENTNESS_CODES,
  PROOF_CURRENTNESS_STATE_IRI,
  proofCurrentnessVerdict,
} from './proof-currentness.mjs';
import { readImplementationWorkGrantAuthorityStateV1 } from './semantic-authority-publication.mjs';

const CONTRACT = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const ACTIVE = 'urn:usf:contractactivationstate:active';
const ACTIVE_LIFECYCLE = 'urn:usf:semanticlifecyclestate:active';
const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
const ACCEPTED = 'urn:usf:decisionstate:accepted';
const RESOLVED_DECISION = new Set(['explicit', 'unique-accepted']);

// Factory action states. Every factory-consumed conclusion in this module
// resolves to exactly one of these, and absence never selects PROCEED.
export const ACTION_STATES = Object.freeze({
  proceed: 'PROCEED',
  reserved: 'RESERVED_NO_ACTION',
  block: 'BLOCK',
  unresolved: 'UNRESOLVED_FAIL_CLOSED',
});
// Precedence when several dispositions hold at once. An explicit negative
// outranks an unproven one because it is more actionable and equally closed;
// PROCEED is only ever reached when nothing else applies.
const ACTION_STATE_PRECEDENCE = [ACTION_STATES.block, ACTION_STATES.unresolved, ACTION_STATES.reserved, ACTION_STATES.proceed];

const APPLICABILITY = Object.freeze({
  required: 'urn:usf:validationapplicabilitystate:required',
  notRequired: 'urn:usf:validationapplicabilitystate:notrequired',
  conditional: 'urn:usf:validationapplicabilitystate:conditional',
  reserved: 'urn:usf:validationapplicabilitystate:reserved',
  unresolved: 'urn:usf:validationapplicabilitystate:unresolved',
});
const ACTIVATION = Object.freeze({
  reserved: 'urn:usf:validationactivationstate:reserved',
  activated: 'urn:usf:validationactivationstate:activated',
  blocked: 'urn:usf:validationactivationstate:blocked',
});
const VALIDATION_NON_PUBLICATION_CLOSURE = 'urn:usf:authoritybindingrule:validationnonpublicationdependencyclosure';
const VALIDATION_CROSS_REPOSITORY_NON_PUBLICATION_CLOSURE =
  'urn:usf:authoritybindingrule:validationcrossrepositorynonpublicationclosure';
const NON_PUBLICATION_DEPENDENCY_ALGORITHM = 'sha256-rdfc10-nonpublication-graph-inventory-v1';
const NON_PUBLICATION_EXCLUDED_GRAPHS = Object.freeze([
  'urn:usf:graph:capabilities',
  'urn:usf:graph:derived:coverage',
  'urn:usf:graph:derived:evidence',
  'urn:usf:graph:derived:obligations',
  'urn:usf:graph:derived:readiness',
  'urn:usf:graph:derived:surfaces',
  'urn:usf:graph:evidence',
  'urn:usf:graph:proofs',
]);
const NON_PUBLICATION_DIGEST_BINDING_GRAPH = 'urn:usf:graph:proofs';
const PASSED_RESULT = 'urn:usf:resultstate:passed';

// One gap code -> one factory disposition. A code with no entry here is a
// programming error, not a silent PROCEED: resolveDisposition throws.
export const GAP_DISPOSITIONS = Object.freeze({
  'missing-successful-proof': ACTION_STATES.block,
  // Proof currentness. A successful historical result is not a current one, so
  // every way the currentness conclusion can fall short has its own disposition
  // and none of them reaches PROCEED.
  [PROOF_CURRENTNESS_CODES.currentnessUnresolved]: ACTION_STATES.unresolved,
  [PROOF_CURRENTNESS_CODES.currentnessAmbiguous]: ACTION_STATES.unresolved,
  [PROOF_CURRENTNESS_CODES.evidenceStale]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.evidenceInvalid]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.authorityBindingStale]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.implementationDigestStale]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.dependencyDigestStale]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.algorithmDigestStale]: ACTION_STATES.block,
  'missing-current-passing-validation': ACTION_STATES.block,
  'validation-obligation-blocked': ACTION_STATES.block,
  'validation-satisfaction-not-current': ACTION_STATES.block,
  'validation-exemption-unwarranted': ACTION_STATES.block,
  'validation-obligation-reserved': ACTION_STATES.reserved,
  'validation-applicability-reserved': ACTION_STATES.reserved,
  'validation-applicability-unresolved': ACTION_STATES.unresolved,
  'validation-applicability-conditional-unevaluated': ACTION_STATES.unresolved,
  'validation-obligation-activation-unresolved': ACTION_STATES.unresolved,
});
// Gaps that withhold only the validated claim. A reserved validation obligation
// does not withdraw realisation authority that an accepted decision and a
// successful proof already granted; it withholds any claim of being validated.
const VALIDATION_SCOPED_GAPS = new Set(['validation-obligation-reserved', 'validation-applicability-reserved']);

// Stable authority reads.
//
// A witness read concurrently with the semantic queries proves nothing: the
// queries may observe a different authority state than the witness did. The
// witness must BRACKET the read — one before, one after — and both must agree on
// digest, graph inventory count and triple total. Only then is the conclusion a
// conclusion about one authority state.
export const AUTHORITY_MOVED_CODE = 'materialisation-authority-moved';

function witnessSummary(witness) {
  return Object.freeze({
    digest: `sha256:${witness.digest}`,
    graphCount: witness.inventory.length,
    triples: witness.triples,
    // Carried for the projection; identity is compared on digest, graph count and
    // triple total only, which is what "the same authority state" means here.
    inventory: Object.freeze(witness.inventory.map((record) => Object.freeze({
      graph: record.graph,
      sha256: `sha256:${record.sha256}`,
      dependencySha256: `sha256:${record.dependencySha256}`,
      triples: record.triples,
    }))),
  });
}

function assertWitnessUnchanged(before, after, phase) {
  if (before.digest === after.digest && before.graphCount === after.graphCount && before.triples === after.triples) return;
  throw new Error(
    `${AUTHORITY_MOVED_CODE}: live authority changed during ${phase} `
    + `(before ${before.digest}/${before.graphCount}g/${before.triples}t, `
    + `after ${after.digest}/${after.graphCount}g/${after.triples}t)`,
  );
}

// Run `read` bracketed by two inventory-derived witnesses and require exact
// equality. Nothing inside `read` may be treated as authoritative unless the
// bracket closes.
export async function stableAuthorityRead(client, phase, read) {
  const before = witnessSummary(await authorityWitness(client));
  const value = await read(before);
  const after = witnessSummary(await authorityWitness(client));
  assertWitnessUnchanged(before, after, phase);
  return { witness: before, value };
}

// The Graph owner boundary.
//
// Every actionability conclusion this module publishes belongs to exactly one
// authority generation. Before the handover that is the V1 proof/publication
// lifecycle. After the D2 fence it is the native V2 generation and its renewable
// validation-currentness head, and the V1 lifecycle is never consulted again:
// not as a fallback, not filtered, not translated. Replacing the source here —
// at the owner — is what keeps every downstream consumer's contract unchanged.

// Native currentness, expressed in the declared reason vocabulary so the public
// work-plan contract is byte-shape identical. A pending handover is an absent
// conclusion, not a negative one, so it fails closed as UNRESOLVED.
function nativeCurrentnessVerdict(owner, mandatoryObligations = []) {
  const terminal = owner.ownershipState === OWNERSHIP.terminal;
  // The contract's mandatory obligations are contract facts, not proof facts:
  // they survive the handover unchanged. Only the V1 PROOF RESULTS disappear, so
  // `obligationProofResults` and `perProof` are empty while the obligation set
  // itself stays exact. Emptying the obligations too would have made a terminal
  // contract look as though it had no obligations at all.
  const obligations = Object.freeze([...new Set(mandatoryObligations)].sort());
  // `facts` is part of the currentness shape every consumer already reads. Under
  // native V2 there is no V1 proof result to name, so every collection is EMPTY
  // rather than absent, and the shape itself is preserved. A bare `{}` satisfied
  // the gap census (which reads the singular `proofResult` and falls back to the
  // contract) but left `proofResults` / `mandatoryObligations` /
  // `obligationProofResults` undefined, so projectContract threw under terminal
  // V2. Keeping the exact shape fixes every consumer at the source instead of
  // scattering defensive defaults.
  if (terminal && owner.validationCurrentnessState === NATIVE_VALIDATION_CURRENT) {
    return Object.freeze({
      state: PROOF_CURRENTNESS.current,
      stateIri: PROOF_CURRENTNESS_STATE_IRI[PROOF_CURRENTNESS.current],
      reasons: Object.freeze([]),
      facts: Object.freeze({
        proofResults: Object.freeze([]),
        mandatoryObligations: obligations,
        obligationProofResults: Object.freeze([]),
        perProof: Object.freeze([]),
      }),
    });
  }
  const state = terminal ? PROOF_CURRENTNESS.stale : PROOF_CURRENTNESS.unresolved;
  const code = terminal
    ? PROOF_CURRENTNESS_CODES.authorityBindingStale
    : PROOF_CURRENTNESS_CODES.currentnessUnresolved;
  return Object.freeze({
    state,
    stateIri: PROOF_CURRENTNESS_STATE_IRI[state],
    reasons: Object.freeze([code]),
    facts: Object.freeze({
      proofResults: Object.freeze([]),
      mandatoryObligations: obligations,
      obligationProofResults: Object.freeze([]),
      perProof: Object.freeze([]),
    }),
  });
}

// One currentness conclusion, one owner. The V1 resolver is reachable only while
// V1 still owns the boundary.
async function ownerBoundaryCurrentness(ctx, owner, contract, mandatoryObligations) {
  if (owner.ownershipState === OWNERSHIP.v1) {
    return proofCurrentnessVerdict(ctx.client, contract, {
      mandatoryObligations,
      observedAt: ctx.observedAt ?? null,
    });
  }
  return nativeCurrentnessVerdict(owner, mandatoryObligations);
}

function resolveDisposition(code) {
  const disposition = GAP_DISPOSITIONS[code];
  if (!disposition) throw new Error(`work-plan gap code has no declared factory disposition: ${code}`);
  return disposition;
}

function strongestState(states) {
  for (const candidate of ACTION_STATE_PRECEDENCE) if (states.includes(candidate)) return candidate;
  return ACTION_STATES.unresolved;
}
const MAX_PACKET_BYTES = 65_536;
const MAX_PACKET_ITEMS = 256;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const DECISION_FORMAT_PREDICATE = 'urn:usf:ontology:authorisesRepresentationFormat';
const READ_ONLY_VALIDATION_MODE = 'urn:usf:executionscopemode:readonlysemanticvalidation';
const MATERIALISATION_MODE = 'urn:usf:executionscopemode:repositorymaterialisation';
const EXECUTION_SCOPE_SCHEMA = 'urn:usf:schema:contract-execution-scope-core:1';
// Canonical IRI of a native V2 validation-currentness head. Declared in
// semantic-model/authority.ttl as usf:V2NativeValidationCurrentnessHead. It is
// the terminal-V2 anchor of an execution scope, occupying the same role a V1
// ProofResult IRI occupies before the handover.
const NATIVE_VALIDATION_CURRENTNESS_IRI_PREFIX = 'urn:usf:v2nativevalidationcurrentness:';
const EXECUTION_SCOPE_PAYLOAD_SCHEMA = Object.freeze({
  schema: 'urn:usf:identitypayloadschema:contract-execution-scope-v1',
  canonicalisation: 'RFC8785',
  digestAlgorithm: 'sha256',
  version: 1,
});
const EXECUTION_SCOPE_PREDICATE_MANIFEST = Object.freeze({
  schema: EXECUTION_SCOPE_SCHEMA,
  authorityBindings: Object.freeze([
    'acceptedDecisionIri',
    'contractIri',
    'currentProofIri',
    'liveProjectionAuthorityDigest',
    'obligationIri',
  ]),
  boundedEffects: Object.freeze([
    'maximumRepositoryWrites',
    'permittedActionIris',
    'permittedEffectIris',
    'permittedTools',
    'readableResourceIris',
    'repositoryMutationPermitted',
    'writePaths',
  ]),
});

const value = (row, key) => row[key]?.value ?? null;
const MATERIALISATION_RULE_WHERE = `
  ?family a <urn:usf:ontology:ArtefactFamily> ;
          <urn:usf:ontology:canonicalName> ?familyName ;
          <urn:usf:ontology:usesMaterialisationRule> ?rule .
  ?rule <urn:usf:ontology:usesStorageClass> ?storage ;
        <urn:usf:ontology:usesRepresentationFormat> ?format ;
        <urn:usf:ontology:usesNamingRule> ?naming .
  ?naming <urn:usf:ontology:filenamePattern> ?namingPattern .
  OPTIONAL { ?rule <urn:usf:ontology:usesPathRole> ?pathRole }
  FILTER NOT EXISTS { ?family <urn:usf:ontology:semanticAdequacyDisposition> ?familyDisposition . FILTER(?familyDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
  FILTER NOT EXISTS { ?rule <urn:usf:ontology:semanticAdequacyDisposition> ?ruleDisposition . FILTER(?ruleDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
  FILTER NOT EXISTS { ?naming <urn:usf:ontology:semanticAdequacyDisposition> ?namingDisposition . FILTER(?namingDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
`;
// EVERY mechanical concern is imported, never reimplemented: path normalisation
// and containment, symlink rejection, operation validation, plan
// canonicalisation and digest, CAS lookup and verification, the filesystem
// apply, idempotence, rollback and rollback error aggregation all live once in
// the lower pure capability module. This gateway keeps exclusive ownership of
// the live authority read, the realisation verdict, the complete contract,
// decision and proof conclusions, witness bracketing, coordinator authorisation
// and the production create/validate/dry-run/apply tools.
import {
  MATERIALISATION_ACTIONS,
  MATERIALISATION_BOUNDS,
  assertNoSymlinkSegments,
  canonicalJson,
  containedBy,
  decisionAuthorisesPath,
  executePlanOperations,
  sha256 as planDigestOf,
  sourceDigest as planSourceDigest,
  resolveCasObject,
  rollbackAndThrow as rethrowWithRollback,
  stable as stableInput,
  validatePlanOperation,
} from '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';

const { MAX_PLAN_BYTES, MAX_OPERATIONS, MAX_TRACKED_WRITE_BYTES } = MATERIALISATION_BOUNDS;
const ACTIONS = new Set(MATERIALISATION_ACTIONS);

export const stable = stableInput;
export const jcs = canonicalJson;
export const digest = planDigestOf;
export const sourceDigest = planSourceDigest;

const AUTHORITY_CONFLICT_BINDING_SCHEMA = 2;
const SEMANTIC_CORRECTION_ACCEPTED = 'urn:usf:semanticcorrectiondecisionstate:accepted';
const AUTHORITY_CONFLICT_RESOLUTION_ACCEPTED = SEMANTIC_CORRECTION_ACCEPTED;
const SEMANTIC_ADEQUACY_REVIEW_ACCEPTED = 'urn:usf:semanticadequacyreviewstate:accepted';
const OWNER_ASSIGNMENT_ACTIVE = 'active';
const OWNER_ENVELOPE_VERIFIED = 'urn:usf:resultstate:passed';
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const REPOSITORY_ID = /^[A-Za-z0-9._/-]{1,256}$/;
const AUTHORITY_IRI = /^urn:usf:[a-z0-9]+:[a-z0-9]+$/;
const CONFLICT_EFFECT_IRI = /^urn:usf:obligationeffect:[a-z0-9]+$/;
const IMPLEMENTATION_WORK_GRANT_PURPOSE = 'urn:usf:implementationworkpurpose:v2nativehandover';
const IMPLEMENTATION_WORK_GRANT_RESERVED = 'urn:usf:implementationworkgrantstate:reserved';
const IMPLEMENTATION_WORK_ALLOWED = Object.freeze([
  'urn:usf:implementationworkaction:candidateexistingfileedit',
  'urn:usf:implementationworkaction:candidatesigningandprotection',
  'urn:usf:implementationworkaction:casclosure',
  'urn:usf:implementationworkaction:compilationandbuild',
  'urn:usf:implementationworkaction:evidencegeneration',
  'urn:usf:implementationworkaction:independentreview',
  'urn:usf:implementationworkaction:isolatedreadonlyrehearsal',
  'urn:usf:implementationworkaction:tests',
]);
const IMPLEMENTATION_WORK_DENIED = Object.freeze([
  'urn:usf:implementationworkeffect:a0capture',
  'urn:usf:implementationworkeffect:authoritymutation',
  'urn:usf:implementationworkeffect:businesssemanticscopeexpansion',
  'urn:usf:implementationworkeffect:deployment',
  'urn:usf:implementationworkeffect:implicitpathwidening',
  'urn:usf:implementationworkeffect:learnedexecution',
  'urn:usf:implementationworkeffect:productionwrite',
  'urn:usf:implementationworkeffect:providercontact',
  'urn:usf:implementationworkeffect:pruning',
  'urn:usf:implementationworkeffect:semanticpublication',
  'urn:usf:implementationworkeffect:v2activation',
]);

function exactKeys(valueToCheck, expected, label) {
  if (!valueToCheck || typeof valueToCheck !== 'object' || Array.isArray(valueToCheck)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(valueToCheck).sort();
  const wanted = [...expected].sort();
  if (jcs(actual) !== jcs(wanted)) throw new Error(`${label} has an unknown or missing field`);
}

function exactSortedSet(items, label, predicate = (item) => typeof item === 'string' && item.length > 0) {
  if (!Array.isArray(items) || items.length === 0 || items.some((item) => !predicate(item))) {
    throw new Error(`${label} must be a non-empty canonical string set`);
  }
  const canonical = [...new Set(items)].sort();
  if (canonical.length !== items.length || jcs(canonical) !== jcs(items)) {
    throw new Error(`${label} must be sorted and unique`);
  }
  return Object.freeze(canonical);
}

function operationSet(operations, key) {
  return Object.freeze([...new Set(operations.map((operation) => operation?.[key]).filter(Boolean))].sort());
}

function normaliseAuthorityConflictBinding(binding, operations) {
  exactKeys(binding, [
    'candidateDigest', 'conflictAuthorityDigest', 'consumptionAuthorityDigest',
    'ownerAuthorityDomain', 'predecessorSourceHead', 'predecessorSourceTree',
    'repository', 'requestedEffects', 'schemaVersion', 'sourcePaths',
    'sourceScopeDigest', 'successorSourceTree', 'validationObligations',
  ], 'authority-conflict binding');
  if (binding.schemaVersion !== AUTHORITY_CONFLICT_BINDING_SCHEMA) {
    throw new Error('authority-conflict binding schema is unsupported');
  }
  if (!Array.isArray(operations) || operations.length === 0 || operations.length > MAX_OPERATIONS) {
    throw new Error('authority-conflict binding requires bounded operations');
  }
  if (!SHA256.test(binding.candidateDigest || '')
      || !SHA256.test(binding.conflictAuthorityDigest || '')
      || !SHA256.test(binding.consumptionAuthorityDigest || '')
      || !SHA256.test(binding.sourceScopeDigest || '')) {
    throw new Error('authority-conflict binding digest is invalid');
  }
  if (![binding.predecessorSourceHead, binding.predecessorSourceTree, binding.successorSourceTree]
    .every((item) => GIT_OBJECT.test(item || ''))) {
    throw new Error('authority-conflict binding Git identity is invalid');
  }
  if (!REPOSITORY_ID.test(binding.repository || '')) throw new Error('authority-conflict binding repository is invalid');
  if (!AUTHORITY_IRI.test(binding.ownerAuthorityDomain || '')) throw new Error('authority-conflict owner domain is invalid');
  const sourcePaths = exactSortedSet(binding.sourcePaths, 'authority-conflict source paths');
  if (digest(jcs(sourcePaths)) !== binding.sourceScopeDigest) {
    throw new Error('authority-conflict source scope digest mismatch');
  }
  const requestedEffects = exactSortedSet(
    binding.requestedEffects,
    'authority-conflict requested effects',
    (item) => typeof item === 'string' && CONFLICT_EFFECT_IRI.test(item),
  );
  const validationObligations = exactSortedSet(
    binding.validationObligations,
    'authority-conflict validation obligations',
    (item) => typeof item === 'string' && item.startsWith('urn:usf:validationobligation:'),
  );
  // Every existing-file write carries its exact preimage. This makes the
  // accepted resolution non-replayable even before its authority generation is
  // superseded: the first application destroys the signed precondition.
  if (operations.some((operation) => ['write-file', 'move-path', 'delete-path'].includes(operation?.action)
      && !SHA256.test(operation?.sourceDigest || ''))) {
    throw new Error('authority-conflict operation requires an exact source preimage');
  }
  const operationCore = Object.freeze({
    operations: stable(operations),
    repository: binding.repository,
    schemaVersion: 1,
  });
  return Object.freeze({
    schemaVersion: AUTHORITY_CONFLICT_BINDING_SCHEMA,
    candidateDigest: binding.candidateDigest,
    conflictAuthorityDigest: binding.conflictAuthorityDigest,
    consumptionAuthorityDigest: binding.consumptionAuthorityDigest,
    ownerAuthorityDomain: binding.ownerAuthorityDomain,
    predecessorSourceHead: binding.predecessorSourceHead,
    predecessorSourceTree: binding.predecessorSourceTree,
    repository: binding.repository,
    requestedActions: operationSet(operations, 'action'),
    requestedEffects,
    requestedFormats: operationSet(operations, 'representationFormat'),
    requestedPaths: operationSet(operations, 'path'),
    operationDigest: digest(jcs(operationCore)),
    sourcePaths,
    sourceScopeDigest: binding.sourceScopeDigest,
    successorSourceTree: binding.successorSourceTree,
    validationObligations,
  });
}

function sameSet(left, right) {
  return jcs([...new Set(left || [])].sort()) === jcs([...new Set(right || [])].sort());
}

function normaliseImplementationWorkGrantBinding(value) {
  exactKeys(value, [
    'evidenceSetDigest', 'grantCandidateDigest', 'grantIri',
    'nonPublicationDependencySetDigest', 'predecessorCommit', 'predecessorTree', 'repository',
  ], 'implementation work grant plan binding');
  if (!SHA256.test(value.evidenceSetDigest || '')
      || !SHA256.test(value.grantCandidateDigest || '')
      || !SHA256.test(value.nonPublicationDependencySetDigest || '')
      || value.grantIri !== `urn:usf:implementationworkgrant:${value.grantCandidateDigest.slice(7)}`
      || !REPOSITORY_ID.test(value.repository || '')
      || !GIT_OBJECT.test(value.predecessorCommit || '')
      || !GIT_OBJECT.test(value.predecessorTree || '')) {
    throw new Error('implementation work grant plan binding identity is invalid');
  }
  return Object.freeze({ ...value });
}

function normaliseImplementationWorkGrantProjection(value) {
  exactKeys(value, [
    'allowedActions', 'authorityDigest', 'deniedEffects', 'evidenceSetDigest', 'expiresAt',
    'grantCandidateDigest', 'grantIri', 'issuedAt', 'nonPublicationDependencySetDigest',
    'nonce', 'purpose', 'repositories', 'state', 'transactionState',
  ], 'implementation work grant projection');
  if (!SHA256.test(value.authorityDigest || '') || !SHA256.test(value.evidenceSetDigest || '')
      || !SHA256.test(value.nonPublicationDependencySetDigest || '')
      || !SHA256.test(value.grantCandidateDigest || '')
      || value.grantIri !== `urn:usf:implementationworkgrant:${value.grantCandidateDigest.slice(7)}`
      || value.purpose !== IMPLEMENTATION_WORK_GRANT_PURPOSE || value.state !== IMPLEMENTATION_WORK_GRANT_RESERVED
      || value.transactionState !== 'reserved'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.nonce || '')
      || !Number.isFinite(Date.parse(value.issuedAt)) || !Number.isFinite(Date.parse(value.expiresAt))) {
    throw new Error('implementation work grant projection identity is invalid');
  }
  const allowedActions = exactSortedSet(value.allowedActions, 'implementation work grant ALLOW set');
  const deniedEffects = exactSortedSet(value.deniedEffects, 'implementation work grant DENY set');
  if (!sameSet(allowedActions, IMPLEMENTATION_WORK_ALLOWED)
      || !sameSet(deniedEffects, IMPLEMENTATION_WORK_DENIED)) {
    throw new Error('implementation work grant ALLOW or DENY set differs from the closed capability');
  }
  if (!Array.isArray(value.repositories) || value.repositories.length !== 2) {
    throw new Error('implementation work grant requires exactly two repository scopes');
  }
  const repositories = value.repositories.map((scope) => {
    exactKeys(scope, [
      'predecessorCommit', 'predecessorTree', 'repository', 'sourcePaths', 'sourceScopeDigest',
    ], 'implementation work repository scope');
    const paths = exactSortedSet(scope.sourcePaths, 'implementation work repository source paths');
    if (!['maldous/usf-factory', 'maldous/usf-graph'].includes(scope.repository)
        || !GIT_OBJECT.test(scope.predecessorCommit || '') || !GIT_OBJECT.test(scope.predecessorTree || '')
        || digest(jcs(paths)) !== scope.sourceScopeDigest) {
      throw new Error('implementation work repository scope is invalid');
    }
    return Object.freeze({ ...scope, sourcePaths: paths });
  }).sort((left, right) => left.repository.localeCompare(right.repository));
  if (jcs(repositories) !== jcs(value.repositories)
      || repositories[0].repository !== 'maldous/usf-factory'
      || repositories[1].repository !== 'maldous/usf-graph') {
    throw new Error('implementation work repository scopes are not the canonical pair');
  }
  return Object.freeze({ ...value, allowedActions, deniedEffects, repositories: Object.freeze(repositories) });
}

function evaluateImplementationWorkGrantProjection({
  grant,
  nonPublicationDependencySetDigest,
  repository,
  predecessorCommit,
  predecessorTree,
  operations,
  observedAt,
  repositoryRoot,
}) {
  const failures = [];
  let canonical;
  try { canonical = normaliseImplementationWorkGrantProjection(grant); } catch (error) {
    return Object.freeze({ actionState: ACTION_STATES.block, authorisedPaths: Object.freeze([]), failures: Object.freeze([{ code: 'implementation-work-grant-invalid', detail: error.message }]) });
  }
  const scope = canonical.repositories.find((item) => item.repository === repository);
  if (canonical.nonPublicationDependencySetDigest !== nonPublicationDependencySetDigest) {
    failures.push({ code: 'implementation-work-grant-stale-authority-dependency' });
  }
  if (!scope) failures.push({ code: 'implementation-work-grant-repository-absent' });
  else {
    if (scope.predecessorCommit !== predecessorCommit) failures.push({ code: 'implementation-work-grant-predecessor-commit' });
    if (scope.predecessorTree !== predecessorTree) failures.push({ code: 'implementation-work-grant-predecessor-tree' });
  }
  const now = Date.parse(observedAt);
  if (!Number.isFinite(now) || Date.parse(canonical.issuedAt) > now || Date.parse(canonical.expiresAt) <= now) {
    failures.push({ code: 'implementation-work-grant-not-current' });
  }
  if (!Array.isArray(operations) || operations.length < 1 || operations.length > MAX_OPERATIONS) {
    failures.push({ code: 'implementation-work-grant-operation-bound' });
  } else if (scope) {
    for (const [index, operation] of operations.entries()) {
      if (operation?.action !== 'write-file' || !SHA256.test(operation?.sourceDigest || '')
          || !scope.sourcePaths.includes(operation?.path)) {
        failures.push({ code: 'implementation-work-grant-operation-outside-scope', index });
        continue;
      }
      try {
        if (!repositoryRoot) throw new Error('repository root is absent');
        const root = realpathSync(repositoryRoot);
        const target = resolve(root, operation.path);
        if (!containedBy(root, target) || !existsSync(target)) throw new Error('target does not exist');
        assertNoSymlinkSegments(root, target, 'implementation work grant target');
        const metadata = lstatSync(target);
        if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(target) !== target) {
          throw new Error('target is not one canonical existing regular file');
        }
        if (sourceDigest(target) !== operation.sourceDigest) throw new Error('source preimage differs');
      } catch (error) {
        failures.push({ code: 'implementation-work-grant-existing-source-precondition', index, detail: error.message });
      }
    }
  }
  return Object.freeze({
    actionState: failures.length === 0 ? ACTION_STATES.proceed : ACTION_STATES.block,
    authorisedPaths: failures.length === 0 ? scope.sourcePaths : Object.freeze([]),
    failures: Object.freeze(failures),
    grant: failures.length === 0 ? canonical : null,
  });
}

function evaluateAuthorityConflictResolution({
  authorityDigest,
  targetContract,
  baseActionState,
  baseActionStateReasons,
  baseValidationGaps,
  applicableContracts,
  authoritySurfaces = [],
  binding,
  resolutions,
}) {
  const failures = [];
  const accepted = (resolutions || []).filter((item) => item.resolutionState === AUTHORITY_CONFLICT_RESOLUTION_ACCEPTED);
  if (baseActionState !== ACTION_STATES.block
      || !Array.isArray(baseActionStateReasons)
      || baseActionStateReasons.length === 0) {
    failures.push({ code: 'authority-conflict-no-longer-exists' });
  }
  if (!baseActionStateReasons.every((code) => code === 'missing-current-passing-validation')) {
    failures.push({ code: 'authority-conflict-unresolved-base-reason' });
  }
  if (accepted.length !== 1) failures.push({ code: accepted.length === 0 ? 'authority-conflict-resolution-absent' : 'authority-conflict-resolution-ambiguous' });
  const resolution = accepted.length === 1 ? accepted[0] : null;
  if (!resolution) return Object.freeze({ actionState: ACTION_STATES.block, failures: Object.freeze(failures), resolution: null });

  const expectedContracts = [...new Set([targetContract, ...(applicableContracts || [])])].sort();
  const expectedObligations = [...new Set((baseValidationGaps || [])
    .filter((gap) => gap.code === 'missing-current-passing-validation')
    .map((gap) => gap.subject))].sort();
  const exact = (observed, expected, code) => { if (observed !== expected) failures.push({ code }); };
  const exactSet = (observed, expected, code) => { if (!sameSet(observed, expected)) failures.push({ code }); };
  // The decision and its independent review are authored against the exact
  // conflict generation. Their governed D0→D1→D2 admission necessarily moves
  // the live authority before the decision can be consumed. Keep that semantic
  // subject distinct from the current consumption boundary: the enclosing
  // materialisation plan is still bound to the latter and apply rechecks it
  // immediately before and after the filesystem transaction.
  exact(binding.consumptionAuthorityDigest, authorityDigest, 'authority-conflict-resolution-consumption-authority');
  exact(resolution.authorityDigest, binding.conflictAuthorityDigest, 'authority-conflict-resolution-authority');
  exact(resolution.candidateDigest, binding.candidateDigest, 'authority-conflict-resolution-candidate');
  exact(resolution.operationDigest, binding.operationDigest, 'authority-conflict-resolution-operation');
  exact(resolution.repository, binding.repository, 'authority-conflict-resolution-repository');
  exact(resolution.predecessorSourceHead, binding.predecessorSourceHead, 'authority-conflict-resolution-predecessor-head');
  exact(resolution.predecessorSourceTree, binding.predecessorSourceTree, 'authority-conflict-resolution-predecessor-tree');
  exact(resolution.successorSourceTree, binding.successorSourceTree, 'authority-conflict-resolution-successor-tree');
  exact(resolution.sourceScopeDigest, binding.sourceScopeDigest, 'authority-conflict-resolution-source-scope');
  exactSet(resolution.sourcePaths, binding.sourcePaths, 'authority-conflict-resolution-source-paths');
  exactSet(resolution.contracts, expectedContracts, 'authority-conflict-resolution-conflicting-authorities');
  exactSet(resolution.requestedActions, binding.requestedActions, 'authority-conflict-resolution-actions');
  exactSet(resolution.requestedPaths, binding.requestedPaths, 'authority-conflict-resolution-paths');
  exactSet(resolution.requestedFormats, binding.requestedFormats, 'authority-conflict-resolution-formats');
  exactSet(resolution.requestedEffects, binding.requestedEffects, 'authority-conflict-resolution-effects');
  exactSet(resolution.validationObligations, expectedObligations, 'authority-conflict-resolution-validation-obligations');
  exactSet(binding.validationObligations, expectedObligations, 'authority-conflict-binding-validation-obligations');
  exact(resolution.decisionState, SEMANTIC_CORRECTION_ACCEPTED, 'authority-conflict-resolution-decision');
  exact(resolution.reviewState, SEMANTIC_ADEQUACY_REVIEW_ACCEPTED, 'authority-conflict-resolution-review');
  exact(resolution.reviewAuthorityDigest, binding.conflictAuthorityDigest, 'authority-conflict-resolution-review-authority');
  exact(resolution.reviewInventoryDigest, binding.candidateDigest, 'authority-conflict-resolution-review-subject');
  exact(resolution.proofState, SUCCESSFUL, 'authority-conflict-resolution-proof');
  exact(resolution.proofSubject, resolution.conflict, 'authority-conflict-resolution-proof-subject');
  exact(resolution.ownerState, OWNER_ASSIGNMENT_ACTIVE, 'authority-conflict-resolution-owner-state');
  exact(resolution.ownerAuthorityDomain, binding.ownerAuthorityDomain, 'authority-conflict-resolution-owner');
  exact(resolution.ownerRepository, binding.repository, 'authority-conflict-resolution-owner-repository');
  exact(resolution.ownerEnvelopeState, OWNER_ENVELOPE_VERIFIED, 'authority-conflict-resolution-owner-signature');
  for (const surface of authoritySurfaces) {
    if (!binding.requestedPaths.every((path) => decisionAuthorisesPath(path, surface.authorisedPaths || []))
        || !binding.requestedFormats.every((format) => (surface.authorisedFormats || []).includes(format))) {
      failures.push({ code: 'authority-conflict-positive-surface-incomplete', contract: surface.contract });
    }
  }
  if (resolution.ownerSourcePaths && ![
    'semantic-model/assurance/evidence.trig',
    'semantic-model/assurance/proofs.trig',
    'semantic-model/realisation/bindings.trig',
  ].every((path) => resolution.ownerSourcePaths.includes(path))) {
    failures.push({ code: 'authority-conflict-resolution-owner-source-scope' });
  }
  return Object.freeze({
    actionState: failures.length === 0 ? ACTION_STATES.proceed : ACTION_STATES.block,
    failures: Object.freeze(failures),
    resolution: failures.length === 0 ? Object.freeze({ ...resolution }) : null,
  });
}

async function gitOutput(repositoryRoot, args, options = {}) {
  try {
    // The semantic-assurance profile deliberately denies child processes. Load
    // the Git execution capability only at the coordinator mutation boundary so
    // read-only projection/validation remains executable in that profile. The
    // complete coordinator path is exercised by the child-permitted full gate.
    const { execFileSync } = await import('node:child_process');
    return execFileSync('git', ['-C', repositoryRoot, ...args], {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      ...options,
    }).trim();
  } catch (error) {
    const diagnostic = error?.stderr?.toString?.().trim();
    throw new Error(`authority-conflict Git identity check failed${diagnostic ? `: ${diagnostic}` : ''}`, { cause: error });
  }
}

async function assertAuthorityConflictPredecessor(repositoryRoot, binding) {
  const head = await gitOutput(repositoryRoot, ['rev-parse', '--verify', 'HEAD']);
  const tree = await gitOutput(repositoryRoot, ['rev-parse', '--verify', 'HEAD^{tree}']);
  if (head !== binding.predecessorSourceHead) {
    throw new Error(`authority-conflict predecessor head mismatch: expected ${binding.predecessorSourceHead}, observed ${head}`);
  }
  if (tree !== binding.predecessorSourceTree) {
    throw new Error(`authority-conflict predecessor tree mismatch: expected ${binding.predecessorSourceTree}, observed ${tree}`);
  }
  if (await gitOutput(repositoryRoot, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
    throw new Error('authority-conflict predecessor worktree is not exact and clean');
  }
}

async function stagedWorktreeTree(repositoryRoot) {
  const temporary = mkdtempSync(join(tmpdir(), 'usf-authority-conflict-index-'));
  const indexPath = join(temporary, 'index');
  const env = { ...process.env, GIT_INDEX_FILE: indexPath };
  try {
    await gitOutput(repositoryRoot, ['read-tree', 'HEAD'], { env });
    await gitOutput(repositoryRoot, ['add', '-A', '--', '.'], { env });
    return await gitOutput(repositoryRoot, ['write-tree'], { env });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function bounded(valueToMeasure, maximum, label) {
  const bytes = Buffer.byteLength(jcs(valueToMeasure));
  if (bytes > maximum) throw new Error(`${label} exceeds ${maximum} bytes`);
  return bytes;
}

async function hashFile(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return `sha256:${hash.digest('hex')}`;
}

async function resolveContract(client, reference = CONTRACT) {
  if (!validContractRef(reference)) throw new Error('invalid contract reference');
  if (reference.startsWith('urn:')) return reference;
  const rows = await client.select(`SELECT ?contract WHERE { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:canonicalName> "${reference}" } LIMIT 2`);
  if (rows.length !== 1) throw new Error('contract reference must resolve exactly once');
  return value(rows[0], 'contract');
}

// The semantic half of the layout read. It performs NO witness read, so a caller
// can bracket it — alone, or together with the validation scope — under one
// stable authority read.
async function readLayoutSemantics(ctx, args = {}) {
  const contract = await resolveContract(ctx.client, args.contract || CONTRACT);
  const [contractRows, roleRows, ruleRows, ruleCountRows] = await Promise.all([
    ctx.client.select(`SELECT ?canonicalName ?lifecycle ?activation ?proof ?proofState ?effectiveDecision ?decision ?decisionState ?authorisedRepository ?authorisedPath WHERE {
      <${contract}> <urn:usf:ontology:canonicalName> ?canonicalName .
      OPTIONAL { <${contract}> <urn:usf:ontology:semanticLifecycleState> ?lifecycle }
      OPTIONAL { <${contract}> <urn:usf:ontology:hasActivationState> ?activation }
      OPTIONAL {
        <${contract}> <urn:usf:ontology:reliesOnProofResult> ?proof .
        OPTIONAL { ?proof <urn:usf:ontology:hasProofResultState> ?proofState }
      }
      OPTIONAL { <${contract}> <urn:usf:ontology:effectiveRealisationDecision> ?effectiveDecision }
      OPTIONAL {
        ?realisation <urn:usf:ontology:realisesContract> <${contract}> ; <urn:usf:ontology:authorisedByDecision> ?decision .
        ?decision <urn:usf:ontology:decisionForContract> <${contract}> ; <urn:usf:ontology:decisionState> ?decisionState .
        OPTIONAL { ?decision <urn:usf:ontology:authorisesRepository> ?authorisedRepository }
        OPTIONAL { ?decision <urn:usf:ontology:authorisesSourcePath> ?authorisedPath }
      }
    } ORDER BY ?decision ?authorisedRepository ?authorisedPath LIMIT 512`),
    ctx.client.select('SELECT ?role ?canonicalName ?parent ?onDemand WHERE { ?role a <urn:usf:ontology:PathRole> ; <urn:usf:ontology:canonicalName> ?canonicalName ; <urn:usf:ontology:authorisedParentPath> ?parent ; <urn:usf:ontology:materialisesOnDemand> ?onDemand . FILTER NOT EXISTS { ?role <urn:usf:ontology:semanticAdequacyDisposition> ?disposition . FILTER(?disposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) } } ORDER BY ?canonicalName LIMIT 256'),
    ctx.client.select(`SELECT ?family ?familyName ?storage ?pathRole ?format ?namingPattern WHERE { ${MATERIALISATION_RULE_WHERE} } ORDER BY ?familyName ?format LIMIT 512`),
    ctx.client.select(`SELECT (COUNT(*) AS ?count) WHERE { ${MATERIALISATION_RULE_WHERE} }`),
  ]);
  if (contractRows.length === 0) throw new Error('contract does not exist in live authority');
  // Every scalar conclusion must resolve exactly once. The rows are a cross
  // product of OPTIONAL patterns, so repetition is expected but disagreement is
  // not: taking the first row would let a contradictory second row hide behind a
  // favourable one.
  const sole = (key, label) => {
    const distinct = [...new Set(contractRows.map((row) => value(row, key)).filter((item) => item !== null))];
    if (distinct.length > 1) throw new Error(`contract has ambiguous ${label} in live authority: ${distinct.join(', ')}`);
    return distinct[0] ?? null;
  };
  const canonicalName = sole('canonicalName', 'canonical name');
  const lifecycleState = sole('lifecycle', 'semantic lifecycle state');
  const activationState = sole('activation', 'activation state');
  const proofResults = [...new Set(contractRows.map((row) => value(row, 'proof')).filter(Boolean))].sort();
  const proofResultStates = proofResults.map((proofResult) => {
    const states = [...new Set(contractRows
      .filter((row) => value(row, 'proof') === proofResult)
      .map((row) => value(row, 'proofState'))
      .filter(Boolean))];
    if (states.length > 1) {
      throw new Error(`proof result ${proofResult} has ambiguous state in live authority: ${states.sort().join(', ')}`);
    }
    return { proofResult, state: states[0] ?? null };
  });
  const aggregateProofStates = [...new Set(proofResultStates.map((item) => item.state).filter(Boolean))];
  const proofResultState = proofResultStates.length > 0
    && proofResultStates.every((item) => item.state !== null)
    && aggregateProofStates.length === 1
    ? aggregateProofStates[0]
    : null;
  if (canonicalName === null) throw new Error('contract has no canonical name in live authority');
  const expectedRuleCount = Number(value(ruleCountRows[0], 'count'));
  if (ruleCountRows.length !== 1 || !Number.isSafeInteger(expectedRuleCount) || expectedRuleCount !== ruleRows.length) {
    throw new Error('materialisation rule projection is incomplete');
  }
  const decisions = new Map();
  const effectiveDecisionIds = new Set();
  for (const row of contractRows) {
    const effectiveDecision = value(row, 'effectiveDecision');
    if (effectiveDecision) effectiveDecisionIds.add(effectiveDecision);
    const id = value(row, 'decision');
    if (!id) continue;
    const state = value(row, 'decisionState');
    const existing = decisions.get(id) || {
      id,
      state,
      authorisedRepositories: new Set(),
      authorisedPaths: new Set(),
    };
    if (existing.state !== state) throw new Error('realisation decision has inconsistent state');
    const repository = value(row, 'authorisedRepository');
    if (repository) existing.authorisedRepositories.add(repository);
    const path = value(row, 'authorisedPath');
    if (path) existing.authorisedPaths.add(path);
    decisions.set(id, existing);
  }
  const acceptedDecisions = [...decisions.values()].filter((decision) => decision.state === ACCEPTED);
  let decisionResolution = 'unresolved';
  let candidateDecision = null;
  if (effectiveDecisionIds.size === 1) {
    candidateDecision = decisions.get([...effectiveDecisionIds][0]) ?? null;
    decisionResolution = candidateDecision?.state === ACCEPTED ? 'explicit' : 'invalid-effective-decision';
  } else if (effectiveDecisionIds.size > 1) {
    decisionResolution = 'multiple-effective-decisions';
  } else if (acceptedDecisions.length === 1) {
    [candidateDecision] = acceptedDecisions;
    decisionResolution = 'unique-accepted';
  } else if (acceptedDecisions.length > 1) {
    decisionResolution = 'missing-effective-decision';
  } else {
    decisionResolution = 'no-accepted-decision';
  }
  if (candidateDecision?.authorisedRepositories.size !== 1) {
    candidateDecision = null;
    if (decisionResolution === 'explicit' || decisionResolution === 'unique-accepted') {
      decisionResolution = 'invalid-authorised-repository';
    }
  }
  const acceptedDecision = candidateDecision?.state === ACCEPTED ? candidateDecision : null;
  const repositories = acceptedDecision ? [...acceptedDecision.authorisedRepositories].sort() : [];
  const paths = acceptedDecision ? [...acceptedDecision.authorisedPaths].sort() : [];
  // Formats are authority granted by the selected decision, not an inference
  // from the global family/materialisation-rule catalogue. Resolve the
  // decision first, then count and read its exact set in separate bounded
  // queries. Keeping this out of the contract/path query also avoids a
  // path-by-format cross product that could mask truncation.
  let authorisedFormats = [];
  if (acceptedDecision) {
    const [formatCountRows, formatRows] = await Promise.all([
      ctx.client.select(`SELECT (COUNT(DISTINCT ?format) AS ?count) WHERE { <${acceptedDecision.id}> <${DECISION_FORMAT_PREDICATE}> ?format . }`),
      ctx.client.select(`SELECT DISTINCT ?format WHERE { <${acceptedDecision.id}> <${DECISION_FORMAT_PREDICATE}> ?format . } ORDER BY ?format LIMIT ${MAX_PACKET_ITEMS}`),
    ]);
    const formatCount = formatCountRows.length === 1 ? value(formatCountRows[0], 'count') : null;
    const expectedFormatCount = formatCount === null ? Number.NaN : Number(formatCount);
    const formats = formatRows.map((row) => value(row, 'format'));
    if (formatCountRows.length !== 1 || !Number.isSafeInteger(expectedFormatCount) || expectedFormatCount < 0) {
      throw new Error('decision representation-format count is invalid');
    }
    if (expectedFormatCount > MAX_PACKET_ITEMS) {
      throw new Error(`decision representation-format projection exceeds ${MAX_PACKET_ITEMS} items`);
    }
    if (
      formatRows.length !== expectedFormatCount
      || formats.some((item) => item === null)
      || new Set(formats).size !== expectedFormatCount
    ) {
      throw new Error('decision representation-format projection is incomplete');
    }
    if (paths.length > 0 && expectedFormatCount === 0) {
      throw new Error('decision authorises source paths but no representation formats');
    }
    authorisedFormats = formats.sort();
  }
  return {
    schemaVersion: 1,
    contract: {
      id: contract,
      canonicalName,
      lifecycleState,
      activationState,
      proofResult: proofResults.length === 1 ? proofResults[0] : null,
      proofResults,
      proofResultStates,
      proofResultState,
      decision: acceptedDecision?.id ?? null,
      decisionState: acceptedDecision?.state ?? null,
      authorisedRepository: repositories[0] ?? null,
    },
    realisationDecisionCount: decisions.size,
    acceptedDecisionCount: acceptedDecisions.length,
    effectiveDecisionCount: effectiveDecisionIds.size,
    decisionResolution,
    authorisedRepositories: repositories,
    authorisedPaths: paths,
    authorisedFormats,
    pathRoles: roleRows.map((row) => ({ id: value(row, 'role'), canonicalName: value(row, 'canonicalName'), parent: value(row, 'parent'), onDemand: value(row, 'onDemand') === 'true' })),
    materialisationRuleCount: expectedRuleCount,
    rules: ruleRows.map((row) => ({ family: value(row, 'family'), familyName: value(row, 'familyName'), storageClass: value(row, 'storage'), pathRole: value(row, 'pathRole'), representationFormat: value(row, 'format'), namingPattern: value(row, 'namingPattern') })),
  };
}

// Public layout context: the semantic read bracketed by two witnesses.
export async function layoutContext(ctx, args = {}) {
  const { witness, value } = await stableAuthorityRead(
    ctx.client,
    'layout context read',
    () => readLayoutSemantics(ctx, args),
  );
  return withAuthority(value, witness, ctx);
}

// Attach the bracketing witness to a semantic read and enforce any configured
// expected digest at the same boundary.
function withAuthority(semantics, witness, ctx) {
  if (ctx.client?.expectedAuthorityDigest && ctx.client.expectedAuthorityDigest !== witness.digest) {
    throw new Error('observed semantic authority digest differs from configured digest');
  }
  return {
    ...semantics,
    authorityDigest: witness.digest,
    authorityGraphCount: witness.graphCount,
    authorityTripleTotal: witness.triples,
    authorityGraphInventory: witness.inventory,
    authorityDigestAlgorithm: 'sha256-rdfc10-graph-inventory-v2',
    authorityWitness: witness,
  };
}

// The verdict is accepted from a caller that already read it, so plan creation,
// validation and apply all judge the same authority read. Absent one, it is read
// here rather than assumed.
export async function validateLayoutPlan(ctx, plan, verdict = null) {
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  const resolved = verdict || await realisationVerdict(ctx, {
    contract: plan?.contract,
    authorityConflictBinding: plan?.authorityConflictBinding,
    implementationWorkGrantBinding: plan?.implementationWorkGrantBinding,
    operations: plan?.operations,
  });
  const { context } = resolved;
  const failures = [];
  if (plan?.authorityConflictBinding && plan?.implementationWorkGrantBinding) {
    failures.push({ code: 'plan-authority-surface-ambiguous' });
  }
  const expectedKeys = plan?.authorityConflictBinding
    ? ['authorityConflictBinding', 'authorityDigest', 'contract', 'operations', 'planDigest', 'schemaVersion']
    : plan?.implementationWorkGrantBinding
      ? ['authorityDigest', 'contract', 'implementationWorkGrantBinding', 'operations', 'planDigest', 'schemaVersion']
      : ['authorityDigest', 'contract', 'operations', 'planDigest', 'schemaVersion'];
  if (!plan || jcs(Object.keys(plan).sort()) !== jcs(expectedKeys.sort())) failures.push({ code: 'plan-field-closure' });
  if (plan?.schemaVersion !== 1) failures.push({ code: 'plan-schema-version' });
  if (plan?.authorityDigest !== context.authorityDigest) failures.push({ code: 'plan-authority-digest' });
  // One stable code per non-PROCEED realisation state, carrying the verdict's own
  // reasons. Calling this tool directly can no longer bypass the projection.
  if (resolved.actionState !== ACTION_STATES.proceed) {
    failures.push({ code: resolved.stateFailureCode, actionState: resolved.actionState, reasons: resolved.actionStateReasons });
  }
  // Retained specific codes for the conjuncts a reviewer reads directly.
  if (context.contract.lifecycleState !== ACTIVE_LIFECYCLE) failures.push({ code: 'plan-contract-lifecycle-not-active' });
  if (context.contract.activationState !== ACTIVE || context.contract.proofResultState !== SUCCESSFUL) failures.push({ code: 'plan-contract-not-active-proven' });
  if (!context.contract.decision || context.contract.decisionState !== ACCEPTED) {
    failures.push({ code: 'plan-decision-not-uniquely-accepted' });
  }
  if (!Array.isArray(plan?.operations) || plan.operations.length < 1 || plan.operations.length > MAX_OPERATIONS) failures.push({ code: 'plan-operation-bound' });
  else plan.operations.forEach((operation, index) => failures.push(...validatePlanOperation(operation, index, context)));
  const unsigned = { ...plan };
  delete unsigned.planDigest;
  const expectedDigest = digest(jcs(unsigned));
  if (plan?.planDigest !== expectedDigest) failures.push({ code: 'plan-digest' });
  return {
    ok: failures.length === 0,
    authorityDigest: context.authorityDigest,
    realisationActionState: resolved.actionState,
    realisationActionStateReasons: resolved.actionStateReasons,
    validationSatisfied: resolved.validation.validationSatisfied,
    expectedPlanDigest: expectedDigest,
    operationCount: plan?.operations?.length ?? 0,
    failures,
  };
}

export async function createLayoutPlan(ctx, args = {}) {
  if (!Array.isArray(args.operations)) throw new Error('operations must be an array');
  const verdict = await realisationVerdict(ctx, {
    contract: args.contract || CONTRACT,
    authorityConflictBinding: args.authorityConflictBinding,
    implementationWorkGrantIri: args.implementationWorkGrantIri,
    repository: args.repository,
    operations: args.operations,
  });
  // Refuse before a plan exists. A plan is an authorisation artefact, so it must
  // not be constructible from a contract that does not authorise realisation.
  if (verdict.actionState !== ACTION_STATES.proceed) {
    throw new Error(`${verdict.stateFailureCode}: realisation action state is ${verdict.actionState} (${verdict.actionStateReasons.join(',') || 'no reasons'})`);
  }
  const { context } = verdict;
  const plan = {
    schemaVersion: 1,
    authorityDigest: context.authorityDigest,
    contract: context.contract.id,
    operations: args.operations,
    ...(verdict.authorityConflictBinding
      ? { authorityConflictBinding: stable(args.authorityConflictBinding) }
      : {}),
    ...(verdict.implementationWorkGrantBinding
      ? { implementationWorkGrantBinding: stable(verdict.implementationWorkGrantBinding) }
      : {}),
  };
  plan.planDigest = digest(jcs(plan));
  const result = await validateLayoutPlan(ctx, plan, verdict);
  if (!result.ok) throw new Error(`invalid materialisation plan: ${result.failures.map((item) => `${item.index ?? '-'}:${item.code}`).join(',')}`);
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  return plan;
}

export async function applyLayoutPlan(ctx, args = {}) {
  const plan = args.plan;
  // Apply judges the same verdict as creation and validation, so a plan minted
  // under PROCEED cannot be applied after the state has moved.
  const verdict = await realisationVerdict(ctx, {
    contract: plan?.contract,
    authorityConflictBinding: plan?.authorityConflictBinding,
    implementationWorkGrantBinding: plan?.implementationWorkGrantBinding,
    operations: plan?.operations,
  });
  const validation = await validateLayoutPlan(ctx, plan, verdict);
  if (!validation.ok) {
    return { applied: false, realisationActionState: verdict.actionState, stateFailureCode: verdict.stateFailureCode, validation };
  }
  if (args.apply !== true) return { applied: false, dryRun: true, validation };
  if (ctx.coordinator !== true || !ctx.repositoryRoot) throw new Error('materialisation apply is coordinator-only');
  // Immediately before the first filesystem mutation, prove authority has not
  // moved since the verdict was taken and that the plan still describes it. A
  // verdict is a statement about one authority state; touching the filesystem on
  // the strength of a stale one is the whole hazard.
  const preApply = witnessSummary(await authorityWitness(ctx.client));
  assertWitnessUnchanged(verdict.witness, preApply, 'pre-apply authority check');
  if (plan.authorityDigest !== preApply.digest) {
    throw new Error(`${AUTHORITY_MOVED_CODE}: plan authority ${plan.authorityDigest} does not match live authority ${preApply.digest} at apply time`);
  }
  if (plan.authorityConflictBinding) {
    await assertAuthorityConflictPredecessor(ctx.repositoryRoot, verdict.authorityConflictBinding);
  }
  // The filesystem apply, CAS resolution, idempotence and rollback are the pure
  // module's, not a second copy: this call returns the still-open rollback stack
  // so the post-apply authority check below can undo the complete run through
  // that same implementation.
  const execution = executePlanOperations({
    plan,
    repositoryRoot: ctx.repositoryRoot,
    casRoot: ctx.casRoot,
  });
  if (plan.authorityConflictBinding) {
    try {
      if (execution.operations.some((operation) => operation.state === 'already-applied')) {
        throw new Error('authority-conflict resolution is single-use and has already been applied');
      }
      const observedTree = await stagedWorktreeTree(ctx.repositoryRoot);
      if (observedTree !== verdict.authorityConflictBinding.successorSourceTree) {
        throw new Error(
          `authority-conflict successor tree mismatch: expected ${verdict.authorityConflictBinding.successorSourceTree}, observed ${observedTree}`,
        );
      }
    } catch (error) {
      execution.rollbackAndThrow(error);
    }
  }
  if (plan.implementationWorkGrantBinding) {
    try {
      if (execution.operations.some((operation) => operation.state === 'already-applied')) {
        throw new Error('implementation work grant is single-use and its source preimage has already been consumed');
      }
    } catch (error) {
      execution.rollbackAndThrow(error);
    }
  }
  // After every operation but before reporting success: if authority moved while
  // the filesystem was being changed, the plan was authorised against a state that
  // no longer exists. Run the complete rollback stack and fail closed; rollback
  // errors are preserved through AggregateError by the pure module.
  try {
    assertWitnessUnchanged(
      verdict.witness,
      witnessSummary(await authorityWitness(ctx.client)),
      'post-apply authority check',
    );
  } catch (error) {
    execution.rollbackAndThrow(error);
  }
  return { applied: true, validation, operations: execution.operations };
}

export async function describeArtifact(ctx, args = {}) {
  if (!SHA256.test(args.digest || '')) throw new Error('digest must be sha256:<64 lowercase hex>');
  const rows = await ctx.client.select(`SELECT ?id ?family ?format ?mediaType ?byteSize ?locator ?artifactType ?storageClass WHERE {
    ?id a <urn:usf:ontology:ExternalPayloadDescriptor> ; <urn:usf:ontology:descriptorDigest> "${args.digest}" ; <urn:usf:ontology:descriptorArtefactFamily> ?family ; <urn:usf:ontology:descriptorRepresentationFormat> ?format ; <urn:usf:ontology:descriptorMediaType> ?mediaType ; <urn:usf:ontology:descriptorByteSize> ?byteSize ; <urn:usf:ontology:descriptorLocator> ?locator ; <urn:usf:ontology:descriptorArtefactType> ?artifactType ; <urn:usf:ontology:descriptorStorageClass> ?storageClass .
  } LIMIT 2`);
  if (rows.length !== 1) throw new Error('external payload descriptor must resolve exactly once');
  const row = rows[0];
  return { id: value(row, 'id'), digest: args.digest, artefactFamily: value(row, 'family'), representationFormat: value(row, 'format'), mediaType: value(row, 'mediaType'), byteSize: Number(value(row, 'byteSize')), locator: value(row, 'locator'), artifactType: value(row, 'artifactType'), storageClass: value(row, 'storageClass') };
}

export async function verifyArtifact(ctx, args = {}) {
  const descriptor = await describeArtifact(ctx, args);
  if (!ctx.casRoot) throw new Error('operator-local CAS root is not configured');
  // CAS locator layout and its containment, symlink and regular-file checks are
  // the pure module's single implementation, not a second copy here.
  const located = resolveCasObject(ctx.casRoot, descriptor.digest, { label: 'artifact' });
  if (!located.found) {
    if (located.code === 'cas-path-escaped-root') throw new Error('CAS path escaped configured root');
    return { verified: false, descriptor, code: located.code === 'cas-object-not-found' ? 'artifact-not-found' : 'artifact-not-regular-file' };
  }
  const observedDigest = await hashFile(located.path);
  const verified = located.byteSize === descriptor.byteSize && observedDigest === descriptor.digest;
  return { verified, descriptor, observed: { byteSize: located.byteSize, digest: observedDigest } };
}

// Applicability and obligation state for one contract. Every field is either an
// explicit IRI from live authority or null, and null is never read as a
// permission: callers map null onto UNRESOLVED_FAIL_CLOSED.
async function validationScope(client, contract) {
  const [applicabilityRows, obligationRows, evidenceRows, pathRows] = await Promise.all([
    client.select(`SELECT ?state ?reason ?authority ?authorityState ?condition WHERE {
      OPTIONAL { <${contract}> <urn:usf:ontology:hasValidationApplicability> ?state }
      OPTIONAL { <${contract}> <urn:usf:ontology:validationApplicabilityReason> ?reason }
      OPTIONAL { <${contract}> <urn:usf:ontology:validationApplicabilityAuthority> ?authority .
        OPTIONAL { ?authority <urn:usf:ontology:hasProofResultState> ?authorityState } }
      OPTIONAL { <${contract}> <urn:usf:ontology:validationApplicabilityCondition> ?condition }
    } LIMIT 64`),
    client.select(`SELECT ?id ?activation ?definition ?activationReason ?target ?defectEvidence ?ownerPath ?conditionMatched
      ?satisfaction ?boundObligation ?resultState ?boundAuthority ?boundHead ?invalidation ?superseded
      ?binding ?bindingResult ?bindingRule ?reevaluationRequired ?reevaluationState ?stageOneEvaluated ?stageOneSettled
      ?nonPublicationDependency ?dependencyAlgorithm ?reevaluationDependency
      ?bindingExecutionReceipt ?bindingEvaluationReceipt ?bindingProducer ?bindingAdmissionPath
      ?bindingProducerRelease ?bindingRepository ?bindingSourceHead ?bindingSourceTree ?bindingSourceScope
      ?bindingProducerRepository ?bindingProducerSourceHead ?bindingProducerSourceTree ?bindingProducerSourceScope
      ?bindingAdmissionRepository ?bindingAdmissionSourceHead ?bindingAdmissionSourceTree ?bindingAdmissionSourceScope
      ?bindingReevaluation ?reevaluatesValidationResult ?reevaluationAuthority ?reevaluationResultState
      ?reevaluationExecutionReceipt ?reevaluationEvaluationReceipt
      ?evaluation ?evaluationReceipt ?execution ?executionReceipt ?executionProducer ?executionAdmissionPath
      ?producerRelease ?producerRepository ?producerSourceHead ?producerSourceTree ?producerSourceScope
      ?admissionProducer ?admissionRepository ?admissionSourceHead ?admissionSourceTree ?admissionSourceScope WHERE {
      ?id a <urn:usf:ontology:ValidationObligation> ; <urn:usf:ontology:validationForContract> <${contract}> .
      OPTIONAL { ?id <urn:usf:ontology:hasValidationActivationState> ?activation }
      OPTIONAL { ?id <urn:usf:ontology:definition> ?definition }
      OPTIONAL { ?id <urn:usf:ontology:validationActivationReason> ?activationReason }
      OPTIONAL { ?id <urn:usf:ontology:obligationFor> ?target }
      OPTIONAL { ?id <urn:usf:ontology:derivedFrom> ?defectEvidence }
      OPTIONAL {
        ?id <urn:usf:ontology:derivedFrom> ?ownerArtefact .
        ?ownerArtefact a <urn:usf:ontology:Artefact> ; <urn:usf:ontology:canonicalPath> ?ownerPath .
      }
      OPTIONAL {
        {
          BIND(<urn:usf:validationobligation:operationexpectedoutcomeerrorclass> AS ?id)
          <urn:usf:permutationfamily:operationexpectedoutcomeerrorclass>
            <urn:usf:ontology:hasFamilyDimensionBinding> ?errorBinding .
          ?errorBinding <urn:usf:ontology:bindsDimension> <urn:usf:permutationdimension:closureerrorclass> .
          <urn:usf:permutationdimension:closureerrorclass>
            <urn:usf:ontology:dimensionValueSource> <urn:usf:dimensionvaluesource:errorclass> .
          <urn:usf:dimensionvaluesource:errorclass>
            <urn:usf:ontology:valueSourceClassIri> "urn:usf:ontology:ValidationFailureCode"^^<http://www.w3.org/2001/XMLSchema#anyURI> .
          FILTER NOT EXISTS { <urn:usf:ontology:ErrorClass> ?errorClassPredicate ?errorClassValue }
          BIND("true" AS ?conditionMatched)
        }
        UNION
        {
          BIND(<urn:usf:validationobligation:resourceactionretentionstatelegalholdstate> AS ?id)
          <urn:usf:permutationfamily:resourceactionretentionstatelegalholdstate>
            <urn:usf:ontology:familyApplicabilityRule> <urn:usf:permutationapplicabilityrule:datamodels> ;
            <urn:usf:ontology:hasFamilyDimensionBinding> ?resourceBinding .
          ?resourceBinding <urn:usf:ontology:bindsDimension> <urn:usf:permutationdimension:closureresource> .
          <urn:usf:permutationdimension:closureresource>
            <urn:usf:ontology:dimensionValueSource> <urn:usf:dimensionvaluesource:resource> .
          <urn:usf:dimensionvaluesource:resource>
            <urn:usf:ontology:valueSourceDerivationRoot> <urn:usf:permutationvaluederivation:resource> ;
            <urn:usf:ontology:valueSourceTerminalClass> <http://www.w3.org/2002/07/owl#Class> .
          BIND("true" AS ?conditionMatched)
        }
        UNION
        {
          BIND(<urn:usf:validationobligation:scheduledjobactionroleserviceidentityenvironmentclass> AS ?id)
          <urn:usf:permutationfamily:scheduledjobactionroleserviceidentityenvironmentclass>
            <urn:usf:ontology:familyApplicabilityRule> <urn:usf:permutationapplicabilityrule:workflows> ;
            <urn:usf:ontology:hasFamilyDimensionBinding> ?scheduledBinding .
          ?scheduledBinding <urn:usf:ontology:bindsDimension> <urn:usf:permutationdimension:closurescheduledjob> .
          <urn:usf:permutationdimension:closurescheduledjob>
            <urn:usf:ontology:dimensionValueSource> <urn:usf:dimensionvaluesource:scheduledjob> .
          <urn:usf:dimensionvaluesource:scheduledjob>
            <urn:usf:ontology:valueSourceDerivationRoot> <urn:usf:permutationvaluederivation:scheduledjob> .
          <urn:usf:permutationvaluederivation:scheduledjob>
            <urn:usf:ontology:valueDerivationOperator> <urn:usf:permutationvaluederivationoperator:filterpathexists> .
          BIND("true" AS ?conditionMatched)
        }
      }
      OPTIONAL { ?id <urn:usf:ontology:satisfiedByValidationResult> ?satisfaction .
        OPTIONAL { ?satisfaction <urn:usf:ontology:resultForValidationObligation> ?boundObligation }
        OPTIONAL { ?satisfaction <urn:usf:ontology:resultState> ?resultState }
        OPTIONAL { ?satisfaction <urn:usf:ontology:validationEvaluatedAuthorityDigest> ?boundAuthority }
        OPTIONAL { ?satisfaction <urn:usf:ontology:validationEvaluatedSourceHead> ?boundHead }
        OPTIONAL { ?satisfaction <urn:usf:ontology:hasValidationInvalidationCondition> ?invalidation }
        OPTIONAL { ?satisfaction <urn:usf:ontology:supersededByValidationResult> ?superseded }
        OPTIONAL {
          ?satisfaction <urn:usf:ontology:hasValidationSelfPublicationAuthorityBinding> ?binding .
          OPTIONAL { ?binding a <urn:usf:ontology:ValidationSelfPublicationBinding> }
          OPTIONAL { ?binding <urn:usf:ontology:authorityBindingForValidationResult> ?bindingResult }
          OPTIONAL { ?binding <urn:usf:ontology:validationUsesAuthorityBindingRule> ?bindingRule }
          OPTIONAL { ?binding <urn:usf:ontology:validationRequiresPostPublicationReevaluation> ?reevaluationRequired }
          OPTIONAL { ?binding <urn:usf:ontology:validationPostPublicationReevaluationState> ?reevaluationState }
          OPTIONAL { ?binding <urn:usf:ontology:validationStageOneEvaluatedAuthorityDigest> ?stageOneEvaluated }
          OPTIONAL { ?binding <urn:usf:ontology:validationStageOneSettledAuthorityDigest> ?stageOneSettled }
          OPTIONAL { ?binding <urn:usf:ontology:validationNonPublicationDependencySetDigest> ?nonPublicationDependency }
          OPTIONAL { ?binding <urn:usf:ontology:validationNonPublicationDependencyDigestAlgorithm> ?dependencyAlgorithm }
          OPTIONAL { ?binding <urn:usf:ontology:validationReevaluationDependencyDigest> ?reevaluationDependency }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingExecutionReceiptDigest> ?bindingExecutionReceipt }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingEvaluationReceiptDigest> ?bindingEvaluationReceipt }
          OPTIONAL { ?binding <urn:usf:ontology:authorityBindingValidationProducer> ?bindingProducer }
          OPTIONAL { ?binding <urn:usf:ontology:authorityBindingEvidenceAdmissionPath> ?bindingAdmissionPath }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingProducerRelease> ?bindingProducerRelease }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingRepository> ?bindingRepository }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingSourceHead> ?bindingSourceHead }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingSourceTree> ?bindingSourceTree }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingSourceScopeDigest> ?bindingSourceScope }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingProducerRepository> ?bindingProducerRepository }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingProducerSourceHead> ?bindingProducerSourceHead }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingProducerSourceTree> ?bindingProducerSourceTree }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingProducerSourceScopeDigest> ?bindingProducerSourceScope }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingAdmissionRepository> ?bindingAdmissionRepository }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingAdmissionSourceHead> ?bindingAdmissionSourceHead }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingAdmissionSourceTree> ?bindingAdmissionSourceTree }
          OPTIONAL { ?binding <urn:usf:ontology:validationBindingAdmissionSourceScopeDigest> ?bindingAdmissionSourceScope }
          OPTIONAL {
            ?binding <urn:usf:ontology:validationBindingPostPublicationReevaluation> ?bindingReevaluation .
            OPTIONAL { ?bindingReevaluation <urn:usf:ontology:reevaluatesValidationResult> ?reevaluatesValidationResult }
            OPTIONAL { ?bindingReevaluation <urn:usf:ontology:reevaluationAuthorityDigest> ?reevaluationAuthority }
            OPTIONAL { ?bindingReevaluation <urn:usf:ontology:reevaluationResultState> ?reevaluationResultState }
            OPTIONAL { ?bindingReevaluation <urn:usf:ontology:reevaluationExecutionReceiptDigest> ?reevaluationExecutionReceipt }
            OPTIONAL { ?bindingReevaluation <urn:usf:ontology:reevaluationEvaluationReceiptDigest> ?reevaluationEvaluationReceipt }
          }
        }
        OPTIONAL {
          ?satisfaction <urn:usf:ontology:validationResultOfEvaluation> ?evaluation .
          OPTIONAL { ?evaluation a <urn:usf:ontology:ValidationEvaluation> }
          OPTIONAL { ?evaluation <urn:usf:ontology:validationEvaluationReceiptDigest> ?evaluationReceipt }
          OPTIONAL {
            ?evaluation <urn:usf:ontology:validationEvaluationOfExecution> ?execution .
            OPTIONAL { ?execution a <urn:usf:ontology:ValidationExecution> }
            OPTIONAL { ?execution <urn:usf:ontology:validationExecutionReceiptDigest> ?executionReceipt }
            OPTIONAL { ?execution <urn:usf:ontology:validationExecutedByProducer> ?executionProducer }
            OPTIONAL { ?execution <urn:usf:ontology:validationUsesEvidenceAdmissionPath> ?executionAdmissionPath }
          }
        }
        OPTIONAL {
          ?bindingProducer a <urn:usf:ontology:ValidationProducer> .
          OPTIONAL { ?bindingProducer <urn:usf:ontology:validationProducerRelease> ?producerRelease }
          OPTIONAL { ?bindingProducer <urn:usf:ontology:validationProducerRepository> ?producerRepository }
          OPTIONAL { ?bindingProducer <urn:usf:ontology:validationProducerSourceHead> ?producerSourceHead }
          OPTIONAL { ?bindingProducer <urn:usf:ontology:validationProducerSourceTree> ?producerSourceTree }
          OPTIONAL { ?bindingProducer <urn:usf:ontology:validationProducerSourceScopeDigest> ?producerSourceScope }
        }
        OPTIONAL {
          ?bindingAdmissionPath a <urn:usf:ontology:EvidenceAdmissionPath> .
          OPTIONAL { ?bindingAdmissionPath <urn:usf:ontology:admissionPathForProducer> ?admissionProducer }
          OPTIONAL { ?bindingAdmissionPath <urn:usf:ontology:admissionPathRepository> ?admissionRepository }
          OPTIONAL { ?bindingAdmissionPath <urn:usf:ontology:admissionPathSourceHead> ?admissionSourceHead }
          OPTIONAL { ?bindingAdmissionPath <urn:usf:ontology:admissionPathSourceTree> ?admissionSourceTree }
          OPTIONAL { ?bindingAdmissionPath <urn:usf:ontology:admissionPathSourceScopeDigest> ?admissionSourceScope }
        }
      }
    } ORDER BY ?id ?satisfaction LIMIT 257`),
    client.select(`SELECT ?id ?satisfaction ?evidence ?evidenceType ?evidenceExecution ?evidenceAdmissionPath WHERE {
      ?id <urn:usf:ontology:validationForContract> <${contract}> ;
          <urn:usf:ontology:satisfiedByValidationResult> ?satisfaction .
      ?satisfaction <urn:usf:ontology:usesAdmittedValidationEvidence> ?evidence .
      ?satisfaction <urn:usf:ontology:validationResultOfEvaluation> ?evaluation .
      ?evaluation <urn:usf:ontology:validationEvaluationOfExecution> ?execution .
      OPTIONAL {
        ?evidence a <urn:usf:ontology:ValidationEvidence> .
        BIND("true" AS ?evidenceType)
      }
      OPTIONAL { ?evidence <urn:usf:ontology:validationEvidenceForExecution> ?evidenceExecution }
      OPTIONAL { ?evidence <urn:usf:ontology:validationEvidenceAdmittedThrough> ?evidenceAdmissionPath }
    } ORDER BY ?id ?satisfaction ?evidence LIMIT 257`),
    client.select(`SELECT ?id ?satisfaction ?field ?path WHERE {
      ?id <urn:usf:ontology:validationForContract> <${contract}> ;
          <urn:usf:ontology:satisfiedByValidationResult> ?satisfaction .
      ?satisfaction <urn:usf:ontology:hasValidationSelfPublicationAuthorityBinding> ?binding .
      {
        ?binding <urn:usf:ontology:validationBindingSourcePath> ?path .
        BIND("bindingSourcePath" AS ?field)
      } UNION {
        ?binding <urn:usf:ontology:validationBindingProducerSourcePath> ?path .
        BIND("bindingProducerSourcePath" AS ?field)
      } UNION {
        ?binding <urn:usf:ontology:validationBindingAdmissionSourcePath> ?path .
        BIND("bindingAdmissionSourcePath" AS ?field)
      } UNION {
        ?binding <urn:usf:ontology:authorityBindingValidationProducer> ?producer .
        ?producer <urn:usf:ontology:validationProducerSourcePath> ?path .
        BIND("producerSourcePath" AS ?field)
      } UNION {
        ?binding <urn:usf:ontology:authorityBindingEvidenceAdmissionPath> ?admissionPath .
        ?admissionPath <urn:usf:ontology:admissionPathSourcePath> ?path .
        BIND("admissionSourcePath" AS ?field)
      }
    } ORDER BY ?id ?satisfaction ?field ?path LIMIT 1025`),
  ]);
  if (obligationRows.length > 256) {
    throw new Error('validation obligation projection exceeds 256 rows');
  }
  if (evidenceRows.length > 256) {
    throw new Error('validation evidence projection exceeds 256 rows');
  }
  if (pathRows.length > 1024) {
    throw new Error('validation self-publication source path projection exceeds 1024 rows');
  }
  const head = applicabilityRows[0] || {};
  const states = new Set(applicabilityRows.map((row) => value(row, 'state')).filter(Boolean));
  if (states.size > 1) throw new Error('contract declares more than one validation applicability state');
  const satisfactionFields = [
    'boundObligation', 'resultState', 'boundAuthority', 'boundHead', 'invalidation', 'superseded',
    'binding', 'bindingResult', 'bindingRule', 'reevaluationRequired', 'reevaluationState',
    'stageOneEvaluated', 'stageOneSettled', 'nonPublicationDependency', 'dependencyAlgorithm',
    'reevaluationDependency', 'bindingExecutionReceipt', 'bindingEvaluationReceipt', 'bindingProducer',
    'bindingAdmissionPath', 'bindingProducerRelease', 'bindingRepository', 'bindingSourceHead',
    'bindingSourceTree', 'bindingSourcePath', 'bindingSourceScope', 'bindingProducerRepository',
    'bindingProducerSourceHead', 'bindingProducerSourceTree', 'bindingProducerSourcePath',
    'bindingProducerSourceScope', 'bindingAdmissionRepository', 'bindingAdmissionSourceHead',
    'bindingAdmissionSourceTree', 'bindingAdmissionSourcePath', 'bindingAdmissionSourceScope',
    'bindingReevaluation', 'reevaluatesValidationResult', 'reevaluationAuthority', 'reevaluationResultState',
    'reevaluationExecutionReceipt', 'reevaluationEvaluationReceipt', 'evaluation', 'evaluationReceipt', 'execution',
    'executionReceipt', 'executionProducer', 'executionAdmissionPath', 'evidence', 'evidenceType', 'evidenceExecution',
    'evidenceAdmissionPath', 'producerRelease', 'producerRepository', 'producerSourceHead',
    'producerSourceTree', 'producerSourcePath', 'producerSourceScope', 'admissionProducer', 'admissionRepository',
    'admissionSourceHead', 'admissionSourceTree', 'admissionSourcePath', 'admissionSourceScope',
  ];
  const obligations = new Map();
  for (const row of obligationRows) {
    const id = value(row, 'id');
    const existing = obligations.get(id) || {
      id,
      activation: value(row, 'activation'),
      definitions: new Set(),
      activationReasons: new Set(),
      targets: new Set(),
      evidence: new Set(),
      ownerPaths: new Set(),
      conditionMatched: false,
      satisfactionRecords: new Map(),
    };
    if (existing.activation !== value(row, 'activation')) throw new Error('validation obligation declares inconsistent activation state');
    for (const [field, terms] of [
      ['definition', existing.definitions],
      ['activationReason', existing.activationReasons],
      ['target', existing.targets],
      ['defectEvidence', existing.evidence],
      ['ownerPath', existing.ownerPaths],
    ]) {
      const term = value(row, field);
      if (term !== null) terms.add(term);
    }
    existing.conditionMatched ||= value(row, 'conditionMatched') === 'true';
    const satisfaction = value(row, 'satisfaction');
    if (satisfaction) {
      const record = existing.satisfactionRecords.get(satisfaction)
        || Object.fromEntries([['result', satisfaction], ...satisfactionFields.map((field) => [field, new Set()])]);
      for (const field of satisfactionFields) {
        const term = value(row, field);
        if (term !== null) record[field].add(term);
      }
      existing.satisfactionRecords.set(satisfaction, record);
    }
    obligations.set(id, existing);
  }
  for (const row of pathRows) {
    const id = value(row, 'id');
    const satisfaction = value(row, 'satisfaction');
    const field = value(row, 'field');
    const path = value(row, 'path');
    const record = obligations.get(id)?.satisfactionRecords.get(satisfaction);
    if (!record || !satisfactionFields.includes(field) || typeof path !== 'string' || path.length === 0) {
      throw new Error('validation self-publication source path projection is inconsistent');
    }
    record[field].add(path);
  }
  for (const row of evidenceRows) {
    const id = value(row, 'id');
    const satisfaction = value(row, 'satisfaction');
    const record = obligations.get(id)?.satisfactionRecords.get(satisfaction);
    if (!record) {
      throw new Error('validation evidence projection is inconsistent');
    }
    const evidence = value(row, 'evidence');
    const evidenceType = value(row, 'evidenceType');
    const evidenceExecution = value(row, 'evidenceExecution');
    const evidenceAdmissionPath = value(row, 'evidenceAdmissionPath');
    if (evidence === null) throw new Error('validation evidence projection is incomplete');
    record.evidence.add(evidence);
    if (evidenceType === null) {
      if (evidenceExecution !== null || evidenceAdmissionPath !== null) {
        throw new Error('validation evidence projection is incomplete');
      }
      continue;
    }
    if (evidenceType !== 'true' || evidenceExecution === null || evidenceAdmissionPath === null) {
      throw new Error('validation evidence projection is incomplete');
    }
    record.evidenceType.add(evidenceType);
    record.evidenceExecution.add(evidenceExecution);
    record.evidenceAdmissionPath.add(evidenceAdmissionPath);
  }
  const projectedObligations = [...obligations.values()].map(({ satisfactionRecords, definitions, activationReasons, targets, evidence, ownerPaths, ...obligation }) => ({
    ...obligation,
    definitions: [...definitions].sort(),
    activationReasons: [...activationReasons].sort(),
    targets: [...targets].sort(),
    evidence: [...evidence].sort(),
    ownerPaths: [...ownerPaths].sort(),
    satisfactions: [...satisfactionRecords.values()].map((record) => Object.fromEntries(
      Object.entries(record).map(([field, terms]) => [field, terms instanceof Set ? [...terms].sort() : terms]),
    )),
  }));
  return {
    applicability: [...states][0] ?? null,
    applicabilityReason: value(head, 'reason'),
    exemptionAuthorityProven: applicabilityRows.some((row) => value(row, 'authority') && value(row, 'authorityState') === SUCCESSFUL),
    conditionCount: new Set(applicabilityRows.map((row) => value(row, 'condition')).filter(Boolean)).size,
    obligations: projectedObligations,
  };
}

function soleTerm(item, field) {
  return item[field]?.length === 1 ? item[field][0] : null;
}

function validationNonPublicationDependencyDigest(inventory) {
  if (!Array.isArray(inventory)) return null;
  const excluded = new Set(NON_PUBLICATION_EXCLUDED_GRAPHS);
  // The binding carrying this digest is in the proofs graph. Excluding that
  // exact graph makes the prospective D2 calculation non-recursive while all
  // non-publication authority graphs remain content-bound.
  if (!excluded.has(NON_PUBLICATION_DIGEST_BINDING_GRAPH)) return null;
  const graphs = [];
  const observed = new Set();
  for (const record of inventory) {
    const observedDigest = record?.dependencySha256 ?? record?.sha256 ?? record?.digest;
    const normalizedDigest = /^[0-9a-f]{64}$/.test(observedDigest || '')
      ? `sha256:${observedDigest}` : observedDigest;
    if (!record || typeof record.graph !== 'string' || record.graph.length === 0
        || !/^sha256:[0-9a-f]{64}$/.test(normalizedDigest || '')
        || !Number.isSafeInteger(record.triples) || record.triples < 0
        || observed.has(record.graph)) return null;
    observed.add(record.graph);
    if (!excluded.has(record.graph)) graphs.push({
      graph: record.graph,
      sha256: normalizedDigest,
      triples: record.triples,
    });
  }
  graphs.sort((left, right) => left.graph.localeCompare(right.graph));
  return digest(jcs({
    algorithm: NON_PUBLICATION_DEPENDENCY_ALGORITHM,
    excludedGraphs: NON_PUBLICATION_EXCLUDED_GRAPHS,
    graphs,
  }));
}

function exactTermSet(item, left, right) {
  const leftTerms = item[left] || [];
  const rightTerms = item[right] || [];
  return leftTerms.length > 0
    && leftTerms.length === rightTerms.length
    && leftTerms.every((term, index) => term === rightTerms[index]);
}

function completeValidationEvidenceSet(item, execution, admissionPath) {
  return item.evidence.length > 0
    && soleTerm(item, 'evidenceType') === 'true'
    && soleTerm(item, 'evidenceExecution') === execution
    && soleTerm(item, 'evidenceAdmissionPath') === admissionPath;
}

function completeSameRepositorySelfPublicationClosure(item, authorityWitnessValue) {
  const authorityDigest = authorityWitnessValue?.digest ?? null;
  const resultAuthority = soleTerm(item, 'boundAuthority');
  const resultHead = soleTerm(item, 'boundHead');
  const stageOneEvaluated = soleTerm(item, 'stageOneEvaluated');
  const stageOneSettled = soleTerm(item, 'stageOneSettled');
  const dependency = soleTerm(item, 'nonPublicationDependency');
  const currentDependency = validationNonPublicationDependencyDigest(authorityWitnessValue?.inventory);
  const executionReceipt = soleTerm(item, 'executionReceipt');
  const evaluationReceipt = soleTerm(item, 'evaluationReceipt');
  const producer = soleTerm(item, 'bindingProducer');
  const admissionPath = soleTerm(item, 'bindingAdmissionPath');
  const repository = soleTerm(item, 'bindingRepository');
  const sourceTree = soleTerm(item, 'bindingSourceTree');
  const sourceScope = soleTerm(item, 'bindingSourceScope');

  return item.binding?.length === 1
    && soleTerm(item, 'bindingResult') === item.result
    && soleTerm(item, 'bindingRule') === VALIDATION_NON_PUBLICATION_CLOSURE
    && soleTerm(item, 'reevaluationRequired') === 'true'
    && soleTerm(item, 'reevaluationState') === PASSED_RESULT
    && stageOneEvaluated !== null
    && stageOneEvaluated !== stageOneSettled
    && stageOneSettled === resultAuthority
    && stageOneSettled !== authorityDigest
    && dependency !== null
    && dependency === currentDependency
    && soleTerm(item, 'reevaluationDependency') === dependency
    && soleTerm(item, 'dependencyAlgorithm') === NON_PUBLICATION_DEPENDENCY_ALGORITHM
    && executionReceipt !== null
    && evaluationReceipt !== null
    && soleTerm(item, 'bindingExecutionReceipt') === executionReceipt
    && soleTerm(item, 'bindingEvaluationReceipt') === evaluationReceipt
    && soleTerm(item, 'evaluation') !== null
    && soleTerm(item, 'execution') !== null
    && soleTerm(item, 'executionProducer') === producer
    && soleTerm(item, 'executionAdmissionPath') === admissionPath
    && completeValidationEvidenceSet(item, soleTerm(item, 'execution'), admissionPath)
    && soleTerm(item, 'admissionProducer') === producer
    && soleTerm(item, 'bindingProducerRelease') === soleTerm(item, 'producerRelease')
    && soleTerm(item, 'bindingRepository') === soleTerm(item, 'producerRepository')
    && soleTerm(item, 'bindingRepository') === soleTerm(item, 'admissionRepository')
    && soleTerm(item, 'bindingSourceHead') === resultHead
    && soleTerm(item, 'bindingSourceHead') === soleTerm(item, 'producerSourceHead')
    && soleTerm(item, 'bindingSourceHead') === soleTerm(item, 'admissionSourceHead')
    && sourceTree !== null
    && sourceTree === soleTerm(item, 'producerSourceTree')
    && sourceTree === soleTerm(item, 'admissionSourceTree')
    && sourceScope !== null
    && sourceScope === soleTerm(item, 'producerSourceScope')
    && sourceScope === soleTerm(item, 'admissionSourceScope')
    && repository !== null;
}

function completeCrossRepositorySelfPublicationClosure(item, authorityWitnessValue) {
  const authorityDigest = authorityWitnessValue?.digest ?? null;
  const resultAuthority = soleTerm(item, 'boundAuthority');
  const resultHead = soleTerm(item, 'boundHead');
  const stageOneEvaluated = soleTerm(item, 'stageOneEvaluated');
  const stageOneSettled = soleTerm(item, 'stageOneSettled');
  const dependency = soleTerm(item, 'nonPublicationDependency');
  const currentDependency = validationNonPublicationDependencyDigest(authorityWitnessValue?.inventory);
  const execution = soleTerm(item, 'execution');
  const executionReceipt = soleTerm(item, 'executionReceipt');
  const evaluation = soleTerm(item, 'evaluation');
  const evaluationReceipt = soleTerm(item, 'evaluationReceipt');
  const producer = soleTerm(item, 'bindingProducer');
  const admissionPath = soleTerm(item, 'bindingAdmissionPath');
  const producerRepository = soleTerm(item, 'bindingProducerRepository');
  const admissionRepository = soleTerm(item, 'bindingAdmissionRepository');
  const reevaluation = soleTerm(item, 'bindingReevaluation');

  return item.binding?.length === 1
    && soleTerm(item, 'bindingResult') === item.result
    && soleTerm(item, 'bindingRule') === VALIDATION_CROSS_REPOSITORY_NON_PUBLICATION_CLOSURE
    && soleTerm(item, 'reevaluationRequired') === 'true'
    && soleTerm(item, 'reevaluationState') === PASSED_RESULT
    && resultAuthority !== null
    && resultAuthority !== authorityDigest
    && stageOneEvaluated !== null
    && stageOneEvaluated !== stageOneSettled
    && stageOneSettled !== null
    && stageOneSettled !== authorityDigest
    && dependency !== null
    && dependency === currentDependency
    && soleTerm(item, 'reevaluationDependency') === dependency
    && soleTerm(item, 'dependencyAlgorithm') === NON_PUBLICATION_DEPENDENCY_ALGORITHM
    && execution !== null
    && evaluation !== null
    && executionReceipt !== null
    && evaluationReceipt !== null
    && soleTerm(item, 'bindingExecutionReceipt') === executionReceipt
    && soleTerm(item, 'bindingEvaluationReceipt') === evaluationReceipt
    && soleTerm(item, 'executionProducer') === producer
    && soleTerm(item, 'executionAdmissionPath') === admissionPath
    && completeValidationEvidenceSet(item, execution, admissionPath)
    && soleTerm(item, 'admissionProducer') === producer
    && soleTerm(item, 'bindingProducerRelease') === soleTerm(item, 'producerRelease')
    && producerRepository !== null
    && admissionRepository !== null
    && producerRepository !== admissionRepository
    && producerRepository === soleTerm(item, 'producerRepository')
    && admissionRepository === soleTerm(item, 'admissionRepository')
    && soleTerm(item, 'bindingProducerSourceHead') === resultHead
    && soleTerm(item, 'bindingProducerSourceHead') === soleTerm(item, 'producerSourceHead')
    && soleTerm(item, 'bindingProducerSourceTree') === soleTerm(item, 'producerSourceTree')
    && soleTerm(item, 'bindingProducerSourceScope') === soleTerm(item, 'producerSourceScope')
    && soleTerm(item, 'bindingAdmissionSourceHead') === soleTerm(item, 'admissionSourceHead')
    && soleTerm(item, 'bindingAdmissionSourceTree') === soleTerm(item, 'admissionSourceTree')
    && soleTerm(item, 'bindingAdmissionSourceScope') === soleTerm(item, 'admissionSourceScope')
    && exactTermSet(item, 'bindingProducerSourcePath', 'producerSourcePath')
    && exactTermSet(item, 'bindingAdmissionSourcePath', 'admissionSourcePath')
    && item.bindingRepository.length === 0
    && item.bindingSourceHead.length === 0
    && item.bindingSourceTree.length === 0
    && item.bindingSourcePath.length === 0
    && item.bindingSourceScope.length === 0
    && reevaluation !== null
    // A single publication reevaluation may close several independently bound
    // validations.  This binding is current only when the shared reevaluation
    // explicitly includes this exact result; requiring the whole plural set to
    // have scalar cardinality rejects an otherwise complete D2 closure.
    && item.reevaluatesValidationResult.includes(item.result)
    && soleTerm(item, 'reevaluationAuthority') === stageOneSettled
    && soleTerm(item, 'reevaluationResultState') === PASSED_RESULT
    && soleTerm(item, 'reevaluationExecutionReceipt') !== null
    && soleTerm(item, 'reevaluationEvaluationReceipt') !== null;
}

function completeSelfPublicationClosure(item, authorityWitnessValue) {
  const bindingRule = soleTerm(item, 'bindingRule');
  if (bindingRule === VALIDATION_NON_PUBLICATION_CLOSURE) {
    return completeSameRepositorySelfPublicationClosure(item, authorityWitnessValue);
  }
  if (bindingRule === VALIDATION_CROSS_REPOSITORY_NON_PUBLICATION_CLOSURE) {
    return completeCrossRepositorySelfPublicationClosure(item, authorityWitnessValue);
  }
  return false;
}

// A satisfaction survives only while it stays identity-bound to this obligation
// and bound to the exact authority the factory is acting on. Anything less is a
// historical record, not a current conclusion.
function requireResolvedOwner(owner, label) {
  // "Owner not supplied" is not V1. These are the last places a default could
  // silently reinstate the V1 branch, so an absent or non-determinate owner
  // refuses instead.
  const state = owner?.ownershipState ?? null;
  if (state !== OWNERSHIP.v1 && state !== OWNERSHIP.pending && state !== OWNERSHIP.terminal) {
    throw new Error(
      `${label} requires a resolved owner boundary; got ${state ?? OWNERSHIP.unresolved}`,
    );
  }
  return owner;
}

function satisfactionCurrent(obligation, authorityWitnessValue, owner) {
  requireResolvedOwner(owner, 'satisfactionCurrent');
  // A pending handover has no owner able to conclude anything. Fail closed
  // rather than borrowing the outgoing V1 conclusion.
  if (owner.ownershipState === OWNERSHIP.pending) return false;
  const terminal = owner.ownershipState === OWNERSHIP.terminal;
  // Terminal V2: whether a satisfaction is CURRENT is decided by the renewable
  // native validation-currentness head, not by the V1 publication lifecycle.
  // A stale head withdraws every satisfaction at once.
  if (terminal && owner.validationCurrentnessState !== NATIVE_VALIDATION_CURRENT) return false;
  const authorityDigest = authorityWitnessValue?.digest ?? null;
  return obligation.satisfactions.some((item) => {
    const boundSourceHead = soleTerm(item, 'boundHead');
    const exactResult = soleTerm(item, 'boundObligation') === obligation.id
      && soleTerm(item, 'resultState') === PASSED_RESULT
      && typeof boundSourceHead === 'string' && boundSourceHead.length > 0
      && item.invalidation.length === 0
      && item.superseded.length === 0;
    if (!exactResult) return false;
    if (terminal) {
      // Identity is still content-exact against the certified baseline, but the
      // authority anchor is the terminal V2 generation and its stable
      // non-publication closure. The live V1 publication digest is not read.
      return (owner.terminalAuthorityDigest !== null
          && soleTerm(item, 'boundAuthority') === owner.terminalAuthorityDigest)
        || completeSelfPublicationClosure(item, authorityWitnessValue);
    }
    // Preserve the historical direct-binding path exactly. The closure is an
    // additional fail-closed path for a result whose publication necessarily
    // changed the authority digest it originally evaluated.
    return (authorityDigest !== null && soleTerm(item, 'boundAuthority') === authorityDigest)
      || completeSelfPublicationClosure(item, authorityWitnessValue);
  });
}

const DURABLE_FAMILY_VALIDATION_OBLIGATIONS = Object.freeze({
  'urn:usf:validationobligation:operationexpectedoutcomeerrorclass': Object.freeze({
    family: 'urn:usf:permutationfamily:operationexpectedoutcomeerrorclass',
  }),
  'urn:usf:validationobligation:resourceactionretentionstatelegalholdstate': Object.freeze({
    family: 'urn:usf:permutationfamily:resourceactionretentionstatelegalholdstate',
  }),
  'urn:usf:validationobligation:scheduledjobactionroleserviceidentityenvironmentclass': Object.freeze({
    family: 'urn:usf:permutationfamily:scheduledjobactionroleserviceidentityenvironmentclass',
  }),
});

function durableFamilyValidationWorkItem(obligation, contract) {
  const expected = DURABLE_FAMILY_VALIDATION_OBLIGATIONS[obligation.id];
  // An activated obligation is not evidence that its former defect still
  // exists. Only the family-specific live triple pattern above enables a work
  // row. When that pattern disappears the obligation stays visible to the
  // validation lifecycle but is not scheduled as remediation.
  if (!expected || !obligation.conditionMatched) return null;
  if (obligation.targets.length !== 1 || obligation.targets[0] !== expected.family) {
    throw new Error(`durable family validation obligation ${obligation.id} has no exact family target`);
  }
  if (obligation.definitions.length !== 1 || obligation.activationReasons.length !== 1) {
    throw new Error(`durable family validation obligation ${obligation.id} has ambiguous analysis semantics`);
  }
  if (obligation.ownerPaths.length !== 1 || obligation.ownerPaths[0] !== 'semantic-model/permutation/families.trig') {
    throw new Error(`durable family validation obligation ${obligation.id} has no exact owner path`);
  }
  if (!obligation.evidence.includes(expected.family)
      || !obligation.evidence.includes('urn:usf:artefact:permutationfamilysource')) {
    throw new Error(`durable family validation obligation ${obligation.id} lacks governed defect evidence`);
  }
  return {
    contract,
    familySubject: expected.family,
    sourceArtefact: 'urn:usf:artefact:permutationfamilysource',
    defectCondition: obligation.activationReasons[0],
    analysisObjective: obligation.definitions[0],
    defectEvidence: [...obligation.evidence].sort(),
    rootCause: obligation.activationReasons[0],
    subjects: [expected.family, ...obligation.evidence.filter((item) => item !== expected.family)].sort(),
    taskClass: 'semantic-planning',
    remediationKind: 'ANALYSIS_ONLY',
    repository: 'maldous/usf-graph',
    decisionIds: ['urn:usf:realisationdecision:repositoryarchitectureandnaming'],
    materialisationOwnerPath: obligation.ownerPaths[0],
    acceptanceCriteria: [
      obligation.definitions[0],
      `Produce a current passing ValidationResult bound to ${obligation.id}; an analysis result alone does not satisfy or close the obligation.`,
    ],
  };
}

// The complete gap set for one contract, as {code, subject} pairs. This is the
// single definition of "outstanding" that both the paged projection and the
// unpaged disposition census use, so a page boundary can never hide a state.
function validationGaps(contract, scope, authorityWitnessValue, owner) {
  requireResolvedOwner(owner, 'validationGaps');
  const gaps = [];
  const { applicability } = scope;
  if (applicability === null || applicability === APPLICABILITY.unresolved) {
    gaps.push({ code: 'validation-applicability-unresolved', subject: contract });
  }
  if (applicability === APPLICABILITY.conditional) {
    gaps.push({ code: 'validation-applicability-conditional-unevaluated', subject: contract });
  }
  if (applicability === APPLICABILITY.reserved) {
    gaps.push({ code: 'validation-applicability-reserved', subject: contract });
  }
  if (applicability === APPLICABILITY.notRequired && !scope.exemptionAuthorityProven) {
    gaps.push({ code: 'validation-exemption-unwarranted', subject: contract });
  }
  for (const obligation of scope.obligations) {
    if (obligation.activation === null) {
      gaps.push({ code: 'validation-obligation-activation-unresolved', subject: obligation.id });
      continue;
    }
    if (obligation.activation === ACTIVATION.blocked) {
      gaps.push({ code: 'validation-obligation-blocked', subject: obligation.id });
      continue;
    }
    if (obligation.activation === ACTIVATION.reserved) {
      gaps.push({ code: 'validation-obligation-reserved', subject: obligation.id });
      continue;
    }
    if (obligation.activation !== ACTIVATION.activated) {
      gaps.push({ code: 'validation-obligation-activation-unresolved', subject: obligation.id });
      continue;
    }
    // A pending handover cannot evaluate satisfaction: no owner is able to
    // certify it. Emitting `missing-current-passing-validation` here would
    // assert an unproven negative AND, because that code carries a declared
    // BLOCK remediation, would schedule validation-evidence work off a
    // conclusion nobody reached. The obligation stays visible through
    // validationSatisfied=false and the unresolved currentness gap; it does not
    // become actionable work.
    if (owner.ownershipState === OWNERSHIP.pending) continue;
    if (!satisfactionCurrent(obligation, authorityWitnessValue, owner)) {
      const code = obligation.satisfactions.length > 0 ? 'validation-satisfaction-not-current' : 'missing-current-passing-validation';
      const workItem = durableFamilyValidationWorkItem(obligation, contract);
      // Correcting the source condition ends remediation scheduling, but it
      // cannot satisfy the durable validation obligation. The obligation
      // remains fail-closed until its own exact current passing result exists.
      gaps.push({
        code,
        subject: obligation.id,
        ...(workItem || {}),
      });
    }
  }
  return gaps;
}

// May the factory execute validation for this contract right now? A separate
// question from whether validation is satisfied, and from whether realisation
// is authorised. One property answering all three is what let a reserved
// obligation read as a satisfied one.
function validationActionStateFor(scope) {
  const { applicability, obligations } = scope;
  if (applicability === null
    || applicability === APPLICABILITY.unresolved
    || applicability === APPLICABILITY.conditional) return ACTION_STATES.unresolved;
  // An unproven exemption is an unproven conclusion, not a licence.
  if (applicability === APPLICABILITY.notRequired) {
    return scope.exemptionAuthorityProven ? ACTION_STATES.reserved : ACTION_STATES.unresolved;
  }
  if (applicability === APPLICABILITY.reserved) return ACTION_STATES.reserved;
  if (applicability !== APPLICABILITY.required) return ACTION_STATES.unresolved;
  // required with nothing bound cannot say what to validate.
  if (obligations.length === 0) return ACTION_STATES.unresolved;
  if (obligations.some((item) => !Object.values(ACTIVATION).includes(item.activation))) return ACTION_STATES.unresolved;
  if (obligations.some((item) => item.activation === ACTIVATION.blocked)) return ACTION_STATES.block;
  if (obligations.some((item) => item.activation === ACTIVATION.activated)) return ACTION_STATES.proceed;
  return ACTION_STATES.reserved;
}

function validationVerdict(contract, scope, authorityWitnessValue, owner) {
  requireResolvedOwner(owner, 'validationVerdict');
  const gaps = validationGaps(contract, scope, authorityWitnessValue, owner);
  const dispositions = gaps.map((gap) => resolveDisposition(gap.code));
  const realisationBlocking = gaps.filter((gap) => !VALIDATION_SCOPED_GAPS.has(gap.code));
  const validationActionState = validationActionStateFor(scope);
  return {
    gaps,
    dispositions,
    realisationBlocking,
    // Satisfaction is a positive conclusion: it needs every obligation
    // activated and currently satisfied, never merely "no gap recorded".
    validationSatisfied: scope.applicability === APPLICABILITY.required
      && scope.obligations.length > 0
      && scope.obligations.every((item) => item.activation === ACTIVATION.activated
        && satisfactionCurrent(item, authorityWitnessValue, owner)),
    validationActionState,
  };
}

async function readAuthorityConflictState(client, binding, authorityDigest) {
  const escapedRepository = binding.repository.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  const [surfaceRows, resolutionRows, setRows] = await Promise.all([
    client.select(`SELECT DISTINCT ?surfaceContract ?authorisedPath ?authorisedFormat ?surfaceObligation WHERE {
      ?surfaceContract a <urn:usf:ontology:SemanticContract> ;
        <urn:usf:ontology:semanticLifecycleState> <urn:usf:semanticlifecyclestate:active> ;
        <urn:usf:ontology:hasActivationState> <urn:usf:contractactivationstate:active> ;
        <urn:usf:ontology:mandatoryProofObligation> ?surfaceObligation ;
        <urn:usf:ontology:reliesOnProofResult> ?surfaceProof ;
        <urn:usf:ontology:effectiveRealisationDecision> ?surfaceDecision .
      ?surfaceProof <urn:usf:ontology:hasProofResultState> <urn:usf:proofresultstate:successful> .
      ?surfaceDecision <urn:usf:ontology:decisionState> <urn:usf:decisionstate:accepted> ;
        <urn:usf:ontology:authorisesRepository> "${escapedRepository}" ;
        <urn:usf:ontology:authorisesSourcePath> ?authorisedPath ;
        <urn:usf:ontology:authorisesRepresentationFormat> ?authorisedFormat .
    } ORDER BY ?surfaceContract ?authorisedPath ?authorisedFormat LIMIT 257`),
    client.select(`SELECT ?resolution ?conflict ?resolutionState ?decisionState ?review ?reviewState
        ?reviewAuthorityDigest ?reviewInventoryDigest ?proofResult ?proofState ?proofSubject
        ?ownerAssignment ?ownerState ?ownerAuthorityDomain ?ownerRepository ?ownerEnvelopeState
        ?authorityDigest ?repository ?operationDigest ?candidateDigest ?predecessorSourceHead
        ?predecessorSourceTree ?successorSourceTree ?sourceScopeDigest WHERE {
      ?resolution a <urn:usf:ontology:SemanticCorrectionDecision> ;
        <urn:usf:ontology:resolvesAuthorityConflict> ?conflict .
      ?conflict <urn:usf:ontology:conflictRepository> "${escapedRepository}" .
      OPTIONAL { ?resolution <urn:usf:ontology:semanticCorrectionDecisionState> ?resolutionState }
      OPTIONAL { ?resolution <urn:usf:ontology:semanticCorrectionDecisionState> ?decisionState }
      OPTIONAL {
        ?resolution <urn:usf:ontology:decisionBasedOnSemanticAdequacyReview> ?review .
        OPTIONAL { ?review <urn:usf:ontology:hasSemanticAdequacyReviewState> ?reviewState }
        OPTIONAL { ?review <urn:usf:ontology:reviewedAuthorityDigest> ?reviewAuthorityDigest }
        OPTIONAL { ?review <urn:usf:ontology:reviewedInventoryDigest> ?reviewInventoryDigest }
      }
      OPTIONAL {
        ?resolution <urn:usf:ontology:warrantedBySemanticAdequacyProof> ?proofResult .
        OPTIONAL { ?proofResult <urn:usf:ontology:hasProofResultState> ?proofState }
        OPTIONAL { ?proofResult <urn:usf:ontology:resultForProof>/<urn:usf:ontology:provesSubject> ?proofSubject }
      }
      OPTIONAL {
        ?resolution <urn:usf:ontology:authorityConflictResolutionOwnerAssignment> ?ownerAssignment .
        OPTIONAL { ?ownerAssignment <urn:usf:ontology:assignmentState> ?ownerState }
        OPTIONAL { ?ownerAssignment <urn:usf:ontology:authorityDomain> ?ownerAuthorityDomain }
        OPTIONAL { ?ownerAssignment <urn:usf:ontology:authorityRepository> ?ownerRepository }
        OPTIONAL { ?ownerAssignment <urn:usf:ontology:hasAdmittedEnvelopeVerification>/<urn:usf:ontology:envelopeVerificationState> ?ownerEnvelopeState }
      }
      OPTIONAL { ?conflict <urn:usf:ontology:conflictAuthorityDigest> ?authorityDigest }
      OPTIONAL { ?conflict <urn:usf:ontology:conflictRepository> ?repository }
      OPTIONAL { ?conflict <urn:usf:ontology:conflictOperationDigest> ?operationDigest }
      OPTIONAL { ?conflict <urn:usf:ontology:conflictCandidateDigest> ?candidateDigest }
      OPTIONAL { ?conflict <urn:usf:ontology:conflictPredecessorSourceHead> ?predecessorSourceHead }
      OPTIONAL { ?conflict <urn:usf:ontology:conflictPredecessorSourceTree> ?predecessorSourceTree }
      OPTIONAL { ?conflict <urn:usf:ontology:conflictSuccessorSourceTree> ?successorSourceTree }
      OPTIONAL { ?conflict <urn:usf:ontology:conflictSourceScopeDigest> ?sourceScopeDigest }
    } ORDER BY ?resolution LIMIT 257`),
    client.select(`SELECT ?resolution ?kind ?item WHERE {
      ?resolution a <urn:usf:ontology:SemanticCorrectionDecision> ;
        <urn:usf:ontology:resolvesAuthorityConflict> ?conflict .
      ?conflict <urn:usf:ontology:conflictRepository> "${escapedRepository}" .
      {
        ?conflict <urn:usf:ontology:conflictingAuthority> ?item . BIND("contract" AS ?kind)
      } UNION {
        ?conflict <urn:usf:ontology:conflictRequestedAction> ?item . BIND("action" AS ?kind)
      } UNION {
        ?conflict <urn:usf:ontology:conflictRequestedPath> ?item . BIND("path" AS ?kind)
      } UNION {
        ?conflict <urn:usf:ontology:conflictRequestedRepresentationFormat> ?item . BIND("format" AS ?kind)
      } UNION {
        ?conflict <urn:usf:ontology:conflictRequestedEffect> ?item . BIND("effect" AS ?kind)
      } UNION {
        ?conflict <urn:usf:ontology:conflictSourcePath> ?item . BIND("sourcePath" AS ?kind)
      } UNION {
        ?conflict <urn:usf:ontology:conflictBlockedByValidationObligation> ?item . BIND("validationObligation" AS ?kind)
      } UNION {
        ?resolution <urn:usf:ontology:authorityConflictResolutionOwnerAssignment>/<urn:usf:ontology:ownerAssignmentSourcePath> ?item . BIND("ownerSourcePath" AS ?kind)
      }
    } ORDER BY ?resolution ?kind ?item LIMIT 2049`),
  ]);
  if (surfaceRows.length >= 257 || resolutionRows.length >= 257 || setRows.length >= 2049) {
    throw new Error('authority-conflict projection exceeds its bounded cardinality');
  }
  const surfaces = new Map();
  for (const row of surfaceRows) {
    const contract = value(row, 'surfaceContract');
    if (!contract) throw new Error('authority-conflict surface projection is incomplete');
    const current = surfaces.get(contract) || {
      contract, authorisedPaths: new Set(), authorisedFormats: new Set(), mandatoryObligations: new Set(),
    };
    const path = value(row, 'authorisedPath');
    const format = value(row, 'authorisedFormat');
    const obligation = value(row, 'surfaceObligation');
    if (!obligation) throw new Error('authority-conflict surface obligation projection is incomplete');
    if (path) current.authorisedPaths.add(path);
    if (format) current.authorisedFormats.add(format);
    current.mandatoryObligations.add(obligation);
    surfaces.set(contract, current);
  }
  const applicableSurfaces = [];
  for (const surface of [...surfaces.values()]
    .filter((item) => binding.requestedPaths.some((path) => decisionAuthorisesPath(path, [...item.authorisedPaths])))) {
    // Authority bindings are schema-specific: the aggregate proof uses the
    // canonical non-publication dependency closure rather than a synthetic
    // settled-authority literal. Reuse the one proof-currentness resolver that
    // governs contract projection instead of inventing a second binding shape.
    const currentness = await proofCurrentnessVerdict(client, surface.contract, {
      mandatoryObligations: [...surface.mandatoryObligations].sort(),
    });
    if (currentness.state !== PROOF_CURRENTNESS.current) continue;
    applicableSurfaces.push(Object.freeze({
      contract: surface.contract,
      authorisedPaths: Object.freeze([...surface.authorisedPaths].sort()),
      authorisedFormats: Object.freeze([...surface.authorisedFormats].sort()),
    }));
  }
  applicableSurfaces.sort((left, right) => left.contract.localeCompare(right.contract));

  const grouped = new Map();
  for (const row of resolutionRows) {
    const id = value(row, 'resolution');
    if (!id) throw new Error('authority-conflict resolution identity is absent');
    const current = grouped.get(id) || { id, scalarRows: [], sets: new Map() };
    current.scalarRows.push(row);
    grouped.set(id, current);
  }
  for (const row of setRows) {
    const id = value(row, 'resolution');
    const kind = value(row, 'kind');
    const item = value(row, 'item');
    const current = grouped.get(id);
    if (!current || !kind || !item) throw new Error('authority-conflict set projection is incomplete');
    const items = current.sets.get(kind) || new Set();
    items.add(item);
    current.sets.set(kind, items);
  }
  const scalarKeys = [
    'conflict', 'resolutionState', 'decisionState', 'review', 'reviewState',
    'reviewAuthorityDigest', 'reviewInventoryDigest', 'proofResult', 'proofState',
    'proofSubject', 'ownerAssignment', 'ownerState', 'ownerAuthorityDomain',
    'ownerRepository', 'ownerEnvelopeState', 'authorityDigest', 'repository',
    'operationDigest', 'candidateDigest', 'predecessorSourceHead',
    'predecessorSourceTree', 'successorSourceTree', 'sourceScopeDigest',
  ];
  const resolutions = [...grouped.values()].map((group) => {
    const parsed = { id: group.id };
    for (const key of scalarKeys) {
      const values = [...new Set(group.scalarRows.map((row) => value(row, key)).filter(Boolean))];
      if (values.length > 1) throw new Error(`authority-conflict resolution has ambiguous ${key}`);
      parsed[key] = values[0] ?? null;
    }
    for (const [kind, target] of [
      ['contract', 'contracts'], ['action', 'requestedActions'], ['path', 'requestedPaths'],
      ['format', 'requestedFormats'], ['effect', 'requestedEffects'], ['sourcePath', 'sourcePaths'],
      ['validationObligation', 'validationObligations'], ['ownerSourcePath', 'ownerSourcePaths'],
    ]) parsed[target] = [...(group.sets.get(kind) || [])].sort();
    return Object.freeze(parsed);
  }).sort((left, right) => left.id.localeCompare(right.id));
  return Object.freeze({
    applicableContracts: Object.freeze(applicableSurfaces.map((surface) => surface.contract)),
    authoritySurfaces: Object.freeze(applicableSurfaces),
    resolutions: Object.freeze(resolutions),
  });
}

// The single authoritative realisation verdict. Every surface that can create,
// validate or apply a materialisation plan consumes this, so a plan tool cannot
// reach a conclusion the projection would refuse. Duplicating the state logic is
// what previously let usf_layout_plan succeed while usf_contract_project said
// BLOCK for the same contract.
//
// One digest-stable authority read: callers pass the verdict on rather than
// re-reading, so a plan cannot be validated against a different authority than
// the one it was created against.
export const REALISATION_STATE_FAILURE_CODES = Object.freeze({
  [ACTION_STATES.block]: 'plan-realisation-blocked',
  [ACTION_STATES.reserved]: 'plan-realisation-reserved',
  [ACTION_STATES.unresolved]: 'plan-realisation-unresolved',
});

export async function realisationVerdict(ctx, args = {}) {
  const authorityConflictBinding = args.authorityConflictBinding
    ? normaliseAuthorityConflictBinding(args.authorityConflictBinding, args.operations)
    : null;
  const implementationWorkGrantBinding = args.implementationWorkGrantBinding
    ? normaliseImplementationWorkGrantBinding(args.implementationWorkGrantBinding)
    : null;
  if (authorityConflictBinding && implementationWorkGrantBinding) {
    throw new Error('one materialisation transition cannot combine authority-conflict and implementation-work-grant bindings');
  }
  const requestedImplementationWorkGrantIri = implementationWorkGrantBinding?.grantIri
    ?? args.implementationWorkGrantIri ?? null;
  const requestedImplementationWorkRepository = implementationWorkGrantBinding?.repository
    ?? args.repository ?? null;
  if ((requestedImplementationWorkGrantIri === null) !== (requestedImplementationWorkRepository === null)
      || (implementationWorkGrantBinding
        && (args.implementationWorkGrantIri && args.implementationWorkGrantIri !== implementationWorkGrantBinding.grantIri
          || args.repository && args.repository !== implementationWorkGrantBinding.repository))) {
    throw new Error('implementation work grant identity and repository must be supplied as one exact binding');
  }
  if (authorityConflictBinding && requestedImplementationWorkGrantIri) {
    throw new Error('one materialisation transition cannot consume two exceptional authority surfaces');
  }
  // One bracket over the COMPLETE semantic read: contract, lifecycle, activation,
  // proof, decision, authorisations, materialisation rules and the whole
  // validation scope. Previously the witness was read concurrently with the
  // contract queries and the validation scope was read afterwards with no closing
  // witness, so a verdict could be assembled across two authority states.
  const { witness, value } = await stableAuthorityRead(
    ctx.client,
    'realisation verdict read',
    async (openingWitness) => {
      const semantics = await readLayoutSemantics(ctx, { contract: args.contract || CONTRACT });
      let implementationWorkGrantIri = requestedImplementationWorkGrantIri;
      if (!implementationWorkGrantIri && Array.isArray(args.operations) && args.operations.length > 0) {
        const grantRows = await ctx.client.select(`SELECT ?grant WHERE {
          ?grant a <urn:usf:ontology:ImplementationWorkGrant> ;
            <urn:usf:ontology:implementationWorkGrantState> <urn:usf:implementationworkgrantstate:reserved> .
        } ORDER BY ?grant LIMIT 2`);
        if (grantRows.length > 1) throw new Error('live authority has ambiguous reserved implementation work grants');
        implementationWorkGrantIri = grantRows[0]?.grant?.value ?? null;
      }
      const currentNonPublicationDependencySetDigest = validationNonPublicationDependencyDigest(openingWitness.inventory);
      const readGrant = ctx.readImplementationWorkGrantAuthorityState
        ?? readImplementationWorkGrantAuthorityStateV1;
      const [validationScopeValue, mandatoryRows, conflictState, implementationWorkGrant] = await Promise.all([
        validationScope(ctx.client, semantics.contract.id),
        ctx.client.select(`SELECT ?obligation WHERE { <${semantics.contract.id}> <urn:usf:ontology:mandatoryProofObligation> ?obligation } ORDER BY ?obligation LIMIT 64`),
        authorityConflictBinding
          ? readAuthorityConflictState(ctx.client, authorityConflictBinding, openingWitness.digest)
          : Promise.resolve(null),
        implementationWorkGrantIri
          ? readGrant(ctx.client, implementationWorkGrantIri, {
            casRoot: ctx.casRoot,
            evidenceStore: ctx.evidenceStore,
            implementationWorkGrantJournalIo: ctx.implementationWorkGrantJournalIo,
            implementationWorkGrantLedgerPath: ctx.implementationWorkGrantLedgerPath,
            nonPublicationDependencySetDigest: currentNonPublicationDependencySetDigest,
            now: ctx.trustedNow ?? ctx.observedAt ?? new Date(),
            requireReservedTransaction: true,
          })
          : Promise.resolve(null),
      ]);
      // Currentness is read inside the SAME bracket as the contract and
      // validation state, so the verdict is one conclusion about one authority
      // AND one owner. Resolving the owner inside the bracket is what stops a
      // verdict being assembled across a handover boundary.
      const owner = await resolveOwnerBoundary(ctx);
      const currentness = await ownerBoundaryCurrentness(ctx, owner, semantics.contract.id,
        // `value` is in the temporal dead zone here: the enclosing
        // stableAuthorityRead destructures a binding of that name. Read the term
        // directly rather than shadowing the accessor.
        mandatoryRows.map((row) => row.obligation?.value).filter(Boolean));
      return {
        semantics,
        scope: validationScopeValue,
        currentness,
        owner,
        conflictState,
        implementationWorkGrant,
        implementationWorkGrantIri,
        currentNonPublicationDependencySetDigest,
      };
    },
  );
  const context = withAuthority(value.semantics, witness, ctx);
  const scope = value.scope;
  const currentness = value.currentness;
  const owner = value.owner;
  const validation = validationVerdict(context.contract.id, scope, witness, owner);

  // Each conjunct is explicit. A null state is unproven, not permission; a wrong
  // state is an explicit negative. Both withhold PROCEED, and they are reported
  // separately so the reason survives.
  const reasons = [];
  const require = (observed, expected, unresolvedCode, blockCode) => {
    if (observed === null) reasons.push({ code: unresolvedCode, state: ACTION_STATES.unresolved });
    else if (observed !== expected) reasons.push({ code: blockCode, state: ACTION_STATES.block });
  };
  require(context.contract.lifecycleState, ACTIVE_LIFECYCLE, 'contract-lifecycle-unresolved', 'contract-lifecycle-not-active');
  require(context.contract.activationState, ACTIVE, 'contract-activation-unresolved', 'contract-not-active');
  require(context.contract.proofResultState, SUCCESSFUL, 'contract-proof-result-unresolved', 'contract-proof-not-successful');
  if (context.contract.proofResults.length === 0) reasons.push({ code: 'contract-proof-result-absent', state: ACTION_STATES.unresolved });
  // A successful result is necessary and NOT sufficient. PROCEED additionally
  // requires the positive currentness conclusion; anything less contributes its
  // own reasons at their own dispositions.
  if (currentness.state !== PROOF_CURRENTNESS.current) {
    for (const code of currentness.reasons) reasons.push({ code, state: resolveDisposition(code) });
    if (currentness.reasons.length === 0) {
      reasons.push({ code: PROOF_CURRENTNESS_CODES.currentnessUnresolved, state: ACTION_STATES.unresolved });
    }
  }
  if (!RESOLVED_DECISION.has(context.decisionResolution)) {
    const unresolved = context.decisionResolution === 'unresolved' || context.decisionResolution === 'no-accepted-decision';
    reasons.push({ code: `decision-${context.decisionResolution}`, state: unresolved ? ACTION_STATES.unresolved : ACTION_STATES.block });
  } else if (context.contract.decisionState !== ACCEPTED) {
    reasons.push({ code: 'decision-not-accepted', state: ACTION_STATES.block });
  }
  // Validation-scoped gaps (both reserved axes) are excluded here on purpose: a
  // reserved obligation withholds the validated claim, not realisation authority
  // an accepted decision and a successful proof already granted.
  for (const gap of validation.realisationBlocking) reasons.push({ code: gap.code, state: resolveDisposition(gap.code) });

  const baseActionState = reasons.length === 0 ? ACTION_STATES.proceed : strongestState(reasons.map((item) => item.state));
  let actionState = baseActionState;
  let actionStateReasons = reasons.map((item) => item.code).sort();
  let conflictResolution = null;
  let implementationWorkGrant = null;
  let effectiveImplementationWorkGrantBinding = null;
  let effectiveContext = context;
  if (authorityConflictBinding) {
    const resolutionVerdict = evaluateAuthorityConflictResolution({
      authorityDigest: context.authorityDigest,
      targetContract: context.contract.id,
      baseActionState,
      baseActionStateReasons: actionStateReasons,
      baseValidationGaps: validation.gaps,
      applicableContracts: value.conflictState?.applicableContracts ?? [],
      authoritySurfaces: value.conflictState?.authoritySurfaces ?? [],
      binding: authorityConflictBinding,
      resolutions: value.conflictState?.resolutions ?? [],
    });
    if (resolutionVerdict.actionState === ACTION_STATES.proceed) {
      actionState = ACTION_STATES.proceed;
      actionStateReasons = [];
      conflictResolution = resolutionVerdict.resolution;
      effectiveContext = Object.freeze({
        ...context,
        authorisedFormats: authorityConflictBinding.requestedFormats,
        authorisedPaths: authorityConflictBinding.requestedPaths,
        authorisedRepositories: Object.freeze([authorityConflictBinding.repository]),
        contract: Object.freeze({
          ...context.contract,
          authorisedRepository: authorityConflictBinding.repository,
        }),
      });
    } else {
      actionState = ACTION_STATES.block;
      actionStateReasons = [...new Set([
        ...actionStateReasons,
        ...resolutionVerdict.failures.map((item) => item.code),
      ])].sort();
    }
  }
  if (value.implementationWorkGrantIri
      && (requestedImplementationWorkGrantIri || baseActionState !== ACTION_STATES.proceed)) {
    let predecessorCommit = null;
    let predecessorTree = null;
    try {
      if (!ctx.repositoryRoot) throw new Error('repository root is absent');
      predecessorCommit = await gitOutput(ctx.repositoryRoot, ['rev-parse', '--verify', 'HEAD']);
      predecessorTree = await gitOutput(ctx.repositoryRoot, ['rev-parse', '--verify', 'HEAD^{tree}']);
    } catch (error) {
      actionState = ACTION_STATES.block;
      actionStateReasons = [...new Set([...actionStateReasons, 'implementation-work-grant-repository-identity'])].sort();
    }
    if (predecessorCommit && predecessorTree) {
      const matchingScopes = value.implementationWorkGrant.repositories.filter((scopeItem) => (
        scopeItem.predecessorCommit === predecessorCommit
        && scopeItem.predecessorTree === predecessorTree
        && args.operations.every((operation) => scopeItem.sourcePaths.includes(operation.path))
      ));
      const implementationWorkRepository = requestedImplementationWorkRepository
        ?? (matchingScopes.length === 1 ? matchingScopes[0].repository : null);
      const grantVerdict = evaluateImplementationWorkGrantProjection({
        grant: value.implementationWorkGrant,
        nonPublicationDependencySetDigest: value.currentNonPublicationDependencySetDigest,
        repository: implementationWorkRepository,
        predecessorCommit,
        predecessorTree,
        operations: args.operations,
        observedAt: ctx.trustedNow ?? ctx.observedAt ?? new Date(),
        repositoryRoot: ctx.repositoryRoot,
      });
      if (grantVerdict.actionState === ACTION_STATES.proceed) {
        implementationWorkGrant = grantVerdict.grant;
        const scopeForRepository = implementationWorkGrant.repositories
          .find((scopeItem) => scopeItem.repository === implementationWorkRepository);
        effectiveImplementationWorkGrantBinding = Object.freeze({
          evidenceSetDigest: implementationWorkGrant.evidenceSetDigest,
          grantCandidateDigest: implementationWorkGrant.grantCandidateDigest,
          grantIri: implementationWorkGrant.grantIri,
          nonPublicationDependencySetDigest: implementationWorkGrant.nonPublicationDependencySetDigest,
          predecessorCommit: scopeForRepository.predecessorCommit,
          predecessorTree: scopeForRepository.predecessorTree,
          repository: scopeForRepository.repository,
        });
        if (implementationWorkGrantBinding
            && jcs(implementationWorkGrantBinding) !== jcs(effectiveImplementationWorkGrantBinding)) {
          actionState = ACTION_STATES.block;
          actionStateReasons = [...new Set([...actionStateReasons, 'implementation-work-grant-plan-binding-stale'])].sort();
          implementationWorkGrant = null;
          effectiveImplementationWorkGrantBinding = null;
        } else {
          actionState = ACTION_STATES.proceed;
          actionStateReasons = [];
          effectiveContext = Object.freeze({
            ...context,
            authorisedPaths: grantVerdict.authorisedPaths,
            authorisedRepositories: Object.freeze([implementationWorkRepository]),
            contract: Object.freeze({
              ...context.contract,
              authorisedRepository: implementationWorkRepository,
            }),
          });
        }
      } else {
        actionState = ACTION_STATES.block;
        actionStateReasons = [...new Set([
          ...actionStateReasons,
          ...grantVerdict.failures.map((item) => item.code),
        ])].sort();
      }
    }
  }
  return Object.freeze({
    context: effectiveContext,
    scope,
    validation,
    currentness,
    // The owner that produced this verdict travels with it, so a consumer
    // cannot re-derive satisfaction under a different owner than the one the
    // bracket resolved.
    owner,
    actionState,
    actionStateReasons,
    stateFailureCode: REALISATION_STATE_FAILURE_CODES[actionState] ?? null,
    authorityConflictBinding,
    conflictResolution,
    implementationWorkGrant,
    implementationWorkGrantBinding: effectiveImplementationWorkGrantBinding,
    // The bracketing witness. Any later read that claims to describe the same
    // authority must still equal this exactly.
    witness,
  });
}

export async function projectContract(ctx, args = {}) {
  const contract = args.contract || CONTRACT;
  // The verdict is ALWAYS derived here. It was previously accepted from `args`,
  // and `callTool` performs no schema validation, so a caller could supply a
  // whole verdict and bypass resolveOwnerBoundary -- the only ownership
  // resolution on this path. `authorised`, `authorisedActions`,
  // `authorisedRepositories` and `authorisedPaths` are all computed from it, so
  // that injection handed the caller its own authority. No production caller
  // ever passed it.
  const verdict = await realisationVerdict(ctx, { contract });
  const { context, scope } = verdict;
  const [assertions, requirements, obligations] = await Promise.all([
    ctx.client.select(`SELECT ?relation ?id WHERE { <${context.contract.id}> ?relation ?id . FILTER(?relation IN (<urn:usf:ontology:asserts>, <urn:usf:ontology:disclaims>)) } ORDER BY ?relation ?id LIMIT 256`),
    ctx.client.select(`SELECT DISTINCT ?id WHERE { { ?id a <urn:usf:ontology:EvidenceRequirement> ; <urn:usf:ontology:obligationFor> <${context.contract.id}> } UNION { ?obligation <urn:usf:ontology:obligationFor> <${context.contract.id}> ; <urn:usf:ontology:requiresEvidence> ?id . ?id a <urn:usf:ontology:EvidenceRequirement> } } ORDER BY ?id LIMIT 256`),
    ctx.client.select(`SELECT DISTINCT ?id WHERE { ?id a <urn:usf:ontology:ProofObligation> ; <urn:usf:ontology:obligationFor> <${context.contract.id}> } ORDER BY ?id LIMIT 256`),
  ]);
  // The verdict was bracketed; these three projection queries ran after it, so
  // their closing witness must still equal the verdict witness exactly — digest,
  // graph count and triple total, not the digest alone.
  assertWitnessUnchanged(
    verdict.witness,
    witnessSummary(await authorityWitness(ctx.client)),
    'agent task packet projection',
  );
  const ids = (rows) => [...new Set(rows.map((row) => value(row, 'id')).filter(Boolean))].sort();
  const validationIds = scope.obligations.map((item) => item.id).sort();
  // Realisation authority comes from the one shared verdict, so this packet and
  // the plan tools can never disagree about the same contract.
  const { actionState: realisationActionState, actionStateReasons, validation, currentness, owner } = verdict;
  // Validation remediation is a distinct, narrower authority surface.  When
  // every realisation blocker is exactly an activated validation obligation
  // lacking a current passing result, project a read-only analysis scope.  The
  // materialisation verdict remains BLOCK, so no repository or authority write
  // is thereby authorised and the layout tools continue to refuse mutation.
  const readOnlyValidation = validation.validationActionState === ACTION_STATES.proceed
    && actionStateReasons.length > 0
    && actionStateReasons.every((code) => code === 'missing-current-passing-validation');
  const actionState = readOnlyValidation ? ACTION_STATES.proceed : realisationActionState;
  const authorised = actionState === ACTION_STATES.proceed && !readOnlyValidation;

  const proofFacts = currentness.facts;
  const proofResultCores = (proofFacts.perProof ?? []).map((item) => {
    if (!item.proofResult
      || !item.obligation
      || !item.algorithm
      || !item.algorithmSourceDigest
      || !item.algorithmVersion
      || !item.implementationSourceSetDigest
      || !item.dependencySetDigest
      || !item.evidenceSetDigest
      || !Array.isArray(item.evidence)
      || !item.authorityBinding
      || !item.authorityBindingRule
      || !item.evaluatedAuthorityDigest) {
      throw new Error(`contract execution scope requires an exact proof chain for ${item.proofResult ?? 'unknown result'}`);
    }
    return {
      schema: 'urn:usf:schema:proof-result-content-binding:1',
      proofResult: item.proofResult,
      proofResultState: item.proofResultState,
      obligation: item.obligation,
      algorithm: item.algorithm,
      algorithmSourceDigest: item.algorithmSourceDigest,
      algorithmVersion: item.algorithmVersion,
      implementationSourceSetDigest: item.implementationSourceSetDigest,
      dependencySetDigest: item.dependencySetDigest,
      evidenceSetDigest: item.evidenceSetDigest,
      evidence: [...item.evidence].sort(),
      authorityBinding: item.authorityBinding,
      authorityBindingRule: item.authorityBindingRule,
      reevaluationState: item.reevaluationState ?? null,
      evaluatedAuthorityDigest: item.evaluatedAuthorityDigest,
      settledAuthorityDigest: item.settledAuthorityDigest ?? null,
    };
  }).sort((left, right) => left.proofResult.localeCompare(right.proofResult));
  if (proofResultCores.length === 0) {
    // Requiring a V1 proof chain is a V1-OWNER requirement, not a universal one.
    // Under terminal native V2 there is no V1 proof result to name -- the
    // execution scope is warranted by the native validation-currentness head --
    // so demanding one made projectContract throw unconditionally after the
    // handover, taking a required consumer and a live MCP tool with it.
    // Every non-terminal owner still fails closed.
    if (owner?.ownershipState !== OWNERSHIP.terminal) {
      throw new Error('contract execution scope requires at least one exact proof chain');
    }
  }

  const proofCurrentness = {
    state: currentness.state,
    stateIri: currentness.stateIri,
    reasons: currentness.reasons,
    proofResults: [...proofFacts.proofResults],
    mandatoryObligations: [...proofFacts.mandatoryObligations],
    obligationProofResults: proofFacts.obligationProofResults.map((item) => ({ ...item })),
    perProof: proofResultCores.map((core) => {
      const proofResultDigest = digest(jcs(core));
      const projected = {
        ...core,
        proofResultDigest,
        currentAuthorityDigest: context.authorityDigest,
      };
      delete projected.schema;
      return projected;
    }),
  };
  // The execution-scope schema's single anchor is its canonical content
  // identity. Each owner supplies that anchor in ITS OWN canonical
  // representation -- there is no translation between them, no adapter and no
  // default. Missing or invalid current data fails closed on both branches.
  //
  // V1: the exact proof-obligation bijection above has already gated CURRENT;
  // this member is not a proof selection.
  // Terminal V2: there is no V1 proof result to name. The anchor is the native
  // validation-currentness head, which occupies exactly the same role.
  let scopeAnchor;
  if (owner?.ownershipState === OWNERSHIP.terminal) {
    const head = owner.nativeValidationCurrentness ?? null;
    const obligationIri = proofCurrentness.mandatoryObligations[0] ?? null;
    if (!head
      || typeof head.digest !== 'string'
      || typeof head.proof_result_digest !== 'string'
      || typeof head.semantic_scope_digest !== 'string'
      || typeof owner.terminalAuthorityDigest !== 'string'
      || !obligationIri) {
      throw new Error('terminal V2 execution scope requires the exact native validation-currentness head');
    }
    scopeAnchor = {
      obligation: obligationIri,
      baseAuthorityDigest: owner.terminalAuthorityDigest,
      proofIri: `${NATIVE_VALIDATION_CURRENTNESS_IRI_PREFIX}${head.digest.slice('sha256:'.length)}`,
      proofDigest: head.proof_result_digest,
    };
  } else {
    const scopePair = proofCurrentness.obligationProofResults[0];
    const scopeProof = scopePair
      ? proofCurrentness.perProof.find((item) => item.proofResult === scopePair.proofResult) ?? null
      : null;
    if (!scopeProof || scopeProof.obligation !== scopePair.obligation) {
      throw new Error('contract execution scope requires one canonical member of the exact proof-obligation set');
    }
    scopeAnchor = {
      obligation: scopeProof.obligation,
      baseAuthorityDigest: scopeProof.evaluatedAuthorityDigest,
      proofIri: scopeProof.proofResult,
      proofDigest: scopeProof.proofResultDigest,
    };
  }

  const scopeMode = readOnlyValidation ? READ_ONLY_VALIDATION_MODE : MATERIALISATION_MODE;
  const scopeCore = readOnlyValidation ? {
    schema: EXECUTION_SCOPE_SCHEMA,
    obligationIri: scopeAnchor.obligation,
    contractIri: context.contract.id,
    decisionIri: context.contract.decision,
    modeIri: scopeMode,
    permittedActionIris: ['urn:usf:executionaction:semanticvalidation'],
    permittedActionCount: 1,
    permittedTools: ['list_paths', 'read_file'],
    permittedToolCount: 2,
    readableResourceIris: [
      'urn:usf:executionresource:authorisedsemanticsnapshot',
      'urn:usf:executionresource:contractprojection',
      'urn:usf:executionresource:semanticpacket',
    ],
    readableResourceCount: 3,
    writePaths: [],
    writePathCount: 0,
    permittedEffectIris: ['urn:usf:executioneffect:validationevidencecandidate'],
    permittedEffectCount: 1,
    repositoryMutationPermitted: false,
    maximumRepositoryWrites: 0,
    prepublicationBaseAuthorityDigest: scopeAnchor.baseAuthorityDigest,
    prepublicationProofIri: scopeAnchor.proofIri,
    prepublicationProofDigest: scopeAnchor.proofDigest,
    payloadSchemaIri: EXECUTION_SCOPE_PAYLOAD_SCHEMA.schema,
    payloadSchemaDigest: digest(jcs(EXECUTION_SCOPE_PAYLOAD_SCHEMA)),
    predicateManifestDigest: digest(jcs(EXECUTION_SCOPE_PREDICATE_MANIFEST)),
  } : {
    schema: EXECUTION_SCOPE_SCHEMA,
    obligationIri: scopeAnchor.obligation,
    contractIri: context.contract.id,
    decisionIri: context.contract.decision,
    modeIri: scopeMode,
    permittedActionIris: ['urn:usf:executionaction:repositorymaterialisation'],
    permittedActionCount: 1,
    permittedTools: ['read_file', 'write_file'],
    permittedToolCount: 2,
    readableResourceIris: ['urn:usf:executionresource:repositorysource'],
    readableResourceCount: 1,
    writePaths: [...context.authorisedPaths].sort(),
    writePathCount: context.authorisedPaths.length,
    permittedEffectIris: ['urn:usf:executioneffect:repositorymutation'],
    permittedEffectCount: 1,
    repositoryMutationPermitted: true,
    maximumRepositoryWrites: MAX_OPERATIONS,
    prepublicationBaseAuthorityDigest: scopeAnchor.baseAuthorityDigest,
    prepublicationProofIri: scopeAnchor.proofIri,
    prepublicationProofDigest: scopeAnchor.proofDigest,
    payloadSchemaIri: EXECUTION_SCOPE_PAYLOAD_SCHEMA.schema,
    payloadSchemaDigest: digest(jcs(EXECUTION_SCOPE_PAYLOAD_SCHEMA)),
    predicateManifestDigest: digest(jcs(EXECUTION_SCOPE_PREDICATE_MANIFEST)),
  };
  const scopeDigest = digest(jcs(scopeCore));
  const scopeIri = `urn:usf:contractexecutionscope:${scopeDigest.slice('sha256:'.length)}`;
  const scopeProjection = {
    scopeIri,
    scopeDigest,
    scopeCore,
    liveProjectionAuthorityDigest: context.authorityDigest,
    currentProofIri: scopeAnchor.proofIri,
    currentProofDigest: scopeAnchor.proofDigest,
  };
  const scopeProjectionDigest = digest(jcs(scopeProjection));
  const executionScope = {
    ...scopeProjection,
    scopeProjectionRef: `cas://sha256/${scopeProjectionDigest.slice('sha256:'.length)}`,
    scopeProjectionDigest,
  };

  // A fail-closed projection may identify the proof that caused the block, but
  // it must not expose an execution grant.  Consumers other than the Factory
  // must not be able to mistake a stale projected scope for current authority.
  const projectedExecutionScope = actionState === ACTION_STATES.proceed ? executionScope : null;

  const packet = {
    schemaVersion: 3,
    contract: context.contract.id,
    acceptedDecisionIri: context.contract.decision,
    executionScope: projectedExecutionScope,
    semanticIdentifiers: [
      context.contract.id,
      context.contract.decision,
      ...(projectedExecutionScope ? [scopeIri] : []),
      ...proofCurrentness.mandatoryObligations,
      ...proofCurrentness.proofResults,
      ...validationIds,
    ].filter(Boolean).sort(),
    authorityDigest: context.authorityDigest,
    contractState: { lifecycle: context.contract.lifecycleState, activation: context.contract.activationState, decision: context.contract.decisionState, proof: context.contract.proofResultState, decisionResolution: context.decisionResolution },
    // Proof currentness is projected explicitly. Neither the graph nor the
    // factory has to infer it from prose or from a successful result state.
    proofCurrentness,
    actionState,
    actionStateReasons,
    objective: args.objective || `Realise and validate ${context.contract.canonicalName} from current semantic authority.`,
    claims: ids(assertions.filter((row) => value(row, 'relation') === 'urn:usf:ontology:asserts')),
    nonclaims: ids(assertions.filter((row) => value(row, 'relation') === 'urn:usf:ontology:disclaims')),
    authorisedActions: authorised ? [...ACTIONS] : [],
    authorisedRepositories: authorised ? context.authorisedRepositories : [],
    authorisedPaths: authorised ? context.authorisedPaths : [],
    authorisedFormats: authorised ? [...context.authorisedFormats] : [],
    acceptanceObligations: [...new Set([...ids(requirements), ...ids(obligations)])].sort(),
    validationApplicability: {
      state: scope.applicability,
      declared: scope.applicability !== null,
      reasonDeclared: typeof scope.applicabilityReason === 'string' && scope.applicabilityReason.length > 0,
      exemptionAuthorityProven: scope.exemptionAuthorityProven,
      conditionCount: scope.conditionCount,
    },
    validationObligations: scope.obligations.map((item) => ({
      id: item.id,
      activation: item.activation,
      satisfactionCurrent: satisfactionCurrent(item, verdict.witness, verdict.owner),
      recordedSatisfactionCount: item.satisfactions.length,
    })),
    validationActionState: validation.validationActionState,
    validationSatisfied: validation.validationSatisfied,
    validationGaps: validation.gaps.map((gap) => ({ code: gap.code, subject: gap.subject, disposition: resolveDisposition(gap.code) })),
    resultRequirements: ['return changed paths and their digests', 'return every validation result and stable result code', 'return explicit nonclaims and residual risk'],
    stopConditions: [
      'authority digest changed',
      'contract or decision is not active',
      'actionState is not PROCEED',
      'path, format, action, or storage class is not authorised',
      'required evidence is missing, stale, invalid, or unknown',
      'payload digest or signature verification fails',
      'validationSatisfied is false and the task would claim validation',
    ],
    bounds: { maximumSerializedBytes: MAX_PACKET_BYTES, maximumItems: MAX_PACKET_ITEMS },
  };
  const itemCount = Object.values(packet).reduce((count, item) => count + (Array.isArray(item) ? item.length : 1), 0);
  if (itemCount > MAX_PACKET_ITEMS) throw new Error('agent task packet exceeds item bound');
  packet.itemCount = itemCount;
  packet.packetDigest = digest(jcs(packet));
  packet.serializedBytes = 0;
  for (;;) {
    const measured = bounded(packet, MAX_PACKET_BYTES, 'agent task packet');
    if (measured === packet.serializedBytes) break;
    packet.serializedBytes = measured;
  }
  return packet;
}

export async function planWork(ctx, args = {}) {
  const contract = await resolveContract(ctx.client, args.contract || CONTRACT);
  const offset = Number.isInteger(args.offset) && args.offset >= 0 ? args.offset : 0;
  if (offset > 10_000) throw new Error('work-plan offset exceeds bounded maximum');
  const pageSize = 50;
  const before = await authorityWitness(ctx.client);
  const authorityWitnessValue = witnessSummary(before);
  const authorityDigest = authorityWitnessValue.digest;
  const [proofRows, scope, mandatoryRows] = await Promise.all([
    ctx.client.select(`SELECT ?subject WHERE {
      <${contract}> <urn:usf:ontology:mandatoryProofObligation> ?subject .
      FILTER NOT EXISTS {
        <${contract}> <urn:usf:ontology:reliesOnProofResult> ?result .
        ?result <urn:usf:ontology:proofResultForObligation> ?subject ;
          <urn:usf:ontology:hasProofResultState> <urn:usf:proofresultstate:successful> .
      }
    } ORDER BY ?subject LIMIT 1024`),
    validationScope(ctx.client, contract),
    ctx.client.select(`SELECT ?obligation WHERE { <${contract}> <urn:usf:ontology:mandatoryProofObligation> ?obligation } ORDER BY ?obligation LIMIT 64`),
  ]);
  // The gap census consumes the same currentness conclusion the realisation
  // verdict does. Checking only hasProofResultState here is what let a stale
  // proof read as no gap at all.
  //
  // Which owner answers "is this current" is resolved first. Before the handover
  // it is the V1 proof lifecycle; after D2 it is the native V2 validation
  // currentness head. The census structure, codes and dispositions below are
  // identical either way — only the decision source moves.
  const owner = await resolveOwnerBoundary(ctx);
  const currentness = await ownerBoundaryCurrentness(ctx, owner, contract,
    mandatoryRows.map((row) => value(row, 'obligation')).filter(Boolean));
  const after = await authorityWitness(ctx.client);
  assertWitnessUnchanged(authorityWitnessValue, witnessSummary(after), 'work plan read');

  const verdict = validationVerdict(contract, scope, authorityWitnessValue, owner);
  const all = [
    ...proofRows.map((row) => ({ code: 'missing-successful-proof', subject: value(row, 'subject') })),
    ...(currentness.state === PROOF_CURRENTNESS.current
      ? []
      : currentness.reasons.map((code) => ({ code, subject: currentness.facts.proofResult ?? contract }))),
    ...verdict.gaps,
  ]
    .map(({ code, ...gap }) => ({ ...gap, type: code, disposition: resolveDisposition(code) }))
    .sort((left, right) => (left.type === right.type ? left.subject.localeCompare(right.subject) : left.type.localeCompare(right.type)));

  // The census is computed over the whole gap set, never over the page, so
  // paginating the projection cannot drop a blocked or unresolved state.
  const dispositionCounts = Object.fromEntries(ACTION_STATE_PRECEDENCE.map((state) => [state, all.filter((gap) => gap.disposition === state).length]));
  const present = ACTION_STATE_PRECEDENCE.filter((state) => dispositionCounts[state] > 0);
  const actionState = all.length === 0 ? ACTION_STATES.proceed : strongestState(present);
  const page = all.slice(offset, offset + pageSize);
  return {
    schemaVersion: 2,
    authorityDigest,
    contract,
    offset,
    pageSize,
    gapCount: all.length,
    truncated: offset + page.length < all.length,
    nextOffset: offset + page.length < all.length ? offset + page.length : null,
    gaps: page,
    dispositionCounts,
    actionState,
    validationApplicability: scope.applicability,
    validationSatisfied: verdict.validationSatisfied,
    proofCurrentness: { state: currentness.state, stateIri: currentness.stateIri, reasons: currentness.reasons },
    evaluatedFamilies: ['mandatory-proof-obligation', 'proof-currentness', 'validation-applicability', 'validation-obligation'],
    // An empty gap set is a statement about the families listed above at this
    // authority digest. It is never a completion claim, and this projection
    // grants no authority to create, close or schedule anything.
    completionClaim: false,
    issueProjectionAuthority: false,
  };
}

export function refuseLifecycleMutation(operation) {
  throw new Error(`${operation} is coordinator-only and must be realised by editing registered authored semantic source and running the compiler's validated single transaction; MCP never performs direct RDF mutation`);
}

export const materialisationConstants = Object.freeze({ CONTRACT, MAX_PLAN_BYTES, MAX_OPERATIONS, MAX_PACKET_BYTES, MAX_PACKET_ITEMS, MAX_TRACKED_WRITE_BYTES });
// Re-exported from the pure module so the gateway's own tests exercise the one
// shared implementation rather than a gateway-private copy of it.
export const materialisationInternals = Object.freeze({
  assertNoSymlinkSegments,
  containedBy,
  evaluateAuthorityConflictResolution,
  evaluateImplementationWorkGrantProjection,
  normaliseImplementationWorkGrantBinding,
  normaliseImplementationWorkGrantProjection,
  normaliseAuthorityConflictBinding,
  rethrowWithRollback,
  validationNonPublicationDependencyDigest,
});
