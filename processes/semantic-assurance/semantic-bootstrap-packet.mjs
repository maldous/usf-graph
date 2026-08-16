// Bounded evidence-first semantic bootstrap packet for the USF MCP surface.
// Every semantic item carries its IRI; focused packets expose the canonical
// model -> evidence -> proof -> contract -> realisation -> validation trace.

import { createHash } from 'node:crypto';
import {
  canonicalGraphDigest,
  canonicalInventoryGraphDigest,
} from '../../capabilities/semantic-model-compilation/compiler.mjs';

const ONT = 'urn:usf:ontology:';
export const BOOTSTRAP_TRACE = 'model -> evidence -> proof -> contract -> realisation -> validation';
export const MAX_BOOTSTRAP_BYTES = 8 * 1024;
export const MAX_BOOTSTRAP_BINDINGS = 50;
export const MAX_BOOTSTRAP_DEPTH = 3;
const DIGEST_ALGORITHM = 'sha256-rdfc10-graph-inventory-v2';
const QUERY_IDENTITY = 'usf_bootstrap:contract:evidence-first:v1';
// openGaps leads deliberately. boundPacket fills the byte budget in this order
// and drops from the tail, so a key placed last is the first casualty of
// truncation. Gaps are the packet's negative and unresolved states: dropping
// them turns a bounded packet into a silently clean one.
const ITEM_KEYS = [
  'openGaps', 'modelResources', 'claims', 'nonClaims', 'evidenceRequirements', 'evidenceResults',
  'proofObligations', 'proofEvaluations', 'proofResults', 'contracts', 'realisations',
  'realisationDecisions', 'validationObligations', 'validationExecutions',
  'validationResults', 'supportingFacets',
];
const GAP_EVALUATED = 'evaluated';
const GAP_NOT_EVALUATED = 'not-evaluated-contract-scope-required';
const UNRESOLVED_FAIL_CLOSED = 'UNRESOLVED_FAIL_CLOSED';
const APPLICABILITY_UNRESOLVED = 'urn:usf:validationapplicabilitystate:unresolved';
const APPLICABILITY_REQUIRED = 'urn:usf:validationapplicabilitystate:required';

export function validContractRef(ref) {
  return typeof ref === 'string' && (/^[a-z0-9]+$/.test(ref) || /^urn:usf:[a-z0-9:_-]+$/i.test(ref));
}

export function authorityDigest(inventory, triples) {
  const body = inventory.map((g) => `${g.graph}=${g.sha256}:${g.triples}`).sort().join('\n');
  return createHash('sha256').update(`${body}\ntotal=${triples}`).digest('hex');
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const val = (row, key) => (row[key] ? row[key].value : null);
const short = (value) => (typeof value === 'string' ? value.replace(/^urn:usf:[a-z]+:/i, '') : value);
const clip = (value, size = 240) => (typeof value === 'string' && value.length > size ? `${value.slice(0, size)}…` : value);
const item = (row, fields) => Object.fromEntries(fields.map(([name, key, transform = (x) => x]) => [name, transform(val(row, key))]).filter(([, value]) => value !== null));

function encodeContinuation(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${sha256(body)}`;
}

export function decodeContinuation(token) {
  if (typeof token !== 'string' || !token.includes('.')) throw new Error('invalid bootstrap continuation token');
  const [body, signature, extra] = token.split('.');
  if (extra !== undefined || sha256(body) !== signature) throw new Error('invalid bootstrap continuation token');
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    throw new Error('invalid bootstrap continuation token');
  }
}

// Total comes from the canonical inventory, not client.size(). db.size is
// eventually consistent after a commit transaction, and the total is folded into
// the digest body, so a transient count yielded a different digest over
// byte-identical content. See WITNESS_TOTAL_SOURCE in the authority gateway.
export const WITNESS_TOTAL_SOURCE = 'canonical-graph-inventory';

// The Graph owner boundary, shared by every production projection in this
// repository. It lives here because this module sits below the gateway in the
// dependency order; both owners must resolve ownership identically or a handover
// could be observed differently by two projections of the same authority.
//
// Before the D2 fence the V1 proof/publication lifecycle owns actionability.
// After it, the native V2 generation and its renewable validation-currentness
// head do, and V1 is never consulted again.
// The first three are determinate observations of durable admitted state. The
// last two are resolution outcomes that are explicitly NOT an owner: an absent
// observer, an unavailable reader or a malformed observation must never be read
// as "V1 owns this". Unknown ownership refuses.
export const OWNERSHIP = Object.freeze({
  v1: 'V1_OWNER',
  pending: 'V2_HANDOVER_PENDING',
  terminal: 'V2_TERMINAL_OWNER',
  unresolved: 'UNRESOLVED',
  invalid: 'INVALID',
});
export const NATIVE_VALIDATION_CURRENT = 'CURRENT';

export const PRETERMINAL_OWNER_BOUNDARY = Object.freeze({
  ownershipState: OWNERSHIP.v1,
  validationCurrentnessState: null,
  terminalAuthorityDigest: null,
  observationIdentityDigest: null,
});

// The composition root supplies the native observation. Neither owner reads
// process.env mid-decision, and absence is never silently promoted to terminal
// — nor demoted to V1. A context without the dependency cannot observe
// ownership at all, so it refuses: "we did not look" is not evidence that V1 is
// the owner, and treating it as such is what lets a retired V1 route execute
// after the fence.
export async function resolveOwnerBoundary(ctx) {
  const observe = ctx?.observeGraphRuntimeOwnership;
  if (typeof observe !== 'function') {
    throw new Error(
      `Graph runtime ownership is ${OWNERSHIP.unresolved}: `
      + 'no ownership observer was supplied by the composition root',
    );
  }
  let observation;
  try {
    observation = await observe();
  } catch (cause) {
    // A reader failure is not a V1 owner either.
    throw new Error(
      `Graph runtime ownership is ${OWNERSHIP.unresolved}: ownership observation failed`,
      { cause },
    );
  }
  const state = observation?.ownership_state ?? null;
  if (state === null) {
    throw new Error(
      `Graph runtime ownership is ${OWNERSHIP.invalid}: observation carries no ownership state`,
    );
  }
  if (state === OWNERSHIP.v1) return PRETERMINAL_OWNER_BOUNDARY;
  if (state === OWNERSHIP.pending) {
    return Object.freeze({
      ownershipState: OWNERSHIP.pending,
      validationCurrentnessState: null,
      terminalAuthorityDigest: null,
      observationIdentityDigest: observation.observation_identity_digest ?? null,
    });
  }
  if (state !== OWNERSHIP.terminal) {
    throw new Error(`Graph runtime ownership observation is not a closed state: ${state}`);
  }
  const currentness = observation.validation_currentness ?? null;
  if (!currentness || typeof currentness.state !== 'string') {
    throw new Error('V2 terminal ownership observation carries no validation currentness state');
  }
  return Object.freeze({
    ownershipState: OWNERSHIP.terminal,
    validationCurrentnessState: currentness.state,
    // The native validation-currentness head travels with the boundary. It is
    // the canonical terminal-V2 anchor for anything that, under V1, anchored on
    // a proof result: same role, native representation, no translation.
    nativeValidationCurrentness: Object.freeze({ ...currentness }),
    terminalAuthorityDigest: observation.authority_digest ?? null,
    observationIdentityDigest: observation.observation_identity_digest ?? null,
  });
}

export async function authorityWitness(client) {
  const rows = await client.select('SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } } ORDER BY ?g');
  const inventory = [];
  for (const row of rows) {
    const graph = val(row, 'g');
    const content = await client.construct(`CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`, 'application/n-quads');
    const [record, dependencyRecord] = await Promise.all([
      canonicalGraphDigest(content), canonicalInventoryGraphDigest(graph, content),
    ]);
    if (record.triples > 0) inventory.push({ graph, ...record, dependencySha256: dependencyRecord.sha256 });
  }
  const triples = inventory.reduce((total, record) => total + record.triples, 0);
  if (!Number.isSafeInteger(triples) || triples < 0) throw new Error('authority witness inventory total is invalid');
  return { triples, inventory, digest: authorityDigest(inventory, triples), totalSource: WITNESS_TOTAL_SOURCE };
}

function measured(packet) {
  let previous = -1;
  for (let i = 0; i < 5; i += 1) {
    const bytes = Buffer.byteLength(JSON.stringify(packet), 'utf8');
    packet.serializedBytes = bytes;
    if (bytes === previous) break;
    previous = bytes;
  }
  return Buffer.byteLength(JSON.stringify(packet), 'utf8');
}

function boundPacket(source, { digest, parametersDigest, offset = 0 }) {
  const flat = ITEM_KEYS.flatMap((key) => (source[key] || []).map((value) => ({ key, value })));
  const packet = { ...source };
  for (const key of ITEM_KEYS) packet[key] = [];
  packet.bounds = { maximumSerializedBytes: MAX_BOOTSTRAP_BYTES, maximumBindings: MAX_BOOTSTRAP_BINDINGS, maximumTraversalDepth: MAX_BOOTSTRAP_DEPTH };
  packet.bindingCount = 0;
  packet.serializedBytes = 0;
  const inserted = [];
  for (const entry of flat.slice(offset, offset + MAX_BOOTSTRAP_BINDINGS)) {
    packet[entry.key].push(entry.value);
    inserted.push(entry);
    packet.bindingCount += 1;
  }
  const finish = () => {
    const nextCursor = offset + inserted.length;
    packet.truncated = nextCursor < flat.length;
    packet.continuation = packet.truncated ? encodeContinuation({ authorityDigest: digest, queryIdentity: QUERY_IDENTITY, parametersDigest, cursor: nextCursor }) : null;
    packet.continuationMetadata = packet.truncated ? { queryIdentity: QUERY_IDENTITY, cursor: nextCursor, authorityDigest: digest } : null;
    return measured(packet);
  };
  while (finish() > MAX_BOOTSTRAP_BYTES && inserted.length > 0) {
    const removed = inserted.pop();
    packet[removed.key].pop();
    packet.bindingCount -= 1;
  }
  if (finish() > MAX_BOOTSTRAP_BYTES) throw new Error('bootstrap metadata exceeds the 8 KiB bound');
  // A first page that cannot carry the complete gap set would present fewer
  // blocking states than the authority holds. Fail closed rather than emit it.
  if (offset === 0 && packet.openGaps.length !== (source.openGaps || []).length) {
    throw new Error('bootstrap packet cannot bound the complete open-gap set');
  }
  return packet;
}

function continuationOffset(token, digest, parametersDigest) {
  if (!token) return 0;
  let decoded;
  try { decoded = decodeContinuation(token); } catch (error) { error.userFacing = true; throw error; }
  if (decoded.authorityDigest !== digest) {
    const error = new Error('bootstrap continuation authority digest no longer matches live state');
    error.userFacing = true;
    throw error;
  }
  if (decoded.queryIdentity !== QUERY_IDENTITY || decoded.parametersDigest !== parametersDigest || !Number.isInteger(decoded.cursor) || decoded.cursor < 0) {
    const error = new Error('bootstrap continuation does not match this query');
    error.userFacing = true;
    throw error;
  }
  return decoded.cursor;
}

export async function bootstrapPacket(ctx, { contract, task, continuation } = {}) {
  const { client, config } = ctx;
  if (contract && !validContractRef(contract)) {
    const error = new Error('invalid contract reference (expected a canonical-name slug or urn:usf: IRI)');
    error.userFacing = true;
    throw error;
  }
  // Resolve the owner before any semantic read, so one packet describes one
  // authority state under one owner and cannot straddle a handover boundary.
  const owner = await resolveOwnerBoundary(ctx);
  const before = await authorityWitness(client);
  const authority = {
    database: config.database,
    digest: before.digest,
    digestAlgorithm: DIGEST_ALGORITHM,
    coveredGraphCount: before.inventory.length,
    triples: before.triples,
    // Names where the total came from, so a consumer can tell a content witness
    // from a server statistic. Only the inventory-derived total is a witness.
    totalSource: before.totalSource,
    verificationState: 'verified-stable-content-sensitive-rdfc10-witness',
  };
  if (!contract) {
    const rows = await client.select(`SELECT ?id ?canonicalName WHERE { ?id a <${ONT}SemanticContract> ; <${ONT}canonicalName> ?canonicalName } ORDER BY ?canonicalName LIMIT 50`);
    const after = await authorityWitness(client);
    if (before.digest !== after.digest) throw new Error('live authority changed while building bootstrap packet');
    // Orientation mode. Nothing per-contract was interrogated, so every
    // obligation and gap array is empty because it was not evaluated — not
    // because live authority holds nothing outstanding. gapEvaluation and
    // actionState say so explicitly; without them an empty openGaps array in
    // this mode reads exactly like a clean contract-scoped one.
    const source = {
      found: true, traceability: BOOTSTRAP_TRACE, authority,
      evaluationScope: 'contract-inventory',
      gapEvaluation: GAP_NOT_EVALUATED,
      actionState: UNRESOLVED_FAIL_CLOSED,
      completionClaim: false,
      modelResources: rows.map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName']])),
      claims: [], nonClaims: [], evidenceRequirements: [], evidenceResults: [], proofObligations: [], proofEvaluations: [], proofResults: [], contracts: [], realisations: [], realisationDecisions: [], validationObligations: [], validationExecutions: [], validationResults: [], supportingFacets: [], openGaps: [],
      task: clip(task || null),
    };
    return boundPacket(source, { digest: before.digest, parametersDigest: sha256(JSON.stringify({ contract: null, task: task || null })), offset: 0 });
  }
  const bind = contract.startsWith('urn:usf:') ? `FILTER(STR(?c) = "${contract}")` : `FILTER(?cn = "${contract}")`;
  const core = await client.select(`SELECT ?c ?cn ?state ?reason ?superseded ?applicability WHERE {
    ?c a <${ONT}SemanticContract> ; <${ONT}canonicalName> ?cn . ${bind}
    OPTIONAL { ?c <${ONT}hasActivationState> ?state }
    OPTIONAL { ?c <${ONT}activationReason> ?reason }
    OPTIONAL { ?c <${ONT}supersededBy> ?superseded }
    OPTIONAL { ?c <${ONT}hasValidationApplicability> ?applicability }
  } LIMIT 8`);
  if (core.length === 0) return { found: false, contract, task: clip(task || null), authority };
  // An ambiguous reference used to be resolved by taking the first row. The
  // packet would then describe one of several contracts without saying which
  // was discarded, so identity has to be exact or the request has to fail.
  const distinctContracts = new Set(core.map((row) => val(row, 'c')));
  if (distinctContracts.size !== 1) {
    const error = new Error('contract reference must resolve to exactly one semantic contract');
    error.userFacing = true;
    throw error;
  }
  const iri = val(core[0], 'c');
  const [assertions, requirements, evidence, obligations, evaluations, results, realisations, decisions, validationObligations, validationExecutions, validationResults, facets] = await Promise.all([
    client.select(`SELECT ?id ?relation ?canonicalName WHERE { <${iri}> ?relation ?id . FILTER(?relation IN (<${ONT}asserts>, <${ONT}disclaims>)) OPTIONAL { ?id <${ONT}canonicalName> ?canonicalName } } ORDER BY ?relation ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?canonicalName ?kind ?freshness WHERE { { ?id a <${ONT}EvidenceRequirement> ; <${ONT}obligationFor> <${iri}> } UNION { ?ob <${ONT}obligationFor> <${iri}> ; <${ONT}requiresEvidence> ?id . ?id a <${ONT}EvidenceRequirement> } OPTIONAL { ?id <${ONT}canonicalName> ?canonicalName } OPTIONAL { ?id <${ONT}requiresEvidenceKind> ?kind } OPTIONAL { ?id <${ONT}requiresFreshness> ?freshness } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?canonicalName ?admission ?freshness ?integrity ?obligation ?digest ?provenance WHERE { ?id a <${ONT}EvidenceResult> . { ?id <${ONT}evidenceForContract> <${iri}> } UNION { ?id <${ONT}evidenceFor> <${iri}> } OPTIONAL { ?id <${ONT}canonicalName> ?canonicalName } OPTIONAL { ?id <${ONT}hasAdmissionState> ?admission } OPTIONAL { ?id <${ONT}hasFreshnessState> ?freshness } OPTIONAL { ?id <${ONT}hasIntegrityState> ?integrity } OPTIONAL { ?id <${ONT}applicableToObligation> ?obligation } OPTIONAL { ?id <${ONT}contentDigest> ?digest } OPTIONAL { ?id <${ONT}wasProducedBy> ?provenance } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?canonicalName ?rung ?requirement WHERE { ?id a <${ONT}ProofObligation> ; <${ONT}obligationFor> <${iri}> . OPTIONAL { ?id <${ONT}canonicalName> ?canonicalName } OPTIONAL { ?id <${ONT}requiresRung> ?rung } OPTIONAL { ?id <${ONT}requiresEvidence> ?requirement } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?obligation ?result WHERE { ?id a <${ONT}ProofEvaluation> ; <${ONT}evaluatesObligation> ?obligation . ?obligation <${ONT}obligationFor> <${iri}> . OPTIONAL { ?id <${ONT}producesProofResult> ?result } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?obligation ?state ?evidenceSetDigest ?confidence ?confidenceBasis ?uncertainty WHERE { ?id a <${ONT}ProofResult> ; <${ONT}proofResultForObligation> ?obligation . ?obligation <${ONT}obligationFor> <${iri}> . OPTIONAL { ?id <${ONT}hasProofResultState> ?state } OPTIONAL { ?id <${ONT}evidenceSetDigest> ?evidenceSetDigest } OPTIONAL { ?id <${ONT}hasConfidenceState> ?confidence } OPTIONAL { ?id <${ONT}confidenceBasis> ?confidenceBasis } OPTIONAL { ?id <${ONT}uncertaintyStatement> ?uncertainty } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?state ?implementation ?decision ?path WHERE { ?id a <${ONT}Realisation> ; <${ONT}realisesContract> <${iri}> . OPTIONAL { ?id <${ONT}realisationState> ?state } OPTIONAL { ?id <${ONT}realisingImplementation> ?implementation } OPTIONAL { ?id <${ONT}authorisedByDecision> ?decision } OPTIONAL { ?id <${ONT}authorisedSourcePath> ?path } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?state ?path ?type ?repository WHERE { ?realisation <${ONT}realisesContract> <${iri}> ; <${ONT}authorisedByDecision> ?id . OPTIONAL { ?id <${ONT}decisionState> ?state } OPTIONAL { ?id <${ONT}authorisesSourcePath> ?path } OPTIONAL { ?id <${ONT}authorisesRealisationType> ?type } OPTIONAL { ?id <${ONT}authorisesRepository> ?repository } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?canonicalName ?activation WHERE { ?id a <${ONT}ValidationObligation> ; <${ONT}validationForContract> <${iri}> . OPTIONAL { ?id <${ONT}canonicalName> ?canonicalName } OPTIONAL { ?id <${ONT}hasValidationActivationState> ?activation } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?obligation ?environment WHERE { ?id a <${ONT}ValidationExecution> ; <${ONT}executesValidation> ?obligation . ?obligation <${ONT}validationForContract> <${iri}> . OPTIONAL { ?id <${ONT}validationEnvironment> ?environment } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?execution ?obligation ?state ?evidence ?evidenceType ?admission ?freshness ?integrity ?within ?applicable ?boundObligation ?boundAuthority ?boundHead ?invalidation ?superseded WHERE { ?id a <${ONT}ValidationResult> . ?execution <${ONT}producesValidationResult> ?id ; <${ONT}executesValidation> ?obligation . ?obligation <${ONT}validationForContract> <${iri}> . OPTIONAL { ?id <${ONT}resultState> ?state } OPTIONAL { ?id <${ONT}resultForValidationObligation> ?boundObligation } OPTIONAL { ?id <${ONT}validationEvaluatedAuthorityDigest> ?boundAuthority } OPTIONAL { ?id <${ONT}validationEvaluatedSourceHead> ?boundHead } OPTIONAL { ?id <${ONT}hasValidationInvalidationCondition> ?invalidation } OPTIONAL { ?id <${ONT}supersededByValidationResult> ?superseded } OPTIONAL { ?id <${ONT}entersEvidenceLifecycleAs> ?evidence . OPTIONAL { ?evidence a ?evidenceType } OPTIONAL { ?evidence <${ONT}hasAdmissionState> ?admission } OPTIONAL { ?evidence <${ONT}hasFreshnessState> ?freshness } OPTIONAL { ?evidence <${ONT}hasIntegrityState> ?integrity } OPTIONAL { ?evidence <${ONT}withinValidityScope> ?within } OPTIONAL { ?evidence <${ONT}applicableToObligation> ?applicable } } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?kind ?status ?statement WHERE { <${iri}> <${ONT}declaresFacet> ?id . OPTIONAL { ?id <${ONT}facetKind> ?kind } OPTIONAL { ?id <${ONT}facetStatus> ?status } OPTIONAL { ?id <${ONT}facetStatement> ?statement } } ORDER BY ?id LIMIT 50`),
  ]);
  const mappedRealisations = realisations.map((row) => item(row, [['id', 'id'], ['state', 'state', short], ['implementation', 'implementation'], ['decision', 'decision'], ['authorisedSourcePath', 'path']]));
  const mappedEvidence = evidence.map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName'], ['admissionState', 'admission', short], ['freshnessState', 'freshness', short], ['integrityState', 'integrity', short], ['applicableToObligation', 'obligation'], ['contentDigest', 'digest'], ['provenance', 'provenance']]));
  const mappedResults = results.map((row) => item(row, [['id', 'id'], ['obligation', 'obligation'], ['state', 'state', short], ['evidenceSetDigest', 'evidenceSetDigest'], ['confidenceState', 'confidence', short], ['confidenceBasis', 'confidenceBasis'], ['uncertainty', 'uncertainty', clip]]));
  // "current" is the satisfaction question, and it is answered by the
  // ValidationObligation satisfaction contract: the result must name this exact
  // obligation, pass, cite the authority and source head it was evaluated
  // against, and be neither invalidated nor superseded. The evidence-admission
  // chain alone was weaker than the contract the model enforces, so a passing
  // result under a reserved obligation used to read as current.
  const mappedValidationResults = validationResults.map((row) => ({
    ...item(row, [['id', 'id'], ['execution', 'execution'], ['state', 'state', short], ['evidence', 'evidence'], ['evidenceType', 'evidenceType'], ['admissionState', 'admission', short], ['freshnessState', 'freshness', short], ['integrityState', 'integrity', short], ['withinValidityScope', 'within'], ['applicableToObligation', 'applicable'], ['resultForValidationObligation', 'boundObligation']]),
    evidenceAdmitted: val(row, 'state') === 'urn:usf:resultstate:passed'
      && val(row, 'evidenceType') === `${ONT}ValidationEvidence`
      && val(row, 'admission') === 'urn:usf:evidenceadmissionstate:admitted'
      && val(row, 'freshness') === 'urn:usf:evidencefreshnessstate:fresh'
      && val(row, 'integrity') === 'urn:usf:evidenceintegritystate:valid'
      && val(row, 'within') === 'true'
      && val(row, 'applicable') === val(row, 'obligation'),
    // Under terminal V2 the same identity contract holds, but WHO decides the
    // result is still current is the native validation-currentness head, not the
    // V1 publication lifecycle. A pending handover has no owner able to conclude
    // anything, so nothing reads as current and the packet fails closed.
    current: owner.ownershipState !== OWNERSHIP.pending
      && (owner.ownershipState !== OWNERSHIP.terminal
        || owner.validationCurrentnessState === NATIVE_VALIDATION_CURRENT)
      && val(row, 'state') === 'urn:usf:resultstate:passed'
      && val(row, 'boundObligation') === val(row, 'obligation')
      && typeof val(row, 'boundAuthority') === 'string'
      && typeof val(row, 'boundHead') === 'string'
      && val(row, 'invalidation') === null
      && val(row, 'superseded') === null,
  }));
  const contractState = short(val(core[0], 'state'));
  const applicability = val(core[0], 'applicability');
  const mappedValidationObligations = validationObligations.map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName'], ['activationState', 'activation', short]]));
  const source = {
    found: true, traceability: BOOTSTRAP_TRACE, authority,
    modelResources: [{ id: iri, type: `${ONT}SemanticContract` }],
    claims: assertions.filter((row) => val(row, 'relation') === `${ONT}asserts`).map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName']])),
    nonClaims: assertions.filter((row) => val(row, 'relation') === `${ONT}disclaims`).map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName']])),
    evidenceRequirements: requirements.map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName'], ['evidenceKind', 'kind', short], ['requiredFreshness', 'freshness', short]])),
    evidenceResults: mappedEvidence,
    proofObligations: obligations.map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName'], ['rung', 'rung', short], ['evidenceRequirement', 'requirement']])),
    proofEvaluations: evaluations.map((row) => item(row, [['id', 'id'], ['obligation', 'obligation'], ['proofResult', 'result']])),
    proofResults: mappedResults,
    contracts: [{ id: iri, canonicalName: val(core[0], 'cn'), activationState: contractState, activationReason: clip(val(core[0], 'reason')), supersededBy: val(core[0], 'superseded'), actionable: mappedRealisations.some((value) => value.state === 'implementable') }],
    realisations: mappedRealisations,
    realisationDecisions: decisions.map((row) => item(row, [['id', 'id'], ['state', 'state', short], ['authorisedSourcePath', 'path'], ['authorisedRealisationType', 'type'], ['authorisedRepository', 'repository']])),
    validationApplicability: applicability,
    validationObligations: mappedValidationObligations,
    validationExecutions: validationExecutions.map((row) => item(row, [['id', 'id'], ['obligation', 'obligation'], ['environment', 'environment']])),
    validationResults: mappedValidationResults,
    supportingFacets: facets.map((row) => item(row, [['id', 'id'], ['kind', 'kind', short], ['status', 'status', short], ['statement', 'statement', clip]])),
    // Facet status is descriptive model coverage. It is deliberately absent
    // from this gap set: a facet marked complete says the model describes the
    // concern, never that the concern is operationally satisfied.
    evaluationScope: 'contract',
    gapEvaluation: GAP_EVALUATED,
    completionClaim: false,
    openGaps: [
      ...(contractState === 'proofblocked' ? [{ id: iri, code: 'contract-proof-blocked' }] : []),
      ...(mappedEvidence.length === 0 ? [{ id: iri, code: 'evidence-unavailable' }] : []),
      ...(mappedResults.length === 0 ? [{ id: iri, code: 'proof-result-unavailable' }] : []),
      ...(!mappedRealisations.some((value) => value.state === 'implementable') ? [{ id: iri, code: 'realisation-not-implementable' }] : []),
      ...(applicability === null || applicability === APPLICABILITY_UNRESOLVED
        ? [{ id: iri, code: 'validation-applicability-unresolved' }] : []),
      ...(applicability === APPLICABILITY_REQUIRED && mappedValidationObligations.length === 0
        ? [{ id: iri, code: 'validation-obligation-unavailable' }] : []),
      ...mappedValidationObligations
        .filter((obligation) => obligation.activationState !== 'activated')
        .map((obligation) => ({ id: obligation.id, code: `validation-obligation-${obligation.activationState || 'activation-unresolved'}` })),
      ...(!mappedValidationResults.some((result) => result.current) ? [{ id: iri, code: 'current-validation-result-unavailable' }] : []),
    ],
    task: clip(task || null),
  };
  const after = await authorityWitness(client);
  if (before.digest !== after.digest) throw new Error('live authority changed while building bootstrap packet');
  const parametersDigest = sha256(JSON.stringify({ contract, task: task || null }));
  const offset = continuationOffset(continuation, before.digest, parametersDigest);
  return boundPacket(source, { digest: before.digest, parametersDigest, offset });
}
