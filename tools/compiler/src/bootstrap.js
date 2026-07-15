// Bounded evidence-first semantic bootstrap packet for the USF MCP surface.
// Every semantic item carries its IRI; focused packets expose the canonical
// model -> evidence -> proof -> contract -> realisation -> validation trace.

import { createHash } from 'node:crypto';

const ONT = 'urn:usf:ontology:';
export const BOOTSTRAP_TRACE = 'model -> evidence -> proof -> contract -> realisation -> validation';
export const MAX_BOOTSTRAP_BYTES = 8 * 1024;
export const MAX_BOOTSTRAP_BINDINGS = 50;
export const MAX_BOOTSTRAP_DEPTH = 3;
const DIGEST_ALGORITHM = 'sha256-graph-count-inventory-v1';
const QUERY_IDENTITY = 'usf_bootstrap:contract:evidence-first:v1';
const ITEM_KEYS = [
  'modelResources', 'claims', 'nonClaims', 'evidenceRequirements', 'evidenceResults',
  'proofObligations', 'proofEvaluations', 'proofResults', 'contracts', 'realisations',
  'realisationDecisions', 'validationObligations', 'validationExecutions',
  'validationResults', 'supportingFacets', 'openGaps',
];

export function validContractRef(ref) {
  return typeof ref === 'string' && (/^[a-z0-9]+$/.test(ref) || /^urn:usf:[a-z0-9:_-]+$/i.test(ref));
}

export function authorityDigest(inventory, triples) {
  const body = inventory.map((g) => `${g.graph}=${g.triples}`).sort().join('\n');
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

export async function authorityWitness(client) {
  const [triples, rows] = await Promise.all([
    client.size(),
    client.select('SELECT ?g (COUNT(*) AS ?triples) WHERE { GRAPH ?g { ?s ?p ?o } } GROUP BY ?g ORDER BY ?g LIMIT 50'),
  ]);
  const inventory = rows.map((row) => ({ graph: val(row, 'g'), triples: Number(val(row, 'triples')) }));
  return { triples, inventory, digest: authorityDigest(inventory, triples) };
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
  const before = await authorityWitness(client);
  const authority = {
    database: config.database,
    digest: before.digest,
    digestAlgorithm: DIGEST_ALGORITHM,
    coveredGraphCount: before.inventory.length,
    triples: before.triples,
    verificationState: 'verified-stable-diagnostic-count-witness',
  };
  if (!contract) {
    const rows = await client.select(`SELECT ?id ?canonicalName WHERE { ?id a <${ONT}SemanticContract> ; <${ONT}canonicalName> ?canonicalName } ORDER BY ?canonicalName LIMIT 50`);
    const after = await authorityWitness(client);
    if (before.digest !== after.digest) throw new Error('live authority changed while building bootstrap packet');
    const source = {
      found: true, traceability: BOOTSTRAP_TRACE, authority,
      modelResources: rows.map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName']])),
      claims: [], nonClaims: [], evidenceRequirements: [], evidenceResults: [], proofObligations: [], proofEvaluations: [], proofResults: [], contracts: [], realisations: [], realisationDecisions: [], validationObligations: [], validationExecutions: [], validationResults: [], supportingFacets: [], openGaps: [],
      task: clip(task || null),
    };
    return boundPacket(source, { digest: before.digest, parametersDigest: sha256(JSON.stringify({ contract: null, task: task || null })), offset: 0 });
  }
  const bind = contract.startsWith('urn:usf:') ? `FILTER(STR(?c) = "${contract}")` : `FILTER(?cn = "${contract}")`;
  const core = await client.select(`SELECT ?c ?cn ?state ?reason ?superseded WHERE {
    ?c a <${ONT}SemanticContract> ; <${ONT}canonicalName> ?cn . ${bind}
    OPTIONAL { ?c <${ONT}hasActivationState> ?state }
    OPTIONAL { ?c <${ONT}activationReason> ?reason }
    OPTIONAL { ?c <${ONT}supersededBy> ?superseded }
  } LIMIT 1`);
  if (core.length === 0) return { found: false, contract, task: clip(task || null), authority };
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
    client.select(`SELECT DISTINCT ?id ?canonicalName WHERE { ?id a <${ONT}ValidationObligation> ; <${ONT}validationForContract> <${iri}> . OPTIONAL { ?id <${ONT}canonicalName> ?canonicalName } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?obligation ?environment WHERE { ?id a <${ONT}ValidationExecution> ; <${ONT}executesValidationObligation> ?obligation . ?obligation <${ONT}validationForContract> <${iri}> . OPTIONAL { ?id <${ONT}validationExecutionEnvironment> ?environment } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?execution ?state ?evidence WHERE { ?id a <${ONT}ValidationResult> ; <${ONT}resultOfValidationExecution> ?execution . ?execution <${ONT}executesValidationObligation> ?obligation . ?obligation <${ONT}validationForContract> <${iri}> . OPTIONAL { ?id <${ONT}validationResultState> ?state } OPTIONAL { ?id <${ONT}entersEvidenceLifecycleAs> ?evidence } } ORDER BY ?id LIMIT 50`),
    client.select(`SELECT DISTINCT ?id ?kind ?status ?statement WHERE { <${iri}> <${ONT}declaresFacet> ?id . OPTIONAL { ?id <${ONT}facetKind> ?kind } OPTIONAL { ?id <${ONT}facetStatus> ?status } OPTIONAL { ?id <${ONT}facetStatement> ?statement } } ORDER BY ?id LIMIT 50`),
  ]);
  const mappedRealisations = realisations.map((row) => item(row, [['id', 'id'], ['state', 'state', short], ['implementation', 'implementation'], ['decision', 'decision'], ['authorisedSourcePath', 'path']]));
  const mappedEvidence = evidence.map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName'], ['admissionState', 'admission', short], ['freshnessState', 'freshness', short], ['integrityState', 'integrity', short], ['applicableToObligation', 'obligation'], ['contentDigest', 'digest'], ['provenance', 'provenance']]));
  const mappedResults = results.map((row) => item(row, [['id', 'id'], ['obligation', 'obligation'], ['state', 'state', short], ['evidenceSetDigest', 'evidenceSetDigest'], ['confidenceState', 'confidence', short], ['confidenceBasis', 'confidenceBasis'], ['uncertainty', 'uncertainty', clip]]));
  const contractState = short(val(core[0], 'state'));
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
    validationObligations: validationObligations.map((row) => item(row, [['id', 'id'], ['canonicalName', 'canonicalName']])),
    validationExecutions: validationExecutions.map((row) => item(row, [['id', 'id'], ['obligation', 'obligation'], ['environment', 'environment']])),
    validationResults: validationResults.map((row) => item(row, [['id', 'id'], ['execution', 'execution'], ['state', 'state', short], ['evidence', 'evidence']])),
    supportingFacets: facets.map((row) => item(row, [['id', 'id'], ['kind', 'kind', short], ['status', 'status', short], ['statement', 'statement', clip]])),
    openGaps: [
      ...(contractState === 'proofblocked' ? [{ id: iri, code: 'contract-proof-blocked' }] : []),
      ...(mappedEvidence.length === 0 ? [{ id: iri, code: 'evidence-unavailable' }] : []),
      ...(mappedResults.length === 0 ? [{ id: iri, code: 'proof-result-unavailable' }] : []),
      ...(!mappedRealisations.some((value) => value.state === 'implementable') ? [{ id: iri, code: 'realisation-not-implementable' }] : []),
      ...(validationResults.length === 0 ? [{ id: iri, code: 'validation-result-unavailable' }] : []),
    ],
    task: clip(task || null),
  };
  const after = await authorityWitness(client);
  if (before.digest !== after.digest) throw new Error('live authority changed while building bootstrap packet');
  const parametersDigest = sha256(JSON.stringify({ contract, task: task || null }));
  const offset = continuationOffset(continuation, before.digest, parametersDigest);
  return boundPacket(source, { digest: before.digest, parametersDigest, offset });
}
