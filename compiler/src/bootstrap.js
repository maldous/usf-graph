// Bounded semantic bootstrap packet for the USF MCP surface.
//
// usf_bootstrap gives an agent the minimum context to start a task from the
// live Stardog authority rather than from graph files or a census:
//   - no focus  -> authority summary: live-state digest, graph inventory,
//                  key-class census, and a bounded contract index to pick from;
//   - a contract -> the model->facet->obligation->contract->realisation trace
//                  for that one contract, each list bounded.
//
// All reads go through the client (stardog.js SDK boundary). The contract
// reference is validated before interpolation so it cannot break out of the
// query.

import { createHash } from 'node:crypto';

const ONT = 'urn:usf:ontology:';
const KEY_CLASSES = [
  'SemanticContract', 'Capability', 'Realisation', 'Claim', 'NonClaim',
  'ContractFacet', 'ProofObligation', 'TestObligation', 'EvidenceRequirement',
  'AssuranceObligation', 'Proof', 'ProofResult', 'Test', 'ValidatorRule', 'Shape',
];

// A contract reference is either a canonical-name slug or a urn:usf: IRI.
// Anything else is refused, which also blocks SPARQL injection through the
// interpolated value.
export function validContractRef(ref) {
  return typeof ref === 'string' && (/^[a-z0-9]+$/.test(ref) || /^urn:usf:[a-z0-9:_-]+$/i.test(ref));
}

// A cheap, deterministic fingerprint of live state: the per-graph triple counts
// plus the total. Not the census digest — a live-state witness for cache keys.
export function authorityDigest(inventory, triples) {
  const body = inventory
    .map((g) => `${g.graph}=${g.triples}`)
    .sort()
    .join('\n');
  return createHash('sha256').update(`${body}\ntotal=${triples}`).digest('hex');
}

const val = (row, k) => (row[k] ? row[k].value : null);
const short = (s) => (typeof s === 'string' ? s.replace(/^urn:usf:[a-z]+:/i, '') : s);
// Keep the packet near the 8 KiB orientation budget: statements orient, they
// are not the authority. The full text is one usf_query away.
const clip = (s, n = 240) => (typeof s === 'string' && s.length > n ? `${s.slice(0, n)}…` : s);

export async function bootstrapPacket(ctx, { contract, task } = {}) {
  const { client, config } = ctx;

  if (contract) {
    if (!validContractRef(contract)) {
      const err = new Error('invalid contract reference (expected a canonical-name slug or urn:usf: IRI)');
      err.userFacing = true;
      throw err;
    }
    const bind = contract.startsWith('urn:usf:')
      ? `FILTER(STR(?c) = "${contract}")`
      : `FILTER(?cn = "${contract}")`;
    const core = await client.select(
      `SELECT ?c ?cn ?state ?superseded WHERE {
        ?c a <${ONT}SemanticContract> ; <${ONT}canonicalName> ?cn .
        ${bind}
        OPTIONAL { ?c <${ONT}semanticLifecycleState> ?state }
        OPTIONAL { ?c <${ONT}supersededBy> ?superseded }
      } LIMIT 1`
    );
    if (core.length === 0) return { found: false, contract, task: task || null };
    const iri = val(core[0], 'c');

    const [assertions, facets, realisations, obligations] = await Promise.all([
      client.select(`SELECT ?rel ?cn WHERE { <${iri}> ?rel ?x . FILTER(?rel IN (<${ONT}asserts>, <${ONT}disclaims>)) OPTIONAL { ?x <${ONT}canonicalName> ?cn } } LIMIT 50`),
      client.select(`SELECT ?kind ?status ?stmt WHERE { <${iri}> <${ONT}declaresFacet> ?f . OPTIONAL { ?f <${ONT}facetKind> ?kind } OPTIONAL { ?f <${ONT}facetStatus> ?status } OPTIONAL { ?f <${ONT}facetStatement> ?stmt } } LIMIT 25`),
      client.select(`SELECT ?state ?impl ?svc WHERE { ?r <${ONT}realisesContract> <${iri}> . OPTIONAL { ?r <${ONT}realisationState> ?state } OPTIONAL { ?r <${ONT}realisingImplementation> ?impl } OPTIONAL { ?r <${ONT}viaService> ?svc } } LIMIT 25`),
      client.select(`SELECT ?type ?rung ?gate WHERE { ?ob <${ONT}obligationFor> <${iri}> ; a ?type . FILTER(?type IN (<${ONT}ProofObligation>, <${ONT}TestObligation>, <${ONT}EvidenceRequirement>, <${ONT}AssuranceObligation>)) OPTIONAL { ?ob <${ONT}requiresRung> ?rung } OPTIONAL { ?ob <${ONT}requiredByGate> ?gate } } LIMIT 50`),
    ]);

    return {
      found: true,
      traceability: 'model -> facet -> obligation -> contract -> realisation',
      contract: { iri, canonicalName: val(core[0], 'cn'), lifecycleState: short(val(core[0], 'state')), supersededBy: short(val(core[0], 'superseded')) },
      claims: assertions.filter((r) => val(r, 'rel').endsWith('asserts')).map((r) => short(val(r, 'cn'))).filter(Boolean),
      nonClaims: assertions.filter((r) => val(r, 'rel').endsWith('disclaims')).map((r) => short(val(r, 'cn'))).filter(Boolean),
      facets: facets.map((r) => ({ kind: short(val(r, 'kind')), status: short(val(r, 'status')), statement: clip(val(r, 'stmt')) })),
      realisations: realisations.map((r) => ({ state: short(val(r, 'state')), implementation: short(val(r, 'impl')), viaService: short(val(r, 'svc')) })),
      obligations: obligations.map((r) => ({ type: short(val(r, 'type')), rung: short(val(r, 'rung')), gate: short(val(r, 'gate')) })),
      task: task || null,
    };
  }

  // No focus: authority orientation.
  const describe = { endpoint: config.endpoint, database: config.database, authMode: config.auth.kind };
  const triples = await client.size();
  const [inv, census, contracts] = await Promise.all([
    client.select('SELECT ?g (COUNT(*) AS ?triples) WHERE { GRAPH ?g { ?s ?p ?o } } GROUP BY ?g ORDER BY ?g'),
    client.select(`SELECT ?c (COUNT(?x) AS ?n) WHERE { VALUES ?c { ${KEY_CLASSES.map((c) => `<${ONT}${c}>`).join(' ')} } ?x a ?c } GROUP BY ?c`),
    client.select(`SELECT ?cn WHERE { ?c a <${ONT}SemanticContract> ; <${ONT}canonicalName> ?cn } ORDER BY ?cn LIMIT 60`),
  ]);
  const inventory = inv.map((r) => ({ graph: val(r, 'g'), triples: Number(val(r, 'triples')) }));
  return {
    authority: { ...describe, triples, ok: true, digest: authorityDigest(inventory, triples) },
    classCensus: Object.fromEntries(census.map((r) => [short(val(r, 'c')), Number(val(r, 'n'))])),
    graphCount: inventory.length,
    graphs: inventory,
    contractIndex: contracts.map((r) => val(r, 'cn')),
    hint: 'call usf_bootstrap with { contract: "<canonicalName>" } for a model->realisation trace',
    task: task || null,
  };
}
