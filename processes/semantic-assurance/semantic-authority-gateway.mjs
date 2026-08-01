import { createHash } from 'node:crypto';

import {
  canonicalGraphDigest,
  canonicalInventoryGraphDigest,
} from '../../capabilities/semantic-model-compilation/compiler.mjs';

const ACCEPTED = 'urn:usf:decisionstate:accepted';
const CONTRACT_REFERENCE = /^(?:urn:usf:[a-z0-9:._-]+|[a-z][a-z0-9]*)$/;
const value = (row, key) => row[key]?.value ?? null;

export function semanticAuthorityInventoryDigest(inventory, triples) {
  if (!Array.isArray(inventory) || !Number.isSafeInteger(triples) || triples < 0) {
    throw new Error('semantic authority witness inventory and triple count are required');
  }
  const body = inventory.map((record) => {
    if (typeof record?.graph !== 'string' || typeof record?.sha256 !== 'string' || !Number.isSafeInteger(record?.triples) || record.triples < 0) {
      throw new Error('semantic authority witness contains an invalid graph record');
    }
    const graphDigest = record.sha256.startsWith('sha256:') ? record.sha256.slice(7) : record.sha256;
    if (!/^[0-9a-f]{64}$/.test(graphDigest)) throw new Error('semantic authority graph digest is invalid');
    return `${record.graph}=${graphDigest}:${record.triples}`;
  }).sort().join('\n');
  return `sha256:${createHash('sha256').update(`${body}\ntotal=${triples}`).digest('hex')}`;
}

// The witness total is the sum of the canonical per-graph inventory, never a
// server statement statistic. db.size (exposed as both client.size() and
// client.connectivity()) is eventually consistent: immediately after a commit
// transaction it over-reports, and because the total is folded into the digest
// body as a trailing `total=<n>` term, a transient count produced a different
// digest over byte-identical content. Deriving the total from the inventory
// makes the witness a pure function of graph content.
export const WITNESS_TOTAL_SOURCE = 'canonical-graph-inventory';

function inventoryTotal(inventory) {
  return inventory.reduce((total, record) => total + record.triples, 0);
}

export async function readSemanticAuthorityWitness(client) {
  if (!client || typeof client.select !== 'function' || typeof client.construct !== 'function') {
    throw new Error('semantic authority witness requires select and construct operations');
  }
  const rows = await client.select('SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } } ORDER BY ?g');
  if (!Array.isArray(rows)) throw new Error('semantic authority witness response is invalid');
  const graphs = rows.map((row) => value(row, 'g'));
  if (graphs.some((graph) => typeof graph !== 'string' || graph.length === 0) || new Set(graphs).size !== graphs.length) {
    throw new Error('semantic authority witness graph inventory is invalid');
  }
  graphs.sort();
  const inventory = [];
  for (const graph of graphs) {
    const content = await client.construct(`CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`, 'application/n-quads');
    const [record, dependencyRecord] = await Promise.all([
      canonicalGraphDigest(content), canonicalInventoryGraphDigest(graph, content),
    ]);
    if (record.triples > 0) inventory.push({ graph, ...record, dependencySha256: dependencyRecord.sha256 });
  }
  const triples = inventoryTotal(inventory);
  if (!Number.isSafeInteger(triples) || triples < 0) throw new Error('semantic authority witness inventory total is invalid');
  return Object.freeze({
    algorithm: 'sha256-rdfc10-graph-inventory-v2',
    totalSource: WITNESS_TOTAL_SOURCE,
    digest: semanticAuthorityInventoryDigest(inventory, triples),
    inventory: Object.freeze(inventory),
    triples,
  });
}

// Normalise a witness digest to its exact `sha256:` form.
function authorityDigest(witness) {
  const digest = witness?.digest || witness?.authorityDigest;
  if (typeof digest !== 'string') throw new Error('authority witness is missing its digest');
  return digest.startsWith('sha256:') ? digest : `sha256:${digest}`;
}

// Witness-only surface. The duplicated planning/validation/materialisation API
// that used to live here has been DELETED, not merely left uncalled.
//
// It reconstructed its own layout context and decision selection and then called
// createMaterialisationPlan / validateMaterialisationPlan / materialisePlan
// directly, so it never consumed the shared realisationVerdict: it enforced
// neither the semantic lifecycle conjunct nor any validation state, and its own
// tests proved coordinator apply succeeded through it. A second tested
// materialisation decision path is a bypass whether or not MCP happens to call it.
//
// The canonical and only executable materialisation decision path is
// processes/semantic-assurance/repository-materialisation-gateway.mjs, where
// realisationVerdict brackets the complete semantic read with before/after
// inventory witnesses and every plan, validation and apply surface consumes it.
// A structural regression fails if another production materialisation
// implementation reappears.
export function createSemanticAuthorityGateway({ client, readAuthorityWitness }) {
  if (!client || typeof client.select !== 'function') throw new Error('semantic authority client is required');
  if (typeof readAuthorityWitness !== 'function') throw new Error('authority witness reader is required');

  return Object.freeze({
    // Liveness and the inventory-derived content witness. Both numbers are named
    // for what they are: the witness total is content-derived and authoritative,
    // the server statistic is eventually consistent and is liveness only.
    async health() {
      const [serverStatementStatistic, witness] = await Promise.all([client.connectivity(), readAuthorityWitness(client)]);
      const observedDigest = authorityDigest(witness);
      if (client.expectedAuthorityDigest && client.expectedAuthorityDigest !== observedDigest) throw new Error('observed semantic authority digest differs from configured digest');
      return {
        triples: witness.triples,
        totalSource: witness.totalSource,
        serverStatementStatistic,
        authorityDigest: observedDigest,
      };
    },
  });
}
