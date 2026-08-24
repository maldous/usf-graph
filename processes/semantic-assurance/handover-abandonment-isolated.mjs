// Isolated-rehearsal harness for the governed handover abandonment.
//
// It builds a REAL Stardog client -- real transactions, real SHACL, real commit -- against a
// WRITE-CONTAINED rehearsal database, and it is mechanically incapable of writing to live
// authority: the live database name and any name outside the contained pattern are refused
// before a connection is constructed, not merely discouraged by convention.
import { createStardogSemanticAuthorityClient } from '../../provider-bindings/stardog/semantic-authority.mjs';
import { validateSemanticAuthorityConfiguration } from '../../configuration/semantic-assurance/semantic-authority.mjs';

export const ISOLATED_DATABASE_PATTERN = /^usfAbandonRehearsal[A-Za-z0-9]*$/;

export const ISOLATED_TOKEN_REFERENCE = 'secret://usf/rehearsal/stardog-token';

// The database options a faithful rehearsal substrate MUST carry.
//
// Asserted-triple fidelity is not behavioural fidelity. A database seeded to the exact live
// authority digest still answered every integrity rule differently, because `query.all.graphs`
// decides whether an unqualified query sees the union of named graphs -- without it, 11099
// references read as unresolved in a database whose asserted content was digest-identical to
// live. Reasoning and schema flags matter for the same reason. These are part of the fidelity
// contract, not tuning.
export const ISOLATED_DATABASE_OPTIONS = Object.freeze({
  'auto.schema.reasoning': true,
  'graphql.auto.schema': true,
  'preserve.bnode.ids': true,
  'query.all.graphs': true,
});

export class IsolationViolationError extends Error {}

// The single containment gate. Everything that can reach a write path goes through here.
export function assertIsolatedDatabase(database, { liveDatabase } = {}) {
  if (typeof database !== 'string' || !ISOLATED_DATABASE_PATTERN.test(database)) {
    throw new IsolationViolationError(
      `ISOLATION_VIOLATION: ${String(database)} is not a contained rehearsal database`);
  }
  if (liveDatabase !== undefined && database === liveDatabase) {
    throw new IsolationViolationError(
      'ISOLATION_VIOLATION: the rehearsal database name equals the live database name');
  }
  return database;
}

export async function createIsolatedAuthorityClient({
  endpoint, database, token, expectedAuthorityDigest, liveDatabase, sdk,
}) {
  assertIsolatedDatabase(database, { liveDatabase });
  const configuration = validateSemanticAuthorityConfiguration({
    accessMode: 'live',
    expectedAuthorityDigest,
    endpoint,
    database,
    authentication: { mode: 'token', tokenReference: ISOLATED_TOKEN_REFERENCE },
  });
  // Double gate: the resolved configuration is re-checked after validation, so a configuration
  // that changed shape between the two points cannot slip a live database through.
  assertIsolatedDatabase(configuration.database, { liveDatabase });
  return createStardogSemanticAuthorityClient({
    sdk: sdk ?? (await import('stardog')).default,
    configuration,
    resolveSecret: (reference) => {
      if (reference !== ISOLATED_TOKEN_REFERENCE) {
        throw new Error(`unexpected secret reference ${reference}`);
      }
      return token;
    },
  });
}

// Replace the whole isolated database with an exact export, inside one real transaction.
export async function seedIsolatedDatabase(client, inventory) {
  const transaction = await client.begin();
  try {
    await client.clearGraphs(transaction, inventory.map(({ graph }) => graph));
    for (const { graph, nquads } of inventory) {
      if (nquads.trim()) {
        await client.addData(transaction, nquads, 'application/n-triples', graph);
      }
    }
    await client.commit(transaction);
  } catch (error) {
    try { await client.rollback(transaction); } catch { /* already gone */ }
    throw error;
  }
}

// Create the contained rehearsal database with the exact fidelity option set. Refuses any
// database name outside containment before issuing a request.
export async function createIsolatedDatabase({ endpoint, database, token, liveDatabase, fetchImpl = fetch }) {
  assertIsolatedDatabase(database, { liveDatabase });
  const base = String(endpoint).replace(/\/$/u, '');
  const headers = { Authorization: `Bearer ${token}` };
  const existing = await fetchImpl(`${base}/admin/databases`, {
    headers: { ...headers, Accept: 'application/json' },
  });
  const names = JSON.parse(await existing.text()).databases ?? [];
  if (names.includes(database)) return { created: false, database };
  const body = new FormData();
  body.append('root', JSON.stringify({
    dbname: database, options: { ...ISOLATED_DATABASE_OPTIONS }, files: [],
  }));
  const response = await fetchImpl(`${base}/admin/databases`, { method: 'POST', headers, body });
  if (!response.ok) {
    throw new Error(`isolated database creation failed: HTTP ${response.status}`);
  }
  return { created: true, database };
}

// Prove the rehearsal database answers the SAME integrity rules as live. This is the check whose
// absence let a digest-identical database behave completely differently.
export async function assertIntegrityRuleParity(liveClient, isolatedClient, rules) {
  const divergent = [];
  for (const rule of rules) {
    const [live, isolated] = await Promise.all([
      liveClient.select(rule.sparql), isolatedClient.select(rule.sparql),
    ]);
    if (live.length !== isolated.length) {
      divergent.push({ rule: rule.file, live: live.length, isolated: isolated.length });
    }
  }
  if (divergent.length > 0) {
    throw new Error(`ISOLATION_FIDELITY: integrity rules diverge: ${JSON.stringify(divergent)}`);
  }
  return true;
}
