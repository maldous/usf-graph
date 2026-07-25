// Reproducible provisioning of the USF semantic-authority endpoint.
//
// Stardog Cloud Free reclaims an endpoint after a fixed inactivity window. When
// that happens the hostname loses its DNS address record and every authority
// operation fails closed. This process rebuilds the database on a replacement
// endpoint from tracked repository source alone.
//
// Scope boundary, deliberately narrow:
//
//   * Database creation is infrastructure provisioning and is performed here.
//   * Loading semantic graphs is a semantic mutation and is NOT performed here.
//     It is delegated to the canonical compiler publication transaction
//     (`npm run publish:authority`), because GOAL.md forbids issuing graph
//     mutations through any ad hoc script, CLI or raw HTTP path.
//
// Nothing in this file invents a configuration value. Every parameter is either
// recovered from tracked source (and labelled RECOVERED) or is an explicit
// Stardog server default that the repository never recorded (labelled
// SERVER_DEFAULT). The distinction is printed on every run so a reconstructed
// endpoint is never mistaken for a byte-faithful restoration of the original.
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import stardog from 'stardog';

import { loadConfig, describeConfig } from '../../configuration/semantic-assurance/stardog-connection.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

// ---------------------------------------------------------------------------
// Recovered configuration
// ---------------------------------------------------------------------------

// The manifest is the authoritative record of which named graphs constitute the
// authority and in what order they load. It is read rather than duplicated.
export function readManifestFacts(root = repositoryRoot) {
  const text = readFileSync(join(root, 'semantic-model', 'manifest.yaml'), 'utf8');
  const database = /^database:\s*(\S+)\s*$/mu.exec(text)?.[1];
  const baseIri = /^baseIri:\s*"([^"]+)"/mu.exec(text)?.[1];
  const entries = [...text.matchAll(
    /-\s+file:\s*(\S+)\s*\n\s+graph:\s*"([^"]+)"\s*\n\s+loadOrder:\s*(\d+)/gu,
  )].map(([, file, graph, loadOrder]) => ({ file, graph, loadOrder: Number(loadOrder) }));
  if (!database || entries.length === 0) throw new Error('manifest did not yield a database and graph set');
  return {
    baseIri,
    database,
    fileEntryCount: entries.length,
    namedGraphs: [...new Set(entries.map(({ graph }) => graph))].sort(),
  };
}

// Provenance of every provisioning parameter. RECOVERED values come from
// tracked source; SERVER_DEFAULT values were never recorded anywhere in the
// repository and are therefore whatever the server chooses. They are listed
// explicitly so the discrepancy report can state what could not be restored.
export function provisioningParameters(manifestFacts) {
  return {
    recovered: {
      baseIri: manifestFacts.baseIri,
      database: manifestFacts.database,
      namedGraphCount: manifestFacts.namedGraphs.length,
      providerClass: 'stardogcloudfree',
      stardogUsername: 'USF',
    },
    // Options the database MUST have. These are not cosmetic: without them a
    // restored endpoint fails the canonical publication in ways whose error
    // messages point somewhere else entirely.
    required: {
      // rules/integrity.rq tests unresolved references with
      // FILTER NOT EXISTS { ?subject ?p2 ?o2 } and no GRAPH clause, so it reads
      // the default graph. Unless the default graph is the union of the named
      // graphs, that filter always succeeds and every referenced urn:usf: IRI
      // is reported as an unresolved reference — 20 spurious violations against
      // IRIs that are correctly declared in vocabulary.ttl. This was never
      // recorded anywhere and cost a full diagnosis cycle to rediscover.
      'query.all.graphs': true,
    },
    serverDefault: {
      // The repository records no database-creation options anywhere: no
      // reasoning schema, no index strategy, no search configuration, no
      // preserve-bnode-ids, no strict-parsing setting. Creation therefore uses
      // server defaults, and any option that was originally set at creation
      // time and is immutable CANNOT be restored from this repository.
      creationOptions: {},
      note: 'no creation-time database options are recorded in tracked source',
    },
    notRecovered: [
      'database creation options (including any immutable options)',
      'additional users beyond the connecting account',
      'roles and permission grants',
      'reasoning schema declarations',
      'search/index configuration',
    ],
  };
}

// ---------------------------------------------------------------------------
// Endpoint operations
// ---------------------------------------------------------------------------

function client(config) {
  return new stardog.Connection({
    endpoint: config.endpoint,
    ...(config.auth.kind === 'token'
      ? { token: config.auth.token }
      : { username: config.auth.username, password: config.auth.password }),
  });
}

export async function endpointReachable(conn) {
  try {
    const res = await stardog.server.status(conn);
    return Boolean(res?.ok);
  } catch {
    return false;
  }
}

export async function databaseExists(conn, database) {
  const res = await stardog.db.list(conn);
  if (!res?.ok) throw new Error(`could not list databases (status ${res?.status})`);
  const names = res.body?.databases ?? [];
  return names.includes(database);
}

// Create the database with server defaults. Options are passed as an explicit
// empty object rather than omitted, so the call site records that "no options"
// is a decision grounded in the absence of recorded options, not an oversight.
export async function createDatabase(conn, database, options = {}) {
  const res = await stardog.db.create(conn, database, options, { name: database });
  if (!res?.ok) throw new Error(`database creation failed (status ${res?.status})`);
  return true;
}

// Verify the options publication depends on. Reported rather than enforced:
// Stardog Cloud Free accepts the PUT and silently keeps the old value, so the
// only reliable remedy is the portal. Surfacing the exact option beats letting
// the canonical publication fail later with unrelated-looking integrity errors.
export async function checkRequiredOptions(conn, database, required) {
  const res = await stardog.db.options.getAll(conn, database);
  if (!res?.ok) throw new Error(`could not read database options (status ${res?.status})`);
  const observed = res.body ?? {};
  const unsatisfied = Object.entries(required)
    .filter(([key, expected]) => String(observed[key]).toLowerCase() !== String(expected).toLowerCase())
    .map(([key, expected]) => ({ key, expected, observed: observed[key] ?? null }));
  return { ok: unsatisfied.length === 0, unsatisfied };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const apply = process.argv.includes('--apply');
  try {
    const facts = readManifestFacts();
    const parameters = provisioningParameters(facts);
    const config = loadConfig();
    const described = describeConfig(config);
    const conn = client(config);

    const reachable = await endpointReachable(conn);
    const report = {
      command: 'provision-authority-endpoint',
      mode: apply ? 'apply' : 'dry-run',
      endpoint: described.endpoint,
      database: described.database,
      authMode: described.authMode,
      reachable,
      parameters,
      manifestNamedGraphs: facts.namedGraphs.length,
    };

    if (!reachable) {
      process.stdout.write(`${JSON.stringify({
        ...report,
        outcome: 'ENDPOINT_UNREACHABLE',
        nextAction: 'provision a replacement Stardog Cloud endpoint and set STARDOG_SERVER/STARDOG_TOKEN, then re-run',
      }, null, 2)}\n`);
      process.exitCode = 1;
    } else {
      const exists = await databaseExists(conn, facts.database);
      let created = false;
      if (!exists && apply) {
        created = await createDatabase(conn, facts.database, parameters.serverDefault.creationOptions);
      }
      const options = exists || created
        ? await checkRequiredOptions(conn, facts.database, parameters.required)
        : { ok: false, unsatisfied: [{ key: 'database', expected: 'present', observed: null }] };
      process.stdout.write(`${JSON.stringify({
        ...report,
        databaseExisted: exists,
        databaseCreated: created,
        requiredOptions: options,
        outcome: !options.ok
          ? 'REQUIRED_OPTIONS_UNSATISFIED'
          : exists || created ? 'DATABASE_READY' : 'DATABASE_ABSENT_DRY_RUN',
        // Graph loading is deliberately not performed here.
        nextAction: exists || created
          ? 'load all graphs through the canonical path: npm run publish:authority:validate then npm run publish:authority'
          : 're-run with --apply to create the database',
      }, null, 2)}\n`);
    }
  } catch (error) {
    process.stderr.write(`${error.code ?? error.name}: ${error.message}\n`);
    process.exitCode = 1;
  }
}
