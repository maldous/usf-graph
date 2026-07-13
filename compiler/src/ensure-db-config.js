// Ensure the USF database carries the options the compiler and the graph
// integrity rules require:
//
//   query.all.graphs = true          so cross-graph SPARQL — notably the
//                                     integrity rule's default-graph
//                                     `FILTER NOT EXISTS { ?s ?p ?o }` reference
//                                     closure — sees definitions that live in
//                                     named graphs. With the Stardog default
//                                     (false) every cross-graph reference reads
//                                     as unresolved.
//   transaction.isolation = SERIALIZABLE   for the guarded single-transaction
//                                     write model.
//
// A dropped/recreated database returns to Stardog defaults (false / SNAPSHOT),
// so provisioning must reassert these before `compile`. Idempotent: the database
// is only taken offline when an option actually needs changing. Credentials are
// never logged, persisted, or placed in errors (see config.js / stardog.js).

import stardog from 'stardog';
import { loadConfig, describeConfig } from './config.js';

const { Connection, db } = stardog;

const REQUIRED = Object.freeze({
  'query.all.graphs': true,
  'transaction.isolation': 'SERIALIZABLE',
});

// Confirm an SDK response succeeded without stringifying credentials or bodies.
function ok(res, op) {
  if (res && res.ok) return res;
  throw new Error(`Stardog ${op} failed (status ${res ? res.status : undefined})`);
}

const emit = (obj) => process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
const query = Object.fromEntries(Object.keys(REQUIRED).map((key) => [key, '']));
const differs = (current) => Object.keys(REQUIRED).filter((key) => String(current[key]) !== String(REQUIRED[key]));

async function main() {
  const config = loadConfig();
  const conn = new Connection(
    config.auth.kind === 'token'
      ? { endpoint: config.endpoint, token: config.auth.token }
      : { endpoint: config.endpoint, username: config.auth.username, password: config.auth.password }
  );
  const database = config.database;

  const current = ok(await db.options.get(conn, database, query), 'options.get').body;
  const changed = differs(current);
  if (changed.length === 0) {
    emit({ command: 'ensure-db-config', target: describeConfig(config), changed: [], options: current });
    return 0;
  }

  // Index/isolation options require the database offline; always bring it back.
  ok(await db.offline(conn, database), 'offline');
  try {
    ok(await db.options.set(conn, database, REQUIRED), 'options.set');
  } finally {
    ok(await db.online(conn, database), 'online');
  }

  const verified = ok(await db.options.get(conn, database, query), 'options.get').body;
  if (differs(verified).length) throw new Error(`database options were not applied: ${differs(verified).join(', ')}`);
  emit({ command: 'ensure-db-config', target: describeConfig(config), changed, options: verified });
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    emit({ ok: false, error: err.name || 'Error', message: err.message });
    process.exit(1);
  });
