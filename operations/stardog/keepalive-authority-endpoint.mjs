// Non-destructive liveness touch for the semantic-authority endpoint.
//
// Stardog Cloud Free reclaims an endpoint after a fixed inactivity window. The
// USF endpoint was reclaimed exactly that way: the hostname lost its DNS
// address record and every authority operation began failing closed, which is
// far more expensive to recover from than it is to prevent.
//
// This process issues one bounded read and nothing else. It performs no
// mutation, opens no transaction, writes no file inside the repository and
// prints no credential. It is safe to run on a timer at any frequency.
//
// Run it well inside the inactivity window rather than at its edge, so a single
// failed run cannot cost the endpoint. Every second day is a reasonable cadence
// for a seven-day window.
//
//   node operations/stardog/keepalive-authority-endpoint.mjs
//
// Exit status is 0 when the endpoint answered and 1 when it did not, so a
// scheduler can alert on the failure rather than discovering the loss later.
import stardog from 'stardog';

import { loadConfig, describeConfig } from '../../configuration/semantic-assurance/stardog-connection.mjs';

// A trivial ASK is enough to count as activity and cannot alter state. It is
// preferred over a size or status call because it exercises the query path
// against the actual database rather than only the server process.
const LIVENESS_QUERY = 'ASK { ?s ?p ?o }';

export async function touchEndpoint({ connection, database, query = stardog.query }) {
  const started = Date.now();
  const res = await query.execute(connection, database, LIVENESS_QUERY, 'application/sparql-results+json', {
    limit: 1,
    reasoning: false,
  });
  return {
    ok: Boolean(res?.ok),
    status: res?.status ?? null,
    elapsedMs: Date.now() - started,
  };
}

if (process.argv[1]) {
  try {
    const config = loadConfig();
    const described = describeConfig(config);
    const connection = new stardog.Connection({
      endpoint: config.endpoint,
      ...(config.auth.kind === 'token'
        ? { token: config.auth.token }
        : { username: config.auth.username, password: config.auth.password }),
    });
    const result = await touchEndpoint({ connection, database: config.database });
    process.stdout.write(`${JSON.stringify({
      command: 'keepalive-authority-endpoint',
      endpoint: described.endpoint,
      database: described.database,
      mutating: false,
      ...result,
      observedAt: new Date().toISOString(),
    })}\n`);
    if (!result.ok) process.exitCode = 1;
  } catch (error) {
    // Never surface a credential in a scheduled job's log.
    process.stderr.write(`${JSON.stringify({
      command: 'keepalive-authority-endpoint',
      ok: false,
      error: error?.name ?? 'Error',
      message: String(error?.message ?? '').slice(0, 200),
    })}\n`);
    process.exitCode = 1;
  }
}
