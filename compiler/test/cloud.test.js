// Opt-in cloud integration tests for the USF semantic compiler.
//
// These require a configured Stardog Cloud endpoint in the environment and are
// NOT run by `npm test`. Run explicitly with `npm run test:cloud` after
// sourcing credentials. They use a transaction and roll it back, never create
// a database, and never clear the whole database.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadConfig } from '../src/config.js';
import { loadManifest, managedGraphs } from '../src/manifest.js';
import { createClient } from '../src/stardog.js';
import { verify } from '../src/compiler.js';
import { proveLiveRollback } from '../src/live-attestation.js';

const GRAPH_DIR = process.env.USF_GRAPH_DIR || join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'graph');
const configured = Boolean(process.env.STARDOG_SERVER && (process.env.STARDOG_TOKEN || process.env.STARDOG_PASSWORD));
const opts = { skip: configured ? false : 'set STARDOG_* to run cloud tests' };

test('cloud: the SDK connects to the configured endpoint', opts, async () => {
  const client = createClient(loadConfig());
  const triples = await client.connectivity();
  assert.equal(typeof triples, 'number');
});

test('cloud: verify reports a reachable, conformant database', opts, async () => {
  const client = createClient(loadConfig());
  const manifest = loadManifest(GRAPH_DIR);
  const report = await verify({ manifest, client });
  assert.equal(report.reachable, true);
  assert.equal(report.validationConforms, true);
  assert.equal(report.integrityConforms, true);
  assert.equal(report.contaminationCount, 0);
  assert.deepEqual(report.missingGraphs, []);
  assert.deepEqual(report.unexpectedGraphs, []);
  assert.ok(report.readinessCount > 0);
});

test('cloud: clearing a graph inside a transaction is undone by rollback', opts, async () => {
  const client = createClient(loadConfig());
  const manifest = loadManifest(GRAPH_DIR);
  const target = managedGraphs(manifest).find((g) => g.includes('derived:readiness'));
  const count = (rows) => (rows.length ? Number(rows[0].c.value) : 0);
  const q = `SELECT (COUNT(*) AS ?c) WHERE { GRAPH <${target}> { ?s ?p ?o } }`;

  const before = count(await client.select(q));
  assert.ok(before > 0, 'expected readiness graph to be populated');

  const tx = await client.begin();
  try {
    await client.clearGraph(tx, target);
    assert.equal(count(await client.selectInTx(tx, q)), 0, 'graph should be empty inside the tx');
  } finally {
    await client.rollback(tx);
  }

  const after = count(await client.select(q));
  assert.equal(after, before, 'rollback must restore the graph unchanged');
});

test('cloud: every compiler failure barrier rolls back without graph drift', { ...opts, timeout: 300_000 }, async () => {
  const client = createClient(loadConfig());
  const manifest = loadManifest(GRAPH_DIR);
  const result = await proveLiveRollback({ manifest, client });
  assert.equal(result.ok, true);
  assert.equal(result.faultCount, 15);
  assert.equal(result.digestsUnchanged, true);
  assert.ok(result.faults.every((fault) => fault.rollbackCount === 1 && fault.activationCount > 0));
  assert.equal(result.commitOutcomeCoverage.mode, 'pre-dispatch-only');
  assert.equal(result.commitOutcomeCoverage.ambiguousPostDispatchOutcomeProven, false);
});
