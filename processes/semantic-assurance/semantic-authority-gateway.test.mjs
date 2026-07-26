import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';
import test from 'node:test';

import { createSemanticAuthorityGateway, readSemanticAuthorityWitness, semanticAuthorityInventoryDigest } from './semantic-authority-gateway.mjs';

const authorityDigest = `sha256:${'d'.repeat(64)}`;
const binding = (value) => ({ value });
const witness = async () => ({
  digest: authorityDigest,
  algorithm: 'sha256-rdfc10-graph-inventory-v2',
  totalSource: 'canonical-graph-inventory',
  triples: 7,
  inventory: [],
});

// --- the duplicated materialisation API is deleted, not merely uncalled --------
// This module used to expose createPlan / validatePlan / materialise over its own
// layout context and decision selection. It never consumed the shared
// realisationVerdict, so it enforced neither the semantic lifecycle conjunct nor
// any validation state — and the test that lived here proved coordinator apply
// succeeded through it. Those methods are gone; what remains is witness-only.

test('the authority gateway exposes no second materialisation decision path', () => {
  const gateway = createSemanticAuthorityGateway({
    client: { select: async () => [], connectivity: async () => 1 },
    readAuthorityWitness: witness,
  });
  assert.deepEqual(Object.keys(gateway).sort(), ['health']);
  for (const removed of ['createPlan', 'validatePlan', 'materialise', 'layoutContext']) {
    assert.equal(removed in gateway, false, `${removed} must not be exposed here`);
  }
  const source = readFileSync(new URL('./semantic-authority-gateway.mjs', import.meta.url), 'utf8');
  for (const symbol of ['createMaterialisationPlan', 'validateMaterialisationPlan', 'materialisePlan']) {
    assert.equal(source.includes(`${symbol}(`), false, `${symbol} must no longer be called here`);
  }
});

test('health names the content witness and the server statistic distinctly', async () => {
  const gateway = createSemanticAuthorityGateway({
    client: { select: async () => [], connectivity: async () => 577_473 },
    readAuthorityWitness: witness,
  });
  const health = await gateway.health();
  assert.equal(health.authorityDigest, authorityDigest);
  assert.equal(health.triples, 7, 'the content witness total is inventory-derived');
  assert.equal(health.totalSource, 'canonical-graph-inventory');
  assert.equal(health.serverStatementStatistic, 577_473, 'the server statistic is liveness only');
});

test('health fails closed when the observed digest differs from the configured one', async () => {
  const gateway = createSemanticAuthorityGateway({
    client: { expectedAuthorityDigest: `sha256:${'e'.repeat(64)}`, select: async () => [], connectivity: async () => 1 },
    readAuthorityWitness: witness,
  });
  await assert.rejects(() => gateway.health(), /differs from configured digest/);
});

// --- structural regression: exactly one production materialisation path --------

const REPOSITORY_ROOT = fileURLToPath(new URL('../..', import.meta.url));
// Directories that ship executable production behaviour. `assurance/` is excluded
// deliberately: it holds proof harnesses that exercise the engine and are not a
// production surface.
const PRODUCTION_ROOTS = ['capabilities', 'configuration', 'operations', 'processes', 'provider-bindings'];
// The one canonical executable materialisation decision path.
const CANONICAL_GATEWAY = 'processes/semantic-assurance/repository-materialisation-gateway.mjs';
// The lower-level plan/validate/apply engine. It makes no authority decision of its
// own — it is handed an already-decided authority projection — and after this change
// no production module imports its apply capability.
const ENGINE = 'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';
const MATERIALISATION_EXPORTS = /export\s+(?:async\s+)?function\s+(createLayoutPlan|validateLayoutPlan|applyLayoutPlan|createMaterialisationPlan|validateMaterialisationPlan|materialisePlan)\b/g;

function productionModules() {
  const found = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) { walk(absolute); continue; }
      if (!entry.isFile() || !entry.name.endsWith('.mjs') || entry.name.endsWith('.test.mjs')) continue;
      found.push(relative(REPOSITORY_ROOT, absolute).split('\\').join('/'));
    }
  };
  for (const root of PRODUCTION_ROOTS) {
    const absolute = join(REPOSITORY_ROOT, root);
    if (statSync(absolute).isDirectory()) walk(absolute);
  }
  return found;
}

test('exactly one production module exports a materialisation decision path', () => {
  const owners = new Map();
  for (const path of productionModules()) {
    const source = readFileSync(join(REPOSITORY_ROOT, path), 'utf8');
    const exported = [...source.matchAll(MATERIALISATION_EXPORTS)].map((match) => match[1]);
    if (exported.length > 0) owners.set(path, exported.sort());
  }
  // Only the canonical gateway and the engine it is layered over may export these.
  // Anything else is a second decision path and must be deleted or routed through
  // realisationVerdict.
  assert.deepEqual(
    [...owners.keys()].sort(),
    [ENGINE, CANONICAL_GATEWAY].sort(),
    `unexpected materialisation implementations: ${JSON.stringify([...owners.entries()])}`,
  );
  assert.deepEqual(owners.get(CANONICAL_GATEWAY), ['applyLayoutPlan', 'createLayoutPlan', 'validateLayoutPlan']);
  assert.deepEqual(owners.get(ENGINE), ['createMaterialisationPlan', 'materialisePlan', 'validateMaterialisationPlan']);
});

test('no production module can apply a materialisation outside the canonical path', () => {
  const importers = [];
  for (const path of productionModules()) {
    if (path === ENGINE) continue;
    const source = readFileSync(join(REPOSITORY_ROOT, path), 'utf8');
    if (!source.includes('materialisation-plan.mjs')) continue;
    // Importing the engine is only acceptable when it cannot apply; materialisePlan
    // is the apply capability.
    if (/\bmaterialisePlan\b/.test(source)) importers.push(path);
  }
  assert.deepEqual(
    importers,
    [],
    `these production modules can apply outside the canonical gateway: ${importers.join(', ')}`,
  );
});

// --- witness utilities (genuinely shared, retained) ----------------------------

test('builds a deterministic content-sensitive witness from canonical graph bytes', async () => {
  const graphContent = new Map([
    ['urn:usf:graph:a', '<urn:subject:a> <urn:predicate:value> "a" .\n'],
    ['urn:usf:graph:b', '<urn:subject:b> <urn:predicate:value> "b" .\n'],
  ]);
  const witnessClient = {
    connectivity: async () => 2,
    select: async () => [{ g: binding('urn:usf:graph:b') }, { g: binding('urn:usf:graph:a') }],
    construct: async (sparql) => graphContent.get([...graphContent.keys()].find((graph) => sparql.includes(`<${graph}>`))),
  };
  const observed = await readSemanticAuthorityWitness(witnessClient);
  assert.deepEqual(observed.inventory.map(({ graph }) => graph), ['urn:usf:graph:a', 'urn:usf:graph:b']);
  assert.equal(observed.digest, semanticAuthorityInventoryDigest(observed.inventory, 2));
  graphContent.set('urn:usf:graph:b', '<urn:subject:b> <urn:predicate:value> "changed" .\n');
  assert.notEqual((await readSemanticAuthorityWitness(witnessClient)).digest, observed.digest);
});

test('witness construction rejects duplicate graph identities and incomplete clients', async () => {
  await assert.rejects(() => readSemanticAuthorityWitness({}), /select and construct/);
  await assert.rejects(() => readSemanticAuthorityWitness({
    connectivity: async () => 1,
    select: async () => [{ g: binding('urn:usf:graph:a') }, { g: binding('urn:usf:graph:a') }],
    construct: async () => '',
  }), /graph inventory is invalid/);
});
