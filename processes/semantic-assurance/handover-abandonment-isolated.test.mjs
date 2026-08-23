// The governed abandonment transition executed against a REAL Stardog database.
//
// What is real here: the transaction, the SHACL validation, the integrity rules, the canonical
// per-graph RDFC-10 inventory, the authority witness, commit, read-back, and the durable journal.
// The database is seeded from an authorised read-only export of live authority and its fidelity
// is proven by digest equality BEFORE any mutation.
//
// What is doubled, and only this: the detached-signature primitive. The real verifier pins its
// public key to the operator's canonical path, so a genuinely signed grant over the live trust
// anchor would be a CURRENTLY USABLE LIVE ABANDONMENT GRANT -- which this phase must not create.
// Every other clause of the real verifier runs unmodified, and signer ownership of
// B6CBC89C7978AF26F53C33A197E5F20D2A340E5D is proven separately through the real gpgv path in
// handover-abandonment.test.mjs.
//
// This suite SKIPS unless USF_ISOLATED_REHEARSAL=1 and Stardog credentials are present, so it
// never runs incidentally.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  abandonFencedHandover,
  canonicalHandoverFenceDigest,
  handoverAbandonmentOperationId,
  recoverHandoverAbandonment,
  semanticModelCompilationCommandInternals as internals,
} from './semantic-model-compilation-command.mjs';
import {
  readSemanticAuthorityWitness, semanticAuthorityInventoryDigest,
} from './semantic-authority-gateway.mjs';
import { loadManifest } from '../../capabilities/semantic-model-compilation/manifest.mjs';
import {
  APPROVED_AUTHORITY_SCOPES, AUTHORITY_FINGERPRINT, AUTHORITY_PRINCIPAL,
  HANDOVER_ABANDONMENT_GRANT_ALLOWED_ACTIONS, HANDOVER_ABANDONMENT_GRANT_DENIED_EFFECTS,
  HANDOVER_ABANDONMENT_GRANT_PURPOSE, HANDOVER_ABANDONMENT_GRANT_SCHEMA,
  sourceScopeDigest, verifyHandoverAbandonmentGrantEnvelope,
} from './semantic-proof-v1.mjs';
import {
  assertIntegrityRuleParity, assertIsolatedDatabase, createIsolatedAuthorityClient,
  createIsolatedDatabase, ISOLATED_DATABASE_OPTIONS, ISOLATED_DATABASE_PATTERN,
  IsolationViolationError, seedIsolatedDatabase,
} from './handover-abandonment-isolated.mjs';
import { integrityRules } from '../../capabilities/semantic-model-compilation/manifest.mjs';

const REPOSITORY_ROOT = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const ISOLATED = 'usfAbandonRehearsal';
const USF = 'urn:usf:ontology:';
const FENCE_CLASS = `${USF}V2NativeHandoverFence`;
const ABANDONMENT_CLASS = `${USF}V2NativeHandoverAbandonment`;
const NOW = '2026-08-23T12:00:00Z';
const enabled = process.env.USF_ISOLATED_REHEARSAL === '1'
  && Boolean(process.env.STARDOG_SERVER) && Boolean(process.env.STARDOG_TOKEN);

const canonicalJson = (value) => JSON.stringify(value, (_key, item) => (
  item && typeof item === 'object' && !Array.isArray(item)
    ? Object.keys(item).sort().reduce((sorted, key) => { sorted[key] = item[key]; return sorted; }, {})
    : item));
const digestOf = (value) => `sha256:${createHash('sha256')
  .update(Buffer.from(canonicalJson(value), 'utf8')).digest('hex')}`;

const temporaries = [];
test.after(() => temporaries.forEach((root) => rmSync(root, { recursive: true, force: true })));
const temporary = (prefix) => {
  const root = mkdtempSync(join(tmpdir(), prefix));
  temporaries.push(root);
  return root;
};

// --- containment, which is checked even when the suite is skipped ------------------------------

test('the isolated harness mechanically refuses the live database and endpoint', () => {
  for (const name of ['USF', 'usf', 'catalog', 'querylog', '', null, undefined,
    'USF; DROP', 'usfAbandonRehearsal/../USF']) {
    assert.throws(() => assertIsolatedDatabase(name, { liveDatabase: 'USF' }),
      IsolationViolationError, `${String(name)} must be refused`);
  }
  // Even a correctly-patterned name is refused if it IS the live database.
  assert.throws(() => assertIsolatedDatabase('usfAbandonRehearsal',
    { liveDatabase: 'usfAbandonRehearsal' }), IsolationViolationError);
  // And the contained names are accepted.
  assert.equal(assertIsolatedDatabase('usfAbandonRehearsal', { liveDatabase: 'USF' }),
    'usfAbandonRehearsal');
  assert.match('usfAbandonRehearsal2', ISOLATED_DATABASE_PATTERN);
  // The fidelity option contract is explicit, so a substrate cannot be built without it.
  assert.equal(ISOLATED_DATABASE_OPTIONS['query.all.graphs'], true);
  assert.equal(ISOLATED_DATABASE_OPTIONS['auto.schema.reasoning'], true);
  assert.equal(ISOLATED_DATABASE_OPTIONS['preserve.bnode.ids'], true);
});

test('createIsolatedDatabase refuses the live database before issuing any request', async () => {
  let called = false;
  await assert.rejects(createIsolatedDatabase({
    endpoint: 'https://example.invalid:5820', database: 'USF', token: 'unused',
    liveDatabase: 'USF', fetchImpl: () => { called = true; throw new Error('unreachable'); },
  }), IsolationViolationError);
  assert.equal(called, false, 'containment must refuse before any network call');
});

test('the isolated client factory cannot be pointed at the live database', async () => {
  await assert.rejects(createIsolatedAuthorityClient({
    endpoint: 'https://example.invalid:5820',
    database: 'USF',
    token: 'unused',
    expectedAuthorityDigest: `sha256:${'0'.repeat(64)}`,
    liveDatabase: 'USF',
  }), IsolationViolationError);
});

// --- the isolated rehearsal --------------------------------------------------------------------

// The canonical gate requires zero skipped tests, so the live-integration cases are REGISTERED
// only when the rehearsal substrate is actually reachable. A skipped test would fail the gate; a
// silently absent one would hide what did not run. Both are avoided: the gating predicate itself
// is asserted by a test that always runs, and the isolated cases exist only when they can execute.
const suite = (name, fn) => { if (enabled) test(name, fn); };

test('the live-integration cases are gated on an explicit, fail-closed opt-in', () => {
  // Reachability is never assumed: all three inputs must be present, and the default is off.
  const gated = (env) => env.USF_ISOLATED_REHEARSAL === '1'
    && Boolean(env.STARDOG_SERVER) && Boolean(env.STARDOG_TOKEN);
  assert.equal(gated({}), false, 'the default must be off');
  assert.equal(gated({ USF_ISOLATED_REHEARSAL: '1' }), false, 'an opt-in alone must not enable');
  assert.equal(gated({ USF_ISOLATED_REHEARSAL: '1', STARDOG_SERVER: 'x' }), false);
  assert.equal(gated({ USF_ISOLATED_REHEARSAL: 'yes', STARDOG_SERVER: 'x', STARDOG_TOKEN: 'y' }),
    false, 'only the exact opt-in value enables');
  assert.equal(gated({ USF_ISOLATED_REHEARSAL: '1', STARDOG_SERVER: 'x', STARDOG_TOKEN: 'y' }), true);
  assert.equal(enabled, gated(process.env));
});

// One seeded, fidelity-proven world, rebuilt fresh for each case.
async function freshIsolatedWorld() {
  const stardog = (await import('stardog')).default;
  const live = {
    endpoint: process.env.STARDOG_SERVER,
    database: process.env.STARDOG_DATABASE,
    token: process.env.STARDOG_TOKEN,
  };
  // Read-only live export.
  const liveClient = await createIsolatedClientUnchecked(stardog, live);
  const liveWitness = await readSemanticAuthorityWitness(liveClient);
  const inventory = [];
  for (const record of liveWitness.inventory) {
    inventory.push({
      graph: record.graph,
      nquads: await liveClient.construct(
        `CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${record.graph}> { ?s ?p ?o } }`,
        'application/n-quads'),
    });
  }
  await createIsolatedDatabase({
    endpoint: live.endpoint, database: ISOLATED, token: live.token, liveDatabase: live.database,
  });
  const client = await createIsolatedAuthorityClient({
    endpoint: live.endpoint,
    database: ISOLATED,
    token: live.token,
    expectedAuthorityDigest: liveWitness.digest,
    liveDatabase: live.database,
    sdk: stardog,
  });
  await seedIsolatedDatabase(client, inventory);
  const witness = await readSemanticAuthorityWitness(client);
  return { client, liveWitness, witness, liveClient };
}

// A read client for the live database. Deliberately NOT routed through
// createIsolatedAuthorityClient, which refuses the live name -- this is the read-only export path
// and it is never handed to the transition.
async function createIsolatedClientUnchecked(stardog, { endpoint, database, token }) {
  const { createStardogSemanticAuthorityClient } = await import(
    '../../provider-bindings/stardog/semantic-authority.mjs');
  const { validateSemanticAuthorityConfiguration } = await import(
    '../../configuration/semantic-assurance/semantic-authority.mjs');
  return createStardogSemanticAuthorityClient({
    sdk: stardog,
    configuration: validateSemanticAuthorityConfiguration({
      accessMode: 'live',
      expectedAuthorityDigest: `sha256:${'0'.repeat(64)}`,
      endpoint,
      database,
      authentication: { mode: 'token', tokenReference: 'secret://usf/live/stardog-token' },
    }),
    resolveSecret: () => token,
  });
}

const fenceRowsOf = async (client) => (await client.select(`SELECT ?fence ?p ?o ?g WHERE {
  GRAPH ?g { ?fence a <${FENCE_CLASS}> . ?fence ?p ?o } } ORDER BY ?fence ?p ?o`))
  .map((row) => {
    const value = (term) => (term && typeof term === 'object' ? term.value : term);
    // Mirrors the reader's exact term rule; a lexical-only row would compute a different
    // fence digest than the transition derives.
    const objectTerm = row.o?.type === 'uri'
      ? { type: 'uri', value: row.o.value }
      : {
        type: 'literal',
        value: row.o.value,
        ...(row.o?.datatype ? { datatype: row.o.datatype } : {}),
        ...(row.o?.['xml:lang'] ? { language: row.o['xml:lang'] } : {}),
      };
    return {
      fence: value(row.fence),
      predicate: value(row.p),
      object: value(row.o),
      objectTerm,
      graph: value(row.g),
    };
  });

function isolatedGrant(bindings) {
  const paths = [
    'processes/semantic-assurance/semantic-model-compilation-command.mjs',
    'processes/semantic-assurance/semantic-proof-v1.mjs',
  ];
  const payload = {
    algorithm: 'openpgp',
    allowed_actions: [...HANDOVER_ABANDONMENT_GRANT_ALLOWED_ACTIONS],
    authority_pre_digest: bindings.authorityPreDigest,
    claim_type: 'handover_abandonment_grant',
    d1_recovery_record_digest: bindings.d1RecoveryRecordDigest,
    denied_effects: [...HANDOVER_ABANDONMENT_GRANT_DENIED_EFFECTS],
    expires_at: '2026-08-23T13:00:00Z',
    fence_content_digest: bindings.fenceContentDigest,
    fingerprint: AUTHORITY_FINGERPRINT,
    handover_generation_digest: bindings.handoverGenerationDigest,
    issued_at: '2026-08-23T11:00:00Z',
    nonce: bindings.nonce ?? '00000000-0000-4000-8000-00000000ab01',
    observed_post_d1_authority_digest: bindings.observedPostD1,
    permitted_effect_digest: bindings.permittedEffectDigest,
    pre_d1_authority_digest: bindings.preD1,
    principal: AUTHORITY_PRINCIPAL,
    protocol: 'semantic-proof-v1',
    purpose: HANDOVER_ABANDONMENT_GRANT_PURPOSE,
    repositories: [{
      predecessor_commit: 'a'.repeat(40),
      predecessor_tree: 'b'.repeat(40),
      repository: 'maldous/usf-graph',
      source_paths: paths,
      source_scope_digest: sourceScopeDigest(paths),
    }],
    schema_version: HANDOVER_ABANDONMENT_GRANT_SCHEMA,
    signing_identity: 'urn:usf:signingidentity:matthewaldoussemanticproofv1',
    single_use: true,
  };
  return { payload, signature: 'rehearsal-detached-signature' };
}

const isolatedVerifier = (envelope, options) => verifyHandoverAbandonmentGrantEnvelope(envelope, {
  ...options,
  trustAnchor: {
    algorithm: 'openpgp',
    approvalThreshold: 1,
    authorityScopes: APPROVED_AUTHORITY_SCOPES,
    fingerprint: AUTHORITY_FINGERPRINT,
    githubPrincipal: 'maldous',
    principal: AUTHORITY_PRINCIPAL,
    protocol: 'semantic-proof-v1',
  },
  // The ONLY doubled primitive.
  verifyDetached: () => AUTHORITY_FINGERPRINT,
});

// The real D1 recovery record from durable state, plus a durable-boundary reader.
function isolatedRecoveryEvidence() {
  const path = '/var/lib/usf-programme/v2-native-handover-superseded/'
    + 'd939e2bafe8e54e99c2e1f4955ba10112b5c1b390f2471040288c748fe6ee603.d1-recovery.json';
  const bytes = readFileSync(path);
  const record = JSON.parse(bytes.toString('utf8'));
  return { record, digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}` };
}
const isolatedDurableReader = () => ({
  readTerminalOwnershipFloor: () => ({ terminal: false }),
  loadGeneration: () => ({ terminal_receipt: null, successor_root: null, activation: null }),
});

async function isolatedContext() {
  const world = await freshIsolatedWorld();
  const manifest = loadManifest(join(REPOSITORY_ROOT, 'semantic-model'));
  const journal = internals.createHandoverAbandonmentJournal(temporary('usf-isolated-journal-'));
  const { record, digest } = isolatedRecoveryEvidence();
  const rows = await fenceRowsOf(world.client);
  const fenceContentDigest = canonicalHandoverFenceDigest(rows);
  const generation = rows.find((row) => row.predicate === `${USF}handoverGenerationDigest`).object;
  const observation = {
    rows, fence: rows[0].fence, graph: rows[0].graph, contentDigest: fenceContentDigest,
  };
  const { buildHandoverAbandonmentEffect, handoverAbandonmentEffectDigest } = await import(
    './semantic-model-compilation-command.mjs');
  const permittedEffectDigest = handoverAbandonmentEffectDigest(buildHandoverAbandonmentEffect(
    observation, {
      generationDigest: generation,
      preD1AuthorityDigest: record.d1_effect.pre_d1_authority_digest,
      observedPostD1AuthorityDigest: record.d1_effect.observed_post_d1_authority_digest,
      d1RecoveryRecordDigest: digest,
      recoveredAt: NOW,
    }));
  return {
    ...world,
    manifest,
    journal,
    record,
    recordDigest: digest,
    observation,
    generation,
    permittedEffectDigest,
    grantFor: (overrides = {}) => isolatedGrant({
      authorityPreDigest: world.witness.digest,
      d1RecoveryRecordDigest: digest,
      fenceContentDigest,
      handoverGenerationDigest: generation,
      observedPostD1: record.d1_effect.observed_post_d1_authority_digest,
      permittedEffectDigest,
      preD1: record.d1_effect.pre_d1_authority_digest,
      ...overrides,
    }),
    run: (envelope, options = {}) => abandonFencedHandover({
      client: world.client,
      manifest,
      grantEnvelope: envelope,
      verifyGrant: isolatedVerifier,
      journal,
      nativeGraphStore: isolatedDurableReader(),
      d1RecoveryRecord: record,
      d1RecoveryRecordDigest: digest,
      implementationIdentity: sourceScopeDigest([
        'processes/semantic-assurance/semantic-model-compilation-command.mjs',
        'processes/semantic-assurance/semantic-proof-v1.mjs',
      ]),
      now: NOW,
      ...options,
    }),
  };
}

suite('isolated fidelity is exact against live before any mutation', async () => {
  const world = await freshIsolatedWorld();
  assert.equal(world.witness.digest, world.liveWitness.digest,
    'the isolated authority digest must equal live');
  assert.equal(
    semanticAuthorityInventoryDigest(world.witness.inventory, world.witness.triples),
    semanticAuthorityInventoryDigest(world.liveWitness.inventory, world.liveWitness.triples));
  assert.equal(world.witness.inventory.length, world.liveWitness.inventory.length);
  assert.equal(world.witness.triples, world.liveWitness.triples);
  // Every graph, digest for digest.
  for (const record of world.liveWitness.inventory) {
    const mirrored = world.witness.inventory.find((item) => item.graph === record.graph);
    assert.ok(mirrored, `${record.graph} must exist in the isolated database`);
    assert.equal(mirrored.sha256, record.sha256, `${record.graph} digest must match live`);
    assert.equal(mirrored.triples, record.triples);
  }
  // The fence, cardinality and canonical contents.
  const liveFence = await fenceRowsOf(world.liveClient);
  const isolatedFence = await fenceRowsOf(world.client);
  assert.equal(isolatedFence.length, liveFence.length);
  assert.equal(canonicalHandoverFenceDigest(isolatedFence),
    canonicalHandoverFenceDigest(liveFence));
  // Behavioural fidelity, not just asserted-triple fidelity. Every integrity rule must answer
  // identically -- the check whose absence let a digest-identical database report 11099
  // unresolved references because `query.all.graphs` was unset.
  const manifest = loadManifest(join(REPOSITORY_ROOT, 'semantic-model'));
  await assertIntegrityRuleParity(world.liveClient, world.client,
    integrityRules(manifest).map((rule) => ({
      file: rule.file, sparql: readFileSync(rule.path, 'utf8'),
    })));
  // And every absence check.
  for (const [label, sparql] of [
    ['successor binding', `SELECT ?b WHERE { GRAPH ?g { ?b a <${USF}V2NativeGraphSuccessorBinding> } }`],
    ['successor link', `SELECT ?f WHERE { GRAPH ?g { ?f <${USF}handoverGraphNativeSuccessorBinding> ?b } }`],
    ['storage owner', `SELECT ?s WHERE { GRAPH ?g { ?s <${USF}handoverStorageOwner> ?o } }`],
    ['abandonment', `SELECT ?r WHERE { GRAPH ?g { ?r a <${ABANDONMENT_CLASS}> } }`],
  ]) {
    assert.equal((await world.client.select(sparql)).length,
      (await world.liveClient.select(sparql)).length, `${label} must match live`);
  }
});

suite('isolated abandonment commits, and the prediction equals the observed authority', async () => {
  const context = await isolatedContext();
  const before = context.witness.digest;
  const result = await context.run(context.grantFor());

  assert.equal(result.outcome, 'COMMITTED');
  assert.equal(result.classification, 'PREDICTED_POST_STATE');
  assert.equal(result.mutated, true);
  assert.equal(result.authority_pre_digest, before);
  // The claim this whole phase exists to establish, against a real transaction.
  assert.equal(result.predicted_post_authority, result.observed_authority_digest);
  assert.notEqual(result.predicted_post_authority, before);

  // Independently re-read: the fence is gone, one history record replaced it.
  const after = await readSemanticAuthorityWitness(context.client);
  assert.equal(after.digest, result.predicted_post_authority);
  assert.equal((await fenceRowsOf(context.client)).length, 0);
  assert.equal((await context.client.select(
    `SELECT ?r WHERE { GRAPH ?g { ?r a <${ABANDONMENT_CLASS}> } }`)).length, 1);
  // No successor, no ownership, no terminal receipt was invented.
  assert.equal((await context.client.select(
    `SELECT ?b WHERE { GRAPH ?g { ?b a <${USF}V2NativeGraphSuccessorBinding> } }`)).length, 0);
  assert.equal((await context.client.select(
    `SELECT ?s WHERE { GRAPH ?g { ?s <${USF}handoverStorageOwner> ?o } }`)).length, 0);
  // Exactly one graph moved.
  const moved = after.inventory.filter((record) => {
    const original = context.witness.inventory.find((item) => item.graph === record.graph);
    return !original || original.sha256 !== record.sha256;
  });
  assert.equal(moved.length, 1);
  assert.equal(moved[0].graph, context.observation.graph);
});

suite('an exact isolated replay after success mutates nothing', async () => {
  const context = await isolatedContext();
  const envelope = context.grantFor();
  const first = await context.run(envelope);
  const afterFirst = (await readSemanticAuthorityWitness(context.client)).digest;

  const replay = await context.run(envelope);
  assert.equal(replay.outcome, 'ALREADY_COMMITTED');
  assert.equal(replay.replayed, true);
  assert.equal(replay.mutated, false);
  assert.equal(replay.operation_id, first.operation_id);
  assert.equal((await readSemanticAuthorityWitness(context.client)).digest, afterFirst);
  assert.equal((await context.client.select(
    `SELECT ?r WHERE { GRAPH ?g { ?r a <${ABANDONMENT_CLASS}> } }`)).length, 1,
  'a replay must not add a second history record');
});

suite('a divergent isolated replay refuses', async () => {
  const context = await isolatedContext();
  await context.run(context.grantFor());
  // Same one-shot nonce, different permitted effect: a different operation entirely.
  await assert.rejects(
    context.run(context.grantFor({ permittedEffectDigest: `sha256:${'cd'.repeat(32)}` })),
    /one-shot nonce already committed a mutation/u);
  assert.equal((await context.client.select(
    `SELECT ?r WHERE { GRAPH ?g { ?r a <${ABANDONMENT_CLASS}> } }`)).length, 1);
});

suite('ambiguous isolated commit is resolved by read-back, never by replay', async () => {
  const context = await isolatedContext();
  const envelope = context.grantFor();
  // Interrupt at the commit boundary, AFTER READY_TO_COMMIT is durable.
  await assert.rejects(context.run(envelope, {
    failpoint: async (point) => {
      if (point === 'immediately-before-commit') throw new Error('rehearsed crash at commit');
    },
  }), /rehearsed crash at commit/u);

  const operationId = handoverAbandonmentOperationId({
    nonce: envelope.payload.nonce,
    authorityPreDigest: envelope.payload.authority_pre_digest,
    fenceContentDigest: envelope.payload.fence_content_digest,
    handoverGenerationDigest: envelope.payload.handover_generation_digest,
    d1RecoveryRecordDigest: envelope.payload.d1_recovery_record_digest,
    permittedEffectDigest: envelope.payload.permitted_effect_digest,
  });
  const attempt = context.journal.readOperation(operationId).attempts[0];
  assert.equal(attempt.state, 'READY_TO_COMMIT');
  assert.match(attempt.ready.predicted_post_authority, /^sha256:[0-9a-f]{64}$/u);

  // Read-only classification against the real database.
  const recovered = await recoverHandoverAbandonment({
    client: context.client, journal: context.journal, operationId, now: NOW,
  });
  // The crash was before commit, so authority is the pre-state and a retry is lawful.
  assert.equal(recovered.classification, 'PRE_STATE');
  assert.equal(recovered.mutated, false);
  assert.equal(recovered.retry_permitted, true);
  assert.equal((await fenceRowsOf(context.client)).length, 12,
  'an interrupted transaction must leave the fence intact');
  assert.equal((await readSemanticAuthorityWitness(context.client)).digest,
    context.witness.digest);

  // The lawful retry then commits exactly once.
  const result = await context.run(envelope);
  assert.equal(result.classification, 'PREDICTED_POST_STATE');
  assert.equal(result.attempt, 1);
  assert.equal((await context.client.select(
    `SELECT ?r WHERE { GRAPH ?g { ?r a <${ABANDONMENT_CLASS}> } }`)).length, 1);
});

suite('an isolated refusal BEFORE staging changes nothing in the real database', async () => {
  const context = await isolatedContext();
  await assert.rejects(
    context.run(context.grantFor({ fenceContentDigest: `sha256:${'ab'.repeat(32)}` })),
    /fence content digest mismatch/u);
  assert.equal((await readSemanticAuthorityWitness(context.client)).digest, context.witness.digest);
  assert.equal((await fenceRowsOf(context.client)).length, 12);
  assert.equal((await context.client.select(
    `SELECT ?r WHERE { GRAPH ?g { ?r a <${ABANDONMENT_CLASS}> } }`)).length, 0);
});

suite('an isolated refusal AFTER the transaction opens rolls the real transaction back', async () => {
  const context = await isolatedContext();
  await assert.rejects(context.run(context.grantFor(), {
    failpoint: async (point) => {
      if (point === 'after-shacl-validation') throw new Error('rehearsed post-validation failure');
    },
  }), /rehearsed post-validation failure/u);
  // Staging and SHACL both ran inside a real transaction that was then rolled back.
  assert.equal((await readSemanticAuthorityWitness(context.client)).digest, context.witness.digest);
  assert.equal((await fenceRowsOf(context.client)).length, 12);
  assert.equal((await context.client.select(
    `SELECT ?r WHERE { GRAPH ?g { ?r a <${ABANDONMENT_CLASS}> } }`)).length, 0);
});

suite('live authority is untouched by the entire isolated suite', async () => {
  const stardog = (await import('stardog')).default;
  const live = await createIsolatedClientUnchecked(stardog, {
    endpoint: process.env.STARDOG_SERVER,
    database: process.env.STARDOG_DATABASE,
    token: process.env.STARDOG_TOKEN,
  });
  const witness = await readSemanticAuthorityWitness(live);
  assert.equal(witness.digest,
    'sha256:a38ff9c34bb2c6051c6be37d1c2ac71ed56d88c687b432a96b45e92d6fc97b13');
  assert.equal((await fenceRowsOf(live)).length, 12);
  assert.equal((await live.select(
    `SELECT ?r WHERE { GRAPH ?g { ?r a <${ABANDONMENT_CLASS}> } }`)).length, 0,
  'live authority must hold no abandonment record');
  assert.equal(typeof digestOf({}), 'string');
});
