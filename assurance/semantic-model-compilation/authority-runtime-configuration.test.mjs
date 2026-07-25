// Runtime configuration and enforcement of the canonical mutation path.
//
// Every fixture below is synthetic. The token, password and endpoint literals
// are deliberately self-describing non-credentials, and several assertions exist
// only to prove that no fixture value reaches any output or error.
//
// No network, no child process and no repository write occurs: the endpoint is
// never contacted, git is injected, and the only files written live under the
// runtime temp directory.
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ConfigError,
  DEFAULT_ENV_FILE,
  ENV_FILE_VARIABLE,
  OVERRIDABLE_ENVIRONMENT_KEY,
  describeConfig,
  describeEnvironmentResolution,
  loadConfig,
  parseEnvironmentFile,
  resolveEnvironment,
} from '../../configuration/semantic-assurance/stardog-connection.mjs';
import {
  REQUIRED_DATABASE_OPTIONS,
  checkRequiredOptions,
  describeUnsatisfiedOptions,
  provisioningParameters,
} from '../../operations/stardog/provision-authority-endpoint.mjs';
import {
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  SELF_PUBLICATION_RULE,
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  authorityDependencySetDigest,
} from '../../capabilities/semantic-model-compilation/authority-binding.mjs';
import {
  PUBLICATION_LOG_FIELDS,
  appendPublicationLogRecord,
  assertRequiredDatabaseOptions,
  collectSatisfyingResultBindings,
  createAuthorityBindingGuardedClient,
  main,
  readPublicationLog,
  redactSecrets,
  reevaluateSatisfyingResultBindings,
  runPublication,
  selfPublicationClosureFindings,
  validatePublicationLogRecord,
} from '../../processes/semantic-assurance/semantic-authority-publication.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

// The reclaimed endpoint from the reproduced failure: its DNS address record is
// gone, so a session that keeps inheriting it fails with ENOTFOUND for its whole
// life. It is never contacted here.
const STALE_ENDPOINT = 'https://sd-7023d2ef.stardog.cloud:5820';
const LIVE_ENDPOINT = 'https://sd-live-fixture.stardog.cloud:5820';
const FIXTURE_TOKEN = 'fixture-token-not-a-credential';
const FIXTURE_PASSWORD = 'fixture-password-not-a-credential';
const DIGEST = `sha256:${'1'.repeat(64)}`;
const OTHER_DIGEST = `sha256:${'2'.repeat(64)}`;
const HEAD = 'a'.repeat(40);

function scratch() {
  return mkdtempSync(join(tmpdir(), 'usf-authority-runtime-'));
}

const withScratch = (body) => {
  const root = scratch();
  try {
    return body(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

// --- F-13: env-file precedence over an inherited stale endpoint -------------

test('an operator env file overrides an inherited stale STARDOG_SERVER', () => {
  withScratch((root) => {
    writeFileSync(join(root, '.env'), [
      '# operator endpoint, reprovisioned after reclamation',
      `STARDOG_SERVER=${LIVE_ENDPOINT}`,
      'STARDOG_DATABASE=USF',
      `STARDOG_TOKEN=${FIXTURE_TOKEN}`,
      '',
    ].join('\n'));
    const inherited = {
      STARDOG_SERVER: STALE_ENDPOINT,
      STARDOG_DATABASE: 'STALE',
      STARDOG_TOKEN: 'stale-token-not-a-credential',
    };
    const resolution = resolveEnvironment(inherited, { cwd: root });
    assert.equal(resolution.envFileLoaded, true);
    assert.equal(resolution.envFilePath, join(root, '.env'));
    assert.deepEqual([...resolution.overriddenKeys], ['STARDOG_DATABASE', 'STARDOG_SERVER', 'STARDOG_TOKEN']);
    assert.equal(resolution.env.STARDOG_SERVER, LIVE_ENDPOINT);

    const config = loadConfig(inherited, { cwd: root });
    assert.equal(config.endpoint, LIVE_ENDPOINT);
    assert.notEqual(config.endpoint, STALE_ENDPOINT);
    assert.equal(config.database, 'USF');
    assert.equal(config.auth.kind, 'token');
    assert.equal(describeConfig(config).endpoint, LIVE_ENDPOINT);
    assert.equal(describeEnvironmentResolution(config).envFileLoaded, true);
  });
});

test('an absent env file leaves the inherited environment in force', () => {
  withScratch((root) => {
    const resolution = resolveEnvironment({ STARDOG_SERVER: STALE_ENDPOINT }, { cwd: root });
    assert.equal(resolution.envFileLoaded, false);
    assert.deepEqual([...resolution.overriddenKeys], []);
    assert.equal(resolution.envFilePath, join(root, '.env'));

    const config = loadConfig({
      STARDOG_SERVER: LIVE_ENDPOINT,
      STARDOG_DATABASE: 'USF',
      STARDOG_TOKEN: FIXTURE_TOKEN,
    }, { cwd: root });
    assert.equal(config.endpoint, LIVE_ENDPOINT);
    assert.equal(config.envFileLoaded, false);
    // A directory in the env-file position is treated as absence, exactly as
    // `[ -f … ]` is false for it, rather than as a fatal error.
    mkdirSync(join(root, '.env'));
    assert.equal(resolveEnvironment({ STARDOG_SERVER: LIVE_ENDPOINT }, { cwd: root }).envFileLoaded, false);
  });
});

test('USF_ENV_FILE selects the env file and the file cannot reselect itself', () => {
  withScratch((root) => {
    const chosen = join(root, 'operator.env');
    writeFileSync(chosen, [
      `STARDOG_SERVER=${LIVE_ENDPOINT}`,
      `${ENV_FILE_VARIABLE}=/nowhere/ignored.env`,
      'STARDOG_DATABASE=USF',
      `STARDOG_TOKEN=${FIXTURE_TOKEN}`,
    ].join('\n'));
    writeFileSync(join(root, '.env'), `STARDOG_SERVER=${STALE_ENDPOINT}\n`);
    const resolution = resolveEnvironment(
      { [ENV_FILE_VARIABLE]: chosen, STARDOG_SERVER: STALE_ENDPOINT },
      { cwd: root },
    );
    assert.equal(resolution.envFilePath, chosen);
    assert.equal(resolution.env.STARDOG_SERVER, LIVE_ENDPOINT);
    // USF_ENV_FILE is not a STARDOG_* key, so the file's own attempt to point
    // elsewhere is not honoured — mirroring the launcher, which expands the
    // variable before sourcing.
    assert.equal(resolution.env[ENV_FILE_VARIABLE], chosen);
    assert.equal(OVERRIDABLE_ENVIRONMENT_KEY.test(ENV_FILE_VARIABLE), false);
  });
});

test('only STARDOG_ keys are overridden and unrelated ambient values survive', () => {
  withScratch((root) => {
    writeFileSync(join(root, '.env'), [
      `STARDOG_SERVER=${LIVE_ENDPOINT}`,
      `STARDOG_TOKEN=${FIXTURE_TOKEN}`,
      'PATH=/attacker/bin',
      'GITHUB_PERSONAL_ACCESS_TOKEN=fixture-github-not-a-credential',
    ].join('\n'));
    const resolution = resolveEnvironment(
      { PATH: '/usr/bin', STARDOG_SERVER: STALE_ENDPOINT, GITHUB_PERSONAL_ACCESS_TOKEN: 'inherited' },
      { cwd: root },
    );
    assert.equal(resolution.env.PATH, '/usr/bin');
    assert.equal(resolution.env.GITHUB_PERSONAL_ACCESS_TOKEN, 'inherited');
    assert.equal(resolution.env.STARDOG_SERVER, LIVE_ENDPOINT);
    assert.deepEqual([...resolution.overriddenKeys], ['STARDOG_SERVER', 'STARDOG_TOKEN']);
  });
});

test('the env-file parser executes nothing and never reports a value', () => {
  const parsed = parseEnvironmentFile([
    '',
    '# a comment',
    '   ',
    `export STARDOG_SERVER=${LIVE_ENDPOINT}`,
    `STARDOG_TOKEN="${FIXTURE_TOKEN}"`,
    `STARDOG_PASSWORD='${FIXTURE_PASSWORD}'`,
    'STARDOG_LITERAL=$(rm -rf /)',
  ].join('\n'));
  assert.equal(parsed.STARDOG_SERVER, LIVE_ENDPOINT);
  assert.equal(parsed.STARDOG_TOKEN, FIXTURE_TOKEN);
  assert.equal(parsed.STARDOG_PASSWORD, FIXTURE_PASSWORD);
  // Retained verbatim: nothing is expanded and nothing is executed.
  assert.equal(parsed.STARDOG_LITERAL, '$(rm -rf /)');

  let error;
  try {
    parseEnvironmentFile(`STARDOG_TOKEN=${FIXTURE_TOKEN}\nthis is not an assignment ${FIXTURE_PASSWORD}\n`, '/fixture/.env');
  } catch (thrown) {
    error = thrown;
  }
  assert.ok(error instanceof ConfigError);
  assert.match(error.message, /\/fixture\/\.env line 2 is not a KEY=VALUE assignment/u);
  assert.equal(error.message.includes(FIXTURE_PASSWORD), false);
  assert.equal(error.message.includes(FIXTURE_TOKEN), false);
});

test('no fixture credential reaches any diagnostic surface', () => {
  withScratch((root) => {
    writeFileSync(join(root, '.env'), [
      `STARDOG_SERVER=${LIVE_ENDPOINT}`,
      'STARDOG_USERNAME=fixture-user',
      `STARDOG_PASSWORD=${FIXTURE_PASSWORD}`,
    ].join('\n'));
    const config = loadConfig({}, { cwd: root });
    assert.equal(config.auth.kind, 'basic');
    const surfaces = JSON.stringify([
      describeConfig(config),
      describeEnvironmentResolution(config),
      resolveEnvironment({}, { cwd: root }).overriddenKeys,
    ]);
    assert.equal(surfaces.includes(FIXTURE_PASSWORD), false);
    assert.equal(surfaces.includes('fixture-user'), false);
    assert.equal(redactSecrets(`failed for ${FIXTURE_TOKEN}`, [FIXTURE_TOKEN]), 'failed for <redacted>');
  });
});

test('the connection module still refuses unusable endpoints and missing credentials', () => {
  withScratch((root) => {
    assert.throws(() => loadConfig({}, { cwd: root }), /STARDOG_SERVER is required/u);
    assert.throws(() => loadConfig({ STARDOG_SERVER: 'http://example.test' }, { cwd: root }), /must use https/u);
    assert.throws(() => loadConfig({ STARDOG_SERVER: 'https://localhost:5820' }, { cwd: root }), /not localhost/u);
    assert.throws(() => loadConfig({ STARDOG_SERVER: LIVE_ENDPOINT }, { cwd: root }), /No credentials/u);
    assert.equal(DEFAULT_ENV_FILE, './.env');
  });
});

// --- F-10: the required database options are enforced, not reported ---------

test('the tracked required-option set carries both options and is never copied', async () => {
  assert.deepEqual(Object.keys(REQUIRED_DATABASE_OPTIONS).sort(), ['auto.schema.reasoning', 'query.all.graphs']);
  assert.equal(REQUIRED_DATABASE_OPTIONS['query.all.graphs'], true);
  assert.equal(REQUIRED_DATABASE_OPTIONS['auto.schema.reasoning'], true);
  assert.equal(Object.isFrozen(REQUIRED_DATABASE_OPTIONS), true);
  // Provisioning reports the same object, not a restatement of the literals.
  assert.equal(provisioningParameters({ baseIri: 'urn:usf:', database: 'USF', namedGraphs: ['urn:usf:graph:x'] }).required, REQUIRED_DATABASE_OPTIONS);
  // The publication preflight defaults to that same object identity.
  let captured;
  await assertRequiredDatabaseOptions({
    connection: null,
    database: 'USF',
    check: async (_conn, _db, required) => {
      captured = required;
      return { ok: true, unsatisfied: [] };
    },
  });
  assert.equal(captured, REQUIRED_DATABASE_OPTIONS);
  // And the publication source restates neither option key as a literal.
  const publicationSource = readFileSync(join(repositoryRoot, 'processes/semantic-assurance/semantic-authority-publication.mjs'), 'utf8');
  assert.equal(/['"`]query\.all\.graphs['"`]/u.test(publicationSource), false);
  assert.equal(/['"`]auto\.schema\.reasoning['"`]/u.test(publicationSource), false);
});

test('an option reader disagreeing with the tracked set yields an exact unsatisfied record', async () => {
  const options = { ok: true, body: { 'query.all.graphs': 'false', 'auto.schema.reasoning': 'true' } };
  const result = await checkRequiredOptions(null, 'USF', REQUIRED_DATABASE_OPTIONS, async () => options);
  assert.equal(result.ok, false);
  assert.deepEqual(result.unsatisfied, [{ key: 'query.all.graphs', expected: true, observed: 'false' }]);
  assert.equal(describeUnsatisfiedOptions(result.unsatisfied), 'query.all.graphs expected true observed false');
  const absent = await checkRequiredOptions(null, 'USF', REQUIRED_DATABASE_OPTIONS, async () => ({ ok: true, body: {} }));
  assert.equal(absent.ok, false);
  assert.equal(absent.unsatisfied.length, 2);
  assert.equal(describeUnsatisfiedOptions(absent.unsatisfied), 'auto.schema.reasoning expected true observed absent; query.all.graphs expected true observed absent');
});

// A client that counts every operation the compiler would perform, so ordering
// can be asserted rather than inferred.
function recordingClient(overrides = {}) {
  const calls = { begin: 0, commit: 0, rollback: 0, select: 0, selectInTransaction: 0, witness: 0 };
  const client = {
    expectedAuthorityDigest: DIGEST,
    async connectivity() { return 1; },
    async begin() { calls.begin += 1; return 'tx-1'; },
    async commit() { calls.commit += 1; },
    async rollback() { calls.rollback += 1; },
    async select() { calls.select += 1; return []; },
    async selectInTransaction() { calls.selectInTransaction += 1; return []; },
    async construct() { return ''; },
    async validateInTransactionWithReceipt() { return { conforms: true }; },
    isTransactionClosedError() { return true; },
    ...overrides,
  };
  return { calls, client };
}

const optionsResponse = (body) => async () => ({ ok: true, body });

const publicationEnvironment = Object.freeze({
  env: Object.freeze({
    STARDOG_SERVER: LIVE_ENDPOINT,
    STARDOG_DATABASE: 'USF',
    STARDOG_TOKEN: FIXTURE_TOKEN,
  }),
  envFilePath: '/fixture/.env',
  envFileLoaded: true,
  overriddenKeys: Object.freeze(['STARDOG_SERVER']),
});

for (const missing of ['query.all.graphs', 'auto.schema.reasoning']) {
  test(`publication exits non-zero before any transaction when ${missing} is false`, async () => {
    const { calls, client } = recordingClient();
    let witnessReads = 0;
    let commandsCreated = 0;
    const errors = [];
    const outputs = [];
    const body = { 'query.all.graphs': 'true', 'auto.schema.reasoning': 'true' };
    body[missing] = 'false';

    const code = await main(['node', 'publication', '--mode=commit', `--authority-digest=${DIGEST}`], {
      write: (text) => outputs.push(text),
      writeError: (text) => errors.push(text),
      environment: publicationEnvironment,
      createClient: () => client,
      readDatabaseOptions: optionsResponse(body),
      readAuthorityWitness: async () => { witnessReads += 1; return { digest: DIGEST, inventory: [], triples: 1 }; },
      createCommand: () => { commandsCreated += 1; return { execute: async () => ({ ok: true }) }; },
      repositoryRoot,
      publicationLogPath: '/must/not/be/written',
      execute: () => { throw new Error('git must not run'); },
      writeFile: () => { throw new Error('the publication log must not be written'); },
    });

    // The process contract: refusal is exit 1, with a reason that names the option.
    assert.equal(code, 1);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /required database options unsatisfied; refusing to open a publication transaction/u);
    assert.ok(errors[0].includes(`${missing} expected true observed false`));
    assert.equal(errors[0].includes(FIXTURE_TOKEN), false);
    assert.deepEqual(outputs, []);
    // The ordering: nothing downstream of the preflight ran at all.
    assert.equal(calls.begin, 0);
    assert.equal(calls.commit, 0);
    assert.equal(calls.rollback, 0);
    assert.equal(witnessReads, 0);
    assert.equal(commandsCreated, 0);
  });
}

test('publication proceeds and exits zero when every required option is satisfied', async () => {
  const { calls, client } = recordingClient();
  const outputs = [];
  const code = await main(['node', 'publication', '--mode=validate', `--authority-digest=${DIGEST}`], {
    write: (text) => outputs.push(text),
    writeError: (text) => { throw new Error(`unexpected diagnostic: ${text}`); },
    environment: publicationEnvironment,
    createClient: () => client,
    readDatabaseOptions: optionsResponse({ 'query.all.graphs': 'true', 'auto.schema.reasoning': 'true' }),
    readAuthorityWitness: async () => ({ digest: DIGEST, inventory: [], triples: 7 }),
    createCommand: ({ client: bound }) => ({
      execute: async () => {
        const transaction = await bound.begin();
        await bound.rollback(transaction);
        return { ok: true, commitOutcome: { state: 'validated-rolled-back' }, evaluatedAuthorityDigest: DIGEST };
      },
    }),
    repositoryRoot,
  });
  assert.equal(code, 0);
  assert.equal(calls.begin, 1);
  assert.equal(calls.commit, 0);
  const reported = JSON.parse(outputs.join(''));
  assert.equal(reported.mode, 'validate');
  assert.equal(reported.ok, true);
  assert.deepEqual(reported.requiredOptionKeys, ['auto.schema.reasoning', 'query.all.graphs']);
  assert.equal(reported.envFileLoaded, true);
  assert.deepEqual(reported.envFileOverriddenKeys, ['STARDOG_SERVER']);
  assert.equal(reported.publicationLog, null);
  assert.equal(JSON.stringify(reported).includes(FIXTURE_TOKEN), false);
});

// --- F-06b: satisfying results and the self-publication closure ------------

const graphInventory = [
  ...SELF_PUBLICATION_EXCLUDED_GRAPHS.map((graph, index) => ({ graph, sha256: `${index}`.repeat(64).slice(0, 64), triples: index + 1 })),
  { graph: 'urn:usf:graph:contracts', sha256: 'c'.repeat(64), triples: 11 },
  { graph: 'urn:usf:graph:ontology', sha256: 'd'.repeat(64), triples: 12 },
];

const term = (value) => ({ value });

function bindingRows({ dependencySetDigest, evaluatedDigest = DIGEST, rule = SELF_PUBLICATION_RULE, reevaluation = 'true', algorithm = AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM }) {
  return [{
    obligation: term('urn:usf:validationobligation:fixture'),
    result: term('urn:usf:validationresult:fixture'),
    evaluatedDigest: term(evaluatedDigest),
    dependencySetDigest: term(dependencySetDigest),
    algorithm: term(algorithm),
    rule: term(rule),
    reevaluation: term(reevaluation),
  }];
}

const exclusionRows = (graphs = SELF_PUBLICATION_EXCLUDED_GRAPHS) => graphs.map((graph) => ({
  result: term('urn:usf:validationresult:fixture'),
  excluded: term(graph),
}));

test('a satisfying result with a complete self-publication closure is well formed', () => {
  const dependencySetDigest = authorityDependencySetDigest(graphInventory);
  const [record] = collectSatisfyingResultBindings(bindingRows({ dependencySetDigest }), exclusionRows());
  assert.equal(record.result, 'urn:usf:validationresult:fixture');
  assert.equal(record.requiresPostPublicationReevaluation, true);
  assert.deepEqual([...record.excludedGraphs], [...SELF_PUBLICATION_EXCLUDED_GRAPHS].sort());
  assert.deepEqual([...selfPublicationClosureFindings(record)], []);
});

test('every missing closure marker is an explicit finding', () => {
  const dependencySetDigest = authorityDependencySetDigest(graphInventory);
  const cases = [
    [{ dependencySetDigest, reevaluation: 'false' }, exclusionRows(), 'postpublication-reevaluation'],
    [{ dependencySetDigest, rule: 'urn:usf:authoritybindingrule:somethingelse' }, exclusionRows(), 'authority-binding-rule'],
    [{ dependencySetDigest, algorithm: 'sha256-whatever' }, exclusionRows(), 'dependency-digest-algorithm'],
    [{ dependencySetDigest, evaluatedDigest: 'not-a-digest' }, exclusionRows(), 'evaluated-authority-digest'],
    [{ dependencySetDigest: 'not-a-digest' }, exclusionRows(), 'dependency-set-digest'],
    [{ dependencySetDigest }, exclusionRows(SELF_PUBLICATION_EXCLUDED_GRAPHS.slice(1)), 'excluded-authority-graphs'],
  ];
  for (const [binding, exclusions, expected] of cases) {
    const [record] = collectSatisfyingResultBindings(bindingRows(binding), exclusions);
    assert.deepEqual([...selfPublicationClosureFindings(record)], [expected], expected);
  }
  // A result carrying no binding at all is refused on every marker.
  const [bare] = collectSatisfyingResultBindings([{
    obligation: term('urn:usf:validationobligation:fixture'),
    result: term('urn:usf:validationresult:fixture'),
    evaluatedDigest: term(DIGEST),
  }], []);
  assert.deepEqual([...selfPublicationClosureFindings(bare)], [
    'authority-binding-rule',
    'dependency-digest-algorithm',
    'dependency-set-digest',
    'excluded-authority-graphs',
    'postpublication-reevaluation',
  ]);
});

test('the pre-commit guard refuses inside the transaction and never delegates the commit', async () => {
  const { calls, client } = recordingClient({
    async selectInTransaction() {
      calls.selectInTransaction += 1;
      // One satisfying result carrying no closure binding at all.
      return calls.selectInTransaction === 1
        ? [{ obligation: term('urn:usf:validationobligation:fixture'), result: term('urn:usf:validationresult:fixture'), evaluatedDigest: term(DIGEST) }]
        : [];
    },
  });
  const observed = {};
  const guarded = createAuthorityBindingGuardedClient({ client, publicationMode: 'commit', observed });
  await assert.rejects(
    () => guarded.commit('tx-1'),
    (error) => {
      assert.match(error.message, /self-publication closure/u);
      assert.equal(error.phase, 'authority:validation-binding:candidate');
      return true;
    },
  );
  assert.equal(calls.commit, 0);
  // A validate run is handed the client unchanged: there is no commit to guard.
  assert.equal(createAuthorityBindingGuardedClient({ client, publicationMode: 'validate', observed }), client);
});

test('the pre-commit guard delegates the commit when the closure is complete', async () => {
  const dependencySetDigest = authorityDependencySetDigest(graphInventory);
  let query = 0;
  const { calls, client } = recordingClient({
    async selectInTransaction() {
      query += 1;
      return query === 1 ? bindingRows({ dependencySetDigest }) : exclusionRows();
    },
  });
  const observed = {};
  const guarded = createAuthorityBindingGuardedClient({ client, publicationMode: 'commit', observed });
  await guarded.commit('tx-1');
  assert.equal(calls.commit, 1);
  assert.equal(observed.preCommit.satisfyingResultCount, 1);
});

test('post-publication re-evaluation reconciles a binding, and refuses one that does not', () => {
  const dependencySetDigest = authorityDependencySetDigest(graphInventory);
  const witness = { digest: OTHER_DIGEST, inventory: graphInventory, triples: 23 };
  const [record] = collectSatisfyingResultBindings(bindingRows({ dependencySetDigest }), exclusionRows());

  // The published digest differs from the evaluated digest — that is expected,
  // because publishing the result is what changed it. Reconciliation is over the
  // non-publication graphs, so the binding still holds.
  const reconciled = reevaluateSatisfyingResultBindings({ records: [record], witness });
  assert.equal(reconciled.ok, true);
  assert.equal(reconciled.algorithm, AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM);
  assert.equal(reconciled.evaluations[0].mode, 'self-publication-closure');
  assert.deepEqual([...reconciled.unreconciled], []);

  // A non-publication graph changed under the binding: it no longer reconciles.
  const drifted = reevaluateSatisfyingResultBindings({
    records: [record],
    witness: {
      ...witness,
      inventory: graphInventory.map((entry) => entry.graph === 'urn:usf:graph:contracts'
        ? { ...entry, sha256: 'e'.repeat(64) }
        : entry),
    },
  });
  assert.equal(drifted.ok, false);
  assert.deepEqual(drifted.unreconciled, [{ result: record.result, findings: ['dependency-set-mismatch'] }]);
});

test('a commit publication exits non-zero when post-publication re-evaluation fails', async () => {
  const dependencySetDigest = authorityDependencySetDigest(graphInventory);
  const witnessInventory = graphInventory.map((entry) => entry.graph === 'urn:usf:graph:ontology'
    ? { ...entry, sha256: 'f'.repeat(64) }
    : entry);
  let query = 0;
  const { client } = recordingClient({
    async selectInTransaction() {
      query += 1;
      return query === 1 ? bindingRows({ dependencySetDigest }) : exclusionRows();
    },
    async select(sparql) {
      return sparql.includes('excludedAuthorityGraphIri') ? exclusionRows() : bindingRows({ dependencySetDigest });
    },
  });
  const written = new Map();
  const outputs = [];
  const code = await main(['node', 'publication', '--mode=commit', `--authority-digest=${DIGEST}`], {
    write: (text) => outputs.push(text),
    writeError: (text) => { throw new Error(`unexpected diagnostic: ${text}`); },
    environment: publicationEnvironment,
    createClient: () => client,
    readDatabaseOptions: optionsResponse({ 'query.all.graphs': 'true', 'auto.schema.reasoning': 'true' }),
    readAuthorityWitness: async () => ({ digest: OTHER_DIGEST, inventory: witnessInventory, triples: 23 }),
    createCommand: ({ client: bound }) => ({
      execute: async () => {
        const transaction = await bound.begin();
        await bound.commit(transaction);
        return { ok: true, commitOutcome: { state: 'confirmed-response' }, evaluatedAuthorityDigest: DIGEST };
      },
    }),
    repositoryRoot,
    publicationLogPath: '/fixture/authority-publication-log.json',
    now: () => '2026-07-25T00:00:00.000Z',
    execute: () => `${HEAD}\n`,
    readFile: () => '[]',
    writeFile: (path, content) => written.set(path, content),
  });
  assert.equal(code, 1);
  const reported = JSON.parse(outputs.join(''));
  assert.equal(reported.ok, false);
  assert.equal(reported.authorityBindingReevaluation.ok, false);
  assert.deepEqual(reported.authorityBindingReevaluation.unreconciled[0].findings, ['dependency-set-mismatch']);
  // The audit record is still written: the publication did happen, and an
  // unattributable published digest is the defect the log exists to prevent.
  assert.equal(written.size, 1);
  assert.equal(JSON.parse(written.get('/fixture/authority-publication-log.json')).length, 1);
});

// --- F-14: the published-digest audit log ----------------------------------

test('the tracked publication log is seeded empty with no fabricated history', () => {
  const path = join(repositoryRoot, 'operations/stardog/authority-publication-log.json');
  assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), []);
  assert.deepEqual(readPublicationLog(path), []);
});

test('a publication log record has the exact shape and rejects every deviation', () => {
  const record = {
    publishedAt: '2026-07-25T12:00:00.000Z',
    authorityDigest: DIGEST,
    triples: 4242,
    graphCount: 10,
    sourceHead: HEAD,
  };
  assert.deepEqual([...PUBLICATION_LOG_FIELDS].sort(), Object.keys(record).sort());
  assert.equal(validatePublicationLogRecord(record), record);
  assert.throws(() => validatePublicationLogRecord({ ...record, extra: 1 }), /exactly/u);
  assert.throws(() => validatePublicationLogRecord({ ...record, publishedAt: '2026-07-25' }), /ISO-8601 UTC/u);
  assert.throws(() => validatePublicationLogRecord({ ...record, authorityDigest: 'nope' }), /sha256/u);
  assert.throws(() => validatePublicationLogRecord({ ...record, triples: -1 }), /triples/u);
  assert.throws(() => validatePublicationLogRecord({ ...record, graphCount: 1.5 }), /graphCount/u);
  assert.throws(() => validatePublicationLogRecord({ ...record, sourceHead: 'HEAD' }), /commit identifier/u);
});

test('appending a record preserves every existing entry verbatim and in order', () => {
  withScratch((root) => {
    const path = join(root, 'authority-publication-log.json');
    writeFileSync(path, '[]\n');
    const first = {
      publishedAt: '2026-07-24T09:00:00.000Z',
      authorityDigest: DIGEST,
      triples: 100,
      graphCount: 9,
      sourceHead: HEAD,
    };
    const second = { ...first, publishedAt: '2026-07-25T09:00:00.000Z', authorityDigest: OTHER_DIGEST, triples: 101 };

    const firstAppend = appendPublicationLogRecord({ path, record: first });
    assert.deepEqual(firstAppend, { path, appended: 1, entryCount: 1, preservedEntryCount: 0 });
    const afterFirst = readFileSync(path, 'utf8');
    assert.equal(afterFirst.endsWith('\n'), true);
    assert.deepEqual(JSON.parse(afterFirst), [first]);

    const secondAppend = appendPublicationLogRecord({ path, record: second });
    assert.deepEqual(secondAppend, { path, appended: 1, entryCount: 2, preservedEntryCount: 1 });
    const entries = JSON.parse(readFileSync(path, 'utf8'));
    assert.deepEqual(entries, [first, second]);
    // The earlier entry is untouched, not merely still present.
    assert.deepEqual(entries[0], JSON.parse(afterFirst)[0]);

    // A log that is not an array is never overwritten.
    writeFileSync(path, '{"not":"an array"}');
    assert.throws(() => appendPublicationLogRecord({ path, record: second }), /must be a JSON array/u);
    assert.equal(readFileSync(path, 'utf8'), '{"not":"an array"}');
  });
});

test('a commit publication appends exactly one audit record', async () => {
  const dependencySetDigest = authorityDependencySetDigest(graphInventory);
  let query = 0;
  const { calls, client } = recordingClient({
    async selectInTransaction() {
      query += 1;
      return query === 1 ? bindingRows({ dependencySetDigest }) : exclusionRows();
    },
    async select(sparql) {
      return sparql.includes('excludedAuthorityGraphIri') ? exclusionRows() : bindingRows({ dependencySetDigest });
    },
  });
  const outputs = [];
  const written = new Map();
  const code = await main(['node', 'publication', '--mode=commit', `--authority-digest=${DIGEST}`], {
    write: (text) => outputs.push(text),
    writeError: (text) => { throw new Error(`unexpected diagnostic: ${text}`); },
    environment: publicationEnvironment,
    createClient: () => client,
    readDatabaseOptions: optionsResponse({ 'query.all.graphs': 'true', 'auto.schema.reasoning': 'true' }),
    readAuthorityWitness: async () => ({ digest: OTHER_DIGEST, inventory: graphInventory, triples: 23 }),
    createCommand: ({ client: bound }) => ({
      execute: async () => {
        const transaction = await bound.begin();
        await bound.commit(transaction);
        return { ok: true, commitOutcome: { state: 'confirmed-response' }, evaluatedAuthorityDigest: DIGEST };
      },
    }),
    repositoryRoot,
    publicationLogPath: '/fixture/authority-publication-log.json',
    now: () => '2026-07-25T00:00:00.000Z',
    execute: (command, args) => {
      assert.equal(command, 'git');
      assert.deepEqual(args, ['rev-parse', 'HEAD']);
      return `${HEAD}\n`;
    },
    readFile: () => '[]\n',
    writeFile: (path, content) => written.set(path, content),
  });
  assert.equal(code, 0);
  assert.equal(calls.commit, 1);
  const reported = JSON.parse(outputs.join(''));
  assert.equal(reported.ok, true);
  assert.equal(reported.postAuthorityDigest, OTHER_DIGEST);
  assert.equal(reported.postGraphCount, graphInventory.length);
  assert.deepEqual(reported.publicationLog, {
    path: '/fixture/authority-publication-log.json',
    appended: 1,
    entryCount: 1,
    preservedEntryCount: 0,
  });
  assert.deepEqual(JSON.parse(written.get('/fixture/authority-publication-log.json')), [{
    publishedAt: '2026-07-25T00:00:00.000Z',
    authorityDigest: OTHER_DIGEST,
    triples: 23,
    graphCount: graphInventory.length,
    sourceHead: HEAD,
  }]);
  assert.equal(JSON.stringify(reported).includes(FIXTURE_TOKEN), false);
});

test('a validate publication writes no audit record at all', async () => {
  const { client } = recordingClient();
  const code = await main(['node', 'publication', '--mode=validate', `--authority-digest=${DIGEST}`], {
    write: () => {},
    writeError: (text) => { throw new Error(`unexpected diagnostic: ${text}`); },
    environment: publicationEnvironment,
    createClient: () => client,
    readDatabaseOptions: optionsResponse({ 'query.all.graphs': 'true', 'auto.schema.reasoning': 'true' }),
    readAuthorityWitness: async () => ({ digest: DIGEST, inventory: graphInventory, triples: 23 }),
    createCommand: () => ({ execute: async () => ({ ok: true, evaluatedAuthorityDigest: DIGEST }) }),
    repositoryRoot,
    execute: () => { throw new Error('git must not run in validate mode'); },
    writeFile: () => { throw new Error('validate mode must not write the publication log'); },
  });
  assert.equal(code, 0);
});

test('runPublication refuses an unsupported mode before touching anything', async () => {
  await assert.rejects(
    () => runPublication({ mode: 'apply', expectedAuthorityDigest: DIGEST, environment: publicationEnvironment }),
    /mode must be validate or commit/u,
  );
});
