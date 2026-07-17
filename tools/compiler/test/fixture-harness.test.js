import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseFixtureHeader, fixtureSubjects, scopeIntegrityQuery, verifyFixtures } from '../src/fixture-harness.js';

test('fixture headers parse graph, expectation, shacl and conforming markers', () => {
  const header = parseFixtureHeader('# graph: urn:usf:graph:services\n# expect: servicedisconnected\n@prefix usf: <urn:usf:ontology:> .');
  assert.equal(header.graph, 'urn:usf:graph:services');
  assert.equal(header.expect, 'servicedisconnected');
  assert.equal(header.annotated, true);
  assert.equal(parseFixtureHeader('# conforming\n').conforming, true);
  assert.equal(parseFixtureHeader('# expect-shacl: nonconforming\n').expectShacl, true);
  assert.equal(parseFixtureHeader('# expect-load: rejected\n').expectLoad, true);
  assert.equal(parseFixtureHeader('@prefix usf: <urn:usf:ontology:> .').annotated, false);
});

test('fixture subjects are collected from turtle and trig content', () => {
  const turtle = '@prefix usf: <urn:usf:ontology:> .\n<urn:usf:fixturenode:a> a usf:Service .';
  assert.deepEqual([...fixtureSubjects(turtle, 'x.ttl')], ['urn:usf:fixturenode:a']);
  const trig = '<urn:usf:graph:services> { <urn:usf:fixturenode:b> <urn:usf:ontology:canonicalName> "b" . }';
  assert.deepEqual([...fixtureSubjects(trig, 'x.trig')], ['urn:usf:fixturenode:b']);
});

test('integrity queries are bounded to exact fixture subjects', () => {
  const query = 'PREFIX usf: <urn:usf:ontology:>\nSELECT DISTINCT ?violation ?subject WHERE { ?subject a usf:Service . }';
  const scoped = scopeIntegrityQuery(query, new Set(['urn:usf:fixturenode:b', 'urn:usf:fixturenode:a']));
  assert.match(scoped, /VALUES \?subject \{ <urn:usf:fixturenode:a> <urn:usf:fixturenode:b> \}/);
  assert.throws(() => scopeIntegrityQuery(query, new Set()), /no named USF subject/);
  assert.throws(() => scopeIntegrityQuery(query, new Set(['https://example.com/x'])), /safe USF IRI/);
});

function harnessWorkspace() {
  const root = mkdtempSync(join(tmpdir(), 'usf-fixture-harness-'));
  mkdirSync(join(root, 'fixtures/conforming'), { recursive: true });
  mkdirSync(join(root, 'fixtures/defects'), { recursive: true });
  writeFileSync(join(root, 'integrity.rq'), 'SELECT ?violation ?subject WHERE { }');
  writeFileSync(join(root, 'shapes.ttl'), '@prefix sh: <http://www.w3.org/ns/shacl#> .');
  writeFileSync(join(root, 'fixtures/defects/planted.trig'),
    '# graph: urn:usf:graph:services\n# expect: servicedisconnected\n@prefix usf: <urn:usf:ontology:> .\n<urn:usf:fixturenode:planted> a usf:Service .\n');
  writeFileSync(join(root, 'fixtures/conforming/clean.trig'),
    '# graph: urn:usf:graph:services\n# conforming\n@prefix usf: <urn:usf:ontology:> .\n<urn:usf:fixturenode:clean> a usf:Service .\n');
  writeFileSync(join(root, 'fixtures/conforming/legacy.ttl'),
    '@prefix usf: <urn:usf:ontology:> .\n<urn:usf:fixturenode:legacy> a usf:Service .\n');
  const manifest = {
    root,
    fixtures: { conforming: 'fixtures/conforming', defects: 'fixtures/defects' },
    shapes: [{ path: join(root, 'shapes.ttl') }],
    rules: [{ kind: 'integrity', path: join(root, 'integrity.rq') }],
  };
  return { root, manifest };
}

function fakeClient(rowsBySubject, { conforms = true, rejectLoad = false, rejectRollback = false, persistedSubjects = [] } = {}) {
  const loaded = [];
  let current = [];
  const calls = { begin: 0, rollback: 0, select: 0, validate: 0 };
  return {
    loaded, calls,
    async connectivity() { return 1; },
    async begin() { calls.begin += 1; current = []; return 'tx'; },
    async rollback() {
      calls.rollback += 1;
      current = [];
      if (rejectRollback) throw Object.assign(new Error('transaction invalidated'), { status: 400 });
    },
    async clearGraph() {},
    async addData(_tx, content) {
      loaded.push(content);
      current.push(content);
      if (rejectLoad) throw Object.assign(new Error('RDF rejected'), { status: 400 });
    },
    async selectInTx() {
      calls.select += 1;
      const transactionContent = current.join('\n');
      const rows = [];
      for (const [subject, violation] of Object.entries(rowsBySubject)) {
        if (transactionContent.includes(subject)) rows.push({ violation: { value: violation }, subject: { value: subject } });
      }
      return rows;
    },
    async validateInTx() { calls.validate += 1; return conforms; },
    async select() {
      return persistedSubjects.map((subject) => ({ subject: { value: subject } }));
    },
  };
}

test('fixture harness detects planted defects, accepts conforming data, reports legacy fixtures', async () => {
  const { root, manifest } = harnessWorkspace();
  try {
    const detectingClient = fakeClient({ 'urn:usf:fixturenode:planted': 'servicedisconnected' });
    const detecting = await verifyFixtures({
      manifest,
      client: detectingClient,
    });
    assert.equal(detecting.ok, true);
    assert.equal(detecting.fixtureCount, 2);
    assert.deepEqual(detecting.skippedLegacyFixtures, ['conforming/legacy.ttl']);
    assert.deepEqual(detectingClient.calls, { begin: 2, rollback: 2, select: 2, validate: 0 });

    const silent = await verifyFixtures({ manifest, client: fakeClient({}) });
    assert.equal(silent.ok, false);
    assert.equal(silent.failures[0].expected, 'servicedisconnected');

    const noisy = await verifyFixtures({
      manifest,
      client: fakeClient({
        'urn:usf:fixturenode:planted': 'servicedisconnected',
        'urn:usf:fixturenode:clean': 'servicedisconnected',
      }),
    });
    assert.equal(noisy.ok, false);
    assert.deepEqual(noisy.failures.map((f) => f.expected), ['conforming']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fixture harness evaluates every registered integrity rule', async () => {
  const { root, manifest } = harnessWorkspace();
  try {
    const second = join(root, 'lifecycle.rq');
    writeFileSync(second, 'SELECT ?violation ?subject WHERE { # SECOND }');
    manifest.rules.push({ kind: 'integrity', path: second });
    const client = fakeClient({});
    client.selectInTx = async (_tx, query) => query.includes('SECOND')
      ? [{ violation: { value: 'servicedisconnected' }, subject: { value: 'urn:usf:fixturenode:planted' } }]
      : [];
    const result = await verifyFixtures({ manifest, client });
    assert.equal(result.ok, true);
    assert.equal(result.results.find((item) => item.fixture === 'defects/planted.trig').detected, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('expect-shacl fixture is detected when the compiled base graph turns non-conforming', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-fixture-harness-shacl-'));
  mkdirSync(join(root, 'fixtures/conforming'), { recursive: true });
  mkdirSync(join(root, 'fixtures/defects'), { recursive: true });
  writeFileSync(join(root, 'integrity.rq'), 'SELECT ?violation ?subject WHERE { }');
  writeFileSync(join(root, 'shapes.ttl'), '@prefix sh: <http://www.w3.org/ns/shacl#> .');
  writeFileSync(join(root, 'fixtures/defects/shacl.trig'),
    '# graph: urn:usf:graph:realisation\n# expect-shacl: nonconforming\n@prefix usf: <urn:usf:ontology:> .\n<urn:usf:fixturenode:shacldefect> a usf:Realisation .\n');
  const manifest = {
    root,
    fixtures: { conforming: 'fixtures/conforming', defects: 'fixtures/defects' },
    shapes: [{ path: join(root, 'shapes.ttl') }],
    rules: [{ kind: 'integrity', path: join(root, 'integrity.rq') }],
  };
  try {
    // Fixture makes the isolated transaction non-conforming -> detected.
    const nonconforming = await verifyFixtures({ manifest, client: fakeClient({}, { conforms: false }) });
    assert.equal(nonconforming.ok, true);
    assert.equal(nonconforming.results[0].expected, 'shacl-nonconforming');
    // If it stays conforming, the expected SHACL defect was not proven -> fail.
    const stillConforming = await verifyFixtures({ manifest, client: fakeClient({}, { conforms: true }) });
    assert.equal(stillConforming.ok, false);
    assert.equal(stillConforming.failures[0].expected, 'shacl-nonconforming');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('expect-load fixture requires a rejected load, live recovery, and no committed subject', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-fixture-harness-load-'));
  mkdirSync(join(root, 'fixtures/conforming'), { recursive: true });
  mkdirSync(join(root, 'fixtures/defects'), { recursive: true });
  writeFileSync(join(root, 'integrity.rq'), 'SELECT ?violation ?subject WHERE { }');
  writeFileSync(join(root, 'shapes.ttl'), '@prefix sh: <http://www.w3.org/ns/shacl#> .');
  const subject = 'urn:usf:fixturenode:rejectedload';
  writeFileSync(join(root, 'fixtures/defects/rejected.ttl'),
    `# expect-load: rejected\n@prefix usf: <urn:usf:ontology:> .\n<${subject}> a usf:Service .\n`);
  const manifest = {
    root,
    fixtures: { conforming: 'fixtures/conforming', defects: 'fixtures/defects' },
    shapes: [{ path: join(root, 'shapes.ttl') }],
    rules: [{ kind: 'integrity', path: join(root, 'integrity.rq') }],
  };
  try {
    const rejected = await verifyFixtures({
      manifest,
      client: fakeClient({}, { rejectLoad: true, rejectRollback: true }),
    });
    assert.equal(rejected.ok, true);
    assert.equal(rejected.results[0].expected, 'load-rejected');
    const leaked = await verifyFixtures({
      manifest,
      client: fakeClient({}, { rejectLoad: true, rejectRollback: true, persistedSubjects: [subject] }),
    });
    assert.equal(leaked.ok, false);
    const accepted = await verifyFixtures({ manifest, client: fakeClient({}) });
    assert.equal(accepted.ok, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
