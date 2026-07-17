// Fixture verification harness.
//
// Loads each annotated fixture into a rolled-back transaction against the
// compiled database and proves that planted-defect fixtures fail for their
// intended reason and that conforming fixtures introduce no violation.
//
// A fixture opts in through header comments:
//   # graph: <named-graph-iri>      target graph for Turtle content
//   # expect: <integrity-code>      integrity SELECT must report this code
//                                   for a subject introduced by the fixture
//   # expect-shacl: nonconforming   SHACL validation must not conform
//   # expect-load: rejected         RDF load must fail without persistence
//   # conforming                    integrity SELECT must report nothing for
//                                   any subject introduced by the fixture
// Fixtures without headers predate the harness and are reported as skipped —
// never silently.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Parser } from 'n3';
import { CompilerError } from './compiler.js';
import { integrityRules } from './manifest.js';

export function parseFixtureHeader(text) {
  const header = { graph: null, expect: null, expectShacl: false, expectLoad: false, conforming: false };
  for (const line of text.split('\n').slice(0, 10)) {
    if (!line.startsWith('#')) continue;
    const graph = line.match(/^#\s*graph:\s*(\S+)\s*$/);
    if (graph) header.graph = graph[1];
    const expect = line.match(/^#\s*expect:\s*(\S+)\s*$/);
    if (expect) header.expect = expect[1];
    if (/^#\s*expect-shacl:\s*nonconforming\s*$/.test(line)) header.expectShacl = true;
    if (/^#\s*expect-load:\s*rejected\s*$/.test(line)) header.expectLoad = true;
    if (/^#\s*conforming\s*$/.test(line)) header.conforming = true;
  }
  header.annotated = Boolean(header.expect || header.expectShacl || header.expectLoad || header.conforming);
  return header;
}

export function fixtureSubjects(text, path) {
  const format = path.endsWith('.trig') && /{/.test(text) ? 'application/trig' : 'text/turtle';
  const subjects = new Set();
  for (const quad of new Parser({ format, baseIRI: 'urn:usf:' }).parse(text)) {
    if (quad.subject.termType === 'NamedNode') subjects.add(quad.subject.value);
  }
  return subjects;
}

export function scopeIntegrityQuery(sparql, subjects) {
  const values = [...subjects].sort();
  if (values.length === 0) throw new Error('annotated fixture has no named USF subject');
  if (values.some((subject) => !/^urn:usf:[A-Za-z0-9:._~-]+$/.test(subject))) throw new Error('fixture subject is not a safe USF IRI');
  const select = /SELECT\s+(?:DISTINCT\s+)?\?violation\s+\?subject\s+WHERE\s*\{/i;
  if (!select.test(sparql)) throw new Error('integrity rule does not expose ?violation and ?subject');
  const clause = `VALUES ?subject { ${values.map((subject) => `<${subject}>`).join(' ')} }`;
  return sparql.replace(select, (match) => `${match}\n  ${clause}`);
}

function fixtureFiles(manifest) {
  const files = [];
  for (const key of ['conforming', 'defects']) {
    const root = manifest.fixtures?.[key];
    if (!root) continue;
    const dir = join(manifest.root, root);
    for (const name of readdirSync(dir).sort()) {
      if (/\.(ttl|trig)$/.test(name)) files.push({ kind: key, name, path: join(dir, name) });
    }
  }
  return files;
}

function shapeConstraints(manifest) {
  return manifest.shapes.map((s) => readFileSync(s.path, 'utf8')).join('\n');
}

async function loadCandidateDefinitions(client, tx, manifest) {
  // Candidate ontology terms must be visible before their first publication;
  // controlled values introduced by a fixture remain explicit fixture data.
  // Overlay only the ontology graph so every fixture transaction stays bounded.
  for (const entry of (manifest.definitions || []).filter((item) => item.role === 'ontology')) {
    await client.clearGraph(tx, entry.graph);
    await client.addData(tx, readFileSync(entry.path, 'utf8'), entry.contentType, entry.graph);
  }
}

async function withRolledBackTransaction(client, operation) {
  const tx = await client.begin();
  let result;
  let primaryError;
  try {
    result = await operation(tx);
  } catch (error) {
    primaryError = error;
  }
  try {
    await client.rollback(tx);
  } catch (rollbackError) {
    if (primaryError) {
      throw new AggregateError([primaryError, rollbackError], 'fixture transaction failed and rollback was not confirmed');
    }
    throw rollbackError;
  }
  if (primaryError) throw primaryError;
  return result;
}

async function loadFixture(client, tx, item) {
  if (item.isTrig) await client.addData(tx, item.text, 'application/trig');
  else await client.addData(tx, item.text, 'text/turtle', item.header.graph);
}

function subjectPresenceQuery(subjects) {
  const values = [...subjects].sort();
  if (!values.length || values.some((subject) => !/^urn:usf:[A-Za-z0-9:._~-]+$/.test(subject))) {
    throw new Error('load-rejection fixture has no safe named USF subject');
  }
  return `SELECT DISTINCT ?subject WHERE { VALUES ?subject { ${values.map((subject) => `<${subject}>`).join(' ')} } ?subject ?predicate ?object } LIMIT ${values.length}`;
}

async function verifyRejectedLoad(client, item) {
  const tx = await client.begin();
  let loadError;
  try {
    await loadFixture(client, tx, item);
  } catch (error) {
    loadError = error;
  }
  if (!loadError) {
    await client.rollback(tx);
    return false;
  }
  let rollbackError;
  try {
    await client.rollback(tx);
  } catch (error) {
    rollbackError = error;
  }
  if (loadError.status !== 400 || (rollbackError && rollbackError.status !== 400)) {
    if (rollbackError) throw new AggregateError([loadError, rollbackError], 'unexpected load rejection and rollback failure');
    throw loadError;
  }
  // Stardog invalidates the transaction after rejecting malformed RDF and
  // reports that invalidated transaction as a 400 on rollback. Prove recovery
  // and absence from committed state instead of treating that response as a
  // successful rollback.
  await client.connectivity();
  const persisted = await client.select(subjectPresenceQuery(item.subjects));
  return !persisted.some((row) => item.subjects.has(row.subject?.value));
}

export async function verifyFixtures({ manifest, client }) {
  await client.connectivity();
  const integrityEntries = integrityRules(manifest);
  if (!integrityEntries.length) throw new CompilerError('no integrity rule registered', { phase: 'fixtures:configuration' });
  const integritySparql = integrityEntries.map((entry) => readFileSync(entry.path, 'utf8'));
  const shapes = shapeConstraints(manifest);
  const results = [];
  const skipped = [];
  const annotated = [];
  for (const fixture of fixtureFiles(manifest)) {
    const text = readFileSync(fixture.path, 'utf8');
    const header = parseFixtureHeader(text);
    if (!header.annotated) {
      skipped.push(`${fixture.kind}/${fixture.name}`);
      continue;
    }
    const subjects = fixtureSubjects(text, fixture.path);
    const isTrig = /^\s*<urn:usf:graph:/m.test(text) && /{/.test(text);
    annotated.push({ fixture, text, header, subjects, isTrig });
  }
  const integrityFixtures = annotated.filter(({ header }) => header.expect || header.conforming);
  for (const item of integrityFixtures) {
    const subjects = item.subjects;
    const rows = await withRolledBackTransaction(client, async (tx) => {
      await loadCandidateDefinitions(client, tx, manifest);
      await loadFixture(client, tx, item);
      const rows = [];
      for (const sparql of integritySparql) {
        rows.push(...await client.selectInTx(tx, scopeIntegrityQuery(sparql, subjects)));
      }
      return rows;
    });
    let outcome;
    if (item.header.expect) {
      const hit = rows.some(
        (row) => row.violation?.value === item.header.expect && item.subjects.has(row.subject?.value)
      );
      outcome = { expected: item.header.expect, detected: hit };
    } else {
      const offending = rows
        .filter((row) => item.subjects.has(row.subject?.value))
        .map((row) => row.violation?.value);
      outcome = { expected: 'conforming', detected: offending.length === 0, offending };
    }
    results.push({ fixture: `${item.fixture.kind}/${item.fixture.name}`, ...outcome });
  }
  for (const item of annotated.filter(({ header }) => header.expectLoad && !header.expect && !header.conforming)) {
    results.push({
      fixture: `${item.fixture.kind}/${item.fixture.name}`,
      expected: 'load-rejected',
      detected: await verifyRejectedLoad(client, item),
    });
  }
  for (const item of annotated.filter(({ header }) => header.expectShacl && !header.expect && !header.conforming)) {
    const conforms = await withRolledBackTransaction(client, async (tx) => {
      await loadCandidateDefinitions(client, tx, manifest);
      await loadFixture(client, tx, item);
      return client.validateInTx(tx, shapes);
    });
    results.push({
      fixture: `${item.fixture.kind}/${item.fixture.name}`,
      expected: 'shacl-nonconforming',
      detected: conforms === false,
    });
  }
  results.sort((left, right) => left.fixture.localeCompare(right.fixture));
  const failures = results.filter((row) => !row.detected);
  return {
    ok: failures.length === 0,
    fixtureCount: results.length,
    failures,
    results,
    skippedLegacyFixtures: skipped,
  };
}
