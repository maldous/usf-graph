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
//   # conforming                    integrity SELECT must report nothing for
//                                   any subject introduced by the fixture
// Fixtures without headers predate the harness and are reported as skipped —
// never silently.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Parser } from 'n3';
import { CompilerError } from './compiler.js';
import { integrityRule } from './manifest.js';

export function parseFixtureHeader(text) {
  const header = { graph: null, expect: null, expectShacl: false, conforming: false };
  for (const line of text.split('\n').slice(0, 10)) {
    if (!line.startsWith('#')) continue;
    const graph = line.match(/^#\s*graph:\s*(\S+)\s*$/);
    if (graph) header.graph = graph[1];
    const expect = line.match(/^#\s*expect:\s*(\S+)\s*$/);
    if (expect) header.expect = expect[1];
    if (/^#\s*expect-shacl:\s*nonconforming\s*$/.test(line)) header.expectShacl = true;
    if (/^#\s*conforming\s*$/.test(line)) header.conforming = true;
  }
  header.annotated = Boolean(header.expect || header.expectShacl || header.conforming);
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

export async function verifyFixtures({ manifest, client }) {
  await client.connectivity();
  const integrityEntry = integrityRule(manifest);
  if (!integrityEntry) throw new CompilerError('no integrity rule registered', { phase: 'fixtures:configuration' });
  const integritySparql = readFileSync(integrityEntry.path, 'utf8');
  const shapes = shapeConstraints(manifest);
  const results = [];
  const skipped = [];
  for (const fixture of fixtureFiles(manifest)) {
    const text = readFileSync(fixture.path, 'utf8');
    const header = parseFixtureHeader(text);
    if (!header.annotated) {
      skipped.push(`${fixture.kind}/${fixture.name}`);
      continue;
    }
    const subjects = fixtureSubjects(text, fixture.path);
    const isTrig = /^\s*<urn:usf:graph:/m.test(text) && /{/.test(text);
    const tx = await client.begin();
    let outcome;
    try {
      if (isTrig) await client.addData(tx, text, 'application/trig');
      else await client.addData(tx, text, 'text/turtle', header.graph);
      if (header.expect) {
        const rows = await client.selectInTx(tx, integritySparql);
        const hit = rows.some(
          (row) => row.violation?.value === header.expect && subjects.has(row.subject?.value)
        );
        outcome = { expected: header.expect, detected: hit };
      } else if (header.conforming) {
        const rows = await client.selectInTx(tx, integritySparql);
        const offending = rows
          .filter((row) => subjects.has(row.subject?.value))
          .map((row) => row.violation?.value);
        outcome = { expected: 'conforming', detected: offending.length === 0, offending };
      } else if (header.expectShacl) {
        // The base graph is proven SHACL-conforming by the compile before the
        // harness runs, and each fixture loads in its own rolled-back
        // transaction whose only delta is the fixture's own triples. So a
        // non-conforming result here is attributable to the fixture — no
        // report focus-node join is needed (and Stardog's report
        // serialisation does not round-trip reliably for that).
        const conforms = await client.validateInTx(tx, shapes);
        outcome = { expected: 'shacl-nonconforming', detected: conforms === false };
      }
    } finally {
      await client.rollback(tx);
    }
    results.push({ fixture: `${fixture.kind}/${fixture.name}`, ...outcome });
  }
  const failures = results.filter((row) => !row.detected);
  return {
    ok: failures.length === 0,
    fixtureCount: results.length,
    failures,
    results,
    skippedLegacyFixtures: skipped,
  };
}
