// Source/live drift verification and derived-graph snapshotting for the
// canonical semantic model. Read-only against the live semantic authority:
// --check compares every managed graph's canonical live digest against the
// registered repository source; --write-derived refreshes the derived
// snapshot files from live rule output before checking them.
import stardog from 'stardog';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DataFactory, Parser, Store, Writer } from 'n3';

const { createStardogSemanticAuthorityClient } = await import('../../provider-bindings/stardog/semantic-authority.mjs');
const { validateSemanticAuthorityConfiguration } = await import('../../configuration/semantic-assurance/semantic-authority.mjs');
const { loadManifest, authoredLoadList, managedGraphs } = await import('../../capabilities/semantic-model-compilation/manifest.mjs');
const { canonicalNQuads, canonicalGraphDigest } = await import('../../capabilities/semantic-model-compilation/compiler.mjs');

const NQUADS = 'application/n-quads';
const { literal, namedNode, quad } = DataFactory;

// Mirror the compiler's transport canonicalisation: every xsd integer-family
// literal is loaded as plain xsd:integer, so the live graphs return that form.
const XSD = 'http://www.w3.org/2001/XMLSchema#';
const XSD_INTEGER_FAMILY = new Set([
  'integer', 'nonNegativeInteger', 'nonPositiveInteger', 'negativeInteger', 'positiveInteger',
  'long', 'int', 'short', 'byte',
  'unsignedLong', 'unsignedInt', 'unsignedShort', 'unsignedByte',
].map((name) => XSD + name));
const canonicalObject = (object) => object.termType === 'Literal' && XSD_INTEGER_FAMILY.has(object.datatype.value)
  ? literal(object.value, namedNode(`${XSD}integer`))
  : object;

function repositoryRoot() {
  return resolve(fileURLToPath(import.meta.url), '../../..');
}

function client() {
  const { STARDOG_SERVER, STARDOG_DATABASE, STARDOG_TOKEN } = process.env;
  if (!STARDOG_SERVER || !STARDOG_DATABASE || !STARDOG_TOKEN) throw new Error('STARDOG_SERVER, STARDOG_DATABASE and STARDOG_TOKEN are required in the environment');
  const TOKEN_REFERENCE = 'secret://semantic-authority/token';
  return createStardogSemanticAuthorityClient({
    sdk: stardog,
    configuration: validateSemanticAuthorityConfiguration({
      accessMode: 'live',
      expectedAuthorityDigest: `sha256:${'0'.repeat(64)}`,
      endpoint: STARDOG_SERVER,
      database: STARDOG_DATABASE,
      authentication: { mode: 'token', tokenReference: TOKEN_REFERENCE },
    }),
    resolveSecret: () => STARDOG_TOKEN,
  });
}

async function localGraphQuads(manifest) {
  const root = manifest.root;
  // Stores deduplicate identical triples the same way the live dataset does.
  const stores = new Map();
  const record = (graph, item) => {
    if (!stores.has(graph)) stores.set(graph, new Store());
    stores.get(graph).add(item);
  };
  const entries = [...authoredLoadList(manifest), ...manifest.shapes, ...manifest.derived];
  for (const entry of entries) {
    if (!entry.file) continue;
    const content = readFileSync(join(root, entry.file), 'utf8');
    const parser = new Parser({ format: entry.contentType === 'application/trig' ? 'application/trig' : 'text/turtle' });
    const graphTerm = namedNode(entry.graph);
    for (const parsed of parser.parse(content)) {
      const graph = parsed.graph && parsed.graph.termType === 'NamedNode' ? parsed.graph.value : entry.graph;
      // Digest per-graph triples: the live comparison side constructs each
      // graph's content without a graph term.
      record(graph, quad(parsed.subject, parsed.predicate, canonicalObject(parsed.object)));
    }
  }
  return stores;
}

const serialiseNQuads = (quads) => new Promise((res, rej) => {
  const writer = new Writer({ format: 'N-Quads' });
  writer.addQuads(quads);
  writer.end((error, result) => error ? rej(error) : res(result));
});

async function liveGraphDigest(live, graph) {
  const content = await live.construct(`CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`, NQUADS);
  return { content, ...await canonicalGraphDigest(content) };
}

export async function snapshotDerived({ manifest, live }) {
  const written = [];
  for (const entry of manifest.derived) {
    const { content } = await liveGraphDigest(live, entry.graph);
    const canonical = await canonicalNQuads(content);
    const lines = canonical.split('\n').filter(Boolean)
      .map((line) => `  ${line.trim()}`)
      .sort();
    const body = `GRAPH <${entry.graph}> {\n${lines.join('\n')}\n}\n`;
    const target = join(manifest.root, entry.file);
    const temporary = `${target}.${process.pid}.tmp`;
    writeFileSync(temporary, body);
    renameSync(temporary, target);
    written.push(entry.file);
  }
  return written;
}

export async function checkDrift({ manifest, live }) {
  const local = await localGraphQuads(manifest);
  const report = [];
  for (const graph of managedGraphs(manifest)) {
    const liveState = await liveGraphDigest(live, graph);
    const store = local.get(graph);
    const quads = store ? store.getQuads(null, null, null, null) : [];
    const localState = await canonicalGraphDigest(await serialiseNQuads(quads));
    report.push({
      graph,
      match: liveState.sha256 === localState.sha256 && liveState.triples === localState.triples,
      live: { digest: liveState.sha256, triples: liveState.triples },
      local: { digest: localState.sha256, triples: localState.triples },
    });
  }
  const mismatched = report.filter((entry) => !entry.match).map((entry) => entry.graph);
  return Object.freeze({ ok: mismatched.length === 0, mismatched, graphCount: report.length, report });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const manifest = loadManifest(join(repositoryRoot(), 'semantic-model'));
  const live = client();
  if (process.argv.includes('--write-derived')) {
    const written = await snapshotDerived({ manifest, live });
    process.stdout.write(`${JSON.stringify({ command: 'snapshot-derived', written })}\n`);
  }
  const drift = await checkDrift({ manifest, live });
  process.stdout.write(`${JSON.stringify({ command: 'drift', ok: drift.ok, graphCount: drift.graphCount, mismatched: drift.mismatched })}\n`);
  if (!drift.ok) process.exitCode = 1;
}
