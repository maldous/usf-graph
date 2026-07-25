// Source/live drift verification and derived-graph snapshotting for the
// canonical semantic model. Read-only against the live semantic authority:
// --check compares every managed graph's canonical live digest against the
// registered repository source; --write-derived refreshes the derived
// snapshot files from live rule output before checking them.
//
// Connection values are resolved through stardog-connection.mjs, so the
// operator env file overrides an inherited STARDOG_* value exactly as it does
// for the MCP launcher and the publication path. `npm run authority:drift` was
// the command that failed with getaddrinfo ENOTFOUND against a reclaimed
// endpoint while the live one sat in the env file.
//
// The last logged published digest is reported alongside the graph comparison.
// The exit-code contract is unchanged: `ok` and `mismatched` continue to mean
// source/live graph parity and nothing else, and a logged-digest mismatch adds
// fields without changing either. operations/stardog/authority-publication-log.json
// is an operational audit record, not semantic authority.
import stardog from 'stardog';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DataFactory, Parser, Store, Writer } from 'n3';

const { createStardogSemanticAuthorityClient } = await import('../../provider-bindings/stardog/semantic-authority.mjs');
const { validateSemanticAuthorityConfiguration } = await import('../../configuration/semantic-assurance/semantic-authority.mjs');
const { resolveEnvironment } = await import('../../configuration/semantic-assurance/stardog-connection.mjs');
const { loadManifest, authoredLoadList, managedGraphs } = await import('../../capabilities/semantic-model-compilation/manifest.mjs');
const { canonicalNQuads, canonicalGraphDigest } = await import('../../capabilities/semantic-model-compilation/compiler.mjs');
const { readSemanticAuthorityWitness } = await import('./semantic-authority-gateway.mjs');

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
  const { STARDOG_SERVER, STARDOG_DATABASE, STARDOG_TOKEN } = resolveEnvironment().env;
  if (!STARDOG_SERVER || !STARDOG_DATABASE || !STARDOG_TOKEN) throw new Error('STARDOG_SERVER, STARDOG_DATABASE and STARDOG_TOKEN are required in the environment or the operator env file');
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

// The publication log is read directly rather than through the publication
// module: this command is read-only and must not import a module whose load
// patches the global fetch dispatcher and pulls in provisioning.
export const PUBLICATION_LOG_PATH = join('operations', 'stardog', 'authority-publication-log.json');

export function readPublicationLogEntries(path, readFile = readFileSync) {
  let text;
  try {
    text = readFile(path, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  const entries = JSON.parse(text);
  if (!Array.isArray(entries)) throw new Error('authority publication log must be a JSON array');
  return entries;
}

// Report whether the last logged published digest is still the live one. `ok`
// and `mismatched` are NOT repurposed: these are additional fields, and a
// logged-digest mismatch does not change the exit code. When the log is empty —
// its seeded state — nothing is claimed and the live witness is not recomputed.
export async function checkLoggedPublication({ live, path, readFile = readFileSync, readWitness = readSemanticAuthorityWitness }) {
  const entries = readPublicationLogEntries(path, readFile);
  const last = entries.length === 0 ? null : entries[entries.length - 1];
  if (!last) {
    return Object.freeze({
      loggedPublicationCount: 0,
      lastLoggedAuthorityDigest: null,
      lastLoggedPublishedAt: null,
      lastLoggedSourceHead: null,
      liveAuthorityDigest: null,
      loggedDigestMatchesLive: null,
    });
  }
  const witness = await readWitness(live);
  const liveAuthorityDigest = witness?.digest ?? witness?.authorityDigest ?? null;
  return Object.freeze({
    loggedPublicationCount: entries.length,
    lastLoggedAuthorityDigest: last.authorityDigest ?? null,
    lastLoggedPublishedAt: last.publishedAt ?? null,
    lastLoggedSourceHead: last.sourceHead ?? null,
    liveAuthorityDigest,
    loggedDigestMatchesLive: (last.authorityDigest ?? null) === liveAuthorityDigest,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const manifest = loadManifest(join(repositoryRoot(), 'semantic-model'));
  const live = client();
  if (process.argv.includes('--write-derived')) {
    const written = await snapshotDerived({ manifest, live });
    process.stdout.write(`${JSON.stringify({ command: 'snapshot-derived', written })}\n`);
  }
  const drift = await checkDrift({ manifest, live });
  const logged = await checkLoggedPublication({ live, path: join(repositoryRoot(), PUBLICATION_LOG_PATH) });
  process.stdout.write(`${JSON.stringify({
    command: 'drift',
    ok: drift.ok,
    graphCount: drift.graphCount,
    mismatched: drift.mismatched,
    ...logged,
    publicationLogRole: 'operational-record-not-semantic-authority',
  })}\n`);
  // Unchanged contract: only source/live graph parity decides the exit code.
  if (!drift.ok) process.exitCode = 1;
}
