import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { DataFactory, Parser, Store, Writer } from 'n3';
import * as rdfCanonize from 'rdf-canonize';

import { authoredLoadList, managedGraphs } from './manifest.js';
import { compile, CompilerError, verificationConforms, verify as verifyDatabase } from './compiler.js';

const { blankNode, defaultGraph, quad } = DataFactory;
const NQUADS = 'application/n-quads';
const REPOSITORY_BINDING_EXCLUSIONS = Object.freeze([
  'v2/usf/census/audit.json',
  'v2/usf/census/closure.json',
]);
const isRepositoryBindingExcluded = (item) =>
  REPOSITORY_BINDING_EXCLUSIONS.includes(item) || item.startsWith('v2/usf/.work/');
const REQUIRED_ROLLBACK_FAULTS = Object.freeze([
  'clear-graph',
  'collect-observed',
  'commit',
  'contamination',
  'derive',
  'derived-insert',
  'integrity',
  'invalid-observed-rdf',
  'load',
  'rollback-response',
  'validate-authored',
  'validate-derived',
  'validate-observed',
  'verify-counts',
  'wrong-rule-output',
]);

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

export const stableJson = (value) => JSON.stringify(stable(value));

const XSD = 'http://www.w3.org/2001/XMLSchema#';
const XSD_INTEGER_FAMILY = new Set([
  'nonNegativeInteger', 'positiveInteger', 'nonPositiveInteger', 'negativeInteger',
  'long', 'int', 'short', 'byte',
  'unsignedLong', 'unsignedInt', 'unsignedShort', 'unsignedByte',
].map((name) => XSD + name));

// Stardog stores literals in canonical form: every xsd:integer-derived
// datatype is normalised to xsd:integer. The digest contract applies the same
// normalisation so source files and live graphs hash identically.
function canonicalLiteralQuad(item) {
  const object = item.object;
  if (object.termType !== 'Literal' || !XSD_INTEGER_FAMILY.has(object.datatype.value)) return item;
  return quad(
    item.subject,
    item.predicate,
    DataFactory.literal(object.value, DataFactory.namedNode(XSD + 'integer')),
    item.graph,
  );
}

async function canonicalNQuads(nquads) {
  // Parse with N3 and canonize the quad array: rdf-canonize's own string
  // parser is pathologically slow on large literals (hours vs seconds for the
  // observed graph), while the canonical output is identical either way.
  const quads = new Parser({ format: NQUADS }).parse(nquads).map(canonicalLiteralQuad);
  return rdfCanonize.canonize(quads, {
    algorithm: 'RDFC-1.0',
    format: NQUADS,
  });
}

function nquadsFor(quads) {
  return new Promise((resolveOutput, reject) => {
    const writer = new Writer({ format: 'N-Quads' });
    writer.addQuads(quads);
    writer.end((error, output) => error ? reject(error) : resolveOutput(output));
  });
}

export async function canonicalGraphDigest(nquads) {
  const canonical = await canonicalNQuads(nquads);
  return {
    algorithm: 'RDFC-1.0',
    digestAlgorithm: 'sha256',
    sha256: sha256(canonical),
    triples: canonical.split('\n').filter(Boolean).length,
  };
}

export async function canonicalGraphTrig(graph, nquads) {
  if (typeof graph !== 'string' || !graph.startsWith('urn:usf:graph:derived:')) {
    throw new CompilerError('derived snapshot requires a registered derived graph IRI', { phase: 'snapshot:derived' });
  }
  const canonical = await canonicalNQuads(nquads);
  const triples = canonical.split('\n').filter(Boolean);
  if (!triples.length) throw new CompilerError(`derived graph is empty: ${graph}`, { phase: 'snapshot:derived' });
  return `GRAPH <${graph}> {\n${triples.map((line) => `  ${line}`).join('\n')}\n}\n`;
}

function scopeBlankNodes(parsed, scope) {
  const ids = new Map();
  const scoped = (term) => {
    if (term.termType !== 'BlankNode') return term;
    if (!ids.has(term.value)) ids.set(term.value, blankNode(`${scope}_${ids.size}`));
    return ids.get(term.value);
  };
  return parsed.map((item) => quad(
    scoped(item.subject),
    item.predicate,
    scoped(item.object),
    defaultGraph(),
  ));
}

function graphEntries(manifest) {
  return [...authoredLoadList(manifest), ...manifest.observed, ...manifest.shapes, ...manifest.derived];
}

export async function localGraphDigests(manifest) {
  // RDF graphs are sets. Source files can repeat an asserted triple across
  // authorised fragments, while Stardog stores that triple only once. Use an
  // N3 Store per named graph so source and live digest the same RDF dataset
  // rather than comparing source-line multiplicity with database set
  // semantics.
  const grouped = new Map(managedGraphs(manifest).map((graph) => [graph, new Store()]));
  for (const [index, entry] of graphEntries(manifest).entries()) {
    const parsed = new Parser({ format: entry.contentType, baseIRI: 'urn:usf:' })
      .parse(readFileSync(entry.path, 'utf8'));
    const bucket = grouped.get(entry.graph);
    // add one by one: spreading ~500k quads overflows the argument stack
    for (const scopedQuad of scopeBlankNodes(parsed, `f${index}`)) bucket.addQuad(scopedQuad);
  }
  const records = [];
  for (const graph of [...grouped.keys()].sort()) {
    records.push({ graph, ...await canonicalGraphDigest(await nquadsFor(grouped.get(graph).getQuads(null, null, null, null))) });
  }
  return records;
}

export async function liveGraphDigests(manifest, client) {
  const rows = await client.select(
    'SELECT DISTINCT ?g WHERE { GRAPH ?g { ?s ?p ?o } FILTER(STRSTARTS(STR(?g), "urn:usf:graph:")) }',
  );
  const present = rows.map((row) => row.g?.value).filter(Boolean);
  const graphs = new Set([...managedGraphs(manifest), ...present]);
  const records = [];
  for (const graph of [...graphs].sort()) {
    const content = await client.construct(
      `CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`,
      NQUADS,
    );
    const record = { graph, ...await canonicalGraphDigest(content) };
    if (record.triples > 0) records.push(record);
  }
  return records;
}

export async function snapshotDerivedGraphs({ manifest, client }) {
  await client.connectivity();
  const staged = [];
  try {
    for (const entry of manifest.derived) {
      const nquads = await client.construct(
        `CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${entry.graph}> { ?s ?p ?o } }`,
        NQUADS,
      );
      const content = await canonicalGraphTrig(entry.graph, nquads);
      const temporary = `${entry.path}.next`;
      writeFileSync(temporary, content, { encoding: 'utf8', mode: 0o644 });
      staged.push({ entry, temporary, content });
    }
    for (const item of staged) renameSync(item.temporary, item.entry.path);
  } catch (error) {
    for (const item of staged) if (existsSync(item.temporary)) unlinkSync(item.temporary);
    if (error instanceof CompilerError) throw error;
    throw new CompilerError(error.message, { phase: 'snapshot:derived' });
  }
  const source = await localGraphDigests(manifest);
  const database = await liveGraphDigests(manifest, client);
  const comparison = compareGraphDigests(source, database);
  if (comparison.missingGraphs.length || comparison.unexpectedGraphs.length || comparison.mismatchedGraphs.length) {
    throw new CompilerError('derived snapshots do not match live rule output', {
      phase: 'snapshot:derived:parity', failures: comparison,
    });
  }
  return {
    ok: true,
    graphs: staged.map(({ entry, content }) => ({
      graph: entry.graph,
      file: entry.file,
      triples: content.split('\n').filter((line) => line.trim().endsWith(' .')).length,
      sha256: sha256(content),
    })),
    comparison,
  };
}

export function compareGraphDigests(source, database) {
  const expected = new Map(source.map((item) => [item.graph, item]));
  const observed = new Map(database.map((item) => [item.graph, item]));
  return {
    missingGraphs: [...expected.keys()].filter((graph) => !observed.has(graph)).sort(),
    unexpectedGraphs: [...observed.keys()].filter((graph) => !expected.has(graph)).sort(),
    mismatchedGraphs: [...expected.keys()].filter((graph) =>
      observed.has(graph) && (
        expected.get(graph).sha256 !== observed.get(graph).sha256 ||
        expected.get(graph).triples !== observed.get(graph).triples
      )
    ).sort(),
  };
}

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: null, maxBuffer: 128 * 1024 * 1024 });
}

export function repositoryState(repoRoot) {
  const root = realpathSync(repoRoot);
  const paths = git(root, ['ls-files', '-co', '--exclude-standard', '-z'])
    .toString('utf8').split('\0').filter(Boolean)
    .filter((item) => !isRepositoryBindingExcluded(item)).sort();
  const accumulator = createHash('sha256');
  for (const path of paths) {
    const absolute = resolve(root, path);
    const content = !existsSync(absolute)
      ? Buffer.from('deleted')
      : lstatSync(absolute).isSymbolicLink()
        ? Buffer.from(`symlink:${readlinkSync(absolute)}`)
        : readFileSync(absolute);
    accumulator.update(path).update('\0').update(sha256(content)).update('\n');
  }
  const statusEntries = git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])
    .toString('utf8').split('\0').filter(Boolean);
  const includedStatus = [];
  for (let index = 0; index < statusEntries.length; index += 1) {
    const entry = statusEntries[index];
    const status = entry.slice(0, 2);
    const firstPath = entry.slice(3);
    const secondPath = status.includes('R') || status.includes('C') ? statusEntries[++index] : null;
    if (isRepositoryBindingExcluded(firstPath) || (secondPath && isRepositoryBindingExcluded(secondPath))) continue;
    includedStatus.push(entry);
    if (secondPath) includedStatus.push(secondPath);
  }
  const status = Buffer.from(includedStatus.join('\0'));
  return {
    gitHead: git(root, ['rev-parse', 'HEAD']).toString('utf8').trim(),
    files: paths.length,
    contentRootSha256: accumulator.digest('hex'),
    statusSha256: sha256(status),
    clean: status.length === 0,
    excludedPaths: [...REPOSITORY_BINDING_EXCLUSIONS, 'v2/usf/.work/'],
  };
}

function registeredSourceFiles(manifest, repoRoot) {
  return graphEntries(manifest).map((entry) => ({
    path: relative(repoRoot, entry.path).split(sep).join('/'),
    sha256: sha256(readFileSync(entry.path)),
  })).sort((a, b) => a.path.localeCompare(b.path));
}

function fingerprint(publicKey) {
  return sha256(publicKey.export({ type: 'spki', format: 'der' }));
}

function outsideRepository(path, repoRoot) {
  const resolved = resolve(path);
  const rel = relative(realpathSync(repoRoot), resolved);
  return rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

export async function observeLiveDrift({ manifest, client }) {
  const sourceGraphDigests = await localGraphDigests(manifest);
  const databaseGraphDigests = await liveGraphDigests(manifest, client);
  const comparison = compareGraphDigests(sourceGraphDigests, databaseGraphDigests);
  return {
    conforms: comparison.missingGraphs.length === 0 &&
      comparison.unexpectedGraphs.length === 0 && comparison.mismatchedGraphs.length === 0,
    sourceGraphDigests,
    databaseGraphDigests,
    comparison,
  };
}

function verificationProjection(report) {
  return {
    reachable: report.reachable,
    // These compatibility field names are consumed by the independent census
    // verifier. Their scope is explicit and is intentionally narrower than
    // the whole-database diagnostics returned by compiler `verify`.
    countScope: 'registered-usf-graphs',
    graphCount: report.registeredGraphCount,
    tripleCount: report.registeredTripleCount,
    missingGraphs: report.missingGraphs,
    unexpectedGraphs: report.unexpectedGraphs,
    validationConforms: report.validationConforms,
    integrityConforms: report.integrityConforms,
    contaminationCount: report.contaminationCount,
    readinessCount: report.readinessCount,
  };
}

function verificationPasses(report) {
  return report.countScope === 'registered-usf-graphs' && verificationConforms(report);
}

export async function proveLiveRollback({ manifest, client }) {
  const before = await liveGraphDigests(manifest, client);
  const firstAuthored = authoredLoadList(manifest)[0].graph;
  const derivedGraphs = new Set(manifest.derived.map((entry) => entry.graph));
  const faults = [
    ['clear-graph', (activate) => ({
      overrides: { async clearGraph() { activate(); throw new Error('injected graph-clear failure'); } },
      injectionPoint: 'registered-graph-clear',
    })],
    ['load', (activate) => ({
      overrides: { async addData() { activate(); throw new Error('injected authored-load failure'); } },
      injectionPoint: 'authored-add-data',
    })],
    ['collect-observed', (activate) => ({
      compileOptions: {
        observedCollector: async () => { activate(); throw new Error('injected observed collection failure'); },
      },
      injectionPoint: 'observed-collector',
    })],
    ['invalid-observed-rdf', (activate) => ({
      compileOptions: {
        observedCollector: async ({ entry }) => {
          activate();
          return {
            graph: entry.graph,
            contentType: 'text/turtle',
            content: '<urn:usf:invalid',
            sourceCount: 1,
            tripleCount: 1,
            observationSetDigest: '0'.repeat(64),
            excludedCarrierPaths: [],
          };
        },
      },
      injectionPoint: 'observed-invalid-rdf',
    })],
    ['validate-authored', (activate) => {
      let calls = 0;
      return {
        overrides: { async validateInTx(...args) { calls += 1; if (calls === 1) { activate(); return false; } return client.validateInTx(...args); } },
        injectionPoint: 'authored-validation-result',
      };
    }],
    ['validate-observed', (activate) => {
      let calls = 0;
      return {
        overrides: { async validateInTx(...args) { calls += 1; if (calls === 2) { activate(); return false; } return client.validateInTx(...args); } },
        injectionPoint: 'observed-validation-result',
      };
    }],
    ['derive', (activate) => ({
      overrides: { async constructInTx() { activate(); throw new Error('injected derivation failure'); } },
      injectionPoint: 'rule-construct',
    })],
    ['wrong-rule-output', (activate) => ({
      overrides: { async constructInTx() { activate(); return ''; } },
      injectionPoint: 'rule-construct-output',
    })],
    ['derived-insert', (activate) => ({
      overrides: {
        async addData(tx, content, contentType, graph) {
          if (derivedGraphs.has(graph)) { activate(); throw new Error('injected derived-insert failure'); }
          return client.addData(tx, content, contentType, graph);
        },
      },
      injectionPoint: 'derived-add-data',
    })],
    ['validate-derived', (activate) => {
      let calls = 0;
      return {
        overrides: { async validateInTx(...args) { calls += 1; if (calls === 3) { activate(); return false; } return client.validateInTx(...args); } },
        injectionPoint: 'derived-validation-result',
      };
    }],
    ['integrity', (activate) => ({
      overrides: {
        async selectInTx(tx, query) {
          if (query.includes('?violation')) { activate(); return [{ violation: { value: 'injected' }, subject: { value: 'urn:usf:injected' } }]; }
          return client.selectInTx(tx, query);
        },
      },
      injectionPoint: 'integrity-query-result',
    })],
    ['contamination', (activate) => ({
      overrides: {
        async selectInTx(tx, query) {
          if (query.includes('REGEX(CONCAT')) { activate(); return [{ c: { value: '1' } }]; }
          return client.selectInTx(tx, query);
        },
      },
      injectionPoint: 'contamination-query-result',
    })],
    ['verify-counts', (activate) => ({
      overrides: {
        async selectInTx(tx, query) {
          if (query.includes(`GRAPH <${firstAuthored}>`) && query.includes('COUNT(*)')) { activate(); return [{ c: { value: '0' } }]; }
          return client.selectInTx(tx, query);
        },
      },
      injectionPoint: 'required-resource-count',
    })],
    ['commit', (activate) => ({
      // The official SDK exposes commit as one promise. Safely proving an
      // error after server commit would risk committing the fault run, so this
      // injection is deliberately before SDK dispatch and the limitation is
      // retained in the signed machine output below.
      overrides: { async commit() { activate(); throw new Error('injected pre-dispatch commit failure'); } },
      injectionPoint: 'before-official-sdk-commit-dispatch',
    })],
    ['rollback-response', (activate) => ({
      overrides: {
        async addData() { throw new Error('injected pre-commit failure'); },
        async rollback(tx) {
          activate();
          await client.rollback(tx);
          throw new Error('injected ambiguous rollback response');
        },
      },
      injectionPoint: 'after-official-sdk-rollback-dispatch',
    })],
  ];
  const configuredFaults = faults.map(([name]) => name).sort();
  if (stableJson(configuredFaults) !== stableJson(REQUIRED_ROLLBACK_FAULTS)) {
    throw new CompilerError('rollback proof barriers differ from the attestation verification contract', {
      phase: 'attest:rollback',
      failures: [{ configuredFaults, requiredFaults: REQUIRED_ROLLBACK_FAULTS }],
    });
  }
  const results = [];
  for (const [index, [name, buildFault]] of faults.entries()) {
    process.stderr.write(`attest: rollback fault ${index + 1}/${faults.length}: ${name}\n`);
    let rollbacks = 0;
    let activationCount = 0;
    const injected = buildFault(() => { activationCount += 1; });
    const injectedRollback = injected.overrides?.rollback;
    const faultClient = {
      ...client,
      ...injected.overrides,
      async rollback(tx) {
        rollbacks += 1;
        if (injectedRollback) return injectedRollback(tx);
        return client.rollback(tx);
      },
    };
    let observedError = null;
    try {
      await compile({ manifest, client: faultClient, ...(injected.compileOptions ?? {}) });
    } catch (error) {
      observedError = error;
    }
    if (!observedError || rollbacks !== 1 || activationCount < 1) {
      throw new CompilerError(`rollback fault was not proven: ${name}`, {
        phase: 'attest:rollback', failures: [{ name, rollbacks, activationCount }],
      });
    }
    results.push({
      name,
      injectionPoint: injected.injectionPoint,
      activationCount,
      rollbackCount: rollbacks,
      errorPhase: observedError.phase ?? 'compile',
    });
  }
  const after = await liveGraphDigests(manifest, client);
  const digestsUnchanged = stableJson(before) === stableJson(after);
  if (!digestsUnchanged) throw new CompilerError('live graph drift followed rollback fault proof', {
    phase: 'attest:rollback', failures: compareGraphDigests(before, after),
  });
  return {
    ok: true,
    faultCount: results.length,
    faults: results,
    digestsUnchanged,
    commitOutcomeCoverage: {
      mode: 'pre-dispatch-only',
      ambiguousPostDispatchOutcomeProven: false,
      limitation: 'official SDK commit is a single promise; simulating a lost response after server commit would risk persisting the fault transaction',
    },
  };
}

export async function createLiveAttestation({
  manifest,
  client,
  repoRoot,
  target,
  signingKeyPath,
  outputPath,
}) {
  const attestStep = (label) => process.stderr.write(`attest: ${label}\n`);
  if (!signingKeyPath) throw new CompilerError('live attestation requires an Ed25519 signing key', { phase: 'attest:configuration' });
  if (!outputPath || !outsideRepository(outputPath, repoRoot)) {
    throw new CompilerError('source-to-database attestation must be written outside the repository', { phase: 'attest:configuration' });
  }
  const drift = await observeLiveDrift({ manifest, client });
  if (!drift.conforms) throw new CompilerError('live graph state differs from local semantic authority', {
    phase: 'attest:drift', failures: drift.comparison,
  });
  const privateKey = createPrivateKey(readFileSync(signingKeyPath));
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new CompilerError('live attestation key must be Ed25519', { phase: 'attest:configuration' });
  }
  const verification = verificationProjection(await verifyDatabase({ manifest, client }));
  if (!verificationPasses(verification)) {
    throw new CompilerError('live database verification failed before attestation', { phase: 'attest:validation', failures: verification });
  }
  attestStep('rollback fault matrix');
  const rollback = await proveLiveRollback({ manifest, client });
  const publicKey = createPublicKey(privateKey);
  const payload = {
    schemaVersion: 1,
    kind: 'source-to-database',
    createdAt: new Date().toISOString(),
    observationKind: 'stardog-access-boundary',
    accessMethod: 'official-sdk',
    connectionAttempted: true,
    observedAt: new Date().toISOString(),
    repository: repositoryState(repoRoot),
    registeredSourceFiles: registeredSourceFiles(manifest, repoRoot),
    target,
    canonicalization: { algorithm: 'RDFC-1.0', digestAlgorithm: 'sha256' },
    sourceGraphDigests: drift.sourceGraphDigests,
    databaseGraphDigests: drift.databaseGraphDigests,
    comparison: drift.comparison,
    verification,
    rollback,
  };
  const bytes = Buffer.from(stableJson(payload));
  const envelope = {
    payload,
    signature: {
      algorithm: 'Ed25519',
      publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
      publicKeyFingerprint: fingerprint(publicKey),
      value: sign(null, bytes, privateKey).toString('base64'),
    },
  };
  writeFileSync(outputPath, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 });
  return {
    ok: true,
    output: outputPath,
    publicKeyFingerprint: envelope.signature.publicKeyFingerprint,
    graphs: drift.sourceGraphDigests.length,
    triples: drift.sourceGraphDigests.reduce((sum, item) => sum + item.triples, 0),
    repository: payload.repository,
    comparison: payload.comparison,
    verification: payload.verification,
    rollback: payload.rollback,
  };
}

export async function verifyLiveAttestation({
  inputPath,
  expectedKeyFingerprint,
  manifest,
  client,
  repoRoot,
}) {
  let envelope;
  try {
    envelope = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch (error) {
    throw new CompilerError(`cannot parse live attestation: ${error.message}`, { phase: 'attest:verify' });
  }
  const publicKey = createPublicKey(envelope?.signature?.publicKey || '');
  const observedFingerprint = fingerprint(publicKey);
  const signatureVerified = envelope?.signature?.algorithm === 'Ed25519' &&
    observedFingerprint === envelope?.signature?.publicKeyFingerprint &&
    verify(null, Buffer.from(stableJson(envelope.payload)), publicKey, Buffer.from(envelope.signature.value || '', 'base64'));
  const trustVerified = typeof expectedKeyFingerprint === 'string' &&
    expectedKeyFingerprint.length > 0 && expectedKeyFingerprint === observedFingerprint;
  const repository = repositoryState(repoRoot);
  const repositoryVerified = stableJson(repository) === stableJson(envelope.payload?.repository);
  const drift = await observeLiveDrift({ manifest, client });
  const currentVerification = verificationProjection(await verifyDatabase({ manifest, client }));
  const sourceVerified = stableJson(drift.sourceGraphDigests) === stableJson(envelope.payload?.sourceGraphDigests);
  const databaseVerified = stableJson(drift.databaseGraphDigests) === stableJson(envelope.payload?.databaseGraphDigests);
  const validationVerified = verificationPasses(currentVerification) &&
    stableJson(currentVerification) === stableJson(envelope.payload?.verification);
  const rollback = envelope.payload?.rollback;
  const rollbackVerified = rollback?.ok === true && rollback?.digestsUnchanged === true &&
    rollback?.faultCount === REQUIRED_ROLLBACK_FAULTS.length &&
    stableJson((rollback?.faults ?? []).map((item) => item.name).sort()) === stableJson(REQUIRED_ROLLBACK_FAULTS) &&
    (rollback?.faults ?? []).every((item) => item.rollbackCount === 1 && item.activationCount > 0 &&
      typeof item.injectionPoint === 'string' && item.injectionPoint.length > 0 && typeof item.errorPhase === 'string') &&
    rollback?.commitOutcomeCoverage?.mode === 'pre-dispatch-only' &&
    rollback?.commitOutcomeCoverage?.ambiguousPostDispatchOutcomeProven === false &&
    typeof rollback?.commitOutcomeCoverage?.limitation === 'string';
  const ok = signatureVerified && trustVerified && repositoryVerified && sourceVerified &&
    databaseVerified && validationVerified && rollbackVerified && drift.conforms;
  return {
    ok,
    signatureVerified,
    trustVerified,
    repositoryVerified,
    sourceVerified,
    databaseVerified,
    validationVerified,
    rollbackVerified,
    publicKeyFingerprint: observedFingerprint,
    comparison: drift.comparison,
  };
}

export const liveAttestationInternals = Object.freeze({
  verificationProjection,
  verificationPasses,
  requiredRollbackFaults: REQUIRED_ROLLBACK_FAULTS,
});
