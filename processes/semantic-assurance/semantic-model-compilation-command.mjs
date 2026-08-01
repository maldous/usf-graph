import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { DataFactory, Parser, Store, Writer } from 'n3';

import {
  canonicalGraphDigest,
  canonicalNQuads,
  checkLocal,
  compile,
  CompilerError,
  shapeConstraints,
} from '../../capabilities/semantic-model-compilation/compiler.mjs';
import {
  integrityRules,
  loadManifest,
  managedGraphs,
} from '../../capabilities/semantic-model-compilation/manifest.mjs';

export const SEMANTIC_MODEL_PATH = 'semantic-model';
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const PATCH_HEADER = /^# semantic-proof-v1 canonical-rdf-patch-v1 (stage1|stage2)$/;
const NQUADS = 'application/n-quads';
const TURTLE = 'text/turtle';
const { defaultGraph, namedNode, quad } = DataFactory;

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object' && !Buffer.isBuffer(value)
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function exactCandidateBytes(value, expectedDigest) {
  if (!Buffer.isBuffer(value) || value.length === 0) {
    throw new CompilerError('canonical RDF Patch candidate bytes are required', { phase: 'candidate:configuration' });
  }
  const observedDigest = sha256(value);
  if (expectedDigest !== undefined && observedDigest !== expectedDigest) {
    throw new CompilerError('canonical RDF Patch bytes do not match the accepted candidate digest', {
      phase: 'candidate:digest', expectedCandidateDigest: expectedDigest, observedCandidateDigest: observedDigest,
    });
  }
  return Object.freeze({ bytes: Buffer.from(value), digest: observedDigest });
}

function parseCanonicalPatch(value, expectedDigest, allowedGraphs) {
  const candidate = exactCandidateBytes(value, expectedDigest);
  const text = candidate.bytes.toString('utf8');
  if (!candidate.bytes.equals(Buffer.from(text, 'utf8')) || text.includes('\r') || !text.endsWith('\n')) {
    throw new CompilerError('candidate is not canonical UTF-8 RDF Patch', { phase: 'candidate:parse' });
  }
  const lines = text.split('\n');
  const header = lines.shift();
  if (!PATCH_HEADER.test(header || '') || lines.pop() !== '' || lines.length === 0) {
    throw new CompilerError('candidate does not use canonical-rdf-patch-v1', { phase: 'candidate:parse' });
  }
  const operations = lines.map((line) => {
    const match = /^([AD]) (.+)$/.exec(line);
    if (!match) throw new CompilerError('candidate contains a malformed RDF Patch operation', { phase: 'candidate:parse' });
    let parsed;
    try {
      parsed = new Parser({ format: NQUADS }).parse(`${match[2]}\n`);
    } catch (error) {
      throw new CompilerError(`candidate contains invalid N-Quads: ${error.message}`, { phase: 'candidate:parse' });
    }
    if (parsed.length !== 1 || parsed[0].graph.termType !== 'NamedNode'
        || [parsed[0].subject, parsed[0].object].some((term) => term.termType === 'BlankNode'
          && !/^c14n[0-9]+$/.test(term.value))
        || !allowedGraphs.has(parsed[0].graph.value)) {
      throw new CompilerError('candidate operation must be one canonical quad in a managed named graph', { phase: 'candidate:scope' });
    }
    return Object.freeze({ action: match[1], line: match[2], value: parsed[0] });
  });
  const deletions = operations.filter(({ action }) => action === 'D');
  const additions = operations.filter(({ action }) => action === 'A');
  const canonicalLines = [
    header,
    ...deletions.map(({ line }) => `D ${line}`).sort(),
    ...additions.map(({ line }) => `A ${line}`).sort(),
    '',
  ];
  if (canonicalLines.join('\n') !== text
      || new Set(operations.map(({ action, line }) => `${action} ${line}`)).size !== operations.length
      || deletions.some(({ line }) => additions.some((entry) => entry.line === line))) {
    throw new CompilerError('candidate RDF Patch is not canonical, unique and contradiction-free', { phase: 'candidate:canonicality' });
  }
  return Object.freeze({ ...candidate, additions, deletions, operations });
}

function triple(item) {
  return quad(item.subject, item.predicate, item.object, defaultGraph());
}

async function graphText(store) {
  return new Promise((resolveText, reject) => {
    const writer = new Writer({ format: TURTLE });
    writer.addQuads(store.getQuads(null, null, null, null));
    writer.end((error, output) => error ? reject(error) : resolveText(output));
  });
}

async function nquadsText(quads) {
  return new Promise((resolveText, reject) => {
    const writer = new Writer({ format: 'N-Quads' });
    writer.addQuads(quads);
    writer.end((error, output) => error ? reject(error) : resolveText(output));
  });
}

async function readCanonicalStores(client, transaction, graphs) {
  const graphNames = [...new Set(graphs)].sort();
  const dataset = [];
  for (const graph of graphNames) {
    const content = await client.constructInTransaction(
      transaction,
      `CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`,
    );
    let values;
    try {
      values = new Parser({ format: TURTLE, baseIRI: 'urn:usf:' }).parse(content || '');
    } catch (error) {
      throw new CompilerError(`managed graph could not be isolated for candidate application: ${error.message}`, {
        phase: 'candidate:isolation', graph,
      });
    }
    dataset.push(...values.map((item) => quad(item.subject, item.predicate, item.object, namedNode(graph))));
  }
  const canonical = await canonicalNQuads(await nquadsText(dataset));
  const stores = new Map(graphNames.map((graph) => [graph, new Store()]));
  for (const item of new Parser({ format: NQUADS }).parse(canonical)) {
    stores.get(item.graph.value).addQuad(triple(item));
  }
  return Object.freeze({ canonical, stores });
}

async function readAffectedStores(client, transaction, patch) {
  return (await readCanonicalStores(
    client,
    transaction,
    patch.operations.map(({ value }) => value.graph.value),
  )).stores;
}

async function replaceStores(client, transaction, stores) {
  const graphs = [...stores.keys()].sort();
  await client.clearGraphs(transaction, graphs);
  for (const graph of graphs) {
    const content = await graphText(stores.get(graph));
    if (content.trim()) await client.addData(transaction, content, TURTLE, graph);
  }
}

async function applyDesiredPatch(client, transaction, patch) {
  const stores = await readAffectedStores(client, transaction, patch);
  for (const { value } of patch.deletions) stores.get(value.graph.value).removeQuad(triple(value));
  for (const { value } of patch.additions) stores.get(value.graph.value).addQuad(triple(value));
  await replaceStores(client, transaction, stores);
}

function canonicalCombinedPatch(stage, before, after) {
  const prior = new Set(before.split('\n').filter(Boolean));
  const target = new Set(after.split('\n').filter(Boolean));
  const deletions = [...prior].filter((line) => !target.has(line)).sort();
  const additions = [...target].filter((line) => !prior.has(line)).sort();
  if (deletions.length + additions.length === 0) {
    throw new CompilerError('combined semantic candidate contains no authority transition', { phase: 'candidate:source-delta' });
  }
  if (!['base', 'stage1', 'stage2'].includes(stage)) {
    throw new CompilerError('combined semantic candidate stage is invalid', { phase: 'candidate:source-delta' });
  }
  return Buffer.from([
    `# semantic-proof-v1 canonical-rdf-patch-v1 ${stage}`,
    ...deletions.map((line) => `D ${line}`),
    ...additions.map((line) => `A ${line}`),
    '',
  ].join('\n'), 'utf8');
}

async function composeSourceCandidate({ client, manifest, generatedPatch = null, authorityWitness, compileFunction, stage }) {
  const graphs = [...managedGraphs(manifest)].sort();
  let beforeDataset;
  let targetDataset;
  let generatedApplied = false;
  const overrides = {
    async begin() {
      const transaction = await client.begin();
      beforeDataset = await readCanonicalStores(client, transaction, graphs);
      return transaction;
    },
    async validateInTransactionWithReceipt(transaction, shapes) {
      if (!generatedApplied) {
        if (generatedPatch) await applyDesiredPatch(client, transaction, generatedPatch);
        generatedApplied = true;
      }
      return client.validateInTransactionWithReceipt(transaction, shapes);
    },
    async rollback(transaction) {
      if (generatedApplied && !targetDataset) targetDataset = await readCanonicalStores(client, transaction, graphs);
      return client.rollback(transaction);
    },
    async commit() {
      throw new CompilerError('source candidate composition must never commit', { phase: 'candidate:source-delta' });
    },
  };
  const compositionClient = new Proxy(client, {
    get(target, property) {
      if (Object.hasOwn(overrides, property)) return overrides[property];
      const value = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const sourceValidation = await compileFunction({
    authorityWitness,
    client: compositionClient,
    manifest,
    publicationBudgetPolicy: manifest.publicationBudget,
    publicationMode: 'validate',
  });
  if (!beforeDataset || !targetDataset || generatedApplied !== true || sourceValidation?.ok !== true) {
    throw new CompilerError('full source candidate could not be constructed and validated', { phase: 'candidate:source-delta' });
  }
  const candidateStage = stage || PATCH_HEADER.exec(generatedPatch?.bytes.toString('utf8').split('\n', 1)[0])?.[1];
  const bytes = canonicalCombinedPatch(candidateStage, beforeDataset.canonical, targetDataset.canonical);
  const combined = candidateStage === 'base'
    ? Object.freeze({ bytes, digest: sha256(bytes) })
    : parseCanonicalPatch(bytes, undefined, new Set(graphs));
  const finalLines = new Set(targetDataset.canonical.split('\n').filter(Boolean));
  for (const operation of generatedPatch?.operations || []) {
    if ((operation.action === 'A') !== finalLines.has(operation.line)) {
      throw new CompilerError('generated aggregate intent was not preserved by full source composition', {
        phase: 'candidate:source-delta', operation: `${operation.action} ${operation.line}`,
      });
    }
  }
  return Object.freeze({
    bytes: combined.bytes,
    digest: combined.digest,
    sourceValidation: Object.freeze(sourceValidation.liveValidation || {}),
  });
}

function patchState(stores, patch) {
  const present = ({ value }) => stores.get(value.graph.value).has(
    value.subject, value.predicate, value.object, null,
  );
  const pre = patch.deletions.every(present) && patch.additions.every((entry) => !present(entry));
  const post = patch.deletions.every((entry) => !present(entry)) && patch.additions.every(present);
  return pre && !post ? 'pre' : post && !pre ? 'post' : 'mixed';
}

async function inspectPatchState(client, patch) {
  let transaction;
  try {
    transaction = await client.begin();
    const stores = await readAffectedStores(client, transaction, patch);
    const state = patchState(stores, patch);
    await client.rollback(transaction);
    transaction = null;
    return state;
  } finally {
    if (transaction) await client.rollback(transaction);
  }
}

async function compilePatch({ client, manifest, patch, publicationMode, readText = readFileSync }) {
  let transaction;
  try {
    transaction = await client.begin();
    const stores = await readAffectedStores(client, transaction, patch);
    if (patchState(stores, patch) !== 'pre') {
      throw new CompilerError('candidate does not match the exact live pre-state', { phase: 'candidate:precondition' });
    }
    for (const { value } of patch.deletions) stores.get(value.graph.value).removeQuad(triple(value));
    for (const { value } of patch.additions) stores.get(value.graph.value).addQuad(triple(value));
    if (patchState(stores, patch) !== 'post') {
      throw new CompilerError('candidate post-state could not be constructed exactly', { phase: 'candidate:postcondition' });
    }
    await replaceStores(client, transaction, stores);
    const shapes = shapeConstraints(manifest);
    const validation = await client.validateInTransactionWithReceipt(transaction, shapes);
    if (validation?.conforms !== true) {
      const report = await client.reportInTransaction(transaction, shapes);
      throw new CompilerError('RDF Patch candidate failed live SHACL validation', {
        phase: 'candidate:shacl', report,
      });
    }
    for (const rule of integrityRules(manifest)) {
      const violations = await client.selectInTransaction(transaction, readText(rule.path, 'utf8'));
      if (violations.length > 0) {
        throw new CompilerError('RDF Patch candidate failed semantic integrity validation', {
          phase: 'candidate:integrity', integrityRule: rule.file, violations: violations.slice(0, 20),
        });
      }
    }
    const projectedStatements = Number.isSafeInteger(manifest.publicationBudget?.maximumProjectedStatementCount)
      ? manifest.publicationBudget.maximumProjectedStatementCount
      : null;
    if (projectedStatements === null) {
      throw new CompilerError('candidate publication budget policy is unavailable', { phase: 'candidate:budget' });
    }
    if (publicationMode === 'validate') {
      await client.rollback(transaction);
      transaction = null;
      return Object.freeze({
        ok: true,
        liveValidation: Object.freeze(validation),
        commitOutcome: Object.freeze({
          candidateDigest: patch.digest,
          exactCandidateStateVerified: true,
          state: 'VALIDATED_ROLLBACK',
        }),
      });
    }
    await client.commit(transaction);
    transaction = null;
    return Object.freeze({
      ok: true,
      liveValidation: Object.freeze(validation),
      commitOutcome: Object.freeze({
        candidateDigest: patch.digest,
        exactCandidateStateVerified: true,
        state: 'COMMITTED',
      }),
    });
  } catch (error) {
    if (transaction) {
      try { await client.rollback(transaction); } catch { /* preserve the primary failure */ }
    }
    if (error instanceof CompilerError) throw error;
    throw new CompilerError(error.message, { phase: 'candidate:transaction' });
  }
}

function digest(value) {
  const observed = value?.digest || value?.authorityDigest;
  if (typeof observed !== 'string') throw new CompilerError('authority witness is missing its digest', { phase: 'authority:witness' });
  return observed.startsWith('sha256:') ? observed : `sha256:${observed}`;
}

function semanticModelDirectory(repositoryRoot) {
  const root = realpathSync(repositoryRoot);
  const candidate = resolve(root, SEMANTIC_MODEL_PATH);
  const repositoryRelative = relative(root, candidate);
  if (repositoryRelative !== SEMANTIC_MODEL_PATH || repositoryRelative.startsWith(`..${sep}`)) {
    throw new CompilerError('semantic model path escapes the repository', { phase: 'compile:configuration' });
  }
  if (lstatSync(candidate).isSymbolicLink()) throw new CompilerError('semantic model path must not be a symbolic link', { phase: 'compile:configuration' });
  const canonical = realpathSync(candidate);
  if (relative(root, canonical) !== SEMANTIC_MODEL_PATH) throw new CompilerError('semantic model path resolves outside its canonical repository role', { phase: 'compile:configuration' });
  return canonical;
}

function validationEvidence(result, authorityDigest, candidateDigest) {
  if (!result?.liveValidation || result.liveValidation.conforms !== true) {
    throw new CompilerError('candidate validation returned no conforming provider receipt', { phase: 'candidate:validation-receipt' });
  }
  const record = Object.freeze({
    authorityDigest,
    candidateDigest,
    providerValidationReceipt: result.liveValidation,
    schema: 'semantic-authority-compiler-validation-report-v1',
    state: result.commitOutcome.state,
  });
  const bytes = Buffer.from(`${canonicalJson(record)}\n`, 'utf8');
  return Object.freeze({ bytes, digest: sha256(bytes), record });
}

function sourceValidationEvidence(sourceValidation, authorityDigest, candidateDigest) {
  if (!sourceValidation || sourceValidation.derived?.conforms !== true) {
    throw new CompilerError('base source preparation returned no real derived validation receipt', {
      phase: 'candidate:validation-receipt',
    });
  }
  const record = Object.freeze({
    authorityDigest,
    candidateDigest,
    providerValidationReceipt: sourceValidation,
    schema: 'semantic-authority-compiler-source-validation-report-v1',
    state: 'VALIDATED_ROLLBACK',
  });
  const bytes = Buffer.from(canonicalJson(record), 'utf8');
  return Object.freeze({ bytes, digest: sha256(bytes), record });
}

export function createSemanticModelCompilationCommand({
  client,
  readAuthorityWitness,
  repositoryRoot,
  loadManifestFunction = loadManifest,
  compileFunction = compile,
  checkLocalFunction = checkLocal,
}) {
  if (!client || typeof client.connectivity !== 'function') throw new TypeError('semantic authority client is required');
  if (typeof readAuthorityWitness !== 'function') throw new TypeError('authority witness reader is required');
  if (typeof repositoryRoot !== 'string') throw new TypeError('repository root is required');

  return Object.freeze({
    requiresCandidateBytes: true,

    async prepareSourceDelta({ expectedAuthorityDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) throw new CompilerError('semantic authority drifted before base source preparation', { phase: 'authority:drift' });
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const prepared = await composeSourceCandidate({
        client, manifest, authorityWitness: beforeWitness, compileFunction, stage: 'base',
      });
      if (digest(await readAuthorityWitness(client)) !== before) {
        throw new CompilerError('base source preparation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      const validation = sourceValidationEvidence(prepared.sourceValidation, before, prepared.digest);
      return Object.freeze({
        baseSemanticDelta: Object.freeze({
          authorityPreDigest: before,
          bytesBase64: prepared.bytes.toString('base64'),
          candidateDigest: prepared.digest,
          exactCandidateStateVerified: true,
          mediaType: 'application/rdf-patch',
          state: 'VALIDATED_ROLLBACK',
          validationReceiptDigest: validation.digest,
        }),
        validationEvidence: validation,
      });
    },

    async composeCandidate({ generatedCandidateBytes, expectedAuthorityDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before source candidate composition', {
          phase: 'authority:drift', expectedAuthorityDigest, observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const generatedPatch = parseCanonicalPatch(generatedCandidateBytes, undefined, new Set(managedGraphs(manifest)));
      const combined = await composeSourceCandidate({
        client, manifest, generatedPatch, authorityWitness: beforeWitness, compileFunction,
      });
      const after = digest(await readAuthorityWitness(client));
      if (after !== before) throw new CompilerError('source candidate composition changed semantic authority', { phase: 'authority:validate-drift' });
      return combined;
    },

    async previewCandidateInventory({ candidateBytes, candidateDigest, expectedAuthorityDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      if (digest(await readAuthorityWitness(client)) !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before candidate preview', { phase: 'authority:drift' });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const patch = parseCanonicalPatch(candidateBytes, candidateDigest, new Set(managedGraphs(manifest)));
      let transaction;
      try {
        transaction = await client.begin();
        const current = await readCanonicalStores(client, transaction, managedGraphs(manifest));
        if (patchState(current.stores, patch) !== 'pre') {
          throw new CompilerError('candidate preview does not match the exact live pre-state', { phase: 'candidate:precondition' });
        }
        for (const { value } of patch.deletions) current.stores.get(value.graph.value).removeQuad(triple(value));
        for (const { value } of patch.additions) current.stores.get(value.graph.value).addQuad(triple(value));
        if (patchState(current.stores, patch) !== 'post') {
          throw new CompilerError('candidate preview could not construct the exact target state', { phase: 'candidate:postcondition' });
        }
        const inventory = [];
        for (const [graph, store] of [...current.stores.entries()].sort(([left], [right]) => left.localeCompare(right))) {
          const graphQuads = store.getQuads(null, null, null, null)
            .map((item) => quad(item.subject, item.predicate, item.object, namedNode(graph)));
          const record = await canonicalGraphDigest(await nquadsText(graphQuads));
          inventory.push(Object.freeze({ graph, sha256: `sha256:${record.sha256}`, triples: record.triples }));
        }
        await client.rollback(transaction);
        transaction = null;
        return Object.freeze({ candidateDigest: patch.digest, inventory: Object.freeze(inventory) });
      } finally {
        if (transaction) await client.rollback(transaction);
      }
    },

    async inspectCandidateState({ candidateBytes, candidateDigest }) {
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const patch = parseCanonicalPatch(candidateBytes, candidateDigest, new Set(managedGraphs(manifest)));
      return Object.freeze({ candidateDigest: patch.digest, state: await inspectPatchState(client, patch) });
    },

    async execute({ expectedAuthorityDigest, publicationMode = 'validate', candidateBytes, candidateDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before compilation', {
          phase: 'authority:drift',
          expectedAuthorityDigest,
          observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      if (candidateBytes !== undefined || candidateDigest !== undefined) {
        checkLocalFunction(manifest);
        const patch = parseCanonicalPatch(candidateBytes, candidateDigest, new Set(managedGraphs(manifest)));
        const result = await compilePatch({ client, manifest, patch, publicationMode });
        if (publicationMode === 'validate') {
          const after = digest(await readAuthorityWitness(client));
          if (after !== before) throw new CompilerError('validate-only RDF Patch changed semantic authority', { phase: 'authority:validate-drift' });
        }
        return Object.freeze({
          ...result,
          evaluatedAuthorityDigest: before,
          semanticModelPath: SEMANTIC_MODEL_PATH,
          validationEvidence: validationEvidence(result, before, patch.digest),
        });
      }
      const result = await compileFunction({
        authorityWitness: beforeWitness,
        client,
        manifest,
        publicationBudgetPolicy: manifest.publicationBudget,
        publicationMode,
      });
      if (publicationMode === 'validate') {
        const after = digest(await readAuthorityWitness(client));
        if (after !== before) throw new CompilerError('validate-only compilation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      return Object.freeze({
        ...result,
        evaluatedAuthorityDigest: before,
        semanticModelPath: SEMANTIC_MODEL_PATH,
      });
    },
  });
}

export const semanticModelCompilationCommandInternals = Object.freeze({
  digest,
  exactCandidateBytes,
  canonicalCombinedPatch,
  composeSourceCandidate,
  parseCanonicalPatch,
  patchState,
  semanticModelDirectory,
});
