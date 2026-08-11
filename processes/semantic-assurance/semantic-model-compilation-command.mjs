import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { DataFactory, Parser, Store, Writer } from 'n3';

import {
  canonicalGraphDigest,
  canonicalInventoryGraphDigest,
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
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const PATCH_HEADER = /^# semantic-proof-v1 canonical-rdf-patch-v1 (base|stage1|stage2)$/;
const EXTERNAL_AUTHORITY_DELTA_SCHEMA = 'usf-external-authority-conflict-resolution-delta-v1';
const NQUADS = 'application/n-quads';
const NTRIPLES = 'application/n-triples';
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

function parseCanonicalPatch(
  value,
  expectedDigest,
  allowedGraphs,
  allowedStages = new Set(['stage1', 'stage2']),
) {
  const candidate = exactCandidateBytes(value, expectedDigest);
  const text = candidate.bytes.toString('utf8');
  if (!candidate.bytes.equals(Buffer.from(text, 'utf8')) || text.includes('\r') || !text.endsWith('\n')) {
    throw new CompilerError('candidate is not canonical UTF-8 RDF Patch', { phase: 'candidate:parse' });
  }
  const lines = text.split('\n');
  const header = lines.shift();
  const patchHeader = PATCH_HEADER.exec(header || '');
  if (!patchHeader || !allowedStages.has(patchHeader[1]) || lines.pop() !== '' || lines.length === 0) {
    throw new CompilerError('candidate does not use canonical-rdf-patch-v1', { phase: 'candidate:parse' });
  }
  const operations = lines.map((line) => {
    const match = /^([AD]) (.+)$/.exec(line);
    if (!match) throw new CompilerError('candidate contains a malformed RDF Patch operation', { phase: 'candidate:parse' });
    let parsed;
    try {
      parsed = new Parser({ format: NQUADS, blankNodePrefix: '' }).parse(`${match[2]}\n`);
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

function exactObjectKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    throw new CompilerError(`${label} has an invalid closed schema`, { phase: 'candidate:external-authority-delta' });
  }
}

function exactSortedUniqueStrings(value, pattern, label, { minimum = 1 } = {}) {
  if (!Array.isArray(value) || value.length < minimum || value.some((item) => typeof item !== 'string' || !pattern.test(item))
      || canonicalJson(value) !== canonicalJson([...new Set(value)].sort())) {
    throw new CompilerError(`${label} must be an exact sorted unique set`, { phase: 'candidate:external-authority-delta' });
  }
  return Object.freeze([...value]);
}

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const USF = 'urn:usf:ontology:';

function patchHas(patch, subject, predicate, object) {
  return patch.additions.some(({ value }) => value.subject.value === subject
    && value.predicate.value === predicate && value.object.value === object);
}

function requirePatchTriple(patch, subject, predicate, object, label) {
  if (!patchHas(patch, subject, predicate, object)) {
    throw new CompilerError(`external authority delta is missing exact ${label}`, {
      phase: 'candidate:external-authority-delta', subject, predicate, object,
    });
  }
}

const EXTERNAL_AUTHORITY_ROLE_PREDICATES = Object.freeze({
  conflict: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}conflictAuthorityDigest`,
    `${USF}conflictingAuthority`, `${USF}conflictRepository`, `${USF}conflictOperationDigest`,
    `${USF}conflictCandidateDigest`, `${USF}conflictPredecessorSourceHead`,
    `${USF}conflictPredecessorSourceTree`, `${USF}conflictSuccessorSourceTree`,
    `${USF}conflictSourceScopeDigest`, `${USF}conflictSourcePath`,
    `${USF}conflictRequestedAction`, `${USF}conflictRequestedPath`,
    `${USF}conflictRequestedRepresentationFormat`, `${USF}conflictRequestedEffect`,
    `${USF}conflictBlockedByValidationObligation`,
  ]),
  review: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}hasSemanticAdequacyReviewState`,
    `${USF}reviewedAuthorityDigest`, `${USF}reviewedInventoryDigest`, `${USF}reviewedItemCount`,
    `${USF}usesDispositionInventoryDescriptor`, `${USF}usesIndependentReviewDescriptor`,
    `${USF}usesSemanticAdequacyProofDescriptor`,
  ]),
  resolution: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}decisionRationale`,
    `${USF}semanticCorrectionDecisionState`, `${USF}decisionBasedOnSemanticAdequacyReview`,
    `${USF}warrantedBySemanticAdequacyProof`, `${USF}resolvesAuthorityConflict`,
    `${USF}authorityConflictResolutionOwnerAssignment`,
  ]),
  proof: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}atRung`, `${USF}exercises`,
    `${USF}inEnvironment`, `${USF}provesSubject`, `${USF}usesProviderMode`,
  ]),
  proofResult: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}claimedRung`, `${USF}observedRung`,
    `${USF}hasFreshness`, `${USF}hasProofResultState`, `${USF}inEnvironment`,
    `${USF}resultState`, `${USF}resultForProof`, `${USF}usesProviderMode`,
    `${USF}proofExecutionEnvironment`, `${USF}evidenceSetDigest`, `${USF}evaluatedAt`,
    `${USF}uncertaintyStatement`, `${USF}hasInvalidationCondition`,
  ]),
  descriptor: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}descriptorArtefactFamily`,
    `${USF}descriptorRepresentationFormat`, `${USF}descriptorMediaType`,
    `${USF}descriptorDigest`, `${USF}descriptorByteSize`, `${USF}descriptorLocator`,
    `${USF}descriptorArtefactType`, `${USF}descriptorStorageClass`,
  ]),
  disposition: new Set([
    RDF_TYPE, `${USF}reviewedInSemanticAdequacyReview`, `${USF}semanticAdequacyDisposition`,
    `${USF}authorisedBySemanticCorrectionDecision`, `${USF}sourceItemDigest`,
    `${USF}finalCanonicalSemanticItem`,
  ]),
});

const EXTERNAL_AUTHORITY_MULTI_PREDICATES = Object.freeze({
  conflict: new Set([
    `${USF}conflictingAuthority`, `${USF}conflictSourcePath`, `${USF}conflictRequestedAction`,
    `${USF}conflictRequestedPath`, `${USF}conflictRequestedRepresentationFormat`,
    `${USF}conflictRequestedEffect`, `${USF}conflictBlockedByValidationObligation`,
  ]),
  proof: new Set([`${USF}exercises`]),
  proofResult: new Set([`${USF}hasInvalidationCondition`]),
});

function exactPatchObjects(patch, subject, predicate) {
  return patch.additions
    .filter(({ value: item }) => item.subject.value === subject && item.predicate.value === predicate)
    .map(({ value: item }) => item.object.value);
}

function assertExternalAuthorityClosedShape(patch, value, roots) {
  const proofLinks = exactPatchObjects(patch, value.proofResultIri, `${USF}resultForProof`);
  if (proofLinks.length !== 1 || !/^urn:usf:proof:[a-z0-9]+$/.test(proofLinks[0])) {
    throw new CompilerError('external authority delta proof identity is not exact', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const proofIri = proofLinks[0];
  const descriptorSubjects = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}descriptorDigest`
      && roots.includes(item.object.value))
    .map(({ value: item }) => item.subject.value))].sort();
  if (descriptorSubjects.length !== roots.length
      || descriptorSubjects.some((item) => !/^urn:usf:externalpayloaddescriptor:[a-z0-9]+$/.test(item))) {
    throw new CompilerError('external authority delta descriptor identities are not one-to-one with CAS roots', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const dispositionSubjects = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}reviewedInSemanticAdequacyReview`
      && item.object.value === value.reviewIri)
    .map(({ value: item }) => item.subject.value))].sort();
  if (dispositionSubjects.some((item) => !/^urn:usf:historicalitem:[0-9a-f]{64}$/.test(item))) {
    throw new CompilerError('external authority delta review disposition identity is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const roleBySubject = new Map([
    [value.conflictIri, 'conflict'], [value.reviewIri, 'review'],
    [value.resolutionIri, 'resolution'], [value.proofResultIri, 'proofResult'], [proofIri, 'proof'],
    ...descriptorSubjects.map((item) => [item, 'descriptor']),
    ...dispositionSubjects.map((item) => [item, 'disposition']),
  ]);
  if (roleBySubject.size !== 5 + descriptorSubjects.length + dispositionSubjects.length) {
    throw new CompilerError('external authority delta semantic roles overlap', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const cardinality = new Map();
  for (const { value: item } of patch.additions) {
    const role = roleBySubject.get(item.subject.value);
    if (!role || !EXTERNAL_AUTHORITY_ROLE_PREDICATES[role].has(item.predicate.value)) {
      throw new CompilerError('external authority delta contains an unrelated semantic operation', {
        phase: 'candidate:external-authority-delta',
        predicate: item.predicate.value,
        subject: item.subject.value,
      });
    }
    const key = `${item.subject.value}\u0000${item.predicate.value}`;
    cardinality.set(key, (cardinality.get(key) || 0) + 1);
    if (!EXTERNAL_AUTHORITY_MULTI_PREDICATES[role]?.has(item.predicate.value)
        && cardinality.get(key) > 1) {
      throw new CompilerError('external authority delta contains an ambiguous singleton property', {
        phase: 'candidate:external-authority-delta',
        predicate: item.predicate.value,
        subject: item.subject.value,
      });
    }
  }
  for (const subject of descriptorSubjects) {
    const digests = exactPatchObjects(patch, subject, `${USF}descriptorDigest`);
    if (digests.length !== 1 || !roots.includes(digests[0])) {
      throw new CompilerError('external authority delta descriptor root is ambiguous', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
  }
  const reviewCounts = exactPatchObjects(patch, value.reviewIri, `${USF}reviewedItemCount`);
  if (reviewCounts.length > 0
      && (reviewCounts.length !== 1 || Number(reviewCounts[0]) !== dispositionSubjects.length)) {
    throw new CompilerError('external authority delta review item count is not exact', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const subject of dispositionSubjects) {
    const suffix = subject.slice('urn:usf:historicalitem:'.length);
    const sourceDigests = exactPatchObjects(patch, subject, `${USF}sourceItemDigest`);
    const decisions = exactPatchObjects(patch, subject, `${USF}authorisedBySemanticCorrectionDecision`);
    if (sourceDigests.length !== 1 || sourceDigests[0] !== `sha256:${suffix}`
        || decisions.length !== 1 || decisions[0] !== value.resolutionIri) {
      throw new CompilerError('external authority delta review disposition is not decision-bound', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
  }
  return proofIri;
}

function assertExternalAuthorityDelta({
  value,
  expectedAuthorityDigest,
  expectedSource,
  evidenceStore,
  allowedGraphs,
}) {
  exactObjectKeys(value, [
    'authorityDigest', 'casRootDigests', 'conflictIri', 'correctionCandidateDigest',
    'ownerAssignmentIri', 'patchBytesBase64', 'patchDigest', 'predecessorSourceHead',
    'predecessorSourceTree', 'proofResultIri', 'repository', 'resolutionIri', 'reviewIri',
    'schema', 'permittedOperations',
  ], 'external authority delta');
  if (value.schema !== EXTERNAL_AUTHORITY_DELTA_SCHEMA || value.authorityDigest !== expectedAuthorityDigest
      || !expectedSource || value.repository !== expectedSource.repository
      || value.predecessorSourceHead !== expectedSource.head
      || value.predecessorSourceTree !== expectedSource.tree
      || !GIT_OBJECT.test(value.predecessorSourceHead || '') || !GIT_OBJECT.test(value.predecessorSourceTree || '')
      || !SHA256.test(value.correctionCandidateDigest || '')
      || !SHA256.test(value.patchDigest || '')) {
    throw new CompilerError('external authority delta does not bind the exact authority and source predecessor', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const [name, iri] of Object.entries({
    conflict: value.conflictIri,
    owner: value.ownerAssignmentIri,
    proof: value.proofResultIri,
    resolution: value.resolutionIri,
    review: value.reviewIri,
  })) {
    if (typeof iri !== 'string' || !/^urn:usf:[a-z0-9]+:[a-z0-9]+$/.test(iri)) {
      throw new CompilerError(`external authority delta ${name} IRI is invalid`, {
        phase: 'candidate:external-authority-delta',
      });
    }
  }
  let bytes;
  try {
    bytes = Buffer.from(value.patchBytesBase64, 'base64');
  } catch {
    throw new CompilerError('external authority delta patch is not base64', { phase: 'candidate:external-authority-delta' });
  }
  if (bytes.toString('base64') !== value.patchBytesBase64 || sha256(bytes) !== value.patchDigest) {
    throw new CompilerError('external authority delta patch bytes or digest are not canonical', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const patch = parseCanonicalPatch(bytes, value.patchDigest, allowedGraphs, new Set(['base']));
  if (patch.deletions.length !== 0) {
    throw new CompilerError('external authority delta must be additive', { phase: 'candidate:external-authority-delta' });
  }
  const permittedOperations = exactSortedUniqueStrings(
    value.permittedOperations,
    /^[AD] .+$/,
    'external authority delta permitted operations',
  );
  const observedOperations = patch.operations.map(({ action, line }) => `${action} ${line}`).sort();
  if (canonicalJson(permittedOperations) !== canonicalJson(observedOperations)) {
    throw new CompilerError('external authority delta exceeds its exact permitted operation set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const roots = exactSortedUniqueStrings(value.casRootDigests, SHA256, 'external authority delta CAS roots', { minimum: 3 });
  if (!evidenceStore || typeof evidenceStore.verify !== 'function') {
    throw new CompilerError('external authority delta requires the canonical CAS verifier', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const root of roots) evidenceStore.verify(root);
  const descriptorRoots = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}descriptorDigest` && SHA256.test(item.object.value))
    .map(({ value: item }) => item.object.value))].sort();
  if (canonicalJson(descriptorRoots) !== canonicalJson(roots)) {
    throw new CompilerError('external authority delta CAS roots do not equal its descriptor closure', {
      phase: 'candidate:external-authority-delta',
    });
  }

  const closedProofIri = assertExternalAuthorityClosedShape(patch, value, roots);

  requirePatchTriple(patch, value.conflictIri, RDF_TYPE, `${USF}AssuranceFinding`, 'authority-conflict type');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictAuthorityDigest`, expectedAuthorityDigest, 'authority digest');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictCandidateDigest`, value.correctionCandidateDigest, 'correction candidate digest');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictRepository`, value.repository, 'repository');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictPredecessorSourceHead`, expectedSource.head, 'predecessor head');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictPredecessorSourceTree`, expectedSource.tree, 'predecessor tree');
  requirePatchTriple(patch, value.reviewIri, RDF_TYPE, `${USF}SemanticAdequacyReview`, 'review type');
  requirePatchTriple(patch, value.reviewIri, `${USF}hasSemanticAdequacyReviewState`, 'urn:usf:semanticadequacyreviewstate:accepted', 'accepted review');
  requirePatchTriple(patch, value.reviewIri, `${USF}reviewedAuthorityDigest`, expectedAuthorityDigest, 'review authority');
  requirePatchTriple(patch, value.reviewIri, `${USF}reviewedInventoryDigest`, value.correctionCandidateDigest, 'review candidate');
  requirePatchTriple(patch, value.proofResultIri, RDF_TYPE, `${USF}ProofResult`, 'proof-result type');
  requirePatchTriple(patch, value.proofResultIri, `${USF}hasProofResultState`, 'urn:usf:proofresultstate:successful', 'successful proof');
  if (!patchHas(patch, closedProofIri, `${USF}provesSubject`, value.conflictIri)) {
    throw new CompilerError('external authority delta proof does not prove the exact conflict', {
      phase: 'candidate:external-authority-delta',
    });
  }
  requirePatchTriple(patch, value.resolutionIri, RDF_TYPE, `${USF}SemanticCorrectionDecision`, 'resolution type');
  requirePatchTriple(patch, value.resolutionIri, `${USF}resolvesAuthorityConflict`, value.conflictIri, 'resolved conflict');
  requirePatchTriple(patch, value.resolutionIri, `${USF}semanticCorrectionDecisionState`, 'urn:usf:semanticcorrectiondecisionstate:accepted', 'accepted resolution');
  requirePatchTriple(patch, value.resolutionIri, `${USF}decisionBasedOnSemanticAdequacyReview`, value.reviewIri, 'resolution review');
  requirePatchTriple(patch, value.resolutionIri, `${USF}warrantedBySemanticAdequacyProof`, value.proofResultIri, 'resolution proof');
  requirePatchTriple(patch, value.resolutionIri, `${USF}authorityConflictResolutionOwnerAssignment`, value.ownerAssignmentIri, 'resolution owner');
  return Object.freeze({
    casRootDigests: roots,
    conflictIri: value.conflictIri,
    correctionCandidateDigest: value.correctionCandidateDigest,
    patch,
    patchDigest: value.patchDigest,
    resolutionIri: value.resolutionIri,
    reviewIri: value.reviewIri,
    proofResultIri: value.proofResultIri,
  });
}

function triple(item) {
  return quad(item.subject, item.predicate, item.object, defaultGraph());
}

async function graphText(store) {
  return new Promise((resolveText, reject) => {
    const writer = new Writer({ format: 'N-Triples' });
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
  for (const item of new Parser({ format: NQUADS, blankNodePrefix: '' }).parse(canonical)) {
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
    if (content.trim()) await client.addData(transaction, content, NTRIPLES, graph);
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

async function composeSourceCandidate({
  client,
  manifest,
  generatedPatch = null,
  preservedPatch = null,
  authorityWitness,
  compileFunction,
  stage,
}) {
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
        if (preservedPatch) await applyDesiredPatch(client, transaction, preservedPatch);
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
  const compositionClient = new Proxy(Object.create(null), {
    get(_target, property) {
      if (Object.hasOwn(overrides, property)) return overrides[property];
      const value = Reflect.get(client, property, client);
      return typeof value === 'function' ? value.bind(client) : value;
    },
    set() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
    defineProperty() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
    deleteProperty() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
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
  for (const operation of [...(preservedPatch?.operations || []), ...(generatedPatch?.operations || [])]) {
    const targetStore = targetDataset.stores.get(operation.value.graph.value);
    const present = targetStore?.has(
      operation.value.subject, operation.value.predicate, operation.value.object, null,
    ) === true;
    if ((operation.action === 'A') !== present) {
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

    async validateExternalAuthorityDelta({
      expectedAuthorityDigest,
      evidenceStore,
      expectedSource,
      externalAuthorityDelta,
    }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) {
        throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      }
      const before = digest(await readAuthorityWitness(client));
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before external delta validation', { phase: 'authority:drift' });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const external = assertExternalAuthorityDelta({
        value: externalAuthorityDelta,
        expectedAuthorityDigest,
        expectedSource,
        evidenceStore,
        allowedGraphs: new Set(managedGraphs(manifest)),
      });
      if (await inspectPatchState(client, external.patch) !== 'pre') {
        throw new CompilerError('external authority delta is not an unused exact live pre-state', {
          phase: 'candidate:external-authority-delta-replay',
        });
      }
      if (digest(await readAuthorityWitness(client)) !== before) {
        throw new CompilerError('external delta validation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      return Object.freeze({
        casRootDigests: external.casRootDigests,
        conflictIri: external.conflictIri,
        correctionCandidateDigest: external.correctionCandidateDigest,
        patchDigest: external.patchDigest,
        proofResultIri: external.proofResultIri,
        resolutionIri: external.resolutionIri,
        reviewIri: external.reviewIri,
      });
    },

    async prepareSourceDelta({
      expectedAuthorityDigest,
      evidenceStore = null,
      expectedSource = null,
      externalAuthorityDelta = null,
    }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) throw new CompilerError('semantic authority drifted before base source preparation', { phase: 'authority:drift' });
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const external = externalAuthorityDelta === null ? null : assertExternalAuthorityDelta({
        value: externalAuthorityDelta,
        expectedAuthorityDigest,
        expectedSource,
        evidenceStore,
        allowedGraphs: new Set(managedGraphs(manifest)),
      });
      if (external !== null && await inspectPatchState(client, external.patch) !== 'pre') {
        throw new CompilerError('external authority delta is not an unused exact live pre-state', {
          phase: 'candidate:external-authority-delta-replay',
        });
      }
      const prepared = await composeSourceCandidate({
        client,
        manifest,
        generatedPatch: external?.patch || null,
        authorityWitness: beforeWitness,
        compileFunction,
        stage: 'base',
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
        externalAuthorityDelta: external === null ? null : Object.freeze({
          casRootDigests: external.casRootDigests,
          conflictIri: external.conflictIri,
          correctionCandidateDigest: external.correctionCandidateDigest,
          patchDigest: external.patchDigest,
          proofResultIri: external.proofResultIri,
          resolutionIri: external.resolutionIri,
          reviewIri: external.reviewIri,
        }),
        preservedAuthorityDelta: external === null ? null : Object.freeze({
          bytesBase64: external.patch.bytes.toString('base64'),
          digest: external.patch.digest,
        }),
        validationEvidence: validation,
      });
    },

    async composeCandidate({ generatedCandidateBytes, expectedAuthorityDigest, preservedAuthorityDelta = null }) {
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
      const allowedGraphs = new Set(managedGraphs(manifest));
      const generatedPatch = parseCanonicalPatch(generatedCandidateBytes, undefined, allowedGraphs);
      let preservedPatch = null;
      if (preservedAuthorityDelta !== null) {
        exactObjectKeys(preservedAuthorityDelta, ['bytesBase64', 'digest'], 'preserved authority delta');
        const preservedBytes = Buffer.from(preservedAuthorityDelta.bytesBase64, 'base64');
        if (preservedBytes.toString('base64') !== preservedAuthorityDelta.bytesBase64) {
          throw new CompilerError('preserved authority delta bytes are not canonical base64', {
            phase: 'candidate:external-authority-delta',
          });
        }
        preservedPatch = parseCanonicalPatch(
          preservedBytes,
          preservedAuthorityDelta.digest,
          allowedGraphs,
          new Set(['base']),
        );
        if (preservedPatch.deletions.length !== 0) {
          throw new CompilerError('preserved authority delta must remain additive', {
            phase: 'candidate:external-authority-delta',
          });
        }
      }
      const combined = await composeSourceCandidate({
        client, manifest, generatedPatch, preservedPatch, authorityWitness: beforeWitness, compileFunction,
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
          const record = await canonicalInventoryGraphDigest(graph, await graphText(store));
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
  assertExternalAuthorityDelta,
  digest,
  exactCandidateBytes,
  canonicalCombinedPatch,
  composeSourceCandidate,
  parseCanonicalPatch,
  patchState,
  semanticModelDirectory,
});
