// The structured generation authority-binding receipt.
//
// The generator previously accepted a bare `--authority-witness-digest
// sha256:<hex>` and, on nothing more than that string being syntactically well
// formed, stamped every projection with it and reported
// `authorityWitnessBound=true`. A syntax-valid digest argument is not proof of
// source/live parity: any 64 hex characters would have bound 100 artefacts to an
// authority state that may never have existed, or may have existed and moved.
//
// A binding is now a receipt that has to survive validation against what the
// generator itself observes: the dataset it actually loaded, the repository
// commit and tree it actually read, and the drift and derived-snapshot results
// that were actually taken. Anything missing, inconsistent or stale fails
// closed, and only a receipt that passes yields `authorityWitnessBound=true`.
//
// Offline local generation remains available with no receipt at all. It reports
// `authorityWitnessBound=false` and carries the generator's local input digest,
// which is exactly what a consumer needs in order to refuse it for production
// materialisation.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

import { GENERATION_INPUT_DIGEST_ALGORITHM } from '../semantic-model-compilation/authority-dataset.mjs';

export const GENERATION_AUTHORITY_BINDING_SCHEMA_VERSION = 1;
export const SUPPORTED_AUTHORITY_DIGEST_ALGORITHMS = Object.freeze(['sha256-rdfc10-graph-inventory-v2']);
export const SUPPORTED_GENERATION_INPUT_DIGEST_ALGORITHMS = Object.freeze([GENERATION_INPUT_DIGEST_ALGORITHM]);

const EXACT_DIGEST = /^sha256:[0-9a-f]{64}$/;
const EXACT_GIT_OBJECT = /^[0-9a-f]{40}$/;
const EXACT_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export class GenerationAuthorityBindingError extends Error {
  constructor(code, detail) {
    super(`generation authority binding ${code}: ${detail}`);
    this.name = 'GenerationAuthorityBindingError';
    this.code = code;
    this.detail = detail;
  }
}

const fail = (code, detail) => { throw new GenerationAuthorityBindingError(code, detail); };

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

export function graphInventoryDigest(inventory) {
  return sha256(inventory
    .map((record) => `${record.graph} ${record.sha256} ${record.triples}`)
    .sort()
    .join('\n'));
}

export function generationAuthorityBindingDigest(receipt) {
  const unsigned = { ...receipt };
  delete unsigned.receiptDigest;
  return sha256(canonicalJson(unsigned));
}

// Observe the exact repository commit and tree the generator is reading. A
// receipt that names a different pair describes a different source state.
export function observeGitSource(repositoryRoot, execute = execFileSync) {
  const read = (args) => String(execute('git', ['-C', repositoryRoot, ...args], { encoding: 'utf8' })).trim();
  return Object.freeze({ sourceCommit: read(['rev-parse', 'HEAD']), sourceTree: read(['rev-parse', 'HEAD^{tree}']) });
}

/**
 * Build a receipt from observations a caller has actually taken.
 * Every field is supplied; nothing is defaulted into existence.
 */
export function buildGenerationAuthorityBinding({
  authorityDigest,
  authorityDigestAlgorithm = SUPPORTED_AUTHORITY_DIGEST_ALGORITHMS[0],
  graphCount,
  tripleTotal,
  graphInventory,
  dataset,
  sourceCommit,
  sourceTree,
  sourceLiveDrift,
  derivedSnapshot,
  observedAt,
}) {
  const receipt = {
    schemaVersion: GENERATION_AUTHORITY_BINDING_SCHEMA_VERSION,
    authorityDigestAlgorithm,
    authorityDigest,
    graphCount,
    tripleTotal,
    graphInventory: graphInventory.map((record) => ({
      graph: record.graph,
      sha256: record.sha256,
      triples: record.triples,
    })).sort((left, right) => left.graph.localeCompare(right.graph)),
    graphInventoryDigest: graphInventoryDigest(graphInventory),
    generationInputDigestAlgorithm: dataset.inputDigestAlgorithm,
    generationInputDigest: dataset.inputDigest,
    generationInputScope: {
      name: dataset.scope.name,
      sections: [...dataset.scope.sections],
      omits: { ...dataset.scope.omits },
    },
    generationInputGraphs: dataset.graphInventory.map((record) => record.graph).sort(),
    sourceCommit,
    sourceTree,
    sourceLiveDrift,
    derivedSnapshot,
    observedAt,
  };
  receipt.receiptDigest = generationAuthorityBindingDigest(receipt);
  return Object.freeze(receipt);
}

/**
 * Validate a receipt against what the generator itself observes.
 *
 * @param receipt the caller-supplied binding
 * @param options.dataset the dataset the generator actually loaded
 * @param options.observedSource `{sourceCommit, sourceTree}` as read from disk
 */
export function assertGenerationAuthorityBinding(receipt, { dataset, observedSource }) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    fail('absent', 'a structured binding receipt is required for authority-bound generation');
  }
  if (receipt.schemaVersion !== GENERATION_AUTHORITY_BINDING_SCHEMA_VERSION) {
    fail('unsupported-schema-version', `expected ${GENERATION_AUTHORITY_BINDING_SCHEMA_VERSION}, saw ${JSON.stringify(receipt.schemaVersion ?? null)}`);
  }
  if (!SUPPORTED_AUTHORITY_DIGEST_ALGORITHMS.includes(receipt.authorityDigestAlgorithm)) {
    fail('unsupported-authority-algorithm', String(receipt.authorityDigestAlgorithm ?? null));
  }
  if (!SUPPORTED_GENERATION_INPUT_DIGEST_ALGORITHMS.includes(receipt.generationInputDigestAlgorithm)) {
    fail('unsupported-generation-input-algorithm', String(receipt.generationInputDigestAlgorithm ?? null));
  }
  for (const [field, value] of [['authorityDigest', receipt.authorityDigest], ['generationInputDigest', receipt.generationInputDigest], ['graphInventoryDigest', receipt.graphInventoryDigest]]) {
    if (!EXACT_DIGEST.test(value || '')) fail('malformed-digest', `${field} is not sha256:<64 lowercase hex>: ${JSON.stringify(value ?? null)}`);
  }
  for (const [field, value] of [['graphCount', receipt.graphCount], ['tripleTotal', receipt.tripleTotal]]) {
    if (!Number.isSafeInteger(value) || value < 0) fail('malformed-count', `${field} is not a non-negative safe integer: ${JSON.stringify(value ?? null)}`);
  }
  if (!EXACT_TIMESTAMP.test(receipt.observedAt || '')) {
    fail('malformed-timestamp', `observedAt must be an exact UTC timestamp: ${JSON.stringify(receipt.observedAt ?? null)}`);
  }

  // Inventory totals must agree with the counts the receipt itself states.
  const inventory = receipt.graphInventory;
  if (!Array.isArray(inventory) || inventory.length === 0) fail('inventory-absent', 'graphInventory is required');
  if (inventory.length !== receipt.graphCount) {
    fail('inconsistent-inventory-total', `graphInventory holds ${inventory.length} graphs but graphCount is ${receipt.graphCount}`);
  }
  let observedTriples = 0;
  for (const record of inventory) {
    if (typeof record?.graph !== 'string' || !record.graph.startsWith('urn:usf:graph:')) fail('inventory-absent', `inventory record has no exact graph IRI: ${JSON.stringify(record?.graph ?? null)}`);
    if (!EXACT_DIGEST.test(record?.sha256 || '')) fail('malformed-digest', `inventory digest for ${record.graph}`);
    if (!Number.isSafeInteger(record?.triples) || record.triples < 0) fail('malformed-count', `inventory triples for ${record.graph}`);
    observedTriples += record.triples;
  }
  if (observedTriples !== receipt.tripleTotal) {
    fail('inconsistent-inventory-total', `inventory sums to ${observedTriples} triples but tripleTotal is ${receipt.tripleTotal}`);
  }
  if (graphInventoryDigest(inventory) !== receipt.graphInventoryDigest) {
    fail('inconsistent-inventory-total', 'graphInventoryDigest does not describe the stated inventory');
  }

  // The receipt must describe the generator's ACTUAL input, not another load.
  if (receipt.generationInputDigest !== dataset.inputDigest) {
    fail('generation-input-mismatch', `receipt names ${receipt.generationInputDigest} but the loaded generation input is ${dataset.inputDigest}`);
  }
  if (receipt.generationInputScope?.name !== dataset.scope.name) {
    fail('generation-input-mismatch', `receipt names scope ${JSON.stringify(receipt.generationInputScope?.name ?? null)} but the loaded scope is ${dataset.scope.name}`);
  }
  const loadedGraphs = dataset.graphInventory.map((record) => record.graph).sort();
  if (canonicalJson([...(receipt.generationInputGraphs ?? [])].sort()) !== canonicalJson(loadedGraphs)) {
    fail('generation-input-mismatch', 'receipt generation-input graph subset differs from the loaded subset');
  }

  // The receipt must describe the source tree the generator is reading.
  for (const [field, value] of [['sourceCommit', receipt.sourceCommit], ['sourceTree', receipt.sourceTree]]) {
    if (!EXACT_GIT_OBJECT.test(value || '')) fail('malformed-source-identity', `${field} is not an exact Git object id: ${JSON.stringify(value ?? null)}`);
  }
  if (receipt.sourceCommit !== observedSource?.sourceCommit || receipt.sourceTree !== observedSource?.sourceTree) {
    fail('source-identity-mismatch', `receipt names ${receipt.sourceCommit}/${receipt.sourceTree} but the generator is reading ${observedSource?.sourceCommit}/${observedSource?.sourceTree}`);
  }

  // Source/live parity and derived determinism must have been established, not
  // merely asserted as an empty object.
  const drift = receipt.sourceLiveDrift;
  if (!drift || drift.checked !== true) fail('drift-unchecked', 'sourceLiveDrift.checked must be true');
  if (!Array.isArray(drift.mismatchedGraphs)) fail('drift-unchecked', 'sourceLiveDrift.mismatchedGraphs must be an array');
  if (drift.mismatchedGraphs.length > 0) {
    fail('source-live-drift', `${drift.mismatchedGraphs.length} managed graphs differ: ${drift.mismatchedGraphs.slice(0, 5).join(', ')}`);
  }
  if (!Number.isSafeInteger(drift.graphCount) || drift.graphCount !== receipt.graphCount) {
    fail('drift-unchecked', `sourceLiveDrift.graphCount ${JSON.stringify(drift.graphCount ?? null)} does not equal the witness graph count ${receipt.graphCount}`);
  }
  const derived = receipt.derivedSnapshot;
  if (!derived || derived.checked !== true || derived.deterministic !== true) {
    fail('derived-snapshot-unproven', 'derivedSnapshot must record a checked, deterministic derivation');
  }

  if (receipt.receiptDigest !== generationAuthorityBindingDigest(receipt)) {
    fail('receipt-digest-mismatch', 'receiptDigest does not describe the receipt');
  }
  return Object.freeze({ ...receipt });
}
