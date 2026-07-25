// Explicit authority-binding input contract for programme state generation.
//
// The programme checkpoint generator must never carry a compiled-in authority
// digest or triple count: a generator that pins its own authority produces a
// mutually consistent artefact set bound to superseded truth, which cannot fail
// closed because every artefact agrees with every other artefact. This module
// defines the only accepted input contract — a mechanically captured manifest
// produced through the approved semantic-authority boundary — together with a
// fail-closed loader and the exact-propagation checks the generator applies to
// every generated artefact and sidecar.
//
// Authority identity is the authority digest and nothing else. Triple count and
// graph count are observational metadata recorded for reporting; they can never
// establish, substitute for or repair authority identity.
import { createHash } from 'node:crypto';

export const AUTHORITY_BINDING_RECORD_KIND = 'USF_PROGRAMME_AUTHORITY_BINDING_MANIFEST';
export const AUTHORITY_BINDING_SCHEMA_VERSION = 1;

// The witness algorithm published by readSemanticAuthorityWitness and by the
// usf_layout_context MCP boundary. A manifest claiming any other algorithm is
// not a witness this contract can interpret.
export const AUTHORITY_WITNESS_ALGORITHM = 'sha256-rdfc10-graph-inventory-v2';

// Capture methods that are approved boundaries onto live semantic authority.
export const AUTHORITY_CAPTURE_METHODS = Object.freeze([
  'USF_MCP_LAYOUT_CONTEXT',
  'USF_SEMANTIC_AUTHORITY_GATEWAY_WITNESS',
]);

const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/u;

export class AuthorityBindingError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'AuthorityBindingError';
    this.code = code;
    this.details = details;
  }
}

function fail(code, message, details) {
  throw new AuthorityBindingError(code, message, details);
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortValue(value[key])]));
  }
  return value;
}

export function canonicalBindingBytes(value) {
  return Buffer.from(`${JSON.stringify(sortValue(value), null, 2)}\n`);
}

export function bindingDigest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

// Canonical digest over the witness graph inventory. The inventory is the
// snapshot identity behind the authority digest; recording its digest lets a
// consumer detect a manifest whose inventory was edited after capture.
export function graphInventoryDigest(inventory) {
  if (!Array.isArray(inventory) || inventory.length === 0) {
    fail('AUTHORITY_BINDING_INVENTORY_EMPTY', 'authority graph inventory is required');
  }
  const seen = new Set();
  const body = inventory.map((record) => {
    const graph = record?.graph;
    const raw = record?.sha256 ?? record?.digest;
    const sha256 = typeof raw === 'string' && raw.startsWith('sha256:') ? raw.slice(7) : raw;
    const triples = Number(record?.triples);
    if (typeof graph !== 'string' || !graph.startsWith('urn:usf:graph:')) {
      fail('AUTHORITY_BINDING_INVENTORY_GRAPH_INVALID', 'invalid authority graph IRI', { graph });
    }
    if (seen.has(graph)) fail('AUTHORITY_BINDING_INVENTORY_DUPLICATE', 'duplicate authority graph', { graph });
    if (typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(sha256)) {
      fail('AUTHORITY_BINDING_INVENTORY_DIGEST_INVALID', 'invalid authority graph digest', { graph });
    }
    if (!Number.isSafeInteger(triples) || triples < 0) {
      fail('AUTHORITY_BINDING_INVENTORY_TRIPLES_INVALID', 'invalid authority graph triple count', { graph });
    }
    seen.add(graph);
    return { graph, sha256, triples };
  }).sort((left, right) => left.graph.localeCompare(right.graph))
    .map((record) => `${record.graph}=${record.sha256}:${record.triples}`)
    .join('\n');
  return `sha256:${createHash('sha256').update(`${AUTHORITY_WITNESS_ALGORITHM}\n${body}`).digest('hex')}`;
}

// Authority identity is exactly the authority digest. This function exists so
// that no caller can accidentally treat an observational count as identity:
// there is one identity accessor and it reads one field.
export function authorityIdentity(binding) {
  if (!binding || typeof binding !== 'object') fail('AUTHORITY_BINDING_ABSENT', 'authority binding is required');
  const digest = binding.authority?.digest;
  if (!SHA256.test(digest ?? '')) fail('AUTHORITY_BINDING_DIGEST_INVALID', 'authority digest is required');
  return digest;
}

function validateAuthority(authority) {
  if (!authority || typeof authority !== 'object') {
    fail('AUTHORITY_BINDING_AUTHORITY_ABSENT', 'manifest authority block is required');
  }
  if (!SHA256.test(authority.digest ?? '')) {
    fail('AUTHORITY_BINDING_DIGEST_INVALID', 'authority digest must be sha256:<64 hex>');
  }
  if (authority.digestAlgorithm !== AUTHORITY_WITNESS_ALGORITHM) {
    fail('AUTHORITY_BINDING_ALGORITHM_INVALID', 'unsupported authority witness algorithm', {
      digestAlgorithm: authority.digestAlgorithm,
    });
  }
  if (!Number.isSafeInteger(authority.tripleCount) || authority.tripleCount < 0) {
    fail('AUTHORITY_BINDING_TRIPLE_COUNT_INVALID', 'authority triple count must be a non-negative integer');
  }
  if (!Number.isSafeInteger(authority.graphCount) || authority.graphCount <= 0) {
    fail('AUTHORITY_BINDING_GRAPH_COUNT_INVALID', 'authority graph count must be a positive integer');
  }
  if (typeof authority.database !== 'string' || authority.database.length === 0) {
    fail('AUTHORITY_BINDING_DATABASE_INVALID', 'authority database identity is required');
  }
  if (typeof authority.endpoint !== 'string' || !/^https?:\/\/\S+$/u.test(authority.endpoint)) {
    fail('AUTHORITY_BINDING_ENDPOINT_INVALID', 'authority endpoint identity is required');
  }
  if (!SHA256.test(authority.graphInventoryDigest ?? '')) {
    fail('AUTHORITY_BINDING_INVENTORY_DIGEST_REQUIRED', 'graph inventory digest is required');
  }
  const observed = graphInventoryDigest(authority.graphInventory);
  if (observed !== authority.graphInventoryDigest) {
    fail('AUTHORITY_BINDING_INVENTORY_DIGEST_MISMATCH', 'graph inventory digest does not match the recorded inventory', {
      observed,
      recorded: authority.graphInventoryDigest,
    });
  }
  if (authority.graphInventory.length !== authority.graphCount) {
    fail('AUTHORITY_BINDING_GRAPH_COUNT_MISMATCH', 'graph count does not match the recorded inventory length', {
      graphCount: authority.graphCount,
      inventoryLength: authority.graphInventory.length,
    });
  }
}

function validateCapture(capture) {
  if (!capture || typeof capture !== 'object') {
    fail('AUTHORITY_BINDING_CAPTURE_ABSENT', 'manifest capture provenance is required');
  }
  if (!INSTANT.test(capture.capturedAt ?? '')) {
    fail('AUTHORITY_BINDING_CAPTURED_AT_INVALID', 'capture timestamp must be an ISO-8601 UTC instant');
  }
  if (!AUTHORITY_CAPTURE_METHODS.includes(capture.method)) {
    fail('AUTHORITY_BINDING_CAPTURE_METHOD_INVALID', 'capture method is not an approved authority boundary', {
      method: capture.method,
    });
  }
  if (!SHA256.test(capture.toolDigest ?? '')) {
    fail('AUTHORITY_BINDING_CAPTURE_TOOL_DIGEST_INVALID', 'capture tool source digest is required');
  }
}

function validateWaveArtefacts(waveArtefacts) {
  if (!Array.isArray(waveArtefacts) || waveArtefacts.length === 0) {
    fail('AUTHORITY_BINDING_WAVE_ABSENT', 'manifest must declare the bound wave artefact set');
  }
  const roles = new Set();
  const paths = new Set();
  for (const artefact of waveArtefacts) {
    if (!artefact || typeof artefact !== 'object') {
      fail('AUTHORITY_BINDING_WAVE_RECORD_INVALID', 'wave artefact record must be an object');
    }
    const { role, path, fileDigest, authorityField } = artefact;
    if (typeof role !== 'string' || !/^[a-zA-Z][a-zA-Z0-9]*$/u.test(role)) {
      fail('AUTHORITY_BINDING_WAVE_ROLE_INVALID', 'wave artefact role is invalid', { role });
    }
    if (roles.has(role)) fail('AUTHORITY_BINDING_WAVE_ROLE_DUPLICATE', 'duplicate wave artefact role', { role });
    if (typeof path !== 'string' || path.length === 0 || path.startsWith('/') || path.includes('..')) {
      fail('AUTHORITY_BINDING_WAVE_PATH_INVALID', 'wave artefact path must be a repository-relative path', { role, path });
    }
    if (paths.has(path)) fail('AUTHORITY_BINDING_WAVE_PATH_DUPLICATE', 'duplicate wave artefact path', { path });
    if (!SHA256.test(fileDigest ?? '')) {
      fail('AUTHORITY_BINDING_WAVE_FILE_DIGEST_INVALID', 'wave artefact file digest is required', { role });
    }
    // A dotted field path locates the artefact's own authority binding. null is
    // the explicit declaration that an artefact carries no authority field of
    // its own and is bound by reference from an artefact that does — recorded
    // deliberately so "no field" can never be confused with "not checked".
    if (authorityField !== null
      && (typeof authorityField !== 'string' || !/^[a-zA-Z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)*$/u.test(authorityField))) {
      fail('AUTHORITY_BINDING_WAVE_FIELD_INVALID', 'wave artefact authority field must be a dotted path or null', { role });
    }
    roles.add(role);
    paths.add(path);
  }
  const canonical = waveArtefacts.map(({ role }) => role);
  if (JSON.stringify(canonical) !== JSON.stringify([...canonical].sort())) {
    fail('AUTHORITY_BINDING_WAVE_UNSORTED', 'wave artefact roles must be canonically sorted');
  }
}

// Fail-closed validation of a candidate manifest value. Returns a frozen
// binding; throws AuthorityBindingError on any structural or consistency defect.
export function validateAuthorityBindingManifest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('AUTHORITY_BINDING_MALFORMED', 'authority binding manifest must be a JSON object');
  }
  if (value.recordKind !== AUTHORITY_BINDING_RECORD_KIND) {
    fail('AUTHORITY_BINDING_RECORD_KIND_INVALID', 'unexpected authority binding record kind', {
      recordKind: value.recordKind,
    });
  }
  if (value.schemaVersion !== AUTHORITY_BINDING_SCHEMA_VERSION) {
    fail('AUTHORITY_BINDING_SCHEMA_VERSION_INVALID', 'unsupported authority binding schema version', {
      schemaVersion: value.schemaVersion,
    });
  }
  validateAuthority(value.authority);
  validateCapture(value.capture);
  validateWaveArtefacts(value.waveArtefacts);
  return Object.freeze({
    authority: Object.freeze({ ...value.authority, graphInventory: Object.freeze([...value.authority.graphInventory]) }),
    capture: Object.freeze({ ...value.capture }),
    recordKind: value.recordKind,
    schemaVersion: value.schemaVersion,
    waveArtefacts: Object.freeze(value.waveArtefacts.map((artefact) => Object.freeze({ ...artefact }))),
  });
}

// Load a manifest from exact bytes under an exact expected digest. The digest
// argument is mandatory: a manifest accepted on path alone would let a stale or
// substituted capture re-enter generation silently.
export function loadAuthorityBindingManifest({ bytes, expectedDigest }) {
  if (!Buffer.isBuffer(bytes) && typeof bytes !== 'string') {
    fail('AUTHORITY_BINDING_BYTES_REQUIRED', 'authority binding manifest bytes are required');
  }
  if (!SHA256.test(expectedDigest ?? '')) {
    fail('AUTHORITY_BINDING_EXPECTED_DIGEST_REQUIRED', 'an exact expected manifest digest is required');
  }
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const observed = bindingDigest(buffer);
  if (observed !== expectedDigest) {
    fail('AUTHORITY_BINDING_DIGEST_MISMATCH', 'authority binding manifest bytes do not match the expected digest', {
      expected: expectedDigest,
      observed,
    });
  }
  let parsed;
  try {
    parsed = JSON.parse(buffer.toString('utf8'));
  } catch {
    fail('AUTHORITY_BINDING_MALFORMED', 'authority binding manifest is not valid JSON');
  }
  const manifest = validateAuthorityBindingManifest(parsed);
  return Object.freeze({ ...manifest, manifestDigest: observed });
}

// Exact-argument contract for programme generation entry points.
//
// Lives here rather than inside the generator script so the fail-closed
// behaviour can be asserted in-process: the hermetic assurance sandbox runs
// with --permission and denies child processes, so a test that could only
// observe this by spawning the CLI would be untestable under the gate that
// matters most.
export function requireExactArgument(argv, name, { required = true } = {}) {
  const prefix = `--${name}=`;
  const supplied = (argv ?? []).filter((value) => typeof value === 'string' && value.startsWith(prefix));
  if (supplied.length === 0) {
    if (!required) return null;
    fail('AUTHORITY_ARGUMENT_REQUIRED', `exactly one ${prefix}<value> argument is required`, { name });
  }
  if (supplied.length > 1) {
    fail('AUTHORITY_ARGUMENT_AMBIGUOUS', `exactly one ${prefix}<value> argument is required`, { name });
  }
  const value = supplied[0].slice(prefix.length);
  if (value.length === 0) {
    fail('AUTHORITY_ARGUMENT_EMPTY', `${prefix}<value> requires a non-empty value`, { name });
  }
  return value;
}

// Read an artefact's declared authority field. A null field means the artefact
// declares no authority binding of its own; callers must treat that as
// "bound by reference" and never as a silent pass.
export function readAuthorityField(record, authorityField) {
  if (authorityField === null) return null;
  let cursor = record;
  for (const segment of authorityField.split('.')) {
    if (!cursor || typeof cursor !== 'object') return undefined;
    cursor = cursor[segment];
  }
  return cursor;
}

// Exact propagation check. Every generated artefact and sidecar must carry the
// one supplied authority identity; a single divergent binding fails generation.
export function assertExactAuthorityPropagation({ binding, artefacts }) {
  const identity = authorityIdentity(binding);
  if (!Array.isArray(artefacts) || artefacts.length === 0) {
    fail('AUTHORITY_PROPAGATION_EMPTY', 'no artefacts were presented for authority propagation');
  }
  const divergent = [];
  let checked = 0;
  for (const artefact of artefacts) {
    const { role, observedDigest, boundByReference = false } = artefact ?? {};
    if (typeof role !== 'string' || role.length === 0) {
      fail('AUTHORITY_PROPAGATION_ROLE_INVALID', 'artefact role is required for propagation checking');
    }
    // An artefact declared as bound by reference carries no authority field.
    // It must present no digest at all; presenting one means the declaration
    // and the artefact disagree, which is itself a defect.
    if (boundByReference) {
      if (observedDigest !== null && observedDigest !== undefined) {
        divergent.push({ observedDigest, role });
      }
      continue;
    }
    checked += 1;
    if (!SHA256.test(observedDigest ?? '')) {
      divergent.push({ observedDigest: observedDigest ?? null, role });
      continue;
    }
    if (observedDigest !== identity) divergent.push({ observedDigest, role });
  }
  if (checked === 0) {
    fail('AUTHORITY_PROPAGATION_UNCHECKED', 'no artefact presented an authority binding to check');
  }
  if (divergent.length > 0) {
    fail('AUTHORITY_PROPAGATION_MISMATCH', 'generated artefacts do not all bind the supplied authority identity', {
      divergent: divergent.sort((left, right) => left.role.localeCompare(right.role)),
      identity,
    });
  }
  return identity;
}
