import { createHash } from 'node:crypto';

export const AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM = 'sha256-rdfc10-nonpublication-graph-inventory-v1';
export const SELF_PUBLICATION_RULE = 'urn:usf:authoritybindingrule:selfpublicationclosure';
export const SELF_PUBLICATION_EXCLUDED_GRAPHS = Object.freeze([
  'urn:usf:graph:capabilities',
  'urn:usf:graph:derived:coverage',
  'urn:usf:graph:derived:evidence',
  'urn:usf:graph:derived:obligations',
  'urn:usf:graph:derived:readiness',
  'urn:usf:graph:derived:surfaces',
  'urn:usf:graph:evidence',
  'urn:usf:graph:proofs',
]);

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));

function normalizedExcludedGraphs(excludedGraphs) {
  if (!Array.isArray(excludedGraphs) || excludedGraphs.length === 0) {
    throw new Error('excluded authority graphs are required');
  }
  const normalized = [...excludedGraphs].sort();
  if (new Set(normalized).size !== normalized.length
      || normalized.some((graph) => typeof graph !== 'string' || !graph.startsWith('urn:usf:graph:'))) {
    throw new Error('invalid excluded authority graph set');
  }
  return normalized;
}

function normalizedInventory(inventory, digestField) {
  if (!Array.isArray(inventory) || inventory.length === 0) throw new Error('authority graph inventory is required');
  const seen = new Set();
  return inventory.map((record) => {
    const graph = record?.graph;
    const raw = record?.[digestField];
    const sha256 = typeof raw === 'string' && HEX.test(raw) ? `sha256:${raw}` : raw;
    const triples = record?.triples;
    if (typeof graph !== 'string' || !graph.startsWith('urn:usf:graph:')) throw new Error('invalid authority graph IRI');
    if (seen.has(graph)) throw new Error('duplicate authority graph');
    if (!SHA256.test(sha256 ?? '')) throw new Error('invalid authority graph digest');
    if (!Number.isSafeInteger(triples) || triples < 0) throw new Error('invalid authority graph triple count');
    seen.add(graph);
    return { graph, sha256, triples };
  }).sort((left, right) => left.graph.localeCompare(right.graph));
}

// Canonical algorithm over an already graph-name-bound dependency inventory.
// This is the single serialization used by candidate construction and every
// live-currentness consumer. Full authority/content identity remains separate.
export function nonPublicationDependencySetDigest(
  inventory,
  excludedGraphs = SELF_PUBLICATION_EXCLUDED_GRAPHS,
) {
  const canonicalExcludedGraphs = normalizedExcludedGraphs(excludedGraphs);
  const excluded = new Set(canonicalExcludedGraphs);
  const graphs = normalizedInventory(inventory, 'sha256')
    // Named graphs with no triples do not exist in the live authority
    // inventory and therefore cannot contribute an identity record.
    .filter((record) => record.triples > 0 && !excluded.has(record.graph));
  return `sha256:${createHash('sha256').update(canonicalJson({
    algorithm: AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
    excludedGraphs: canonicalExcludedGraphs,
    graphs,
  })).digest('hex')}`;
}

// Live authority witnesses carry both content identity (sha256) and the
// named-graph dependency identity (dependencySha256). Never reinterpret the
// former as the latter: absence is an incomplete witness and fails closed.
export function authorityDependencySetDigest(
  inventory,
  excludedGraphs = SELF_PUBLICATION_EXCLUDED_GRAPHS,
) {
  const graphBoundInventory = normalizedInventory(inventory, 'dependencySha256')
    .map(({ graph, sha256, triples }) => ({ graph, sha256, triples }));
  return nonPublicationDependencySetDigest(graphBoundInventory, excludedGraphs);
}

function sameExactSet(left, right) {
  return left.length === right.length
    && new Set(left).size === left.length
    && [...left].sort().every((item, index) => item === [...right].sort()[index]);
}

export function evaluateAuthorityBinding({
  currentAuthorityDigest,
  evaluatedAuthorityDigest,
  dependencySetDigest,
  dependencyDigestAlgorithm,
  excludedGraphs,
  graphInventory,
  requiresPostPublicationReevaluation,
  rule,
}) {
  const findings = [];
  if (!SHA256.test(currentAuthorityDigest ?? '')) findings.push('current-authority-digest');
  if (!SHA256.test(evaluatedAuthorityDigest ?? '')) findings.push('evaluated-authority-digest');
  if (!SHA256.test(dependencySetDigest ?? '')) findings.push('dependency-set-digest');
  if (dependencyDigestAlgorithm !== AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM) findings.push('dependency-digest-algorithm');
  if (rule !== SELF_PUBLICATION_RULE) findings.push('authority-binding-rule');
  if (!Array.isArray(excludedGraphs) || !sameExactSet(excludedGraphs, SELF_PUBLICATION_EXCLUDED_GRAPHS)) findings.push('excluded-authority-graphs');
  if (requiresPostPublicationReevaluation !== true) findings.push('postpublication-reevaluation');
  let observedDependencySetDigest = null;
  try {
    observedDependencySetDigest = authorityDependencySetDigest(graphInventory);
    if (dependencySetDigest !== observedDependencySetDigest) findings.push('dependency-set-mismatch');
  } catch {
    findings.push('authority-graph-inventory');
  }
  const mode = currentAuthorityDigest === evaluatedAuthorityDigest ? 'direct-authority' : 'self-publication-closure';
  return { ok: findings.length === 0, mode, findings: [...new Set(findings)].sort(), observedDependencySetDigest };
}
