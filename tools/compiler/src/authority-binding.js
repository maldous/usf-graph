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

function normalizedInventory(inventory) {
  if (!Array.isArray(inventory) || inventory.length === 0) throw new Error('authority graph inventory is required');
  const seen = new Set();
  return inventory.map((record) => {
    const graph = record?.graph;
    const raw = record?.sha256 ?? record?.digest;
    const sha256 = typeof raw === 'string' && raw.startsWith('sha256:') ? raw.slice(7) : raw;
    const triples = Number(record?.triples);
    if (typeof graph !== 'string' || !graph.startsWith('urn:usf:graph:')) throw new Error('invalid authority graph IRI');
    if (seen.has(graph)) throw new Error('duplicate authority graph');
    if (!HEX.test(sha256 ?? '')) throw new Error('invalid authority graph digest');
    if (!Number.isSafeInteger(triples) || triples < 0) throw new Error('invalid authority graph triple count');
    seen.add(graph);
    return { graph, sha256, triples };
  }).sort((left, right) => left.graph.localeCompare(right.graph));
}

export function authorityDependencySetDigest(inventory, excludedGraphs = SELF_PUBLICATION_EXCLUDED_GRAPHS) {
  const excluded = new Set(excludedGraphs);
  if (excluded.size !== excludedGraphs.length) throw new Error('duplicate excluded authority graph');
  const records = normalizedInventory(inventory);
  for (const graph of excluded) {
    if (!records.some((record) => record.graph === graph)) throw new Error(`excluded authority graph absent: ${graph}`);
  }
  const body = records
    .filter((record) => !excluded.has(record.graph))
    .map((record) => `${record.graph}=${record.sha256}:${record.triples}`)
    .join('\n');
  return `sha256:${createHash('sha256').update(`${AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM}\n${body}`).digest('hex')}`;
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
