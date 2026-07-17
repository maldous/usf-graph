import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  SELF_PUBLICATION_RULE,
  authorityDependencySetDigest,
  evaluateAuthorityBinding,
} from '../src/authority-binding.js';

const digest = (character) => `sha256:${character.repeat(64)}`;
const inventory = [
  { graph: 'urn:usf:graph:ontology', sha256: 'a'.repeat(64), triples: 10 },
  ...SELF_PUBLICATION_EXCLUDED_GRAPHS.map((graph, index) => ({ graph, sha256: (index % 10).toString().repeat(64), triples: index + 1 })),
];
const dependencySetDigest = authorityDependencySetDigest(inventory);
const binding = {
  currentAuthorityDigest: digest('c'),
  evaluatedAuthorityDigest: digest('b'),
  dependencySetDigest,
  dependencyDigestAlgorithm: AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  excludedGraphs: [...SELF_PUBLICATION_EXCLUDED_GRAPHS],
  graphInventory: inventory,
  requiresPostPublicationReevaluation: true,
  rule: SELF_PUBLICATION_RULE,
};

test('self-publication authority binding accepts only an unchanged non-publication graph inventory', () => {
  assert.deepEqual(evaluateAuthorityBinding(binding), {
    ok: true,
    mode: 'self-publication-closure',
    findings: [],
    observedDependencySetDigest: dependencySetDigest,
  });
});

test('direct-current authority binding uses the same complete dependency controls', () => {
  const result = evaluateAuthorityBinding({ ...binding, evaluatedAuthorityDigest: binding.currentAuthorityDigest });
  assert.equal(result.ok, true);
  assert.equal(result.mode, 'direct-authority');
});

test('authority binding rejects changed dependencies, broadened exclusions, and a skipped postpublication rerun', () => {
  const changed = inventory.map((record) => record.graph === 'urn:usf:graph:ontology' ? { ...record, sha256: 'f'.repeat(64) } : record);
  const result = evaluateAuthorityBinding({
    ...binding,
    excludedGraphs: [...binding.excludedGraphs, 'urn:usf:graph:ontology'],
    graphInventory: changed,
    requiresPostPublicationReevaluation: false,
  });
  assert.deepEqual(result.findings, ['dependency-set-mismatch', 'excluded-authority-graphs', 'postpublication-reevaluation']);
});

test('authority dependency digest is order-independent and content-sensitive', () => {
  assert.equal(authorityDependencySetDigest([...inventory].reverse()), dependencySetDigest);
  const changed = inventory.map((record) => record.graph === 'urn:usf:graph:ontology' ? { ...record, sha256: 'e'.repeat(64) } : record);
  assert.notEqual(authorityDependencySetDigest(changed), dependencySetDigest);
});
