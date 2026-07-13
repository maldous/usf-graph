import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyMember, familyFor } from '../src/classify.mjs';

const base = {
  path: 'apps/api/src/main.ts', universe: 'repository-output', sourceState: 'tracked', contentDigest: 'a'.repeat(64),
  byteSize: 100, fileMode: '100644', executable: false, binary: false, extension: '.ts', mediaType: 'text/plain',
  formatKind: 'source-code', symbolicLinkTarget: null
};

test('primary ownership is content-role based across universes', () => {
  assert.equal(familyFor(base), 'implementation');
  assert.equal(familyFor({ ...base, path: '.github/workflows/check.yml', formatKind: 'structured-yaml' }), 'automation');
  assert.equal(familyFor({ ...base, path: 'v2/usf/graph/shapes.ttl', universe: 'v2-graph-authority', formatKind: 'rdf-turtle' }), 'verification');
  assert.equal(familyFor({ ...base, path: 'v2/usf/SETUP.md', universe: 'v2-support-provisioning', formatKind: 'document-markdown' }), 'v2-support');
});

test('classification resolves every mandatory final value', () => {
  const record = classifyMember(base);
  assert.equal(record.primaryOwner, 'implementation');
  assert.equal(record.v2ConceptCoverage, 'identityonly');
  assert.ok(record.gapClassification.length > 0);
  assert.ok(record.requiredSemanticLayers.length > 0);
});
