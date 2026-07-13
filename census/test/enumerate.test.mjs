import assert from 'node:assert/strict';
import test from 'node:test';
import { identifyFormat, universeSummary } from '../src/universe.mjs';

test('format discovery represents known text, structured, binary, and LFS forms', () => {
  assert.equal(identifyFormat('a.json', Buffer.from('{}'), '100644').formatKind, 'structured-json');
  assert.equal(identifyFormat('a.ttl', Buffer.from('@prefix a: <b> .'), '100644').formatKind, 'rdf-turtle');
  assert.equal(identifyFormat('a.bin', Buffer.from([0, 1]), '100644').formatKind, 'opaque-binary');
  assert.equal(identifyFormat('a.dat', Buffer.from('version https://git-lfs.github.com/spec/v1\n'), '100644').formatKind, 'git-lfs-pointer');
});

test('universe summary changes for a new path, mode, state, or content digest', () => {
  const base = { universe: 'repository-output', path: 'a', sourceState: 'tracked', fileMode: '100644', contentDigest: 'a'.repeat(64) };
  const first = universeSummary({
    'repository-output': [base], 'v2-graph-authority': [], 'v2-compiler-implementation': [], 'v2-support-provisioning': []
  });
  for (const changed of [
    { ...base, path: 'b' },
    { ...base, sourceState: 'modified' },
    { ...base, fileMode: '100755' },
    { ...base, contentDigest: 'b'.repeat(64) }
  ]) {
    const next = universeSummary({
      'repository-output': [changed], 'v2-graph-authority': [], 'v2-compiler-implementation': [], 'v2-support-provisioning': []
    });
    assert.notEqual(first.repositoryUniverseDigest, next.repositoryUniverseDigest);
  }
});
