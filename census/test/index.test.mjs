import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { buildIndex } from '../src/index.mjs';
import { repositoryRoot } from '../src/constants.mjs';
import { sha256 } from '../src/canonical.mjs';

test('a missing relationship target is retained with a bounded finding', () => {
  const relative = `v2/usf/census/.work-test/census-index-${process.pid}.mjs`;
  const absolute = path.join(repositoryRoot, relative);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, "import './definitely-missing.js';\n");
  try {
    const bytes = fs.readFileSync(absolute);
    const member = {
      path: relative,
      universe: 'repository-output',
      sourceState: 'untracked',
      contentDigest: sha256(bytes),
      byteSize: bytes.length,
      fileMode: '100644',
      executable: false,
      binary: false,
      extension: '.mjs',
      mediaType: 'text/plain',
      formatKind: 'source-code',
      symbolicLinkTarget: null
    };
    const index = buildIndex([member]);
    assert.equal(index.relationships.length, 1);
    assert.equal(index.relationships[0].resolved, false);
    assert.equal(index.findings.length, 1);
    assert.equal(index.summary.closureStatus, 'complete');
  } finally {
    fs.rmSync(path.dirname(absolute), { recursive: true, force: true });
  }
});

test('binary artifacts are represented without textual parsing', () => {
  const index = buildIndex([{ path: 'binary.dat', universe: 'repository-output', binary: true, formatKind: 'opaque-binary', sourceState: 'tracked' }]);
  assert.equal(index.summary.binaryOrStaticRepresentedCount, 1);
  assert.equal(index.summary.unrepresentedArtifactCount, 0);
});
