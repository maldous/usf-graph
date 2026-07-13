import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { recomputeIndependentAudit } from '../src/closure.mjs';

test('closure recomputes the independent audit against explicit roots instead of loading audit output', async () => {
  const expected = { auditId: 'independent', status: 'pass', checks: [] };
  const calls = [];
  const result = await recomputeIndependentAudit({
    censusDirectory: '/independent/census',
    repositoryDirectory: '/independent/repository',
    auditRunner: async (options) => {
      calls.push(options);
      return expected;
    },
  });

  assert.equal(result, expected);
  assert.deepEqual(calls, [{
    censusRoot: '/independent/census',
    repositoryRoot: '/independent/repository',
  }]);

  const source = fs.readFileSync(new URL('../src/closure.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /readFileSync\([^\n]*audit\.json/);
  assert.match(source, /const audit = await recomputeIndependentAudit\(\)/);
  assert.match(source, /independentlyRecomputed: true/);
  assert.match(source, /unresolvedOrInvalidDependencyEdges/);
});
