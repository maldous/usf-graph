import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { auditIgnoreText, enumerateObservationCarrierMembers, enumerateUniverses, observationCarrierPaths, universeForPath, universeSummary } from '../src/universe.mjs';
import { discoverMaterialisationContracts } from '../src/materialisation.mjs';

function write(root, relative, content) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
}

function git(root, args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8' });
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'usf-universe-'));
  git(root, ['init', '--quiet']);
  git(root, ['config', 'user.email', 'census@example.invalid']);
  git(root, ['config', 'user.name', 'Census Test']);
  write(root, '.gitignore', 'node_modules/\n');
  write(root, 'docs/readme.md', 'repository\n');
  write(root, 'v2/usf/graph/authority.ttl', '@prefix usf: <urn:usf:> .\n');
  write(root, 'v2/usf/graph/manifest.yaml', [
    'observedGraphs:',
    '  - file: observed/source-artefacts.trig',
    'derivedGraphs:',
    '  - file: derived/projection.trig',
    ''
  ].join('\n'));
  write(root, 'v2/usf/graph/observed/source-artefacts.trig', 'GRAPH <urn:observed> {}\n');
  write(root, 'v2/usf/graph/derived/projection.trig', 'GRAPH <urn:derived> {}\n');
  write(root, 'v2/usf/compiler/package.json', '{"engines":{"node":">=22"}}\n');
  write(root, 'v2/usf/compiler/package-lock.json', '{"lockfileVersion":3,"packages":{}}\n');
  write(root, 'v2/usf/compiler/src/compiler.js', 'export const compiler = true;\n');
  write(root, 'v2/usf/SETUP.md', 'support\n');
  git(root, ['add', '.']);
  git(root, ['commit', '--quiet', '-m', 'fixture']);
  return root;
}

test('four universes are disjoint, canonical, and deterministically ordered', (t) => {
  const root = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const first = enumerateUniverses({ repositoryRoot: root });
  const second = enumerateUniverses({ repositoryRoot: root });
  assert.deepEqual(first, second);
  assert.deepEqual(Object.keys(first.universes), [
    'repository-output', 'v2-graph-authority', 'v2-compiler-implementation', 'v2-support-provisioning'
  ]);
  assert.deepEqual(first.universes['v2-compiler-implementation'].map((member) => member.path), [
    'v2/usf/compiler/package-lock.json', 'v2/usf/compiler/package.json', 'v2/usf/compiler/src/compiler.js'
  ]);
  assert.ok(Object.values(first.universes).flat().every((member) => member.canonicalSource === true));
  assert.ok(!Object.values(first.universes).flat().some((member) => member.path.includes('/observed/') || member.path.includes('/derived/')));
  assert.deepEqual(universeSummary(first.universes), universeSummary(second.universes));
});

test('observation carriers and noncanonical work state are excluded even if tracked', (t) => {
  const root = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  write(root, 'v2/usf/.work/audit/result.json', '{}\n');
  git(root, ['add', 'v2/usf/.work/audit/result.json']);
  git(root, ['commit', '--quiet', '-m', 'plant forbidden scratch']);
  const carriers = observationCarrierPaths(root);
  assert.equal(universeForPath('v2/usf/graph/observed/source-artefacts.trig', carriers), null);
  assert.equal(universeForPath('v2/usf/graph/derived/projection.trig', carriers), null);
  assert.equal(universeForPath('v2/usf/.work/audit/result.json', carriers), null);
  const paths = Object.values(enumerateUniverses({ repositoryRoot: root }).universes).flat().map((member) => member.path);
  assert.ok(!paths.includes('v2/usf/.work/audit/result.json'));
  assert.deepEqual(enumerateObservationCarrierMembers({ repositoryRoot: root }).map((member) => [member.path, member.universe]), [
    ['v2/usf/graph/derived/projection.trig', 'v2-graph-authority'],
    ['v2/usf/graph/observed/source-artefacts.trig', 'v2-graph-authority']
  ]);
});

test('observation carrier paths fail closed on noncanonical or missing manifest members', (t) => {
  const root = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  write(root, 'v2/usf/graph/manifest.yaml', 'observedGraphs:\n  - file: ./observed/source-artefacts.trig\n');
  assert.throws(() => observationCarrierPaths(root), /contained relative POSIX path/);
  write(root, 'v2/usf/graph/manifest.yaml', 'observedGraphs:\n  - file: observed/missing.trig\n');
  assert.throws(() => enumerateObservationCarrierMembers({ repositoryRoot: root }), /graph observation carrier is missing/);
});

test('clean, installed, and removed dependency states never change compiler source identity', (t) => {
  const root = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const cleanUniverse = enumerateUniverses({ repositoryRoot: root });
  const cleanContract = discoverMaterialisationContracts({ repositoryRoot: root })
    .find((contract) => contract.key === 'npm:v2/usf/compiler');
  assert.equal(cleanContract.currentStatus, 'observed-absent');

  write(root, 'v2/usf/compiler/node_modules/dependency/index.js', 'materialised\n');
  const installedUniverse = enumerateUniverses({ repositoryRoot: root });
  const installedContract = discoverMaterialisationContracts({ repositoryRoot: root })
    .find((contract) => contract.key === 'npm:v2/usf/compiler');
  assert.equal(installedContract.currentStatus, 'observed-present');
  assert.equal(installedContract.canonicalDigestInput, false);
  assert.equal(installedContract.expectedClosureDigest, cleanContract.expectedClosureDigest);
  assert.deepEqual(installedUniverse.universes['v2-compiler-implementation'], cleanUniverse.universes['v2-compiler-implementation']);

  fs.rmSync(path.join(root, 'v2/usf/compiler/node_modules'), { recursive: true, force: true });
  const removedUniverse = enumerateUniverses({ repositoryRoot: root });
  const removedContract = discoverMaterialisationContracts({ repositoryRoot: root })
    .find((contract) => contract.key === 'npm:v2/usf/compiler');
  assert.equal(removedContract.currentStatus, 'observed-absent');
  assert.equal(removedContract.expectedClosureDigest, cleanContract.expectedClosureDigest);
  assert.deepEqual(removedUniverse.universes['v2-compiler-implementation'], cleanUniverse.universes['v2-compiler-implementation']);
});

test('ignore audit fails closed for an unclassified pattern', () => {
  const audit = auditIgnoreText('.gitignore', 'node_modules/\nunknown-output/\n');
  assert.equal(audit[0].closureDecision, 'allowed');
  assert.equal(audit[1].closureDecision, 'blocked');
  assert.match(audit[1].reason, /requires an explicit materialisation or source decision/);
});
