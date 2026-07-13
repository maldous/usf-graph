import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { censusRoot, classifications } from '../src/constants.mjs';
import { readJsonl } from '../src/canonical.mjs';

test('reviewed selectors are digest anchored and unique', () => {
  const rows = readJsonl(path.join(censusRoot, 'src', 'reviewed-overrides.jsonl'));
  const keys = rows.map((row) => `${row.universe}\0${row.path}\0${row.contentDigest}`);
  assert.equal(new Set(keys).size, rows.length);
  assert.ok(rows.every((row) => /^[a-f0-9]{64}$/.test(row.contentDigest)));
});

test('semantic layer review covers the complete controlled layer set', () => {
  const rows = readJsonl(path.join(censusRoot, 'src', 'semantic-layer-review.jsonl'));
  assert.deepEqual(rows.map((row) => row.layer).sort(), [...classifications.semanticLayers].sort());
  assert.ok(rows.every((row) => row.coverageStatus === 'complete' || (row.preciseGaps.length > 0 && row.requiredSemanticLayers.length > 0)));
});

test('work packages own every hardened entity exactly once', () => {
  const work = JSON.parse(fs.readFileSync(path.join(censusRoot, 'workpackages.json'), 'utf8'));
  const summary = JSON.parse(fs.readFileSync(path.join(censusRoot, 'summary.json'), 'utf8'));
  const canonicalArtifacts = readJsonl(path.join(censusRoot, 'canonical-artifacts.jsonl'));
  for (const records of Object.values(work.ownership)) assert.equal(records.length, new Set(records.map((item) => item.ownedKey)).size);
  assert.equal(work.ownership.artifacts.length, readJsonl(path.join(censusRoot, 'artifacts.jsonl')).length);
  assert.equal(work.ownership.canonicalArtifacts.length, canonicalArtifacts.length);
  assert.equal(canonicalArtifacts.length, summary.sourceDispositionAcceptedOutputPlanCount);
  assert.ok(canonicalArtifacts.length > 0);
  assert.ok(canonicalArtifacts.every((record) => record.productionContract.planIri && record.productionContract.generatorIri && record.equivalenceContract.gates.length > 0));
  assert.equal(work.ownership.missingEntirely.length, readJsonl(path.join(censusRoot, 'missing-entirely.jsonl')).length);
});

test('work-package boundaries preserve required prerequisites while proving point-in-time satisfaction', () => {
  const packages = JSON.parse(fs.readFileSync(path.join(censusRoot, 'workpackages.json'), 'utf8')).workPackages;
  const dependencies = readJsonl(path.join(censusRoot, 'dependencies.jsonl')).filter((item) => item.status === 'required-prerequisite');
  const keys = new Set(packages.map((item) => item.key));
  for (const dependency of dependencies) {
    assert.ok(keys.has(dependency.source));
    assert.ok(keys.has(dependency.prerequisite));
    assert.notEqual(dependency.dependencyType, 'soft-coordination');
    assert.notEqual(dependency.reasonCode, 'cycle-softened-by-runtime-reference');
  }
  const summary = JSON.parse(fs.readFileSync(path.join(censusRoot, 'summary.json'), 'utf8'));
  const resolved = dependencies.filter((dependency) => dependency.resolutionStatus === 'resolved-retained');
  const satisfied = dependencies.filter((dependency) => dependency.satisfactionStatus === 'satisfied');
  assert.equal(summary.requiredPrerequisiteRelationshipCount, dependencies.length);
  assert.equal(summary.resolvedPrerequisiteRelationshipCount, resolved.length);
  assert.equal(summary.satisfiedPrerequisiteRelationshipCount, satisfied.length);
  assert.equal(summary.blockingRelationshipCount, 0);
  assert.equal(summary.activeBlockingRelationshipCount, dependencies.length - satisfied.length);
  assert.ok(dependencies.every((dependency) => dependency.satisfactionBasis && dependency.satisfactionStatus === 'satisfied'));
  assert.equal(summary.activeBlockingRelationshipCount, 0);
  assert.equal(summary.requiredPrerequisiteCycleCount, 0);
  assert.equal(summary.unreviewedParallelismReductionCount, 0);
  assert.equal(summary.closureEvaluation, 'deferred-to-closure-command');
  assert.ok(!Object.hasOwn(summary, 'closureStatus'));
});

test('canonical outputs contain no coordinator or current issue metadata', () => {
  const files = fs.readdirSync(censusRoot).filter((file) => /\.jsonl?$/.test(file));
  const forbidden = /\/home\/user|USF-(?:111[6-9]|112\d|113[0-3])|linearIssue|linearProject|agentMetadata|gitBranch|gitCommit/;
  for (const file of files) assert.doesNotMatch(fs.readFileSync(path.join(censusRoot, file), 'utf8'), forbidden, file);
});
