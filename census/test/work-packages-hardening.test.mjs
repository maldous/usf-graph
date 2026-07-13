import assert from 'node:assert/strict';
import test from 'node:test';
import { buildWorkPackages, buildWorkPackageLineage, readBaselinePackageMembership } from '../src/work-packages.mjs';

function artifact(key, path, family = 'implementation') {
  return { artifactKey: key, path, universe: 'repository-output', artifactFamily: family };
}

function mapping(key, ambiguity = false) {
  return { artifactKey: key, ambiguities: ambiguity ? ['review'] : [], conflicts: [] };
}

function canonical(key, currentArtifacts, layer, kind = 'source-module', responsibility = 'generator', ownsLayer = false) {
  const gateKey = `gate-${key}`;
  return {
    canonicalArtifactKey: key,
    artifactKind: kind,
    currentArtifacts,
    requiredSemanticLayers: [layer],
    ownedSemanticLayers: ownsLayer ? [layer] : [],
    semanticInputs: [`semantic:${layer}`],
    productionResponsibilities: [responsibility],
    materialisationContract: null,
    equivalenceContract: { gates: [{ gateKey, mechanism: 'contract-comparison' }] },
    acceptanceGates: [{ gateKey, mechanism: 'contract-comparison' }]
  };
}

function replacement(key, currentArtifacts, canonicalArtifacts, action = 'rewrite') {
  const gate = canonicalArtifacts.length ? `gate-${canonicalArtifacts[0]}` : `absence-${key}`;
  return {
    groupKey: key,
    currentArtifacts,
    canonicalArtifacts,
    reuseActions: [action],
    equivalenceGates: [gate],
    proofEvidenceGates: [gate]
  };
}

const artifacts = [
  artifact('a', 'src/a.mjs'), artifact('b', 'src/b.mjs'),
  artifact('c', 'proof/c.json', 'proof-evidence'), artifact('d', 'proof/d.json', 'proof-evidence'),
  artifact('e', 'obsolete/e.txt', 'repository-governance')
];
const mappings = artifacts.map(({ artifactKey }) => mapping(artifactKey, artifactKey === 'b'));
const canonicalArtifacts = [
  canonical('ca', ['a'], 'implementation-obligations', 'source-module', 'generator', true),
  canonical('cb', ['b'], 'implementation-obligations'),
  canonical('cc', ['c'], 'proof-obligations', 'proof-executable', 'generator', true),
  canonical('cd', ['d'], 'proof-obligations', 'evidence-output', 'collector')
];
const replacementGroups = [
  replacement('ra', ['a'], ['ca']), replacement('rb', ['b'], ['cb'], 'wrap'),
  replacement('rc', ['c'], ['cc']), replacement('rd', ['d'], ['cd'], 'template'),
  replacement('re', ['e'], [], 'none')
];
const missingEntirely = [{ missingKey: 'gap-b', artifactKey: 'b', requiredSemanticLayers: ['equivalence-rules'] }];

test('builder creates cohesive outcomes with exact primary ownership', () => {
  const result = buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts, replacementGroups, baselinePackages: [] });
  const repeated = buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts, replacementGroups, baselinePackages: [] });
  assert.deepEqual(result, repeated);
  assert.ok(result.workPackages.length < artifacts.length);
  for (const records of Object.values(result.ownership)) assert.equal(records.length, new Set(records.map((record) => record.ownedKey)).size);
  assert.equal(result.ownership.artifacts.length, artifacts.length);
  assert.equal(result.ownership.missingEntirely.length, 1);
  assert.equal(result.ownership.canonicalArtifacts.length, canonicalArtifacts.length);
  assert.deepEqual(new Set(result.ownership.semanticLayers.map((record) => record.ownedKey)), new Set(['implementation-obligations', 'proof-obligations']));
  assert.equal(result.ownership.replacementGroups.length, replacementGroups.length);
  assert.equal(result.ownership.reuseActions.length, replacementGroups.length);
  const gateKeys = new Set(canonicalArtifacts.map((record) => record.equivalenceContract.gates[0].gateKey).concat('absence-re'));
  assert.deepEqual(new Set(result.ownership.equivalenceGates.map((record) => record.ownedKey)), gateKeys);
  const implementation = result.workPackages.find((record) => record.outcomeClass === 'implementation-realisation:implementation:src');
  assert.deepEqual(implementation.artifactKeys, ['a', 'b']);
  assert.deepEqual(implementation.missingEntirelyKeys, ['gap-b']);
});

test('complexity is evidence-derived and never uses row or byte sizing', () => {
  const { workPackages } = buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts, replacementGroups, baselinePackages: [] });
  for (const workPackage of workPackages) {
    assert.equal(workPackage.complexityDrivers.length, workPackage.complexityEvidence.length);
    assert.doesNotMatch(JSON.stringify(workPackage.complexityEvidence), /byte.?size|row.?count/i);
    assert.ok(['small', 'medium', 'large', 'programme'].includes(workPackage.complexity));
    assert.equal(workPackage.acceptanceCriteria.length, 3);
    assert.ok(workPackage.safeParallelism.boundary);
  }
});

test('lineage supports retained, merged, split, and retired dispositions', () => {
  const { workPackages } = buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts, replacementGroups, baselinePackages: [] });
  const baseline = [
    { key: 'baseline-retained', affectedRows: ['repository-output:obsolete/e.txt'], canonicalOutcome: 'closed' },
    { key: 'baseline-merged-a', affectedRows: ['repository-output:src/a.mjs'], canonicalOutcome: 'implementation-a' },
    { key: 'baseline-merged-b', affectedRows: ['repository-output:src/b.mjs'], canonicalOutcome: 'implementation-b' },
    { key: 'baseline-split', affectedRows: ['repository-output:proof/c.json', 'semantic-layer:implementation-obligations'], canonicalOutcome: 'mixed' },
    { key: 'baseline-retired', affectedRows: ['repository-output:absent.txt'], canonicalOutcome: 'invalid' }
  ];
  const lineage = buildWorkPackageLineage({ baselinePackages: baseline, workPackages, artifacts });
  assert.deepEqual(new Set(lineage.map((record) => record.disposition)), new Set([
    'retained-successor', 'merged-successor', 'split-successors', 'retired-invalid-bucket'
  ]));
});

test('the retained baseline lineage is nonempty and deterministic without fixing its size in code', () => {
  const first = readBaselinePackageMembership();
  const second = readBaselinePackageMembership();
  assert.ok(first.length > 0);
  assert.deepEqual(first, second);
  assert.equal(new Set(first.map((record) => record.key)).size, first.length);
  const result = buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts, replacementGroups });
  assert.equal(result.workPackageLineage.length, first.length);
  assert.ok(result.workPackageLineage.every((record) => [
    'retained-successor', 'merged-successor', 'split-successors', 'retired-invalid-bucket'
  ].includes(record.disposition)));
});

test('builder fails closed when an artifact has no replacement owner', () => {
  assert.throws(() => buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts, replacementGroups: replacementGroups.slice(1), baselinePackages: [] }), /artifact primary ownership is not closed/);
});

test('semantic layer ownership comes only from one canonical artifact owner', () => {
  const result = buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts, replacementGroups, baselinePackages: [] });
  const equivalence = result.ownership.semanticLayers.find((record) => record.ownedKey === 'equivalence-rules');
  assert.equal(equivalence, undefined, 'a missing-entirely demand must not manufacture semantic-layer ownership');
  const lineage = buildWorkPackageLineage({
    baselinePackages: [{ key: 'missing-layer', affectedRows: ['semantic-layer:equivalence-rules'], canonicalOutcome: 'review' }],
    workPackages: result.workPackages,
    artifacts
  });
  assert.deepEqual(lineage[0].successorWorkPackageKeys, []);
  assert.deepEqual(lineage[0].lineageEvidence.unmatchedBaselineRows, ['semantic-layer:equivalence-rules']);
  assert.deepEqual(canonicalArtifacts.find((record) => record.canonicalArtifactKey === 'ca').ownedSemanticLayers, ['implementation-obligations']);

  const samePackageDuplicate = canonicalArtifacts.map((record) => record.canonicalArtifactKey === 'cb'
    ? { ...record, ownedSemanticLayers: ['implementation-obligations'] }
    : record);
  assert.throws(
    () => buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts: samePackageDuplicate, replacementGroups, baselinePackages: [] }),
    /semantic layer has multiple canonical artifact owners/
  );

  const missingOwner = canonicalArtifacts.map((record) => record.canonicalArtifactKey === 'ca'
    ? { ...record, ownedSemanticLayers: [] }
    : record);
  assert.throws(
    () => buildWorkPackages({ artifacts, mappings, missingEntirely, canonicalArtifacts: missingOwner, replacementGroups, baselinePackages: [] }),
    /semantic layer lacks canonical artifact owner: implementation-obligations/
  );
});
