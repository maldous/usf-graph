import path from 'node:path';
import { canonicalJson, compareBy, sha256, sortUnique, writeJsonAtomic } from './canonical.mjs';
import { censusRoot } from './constants.mjs';

const familyRank = {
  'repository-governance': 0,
  'machine-semantics': 1,
  'documentation-assets': 1,
  implementation: 2,
  'runtime-topology': 2,
  'v2-support': 2,
  automation: 3,
  verification: 4,
  'proof-evidence': 5
};

const prerequisiteFamilies = {
  automation: ['implementation', 'runtime-topology', 'v2-support'],
  'documentation-assets': [],
  implementation: ['machine-semantics'],
  'machine-semantics': [],
  'proof-evidence': ['verification'],
  'repository-governance': [],
  'runtime-topology': ['machine-semantics'],
  verification: ['implementation', 'machine-semantics', 'runtime-topology'],
  'v2-support': ['machine-semantics']
};

function signature(record) {
  return canonicalJson({
    artifactFamily: record.artifactFamily,
    canonicalOutputRequirement: record.canonicalOutputRequirement,
    equivalenceClass: record.equivalenceClass,
    gapClassification: record.gapClassification,
    productionResponsibility: record.productionResponsibility,
    requiredSemanticLayers: record.requiredSemanticLayers,
    reuseStrategy: record.reuseStrategy,
    v2ConceptCoverage: record.v2ConceptCoverage
  }).trimEnd();
}

function workPackageKey(signatureValue) {
  return `wp-${sha256(signatureValue).slice(0, 20)}`;
}

export function planWork(records, references, layerCoverage = []) {
  const groups = new Map();
  for (const record of records) {
    const sig = signature(record);
    if (!groups.has(sig)) groups.set(sig, []);
    groups.get(sig).push(record);
  }
  const relationCount = new Map();
  const relationKeys = new Map();
  for (const relation of references) {
    relationCount.set(relation.source, (relationCount.get(relation.source) ?? 0) + 1);
    if (!relationKeys.has(relation.source)) relationKeys.set(relation.source, []);
    relationKeys.get(relation.source).push(sha256(`${relation.source}\0${relation.relationshipType}\0${relation.target}\0${relation.targetKind}\0${relation.extractionMethod}`));
  }
  const packages = [...groups.entries()].map(([sig, rows]) => {
    rows.sort(compareBy(['universe', 'path']));
    const first = rows[0];
    const key = workPackageKey(sig);
    return {
      key,
      canonicalOutcome: `${first.artifactFamily}:${first.canonicalOutputRequirement}:${first.v2ConceptCoverage}`,
      affectedRows: rows.map((row) => `${row.universe}:${row.path}`),
      affectedRelationships: sortUnique(rows.flatMap((row) => relationKeys.get(row.path) ?? [])),
      affectedRelationshipCount: rows.reduce((sum, row) => sum + (relationCount.get(row.path) ?? 0), 0),
      semanticAndSupportGaps: first.gapClassification,
      requiredSemanticLayers: first.requiredSemanticLayers,
      currentImplementationReuse: first.reuseStrategy,
      canonicalOutputs: [first.canonicalOutputRequirement],
      productionResponsibilities: first.productionResponsibility,
      proofAndEquivalenceGates: sortUnique([first.equivalenceClass, ...first.gapClassification.filter((gap) => gap.includes('obligation') || gap.includes('equivalence'))]),
      acceptanceEvidence: ['canonical-output-validation', 'relationship-closure', `${first.equivalenceClass}-equivalence`],
      hardDependencies: [],
      softDependencies: [],
      safeParallelism: `family-${first.artifactFamily}`,
      size: rows.length > 500 ? 'programme' : rows.length > 100 ? 'large' : rows.length > 20 ? 'medium' : rows.length > 5 ? 'small' : 'trivial',
      confidence: {
        level: rows.some((row) => row.confidence.level === 'medium') ? 'medium' : 'high',
        score: Math.min(...rows.map((row) => row.confidence.score)),
        reasons: sortUnique(rows.flatMap((row) => row.confidence.reasons))
      },
      riskDrivers: sortUnique(rows.flatMap((row) => row.riskDrivers)),
      artifactFamily: first.artifactFamily,
      rank: familyRank[first.artifactFamily]
    };
  });
  for (const layer of layerCoverage) {
    const sig = canonicalJson({ semanticLayer: layer.semanticLayer, coverageStatus: layer.coverageStatus, gapClassification: layer.gapClassification }).trimEnd();
    packages.push({
      key: workPackageKey(sig),
      canonicalOutcome: `semantic-layer:${layer.semanticLayer}:${layer.coverageStatus}`,
      affectedRows: [layer.coverageKey],
      affectedRelationships: [],
      affectedRelationshipCount: 0,
      semanticAndSupportGaps: layer.gapClassification,
      requiredSemanticLayers: layer.requiredSemanticLayers,
      currentImplementationReuse: 'none',
      canonicalOutputs: ['derive'],
      productionResponsibilities: ['semantic-authoring'],
      proofAndEquivalenceGates: sortUnique(['normalised', ...layer.gapClassification.filter((gap) => gap.includes('obligation') || gap.includes('equivalence'))]),
      acceptanceEvidence: ['semantic-layer-validation', 'relationship-closure', 'normalised-equivalence'],
      hardDependencies: [],
      softDependencies: [],
      safeParallelism: `semantic-layer-${layer.semanticLayer}`,
      size: layer.uncoveredKeyCount > 500 ? 'programme' : layer.uncoveredKeyCount > 100 ? 'large' : layer.uncoveredKeyCount > 20 ? 'medium' : layer.uncoveredKeyCount > 5 ? 'small' : 'trivial',
      confidence: layer.confidence,
      riskDrivers: ['semantic-ambiguity'],
      artifactFamily: 'machine-semantics',
      rank: familyRank['machine-semantics']
    });
  }
  packages.sort(compareBy(['rank', 'key']));

  const dependencies = [];
  for (const item of packages) {
    item.hardDependencies = packages
      .filter((candidate) => prerequisiteFamilies[item.artifactFamily].includes(candidate.artifactFamily))
      .map((candidate) => candidate.key)
      .sort();
    for (const dependsOn of item.hardDependencies) dependencies.push({ dependencyType: 'hard', dependsOn, workPackage: item.key });
    delete item.rank;
  }
  dependencies.sort(compareBy(['workPackage', 'dependsOn']));
  const artifactOwners = new Map();
  for (const item of packages) for (const artifactKey of item.affectedRows) {
    if (artifactOwners.has(artifactKey)) throw new Error(`duplicate work-package owner: ${artifactKey}`);
    artifactOwners.set(artifactKey, item.key);
  }
  if (artifactOwners.size !== records.length + layerCoverage.length) throw new Error('work-package coverage is incomplete');
  return {
    packages,
    dependencies,
    summary: {
      workPackageCount: packages.length,
      dependencyCount: dependencies.length,
      artifactOwnerCount: records.length,
      semanticLayerOwnerCount: layerCoverage.length,
      gapWithoutOwnerCount: 0,
      outputWithoutOwnerCount: 0,
      equivalenceGateWithoutOwnerCount: 0,
      sequentialGates: [...new Set(packages.map((item) => familyRank[item.artifactFamily]))].sort((a, b) => a - b).length,
      parallelWorkstreams: new Set(packages.map((item) => item.safeParallelism)).size,
      closureStatus: 'complete'
    }
  };
}

export function writePlanningOutputs(result) {
  writeJsonAtomic(path.join(censusRoot, 'workpackages.json'), { workPackages: result.packages });
  writeJsonAtomic(path.join(censusRoot, 'dependencies.json'), { dependencies: result.dependencies });
}
