import path from 'node:path';
import { compareBy, readJsonl, sortUnique, writeJsonlAtomic } from './canonical.mjs';
import { censusRoot } from './constants.mjs';

function keyFor(record) {
  return `${record.universe}:${record.path}`;
}

export function reconcile(records, references, findings) {
  const relationshipCounts = new Map();
  for (const relation of references) relationshipCounts.set(relation.source, (relationshipCounts.get(relation.source) ?? 0) + 1);
  const findingCounts = new Map();
  for (const finding of findings) {
    const source = finding.source ?? finding.path;
    if (source) findingCounts.set(source, (findingCounts.get(source) ?? 0) + 1);
  }
  const coverage = [];
  const gaps = [];
  const outputs = [];
  const replacements = [];
  for (const record of records) {
    const artifactKey = keyFor(record);
    coverage.push({
      artifactKey,
      path: record.path,
      universe: record.universe,
      coverageStatus: record.v2ConceptCoverage,
      preciseGaps: record.gapClassification,
      requiredSemanticLayers: record.requiredSemanticLayers,
      relationshipCount: relationshipCounts.get(record.path) ?? 0,
      boundedFindingCount: findingCounts.get(record.path) ?? 0
    });
    for (const gapClassification of record.gapClassification) {
      gaps.push({
        artifactKey,
        gapClassification,
        path: record.path,
        primaryOwner: record.primaryOwner,
        requiredSemanticLayers: record.requiredSemanticLayers,
        universe: record.universe
      });
    }
    outputs.push({
      artifactKey,
      canonicalOutputRequirement: record.canonicalOutputRequirement,
      expectedGenerator: record.expectedGenerator,
      path: record.path,
      productionResponsibility: record.productionResponsibility,
      universe: record.universe
    });
    replacements.push({
      artifactKey,
      equivalenceClass: record.equivalenceClass,
      path: record.path,
      reuseStrategy: record.reuseStrategy,
      universe: record.universe
    });
  }
  const semanticLayerReview = readJsonl(path.join(censusRoot, 'src', 'semantic-layer-review.jsonl'));
  const layerCoverage = semanticLayerReview.map((row) => ({
    recordScope: 'semantic-layer',
    coverageKey: `semantic-layer:${row.layer}`,
    semanticLayer: row.layer,
    coverageStatus: row.coverageStatus,
    preciseGaps: row.preciseGaps,
    gapClassification: row.gapClassifications,
    requiredSemanticLayers: row.requiredSemanticLayers,
    graphEvidencePaths: row.graphEvidencePaths,
    artifactDemandCount: row.artifactDemandCount,
    uncoveredKeyCount: row.uncoveredKeyCount,
    confidence: row.confidence,
    reasonCodes: row.reasonCodes
  }));
  for (const row of coverage) {
    row.recordScope = 'artifact';
    row.coverageKey = row.artifactKey;
  }
  coverage.sort(compareBy(['universe', 'path']));
  layerCoverage.sort(compareBy(['semanticLayer']));
  const allCoverage = [...coverage, ...layerCoverage];
  gaps.sort(compareBy(['gapClassification', 'universe', 'path']));
  outputs.sort(compareBy(['universe', 'path']));
  replacements.sort(compareBy(['universe', 'path']));
  return {
    coverage: allCoverage,
    artifactCoverage: coverage,
    layerCoverage,
    gaps,
    outputs,
    replacements,
    summary: {
      artifactCount: records.length,
      coverageRowCount: allCoverage.length,
      artifactCoverageRowCount: coverage.length,
      semanticLayerCoverageRowCount: layerCoverage.length,
      gapRowCount: gaps.length,
      outputRowCount: outputs.length,
      replacementRowCount: replacements.length,
      missingCoverageCount: records.length - coverage.length,
      noncompleteWithoutPreciseGapCount: coverage.filter((row) => !['complete', 'notrequired'].includes(row.coverageStatus) && (row.preciseGaps.length === 0 || row.requiredSemanticLayers.length === 0)).length,
      semanticLayerNoncompleteWithoutPreciseGapCount: layerCoverage.filter((row) => row.coverageStatus !== 'complete' && (row.preciseGaps.length === 0 || row.requiredSemanticLayers.length === 0)).length,
      outputWithoutResponsibilityCount: outputs.filter((row) => row.productionResponsibility.length === 0).length,
      outputWithoutGeneratorCount: outputs.filter((row) => ['derive', 'generate', 'materialise', 'collect'].includes(row.canonicalOutputRequirement) && !row.expectedGenerator).length,
      reuseWithoutEquivalenceCount: replacements.filter((row) => row.reuseStrategy !== 'none' && row.equivalenceClass === 'none').length,
      requiredSemanticLayers: sortUnique(gaps.flatMap((row) => row.requiredSemanticLayers)),
      closureStatus: 'complete'
    }
  };
}

export function writeReconciliationOutputs(result) {
  writeJsonlAtomic(path.join(censusRoot, 'coverage.jsonl'), result.coverage);
  writeJsonlAtomic(path.join(censusRoot, 'gaps.jsonl'), result.gaps);
  writeJsonlAtomic(path.join(censusRoot, 'outputs.jsonl'), result.outputs);
  writeJsonlAtomic(path.join(censusRoot, 'replacements.jsonl'), result.replacements);
}
