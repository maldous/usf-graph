import fs from 'node:fs';
import path from 'node:path';
import { buildArtifactPlan } from './artifact-plan.mjs';
import { compareBy, sortUnique, writeJsonAtomic, writeJsonlAtomic } from './canonical.mjs';
import { censusRoot } from './constants.mjs';
import { buildDependencyGraph } from './dependency-graph.mjs';
import { classifyArtifacts, familyReviewCandidates } from './family.mjs';
import { applySourceDispositionMappings, buildMappings, buildMissingEntirely, rankIdentityCandidates } from './mapping.mjs';
import { discoverMaterialisationContracts } from './materialisation.mjs';
import { writeParserEvidence } from './parser-evidence.mjs';
import { parseMembers } from './parsers/registry.mjs';
import { sourceSemanticParsers } from './parsers/source-semantic.mjs';
import { structuredParsers } from './parsers/structured.mjs';
import { buildRelationships, reconcileInventories } from './relationships.mjs';
import { enumerateObservationCarrierMembers, enumerateUniverses, universeSummary } from './universe.mjs';
import { buildWorkPackages } from './work-packages.mjs';

const universeFiles = {
  'repository-output': 'repository-universe.jsonl',
  'v2-graph-authority': 'v2-graph-universe.jsonl',
  'v2-compiler-implementation': 'v2-compiler-universe.jsonl',
  'v2-support-provisioning': 'v2-support-universe.jsonl'
};

const retiredOutputs = [
  'architectural-review.json',
  'census.jsonl', 'classification-summary.json', 'dependencies.json', 'gaps.jsonl',
  'outputs.jsonl', 'reference-findings.jsonl', 'reference-summary.json',
  'references.jsonl', 'replacements.jsonl'
];

function distribution(records, selector) {
  const values = records.flatMap((record) => selector(record)).filter((value) => value !== null && value !== undefined);
  return Object.fromEntries(sortUnique(values).map((value) => [value, values.filter((candidate) => candidate === value).length]));
}

function identityReview(candidates, ownedArtifactKeys) {
  return candidates.slice(0, 100).map((candidate, index) => {
    const provedIdentity = candidate.matchedResources.length > 0 && candidate.mappingEvidence.some((evidence) => evidence.strength >= 0.8);
    const materialSemantics = candidate.representedSemantics.some((value) => value !== 'semantic-identity');
    const decision = candidate.candidateCoverage === 'identityonly' && materialSemantics ? 'reclassify-partial' : candidate.candidateCoverage;
    return {
      rank: index + 1,
      artifactKey: candidate.artifactKey,
      path: candidate.path,
      artifactFamily: candidate.artifactFamily,
      rankingScore: candidate.rankingScore,
      rankingEvidence: candidate.rankingEvidence,
      provedIdentity,
      materialSemanticsObserved: materialSemantics,
      reviewDecision: decision,
      matchedResources: candidate.matchedResources,
      workPackageOwnershipVerified: ownedArtifactKeys.has(candidate.artifactKey),
      semanticBoundaryVerified: false,
      reviewRationaleCode: 'independent-review-required',
      reviewStatus: 'machine-reviewed'
    };
  });
}

export function buildHardenedCensus() {
  const enumeration = enumerateUniverses();
  const members = Object.values(enumeration.universes).flat().sort(compareBy(['universe', 'path']));
  const materialisations = discoverMaterialisationContracts();
  const parserResults = parseMembers(members, [...structuredParsers, ...sourceSemanticParsers]);
  const carrierMembers = enumerateObservationCarrierMembers();
  const carrierPaths = new Set(carrierMembers.map((member) => member.path));
  const carrierParserResults = parseMembers(carrierMembers, [...structuredParsers, ...sourceSemanticParsers]);
  const graphEvidenceParserResults = [...parserResults, ...carrierParserResults];
  const relationshipResult = buildRelationships(members, parserResults, carrierPaths);
  const inventoryResult = reconcileInventories(members, parserResults, relationshipResult.relationships, relationshipResult.relationshipFindings, carrierPaths);
  const artifacts = classifyArtifacts(members, parserResults, relationshipResult.relationships, inventoryResult.inventories);
  const preliminaryMappingResult = buildMappings(artifacts, parserResults, relationshipResult.relationships);
  const preliminaryArtifactPlan = buildArtifactPlan(artifacts, graphEvidenceParserResults, preliminaryMappingResult.mappings, [], relationshipResult.relationships);
  const mappingResult = { ...preliminaryMappingResult, mappings: applySourceDispositionMappings(preliminaryMappingResult.mappings, preliminaryArtifactPlan.sourcePlanOwnership) };
  const identityCandidates = rankIdentityCandidates(artifacts, mappingResult.mappings, relationshipResult.relationships);
  const artifactPlan = buildArtifactPlan(artifacts, graphEvidenceParserResults, mappingResult.mappings, [], relationshipResult.relationships);
  const missingEntirely = buildMissingEntirely(mappingResult.mappings, artifactPlan.sourcePlanOwnership);
  const packageResult = buildWorkPackages({
    artifacts,
    mappings: mappingResult.mappings,
    missingEntirely,
    canonicalArtifacts: artifactPlan.canonicalArtifacts,
    replacementGroups: artifactPlan.replacementGroups
  });
  const gapOwner = new Map(packageResult.ownership.missingEntirely.map((record) => [record.ownedKey, record.primaryWorkPackage]));
  const ownedMissingEntirely = missingEntirely.map((record) => ({ ...record, primaryWorkPackage: gapOwner.get(record.missingKey) }));
  const dependencyResult = buildDependencyGraph(packageResult.workPackages, artifacts, artifactPlan.canonicalArtifacts, artifactPlan.replacementGroups, relationshipResult.relationships, packageResult.workPackageLineage);
  const identities = identityReview(identityCandidates, new Set(packageResult.ownership.artifacts.map((record) => record.ownedKey)));
  const universes = universeSummary(enumeration.universes);
  const familyReviews = familyReviewCandidates(artifacts);
  const summary = {
    ...universes,
    materialisationContractCount: materialisations.length,
    parserCount: parserResults.length,
    parserCoverageByFormat: distribution(parserResults, (record) => [record.syntaxKind]),
    structuralCoverageDistribution: distribution(parserResults, (record) => [record.structuralCoverage]),
    unsupportedFormatCount: parserResults.filter((record) => record.structuralCoverage === 'unsupported').length,
    relationshipCount: relationshipResult.relationships.length,
    unresolvedRelationshipFindingCount: relationshipResult.relationshipFindings.length,
    inventoryCount: inventoryResult.inventories.length,
    inventoryFindingCount: inventoryResult.inventoryFindings.length,
    inventoryFindingClassDistribution: distribution(inventoryResult.inventoryFindings, (record) => [record.findingClass]),
    openInventoryFindingCount: inventoryResult.inventoryFindings.filter((record) => record.resolutionStatus === 'open').length,
    artifactCount: artifacts.length,
    artifactFamilyDistribution: distribution(artifacts, (record) => [record.artifactFamily]),
    familyConfidenceDistribution: distribution(artifacts, (record) => [record.familyConfidence.level]),
    familyReviewCandidateCount: familyReviews.length,
    mappingTypeDistribution: distribution(mappingResult.mappings, (record) => [record.mappingType]),
    coverageStateDistribution: distribution(mappingResult.mappings, (record) => [record.coverageDecision]),
    coverageConfidenceDistribution: distribution(mappingResult.mappings, (record) => [record.coverageConfidence.level]),
    identityOnlyCohortSize: mappingResult.mappings.filter((record) => record.coverageDecision === 'identityonly').length,
    identityReviewCount: identities.length,
    absentCount: mappingResult.mappings.filter((record) => record.coverageDecision === 'absent').length,
    missingEntirelyCount: ownedMissingEntirely.length,
    gapDistribution: distribution(ownedMissingEntirely, (record) => [record.missingKind]),
    requiredSemanticLayerDistribution: distribution(ownedMissingEntirely, (record) => record.requiredSemanticLayers),
    canonicalArtifactCount: artifactPlan.canonicalArtifacts.length,
    graphArtefactPlanCount: artifactPlan.observedArtefactPlans.length,
    sourceDispositionAcceptedCount: artifactPlan.sourcePlanOwnership.acceptedDispositionCount,
    sourceDispositionRejectedCount: artifactPlan.sourcePlanOwnership.rejectedDispositionCount,
    sourceDispositionOutputPlanRequiredCount: artifactPlan.sourcePlanOwnership.outputDispositionCount,
    sourceDispositionAcceptedOutputPlanCount: artifactPlan.sourcePlanOwnership.acceptedOutputPlanCount,
    sourceDispositionAcceptedNoOutputCount: artifactPlan.sourcePlanOwnership.acceptedNoOutputDispositionCount,
    sourceDispositionFindingDistribution: artifactPlan.sourcePlanOwnership.findingDistribution,
    sourceObservationResourceCount: artifactPlan.sourcePlanOwnership.observationResourceCount,
    sourceDispositionResourceCount: artifactPlan.sourcePlanOwnership.dispositionResourceCount,
    sourceOrphanObservationCount: artifactPlan.sourcePlanOwnership.orphanObservationCount,
    newCanonicalArtifactCount: artifactPlan.canonicalArtifacts.filter((record) => record.currentArtifacts.length === 0).length,
    replacementCardinalityDistribution: distribution(artifactPlan.replacementGroups, (record) => [record.cardinality]),
    consolidationDistribution: distribution(artifactPlan.replacementGroups, (record) => [record.consolidationClass]),
    outputDispositionDistribution: distribution(artifactPlan.canonicalArtifacts, (record) => [record.productionContract.disposition]),
    reuseDistribution: distribution(artifactPlan.replacementGroups, (record) => record.reuseActions),
    equivalenceDistribution: distribution(artifactPlan.canonicalArtifacts, (record) => [record.equivalenceContract.primaryClass]),
    baselineWorkPackageCount: packageResult.workPackageLineage.length,
    workPackageCount: packageResult.workPackages.length,
    workPackageLineageDistribution: distribution(packageResult.workPackageLineage, (record) => [record.disposition]),
    baselineDependencyCount: dependencyResult.lineage.length,
    dependencyLineageDistribution: distribution(dependencyResult.lineage, (record) => [record.disposition]),
    ...dependencyResult.metrics,
    closureEvaluation: 'deferred-to-closure-command'
  };
  return {
    enumeration, members, materialisations, parserResults,
    relationships: relationshipResult.relationships,
    inventories: inventoryResult.inventories,
    inventoryFindings: inventoryResult.inventoryFindings,
    artifacts, mappings: mappingResult.mappings,
    coverage: mappingResult.mappings.map((record) => ({ artifactKey: record.artifactKey, universe: record.universe, path: record.path, coverageDecision: record.coverageDecision, coverageReason: record.coverageReason, coverageConfidence: record.coverageConfidence, representedSemantics: record.representedSemantics, missingSemantics: record.missingSemantics })),
    missingEntirely: ownedMissingEntirely,
    identityReview: identities,
    canonicalArtifacts: artifactPlan.canonicalArtifacts,
    replacementGroups: artifactPlan.replacementGroups,
    observedArtefactPlans: artifactPlan.observedArtefactPlans,
    sourceDispositionOwnership: artifactPlan.sourcePlanOwnership,
    workPackages: packageResult.workPackages,
    workPackageLineage: packageResult.workPackageLineage,
    ownership: packageResult.ownership,
    dependencies: dependencyResult.dependencies,
    dependencyLineage: dependencyResult.lineage,
    universes,
    summary
  };
}

export function writeHardenedCensus(result) {
  for (const filename of ['architecture.json', 'classifications.json', 'schema.json']) {
    const target = path.join(censusRoot, filename);
    writeJsonAtomic(target, JSON.parse(fs.readFileSync(target, 'utf8')));
  }
  for (const [universe, filename] of Object.entries(universeFiles)) writeJsonlAtomic(path.join(censusRoot, filename), result.enumeration.universes[universe]);
  writeJsonAtomic(path.join(censusRoot, 'universes.json'), result.universes);
  writeJsonAtomic(path.join(censusRoot, 'ignore-audit.json'), result.enumeration.ignoreAudit);
  writeJsonlAtomic(path.join(censusRoot, 'materialisations.jsonl'), result.materialisations);
  writeParserEvidence(censusRoot, result.parserResults);
  writeJsonlAtomic(path.join(censusRoot, 'relationships.jsonl'), result.relationships);
  writeJsonlAtomic(path.join(censusRoot, 'inventories.jsonl'), result.inventories);
  writeJsonlAtomic(path.join(censusRoot, 'inventory-findings.jsonl'), result.inventoryFindings);
  writeJsonlAtomic(path.join(censusRoot, 'artifacts.jsonl'), result.artifacts);
  writeJsonlAtomic(path.join(censusRoot, 'mappings.jsonl'), result.mappings);
  writeJsonlAtomic(path.join(censusRoot, 'coverage.jsonl'), result.coverage);
  writeJsonlAtomic(path.join(censusRoot, 'missing-entirely.jsonl'), result.missingEntirely);
  writeJsonlAtomic(path.join(censusRoot, 'identity-review.jsonl'), result.identityReview);
  writeJsonlAtomic(path.join(censusRoot, 'canonical-artifacts.jsonl'), result.canonicalArtifacts);
  writeJsonlAtomic(path.join(censusRoot, 'replacement-groups.jsonl'), result.replacementGroups);
  writeJsonAtomic(path.join(censusRoot, 'workpackages.json'), { ownership: result.ownership, workPackages: result.workPackages });
  writeJsonlAtomic(path.join(censusRoot, 'workpackage-lineage.jsonl'), result.workPackageLineage);
  writeJsonlAtomic(path.join(censusRoot, 'dependencies.jsonl'), result.dependencies);
  writeJsonlAtomic(path.join(censusRoot, 'dependency-lineage.jsonl'), result.dependencyLineage);
  writeJsonAtomic(path.join(censusRoot, 'summary.json'), result.summary);
  for (const filename of retiredOutputs) {
    const target = path.join(censusRoot, filename);
    if (fs.existsSync(target)) fs.unlinkSync(target);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = buildHardenedCensus();
  writeHardenedCensus(result);
  process.stdout.write(`${JSON.stringify({
    stage: 'build',
    artifactCount: result.artifacts.length,
    workPackageCount: result.workPackages.length,
    requiredPrerequisiteRelationships: result.summary.requiredPrerequisiteRelationshipCount,
    resolvedPrerequisiteRelationships: result.summary.resolvedPrerequisiteRelationshipCount,
    satisfiedPrerequisiteRelationships: result.summary.satisfiedPrerequisiteRelationshipCount,
    activeBlockers: result.summary.activeBlockingRelationshipCount,
  })}\n`);
}
