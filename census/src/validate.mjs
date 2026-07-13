import fs from 'node:fs';
import path from 'node:path';
import { canonicalJson, canonicalLine, readJsonl, sha256 } from './canonical.mjs';
import { censusRoot } from './constants.mjs';
import { readParserEvidence } from './parser-evidence.mjs';
import {
  assertUnique, rejectFinalFallback, validateCanonicalArtifact, validateClassificationContract,
  validateDependency, validateMapping, validateMaterialisation, validateParserResult,
  validateRelationship, validateUniverseMember
} from './contract.mjs';
import { validateReplacementGroup } from './artifact-plan.mjs';
import { validateWorkPackageOwnership } from './work-packages.mjs';

const universeFiles = ['repository-universe.jsonl', 'v2-graph-universe.jsonl', 'v2-compiler-universe.jsonl', 'v2-support-universe.jsonl'];
const jsonlFiles = [
  ...universeFiles, 'materialisations.jsonl', 'relationships.jsonl',
  'inventories.jsonl', 'inventory-findings.jsonl', 'artifacts.jsonl', 'mappings.jsonl',
  'coverage.jsonl', 'missing-entirely.jsonl', 'identity-review.jsonl', 'canonical-artifacts.jsonl',
  'replacement-groups.jsonl', 'workpackage-lineage.jsonl', 'dependencies.jsonl', 'dependency-lineage.jsonl'
];
const jsonFiles = ['architecture.json', 'classifications.json', 'schema.json', 'universes.json', 'ignore-audit.json', 'workpackages.json', 'summary.json'];

function readCanonicalJson(filename) {
  const target = path.join(censusRoot, filename);
  const text = fs.readFileSync(target, 'utf8');
  const value = JSON.parse(text);
  if (text !== canonicalJson(value)) throw new Error(`noncanonical JSON serialization: ${filename}`);
  return value;
}

function readCanonicalJsonl(filename) {
  const target = path.join(censusRoot, filename);
  const text = fs.readFileSync(target, 'utf8');
  const values = readJsonl(target);
  if (text !== values.map(canonicalLine).join('')) throw new Error(`noncanonical JSONL serialization: ${filename}`);
  return values;
}

export async function validateHardenedOutputs() {
  validateClassificationContract();
  const parsedJson = Object.fromEntries(jsonFiles.map((filename) => [filename, readCanonicalJson(filename)]));
  const parsedJsonl = Object.fromEntries(jsonlFiles.map((filename) => [filename, readCanonicalJsonl(filename)]));
  for (const definition of ['universeMember', 'materialisation', 'parserResult', 'parserEvidenceManifest', 'relationship', 'artifact', 'mapping', 'canonicalArtifact', 'replacementGroup', 'workPackage', 'dependency', 'audit', 'closure']) {
    if (!parsedJson['schema.json'].$defs?.[definition]) throw new Error(`schema definition missing: ${definition}`);
  }
  const members = universeFiles.flatMap((filename) => parsedJsonl[filename]);
  members.forEach(validateUniverseMember);
  assertUnique(members, 'path');
  const expectedCount = Object.values(parsedJson['universes.json'].universeCounts).reduce((sum, count) => sum + count, 0);
  if (members.length !== expectedCount) throw new Error('universe count closure failed');
  const ignoreAudit = parsedJson['ignore-audit.json'];
  if (ignoreAudit.closureStatus !== 'complete' || ignoreAudit.blockedPatternCount !== 0) throw new Error('ignore audit is incomplete');

  const materialisations = parsedJsonl['materialisations.jsonl'];
  materialisations.forEach(validateMaterialisation);
  assertUnique(materialisations, 'key');
  const { manifest: parserEvidenceManifest, records: parserResults } = await readParserEvidence(censusRoot);
  parserResults.forEach(validateParserResult);
  assertUnique(parserResults, (record) => `${record.universe}\0${record.path}`);
  if (parserResults.length !== members.length || parserResults.some((record) => record.structuralCoverage === 'unsupported')) throw new Error('parser coverage is incomplete');
  if (parserResults.some((record) => record.structuralCoverage === 'partial' && record.unsupportedStructures.length === 0)) throw new Error('partial parser lacks bounded limitations');

  const relationships = parsedJsonl['relationships.jsonl'];
  relationships.forEach(validateRelationship);
  if (relationships.some((record) => !record.evidenceKind)) throw new Error('hardened relationship lacks evidence kind');
  assertUnique(relationships, (record) => [record.source, record.relationshipType, record.target, record.targetKind, record.extractionMethod].join('\0'));
  const findings = parsedJsonl['inventory-findings.jsonl'];
  assertUnique(findings, 'findingKey');
  const findingFields = ['findingCategory', 'findingClass', 'severity', 'resolutionStatus', 'ownerClass', 'requiredAction', 'classificationEvidence'];
  if (findings.some((record) => findingFields.some((field) => !(field in record) || record[field] === '' || (Array.isArray(record[field]) && record[field].length === 0)))) throw new Error('relationship or inventory finding lacks classification');
  const findingRelationships = new Set(findings.map((record) => record.relationshipKey).filter(Boolean));
  for (const relation of relationships.filter((record) => !record.resolved)) {
    const key = sha256([relation.source, relation.relationshipType, relation.target, relation.targetKind, relation.extractionMethod].join('\0'));
    if (!findingRelationships.has(key)) throw new Error(`unresolved relationship lacks bounded finding: ${relation.source}`);
  }
  const inventories = parsedJsonl['inventories.jsonl'];
  assertUnique(inventories, (record) => `${record.universe}\0${record.path}`);
  if (inventories.some((record) => !Array.isArray(record.comparisonExecuted) || record.comparisonExecuted.length === 0)) throw new Error('inventory was not cross-checked');

  const artifacts = parsedJsonl['artifacts.jsonl'];
  assertUnique(artifacts, 'artifactKey');
  if (artifacts.length !== members.length) throw new Error('artifact ownership does not close the universes');
  for (const artifact of artifacts) {
    if (!artifact.artifactFamily || !artifact.authorityStatus || !artifact.ownershipEvidence.length) throw new Error(`artifact ownership incomplete: ${artifact.path}`);
    rejectFinalFallback(artifact);
  }
  const mappings = parsedJsonl['mappings.jsonl'];
  mappings.forEach(validateMapping);
  assertUnique(mappings, 'artifactKey');
  if (mappings.length !== artifacts.length || mappings.some((record) => record.mappingEvidence.length === 0)) throw new Error('mapping coverage is incomplete');
  const mappingByKey = new Map(mappings.map((record) => [record.artifactKey, record]));
  const coverage = parsedJsonl['coverage.jsonl'];
  assertUnique(coverage, 'artifactKey');
  for (const row of coverage) if (mappingByKey.get(row.artifactKey)?.coverageDecision !== row.coverageDecision) throw new Error(`coverage is not derived from mapping: ${row.artifactKey}`);
  const identityReview = parsedJsonl['identity-review.jsonl'];
  if (identityReview.length > 100 || identityReview.some((record) => record.reviewStatus !== 'machine-reviewed' || record.semanticBoundaryVerified || (record.provedIdentity && !record.matchedResources.length) || !record.workPackageOwnershipVerified)) throw new Error('identity candidates overclaim review or lack ownership');

  const canonicalArtifacts = parsedJsonl['canonical-artifacts.jsonl'];
  canonicalArtifacts.forEach(validateCanonicalArtifact);
  assertUnique(canonicalArtifacts, 'canonicalArtifactKey');
  assertUnique(canonicalArtifacts.filter((record) => record.targetPath !== null), 'targetPath');
  const requiredCanonicalLayers = new Set(canonicalArtifacts.flatMap((record) => record.requiredSemanticLayers));
  const semanticLayerArtifactOwners = new Map();
  for (const artifact of canonicalArtifacts) for (const layer of artifact.ownedSemanticLayers) {
    if (semanticLayerArtifactOwners.has(layer)) throw new Error(`semantic layer has multiple canonical artifact owners: ${layer}`);
    semanticLayerArtifactOwners.set(layer, artifact.canonicalArtifactKey);
  }
  const missingCanonicalLayerOwners = [...requiredCanonicalLayers].filter((layer) => !semanticLayerArtifactOwners.has(layer));
  if (missingCanonicalLayerOwners.length) throw new Error(`semantic layer lacks canonical artifact owner: ${missingCanonicalLayerOwners.sort().join(',')}`);
  const replacementGroups = parsedJsonl['replacement-groups.jsonl'];
  const currentKeys = new Set(artifacts.map((record) => record.artifactKey));
  const canonicalKeys = new Set(canonicalArtifacts.map((record) => record.canonicalArtifactKey));
  replacementGroups.forEach((record) => validateReplacementGroup(record, currentKeys, canonicalKeys));
  assertUnique(replacementGroups, 'groupKey');
  const currentOwners = replacementGroups.flatMap((record) => record.currentArtifacts);
  const canonicalOwners = replacementGroups.flatMap((record) => record.canonicalArtifacts);
  if (currentOwners.length !== currentKeys.size || new Set(currentOwners).size !== currentKeys.size) throw new Error('current replacement ownership incomplete');
  if (canonicalOwners.length !== canonicalKeys.size || new Set(canonicalOwners).size !== canonicalKeys.size) throw new Error('canonical replacement ownership incomplete');

  const work = parsedJson['workpackages.json'];
  validateWorkPackageOwnership(work.workPackages, work.ownership);
  const canonicalPackageOwners = new Map(work.ownership.canonicalArtifacts.map((record) => [record.ownedKey, record.primaryWorkPackage]));
  const semanticLayerPackageOwners = new Map(work.ownership.semanticLayers.map((record) => [record.ownedKey, record.primaryWorkPackage]));
  for (const [layer, canonicalArtifactKey] of semanticLayerArtifactOwners) {
    if (semanticLayerPackageOwners.get(layer) !== canonicalPackageOwners.get(canonicalArtifactKey)) throw new Error(`semantic layer owner is not canonical artifact primary owner: ${layer}`);
  }
  if (semanticLayerPackageOwners.size !== semanticLayerArtifactOwners.size) throw new Error('semantic layer package ownership is not closed');
  const packageKeys = new Set(work.workPackages.map((record) => record.key));
  const missingEntirely = parsedJsonl['missing-entirely.jsonl'];
  const validReviewRequiredDisposition = (record) => record.missingKind === 'review-required-source-disposition' &&
    record.requiredClassIri === 'urn:usf:ontology:SourceArtefactDisposition' &&
    record.reasonCode === 'source-disposition-review-required';
  if (missingEntirely.some((record) => !packageKeys.has(record.primaryWorkPackage) || (record.requiredSemanticLayers.length === 0 && !validReviewRequiredDisposition(record)))) throw new Error('missing-entirely ownership incomplete');
  const lineage = parsedJsonl['workpackage-lineage.jsonl'];
  if (lineage.length === 0 || new Set(lineage.map((record) => record.baselinePackageKey)).size !== lineage.length) throw new Error('baseline package lineage incomplete');
  const dependencies = parsedJsonl['dependencies.jsonl'];
  dependencies.forEach(validateDependency);
  assertUnique(dependencies, 'dependencyKey');
  if (dependencies.some((record) => !packageKeys.has(record.source) || !packageKeys.has(record.prerequisite))) throw new Error('dependency endpoint missing');
  const requiredPrerequisites = dependencies.filter((record) => record.status === 'required-prerequisite');
  const dependencyCounts = {
    requiredPrerequisiteRelationshipCount: requiredPrerequisites.length,
    resolvedPrerequisiteRelationshipCount: requiredPrerequisites.filter((record) => record.resolutionStatus === 'resolved-retained').length,
    satisfiedPrerequisiteRelationshipCount: requiredPrerequisites.filter((record) => record.satisfactionStatus === 'satisfied').length,
    blockingRelationshipCount: 0,
    activeBlockingRelationshipCount: requiredPrerequisites.filter((record) => record.satisfactionStatus !== 'satisfied').length,
  };
  for (const [field, count] of Object.entries(dependencyCounts)) if (parsedJson['summary.json'][field] !== count) throw new Error(`dependency summary count mismatch: ${field}`);
  if (dependencyCounts.activeBlockingRelationshipCount !== 0) throw new Error('an unsatisfied required prerequisite remains active as a blocker');
  const dependencyLineage = parsedJsonl['dependency-lineage.jsonl'];
  if (new Set(dependencyLineage.map((record) => `${record.baselineSource}\0${record.baselinePrerequisite}`)).size !== dependencyLineage.length) throw new Error('baseline dependency lineage contains duplicates');
  return {
    validationStatus: 'pass', jsonFiles: jsonFiles.length, jsonlFiles: jsonlFiles.length,
    artifacts: artifacts.length, relationships: relationships.length, inventories: inventories.length,
    mappings: mappings.length, canonicalArtifacts: canonicalArtifacts.length,
    workPackages: work.workPackages.length, dependencies: dependencies.length,
    parserEvidenceShards: parserEvidenceManifest.shards.length,
    parserEvidenceCompressedBytes: parserEvidenceManifest.shards.reduce((sum, shard) => sum + shard.compressedBytes, 0),
    parserEvidenceUncompressedBytes: parserEvidenceManifest.aggregate.uncompressedBytes
  };
}

if (import.meta.url === `file://${process.argv[1]}`) process.stdout.write(`${JSON.stringify(await validateHardenedOutputs())}\n`);
