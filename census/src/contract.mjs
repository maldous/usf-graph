import path from 'node:path';
import { canonicalJson } from './canonical.mjs';
import { classifications, forbiddenFinalTokens, mandatoryArtifactFields, assertClassification } from './constants.mjs';
import { prerequisiteDependencySatisfactionStatus, dependencyEvidenceFamilies, dependencyKeyFor, dependencyResolutionBasis } from './dependency-resolution.mjs';

const digestPattern = /^[a-f0-9]{64}$/;
const modePattern = /^[0-7]{6}$/;

export function validateRelativePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\') || value.includes('\0') || path.posix.isAbsolute(value)) throw new Error(`invalid relative path: ${String(value)}`);
  const normal = path.posix.normalize(value);
  if (normal !== value || value === '..' || value.startsWith('../') || value.includes('/../')) throw new Error(`escaping or noncanonical path: ${value}`);
}

export function validateConfidence(confidence) {
  if (!confidence || typeof confidence !== 'object') throw new Error('confidence must be an object');
  assertClassification('confidenceLevels', confidence.level, 'confidence level');
  if (typeof confidence.score !== 'number' || confidence.score < 0 || confidence.score > 1) throw new Error('confidence score out of range');
  if (!Array.isArray(confidence.reasons) || confidence.reasons.length === 0) throw new Error('confidence reasons required');
}

function requireFields(record, fields, label) {
  for (const field of fields) if (!(field in record)) throw new Error(`${label} missing ${field}`);
}

function validateControlledArray(group, values, label) {
  if (!Array.isArray(values)) throw new Error(`${label} must be an array`);
  for (const value of values) assertClassification(group, value, label);
}

export function validateUniverseMember(record) {
  requireFields(record, ['path', 'universe', 'sourceState', 'contentDigest', 'byteSize', 'fileMode', 'executable', 'binary', 'formatKind', 'canonicalSource'], 'universe member');
  validateRelativePath(record.path);
  assertClassification('universes', record.universe);
  assertClassification('sourceStates', record.sourceState);
  assertClassification('formatKinds', record.formatKind);
  if (!digestPattern.test(record.contentDigest)) throw new Error(`invalid digest for ${record.path}`);
  if (!Number.isInteger(record.byteSize) || record.byteSize < 0) throw new Error(`invalid byte size for ${record.path}`);
  if (!modePattern.test(record.fileMode)) throw new Error(`invalid file mode for ${record.path}`);
  if (typeof record.executable !== 'boolean' || typeof record.binary !== 'boolean' || record.canonicalSource !== true) throw new Error(`invalid universe flags for ${record.path}`);
}

export function validateMaterialisation(record) {
  requireFields(record, ['key', 'kind', 'sourceRoot', 'manifestPaths', 'lockPaths', 'installCommand', 'integrityPolicy', 'expectedClosureDigest', 'currentStatus', 'canonicalDigestInput', 'verification'], 'materialisation');
  assertClassification('materialisationKinds', record.kind);
  assertClassification('materialisationStatuses', record.currentStatus);
  validateRelativePath(record.sourceRoot);
  record.manifestPaths.forEach(validateRelativePath);
  record.lockPaths.forEach(validateRelativePath);
  if (!digestPattern.test(record.expectedClosureDigest)) throw new Error(`invalid materialisation digest: ${record.key}`);
  if (record.canonicalDigestInput !== false) throw new Error(`materialisation status cannot define source digest: ${record.key}`);
}

export function validateParserResult(record) {
  requireFields(record, ['path', 'universe', 'contentDigest', 'formatKind', 'syntaxKind', 'parserMode', 'parserImplementation', 'parserVersion', 'pathContext', 'cacheKey', 'structuralCoverage', 'unsupportedStructures', 'confidence', 'declarations', 'relationships', 'inventory'], 'parser result');
  validateRelativePath(record.path);
  assertClassification('universes', record.universe);
  assertClassification('formatKinds', record.formatKind);
  assertClassification('parserModes', record.parserMode);
  assertClassification('structuralCoverageStates', record.structuralCoverage);
  if (!digestPattern.test(record.contentDigest) || !digestPattern.test(record.cacheKey)) throw new Error(`invalid parser digest: ${record.path}`);
  validateConfidence(record.confidence);
  if (!Array.isArray(record.unsupportedStructures) || !Array.isArray(record.declarations) || !Array.isArray(record.relationships)) throw new Error(`invalid parser arrays: ${record.path}`);
}

export function validateRelationship(record) {
  if (typeof record.target !== 'string' || record.target.length === 0) throw new Error('relationship target required');
  requireFields(record, ['source', 'relationshipType', 'target', 'targetKind', 'extractionMethod', 'confidence', 'resolved', 'reasonCodes'], 'relationship');
  validateRelativePath(record.source);
  assertClassification('relationshipTypes', record.relationshipType);
  assertClassification('targetKinds', record.targetKind);
  if (record.evidenceKind !== undefined) assertClassification('relationshipEvidenceKinds', record.evidenceKind);
  validateConfidence(record.confidence);
  if (typeof record.target !== 'string' || record.target.length === 0 || typeof record.resolved !== 'boolean') throw new Error(`invalid relationship: ${record.source}`);
}

// Retained only for validating superseded baseline fixtures and lineage inputs.
export function validateArtifact(record) {
  for (const field of mandatoryArtifactFields) if (!(field in record)) throw new Error(`missing mandatory field ${field} for ${record.path ?? '<record>'}`);
  validateRelativePath(record.path);
  for (const [group, value] of [
    ['universes', record.universe], ['sourceStates', record.sourceState], ['formatKinds', record.formatKind],
    ['artifactFamilies', record.artifactFamily], ['authorityStatuses', record.authorityStatus],
    ['outputRequirements', record.canonicalOutputRequirement], ['equivalenceClasses', record.equivalenceClass],
    ['reuseStrategies', record.reuseStrategy], ['v2CoverageStates', record.v2ConceptCoverage],
    ['implementationSizes', record.implementationSize]
  ]) assertClassification(group, value);
  validateControlledArray('productionResponsibilities', record.productionResponsibility, 'production responsibility');
  validateControlledArray('gapClassifications', record.gapClassification, 'gap classification');
  validateControlledArray('semanticLayers', record.requiredSemanticLayers, 'semantic layer');
  validateControlledArray('riskDrivers', record.riskDrivers, 'risk driver');
  validateControlledArray('reasonCodes', record.reasonCodes, 'reason code');
  validateConfidence(record.confidence);
  if (!digestPattern.test(record.contentDigest)) throw new Error(`invalid digest for ${record.path}`);
  if (!['complete', 'notrequired'].includes(record.v2ConceptCoverage) && (record.gapClassification.length === 0 || record.requiredSemanticLayers.length === 0)) throw new Error(`noncomplete record lacks precise gaps: ${record.path}`);
  rejectFinalFallback(record);
}

// Retained only for superseded index tests; hardened inventories use richer comparison fields.
export function validateInventory(record) {
  validateRelativePath(record.path);
  assertClassification('inventoryKinds', record.inventoryKind);
  if (!Array.isArray(record.declarations) || !Array.isArray(record.relationships) || !Array.isArray(record.findings)) throw new Error(`malformed inventory record: ${record.path}`);
  validateConfidence(record.confidence);
  rejectFinalFallback(record);
}

export function validateMapping(record) {
  requireFields(record, ['artifactKey', 'path', 'universe', 'mappingType', 'mappingCardinality', 'matchedResources', 'mappingEvidence', 'representedSemantics', 'missingSemantics', 'representedConstraints', 'representedProofEvidence', 'representedGeneration', 'ambiguities', 'conflicts', 'mappingConfidence', 'coverageDecision', 'coverageReason', 'coverageConfidence', 'reviewStatus'], 'mapping');
  validateRelativePath(record.path);
  assertClassification('universes', record.universe);
  assertClassification('mappingTypes', record.mappingType);
  assertClassification('mappingCardinalities', record.mappingCardinality);
  assertClassification('v2CoverageStates', record.coverageDecision);
  assertClassification('reviewStatuses', record.reviewStatus);
  validateConfidence(record.mappingConfidence);
  validateConfidence(record.coverageConfidence);
  if (record.mappingType === 'unmapped' && record.coverageDecision !== 'absent') throw new Error(`unmapped artifact must be absent: ${record.path}`);
  if (record.coverageDecision === 'identityonly' && record.matchedResources.length === 0) throw new Error(`identity-only artifact lacks identity: ${record.path}`);
  if (record.coverageDecision === 'partial' && record.representedSemantics.length === 0) throw new Error(`partial artifact lacks represented semantics: ${record.path}`);
  if (record.coverageDecision === 'complete' && (record.representedGeneration.length === 0 || record.missingSemantics.length !== 0)) throw new Error(`unsupported complete mapping: ${record.path}`);
  rejectFinalFallback(record);
}

export function validateCanonicalArtifact(record) {
  requireFields(record, ['canonicalArtifactKey', 'semanticPurpose', 'artifactKind', 'mediaType', 'targetPath', 'pathRule', 'authorityStatus', 'mutabilityClass', 'semanticInputs', 'requiredSemanticLayers', 'ownedSemanticLayers', 'artifactDependencies', 'productionResponsibilities', 'productionContract', 'integrityPolicy', 'equivalenceContract', 'acceptanceGates', 'currentArtifacts', 'replacementGroup', 'lifecyclePolicy', 'confidence', 'reviewStatus'], 'canonical artifact');
  assertClassification('artifactKinds', record.artifactKind);
  assertClassification('authorityStatuses', record.authorityStatus);
  assertClassification('mutabilityClasses', record.mutabilityClass);
  assertClassification('reviewStatuses', record.reviewStatus);
  validateControlledArray('semanticLayers', record.requiredSemanticLayers, 'semantic layer');
  validateControlledArray('semanticLayers', record.ownedSemanticLayers, 'owned semantic layer');
  if (record.ownedSemanticLayers.some((layer) => !record.requiredSemanticLayers.includes(layer))) throw new Error(`canonical artifact owns undeclared semantic layer: ${record.canonicalArtifactKey}`);
  validateControlledArray('productionResponsibilities', record.productionResponsibilities, 'production responsibility');
  if (record.targetPath !== null) validateRelativePath(record.targetPath);
  if (record.targetPath === null && record.pathRule === null && record.mutabilityClass !== 'removed') throw new Error(`canonical artifact lacks path: ${record.canonicalArtifactKey}`);
  validateConfidence(record.confidence);
  rejectFinalFallback(record);
}

export function validateDependency(record) {
  requireFields(record, ['dependencyKey', 'source', 'prerequisite', 'dependencyType', 'status', 'reasonCode', 'semanticEvidence', 'artifactEvidence', 'repositoryRelationshipEvidence', 'proofEquivalenceEvidence', 'migrationEvidence', 'confidence', 'reviewStatus', 'resolutionStatus', 'resolutionBasis'], 'dependency');
  if (record.source === record.prerequisite) throw new Error(`self dependency: ${record.source}`);
  assertClassification('dependencyTypes', record.dependencyType);
  assertClassification('dependencyStatuses', record.status);
  assertClassification('reviewStatuses', record.reviewStatus);
  if (record.reviewStatus !== 'machine-reviewed') throw new Error(`dependency resolution is not machine reviewed: ${record.source}`);
  validateConfidence(record.confidence);
  for (const field of ['semanticEvidence', 'artifactEvidence', 'repositoryRelationshipEvidence', 'proofEquivalenceEvidence', 'migrationEvidence']) {
    if (!Array.isArray(record[field]) || record[field].some((value) => typeof value !== 'string' || value.length === 0)) throw new Error(`dependency has invalid ${field}: ${record.source}`);
    if (new Set(record[field]).size !== record[field].length) throw new Error(`dependency has duplicate ${field}: ${record.source}`);
  }
  if (dependencyEvidenceFamilies(record).length === 0) throw new Error(`dependency lacks evidence: ${record.source}`);
  if (record.dependencyKey !== dependencyKeyFor(record)) throw new Error(`dependency key mismatch: ${record.source}`);
  if (record.resolutionStatus !== 'resolved-retained') throw new Error(`dependency is not resolved-retained: ${record.source}`);
  if (canonicalJson(record.resolutionBasis) !== canonicalJson(dependencyResolutionBasis(record))) throw new Error(`dependency resolution basis mismatch: ${record.source}`);
  if (record.status === 'required-prerequisite') {
    requireFields(record, ['satisfactionStatus', 'satisfactionBasis'], 'required prerequisite');
    if (!['satisfied', 'unsatisfied'].includes(record.satisfactionStatus)) throw new Error(`required prerequisite satisfaction status invalid: ${record.source}`);
    if (record.satisfactionStatus !== prerequisiteDependencySatisfactionStatus(record.satisfactionBasis)) throw new Error(`required prerequisite satisfaction basis mismatch: ${record.source}`);
  } else if ('satisfactionStatus' in record || 'satisfactionBasis' in record) throw new Error(`coordination dependency has satisfaction state: ${record.source}`);
}

export function rejectFinalFallback(value) {
  const visit = (item) => {
    if (typeof item === 'string' && forbiddenFinalTokens.has(item.toLowerCase())) throw new Error(`forbidden final fallback: ${item}`);
    if (Array.isArray(item)) item.forEach(visit);
    else if (item && typeof item === 'object') Object.values(item).forEach(visit);
  };
  visit(value);
}

export function assertUnique(records, key) {
  const seen = new Set();
  for (const record of records) {
    const value = typeof key === 'function' ? key(record) : record[key];
    if (seen.has(value)) throw new Error(`duplicate primary record: ${value}`);
    seen.add(value);
  }
}

export function validateClassificationContract() {
  for (const [group, values] of Object.entries(classifications)) {
    if (['id', 'version'].includes(group)) continue;
    if (!Array.isArray(values) || values.length === 0 || new Set(values).size !== values.length) throw new Error(`invalid classification group: ${group}`);
    values.forEach(rejectFinalFallback);
  }
}
