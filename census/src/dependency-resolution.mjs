import { sha256 } from './canonical.mjs';

export const DEPENDENCY_EVIDENCE_FAMILIES = Object.freeze([
  ['artifact', 'artifactEvidence'],
  ['migration', 'migrationEvidence'],
  ['proof-equivalence', 'proofEquivalenceEvidence'],
  ['repository-relationship', 'repositoryRelationshipEvidence'],
  ['semantic', 'semanticEvidence'],
]);

export function dependencyKeyFor(record) {
  return `dependency-${sha256(`${record.source}\0${record.prerequisite}\0${record.dependencyType}`)}`;
}

export function dependencyEvidenceFamilies(record) {
  return DEPENDENCY_EVIDENCE_FAMILIES
    .filter(([, field]) => Array.isArray(record[field]) && record[field].length > 0)
    .map(([family]) => family);
}

export function dependencyEvidenceCounts(record) {
  return Object.fromEntries(DEPENDENCY_EVIDENCE_FAMILIES.map(([family, field]) => [family, Array.isArray(record[field]) ? record[field].length : 0]));
}

export function dependencyResolutionBasis(record) {
  return {
    direction: 'source-requires-prerequisite',
    endpointOwnership: 'primary-work-package',
    evidenceFamilies: dependencyEvidenceFamilies(record),
    evidenceCounts: dependencyEvidenceCounts(record),
    cycleCheck: record.status === 'required-prerequisite' ? 'required-prerequisite-dag-verified' : 'not-applicable-coordination',
    transitiveReduction: record.status === 'required-prerequisite' ? 'retained-direct-edge' : 'not-applicable-coordination',
    reviewBasis: 'machine-reviewed',
  };
}

const satisfactionCountFields = Object.freeze([
  'exactEvidenceHashCount',
  'currentRelationshipHashCount',
  'structurallyProvenRelationshipHashCount',
  'directionMatchedRelationshipHashCount',
  'currentPrerequisiteArtifactHashCount',
  'currentPrerequisiteArtifactCount',
]);

export function prerequisiteDependencySatisfactionStatus(basis) {
  if (!basis || typeof basis !== 'object' || Array.isArray(basis)) return 'unsatisfied';
  if (satisfactionCountFields.some((field) => !Number.isInteger(basis[field]) || basis[field] < 0)) return 'unsatisfied';
  const expectedKeys = [...satisfactionCountFields, 'sourceEndpointExists', 'prerequisiteEndpointExists', 'edgeSurvivedTransitiveReduction', 'requiredPrerequisiteGraphAcyclic'].sort();
  if (JSON.stringify(Object.keys(basis).sort()) !== JSON.stringify(expectedKeys)) return 'unsatisfied';
  const exact = basis.exactEvidenceHashCount;
  return exact > 0 &&
    basis.currentRelationshipHashCount === exact &&
    basis.structurallyProvenRelationshipHashCount === exact &&
    basis.directionMatchedRelationshipHashCount === exact &&
    basis.currentPrerequisiteArtifactHashCount === exact &&
    basis.currentPrerequisiteArtifactCount > 0 &&
    basis.sourceEndpointExists === true &&
    basis.prerequisiteEndpointExists === true &&
    basis.edgeSurvivedTransitiveReduction === true &&
    basis.requiredPrerequisiteGraphAcyclic === true
    ? 'satisfied'
    : 'unsatisfied';
}
