import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const censusRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const repositoryRoot = path.resolve(censusRoot, '../../..');
export const classifications = JSON.parse(fs.readFileSync(path.join(censusRoot, 'classifications.json'), 'utf8'));

export const mandatoryArtifactFields = [
  'path',
  'universe',
  'sourceState',
  'contentDigest',
  'mediaType',
  'fileMode',
  'formatKind',
  'artifactFamily',
  'authorityStatus',
  'canonicalOutputRequirement',
  'productionResponsibility',
  'expectedGenerator',
  'equivalenceClass',
  'reuseStrategy',
  'v2ConceptCoverage',
  'gapClassification',
  'requiredSemanticLayers',
  'implementationSize',
  'confidence',
  'riskDrivers',
  'reasonCodes',
  'primaryOwner'
];

export const forbiddenFinalTokens = new Set(['other', 'unknown', 'unresolved', 'fallback', 'unregistered']);

export function assertClassification(group, value, label = group) {
  const values = classifications[group];
  if (!Array.isArray(values) || !values.includes(value)) {
    throw new Error(`invalid ${label}: ${String(value)}`);
  }
}
