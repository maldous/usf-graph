import path from 'node:path';
import { sortUnique } from '../canonical.mjs';

export const confidence = {
  structural: { level: 'high', score: 0.98, reasons: ['structural-parser-evidence'] },
  bounded: { level: 'medium', score: 0.72, reasons: ['bounded-lexical-alternative'] },
  ambiguous: { level: 'low', score: 0.4, reasons: ['bounded-lexical-alternative', 'semantic-ambiguity'] }
};

export function declaration(kind, identifier, attributes = {}) {
  return { kind, identifier: String(identifier), attributes };
}

export function relationship(relationshipType, target, targetKind, extractionMethod, evidenceKind = 'structurally-proven', relationConfidence = confidence.structural, attributes = {}) {
  return {
    relationshipType,
    target: String(target),
    targetKind,
    extractionMethod,
    evidenceKind,
    confidence: relationConfidence,
    attributes
  };
}

export function inventory(inventoryKind, scope, declarations, relationships, completenessClaims = []) {
  return {
    inventoryKind,
    scope,
    declarations,
    relationships,
    completenessClaims,
    authorityAssessment: 'cross-check-required'
  };
}

export function result({ declarations = [], relationships = [], inventory: inventoryValue = null, structuralCoverage = 'complete', unsupportedStructures = [], confidence: resultConfidence = confidence.structural }) {
  return {
    declarations,
    relationships,
    inventory: inventoryValue,
    structuralCoverage,
    unsupportedStructures: sortUnique(unsupportedStructures),
    confidence: resultConfidence
  };
}

export function pathLike(value) {
  return typeof value === 'string' && value.length > 0 && value.length < 1024 && !value.includes('\n') &&
    (/^(?:\.\.?\/|[A-Za-z0-9_.-]+\/)/.test(value) || /\.(?:json|jsonl|ya?ml|toml|xml|csv|md|js|mjs|cjs|ts|tsx|jsx|py|sh|sql|ttl|trig|rq|sparql|graphql|gql|svg|png|css|html|lock)$/i.test(value));
}

export function normaliseTarget(source, target) {
  if (/^(?:https?:|urn:|mailto:|data:|node:)/.test(target) || target.startsWith('@')) return target;
  if (target.startsWith('/')) return `v2${target}`;
  return path.posix.normalize(path.posix.join(path.posix.dirname(source), target));
}

export function walkObject(value, visitor, keyPath = [], depth = 0) {
  if (depth > 64) throw new Error(`structured document exceeds maximum depth at ${keyPath.join('.')}`);
  visitor(value, keyPath);
  if (Array.isArray(value)) value.forEach((entry, index) => walkObject(entry, visitor, [...keyPath, String(index)], depth + 1));
  else if (value && typeof value === 'object') Object.entries(value).forEach(([key, entry]) => walkObject(entry, visitor, [...keyPath, key], depth + 1));
}
