import path from 'node:path';
import { compareBy, sha256, sortUnique } from './canonical.mjs';
import { assertUnique, validateConfidence, validateRelationship } from './contract.mjs';

function extensionCandidates(value) {
  if (path.posix.extname(value)) return [value];
  return [value, `${value}.js`, `${value}.mjs`, `${value}.cjs`, `${value}.ts`, `${value}.tsx`, `${value}.py`, `${value}.json`, `${value}.yaml`, `${value}.yml`, `${value}/index.js`, `${value}/index.mjs`, `${value}/__init__.py`, `${value}/package.json`];
}

function externalReferenceClass(value) {
  const target = String(value);
  if (/^https?:/.test(target)) return 'web-uri';
  if (/^urn:/.test(target)) return 'semantic-urn';
  if (/^mailto:/.test(target)) return 'mail-uri';
  if (/^data:/.test(target)) return 'embedded-data';
  if (/^node:/.test(target)) return 'runtime-module';
  if (target.startsWith('@')) return 'scoped-package';
  return null;
}

function directorySetFor(pathSet) {
  const directories = new Set(['.']);
  for (const memberPath of pathSet) {
    const parts = memberPath.split('/');
    for (let index = 1; index < parts.length; index += 1) directories.add(parts.slice(0, index).join('/'));
  }
  return directories;
}

function rootCandidate(value) {
  return value.startsWith('/') ? `v2${value}` : value.replace(/^\.\//, '');
}

function fixtureRelativeCandidate(source, target, attributes, pathSet) {
  if (!/^tools\/validate-spec\/manifests\//.test(source)) return null;
  if (!/^\d+\.path$/.test(String(attributes?.keyPath ?? ''))) return null;
  if (!/^(?:negative|positive)\//.test(target)) return null;
  const candidate = `tools/validate-spec/fixtures/${target}`;
  return extensionCandidates(candidate).find((value) => pathSet.has(value)) ?? null;
}

function nonInternalReferenceClass(source, target, extractionMethod, attributes, pathSet, directorySet) {
  const value = String(target);
  const keyPath = String(attributes?.keyPath ?? '');
  const external = externalReferenceClass(value);
  if (external) return `external-${external}`;
  if (/(?:^|\.)sourceRef(?:\.|$)/i.test(keyPath)) return 'source-lineage-reference';
  if (/^allowlist\.\d+\.path$/i.test(keyPath) && /^usf\//.test(value)) return 'allowlisted-lineage-reference';
  if (/(?:^|\.)source_build\.(?:context|dockerfile)$/i.test(keyPath)) return 'source-lineage-build-reference';
  if (/(?:^|\.)(?:removedInvalidOrStaleReferences|staleGuidanceAudit|removedReferences|retiredReferences)(?:\.|$)/i.test(keyPath)) return 'declared-stale-or-removed-reference';
  if (/(?:^|\.)observedArtifactSizeSnapshot(?:\.|$)/i.test(keyPath)) return 'historical-size-snapshot';
  if (/(?:^|\.)renderedEndpoints\.\d+\.path$/i.test(keyPath) && value.startsWith('/')) return 'http-route';
  if (/\$\{|\$[A-Za-z_]/.test(value)) return 'dynamic-path-expression';
  if (/[*?{}[\]]/.test(value)) return 'path-pattern';
  if (value.includes(',')) return 'path-list';
  const root = rootCandidate(value);
  if (/^(?:v2\/tmp|tmp|coverage|dist|build|reports)\//.test(root) || /(?:^|\/)\.proof-review(?:\/|$)/.test(root)) return 'generated-or-runtime-output';
  if (value === '.' || value === './' || value.endsWith('/')) return 'directory-scope';
  const relative = path.posix.normalize(path.posix.join(path.posix.dirname(source), value));
  const resolvesToFile = [...extensionCandidates(root), ...extensionCandidates(relative)].some((candidate) => pathSet.has(candidate));
  if (!resolvesToFile && (directorySet.has(root) || directorySet.has(relative))) return 'directory-scope';
  if (!resolvesToFile && /(?:^|\/)evidenceRecords\.\d+\.path$/i.test(keyPath) && /(?:^|\/)artifacts\/proof-cockpit\/machine-runs\//.test(value)) return 'historical-evidence-reference';
  if (!resolvesToFile && /(?:^|\/)(?:fixtures|planted-defects)(?:\/|$)/.test(source)) return 'fixture-payload-reference';
  if (/\s/.test(value) && extractionMethod === 'plain-text-line') return 'parser-directive';
  return null;
}

function nonInternalTargetKind(referenceClass) {
  if (!referenceClass) return null;
  if (referenceClass.startsWith('external-') || [
    'source-lineage-reference',
    'allowlisted-lineage-reference',
    'source-lineage-build-reference',
    'generated-or-runtime-output',
    'historical-evidence-reference'
  ].includes(referenceClass)) return 'external-resource';
  return 'semantic-entity';
}

function resolveArtifactTarget(source, target, pathSet, attributes = {}) {
  const clean = String(target).split('#')[0].split('?')[0];
  if (!clean) return { target: String(target), resolved: true };
  if (externalReferenceClass(clean)) return { target: clean, resolved: true };
  const explicitRelative = /^\.\.?\//.test(clean);
  const root = rootCandidate(clean);
  if (!explicitRelative) {
    for (const candidate of extensionCandidates(root)) if (pathSet.has(candidate)) return { target: candidate, resolved: true };
  }
  const fixture = fixtureRelativeCandidate(source, clean, attributes, pathSet);
  if (fixture) return { target: fixture, resolved: true };
  const relative = path.posix.normalize(path.posix.join(path.posix.dirname(source), clean));
  for (const candidate of extensionCandidates(relative)) if (pathSet.has(candidate)) return { target: candidate, resolved: true };
  if (explicitRelative) for (const candidate of extensionCandidates(root)) if (pathSet.has(candidate)) return { target: candidate, resolved: true };
  return { target: clean, resolved: false };
}

function relationshipKey(record) {
  return sha256([record.source, record.relationshipType, record.target, record.targetKind, record.extractionMethod].join('\0'));
}

function classifyFinding(record, overrides = {}) {
  return {
    ...record,
    findingCategory: overrides.findingCategory ?? 'inventory-consistency',
    findingClass: overrides.findingClass ?? record.detailCode,
    severity: overrides.severity ?? 'blocking',
    resolutionStatus: 'open',
    ownerClass: overrides.ownerClass ?? 'source-artifact-owner',
    requiredAction: overrides.requiredAction ?? 'define-or-correct-declared-resource',
    classificationEvidence: overrides.classificationEvidence ?? ['structural-parser-result', 'physical-universe-comparison']
  };
}

export function buildRelationships(members, parserResults, knownGeneratedPaths = new Set()) {
  const pathSet = new Set([...members.map((member) => member.path), ...knownGeneratedPaths]);
  const directorySet = directorySetFor(pathSet);
  const relationships = [];
  const findings = [];
  for (const parsed of parserResults) {
    for (const raw of parsed.relationships) {
      const nonInternalClass = raw.targetKind === 'artifact'
        ? nonInternalReferenceClass(parsed.path, raw.target, raw.extractionMethod, raw.attributes ?? {}, pathSet, directorySet)
        : null;
      const initiallyTargetKind = nonInternalTargetKind(nonInternalClass) ?? raw.targetKind;
      const resolvedTarget = initiallyTargetKind === 'artifact' ? resolveArtifactTarget(parsed.path, raw.target, pathSet, raw.attributes ?? {}) : { target: raw.target, resolved: true };
      const generatedCarrier = initiallyTargetKind === 'artifact' && resolvedTarget.resolved && knownGeneratedPaths.has(resolvedTarget.target);
      const targetKind = generatedCarrier ? 'semantic-entity' : initiallyTargetKind;
      const record = {
        source: parsed.path,
        relationshipType: raw.relationshipType,
        target: resolvedTarget.target,
        targetKind,
        attributes: raw.attributes ?? {},
        extractionMethod: raw.extractionMethod,
        evidenceKind: raw.evidenceKind,
        confidence: raw.confidence,
        resolved: resolvedTarget.resolved,
        reasonCodes: generatedCarrier
          ? ['structural-parser-evidence', 'generated-observation-carrier']
          : nonInternalClass
          ? targetKind === 'external-resource'
            ? ['structural-parser-evidence', 'expected-external-reference', `non-internal-reference-class:${nonInternalClass}`]
            : ['structural-parser-evidence', `non-internal-reference-class:${nonInternalClass}`]
          : raw.targetKind === 'external-resource'
            ? ['structural-parser-evidence', 'parser-classified-external-resource']
            : [resolvedTarget.resolved ? 'structural-parser-evidence' : 'unresolved-target-finding']
      };
      validateRelationship(record);
      relationships.push(record);
      if (!record.resolved) findings.push(classifyFinding({
        findingKey: sha256(`missing-target\0${relationshipKey(record)}`),
        source: record.source,
        findingKind: 'missing-target',
        subject: record.target,
        detailCode: 'relationship-target-not-observed',
        relationshipKey: relationshipKey(record),
        comparisonEvidence: ['normalized-universe-path-set']
      }, { findingCategory: 'relationship-resolution', findingClass: 'unresolved-relationship-target', requiredAction: 'define-correct-or-explicitly-externalise-target' }));
    }
  }
  const unique = [...new Map(relationships.map((record) => [relationshipKey(record), record])).values()]
    .sort(compareBy(['source', 'relationshipType', 'target', 'extractionMethod']));
  return { relationships: unique, relationshipFindings: findings.sort(compareBy(['source', 'findingKind', 'subject'])) };
}

function declarationsWithIdentityScope(parsed, scope) {
  return (parsed.inventory?.declarations ?? parsed.declarations)
    .filter((entry) => entry && typeof entry === 'object' && entry.attributes?.identityScope === scope)
    .map((entry) => `${entry.kind}\0${entry.identifier}`);
}

export function reconcileInventories(members, parserResults, relationships, relationshipFindings = [], knownGeneratedPaths = new Set()) {
  const pathSet = new Set([...members.map((member) => member.path), ...knownGeneratedPaths]);
  const directorySet = directorySetFor(pathSet);
  const memberByPath = new Map(members.map((member) => [member.path, member]));
  const inventoryParsers = parserResults.filter((parsed) => parsed.inventory !== null);
  const identifierOwners = new Map();
  // Parser identifiers are document-local unless the parser contract marks an
  // identity as globally owned.  Treating ordinary JSON keys, YAML node paths,
  // or package fields as global identities manufactured tens of thousands of
  // owner collisions and local duplicates.
  for (const parsed of inventoryParsers) for (const identifier of declarationsWithIdentityScope(parsed, 'global')) {
    if (!identifierOwners.has(identifier)) identifierOwners.set(identifier, []);
    identifierOwners.get(identifier).push(parsed.path);
  }
  const inventories = [];
  const findings = [...relationshipFindings];
  for (const parsed of inventoryParsers) {
    const locallyUnique = declarationsWithIdentityScope(parsed, 'document-unique');
    const globallyOwned = declarationsWithIdentityScope(parsed, 'global');
    const rawRelations = (parsed.inventory.relationships ?? []).map((entry) => typeof entry === 'string' ? { target: entry, targetKind: 'artifact', extractionMethod: 'inventory-string', attributes: {} } : entry).filter((entry) => entry?.target);
    const rawTargets = rawRelations.map((entry) => entry.target);
    const missingDeclarations = rawRelations.filter((entry) => {
      if (entry.targetKind !== 'artifact') return false;
      if (nonInternalReferenceClass(parsed.path, entry.target, entry.extractionMethod, entry.attributes ?? {}, pathSet, directorySet)) return false;
      return !resolveArtifactTarget(parsed.path, entry.target, pathSet, entry.attributes ?? {}).resolved;
    }).map((entry) => entry.target);
    const duplicateDeclarations = locallyUnique.filter((identifier, index) => locallyUnique.indexOf(identifier) !== index);
    const crossInventoryDuplicates = globallyOwned.filter((identifier) => (identifierOwners.get(identifier) ?? []).length > 1);
    const contradictions = [];
    for (const relation of rawRelations) {
      const target = relation.target;
      if (relation.targetKind !== 'artifact' || nonInternalReferenceClass(parsed.path, target, relation.extractionMethod, relation.attributes ?? {}, pathSet, directorySet)) continue;
      const resolved = resolveArtifactTarget(parsed.path, target, pathSet, relation.attributes ?? {});
      if (resolved.resolved && memberByPath.get(resolved.target)?.sourceState === 'deleted') contradictions.push(`declares-deleted:${resolved.target}`);
    }
    const completenessClaims = parsed.inventory.completenessClaims ?? [];
    const extraDeclarations = [];
    if (completenessClaims.includes('complete-graph-manifest')) {
      const declaredPaths = new Set(rawRelations.filter((entry) => entry.targetKind === 'artifact' && !nonInternalReferenceClass(parsed.path, entry.target, entry.extractionMethod, entry.attributes ?? {}, pathSet, directorySet)).map((entry) => resolveArtifactTarget(parsed.path, entry.target, pathSet, entry.attributes ?? {})).filter((entry) => entry.resolved).map((entry) => entry.target));
      for (const member of members.filter((entry) => entry.universe === 'v2-graph-authority' && /\.(?:ttl|trig|rq|sparql)$/.test(entry.path))) {
        if (member.path !== parsed.path && !member.path.includes('/fixtures/') && !declaredPaths.has(member.path)) extraDeclarations.push(member.path);
      }
    }
    const inventoryFindings = [
      ...missingDeclarations.map((subject) => ({ findingKind: 'missing-declaration', subject, detailCode: 'declared-target-not-observed', findingClass: 'inventory-target-missing', requiredAction: 'define-correct-or-remove-declared-target' })),
      ...duplicateDeclarations.map((subject) => ({ findingKind: 'duplicate-declaration', subject, detailCode: 'duplicate-within-inventory', findingClass: 'inventory-local-duplicate', requiredAction: 'deduplicate-inventory-declaration' })),
      ...crossInventoryDuplicates.map((subject) => ({ findingKind: 'duplicate-declaration', subject, detailCode: 'declared-by-multiple-inventories', findingClass: 'inventory-owner-collision', requiredAction: 'assign-canonical-inventory-owner' })),
      ...contradictions.map((subject) => ({ findingKind: 'contradictory-declaration', subject, detailCode: 'declaration-contradicts-universe-state', findingClass: 'inventory-state-contradiction', requiredAction: 'reconcile-declaration-with-observed-state' })),
      ...extraDeclarations.map((subject) => ({ findingKind: 'extra-declaration', subject, detailCode: 'complete-scope-member-unregistered', findingClass: 'inventory-scope-omission', requiredAction: 'register-or-explicitly-exempt-scope-member' }))
    ];
    for (const finding of inventoryFindings) findings.push(classifyFinding({
      findingKey: sha256([parsed.path, finding.findingKind, finding.subject, finding.detailCode].join('\0')),
      source: parsed.path,
      findingKind: finding.findingKind,
      subject: finding.subject,
      detailCode: finding.detailCode,
      relationshipKey: null,
      comparisonEvidence: ['physical-universe', 'cross-inventory-declarations', 'normalized-relationships']
    }, { findingClass: finding.findingClass, requiredAction: finding.requiredAction }));
    const confidence = inventoryFindings.length === 0
      ? { level: 'high', score: 0.95, reasons: ['inventory-cross-check'] }
      : { level: 'medium', score: 0.7, reasons: ['inventory-cross-check', 'semantic-ambiguity'] };
    validateConfidence(confidence);
    inventories.push({
      path: parsed.path,
      universe: parsed.universe,
      inventoryKind: parsed.inventory.inventoryKind,
      scope: parsed.inventory.scope,
      declarations: parsed.inventory.declarations ?? parsed.declarations,
      relationships: parsed.inventory.relationships ?? [],
      completenessClaims,
      actualMatchCount: rawTargets.length - missingDeclarations.length,
      missingDeclarations: sortUnique(missingDeclarations),
      extraDeclarations: sortUnique(extraDeclarations),
      duplicateDeclarations: sortUnique([...duplicateDeclarations, ...crossInventoryDuplicates]),
      contradictions: sortUnique(contradictions),
      ambiguities: sortUnique(inventoryFindings.filter((entry) => entry.findingKind === 'ambiguous-target').map((entry) => entry.subject)),
      stalenessFindings: sortUnique(missingDeclarations.map((target) => `missing-target:${target}`)),
      authorityAssessment: parsed.inventory.authorityAssessment,
      scopeCompleteness: inventoryFindings.length === 0 ? 'comparison-complete' : 'comparison-has-findings',
      comparisonExecuted: ['physical-universe', 'cross-inventory-declarations', 'normalized-relationships'],
      confidence
    });
  }
  inventories.sort(compareBy(['universe', 'path']));
  assertUnique(inventories, (record) => `${record.universe}\0${record.path}`);
  const uniqueFindings = [...new Map(findings.map((finding) => [finding.findingKey, finding])).values()].sort(compareBy(['source', 'findingKind', 'subject']));
  return { inventories, inventoryFindings: uniqueFindings };
}

export const relationshipInternals = { directorySetFor, externalReferenceClass, fixtureRelativeCandidate, nonInternalReferenceClass, nonInternalTargetKind, relationshipKey, resolveArtifactTarget };
