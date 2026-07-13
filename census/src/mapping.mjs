import path from 'node:path';
import { compareBy, sha256, sortUnique } from './canonical.mjs';
import { assertUnique, validateMapping } from './contract.mjs';

const familyLayers = {
  automation: ['constraints-permissions', 'interfaces-events-workflows', 'generation-renderer-contracts', 'equivalence-rules'],
  'documentation-assets': ['requirements-projections', 'artifact-output-plans', 'generation-renderer-contracts'],
  implementation: ['contracts', 'implementation-obligations', 'artifact-output-plans', 'generation-renderer-contracts', 'equivalence-rules'],
  'machine-semantics': ['ontology', 'vocabulary', 'taxonomy', 'contracts', 'derivation-integrity', 'artifact-output-plans'],
  'proof-evidence': ['proof-obligations', 'evidence-requirements', 'collector-normaliser-ingestion-contracts', 'readiness-consequences'],
  'repository-governance': ['policy', 'constraints-permissions', 'artifact-output-plans'],
  'runtime-topology': ['data-configuration-lifecycle', 'provider-service-realisation', 'materialisation-contracts', 'equivalence-rules'],
  'v2-support': ['materialisation-contracts', 'self-hosting-clean-room-support', 'equivalence-rules'],
  verification: ['validation-tests-fixtures-defects', 'proof-obligations', 'generation-renderer-contracts']
};
const layerResourceKinds = Object.freeze({
  'artifact-output-plans': 'ArtefactPlan',
  'collector-normaliser-ingestion-contracts': 'EvidenceIngestionContract',
  'constraints-permissions': 'Constraint',
  contracts: 'SemanticContract',
  'data-configuration-lifecycle': 'ConfigurationContract',
  'derivation-integrity': 'DerivationIntegrityPolicy',
  'equivalence-rules': 'EquivalenceRule',
  'evidence-requirements': 'EvidenceRequirement',
  'generation-renderer-contracts': 'GeneratorContract',
  'implementation-obligations': 'ImplementationObligation',
  'interfaces-events-workflows': 'InterfaceContract',
  'materialisation-contracts': 'MaterialisationContract',
  ontology: 'OntologyDefinition',
  policy: 'Policy',
  'proof-obligations': 'ProofObligation',
  'provider-service-realisation': 'ProviderRealisation',
  'readiness-consequences': 'ReadinessRule',
  'requirements-projections': 'RequirementProjection',
  'self-hosting-clean-room-support': 'CleanRoomGenerationContract',
  taxonomy: 'TaxonomyAssignment',
  'validation-tests-fixtures-defects': 'TestObligation',
  vocabulary: 'ControlledValue'
});

function localName(identifier) {
  const value = String(identifier);
  return value.slice(Math.max(value.lastIndexOf('#'), value.lastIndexOf('/'), value.lastIndexOf(':')) + 1).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function graphResources(parserResults) {
  const resourceKinds = new Set(['owl-class', 'owl-datatype-property', 'owl-object-property', 'shacl-node-shape', 'semantic-graph']);
  const resources = new Map();
  for (const parsed of parserResults.filter((entry) => entry.universe === 'v2-graph-authority')) {
    for (const declaration of parsed.declarations) {
      let kind = declaration.kind;
      let identifier = declaration.identifier;
      let attributes = declaration.attributes ?? {};
      if (declaration.kind === 'semantic-triple' && declaration.attributes?.predicate === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type' && !declaration.attributes.subject.startsWith('_:') && !/\/owl#|\/rdf-schema#|\/shacl#/.test(declaration.attributes.object)) {
        identifier = declaration.attributes.subject;
        kind = `rdf-instance:${localName(declaration.attributes.object)}`;
        attributes = { graph: declaration.attributes.graph, rdfType: declaration.attributes.object };
      } else if (!resourceKinds.has(declaration.kind)) continue;
      if (!identifier || identifier.startsWith('_:')) continue;
      const existing = resources.get(identifier);
      if (!existing || resourceKinds.has(kind)) resources.set(identifier, { identifier, localName: localName(identifier), kind, source: parsed.path, attributes });
    }
  }
  return [...resources.values()].sort((a, b) => a.identifier.localeCompare(b.identifier));
}

function explicitCandidates(artifact, parsed, relations, resources) {
  const byIdentifier = new Map(resources.map((resource) => [resource.identifier, resource]));
  const candidates = new Map();
  const evidence = [];
  const add = (resource, kind, source, strength) => {
    if (!resource) return;
    candidates.set(resource.identifier, resource);
    evidence.push({ kind, source, resource: resource.identifier, strength });
  };
  for (const relation of relations.filter((entry) => entry.targetKind === 'semantic-entity')) {
    const exact = byIdentifier.get(relation.target);
    if (exact) add(exact, 'explicit-semantic-identifier', `relationship:${relation.extractionMethod}`, 1);
  }
  for (const declaration of parsed.declarations) {
    const exact = byIdentifier.get(declaration.identifier);
    if (exact) add(exact, artifact.universe === 'v2-graph-authority' ? 'manifest-registration' : 'explicit-semantic-identifier', `declaration:${declaration.kind}`, 1);
  }
  if (artifact.universe === 'v2-graph-authority') {
    for (const resource of resources.filter((entry) => entry.source === artifact.path)) add(resource, 'manifest-registration', 'graph-source-membership', 1);
  }
  return { candidates: [...candidates.values()], evidence };
}

function nonRequired(artifact) {
  return artifact.authorityStatus === 'transient' || artifact.path.endsWith('.gitkeep') ||
    (artifact.artifactFamily === 'proof-evidence' && /(?:^|\/)(?:artifacts|\.claude\/runs)\//.test(artifact.path));
}

function coverageFor(artifact, parsed, candidates, evidence) {
  if (nonRequired(artifact)) return { state: 'notrequired', reason: 'Closed removal, exclusion, or transient-state disposition requires no semantic identity.', represented: [], missing: [], score: 0.98 };
  if (candidates.length === 0) return { state: 'absent', reason: 'No exact semantic resource or accepted graph-owned source disposition was observed; applicability remains review-required.', represented: [], missing: [], score: 0.2 };
  const materialEvidence = evidence.some((entry) => entry.strength >= 0.8) && (parsed.relationships.length > 0 || parsed.declarations.length > 1 || artifact.universe === 'v2-graph-authority');
  if (!materialEvidence) return { state: 'identityonly', reason: 'A semantic identity is proved, but structural evidence does not determine further applicable semantic layers; source disposition remains review-required.', represented: ['semantic-identity'], missing: [], score: 0.72 };
  const represented = sortUnique(['semantic-identity', ...candidates.map((resource) => `resource-kind:${resource.kind}`)]);
  return { state: 'partial', reason: 'An exact semantic identifier exists; no additional per-file obligation is inferred without an explicit graph contract or exact structural evidence.', represented, missing: [], score: 0.7 };
}

function mappingTypeFor(artifact, candidates, coverage) {
  if (coverage.state === 'notrequired') return 'not-required';
  if (coverage.state === 'absent') return 'unmapped';
  if (artifact.universe === 'v2-graph-authority') return candidates.length === 1 ? 'exact-semantic-identity' : 'semantic-resource-component';
  if (artifact.artifactFamily === 'implementation') return 'contract-or-obligation-implementation';
  if (artifact.artifactFamily === 'verification' || artifact.artifactFamily === 'proof-evidence') return 'requirement-fixture-or-proof';
  if (artifact.artifactFamily === 'v2-support' || artifact.artifactFamily === 'runtime-topology') return 'support-contract-materialisation';
  return candidates.length > 1 ? 'one-artifact-many-resources' : 'semantic-resource-projection';
}

export function buildMappings(artifacts, parserResults, relationships) {
  const parsedByPath = new Map(parserResults.map((record) => [record.path, record]));
  const relationsByPath = new Map();
  for (const relation of relationships) {
    if (!relationsByPath.has(relation.source)) relationsByPath.set(relation.source, []);
    relationsByPath.get(relation.source).push(relation);
  }
  const resources = graphResources(parserResults);
  const preliminary = [];
  for (const artifact of artifacts) {
    const parsed = parsedByPath.get(artifact.path);
    const discovered = explicitCandidates(artifact, parsed, relationsByPath.get(artifact.path) ?? [], resources);
    const provedIdentifiers = new Set(discovered.evidence.filter((entry) => entry.strength === 1).map((entry) => entry.resource));
    const candidates = discovered.candidates.filter((candidate) => provedIdentifiers.has(candidate.identifier));
    const evidence = discovered.evidence.filter((entry) => provedIdentifiers.has(entry.resource));
    const coverage = coverageFor(artifact, parsed, candidates, evidence);
    preliminary.push({ artifact, parsed, candidates, evidence, coverage });
  }
  const resourceUse = new Map();
  for (const entry of preliminary) for (const resource of entry.candidates) resourceUse.set(resource.identifier, (resourceUse.get(resource.identifier) ?? 0) + 1);
  const mappings = preliminary.map(({ artifact, candidates, evidence, coverage }) => {
    const mappingType = mappingTypeFor(artifact, candidates, coverage);
    const sharedResource = candidates.some((resource) => resourceUse.get(resource.identifier) > 1);
    const mappingCardinality = coverage.state === 'notrequired' ? 'one-to-zero' : candidates.length === 0 ? 'one-to-zero' : candidates.length > 1 ? 'one-to-many' : sharedResource ? 'many-to-one' : 'one-to-one';
    const mappingConfidence = {
      level: coverage.state === 'absent' ? 'low' : coverage.state === 'notrequired' || evidence.some((entry) => entry.strength === 1) ? 'high' : 'medium',
      score: coverage.state === 'absent' ? 0.2 : evidence.length ? Math.min(0.99, evidence.reduce((maximum, entry) => Math.max(maximum, entry.strength), 0)) : 0.95,
      reasons: coverage.state === 'absent' ? ['no-adequate-semantic-resource'] : coverage.state === 'notrequired' ? ['closed-no-output-disposition'] : ['explicit-semantic-identifier']
    };
    const coverageConfidence = { level: coverage.state === 'absent' ? 'low' : coverage.score >= 0.9 ? 'high' : 'medium', score: coverage.state === 'absent' ? 0.2 : coverage.score, reasons: [coverage.state === 'absent' ? 'no-adequate-semantic-resource' : coverage.state === 'notrequired' ? 'closed-no-output-disposition' : 'missing-semantic-depth'] };
    const mappingEvidence = evidence.length ? evidence.map(({ kind, source, resource, strength }) => ({ kind, source, resource, strength })) : [{
      kind: coverage.state === 'notrequired' ? 'closed-disposition' : 'exhaustive-negative-resource-search',
      source: coverage.state === 'notrequired' ? 'authority-and-lifecycle-disposition' : 'normalized-graph-resource-catalogue',
      resource: null,
      strength: coverage.state === 'notrequired' ? 0.98 : 0.2
    }];
    let record = {
      artifactKey: artifact.artifactKey,
      path: artifact.path,
      universe: artifact.universe,
      mappingType,
      mappingCardinality,
      matchedResources: candidates.map((resource) => resource.identifier).sort(),
      mappingEvidence: mappingEvidence.sort((a, b) => String(a.resource ?? '').localeCompare(String(b.resource ?? '')) || a.kind.localeCompare(b.kind)),
      representedSemantics: coverage.represented,
      missingSemantics: coverage.missing,
      representedConstraints: candidates.filter((resource) => /shape|constraint|policy|permission/i.test(`${resource.kind} ${resource.identifier}`)).map((resource) => resource.identifier),
      representedProofEvidence: candidates.filter((resource) => /proof|evidence|obligation|result/i.test(`${resource.kind} ${resource.identifier}`)).map((resource) => resource.identifier),
      representedGeneration: candidates.filter((resource) => /artifact|generator|renderer|materiali/i.test(`${resource.kind} ${resource.identifier}`)).map((resource) => resource.identifier),
      ambiguities: [],
      conflicts: [],
      mappingConfidence,
      coverageDecision: coverage.state,
      coverageReason: coverage.reason,
      coverageConfidence,
      reviewStatus: 'machine-reviewed'
    };
    validateMapping(record);
    return record;
  }).sort(compareBy(['universe', 'path']));
  assertUnique(mappings, (record) => `${record.universe}\0${record.path}`);
  return { mappings, resources };
}

export function applySourceDispositionMappings(mappings, sourceDispositionOwnership) {
  const ownershipByKey = new Map(sourceDispositionOwnership.assessments.map((record) => [record.artifactKey, record]));
  return mappings.map((record) => {
    const ownership = ownershipByKey.get(record.artifactKey);
    if (!ownership?.accepted) return record;
    const references = [...new Set(ownership.semanticReferences ?? [])].sort();
    const gapReferences = [...new Set(ownership.gapSemanticReferences ?? [])].sort();
    const output = ownership.planRequired;
    const evidence = [
      { kind: 'accepted-source-disposition', source: ownership.dispositionIri, resource: ownership.sourceIri, strength: 1 },
      ...(ownership.planIri ? [{ kind: 'graph-owned-artifact-plan', source: ownership.dispositionIri, resource: ownership.planIri, strength: 1 }] : []),
      ...references.map((resource) => ({ kind: 'exact-observed-semantic-reference', source: ownership.observationIri, resource, strength: 1 })),
    ];
    const coverageDecision = output ? 'partial' : 'notrequired';
    const mapped = {
      ...record,
      mappingType: output ? 'semantic-resource-projection' : 'not-required',
      mappingCardinality: references.length > 1 ? 'one-to-many' : references.length === 1 ? 'one-to-one' : 'one-to-zero',
      matchedResources: references,
      mappingEvidence: evidence.sort((a, b) => String(a.resource ?? '').localeCompare(String(b.resource ?? '')) || a.kind.localeCompare(b.kind)),
      representedSemantics: output
        ? ['semantic-identity', 'graph-owned-source-disposition', 'graph-owned-artifact-plan']
        : ['semantic-identity', 'graph-owned-no-output-disposition'],
      missingSemantics: gapReferences,
      representedConstraints: references.filter((resource) => /contractfacet|constraint|policy|permission/.test(resource)),
      representedProofEvidence: references.filter((resource) => /proof|evidence|obligation|equivalencerule/.test(resource)),
      representedGeneration: ownership.planIri ? [ownership.planIri] : [],
      ambiguities: [], conflicts: [],
      mappingConfidence: { level: 'high', score: 1, reasons: ['accepted-exact-source-disposition', ...(output ? ['graph-owned-artifact-plan'] : ['graph-owned-no-output-disposition'])] },
      coverageDecision,
      coverageReason: output
        ? gapReferences.length
          ? `An accepted exact source disposition and graph-owned output plan exist; ${gapReferences.length} exact contract facets remain gapped, so generation and equivalence are not complete.`
          : 'An accepted exact source disposition and graph-owned output plan exist; generated equivalence evidence is still required before complete coverage.'
        : 'An accepted exact graph-owned no-output disposition excludes this noncanonical source from generated output.',
      coverageConfidence: output
        ? { level: 'medium', score: 0.85, reasons: ['exact-source-disposition-and-plan', gapReferences.length ? 'unresolved-exact-facet-gaps' : 'equivalence-not-yet-observed'] }
        : { level: 'high', score: 1, reasons: ['accepted-exact-no-output-disposition'] },
      reviewStatus: 'machine-reviewed',
    };
    validateMapping(mapped);
    return mapped;
  }).sort(compareBy(['universe', 'path']));
}

export function rankIdentityCandidates(artifacts, mappings, relationships, baselineCandidateRows = null) {
  const relationCounts = new Map();
  for (const relation of relationships) {
    relationCounts.set(relation.source, (relationCounts.get(relation.source) ?? 0) + 1);
    if (relation.targetKind === 'artifact') relationCounts.set(relation.target, (relationCounts.get(relation.target) ?? 0) + 1);
  }
  const artifactByKey = new Map(artifacts.map((record) => [record.artifactKey, record]));
  const familyWeight = { implementation: 9, 'proof-evidence': 9, automation: 8, verification: 8, 'runtime-topology': 8, 'machine-semantics': 7, 'repository-governance': 6, 'v2-support': 8, 'documentation-assets': 4 };
  const baselineCandidates = baselineCandidateRows ? new Set(baselineCandidateRows) : null;
  return mappings.filter((mapping) => baselineCandidates ? baselineCandidates.has(`${mapping.universe}:${mapping.path}`) : mapping.coverageDecision === 'identityonly')
    .map((mapping) => {
      const artifact = artifactByKey.get(mapping.artifactKey);
      const centrality = relationCounts.get(mapping.path) ?? 0;
      const score = centrality * 3 + (familyWeight[artifact.artifactFamily] ?? 1) * 5 + mapping.missingSemantics.length * 4 + Math.round((1 - mapping.mappingConfidence.score) * 20);
      return { artifactKey: mapping.artifactKey, path: mapping.path, universe: mapping.universe, artifactFamily: artifact.artifactFamily, candidateCoverage: mapping.coverageDecision, matchedResources: mapping.matchedResources, mappingEvidence: mapping.mappingEvidence, representedSemantics: mapping.representedSemantics, missingSemantics: mapping.missingSemantics, rankingScore: score, rankingEvidence: { relationshipCentrality: centrality, familyImportance: familyWeight[artifact.artifactFamily] ?? 1, semanticDepth: mapping.missingSemantics.length, mappingUncertainty: 1 - mapping.mappingConfidence.score } };
    }).sort((a, b) => b.rankingScore - a.rankingScore || a.path.localeCompare(b.path));
}

export function buildMissingEntirely(mappings, sourceDispositionOwnership = null) {
  const dispositionByArtifact = new Map((sourceDispositionOwnership?.assessments ?? []).map((record) => [record.artifactKey, record]));
  return mappings.filter((mapping) => !['complete', 'notrequired'].includes(mapping.coverageDecision))
    .filter((mapping) => !dispositionByArtifact.get(mapping.artifactKey)?.accepted)
    .map((mapping) => ({
      missingKey: sha256(`source-disposition-review\0${mapping.artifactKey}`),
      artifactKey: mapping.artifactKey,
      path: mapping.path,
      universe: mapping.universe,
      missingKind: 'review-required-source-disposition',
      requiredSemanticLayers: [],
      requiredResourceKind: 'SourceArtefactDisposition',
      requiredClassIri: 'urn:usf:ontology:SourceArtefactDisposition',
      requiredForPath: mapping.path,
      reasonCode: 'source-disposition-review-required',
      evidence: ['exact-iri-resource-comparison', `mapping:${mapping.artifactKey}`, ...(dispositionByArtifact.get(mapping.artifactKey)?.findings ?? ['source-disposition-not-observed'])],
      requiredCanonicalOutcome: `Record and accept a graph-owned source disposition for ${path.posix.basename(mapping.path)} without inferring output or semantic-layer obligations.`,
      primaryWorkPackage: null
    })).sort(compareBy(['universe', 'path', 'requiredClassIri']));
}

export const mappingInternals = { familyLayers, graphResources, layerResourceKinds, localName };
