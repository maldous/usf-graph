import assert from 'node:assert/strict';
import test from 'node:test';
import {
  auditArtifactDispositions, auditCanonicalArtifacts, auditDependencies, auditDeterminism, auditFamilyOwnership,
  auditFindingClassifications, auditMappingsCoverage, auditMutationBoundary, auditParserRelationships, auditUniverses, auditWorkPackages,
  auditSourceDispositionOwnership,
  canonicalJson, framedDigest, sha256
} from '../audit/index.mjs';

const digest = 'a'.repeat(64);
const member = (path, universe = 'repository-output') => ({ path, universe, contentDigest: digest, sourceState: 'tracked', fileMode: '100644', binary: false, formatKind: 'structured-json' });
const artifact = { artifactKey: 'repository-output:a.json', universe: 'repository-output', path: 'a.json', artifactFamily: 'machine-semantics', ownershipEvidence: [{ reason: 'parsed semantic structure' }], familyConfidence: { level: 'high' } };
const mapping = { artifactKey: artifact.artifactKey, mappingEvidence: [{}], coverageDecision: 'partial', coverageReason: 'observed', representedGeneration: [], missingSemantics: ['x'] };
const canonical = { canonicalArtifactKey: 'artifact.a', targetPath: 'a.json', pathRule: null, mutabilityClass: 'generated', acceptanceGates: [{}], productionResponsibilities: ['generator'], replacementGroup: 'group.a', requiredSemanticLayers: [], ownedSemanticLayers: [] };
const work = { key: 'work.a', architecturalOutcome: 'Produce one canonical outcome.', canonicalArtifactKeys: ['artifact.a'], ownedSemanticLayers: [], acceptanceCriteria: ['a'], complexityEvidence: [{}], equivalenceGates: [{}], dependencies: [] };
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const auditTriple = (graph, subject, predicate, object) => ({ kind: 'semantic-triple', attributes: { graph, subject, predicate, object } });
function auditDispositionFixture({ state = 'urn:usf:dispositiondecisionstate:accepted', digestValue = digest, kind = 'urn:usf:dispositionkind:retainedasset', includePlan = false, planCount = includePlan ? 1 : 0, graph = 'urn:usf:graph:source-dispositions', decidedAgainst = 'urn:usf:observation:a', dispositionSetDigest = 'f'.repeat(64), observationSetDigest = 'f'.repeat(64) } = {}) {
  const declarations = [
    auditTriple(null, 'urn:usf:namedgraph:source-dispositions', RDF_TYPE, 'urn:usf:ontology:NamedGraph'),
    auditTriple(null, 'urn:usf:namedgraph:source-dispositions', 'urn:usf:ontology:graphIri', '"urn:usf:graph:source-dispositions"^^http://www.w3.org/2001/XMLSchema#anyURI'),
    auditTriple(null, 'urn:usf:namedgraph:source-dispositions', 'urn:usf:ontology:graphClass', 'urn:usf:graphclass:authoredgraph'),
    auditTriple(graph, 'urn:usf:source:a', RDF_TYPE, 'urn:usf:ontology:SourceArtefact'),
    auditTriple(graph, 'urn:usf:observation:a', RDF_TYPE, 'urn:usf:ontology:SourceArtefactObservation'),
    auditTriple(graph, 'urn:usf:disposition:a', RDF_TYPE, 'urn:usf:ontology:SourceArtefactDisposition'),
    auditTriple(graph, kind, RDF_TYPE, 'urn:usf:ontology:DispositionKind'),
    auditTriple(graph, 'urn:usf:observation:a', 'urn:usf:ontology:observesSourceArtefact', 'urn:usf:source:a'),
    auditTriple(graph, 'urn:usf:observation:a', 'urn:usf:ontology:observedSourcePath', '"a.json"^^http://www.w3.org/2001/XMLSchema#string'),
    auditTriple(graph, 'urn:usf:observation:a', 'urn:usf:ontology:observedContentDigest', `"${digestValue}"^^http://www.w3.org/2001/XMLSchema#string`),
    auditTriple(graph, 'urn:usf:observation:a', 'urn:usf:ontology:observedUniverse', '"repository-output"^^http://www.w3.org/2001/XMLSchema#string'),
    auditTriple(graph, 'urn:usf:observation:a', 'urn:usf:ontology:observationSetDigest', `"${observationSetDigest}"^^http://www.w3.org/2001/XMLSchema#string`),
    auditTriple(graph, 'urn:usf:source:a', 'urn:usf:ontology:hasSourceDisposition', 'urn:usf:disposition:a'),
    auditTriple(graph, 'urn:usf:disposition:a', 'urn:usf:ontology:dispositionOfSourceArtefact', 'urn:usf:source:a'),
    auditTriple(graph, 'urn:usf:disposition:a', 'urn:usf:ontology:decidedAgainstObservation', decidedAgainst),
    auditTriple(graph, 'urn:usf:disposition:a', 'urn:usf:ontology:observationSetDigest', `"${dispositionSetDigest}"^^http://www.w3.org/2001/XMLSchema#string`),
    auditTriple(graph, 'urn:usf:disposition:a', 'urn:usf:ontology:hasDispositionKind', kind),
    auditTriple(graph, 'urn:usf:disposition:a', 'urn:usf:ontology:hasDispositionDecisionState', state)
  ];
  for (let index = 0; index < planCount; index += 1) {
    const suffix = String.fromCharCode(97 + index);
    declarations.push(auditTriple(graph, `urn:usf:artefactplan:${suffix}`, RDF_TYPE, 'urn:usf:ontology:ArtefactPlan'));
    declarations.push(auditTriple(graph, 'urn:usf:disposition:a', 'urn:usf:ontology:assignedToArtefactPlan', `urn:usf:artefactplan:${suffix}`));
  }
  return [{ path: 'v2/usf/graph/source-dispositions.trig', universe: 'v2-graph-authority', declarations }];
}
const sourceArtifact = { ...artifact, contentDigest: digest };
const dispositionGroup = (status, plan = null) => ({ currentArtifacts: [artifact.artifactKey], dispositionStatus: status, requiredGraphObligation: { sourceIri: 'urn:usf:source:a', observationIri: 'urn:usf:observation:a', dispositionIri: 'urn:usf:disposition:a', assignedPlanIri: plan } });

test('universe audit recomputes partition, ordering, counts, and framed digests', () => {
  const recordsByUniverse = {
    'repository-output': [member('a.json')],
    'v2-graph-authority': [member('v2/usf/graph/a.ttl', 'v2-graph-authority')],
    'v2-compiler-implementation': [member('v2/usf/compiler/a.mjs', 'v2-compiler-implementation')],
    'v2-support-provisioning': [member('v2/setup.sh', 'v2-support-provisioning')]
  };
  const summary = { universeCounts: Object.fromEntries(Object.entries(recordsByUniverse).map(([key, value]) => [key, value.length])) };
  const names = { 'repository-output': 'repositoryUniverseDigest', 'v2-graph-authority': 'v2GraphUniverseDigest', 'v2-compiler-implementation': 'v2CompilerUniverseDigest', 'v2-support-provisioning': 'v2SupportUniverseDigest' };
  for (const [key, records] of Object.entries(recordsByUniverse)) summary[names[key]] = framedDigest(records, ['universe', 'path', 'sourceState', 'fileMode', 'contentDigest']);
  assert.equal(auditUniverses({ recordsByUniverse, summary, physicalPaths: recordsByUniverse && Object.values(recordsByUniverse).flat().map((entry) => entry.path) }).status, 'pass');
  recordsByUniverse['repository-output'][0].universe = 'v2-support-provisioning';
  assert.equal(auditUniverses({ recordsByUniverse, summary }).status, 'fail');
});

test('parser and relationship audit rejects omissions, false resolution, partial silence, and context-free commands', () => {
  const members = [member('a.json')];
  const parser = { path: 'a.json', parserImplementation: 'x', parserMode: 'structural', pathContext: 'ordinary', structuralCoverage: 'complete', unsupportedStructures: [], declarations: [{ kind: 'command', identifier: 'x', attributes: { executableContext: { kind: 'script' } } }] };
  assert.equal(auditParserRelationships(members, [parser], [], [{ path: 'a.json', declarations: [{}], comparisonExecuted: ['physical'] }]).status, 'pass');
  delete parser.declarations[0].attributes.executableContext;
  parser.structuralCoverage = 'partial';
  assert.equal(auditParserRelationships(members, [parser], [{ source: 'a.json', target: 'missing', targetKind: 'artifact', resolved: true, relationshipType: 'references', extractionMethod: 'x' }], []).status, 'fail');
});

test('family ownership is exactly one evidence-backed owner per member', () => {
  assert.equal(auditFamilyOwnership([member('a.json')], [artifact]).status, 'pass');
  assert.equal(auditFamilyOwnership([member('a.json')], [artifact, { ...artifact }]).status, 'fail');
});

test('mappings and coverage cannot claim unsupported completeness or omit artifacts', () => {
  assert.equal(auditMappingsCoverage([artifact], [mapping], [{ artifactKey: artifact.artifactKey, coverageDecision: 'partial' }]).status, 'pass');
  assert.equal(auditMappingsCoverage([artifact], [{ ...mapping, coverageDecision: 'complete', missingSemantics: ['x'] }], [{ artifactKey: artifact.artifactKey, coverageDecision: 'complete' }]).status, 'fail');
});

test('canonical artifacts and replacement groups must close production contracts', () => {
  assert.equal(auditCanonicalArtifacts([canonical], [{ key: 'group.a', canonicalArtifactKeys: ['artifact.a'] }]).status, 'pass');
  assert.equal(auditCanonicalArtifacts([{ ...canonical, targetPath: null, acceptanceGates: [] }], []).status, 'fail');
});

test('work package coherence enforces singular complete artifact ownership', () => {
  assert.equal(auditWorkPackages([canonical], [work]).status, 'pass');
  assert.equal(auditWorkPackages([canonical], [work, { ...work, key: 'work.b' }]).status, 'fail');
});

test('semantic layers require one explicit canonical artifact owner and its primary package', () => {
  const owner = { ...canonical, requiredSemanticLayers: ['policy'], ownedSemanticLayers: ['policy'] };
  const consumer = { ...canonical, canonicalArtifactKey: 'artifact.b', targetPath: 'b.json', requiredSemanticLayers: ['policy'], ownedSemanticLayers: [] };
  const groups = [{ key: 'group.a', canonicalArtifactKeys: ['artifact.a', 'artifact.b'] }];
  assert.equal(auditCanonicalArtifacts([owner, consumer], groups).status, 'pass');
  assert.equal(auditCanonicalArtifacts([{ ...owner, ownedSemanticLayers: [] }, consumer], groups).status, 'fail');
  assert.equal(auditCanonicalArtifacts([owner, { ...consumer, ownedSemanticLayers: ['policy'] }], groups).status, 'fail');
  assert.equal(auditWorkPackages([owner, consumer], [{ ...work, canonicalArtifactKeys: ['artifact.a', 'artifact.b'], ownedSemanticLayers: ['policy'] }]).status, 'pass');
  assert.equal(auditWorkPackages([owner, consumer], [{ ...work, canonicalArtifactKeys: ['artifact.a', 'artifact.b'], ownedSemanticLayers: [] }]).status, 'fail');
});

test('dependency audit catches cycles, transitive edges, missing endpoints, and missing evidence', () => {
  const packages = ['a', 'b', 'c'].map((key) => ({ key, artifactKeys: [`artifact.${key}`], canonicalArtifactKeys: [], ownedSemanticLayers: [], requiredSemanticLayers: [], equivalenceGates: [] }));
  const artifacts = ['a', 'b', 'c'].map((key) => ({ artifactKey: `artifact.${key}`, path: `${key}.json`, sourceState: 'tracked', contentDigest: key.repeat(64) }));
  const relationship = (source, prerequisite) => ({ source: `${source}.json`, target: `${prerequisite}.json`, relationshipType: 'references', resolved: true, targetKind: 'artifact', evidenceKind: 'structurally-proven' });
  const edge = (source, prerequisite) => {
    const relation = relationship(source, prerequisite);
    const record = {
      source, prerequisite, dependencyType: 'canonical-artifact-input', status: 'required-prerequisite', reasonCode: 'canonical-artifact-input', semanticEvidence: [], artifactEvidence: [],
      repositoryRelationshipEvidence: [sha256(`${relation.source}\0${relation.relationshipType}\0${relation.target}`)], proofEquivalenceEvidence: [], migrationEvidence: [], reviewStatus: 'machine-reviewed'
    };
    record.dependencyKey = `dependency-${sha256(`${source}\0${prerequisite}\0${record.dependencyType}`)}`;
    record.resolutionStatus = 'resolved-retained';
    record.resolutionBasis = { direction: 'source-requires-prerequisite', endpointOwnership: 'primary-work-package', evidenceFamilies: ['repository-relationship'], evidenceCounts: { artifact: 0, migration: 0, 'proof-equivalence': 0, 'repository-relationship': 1, semantic: 0 }, cycleCheck: 'required-prerequisite-dag-verified', transitiveReduction: 'retained-direct-edge', reviewBasis: 'machine-reviewed' };
    record.satisfactionStatus = 'satisfied';
    record.satisfactionBasis = { exactEvidenceHashCount: 1, currentRelationshipHashCount: 1, structurallyProvenRelationshipHashCount: 1, directionMatchedRelationshipHashCount: 1, currentPrerequisiteArtifactHashCount: 1, currentPrerequisiteArtifactCount: 1, sourceEndpointExists: true, prerequisiteEndpointExists: true, edgeSurvivedTransitiveReduction: true, requiredPrerequisiteGraphAcyclic: true };
    return { record, relation };
  };
  const ab = edge('a', 'b'); const bc = edge('b', 'c');
  const context = { artifacts, relationships: [ab.relation, bc.relation], canonicalArtifacts: [], replacementGroups: [], summary: { requiredPrerequisiteRelationshipCount: 2, resolvedPrerequisiteRelationshipCount: 2, satisfiedPrerequisiteRelationshipCount: 2, blockingRelationshipCount: 0, activeBlockingRelationshipCount: 0 } };
  assert.equal(auditDependencies(packages, [ab.record, bc.record], context).status, 'pass');
  const stale = structuredClone(ab.record); stale.repositoryRelationshipEvidence = ['f'.repeat(64)];
  assert.equal(auditDependencies(packages, [stale], context).status, 'fail');
  const missingResolution = structuredClone(ab.record); delete missingResolution.resolutionStatus;
  assert.equal(auditDependencies(packages, [missingResolution], context).status, 'fail');
  const forgedSatisfaction = structuredClone(ab.record); forgedSatisfaction.satisfactionBasis.currentRelationshipHashCount = 0;
  assert.equal(auditDependencies(packages, [forgedSatisfaction], { ...context, summary: null }).status, 'fail');
  const stalePrerequisite = structuredClone(artifacts); stalePrerequisite[1].sourceState = 'deleted';
  assert.equal(auditDependencies(packages, [ab.record], { ...context, artifacts: stalePrerequisite, summary: null }).status, 'fail');
  assert.equal(auditDependencies(packages, [ab.record], { ...context, summary: { requiredPrerequisiteRelationshipCount: 1, resolvedPrerequisiteRelationshipCount: 1, satisfiedPrerequisiteRelationshipCount: 0, blockingRelationshipCount: 0, activeBlockingRelationshipCount: 1 } }).status, 'fail');
  const ac = edge('a', 'c'); const ca = edge('c', 'a'); const missing = edge('a', 'missing'); missing.record.repositoryRelationshipEvidence = [];
  assert.equal(auditDependencies(packages, [ab.record, bc.record, ac.record, ca.record, missing.record], { ...context, relationships: [ab.relation, bc.relation, ac.relation, ca.relation] }).status, 'fail');
});

test('canonical serialization is key-stable and record order is independently checked', () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, x: 3 } }), '{\n  "a": {\n    "x": 3,\n    "y": 2\n  },\n  "z": 1\n}\n');
  assert.equal(auditDeterminism({ rows: [{ path: 'a' }, { path: 'b' }] }).status, 'pass');
  assert.equal(auditDeterminism({ rows: [{ path: 'b' }, { path: 'a' }] }).status, 'fail');
});

test('mutation boundary rejects any changed file outside the census root', () => {
  const before = new Map([['README.md', 'a'], ['v2/usf/census/output.json', 'a']]);
  assert.equal(auditMutationBoundary(before, new Map(before)).status, 'pass');
  assert.equal(auditMutationBoundary(before, new Map([['README.md', 'b'], ['v2/usf/census/output.json', 'b']])).status, 'fail');
});

test('artifact dispositions and finding classifications are independently fail-closed', () => {
  const source = [{ artifactKey: 'a' }];
  const unavailable = [{ currentArtifacts: ['a'], canonicalArtifacts: [], requiredGenerationProjections: [], removedDuplication: [], dispositionStatus: 'missing-accepted-source-disposition', requiredGraphObligation: { classIri: 'urn:usf:ontology:SourceArtefactDisposition' }, confidence: { level: 'low' }, reviewStatus: 'machine-reviewed' }];
  const dispositionAudit = auditArtifactDispositions(source, [], unavailable);
  assert.equal(dispositionAudit.status, 'fail');
  assert.equal(dispositionAudit.facts.missingDispositionCount, 1);
  const classified = [{ findingKey: 'f', source: 'a', findingCategory: 'relationship-resolution', findingClass: 'unresolved-target', severity: 'blocking', resolutionStatus: 'closed', ownerClass: 'source-artifact-owner', requiredAction: 'define-target', classificationEvidence: ['physical-universe'] }];
  assert.equal(auditFindingClassifications(classified).status, 'pass');
  classified[0].resolutionStatus = 'open';
  assert.equal(auditFindingClassifications(classified).status, 'fail');
  classified[0].resolutionStatus = 'closed';
  delete classified[0].ownerClass;
  assert.equal(auditFindingClassifications(classified).status, 'fail');
});

test('independent relationship identity preserves distinct target semantics', () => {
  const members = [
    { path: 'a.json', universe: 'repository-output', contentDigest: digest, sourceState: 'tracked', fileMode: '100644', binary: false, formatKind: 'structured-json' },
    { path: 'retired.json', universe: 'repository-output', contentDigest: digest, sourceState: 'tracked', fileMode: '100644', binary: true, formatKind: 'opaque-binary' }
  ];
  const parser = { path: 'a.json', parserImplementation: 'fixture', parserMode: 'structural', pathContext: 'fixture', structuralCoverage: 'complete', declarations: [] };
  const base = { source: 'a.json', target: 'retired.json', resolved: true, relationshipType: 'references', extractionMethod: 'json-pointer', reasonCodes: ['structural-parser-evidence'] };
  const relationships = [
    { ...base, targetKind: 'artifact' },
    { ...base, targetKind: 'semantic-entity' }
  ];
  assert.equal(auditParserRelationships(members, [parser], relationships, []).status, 'pass');
});

test('independent source disposition audit accepts no-output and planned output, and rejects all fail-closed cases', () => {
  assert.equal(auditSourceDispositionOwnership([sourceArtifact], auditDispositionFixture(), [dispositionGroup('graph-owned-no-output-disposition')]).status, 'pass');
  assert.equal(auditSourceDispositionOwnership([sourceArtifact], auditDispositionFixture({ kind: 'urn:usf:dispositionkind:generateequivalent', includePlan: true }), [dispositionGroup('graph-owned-output-plan', 'urn:usf:artefactplan:a')]).status, 'pass');
  for (const fixture of [
    auditDispositionFixture({ state: 'urn:usf:dispositiondecisionstate:review-required' }),
    auditDispositionFixture({ state: 'urn:usf:dispositiondecisionstate:rejected' }),
    auditDispositionFixture({ digestValue: 'b'.repeat(64) }),
    auditDispositionFixture({ kind: 'urn:usf:dispositionkind:generateequivalent' }),
    auditDispositionFixture({ kind: 'urn:usf:dispositionkind:generateequivalent', planCount: 2 }),
    auditDispositionFixture({ graph: 'urn:usf:graph:not-registered' }),
    auditDispositionFixture({ decidedAgainst: 'urn:usf:observation:stale' }),
    auditDispositionFixture({ dispositionSetDigest: 'e'.repeat(64) })
  ]) assert.equal(auditSourceDispositionOwnership([sourceArtifact], fixture, [dispositionGroup('missing-accepted-source-disposition')]).status, 'fail');
});

test('missing architectural inputs are incomplete rather than hard-coded success', () => {
  for (const value of [
    auditParserRelationships([], null, null), auditFamilyOwnership([], null), auditMappingsCoverage([], null, null),
    auditCanonicalArtifacts(null, null), auditArtifactDispositions(null, null, null), auditSourceDispositionOwnership(null, null, null), auditFindingClassifications(null),
    auditWorkPackages(null, null), auditDependencies(null, null), auditDeterminism(null), auditMutationBoundary(null, null)
  ]) assert.equal(value.status, 'incomplete');
});

test('audit implementation has no production census imports or production invocation', () => {
  const source = new URL('../audit/index.mjs', import.meta.url);
  return import('node:fs').then(({ readFileSync }) => {
    const text = readFileSync(source, 'utf8');
    assert.doesNotMatch(text, /(?:from\s+|import\s*\()['"]\.\.\/src\//);
    assert.doesNotMatch(text, /execFileSync\([^,]*['"]node['"]/);
  });
});
