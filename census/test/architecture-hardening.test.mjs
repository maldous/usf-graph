import assert from 'node:assert/strict';
import test from 'node:test';
import { buildArtifactPlan, validateReplacementGroup } from '../src/artifact-plan.mjs';
import { buildDependencyGraph, dependencyGraphInternals } from '../src/dependency-graph.mjs';
import { dependencyKeyFor } from '../src/dependency-resolution.mjs';
import { applySourceDispositionMappings, buildMappings, buildMissingEntirely } from '../src/mapping.mjs';
import { buildRelationships } from '../src/relationships.mjs';
import { buildSourcePlanOwnership } from '../src/source-plan-ownership.mjs';

const confidence = { level: 'high', score: 0.98, reasons: ['structural-parser-evidence'] };
const artifact = (artifactKey, path, overrides = {}) => ({
  artifactKey, path, universe: 'repository-output', sourceState: 'tracked', contentDigest: 'a'.repeat(64),
  mediaType: 'text/plain', fileMode: '100644', formatKind: 'source-code', syntaxKind: 'javascript-typescript',
  parserImplementation: 'fixture', machineFamilyProposal: 'implementation', artifactFamily: 'implementation',
  familyScores: {}, ownershipEvidence: [{}], authorityStatus: 'implementation', formatConfidence: confidence,
  relationshipConfidence: confidence, familyConfidence: confidence, mappingConfidence: confidence,
  coverageConfidence: confidence, reviewStatus: 'machine-reviewed', reviewEvidence: [], ...overrides
});
const parsed = (path, declarations, universe = 'repository-output') => ({ path, universe, declarations, relationships: [] });
const triple = (graph, subject, predicate, object) => ({ kind: 'semantic-triple', identifier: `${subject}:${predicate}`, attributes: { graph, subject, predicate, object } });
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';

function dispositionDataset({ kind = 'urn:usf:dispositionkind:retainedasset', state = 'urn:usf:dispositiondecisionstate:accepted', digest = 'a'.repeat(64), planCount = 0, includePlan = false, registeredGraph = true, decidedAgainst = 'urn:usf:observation:a', dispositionSetDigest = 'f'.repeat(64), observationSetDigest = 'f'.repeat(64) } = {}) {
  const authorityGraph = registeredGraph ? 'urn:usf:graph:source-dispositions' : 'urn:usf:graph:not-registered';
  const declarations = [
    triple(null, 'urn:usf:namedgraph:source-dispositions', RDF_TYPE, 'urn:usf:ontology:NamedGraph'),
    triple(null, 'urn:usf:namedgraph:source-dispositions', 'urn:usf:ontology:graphIri', '"urn:usf:graph:source-dispositions"^^http://www.w3.org/2001/XMLSchema#anyURI'),
    triple(null, 'urn:usf:namedgraph:source-dispositions', 'urn:usf:ontology:graphClass', 'urn:usf:graphclass:authoredgraph'),
    triple(authorityGraph, 'urn:usf:source:a', RDF_TYPE, 'urn:usf:ontology:SourceArtefact'),
    triple(authorityGraph, 'urn:usf:observation:a', RDF_TYPE, 'urn:usf:ontology:SourceArtefactObservation'),
    triple(authorityGraph, 'urn:usf:disposition:a', RDF_TYPE, 'urn:usf:ontology:SourceArtefactDisposition'),
    triple(authorityGraph, kind, RDF_TYPE, 'urn:usf:ontology:DispositionKind'),
    triple(authorityGraph, 'urn:usf:observation:a', 'urn:usf:ontology:observesSourceArtefact', 'urn:usf:source:a'),
    triple(authorityGraph, 'urn:usf:observation:a', 'urn:usf:ontology:observedSourcePath', '"src/example.ts"^^http://www.w3.org/2001/XMLSchema#string'),
    triple(authorityGraph, 'urn:usf:observation:a', 'urn:usf:ontology:observedContentDigest', `"${digest}"^^http://www.w3.org/2001/XMLSchema#string`),
    triple(authorityGraph, 'urn:usf:observation:a', 'urn:usf:ontology:observedUniverse', '"repository-output"^^http://www.w3.org/2001/XMLSchema#string'),
    triple(authorityGraph, 'urn:usf:observation:a', 'urn:usf:ontology:observationSetDigest', `"${observationSetDigest}"^^http://www.w3.org/2001/XMLSchema#string`),
    triple(authorityGraph, 'urn:usf:source:a', 'urn:usf:ontology:hasSourceDisposition', 'urn:usf:disposition:a'),
    triple(authorityGraph, 'urn:usf:disposition:a', 'urn:usf:ontology:dispositionOfSourceArtefact', 'urn:usf:source:a'),
    triple(authorityGraph, 'urn:usf:disposition:a', 'urn:usf:ontology:decidedAgainstObservation', decidedAgainst),
    triple(authorityGraph, 'urn:usf:disposition:a', 'urn:usf:ontology:observationSetDigest', `"${dispositionSetDigest}"^^http://www.w3.org/2001/XMLSchema#string`),
    triple(authorityGraph, 'urn:usf:disposition:a', 'urn:usf:ontology:hasDispositionKind', kind),
    triple(authorityGraph, 'urn:usf:disposition:a', 'urn:usf:ontology:hasDispositionDecisionState', state)
  ];
  const count = includePlan ? Math.max(1, planCount) : planCount;
  for (let index = 0; index < count; index += 1) {
    const suffix = String.fromCharCode(97 + index);
    declarations.push(triple(authorityGraph, `urn:usf:artefactplan:${suffix}`, RDF_TYPE, 'urn:usf:ontology:ArtefactPlan'));
    declarations.push(triple(authorityGraph, 'urn:usf:disposition:a', 'urn:usf:ontology:assignedToArtefactPlan', `urn:usf:artefactplan:${suffix}`));
  }
  return [parsed('v2/usf/graph/source-dispositions.trig', declarations, 'v2-graph-authority')];
}

test('typed graph instances map only through exact semantic identifiers', () => {
  const graph = parsed('v2/usf/graph/example.trig', [
    { kind: 'semantic-triple', identifier: 'typed', attributes: { graph: 'urn:g', subject: 'urn:usf:capability:ownedthing', predicate: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type', object: 'urn:usf:ontology:Capability' } },
    { kind: 'owl-class', identifier: 'urn:usf:ontology:SameName', attributes: {} }
  ], 'v2-graph-authority');
  const source = parsed('src/example.ts', [{ kind: 'semantic-reference', identifier: 'urn:usf:capability:ownedthing', attributes: {} }, { kind: 'function', identifier: 'SameName', attributes: {} }]);
  const result = buildMappings([artifact('a', 'src/example.ts')], [graph, source], []).mappings[0];
  assert.equal(result.coverageDecision, 'partial');
  assert.deepEqual(result.matchedResources, ['urn:usf:capability:ownedthing']);
  assert.ok(!result.matchedResources.includes('urn:usf:ontology:SameName'));
});

test('accepted exact output dispositions rederive graph-grounded partial mappings without claiming equivalence', () => {
  const sourceArtifact = artifact('a', 'src/example.ts');
  const base = buildMappings([sourceArtifact], [parsed('src/example.ts', [])], []).mappings;
  const mapped = applySourceDispositionMappings(base, { assessments: [{
    artifactKey: 'a', accepted: true, planRequired: true, sourceIri: 'urn:usf:source:a', observationIri: 'urn:usf:observation:a',
    dispositionIri: 'urn:usf:disposition:a', planIri: 'urn:usf:artefactplan:a',
    semanticReferences: ['urn:usf:semanticcontract:a', 'urn:usf:contractfacet:auisemantics'],
    gapSemanticReferences: ['urn:usf:contractfacet:auisemantics']
  }] })[0];
  assert.equal(mapped.coverageDecision, 'partial');
  assert.equal(mapped.mappingType, 'semantic-resource-projection');
  assert.deepEqual(mapped.missingSemantics, ['urn:usf:contractfacet:auisemantics']);
  assert.deepEqual(mapped.representedGeneration, ['urn:usf:artefactplan:a']);
  assert.ok(mapped.mappingEvidence.some((entry) => entry.kind === 'accepted-source-disposition' && entry.strength === 1));
});

test('artifact planning remains an explicit graph obligation and invents no target or disposition', () => {
  const sourceArtifact = artifact('a', 'src/example.ts');
  const mapping = buildMappings([sourceArtifact], [parsed('src/example.ts', [])], []).mappings[0];
  const result = buildArtifactPlan([sourceArtifact], [], [mapping], [], []);
  assert.deepEqual(result.canonicalArtifacts, []);
  assert.equal(result.replacementGroups[0].dispositionStatus, 'missing-accepted-source-disposition');
  assert.equal(result.replacementGroups[0].requiredGraphObligation.classIri, 'urn:usf:ontology:SourceArtefactDisposition');
  assert.deepEqual(result.replacementGroups[0].requiredGenerationProjections, []);
});

test('artifact planning does not treat unrelated observed plans as source disposition ownership', () => {
  const sourceArtifact = artifact('a', 'src/example.ts');
  const mapping = buildMappings([sourceArtifact], [parsed('src/example.ts', [])], []).mappings[0];
  const graph = parsed('v2/usf/graph/generation.trig', [{
    kind: 'semantic-triple',
    identifier: 'urn:usf:artefactplan:example',
    attributes: {
      graph: 'urn:usf:graph:generation',
      subject: 'urn:usf:artefactplan:example',
      predicate: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
      object: 'urn:usf:ontology:ArtefactPlan'
    }
  }], 'v2-graph-authority');
  const fixture = { ...graph, path: 'v2/usf/graph/fixtures/defects/generation.trig' };
  const result = buildArtifactPlan([sourceArtifact], [graph, fixture], [mapping], [], []);
  assert.equal(result.observedArtefactPlans.length, 1);
  assert.equal(result.replacementGroups[0].dispositionStatus, 'missing-accepted-source-disposition');
  assert.equal(result.replacementGroups[0].requiredGraphObligation.observedArtefactPlanCount, 1);
  assert.equal(result.replacementGroups[0].requiredGraphObligation.reasonCode, 'source-observation-missing');
});

test('accepted no-output source disposition needs no artifact plan while output kinds do', () => {
  const sourceArtifact = artifact('a', 'src/example.ts');
  const noOutput = buildSourcePlanOwnership([sourceArtifact], dispositionDataset(), []);
  assert.equal(noOutput.acceptedDispositionCount, 1);
  assert.equal(noOutput.acceptedNoOutputDispositionCount, 1);
  assert.equal(noOutput.assessments[0].planRequired, false);
  const outputWithoutPlan = buildSourcePlanOwnership([sourceArtifact], dispositionDataset({ kind: 'urn:usf:dispositionkind:generateequivalent' }), []);
  assert.equal(outputWithoutPlan.rejectedDispositionCount, 1);
  assert.ok(outputWithoutPlan.assessments[0].findings.includes('source-disposition-plan-cardinality-invalid'));
  const outputWithPlan = buildSourcePlanOwnership([sourceArtifact], dispositionDataset({ kind: 'urn:usf:dispositionkind:generateequivalent', includePlan: true }), [{ planIri: 'urn:usf:artefactplan:a' }]);
  assert.equal(outputWithPlan.acceptedDispositionCount, 1);
  assert.equal(outputWithPlan.acceptedOutputPlanCount, 1);
  const outputWithManyPlans = buildSourcePlanOwnership(
    [sourceArtifact],
    dispositionDataset({ kind: 'urn:usf:dispositionkind:generateequivalent', planCount: 2 }),
    [{ planIri: 'urn:usf:artefactplan:a' }, { planIri: 'urn:usf:artefactplan:b' }]
  );
  assert.equal(outputWithManyPlans.acceptedDispositionCount, 0);
  assert.ok(outputWithManyPlans.assessments[0].findings.includes('source-disposition-plan-cardinality-invalid'));
  assert.deepEqual(outputWithManyPlans.assessments[0].planIris, ['urn:usf:artefactplan:a', 'urn:usf:artefactplan:b']);
  const noOutputWithPlan = buildSourcePlanOwnership([sourceArtifact], dispositionDataset({ planCount: 1 }), [{ planIri: 'urn:usf:artefactplan:a' }]);
  assert.ok(noOutputWithPlan.assessments[0].findings.includes('source-disposition-plan-cardinality-invalid'));
});

test('source disposition ownership fails closed on review, stale digest, missing plan, unregistered graph, and rejection', () => {
  const sourceArtifact = artifact('a', 'src/example.ts');
  const cases = [
    [dispositionDataset({ state: 'urn:usf:dispositiondecisionstate:reviewrequired' }), 'source-disposition-review-required', []],
    [dispositionDataset({ digest: 'b'.repeat(64) }), 'source-observation-digest-mismatch', []],
    [dispositionDataset({ kind: 'urn:usf:dispositionkind:generateequivalent', includePlan: true }), 'source-disposition-plan-missing', []],
    [dispositionDataset({ registeredGraph: false }), 'source-observation-unregistered-graph', []],
    [dispositionDataset({ state: 'urn:usf:dispositiondecisionstate:rejected' }), 'source-disposition-not-accepted', []],
    [dispositionDataset({ decidedAgainst: 'urn:usf:observation:stale' }), 'source-disposition-stale-observation', []],
    [dispositionDataset({ dispositionSetDigest: 'e'.repeat(64) }), 'source-disposition-set-digest-mismatch', []]
  ];
  for (const [dataset, reason, plans] of cases) {
    const result = buildSourcePlanOwnership([sourceArtifact], dataset, plans);
    assert.equal(result.rejectedDispositionCount, 1, reason);
    assert.ok(result.assessments[0].findings.includes(reason), reason);
  }
});

test('workflow mapping does not invent every family semantic layer', () => {
  const workflow = artifact('workflow', '.github/workflows/validate.yml', { artifactFamily: 'automation', formatKind: 'structured-yaml' });
  const mapping = buildMappings([workflow], [parsed(workflow.path, [])], []).mappings[0];
  assert.deepEqual(mapping.missingSemantics, []);
  const missing = buildMissingEntirely([mapping]);
  assert.equal(missing.length, 1);
  assert.equal(missing[0].requiredClassIri, 'urn:usf:ontology:SourceArtefactDisposition');
  assert.deepEqual(missing[0].requiredSemanticLayers, []);
  assert.doesNotMatch(JSON.stringify(missing[0]), /Constraint|EquivalenceRule|GeneratorContract|InterfaceContract/);
});

test('same-name formal resource without typed instance evidence remains absent', () => {
  const graph = parsed('v2/usf/graph/example.trig', [{ kind: 'owl-class', identifier: 'urn:usf:ontology:OnlyAName', attributes: {} }], 'v2-graph-authority');
  const source = parsed('src/name.ts', [{ kind: 'function', identifier: 'OnlyAName', attributes: {} }]);
  const result = buildMappings([artifact('b', 'src/name.ts')], [graph, source], []).mappings[0];
  assert.equal(result.coverageDecision, 'absent');
  assert.equal(result.mappingType, 'unmapped');
  assert.ok(result.mappingEvidence.some((entry) => entry.kind === 'exhaustive-negative-resource-search'));
});

test('replacement cardinalities are closed and mismatches fail', () => {
  const current = new Set(['a', 'b']);
  const canonical = new Set(['x', 'y']);
  for (const record of [
    { groupKey: '1-1', cardinality: 'one-to-one', currentArtifacts: ['a'], canonicalArtifacts: ['x'] },
    { groupKey: 'n-1', cardinality: 'many-to-one', currentArtifacts: ['a', 'b'], canonicalArtifacts: ['x'] },
    { groupKey: '1-n', cardinality: 'one-to-many', currentArtifacts: ['a'], canonicalArtifacts: ['x', 'y'] },
    { groupKey: 'n-n', cardinality: 'many-to-many', currentArtifacts: ['a', 'b'], canonicalArtifacts: ['x', 'y'] },
    { groupKey: '1-0', cardinality: 'one-to-zero', currentArtifacts: ['a'], canonicalArtifacts: [] },
    { groupKey: '0-1', cardinality: 'zero-to-one', currentArtifacts: [], canonicalArtifacts: ['x'] }
  ]) validateReplacementGroup(record, current, canonical);
  assert.throws(() => validateReplacementGroup({ groupKey: 'bad', cardinality: 'many-to-one', currentArtifacts: ['a'], canonicalArtifacts: ['x'] }, current, canonical), /cardinality mismatch/);
});

test('required-prerequisite graph algorithms detect cycles and remove transitive edges', () => {
  const edge = (source, prerequisite) => ({ source, prerequisite });
  assert.equal(dependencyGraphInternals.hasCycle([edge('a', 'b'), edge('b', 'a')]), true);
  const reduced = dependencyGraphInternals.transitiveReduction([edge('a', 'b'), edge('b', 'c'), edge('a', 'c')]);
  assert.equal(reduced.kept.length, 2);
  assert.deepEqual(reduced.removed, [edge('a', 'c')]);
});

test('dependency status is derived from structural relationship context rather than cycle presence', () => {
  const classify = dependencyGraphInternals.relationshipDependencyStatus;
  assert.equal(classify({ extractionMethod: 'json-pointer', attributes: { keyPath: 'include.0' } }), 'coordination');
  assert.equal(classify({ extractionMethod: 'json-pointer', attributes: { keyPath: 'exclude.2' } }), 'coordination');
  assert.equal(classify({ extractionMethod: 'json-pointer', attributes: { keyPath: 'compilerOptions.paths.alias.0' } }), 'coordination');
  assert.equal(classify({ extractionMethod: 'json-pointer', attributes: { keyPath: 'extends' } }), 'required-prerequisite');
  assert.equal(classify({ extractionMethod: 'babel-import-declaration', attributes: {} }), 'required-prerequisite');
  assert.equal(classify({ relationshipType: 'references', extractionMethod: 'json-pointer', attributes: { keyPath: 'authorityInputs.0.path' } }, { artifactFamily: 'documentation-assets' }), 'coordination');
  assert.equal(classify({ relationshipType: 'references', extractionMethod: 'markdown-inline-link', attributes: {} }, { artifactFamily: 'repository-governance' }), 'coordination');
});

test('dependency ownership uses the canonical semantic-layer owner, not the first consumer', () => {
  const packages = [
    { key: 'consumer', requiredSemanticLayers: ['equivalence-rules'], ownedSemanticLayers: [] },
    { key: 'validation-owner', requiredSemanticLayers: ['equivalence-rules'], ownedSemanticLayers: ['equivalence-rules'] }
  ];
  assert.equal(dependencyGraphInternals.ownerMaps(packages).layers.get('equivalence-rules'), 'validation-owner');
  assert.throws(
    () => dependencyGraphInternals.ownerMaps([...packages, { key: 'duplicate-owner', ownedSemanticLayers: ['equivalence-rules'] }]),
    /semantic layer has multiple package owners/
  );
});

test('dependency graph persists only independently resolvable retained edges', () => {
  const packages = [
    { key: 'work.a', artifactKeys: ['a'], canonicalArtifactKeys: [], ownedSemanticLayers: [], requiredSemanticLayers: [], equivalenceGates: [] },
    { key: 'work.b', artifactKeys: ['b'], canonicalArtifactKeys: [], ownedSemanticLayers: [], requiredSemanticLayers: [], equivalenceGates: [] },
  ];
  const artifacts = [artifact('a', 'src/a.ts'), artifact('b', 'src/b.ts')];
  const relation = { source: 'src/a.ts', target: 'src/b.ts', relationshipType: 'imports', targetKind: 'artifact', resolved: true, extractionMethod: 'babel-import-declaration', evidenceKind: 'structurally-proven', attributes: {} };
  const result = buildDependencyGraph(packages, artifacts, [], [], [relation], []);
  assert.equal(result.dependencies.length, 1);
  const dependency = result.dependencies[0];
  assert.equal(dependency.dependencyKey, dependencyKeyFor(dependency));
  assert.equal(dependency.resolutionStatus, 'resolved-retained');
  assert.deepEqual(dependency.resolutionBasis.evidenceFamilies, ['repository-relationship']);
  assert.equal(dependency.resolutionBasis.evidenceCounts['repository-relationship'], 1);
  assert.equal(dependency.resolutionBasis.cycleCheck, 'required-prerequisite-dag-verified');
  assert.equal(dependency.resolutionBasis.transitiveReduction, 'retained-direct-edge');
  assert.equal(dependency.satisfactionStatus, 'satisfied');
  assert.deepEqual(dependency.satisfactionBasis, {
    exactEvidenceHashCount: 1, currentRelationshipHashCount: 1, structurallyProvenRelationshipHashCount: 1,
    directionMatchedRelationshipHashCount: 1, currentPrerequisiteArtifactHashCount: 1, currentPrerequisiteArtifactCount: 1,
    sourceEndpointExists: true, prerequisiteEndpointExists: true, edgeSurvivedTransitiveReduction: true, requiredPrerequisiteGraphAcyclic: true,
  });
  assert.equal(result.metrics.requiredPrerequisiteRelationshipCount, 1);
  assert.equal(result.metrics.resolvedPrerequisiteRelationshipCount, 1);
  assert.equal(result.metrics.satisfiedPrerequisiteRelationshipCount, 1);
  assert.equal(result.metrics.blockingRelationshipCount, 0);
  assert.equal(result.metrics.activeBlockingRelationshipCount, 0);
  assert.throws(() => buildDependencyGraph(packages, artifacts, [], [], [{ ...relation, evidenceKind: 'heuristic' }], []), /does not prove direction and ownership/);
  assert.throws(() => buildDependencyGraph(packages, [artifacts[0], { ...artifacts[1], sourceState: 'deleted' }], [], [], [relation], []), /not satisfied/);
  assert.throws(() => buildDependencyGraph(packages, artifacts, [], [], [relation, { ...relation, extractionMethod: 'second-structural-parser' }], []), /not satisfied/);
  const reverse = { ...relation, source: 'src/b.ts', target: 'src/a.ts' };
  assert.throws(() => buildDependencyGraph(packages, artifacts, [], [], [relation, reverse], []), /acyclic required-prerequisite graph/);
});

test('relationship closure distinguishes allowlisted external references from unresolved internal targets', () => {
  const raw = parsed('src/example.mjs', [], 'repository-output');
  raw.relationships = [
    { relationshipType: 'references', target: 'https://example.test/schema.json', targetKind: 'artifact', extractionMethod: 'fixture', evidenceKind: 'structurally-proven', confidence },
    { relationshipType: 'imports', target: './missing.mjs', targetKind: 'artifact', extractionMethod: 'fixture', evidenceKind: 'structurally-proven', confidence }
  ];
  const result = buildRelationships([{ path: 'src/example.mjs' }], [raw]);
  const external = result.relationships.find((record) => record.target.startsWith('https:'));
  const internal = result.relationships.find((record) => record.target === './missing.mjs');
  assert.equal(external.targetKind, 'external-resource');
  assert.ok(external.reasonCodes.includes('expected-external-reference'));
  assert.equal(internal.resolved, false);
  assert.equal(result.relationshipFindings.length, 1);
  assert.equal(result.relationshipFindings[0].resolutionStatus, 'open');
});

test('observation carrier references resolve without admitting carriers to the source universe', () => {
  const manifest = parsed('v2/usf/graph/manifest.yaml', [], 'v2-graph-authority');
  manifest.relationships = [{
    relationshipType: 'references', target: 'v2/usf/graph/derived/coverage.trig', targetKind: 'artifact',
    extractionMethod: 'yaml-graph-manifest', evidenceKind: 'structurally-proven', confidence
  }];
  const result = buildRelationships(
    [{ path: manifest.path, universe: manifest.universe }],
    [manifest],
    new Set(['v2/usf/graph/derived/coverage.trig'])
  );
  assert.equal(result.relationshipFindings.length, 0);
  assert.deepEqual(result.relationships.map((record) => ({ target: record.target, targetKind: record.targetKind, resolved: record.resolved, reasonCodes: record.reasonCodes })), [{
    target: 'v2/usf/graph/derived/coverage.trig', targetKind: 'semantic-entity', resolved: true,
    reasonCodes: ['structural-parser-evidence', 'generated-observation-carrier']
  }]);
});

test('relationship closure resolves structural bases and classifies proven non-file references', () => {
  const source = parsed('docs/authority.json', [], 'repository-output');
  source.relationships = [
    { relationshipType: 'references', target: 'spec/existing.json', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: 'authority.path', pathField: 'path' }, evidenceKind: 'structurally-proven', confidence },
    { relationshipType: 'references', target: 'donor/apps/api.ts', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: 'entries.0.sourceRef.path', pathField: 'path' }, evidenceKind: 'structurally-proven', confidence },
    { relationshipType: 'references', target: 'docs/retired.json', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: 'removedInvalidOrStaleReferences.0.path', pathField: 'path' }, evidenceKind: 'structurally-proven', confidence },
    { relationshipType: 'references', target: 'artifacts/old.json', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: 'observedArtifactSizeSnapshot.largestObservedFiles.0.path', pathField: 'path' }, evidenceKind: 'structurally-proven', confidence },
    { relationshipType: 'references', target: 'v2/tmp/run/output.json', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: 'outputs.0.files.0', pathField: 'files' }, evidenceKind: 'structurally-proven', confidence },
    { relationshipType: 'references', target: 'spec/', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: 'scopes.0.path', pathField: 'path' }, evidenceKind: 'structurally-proven', confidence },
    { relationshipType: 'references', target: 'src/**/*.ts', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: 'include.0', pathField: 'include' }, evidenceKind: 'structurally-proven', confidence },
    { relationshipType: 'references', target: '/v2/openapi.json', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: 'renderedEndpoints.0.path', pathField: 'path' }, evidenceKind: 'structurally-proven', confidence }
  ];
  const manifest = parsed('tools/validate-spec/manifests/adr.json', [], 'repository-output');
  manifest.relationships = [{ relationshipType: 'references', target: 'negative/adr/bad.json', targetKind: 'artifact', extractionMethod: 'json-pointer', attributes: { keyPath: '0.path', pathField: 'path' }, evidenceKind: 'structurally-proven', confidence }];
  const result = buildRelationships([
    { path: 'docs/authority.json' },
    { path: 'spec/existing.json' },
    { path: 'tools/validate-spec/manifests/adr.json' },
    { path: 'tools/validate-spec/fixtures/negative/adr/bad.json' }
  ], [source, manifest]);
  assert.equal(result.relationshipFindings.length, 0);
  assert.ok(result.relationships.some((record) => record.target === 'spec/existing.json' && record.targetKind === 'artifact' && record.resolved));
  assert.ok(result.relationships.some((record) => record.target === 'tools/validate-spec/fixtures/negative/adr/bad.json' && record.targetKind === 'artifact' && record.resolved));
  const byClass = new Map(result.relationships.flatMap((record) => record.reasonCodes.filter((reason) => reason.startsWith('non-internal-reference-class:')).map((reason) => [reason, record])));
  for (const expected of [
    'non-internal-reference-class:source-lineage-reference',
    'non-internal-reference-class:declared-stale-or-removed-reference',
    'non-internal-reference-class:historical-size-snapshot',
    'non-internal-reference-class:generated-or-runtime-output',
    'non-internal-reference-class:directory-scope',
    'non-internal-reference-class:path-pattern',
    'non-internal-reference-class:http-route'
  ]) assert.ok(byClass.has(expected), expected);
  for (const expected of [
    'non-internal-reference-class:source-lineage-reference',
    'non-internal-reference-class:generated-or-runtime-output'
  ]) assert.equal(byClass.get(expected).targetKind, 'external-resource', expected);
  for (const expected of [
    'non-internal-reference-class:declared-stale-or-removed-reference',
    'non-internal-reference-class:historical-size-snapshot',
    'non-internal-reference-class:directory-scope',
    'non-internal-reference-class:path-pattern',
    'non-internal-reference-class:http-route'
  ]) assert.equal(byClass.get(expected).targetKind, 'semantic-entity', expected);
});
