import assert from 'node:assert/strict';
import test from 'node:test';

import { auditRepositoryStructureDataset, repositoryStructureInternals } from '../audit/repository-structure.mjs';

const { DERIVED_GRAPH, OBSERVED_GRAPH, recordDigest, relationshipEvidenceDigest, sha256, stableJson } = repositoryStructureInternals;
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const XSD_BOOLEAN = 'http://www.w3.org/2001/XMLSchema#boolean';
const XSD_NON_NEGATIVE_INTEGER = 'http://www.w3.org/2001/XMLSchema#nonNegativeInteger';
const NS = 'urn:usf:ontology:';
const t = (local) => `${NS}${local}`;
const q = (subject, predicate, object, graph = OBSERVED_GRAPH, objectDatatype = null) => ({ subject, predicate, object: String(object), graph, objectDatatype });
const forbidden = /linear\.app|github\.com|gitlab\.com|USF-[0-9]|issueId|projectId|branchName|commitSha|refs\/heads/;
const disclose = (value) => ({ digest: sha256(value), status: forbidden.test(value) ? 'urn:usf:observationdisclosurestatus:withheldprohibitedmetadata' : 'urn:usf:observationdisclosurestatus:disclosed' });
const workPackageObservationName = (key) => `w${key.slice('work-package-'.length)}`;
const dependencyObservationName = (key) => `d${key.slice('dependency-'.length)}`;
const workPackageObservationIri = (key) => `urn:usf:workpackageobservation:${workPackageObservationName(key)}`;
const repositoryWorkPackageIri = (key) => `urn:usf:repositoryworkpackage:${workPackageObservationName(key)}`;

function fixture({ withheld = false } = {}) {
  const targetPath = withheld ? 'github.com/fixture/repository-target' : 'b.json';
  const artifacts = [
    { artifactKey: 'a'.repeat(64), path: 'a.json', sourceState: 'tracked', contentDigest: '1'.repeat(64), parserImplementation: 'fixture-parser', syntaxKind: 'json', formatKind: 'structured-json' },
    { artifactKey: 'b'.repeat(64), path: targetPath, sourceState: 'tracked', contentDigest: '2'.repeat(64), parserImplementation: 'fixture-parser', syntaxKind: 'json', formatKind: 'structured-json' },
  ];
  const relationship = {
    source: 'a.json', target: targetPath, relationshipType: 'references', targetKind: 'artifact', evidenceKind: 'structurally-proven', extractionMethod: 'json-pointer',
    resolved: true, attributes: withheld ? { branchName: 'refs/heads/main' } : { keyPath: 'input.path' }, reasonCodes: ['structural-parser-evidence'], confidence: { level: 'high', score: 1, reasons: ['fixture'] },
  };
  const relationshipRow = { record: relationship, fullDigest: recordDigest(relationship), evidenceDigest: relationshipEvidenceDigest(relationship) };
  const canonicalArtifact = 'urn:usf:artefact:fixturecanonicala';
  const workA = { key: 'work-package-aaaaaaaaaaaaaaaaaaaa', title: 'A', outcomeClass: 'fixture:a', artifactKeys: [artifacts[0].artifactKey], canonicalArtifactKeys: [canonicalArtifact], primaryOwnership: { artifactKeys: [artifacts[0].artifactKey], canonicalArtifactKeys: [canonicalArtifact] } };
  const workB = { key: 'work-package-bbbbbbbbbbbbbbbbbbbb', title: 'B', outcomeClass: 'fixture:b', artifactKeys: [artifacts[1].artifactKey], canonicalArtifactKeys: [], primaryOwnership: { artifactKeys: [artifacts[1].artifactKey], canonicalArtifactKeys: [] } };
  const dependency = {
    dependencyKey: `dependency-${'d'.repeat(64)}`, source: workA.key, prerequisite: workB.key, dependencyType: 'canonical-artifact-input', status: 'required-prerequisite',
    resolutionStatus: 'resolved-retained', reasonCode: 'canonical-artifact-input', repositoryRelationshipEvidence: [relationshipRow.evidenceDigest],
    semanticEvidence: [], artifactEvidence: [], proofEquivalenceEvidence: [], migrationEvidence: [],
    resolutionBasis: { direction: 'source-requires-prerequisite', endpointOwnership: 'primary-work-package', evidenceFamilies: ['repository-relationship'], evidenceCounts: { artifact: 0, migration: 0, 'proof-equivalence': 0, 'repository-relationship': 1, semantic: 0 }, cycleCheck: 'required-prerequisite-dag-verified', transitiveReduction: 'retained-direct-edge', reviewBasis: 'machine-reviewed' },
    satisfactionStatus: 'satisfied',
    satisfactionBasis: { exactEvidenceHashCount: 1, currentRelationshipHashCount: 1, structurallyProvenRelationshipHashCount: 1, directionMatchedRelationshipHashCount: 1, currentPrerequisiteArtifactHashCount: 1, currentPrerequisiteArtifactCount: 1, sourceEndpointExists: true, prerequisiteEndpointExists: true, edgeSurvivedTransitiveReduction: true, requiredPrerequisiteGraphAcyclic: true },
  };
  const lineage = { baselineSource: 'baseline.a', baselinePrerequisite: 'baseline.b', successorSources: [workA.key], successorPrerequisites: [workB.key], disposition: 'retained-with-evidence', reason: 'exact successor edge retains the prerequisite' };
  const input = { path: 'relationships.jsonl', contentDigest: '3'.repeat(64), byteCount: 100, recordCount: 1 };
  const shard = { path: 'parser-results/repository-output.jsonl.gz', universe: 'repository-output', recordCount: 2, compressedSha256: '4'.repeat(64), uncompressedSha256: '5'.repeat(64) };
  const expected = {
    artifacts, artifactByPath: new Map(artifacts.map((record) => [record.path, record])), relationshipRows: [relationshipRow],
    workPackages: [workA, workB].map((record) => ({ record, fullDigest: recordDigest(record) })),
    ownership: { artifacts: artifacts.map((artifact, index) => ({ ownedKey: artifact.artifactKey, primaryWorkPackage: index ? workB.key : workA.key })), canonicalArtifacts: [{ ownedKey: canonicalArtifact, primaryWorkPackage: workA.key }] },
    dependencies: [{ record: dependency, fullDigest: recordDigest(dependency), relationshipMatches: [relationshipRow.fullDigest] }],
    lineage: [{ record: lineage, fullDigest: recordDigest(lineage) }], inputs: [input], parserShards: [shard], requiredPrerequisiteCount: 1,
    summary: { requiredPrerequisiteRelationshipCount: 1, resolvedPrerequisiteRelationshipCount: 1, satisfiedPrerequisiteRelationshipCount: 1, blockingRelationshipCount: 0, activeBlockingRelationshipCount: 0 },
  };
  const run = `urn:usf:censusobservationrun:r${'6'.repeat(64)}`;
  const triples = [
    q(run, RDF_TYPE, t('CensusObservationRun')), q(run, t('observationSetDigest'), '6'.repeat(64)), q(run, t('observedByCollector'), 'repositorysourceobserver'),
    q(run, t('observedSourceArtefactCount'), 2), q(run, t('observedSourceRelationshipCount'), 1), q(run, t('observedWorkPackageCount'), 2),
    q(run, t('observedWorkPackageDependencyCount'), 1), q(run, t('observedRequiredPrerequisiteDependencyCount'), 1), q(run, t('observedResolvedPrerequisiteDependencyCount'), 1),
    q(run, t('observedSatisfiedPrerequisiteDependencyCount'), 1), q(run, t('observedActiveBlockingDependencyCount'), 0), q(run, t('observedRetainedDependencyLineageCount'), 1),
  ];
  for (const artifact of artifacts) {
    const source = `urn:usf:sourceartefact:s${artifact.artifactKey}`; const observation = `urn:usf:sourceartefactobservation:o${artifact.artifactKey}`;
    triples.push(q(source, RDF_TYPE, t('SourceArtefact')), q(source, t('hasCurrentSourceObservation'), observation), q(observation, RDF_TYPE, t('SourceArtefactObservation')),
      q(observation, t('observedSourcePath'), artifact.path), q(observation, t('observedContentDigest'), artifact.contentDigest),
      q(observation, t('observedParserImplementation'), artifact.parserImplementation), q(observation, t('observedSyntaxKind'), artifact.syntaxKind),
      q(observation, t('observedFormatKind'), artifact.formatKind), q(observation, t('observedInCensusRun'), run));
  }
  const inputSubject = `urn:usf:censusobservationinput:i${sha256(input.path)}`;
  triples.push(q(inputSubject, RDF_TYPE, t('CensusObservationInput')), q(inputSubject, t('observedInputPath'), input.path), q(inputSubject, t('observedInputContentDigest'), input.contentDigest),
    q(inputSubject, t('observedInputByteCount'), input.byteCount), q(inputSubject, t('observedInputRecordCount'), input.recordCount), q(inputSubject, t('observedInCensusRun'), run), q(run, t('hasCensusObservationInput'), inputSubject));
  const shardSubject = `urn:usf:censusparsershardobservation:s${sha256(shard.path)}`;
  triples.push(q(shardSubject, RDF_TYPE, t('CensusParserShardObservation')), q(shardSubject, t('observedParserShardPath'), shard.path), q(shardSubject, t('observedParserRecordCount'), shard.recordCount),
    q(shardSubject, t('observedParserUniverse'), 'urn:usf:sourceuniverse:canonicalrepository'),
    q(shardSubject, t('observedCompressedContentDigest'), shard.compressedSha256), q(shardSubject, t('observedUncompressedContentDigest'), shard.uncompressedSha256),
    q(shardSubject, t('observedInCensusRun'), run), q(run, t('hasCensusParserShardObservation'), shardSubject));
  const relationshipSubject = `urn:usf:sourcerelationshipobservation:r${relationshipRow.fullDigest}`;
  const targetSubject = `urn:usf:sourcerelationshiptarget:t${sha256(`${relationship.targetKind}\0${relationship.target}`)}`;
  const targetDisclosure = disclose(relationship.target);
  const attributesValue = stableJson(relationship.attributes);
  const attributesDisclosure = disclose(attributesValue);
  triples.push(q(targetSubject, RDF_TYPE, t('SourceRelationshipTargetObservation')),
    q(targetSubject, t('observedRelationshipTargetDigest'), targetDisclosure.digest), q(targetSubject, t('observedRelationshipTargetDisclosureStatus'), targetDisclosure.status),
    q(targetSubject, t('observedRelationshipTargetKind'), 'urn:usf:sourcerelationshiptargetkind:artifact'), q(targetSubject, t('resolvesToSourceArtefact'), `urn:usf:sourceartefact:s${artifacts[1].artifactKey}`), q(targetSubject, t('observedInCensusRun'), run),
    q(relationshipSubject, RDF_TYPE, t('SourceRelationshipObservation')), q(relationshipSubject, t('sourceRelationshipSource'), `urn:usf:sourceartefact:s${artifacts[0].artifactKey}`),
    q(relationshipSubject, t('sourceRelationshipTarget'), targetSubject), q(relationshipSubject, t('sourceRelationshipType'), 'urn:usf:sourcerelationshiptype:references'),
    q(relationshipSubject, t('sourceRelationshipResolved'), 'true'), q(relationshipSubject, t('sourceRelationshipEvidenceKind'), 'urn:usf:sourcerelationshipevidencekind:structurallyproven'),
    q(relationshipSubject, t('sourceRelationshipExtractionMethod'), relationship.extractionMethod), q(relationshipSubject, t('sourceRelationshipAttributesDigest'), attributesDisclosure.digest),
    q(relationshipSubject, t('sourceRelationshipAttributesDisclosureStatus'), attributesDisclosure.status),
    q(relationshipSubject, t('sourceRelationshipConfidence'), stableJson(relationship.confidence)), q(relationshipSubject, t('sourceRelationshipRecordDigest'), relationshipRow.fullDigest),
    q(relationshipSubject, t('relationshipEvidenceDigest'), relationshipRow.evidenceDigest), q(relationshipSubject, t('sourceRelationshipReasonCode'), relationship.reasonCodes[0]), q(relationshipSubject, t('observedInCensusRun'), run));
  if (targetDisclosure.status.endsWith(':disclosed')) triples.push(q(targetSubject, t('observedRelationshipTarget'), relationship.target));
  if (attributesDisclosure.status.endsWith(':disclosed')) triples.push(q(relationshipSubject, t('sourceRelationshipAttributes'), attributesValue));
  const derivedPackages = new Map();
  for (const { record, fullDigest } of expected.workPackages) {
    const observation = workPackageObservationIri(record.key); const derived = repositoryWorkPackageIri(record.key); derivedPackages.set(record.key, derived);
    triples.push(q(observation, RDF_TYPE, t('WorkPackageObservation')), q(observation, t('workPackageKey'), record.key), q(observation, t('workPackageTitle'), record.title),
      q(observation, t('workPackageOutcomeClass'), record.outcomeClass), q(observation, t('workPackageRecordDigest'), fullDigest), q(observation, t('observedInCensusRun'), run),
      q(observation, t('observedOwnedSourceArtefact'), `urn:usf:sourceartefact:s${record.artifactKeys[0]}`),
      q(derived, RDF_TYPE, t('RepositoryWorkPackage'), DERIVED_GRAPH), q(derived, t('promotedFromWorkPackageObservation'), observation, DERIVED_GRAPH),
      q(derived, t('ownsObservedSourceArtefact'), `urn:usf:sourceartefact:s${record.artifactKeys[0]}`, DERIVED_GRAPH));
    for (const canonical of record.canonicalArtifactKeys) triples.push(
      q(observation, t('observedOwnedCanonicalArtefact'), canonical),
      q(derived, t('ownsCanonicalArtefact'), canonical, DERIVED_GRAPH),
    );
  }
  const dependencyName = dependencyObservationName(dependency.dependencyKey);
  const dependencyObservation = `urn:usf:workpackagedependencyobservation:${dependencyName}`;
  const derivedDependency = `urn:usf:resolvedworkpackagedependency:${dependencyName}`;
  const basisPayload = { dependencyKey: dependency.dependencyKey, satisfactionStatus: dependency.satisfactionStatus, satisfactionBasis: dependency.satisfactionBasis, repositoryRelationshipEvidence: [...dependency.repositoryRelationshipEvidence].sort() };
  const basisDigest = sha256(stableJson(basisPayload));
  const basisName = `s${basisDigest}`;
  const basisSubject = `urn:usf:workpackagedependencysatisfactionbasisobservation:${basisName}`;
  const satisfactionStatus = 'urn:usf:dependencysatisfactionstatus:satisfied';
  triples.push(q(dependencyObservation, RDF_TYPE, t('WorkPackageDependencyObservation')), q(dependencyObservation, t('workPackageDependencyKey'), dependency.dependencyKey),
    q(dependencyObservation, t('workPackageDependencySource'), workPackageObservationIri(workA.key)), q(dependencyObservation, t('workPackageDependencyPrerequisite'), workPackageObservationIri(workB.key)),
    q(dependencyObservation, t('workPackageDependencyType'), 'urn:usf:workpackagedependencytype:canonicalartifactinput'), q(dependencyObservation, t('workPackageDependencyStatus'), 'urn:usf:workpackagedependencystatus:requiredprerequisite'),
    q(dependencyObservation, t('workPackageDependencyResolutionStatus'), 'urn:usf:workpackagedependencyresolutionstatus:resolvedretained'), q(dependencyObservation, t('workPackageDependencyReasonCode'), dependency.reasonCode),
    q(dependencyObservation, t('workPackageDependencyResolutionBasis'), stableJson(dependency.resolutionBasis)), q(dependencyObservation, t('workPackageDependencyRecordDigest'), recordDigest(dependency)),
    q(dependencyObservation, t('workPackageDependencySatisfactionSeed'), satisfactionStatus), q(dependencyObservation, t('hasWorkPackageDependencySatisfactionBasis'), basisSubject),
    q(dependencyObservation, t('workPackageDependencyEvidenceDigest'), relationshipRow.evidenceDigest), q(dependencyObservation, t('supportedBySourceRelationshipObservation'), relationshipSubject), q(dependencyObservation, t('observedInCensusRun'), run),
    q(basisSubject, RDF_TYPE, t('WorkPackageDependencySatisfactionBasisObservation')), q(basisSubject, t('canonicalName'), basisName),
    q(basisSubject, t('satisfactionBasisForWorkPackageDependency'), dependencyObservation), q(basisSubject, t('observedDependencySatisfactionStatus'), satisfactionStatus),
    q(basisSubject, t('dependencySatisfactionBasisKind'), 'urn:usf:dependencysatisfactionbasiskind:resolveddirectrelationshipevidence'),
    q(basisSubject, t('satisfactionBasisRecordDigest'), basisDigest), q(basisSubject, t('satisfactionBasisRelationshipObservation'), relationshipSubject), q(basisSubject, t('observedInCensusRun'), run),
    q(derivedDependency, RDF_TYPE, t('RepositoryDependency'), DERIVED_GRAPH), q(derivedDependency, RDF_TYPE, t('ResolvedWorkPackageDependency'), DERIVED_GRAPH), q(derivedDependency, t('derivedFromWorkPackageDependencyObservation'), dependencyObservation, DERIVED_GRAPH),
    q(derivedDependency, t('resolvedDependencySource'), derivedPackages.get(workA.key), DERIVED_GRAPH), q(derivedDependency, t('resolvedDependencyPrerequisite'), derivedPackages.get(workB.key), DERIVED_GRAPH),
    q(derivedDependency, t('resolvedDependencyType'), 'urn:usf:workpackagedependencytype:canonicalartifactinput', DERIVED_GRAPH), q(derivedDependency, t('resolvedDependencyStatus'), 'urn:usf:workpackagedependencystatus:requiredprerequisite', DERIVED_GRAPH),
    q(derivedDependency, t('dependencyResolutionState'), 'urn:usf:workpackagedependencyresolutionstatus:resolvedretained', DERIVED_GRAPH), q(derivedDependency, t('supportedBySourceRelationshipObservation'), relationshipSubject, DERIVED_GRAPH),
    q(derivedDependency, t('dependencySatisfactionStatus'), satisfactionStatus, DERIVED_GRAPH), q(derivedDependency, t('derivedFromDependencySatisfactionBasis'), basisSubject, DERIVED_GRAPH));
  for (const field of ['exactEvidenceHashCount', 'currentRelationshipHashCount', 'structurallyProvenRelationshipHashCount', 'directionMatchedRelationshipHashCount', 'currentPrerequisiteArtifactHashCount', 'currentPrerequisiteArtifactCount']) {
    triples.push(q(basisSubject, t(`satisfactionBasis${field[0].toUpperCase()}${field.slice(1)}`), dependency.satisfactionBasis[field], OBSERVED_GRAPH, XSD_NON_NEGATIVE_INTEGER));
  }
  for (const field of ['sourceEndpointExists', 'prerequisiteEndpointExists', 'edgeSurvivedTransitiveReduction', 'requiredPrerequisiteGraphAcyclic']) {
    triples.push(q(basisSubject, t(`satisfactionBasis${field[0].toUpperCase()}${field.slice(1)}`), dependency.satisfactionBasis[field], OBSERVED_GRAPH, XSD_BOOLEAN));
  }
  const lineageObservation = `urn:usf:workpackagedependencylineageobservation:l${recordDigest(lineage)}`;
  const derivedLineage = `urn:usf:retainedworkpackagedependencylineage:l${recordDigest(lineage)}`;
  triples.push(q(lineageObservation, RDF_TYPE, t('WorkPackageDependencyLineageObservation')), q(lineageObservation, t('baselineDependencySourceKey'), lineage.baselineSource),
    q(lineageObservation, t('baselineDependencyPrerequisiteKey'), lineage.baselinePrerequisite), q(lineageObservation, t('dependencyLineageDisposition'), 'urn:usf:dependencylineagedisposition:retainedwithevidence'),
    q(lineageObservation, t('dependencyLineageReason'), lineage.reason), q(lineageObservation, t('dependencyLineageRecordDigest'), recordDigest(lineage)), q(lineageObservation, t('observedInCensusRun'), run),
    q(lineageObservation, t('successorDependencySource'), workPackageObservationIri(workA.key)), q(lineageObservation, t('successorDependencyPrerequisite'), workPackageObservationIri(workB.key)),
    q(derivedLineage, RDF_TYPE, t('RetainedWorkPackageDependencyLineage'), DERIVED_GRAPH), q(derivedLineage, t('derivedFromWorkPackageDependencyLineageObservation'), lineageObservation, DERIVED_GRAPH),
    q(derivedLineage, t('retainedLineageSuccessorSource'), derivedPackages.get(workA.key), DERIVED_GRAPH), q(derivedLineage, t('retainedLineageSuccessorPrerequisite'), derivedPackages.get(workB.key), DERIVED_GRAPH));
  return { expected, triples };
}

test('repository structure audit independently proves exact observed and derived parity', () => {
  const { expected, triples } = fixture();
  const result = auditRepositoryStructureDataset({ expected, triples });
  assert.equal(result.status, 'pass', result.findings.join('\n'));
  assert.deepEqual(result.facts, {
    relationshipCount: 1, workPackageCount: 2, dependencyCount: 1, requiredPrerequisiteDependencyCount: 1,
    resolvedPrerequisiteDependencyCount: 1, satisfiedPrerequisiteDependencyCount: 1, activeBlockingDependencyCount: 0, satisfactionBasisCount: 1,
    retainedLineageCount: 1, inputCount: 1, parserShardCount: 1, findingCount: 0,
  });
});

test('repository structure audit accepts digest-only disclosure for prohibited metadata', () => {
  const { expected, triples } = fixture({ withheld: true });
  const result = auditRepositoryStructureDataset({ expected, triples });
  assert.equal(result.status, 'pass', result.findings.join('\n'));
  assert.equal(triples.some((row) => row.predicate === t('observedRelationshipTarget')), false);
  assert.equal(triples.some((row) => row.predicate === t('sourceRelationshipAttributes')), false);
});

test('repository structure audit rejects missing, stale, misplaced, and unsupported materialization evidence', () => {
  const cases = [
    (rows) => rows.filter((row) => row.predicate !== t('supportedBySourceRelationshipObservation')),
    (rows) => rows.map((row) => row.predicate === t('observedInputContentDigest') ? { ...row, object: 'f'.repeat(64) } : row),
    (rows) => rows.map((row) => row.predicate === t('derivedFromWorkPackageDependencyObservation') ? { ...row, graph: OBSERVED_GRAPH } : row),
    (rows) => rows.filter((row) => row.predicate !== t('ownsObservedSourceArtefact') || !row.object.endsWith('a'.repeat(64))),
    (rows) => [...rows, q(`urn:usf:sourcerelationshipobservation:r${'f'.repeat(64)}`, RDF_TYPE, t('SourceRelationshipObservation'))],
    (rows) => rows.filter((row) => row.predicate !== t('observedUncompressedContentDigest')),
    (rows) => rows.filter((row) => row.predicate !== t('satisfactionBasisRelationshipObservation')),
    (rows) => rows.map((row) => row.predicate === t('satisfactionBasisRecordDigest') ? { ...row, object: 'f'.repeat(64) } : row),
    (rows) => rows.map((row) => row.predicate === t('satisfactionBasisExactEvidenceHashCount') ? { ...row, objectDatatype: XSD_BOOLEAN } : row),
    (rows) => rows.filter((row) => row.predicate !== t('dependencySatisfactionStatus')),
    (rows) => rows.map((row) => row.predicate === t('observedSatisfiedPrerequisiteDependencyCount') ? { ...row, object: '0' } : row),
    (rows) => rows.filter((row) => row.predicate !== t('observedRelationshipTargetDigest')),
    (rows) => rows.map((row) => row.predicate === t('sourceRelationshipAttributesDisclosureStatus') ? { ...row, object: 'urn:usf:observationdisclosurestatus:withheldprohibitedmetadata' } : row),
  ];
  for (const mutate of cases) {
    const { expected, triples } = fixture();
    assert.equal(auditRepositoryStructureDataset({ expected, triples: mutate(triples) }).status, 'fail');
  }
});

test('repository structure audit rejects raw prohibited metadata and missing disclosure digests', () => {
  const { expected, triples } = fixture({ withheld: true });
  const target = expected.relationshipRows[0].record.target;
  const targetSubject = `urn:usf:sourcerelationshiptarget:t${sha256(`artifact\0${target}`)}`;
  assert.equal(auditRepositoryStructureDataset({ expected, triples: [...triples, q(targetSubject, t('observedRelationshipTarget'), target)] }).status, 'fail');
  assert.equal(auditRepositoryStructureDataset({ expected, triples: triples.filter((row) => row.predicate !== t('sourceRelationshipAttributesDigest')) }).status, 'fail');
});
