import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Parser as N3Parser } from 'n3';
import { parse as parseYaml } from 'yaml';

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const XSD_BOOLEAN = 'http://www.w3.org/2001/XMLSchema#boolean';
const XSD_NON_NEGATIVE_INTEGER = 'http://www.w3.org/2001/XMLSchema#nonNegativeInteger';
const NS = 'urn:usf:ontology:';
const OBSERVED_GRAPH = 'urn:usf:graph:observed:sourceartefacts';
const DERIVED_GRAPH = 'urn:usf:graph:derived:repositorystructure';
const UNIVERSES = Object.freeze({ 'repository-output': 'canonicalrepository', 'v2-compiler-implementation': 'compilerimplementation', 'v2-graph-authority': 'graphauthority', 'v2-support-provisioning': 'supportprovisioning' });
const term = (local) => `${NS}${local}`;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

const recordDigest = (record) => sha256(stableJson(record));
const relationshipEvidenceDigest = (record) => sha256(`${record.source}\0${record.relationshipType}\0${record.target}`);
const controlled = (value) => value.toLowerCase().replace(/[^a-z0-9]+/g, '');
const OBSERVATION_CONTAMINATION_RE = new RegExp([
  'linear\\.app', 'github\\.com', 'gitlab\\.com', 'USF-[0-9]', 'ADR-[0-9]', 'issueId', 'projectId', 'branchName', 'commitSha', 'refs/heads',
].join('|'));
const DISCLOSED = 'urn:usf:observationdisclosurestatus:disclosed';
const WITHHELD = 'urn:usf:observationdisclosurestatus:withheldprohibitedmetadata';
const SATISFACTION_COUNT_FIELDS = Object.freeze([
  'exactEvidenceHashCount', 'currentRelationshipHashCount', 'structurallyProvenRelationshipHashCount',
  'directionMatchedRelationshipHashCount', 'currentPrerequisiteArtifactHashCount', 'currentPrerequisiteArtifactCount',
]);
const SATISFACTION_BOOLEAN_FIELDS = Object.freeze([
  'sourceEndpointExists', 'prerequisiteEndpointExists', 'edgeSurvivedTransitiveReduction', 'requiredPrerequisiteGraphAcyclic',
]);
const workPackageObservationName = (key) => `w${key.slice('work-package-'.length)}`;
const dependencyObservationName = (key) => `d${key.slice('dependency-'.length)}`;
const workPackageObservationIri = (key) => `urn:usf:workpackageobservation:${workPackageObservationName(key)}`;
const repositoryWorkPackageIri = (key) => `urn:usf:repositoryworkpackage:${workPackageObservationName(key)}`;
const dependencyObservationIri = (key) => `urn:usf:workpackagedependencyobservation:${dependencyObservationName(key)}`;
const resolvedDependencyIri = (key) => `urn:usf:resolvedworkpackagedependency:${dependencyObservationName(key)}`;
const disclosure = (value) => ({ digest: sha256(value), status: OBSERVATION_CONTAMINATION_RE.test(value) ? WITHHELD : DISCLOSED });
const satisfactionPayload = (record) => ({
  dependencyKey: record.dependencyKey,
  satisfactionStatus: record.satisfactionStatus,
  satisfactionBasis: record.satisfactionBasis,
  repositoryRelationshipEvidence: [...record.repositoryRelationshipEvidence].sort(),
});
const satisfactionBasisDigest = (record) => sha256(stableJson(satisfactionPayload(record)));

function readJson(target) { return JSON.parse(fs.readFileSync(target, 'utf8')); }
function readJsonl(target) { return fs.readFileSync(target, 'utf8').split(/\r?\n/).filter(Boolean).map(JSON.parse); }

function inputObservation(censusRoot, relative, format) {
  const content = fs.readFileSync(path.join(censusRoot, relative));
  return { path: relative, contentDigest: sha256(content), byteCount: content.length, recordCount: format === 'jsonl' ? readJsonl(path.join(censusRoot, relative)).length : null };
}

export function expectedRepositoryStructure(censusRoot) {
  const artifacts = readJsonl(path.join(censusRoot, 'artifacts.jsonl'));
  const relationships = readJsonl(path.join(censusRoot, 'relationships.jsonl'));
  const workPackageDocument = readJson(path.join(censusRoot, 'workpackages.json'));
  const dependencies = readJsonl(path.join(censusRoot, 'dependencies.jsonl'));
  const lineage = readJsonl(path.join(censusRoot, 'dependency-lineage.jsonl')).filter((record) => record.disposition === 'retained-with-evidence');
  const parserManifest = readJson(path.join(censusRoot, 'parser-results/manifest.json'));
  const summary = readJson(path.join(censusRoot, 'summary.json'));
  const inputs = [
    ['artifacts.jsonl', 'jsonl'], ['mappings.jsonl', 'jsonl'], ['relationships.jsonl', 'jsonl'],
    ['workpackages.json', 'json'], ['dependencies.jsonl', 'jsonl'], ['dependency-lineage.jsonl', 'jsonl'],
    ['parser-results/manifest.json', 'json'], ['summary.json', 'json'], ['universes.json', 'json'],
  ].map(([relative, format]) => inputObservation(censusRoot, relative, format));
  const artifactByPath = new Map(artifacts.map((record) => [record.path, record]));
  const relationshipRows = relationships.map((record) => ({ record, fullDigest: recordDigest(record), evidenceDigest: relationshipEvidenceDigest(record) }));
  const relationshipsByEvidence = new Map();
  for (const row of relationshipRows) {
    if (!relationshipsByEvidence.has(row.evidenceDigest)) relationshipsByEvidence.set(row.evidenceDigest, []);
    relationshipsByEvidence.get(row.evidenceDigest).push(row.fullDigest);
  }
  return {
    artifacts, artifactByPath, relationshipRows,
    workPackages: workPackageDocument.workPackages.map((record) => ({ record, fullDigest: recordDigest(record) })),
    ownership: workPackageDocument.ownership,
    dependencies: dependencies.map((record) => ({
      record, fullDigest: recordDigest(record),
      relationshipMatches: [...new Set(record.repositoryRelationshipEvidence.flatMap((digest) => relationshipsByEvidence.get(digest) ?? []))].sort(),
    })),
    lineage: lineage.map((record) => ({ record, fullDigest: recordDigest(record) })),
    inputs,
    parserShards: parserManifest.shards,
    summary,
    requiredPrerequisiteCount: dependencies.filter((record) => record.status === 'required-prerequisite').length,
  };
}

function rdfTerm(value) {
  if (value.termType === 'DefaultGraph') return null;
  return value.value;
}

function parseCarrier(repositoryRoot, relative) {
  const format = relative.endsWith('.ttl') ? 'text/turtle' : 'application/trig';
  const quads = new N3Parser({ format }).parse(fs.readFileSync(path.join(repositoryRoot, relative), 'utf8'));
  return quads.map((quad) => ({
    subject: rdfTerm(quad.subject), predicate: rdfTerm(quad.predicate), object: rdfTerm(quad.object), graph: rdfTerm(quad.graph),
    objectDatatype: quad.object.termType === 'Literal' ? quad.object.datatype.value : null,
  }));
}

export function readRegisteredRepositoryStructure(repositoryRoot) {
  const manifest = parseYaml(fs.readFileSync(path.join(repositoryRoot, 'v2/usf/graph/manifest.yaml'), 'utf8'));
  const observedRows = manifest.observedGraphs ?? [];
  const derivedRows = manifest.derivedGraphs ?? [];
  const observed = observedRows.find((row) => row.graph === OBSERVED_GRAPH);
  const derived = derivedRows.find((row) => row.graph === DERIVED_GRAPH);
  const findings = [];
  if (!observed?.file || observed.collector !== 'repositorysourceobserver') findings.push('repository-structure-observed-graph-not-registered');
  if (!derived?.file) findings.push('repository-structure-derived-graph-not-registered');
  const triples = [];
  for (const row of [...observedRows, ...derivedRows]) if (row?.file) {
    try {
      for (const triple of parseCarrier(repositoryRoot, `v2/usf/graph/${row.file}`)) triples.push(triple);
    }
    catch (error) { findings.push(`repository-structure-carrier-unreadable:${row.file}:${error.message}`); }
  }
  return { triples, findings };
}

function indexTriples(triples) {
  const bySubject = new Map();
  for (const triple of triples) {
    if (!bySubject.has(triple.subject)) bySubject.set(triple.subject, []);
    bySubject.get(triple.subject).push(triple);
  }
  const values = (subject, predicate) => [...new Set((bySubject.get(subject) ?? []).filter((row) => row.predicate === predicate).map((row) => row.object))].sort();
  const typed = (classIri) => [...new Set(triples.filter((row) => row.predicate === RDF_TYPE && row.object === classIri).map((row) => row.subject))].sort();
  return { bySubject, values, typed };
}

function prerequisiteGraphIsAcyclic(records) {
  const adjacency = new Map();
  for (const record of records) {
    if (!adjacency.has(record.source)) adjacency.set(record.source, []);
    adjacency.get(record.source).push(record.prerequisite);
  }
  const visiting = new Set(); const visited = new Set();
  const visit = (node) => {
    if (visiting.has(node)) return false;
    if (visited.has(node)) return true;
    visiting.add(node);
    for (const next of adjacency.get(node) ?? []) if (!visit(next)) return false;
    visiting.delete(node); visited.add(node); return true;
  };
  return [...new Set(records.flatMap((record) => [record.source, record.prerequisite]))].every(visit);
}

function hasAlternativePrerequisitePath(records, excluded) {
  const queue = [excluded.source]; const seen = new Set();
  while (queue.length) {
    const node = queue.shift();
    if (node === excluded.prerequisite) return true;
    if (seen.has(node)) continue;
    seen.add(node);
    for (const record of records) if (record !== excluded && record.source === node && !seen.has(record.prerequisite)) queue.push(record.prerequisite);
  }
  return false;
}

function recomputeSatisfactionBasis(record, { packageKeys, artifactByPath, artifactOwners, relationshipByEvidence, prerequisiteRecords, acyclic }) {
  let currentRelationshipHashCount = 0;
  let structurallyProvenRelationshipHashCount = 0;
  let directionMatchedRelationshipHashCount = 0;
  let currentPrerequisiteArtifactHashCount = 0;
  const prerequisiteArtifacts = new Set();
  for (const evidence of record.repositoryRelationshipEvidence) {
    const matches = relationshipByEvidence.get(evidence) ?? [];
    if (matches.length !== 1) continue;
    currentRelationshipHashCount += 1;
    const relation = matches[0].record;
    const structural = relation.resolved === true && relation.targetKind === 'artifact' && relation.evidenceKind === 'structurally-proven';
    if (structural) structurallyProvenRelationshipHashCount += 1;
    const sourceArtifact = artifactByPath.get(relation.source);
    const prerequisiteArtifact = artifactByPath.get(relation.target);
    if (structural && artifactOwners.get(sourceArtifact?.artifactKey) === record.source && artifactOwners.get(prerequisiteArtifact?.artifactKey) === record.prerequisite) directionMatchedRelationshipHashCount += 1;
    if (prerequisiteArtifact && prerequisiteArtifact.sourceState !== 'deleted' && /^[a-f0-9]{64}$/.test(prerequisiteArtifact.contentDigest ?? '')) {
      currentPrerequisiteArtifactHashCount += 1;
      prerequisiteArtifacts.add(prerequisiteArtifact.artifactKey);
    }
  }
  return {
    exactEvidenceHashCount: record.repositoryRelationshipEvidence.length,
    currentRelationshipHashCount,
    structurallyProvenRelationshipHashCount,
    directionMatchedRelationshipHashCount,
    currentPrerequisiteArtifactHashCount,
    currentPrerequisiteArtifactCount: prerequisiteArtifacts.size,
    sourceEndpointExists: packageKeys.has(record.source),
    prerequisiteEndpointExists: packageKeys.has(record.prerequisite),
    edgeSurvivedTransitiveReduction: !hasAlternativePrerequisitePath(prerequisiteRecords, record),
    requiredPrerequisiteGraphAcyclic: acyclic,
  };
}

function satisfactionStatus(basis) {
  const exact = basis.exactEvidenceHashCount;
  return exact > 0 && SATISFACTION_COUNT_FIELDS.slice(1, 5).every((field) => basis[field] === exact) && basis.currentPrerequisiteArtifactCount > 0 &&
    SATISFACTION_BOOLEAN_FIELDS.every((field) => basis[field] === true) ? 'satisfied' : 'unsatisfied';
}

export function auditRepositoryStructureDataset({ triples, expected, initialFindings = [] }) {
  const findings = [];
  let findingCount = 0;
  const add = (finding) => { findingCount += 1; if (findings.length < 250) findings.push(finding); };
  initialFindings.forEach(add);
  const { bySubject, values, typed } = indexTriples(triples);
  const requiredPrerequisites = expected.dependencies.filter(({ record }) => record.status === 'required-prerequisite');
  const prerequisiteRecords = requiredPrerequisites.map(({ record }) => record);
  const packageKeys = new Set(expected.workPackages.map(({ record }) => record.key));
  const artifactOwners = new Map(expected.workPackages.flatMap(({ record }) => record.artifactKeys.map((key) => [key, record.key])));
  const relationshipByEvidence = new Map();
  for (const row of expected.relationshipRows) {
    if (!relationshipByEvidence.has(row.evidenceDigest)) relationshipByEvidence.set(row.evidenceDigest, []);
    relationshipByEvidence.get(row.evidenceDigest).push(row);
  }
  const acyclic = prerequisiteGraphIsAcyclic(prerequisiteRecords);
  const independentlyRecomputedSatisfaction = new Map();
  for (const record of prerequisiteRecords) {
    const basis = recomputeSatisfactionBasis(record, { packageKeys, artifactByPath: expected.artifactByPath, artifactOwners, relationshipByEvidence, prerequisiteRecords, acyclic });
    independentlyRecomputedSatisfaction.set(record.dependencyKey, { basis, status: satisfactionStatus(basis) });
    if (stableJson(record.satisfactionBasis) !== stableJson(basis)) add(`census-dependency-satisfaction-basis-invalid:${record.dependencyKey}`);
    if (record.satisfactionStatus !== satisfactionStatus(basis)) add(`census-dependency-satisfaction-status-invalid:${record.dependencyKey}`);
  }
  const resolvedPrerequisiteCount = requiredPrerequisites.filter(({ record }) => record.resolutionStatus === 'resolved-retained').length;
  const satisfiedPrerequisiteCount = requiredPrerequisites.filter(({ record }) => independentlyRecomputedSatisfaction.get(record.dependencyKey)?.status === 'satisfied').length;
  const activeBlockingCount = requiredPrerequisites.length - satisfiedPrerequisiteCount;
  const placement = new Map();
  const checkPlacement = (subject, predicate, label) => {
    const expectedGraph = placement.get(subject);
    if (expectedGraph && (bySubject.get(subject) ?? []).filter((row) => row.predicate === predicate).some((row) => row.graph !== expectedGraph)) add(`${label}-graph:${subject}`);
  };
  const one = (subject, predicate, expectedValue, label) => {
    checkPlacement(subject, predicate, label);
    const actual = values(subject, predicate);
    if (actual.length !== 1 || actual[0] !== String(expectedValue)) add(`${label}:${subject}`);
  };
  const typedOne = (subject, predicate, expectedValue, datatype, label) => {
    one(subject, predicate, expectedValue, label);
    const rows = (bySubject.get(subject) ?? []).filter((row) => row.predicate === predicate);
    if (rows.length !== 1 || rows[0].objectDatatype !== datatype) add(`${label}-datatype:${subject}`);
  };
  const exact = (subject, predicate, expectedValues, label) => {
    checkPlacement(subject, predicate, label);
    const actual = values(subject, predicate);
    const wanted = [...new Set(expectedValues.map(String))].sort();
    if (stableJson(actual) !== stableJson(wanted)) add(`${label}:${subject}`);
  };
  const graph = (subject, expectedGraph, label) => {
    placement.set(subject, expectedGraph);
    const rows = (bySubject.get(subject) ?? []).filter((row) => row.predicate === RDF_TYPE);
    if (!rows.length || rows.some((row) => row.graph !== expectedGraph)) add(`${label}:${subject}`);
  };
  const exactSubjects = (classIri, expectedSubjects, label) => {
    const actual = typed(classIri); const wanted = [...expectedSubjects].sort();
    if (stableJson(actual) !== stableJson(wanted)) add(`${label}:count=${actual.length}/${wanted.length}`);
  };

  const runs = typed(term('CensusObservationRun'));
  if (runs.length !== 1) add(`census-run-cardinality:${runs.length}`);
  const run = runs[0];
  if (run) {
    graph(run, OBSERVED_GRAPH, 'census-run-graph');
    one(run, term('observedByCollector'), 'repositorysourceobserver', 'census-run-collector');
    one(run, term('observedSourceArtefactCount'), expected.artifacts.length, 'census-run-source-count');
    one(run, term('observedSourceRelationshipCount'), expected.relationshipRows.length, 'census-run-relationship-count');
    one(run, term('observedWorkPackageCount'), expected.workPackages.length, 'census-run-work-package-count');
    one(run, term('observedWorkPackageDependencyCount'), expected.dependencies.length, 'census-run-dependency-count');
    one(run, term('observedRequiredPrerequisiteDependencyCount'), requiredPrerequisites.length, 'census-run-required-prerequisite-count');
    one(run, term('observedResolvedPrerequisiteDependencyCount'), resolvedPrerequisiteCount, 'census-run-resolved-prerequisite-count');
    one(run, term('observedSatisfiedPrerequisiteDependencyCount'), satisfiedPrerequisiteCount, 'census-run-satisfied-prerequisite-count');
    one(run, term('observedActiveBlockingDependencyCount'), activeBlockingCount, 'census-run-active-blocking-count');
    one(run, term('observedRetainedDependencyLineageCount'), expected.lineage.length, 'census-run-lineage-count');
    if (!values(run, term('observationSetDigest')).some((value) => /^[a-f0-9]{64}$/.test(value))) add(`census-run-digest:${run}`);
  }
  const summaryCounts = {
    requiredPrerequisiteRelationshipCount: requiredPrerequisites.length,
    resolvedPrerequisiteRelationshipCount: resolvedPrerequisiteCount,
    satisfiedPrerequisiteRelationshipCount: satisfiedPrerequisiteCount,
    blockingRelationshipCount: 0,
    activeBlockingRelationshipCount: activeBlockingCount,
  };
  for (const [field, count] of Object.entries(summaryCounts)) if (expected.summary?.[field] !== count) add(`census-summary-${field}:${expected.summary?.[field]}/${count}`);

  if (expected.ownership) {
    const observedArtifactOwnership = (expected.ownership.artifacts ?? []).map((row) => `${row.ownedKey}\0${row.primaryWorkPackage}`).sort();
    const recordArtifactOwnership = expected.workPackages.flatMap(({ record }) => record.artifactKeys.map((key) => `${key}\0${record.key}`)).sort();
    if (stableJson(observedArtifactOwnership) !== stableJson(recordArtifactOwnership)) add('work-package-artifact-ownership-document-mismatch');
    const observedCanonicalOwnership = (expected.ownership.canonicalArtifacts ?? []).map((row) => `${row.ownedKey}\0${row.primaryWorkPackage}`).sort();
    const recordCanonicalOwnership = expected.workPackages.flatMap(({ record }) => record.canonicalArtifactKeys.map((key) => `${key}\0${record.key}`)).sort();
    if (stableJson(observedCanonicalOwnership) !== stableJson(recordCanonicalOwnership)) add('work-package-canonical-ownership-document-mismatch');
  }

  for (const artifact of expected.artifacts) {
    const source = `urn:usf:sourceartefact:s${artifact.artifactKey}`;
    const observations = values(source, term('hasCurrentSourceObservation'));
    if (observations.length !== 1) { add(`source-observation-cardinality:${artifact.artifactKey}:${observations.length}`); continue; }
    const observation = observations[0];
    graph(source, OBSERVED_GRAPH, 'source-artefact-graph'); graph(observation, OBSERVED_GRAPH, 'source-observation-graph');
    one(observation, term('observedSourcePath'), artifact.path, 'source-observation-path');
    one(observation, term('observedContentDigest'), artifact.contentDigest, 'source-observation-digest');
    one(observation, term('observedParserImplementation'), artifact.parserImplementation, 'source-observation-parser');
    one(observation, term('observedSyntaxKind'), artifact.syntaxKind, 'source-observation-syntax');
    one(observation, term('observedFormatKind'), artifact.formatKind, 'source-observation-format');
    if (run) one(observation, term('observedInCensusRun'), run, 'source-observation-run');
  }

  const expectedInputs = expected.inputs.map((input) => `urn:usf:censusobservationinput:i${sha256(input.path)}`);
  exactSubjects(term('CensusObservationInput'), expectedInputs, 'census-input-parity');
  for (const input of expected.inputs) {
    const subject = `urn:usf:censusobservationinput:i${sha256(input.path)}`;
    graph(subject, OBSERVED_GRAPH, 'census-input-graph');
    one(subject, term('observedInputPath'), input.path, 'census-input-path');
    one(subject, term('observedInputContentDigest'), input.contentDigest, 'census-input-digest');
    one(subject, term('observedInputByteCount'), input.byteCount, 'census-input-byte-count');
    exact(subject, term('observedInputRecordCount'), input.recordCount === null ? [] : [input.recordCount], 'census-input-record-count');
    if (run) { one(subject, term('observedInCensusRun'), run, 'census-input-run'); exact(run, term('hasCensusObservationInput'), expectedInputs, 'census-run-input-links'); }
  }

  const expectedShards = expected.parserShards.map((shard) => `urn:usf:censusparsershardobservation:s${sha256(shard.path)}`);
  exactSubjects(term('CensusParserShardObservation'), expectedShards, 'parser-shard-parity');
  for (const shard of expected.parserShards) {
    const subject = `urn:usf:censusparsershardobservation:s${sha256(shard.path)}`;
    graph(subject, OBSERVED_GRAPH, 'parser-shard-graph');
    one(subject, term('observedParserShardPath'), shard.path, 'parser-shard-path');
    one(subject, term('observedParserUniverse'), `urn:usf:sourceuniverse:${UNIVERSES[shard.universe]}`, 'parser-shard-universe');
    one(subject, term('observedParserRecordCount'), shard.recordCount, 'parser-shard-count');
    one(subject, term('observedCompressedContentDigest'), shard.compressedSha256, 'parser-shard-compressed-digest');
    one(subject, term('observedUncompressedContentDigest'), shard.uncompressedSha256, 'parser-shard-uncompressed-digest');
    if (run) { one(subject, term('observedInCensusRun'), run, 'parser-shard-run'); exact(run, term('hasCensusParserShardObservation'), expectedShards, 'census-run-parser-links'); }
  }

  const expectedRelationships = expected.relationshipRows.map((row) => `urn:usf:sourcerelationshipobservation:r${row.fullDigest}`);
  exactSubjects(term('SourceRelationshipObservation'), expectedRelationships, 'relationship-observation-parity');
  const expectedTargets = new Map();
  for (const row of expected.relationshipRows) {
    const { record, fullDigest, evidenceDigest } = row;
    const subject = `urn:usf:sourcerelationshipobservation:r${fullDigest}`;
    const sourceArtifact = expected.artifactByPath.get(record.source);
    const targetKey = `${record.targetKind}\0${record.target}`;
    const target = `urn:usf:sourcerelationshiptarget:t${sha256(targetKey)}`;
    expectedTargets.set(target, record);
    graph(subject, OBSERVED_GRAPH, 'relationship-observation-graph');
    one(subject, term('sourceRelationshipSource'), `urn:usf:sourceartefact:s${sourceArtifact?.artifactKey}`, 'relationship-source');
    one(subject, term('sourceRelationshipTarget'), target, 'relationship-target');
    one(subject, term('sourceRelationshipExtractionMethod'), record.extractionMethod, 'relationship-extraction');
    one(subject, term('sourceRelationshipType'), `urn:usf:sourcerelationshiptype:${controlled(record.relationshipType)}`, 'relationship-type');
    one(subject, term('sourceRelationshipResolved'), 'true', 'relationship-resolved');
    one(subject, term('sourceRelationshipEvidenceKind'), `urn:usf:sourcerelationshipevidencekind:${controlled(record.evidenceKind)}`, 'relationship-evidence-kind');
    const attributesValue = stableJson(record.attributes);
    const attributesDisclosure = disclosure(attributesValue);
    one(subject, term('sourceRelationshipAttributesDigest'), attributesDisclosure.digest, 'relationship-attributes-digest');
    one(subject, term('sourceRelationshipAttributesDisclosureStatus'), attributesDisclosure.status, 'relationship-attributes-disclosure-status');
    exact(subject, term('sourceRelationshipAttributes'), attributesDisclosure.status === DISCLOSED ? [attributesValue] : [], 'relationship-attributes');
    one(subject, term('sourceRelationshipConfidence'), stableJson(record.confidence), 'relationship-confidence');
    one(subject, term('sourceRelationshipRecordDigest'), fullDigest, 'relationship-record-digest');
    one(subject, term('relationshipEvidenceDigest'), evidenceDigest, 'relationship-evidence-digest');
    exact(subject, term('sourceRelationshipReasonCode'), record.reasonCodes, 'relationship-reason-codes');
    if (run) one(subject, term('observedInCensusRun'), run, 'relationship-run');
  }
  exactSubjects(term('SourceRelationshipTargetObservation'), [...expectedTargets.keys()], 'relationship-target-parity');
  for (const [subject, record] of expectedTargets) {
    graph(subject, OBSERVED_GRAPH, 'relationship-target-graph');
    const targetDisclosure = disclosure(record.target);
    one(subject, term('observedRelationshipTargetDigest'), targetDisclosure.digest, 'relationship-target-digest');
    one(subject, term('observedRelationshipTargetDisclosureStatus'), targetDisclosure.status, 'relationship-target-disclosure-status');
    exact(subject, term('observedRelationshipTarget'), targetDisclosure.status === DISCLOSED ? [record.target] : [], 'relationship-target-value');
    one(subject, term('observedRelationshipTargetKind'), `urn:usf:sourcerelationshiptargetkind:${controlled(record.targetKind)}`, 'relationship-target-kind');
    if (record.targetKind === 'artifact') one(subject, term('resolvesToSourceArtefact'), `urn:usf:sourceartefact:s${expected.artifactByPath.get(record.target)?.artifactKey}`, 'relationship-target-resolution');
    if (run) one(subject, term('observedInCensusRun'), run, 'relationship-target-run');
  }

  const expectedWorkObservations = expected.workPackages.map(({ record }) => workPackageObservationIri(record.key));
  exactSubjects(term('WorkPackageObservation'), expectedWorkObservations, 'work-package-observation-parity');
  const derivedPackageByKey = new Map();
  for (const { record, fullDigest } of expected.workPackages) {
    const observation = workPackageObservationIri(record.key);
    const expectedDerived = repositoryWorkPackageIri(record.key);
    graph(observation, OBSERVED_GRAPH, 'work-package-observation-graph');
    one(observation, term('workPackageKey'), record.key, 'work-package-key');
    one(observation, term('workPackageTitle'), record.title, 'work-package-title');
    one(observation, term('workPackageOutcomeClass'), record.outcomeClass, 'work-package-outcome');
    one(observation, term('workPackageRecordDigest'), fullDigest, 'work-package-digest');
    exact(observation, term('observedOwnedSourceArtefact'), record.artifactKeys.map((key) => `urn:usf:sourceartefact:s${key}`), 'work-package-source-ownership');
    exact(observation, term('observedOwnedCanonicalArtefact'), record.canonicalArtifactKeys, 'work-package-canonical-ownership');
    if (run) one(observation, term('observedInCensusRun'), run, 'work-package-run');
    const derived = triples.filter((row) => row.predicate === term('promotedFromWorkPackageObservation') && row.object === observation).map((row) => row.subject);
    if (derived.length !== 1) add(`derived-work-package-cardinality:${record.key}:${derived.length}`);
    else {
      if (derived[0] !== expectedDerived) add(`derived-work-package-identity:${record.key}:${derived[0]}`);
      derivedPackageByKey.set(record.key, derived[0]); graph(derived[0], DERIVED_GRAPH, 'derived-work-package-graph');
      if (!values(derived[0], RDF_TYPE).includes(term('RepositoryWorkPackage'))) add(`derived-work-package-type:${record.key}`);
      one(derived[0], term('promotedFromWorkPackageObservation'), observation, 'derived-work-package-observation');
      exact(derived[0], term('ownsObservedSourceArtefact'), record.artifactKeys.map((key) => `urn:usf:sourceartefact:s${key}`), 'derived-source-ownership');
      exact(derived[0], term('ownsCanonicalArtefact'), record.canonicalArtifactKeys, 'derived-canonical-ownership');
    }
  }
  exactSubjects(term('RepositoryWorkPackage'), expected.workPackages.map(({ record }) => repositoryWorkPackageIri(record.key)), 'derived-work-package-parity');

  const expectedDependencyObservations = expected.dependencies.map(({ record }) => dependencyObservationIri(record.dependencyKey));
  exactSubjects(term('WorkPackageDependencyObservation'), expectedDependencyObservations, 'dependency-observation-parity');
  const derivedDependencies = [];
  const expectedSatisfactionBases = [];
  const expectedActiveBlockers = [];
  let derivedRequiredPrerequisites = 0;
  let derivedSatisfiedPrerequisites = 0;
  for (const { record, fullDigest, relationshipMatches } of expected.dependencies) {
    const observation = dependencyObservationIri(record.dependencyKey);
    const expectedDerived = resolvedDependencyIri(record.dependencyKey);
    graph(observation, OBSERVED_GRAPH, 'dependency-observation-graph');
    one(observation, term('workPackageDependencyKey'), record.dependencyKey, 'dependency-key');
    one(observation, term('workPackageDependencySource'), workPackageObservationIri(record.source), 'dependency-source');
    one(observation, term('workPackageDependencyPrerequisite'), workPackageObservationIri(record.prerequisite), 'dependency-prerequisite');
    one(observation, term('workPackageDependencyRecordDigest'), fullDigest, 'dependency-record-digest');
    one(observation, term('workPackageDependencyType'), `urn:usf:workpackagedependencytype:${controlled(record.dependencyType)}`, 'dependency-type');
    one(observation, term('workPackageDependencyStatus'), `urn:usf:workpackagedependencystatus:${controlled(record.status)}`, 'dependency-status');
    one(observation, term('workPackageDependencyResolutionStatus'), `urn:usf:workpackagedependencyresolutionstatus:${controlled(record.resolutionStatus)}`, 'dependency-resolution-status');
    one(observation, term('workPackageDependencyReasonCode'), record.reasonCode, 'dependency-reason');
    one(observation, term('workPackageDependencyResolutionBasis'), stableJson(record.resolutionBasis), 'dependency-resolution-basis');
    exact(observation, term('workPackageDependencyEvidenceDigest'), record.repositoryRelationshipEvidence, 'dependency-evidence-digests');
    exact(observation, term('supportedBySourceRelationshipObservation'), relationshipMatches.map((digest) => `urn:usf:sourcerelationshipobservation:r${digest}`), 'dependency-evidence-links');
    if (run) one(observation, term('observedInCensusRun'), run, 'dependency-run');
    let satisfactionBasis = null;
    if (record.status === 'required-prerequisite') {
      const recomputed = independentlyRecomputedSatisfaction.get(record.dependencyKey);
      const satisfactionRecord = { ...record, satisfactionStatus: recomputed.status, satisfactionBasis: recomputed.basis };
      const basisDigest = satisfactionBasisDigest(satisfactionRecord);
      const basisName = `s${basisDigest}`;
      satisfactionBasis = `urn:usf:workpackagedependencysatisfactionbasisobservation:${basisName}`;
      expectedSatisfactionBases.push(satisfactionBasis);
      const satisfactionStatus = `urn:usf:dependencysatisfactionstatus:${controlled(recomputed.status)}`;
      one(observation, term('workPackageDependencySatisfactionSeed'), satisfactionStatus, 'dependency-satisfaction-seed');
      one(observation, term('hasWorkPackageDependencySatisfactionBasis'), satisfactionBasis, 'dependency-satisfaction-basis-link');
      graph(satisfactionBasis, OBSERVED_GRAPH, 'dependency-satisfaction-basis-graph');
      one(satisfactionBasis, term('canonicalName'), basisName, 'dependency-satisfaction-basis-name');
      one(satisfactionBasis, term('satisfactionBasisForWorkPackageDependency'), observation, 'dependency-satisfaction-basis-dependency');
      one(satisfactionBasis, term('observedDependencySatisfactionStatus'), satisfactionStatus, 'dependency-satisfaction-basis-status');
      one(satisfactionBasis, term('dependencySatisfactionBasisKind'), 'urn:usf:dependencysatisfactionbasiskind:resolveddirectrelationshipevidence', 'dependency-satisfaction-basis-kind');
      one(satisfactionBasis, term('satisfactionBasisRecordDigest'), basisDigest, 'dependency-satisfaction-basis-digest');
      exact(satisfactionBasis, term('satisfactionBasisRelationshipObservation'), relationshipMatches.map((digest) => `urn:usf:sourcerelationshipobservation:r${digest}`), 'dependency-satisfaction-basis-relationships');
      for (const field of SATISFACTION_COUNT_FIELDS) typedOne(satisfactionBasis, term(`satisfactionBasis${field[0].toUpperCase()}${field.slice(1)}`), recomputed.basis[field], XSD_NON_NEGATIVE_INTEGER, `dependency-satisfaction-${field}`);
      for (const field of SATISFACTION_BOOLEAN_FIELDS) typedOne(satisfactionBasis, term(`satisfactionBasis${field[0].toUpperCase()}${field.slice(1)}`), recomputed.basis[field], XSD_BOOLEAN, `dependency-satisfaction-${field}`);
      if (run) one(satisfactionBasis, term('observedInCensusRun'), run, 'dependency-satisfaction-basis-run');
    } else {
      exact(observation, term('workPackageDependencySatisfactionSeed'), [], 'coordination-dependency-satisfaction-seed');
      exact(observation, term('hasWorkPackageDependencySatisfactionBasis'), [], 'coordination-dependency-satisfaction-basis');
    }
    const derived = triples.filter((row) => row.predicate === term('derivedFromWorkPackageDependencyObservation') && row.object === observation).map((row) => row.subject);
    if (record.status !== 'required-prerequisite') {
      if (derived.length !== 0) add(`coordination-dependency-improperly-derived:${record.dependencyKey}:${derived.length}`);
      continue;
    }
    if (derived.length !== 1) { add(`derived-dependency-cardinality:${record.dependencyKey}:${derived.length}`); continue; }
    const subject = derived[0]; derivedDependencies.push(subject); graph(subject, DERIVED_GRAPH, 'derived-dependency-graph');
    if (subject !== expectedDerived) add(`derived-dependency-identity:${record.dependencyKey}:${subject}`);
    if (!values(subject, RDF_TYPE).includes(term('ResolvedWorkPackageDependency'))) add(`derived-dependency-type:${record.dependencyKey}`);
    one(subject, term('derivedFromWorkPackageDependencyObservation'), observation, 'derived-dependency-observation');
    one(subject, term('resolvedDependencySource'), derivedPackageByKey.get(record.source), 'derived-dependency-source');
    one(subject, term('resolvedDependencyPrerequisite'), derivedPackageByKey.get(record.prerequisite), 'derived-dependency-prerequisite');
    one(subject, term('resolvedDependencyStatus'), `urn:usf:workpackagedependencystatus:${record.status.replace(/[^a-z0-9]+/gi, '').toLowerCase()}`, 'derived-dependency-status');
    one(subject, term('resolvedDependencyType'), `urn:usf:workpackagedependencytype:${controlled(record.dependencyType)}`, 'derived-dependency-type-value');
    one(subject, term('dependencyResolutionState'), 'urn:usf:workpackagedependencyresolutionstatus:resolvedretained', 'derived-dependency-resolution');
    exact(subject, term('supportedBySourceRelationshipObservation'), relationshipMatches.map((digest) => `urn:usf:sourcerelationshipobservation:r${digest}`), 'derived-dependency-evidence');
    if (record.status === 'required-prerequisite') {
      derivedRequiredPrerequisites += 1;
      const recomputedStatus = independentlyRecomputedSatisfaction.get(record.dependencyKey).status;
      const status = `urn:usf:dependencysatisfactionstatus:${controlled(recomputedStatus)}`;
      one(subject, term('dependencySatisfactionStatus'), status, 'derived-dependency-satisfaction-status');
      one(subject, term('derivedFromDependencySatisfactionBasis'), satisfactionBasis, 'derived-dependency-satisfaction-basis');
      if (recomputedStatus === 'satisfied') derivedSatisfiedPrerequisites += 1;
      else {
        const blocker = subject.replace('resolvedworkpackagedependency:', 'activerepositorydependencyblocker:');
        expectedActiveBlockers.push(blocker);
        graph(blocker, DERIVED_GRAPH, 'active-dependency-blocker-graph');
        one(blocker, term('activeBlockerForResolvedDependency'), subject, 'active-dependency-blocker-dependency');
        one(blocker, term('activeBlockerFromSatisfactionBasis'), satisfactionBasis, 'active-dependency-blocker-basis');
      }
    } else {
      exact(subject, term('dependencySatisfactionStatus'), [], 'coordination-derived-dependency-satisfaction-status');
      exact(subject, term('derivedFromDependencySatisfactionBasis'), [], 'coordination-derived-dependency-satisfaction-basis');
    }
  }
  exactSubjects(term('ResolvedWorkPackageDependency'), requiredPrerequisites.map(({ record }) => resolvedDependencyIri(record.dependencyKey)), 'derived-dependency-parity');
  exactSubjects(term('RepositoryDependency'), requiredPrerequisites.map(({ record }) => resolvedDependencyIri(record.dependencyKey)), 'repository-dependency-parity');
  exactSubjects(term('WorkPackageDependencySatisfactionBasisObservation'), expectedSatisfactionBases, 'dependency-satisfaction-basis-parity');
  exactSubjects(term('ActiveRepositoryDependencyBlocker'), expectedActiveBlockers, 'active-dependency-blocker-parity');
  if (derivedRequiredPrerequisites !== expected.requiredPrerequisiteCount) add(`derived-required-prerequisite-count:${derivedRequiredPrerequisites}/${expected.requiredPrerequisiteCount}`);
  if (derivedSatisfiedPrerequisites !== satisfiedPrerequisiteCount) add(`derived-satisfied-prerequisite-count:${derivedSatisfiedPrerequisites}/${satisfiedPrerequisiteCount}`);

  const expectedLineageObservations = expected.lineage.map(({ fullDigest }) => `urn:usf:workpackagedependencylineageobservation:l${fullDigest}`);
  exactSubjects(term('WorkPackageDependencyLineageObservation'), expectedLineageObservations, 'lineage-observation-parity');
  const derivedLineage = [];
  for (const { record, fullDigest } of expected.lineage) {
    const observation = `urn:usf:workpackagedependencylineageobservation:l${fullDigest}`;
    graph(observation, OBSERVED_GRAPH, 'lineage-observation-graph');
    one(observation, term('dependencyLineageRecordDigest'), fullDigest, 'lineage-record-digest');
    one(observation, term('baselineDependencySourceKey'), record.baselineSource, 'lineage-baseline-source');
    one(observation, term('baselineDependencyPrerequisiteKey'), record.baselinePrerequisite, 'lineage-baseline-prerequisite');
    one(observation, term('dependencyLineageDisposition'), 'urn:usf:dependencylineagedisposition:retainedwithevidence', 'lineage-disposition');
    one(observation, term('dependencyLineageReason'), record.reason, 'lineage-reason');
    exact(observation, term('successorDependencySource'), record.successorSources.map(workPackageObservationIri), 'lineage-source-observations');
    exact(observation, term('successorDependencyPrerequisite'), record.successorPrerequisites.map(workPackageObservationIri), 'lineage-prerequisite-observations');
    if (run) one(observation, term('observedInCensusRun'), run, 'lineage-run');
    const derived = triples.filter((row) => row.predicate === term('derivedFromWorkPackageDependencyLineageObservation') && row.object === observation).map((row) => row.subject);
    if (derived.length !== 1) { add(`derived-lineage-cardinality:${fullDigest}:${derived.length}`); continue; }
    derivedLineage.push(derived[0]); graph(derived[0], DERIVED_GRAPH, 'derived-lineage-graph');
    if (!values(derived[0], RDF_TYPE).includes(term('RetainedWorkPackageDependencyLineage'))) add(`derived-lineage-type:${fullDigest}`);
    one(derived[0], term('derivedFromWorkPackageDependencyLineageObservation'), observation, 'derived-lineage-observation');
    exact(derived[0], term('retainedLineageSuccessorSource'), record.successorSources.map((key) => derivedPackageByKey.get(key)), 'derived-lineage-sources');
    exact(derived[0], term('retainedLineageSuccessorPrerequisite'), record.successorPrerequisites.map((key) => derivedPackageByKey.get(key)), 'derived-lineage-prerequisites');
  }
  exactSubjects(term('RetainedWorkPackageDependencyLineage'), derivedLineage, 'derived-lineage-parity');

  if (findingCount > findings.length) findings.push(`additional-findings:${findingCount - findings.length}`);
  return {
    id: 'repository-structure-materialization', status: findingCount ? 'fail' : 'pass', findings,
    facts: {
      relationshipCount: expected.relationshipRows.length, workPackageCount: expected.workPackages.length,
      dependencyCount: expected.dependencies.length, requiredPrerequisiteDependencyCount: expected.requiredPrerequisiteCount,
      resolvedPrerequisiteDependencyCount: resolvedPrerequisiteCount, satisfiedPrerequisiteDependencyCount: satisfiedPrerequisiteCount,
      activeBlockingDependencyCount: activeBlockingCount, satisfactionBasisCount: expectedSatisfactionBases.length,
      retainedLineageCount: expected.lineage.length, inputCount: expected.inputs.length, parserShardCount: expected.parserShards.length,
      findingCount,
    },
  };
}

export function auditRepositoryStructureMaterialization({ censusRoot, repositoryRoot }) {
  let expected;
  try { expected = expectedRepositoryStructure(censusRoot); }
  catch (error) { return { id: 'repository-structure-materialization', status: 'incomplete', findings: [`repository-structure-input-unreadable:${error.message}`], facts: {} }; }
  const registered = readRegisteredRepositoryStructure(repositoryRoot);
  return auditRepositoryStructureDataset({ triples: registered.triples, expected, initialFindings: registered.findings });
}

export const repositoryStructureInternals = { DERIVED_GRAPH, OBSERVED_GRAPH, recordDigest, relationshipEvidenceDigest, sha256, stableJson };
