import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { DataFactory, Parser, Store, Writer } from 'n3';

const { namedNode, literal, quad } = DataFactory;
const RDF_TYPE = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
const XSD_BOOLEAN = namedNode('http://www.w3.org/2001/XMLSchema#boolean');
const XSD_INTEGER = namedNode('http://www.w3.org/2001/XMLSchema#integer');
const XSD_NON_NEGATIVE_INTEGER = namedNode('http://www.w3.org/2001/XMLSchema#nonNegativeInteger');
const USF = 'urn:usf:ontology:';
const p = (local) => namedNode(`${USF}${local}`);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const UNIVERSES = Object.freeze({
  'repository-output': 'canonicalrepository',
  'v2-compiler-implementation': 'compilerimplementation',
  'v2-graph-authority': 'graphauthority',
  'v2-support-provisioning': 'supportprovisioning',
});

const FAMILY_ROLES = Object.freeze({
  automation: 'automation',
  'documentation-assets': 'documentation',
  implementation: 'implementation',
  'machine-semantics': 'machinesemantics',
  'proof-evidence': 'proofevidence',
  'repository-governance': 'repositorygovernance',
  'runtime-topology': 'runtimetopology',
  'v2-support': 'supportprovisioning',
  verification: 'verification',
});

const EQUIVALENCE_FIXTURE_EXACT_PATHS = new Set([
  'tests/packages/supply-chain/supply-chain-planted-defects.json',
]);

// Kept byte-for-byte aligned with compiler.js CONTAMINATION_PATTERNS. The
// compiler test suite asserts parity so observed disclosure cannot silently
// weaken when the transaction contamination boundary changes.
const OBSERVATION_CONTAMINATION_PATTERNS = Object.freeze([
  'linear\\.app',
  'github\\.com',
  'gitlab\\.com',
  'USF-[0-9]',
  'ADR-[0-9]',
  'issueId',
  'projectId',
  'branchName',
  'commitSha',
  'refs/heads',
]);
const OBSERVATION_CONTAMINATION_RE = new RegExp(OBSERVATION_CONTAMINATION_PATTERNS.join('|'));
const DISCLOSED = 'urn:usf:observationdisclosurestatus:disclosed';
const WITHHELD_PROHIBITED_METADATA = 'urn:usf:observationdisclosurestatus:withheldprohibitedmetadata';
const SATISFACTION_COUNT_FIELDS = Object.freeze([
  'exactEvidenceHashCount', 'currentRelationshipHashCount', 'structurallyProvenRelationshipHashCount',
  'directionMatchedRelationshipHashCount', 'currentPrerequisiteArtifactHashCount', 'currentPrerequisiteArtifactCount',
]);
const SATISFACTION_BOOLEAN_FIELDS = Object.freeze([
  'sourceEndpointExists', 'prerequisiteEndpointExists', 'edgeSurvivedTransitiveReduction', 'requiredPrerequisiteGraphAcyclic',
]);
const SATISFACTION_BASIS_FIELDS = Object.freeze([...SATISFACTION_COUNT_FIELDS, ...SATISFACTION_BOOLEAN_FIELDS].sort());

function isEquivalenceFixture(artifact) {
  if (artifact.universe !== 'repository-output') return false;
  if (EQUIVALENCE_FIXTURE_EXACT_PATHS.has(artifact.path)) return true;
  return artifact.path.split('/').some((segment) =>
    segment === 'fixtures' || segment === 'planted-defects' || segment.endsWith('-planted-defects')
  );
}

function readJsonl(path) {
  const lines = readFileSync(path, 'utf8').split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  if (lines.some((line) => line.length === 0)) throw new Error(`JSONL contains an empty record: ${path}`);
  return lines.map((line, index) => {
    try { return JSON.parse(line); } catch (error) { throw new Error(`invalid JSONL record ${index + 1} in ${path}: ${error.message}`, { cause: error }); }
  });
}

function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch (error) { throw new Error(`invalid JSON in ${path}: ${error.message}`, { cause: error }); }
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function requireString(value, label) {
  requireValue(typeof value === 'string' && value.length > 0, `${label} must be a non-empty string`);
  return value;
}

function controlled(value) {
  return requireString(value, 'controlled value').toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function recordDigest(record) {
  return sha256(stableJson(record));
}

function relationshipEvidenceDigest(record) {
  return sha256(`${record.source}\0${record.relationshipType}\0${record.target}`);
}

function observationDisclosure(value) {
  requireString(value, 'observed disclosure value');
  const withheld = OBSERVATION_CONTAMINATION_RE.test(value);
  return Object.freeze({
    digest: sha256(value),
    status: withheld ? WITHHELD_PROHIBITED_METADATA : DISCLOSED,
    disclosedValue: withheld ? null : value,
  });
}

function workPackageObservationName(key) {
  return `w${key.slice('work-package-'.length)}`;
}

function workPackageDependencyObservationName(key) {
  return `d${key.slice('dependency-'.length)}`;
}

function validateConfidence(confidence, label) {
  requireValue(confidence && typeof confidence === 'object' && !Array.isArray(confidence), `${label} confidence must be an object`);
  requireString(confidence.level, `${label} confidence level`);
  requireValue(Number.isFinite(confidence.score) && confidence.score >= 0 && confidence.score <= 1, `${label} confidence score must be between zero and one`);
  requireValue(Array.isArray(confidence.reasons) && confidence.reasons.every((reason) => typeof reason === 'string' && reason.length > 0), `${label} confidence reasons must be strings`);
}

function requiredPrerequisiteDependenciesAreAcyclic(dependencies) {
  const edges = new Map();
  for (const record of dependencies.filter((candidate) => candidate.status === 'required-prerequisite')) {
    if (!edges.has(record.source)) edges.set(record.source, []);
    edges.get(record.source).push(record.prerequisite);
  }
  const active = new Set();
  const complete = new Set();
  const visit = (node) => {
    if (active.has(node)) return false;
    if (complete.has(node)) return true;
    active.add(node);
    for (const target of edges.get(node) ?? []) if (!visit(target)) return false;
    active.delete(node);
    complete.add(node);
    return true;
  };
  return [...edges.keys()].every(visit);
}

function validateDependencySatisfaction(record, recomputed = null) {
  const hasStatus = Object.hasOwn(record, 'satisfactionStatus');
  const hasBasis = Object.hasOwn(record, 'satisfactionBasis');
  if (record.status === 'coordination') {
    requireValue(!hasStatus && !hasBasis, `coordination dependency must not claim satisfaction: ${record.dependencyKey}`);
    return null;
  }
  requireValue(record.status === 'required-prerequisite', `dependency satisfaction is only valid for a required prerequisite: ${record.dependencyKey}`);
  requireValue(hasStatus && hasBasis, `required prerequisite requires satisfaction status and basis: ${record.dependencyKey}`);
  requireValue(record.satisfactionStatus === 'satisfied' || record.satisfactionStatus === 'unsatisfied', `invalid required prerequisite satisfaction status: ${record.dependencyKey}`);
  requireValue(record.satisfactionBasis && typeof record.satisfactionBasis === 'object' && !Array.isArray(record.satisfactionBasis), `invalid required prerequisite satisfaction basis: ${record.dependencyKey}`);
  requireValue(stableJson(Object.keys(record.satisfactionBasis).sort()) === stableJson(SATISFACTION_BASIS_FIELDS), `required prerequisite satisfaction basis fields differ: ${record.dependencyKey}`);
  for (const field of SATISFACTION_COUNT_FIELDS) requireValue(Number.isInteger(record.satisfactionBasis[field]) && record.satisfactionBasis[field] >= 0, `invalid satisfaction count ${field}: ${record.dependencyKey}`);
  for (const field of SATISFACTION_BOOLEAN_FIELDS) requireValue(typeof record.satisfactionBasis[field] === 'boolean', `invalid satisfaction boolean ${field}: ${record.dependencyKey}`);
  const basis = record.satisfactionBasis;
  const satisfied = basis.exactEvidenceHashCount > 0
    && ['currentRelationshipHashCount', 'structurallyProvenRelationshipHashCount', 'directionMatchedRelationshipHashCount', 'currentPrerequisiteArtifactHashCount']
      .every((field) => basis[field] === basis.exactEvidenceHashCount)
    && basis.currentPrerequisiteArtifactCount > 0
    && SATISFACTION_BOOLEAN_FIELDS.every((field) => basis[field] === true);
  requireValue(record.satisfactionStatus === (satisfied ? 'satisfied' : 'unsatisfied'), `required prerequisite satisfaction status contradicts basis: ${record.dependencyKey}`);
  if (recomputed) {
    for (const field of SATISFACTION_COUNT_FIELDS) requireValue(basis[field] === recomputed[field], `required prerequisite satisfaction count differs from current evidence ${field}: ${record.dependencyKey}`);
    for (const field of SATISFACTION_BOOLEAN_FIELDS) requireValue(basis[field] === recomputed[field], `required prerequisite satisfaction boolean differs from current evidence ${field}: ${record.dependencyKey}`);
    const recomputedSatisfied = recomputed.exactEvidenceHashCount > 0
      && ['currentRelationshipHashCount', 'structurallyProvenRelationshipHashCount', 'directionMatchedRelationshipHashCount', 'currentPrerequisiteArtifactHashCount']
        .every((field) => recomputed[field] === recomputed.exactEvidenceHashCount)
      && recomputed.currentPrerequisiteArtifactCount > 0
      && SATISFACTION_BOOLEAN_FIELDS.every((field) => recomputed[field] === true);
    requireValue(record.satisfactionStatus === (recomputedSatisfied ? 'satisfied' : 'unsatisfied'), `required prerequisite satisfaction status differs from current evidence: ${record.dependencyKey}`);
  }
  return { status: record.satisfactionStatus, basis };
}

function dependencySatisfactionBasisDigest(record) {
  return sha256(stableJson({
    dependencyKey: record.dependencyKey,
    satisfactionStatus: record.satisfactionStatus,
    satisfactionBasis: record.satisfactionBasis,
    repositoryRelationshipEvidence: [...record.repositoryRelationshipEvidence].sort(),
  }));
}

function inputObservation(path, relativePath, format) {
  const content = readFileSync(path);
  let recordCount = null;
  if (format === 'jsonl') recordCount = readJsonl(path).length;
  return { path: relativePath, contentDigest: sha256(content), byteCount: content.length, recordCount };
}

function exactlyOne(store, subject, predicate, label) {
  const values = store.getObjects(subject, predicate, null);
  if (values.length !== 1) throw new Error(`${label} requires exactly one value for ${subject.value}; observed ${values.length}`);
  return values[0];
}

function sourceSemanticBindings(manifest) {
  const store = new Store();
  for (const entry of [...manifest.definitions, ...manifest.authored]) {
    store.addQuads(new Parser({ format: entry.contentType, baseIRI: manifest.baseIri }).parse(readFileSync(entry.path, 'utf8')));
  }
  const bindings = new Map();
  for (const binding of store.getSubjects(RDF_TYPE, namedNode(`${USF}SourceSemanticBinding`), null)) {
    const source = exactlyOne(store, binding, p('sourceBindingSource'), 'source semantic binding source');
    const path = exactlyOne(store, binding, p('sourceBindingPath'), 'source semantic binding path').value;
    const contentDigest = exactlyOne(store, binding, p('sourceBindingContentDigest'), 'source semantic binding content digest').value;
    const match = source.value.match(/^urn:usf:sourceartefact:s([0-9a-f]{64})$/);
    if (!match || !/^[0-9a-f]{64}$/.test(contentDigest)) throw new Error(`invalid source semantic binding identity: ${binding.value}`);
    const targets = store.getObjects(binding, p('sourceBindingTarget'), null).filter((term) => term.termType === 'NamedNode').map((term) => term.value).sort();
    if (!targets.length || bindings.has(match[1])) throw new Error(`ambiguous or empty source semantic binding: ${binding.value}`);
    bindings.set(match[1], { binding: binding.value, path, contentDigest, targets });
  }
  return bindings;
}

function authoredArtefactIris(manifest) {
  const result = new Set();
  for (const entry of [...manifest.definitions, ...manifest.authored]) {
    const store = new Store(new Parser({ format: entry.contentType, baseIRI: manifest.baseIri }).parse(readFileSync(entry.path, 'utf8')));
    for (const subject of store.getSubjects(RDF_TYPE, p('Artefact'), null)) result.add(subject.value);
  }
  return result;
}

function graphRoleByPath(manifest) {
  const result = new Map();
  const add = (entries, role) => {
    for (const entry of entries) if (entry.file) result.set(`v2/usf/graph/${entry.file}`, role);
  };
  add(manifest.definitions, 'semanticdefinition');
  add(manifest.authored, 'authoredsemantics');
  add(manifest.shapes, 'validatorshape');
  add(manifest.rules, 'derivationrule');
  add(manifest.derived, 'derivedprojection');
  result.set('v2/usf/graph/manifest.yaml', 'authoritymanifest');
  return result;
}

function rolesFor(artifact, registeredRoles, manifest) {
  const roles = new Set();
  const familyRole = FAMILY_ROLES[artifact.artifactFamily];
  if (familyRole) roles.add(familyRole);
  if (registeredRoles.has(artifact.path)) roles.add(registeredRoles.get(artifact.path));
  const fixtureRoots = [manifest.fixtures?.conforming, manifest.fixtures?.defects].filter(Boolean)
    .map((root) => `v2/usf/graph/${root}/`);
  if (fixtureRoots.some((root) => artifact.path.startsWith(root))) roles.add('fixture');
  if (isEquivalenceFixture(artifact)) roles.add('equivalencefixture');
  if (artifact.path.endsWith('/.gitkeep') || artifact.path === '.gitkeep') roles.add('placeholder');
  if (artifact.universe === 'v2-support-provisioning' && !roles.has('placeholder')) roles.add('supportprovisioning');
  return [...roles].sort();
}

function observationRows(artifacts, mappings, manifest, semanticBindings = new Map()) {
  const mappingByKey = new Map(mappings.map((record) => [record.artifactKey, record]));
  const registeredRoles = graphRoleByPath(manifest);
  const carrierPaths = new Set([
    ...manifest.observed.filter((entry) => entry.file).map((entry) => `v2/usf/graph/${entry.file}`),
    ...manifest.derived.filter((entry) => entry.file).map((entry) => `v2/usf/graph/${entry.file}`),
  ]);
  const rows = artifacts.filter((artifact) => !carrierPaths.has(artifact.path)).map((artifact) => {
    const universe = UNIVERSES[artifact.universe];
    if (!universe) throw new Error(`unknown source universe: ${artifact.universe}`);
    const roles = rolesFor(artifact, registeredRoles, manifest);
    if (!roles.length) throw new Error(`source observation has no structural role: ${artifact.artifactKey}`);
    const binding = semanticBindings.get(artifact.artifactKey);
    if (binding && (binding.path !== artifact.path || binding.contentDigest !== artifact.contentDigest)) {
      throw new Error(`source semantic binding does not match current artifact: ${binding.binding}`);
    }
    const semanticReferences = [...new Set([
      ...(mappingByKey.get(artifact.artifactKey)?.matchedResources ?? []),
      ...(binding?.targets ?? []),
    ])].sort();
    return {
      artifactKey: artifact.artifactKey,
      path: artifact.path,
      contentDigest: artifact.contentDigest,
      fileMode: artifact.fileMode,
      parserImplementation: requireString(artifact.parserImplementation, `parser implementation for ${artifact.artifactKey}`),
      syntaxKind: requireString(artifact.syntaxKind, `syntax kind for ${artifact.artifactKey}`),
      formatKind: requireString(artifact.formatKind, `format kind for ${artifact.artifactKey}`),
      universe,
      roles,
      semanticReferences,
    };
  }).sort((a, b) => a.artifactKey.localeCompare(b.artifactKey));
  const setDigest = sha256(rows.map((row) => JSON.stringify(row)).join('\n'));
  return { rows, setDigest, carrierPaths: [...carrierPaths].sort() };
}

function validateParserProvenance(censusRoot, parserManifest, artifacts, universes) {
  requireValue(parserManifest?.formatVersion === 1 && parserManifest.encoding === 'gzip-jsonl', 'unsupported parser-results manifest');
  requireValue(Array.isArray(parserManifest.shards) && parserManifest.shards.length > 0, 'parser-results manifest requires shards');
  const shards = [...parserManifest.shards].sort((left, right) => left.path.localeCompare(right.path));
  const uncompressed = [];
  const seenUniverses = new Set();
  for (const shard of shards) {
    for (const field of ['path', 'universe', 'compressedSha256', 'uncompressedSha256', 'firstPath', 'lastPath']) requireString(shard[field], `parser shard ${field}`);
    requireValue(!seenUniverses.has(shard.universe), `duplicate parser shard universe: ${shard.universe}`);
    seenUniverses.add(shard.universe);
    requireValue(Number.isInteger(shard.recordCount) && shard.recordCount > 0, `invalid parser shard record count: ${shard.path}`);
    const compressed = readFileSync(join(censusRoot, shard.path));
    requireValue(compressed.length === shard.compressedBytes && sha256(compressed) === shard.compressedSha256, `parser shard compressed integrity mismatch: ${shard.path}`);
    const expanded = gunzipSync(compressed);
    requireValue(expanded.length === shard.uncompressedBytes && sha256(expanded) === shard.uncompressedSha256, `parser shard uncompressed integrity mismatch: ${shard.path}`);
    const parsedCount = expanded.toString('utf8').split(/\r?\n/).filter(Boolean).length;
    requireValue(parsedCount === shard.recordCount, `parser shard record-count mismatch: ${shard.path}`);
    requireValue(universes.universeCounts?.[shard.universe] === shard.recordCount, `parser shard universe-count mismatch: ${shard.universe}`);
    uncompressed.push(expanded);
  }
  const aggregate = Buffer.concat(uncompressed);
  requireValue(parserManifest.aggregate?.recordCount === artifacts.length, 'parser aggregate/artifact count mismatch');
  requireValue(parserManifest.aggregate.recordCount === shards.reduce((sum, shard) => sum + shard.recordCount, 0), 'parser aggregate/shard count mismatch');
  requireValue(parserManifest.aggregate.uncompressedBytes === aggregate.length && parserManifest.aggregate.uncompressedSha256 === sha256(aggregate), 'parser aggregate integrity mismatch');
  return shards;
}

function censusObservationModel({ rows, relationships, workPackageDocument, dependencies, dependencyLineage, parserManifest, summary, universes, inputs, parserShards, authoredArtefacts = new Set() }) {
  rows = [...rows].sort((left, right) => left.artifactKey.localeCompare(right.artifactKey));
  parserShards = [...parserShards].sort((left, right) => left.path.localeCompare(right.path));
  requireValue(summary.artifactCount === rows.length, `summary artifact count mismatch: ${summary.artifactCount}/${rows.length}`);
  requireValue(summary.relationshipCount === relationships.length, `summary relationship count mismatch: ${summary.relationshipCount}/${relationships.length}`);
  requireValue(summary.workPackageCount === workPackageDocument?.workPackages?.length, 'summary work-package count mismatch');
  requireValue(summary.requiredPrerequisiteRelationshipCount + summary.coordinationRelationshipCount === dependencies.length, 'summary dependency count mismatch');
  requireValue(summary.blockingRelationshipCount === 0, 'summary must not classify satisfied prerequisites as blocking relationships');
  for (const field of ['requiredPrerequisiteRelationshipCount', 'resolvedPrerequisiteRelationshipCount', 'satisfiedPrerequisiteRelationshipCount', 'activeBlockingRelationshipCount', 'blockingRelationshipCount']) {
    requireValue(Number.isInteger(summary[field]) && summary[field] >= 0, `summary ${field} must be a non-negative integer`);
  }
  requireValue(stableJson(summary.universeCounts) === stableJson(universes.universeCounts), 'summary/universes count mismatch');
  for (const field of ['repositoryUniverseDigest', 'v2CompilerUniverseDigest', 'v2GraphUniverseDigest', 'v2SupportUniverseDigest']) {
    requireValue(summary[field] === universes[field] && /^[0-9a-f]{64}$/.test(summary[field]), `summary/universes digest mismatch: ${field}`);
  }

  const sourceByKey = new Map(rows.map((row) => [row.artifactKey, row]));
  const sourceByPath = new Map(rows.map((row) => [row.path, row]));
  requireValue(sourceByKey.size === rows.length && sourceByPath.size === rows.length, 'source observations require unique keys and paths');
  const relationshipRecords = [];
  const relationshipsByEvidenceDigest = new Map();
  const fullRelationshipDigests = new Set();
  for (const record of relationships) {
    for (const field of ['source', 'target', 'relationshipType', 'targetKind', 'evidenceKind', 'extractionMethod']) requireString(record[field], `relationship ${field}`);
    requireValue(record.resolved === true, `relationship is not resolved: ${record.source} -> ${record.target}`);
    requireValue(sourceByPath.has(record.source), `relationship source endpoint is missing: ${record.source}`);
    if (record.targetKind === 'artifact') requireValue(sourceByPath.has(record.target), `relationship artifact target endpoint is missing: ${record.target}`);
    requireValue(record.attributes && typeof record.attributes === 'object' && !Array.isArray(record.attributes), `relationship attributes must be an object: ${record.source}`);
    requireValue(Array.isArray(record.reasonCodes) && record.reasonCodes.length > 0 && record.reasonCodes.every((reason) => typeof reason === 'string' && reason.length > 0), `relationship reason codes are missing: ${record.source}`);
    validateConfidence(record.confidence, `relationship ${record.source}`);
    const fullDigest = recordDigest(record);
    requireValue(!fullRelationshipDigests.has(fullDigest), `duplicate full relationship record: ${fullDigest}`);
    fullRelationshipDigests.add(fullDigest);
    const evidenceDigest = relationshipEvidenceDigest(record);
    const row = {
      record,
      fullDigest,
      evidenceDigest,
      targetDisclosure: observationDisclosure(record.target),
      attributesDisclosure: observationDisclosure(stableJson(record.attributes)),
    };
    relationshipRecords.push(row);
    if (!relationshipsByEvidenceDigest.has(evidenceDigest)) relationshipsByEvidenceDigest.set(evidenceDigest, []);
    relationshipsByEvidenceDigest.get(evidenceDigest).push(row);
  }
  relationshipRecords.sort((left, right) => left.fullDigest.localeCompare(right.fullDigest));

  requireValue(workPackageDocument && Array.isArray(workPackageDocument.workPackages) && workPackageDocument.ownership && typeof workPackageDocument.ownership === 'object', 'invalid work-packages document');
  const workPackages = [...workPackageDocument.workPackages].sort((left, right) => left.key.localeCompare(right.key));
  const workPackageByKey = new Map();
  for (const record of workPackages) {
    requireValue(/^work-package-[0-9a-f]{20}$/.test(record.key), `invalid work-package key: ${record.key}`);
    requireValue(!workPackageByKey.has(record.key), `duplicate work-package key: ${record.key}`);
    requireString(record.title, `work-package title ${record.key}`);
    requireString(record.outcomeClass, `work-package outcome ${record.key}`);
    requireValue(Array.isArray(record.artifactKeys), `work-package artifactKeys must be an array: ${record.key}`);
    for (const artifactKey of record.artifactKeys) requireValue(sourceByKey.has(artifactKey), `work-package artifact endpoint is missing: ${record.key}/${artifactKey}`);
    requireValue(Array.isArray(record.canonicalArtifactKeys), `work-package canonicalArtifactKeys must be an array: ${record.key}`);
    for (const artefactIri of record.canonicalArtifactKeys) requireValue(authoredArtefacts.has(artefactIri), `work-package canonical artefact endpoint is missing: ${record.key}/${artefactIri}`);
    requireValue(stableJson([...record.artifactKeys].sort()) === stableJson([...(record.primaryOwnership?.artifactKeys ?? [])].sort()), `work-package primary artifact ownership mismatch: ${record.key}`);
    requireValue(stableJson([...record.canonicalArtifactKeys].sort()) === stableJson([...(record.primaryOwnership?.canonicalArtifactKeys ?? [])].sort()), `work-package canonical ownership mismatch: ${record.key}`);
    workPackageByKey.set(record.key, { record, fullDigest: recordDigest(record) });
  }
  requireValue(Array.isArray(workPackageDocument.ownership.artifacts) && workPackageDocument.ownership.artifacts.length === rows.length, 'work-package ownership/source count mismatch');
  const observedOwnership = new Map();
  for (const ownership of workPackageDocument.ownership.artifacts) {
    requireValue(sourceByKey.has(ownership.ownedKey), `ownership source endpoint is missing: ${ownership.ownedKey}`);
    requireValue(workPackageByKey.has(ownership.primaryWorkPackage), `ownership package endpoint is missing: ${ownership.primaryWorkPackage}`);
    requireValue(!observedOwnership.has(ownership.ownedKey), `duplicate source ownership: ${ownership.ownedKey}`);
    observedOwnership.set(ownership.ownedKey, ownership.primaryWorkPackage);
  }
  for (const [key, row] of workPackageByKey) for (const artifactKey of row.record.artifactKeys) {
    requireValue(observedOwnership.get(artifactKey) === key, `work-package ownership index mismatch: ${artifactKey}`);
  }
  requireValue(observedOwnership.size === sourceByKey.size, 'work-package ownership does not cover every source artefact');
  requireValue(Array.isArray(workPackageDocument.ownership.canonicalArtifacts), 'canonical artefact ownership must be an array');
  const canonicalOwnership = new Map();
  for (const ownership of workPackageDocument.ownership.canonicalArtifacts) {
    requireValue(authoredArtefacts.has(ownership.ownedKey), `canonical ownership artefact endpoint is missing: ${ownership.ownedKey}`);
    requireValue(workPackageByKey.has(ownership.primaryWorkPackage), `canonical ownership package endpoint is missing: ${ownership.primaryWorkPackage}`);
    requireValue(!canonicalOwnership.has(ownership.ownedKey), `duplicate canonical artefact ownership: ${ownership.ownedKey}`);
    canonicalOwnership.set(ownership.ownedKey, ownership.primaryWorkPackage);
  }
  for (const [key, row] of workPackageByKey) for (const artefactIri of row.record.canonicalArtifactKeys) {
    requireValue(canonicalOwnership.get(artefactIri) === key, `work-package canonical ownership index mismatch: ${artefactIri}`);
  }
  requireValue(canonicalOwnership.size === workPackages.reduce((sum, record) => sum + record.canonicalArtifactKeys.length, 0), 'canonical ownership index contains unscoped artefacts');

  const dependencyRecords = [];
  const dependencyKeys = new Set();
  let requiredPrerequisites = 0;
  let coordination = 0;
  let resolvedPrerequisites = 0;
  let satisfiedPrerequisites = 0;
  let activeBlocking = 0;
  const requiredPrerequisiteGraphAcyclic = requiredPrerequisiteDependenciesAreAcyclic(dependencies);
  for (const record of dependencies) {
    requireValue(/^dependency-[0-9a-f]{64}$/.test(record.dependencyKey), `invalid dependency key: ${record.dependencyKey}`);
    requireValue(!dependencyKeys.has(record.dependencyKey), `duplicate dependency key: ${record.dependencyKey}`);
    dependencyKeys.add(record.dependencyKey);
    requireValue(workPackageByKey.has(record.source) && workPackageByKey.has(record.prerequisite), `dependency endpoint is missing: ${record.dependencyKey}`);
    requireString(record.dependencyType, `dependency type ${record.dependencyKey}`);
    requireString(record.reasonCode, `dependency reason ${record.dependencyKey}`);
    requireValue(record.resolutionStatus === 'resolved-retained', `dependency is not resolved-retained: ${record.dependencyKey}`);
    requireValue(record.status === 'required-prerequisite' || record.status === 'coordination', `invalid dependency status: ${record.dependencyKey}`);
    let satisfaction = validateDependencySatisfaction(record);
    requireValue(record.resolutionBasis?.cycleCheck === (record.status === 'required-prerequisite' ? 'required-prerequisite-dag-verified' : 'not-applicable-coordination'), `dependency cycle-check basis contradicts status: ${record.dependencyKey}`);
    validateConfidence(record.confidence, `dependency ${record.dependencyKey}`);
    const evidenceFields = ['semanticEvidence', 'artifactEvidence', 'repositoryRelationshipEvidence', 'proofEquivalenceEvidence', 'migrationEvidence'];
    requireValue(evidenceFields.every((field) => Array.isArray(record[field])), `dependency evidence fields must be arrays: ${record.dependencyKey}`);
    requireValue(evidenceFields.some((field) => record[field].length > 0), `dependency has no evidence: ${record.dependencyKey}`);
    const countNames = { semanticEvidence: 'semantic', artifactEvidence: 'artifact', repositoryRelationshipEvidence: 'repository-relationship', proofEquivalenceEvidence: 'proof-equivalence', migrationEvidence: 'migration' };
    for (const field of evidenceFields) requireValue(record[field].length === record.resolutionBasis?.evidenceCounts?.[countNames[field]], `dependency evidence count mismatch: ${record.dependencyKey}/${field}`);
    const relationshipMatches = [];
    const matchedRows = [];
    for (const digest of record.repositoryRelationshipEvidence) {
      requireValue(/^[0-9a-f]{64}$/.test(digest), `invalid relationship evidence digest: ${record.dependencyKey}`);
      const matches = relationshipsByEvidenceDigest.get(digest) ?? [];
      requireValue(record.status === 'required-prerequisite' ? matches.length === 1 : matches.length > 0, `dependency relationship evidence must resolve ${record.status === 'required-prerequisite' ? 'exactly once' : 'at least once'}: ${record.dependencyKey}/${digest}`);
      matchedRows.push(...matches);
      relationshipMatches.push(...matches.map((match) => match.fullDigest));
    }
    if (record.status === 'required-prerequisite') {
      const sourceArtifacts = new Set(workPackageByKey.get(record.source).record.artifactKeys);
      const prerequisiteArtifacts = new Set(workPackageByKey.get(record.prerequisite).record.artifactKeys);
      const uniqueEvidence = new Set(record.repositoryRelationshipEvidence);
      const uniqueMatches = new Set(relationshipMatches);
      requireValue(uniqueEvidence.size === record.repositoryRelationshipEvidence.length, `required prerequisite contains duplicate relationship evidence: ${record.dependencyKey}`);
      requireValue(uniqueMatches.size === record.repositoryRelationshipEvidence.length, `required prerequisite relationship link count differs from exact evidence: ${record.dependencyKey}`);
      const currentRelationships = [];
      const structurallyProven = [];
      const directionMatched = [];
      const currentPrerequisiteHashes = [];
      const currentPrerequisiteArtifacts = new Set();
      for (const match of matchedRows) {
        const relationship = match.record;
        requireValue(relationship.resolved === true, `required prerequisite relationship is unresolved: ${record.dependencyKey}/${match.evidenceDigest}`);
        requireValue(relationship.targetKind === 'artifact', `required prerequisite relationship target is not an artifact: ${record.dependencyKey}/${match.evidenceDigest}`);
        requireValue(relationship.evidenceKind === 'structurally-proven', `required prerequisite relationship is not structurally proven: ${record.dependencyKey}/${match.evidenceDigest}`);
        const sourceRow = sourceByPath.get(relationship.source);
        const targetRow = sourceByPath.get(relationship.target);
        requireValue(sourceRow && targetRow, `required prerequisite relationship endpoint is not current: ${record.dependencyKey}/${match.evidenceDigest}`);
        currentRelationships.push(match);
        structurallyProven.push(match);
        requireValue(sourceArtifacts.has(sourceRow.artifactKey), `required prerequisite relationship source ownership mismatch: ${record.dependencyKey}/${match.evidenceDigest}`);
        requireValue(prerequisiteArtifacts.has(targetRow.artifactKey), `required prerequisite relationship prerequisite ownership mismatch: ${record.dependencyKey}/${match.evidenceDigest}`);
        directionMatched.push(match);
        requireValue(/^[0-9a-f]{64}$/.test(targetRow.contentDigest), `required prerequisite artifact has no current digest: ${record.dependencyKey}/${targetRow.artifactKey}`);
        currentPrerequisiteHashes.push(match);
        currentPrerequisiteArtifacts.add(targetRow.artifactKey);
      }
      const recomputed = {
        exactEvidenceHashCount: record.repositoryRelationshipEvidence.length,
        currentRelationshipHashCount: currentRelationships.length,
        structurallyProvenRelationshipHashCount: structurallyProven.length,
        directionMatchedRelationshipHashCount: directionMatched.length,
        currentPrerequisiteArtifactHashCount: currentPrerequisiteHashes.length,
        currentPrerequisiteArtifactCount: currentPrerequisiteArtifacts.size,
        sourceEndpointExists: workPackageByKey.has(record.source),
        prerequisiteEndpointExists: workPackageByKey.has(record.prerequisite),
        edgeSurvivedTransitiveReduction: record.resolutionBasis?.transitiveReduction === 'retained-direct-edge',
        requiredPrerequisiteGraphAcyclic,
      };
      satisfaction = validateDependencySatisfaction(record, recomputed);
      requiredPrerequisites += 1;
      if (record.resolutionStatus === 'resolved-retained') resolvedPrerequisites += 1;
      if (satisfaction.status === 'satisfied') satisfiedPrerequisites += 1; else activeBlocking += 1;
    } else coordination += 1;
    dependencyRecords.push({ record, fullDigest: recordDigest(record), relationshipMatches: [...new Set(relationshipMatches)].sort(), satisfaction });
  }
  requireValue(requiredPrerequisites === summary.requiredPrerequisiteRelationshipCount && coordination === summary.coordinationRelationshipCount, 'dependency status counts do not match summary');
  requireValue(resolvedPrerequisites === summary.resolvedPrerequisiteRelationshipCount, 'resolved prerequisite dependency count does not match summary');
  requireValue(satisfiedPrerequisites === summary.satisfiedPrerequisiteRelationshipCount, 'satisfied prerequisite dependency count does not match summary');
  requireValue(activeBlocking === summary.activeBlockingRelationshipCount, 'active blocking dependency count does not match summary');
  requireValue(satisfiedPrerequisites + activeBlocking === resolvedPrerequisites, 'resolved prerequisite dependency satisfaction partition is incomplete');
  requireValue(activeBlocking === 0, 'active blocking dependency remains in the definitive census');
  dependencyRecords.sort((left, right) => left.record.dependencyKey.localeCompare(right.record.dependencyKey));

  requireValue(Array.isArray(dependencyLineage), 'dependency lineage must be an array');
  const lineageDistribution = Object.create(null);
  for (const record of dependencyLineage) lineageDistribution[record.disposition] = (lineageDistribution[record.disposition] ?? 0) + 1;
  requireValue(stableJson(lineageDistribution) === stableJson(summary.dependencyLineageDistribution), 'dependency lineage distribution mismatch');
  const retainedLineage = dependencyLineage.filter((record) => record.disposition === 'retained-with-evidence').map((record) => {
    requireString(record.reason, 'retained dependency lineage reason');
    requireValue(Array.isArray(record.successorSources) && record.successorSources.length > 0, 'retained dependency lineage requires successor sources');
    requireValue(Array.isArray(record.successorPrerequisites) && record.successorPrerequisites.length > 0, 'retained dependency lineage requires successor prerequisites');
    for (const key of [...record.successorSources, ...record.successorPrerequisites]) requireValue(workPackageByKey.has(key), `retained dependency lineage endpoint is missing: ${key}`);
    return { record, fullDigest: recordDigest(record) };
  }).sort((left, right) => left.fullDigest.localeCompare(right.fullDigest));

  const digestPayload = {
    sources: rows,
    relationships: relationshipRecords.map((row) => row.record),
    workPackages: workPackages,
    dependencies: dependencyRecords.map((row) => row.record),
    retainedDependencyLineage: retainedLineage.map((row) => row.record),
    parserManifest,
    summary,
    universes,
    inputs: [...inputs].sort((left, right) => left.path.localeCompare(right.path)),
    parserShards,
  };
  return {
    rows,
    relationshipRecords,
    workPackages: [...workPackageByKey.values()].sort((left, right) => left.record.key.localeCompare(right.record.key)),
    dependencyRecords,
    dependencySatisfactionCounts: { requiredPrerequisites, resolvedPrerequisites, satisfiedPrerequisites, activeBlocking },
    retainedLineage,
    inputs: [...inputs].sort((left, right) => left.path.localeCompare(right.path)),
    parserShards,
    setDigest: sha256(stableJson(digestPayload)),
  };
}

function writeTriG(quads) {
  return new Promise((resolvePromise, reject) => {
    const writer = new Writer({ format: 'application/trig' });
    writer.addQuads(interleaveQuadsBySubject(quads));
    writer.end((error, output) => error ? reject(error) : resolvePromise(spaceBeforeTerminator(output)));
  });
}

// N3 writes a bare boolean or integer object immediately before the statement
// terminator with no separating space (e.g. `... true.`, `... 5.`). That is
// lenient Turtle: Stardog's stricter TurtleParser consumes the dot as part of a
// prefixed name, then fails with "Expected ':'", rejecting the entire load
// (silently committing only the triples before the first such line). Guarantee a
// space before every statement-terminating dot. interleaveQuadsBySubject keeps
// one statement per line, and N3 escapes newlines inside literals, so the final
// dot on each line is always the terminator.
// ponytail: text fix-up for an N3/Stardog serialisation mismatch; drop it if N3 or Stardog stops disagreeing.
function spaceBeforeTerminator(trig) {
  return trig.replace(/([^\s.])\.(\r?\n|$)/g, '$1 .$2');
}

// N3 Writer compacts adjacent quads for one subject into comma/semicolon
// lists. A source file with thousands of exact semantic references can then
// become one deeply nested statement that overflows otherwise independent RDF
// parsers. Deterministically interleave subjects so the TriG remains one quad
// per statement without changing the dataset.
function interleaveQuadsBySubject(quads) {
  const bySubject = new Map();
  for (const item of quads) {
    const key = `${item.subject.termType}\0${item.subject.value}`;
    if (!bySubject.has(key)) bySubject.set(key, []);
    bySubject.get(key).push(item);
  }
  const compareQuad = (left, right) =>
    left.predicate.value.localeCompare(right.predicate.value) ||
    left.object.termType.localeCompare(right.object.termType) ||
    left.object.value.localeCompare(right.object.value);
  const heap = [...bySubject].map(([key, rows]) => ({ key, rows: rows.sort(compareQuad), index: 0 }));
  const before = (left, right) => {
    const leftRemaining = left.rows.length - left.index;
    const rightRemaining = right.rows.length - right.index;
    return leftRemaining > rightRemaining || (leftRemaining === rightRemaining && left.key < right.key);
  };
  const swap = (left, right) => { [heap[left], heap[right]] = [heap[right], heap[left]]; };
  const push = (entry) => {
    heap.push(entry);
    for (let child = heap.length - 1; child > 0;) {
      const parent = Math.floor((child - 1) / 2);
      if (!before(heap[child], heap[parent])) break;
      swap(child, parent); child = parent;
    }
  };
  const pop = () => {
    const first = heap[0];
    const last = heap.pop();
    if (heap.length) {
      heap[0] = last;
      for (let parent = 0;;) {
        const left = parent * 2 + 1; const right = left + 1;
        let best = parent;
        if (left < heap.length && before(heap[left], heap[best])) best = left;
        if (right < heap.length && before(heap[right], heap[best])) best = right;
        if (best === parent) break;
        swap(parent, best); parent = best;
      }
    }
    return first;
  };
  // Heapify after the local push helper has been defined.
  const initial = heap.splice(0);
  for (const entry of initial) push(entry);
  const ordered = []; let previousKey = null;
  while (heap.length) {
    let entry = pop();
    if (entry.key === previousKey && heap.length) {
      const alternate = pop();
      push(entry); entry = alternate;
    }
    ordered.push(entry.rows[entry.index++]);
    previousKey = entry.key;
    if (entry.index < entry.rows.length) push(entry);
  }
  return ordered;
}

export async function collectRepositorySourceObservations({ manifest, entry }) {
  // census is always a sibling of the graph directory (…/census next to …/graph),
  // so resolve it relative to the graph root. Both live side by side in the
  // parent usf repository and are used host-side, outside the chroot.
  const censusRoot = resolve(manifest.root, '../census');
  const inputSpecs = [
    ['artifacts.jsonl', 'jsonl'], ['mappings.jsonl', 'jsonl'], ['relationships.jsonl', 'jsonl'],
    ['workpackages.json', 'json'], ['dependencies.jsonl', 'jsonl'], ['dependency-lineage.jsonl', 'jsonl'],
    ['parser-results/manifest.json', 'json'], ['summary.json', 'json'], ['universes.json', 'json'],
  ];
  const inputs = inputSpecs.map(([relativePath, format]) => inputObservation(join(censusRoot, relativePath), relativePath, format));
  const artifacts = readJsonl(join(censusRoot, 'artifacts.jsonl'));
  const mappings = readJsonl(join(censusRoot, 'mappings.jsonl'));
  const relationships = readJsonl(join(censusRoot, 'relationships.jsonl'));
  const workPackageDocument = readJson(join(censusRoot, 'workpackages.json'));
  const dependencies = readJsonl(join(censusRoot, 'dependencies.jsonl'));
  const dependencyLineage = readJsonl(join(censusRoot, 'dependency-lineage.jsonl'));
  const parserManifest = readJson(join(censusRoot, 'parser-results/manifest.json'));
  const summary = readJson(join(censusRoot, 'summary.json'));
  const universes = readJson(join(censusRoot, 'universes.json'));
  const mappingKeys = new Set(mappings.map((record) => record.artifactKey));
  requireValue(mappings.length === artifacts.length && mappingKeys.size === artifacts.length && artifacts.every((artifact) => mappingKeys.has(artifact.artifactKey)), 'source observation collection requires exactly one current mapping per artifact');
  const bindings = sourceSemanticBindings(manifest);
  const authoredArtefacts = authoredArtefactIris(manifest);
  for (const artifactKey of bindings.keys()) if (!artifacts.some((artifact) => artifact.artifactKey === artifactKey)) {
    throw new Error(`source semantic binding has no current census artifact: ${artifactKey}`);
  }
  const { rows, carrierPaths, setDigest: rowSetDigest } = observationRows(artifacts, mappings, manifest, bindings);
  const parserShards = validateParserProvenance(censusRoot, parserManifest, artifacts, universes);
  const model = censusObservationModel({ rows, relationships, workPackageDocument, dependencies, dependencyLineage, parserManifest, summary, universes, inputs, parserShards, authoredArtefacts });
  // The observation set identity binds the observed source rows only. The
  // full census state hash (model.setDigest) covers outputs that themselves
  // embed the previous run's observation IRIs, so using it as the identity
  // digest can never reach a fixpoint across regeneration rounds. It is kept
  // as run-level provenance below (censusStateDigest).
  const setDigest = rowSetDigest;
  const quads = [];
  const runName = `r${setDigest}`;
  const run = namedNode(`urn:usf:censusobservationrun:${runName}`);
  quads.push(
    quad(run, RDF_TYPE, namedNode(`${USF}CensusObservationRun`)),
    quad(run, p('canonicalName'), literal(runName)),
    quad(run, p('observationSetDigest'), literal(setDigest)),
    quad(run, p('censusStateDigest'), literal(model.setDigest)),
    quad(run, p('observedByCollector'), literal(entry.collector)),
    quad(run, p('observedSourceArtefactCount'), literal(String(model.rows.length), XSD_INTEGER)),
    quad(run, p('observedSourceRelationshipCount'), literal(String(model.relationshipRecords.length), XSD_INTEGER)),
    quad(run, p('observedWorkPackageCount'), literal(String(model.workPackages.length), XSD_INTEGER)),
    quad(run, p('observedWorkPackageDependencyCount'), literal(String(model.dependencyRecords.length), XSD_INTEGER)),
    quad(run, p('observedRequiredPrerequisiteDependencyCount'), literal(String(model.dependencySatisfactionCounts.requiredPrerequisites), XSD_NON_NEGATIVE_INTEGER)),
    quad(run, p('observedResolvedPrerequisiteDependencyCount'), literal(String(model.dependencySatisfactionCounts.resolvedPrerequisites), XSD_NON_NEGATIVE_INTEGER)),
    quad(run, p('observedSatisfiedPrerequisiteDependencyCount'), literal(String(model.dependencySatisfactionCounts.satisfiedPrerequisites), XSD_NON_NEGATIVE_INTEGER)),
    quad(run, p('observedActiveBlockingDependencyCount'), literal(String(model.dependencySatisfactionCounts.activeBlocking), XSD_NON_NEGATIVE_INTEGER)),
    quad(run, p('observedRetainedDependencyLineageCount'), literal(String(model.retainedLineage.length), XSD_INTEGER)),
  );
  for (const input of model.inputs) {
    const inputName = `i${sha256(input.path)}`;
    const resource = namedNode(`urn:usf:censusobservationinput:${inputName}`);
    quads.push(
      quad(resource, RDF_TYPE, namedNode(`${USF}CensusObservationInput`)),
      quad(resource, p('canonicalName'), literal(inputName)),
      quad(resource, p('observedInputPath'), literal(input.path)),
      quad(resource, p('observedInputContentDigest'), literal(input.contentDigest)),
      quad(resource, p('observedInputByteCount'), literal(String(input.byteCount), XSD_INTEGER)),
      quad(resource, p('observedInCensusRun'), run),
      quad(run, p('hasCensusObservationInput'), resource),
    );
    if (input.recordCount !== null) quads.push(quad(resource, p('observedInputRecordCount'), literal(String(input.recordCount), XSD_INTEGER)));
  }
  for (const shard of model.parserShards) {
    const shardName = `s${sha256(shard.path)}`;
    const resource = namedNode(`urn:usf:censusparsershardobservation:${shardName}`);
    quads.push(
      quad(resource, RDF_TYPE, namedNode(`${USF}CensusParserShardObservation`)),
      quad(resource, p('canonicalName'), literal(shardName)),
      quad(resource, p('observedParserShardPath'), literal(shard.path)),
      quad(resource, p('observedParserUniverse'), namedNode(`urn:usf:sourceuniverse:${UNIVERSES[shard.universe]}`)),
      quad(resource, p('observedParserRecordCount'), literal(String(shard.recordCount), XSD_INTEGER)),
      quad(resource, p('observedCompressedContentDigest'), literal(shard.compressedSha256)),
      quad(resource, p('observedUncompressedContentDigest'), literal(shard.uncompressedSha256)),
      quad(resource, p('observedInCensusRun'), run),
      quad(run, p('hasCensusParserShardObservation'), resource),
    );
  }
  for (const row of rows) {
    const sourceName = `s${row.artifactKey}`;
    const source = namedNode(`urn:usf:sourceartefact:${sourceName}`);
    const observationDigest = sha256(JSON.stringify({ ...row, setDigest }));
    const observationName = `o${observationDigest}`;
    const observation = namedNode(`urn:usf:sourceartefactobservation:${observationName}`);
    quads.push(
      quad(source, RDF_TYPE, namedNode(`${USF}SourceArtefact`)),
      quad(source, p('canonicalName'), literal(sourceName)),
      quad(source, p('sourceIdentityDigest'), literal(row.artifactKey)),
      quad(source, p('hasCurrentSourceObservation'), observation),
      quad(observation, RDF_TYPE, namedNode(`${USF}SourceArtefactObservation`)),
      quad(observation, p('canonicalName'), literal(observationName)),
      quad(observation, p('observesSourceArtefact'), source),
      quad(observation, p('observedSourcePath'), literal(row.path)),
      quad(observation, p('observedContentDigest'), literal(row.contentDigest)),
      quad(observation, p('observedFileMode'), literal(row.fileMode)),
      quad(observation, p('observedUniverse'), namedNode(`urn:usf:sourceuniverse:${row.universe}`)),
      quad(observation, p('observedParserImplementation'), literal(row.parserImplementation)),
      quad(observation, p('observedSyntaxKind'), literal(row.syntaxKind)),
      quad(observation, p('observedFormatKind'), literal(row.formatKind)),
      quad(observation, p('observationSetDigest'), literal(setDigest)),
      quad(observation, p('observedInCensusRun'), run),
    );
    for (const role of row.roles) quads.push(quad(observation, p('observedContentRole'), namedNode(`urn:usf:sourcecontentrole:${role}`)));
    for (const reference of row.semanticReferences) quads.push(quad(observation, p('hasExactSemanticReference'), namedNode(reference)));
  }
  const targetResources = new Map();
  const sourceRowByPath = new Map(model.rows.map((row) => [row.path, row]));
  for (const row of model.relationshipRecords) {
    const { record, fullDigest, evidenceDigest, targetDisclosure, attributesDisclosure } = row;
    const relationship = namedNode(`urn:usf:sourcerelationshipobservation:r${fullDigest}`);
    const source = namedNode(`urn:usf:sourceartefact:s${sourceRowByPath.get(record.source).artifactKey}`);
    const targetKey = `${record.targetKind}\0${record.target}`;
    let target = targetResources.get(targetKey);
    if (!target) {
      const targetName = `t${sha256(targetKey)}`;
      target = namedNode(`urn:usf:sourcerelationshiptarget:${targetName}`);
      targetResources.set(targetKey, target);
      quads.push(
        quad(target, RDF_TYPE, namedNode(`${USF}SourceRelationshipTargetObservation`)),
        quad(target, p('canonicalName'), literal(targetName)),
        quad(target, p('observedRelationshipTargetDigest'), literal(targetDisclosure.digest)),
        quad(target, p('observedRelationshipTargetDisclosureStatus'), namedNode(targetDisclosure.status)),
        quad(target, p('observedRelationshipTargetKind'), namedNode(`urn:usf:sourcerelationshiptargetkind:${controlled(record.targetKind)}`)),
        quad(target, p('observedInCensusRun'), run),
      );
      if (targetDisclosure.disclosedValue !== null) quads.push(quad(target, p('observedRelationshipTarget'), literal(targetDisclosure.disclosedValue)));
      const artifactTarget = sourceRowByPath.get(record.target);
      if (record.targetKind === 'artifact') quads.push(quad(target, p('resolvesToSourceArtefact'), namedNode(`urn:usf:sourceartefact:s${artifactTarget.artifactKey}`)));
    }
    quads.push(
      quad(relationship, RDF_TYPE, namedNode(`${USF}SourceRelationshipObservation`)),
      quad(relationship, p('canonicalName'), literal(`r${fullDigest}`)),
      quad(relationship, p('sourceRelationshipSource'), source),
      quad(relationship, p('sourceRelationshipTarget'), target),
      quad(relationship, p('sourceRelationshipType'), namedNode(`urn:usf:sourcerelationshiptype:${controlled(record.relationshipType)}`)),
      quad(relationship, p('sourceRelationshipResolved'), literal('true', XSD_BOOLEAN)),
      quad(relationship, p('sourceRelationshipEvidenceKind'), namedNode(`urn:usf:sourcerelationshipevidencekind:${controlled(record.evidenceKind)}`)),
      quad(relationship, p('sourceRelationshipExtractionMethod'), literal(record.extractionMethod)),
      quad(relationship, p('sourceRelationshipAttributesDigest'), literal(attributesDisclosure.digest)),
      quad(relationship, p('sourceRelationshipAttributesDisclosureStatus'), namedNode(attributesDisclosure.status)),
      quad(relationship, p('sourceRelationshipConfidence'), literal(stableJson(record.confidence))),
      quad(relationship, p('sourceRelationshipRecordDigest'), literal(fullDigest)),
      quad(relationship, p('relationshipEvidenceDigest'), literal(evidenceDigest)),
      quad(relationship, p('observedInCensusRun'), run),
    );
    if (attributesDisclosure.disclosedValue !== null) quads.push(quad(relationship, p('sourceRelationshipAttributes'), literal(attributesDisclosure.disclosedValue)));
    for (const reason of record.reasonCodes) quads.push(quad(relationship, p('sourceRelationshipReasonCode'), literal(reason)));
  }
  for (const row of model.workPackages) {
    const { record, fullDigest } = row;
    const resourceName = workPackageObservationName(record.key);
    const resource = namedNode(`urn:usf:workpackageobservation:${resourceName}`);
    quads.push(
      quad(resource, RDF_TYPE, namedNode(`${USF}WorkPackageObservation`)),
      quad(resource, p('canonicalName'), literal(resourceName)),
      quad(resource, p('workPackageKey'), literal(record.key)),
      quad(resource, p('workPackageTitle'), literal(record.title)),
      quad(resource, p('workPackageOutcomeClass'), literal(record.outcomeClass)),
      quad(resource, p('workPackageRecordDigest'), literal(fullDigest)),
      quad(resource, p('observedInCensusRun'), run),
    );
    for (const artifactKey of record.artifactKeys) quads.push(quad(resource, p('observedOwnedSourceArtefact'), namedNode(`urn:usf:sourceartefact:s${artifactKey}`)));
    for (const artefactIri of record.canonicalArtifactKeys) quads.push(quad(resource, p('observedOwnedCanonicalArtefact'), namedNode(artefactIri)));
  }
  for (const row of model.dependencyRecords) {
    const { record, fullDigest, relationshipMatches, satisfaction } = row;
    const resourceName = workPackageDependencyObservationName(record.dependencyKey);
    const resource = namedNode(`urn:usf:workpackagedependencyobservation:${resourceName}`);
    quads.push(
      quad(resource, RDF_TYPE, namedNode(`${USF}WorkPackageDependencyObservation`)),
      quad(resource, p('canonicalName'), literal(resourceName)),
      quad(resource, p('workPackageDependencyKey'), literal(record.dependencyKey)),
      quad(resource, p('workPackageDependencySource'), namedNode(`urn:usf:workpackageobservation:${workPackageObservationName(record.source)}`)),
      quad(resource, p('workPackageDependencyPrerequisite'), namedNode(`urn:usf:workpackageobservation:${workPackageObservationName(record.prerequisite)}`)),
      quad(resource, p('workPackageDependencyType'), namedNode(`urn:usf:workpackagedependencytype:${controlled(record.dependencyType)}`)),
      quad(resource, p('workPackageDependencyStatus'), namedNode(`urn:usf:workpackagedependencystatus:${controlled(record.status)}`)),
      quad(resource, p('workPackageDependencyResolutionStatus'), namedNode(`urn:usf:workpackagedependencyresolutionstatus:${controlled(record.resolutionStatus)}`)),
      quad(resource, p('workPackageDependencyReasonCode'), literal(record.reasonCode)),
      quad(resource, p('workPackageDependencyResolutionBasis'), literal(stableJson(record.resolutionBasis))),
      quad(resource, p('workPackageDependencyRecordDigest'), literal(fullDigest)),
      quad(resource, p('observedInCensusRun'), run),
    );
    if (satisfaction) {
      const satisfactionStatus = namedNode(`urn:usf:dependencysatisfactionstatus:${controlled(satisfaction.status)}`);
      const basisDigest = dependencySatisfactionBasisDigest(record);
      const basisName = `s${basisDigest}`;
      const basis = namedNode(`urn:usf:workpackagedependencysatisfactionbasisobservation:${basisName}`);
      quads.push(
        quad(resource, p('workPackageDependencySatisfactionSeed'), satisfactionStatus),
        quad(resource, p('hasWorkPackageDependencySatisfactionBasis'), basis),
        quad(basis, RDF_TYPE, namedNode(`${USF}WorkPackageDependencySatisfactionBasisObservation`)),
        quad(basis, p('canonicalName'), literal(basisName)),
        quad(basis, p('satisfactionBasisForWorkPackageDependency'), resource),
        quad(basis, p('observedDependencySatisfactionStatus'), satisfactionStatus),
        quad(basis, p('dependencySatisfactionBasisKind'), namedNode('urn:usf:dependencysatisfactionbasiskind:resolveddirectrelationshipevidence')),
        quad(basis, p('satisfactionBasisRecordDigest'), literal(basisDigest)),
        quad(basis, p('observedInCensusRun'), run),
      );
      for (const field of SATISFACTION_COUNT_FIELDS) quads.push(quad(basis, p(`satisfactionBasis${field[0].toUpperCase()}${field.slice(1)}`), literal(String(satisfaction.basis[field]), XSD_NON_NEGATIVE_INTEGER)));
      for (const field of SATISFACTION_BOOLEAN_FIELDS) quads.push(quad(basis, p(`satisfactionBasis${field[0].toUpperCase()}${field.slice(1)}`), literal(String(satisfaction.basis[field]), XSD_BOOLEAN)));
      for (const digest of relationshipMatches) quads.push(quad(basis, p('satisfactionBasisRelationshipObservation'), namedNode(`urn:usf:sourcerelationshipobservation:r${digest}`)));
    }
    for (const digest of record.repositoryRelationshipEvidence) quads.push(quad(resource, p('workPackageDependencyEvidenceDigest'), literal(digest)));
    for (const digest of relationshipMatches) quads.push(quad(resource, p('supportedBySourceRelationshipObservation'), namedNode(`urn:usf:sourcerelationshipobservation:r${digest}`)));
  }
  for (const row of model.retainedLineage) {
    const { record, fullDigest } = row;
    const resource = namedNode(`urn:usf:workpackagedependencylineageobservation:l${fullDigest}`);
    quads.push(
      quad(resource, RDF_TYPE, namedNode(`${USF}WorkPackageDependencyLineageObservation`)),
      quad(resource, p('canonicalName'), literal(`l${fullDigest}`)),
      quad(resource, p('baselineDependencySourceKey'), literal(record.baselineSource)),
      quad(resource, p('baselineDependencyPrerequisiteKey'), literal(record.baselinePrerequisite)),
      quad(resource, p('dependencyLineageDisposition'), namedNode('urn:usf:dependencylineagedisposition:retainedwithevidence')),
      quad(resource, p('dependencyLineageReason'), literal(record.reason)),
      quad(resource, p('dependencyLineageRecordDigest'), literal(fullDigest)),
      quad(resource, p('observedInCensusRun'), run),
    );
    for (const key of record.successorSources) quads.push(quad(resource, p('successorDependencySource'), namedNode(`urn:usf:workpackageobservation:${workPackageObservationName(key)}`)));
    for (const key of record.successorPrerequisites) quads.push(quad(resource, p('successorDependencyPrerequisite'), namedNode(`urn:usf:workpackageobservation:${workPackageObservationName(key)}`)));
  }
  const uniqueQuads = new Store(quads).getQuads(null, null, null, null);
  return Object.freeze({
    graph: entry.graph,
    contentType: 'application/trig',
    content: await writeTriG(uniqueQuads.map((item) => quad(item.subject, item.predicate, item.object, namedNode(entry.graph)))),
    sourceCount: rows.length,
    relationshipCount: model.relationshipRecords.length,
    workPackageCount: model.workPackages.length,
    sourceOwnershipCount: model.workPackages.reduce((sum, row) => sum + row.record.artifactKeys.length, 0),
    canonicalOwnershipCount: model.workPackages.reduce((sum, row) => sum + row.record.canonicalArtifactKeys.length, 0),
    dependencyCount: model.dependencyRecords.length,
    requiredPrerequisiteDependencyCount: model.dependencySatisfactionCounts.requiredPrerequisites,
    resolvedPrerequisiteDependencyCount: model.dependencySatisfactionCounts.resolvedPrerequisites,
    satisfiedPrerequisiteDependencyCount: model.dependencySatisfactionCounts.satisfiedPrerequisites,
    activeBlockingDependencyCount: model.dependencySatisfactionCounts.activeBlocking,
    dependencyRelationshipLinkCount: model.dependencyRecords.reduce((sum, row) => sum + row.relationshipMatches.length, 0),
    retainedLineageCount: model.retainedLineage.length,
    inputCount: model.inputs.length,
    parserShardCount: model.parserShards.length,
    tripleCount: uniqueQuads.length,
    observationSetDigest: setDigest,
    excludedCarrierPaths: carrierPaths,
  });
}

export async function collectObservedEntry({ manifest, entry }) {
  if (entry.collector === 'repositorysourceobserver') return collectRepositorySourceObservations({ manifest, entry });
  throw new Error(`unknown observed graph collector: ${entry.collector}`);
}

export const sourceObserverInternals = {
  EQUIVALENCE_FIXTURE_EXACT_PATHS, FAMILY_ROLES, OBSERVATION_CONTAMINATION_PATTERNS, UNIVERSES,
  authoredArtefactIris, censusObservationModel, dependencySatisfactionBasisDigest, isEquivalenceFixture, observationDisclosure, observationRows,
  interleaveQuadsBySubject, recordDigest, relationshipEvidenceDigest, rolesFor, sourceSemanticBindings, stableJson,
  workPackageDependencyObservationName, workPackageObservationName,
};
