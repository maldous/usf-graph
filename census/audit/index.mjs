import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Parser as N3Parser } from 'n3';
import { parse as parseYaml } from 'yaml';
import { readIndependentParserEvidence } from './parser-evidence.mjs';
import { auditRepositoryStructureMaterialization } from './repository-structure.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CENSUS_ROOT = path.resolve(HERE, '..');
const REPOSITORY_ROOT = path.resolve(CENSUS_ROOT, '../../..');

function independentCarrierPaths(repositoryRoot = REPOSITORY_ROOT) {
  const manifest = parseYaml(fs.readFileSync(path.join(repositoryRoot, 'v2/usf/graph/manifest.yaml'), 'utf8'));
  const rows = [...(manifest?.observedGraphs ?? []), ...(manifest?.derivedGraphs ?? [])];
  const paths = rows.map((row) => {
    if (!row || typeof row.file !== 'string' || !row.file || path.posix.isAbsolute(row.file) || row.file.includes('\\') || row.file.split('/').includes('..') || path.posix.normalize(row.file) !== row.file) throw new Error('invalid independent graph carrier path');
    return `v2/usf/graph/${row.file}`;
  });
  if (new Set(paths).size !== paths.length) throw new Error('duplicate independent graph carrier path');
  return new Set(paths);
}

const universeFiles = {
  'repository-output': 'repository-universe.jsonl',
  'v2-graph-authority': 'v2-graph-universe.jsonl',
  'v2-compiler-implementation': 'v2-compiler-universe.jsonl',
  'v2-support-provisioning': 'v2-support-universe.jsonl'
};

export function canonicalJson(value) {
  const normalize = (item) => Array.isArray(item) ? item.map(normalize) : item && typeof item === 'object'
    ? Object.fromEntries(Object.keys(item).sort().map((key) => [key, normalize(item[key])])) : item;
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function framedDigest(records, fields) {
  const hash = createHash('sha256');
  for (const record of records) for (const field of fields) {
    const value = Buffer.from(String(record[field] ?? ''), 'utf8');
    const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(value.length));
    hash.update(length).update(value);
  }
  return hash.digest('hex');
}

function check(id, status, findings = [], facts = {}) {
  return { id, status, findings: [...new Set(findings)].sort(), facts };
}

function outcome(id, findings, facts = {}) {
  return check(id, findings.length ? 'fail' : 'pass', findings, facts);
}

function incomplete(id, reason, facts = {}) {
  return check(id, 'incomplete', [reason], facts);
}

function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function readJsonl(file) { const text = fs.readFileSync(file, 'utf8'); return text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line)); }
function exists(root, relative) { return fs.existsSync(path.join(root, relative)); }
function loadJson(root, relative) { return exists(root, relative) ? readJson(path.join(root, relative)) : null; }
function loadJsonl(root, relative) { return exists(root, relative) ? readJsonl(path.join(root, relative)) : null; }

function universeFor(relative, carrierPaths = new Set()) {
  if (relative.startsWith('v2/usf/census/')) return null;
  if (relative.startsWith('v2/usf/.work/')) return null;
  if (carrierPaths.has(relative)) return null;
  if (relative.startsWith('v2/usf/graph/')) return 'v2-graph-authority';
  if (relative.startsWith('v2/usf/compiler/')) return 'v2-compiler-implementation';
  if (relative.startsWith('v2/')) return 'v2-support-provisioning';
  return 'repository-output';
}

function listGitVisible(root, carrierPaths = independentCarrierPaths(root)) {
  const run = (args) => execFileSync('git', args, { cwd: root, encoding: 'buffer', maxBuffer: 128 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] }).toString('utf8').split('\0').filter(Boolean);
  const tracked = run(['ls-files', '--cached', '-z']);
  const untracked = run(['ls-files', '--others', '--exclude-standard', '-z']);
  const visibleUntracked = untracked.filter((item) => universeFor(item, carrierPaths) !== 'v2-support-provisioning');
  return [...new Set([...tracked, ...visibleUntracked])]
    .filter((item) => !item.startsWith('.git/') && universeFor(item, carrierPaths) !== null).sort();
}

function independentRdfTerm(term) {
  if (!term) return null;
  if (term.termType === 'NamedNode') return term.value;
  if (term.termType === 'BlankNode') return `_:${term.value}`;
  if (term.termType === 'DefaultGraph') return null;
  if (term.termType === 'Literal') {
    const suffix = term.language ? `@${term.language}` : term.datatype?.value ? `^^${term.datatype.value}` : '';
    return `${JSON.stringify(term.value)}${suffix}`;
  }
  return String(term.value ?? term.id ?? term);
}

function readIndependentCarrierTriples(repositoryRoot = REPOSITORY_ROOT) {
  return [...independentCarrierPaths(repositoryRoot)].sort().flatMap((relative) => {
    const format = relative.endsWith('.ttl') ? 'text/turtle' : 'application/trig';
    const quads = new N3Parser({ format }).parse(fs.readFileSync(path.join(repositoryRoot, relative), 'utf8'));
    return quads.map((quad) => ({
      sourcePath: relative,
      subject: independentRdfTerm(quad.subject), predicate: independentRdfTerm(quad.predicate),
      object: independentRdfTerm(quad.object), graph: independentRdfTerm(quad.graph),
    }));
  });
}

function physicalDigest(root, relative) {
  const absolute = path.join(root, relative);
  const stat = fs.lstatSync(absolute);
  if (stat.isSymbolicLink()) return sha256(fs.readlinkSync(absolute));
  if (!stat.isFile()) return null;
  return sha256(fs.readFileSync(absolute));
}

export function auditUniverses({ recordsByUniverse, summary, repositoryRoot, physicalPaths = null, carrierPaths = new Set() }) {
  const findings = [];
  const all = [];
  for (const universe of Object.keys(universeFiles)) {
    const records = recordsByUniverse[universe];
    if (!Array.isArray(records)) return incomplete('universes', `missing-universe:${universe}`);
    const sorted = records.slice().sort((a, b) => a.path.localeCompare(b.path));
    if (JSON.stringify(records.map((entry) => entry.path)) !== JSON.stringify(sorted.map((entry) => entry.path))) findings.push(`nondeterministic-order:${universe}`);
    for (const record of records) {
      if (record.universe !== universe) findings.push(`wrong-universe-field:${record.path}`);
      if (universeFor(record.path, carrierPaths) !== universe) findings.push(`wrong-membership:${record.path}`);
      if (all.some((entry) => entry.path === record.path)) findings.push(`overlapping-path:${record.path}`);
      all.push(record);
      if (repositoryRoot && fs.existsSync(path.join(repositoryRoot, record.path))) {
        const digest = physicalDigest(repositoryRoot, record.path);
        if (digest && digest !== record.contentDigest) findings.push(`digest-mismatch:${record.path}`);
      } else if (repositoryRoot) findings.push(`missing-physical-path:${record.path}`);
    }
    if (summary?.universeCounts?.[universe] !== records.length) findings.push(`count-mismatch:${universe}`);
  }
  if (physicalPaths) {
    const recordPaths = new Set(all.map((entry) => entry.path));
    for (const item of physicalPaths) if (!recordPaths.has(item)) findings.push(`unrecorded-path:${item}`);
    for (const item of recordPaths) if (!physicalPaths.includes(item)) findings.push(`recorded-path-not-enumerated:${item}`);
  }
  const digestNames = { 'repository-output': 'repositoryUniverseDigest', 'v2-graph-authority': 'v2GraphUniverseDigest', 'v2-compiler-implementation': 'v2CompilerUniverseDigest', 'v2-support-provisioning': 'v2SupportUniverseDigest' };
  for (const [universe, records] of Object.entries(recordsByUniverse)) {
    const computed = framedDigest(records, ['universe', 'path', 'sourceState', 'fileMode', 'contentDigest']);
    if (summary?.[digestNames[universe]] !== computed) findings.push(`summary-digest-mismatch:${universe}`);
  }
  return outcome('universes', findings, { universeCount: 4, memberCount: all.length });
}

export function auditParserRelationships(members, parserResults, relationships, inventories = []) {
  if (![members, parserResults, relationships, inventories].every(Array.isArray)) return incomplete('parser-relationships', 'missing-parser-or-relationship-input');
  const findings = [];
  let unresolvedInternalCount = 0; let unclassifiedExternalCount = 0;
  const memberPaths = new Set(members.map((entry) => entry.path));
  const parsedPaths = new Set(parserResults.map((entry) => entry.path));
  for (const member of members) if (!member.binary && !['gitlink', 'symbolic-link'].includes(member.formatKind) && !parsedPaths.has(member.path)) findings.push(`unparsed:${member.path}`);
  for (const parsed of parserResults) {
    if (!memberPaths.has(parsed.path)) findings.push(`parser-without-member:${parsed.path}`);
    if (!parsed.parserImplementation || !parsed.parserMode || !parsed.pathContext) findings.push(`parser-metadata:${parsed.path}`);
    if (parsed.structuralCoverage === 'partial' && !(parsed.unsupportedStructures?.length)) findings.push(`partial-without-unsupported:${parsed.path}`);
    for (const command of (parsed.declarations ?? []).filter((entry) => entry.kind === 'command')) if (!command.attributes?.executableContext) findings.push(`command-without-context:${parsed.path}:${command.identifier}`);
  }
  const relationKeys = new Set();
  for (const relation of relationships) {
    const key = [relation.source, relation.relationshipType, relation.target, relation.targetKind, relation.extractionMethod].join('\0');
    if (relationKeys.has(key)) findings.push(`duplicate-relationship:${key}`); relationKeys.add(key);
    if (!memberPaths.has(relation.source)) findings.push(`relationship-source-missing:${relation.source}`);
    if (relation.targetKind === 'artifact' && relation.resolved && !/^(?:https?:|urn:|mailto:|data:|node:)/.test(relation.target) && !memberPaths.has(relation.target)) findings.push(`false-resolved-target:${relation.target}`);
    if (relation.targetKind === 'artifact' && !relation.resolved) unresolvedInternalCount += 1;
    if (relation.targetKind === 'external-resource' && !relation.reasonCodes?.some((reason) => reason === 'expected-external-reference' || reason === 'parser-classified-external-resource')) unclassifiedExternalCount += 1;
  }
  if (unresolvedInternalCount) findings.push(`unresolved-internal-targets:${unresolvedInternalCount}`);
  if (unclassifiedExternalCount) findings.push(`unclassified-external-references:${unclassifiedExternalCount}`);
  for (const inventory of inventories) if (!Array.isArray(inventory.declarations) || !inventory.comparisonExecuted?.length) findings.push(`insubstantive-inventory:${inventory.path}`);
  return outcome('parser-relationships', findings, { parserCount: parserResults.length, relationshipCount: relationships.length, inventoryCount: inventories.length });
}

export function auditFamilyOwnership(members, artifacts) {
  if (![members, artifacts].every(Array.isArray)) return incomplete('family-ownership', 'missing-family-input');
  const findings = [];
  const owners = new Map();
  for (const artifact of artifacts) {
    const key = `${artifact.universe}\0${artifact.path}`;
    if (owners.has(key)) findings.push(`multiple-primary-owners:${artifact.path}`);
    if (!artifact.artifactFamily || !artifact.ownershipEvidence?.length || !artifact.familyConfidence || artifact.ownershipEvidence.every((entry) => entry.reason === 'supporting path signal')) findings.push(`unsubstantiated-owner:${artifact.path}`);
    else owners.set(key, artifact.artifactFamily);
  }
  for (const member of members) if (!owners.has(`${member.universe}\0${member.path}`)) findings.push(`unowned:${member.path}`);
  for (const key of owners.keys()) if (!members.some((member) => `${member.universe}\0${member.path}` === key)) findings.push(`owner-without-member:${key.split('\0')[1]}`);
  return outcome('family-ownership', findings, { ownerCount: owners.size });
}

export function auditMappingsCoverage(artifacts, mappings, coverage, identityReviews = null, missingEntirely = null, replacementGroups = null) {
  if (![artifacts, mappings, coverage].every(Array.isArray)) return incomplete('mappings-coverage', 'missing-mapping-input');
  const findings = [];
  const artifactKeys = new Set(artifacts.map((entry) => entry.artifactKey ?? `${entry.universe}:${entry.path}`));
  const mapped = new Map();
  for (const mapping of mappings) {
    if (mapped.has(mapping.artifactKey)) findings.push(`duplicate-mapping:${mapping.artifactKey}`); mapped.set(mapping.artifactKey, mapping);
    if (!artifactKeys.has(mapping.artifactKey)) findings.push(`mapping-without-artifact:${mapping.artifactKey}`);
    if (mapping.coverageDecision === 'complete' && (mapping.missingSemantics?.length || !mapping.representedGeneration?.length)) findings.push(`unsupported-complete:${mapping.artifactKey}`);
    if (!mapping.mappingEvidence?.length || !mapping.coverageReason) findings.push(`mapping-without-evidence:${mapping.artifactKey}`);
  }
  for (const key of artifactKeys) if (!mapped.has(key)) findings.push(`unmapped-artifact:${key}`);
  for (const row of coverage) {
    const source = mapped.get(row.artifactKey);
    if (!source || row.coverageDecision !== source.coverageDecision) findings.push(`coverage-not-derived:${row.artifactKey}`);
  }
  if (identityReviews !== null) {
    if (!Array.isArray(identityReviews)) findings.push('identity-review-input-invalid');
    else for (const review of identityReviews) {
      const mapping = mapped.get(review.artifactKey);
      if (!mapping) findings.push(`identity-review-without-mapping:${review.artifactKey}`);
      if (review.reviewStatus !== 'machine-reviewed') findings.push(`identity-review-overclaims-review:${review.artifactKey}`);
      if (!review.workPackageOwnershipVerified || (review.provedIdentity && !mapping?.matchedResources?.length)) findings.push(`identity-review-unverified:${review.artifactKey}`);
    }
  }
  if (missingEntirely !== null) {
    const absent = new Set(mappings.filter((mapping) => mapping.coverageDecision === 'absent').map((mapping) => mapping.artifactKey));
    const missing = new Set((missingEntirely ?? []).map((record) => record.artifactKey));
    const acceptedDisposition = new Set((replacementGroups ?? []).filter((group) => ['graph-owned-output-plan', 'graph-owned-no-output-disposition'].includes(group.dispositionStatus)).flatMap((group) => group.currentArtifacts ?? []));
    for (const key of absent) if (!missing.has(key) && !acceptedDisposition.has(key)) findings.push(`absent-without-missing-disposition:${key}`);
    const validReviewRequiredDisposition = (record) => record.missingKind === 'review-required-source-disposition' &&
      record.requiredClassIri === 'urn:usf:ontology:SourceArtefactDisposition' &&
      record.reasonCode === 'source-disposition-review-required';
    for (const record of missingEntirely ?? []) if (!record.primaryWorkPackage || (!record.requiredSemanticLayers?.length && !validReviewRequiredDisposition(record))) findings.push(`missing-entirely-unowned:${record.artifactKey}`);
  }
  return outcome('mappings-coverage', findings, { mappingCount: mappings.length, coverageCount: coverage.length });
}

export function auditArtifactDispositions(artifacts, canonicalArtifacts, replacementGroups) {
  if (![artifacts, canonicalArtifacts, replacementGroups].every(Array.isArray)) return incomplete('artifact-dispositions', 'missing-artifact-disposition-input');
  const findings = [];
  const artifactKeys = new Set(artifacts.map((record) => record.artifactKey));
  const accepted = new Set();
  const missing = new Set();
  for (const group of replacementGroups) {
    for (const key of group.currentArtifacts ?? []) {
      if (!artifactKeys.has(key)) findings.push(`artifact-disposition-owner-missing:${key}`);
      if (accepted.has(key) || missing.has(key)) findings.push(`duplicate-artifact-disposition-state:${key}`);
      if (group.dispositionStatus === 'missing-accepted-source-disposition') {
        missing.add(key);
        if (group.canonicalArtifacts?.length || group.requiredGenerationProjections?.length || group.removedDuplication?.length) findings.push(`unavailable-disposition-invents-output-or-removal:${key}`);
        if (group.reviewStatus !== 'machine-reviewed' || group.confidence?.level !== 'low') findings.push(`unavailable-disposition-overclaims-review-or-confidence:${key}`);
        if (group.requiredGraphObligation?.classIri !== 'urn:usf:ontology:SourceArtefactDisposition') findings.push(`source-disposition-obligation-imprecise:${key}`);
      } else if (['graph-owned-output-plan', 'graph-owned-no-output-disposition'].includes(group.dispositionStatus)) accepted.add(key);
      else findings.push(`invalid-artifact-disposition-state:${key}`);
    }
  }
  for (const key of artifactKeys) if (!accepted.has(key) && !missing.has(key)) findings.push(`artifact-disposition-state-absent:${key}`);
  if (missing.size) findings.push(`required-source-disposition-unavailable:${missing.size}`);
  return outcome('artifact-dispositions', findings, {
    artifactCount: artifactKeys.size,
    acceptedDispositionCount: accepted.size,
    missingDispositionCount: missing.size,
    canonicalArtifactCount: canonicalArtifacts.length
  });
}

const SOURCE_TERMS = Object.freeze({
  namedGraph: 'urn:usf:ontology:NamedGraph', graphIri: 'urn:usf:ontology:graphIri', graphClass: 'urn:usf:ontology:graphClass',
  source: 'urn:usf:ontology:SourceArtefact', observation: 'urn:usf:ontology:SourceArtefactObservation', disposition: 'urn:usf:ontology:SourceArtefactDisposition', kind: 'urn:usf:ontology:DispositionKind',
  observes: 'urn:usf:ontology:observesSourceArtefact', path: 'urn:usf:ontology:observedSourcePath', digest: 'urn:usf:ontology:observedContentDigest', universe: 'urn:usf:ontology:observedUniverse',
  hasDisposition: 'urn:usf:ontology:hasSourceDisposition', dispositionOf: 'urn:usf:ontology:dispositionOfSourceArtefact', assignedPlan: 'urn:usf:ontology:assignedToArtefactPlan', dispositionKind: 'urn:usf:ontology:hasDispositionKind', decision: 'urn:usf:ontology:hasDispositionDecisionState',
  decidedAgainst: 'urn:usf:ontology:decidedAgainstObservation', setDigest: 'urn:usf:ontology:observationSetDigest'
});
const SOURCE_RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const ACCEPTED_DISPOSITION = 'urn:usf:dispositiondecisionstate:accepted';
const OUTPUT_KINDS = new Set(['urn:usf:dispositionkind:generateequivalent', 'urn:usf:dispositionkind:retireafterequivalence']);
const SOURCE_UNIVERSES = new Map([
  ['urn:usf:sourceuniverse:canonicalrepository', 'repository-output'],
  ['urn:usf:sourceuniverse:compilerimplementation', 'v2-compiler-implementation'],
  ['urn:usf:sourceuniverse:graphauthority', 'v2-graph-authority'],
  ['urn:usf:sourceuniverse:supportprovisioning', 'v2-support-provisioning']
]);

function sourceTriples(parserResults) {
  return parserResults.filter((record) => record.universe === 'v2-graph-authority' && !record.path.includes('/fixtures/')).flatMap((record) =>
    (record.declarations ?? []).filter((item) => item.kind === 'semantic-triple').map((item) => ({ sourcePath: record.path, ...item.attributes }))
  ).filter((triple) => triple.subject && triple.predicate && triple.object);
}

function sourceLexical(term) {
  if (typeof term !== 'string' || !term.startsWith('"')) return term;
  const match = term.match(/^("(?:[^"\\]|\\.)*")(?:\^\^.+|@[A-Za-z0-9-]+)?$/s);
  if (!match) return term;
  try { return JSON.parse(match[1]); } catch { return term; }
}

function sourceTyped(triples, classIri) {
  return [...new Set(triples.filter((triple) => triple.predicate === SOURCE_RDF_TYPE && triple.object === classIri && !triple.subject.startsWith('_:')).map((triple) => triple.subject))].sort();
}

export function auditSourceDispositionOwnership(artifacts, parserResults, replacementGroups, carrierTriples = []) {
  if (![artifacts, parserResults, replacementGroups].every(Array.isArray)) return incomplete('source-disposition-ownership', 'missing-source-disposition-input');
  const triples = [...sourceTriples(parserResults), ...carrierTriples];
  const objectIndex = new Map(); const resourceGraphIndex = new Map();
  for (const triple of triples) {
    const key = `${triple.subject}\0${triple.predicate}`;
    if (!objectIndex.has(key)) objectIndex.set(key, new Set());
    objectIndex.get(key).add(triple.object);
    if (triple.graph) {
      if (!resourceGraphIndex.has(triple.subject)) resourceGraphIndex.set(triple.subject, new Set());
      resourceGraphIndex.get(triple.subject).add(triple.graph);
    }
  }
  const get = (subject, predicate) => [...(objectIndex.get(`${subject}\0${predicate}`) ?? [])].sort();
  const registered = new Set();
  for (const resource of sourceTyped(triples, SOURCE_TERMS.namedGraph)) {
    const graphIris = get(resource, SOURCE_TERMS.graphIri).map(sourceLexical);
    const graphClasses = get(resource, SOURCE_TERMS.graphClass);
    if (graphIris.length === 1 && graphClasses.length === 1 && [
      'urn:usf:graphclass:definitiongraph',
      'urn:usf:graphclass:authoredgraph',
      'urn:usf:graphclass:observedgraph',
      'urn:usf:graphclass:derivedgraph'
    ].includes(graphClasses[0])) registered.add(graphIris[0]);
  }
  const typed = Object.fromEntries(['source', 'observation', 'disposition', 'kind'].map((name) => [name, new Set(sourceTyped(triples, SOURCE_TERMS[name]))]));
  const plans = new Set(sourceTyped(triples, 'urn:usf:ontology:ArtefactPlan'));
  const resourceRegistered = (subject) => {
    const graphs = [...(resourceGraphIndex.get(subject) ?? [])];
    return graphs.length > 0 && graphs.every((graph) => registered.has(graph));
  };
  const observations = [...typed.observation].map((iri) => ({
    iri,
    sources: get(iri, SOURCE_TERMS.observes),
    paths: get(iri, SOURCE_TERMS.path).map(sourceLexical),
    digests: get(iri, SOURCE_TERMS.digest).map(sourceLexical),
    universes: get(iri, SOURCE_TERMS.universe).map(sourceLexical).map((value) => SOURCE_UNIVERSES.get(value) ?? value),
    setDigests: get(iri, SOURCE_TERMS.setDigest).map(sourceLexical)
  }));
  const observationsByPath = new Map();
  for (const observation of observations) {
    if (observation.paths.length !== 1 || observation.universes.length !== 1) continue;
    const key = `${observation.universes[0]}\0${observation.paths[0]}`;
    if (!observationsByPath.has(key)) observationsByPath.set(key, []);
    observationsByPath.get(key).push(observation);
  }
  const reverseDispositions = new Map();
  for (const iri of typed.disposition) for (const sourceIri of get(iri, SOURCE_TERMS.dispositionOf)) {
    if (!reverseDispositions.has(sourceIri)) reverseDispositions.set(sourceIri, []);
    reverseDispositions.get(sourceIri).push(iri);
  }
  const groups = new Map(replacementGroups.flatMap((group) => (group.currentArtifacts ?? []).map((key) => [key, group])));
  const findingCounts = new Map();
  const addFindings = (reasons) => { for (const reason of new Set(reasons)) findingCounts.set(reason, (findingCounts.get(reason) ?? 0) + 1); };
  let acceptedCount = 0; let outputPlanCount = 0; let noOutputCount = 0;
  for (const artifact of artifacts) {
    const artifactFindings = [];
    const candidates = observationsByPath.get(`${artifact.universe}\0${artifact.path}`) ?? [];
    if (candidates.length !== 1) { addFindings([candidates.length ? 'source-observation-duplicate' : 'source-observation-missing']); continue; }
    const observation = candidates[0];
    if (observation.digests.length !== 1 || observation.digests[0] !== artifact.contentDigest) artifactFindings.push('source-observation-digest-mismatch');
    if (observation.sources.length !== 1 || !typed.source.has(observation.sources[0])) { addFindings([...artifactFindings, 'source-observation-source-invalid']); continue; }
    const sourceIri = observation.sources[0];
    if (!resourceRegistered(observation.iri)) artifactFindings.push('source-observation-unregistered-graph');
    if (!resourceRegistered(sourceIri)) artifactFindings.push('source-artefact-unregistered-graph');
    const forward = get(sourceIri, SOURCE_TERMS.hasDisposition);
    const reverse = (reverseDispositions.get(sourceIri) ?? []).sort();
    const dispositions = [...new Set([...forward, ...reverse])].sort();
    if (forward.length !== 1 || reverse.length !== 1 || dispositions.length !== 1 || forward[0] !== reverse[0]) { addFindings([...artifactFindings, 'source-disposition-bijection-invalid']); continue; }
    const dispositionIri = dispositions[0];
    const states = get(dispositionIri, SOURCE_TERMS.decision);
    const kinds = get(dispositionIri, SOURCE_TERMS.dispositionKind);
    const assignedPlans = get(dispositionIri, SOURCE_TERMS.assignedPlan);
    const decidedAgainst = get(dispositionIri, SOURCE_TERMS.decidedAgainst);
    const dispositionSetDigests = get(dispositionIri, SOURCE_TERMS.setDigest).map(sourceLexical);
    if (!resourceRegistered(dispositionIri)) artifactFindings.push('source-disposition-unregistered-graph');
    if (decidedAgainst.length !== 1 || decidedAgainst[0] !== observation.iri) artifactFindings.push('source-disposition-stale-observation');
    if (observation.setDigests.length !== 1 || dispositionSetDigests.length !== 1 || dispositionSetDigests[0] !== observation.setDigests[0]) artifactFindings.push('source-disposition-set-digest-mismatch');
    if (states.length !== 1 || states[0] !== ACCEPTED_DISPOSITION) artifactFindings.push(states.includes('urn:usf:dispositiondecisionstate:reviewrequired') ? 'source-disposition-review-required' : 'source-disposition-not-accepted');
    if (kinds.length !== 1 || !typed.kind.has(kinds[0])) artifactFindings.push('source-disposition-kind-invalid');
    const planRequired = kinds.length === 1 && OUTPUT_KINDS.has(kinds[0]);
    if ((planRequired && assignedPlans.length !== 1) || (!planRequired && assignedPlans.length !== 0)) artifactFindings.push('source-disposition-plan-cardinality-invalid');
    if (assignedPlans.some((plan) => !plans.has(plan))) artifactFindings.push('source-disposition-plan-missing');
    if (artifactFindings.length === 0) {
      acceptedCount += 1;
      if (planRequired) outputPlanCount += 1; else noOutputCount += 1;
    }
    const group = groups.get(artifact.artifactKey);
    const expectedStatus = artifactFindings.length ? 'missing-accepted-source-disposition' : planRequired ? 'graph-owned-output-plan' : 'graph-owned-no-output-disposition';
    if (group?.dispositionStatus !== expectedStatus) artifactFindings.push('generated-disposition-status-mismatch');
    if (!artifactFindings.length && (group?.requiredGraphObligation?.sourceIri !== sourceIri || group?.requiredGraphObligation?.observationIri !== observation.iri || group?.requiredGraphObligation?.dispositionIri !== dispositionIri || group?.requiredGraphObligation?.assignedPlanIri !== (assignedPlans[0] ?? null))) artifactFindings.push('generated-disposition-evidence-mismatch');
    addFindings(artifactFindings);
  }
  const findings = [...findingCounts].sort(([left], [right]) => left.localeCompare(right)).map(([reason, count]) => `${reason}:${count}`);
  if (artifacts.length - acceptedCount > 0) findings.push(`required-source-disposition-unavailable:${artifacts.length - acceptedCount}`);
  const distinctSetDigests = new Set([
    ...observations.flatMap((record) => record.setDigests),
    ...[...typed.disposition].flatMap((iri) => get(iri, SOURCE_TERMS.setDigest).map(sourceLexical))
  ]);
  if (distinctSetDigests.size > 1) findings.push(`incoherent-observation-set-digests:${distinctSetDigests.size}`);
  return outcome('source-disposition-ownership', findings, { artifactCount: artifacts.length, acceptedDispositionCount: acceptedCount, rejectedDispositionCount: artifacts.length - acceptedCount, outputPlanDispositionCount: outputPlanCount, noOutputDispositionCount: noOutputCount, observationCount: observations.length, dispositionCount: typed.disposition.size, observationSetDigestCount: distinctSetDigests.size, findingDistribution: Object.fromEntries([...findingCounts].sort(([left], [right]) => left.localeCompare(right))) });
}

export function auditFindingClassifications(findingsInput) {
  if (!Array.isArray(findingsInput)) return incomplete('finding-classifications', 'missing-finding-input');
  const findings = [];
  const required = ['findingKey', 'source', 'findingCategory', 'findingClass', 'severity', 'resolutionStatus', 'ownerClass', 'requiredAction', 'classificationEvidence'];
  for (const record of findingsInput) {
    for (const field of required) if (!(field in record) || record[field] === null || record[field] === '' || (Array.isArray(record[field]) && record[field].length === 0)) findings.push(`unclassified-finding:${record.findingKey ?? '<missing>'}:${field}`);
  }
  const unexplained = findingsInput.filter((record) => record.resolutionStatus === 'open').length;
  if (unexplained) findings.push(`unexplained-open-findings:${unexplained}`);
  return outcome('finding-classifications', findings, { findingCount: findingsInput.length, openCount: findingsInput.filter((record) => record.resolutionStatus === 'open').length });
}

export function auditCanonicalArtifacts(canonicalArtifacts, replacementGroups) {
  if (![canonicalArtifacts, replacementGroups].every(Array.isArray)) return incomplete('canonical-replacements', 'missing-canonical-input');
  const findings = [];
  const keys = new Set(); const groups = new Map(replacementGroups.map((entry) => [entry.groupKey ?? entry.key ?? entry.replacementGroup, entry]));
  const requiredLayers = new Set(); const semanticLayerArtifactOwners = new Map();
  for (const artifact of canonicalArtifacts) {
    if (keys.has(artifact.canonicalArtifactKey)) findings.push(`duplicate-canonical-key:${artifact.canonicalArtifactKey}`); keys.add(artifact.canonicalArtifactKey);
    if (!artifact.targetPath && !artifact.pathRule && artifact.mutabilityClass !== 'removed') findings.push(`missing-production-path:${artifact.canonicalArtifactKey}`);
    if (!artifact.acceptanceGates?.length || !artifact.productionResponsibilities?.length) findings.push(`missing-production-contract:${artifact.canonicalArtifactKey}`);
    if (!groups.has(artifact.replacementGroup)) findings.push(`missing-replacement-group:${artifact.canonicalArtifactKey}`);
    for (const layer of artifact.requiredSemanticLayers ?? []) requiredLayers.add(layer);
    if (!Array.isArray(artifact.ownedSemanticLayers)) findings.push(`semantic-layer-ownership-undeclared:${artifact.canonicalArtifactKey}`);
    for (const layer of artifact.ownedSemanticLayers ?? []) {
      if (!(artifact.requiredSemanticLayers ?? []).includes(layer)) findings.push(`owned-semantic-layer-not-required:${artifact.canonicalArtifactKey}:${layer}`);
      if (semanticLayerArtifactOwners.has(layer)) findings.push(`duplicate-semantic-layer-artifact-owner:${layer}:${semanticLayerArtifactOwners.get(layer)}:${artifact.canonicalArtifactKey}`);
      else semanticLayerArtifactOwners.set(layer, artifact.canonicalArtifactKey);
    }
  }
  for (const layer of requiredLayers) if (!semanticLayerArtifactOwners.has(layer)) findings.push(`missing-semantic-layer-artifact-owner:${layer}`);
  for (const group of replacementGroups) for (const key of group.canonicalArtifacts ?? group.canonicalArtifactKeys ?? group.outputs ?? []) if (!keys.has(key)) findings.push(`replacement-target-missing:${key}`);
  return outcome('canonical-replacements', findings, { canonicalArtifactCount: keys.size, replacementGroupCount: groups.size, semanticLayerArtifactOwnerCount: semanticLayerArtifactOwners.size });
}

export function auditWorkPackages(canonicalArtifacts, workPackages) {
  if (![canonicalArtifacts, workPackages].every(Array.isArray)) return incomplete('work-packages', 'missing-work-package-input');
  const findings = []; const ownership = new Map(); const semanticLayerPackageOwners = new Map(); const packageKeys = new Set(workPackages.map((entry) => entry.key));
  for (const item of workPackages) {
    if (!item.key || !item.architecturalOutcome || !item.acceptanceCriteria?.length || !item.complexityEvidence?.length || !item.equivalenceGates?.length) findings.push(`incoherent-package:${item.key ?? '<missing>'}`);
    for (const key of item.canonicalArtifactKeys ?? item.ownedArtifacts ?? []) {
      if (ownership.has(key)) findings.push(`multiply-packaged:${key}`); ownership.set(key, item.key);
    }
    for (const layer of item.ownedSemanticLayers ?? []) {
      if (semanticLayerPackageOwners.has(layer)) findings.push(`multiply-packaged-semantic-layer:${layer}`);
      else semanticLayerPackageOwners.set(layer, item.key);
    }
    for (const dependency of item.dependencies ?? []) if (!packageKeys.has(dependency)) findings.push(`package-dependency-missing:${item.key}:${dependency}`);
  }
  const expectedLayers = new Set();
  for (const artifact of canonicalArtifacts) {
    if (!ownership.has(artifact.canonicalArtifactKey)) findings.push(`unpackaged:${artifact.canonicalArtifactKey}`);
    for (const layer of artifact.ownedSemanticLayers ?? []) {
      expectedLayers.add(layer);
      const artifactPackage = ownership.get(artifact.canonicalArtifactKey);
      const layerPackage = semanticLayerPackageOwners.get(layer);
      if (!artifactPackage || layerPackage !== artifactPackage) findings.push(`semantic-layer-package-owner-mismatch:${layer}:${artifact.canonicalArtifactKey}`);
    }
  }
  for (const layer of semanticLayerPackageOwners.keys()) if (!expectedLayers.has(layer)) findings.push(`semantic-layer-package-owner-without-canonical-artifact:${layer}`);
  return outcome('work-packages', findings, { workPackageCount: workPackages.length, semanticLayerPackageOwnerCount: semanticLayerPackageOwners.size });
}

const DEPENDENCY_EVIDENCE_FAMILIES = Object.freeze([
  ['artifact', 'artifactEvidence'], ['migration', 'migrationEvidence'], ['proof-equivalence', 'proofEquivalenceEvidence'],
  ['repository-relationship', 'repositoryRelationshipEvidence'], ['semantic', 'semanticEvidence']
]);

function independentDependencyKey(edge) {
  return `dependency-${sha256(`${edge.source}\0${edge.prerequisite}\0${edge.dependencyType}`)}`;
}

function independentDependencyBasis(edge) {
  return {
    direction: 'source-requires-prerequisite',
    endpointOwnership: 'primary-work-package',
    evidenceFamilies: DEPENDENCY_EVIDENCE_FAMILIES.filter(([, field]) => Array.isArray(edge[field]) && edge[field].length).map(([family]) => family),
    evidenceCounts: Object.fromEntries(DEPENDENCY_EVIDENCE_FAMILIES.map(([family, field]) => [family, Array.isArray(edge[field]) ? edge[field].length : 0])),
    cycleCheck: edge.status === 'required-prerequisite' ? 'required-prerequisite-dag-verified' : 'not-applicable-coordination',
    transitiveReduction: edge.status === 'required-prerequisite' ? 'retained-direct-edge' : 'not-applicable-coordination',
    reviewBasis: 'machine-reviewed',
  };
}

function independentPrerequisiteSatisfactionBasis(edge, { keys, artifactByPath, artifactOwners, relationshipByHash, retained, acyclic }) {
  let currentRelationshipHashCount = 0;
  let structurallyProvenRelationshipHashCount = 0;
  let directionMatchedRelationshipHashCount = 0;
  let currentPrerequisiteArtifactHashCount = 0;
  const currentPrerequisiteArtifacts = new Set();
  for (const evidenceId of edge.repositoryRelationshipEvidence ?? []) {
    const matches = relationshipByHash.get(evidenceId) ?? [];
    if (matches.length !== 1) continue;
    currentRelationshipHashCount += 1;
    const relation = matches[0];
    const resolvedStructural = relation.resolved === true && relation.targetKind === 'artifact' && relation.evidenceKind === 'structurally-proven';
    if (resolvedStructural) structurallyProvenRelationshipHashCount += 1;
    const sourceArtifact = artifactByPath.get(relation.source);
    const prerequisiteArtifact = artifactByPath.get(relation.target);
    if (resolvedStructural && artifactOwners.get(sourceArtifact?.artifactKey) === edge.source && artifactOwners.get(prerequisiteArtifact?.artifactKey) === edge.prerequisite) directionMatchedRelationshipHashCount += 1;
    if (prerequisiteArtifact && prerequisiteArtifact.sourceState !== 'deleted' && /^[a-f0-9]{64}$/.test(prerequisiteArtifact.contentDigest ?? '')) {
      currentPrerequisiteArtifactHashCount += 1;
      currentPrerequisiteArtifacts.add(prerequisiteArtifact.artifactKey);
    }
  }
  return {
    exactEvidenceHashCount: (edge.repositoryRelationshipEvidence ?? []).length,
    currentRelationshipHashCount,
    structurallyProvenRelationshipHashCount,
    directionMatchedRelationshipHashCount,
    currentPrerequisiteArtifactHashCount,
    currentPrerequisiteArtifactCount: currentPrerequisiteArtifacts.size,
    sourceEndpointExists: keys.has(edge.source),
    prerequisiteEndpointExists: keys.has(edge.prerequisite),
    edgeSurvivedTransitiveReduction: retained,
    requiredPrerequisiteGraphAcyclic: acyclic,
  };
}

function independentSatisfactionStatus(basis) {
  const exact = basis.exactEvidenceHashCount;
  return exact > 0 && basis.currentRelationshipHashCount === exact && basis.structurallyProvenRelationshipHashCount === exact &&
    basis.directionMatchedRelationshipHashCount === exact && basis.currentPrerequisiteArtifactHashCount === exact &&
    basis.currentPrerequisiteArtifactCount > 0 && basis.sourceEndpointExists && basis.prerequisiteEndpointExists &&
    basis.edgeSurvivedTransitiveReduction && basis.requiredPrerequisiteGraphAcyclic ? 'satisfied' : 'unsatisfied';
}

function hasAlternativePrerequisitePath(edges, excluded) {
  const queue = [excluded.source]; const seen = new Set();
  while (queue.length) {
    const node = queue.shift();
    if (node === excluded.prerequisite) return true;
    if (seen.has(node)) continue;
    seen.add(node);
    for (const edge of edges) if (edge !== excluded && edge.source === node && !seen.has(edge.prerequisite)) queue.push(edge.prerequisite);
  }
  return false;
}

export function auditDependencies(workPackages, dependencies, { artifacts = null, relationships = null, canonicalArtifacts = null, replacementGroups = null, summary = null } = {}) {
  if (![workPackages, dependencies].every(Array.isArray)) return incomplete('dependencies', 'missing-dependency-input');
  const findings = []; const keys = new Set(workPackages.map((entry) => entry.key)); const graph = new Map([...keys].map((key) => [key, []])); const seen = new Set();
  const packageByKey = new Map(workPackages.map((entry) => [entry.key, entry]));
  const artifactByPath = new Map((artifacts ?? []).map((entry) => [entry.path, entry]));
  const artifactOwners = new Map(workPackages.flatMap((entry) => (entry.artifactKeys ?? []).map((key) => [key, entry.key])));
  const canonicalOwners = new Map(workPackages.flatMap((entry) => (entry.canonicalArtifactKeys ?? []).map((key) => [key, entry.key])));
  const layerOwners = new Map(workPackages.flatMap((entry) => (entry.ownedSemanticLayers ?? []).map((key) => [key, entry.key])));
  const gateOwners = new Map(workPackages.flatMap((entry) => (entry.equivalenceGates ?? []).map((gate) => [gate.gateKey ?? gate, entry.key])));
  const canonicalByKey = new Map((canonicalArtifacts ?? []).map((entry) => [entry.canonicalArtifactKey, entry]));
  const replacementByKey = new Map((replacementGroups ?? []).map((entry) => [entry.groupKey, entry]));
  const relationshipByHash = new Map();
  for (const relation of relationships ?? []) {
    const key = sha256(`${relation.source}\0${relation.relationshipType}\0${relation.target}`);
    if (!relationshipByHash.has(key)) relationshipByHash.set(key, []);
    relationshipByHash.get(key).push(relation);
  }
  for (const edge of dependencies) {
    const edgeKey = `${edge.source}\0${edge.prerequisite}\0${edge.dependencyType}`;
    if (seen.has(edgeKey)) findings.push(`duplicate-edge:${edge.source}:${edge.prerequisite}`); seen.add(edgeKey);
    if (!keys.has(edge.source) || !keys.has(edge.prerequisite)) findings.push(`edge-endpoint-missing:${edge.source}:${edge.prerequisite}`);
    if (edge.source === edge.prerequisite) findings.push(`self-cycle:${edge.source}`);
    const evidence = ['semanticEvidence', 'artifactEvidence', 'repositoryRelationshipEvidence', 'proofEquivalenceEvidence', 'migrationEvidence'].flatMap((field) => edge[field] ?? []);
    if (!evidence.length) findings.push(`edge-without-evidence:${edge.source}:${edge.prerequisite}`);
    if (edge.dependencyKey !== independentDependencyKey(edge)) findings.push(`dependency-key-invalid:${edge.source}:${edge.prerequisite}`);
    if (edge.resolutionStatus !== 'resolved-retained' || edge.reviewStatus !== 'machine-reviewed') findings.push(`dependency-not-resolved-retained:${edge.source}:${edge.prerequisite}`);
    if (canonicalJson(edge.resolutionBasis) !== canonicalJson(independentDependencyBasis(edge))) findings.push(`dependency-resolution-basis-invalid:${edge.source}:${edge.prerequisite}`);
    for (const evidenceId of edge.repositoryRelationshipEvidence ?? []) {
      const matches = relationshipByHash.get(evidenceId) ?? [];
      const valid = matches.some((relation) => {
        const sourceArtifact = artifactByPath.get(relation.source);
        const prerequisiteArtifact = artifactByPath.get(relation.target);
        return relation.resolved === true && relation.targetKind === 'artifact' && relation.evidenceKind === 'structurally-proven' &&
          artifactOwners.get(sourceArtifact?.artifactKey) === edge.source && artifactOwners.get(prerequisiteArtifact?.artifactKey) === edge.prerequisite;
      });
      if (!valid) findings.push(`dependency-relationship-evidence-invalid:${evidenceId}`);
    }
    for (const layer of edge.semanticEvidence ?? []) if (!packageByKey.get(edge.source)?.requiredSemanticLayers?.includes(layer) || layerOwners.get(layer) !== edge.prerequisite) findings.push(`dependency-semantic-evidence-invalid:${layer}`);
    for (const evidenceId of edge.artifactEvidence ?? []) {
      const canonicalKey = [...canonicalByKey.keys()].find((key) => evidenceId.startsWith(`${key}:`));
      const dependencyPath = canonicalKey ? evidenceId.slice(canonicalKey.length + 1) : null;
      const dependencyArtifact = dependencyPath ? artifactByPath.get(dependencyPath) : null;
      if (!canonicalKey || canonicalOwners.get(canonicalKey) !== edge.source || !canonicalByKey.get(canonicalKey)?.artifactDependencies?.includes(dependencyPath) || artifactOwners.get(dependencyArtifact?.artifactKey) !== edge.prerequisite) findings.push(`dependency-artifact-evidence-invalid:${evidenceId}`);
    }
    for (const evidenceId of edge.proofEquivalenceEvidence ?? []) if (gateOwners.get(evidenceId) !== edge.prerequisite) findings.push(`dependency-proof-evidence-invalid:${evidenceId}`);
    for (const evidenceId of edge.migrationEvidence ?? []) {
      const group = replacementByKey.get(evidenceId);
      const groupPackages = [...new Set([...(group?.currentArtifacts ?? []).map((key) => artifactOwners.get(key)), ...(group?.canonicalArtifacts ?? []).map((key) => canonicalOwners.get(key))].filter(Boolean))].sort();
      if (!group || groupPackages[0] !== edge.prerequisite || !groupPackages.slice(1).includes(edge.source)) findings.push(`dependency-migration-evidence-invalid:${evidenceId}`);
    }
    if (edge.status === 'required-prerequisite') graph.get(edge.source)?.push(edge.prerequisite);
  }
  const visiting = new Set(); const visited = new Set(); let cyclic = false;
  const visit = (node) => { if (visiting.has(node)) { cyclic = true; findings.push(`dependency-cycle:${node}`); return; } if (visited.has(node)) return; visiting.add(node); for (const next of graph.get(node) ?? []) visit(next); visiting.delete(node); visited.add(node); };
  for (const key of keys) visit(key);
  if (!cyclic) {
    for (const [source, direct] of graph) for (const intermediate of direct) for (const target of graph.get(intermediate) ?? []) if (direct.includes(target)) findings.push(`transitive-edge-not-reduced:${source}:${target}`);
  }
  const prerequisites = dependencies.filter((edge) => edge.status === 'required-prerequisite');
  let independentlySatisfied = 0;
  for (const edge of prerequisites) {
    const basis = independentPrerequisiteSatisfactionBasis(edge, {
      keys, artifactByPath, artifactOwners, relationshipByHash,
      retained: !hasAlternativePrerequisitePath(prerequisites, edge), acyclic: !cyclic,
    });
    const status = independentSatisfactionStatus(basis);
    if (canonicalJson(edge.satisfactionBasis) !== canonicalJson(basis)) findings.push(`dependency-satisfaction-basis-invalid:${edge.source}:${edge.prerequisite}`);
    if (edge.satisfactionStatus !== status) findings.push(`dependency-satisfaction-status-invalid:${edge.source}:${edge.prerequisite}`);
    if (status === 'satisfied') independentlySatisfied += 1;
    else findings.push(`active-unsatisfied-required-prerequisite:${edge.source}:${edge.prerequisite}`);
  }
  const counts = {
    requiredPrerequisiteRelationshipCount: prerequisites.length,
    resolvedPrerequisiteRelationshipCount: prerequisites.filter((edge) => edge.resolutionStatus === 'resolved-retained').length,
    satisfiedPrerequisiteRelationshipCount: independentlySatisfied,
    blockingRelationshipCount: 0,
    activeBlockingRelationshipCount: prerequisites.length - independentlySatisfied,
  };
  if (summary) for (const [field, count] of Object.entries(counts)) if (summary[field] !== count) findings.push(`dependency-summary-count-invalid:${field}:${summary[field]}/${count}`);
  return outcome('dependencies', findings, { dependencyCount: dependencies.length, ...counts });
}

export function auditDeterminism(outputs) {
  if (!outputs || typeof outputs !== 'object') return incomplete('determinism', 'missing-output-map');
  const findings = [];
  const digest = createHash('sha256');
  const frame = (value) => { const bytes = Buffer.from(value); const size = Buffer.alloc(8); size.writeBigUInt64BE(BigInt(bytes.length)); digest.update(size).update(bytes); };
  const selectors = {
    artifacts: (entry) => [entry.universe, entry.path],
    parserResults: (entry) => [entry.universe, entry.path],
    relationships: (entry) => [entry.source, entry.relationshipType, entry.target, entry.extractionMethod],
    inventories: (entry) => [entry.universe, entry.path],
    mappings: (entry) => [entry.universe, entry.path],
    coverage: (entry) => [entry.universe, entry.path],
    identityReview: (entry) => [String(entry.rank).padStart(6, '0')],
    missingEntirely: (entry) => [entry.universe, entry.path],
    canonicalArtifacts: (entry) => [entry.canonicalArtifactKey],
    replacementGroups: (entry) => [entry.groupKey],
    dependencies: (entry) => [entry.status, entry.source, entry.prerequisite],
    inventoryFindings: (entry) => [entry.source, entry.findingKind, entry.subject]
  };
  for (const [name, value] of Object.entries(outputs)) {
    frame(name);
    const records = Array.isArray(value) ? value : [value];
    const selector = selectors[name] ?? ((entry) => entry?.path ?? entry?.key ?? entry?.canonicalArtifactKey ?? entry?.artifactKey ?? JSON.stringify(entry));
    const keys = records.map((entry) => { const selected = selector(entry); return Array.isArray(selected) ? selected : [selected]; });
    const ordered = keys.slice().sort((left, right) => {
      for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
        const compared = String(left[index] ?? '').localeCompare(String(right[index] ?? ''));
        if (compared !== 0) return compared;
      }
      return 0;
    });
    if (JSON.stringify(keys) !== JSON.stringify(ordered)) findings.push(`nondeterministic-record-order:${name}`);
    for (const record of records) frame(canonicalJson(record));
  }
  return outcome('determinism', findings, { outputCount: Object.keys(outputs).length, canonicalDigest: digest.digest('hex') });
}

export function auditMutationBoundary(before, after, mutableRoot = 'v2/usf/census') {
  if (!(before instanceof Map) || !(after instanceof Map)) return incomplete('mutation-boundary', 'missing-before-or-after-snapshot');
  const findings = [];
  for (const key of new Set([...before.keys(), ...after.keys()])) if (!key.startsWith(`${mutableRoot}/`) && before.get(key) !== after.get(key)) findings.push(`read-only-path-mutated:${key}`);
  return outcome('mutation-boundary', findings, { beforeCount: before.size, afterCount: after.size });
}

function snapshot(root, paths) {
  const map = new Map(); for (const relative of paths) { try { const digest = physicalDigest(root, relative); if (digest) map.set(relative, digest); } catch { /* an unreadable physical file is an acceptable absence here */ } } return map;
}

export async function runAudit({ censusRoot = CENSUS_ROOT, repositoryRoot = REPOSITORY_ROOT } = {}) {
  const carrierPaths = independentCarrierPaths(repositoryRoot);
  let physicalPaths;
  try { physicalPaths = listGitVisible(repositoryRoot, carrierPaths); } catch { physicalPaths = null; }
  const outside = (physicalPaths ?? []).filter((item) => !item.startsWith('v2/usf/census/'));
  const before = snapshot(repositoryRoot, outside);
  const recordsByUniverse = Object.fromEntries(Object.entries(universeFiles).map(([key, file]) => [key, loadJsonl(censusRoot, file)]));
  const members = Object.values(recordsByUniverse).filter(Array.isArray).flat();
  let parserEvidence = null; let parserEvidenceFailure = null;
  try { parserEvidence = await readIndependentParserEvidence(censusRoot); } catch (error) { parserEvidenceFailure = error.message; }
  const outputs = {
    artifacts: loadJsonl(censusRoot, 'artifacts.jsonl'), parserResults: parserEvidence?.records ?? null, relationships: loadJsonl(censusRoot, 'relationships.jsonl'),
    inventories: loadJsonl(censusRoot, 'inventories.jsonl'), mappings: loadJsonl(censusRoot, 'mappings.jsonl'), coverage: loadJsonl(censusRoot, 'coverage.jsonl'),
    canonicalArtifacts: loadJsonl(censusRoot, 'canonical-artifacts.jsonl'), replacementGroups: loadJsonl(censusRoot, 'replacement-groups.jsonl'),
    identityReview: loadJsonl(censusRoot, 'identity-review.jsonl'), missingEntirely: loadJsonl(censusRoot, 'missing-entirely.jsonl'),
    workPackages: loadJson(censusRoot, 'workpackages.json'), dependencies: loadJsonl(censusRoot, 'dependencies.jsonl'),
    inventoryFindings: loadJsonl(censusRoot, 'inventory-findings.jsonl'), summary: loadJson(censusRoot, 'summary.json')
  };
  const workPackages = Array.isArray(outputs.workPackages) ? outputs.workPackages : outputs.workPackages?.workPackages;
  const repositoryStructureMaterialization = auditRepositoryStructureMaterialization({ censusRoot, repositoryRoot });
  const checks = [
    parserEvidenceFailure
      ? incomplete('parser-evidence-storage', parserEvidenceFailure)
      : check('parser-evidence-storage', 'pass', [], { recordCount: parserEvidence.manifest.aggregate.recordCount, shardCount: parserEvidence.manifest.shards.length, uncompressedBytes: parserEvidence.manifest.aggregate.uncompressedBytes }),
    auditUniverses({ recordsByUniverse, summary: loadJson(censusRoot, 'universes.json'), repositoryRoot, physicalPaths, carrierPaths }),
    auditParserRelationships(members, outputs.parserResults, outputs.relationships, outputs.inventories),
    auditFamilyOwnership(members, outputs.artifacts), auditMappingsCoverage(outputs.artifacts, outputs.mappings, outputs.coverage, outputs.identityReview, outputs.missingEntirely, outputs.replacementGroups),
    auditCanonicalArtifacts(outputs.canonicalArtifacts, outputs.replacementGroups),
    auditArtifactDispositions(outputs.artifacts, outputs.canonicalArtifacts, outputs.replacementGroups),
    auditSourceDispositionOwnership(outputs.artifacts, outputs.parserResults, outputs.replacementGroups, readIndependentCarrierTriples(repositoryRoot)),
    auditWorkPackages(outputs.canonicalArtifacts, workPackages), auditDependencies(workPackages, outputs.dependencies, {
      artifacts: outputs.artifacts, relationships: outputs.relationships, canonicalArtifacts: outputs.canonicalArtifacts, replacementGroups: outputs.replacementGroups, summary: outputs.summary
    }),
    repositoryStructureMaterialization,
    auditFindingClassifications(outputs.inventoryFindings),
    auditDeterminism(Object.fromEntries(Object.entries(outputs).filter(([name, value]) => value !== null && name !== 'parserResults')))
  ];
  const after = snapshot(repositoryRoot, outside); checks.push(auditMutationBoundary(before, after));
  const status = checks.some((entry) => entry.status === 'fail') ? 'fail' : checks.some((entry) => entry.status === 'incomplete') ? 'incomplete' : 'pass';
  return { auditId: 'independent-hardened-regeneration-census', status, checks };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const audit = await runAudit();
  const target = path.join(CENSUS_ROOT, 'audit.json');
  const temporary = `${target}.writing`;
  fs.writeFileSync(temporary, canonicalJson(audit));
  fs.renameSync(temporary, target);
  process.stdout.write(canonicalJson(audit));
  if (audit.status === 'fail') process.exitCode = 1;
  else if (audit.status === 'incomplete') process.exitCode = 2;
}
