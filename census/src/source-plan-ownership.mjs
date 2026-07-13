import { compareBy } from './canonical.mjs';

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const NS = 'urn:usf:ontology:';
const TERMS = Object.freeze({
  namedGraph: `${NS}NamedGraph`,
  graphIri: `${NS}graphIri`,
  graphClass: `${NS}graphClass`,
  sourceArtefact: `${NS}SourceArtefact`,
  observation: `${NS}SourceArtefactObservation`,
  disposition: `${NS}SourceArtefactDisposition`,
  dispositionKind: `${NS}DispositionKind`,
  observes: `${NS}observesSourceArtefact`,
  observedPath: `${NS}observedSourcePath`,
  observedDigest: `${NS}observedContentDigest`,
  observedUniverse: `${NS}observedUniverse`,
  hasDisposition: `${NS}hasSourceDisposition`,
  dispositionOf: `${NS}dispositionOfSourceArtefact`,
  assignedPlan: `${NS}assignedToArtefactPlan`,
  exactSemanticReference: `${NS}hasExactSemanticReference`,
  facetStatus: `${NS}facetStatus`,
  hasDispositionKind: `${NS}hasDispositionKind`,
  decisionState: `${NS}hasDispositionDecisionState`,
  decidedAgainst: `${NS}decidedAgainstObservation`,
  observationSetDigest: `${NS}observationSetDigest`
});
const ACCEPTED = 'urn:usf:dispositiondecisionstate:accepted';
const DATA_GRAPH_CLASSES = new Set([
  'urn:usf:graphclass:definitiongraph',
  'urn:usf:graphclass:authoredgraph',
  'urn:usf:graphclass:observedgraph',
  'urn:usf:graphclass:derivedgraph'
]);
const SOURCE_UNIVERSES = new Map([
  ['urn:usf:sourceuniverse:canonicalrepository', 'repository-output'],
  ['urn:usf:sourceuniverse:compilerimplementation', 'v2-compiler-implementation'],
  ['urn:usf:sourceuniverse:graphauthority', 'v2-graph-authority'],
  ['urn:usf:sourceuniverse:supportprovisioning', 'v2-support-provisioning']
]);
const OUTPUT_DISPOSITION_KINDS = new Set([
  'urn:usf:dispositionkind:generateequivalent',
  'urn:usf:dispositionkind:retireafterequivalence'
]);

function dataset(parserResults) {
  return parserResults.filter((record) => record.universe === 'v2-graph-authority' && !record.path.includes('/fixtures/')).flatMap((record) =>
    record.declarations.filter((declaration) => declaration.kind === 'semantic-triple').map((declaration) => ({
      sourcePath: record.path,
      graph: declaration.attributes?.graph,
      subject: declaration.attributes?.subject,
      predicate: declaration.attributes?.predicate,
      object: declaration.attributes?.object
    }))
  ).filter((triple) => triple.subject && triple.predicate && triple.object);
}

function objects(triples, subject, predicate) {
  return [...new Set(triples.filter((triple) => triple.subject === subject && triple.predicate === predicate).map((triple) => triple.object))].sort();
}

function lexicalValue(term) {
  if (typeof term !== 'string' || !term.startsWith('"')) return term;
  const match = term.match(/^("(?:[^"\\]|\\.)*")(?:\^\^.+|@[A-Za-z0-9-]+)?$/s);
  if (!match) return term;
  try { return JSON.parse(match[1]); } catch { return term; }
}

function typedSubjects(triples, classIri) {
  return [...new Set(triples.filter((triple) => triple.predicate === RDF_TYPE && triple.object === classIri && !triple.subject.startsWith('_:')).map((triple) => triple.subject))].sort();
}

function indexDataset(triples) {
  const bySubjectPredicate = new Map(); const byType = new Map(); const graphsBySubject = new Map();
  for (const triple of triples) {
    const key = `${triple.subject}\0${triple.predicate}`;
    if (!bySubjectPredicate.has(key)) bySubjectPredicate.set(key, new Set());
    bySubjectPredicate.get(key).add(triple.object);
    if (triple.predicate === RDF_TYPE && !triple.subject.startsWith('_:')) {
      if (!byType.has(triple.object)) byType.set(triple.object, new Set());
      byType.get(triple.object).add(triple.subject);
    }
    if (triple.graph) {
      if (!graphsBySubject.has(triple.subject)) graphsBySubject.set(triple.subject, new Set());
      graphsBySubject.get(triple.subject).add(triple.graph);
    }
  }
  const get = (subject, predicate) => [...(bySubjectPredicate.get(`${subject}\0${predicate}`) ?? [])].sort();
  const typed = (classIri) => [...(byType.get(classIri) ?? [])].sort();
  return { get, typed, graphsBySubject };
}

export function buildSourcePlanOwnership(artifacts, parserResults, observedPlans) {
  const triples = dataset(parserResults);
  const index = indexDataset(triples);
  const registeredGraphs = new Set();
  for (const subject of index.typed(TERMS.namedGraph)) {
    const graphIris = index.get(subject, TERMS.graphIri).map(lexicalValue);
    const graphClasses = index.get(subject, TERMS.graphClass);
    if (graphIris.length === 1 && graphClasses.length === 1 && DATA_GRAPH_CLASSES.has(graphClasses[0])) registeredGraphs.add(graphIris[0]);
  }
  const registered = (subject) => {
    const graphs = [...(index.graphsBySubject.get(subject) ?? [])];
    return graphs.length > 0 && graphs.every((graph) => registeredGraphs.has(graph));
  };
  const planIris = new Set(observedPlans.map((record) => record.planIri));
  const sourceIris = new Set(index.typed(TERMS.sourceArtefact));
  const dispositionIris = new Set(index.typed(TERMS.disposition));
  const dispositionKinds = new Set(index.typed(TERMS.dispositionKind));
  const observations = index.typed(TERMS.observation).map((observationIri) => ({
    observationIri,
    sourceIris: index.get(observationIri, TERMS.observes),
    paths: index.get(observationIri, TERMS.observedPath).map(lexicalValue),
    digests: index.get(observationIri, TERMS.observedDigest).map(lexicalValue),
    universes: index.get(observationIri, TERMS.observedUniverse).map(lexicalValue).map((value) => SOURCE_UNIVERSES.get(value) ?? value),
    setDigests: index.get(observationIri, TERMS.observationSetDigest).map(lexicalValue)
  }));
  const byPathUniverse = new Map();
  for (const observation of observations) {
    if (observation.paths.length !== 1 || observation.universes.length !== 1) continue;
    const key = `${observation.universes[0]}\0${observation.paths[0]}`;
    if (!byPathUniverse.has(key)) byPathUniverse.set(key, []);
    byPathUniverse.get(key).push(observation);
  }
  const reverseDispositions = new Map();
  for (const dispositionIri of dispositionIris) for (const sourceIri of index.get(dispositionIri, TERMS.dispositionOf)) {
    if (!reverseDispositions.has(sourceIri)) reverseDispositions.set(sourceIri, []);
    reverseDispositions.get(sourceIri).push(dispositionIri);
  }
  const assessDisposition = (sourceIri, observation) => {
    const observationIri = observation.observationIri;
    const forward = index.get(sourceIri, TERMS.hasDisposition);
    const reverse = (reverseDispositions.get(sourceIri) ?? []).sort();
    const dispositions = [...new Set([...forward, ...reverse])].sort();
    const findings = [];
    if (forward.length !== 1 || reverse.length !== 1 || dispositions.length !== 1 || forward[0] !== reverse[0]) findings.push('source-disposition-bijection-invalid');
    if (dispositions.length !== 1) return { accepted: false, findings, observationIri };
    const dispositionIri = dispositions[0];
    const states = index.get(dispositionIri, TERMS.decisionState);
    const plans = index.get(dispositionIri, TERMS.assignedPlan);
    const kinds = index.get(dispositionIri, TERMS.hasDispositionKind);
    const decidedAgainst = index.get(dispositionIri, TERMS.decidedAgainst);
    const dispositionSetDigests = index.get(dispositionIri, TERMS.observationSetDigest).map(lexicalValue);
    const planRequired = kinds.length === 1 && OUTPUT_DISPOSITION_KINDS.has(kinds[0]);
    if (!registered(dispositionIri)) findings.push('source-disposition-unregistered-graph');
    if (states.length !== 1 || states[0] !== ACCEPTED) findings.push(states.includes('urn:usf:dispositiondecisionstate:reviewrequired') ? 'source-disposition-review-required' : 'source-disposition-not-accepted');
    if (decidedAgainst.length !== 1 || decidedAgainst[0] !== observationIri) findings.push('source-disposition-stale-observation');
    if (observation.setDigests.length !== 1 || dispositionSetDigests.length !== 1 || dispositionSetDigests[0] !== observation.setDigests[0]) findings.push('source-disposition-set-digest-mismatch');
    if ((planRequired && plans.length !== 1) || (!planRequired && plans.length !== 0)) findings.push('source-disposition-plan-cardinality-invalid');
    if (plans.some((plan) => !planIris.has(plan))) findings.push('source-disposition-plan-missing');
    if (kinds.length !== 1 || !dispositionKinds.has(kinds[0])) findings.push('source-disposition-kind-invalid');
    return { accepted: findings.length === 0, findings, observationIri, dispositionIri, planRequired, planIris: plans, planIri: plans[0] ?? null, dispositionKindIri: kinds[0] ?? null, decisionStateIri: states[0] ?? null };
  };
  const assessments = artifacts.map((artifact) => {
    const candidates = byPathUniverse.get(`${artifact.universe}\0${artifact.path}`) ?? [];
    const findings = [];
    if (candidates.length === 0) findings.push('source-observation-missing');
    if (candidates.length > 1) findings.push('source-observation-duplicate');
    const observation = candidates.length === 1 ? candidates[0] : null;
    if (!observation) return { artifactKey: artifact.artifactKey, path: artifact.path, universe: artifact.universe, accepted: false, findings };
    if (observation.sourceIris.length !== 1 || !sourceIris.has(observation.sourceIris[0])) findings.push('source-observation-source-invalid');
    if (observation.digests.length !== 1 || observation.digests[0] !== artifact.contentDigest) findings.push('source-observation-digest-mismatch');
    if (!registered(observation.observationIri)) findings.push('source-observation-unregistered-graph');
    const sourceIri = observation.sourceIris[0];
    if (sourceIri && !registered(sourceIri)) findings.push('source-artefact-unregistered-graph');
    const disposition = sourceIri ? assessDisposition(sourceIri, observation) : { accepted: false, findings: [] };
    findings.push(...disposition.findings);
    return {
      artifactKey: artifact.artifactKey,
      path: artifact.path,
      universe: artifact.universe,
      accepted: findings.length === 0 && disposition.accepted,
      findings: [...new Set(findings)].sort(),
      sourceIri: sourceIri ?? null,
      observationIri: observation.observationIri,
      dispositionIri: disposition.dispositionIri ?? null,
      planRequired: disposition.planRequired ?? false,
      planIris: disposition.planIris ?? [],
      planIri: disposition.planIri ?? null,
      dispositionKindIri: disposition.dispositionKindIri ?? null,
      decisionStateIri: disposition.decisionStateIri ?? null,
      semanticReferences: index.get(observation.observationIri, TERMS.exactSemanticReference),
      gapSemanticReferences: index.get(observation.observationIri, TERMS.exactSemanticReference).filter((reference) => index.get(reference, TERMS.facetStatus).includes('urn:usf:facetstatus:gap'))
    };
  }).sort(compareBy(['universe', 'path']));
  const matchedObservations = new Set(assessments.map((record) => record.observationIri).filter(Boolean));
  const orphanObservationCount = observations.filter((record) => !matchedObservations.has(record.observationIri)).length;
  const observationSetDigests = [...new Set([
    ...observations.flatMap((record) => record.setDigests),
    ...[...dispositionIris].flatMap((iri) => index.get(iri, TERMS.observationSetDigest).map(lexicalValue))
  ])].sort();
  return {
    assessments,
    registeredAuthorityGraphCount: registeredGraphs.size,
    sourceResourceCount: sourceIris.size,
    observationResourceCount: observations.length,
    dispositionResourceCount: dispositionIris.size,
    acceptedDispositionCount: assessments.filter((record) => record.accepted).length,
    rejectedDispositionCount: assessments.filter((record) => !record.accepted).length,
    outputDispositionCount: assessments.filter((record) => record.planRequired).length,
    acceptedOutputPlanCount: assessments.filter((record) => record.accepted && record.planRequired && record.planIri).length,
    acceptedNoOutputDispositionCount: assessments.filter((record) => record.accepted && !record.planRequired).length,
    orphanObservationCount,
    observationSetDigests,
    findingDistribution: Object.fromEntries([...new Set(assessments.flatMap((record) => record.findings))].sort().map((reason) => [reason, assessments.filter((record) => record.findings.includes(reason)).length]))
  };
}

export const sourcePlanOwnershipInternals = { ACCEPTED, DATA_GRAPH_CLASSES, OUTPUT_DISPOSITION_KINDS, SOURCE_UNIVERSES, TERMS, dataset, lexicalValue, objects, typedSubjects };
