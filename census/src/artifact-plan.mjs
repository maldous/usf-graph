import { compareBy, sha256 } from './canonical.mjs';
import { buildSourcePlanOwnership } from './source-plan-ownership.mjs';

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const ARTEFACT_PLAN_CLASS = 'urn:usf:ontology:ArtefactPlan';
const NS = 'urn:usf:ontology:';
const TERMS = Object.freeze({
  canonicalName: `${NS}canonicalName`, ownedByRepository: `${NS}ownedByRepository`, plansArtefact: `${NS}plansArtefact`,
  plansSemanticResource: `${NS}plansSemanticResource`, artefactKind: `${NS}artefactKind`, canonicalPath: `${NS}canonicalPath`,
  governedByPathRule: `${NS}governedByPathRule`, generatedByComponent: `${NS}generatedByComponent`, pathPattern: `${NS}pathPattern`,
  semanticInputQuery: `${NS}semanticInputQuery`, outputSchema: `${NS}outputSchema`, outputPathRule: `${NS}outputPathRule`,
  integrityPolicy: `${NS}integrityPolicy`, normalisationPolicy: `${NS}normalisationPolicy`, missingSemanticsConstraint: `${NS}missingSemanticsConstraint`,
  requiresEquivalenceKind: `${NS}requiresEquivalenceKind`, sourceBindingArtefactPlan: `${NS}sourceBindingArtefactPlan`,
  sourceBindingEquivalenceRule: `${NS}sourceBindingEquivalenceRule`
});

function graphTriples(parserResults) {
  return parserResults.filter((record) => record.universe === 'v2-graph-authority' && !record.path.includes('/fixtures/')).flatMap((record) =>
    record.declarations.filter((declaration) => declaration.kind === 'semantic-triple').map((declaration) => ({
      sourcePath: record.path, subject: declaration.attributes?.subject, predicate: declaration.attributes?.predicate, object: declaration.attributes?.object
    }))
  ).filter((triple) => triple.subject && triple.predicate && triple.object);
}

function lexicalValue(term) {
  if (typeof term !== 'string' || !term.startsWith('"')) return term;
  const match = term.match(/^("(?:[^"\\]|\\.)*")(?:\^\^.+|@[A-Za-z0-9-]+)?$/s);
  if (!match) return term;
  try { return JSON.parse(match[1]); } catch { return term; }
}

function values(triples, subject, predicate, lexical = false) {
  const result = [...new Set(triples.filter((triple) => triple.subject === subject && triple.predicate === predicate).map((triple) => triple.object))].sort();
  return lexical ? result.map(lexicalValue) : result;
}

function observedArtefactPlans(parserResults) {
  const triples = graphTriples(parserResults);
  const plans = new Map();
  for (const parsed of parserResults.filter((record) => record.universe === 'v2-graph-authority' && !record.path.includes('/fixtures/'))) {
    for (const declaration of parsed.declarations) {
      const attributes = declaration.attributes ?? {};
      if (declaration.kind !== 'semantic-triple' || attributes.predicate !== RDF_TYPE || attributes.object !== ARTEFACT_PLAN_CLASS || attributes.subject?.startsWith('_:')) continue;
      if (!plans.has(attributes.subject)) plans.set(attributes.subject, { planIri: attributes.subject, evidencePaths: [] });
      plans.get(attributes.subject).evidencePaths.push(parsed.path);
    }
  }
  return [...plans.values()].map((record) => {
    const planIri = record.planIri;
    const ownerIris = values(triples, planIri, TERMS.ownedByRepository);
    const semanticResourceIris = values(triples, planIri, TERMS.plansSemanticResource);
    const artefactIris = values(triples, planIri, TERMS.plansArtefact);
    const bindings = [...new Set(triples.filter((triple) => triple.predicate === TERMS.sourceBindingArtefactPlan && triple.object === planIri).map((triple) => triple.subject))].sort();
    const equivalenceRuleIris = [...new Set(bindings.flatMap((binding) => values(triples, binding, TERMS.sourceBindingEquivalenceRule)))].sort();
    const findings = [];
    if (ownerIris.length !== 1) findings.push('plan-owner-cardinality');
    if (artefactIris.length < 1) findings.push('plan-artefact-cardinality');
    const artefacts = artefactIris.map((artefactIri) => {
      const paths = values(triples, artefactIri, TERMS.canonicalPath, true);
      const kinds = values(triples, artefactIri, TERMS.artefactKind);
      const pathRules = values(triples, artefactIri, TERMS.governedByPathRule);
      const components = values(triples, artefactIri, TERMS.generatedByComponent);
      if (paths.length !== 1) findings.push(`artefact-path-cardinality:${artefactIri}`);
      if (kinds.length !== 1) findings.push(`artefact-kind-cardinality:${artefactIri}`);
      if (pathRules.length !== 1 || values(triples, pathRules[0], TERMS.pathPattern, true).length !== 1) findings.push(`artefact-path-rule-cardinality:${artefactIri}`);
      if (components.length !== 1) findings.push(`artefact-generator-cardinality:${artefactIri}`);
      const componentIri = components[0] ?? null;
      const component = componentIri ? {
        componentIri,
        semanticInputQueries: values(triples, componentIri, TERMS.semanticInputQuery, true),
        outputSchemaIris: values(triples, componentIri, TERMS.outputSchema),
        outputPathRuleIris: values(triples, componentIri, TERMS.outputPathRule),
        integrityPolicyIris: values(triples, componentIri, TERMS.integrityPolicy),
        normalisationPolicyIris: values(triples, componentIri, TERMS.normalisationPolicy),
        missingSemanticsConstraintIris: values(triples, componentIri, TERMS.missingSemanticsConstraint),
        equivalenceKindIris: values(triples, componentIri, TERMS.requiresEquivalenceKind)
      } : null;
      if (component && (component.semanticInputQueries.length !== 1 || component.outputSchemaIris.length < 1 || component.outputPathRuleIris.length !== 1 || component.integrityPolicyIris.length !== 1 || component.normalisationPolicyIris.length !== 1 || component.missingSemanticsConstraintIris.length < 1 || component.equivalenceKindIris.length < 1)) findings.push(`generator-contract-incomplete:${componentIri}`);
      return { artefactIri, canonicalNames: values(triples, artefactIri, TERMS.canonicalName, true), paths, kinds, pathRuleIris: pathRules,
        pathPatterns: pathRules.flatMap((rule) => values(triples, rule, TERMS.pathPattern, true)), component };
    });
    return { ...record, ownerIris, semanticResourceIris, artefactIris, artefacts, bindings, equivalenceRuleIris,
      evidencePaths: [...new Set(record.evidencePaths)].sort(), findings: [...new Set(findings)].sort(), valid: findings.length === 0 };
  }).sort(compareBy(['planIri']));
}

export function validateReplacementGroup(record, currentKeys, canonicalKeys) {
  const allowed = new Set(['one-to-one', 'many-to-one', 'one-to-many', 'many-to-many', 'one-to-zero', 'zero-to-one']);
  if (!allowed.has(record.cardinality)) throw new Error(`invalid replacement cardinality: ${record.groupKey}`);
  if (record.currentArtifacts.some((key) => !currentKeys.has(key))) throw new Error(`replacement has missing current artifact: ${record.groupKey}`);
  if (record.canonicalArtifacts.some((key) => !canonicalKeys.has(key))) throw new Error(`replacement has missing canonical artifact: ${record.groupKey}`);
  const counts = `${record.currentArtifacts.length}:${record.canonicalArtifacts.length}`;
  const valid = record.cardinality === 'one-to-one' ? counts === '1:1' :
    record.cardinality === 'many-to-one' ? record.currentArtifacts.length > 1 && record.canonicalArtifacts.length === 1 :
    record.cardinality === 'one-to-many' ? record.currentArtifacts.length === 1 && record.canonicalArtifacts.length > 1 :
    record.cardinality === 'many-to-many' ? record.currentArtifacts.length > 1 && record.canonicalArtifacts.length > 1 :
    record.cardinality === 'one-to-zero' ? record.currentArtifacts.length === 1 && record.canonicalArtifacts.length === 0 :
    record.currentArtifacts.length === 0 && record.canonicalArtifacts.length === 1;
  if (!valid) throw new Error(`replacement cardinality mismatch: ${record.groupKey}`);
}

export function buildArtifactPlan(artifacts, _parserResults, mappings, _missingEntirely, _relationships) {
  const mappingByKey = new Map(mappings.map((record) => [record.artifactKey, record]));
  const graphPlans = observedArtefactPlans(_parserResults);
  const sourceOwnership = buildSourcePlanOwnership(artifacts, _parserResults, graphPlans);
  const ownershipByKey = new Map(sourceOwnership.assessments.map((record) => [record.artifactKey, record]));
  const planEvidencePaths = [...new Set(graphPlans.flatMap((record) => record.evidencePaths))].sort();
  const planByIri = new Map(graphPlans.map((record) => [record.planIri, record]));
  const canonicalArtifacts = [];
  const replacementGroups = [...artifacts].sort(compareBy(['universe', 'path'])).map((artifact) => {
    const mapping = mappingByKey.get(artifact.artifactKey);
    const ownership = ownershipByKey.get(artifact.artifactKey);
    const dispositionStatus = ownership?.accepted
      ? ownership.planRequired ? 'graph-owned-output-plan' : 'graph-owned-no-output-disposition'
      : 'missing-accepted-source-disposition';
    const reasonCode = ownership?.accepted
      ? ownership.planRequired ? 'accepted-output-disposition-and-plan' : 'accepted-no-output-disposition'
      : ownership?.findings?.[0] ?? 'accepted-source-disposition-not-observed';
    const groupKey = `replacement-${sha256(`artifact-plan-missing\0${artifact.artifactKey}`).slice(0, 24)}`;
    let canonicalArtifact = null;
    if (ownership?.accepted && ownership.planRequired && ownership.planIri) {
      const plan = planByIri.get(ownership.planIri);
      if (!plan?.valid || plan.artefacts.length !== 1 || plan.semanticResourceIris.length !== 1) throw new Error(`accepted source output plan is not independently complete: ${ownership.planIri}`);
      const output = plan.artefacts[0];
      const component = output.component;
      const gateKey = `semantic-equivalence-${sha256(`${ownership.planIri}\0${artifact.artifactKey}`).slice(0, 24)}`;
      canonicalArtifact = {
        canonicalArtifactKey: output.artefactIri,
        semanticPurpose: `Generate the canonical machine contract projection for ${plan.semanticResourceIris[0]} from graph authority.`,
        artifactKind: 'schema-contract', mediaType: 'application/json', targetPath: output.paths[0],
        pathRule: { iri: output.pathRuleIris[0], pattern: output.pathPatterns[0] }, authorityStatus: 'projection', mutabilityClass: 'generated',
        semanticInputs: [...plan.semanticResourceIris], requiredSemanticLayers: [], ownedSemanticLayers: [],
        artifactDependencies: [...component.outputSchemaIris], productionResponsibilities: ['generator'],
        productionContract: { disposition: 'generate-equivalent', planIri: plan.planIri, generatorIri: component.componentIri,
          semanticInputQuery: component.semanticInputQueries[0], outputSchemaIris: component.outputSchemaIris, outputPathRuleIri: component.outputPathRuleIris[0],
          missingSemanticsConstraintIris: component.missingSemanticsConstraintIris },
        integrityPolicy: { integrityPolicyIri: component.integrityPolicyIris[0], normalisationPolicyIri: component.normalisationPolicyIris[0] },
        equivalenceContract: { primaryClass: 'semantic-equivalence', ruleIris: plan.equivalenceRuleIris, kinds: component.equivalenceKindIris,
          gates: [{ gateKey, mechanism: 'source-binding-semantic-contract-comparison' }] },
        acceptanceGates: [{ gateKey, mechanism: 'source-binding-semantic-contract-comparison' }], currentArtifacts: [artifact.artifactKey], replacementGroup: groupKey,
        lifecyclePolicy: { sourceDispositionKindIri: ownership.dispositionKindIri, retireOnlyAfterGate: gateKey },
        confidence: { level: 'high', score: 1, reasons: ['accepted-exact-source-disposition', 'complete-graph-artifact-plan-chain'] }, reviewStatus: 'machine-reviewed'
      };
      canonicalArtifacts.push(canonicalArtifact);
    }
    return {
      groupKey,
      semanticInvariant: `No canonical target or disposition may be selected for ${artifact.path} until graph authority defines an accepted source disposition and, for output-producing kinds, an artifact plan.`,
      currentArtifacts: [artifact.artifactKey],
      canonicalArtifacts: canonicalArtifact ? [canonicalArtifact.canonicalArtifactKey] : [],
      cardinality: canonicalArtifact ? 'one-to-one' : 'one-to-zero',
      consolidationClass: ownership?.accepted
        ? ownership.planRequired ? 'accepted-output-plan' : 'accepted-no-output-disposition'
        : 'source-disposition-unavailable',
      dispositionStatus,
      requiredGraphObligation: {
        classIri: 'urn:usf:ontology:SourceArtefactDisposition',
        outputPlanClassIri: ownership?.planRequired ? 'urn:usf:ontology:ArtefactPlan' : null,
        artifactPath: artifact.path,
        mappingState: mapping?.coverageDecision ?? 'absent',
        reasonCode,
        observedArtefactPlanCount: graphPlans.length,
        observedArtefactPlanEvidencePaths: planEvidencePaths,
        sourceOwnershipFindings: ownership?.findings ?? ['source-ownership-assessment-missing'],
        sourceIri: ownership?.sourceIri ?? null,
        observationIri: ownership?.observationIri ?? null,
        dispositionIri: ownership?.dispositionIri ?? null,
        planRequired: ownership?.planRequired ?? false,
        assignedPlanIri: ownership?.planIri ?? null,
        dispositionKindIri: ownership?.dispositionKindIri ?? null,
        decisionStateIri: ownership?.decisionStateIri ?? null
      },
      safetyEvidence: [`mapping:${artifact.artifactKey}`, `graph-artefact-plan-instance-count:${graphPlans.length}`, ...planEvidencePaths.map((evidencePath) => `graph-evidence:${evidencePath}`)],
      reuseActions: canonicalArtifact ? ['rewrite'] : ['none'],
      removedDuplication: [],
      requiredGenerationProjections: canonicalArtifact ? [canonicalArtifact.canonicalArtifactKey] : [],
      equivalenceGates: canonicalArtifact ? canonicalArtifact.acceptanceGates.map((gate) => gate.gateKey) : [`artifact-plan-required-${artifact.artifactKey}`],
      proofEvidenceGates: canonicalArtifact ? canonicalArtifact.acceptanceGates.map((gate) => gate.gateKey) : [`artifact-plan-required-${artifact.artifactKey}`],
      migrationOrdering: ['define-artifact-plan-semantics', 'author-artifact-plan', 'recompute-census'],
      confidence: ownership?.accepted
        ? { level: 'high', score: 0.99, reasons: [ownership.planRequired ? 'accepted-exact-output-disposition-and-plan' : 'accepted-exact-no-output-disposition'] }
        : { level: 'low', score: 0.1, reasons: ['accepted-source-disposition-not-observed'] },
      reviewStatus: 'machine-reviewed'
    };
  }).sort(compareBy(['groupKey']));
  const currentKeys = new Set(artifacts.map((record) => record.artifactKey));
  canonicalArtifacts.sort(compareBy(['canonicalArtifactKey']));
  const canonicalKeys = new Set(canonicalArtifacts.map((record) => record.canonicalArtifactKey));
  for (const group of replacementGroups) validateReplacementGroup(group, currentKeys, canonicalKeys);
  return { canonicalArtifacts, replacementGroups, observedArtefactPlans: graphPlans, sourcePlanOwnership: sourceOwnership };
}

export const artifactPlanInternals = { observedArtefactPlans };
