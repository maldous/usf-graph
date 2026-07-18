import { DataFactory } from 'n3';
import {
  USF,
  iriValue,
  literalValue,
  objects,
  subjectsOfType,
} from './authority-dataset.js';
import { CompilerError } from './compiler.js';

const { namedNode } = DataFactory;
const p = (local) => namedNode(`${USF}${local}`);
const RDF_TYPE = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
const RDFS_SUBCLASS_OF = namedNode('http://www.w3.org/2000/01/rdf-schema#subClassOf');
const RETAINED = 'urn:usf:semanticadequacydisposition:independentlywarrantedretained';

const FORBIDDEN_SEGMENTS = new Set(['v2', 'legacy', 'old', 'new', 'temp', 'transitional', 'usf']);

function requiredOne(store, subject, predicate, kind, obligations) {
  const values = objects(store, subject, predicate);
  if (values.length !== 1) {
    obligations.push({ subject: subject.value, predicate: predicate.value, expected: 'exactly-one', observed: values.length, kind });
    return null;
  }
  return values[0];
}

function validatePath(path, subject, obligations) {
  if (!path || path.startsWith('/') || path.includes('\\') || path.split('/').includes('..')) {
    obligations.push({ subject, predicate: `${USF}canonicalPath`, expected: 'safe-repository-relative-path', observed: path, kind: 'invalid-path' });
    return;
  }
  const forbidden = path.split('/').find((segment) => FORBIDDEN_SEGMENTS.has(segment));
  if (forbidden) obligations.push({ subject, predicate: `${USF}canonicalPath`, expected: 'clean-final-state-path', observed: path, kind: 'forbidden-path-segment' });
}

function classDescendsFrom(store, candidate, expected, seen = new Set()) {
  if (candidate.value === expected.value) return true;
  if (seen.has(candidate.value)) return false;
  seen.add(candidate.value);
  return objects(store, candidate, RDFS_SUBCLASS_OF).some((parent) => classDescendsFrom(store, parent, expected, seen));
}

function hasType(store, subject, classIri) {
  const expected = namedNode(classIri);
  return objects(store, subject, RDF_TYPE).some((candidate) => classDescendsFrom(store, candidate, expected));
}

function isSemanticallyCurrent(store, subject) {
  const dispositions = objects(store, subject, p('semanticAdequacyDisposition'));
  return dispositions.length === 0 || dispositions.some((candidate) => candidate.value === RETAINED);
}

function currentSubjectsOfType(store, classIri) {
  return subjectsOfType(store, classIri).filter((subject) => isSemanticallyCurrent(store, subject));
}

export function buildGenerationPlan(store) {
  const obligations = [];
  const outputs = [];
  const validatedComponents = new Set();
  const plans = currentSubjectsOfType(store, `${USF}ArtefactPlan`).sort((a, b) => a.value.localeCompare(b.value));
  if (!plans.length) obligations.push({ subject: 'urn:usf:repository:foundation', predicate: `${USF}hasArtefactPlan`, expected: 'one-or-more', observed: 0, kind: 'missing-artefact-plans' });

  for (const plan of plans) {
    const owners = objects(store, plan, p('ownedByRepository'));
    requiredOne(store, plan, p('ownedByRepository'), 'missing-plan-owner', obligations);
    if (owners.length !== 1) obligations.push({ subject: plan.value, predicate: `${USF}ownedByRepository`, expected: 'exactly-one', observed: owners.length, kind: 'plan-owner-cardinality' });
    const artefacts = objects(store, plan, p('plansArtefact'));
    if (!artefacts.length) obligations.push({ subject: plan.value, predicate: `${USF}plansArtefact`, expected: 'one-or-more', observed: 0, kind: 'missing-plan-output' });
    for (const artefact of artefacts) {
      const semanticResources = objects(store, plan, p('plansSemanticResource'));
      if (semanticResources.length > 1) obligations.push({ subject: plan.value, predicate: `${USF}plansSemanticResource`, expected: 'zero-or-one', observed: semanticResources.length, kind: 'ambiguous-plan-semantic-resource' });
      const paths = objects(store, artefact, p('canonicalPath'));
      const pathTerm = requiredOne(store, artefact, p('canonicalPath'), 'missing-canonical-path', obligations);
      if (paths.length !== 1) obligations.push({ subject: plan.value, predicate: `${USF}canonicalPath`, expected: 'exactly-one-planned-output-path', observed: paths.length, kind: 'plan-path-cardinality' });
      const kindTerm = requiredOne(store, artefact, p('artefactKind'), 'missing-artefact-kind', obligations);
      const pathRule = requiredOne(store, artefact, p('governedByPathRule'), 'missing-path-rule', obligations);
      const component = requiredOne(store, artefact, p('generatedByComponent'), 'missing-generator-owner', obligations);
      const path = literalValue(pathTerm);
      validatePath(path, artefact.value, obligations);
      if (pathRule) requiredOne(store, pathRule, p('pathPattern'), 'missing-path-pattern', obligations);
      if (component) {
        if (!validatedComponents.has(component.value)) {
          const componentObligationStart = obligations.length;
          if (!hasType(store, component, `${USF}CompilerComponent`)) obligations.push({ subject: component.value, predicate: RDF_TYPE.value, expected: `${USF}CompilerComponent`, observed: 0, kind: 'invalid-generator-owner' });
          requiredOne(store, component, p('semanticInputQuery'), 'missing-semantic-input-query', obligations);
          requiredOne(store, component, p('outputSchema'), 'missing-output-schema', obligations);
          requiredOne(store, component, p('outputPathRule'), 'missing-component-path-rule', obligations);
          requiredOne(store, component, p('integrityPolicy'), 'missing-integrity-policy', obligations);
          requiredOne(store, component, p('normalisationPolicy'), 'missing-normalisation-policy', obligations);
          if (!objects(store, component, p('missingSemanticsConstraint')).length) obligations.push({ subject: component.value, predicate: `${USF}missingSemanticsConstraint`, expected: 'one-or-more', observed: 0, kind: 'missing-fail-closed-constraint' });
          if (!objects(store, component, p('requiresEquivalenceKind')).length) obligations.push({ subject: component.value, predicate: `${USF}requiresEquivalenceKind`, expected: 'one-or-more', observed: 0, kind: 'missing-equivalence-contract' });
          if (obligations.length > componentObligationStart) {
            const failures = obligations.slice(componentObligationStart).map((item) => item.kind).sort();
            obligations.push({ subject: component.value, predicate: `${USF}generatedByComponent`, expected: 'complete-generator-contract', observed: failures, kind: 'incomplete-generator' });
          }
          validatedComponents.add(component.value);
        }
      }
      if (path && kindTerm && component) outputs.push({ plan: plan.value, artefact: artefact.value, path, artefactKind: iriValue(kindTerm), component: component.value, semanticResources: semanticResources.map(iriValue).filter(Boolean) });
    }
  }
  const byPath = new Map();
  for (const output of outputs) {
    const prior = byPath.get(output.path);
    if (prior) obligations.push({ subject: output.artefact, predicate: `${USF}canonicalPath`, expected: 'unique-output-path', observed: output.path, conflictsWith: prior.artefact, kind: 'path-collision' });
    else byPath.set(output.path, output);
  }
  const ordered = outputs.sort((a, b) => a.path.localeCompare(b.path) || a.artefact.localeCompare(b.artefact));
  return Object.freeze({ plans: plans.length, outputs: ordered, obligations: obligations.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))), complete: obligations.length === 0 });
}

export function requireCompleteGenerationPlan(store) {
  const plan = buildGenerationPlan(store);
  if (!plan.complete) throw new CompilerError('semantic generation plan is incomplete', { phase: 'plan', count: plan.obligations.length, obligations: plan.obligations.slice(0, 100) });
  return plan;
}
