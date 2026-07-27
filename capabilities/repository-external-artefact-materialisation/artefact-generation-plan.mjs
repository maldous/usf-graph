import { createHash } from 'node:crypto';
import { DataFactory } from 'n3';
import {
  USF,
  iriValue,
  literalValue,
  objects,
  oneObject,
  subjectsOfType,
} from '../semantic-model-compilation/authority-dataset.mjs';
import { CompilerError } from '../semantic-model-compilation/compiler.mjs';

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

const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

// Every field a materialisation operation needs, read from stored authority.
//
// A generation plan that named only a path and a generator could not produce a
// materialisation operation: the gateway's validator requires the exact artefact
// family, representation format and path role, and matches the filename against
// the family's declared naming pattern.
//
// Neither the family nor the format is inferred here. Both are STORED on the
// artefact (usf:artefactMaterialisationFamily, usf:artefactRepresentationFormat)
// under the authorised owner decision that every generated-projection output
// materialises as urn:usf:artefactfamily:generatedprojection. Everything else —
// target repository, storage class, path role, naming rule, generation mode,
// authority class, content addressing and the permitted format set — is derived
// from that family's unique materialisation rule and validated against the
// stored format. A missing, ambiguous or unauthorised value is an obligation,
// never a guess.
function resolveMaterialisation(store, artefact, path, targetRepository, obligations) {
  const record = (item) => { obligations.push(item); return null; };
  const family = objects(store, artefact, p('artefactMaterialisationFamily'));
  if (family.length !== 1) {
    return record({ subject: artefact.value, predicate: `${USF}artefactMaterialisationFamily`, expected: 'exactly-one', observed: family.length, kind: 'unresolved-materialisation-family' });
  }
  const declaredFormat = objects(store, artefact, p('artefactRepresentationFormat'));
  if (declaredFormat.length !== 1) {
    return record({ subject: artefact.value, predicate: `${USF}artefactRepresentationFormat`, expected: 'exactly-one', observed: declaredFormat.length, kind: 'unresolved-representation-format' });
  }
  if (!isSemanticallyCurrent(store, family[0])) {
    return record({ subject: artefact.value, predicate: `${USF}artefactMaterialisationFamily`, expected: 'independently-warranted-retained-family', observed: family[0].value, kind: 'superseded-materialisation-family' });
  }

  const rules = objects(store, family[0], p('usesMaterialisationRule')).filter((rule) => isSemanticallyCurrent(store, rule));
  if (rules.length !== 1) {
    return record({ subject: family[0].value, predicate: `${USF}usesMaterialisationRule`, expected: 'exactly-one-current-rule', observed: rules.length, kind: 'ambiguous-materialisation-rule' });
  }
  const rule = rules[0];
  const format = declaredFormat[0];
  const permitted = objects(store, rule, p('usesRepresentationFormat')).map((item) => item.value);
  if (!permitted.includes(format.value)) {
    return record({ subject: artefact.value, predicate: `${USF}artefactRepresentationFormat`, expected: 'format-permitted-by-materialisation-rule', observed: format.value, rule: rule.value, kind: 'unauthorised-representation-format' });
  }

  const single = (subject, local, kind) => {
    const values = objects(store, subject, p(local));
    if (values.length === 1) return values[0];
    obligations.push({ subject: subject.value, predicate: `${USF}${local}`, expected: 'exactly-one', observed: values.length, kind });
    return null;
  };
  const pathRole = single(rule, 'usesPathRole', 'missing-path-role');
  const storageClass = single(rule, 'usesStorageClass', 'missing-storage-class');
  const namingRule = single(rule, 'usesNamingRule', 'missing-naming-rule');
  const generationMode = single(rule, 'usesGenerationMode', 'missing-generation-mode');
  const authorityClass = single(rule, 'usesAuthorityClass', 'missing-authority-class');
  const contentAddressing = literalValue(oneObject(store, rule, p('contentAddressingRequired')));
  const mediaType = literalValue(oneObject(store, format, p('canonicalMediaType')));
  const canonicalExtension = literalValue(oneObject(store, format, p('canonicalExtension')));
  if (!pathRole || !storageClass || !namingRule || !generationMode || !authorityClass) return null;
  if (contentAddressing === null) {
    return record({ subject: rule.value, predicate: `${USF}contentAddressingRequired`, expected: 'exactly-one', observed: null, kind: 'missing-content-addressing' });
  }
  if (!mediaType) {
    return record({ subject: format.value, predicate: `${USF}canonicalMediaType`, expected: 'exactly-one', observed: null, kind: 'missing-mediatype' });
  }
  const namingPattern = literalValue(oneObject(store, namingRule, p('filenamePattern')));
  if (!namingPattern) {
    return record({ subject: namingRule.value, predicate: `${USF}filenamePattern`, expected: 'exactly-one', observed: null, kind: 'missing-namingpattern' });
  }

  // The stored destination must actually accept this path and filename.
  const parents = objects(store, pathRole, p('authorisedParentPath')).map(literalValue).filter(Boolean);
  if (!parents.some((parent) => parent === '.' ? !path.includes('/') : path === parent || path.startsWith(`${parent}/`))) {
    return record({ subject: artefact.value, predicate: `${USF}authorisedParentPath`, expected: parents.sort(), observed: path, kind: 'path-outside-authorised-parent' });
  }
  if (!new RegExp(namingPattern).test(path.split('/').pop())) {
    return record({ subject: artefact.value, predicate: `${USF}filenamePattern`, expected: namingPattern, observed: path, kind: 'filename-violates-naming-rule' });
  }
  if (!targetRepository) {
    return record({ subject: artefact.value, predicate: `${USF}ownedByRepository`, expected: 'exactly-one', observed: null, kind: 'missing-target-repository' });
  }

  return {
    artefactFamily: family[0].value,
    materialisationRule: rule.value,
    representationFormat: format.value,
    canonicalExtension,
    mediaType,
    pathRole: pathRole.value,
    storageClass: storageClass.value,
    namingRule: namingRule.value,
    namingPattern,
    generationMode: generationMode.value,
    authorityClass: authorityClass.value,
    contentAddressingRequired: contentAddressing === 'true',
  };
}

function resolveGenerator(store, component) {
  const query = literalValue(oneObject(store, component, p('semanticInputQuery')));
  return {
    generator: component.value,
    semanticInputQuery: query,
    semanticInputQueryDigest: query ? sha256(query) : null,
    outputSchema: objects(store, component, p('outputSchema'))[0]?.value ?? null,
    outputPathRule: objects(store, component, p('outputPathRule'))[0]?.value ?? null,
    generationPolicy: objects(store, component, p('integrityPolicy'))[0]?.value ?? null,
    normalisationPolicy: objects(store, component, p('normalisationPolicy'))[0]?.value ?? null,
    requiresEquivalenceKind: objects(store, component, p('requiresEquivalenceKind')).map(iriValue).filter(Boolean).sort(),
    missingSemanticsConstraint: objects(store, component, p('missingSemanticsConstraint')).map(iriValue).filter(Boolean).sort(),
  };
}

export function buildGenerationPlan(store) {
  const obligations = [];
  // Destination-resolution gaps are reported separately from generation
  // completeness: a generator can produce correct bytes for an output whose
  // materialisation destination authority has not yet decided. The factory
  // refuses to materialise those; it does not stop the deliverable being built.
  const materialisationObligations = [];
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
      if (path && kindTerm && component) {
        const materialisation = resolveMaterialisation(store, artefact, path, owners.length === 1 ? iriValue(owners[0]) : null, materialisationObligations);
        outputs.push({
          plan: plan.value,
          artefact: artefact.value,
          path,
          artefactKind: iriValue(kindTerm),
          component: component.value,
          semanticResources: semanticResources.map(iriValue).filter(Boolean),
          // Authority-derived materialisation identity. `component` is retained
          // under its historical name; `generator` is the same IRI named as the
          // enriched contract names it.
          targetRepository: owners.length === 1 ? iriValue(owners[0]) : null,
          pathRule: pathRule ? iriValue(pathRule) : null,
          outputMode: 'materialise-generated-untracked',
          dependencies: [plan.value, artefact.value, component.value, ...semanticResources.map(iriValue).filter(Boolean)].sort(),
          ...resolveGenerator(store, component),
          ...(materialisation ?? {}),
          materialisationResolved: materialisation !== null,
        });
      }
    }
  }
  const byPath = new Map();
  for (const output of outputs) {
    const prior = byPath.get(output.path);
    if (prior) obligations.push({ subject: output.artefact, predicate: `${USF}canonicalPath`, expected: 'unique-output-path', observed: output.path, conflictsWith: prior.artefact, kind: 'path-collision' });
    else byPath.set(output.path, output);
  }
  // One deterministic canonical final ordering, kept as the plan's own order.
  const ordered = outputs.sort((a, b) => a.path.localeCompare(b.path) || a.artefact.localeCompare(b.artefact));
  // Execution and accounting group by generator; the grouping references the
  // canonical ordering rather than reordering it, so there is exactly one final
  // sequence no matter which view a consumer reads.
  const byGenerator = new Map();
  ordered.forEach((output, index) => {
    const group = byGenerator.get(output.component) ?? { generator: output.component, outputIndexes: [], outputCount: 0 };
    group.outputIndexes.push(index);
    group.outputCount += 1;
    byGenerator.set(output.component, group);
  });
  const generatorGroups = [...byGenerator.values()]
    .sort((left, right) => left.generator.localeCompare(right.generator))
    .map((group) => Object.freeze({ ...group, outputIndexes: Object.freeze(group.outputIndexes) }));
  return Object.freeze({
    plans: plans.length,
    outputs: ordered,
    generatorGroups: Object.freeze(generatorGroups),
    generatorCount: generatorGroups.length,
    unresolvedOutputs: Object.freeze(ordered.filter((output) => output.materialisationResolved !== true).map((output) => output.path)),
    materialisationObligations: Object.freeze(materialisationObligations
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))),
    materialisationComplete: materialisationObligations.length === 0,
    obligations: obligations.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    complete: obligations.length === 0,
  });
}

export function requireCompleteGenerationPlan(store) {
  const plan = buildGenerationPlan(store);
  if (!plan.complete) throw new CompilerError('semantic generation plan is incomplete', { phase: 'plan', count: plan.obligations.length, obligations: plan.obligations.slice(0, 100) });
  return plan;
}
