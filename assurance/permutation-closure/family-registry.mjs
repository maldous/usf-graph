import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import N3 from 'n3';
import {
  canonicalJson,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';

const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
const RDFS = 'http://www.w3.org/2000/01/rdf-schema#';
const OWL = 'http://www.w3.org/2002/07/owl#';
const XSD = 'http://www.w3.org/2001/XMLSchema#';
const O = 'urn:usf:ontology:';
const TYPE = `${RDF}type`;
const named = N3.DataFactory.namedNode;
const compare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const uniqueSorted = (values) => [...new Set(values)].sort(compare);
const localName = (iri) => iri.startsWith(O) ? iri.slice(O.length) : iri.split(':').at(-1);

const TYPES = Object.freeze({
  clause: `${O}PermutationApplicabilityClause`,
  classClosure: `${O}PermutationClassClosure`,
  derivation: `${O}PermutationValueDerivation`,
  derivationOperand: `${O}PermutationValueDerivationOperand`,
  family: `${O}PermutationFamily`,
  operand: `${O}PermutationApplicabilityOperand`,
  rule: `${O}PermutationApplicabilityRule`,
  selector: `${O}PermutationSignalSelector`,
  step: `${O}PermutationSignalPathStep`,
  subjectRegistration: `${O}PermutationSubjectRegistration`,
});

const P = Object.freeze({
  aggregation: `${O}selectorAggregation`,
  axisClassClosure: `${O}dimensionAxisClassClosure`,
  canonicalName: `${O}canonicalName`,
  classClosureDigest: `${O}classClosureDigest`,
  classClosureEdgeSetDigest: `${O}classClosureEdgeSetDigest`,
  classClosureMemberClass: `${O}classClosureMemberClass`,
  classClosureMemberSetDigest: `${O}classClosureMemberSetDigest`,
  classClosurePolicy: `${O}classClosurePolicy`,
  classClosureRootClass: `${O}classClosureRootClass`,
  clauseOperand: `${O}applicabilityClauseOperand`,
  clauseOperator: `${O}applicabilityClauseOperator`,
  dimension: `${O}bindsDimension`,
  dimensionBinding: `${O}hasFamilyDimensionBinding`,
  dimensionKey: `${O}permutationDimensionKey`,
  dimensionPosition: `${O}dimensionPosition`,
  dimensionValueSource: `${O}dimensionValueSource`,
  expectedValue: `${O}applicabilityExpectedValue`,
  familyRule: `${O}familyApplicabilityRule`,
  familySubjectRegistration: `${O}familySubjectRegistration`,
  operandClause: `${O}applicabilityOperandClause`,
  operandIndex: `${O}applicabilityOperandIndex`,
  plane: `${O}registeredFamilyPlane`,
  rootClause: `${O}applicabilityRootClause`,
  ruleDigest: `${O}applicabilityRuleDigest`,
  satisfiedDisposition: `${O}applicabilitySatisfiedDisposition`,
  selector: `${O}applicabilitySignalSelector`,
  selectorDigest: `${O}selectorDigest`,
  selectorSubjectClassClosure: `${O}selectorSubjectClassClosure`,
  selectorStep: `${O}selectorPathStep`,
  selectorTerminalClassClosure: `${O}selectorTerminalClassClosure`,
  stepDirection: `${O}signalPathStepDirection`,
  stepIndex: `${O}signalPathStepIndex`,
  stepPredicate: `${O}signalPathStepPredicate`,
  subjectClass: `${O}registeredSubjectClass`,
  subjectClassClosure: `${O}subjectClassClosure`,
  selectorSubjectClass: `${O}selectorSubjectClass`,
  terminalClass: `${O}selectorTerminalClass`,
  threshold: `${O}applicabilityThreshold`,
  unsatisfiedDisposition: `${O}applicabilityUnsatisfiedDisposition`,
  unsatisfiedReason: `${O}applicabilityUnsatisfiedReason`,
  valueSourceSelector: `${O}valueSourceSelector`,
  valueSourceDerivationRoot: `${O}valueSourceDerivationRoot`,
  valueSourceDigest: `${O}valueSourceDigest`,
  valueSourceDerivationPredicate: `${O}valueSourceDerivationPredicate`,
  valueSourceClassIri: `${O}valueSourceClassIri`,
  valueSourceKind: `${O}valueSourceKind`,
  valueSourceScope: `${O}valueSourceScope`,
  valueSourceTerminalClass: `${O}valueSourceTerminalClass`,
  valueDerivationClass: `${O}valueDerivationClass`,
  valueDerivationClassClosure: `${O}valueDerivationClassClosure`,
  valueDerivationOperator: `${O}valueDerivationOperator`,
  valueDerivationOperand: `${O}valueDerivationOperand`,
  valueDerivationOperandExpression: `${O}valueDerivationOperandExpression`,
  valueDerivationPathStep: `${O}valueDerivationPathStep`,
});

const CLASS_CLOSURE_POLICIES = Object.freeze({
  exact: 'urn:usf:classclosurepolicy:exactdeclaredclass',
  transitive: 'urn:usf:classclosurepolicy:declaredtransitivesubclass',
});

const CLASS_BEARING_DERIVATION_OPERATORS = new Set([
  'urn:usf:permutationvaluederivationoperator:classinstances',
  'urn:usf:permutationvaluederivationoperator:filtertypeany',
]);

export const FAMILY_PLANES = Object.freeze({
  assurance: 'urn:usf:permutationfamilyplane:assuranceobligation',
  runtime: 'urn:usf:permutationfamilyplane:runtimebehaviour',
});

const OPERATORS = Object.freeze({
  allOf: 'urn:usf:permutationapplicabilityoperator:allof',
  anyOf: 'urn:usf:permutationapplicabilityoperator:anyof',
  countAtLeast: 'urn:usf:permutationapplicabilityoperator:countatleast',
  countExactly: 'urn:usf:permutationapplicabilityoperator:countexactly',
  not: 'urn:usf:permutationapplicabilityoperator:not',
  true: 'urn:usf:permutationapplicabilityoperator:true',
  valueEquals: 'urn:usf:permutationapplicabilityoperator:valueequals',
  valueInDeclaredSet: 'urn:usf:permutationapplicabilityoperator:valueindeclaredset',
});

const AGGREGATIONS = Object.freeze({
  countDistinct: 'urn:usf:permutationsignalaggregation:countdistinct',
  distinctValues: 'urn:usf:permutationsignalaggregation:distinctvalues',
});

const DIRECTIONS = Object.freeze({
  inbound: 'urn:usf:permutationpathdirection:inbound',
  outbound: 'urn:usf:permutationpathdirection:outbound',
});

export class FamilyRegistryError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'FamilyRegistryError';
    this.code = code;
    this.details = details;
  }
}

const fail = (code, message, details) => {
  throw new FamilyRegistryError(code, message, details);
};

function objects(store, subjectIri, predicateIri) {
  return store.getObjects(named(subjectIri), named(predicateIri), null);
}

function exactTerm(store, subjectIri, predicateIri, code) {
  const values = objects(store, subjectIri, predicateIri);
  if (values.length !== 1) fail(code, `${subjectIri} requires exactly one ${predicateIri}`, { count: values.length });
  return values[0];
}

function exactIri(store, subjectIri, predicateIri, code) {
  const value = exactTerm(store, subjectIri, predicateIri, code);
  if (value.termType !== 'NamedNode') fail(code, `${subjectIri} ${predicateIri} must be an IRI`);
  return value.value;
}

function exactLiteral(store, subjectIri, predicateIri, code) {
  const value = exactTerm(store, subjectIri, predicateIri, code);
  if (value.termType !== 'Literal') fail(code, `${subjectIri} ${predicateIri} must be a literal`);
  return value.value;
}

function optionalTerms(store, subjectIri, predicateIri) {
  return objects(store, subjectIri, predicateIri);
}

function exactInteger(store, subjectIri, predicateIri, code) {
  const term = exactTerm(store, subjectIri, predicateIri, code);
  if (term.termType !== 'Literal' || !/^[0-9]+$/u.test(term.value)
    || ![`${XSD}integer`, `${XSD}nonNegativeInteger`, `${XSD}positiveInteger`].includes(term.datatype.value)) {
    fail(code, `${subjectIri} ${predicateIri} must be a non-negative integer`);
  }
  return Number(term.value);
}

function typedSubjects(store, classIri) {
  return uniqueSorted(store.getSubjects(named(TYPE), named(classIri), null).map(({ value }) => value));
}

function assertExactReachability(actualValues, expectedValues, code, kind) {
  const actual = uniqueSorted(actualValues);
  const expected = uniqueSorted(expectedValues);
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(code, `${kind} registry reachability is incomplete`, {
      missing: expected.filter((value) => !actual.includes(value)),
      unexpected: actual.filter((value) => !expected.includes(value)),
    });
  }
}

function assertUniqueContiguous(records, property, code, owner) {
  const values = records.map((record) => record[property]);
  if (new Set(values).size !== values.length
    || values.some((value, index) => value !== index + 1)) {
    fail(code, `${owner} indexes must be unique and contiguous from one`, { values });
  }
}

function declaredClass(store, classIri) {
  return classIri === `${OWL}Class` || classIri === `${RDFS}Class`
    || [`${OWL}Class`, `${RDFS}Class`].some((kind) => (
    store.countQuads(named(classIri), named(TYPE), named(kind), null) > 0
    ));
}

function reconstructClassClosure(store, rootClassIri, policyIri) {
  if (!declaredClass(store, rootClassIri)) {
    fail('CLASS_CLOSURE_ROOT_UNDECLARED', `${rootClassIri} is not a declared named class`);
  }
  const members = new Set([rootClassIri]);
  const active = new Set();
  const visit = (classIri) => {
    if (active.has(classIri)) fail('CLASS_CLOSURE_CYCLE', `${rootClassIri} contains a subclass cycle at ${classIri}`);
    active.add(classIri);
    const children = store.getSubjects(named(`${RDFS}subClassOf`), named(classIri), null)
      .filter(({ termType }) => termType === 'NamedNode')
      .map(({ value }) => value)
      .sort(compare);
    for (const child of children) {
      if (!declaredClass(store, child)) fail('CLASS_CLOSURE_ROOT_UNDECLARED', `${child} is not a declared named class`);
      if (!members.has(child)) {
        members.add(child);
        visit(child);
      } else if (active.has(child)) {
        fail('CLASS_CLOSURE_CYCLE', `${rootClassIri} contains a subclass cycle at ${child}`);
      }
    }
    active.delete(classIri);
  };
  if (policyIri === CLASS_CLOSURE_POLICIES.transitive) visit(rootClassIri);
  else if (policyIri !== CLASS_CLOSURE_POLICIES.exact) {
    fail('CLASS_CLOSURE_POLICY_UNCONTROLLED', `${rootClassIri} uses ${policyIri}`);
  }
  const memberClassIris = [...members].sort(compare);
  const memberSet = new Set(memberClassIris);
  const subclassEdges = policyIri === CLASS_CLOSURE_POLICIES.exact ? [] : store
    .getQuads(null, named(`${RDFS}subClassOf`), null, null)
    .filter(({ subject, object }) => subject.termType === 'NamedNode' && object.termType === 'NamedNode'
      && memberSet.has(subject.value) && memberSet.has(object.value))
    .map(({ subject, object }) => [subject.value, object.value])
    .sort((left, right) => compare(canonicalJson(left), canonicalJson(right)));
  return { memberClassIris, subclassEdges };
}

export function classClosureCanonicalRecord({ rootClassIri, policyIri, memberClassIris, subclassEdges }) {
  return {
    memberClassIris,
    policyIri,
    rootClassIri,
    schemaVersion: 1,
    subclassEdges,
  };
}

function loadClassClosures(store, verifyStoredDigests) {
  const closures = new Map();
  const byRoot = new Map();
  for (const iri of typedSubjects(store, TYPES.classClosure)) {
    const rootClassIri = exactIri(store, iri, P.classClosureRootClass, 'CLASS_CLOSURE_ROOT_CARDINALITY');
    const policyIri = exactIri(store, iri, P.classClosurePolicy, 'CLASS_CLOSURE_POLICY_MISSING');
    const reconstructed = reconstructClassClosure(store, rootClassIri, policyIri);
    const declaredMembers = optionalTerms(store, iri, P.classClosureMemberClass);
    if (declaredMembers.some(({ termType }) => termType !== 'NamedNode')) {
      fail('CLASS_CLOSURE_MEMBER_UNEXPECTED', `${iri} contains a non-IRI member`);
    }
    const memberClassIris = uniqueSorted(declaredMembers.map(({ value }) => value));
    const missing = reconstructed.memberClassIris.filter((member) => !memberClassIris.includes(member));
    const unexpected = memberClassIris.filter((member) => !reconstructed.memberClassIris.includes(member));
    if (missing.length) fail('CLASS_CLOSURE_MEMBER_MISSING', `${iri} omits reconstructed members`, { missing });
    if (unexpected.length) fail('CLASS_CLOSURE_MEMBER_UNEXPECTED', `${iri} contains unexpected members`, { unexpected });
    const record = classClosureCanonicalRecord({
      memberClassIris,
      policyIri,
      rootClassIri,
      subclassEdges: reconstructed.subclassEdges,
    });
    const memberSetDigest = sha256(canonicalJson(memberClassIris));
    const edgeSetDigest = sha256(canonicalJson(reconstructed.subclassEdges));
    const digest = sha256(canonicalJson(record));
    const storedMemberSetDigest = exactLiteral(store, iri, P.classClosureMemberSetDigest,
      'CLASS_CLOSURE_MEMBER_SET_DIGEST_MISMATCH');
    const storedEdgeSetDigest = exactLiteral(store, iri, P.classClosureEdgeSetDigest,
      'CLASS_CLOSURE_EDGE_SET_DIGEST_MISMATCH');
    const storedDigest = exactLiteral(store, iri, P.classClosureDigest, 'CLASS_CLOSURE_DIGEST_MISMATCH');
    if (verifyStoredDigests && storedMemberSetDigest !== memberSetDigest) {
      fail('CLASS_CLOSURE_MEMBER_SET_DIGEST_MISMATCH', `${iri} member-set digest is stale`);
    }
    if (verifyStoredDigests && storedEdgeSetDigest !== edgeSetDigest) {
      fail('CLASS_CLOSURE_EDGE_SET_DIGEST_MISMATCH', `${iri} edge-set digest is stale`);
    }
    if (verifyStoredDigests && storedDigest !== digest) {
      fail('CLASS_CLOSURE_DIGEST_MISMATCH', `${iri} closure digest is stale`);
    }
    if (byRoot.has(rootClassIri)) fail('CLASS_CLOSURE_POLICY_MULTIPLE', `${rootClassIri} has multiple closure resources`);
    const closure = Object.freeze({
      digest,
      edgeSetDigest,
      iri,
      memberClassIris: Object.freeze(memberClassIris),
      memberSetDigest,
      policyIri,
      rootClassIri,
      subclassEdges: Object.freeze(reconstructed.subclassEdges),
    });
    closures.set(iri, closure);
    byRoot.set(rootClassIri, closure);
  }
  return { byRoot, closures };
}

function exactClosure(store, ownerIri, predicateIri, closures, code) {
  const closureIri = exactIri(store, ownerIri, predicateIri, code);
  const closure = closures.get(closureIri);
  if (!closure) fail(code, `${ownerIri} references unknown class closure ${closureIri}`);
  return closure;
}

export function selectorCanonicalRecord(selector) {
  return {
    aggregationIri: selector.aggregationIri,
    canonicalName: selector.canonicalName,
    schemaVersion: 2,
    selectorIri: selector.iri,
    steps: selector.steps.map(({ directionIri, index, predicateIri }) => ({
      directionIri,
      index,
      predicateIri,
    })),
    subjectClassIri: selector.subjectClassIri,
    subjectClassClosureDigest: selector.subjectClassClosure.digest,
    terminalClassIri: selector.terminalClassIri,
    terminalClassClosureDigest: selector.terminalClassClosure.digest,
  };
}

function loadSelectors(store, closures, verifyStoredDigests) {
  const selectors = new Map();
  for (const iri of typedSubjects(store, TYPES.selector)) {
    const steps = optionalTerms(store, iri, P.selectorStep).map(({ value: stepIri }) => ({
      canonicalName: exactLiteral(store, stepIri, P.canonicalName, 'SELECTOR_STEP_NAME_CARDINALITY'),
      directionIri: exactIri(store, stepIri, P.stepDirection, 'SELECTOR_STEP_DIRECTION_CARDINALITY'),
      index: exactInteger(store, stepIri, P.stepIndex, 'SELECTOR_STEP_INDEX_INVALID'),
      iri: stepIri,
      predicateIri: exactIri(store, stepIri, P.stepPredicate, 'SELECTOR_STEP_PREDICATE_CARDINALITY'),
    })).sort((left, right) => left.index - right.index);
    if (steps.length === 0) fail('SELECTOR_PATH_EMPTY', `${iri} has no path steps`);
    assertUniqueContiguous(steps, 'index', 'SELECTOR_PATH_INDEX_INVALID', iri);
    for (const step of steps) {
      if (!Object.values(DIRECTIONS).includes(step.directionIri)) {
        fail('SELECTOR_STEP_DIRECTION_UNCONTROLLED', `${step.iri} has unsupported direction ${step.directionIri}`);
      }
    }
    const selector = {
      aggregationIri: exactIri(store, iri, P.aggregation, 'SELECTOR_AGGREGATION_CARDINALITY'),
      canonicalName: exactLiteral(store, iri, P.canonicalName, 'SELECTOR_NAME_CARDINALITY'),
      iri,
      steps,
      storedDigest: exactLiteral(store, iri, P.selectorDigest, 'SELECTOR_DIGEST_CARDINALITY'),
      subjectClassIri: exactIri(store, iri, P.selectorSubjectClass, 'SELECTOR_SUBJECT_CLASS_CARDINALITY'),
      terminalClassIri: exactIri(store, iri, P.terminalClass, 'SELECTOR_TERMINAL_CLASS_CARDINALITY'),
    };
    selector.subjectClassClosure = exactClosure(store, iri, P.selectorSubjectClassClosure, closures,
      'CLASS_CLOSURE_POLICY_MISSING');
    selector.terminalClassClosure = exactClosure(store, iri, P.selectorTerminalClassClosure, closures,
      'CLASS_CLOSURE_POLICY_MISSING');
    if (selector.subjectClassClosure.rootClassIri !== selector.subjectClassIri) {
      fail('SELECTOR_SUBJECT_CLASS_CLOSURE_MISMATCH', `${iri} subject closure root differs`);
    }
    if (selector.terminalClassClosure.rootClassIri !== selector.terminalClassIri) {
      fail('SELECTOR_TERMINAL_CLASS_CLOSURE_MISMATCH', `${iri} terminal closure root differs`);
    }
    if (!Object.values(AGGREGATIONS).includes(selector.aggregationIri)) {
      fail('SELECTOR_AGGREGATION_UNCONTROLLED', `${iri} has unsupported aggregation ${selector.aggregationIri}`);
    }
    selector.digest = sha256(canonicalJson(selectorCanonicalRecord(selector)));
    if (verifyStoredDigests && selector.storedDigest !== selector.digest) {
      fail('SELECTOR_DIGEST_MISMATCH', `${iri} stored digest does not bind its canonical selector`, {
        actual: selector.storedDigest,
        expected: selector.digest,
      });
    }
    selectors.set(iri, Object.freeze(selector));
  }
  return selectors;
}

function canonicalRdfTerm(term) {
  if (term.termType === 'NamedNode') return { termType: 'NamedNode', value: term.value };
  if (term.termType === 'Literal') {
    return {
      datatypeIri: term.datatype.value,
      language: term.language,
      termType: 'Literal',
      value: term.value,
    };
  }
  fail('APPLICABILITY_EXPECTED_VALUE_INVALID', `unsupported RDF term ${term.termType}`);
}

function loadRules(store, selectors, verifyStoredDigests) {
  const clauseCache = new Map();

  const clauseRecord = (iri, visiting = new Set()) => {
    if (clauseCache.has(iri)) return clauseCache.get(iri);
    if (visiting.has(iri)) fail('APPLICABILITY_EXPRESSION_CYCLE', `${iri} is cyclic`);
    const nextVisiting = new Set(visiting).add(iri);
    const operatorIri = exactIri(store, iri, P.clauseOperator, 'APPLICABILITY_OPERATOR_CARDINALITY');
    if (!Object.values(OPERATORS).includes(operatorIri)) {
      fail('APPLICABILITY_OPERATOR_UNSUPPORTED', `${iri} uses ${operatorIri}`);
    }
    const selectorTerms = optionalTerms(store, iri, P.selector);
    const thresholdTerms = optionalTerms(store, iri, P.threshold);
    const expectedValues = optionalTerms(store, iri, P.expectedValue)
      .map(canonicalRdfTerm)
      .sort((left, right) => compare(canonicalJson(left), canonicalJson(right)));
    if (new Set(expectedValues.map(canonicalJson)).size !== expectedValues.length) {
      fail('APPLICABILITY_EXPECTED_VALUE_INVALID', `${iri} contains duplicate expected values`);
    }
    const operands = optionalTerms(store, iri, P.clauseOperand).map(({ value: operandIri }) => ({
      clauseIri: exactIri(store, operandIri, P.operandClause, 'APPLICABILITY_OPERAND_CLAUSE_CARDINALITY'),
      index: exactInteger(store, operandIri, P.operandIndex, 'APPLICABILITY_OPERAND_INDEX_INVALID'),
      iri: operandIri,
    })).sort((left, right) => left.index - right.index);
    assertUniqueContiguous(operands, 'index', 'APPLICABILITY_OPERAND_INDEX_INVALID', iri);

    const selectorRequired = [OPERATORS.countAtLeast, OPERATORS.countExactly,
      OPERATORS.valueEquals, OPERATORS.valueInDeclaredSet].includes(operatorIri);
    const thresholdRequired = [OPERATORS.countAtLeast, OPERATORS.countExactly].includes(operatorIri);
    const expectedRequired = [OPERATORS.valueEquals, OPERATORS.valueInDeclaredSet].includes(operatorIri);
    const operandRange = operatorIri === OPERATORS.not ? [1, 1]
      : [OPERATORS.allOf, OPERATORS.anyOf].includes(operatorIri) ? [2, Number.POSITIVE_INFINITY] : [0, 0];
    if (selectorTerms.length !== (selectorRequired ? 1 : 0)) {
      fail('APPLICABILITY_SELECTOR_CARDINALITY_INVALID', `${iri} selector cardinality is invalid`);
    }
    if (thresholdTerms.length !== (thresholdRequired ? 1 : 0)) {
      fail('APPLICABILITY_THRESHOLD_INVALID', `${iri} threshold cardinality is invalid`);
    }
    if ((expectedRequired && expectedValues.length < 1) || (!expectedRequired && expectedValues.length !== 0)) {
      fail('APPLICABILITY_EXPECTED_VALUE_INVALID', `${iri} expected-value cardinality is invalid`);
    }
    if (operatorIri === OPERATORS.valueEquals && expectedValues.length !== 1) {
      fail('APPLICABILITY_EXPECTED_VALUE_INVALID', `${iri} valueequals requires exactly one value`);
    }
    if (operands.length < operandRange[0] || operands.length > operandRange[1]) {
      fail('APPLICABILITY_OPERATOR_ARITY_INVALID', `${iri} operand cardinality is invalid`);
    }
    const selectorIri = selectorTerms[0]?.value ?? null;
    const selector = selectorIri ? selectors.get(selectorIri) : null;
    if (selectorIri && !selector) fail('APPLICABILITY_SELECTOR_UNKNOWN', `${iri} references ${selectorIri}`);
    const threshold = thresholdRequired
      ? exactInteger(store, iri, P.threshold, 'APPLICABILITY_THRESHOLD_INVALID')
      : null;
    const record = {
      canonicalName: exactLiteral(store, iri, P.canonicalName, 'APPLICABILITY_CLAUSE_NAME_CARDINALITY'),
      clauseIri: iri,
      expectedValues,
      operands: operands.map((operand) => ({
        clause: clauseRecord(operand.clauseIri, nextVisiting),
        index: operand.index,
      })),
      operatorIri,
      selectorDigest: selector?.digest ?? null,
      selectorIri,
      threshold,
    };
    clauseCache.set(iri, Object.freeze(record));
    return clauseCache.get(iri);
  };

  const rules = new Map();
  for (const iri of typedSubjects(store, TYPES.rule)) {
    const record = {
      canonicalName: exactLiteral(store, iri, P.canonicalName, 'APPLICABILITY_RULE_NAME_CARDINALITY'),
      rootClause: clauseRecord(exactIri(store, iri, P.rootClause, 'APPLICABILITY_ROOT_CARDINALITY')),
      ruleIri: iri,
      satisfiedDispositionIri: exactIri(store, iri, P.satisfiedDisposition, 'APPLICABILITY_SATISFIED_DISPOSITION_CARDINALITY'),
      schemaVersion: 1,
      unsatisfiedDispositionIri: exactIri(store, iri, P.unsatisfiedDisposition, 'APPLICABILITY_UNSATISFIED_DISPOSITION_CARDINALITY'),
      unsatisfiedReasonIri: exactIri(store, iri, P.unsatisfiedReason, 'APPLICABILITY_UNSATISFIED_REASON_CARDINALITY'),
    };
    const storedDigest = exactLiteral(store, iri, P.ruleDigest, 'APPLICABILITY_RULE_DIGEST_CARDINALITY');
    const ruleDigest = sha256(canonicalJson(record));
    if (verifyStoredDigests && storedDigest !== ruleDigest) {
      fail('RULE_DIGEST_MISMATCH', `${iri} stored digest does not bind its recursive rule`, {
        actual: storedDigest,
        expected: ruleDigest,
      });
    }
    rules.set(iri, Object.freeze({ ...record, ruleDigest, storedDigest }));
  }
  return rules;
}

function parseRegistryStore(repositoryRoot) {
  const store = new N3.Store();
  for (const relativePath of [
    'semantic-model/ontology.ttl',
    'semantic-model/permutation/closure-vocabulary.trig',
    'semantic-model/permutation/families.trig',
  ]) {
    const parser = new N3.Parser({ baseIRI: `file://${join(repositoryRoot, relativePath)}` });
    store.addQuads(parser.parse(readFileSync(join(repositoryRoot, relativePath), 'utf8')));
  }
  return store;
}

export function loadPermutationFamilyRegistry({ repositoryRoot, verifyStoredDigests = true }) {
  if (!repositoryRoot) fail('FAMILY_REGISTRY_ROOT_REQUIRED', 'repositoryRoot is required');
  const store = parseRegistryStore(repositoryRoot);
  const { byRoot: classClosuresByRoot, closures: classClosures } = loadClassClosures(store, verifyStoredDigests);
  const selectors = loadSelectors(store, classClosures, verifyStoredDigests);
  const rules = loadRules(store, selectors, verifyStoredDigests);
  const allowedPlanes = new Set(Object.values(FAMILY_PLANES));
  const families = typedSubjects(store, TYPES.family).map((iri) => {
    const registrationIri = exactIri(store, iri, P.familySubjectRegistration,
      'FAMILY_SUBJECT_REGISTRATION_CARDINALITY');
    const ruleIri = exactIri(store, iri, P.familyRule, 'FAMILY_APPLICABILITY_RULE_CARDINALITY');
    const rule = rules.get(ruleIri);
    if (!rule) fail('FAMILY_APPLICABILITY_RULE_UNKNOWN', `${iri} references ${ruleIri}`);
    const subjectClassIri = exactIri(store, registrationIri, P.subjectClass,
      'REGISTERED_SUBJECT_CLASS_CARDINALITY');
    const subjectClassClosure = exactClosure(store, registrationIri, P.subjectClassClosure, classClosures,
      'CLASS_CLOSURE_POLICY_MISSING');
    if (subjectClassClosure.rootClassIri !== subjectClassIri) {
      fail('REGISTERED_SUBJECT_CLASS_CLOSURE_MISMATCH', `${registrationIri} closure root differs`);
    }
    const planeIri = exactIri(store, registrationIri, P.plane,
      'REGISTERED_FAMILY_PLANE_CARDINALITY');
    if (!allowedPlanes.has(planeIri)) {
      fail('REGISTERED_FAMILY_PLANE_UNCONTROLLED', `${registrationIri} uses ${planeIri}`);
    }
    const bindings = optionalTerms(store, iri, P.dimensionBinding).map(({ value: bindingIri }) => {
      const dimensionIri = exactIri(store, bindingIri, P.dimension, 'FAMILY_DIMENSION_CARDINALITY');
      const sourceIri = exactIri(store, dimensionIri, P.dimensionValueSource,
        'FAMILY_DIMENSION_VALUE_SOURCE_CARDINALITY');
      const selectorTerms = optionalTerms(store, sourceIri, P.valueSourceSelector);
      if (selectorTerms.length > 1 || selectorTerms.some(({ termType }) => termType !== 'NamedNode')) {
        fail('VALUE_SOURCE_SELECTOR_CARDINALITY_INVALID', `${sourceIri} has an invalid value-source selector`);
      }
      const valueSelectorIri = selectorTerms[0]?.value ?? null;
      const derivationRootTerms = optionalTerms(store, sourceIri, P.valueSourceDerivationRoot);
      if (derivationRootTerms.length > 1 || derivationRootTerms.some(({ termType }) => termType !== 'NamedNode')) {
        fail('VALUE_SOURCE_DERIVATION_ROOT_CARDINALITY', `${sourceIri} has an invalid derivation root`);
      }
      const valueDerivationRootIri = derivationRootTerms[0]?.value ?? null;
      if (valueSelectorIri && !selectors.has(valueSelectorIri)) {
        fail('VALUE_SOURCE_SELECTOR_UNKNOWN', `${sourceIri} references ${valueSelectorIri}`);
      }
      const sourceKind = exactLiteral(store, sourceIri, P.valueSourceKind,
        'VALUE_SOURCE_KIND_CARDINALITY_INVALID');
      const sourceScopeIri = exactIri(store, sourceIri, P.valueSourceScope,
        'VALUE_SOURCE_SCOPE_CARDINALITY_INVALID');
      const derivationPredicateIris = optionalTerms(store, sourceIri, P.valueSourceDerivationPredicate)
        .map(({ value }) => value).sort(compare);
      const registeredScope = 'urn:usf:dimensionvaluesourcescope:registeredsubjectrelationship';
      if (valueSelectorIri && (sourceKind !== 'derivedselector' || sourceScopeIri !== registeredScope)) {
        fail('VALUE_SOURCE_SELECTOR_SCOPE_INVALID', `${sourceIri} selector requires registered-subject derivation scope`);
      }
      if (!valueSelectorIri && sourceScopeIri === registeredScope) {
        fail('VALUE_SOURCE_SELECTOR_CARDINALITY_INVALID', `${sourceIri} registered-subject scope requires one selector`);
      }
      if (valueDerivationRootIri && (sourceKind !== 'derivedselector' || sourceScopeIri === registeredScope)) {
        fail('VALUE_SOURCE_DERIVATION_MODE_CONFLICT', `${sourceIri} expression binding is incompatible with its mode`);
      }
      if (sourceKind === 'derivedselector' && sourceScopeIri !== registeredScope && !valueDerivationRootIri) {
        fail('VALUE_SOURCE_DERIVATION_ROOT_CARDINALITY', `${sourceIri} requires one semantic derivation root`);
      }
      if (sourceKind !== 'derivedselector' && (valueSelectorIri || valueDerivationRootIri)) {
        fail('VALUE_SOURCE_DERIVATION_MODE_CONFLICT', `${sourceIri} is not a derived source`);
      }
      if (valueSelectorIri) {
        const selector = selectors.get(valueSelectorIri);
        if (selector.aggregationIri !== AGGREGATIONS.distinctValues) {
          fail('VALUE_SOURCE_SELECTOR_AGGREGATION_INVALID', `${valueSelectorIri} must return distinct values`);
        }
        const selectorPredicates = uniqueSorted(selector.steps.map(({ predicateIri }) => predicateIri));
        if (canonicalJson(derivationPredicateIris) !== canonicalJson(selectorPredicates)) {
          fail('VALUE_SOURCE_SELECTOR_PREDICATE_MISMATCH', `${sourceIri} does not bind its selector path predicates`);
        }
      }
      let expectedAxisRoots;
      if (sourceKind === 'controlledlist') expectedAxisRoots = [`${O}PermutationDimensionValue`];
      else if (sourceKind === 'classinstances') {
        expectedAxisRoots = [exactLiteral(store, sourceIri, P.valueSourceClassIri,
          'CLASS_SOURCE_IRI_CARDINALITY')];
      } else if (valueSelectorIri) expectedAxisRoots = [selectors.get(valueSelectorIri).terminalClassIri];
      else expectedAxisRoots = optionalTerms(store, sourceIri, P.valueSourceTerminalClass)
        .map(({ value }) => value).sort(compare);
      const axisClosureTerms = optionalTerms(store, bindingIri, P.axisClassClosure);
      if (axisClosureTerms.length === 0 || axisClosureTerms.some(({ termType }) => termType !== 'NamedNode')) {
        fail('CLASS_CLOSURE_POLICY_MISSING', `${bindingIri} requires explicit axis closures`);
      }
      const axisClosureIris = axisClosureTerms.map(({ value }) => value);
      if (new Set(axisClosureIris).size !== axisClosureIris.length) {
        fail('DIMENSION_AXIS_CLASS_CLOSURE_DUPLICATE', `${bindingIri} repeats an axis closure`);
      }
      axisClosureIris.sort(compare);
      const axisClassClosures = axisClosureIris.map((closureIri) => classClosures.get(closureIri));
      if (axisClassClosures.some((closure) => !closure)) {
        fail('DIMENSION_AXIS_CLASS_CLOSURE_MISMATCH', `${bindingIri} references an unknown closure`);
      }
      const actualAxisRoots = uniqueSorted(axisClassClosures.map(({ rootClassIri }) => rootClassIri));
      if (canonicalJson(actualAxisRoots) !== canonicalJson(uniqueSorted(expectedAxisRoots))) {
        fail('DIMENSION_AXIS_CLASS_CLOSURE_MISMATCH', `${bindingIri} axis roots differ from its value source`, {
          actual: actualAxisRoots,
          expected: uniqueSorted(expectedAxisRoots),
        });
      }
      return {
        axisClassClosures: Object.freeze(axisClassClosures),
        bindingIri,
        derivationPredicateIris,
        dimensionIri,
        key: exactLiteral(store, dimensionIri, P.dimensionKey, 'FAMILY_DIMENSION_KEY_CARDINALITY'),
        position: exactInteger(store, bindingIri, P.dimensionPosition, 'FAMILY_DIMENSION_POSITION_INVALID'),
        sourceKind,
        sourceIri,
        sourceScopeIri,
        valueDerivationRootIri,
        valueSourceDigest: valueDerivationRootIri
          ? exactLiteral(store, sourceIri, P.valueSourceDigest, 'VALUE_SOURCE_DIGEST_CARDINALITY') : null,
        valueSelectorIri,
      };
    }).sort((left, right) => left.position - right.position);
    if (bindings.length === 0) fail('FAMILY_DIMENSION_SET_EMPTY', `${iri} has no dimensions`);
    assertUniqueContiguous(bindings, 'position', 'FAMILY_DIMENSION_POSITION_INVALID', iri);
    if (new Set(bindings.map(({ dimensionIri }) => dimensionIri)).size !== bindings.length) {
      fail('FAMILY_DIMENSION_DUPLICATE', `${iri} binds one dimension more than once`);
    }
    if (new Set(bindings.map(({ key }) => key)).size !== bindings.length) {
      fail('FAMILY_DIMENSION_KEY_DUPLICATE', `${iri} binds duplicate dimension keys`);
    }
    return Object.freeze({
      bindings,
      canonicalName: exactLiteral(store, iri, P.canonicalName, 'FAMILY_NAME_CARDINALITY'),
      iri,
      key: exactLiteral(store, iri, P.canonicalName, 'FAMILY_NAME_CARDINALITY'),
      orderedDimensions: bindings.map(({ key }) => key),
      planeIri,
      registrationIri,
      rule,
      ruleIri,
      subjectClassIri,
      subjectClassClosure,
    });
  }).sort((left, right) => compare(left.iri, right.iri));

  const referencedRules = families.map(({ ruleIri }) => ruleIri);
  const referencedRegistrations = families.map(({ registrationIri }) => registrationIri);
  const reachableClauses = new Set();
  const reachableOperands = new Set();
  const reachableSelectors = new Set();
  const reachableSteps = new Set();
  const reachableDerivations = new Set();
  const reachableDerivationOperands = new Set();
  const visitDerivation = (derivationIri, visiting = new Set()) => {
    if (reachableDerivations.has(derivationIri)) return;
    if (visiting.has(derivationIri)) fail('VALUE_DERIVATION_EXPRESSION_CYCLE', `${derivationIri} is cyclic`);
    reachableDerivations.add(derivationIri);
    const next = new Set(visiting).add(derivationIri);
    const operatorIri = exactIri(store, derivationIri, P.valueDerivationOperator,
      'VALUE_DERIVATION_OPERATOR_TERM_INVALID');
    const classTerms = optionalTerms(store, derivationIri, P.valueDerivationClass);
    if (classTerms.some(({ termType }) => termType !== 'NamedNode')) {
      fail('VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH', `${derivationIri} has non-IRI classes`);
    }
    const classIris = uniqueSorted(classTerms.map(({ value }) => value));
    const closureTerms = optionalTerms(store, derivationIri, P.valueDerivationClassClosure);
    if (closureTerms.some(({ termType }) => termType !== 'NamedNode')) {
      fail('VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH', `${derivationIri} has non-IRI closures`);
    }
    const derivationClosures = closureTerms.map(({ value }) => classClosures.get(value));
    if (derivationClosures.some((closure) => !closure)) {
      fail('VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH', `${derivationIri} references an unknown closure`);
    }
    const closureRoots = uniqueSorted(derivationClosures.map(({ rootClassIri }) => rootClassIri));
    if (CLASS_BEARING_DERIVATION_OPERATORS.has(operatorIri)) {
      if (canonicalJson(closureRoots) !== canonicalJson(classIris)) {
        fail('VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH', `${derivationIri} class closures differ from its classes`);
      }
    } else if (derivationClosures.length !== 0) {
      fail('VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH', `${derivationIri} is not class-bearing`);
    }
    for (const { value: operandIri } of optionalTerms(store, derivationIri, P.valueDerivationOperand)) {
      reachableDerivationOperands.add(operandIri);
      visitDerivation(exactIri(store, operandIri, P.valueDerivationOperandExpression,
        'VALUE_DERIVATION_OPERAND_EXPRESSION_CARDINALITY'), next);
    }
    for (const { value: stepIri } of optionalTerms(store, derivationIri, P.valueDerivationPathStep)) {
      reachableSteps.add(stepIri);
    }
  };
  const visitClause = (clause) => {
    if (reachableClauses.has(clause.clauseIri)) return;
    reachableClauses.add(clause.clauseIri);
    if (clause.selectorIri) reachableSelectors.add(clause.selectorIri);
    for (const operand of optionalTerms(store, clause.clauseIri, P.clauseOperand)) {
      reachableOperands.add(operand.value);
    }
    for (const { clause: nested } of clause.operands) visitClause(nested);
  };
  for (const family of families) {
    visitClause(family.rule.rootClause);
    const selectorIris = new Set();
    const collectSelectors = (clause) => {
      if (clause.selectorIri) selectorIris.add(clause.selectorIri);
      for (const { clause: nested } of clause.operands) collectSelectors(nested);
    };
    collectSelectors(family.rule.rootClause);
    for (const selectorIri of selectorIris) {
      const selector = selectors.get(selectorIri);
      if (selector.subjectClassIri !== family.subjectClassIri) {
        fail('SELECTOR_REGISTRATION_CLASS_MISMATCH',
          `${family.iri} subject class does not match selector ${selectorIri}`, {
            familySubjectClassIri: family.subjectClassIri,
            selectorSubjectClassIri: selector.subjectClassIri,
          });
      }
    }
    for (const { valueDerivationRootIri, valueSelectorIri } of family.bindings) {
      if (valueDerivationRootIri) visitDerivation(valueDerivationRootIri);
      if (!valueSelectorIri) continue;
      reachableSelectors.add(valueSelectorIri);
      const selector = selectors.get(valueSelectorIri);
      if (selector.subjectClassIri !== family.subjectClassIri) {
        fail('VALUE_SOURCE_SELECTOR_SUBJECT_CLASS_MISMATCH',
          `${family.iri} subject class does not match value-source selector ${valueSelectorIri}`, {
            familySubjectClassIri: family.subjectClassIri,
            selectorSubjectClassIri: selector.subjectClassIri,
          });
      }
    }
  }
  for (const selectorIri of reachableSelectors) {
    for (const step of selectors.get(selectorIri).steps) reachableSteps.add(step.iri);
  }
  const referencedClassClosures = uniqueSorted([
    ...typedSubjects(store, TYPES.subjectRegistration)
      .flatMap((owner) => optionalTerms(store, owner, P.subjectClassClosure).map(({ value }) => value)),
    ...typedSubjects(store, TYPES.selector)
      .flatMap((owner) => [P.selectorSubjectClassClosure, P.selectorTerminalClassClosure]
        .flatMap((predicate) => optionalTerms(store, owner, predicate).map(({ value }) => value))),
    ...families.flatMap(({ bindings }) => bindings
      .flatMap(({ axisClassClosures }) => axisClassClosures.map(({ iri }) => iri))),
    ...typedSubjects(store, TYPES.derivation)
      .flatMap((owner) => optionalTerms(store, owner, P.valueDerivationClassClosure).map(({ value }) => value)),
  ]);
  assertExactReachability(referencedRules, typedSubjects(store, TYPES.rule),
    'ORPHAN_APPLICABILITY_RULE', 'rule');
  assertExactReachability(referencedRegistrations, typedSubjects(store, TYPES.subjectRegistration),
    'ORPHAN_SUBJECT_REGISTRATION', 'subject registration');
  assertExactReachability([...reachableClauses], typedSubjects(store, TYPES.clause),
    'ORPHAN_APPLICABILITY_CLAUSE', 'clause');
  assertExactReachability([...reachableOperands], typedSubjects(store, TYPES.operand),
    'ORPHAN_APPLICABILITY_OPERAND', 'operand');
  assertExactReachability([...reachableSelectors], typedSubjects(store, TYPES.selector),
    'ORPHAN_SIGNAL_SELECTOR', 'selector');
  assertExactReachability([...reachableSteps], typedSubjects(store, TYPES.step),
    'ORPHAN_SIGNAL_PATH_STEP', 'path step');
  assertExactReachability([...reachableDerivations], typedSubjects(store, TYPES.derivation),
    'ORPHAN_VALUE_DERIVATION', 'value derivation');
  assertExactReachability([...reachableDerivationOperands], typedSubjects(store, TYPES.derivationOperand),
    'ORPHAN_VALUE_DERIVATION_OPERAND', 'value derivation operand');
  assertExactReachability(referencedClassClosures, typedSubjects(store, TYPES.classClosure),
    'ORPHAN_CLASS_CLOSURE', 'class closure');

  const familyRegistryRecord = {
    families: families.map((family) => ({
      canonicalName: family.canonicalName,
      dimensions: family.bindings.map(({ axisClassClosures, bindingIri, derivationPredicateIris, dimensionIri, key, position, sourceIri,
        sourceKind, sourceScopeIri, valueDerivationRootIri, valueSelectorIri, valueSourceDigest }) => ({
        axisClassClosureDigests: axisClassClosures.map(({ digest }) => digest),
        bindingIri,
        derivationPredicateIris,
        dimensionIri,
        key,
        position,
        sourceKind,
        sourceIri,
        sourceScopeIri,
        valueDerivationRootIri,
        valueSelectorDigest: valueSelectorIri ? selectors.get(valueSelectorIri).digest : null,
        valueSelectorIri,
        valueSourceDigest,
      })),
      familyIri: family.iri,
      planeIri: family.planeIri,
      registrationIri: family.registrationIri,
      ruleDigest: family.rule.ruleDigest,
      ruleIri: family.ruleIri,
      subjectClassIri: family.subjectClassIri,
      subjectClassClosureDigest: family.subjectClassClosure.digest,
    })),
    classClosures: [...classClosures.values()].map((closure) => ({
      closureDigest: closure.digest,
      closureIri: closure.iri,
      edgeSetDigest: closure.edgeSetDigest,
      memberSetDigest: closure.memberSetDigest,
      policyIri: closure.policyIri,
      rootClassIri: closure.rootClassIri,
    })).sort((left, right) => compare(left.closureIri, right.closureIri)),
    schemaVersion: 4,
  };
  return Object.freeze({
    families: Object.freeze(families),
    familyCount: families.length,
    classClosures,
    classClosuresByRoot,
    registryDigest: sha256(canonicalJson(familyRegistryRecord)),
    registryRecord: Object.freeze(familyRegistryRecord),
    rules,
    selectors,
  });
}

function canonicalExpectedValue(value) {
  if (typeof value === 'string') return canonicalJson({ termType: 'NamedNode', value });
  return canonicalJson(value);
}

export function evaluateApplicabilityClause(clause, selectorValues, observed = new Map()) {
  const selectorValue = clause.selectorIri ? selectorValues.get(clause.selectorIri) : undefined;
  if (clause.selectorIri) {
    if (selectorValue === undefined) {
      fail('AUTHORITY_SIGNAL_MISSING', `selector ${clause.selectorIri} is missing`);
    }
    observed.set(clause.selectorIri, selectorValue);
  }
  switch (clause.operatorIri) {
    case OPERATORS.true: return true;
    case OPERATORS.allOf: {
      const results = clause.operands.map(({ clause: child }) => (
        evaluateApplicabilityClause(child, selectorValues, observed)
      ));
      return results.every(Boolean);
    }
    case OPERATORS.anyOf: {
      const results = clause.operands.map(({ clause: child }) => (
        evaluateApplicabilityClause(child, selectorValues, observed)
      ));
      return results.some(Boolean);
    }
    case OPERATORS.not:
      return !evaluateApplicabilityClause(clause.operands[0].clause, selectorValues, observed);
    case OPERATORS.countAtLeast: {
      const count = Array.isArray(selectorValue) ? selectorValue.length : Number(selectorValue);
      return Number.isSafeInteger(count) && count >= 0 && count >= clause.threshold;
    }
    case OPERATORS.countExactly: {
      const count = Array.isArray(selectorValue) ? selectorValue.length : Number(selectorValue);
      return Number.isSafeInteger(count) && count >= 0 && count === clause.threshold;
    }
    case OPERATORS.valueEquals:
      return (Array.isArray(selectorValue) ? selectorValue : [selectorValue])
        .some((value) => canonicalExpectedValue(value) === canonicalJson(clause.expectedValues[0]));
    case OPERATORS.valueInDeclaredSet: {
      const expected = new Set(clause.expectedValues.map(canonicalJson));
      return (Array.isArray(selectorValue) ? selectorValue : [selectorValue])
        .some((value) => expected.has(canonicalExpectedValue(value)));
    }
    default:
      fail('APPLICABILITY_OPERATOR_UNSUPPORTED', `unsupported operator ${clause.operatorIri}`);
  }
}

export function evaluateFamilyRule(family, selectorValues) {
  const observed = new Map();
  const applicable = evaluateApplicabilityClause(family.rule.rootClause, selectorValues, observed);
  return {
    applicable,
    dispositionIri: applicable
      ? family.rule.satisfiedDispositionIri
      : family.rule.unsatisfiedDispositionIri,
    observedSelectors: Object.fromEntries([...observed].sort(([left], [right]) => compare(left, right))),
    reasonIri: applicable ? null : family.rule.unsatisfiedReasonIri,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const repositoryRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
    const registry = loadPermutationFamilyRegistry({
      repositoryRoot,
      verifyStoredDigests: process.argv.includes('--skip-stored-digest-check') === false,
    });
    process.stdout.write(`${canonicalJson({
      assuranceFamilyCount: registry.families.filter(({ planeIri }) => planeIri === FAMILY_PLANES.assurance).length,
      familyCount: registry.familyCount,
      registryDigest: registry.registryDigest,
      ruleDigests: Object.fromEntries([...registry.rules].map(([iri, rule]) => [iri, rule.ruleDigest])),
      runtimeFamilyCount: registry.families.filter(({ planeIri }) => planeIri === FAMILY_PLANES.runtime).length,
      selectorDigests: Object.fromEntries([...registry.selectors].map(([iri, selector]) => [iri, selector.digest])),
    })}\n`);
  } catch (error) {
    process.stderr.write(`${error.code ?? error.name}:${error.message}\n`);
    process.exitCode = 1;
  }
}
