// Deterministic permutation-family census generator (GOAL.md §16).
// Assigns exactly one family-applicability disposition per registered subject
// per census family, bound to a verified live-authority projection. Authored
// RDF is never consulted for subject or applicability truth.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  canonicalJson,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import {
  evaluateFamilyRule,
  loadPermutationFamilyRegistry,
} from './family-registry.mjs';

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const O = 'urn:usf:ontology:';
const VERIFIED_AUTHORITY_INPUTS = new WeakSet();

export class PermutationInputError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'PermutationInputError';
    this.code = code;
    this.details = details;
  }
}

const fail = (code, message, details) => {
  throw new PermutationInputError(code, message, details);
};

const assertSha256 = (value, code, label) => {
  if (!/^sha256:[0-9a-f]{64}$/.test(String(value))) fail(code, `${label} must be sha256:<64 lowercase hex>`);
};

const uniqueSorted = (values) => [...new Set(values)].sort();
const isUniqueSorted = (values) => values.length === new Set(values).size
  && values.every((value, index) => index === 0 || values[index - 1] < value);
const contentAddressFromName = (path) => basename(path).match(/-([0-9a-f]{64})\.json$/)?.[1] ?? null;

export const DISPOSITIONS = Object.freeze({
  required: 'MATRIX_REQUIRED',
  notApplicable: 'MATRIX_NOT_APPLICABLE',
});

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const familyRegistry = loadPermutationFamilyRegistry({ repositoryRoot });
export const censusFamilies = familyRegistry.families;

export class AuthorityProjectionIndex {
  constructor(projection) {
    this.projectedClassIris = new Set(projection.projectedClassIris);
    this.projectedPredicateIris = new Set(projection.projectedPredicateIris);
    this.bySubjectPredicate = new Map();
    this.byPredicateObject = new Map();
    this.gatewayOperationsByCapability = new Map();
    this.operationClasses = new Map();
    this.operationInstances = new Set();

    for (const [subject, predicate, objectType, value, datatype, language] of projection.triples) {
      const object = Object.freeze({ datatype, language, type: objectType, value });
      const subjectKey = `${subject}\u0000${predicate}`;
      const reverseKey = `${predicate}\u0000${objectType}\u0000${value}`;
      if (!this.bySubjectPredicate.has(subjectKey)) this.bySubjectPredicate.set(subjectKey, []);
      if (!this.byPredicateObject.has(reverseKey)) this.byPredicateObject.set(reverseKey, []);
      this.bySubjectPredicate.get(subjectKey).push(object);
      this.byPredicateObject.get(reverseKey).push(subject);
    }
    for (const values of this.bySubjectPredicate.values()) values.sort((a, b) => a.value.localeCompare(b.value, 'en'));
    for (const values of this.byPredicateObject.values()) values.sort((a, b) => a.localeCompare(b, 'en'));

    for (const [capability, operation] of projection.gatewayOperationCapabilityBindings) {
      if (!this.gatewayOperationsByCapability.has(capability)) this.gatewayOperationsByCapability.set(capability, []);
      this.gatewayOperationsByCapability.get(capability).push(operation);
      const predicate = `${O}gatewayOperationForCapability`;
      const subjectKey = `${operation}\u0000${predicate}`;
      const reverseKey = `${predicate}\u0000iri\u0000${capability}`;
      if (!this.bySubjectPredicate.has(subjectKey)) this.bySubjectPredicate.set(subjectKey, []);
      if (!this.byPredicateObject.has(reverseKey)) this.byPredicateObject.set(reverseKey, []);
      this.bySubjectPredicate.get(subjectKey).push(Object.freeze({
        datatype: null,
        language: null,
        type: 'iri',
        value: capability,
      }));
      this.byPredicateObject.get(reverseKey).push(operation);
    }
    for (const values of this.gatewayOperationsByCapability.values()) values.sort();
    this.projectedPredicateIris.add(`${O}gatewayOperationForCapability`);

    for (const [operationClass, operation] of projection.operationClassBindings ?? []) {
      if (!this.operationClasses.has(operationClass)) this.operationClasses.set(operationClass, []);
      if (operation !== null) {
        this.operationClasses.get(operationClass).push(operation);
        this.operationInstances.add(operation);
      }
    }
    for (const values of this.operationClasses.values()) values.sort();
  }

  objects(subject, predicate) {
    return this.bySubjectPredicate.get(`${subject}\u0000${predicate}`) ?? [];
  }

  values(subject, predicate) {
    return uniqueSorted(this.objects(subject, predicate).map(({ value }) => value));
  }

  subjects(predicate, objectIri) {
    return this.byPredicateObject.get(`${predicate}\u0000iri\u0000${objectIri}`) ?? [];
  }

  instances(classIri) {
    if (!this.projectedClassIris.has(classIri) && !this.operationClasses.has(classIri)) {
      fail('AUTHORITY_CLASS_NOT_PROJECTED', `class ${classIri} is not present in the bounded projection`);
    }
    return uniqueSorted([
      ...this.subjects(RDF_TYPE, classIri),
      ...(this.operationClasses.get(classIri) ?? []),
    ]);
  }

  isType(subject, classIri) {
    return this.values(subject, RDF_TYPE).includes(classIri)
      || (this.operationClasses.get(classIri) ?? []).includes(subject);
  }
}

export function instancesForClassClosure(index, closure) {
  const values = [];
  for (const classIri of closure.memberClassIris) {
    try {
      values.push(...index.instances(classIri));
    } catch (error) {
      if (error?.code === 'AUTHORITY_CLASS_NOT_PROJECTED') {
        fail('CLASS_CLOSURE_MEMBER_NOT_PROJECTED', `${closure.iri} member ${classIri} is absent from the bounded projection`);
      }
      throw error;
    }
  }
  return uniqueSorted(values);
}

export function isTypeInClassClosure(index, subject, closure) {
  return closure.memberClassIris.some((classIri) => index.isType(subject, classIri));
}

function readVerifiedJson(path, expectedDigest, kind) {
  assertSha256(expectedDigest, `${kind}_DIGEST_INVALID`, `${kind} digest`);
  const bytes = readFileSync(path);
  const actualDigest = sha256(bytes);
  if (actualDigest !== expectedDigest) fail(`${kind}_FILE_DIGEST_MISMATCH`, `${path} digest ${actualDigest} does not equal ${expectedDigest}`);
  const nameDigest = contentAddressFromName(path);
  if (!nameDigest || `sha256:${nameDigest}` !== expectedDigest) {
    fail(`${kind}_CONTENT_ADDRESS_MISMATCH`, `${path} filename is not bound to its exact bytes`);
  }
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch (error) {
    fail(`${kind}_JSON_INVALID`, error.message);
  }
  return { actualDigest, bytes, value };
}

const exactCount = (index, className, expected, signal) => {
  const actual = index.instances(`${O}${className}`).length;
  if (actual !== expected) fail('AUTHORITY_PACKET_PROJECTION_MISMATCH', `${signal}: packet=${expected}, projection=${actual}`);
};

export function loadVerifiedAuthorityInputs({
  authorityDigest,
  authorityPacketDigest,
  authorityPacketPath,
  authorityProjectionDigest,
  authorityProjectionPath,
}) {
  assertSha256(authorityDigest, 'AUTHORITY_DIGEST_INVALID', 'authority digest');
  const packetFile = readVerifiedJson(authorityPacketPath, authorityPacketDigest, 'AUTHORITY_PACKET');
  const projectionFile = readVerifiedJson(authorityProjectionPath, authorityProjectionDigest, 'AUTHORITY_PROJECTION');
  const packet = packetFile.value;
  const projection = projectionFile.value;

  if (packet.recordKind !== 'USF_PERMUTATION_AUTHORITY_INPUT_PACKET' || packet.packetSchemaVersion !== 1) {
    fail('AUTHORITY_PACKET_SCHEMA_INVALID', 'unexpected authority packet kind or schema');
  }
  if (projection.recordKind !== 'USF_PERMUTATION_AUTHORITY_PROJECTION' || projection.schemaVersion !== 1) {
    fail('AUTHORITY_PROJECTION_SCHEMA_INVALID', 'unexpected authority projection kind or schema');
  }
  if (packet.authorityDigest !== authorityDigest || projection.authorityDigest !== authorityDigest) {
    fail('AUTHORITY_DIGEST_MISMATCH', 'packet, projection and expected live witness must bind one authority digest');
  }
  if (projection.basePacketDigest !== authorityPacketDigest) {
    fail('AUTHORITY_PROJECTION_PACKET_BINDING_MISMATCH', 'projection does not bind the verified authority packet');
  }
  if (projection.projectionMethod !== 'BOUNDED_USF_MCP_SELECT') {
    fail('AUTHORITY_PROJECTION_PROVENANCE_INVALID', 'projection method is not the bounded USF MCP read path');
  }
  if (!Array.isArray(projection.triples) || projection.triples.length === 0) {
    fail('AUTHORITY_PACKET_PROJECTION_INCOMPLETE', 'projection contains no exact authority records');
  }
  if (!isUniqueSorted(projection.projectedClassIris) || !isUniqueSorted(projection.projectedPredicateIris)) {
    fail('AUTHORITY_PROJECTION_REGISTRY_INVALID', 'projected class and predicate registries must be unique and canonically sorted');
  }
  const tripleKeys = projection.triples.map((triple) => canonicalJson(triple));
  if (!isUniqueSorted(tripleKeys)) fail('AUTHORITY_PROJECTION_RECORD_SET_INVALID', 'authority records must be unique and canonically sorted');
  const gatewayBindings = projection.gatewayOperationCapabilityBindings;
  const gatewayKeys = Array.isArray(gatewayBindings)
    ? gatewayBindings.map((binding) => canonicalJson(binding))
    : [];
  if (!Array.isArray(gatewayBindings)
    || !gatewayBindings.every((binding) => Array.isArray(binding)
      && binding.length === 3
      && binding.every((value) => typeof value === 'string' && value.length > 0))
    || !isUniqueSorted(gatewayKeys)) {
    fail('AUTHORITY_GATEWAY_BINDING_INVALID', 'gateway bindings must be typed, unique and canonically sorted');
  }
  const operationClassBindings = projection.operationClassBindings;
  const operationClassKeys = Array.isArray(operationClassBindings)
    ? operationClassBindings.map((binding) => canonicalJson(binding))
    : [];
  if (!Array.isArray(operationClassBindings)
    || !operationClassBindings.every((binding) => Array.isArray(binding)
      && binding.length === 2
      && typeof binding[0] === 'string'
      && binding[0].length > 0
      && (binding[1] === null || (typeof binding[1] === 'string' && binding[1].length > 0)))
    || !isUniqueSorted(operationClassKeys)) {
    fail('AUTHORITY_OPERATION_CLASS_BINDING_INVALID', 'operation class bindings must be typed, unique and canonically sorted');
  }
  if (!operationClassBindings.some(([classIri]) => classIri === `${O}Operation`)) {
    fail('OPERATION_CLASS_CLOSURE_INVALID', 'operation class bindings do not include the Operation root');
  }

  const index = new AuthorityProjectionIndex(projection);
  exactCount(index, 'Capability', packet.liveSignals.capabilities, 'capabilities');
  exactCount(index, 'SemanticContract', packet.activeIdentities.contractCount, 'contracts');
  exactCount(index, 'Query', packet.liveSignals.operationTypes.Query, 'queries');
  exactCount(index, 'Command', packet.liveSignals.operationTypes.Command, 'commands');
  exactCount(index, 'GatewayOperation', packet.liveSignals.gatewayOperations, 'gateway operations');
  exactCount(index, 'Role', packet.liveSignals.roles, 'roles');
  exactCount(index, 'Permission', packet.liveSignals.permissions, 'permissions');
  exactCount(index, 'Port', packet.liveSignals.ports, 'ports');
  exactCount(index, 'Event', packet.liveSignals.events, 'events');
  exactCount(index, 'State', packet.liveSignals.states, 'states');
  exactCount(index, 'Transition', packet.liveSignals.transitions, 'transitions');
  exactCount(index, 'EnvironmentClass', packet.liveSignals.environmentClasses, 'environment classes');

  const projectedRoles = index.instances(`${O}Role`);
  const packetRoles = packet.controlledDimensions.roles.map((name) => `urn:usf:role:${name}`).sort();
  if (canonicalJson(projectedRoles) !== canonicalJson(packetRoles)) {
    fail('AUTHORITY_PACKET_PROJECTION_MISMATCH', 'role identities differ between witness packet and exact projection');
  }

  const inputs = Object.freeze({
    authorityDigest,
    authorityPacket: packet,
    authorityPacketDigest,
    authorityPacketPath,
    authorityProjection: projection,
    authorityProjectionDigest,
    authorityProjectionPath,
    index,
  });
  VERIFIED_AUTHORITY_INPUTS.add(inputs);
  return inputs;
}

export function assertVerifiedAuthorityInputs(inputs) {
  if (!inputs || !VERIFIED_AUTHORITY_INPUTS.has(inputs)) fail('UNVERIFIED_AUTHORITY_INPUTS', 'use loadVerifiedAuthorityInputs before generation');
  return inputs;
}

function contractForCapability(index, capabilityIri) {
  const contracts = index.values(capabilityIri, `${O}hasContract`);
  if (contracts.length !== 1) {
    fail('CAPABILITY_CONTRACT_CARDINALITY', `${capabilityIri} must declare exactly one contract`, { contracts });
  }
  return contracts[0];
}

function evaluateSelector(index, selector, subjectIri) {
  if (!index.projectedClassIris.has(selector.subjectClassIri)) {
    fail('AUTHORITY_SELECTOR_SUBJECT_CLASS_NOT_PROJECTED', `${selector.subjectClassIri} is absent from the authority projection`);
  }
  if (!index.projectedClassIris.has(selector.terminalClassIri)) {
    fail('AUTHORITY_SELECTOR_TERMINAL_CLASS_NOT_PROJECTED', `${selector.terminalClassIri} is absent from the authority projection`);
  }
  if (!index.projectedPredicateIris.has(RDF_TYPE)) {
    fail('AUTHORITY_SELECTOR_PATH_PREDICATE_NOT_PROJECTED', `${RDF_TYPE} is absent from the authority projection`);
  }
  for (const step of selector.steps) {
    if (!index.projectedPredicateIris.has(step.predicateIri)) {
      fail('AUTHORITY_SELECTOR_PATH_PREDICATE_NOT_PROJECTED', `${step.predicateIri} is absent from the authority projection`);
    }
  }
  if (!isTypeInClassClosure(index, subjectIri, selector.subjectClassClosure)) {
    fail('SELECTOR_SUBJECT_CLASS_MISMATCH', `${subjectIri} is not a ${selector.subjectClassIri}`);
  }
  let values = [subjectIri];
  for (const step of selector.steps) {
    values = uniqueSorted(values.flatMap((value) => (
      step.directionIri === 'urn:usf:permutationpathdirection:outbound'
        ? index.values(value, step.predicateIri)
        : index.subjects(step.predicateIri, value)
    )));
  }
  const terminalValues = values.filter((value) => isTypeInClassClosure(index, value, selector.terminalClassClosure));
  if (selector.aggregationIri === 'urn:usf:permutationsignalaggregation:countdistinct') {
    return terminalValues.length;
  }
  if (selector.aggregationIri === 'urn:usf:permutationsignalaggregation:distinctvalues') {
    return terminalValues;
  }
  fail('SELECTOR_AGGREGATION_UNCONTROLLED', `${selector.iri} has unsupported aggregation`);
}

function familyRuleSelectors(family) {
  const selectors = new Set();
  const visit = (clause) => {
    if (clause.selectorIri) selectors.add(clause.selectorIri);
    for (const { clause: nested } of clause.operands) visit(nested);
  };
  visit(family.rule.rootClause);
  return [...selectors].sort();
}

export function computeSubjectSelectorValues(authorityInputs, family, subjectIri) {
  const { index } = assertVerifiedAuthorityInputs(authorityInputs);
  if (!isTypeInClassClosure(index, subjectIri, family.subjectClassClosure)) {
    fail('SELECTOR_SUBJECT_CLASS_MISMATCH', `${subjectIri} is not a ${family.subjectClassIri}`);
  }
  return new Map(familyRuleSelectors(family).map((selectorIri) => {
    const selector = familyRegistry.selectors.get(selectorIri);
    return [
    selectorIri,
    evaluateSelector(index, selector, subjectIri),
    ];
  }));
}

export function computeCapabilitySelectorValues(authorityInputs, capabilityIri) {
  const { index } = assertVerifiedAuthorityInputs(authorityInputs);
  contractForCapability(index, capabilityIri);
  const values = new Map();
  for (const family of censusFamilies.filter(({ subjectClassIri }) => subjectClassIri === `${O}Capability`)) {
    for (const [selectorIri, value] of computeSubjectSelectorValues(authorityInputs, family, capabilityIri)) {
      if (values.has(selectorIri) && canonicalJson(values.get(selectorIri)) !== canonicalJson(value)) {
        fail('SELECTOR_VALUE_INCONSISTENT', `${selectorIri} differs across capability families`);
      }
      values.set(selectorIri, value);
    }
  }
  return values;
}

export function computeCapabilitySignals(authorityInputs, capabilityIri) {
  const values = computeCapabilitySelectorValues(authorityInputs, capabilityIri);
  return Object.freeze(Object.fromEntries([...values].map(([selectorIri, value]) => [
    familyRegistry.selectors.get(selectorIri).canonicalName,
    value,
  ]).sort(([left], [right]) => left.localeCompare(right, 'en'))));
}

export function evaluateFamilyApplicability(familyIdentity, signals) {
  const family = censusFamilies.find(({ iri, key }) => familyIdentity === iri || familyIdentity === key);
  if (!family) fail('CENSUS_FAMILY_UNKNOWN', `unknown census family ${familyIdentity}`);
  const selectorValues = new Map([...familyRegistry.selectors].map(([selectorIri, selector]) => [
    selectorIri,
    signals[selector.canonicalName],
  ]));
  const result = evaluateFamilyRule(family, selectorValues);
  const observedSignals = Object.fromEntries(Object.entries(result.observedSelectors).map(([selectorIri, value]) => [
    familyRegistry.selectors.get(selectorIri).canonicalName,
    value,
  ]).sort(([left], [right]) => left.localeCompare(right, 'en')));
  return {
    disposition: result.applicable ? DISPOSITIONS.required : DISPOSITIONS.notApplicable,
    observedSignals,
    reasonCode: result.reasonIri,
    reasonIri: result.reasonIri,
    ruleDigest: family.rule.ruleDigest,
  };
}

export function generateFamilyCensus({ authorityInputs }) {
  const verified = assertVerifiedAuthorityInputs(authorityInputs);
  const { authorityDigest, authorityPacketDigest, authorityProjectionDigest, index } = verified;
  const records = [];
  const dispositionCounts = { [DISPOSITIONS.required]: 0, [DISPOSITIONS.notApplicable]: 0 };
  const subjectCountsByRegistration = {};
  const subjectSetDigestsByRegistration = {};
  const subjectClassClosureDigestsByRegistration = {};
  const allSubjects = new Set();
  for (const family of censusFamilies) {
    if (Object.hasOwn(subjectCountsByRegistration, family.registrationIri)) continue;
    const subjects = instancesForClassClosure(index, family.subjectClassClosure);
    subjectCountsByRegistration[family.registrationIri] = subjects.length;
    subjectSetDigestsByRegistration[family.registrationIri] = sha256(canonicalJson(subjects));
    subjectClassClosureDigestsByRegistration[family.registrationIri] = family.subjectClassClosure.digest;
  }
  for (const family of censusFamilies) {
    const subjects = instancesForClassClosure(index, family.subjectClassClosure);
    for (const subject of subjects) {
      allSubjects.add(subject);
      const contract = family.subjectClassIri === `${O}Capability`
        ? contractForCapability(index, subject) : null;
      const selectorValues = computeSubjectSelectorValues(verified, family, subject);
      const signals = Object.fromEntries([...selectorValues].map(([selectorIri, value]) => [
        familyRegistry.selectors.get(selectorIri).canonicalName,
        value,
      ]).sort(([left], [right]) => left.localeCompare(right, 'en')));
      const {
        disposition, reasonCode, observedSignals, ruleDigest,
      } = evaluateFamilyApplicability(family.key, signals);
      dispositionCounts[disposition] += 1;
      records.push({
        capability: family.subjectClassIri === `${O}Capability` ? subject : null,
        contract,
        family: family.iri,
        familyKey: family.key,
        canonicalName: family.canonicalName,
        disposition,
        reasonCode,
        registrationIri: family.registrationIri,
        ruleDigest,
        signals: observedSignals,
        subject,
        subjectClass: family.subjectClassIri,
        subjectClassClosureDigest: family.subjectClassClosure.digest,
        provenance: {
          authorityDigest,
          authorityProjectionDigest,
          familyRegistryDigest: familyRegistry.registryDigest,
          kind: 'LIVE_AUTHORITY_PROJECTION',
          signalKeys: Object.keys(observedSignals).sort(),
        },
      });
    }
  }
  records.sort((left, right) => {
    const leftKey = canonicalJson([left.family, left.subject]);
    const rightKey = canonicalJson([right.family, right.subject]);
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  const pairKeys = records.map(({ family, subject }) => `${family}\u0000${subject}`);
  const expectedPairCount = pairKeys.length;
  const pairSetDigest = sha256(canonicalJson(pairKeys));
  const recordsDigest = sha256(canonicalJson(records));
  const subjectCount = allSubjects.size;
  return {
    recordKind: 'USF_PERMUTATION_FAMILY_CENSUS',
    schemaVersion: 4,
    authorityDigest,
    authorityPacketDigest,
    authorityProjectionDigest,
    familyRegistryDigest: familyRegistry.registryDigest,
    expectedPairCount,
    pairSetDigest,
    subjectCount,
    subjectCountsByRegistration,
    subjectSetDigestsByRegistration,
    subjectClassClosureDigestsByRegistration,
    familyCount: censusFamilies.length,
    records,
    dispositionCounts,
    recordsDigest,
    censusDigest: sha256(canonicalJson({
      authorityDigest,
      authorityPacketDigest,
      authorityProjectionDigest,
      familyRegistryDigest: familyRegistry.registryDigest,
      dispositionCounts,
      expectedPairCount,
      familyCount: censusFamilies.length,
      recordsDigest,
      pairSetDigest,
      subjectCount,
      subjectCountsByRegistration,
      subjectSetDigestsByRegistration,
      subjectClassClosureDigestsByRegistration,
    })),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const exactArg = (name) => {
    const prefix = `--${name}=`;
    const supplied = process.argv.filter((value) => value.startsWith(prefix));
    if (supplied.length !== 1) fail('EXACT_INPUT_PATH_REQUIRED', `exactly one ${prefix}<value> argument is required`);
    return supplied[0].slice(prefix.length);
  };
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const authorityInputs = loadVerifiedAuthorityInputs({
    authorityDigest: exactArg('authority-digest'),
    authorityPacketDigest: exactArg('authority-packet-digest'),
    authorityPacketPath: resolve(repositoryRoot, exactArg('authority-packet')),
    authorityProjectionDigest: exactArg('authority-projection-digest'),
    authorityProjectionPath: resolve(repositoryRoot, exactArg('authority-projection')),
  });
  const census = generateFamilyCensus({ authorityInputs });
  const content = `${canonicalJson(census)}\n`;
  const relativeOutputPath = join('.work', 'generated', `permutation-family-census-${sha256(content).slice('sha256:'.length)}.json`);
  mkdirSync(dirname(join(repositoryRoot, relativeOutputPath)), { recursive: true });
  writeFileSync(join(repositoryRoot, relativeOutputPath), content);
  process.stdout.write(`${canonicalJson({
    subjectCount: census.subjectCount,
    familyCount: census.familyCount,
    required: census.dispositionCounts[DISPOSITIONS.required],
    notApplicable: census.dispositionCounts[DISPOSITIONS.notApplicable],
    censusDigest: census.censusDigest,
    outputPath: relativeOutputPath,
  })}\n`);
}
