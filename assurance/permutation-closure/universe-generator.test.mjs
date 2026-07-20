import assert from 'node:assert/strict';
import { test } from 'node:test';
import N3 from 'n3';
import {
  canonicalJson,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import {
  DISPOSITIONS,
  canonicalCellIdentity,
  closureClassificationForDisposition,
  derivePermissionAtomCandidates,
  universeGeneratorInternals,
} from './universe-generator.mjs';
import { universeProofInternals } from './universe-proof.mjs';
import { loadPermutationFamilyRegistry } from './family-registry.mjs';

const O = 'urn:usf:ontology:';
const FAMILY = 'urn:usf:permutationfamily:operationpermissionatom';
const CAPABILITY = 'urn:test:capability';
const AUTHORITY = `sha256:${'a'.repeat(64)}`;
const PACKET = `sha256:${'b'.repeat(64)}`;
const PROJECTION = `sha256:${'c'.repeat(64)}`;
const GRAPH = N3.DataFactory.namedNode('urn:usf:graph:permutation-vocabulary');
const FAMILY_GRAPH = N3.DataFactory.namedNode('urn:usf:graph:permutation-families');
const named = N3.DataFactory.namedNode;
const literal = N3.DataFactory.literal;
const COVERAGE_RULES = Object.freeze({
  records: Object.freeze([
    Object.freeze({
      declaredDigest: `sha256:${'1'.repeat(64)}`,
      disposition: 'urn:usf:permutationclosuredisposition:notapplicable',
      families: Object.freeze([FAMILY]),
      predicate: `${O}requiresPermission`,
      reasonCode: 'OPERATION_DOES_NOT_REQUIRE_PERMISSION',
      resource: 'urn:test:rule:operationdoesnotrequirepermission',
      ruleKind: 'AUTHORITY_SET_NON_MEMBERSHIP',
      testedDimensionKey: 'permissionatom',
    }),
  ]),
});
const PUBLICATION_POLICY = Object.freeze({
  digest: `sha256:${'2'.repeat(64)}`,
  encodingPolicy: Object.freeze({
    fixedManifestTripleUpperBound: 4096,
    operationalCellTripleUpperBound: 64,
    regionTripleUpperBound: 48,
  }),
  failClosed: true,
  hardStatementLimit: 10_000,
  maximumProjectedStatementCount: 9_000,
  policyIri: 'urn:usf:permutationpublicationbudget:test',
  provider: 'stardogcloudfree',
  reserveStatementCount: 1_000,
});

const expectCode = (callback, code) => assert.throws(callback, (error) => error?.code === code);

function fakeIndex({
  required = new Map(),
  grants = new Map(),
  coordinatorOnly = new Set(),
  instances = new Map(),
  forward = new Map(),
  reverse = new Map(),
} = {}) {
  return {
    gatewayOperationsByCapability: new Map(),
    operationClasses: new Map(),
    projectedClassIris: new Set([...instances.keys(), `${O}Permission`]),
    projectedPredicateIris: new Set([...forward.keys()].map((key) => key.split('\u0000')[1])),
    instances: (classIri) => [...(instances.get(classIri) ?? [])].sort(),
    isType: (subject, classIri) => instances.get(classIri)?.has(subject) ?? false,
    objects: (subject, predicate) => {
      const explicit = forward.get(`${subject}\u0000${predicate}`);
      return [...(explicit ?? [])].sort().map((value) => ({
        datatype: null, language: null, type: 'iri', value,
      }));
    },
    subjects: (predicate, object) => [...(reverse.get(`${predicate}\u0000${object}`) ?? [])].sort(),
    values: (subject, predicate) => {
      const explicit = forward.get(`${subject}\u0000${predicate}`);
      if (explicit) return [...explicit].sort();
      if (predicate === `${O}hasContract` && subject === CAPABILITY) return ['urn:test:contract'];
      if (predicate === `${O}requiresPermission`) return [...(required.get(subject) ?? [])].sort();
      if (predicate === `${O}grantsPermission`) return [...(grants.get(subject) ?? [])].sort();
      if (predicate === `${O}coordinatorOnly` && coordinatorOnly.has(subject)) return ['true'];
      return [];
    },
  };
}

const authorityInputs = (index) => ({
  authorityDigest: AUTHORITY,
  authorityPacketDigest: PACKET,
  authorityProjectionDigest: PROJECTION,
  authorityProjection: {
    operationClassBindings: [[`${O}Operation`, null]],
  },
  index,
});

function controlledFamilyModel() {
  const store = new N3.Store();
  const registration = 'urn:test:subject-registration:capability';
  const capabilityClosureIri = 'urn:test:class-closure:capability';
  const dimensionValueClosureIri = 'urn:test:class-closure:dimension-value';
  const capabilityClosure = Object.freeze({
    digest: `sha256:${'3'.repeat(64)}`,
    iri: capabilityClosureIri,
    memberClassIris: Object.freeze([`${O}Capability`]),
    rootClassIri: `${O}Capability`,
  });
  const dimensionValueClosure = Object.freeze({
    digest: `sha256:${'4'.repeat(64)}`,
    iri: dimensionValueClosureIri,
    memberClassIris: Object.freeze([`${O}PermutationDimensionValue`]),
    rootClassIri: `${O}PermutationDimensionValue`,
  });
  const operationDimension = 'urn:test:dimension:operation';
  const permissionDimension = 'urn:test:dimension:permission';
  const operationSource = 'urn:test:source:operation';
  const permissionSource = 'urn:test:source:permission';
  const bindings = [
    ['urn:test:binding:operation', operationDimension, 'operation', 1, operationSource,
      ['urn:test:operation:one', 'urn:test:operation:two']],
    ['urn:test:binding:permission', permissionDimension, 'permissionatom', 2, permissionSource,
      ['urn:test:permission:one', 'urn:test:permission:two']],
  ];
  store.addQuad(named(FAMILY), named('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
    named(`${O}PermutationFamily`), FAMILY_GRAPH);
  store.addQuad(named(FAMILY), named(`${O}canonicalName`), literal('operationpermissionatom'), FAMILY_GRAPH);
  store.addQuad(named(FAMILY), named(`${O}familySubjectRegistration`), named(registration), FAMILY_GRAPH);
  store.addQuad(named(registration), named(`${O}registeredSubjectClass`), named(`${O}Capability`), FAMILY_GRAPH);
  for (const [binding, dimension, key, position, source, domain] of bindings) {
    store.addQuad(named(FAMILY), named(`${O}hasFamilyDimensionBinding`), named(binding), FAMILY_GRAPH);
    store.addQuad(named(binding), named(`${O}bindsDimension`), named(dimension), FAMILY_GRAPH);
    store.addQuad(named(binding), named(`${O}dimensionAxisClassClosure`),
      named(dimensionValueClosureIri), FAMILY_GRAPH);
    store.addQuad(named(binding), named(`${O}dimensionPosition`), literal(String(position)), FAMILY_GRAPH);
    store.addQuad(named(dimension), named(`${O}permutationDimensionKey`), literal(key), FAMILY_GRAPH);
    store.addQuad(named(dimension), named(`${O}dimensionValueSource`), named(source), FAMILY_GRAPH);
    store.addQuad(named(source), named(`${O}valueSourceKind`), literal('controlledlist'), FAMILY_GRAPH);
    store.addQuad(named(source), named(`${O}valueSourceScope`),
      named('urn:usf:dimensionvaluesourcescope:foundationcatalogue'), FAMILY_GRAPH);
    for (const [valueIndex, value] of domain.entries()) {
      store.addQuad(named(dimension), named(`${O}hasDimensionValue`), named(value), FAMILY_GRAPH);
      store.addQuad(named(value), named('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
        named(`${O}PermutationDimensionValue`), GRAPH);
      store.addQuad(named(value), named(`${O}dimensionValueKey`), literal(`${key}-${valueIndex + 1}`), GRAPH);
    }
  }
  return {
    digest: `sha256:${'d'.repeat(64)}`,
    familyRegistry: {
      classClosures: new Map([
        [capabilityClosureIri, capabilityClosure],
        [dimensionValueClosureIri, dimensionValueClosure],
      ]),
      families: [Object.freeze({
        iri: FAMILY,
        registrationIri: registration,
        subjectClassClosure: capabilityClosure,
        subjectClassIri: `${O}Capability`,
      })],
    },
    store,
  };
}

function censusFixture(recordOverrides = {}) {
  const record = {
    capability: CAPABILITY,
    canonicalName: 'operationpermissionatom',
    contract: 'urn:test:contract',
    disposition: 'MATRIX_REQUIRED',
    family: FAMILY,
    registrationIri: 'urn:test:subject-registration:capability',
    subject: CAPABILITY,
    subjectClass: `${O}Capability`,
    subjectClassClosureDigest: `sha256:${'3'.repeat(64)}`,
    ...recordOverrides,
  };
  const records = [record];
  const pairKeys = [`${FAMILY}\u0000${CAPABILITY}`];
  const core = {
    authorityDigest: AUTHORITY,
    authorityPacketDigest: PACKET,
    authorityProjectionDigest: PROJECTION,
    dispositionCounts: { MATRIX_REQUIRED: 1 },
    expectedPairCount: 1,
    familyCount: 1,
    familyRegistryDigest: `sha256:${'e'.repeat(64)}`,
    pairSetDigest: sha256(canonicalJson(pairKeys)),
    recordsDigest: sha256(canonicalJson(records)),
    subjectCount: 1,
    subjectClassClosureDigestsByRegistration: {
      'urn:test:subject-registration:capability': `sha256:${'3'.repeat(64)}`,
    },
    subjectCountsByRegistration: { 'urn:test:subject-registration:capability': 1 },
    subjectSetDigestsByRegistration: {
      'urn:test:subject-registration:capability': sha256(canonicalJson([CAPABILITY])),
    },
  };
  return {
    recordKind: 'USF_PERMUTATION_FAMILY_CENSUS',
    schemaVersion: 4,
    ...core,
    records,
    censusDigest: sha256(canonicalJson(core)),
  };
}

test('registered-subject census validation rejects every compatibility substitution', () => {
  const metaModel = controlledFamilyModel();
  const inputs = authorityInputs(fakeIndex({ instances: new Map([[`${O}Capability`, new Set([CAPABILITY])]]) }));
  assert.doesNotThrow(() => universeGeneratorInternals.validateCensus(censusFixture(), inputs, metaModel));
  for (const [overrides, code] of [
    [{ subject: undefined }, 'CENSUS_RECORD_SUBJECT_MISSING'],
    [{ subjectClass: undefined }, 'CENSUS_RECORD_SUBJECT_CLASS_MISSING'],
    [{ subjectClass: `${O}Binding` }, 'CENSUS_RECORD_SUBJECT_CLASS_MISMATCH'],
    [{ capability: 'urn:test:capability:other' }, 'CENSUS_RECORD_CAPABILITY_BINDING_INVALID'],
    [{ contract: 'urn:test:contract:other' }, 'CENSUS_RECORD_CONTRACT_BINDING_INVALID'],
  ]) {
    expectCode(() => universeGeneratorInternals.validateCensus(
      censusFixture(overrides), inputs, metaModel,
    ), code);
  }
});

const record = {
  capability: CAPABILITY,
  canonicalName: 'operationpermissionatom',
  contract: 'urn:test:contract',
  family: FAMILY,
  registrationIri: 'urn:test:subject-registration:capability',
  subject: CAPABILITY,
  subjectClass: `${O}Capability`,
  subjectClassClosureDigest: `sha256:${'3'.repeat(64)}`,
};

test('canonical cell identity is URN-safe and insertion-order independent', () => {
  const bindings = [
    { dimension: 'urn:test:dimension:b', key: 'permissionatom', position: 2, value: 'urn:test:permission#read' },
    { dimension: 'urn:test:dimension:a', key: 'operation', position: 1, value: 'https://example.test/op/read' },
  ];
  const first = canonicalCellIdentity(FAMILY, CAPABILITY, bindings);
  const second = canonicalCellIdentity(FAMILY, CAPABILITY, [...bindings].reverse());
  assert.deepEqual(second, first);
  assert.match(first.stableKey, /^family=/);
  assert.ok(first.stableKey.includes('subject=urn%3Atest%3Acapability'));
  assert.equal(first.cellIri, `urn:usf:permutationcell:${sha256(first.stableKey).slice('sha256:'.length)}`);
  assert.equal(first.identityAlgorithm, 'family-subject-ordered-dimension-identity-v1');
});

test('cell identity separates capabilities and families', () => {
  const bindings = [{ dimension: 'urn:test:d', key: 'operation', position: 1, value: 'urn:test:o' }];
  const first = canonicalCellIdentity(FAMILY, 'urn:test:capability:a', bindings);
  const second = canonicalCellIdentity(FAMILY, 'urn:test:capability:b', bindings);
  const third = canonicalCellIdentity('urn:test:family:other', 'urn:test:capability:a', bindings);
  assert.notEqual(first.stableKey, second.stableKey);
  assert.notEqual(first.stableKey, third.stableKey);
  assert.notEqual(first.cellIri, second.cellIri);
});

test('duplicate bindings and non-contiguous positions have distinct exact failures', () => {
  expectCode(() => canonicalCellIdentity(FAMILY, CAPABILITY, [
    { dimension: 'urn:test:d1', key: 'operation', position: 1, value: 'urn:test:o1' },
    { dimension: 'urn:test:d2', key: 'operation', position: 2, value: 'urn:test:o2' },
  ]), 'DUPLICATE_DIMENSION_BINDING');
  expectCode(() => canonicalCellIdentity(FAMILY, CAPABILITY, [
    { dimension: 'urn:test:d1', key: 'operation', position: 2, value: 'urn:test:o1' },
  ]), 'CELL_DIMENSION_POSITION_INVALID');
});

test('generic Cartesian generation retains multiple permissions per operation', () => {
  const required = new Map([
    ['urn:test:operation:one', new Set(['urn:test:permission:one', 'urn:test:permission:two'])],
  ]);
  const generated = universeGeneratorInternals.generateFamilyCells(
    controlledFamilyModel(),
    authorityInputs(fakeIndex({ required })),
    record,
  );
  assert.equal(generated.expectedCellCount, 4);
  assert.equal(generated.cells.length, 4);
  assert.equal(generated.cells.filter(({ disposition }) => disposition === DISPOSITIONS.required).length, 2);
  assert.equal(generated.cells.filter(({ disposition }) => disposition === DISPOSITIONS.notApplicable).length, 2);
  assert.ok(generated.cells.every(({ dispositions }) => dispositions.length === 1));
});

test('PermissionAtom candidates derive only from active exact source cells', () => {
  const required = new Map([
    ['urn:test:operation:one', new Set(['urn:test:permission:one', 'urn:test:permission:two'])],
  ]);
  const universe = {
    cells: universeGeneratorInternals.generateFamilyCells(
      controlledFamilyModel(),
      authorityInputs(fakeIndex({ required })),
      record,
    ).cells,
  };
  const candidateSet = derivePermissionAtomCandidates(universe);
  assert.equal(candidateSet.sourceCellCount, 2);
  assert.equal(candidateSet.candidateCount, 2);
  assert.equal(candidateSet.gaps.length, 2);
  assert.ok(candidateSet.candidates.every((candidate) => candidate.authorising === false));
  assert.ok(candidateSet.candidates.every((candidate) => candidate.capability === CAPABILITY));
  assert.ok(candidateSet.candidates.every((candidate) => candidate.missingProperties.length === 5));
  assert.match(candidateSet.candidateSetDigest, /^sha256:[0-9a-f]{64}$/);
});

test('same source permission in two capabilities produces distinct candidates', () => {
  const sourcePermission = 'urn:test:permission:one';
  const makeCell = (capability, index) => ({
    authorityDigest: AUTHORITY,
    capability,
    cellIri: `urn:test:cell:${index}`,
    dimensionBindings: [
      { key: 'operation', value: `urn:test:operation:${index}` },
      { key: 'permissionatom', value: sourcePermission },
    ],
    disposition: DISPOSITIONS.required,
    family: FAMILY,
  });
  const result = derivePermissionAtomCandidates({ cells: [makeCell('urn:test:capability:a', 1), makeCell('urn:test:capability:b', 2)] });
  assert.equal(result.candidateCount, 2);
  assert.notEqual(result.candidates[0].candidateDigest, result.candidates[1].candidateDigest);
});

test('forbidden, deferred, unresolved and not-applicable cells cannot produce candidates', () => {
  const cells = [
    DISPOSITIONS.forbidden,
    DISPOSITIONS.deferred,
    DISPOSITIONS.unresolved,
    DISPOSITIONS.notApplicable,
  ].map((disposition, index) => ({
    authorityDigest: AUTHORITY,
    capability: CAPABILITY,
    cellIri: `urn:test:cell:${index}`,
    dimensionBindings: [
      { key: 'operation', value: 'urn:test:operation' },
      { key: 'permissionatom', value: 'urn:test:permission' },
    ],
    disposition,
    family: FAMILY,
  }));
  assert.equal(derivePermissionAtomCandidates({ cells }).candidateCount, 0);
});

test('missing source-cell operation fails closed', () => {
  expectCode(() => derivePermissionAtomCandidates({ cells: [{
    authorityDigest: AUTHORITY,
    capability: CAPABILITY,
    cellIri: 'urn:test:cell',
    dimensionBindings: [{ key: 'permissionatom', value: 'urn:test:permission' }],
    disposition: DISPOSITIONS.required,
    family: FAMILY,
  }] }), 'PERMISSION_ATOM_SOURCE_CELL_INVALID');
});

function classSourceModel(kind = 'classinstances', scopes = ['urn:usf:dimensionvaluesourcescope:authorityinstanceset']) {
  const store = new N3.Store();
  const closure = Object.freeze({
    digest: `sha256:${'5'.repeat(64)}`,
    iri: 'urn:test:class-closure:permission',
    memberClassIris: Object.freeze([`${O}Permission`]),
    rootClassIri: `${O}Permission`,
  });
  const descriptor = {
    axisClassClosureDigests: [closure.digest],
    axisClassClosures: [closure],
    binding: 'urn:test:binding',
    dimension: 'urn:test:dimension',
    key: 'permissionatom',
    position: 1,
  };
  const source = 'urn:test:source';
  store.addQuad(named(descriptor.dimension), named(`${O}dimensionValueSource`), named(source), FAMILY_GRAPH);
  store.addQuad(named(source), named(`${O}valueSourceKind`), literal(kind), FAMILY_GRAPH);
  for (const scope of scopes) store.addQuad(named(source), named(`${O}valueSourceScope`), named(scope), FAMILY_GRAPH);
  store.addQuad(named(source), named(`${O}valueSourceClassIri`), named(`${O}Permission`), FAMILY_GRAPH);
  return {
    descriptor,
    metaModel: {
      digest: `sha256:${'e'.repeat(64)}`,
      familyRegistry: { classClosures: new Map([[closure.iri, closure]]) },
      store,
    },
  };
}

function derivedSourceModel(predicates = []) {
  const store = new N3.Store();
  const descriptor = { dimension: 'urn:test:dimension:operation', key: 'operation', position: 1 };
  const source = 'urn:test:source:operation';
  store.addQuad(named(descriptor.dimension), named(`${O}dimensionValueSource`), named(source), FAMILY_GRAPH);
  store.addQuad(named(source), named(`${O}valueSourceKind`), literal('derivedselector'), FAMILY_GRAPH);
  store.addQuad(named(source), named(`${O}valueSourceScope`),
    named('urn:usf:dimensionvaluesourcescope:capabilityrelationship'), FAMILY_GRAPH);
  for (const predicate of predicates) {
    store.addQuad(named(source), named(`${O}valueSourceDerivationPredicate`), named(predicate), FAMILY_GRAPH);
  }
  return { descriptor, metaModel: { digest: `sha256:${'f'.repeat(64)}`, store } };
}

test('unsupported source kind fails with its specific code', () => {
  const { descriptor, metaModel } = classSourceModel('fallback-list');
  expectCode(() => universeGeneratorInternals.resolveDomain(
    metaModel,
    authorityInputs(fakeIndex()),
    CAPABILITY,
    descriptor,
  ), 'DIMENSION_SOURCE_KIND_INVALID');
});

test('missing, unknown and multiple source scopes fail with their exact code', () => {
  for (const scopes of [
    [],
    ['urn:test:source-scope:unknown'],
    [
      'urn:usf:dimensionvaluesourcescope:authorityinstanceset',
      'urn:usf:dimensionvaluesourcescope:foundationcatalogue',
    ],
  ]) {
    const { descriptor, metaModel } = classSourceModel('classinstances', scopes);
    expectCode(() => universeGeneratorInternals.resolveDomain(
      metaModel, authorityInputs(fakeIndex()), CAPABILITY, descriptor,
    ), 'DIMENSION_SOURCE_SCOPE_INVALID');
  }
});

test('source kind and source scope mismatch fails closed', () => {
  const { descriptor, metaModel } = classSourceModel(
    'classinstances', ['urn:usf:dimensionvaluesourcescope:capabilityrelationship'],
  );
  expectCode(() => universeGeneratorInternals.resolveDomain(
    metaModel, authorityInputs(fakeIndex()), CAPABILITY, descriptor,
  ), 'DIMENSION_SOURCE_SCOPE_KIND_MISMATCH');
});

test('derived source requires one semantic root and an exact transitive predicate closure', () => {
  const absent = derivedSourceModel();
  expectCode(() => universeGeneratorInternals.resolveDomain(
    absent.metaModel, authorityInputs(fakeIndex()), CAPABILITY, absent.descriptor,
  ), 'DERIVED_SELECTOR_PREDICATE_ABSENT');
  const rootless = derivedSourceModel([`${O}requiredConsumer`]);
  expectCode(() => universeGeneratorInternals.resolveDomain(
    rootless.metaModel, authorityInputs(fakeIndex()), CAPABILITY, rootless.descriptor,
  ), 'VALUE_SOURCE_DERIVATION_ROOT_CARDINALITY');
  const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
  const source = 'urn:usf:dimensionvaluesource:operation';
  metaModel.store.addQuad(named(source), named(`${O}valueSourceDerivationPredicate`),
    named(`${O}unexpectedPredicate`), FAMILY_GRAPH);
  expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(metaModel, source),
    'VALUE_SOURCE_DERIVATION_PREDICATE_MISMATCH');
});

function replaceMetaObject(metaModel, subjectIri, predicateIri, object) {
  const quads = metaModel.store.getQuads(named(subjectIri), named(predicateIri), null, FAMILY_GRAPH);
  assert.equal(quads.length, 1, `${subjectIri}:${predicateIri}`);
  metaModel.store.removeQuad(quads[0]);
  metaModel.store.addQuad(named(subjectIri), named(predicateIri), object, FAMILY_GRAPH);
}

test('semantic derivations reject non-IRI terms, undeclared terms, cycles and stale digests specifically', () => {
  {
    const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
    replaceMetaObject(metaModel, 'urn:usf:permutationvaluederivation:gatewayoperations',
      `${O}valueDerivationPredicate`, literal(`${O}gatewayOperationForCapability`));
    expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(
      metaModel, 'urn:usf:dimensionvaluesource:operation',
    ), 'VALUE_DERIVATION_PREDICATE_TERM_INVALID');
  }
  {
    const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
    replaceMetaObject(metaModel, 'urn:usf:permutationvaluederivation:gatewayoperations',
      `${O}valueDerivationPredicate`, named('urn:test:undeclaredpredicate'));
    expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(
      metaModel, 'urn:usf:dimensionvaluesource:operation',
    ), 'VALUE_DERIVATION_PREDICATE_UNDECLARED');
  }
  {
    const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
    replaceMetaObject(metaModel, 'urn:usf:dimensionvaluesource:operation',
      `${O}valueSourceTerminalClass`, literal(`${O}Operation`));
    expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(
      metaModel, 'urn:usf:dimensionvaluesource:operation',
    ), 'VALUE_SOURCE_TERMINAL_CLASS_TERM_INVALID');
  }
  {
    const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
    replaceMetaObject(metaModel, 'urn:usf:permutationvaluederivationoperand:operationsgateways',
      `${O}valueDerivationOperandExpression`, named('urn:usf:permutationvaluederivation:operations'));
    expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(
      metaModel, 'urn:usf:dimensionvaluesource:operation',
    ), 'VALUE_DERIVATION_EXPRESSION_CYCLE');
  }
  {
    const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
    replaceMetaObject(metaModel, 'urn:usf:permutationvaluederivation:operations',
      `${O}valueDerivationDigest`, literal(`sha256:${'0'.repeat(64)}`));
    expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(
      metaModel, 'urn:usf:dimensionvaluesource:operation',
    ), 'VALUE_DERIVATION_DIGEST_MISMATCH');
  }
  {
    const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
    replaceMetaObject(metaModel, 'urn:usf:dimensionvaluesource:operation',
      `${O}valueSourceDigest`, literal(`sha256:${'0'.repeat(64)}`));
    expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(
      metaModel, 'urn:usf:dimensionvaluesource:operation',
    ), 'VALUE_SOURCE_DIGEST_MISMATCH');
  }
});

test('semantic derivation operand and path positions reject duplicate and gapped indexes', () => {
  {
    const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
    replaceMetaObject(metaModel, 'urn:usf:permutationvaluederivationoperand:operationsgateways',
      `${O}valueDerivationOperandIndex`, literal('1', named('http://www.w3.org/2001/XMLSchema#positiveInteger')));
    expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(
      metaModel, 'urn:usf:dimensionvaluesource:operation',
    ), 'VALUE_DERIVATION_OPERAND_INDEX_INVALID');
  }
  {
    const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
    replaceMetaObject(metaModel, 'urn:usf:permutationsignalpathstep:scheduledpolicy2',
      `${O}signalPathStepIndex`, literal('3', named('http://www.w3.org/2001/XMLSchema#positiveInteger')));
    expectCode(() => universeGeneratorInternals.loadValueSourceDerivation(
      metaModel, 'urn:usf:dimensionvaluesource:scheduledjob',
    ), 'VALUE_DERIVATION_PATH_STEP_INVALID');
  }
});

test('all derived-source declarations bind one semantic execution mode without name dispatch', () => {
  const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
  const registry = loadPermutationFamilyRegistry({ repositoryRoot: process.cwd() });
  const sources = metaModel.store.getQuads(null, named(`${O}valueSourceKind`), literal('derivedselector'), FAMILY_GRAPH)
    .map(({ subject }) => subject.value).sort();
  const structured = sources.filter((source) => metaModel.store
    .getQuads(named(source), named(`${O}valueSourceSelector`), null, FAMILY_GRAPH).length > 0);
  const expressionBound = sources.filter((source) => metaModel.store
    .getQuads(named(source), named(`${O}valueSourceDerivationRoot`), null, FAMILY_GRAPH).length > 0);
  assert.equal(sources.length, expressionBound.length + structured.length);
  assert.equal(new Set([...expressionBound, ...structured]).size, sources.length);
  let linkCount = 0;
  for (const source of expressionBound) {
    const actual = metaModel.store.getQuads(named(source), named(`${O}valueSourceDerivationPredicate`), null, FAMILY_GRAPH)
      .map(({ object }) => object.value).sort();
    const definition = universeGeneratorInternals.loadValueSourceDerivation(metaModel, source);
    assert.deepEqual(actual, definition.root.transitivePredicateIris, source);
    linkCount += actual.length;
  }
  for (const source of structured) {
    const selectorIri = metaModel.store
      .getQuads(named(source), named(`${O}valueSourceSelector`), null, FAMILY_GRAPH)[0].object.value;
    const actual = metaModel.store.getQuads(named(source), named(`${O}valueSourceDerivationPredicate`), null, FAMILY_GRAPH)
      .map(({ object }) => object.value).sort();
    const expected = [...new Set(registry.selectors.get(selectorIri).steps
      .map(({ predicateIri }) => predicateIri))].sort();
    assert.deepEqual(actual, expected, source);
    linkCount += actual.length;
  }
  assert.ok(linkCount >= sources.length);
});

test('foundation taxonomy and template sources resolve only from the candidate catalogue', () => {
  const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
  const expected = new Map([
    ['action', 122],
    ['conditionprofile', 11],
    ['direction', 4],
    ['environmentclass', 7],
    ['interactionpattern', 12],
    ['principalkind', 7],
    ['privacyclassification', 9],
    ['proofrung', 7],
    ['providermode', 5],
    ['resourceselectorkind', 11],
    ['routekind', 6],
    ['secretclass', 2],
    ['sessionmodel', 6],
    ['transport', 13],
  ]);
  for (const [key, count] of expected) {
    const dimensions = metaModel.store
      .getQuads(null, named(`${O}permutationDimensionKey`), literal(key), FAMILY_GRAPH)
      .map(({ subject }) => subject.value);
    const dimension = dimensions.find((candidate) => {
      const source = metaModel.store
        .getQuads(named(candidate), named(`${O}dimensionValueSource`), null, FAMILY_GRAPH)[0]?.object.value;
      return source && metaModel.store.getQuads(
        named(source), named(`${O}valueSourceScope`),
        named('urn:usf:dimensionvaluesourcescope:foundationcatalogue'), FAMILY_GRAPH,
      ).length === 1;
    });
    assert.ok(dimension, `foundation catalogue dimension for ${key}`);
    const descriptor = metaModel.familyRegistry.families
      .flatMap(({ iri: familyIri }) => universeGeneratorInternals.familyDimensions(metaModel, familyIri))
      .find((candidate) => candidate.dimension === dimension);
    assert.ok(descriptor, `class-closure-bound descriptor for ${key}`);
    const domain = universeGeneratorInternals.resolveDomain(
      metaModel, authorityInputs(fakeIndex()), CAPABILITY, descriptor,
    );
    assert.equal(domain.sourcePlane, 'CANDIDATE_FOUNDATION_CATALOGUE');
    assert.equal(domain.valueCount, count);
  }
  assert.equal(metaModel.store.getSubjects(
    named('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
    named(`${O}TokenClaimConstraintTemplate`), null,
  ).length, 25, 'the finite claim-constraint catalogue remains explicit even though families select per-template subsets');
  assert.equal(metaModel.store.getSubjects(
    named('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
    named(`${O}TokenProfileTemplate`), null,
  ).length, 6, 'the finite token-profile catalogue remains explicit even though families select exact template bindings');
});

test('empty class domain remains empty and no fallback vocabulary is invented', () => {
  const { descriptor, metaModel } = classSourceModel();
  const domain = universeGeneratorInternals.resolveDomain(
    metaModel,
    authorityInputs(fakeIndex()),
    CAPABILITY,
    descriptor,
  );
  assert.deepEqual(domain.values, []);
  assert.equal(domain.sourcePlane, 'LIVE_AUTHORITY_EMPTY');
  assert.equal(domain.valueCount, 0);
});

test('repository/live source disagreement fails closed', () => {
  const { descriptor, metaModel } = classSourceModel();
  metaModel.store.addQuad(named('urn:test:permission:local'), named('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
    named(`${O}Permission`), named('urn:test:ordinary-graph'));
  const instances = new Map([[`${O}Permission`, new Set(['urn:test:permission:live'])]]);
  expectCode(() => universeGeneratorInternals.resolveDomain(
    metaModel,
    authorityInputs(fakeIndex({ instances })),
    CAPABILITY,
    descriptor,
  ), 'SOURCE_AUTHORITY_DISAGREEMENT');
});

test('coordinator-only operation cannot become an ordinary role grant', () => {
  const operation = 'urn:test:gateway';
  const role = 'urn:test:role';
  const permission = 'urn:test:permission';
  const disposition = universeGeneratorInternals.dispositionForCell(
    'urn:usf:permutationfamily:operationroleconditionprofile',
    [{ key: 'operation', value: operation }, { key: 'role', value: role }],
    authorityInputs(fakeIndex({
      coordinatorOnly: new Set([operation]),
      grants: new Map([[role, new Set([permission])]]),
      required: new Map([[operation, new Set([permission])]]),
    })),
  );
  assert.equal(disposition.iri, DISPOSITIONS.forbidden);
  assert.equal(disposition.reasonCode, 'FORBIDDEN_BY_COORDINATOR_ONLY');
});

test('role absence remains unresolved rather than not-applicable', () => {
  const operation = 'urn:test:operation';
  const disposition = universeGeneratorInternals.dispositionForCell(
    'urn:usf:permutationfamily:operationroleconditionprofile',
    [{ key: 'operation', value: operation }, { key: 'role', value: 'urn:test:role' }],
    authorityInputs(fakeIndex({ required: new Map([[operation, new Set(['urn:test:permission'])]]) })),
  );
  assert.equal(disposition.iri, DISPOSITIONS.unresolved);
  assert.equal(disposition.reasonCode, 'ROLE_GRANT_ABSENCE_IS_NOT_NON_APPLICABILITY');
});

test('scheduled-job selector requires a structured schedule trigger kind', () => {
  const contract = 'urn:test:contract';
  const scheduled = 'urn:test:workflow:scheduled';
  const unscheduled = 'urn:test:workflow:unscheduled';
  const scheduledPolicy = 'urn:test:workflowpolicy:scheduled';
  const unscheduledPolicy = 'urn:test:workflowpolicy:unscheduled';
  const forward = new Map([
    [`${CAPABILITY}\u0000${O}hasContract`, new Set([contract])],
    [`${scheduled}\u0000${O}workflowExecutionPolicy`, new Set([scheduledPolicy])],
    [`${unscheduled}\u0000${O}workflowExecutionPolicy`, new Set([unscheduledPolicy])],
    [`${scheduledPolicy}\u0000${O}scheduleTriggerKind`, new Set(['urn:usf:scheduletriggerkind:fixedinstant'])],
  ]);
  const reverse = new Map([
    [`${O}workflowForContract\u0000${contract}`, new Set([scheduled, unscheduled])],
  ]);
  const instances = new Map([
    [`${O}Capability`, new Set([CAPABILITY])],
    [`${O}Workflow`, new Set([scheduled, unscheduled])],
  ]);
  const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
  assert.deepEqual(universeGeneratorInternals.semanticValueSource(metaModel,
    authorityInputs(fakeIndex({ forward, instances, reverse })), CAPABILITY,
    'urn:usf:dimensionvaluesource:scheduledjob'), [scheduled]);
});

test('role/service-identity selector includes bound identities without inventing grants', () => {
  const role = 'urn:usf:role:tenantmember';
  const identity = 'urn:test:serviceidentity:worker';
  const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
  const roleClosure = metaModel.familyRegistry.classClosuresByRoot.get(`${O}Role`);
  const identityClosure = metaModel.familyRegistry.classClosuresByRoot.get(`${O}ServiceIdentity`);
  const instances = new Map([...new Set([
    ...roleClosure.memberClassIris,
    ...identityClosure.memberClassIris,
  ])].map((classIri) => [classIri, new Set()]));
  instances.set(`${O}Capability`, new Set([CAPABILITY]));
  instances.set(`${O}Role`, new Set([role]));
  instances.set(`${O}ServiceIdentity`, new Set([identity]));
  const reverse = new Map([
    [`${O}serviceIdentityForCapability\u0000${CAPABILITY}`, new Set([identity])],
  ]);
  const index = fakeIndex({ instances, reverse });
  assert.deepEqual(universeGeneratorInternals.semanticValueSource(metaModel,
    authorityInputs(index), CAPABILITY, 'urn:usf:dimensionvaluesource:roleserviceidentity'), [identity, role]);
  assert.deepEqual(index.values(role, `${O}grantsPermission`), []);
  assert.deepEqual(index.values(identity, `${O}grantsPermission`), []);
});

test('protocol, external, form and trigger selectors use every declared relationship', () => {
  const contract = 'urn:test:contract';
  const interfaceIri = 'urn:test:interface';
  const route = 'urn:test:route';
  const uiModel = 'urn:test:ui';
  const surface = 'urn:test:surface';
  const viewModel = 'urn:test:viewmodel';
  const form = 'urn:test:form';
  const externalPort = 'urn:test:port:external';
  const externalDependency = 'urn:test:externaldependency';
  const unboundPort = 'urn:test:port:unbound';
  const workflow = 'urn:test:workflow';
  const eventTransition = 'urn:test:transition:event';
  const operationTransition = 'urn:test:transition:operation';
  const event = 'urn:test:event';
  const operation = 'urn:test:operation';
  const forward = new Map([
    [`${CAPABILITY}\u0000${O}hasContract`, new Set([contract])],
    [`${CAPABILITY}\u0000${O}hasUISemanticModel`, new Set([uiModel])],
    [`${uiModel}\u0000${O}hasSurface`, new Set([surface])],
    [`${uiModel}\u0000${O}hasViewModel`, new Set([viewModel])],
    [`${surface}\u0000${O}surfaceRoute`, new Set([route])],
    [`${viewModel}\u0000${O}hasForm`, new Set([form])],
    [`${externalDependency}\u0000${O}externalDependencyProvider`, new Set(['urn:test:provider'])],
    [`${workflow}\u0000${O}hasTransition`, new Set([eventTransition, operationTransition])],
    [`${eventTransition}\u0000${O}onEvent`, new Set([event])],
    [`${operationTransition}\u0000${O}onOperation`, new Set([operation])],
  ]);
  const reverse = new Map([
    [`${O}interfaceForContract\u0000${contract}`, new Set([interfaceIri])],
    [`${O}portForContract\u0000${contract}`, new Set([externalPort, unboundPort])],
    [`${O}externalDependencyAtPort\u0000${externalPort}`, new Set([externalDependency])],
    [`${O}workflowForContract\u0000${contract}`, new Set([workflow])],
  ]);
  const instances = new Map([
    [`${O}Capability`, new Set([CAPABILITY])],
    [`${O}Event`, new Set([event])],
    [`${O}ExternalDependency`, new Set([externalDependency])],
    [`${O}Form`, new Set([form])],
    [`${O}Interface`, new Set([interfaceIri])],
    [`${O}Operation`, new Set([operation])],
    [`${O}Port`, new Set([externalPort, unboundPort])],
    [`${O}Route`, new Set([route])],
    [`${O}ViewModel`, new Set([viewModel])],
  ]);
  const inputs = authorityInputs(fakeIndex({ forward, instances, reverse }));
  const metaModel = universeGeneratorInternals.loadPermutationMetaModel(process.cwd());
  const derive = (source) => universeGeneratorInternals.semanticValueSource(metaModel, inputs, CAPABILITY,
    `urn:usf:dimensionvaluesource:${source}`);
  assert.deepEqual(derive('apiprotocolsurface'), [interfaceIri, route]);
  assert.deepEqual(derive('externaldependency'), [externalDependency]);
  assert.deepEqual(derive('formview'), [form, viewModel]);
  assert.deepEqual(derive('trigger'), [event, operation]);
});

test('independent key classifier distinguishes missing, extra and duplicate defects', () => {
  const diagnostics = universeProofInternals.classifyUniverseKeys(
    ['expected-a', 'expected-b'],
    ['expected-a', 'extra', 'extra'],
  );
  assert.deepEqual(diagnostics.map(({ code }) => code), [
    'PERMUTATION_UNIVERSE_DUPLICATE_CELL',
    'PERMUTATION_UNIVERSE_EXTRA_CELL',
    'PERMUTATION_UNIVERSE_MISSING_CELL',
  ]);
});

test('independent key classifier rejects an empty actual universe', () => {
  const diagnostics = universeProofInternals.classifyUniverseKeys(['required'], []);
  assert.deepEqual(diagnostics.map(({ code }) => code), [
    'PERMUTATION_UNIVERSE_EMPTY',
    'PERMUTATION_UNIVERSE_MISSING_CELL',
  ]);
});

function inspectedCell() {
  const domains = [
    { dimension: 'urn:test:d1', key: 'operation', position: 1, valueSetDigest: 'sha256:one', values: ['urn:test:operation'] },
    { dimension: 'urn:test:d2', key: 'permissionatom', position: 2, valueSetDigest: 'sha256:two', values: ['urn:test:permission'] },
  ];
  const bindings = domains.map((domain) => ({
    dimension: domain.dimension,
    key: domain.key,
    position: domain.position,
    value: domain.values[0],
    valueSetDigest: domain.valueSetDigest,
  }));
  const identity = canonicalCellIdentity(FAMILY, CAPABILITY, bindings);
  const inputs = authorityInputs(fakeIndex({ required: new Map([['urn:test:operation', new Set(['urn:test:permission'])]]) }));
  const disposition = universeGeneratorInternals.dispositionForCell(FAMILY, bindings, inputs);
  return {
    cell: {
      ...identity,
      authorityDigest: AUTHORITY,
      capability: CAPABILITY,
      dimensionBindings: bindings,
      dimensionKeys: bindings.map(({ key }) => key),
      dimensionValues: bindings.map(({ value }) => value),
      disposition: disposition.iri,
      dispositions: [disposition],
      family: FAMILY,
      familyCanonicalName: 'operationpermissionatom',
      subject: CAPABILITY,
    },
    inputs,
    plan: { domains, record: { canonicalName: 'operationpermissionatom', subject: CAPABILITY } },
  };
}

const inspectCodes = (mutate) => {
  const fixture = inspectedCell();
  mutate(fixture.cell);
  const collector = universeProofInternals.diagnosticCollector();
  universeProofInternals.inspectCell(fixture.cell, fixture.plan, fixture.inputs, collector, 0);
  return collector.list().map(({ code }) => code);
};

test('missing disposition reaches PERMUTATION_CELL_DISPOSITION_ABSENT', () => {
  assert.ok(inspectCodes((cell) => { cell.disposition = null; cell.dispositions = []; })
    .includes('PERMUTATION_CELL_DISPOSITION_ABSENT'));
});

test('multiple dispositions reach PERMUTATION_CELL_DISPOSITION_MULTIPLE', () => {
  assert.ok(inspectCodes((cell) => { cell.dispositions.push({ ...cell.dispositions[0] }); })
    .includes('PERMUTATION_CELL_DISPOSITION_MULTIPLE'));
});

test('invalid disposition reaches PERMUTATION_CELL_DISPOSITION_INVALID', () => {
  assert.ok(inspectCodes((cell) => {
    cell.disposition = 'urn:test:invalid';
    cell.dispositions[0].iri = 'urn:test:invalid';
  }).includes('PERMUTATION_CELL_DISPOSITION_INVALID'));
});

test('cross-scope disposition substitution reaches semantic mismatch', () => {
  assert.ok(inspectCodes((cell) => {
    cell.disposition = DISPOSITIONS.allowed;
    cell.dispositions[0].iri = DISPOSITIONS.allowed;
  }).includes('PERMUTATION_CELL_DISPOSITION_MISMATCH'));
});

test('identity tampering reaches PERMUTATION_CELL_IDENTITY_INVALID', () => {
  assert.ok(inspectCodes((cell) => { cell.stableKey = 'tampered'; })
    .includes('PERMUTATION_CELL_IDENTITY_INVALID'));
});

test('cell subject absence and substitution reach their exact diagnostics', () => {
  assert.deepEqual(inspectCodes((cell) => { delete cell.subject; }), [
    'PERMUTATION_CELL_SUBJECT_ABSENT',
  ]);
  assert.ok(inspectCodes((cell) => { cell.subject = 'urn:test:capability:other'; })
    .includes('PERMUTATION_CELL_SUBJECT_MISMATCH'));
});

test('candidate output is deterministic across input ordering', () => {
  const cells = universeGeneratorInternals.generateFamilyCells(
    controlledFamilyModel(),
    authorityInputs(fakeIndex({
      required: new Map([['urn:test:operation:one', new Set(['urn:test:permission:one', 'urn:test:permission:two'])]]),
    })),
    record,
  ).cells;
  const first = derivePermissionAtomCandidates({ cells });
  const second = derivePermissionAtomCandidates({ cells: [...cells].reverse() });
  assert.equal(canonicalJson(first), canonicalJson(second));
});

test('all six dispositions map to one exact sparse closure partition', () => {
  const expected = new Map([
    [DISPOSITIONS.required, ['APPLICABLE', 'SATISFIABLE', 'OPERATIONAL_CELL']],
    [DISPOSITIONS.allowed, ['APPLICABLE', 'SATISFIABLE', 'OPERATIONAL_CELL']],
    [DISPOSITIONS.forbidden, ['APPLICABLE', 'UNSATISFIABLE', 'RULE_COVERED']],
    [DISPOSITIONS.notApplicable, ['NOT_APPLICABLE', 'NOT_APPLICABLE', 'RULE_COVERED']],
    [DISPOSITIONS.deferred, ['UNDETERMINED', 'UNDETERMINED', 'PENDING_REGION']],
    [DISPOSITIONS.unresolved, ['UNDETERMINED', 'UNDETERMINED', 'PENDING_REGION']],
  ]);
  for (const [disposition, [applicability, satisfiability, representation]] of expected) {
    const generated = closureClassificationForDisposition(disposition);
    const independentlyVerified = universeProofInternals.independentClosureClassification(disposition);
    assert.deepEqual(generated, { applicability, representation, satisfiability });
    assert.deepEqual(independentlyVerified, { applicability, representation, satisfiability });
  }
  expectCode(() => closureClassificationForDisposition('urn:test:unknown'), 'PERMUTATION_CELL_DISPOSITION_INVALID');
});

test('sparse partition equation rejects overlap, omission and region mismatch', () => {
  const dispositionCounts = {
    [DISPOSITIONS.allowed]: 1,
    [DISPOSITIONS.deferred]: 2,
    [DISPOSITIONS.forbidden]: 3,
    [DISPOSITIONS.notApplicable]: 4,
    [DISPOSITIONS.required]: 5,
    [DISPOSITIONS.unresolved]: 6,
  };
  const valid = {
    closureCounts: {
      rawCandidateCount: 21,
      representation: { operationalCell: 6, pendingRegionMember: 8, ruleCovered: 7 },
    },
    dispositionCounts,
    pendingCoverageRegions: [{ coveredCellCount: 8 }],
    ruleCoverageRegions: [{ coveredCellCount: 7 }],
  };
  assert.doesNotThrow(() => universeGeneratorInternals.assertExactSparsePartition(valid));
  for (const mutate of [
    (fixture) => { fixture.closureCounts.rawCandidateCount += 1; },
    (fixture) => { fixture.closureCounts.representation.operationalCell += 1; },
    (fixture) => { fixture.pendingCoverageRegions[0].coveredCellCount -= 1; },
    (fixture) => { fixture.ruleCoverageRegions[0].coveredCellCount += 1; },
  ]) {
    const fixture = structuredClone(valid);
    mutate(fixture);
    expectCode(() => universeGeneratorInternals.assertExactSparsePartition(fixture), 'PERMUTATION_SPARSE_PARTITION_MISMATCH');
  }
});

test('publication preflight is exact at the reserve boundary and rejects one-edge overflow', () => {
  const base = {
    operationalCellCount: 0,
    pendingRegionCount: 0,
    providerEdgeLimit: 10_000,
    publicationReserve: 1_000,
    ruleRegionCount: 0,
  };
  const atBoundary = universeGeneratorInternals.publicationBudget({ ...base, liveTripleCount: 4_904, policy: PUBLICATION_POLICY });
  assert.equal(atBoundary.candidateTripleUpperBound, 4_096);
  assert.equal(atBoundary.projectedTripleUpperBound, 9_000);
  assert.equal(atBoundary.result, 'PREFLIGHT_PASS');
  assert.equal(atBoundary.exactCandidateGraphGate, 'REQUIRED_BEFORE_AUTHORITY_TRANSACTION');
  assert.deepEqual(universeProofInternals.independentPublicationBudget({ ...base, liveTripleCount: 4_904, policy: PUBLICATION_POLICY }), atBoundary);
  expectCode(() => universeGeneratorInternals.publicationBudget({ ...base, liveTripleCount: 4_905, policy: PUBLICATION_POLICY }),
    'PERMUTATION_PUBLICATION_BUDGET_EXCEEDED');
});

test('publication preflight rejects negative, fractional and overflowing operands', () => {
  const base = {
    liveTripleCount: 1,
    operationalCellCount: 0,
    pendingRegionCount: 0,
    providerEdgeLimit: 10_000,
    publicationReserve: 1_000,
    ruleRegionCount: 0,
  };
  for (const override of [
    { operationalCellCount: -1 },
    { pendingRegionCount: 0.5 },
    { ruleRegionCount: Number.MAX_SAFE_INTEGER },
  ]) {
    expectCode(() => universeGeneratorInternals.publicationBudget({ ...base, ...override, policy: PUBLICATION_POLICY }),
      'PERMUTATION_PUBLICATION_BUDGET_INVALID');
  }
});

test('symbolic coverage is limited to its exact registered family and rule', () => {
  const operation = 'urn:test:operation';
  const permission = 'urn:test:permission';
  const requiredPermissions = [];
  const applicabilityProof = sha256(canonicalJson({ operation, requiredPermissions }));
  const cell = {
    cellIri: 'urn:test:cell',
    dimensionBindings: [
      { key: 'operation', value: operation },
      { key: 'permissionatom', value: permission },
    ],
    disposition: DISPOSITIONS.notApplicable,
    dispositions: [{
      applicabilityProof,
      iri: DISPOSITIONS.notApplicable,
      reasonCode: 'OPERATION_DOES_NOT_REQUIRE_PERMISSION',
    }],
    family: FAMILY,
  };
  assert.equal(universeGeneratorInternals.authorityBackedCoverageRule(
    cell,
    authorityInputs(fakeIndex()),
    COVERAGE_RULES,
  ).ruleKind, 'AUTHORITY_SET_NON_MEMBERSHIP');
  const wrongFamily = { ...cell, family: 'urn:usf:permutationfamily:other' };
  expectCode(() => universeGeneratorInternals.authorityBackedCoverageRule(
    wrongFamily,
    authorityInputs(fakeIndex()),
    COVERAGE_RULES,
  ), 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_SCOPE_INVALID');
  expectCode(() => universeProofInternals.independentCoverageRule(
    wrongFamily,
    authorityInputs(fakeIndex()),
    COVERAGE_RULES,
  ), 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_SCOPE_INVALID');
});

test('independent raw proof distinguishes incomplete closure from failed invariants', () => {
  assert.equal(universeProofInternals.rawProofVerdict([
    { code: 'REQUIRED_FINITE_DOMAIN_EMPTY', count: 1, severity: 'INCOMPLETE' },
  ], { unresolvedCount: 0 }), 'PERMUTATION_CLOSURE_INCOMPLETE');
  assert.equal(universeProofInternals.rawProofVerdict([], { unresolvedCount: 1 }), 'PERMUTATION_CLOSURE_INCOMPLETE');
  assert.equal(universeProofInternals.rawProofVerdict([
    { code: 'PERMUTATION_UNIVERSE_MISSING_CELL', count: 1, severity: 'ERROR' },
  ], { unresolvedCount: 1 }), 'INVARIANTS_FAILED');
});
