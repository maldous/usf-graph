// Authority-bound deterministic permutation universe generator.
// Live domain truth comes only from verified USF MCP packets/projections.
// Repository RDF supplies the unpublished permutation meta-model only.

import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync, gzipSync } from 'node:zlib';
import N3 from 'n3';
import {
  canonicalJson,
  evaluationInternals,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import {
  AuthorityProjectionIndex,
  assertVerifiedAuthorityInputs,
  instancesForClassClosure,
  isTypeInClassClosure,
  loadVerifiedAuthorityInputs,
  PermutationInputError,
} from './family-census.mjs';
import { loadPermutationFamilyRegistry } from './family-registry.mjs';

const { RDF_TYPE, term, iri, objects, subjects, has } = evaluationInternals;
const O = 'urn:usf:ontology:';
const PERMUTATION_FAMILY_PREFIX = 'urn:usf:permutationfamily:';
const PERMUTATION_CELL_PREFIX = 'urn:usf:permutationcell:';
const FOUNDATION_FIXTURE_RELATIVE_PATH = 'semantic-model/fixtures/conforming/universal-service-foundation.trig';
const FOUNDATION_FIXTURE_SCOPE = 'FOUNDATION_CONFORMANCE_FIXTURE';
const VERIFIED_FOUNDATION_FIXTURE_INPUTS = new WeakSet();
const modulePath = fileURLToPath(import.meta.url);
const independentVerifierPath = join(dirname(modulePath), 'universe-proof.mjs');
const ALGORITHM_DEPENDENCY_FILES = Object.freeze([
  'assurance/permutation-closure/family-census.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation.mjs',
]);
const META_MODEL_GRAPHS = new Set([
  'urn:usf:graph:permutation-actions',
  'urn:usf:graph:permutation-families',
  'urn:usf:graph:permutation-transports',
  'urn:usf:graph:permutation-vocabulary',
  'urn:usf:graph:vocabulary',
]);
const META_MODEL_FILES = Object.freeze([
  'semantic-model/ontology.ttl',
  'semantic-model/vocabulary.ttl',
  'semantic-model/permutation/action-catalogue.trig',
  'semantic-model/permutation/closure-vocabulary.trig',
  'semantic-model/permutation/families.trig',
  'semantic-model/permutation/transport-catalogue.trig',
  'semantic-model/shapes/permutation.ttl',
]);
const META_MODEL_FILE_GRAPHS = Object.freeze({
  'semantic-model/ontology.ttl': 'urn:usf:graph:ontology',
  'semantic-model/vocabulary.ttl': 'urn:usf:graph:vocabulary',
});

export const DISPOSITIONS = Object.freeze({
  allowed: 'urn:usf:permutationclosuredisposition:allowed',
  deferred: 'urn:usf:permutationclosuredisposition:deferred',
  forbidden: 'urn:usf:permutationclosuredisposition:forbidden',
  notApplicable: 'urn:usf:permutationclosuredisposition:notapplicable',
  required: 'urn:usf:permutationclosuredisposition:required',
  unresolved: 'urn:usf:permutationclosuredisposition:unresolved',
});

const SOURCE_KIND = Object.freeze({
  CLASS_INSTANCES: 'classinstances',
  CONTROLLED_LIST: 'controlledlist',
  DERIVED_SELECTOR: 'derivedselector',
});
const SOURCE_SCOPE = Object.freeze({
  AUTHORITY_INSTANCE_SET: 'urn:usf:dimensionvaluesourcescope:authorityinstanceset',
  CAPABILITY_RELATIONSHIP: 'urn:usf:dimensionvaluesourcescope:capabilityrelationship',
  DOWNSTREAM_CLOSURE: 'urn:usf:dimensionvaluesourcescope:downstreamclosure',
  FOUNDATION_CATALOGUE: 'urn:usf:dimensionvaluesourcescope:foundationcatalogue',
  REGISTERED_SUBJECT_RELATIONSHIP: 'urn:usf:dimensionvaluesourcescope:registeredsubjectrelationship',
});
const VALUE_DERIVATION_OPERATOR = Object.freeze({
  CLASS_INSTANCES: 'urn:usf:permutationvaluederivationoperator:classinstances',
  FILTER_PATH_EXISTS: 'urn:usf:permutationvaluederivationoperator:filterpathexists',
  FILTER_PATH_VALUE_IN: 'urn:usf:permutationvaluederivationoperator:filterpathvaluein',
  FILTER_TYPE_ANY: 'urn:usf:permutationvaluederivationoperator:filtertypeany',
  INBOUND: 'urn:usf:permutationvaluederivationoperator:inbound',
  OUTBOUND: 'urn:usf:permutationvaluederivationoperator:outbound',
  SUBJECT: 'urn:usf:permutationvaluederivationoperator:subject',
  UNION: 'urn:usf:permutationvaluederivationoperator:union',
});
const VALUE_DERIVATION_INPUT_SCOPE = Object.freeze({
  ALL: 'urn:usf:permutationvaluederivationinputscope:all',
  FOUNDATION_FIXTURE: 'urn:usf:permutationvaluederivationinputscope:foundationconformancefixture',
  LIVE_AUTHORITY: 'urn:usf:permutationvaluederivationinputscope:liveauthority',
});
const VALUE_TERMINAL_KIND = Object.freeze({
  NAMED_NODE: 'urn:usf:permutationvalueterminalkind:namednode',
});
const OWL_CLASS = 'http://www.w3.org/2002/07/owl#Class';
const RDFS_CLASS = 'http://www.w3.org/2000/01/rdf-schema#Class';
const RDFS_SUBCLASS_OF = 'http://www.w3.org/2000/01/rdf-schema#subClassOf';
const RDF_PROPERTY = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#Property';
const OWL_PROPERTY_KINDS = Object.freeze([
  'http://www.w3.org/2002/07/owl#AnnotationProperty',
  'http://www.w3.org/2002/07/owl#DatatypeProperty',
  'http://www.w3.org/2002/07/owl#ObjectProperty',
]);

const fail = (code, message, details = {}) => {
  throw new PermutationInputError(code, message, details);
};
const compareCodeUnits = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const uniqueSorted = (values) => [...new Set(values)].sort();
const metaValues = (terms) => uniqueSorted(terms.map(({ value }) => value));
const metaObjects = (store, subject, predicate) => objects(store, iri(subject), term(predicate));
const metaObjectValues = (store, subject, predicate) => metaValues(metaObjects(store, subject, predicate));
const metaIriValues = (store, subject, predicate, code) => {
  const terms = metaObjects(store, subject, predicate);
  if (terms.some(({ termType }) => termType !== 'NamedNode')) {
    fail(code, `${subject} ${predicate} values must be IRIs`);
  }
  return metaValues(terms);
};
const fullDigest = (value) => sha256(canonicalJson(value));

function ownerClassClosures(metaModel, ownerIri, predicate, code) {
  const closureIris = metaIriValues(metaModel.store, ownerIri, predicate, code);
  if (closureIris.length === 0) fail('CLASS_CLOSURE_POLICY_MISSING', `${ownerIri} has no ${predicate}`);
  return closureIris.map((closureIri) => {
    const closure = metaModel.familyRegistry.classClosures.get(closureIri);
    if (!closure) fail(code, `${ownerIri} references unknown closure ${closureIri}`);
    return closure;
  });
}

function resourceHasClosureType(index, resourceIri, closures) {
  return closures.some(({ memberClassIris }) => memberClassIris.some((classIri) => index.isType(resourceIri, classIri)));
}

function metaResourceHasClosureType(store, resourceIri, closures) {
  const exactTypes = new Set(store.getObjects(iri(resourceIri), RDF_TYPE, null).map(({ value }) => value));
  return closures.some(({ memberClassIris }) => memberClassIris.some((classIri) => exactTypes.has(classIri)));
}

function closureInstances(authorityInputs, closures) {
  const foundation = VERIFIED_FOUNDATION_FIXTURE_INPUTS.has(authorityInputs);
  const result = [];
  for (const closure of closures) {
    for (const classIri of closure.memberClassIris) {
      const projected = authorityInputs.index.projectedClassIris.has(classIri)
        || authorityInputs.index.operationClasses.has(classIri);
      if (!projected) {
        if (foundation) continue;
        fail('CLASS_CLOSURE_MEMBER_NOT_PROJECTED', `${closure.iri} member ${classIri} is absent from the bounded projection`);
      }
      result.push(...authorityInputs.index.instances(classIri));
    }
  }
  return uniqueSorted(result);
}
function sourceAlgorithmBindings(repositoryRoot, applicabilityRuleDigest) {
  const dependencySources = ALGORITHM_DEPENDENCY_FILES.map((path) => ({
    digest: sha256(readFileSync(resolve(repositoryRoot, path))),
    path,
  }));
  return {
    applicabilityRuleDigest,
    dependencySourceDigest: fullDigest(dependencySources),
    generatorDigest: sha256(readFileSync(modulePath)),
    independentVerifierDigest: sha256(readFileSync(resolve(repositoryRoot, independentVerifierPath))),
  };
}

function loadPermutationMetaModel(repositoryRoot) {
  const store = new N3.Store();
  const sourceFiles = [];
  for (const path of META_MODEL_FILES) {
    const bytes = readFileSync(join(repositoryRoot, path));
    sourceFiles.push({ digest: sha256(bytes), path });
    const quads = new N3.Parser({
      baseIRI: 'urn:usf:',
      format: path.endsWith('.trig') ? 'application/trig' : 'text/turtle',
    }).parse(bytes.toString('utf8'));
    const graphIri = META_MODEL_FILE_GRAPHS[path];
    store.addQuads(graphIri
      ? quads.map((quad) => N3.DataFactory.quad(
        quad.subject,
        quad.predicate,
        quad.object,
        N3.DataFactory.namedNode(graphIri),
      ))
      : quads);
  }
  const coverageRules = loadCoverageRules(store);
  const familyRegistry = loadPermutationFamilyRegistry({ repositoryRoot });
  const foundationProjectionRules = loadFoundationProjectionRules(store);
  const publicationBudgetPolicy = loadPublicationBudgetPolicy(store);
  return {
    coverageRules,
    digest: fullDigest(sourceFiles),
    foundationProjectionRules,
    familyRegistry,
    publicationBudgetPolicy,
    sourceFiles,
    store,
  };
}

const fixtureQuadRecord = ({ subject, predicate, object, graph }) => [
  subject.value,
  predicate.value,
  object.termType === 'NamedNode' ? 'iri' : 'literal',
  object.value,
  object.termType === 'Literal' ? object.datatype.value : null,
  object.termType === 'Literal' && object.language ? object.language : null,
  graph.value,
];

function foundationFixtureDigest(quads) {
  return fullDigest(quads
    .filter(({ predicate }) => predicate.value !== `${O}foundationFixtureDigest`)
    .map(fixtureQuadRecord)
    .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right))));
}

function assertFoundationFixtureInputs(inputs) {
  if (!inputs || !VERIFIED_FOUNDATION_FIXTURE_INPUTS.has(inputs)) {
    fail('FOUNDATION_FIXTURE_INPUT_UNVERIFIED', 'use loadFoundationFixtureInputs before fixture evaluation');
  }
  return inputs;
}

export function loadFoundationFixtureInputs({ authorityInputs, repositoryRoot }) {
  const authority = assertVerifiedAuthorityInputs(authorityInputs);
  const fixturePath = resolve(repositoryRoot, FOUNDATION_FIXTURE_RELATIVE_PATH);
  const fixtureRoot = resolve(repositoryRoot, 'semantic-model', 'fixtures', 'conforming');
  if (!existsSync(fixturePath) || !lstatSync(fixturePath).isFile() || lstatSync(fixturePath).isSymbolicLink()
    || !realpathSync(fixturePath).startsWith(`${realpathSync(fixtureRoot)}/`)) {
    fail('FOUNDATION_FIXTURE_PATH_INVALID', 'the canonical conforming fixture must be one regular non-symlink file');
  }
  const bytes = readFileSync(fixturePath);
  let quads;
  try {
    quads = new N3.Parser({ format: 'application/trig', baseIRI: 'urn:usf:' }).parse(bytes.toString('utf8'));
  } catch (error) {
    fail('FOUNDATION_FIXTURE_RDF_INVALID', error.message);
  }
  const graphIris = uniqueSorted(quads.map(({ graph }) => graph.value));
  if (quads.length === 0 || graphIris.length !== 1
    || quads.some(({ subject, predicate, object, graph }) => graph.termType !== 'NamedNode'
      || subject.termType !== 'NamedNode'
      || predicate.termType !== 'NamedNode'
      || !['NamedNode', 'Literal'].includes(object.termType))) {
    fail('FOUNDATION_FIXTURE_GRAPH_INVALID', 'fixture statements must occupy an explicit named graph');
  }
  const store = new N3.Store(quads);
  const roots = uniqueSorted(store.getQuads(null, RDF_TYPE, iri(`${O}FoundationConformanceFixture`), null)
    .map(({ subject }) => subject.value));
  if (roots.length !== 1) fail('FOUNDATION_FIXTURE_ROOT_CARDINALITY', 'fixture must contain exactly one conformance root');
  const fixtureRootIri = roots[0];
  const conformanceFlags = metaObjectValues(store, fixtureRootIri, 'foundationConformanceOnly');
  if (canonicalJson(conformanceFlags) !== canonicalJson(['true'])) {
    fail('FOUNDATION_FIXTURE_SCOPE_INVALID', 'fixture root must be explicitly non-authority conformance-only');
  }
  const primaryCapabilities = metaObjectValues(store, fixtureRootIri, 'foundationFixturePrimaryCapability');
  if (primaryCapabilities.length !== 1
    || store.getQuads(iri(primaryCapabilities[0]), RDF_TYPE, iri(`${O}Capability`), null).length !== 1) {
    fail('FOUNDATION_FIXTURE_PRIMARY_CAPABILITY_INVALID', 'fixture root must select one explicitly typed primary capability');
  }
  const primarySubjects = metaObjectValues(store, fixtureRootIri, 'foundationFixturePrimarySubject');
  if (primarySubjects.length === 0 || new Set(primarySubjects).size !== primarySubjects.length
    || !primarySubjects.includes(primaryCapabilities[0])) {
    fail('FOUNDATION_FIXTURE_PRIMARY_SUBJECT_SET_INVALID',
      'fixture root must select a unique primary subject set containing its primary capability');
  }
  const declaredDigests = metaObjectValues(store, fixtureRootIri, 'foundationFixtureDigest');
  const digestStatements = store.getQuads(null, iri(`${O}foundationFixtureDigest`), null, null);
  if (digestStatements.length !== 1 || digestStatements[0].subject.value !== fixtureRootIri) {
    fail('FOUNDATION_FIXTURE_DIGEST_MISMATCH', 'fixture must contain one digest statement on its conformance root');
  }
  const semanticDigest = foundationFixtureDigest(quads);
  if (canonicalJson(declaredDigests) !== canonicalJson([semanticDigest])) {
    fail('FOUNDATION_FIXTURE_DIGEST_MISMATCH', 'fixture semantic digest does not match its canonical statements');
  }
  const prohibitedPredicates = new Set([
    `${O}grantsPermission`, `${O}cellTokenScope`, `${O}pathTokenScope`, `${O}profileScope`, `${O}scopePermissionAtom`,
    `${O}cellAuthorityDigest`, `${O}reachabilityAuthorityDigest`, `${O}cellAuthorisationPath`, `${O}cellPermissionAtom`,
  ]);
  const prohibitedTypes = new Set([
    `${O}AuthorisationPath`, `${O}PermissionAtom`, `${O}PermissionAtomCandidate`, `${O}RolePermissionDisposition`, `${O}TokenScope`,
  ]);
  const operationalTypes = new Set([
    ...prohibitedTypes,
    `${O}ActionReachability`, `${O}PermutationCell`,
  ]);
  const ontology = new N3.Store(new N3.Parser({ format: 'text/turtle' })
    .parse(readFileSync(resolve(repositoryRoot, 'semantic-model', 'ontology.ttl'), 'utf8')));
  const domainPredicate = iri('http://www.w3.org/2000/01/rdf-schema#domain');
  const rangePredicate = iri('http://www.w3.org/2000/01/rdf-schema#range');
  const prohibited = quads.filter(({ predicate, object }) => prohibitedPredicates.has(predicate.value)
    || (predicate.equals(RDF_TYPE) && operationalTypes.has(object.value))
    || ontology.getQuads(predicate, domainPredicate, null, null).some(({ object: domain }) => operationalTypes.has(domain.value))
    || (object.termType === 'NamedNode'
      && ontology.getQuads(predicate, rangePredicate, null, null).some(({ object: range }) => operationalTypes.has(range.value))));
  if (prohibited.length > 0) {
    fail('FOUNDATION_FIXTURE_AUTHORISATION_PROHIBITED', 'foundation fixture cannot assert or entail operational authorisation resources');
  }
  const tripleRecords = quads.map(fixtureQuadRecord).map((record) => record.slice(0, 6))
    .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  if (new Set(tripleRecords.map((record) => canonicalJson(record))).size !== tripleRecords.length) {
    fail('FOUNDATION_FIXTURE_TRIPLE_DUPLICATE', 'fixture contains duplicate semantic statements');
  }
  const projectedClassIris = uniqueSorted(quads
    .filter(({ predicate, object }) => predicate.equals(RDF_TYPE) && object.termType === 'NamedNode')
    .map(({ object }) => object.value));
  const projectedPredicateIris = uniqueSorted(quads.map(({ predicate }) => predicate.value));
  const operationClasses = [`${O}Command`, `${O}GatewayOperation`, `${O}Operation`, `${O}Query`];
  const operationClassBindings = [[`${O}Operation`, null]];
  for (const operationClass of operationClasses) {
    for (const operation of uniqueSorted(store.getQuads(null, RDF_TYPE, iri(operationClass), null)
      .map(({ subject }) => subject.value))) {
      operationClassBindings.push([operationClass, operation]);
    }
  }
  operationClassBindings.sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  const projection = {
    gatewayOperationCapabilityBindings: [],
    operationClassBindings,
    projectedClassIris,
    projectedPredicateIris,
    triples: tripleRecords,
  };
  const fixtureProjectionDigest = fullDigest(projection);
  const nonClaims = Object.freeze([
    'NOT_APPLICABILITY_EVIDENCE',
    'NOT_AUTHORISATION',
    'NOT_DISPOSITION_EVIDENCE',
    'NOT_LIVE_AUTHORITY',
    'NOT_PERMISSION_GRANT',
    'NOT_PRODUCTION_READINESS',
    'NOT_TOKEN_SCOPE',
  ]);
  const core = {
    authorising: false,
    baselineAuthorityBinding: {
      authorityDigest: authority.authorityDigest,
      authorityPacketDigest: authority.authorityPacketDigest,
      authorityProjectionDigest: authority.authorityProjectionDigest,
    },
    foundationFixtureDigest: semanticDigest,
    foundationFixtureFileDigest: sha256(bytes),
    foundationFixturePath: FOUNDATION_FIXTURE_RELATIVE_PATH,
    foundationFixtureProjectionDigest: fixtureProjectionDigest,
    foundationFixtureRoot: fixtureRootIri,
    foundationFixturePrimaryCapability: primaryCapabilities[0],
    foundationFixturePrimarySubjects: primarySubjects,
    foundationConformanceOnly: true,
    inputMode: FOUNDATION_FIXTURE_SCOPE,
    nonClaims,
    purpose: 'FINITE_DOMAIN_EXPRESSIBILITY_ONLY',
    recordKind: 'USF_FOUNDATION_CONFORMANCE_FIXTURE_INPUT',
    schemaVersion: 2,
  };
  const inputs = Object.freeze({
    ...core,
    fixtureInputDigest: fullDigest(core),
    fixtureProjection: projection,
    index: new AuthorityProjectionIndex(projection),
    store,
  });
  VERIFIED_FOUNDATION_FIXTURE_INPUTS.add(inputs);
  return inputs;
}

function metaInstances(store, classIri) {
  return uniqueSorted(store.getQuads(null, RDF_TYPE, iri(classIri), null)
    .filter(({ graph }) => META_MODEL_GRAPHS.has(graph.value))
    .map(({ subject }) => subject.value));
}

function oneMetaValue(store, subject, predicate, code) {
  const found = metaObjectValues(store, subject, predicate);
  if (found.length !== 1) fail(code, `${subject} must have exactly one ${predicate}`);
  return found[0];
}

function loadCoverageRules(store) {
  const records = metaInstances(store, `${O}PermutationCoverageRule`).map((resource) => {
    const record = {
      disposition: oneMetaValue(store, resource, 'coverageRuleDisposition', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
      families: metaObjectValues(store, resource, 'coverageRuleForFamily'),
      predicate: oneMetaValue(store, resource, 'coverageRuleAuthorityPredicate', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
      reasonCode: oneMetaValue(store, resource, 'coverageRuleReasonCode', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
      ruleKind: oneMetaValue(store, resource, 'coverageRuleKind', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
      testedDimensionKey: oneMetaValue(store, resource, 'coverageRuleTestedDimensionKey', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
    };
    const declaredDigest = oneMetaValue(store, resource, 'coverageRuleDigest', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED');
    if (record.families.length === 0 || declaredDigest !== fullDigest(record)) {
      fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', `${resource} has an invalid family set or digest`);
    }
    return { ...record, declaredDigest, resource };
  }).sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  if (records.length === 0) fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', 'no symbolic coverage rules are registered');
  const specification = records.map(({ declaredDigest: omittedDigest, resource: omittedResource, ...record }) => record);
  const identities = records.map(({ disposition, families, reasonCode }) => canonicalJson({ disposition, families, reasonCode }));
  if (new Set(identities).size !== identities.length) {
    fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', 'symbolic coverage rule identities are duplicated');
  }
  return { digest: fullDigest(specification), records, specification };
}

function loadFoundationProjectionRules(store) {
  const identityModes = new Set([
    'urn:usf:foundationprojectionidentitymode:digestshadow',
    'urn:usf:foundationprojectionidentitymode:sourcealias',
  ]);
  const permittedTargets = new Set([`${O}ActionReachability`, `${O}PermissionAtom`, `${O}PermutationCell`]);
  const prohibitedTargetPredicates = new Set([
    `${O}cellAuthorityDigest`, `${O}cellDigest`, `${O}cellProofResult`, `${O}cellProvenanceRule`,
    `${O}reachabilityAuthorityDigest`, `${O}reachabilityDigest`,
  ]);
  const domainPredicate = iri('http://www.w3.org/2000/01/rdf-schema#domain');
  const subclassPredicate = iri(RDFS_SUBCLASS_OF);
  const declaredProperty = (propertyIri) => [RDF_PROPERTY, ...OWL_PROPERTY_KINDS]
    .some((kind) => store.getQuads(iri(propertyIri), RDF_TYPE, iri(kind), null).length > 0);
  const one = (subject, predicate, code) => oneMetaValue(store, subject, predicate, code);
  const rules = metaInstances(store, `${O}FoundationConformanceProjectionRule`).map((resource) => {
    const sourceClass = one(resource, 'foundationProjectionSourceClass', 'FOUNDATION_PROJECTION_RULE_CARDINALITY');
    const targetClass = one(resource, 'foundationProjectionTargetClass', 'FOUNDATION_PROJECTION_RULE_CARDINALITY');
    const identityMode = one(resource, 'foundationProjectionIdentityMode', 'FOUNDATION_PROJECTION_RULE_CARDINALITY');
    const structuralOnly = one(resource, 'foundationProjectionStructuralOnly', 'FOUNDATION_PROJECTION_RULE_CARDINALITY') === 'true';
    if (!identityModes.has(identityMode) || !structuralOnly || !permittedTargets.has(targetClass)
      || store.getQuads(iri(sourceClass), subclassPredicate, iri(`${O}Fixture`), null).length !== 1
      || store.getQuads(iri(targetClass), RDF_TYPE, iri(OWL_CLASS), null).length !== 1) {
      fail('FOUNDATION_PROJECTION_RULE_SCOPE_INVALID', `${resource} is not a structural fixture projection`);
    }
    const mappingResources = metaObjectValues(store, resource, 'foundationProjectionPredicateMapping');
    const mappings = mappingResources.map((mappingResource) => {
      const position = Number(one(mappingResource, 'foundationProjectionMappingPosition', 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE'));
      const sourcePredicate = one(mappingResource, 'foundationProjectionSourcePredicate', 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE');
      const targetPredicate = one(mappingResource, 'foundationProjectionTargetPredicate', 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE');
      const core = { position, sourcePredicate, targetPredicate };
      const declaredDigest = one(mappingResource, 'foundationProjectionMappingDigest', 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE');
      if (!Number.isSafeInteger(position) || position < 1 || !declaredProperty(sourcePredicate)
        || !declaredProperty(targetPredicate) || prohibitedTargetPredicates.has(targetPredicate)
        || store.getQuads(iri(sourcePredicate), domainPredicate, iri(sourceClass), null).length !== 1
        || store.getQuads(iri(targetPredicate), domainPredicate, iri(targetClass), null).length !== 1) {
        fail('FOUNDATION_PROJECTION_DOMAIN_RANGE_MISMATCH', `${mappingResource} is not an exact class-bound predicate mapping`);
      }
      if (declaredDigest !== fullDigest(core)) {
        fail('FOUNDATION_PROJECTION_DIGEST_MISMATCH', `${mappingResource} digest is stale`);
      }
      return { ...core, declaredDigest, resource: mappingResource };
    }).sort((left, right) => left.position - right.position);
    const sourceAliasMappingAllowed = identityMode.endsWith(':sourcealias')
      && sourceClass === `${O}FoundationPermissionAtomWitness`
      && targetClass === `${O}PermissionAtom`;
    if (mappings.some(({ position }, index) => position !== index + 1)
      || new Set(mappings.map(({ sourcePredicate }) => sourcePredicate)).size !== mappings.length
      || new Set(mappings.map(({ targetPredicate }) => targetPredicate)).size !== mappings.length
      || (identityMode.endsWith(':digestshadow') && mappings.length === 0)
      || (identityMode.endsWith(':sourcealias')
        && ((mappings.length !== 0 && !sourceAliasMappingAllowed)
          || (sourceAliasMappingAllowed && mappings.length === 0)))) {
      fail('FOUNDATION_PROJECTION_MAPPING_INCOMPLETE', `${resource} mappings are not a complete ordered set`);
    }
    const core = {
      identityMode,
      mappings: mappings.map(({ position, sourcePredicate, targetPredicate }) => ({
        position,
        sourcePredicate,
        targetPredicate,
      })),
      sourceClass,
      structuralOnly,
      targetClass,
    };
    const declaredDigest = one(resource, 'foundationProjectionRuleDigest', 'FOUNDATION_PROJECTION_RULE_CARDINALITY');
    if (declaredDigest !== fullDigest(core)) {
      fail('FOUNDATION_PROJECTION_DIGEST_MISMATCH', `${resource} digest is stale`);
    }
    return { ...core, declaredDigest, resource };
  }).sort((left, right) => compareCodeUnits(left.resource, right.resource));
  if (rules.length === 0 || new Set(rules.map(({ targetClass }) => targetClass)).size !== rules.length) {
    fail('FOUNDATION_PROJECTION_RULE_CARDINALITY', 'each structural target class requires one projection rule');
  }
  const specification = rules.map(({ declaredDigest, resource, ...rule }) => ({
    ...rule,
    ruleDigest: declaredDigest,
  }));
  return { digest: fullDigest(specification), records: rules, specification };
}

function buildFoundationStructuralProjection(metaModel, fixture) {
  const records = new Map(fixture.fixtureProjection.triples
    .map((record) => [canonicalJson(record), record]));
  const projectedBySource = new Map();
  const projectedRecords = [];
  for (const rule of metaModel.foundationProjectionRules.records) {
    const sources = uniqueSorted(fixture.store.getQuads(null, RDF_TYPE, iri(rule.sourceClass), null)
      .map(({ subject }) => subject.value));
    for (const source of sources) {
      const projected = rule.identityMode.endsWith(':sourcealias')
        ? source
        : `urn:usf:foundationprojection:${fullDigest({
          ruleDigest: rule.declaredDigest,
          source,
          targetClass: rule.targetClass,
        }).slice('sha256:'.length)}`;
      const typedRecord = [projected, RDF_TYPE.value, 'iri', rule.targetClass, null, null];
      records.set(canonicalJson(typedRecord), typedRecord);
      projectedRecords.push(typedRecord);
      if (!projectedBySource.has(source)) projectedBySource.set(source, []);
      projectedBySource.get(source).push(projected);
      for (const mapping of rule.mappings) {
        const values = fixture.store.getQuads(iri(source), iri(mapping.sourcePredicate), null, null);
        if (values.length === 0 || values.some(({ object }) => object.termType !== 'NamedNode')) {
          fail('FOUNDATION_PROJECTION_MAPPING_INCOMPLETE', `${source} lacks IRI values for ${mapping.sourcePredicate}`);
        }
        for (const { object } of values) {
          const record = [projected, mapping.targetPredicate, 'iri', object.value, null, null];
          records.set(canonicalJson(record), record);
          projectedRecords.push(record);
        }
      }
    }
  }
  for (const values of projectedBySource.values()) values.sort(compareCodeUnits);
  const triples = [...records.values()]
    .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  const projection = {
    gatewayOperationCapabilityBindings: fixture.fixtureProjection.gatewayOperationCapabilityBindings,
    operationClassBindings: fixture.fixtureProjection.operationClassBindings,
    projectedClassIris: uniqueSorted([
      ...fixture.fixtureProjection.projectedClassIris,
      ...metaModel.foundationProjectionRules.records.map(({ targetClass }) => targetClass),
    ]),
    projectedPredicateIris: uniqueSorted([
      ...fixture.fixtureProjection.projectedPredicateIris,
      ...metaModel.foundationProjectionRules.records.flatMap(({ mappings }) => mappings
        .map(({ targetPredicate }) => targetPredicate)),
    ]),
    triples,
  };
  const core = {
    foundationFixtureInputDigest: fixture.fixtureInputDigest,
    projectionRuleSetDigest: metaModel.foundationProjectionRules.digest,
    projectedRecordCount: new Set(projectedRecords.map(canonicalJson)).size,
    projection,
    recordKind: 'USF_FOUNDATION_STRUCTURAL_SELECTOR_PROJECTION',
    structuralOnly: true,
  };
  return {
    ...core,
    index: new AuthorityProjectionIndex(projection),
    projectedBySource,
    projectionDigest: fullDigest(core),
  };
}

function loadPublicationBudgetPolicy(store) {
  const universes = metaInstances(store, `${O}PermutationUniverse`);
  if (universes.length !== 1) fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'exactly one permutation universe is required');
  const universe = universes[0];
  if (oneMetaValue(store, universe, 'universeClosureRepresentation', 'PERMUTATION_PUBLICATION_BUDGET_INVALID')
    !== 'urn:usf:permutationclosurerepresentation:sparsesymbolic') {
    fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'universe does not use sparse symbolic closure');
  }
  const policyIri = oneMetaValue(store, universe, 'universePublicationBudget', 'PERMUTATION_PUBLICATION_BUDGET_INVALID');
  const integer = (predicate) => {
    const value = Number(oneMetaValue(store, policyIri, predicate, 'PERMUTATION_PUBLICATION_BUDGET_INVALID'));
    if (!Number.isSafeInteger(value) || value < 0) fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', `${predicate} is invalid`);
    return value;
  };
  const core = {
    encodingPolicy: {
      fixedManifestTripleUpperBound: integer('publicationFixedManifestStatementUpperBound'),
      operationalCellTripleUpperBound: integer('publicationOperationalCellStatementUpperBound'),
      regionTripleUpperBound: integer('publicationCoverageRegionStatementUpperBound'),
    },
    failClosed: oneMetaValue(store, policyIri, 'publicationBudgetFailClosed', 'PERMUTATION_PUBLICATION_BUDGET_INVALID') === 'true',
    hardStatementLimit: integer('publicationHardStatementLimit'),
    maximumProjectedStatementCount: integer('publicationMaximumProjectedStatementCount'),
    policyIri,
    provider: oneMetaValue(store, policyIri, 'publicationBudgetForProvider', 'PERMUTATION_PUBLICATION_BUDGET_INVALID'),
    reserveStatementCount: integer('publicationReservedStatementCount'),
  };
  const declaredDigest = oneMetaValue(store, policyIri, 'publicationBudgetDigest', 'PERMUTATION_PUBLICATION_BUDGET_INVALID');
  if (!core.failClosed || core.hardStatementLimit !== 1_000_000
    || core.maximumProjectedStatementCount !== core.hardStatementLimit - core.reserveStatementCount
    || declaredDigest !== fullDigest(core)) {
    fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'publication budget policy or digest is invalid');
  }
  return { ...core, digest: declaredDigest };
}

function repositoryAuthorityInstances(store, classIri) {
  return uniqueSorted(store.getQuads(null, RDF_TYPE, iri(classIri), null)
    .filter(({ graph }) => !META_MODEL_GRAPHS.has(graph.value)
      && graph.value !== 'urn:usf:graph:permutation-permission-atoms')
    .map(({ subject }) => subject.value));
}

function assertSourceAuthorityAgreement(store, authorityIndex, classIri, authorityValues) {
  const sourceValues = repositoryAuthorityInstances(store, classIri);
  if (sourceValues.length > 0 && canonicalJson(sourceValues) !== canonicalJson(authorityValues)) {
    fail('SOURCE_AUTHORITY_DISAGREEMENT', `${classIri} repository projection differs from live authority`, {
      authorityValues,
      sourceValues,
    });
  }
  if (!authorityIndex.projectedClassIris.has(classIri)) {
    fail('AUTHORITY_CLASS_NOT_PROJECTED', `${classIri} is absent from the bounded authority projection`);
  }
}

function contractForCapability(index, capabilityIri) {
  const contracts = index.values(capabilityIri, `${O}hasContract`);
  if (contracts.length !== 1) fail('CAPABILITY_CONTRACT_CARDINALITY', `${capabilityIri} must have one contract`, { contracts });
  return contracts[0];
}

function operationClosure(authorityInputs) {
  const projection = VERIFIED_FOUNDATION_FIXTURE_INPUTS.has(authorityInputs)
    ? authorityInputs.fixtureProjection
    : authorityInputs.authorityProjection;
  const bindings = projection.operationClassBindings ?? [];
  const operationClasses = uniqueSorted(bindings.map(([operationClass]) => operationClass));
  const operations = uniqueSorted(bindings.flatMap(([, operation]) => operation === null ? [] : [operation]));
  if (!operationClasses.includes(`${O}Operation`)) fail('OPERATION_CLASS_CLOSURE_INVALID', 'Operation root is absent');
  return { operationClasses, operations: new Set(operations) };
}

function operationsForCapability(authorityInputs, capabilityIri) {
  const { index } = authorityInputs;
  const contract = contractForCapability(index, capabilityIri);
  const interfaces = index.subjects(`${O}interfaceForContract`, contract);
  const interfaceOperations = uniqueSorted(interfaces.flatMap((surface) => index.values(surface, `${O}hasOperation`)));
  const gateways = uniqueSorted(index.gatewayOperationsByCapability.get(capabilityIri) ?? []);
  const selected = uniqueSorted([...interfaceOperations, ...gateways]);
  const closure = operationClosure(authorityInputs);
  for (const operation of selected) {
    if (!closure.operations.has(operation)) {
      fail('SELECTED_OPERATION_TYPE_INVALID', `${operation} is not typed through the Operation closure`);
    }
  }
  return selected;
}

function exactMetaValue(store, subject, predicate, code) {
  const found = metaObjectValues(store, subject, predicate);
  if (found.length !== 1) fail(code, `${subject} must have exactly one ${predicate}`, { found });
  return found[0];
}

function exactMetaIri(store, subject, predicate, code) {
  const found = metaIriValues(store, subject, predicate, code);
  if (found.length !== 1) fail(code, `${subject} must have exactly one IRI-valued ${predicate}`, { found });
  return found[0];
}

function declaredSemanticClass(store, classIri) {
  return classIri === OWL_CLASS || [OWL_CLASS, RDFS_CLASS].some((classKind) => (
    store.countQuads(iri(classIri), RDF_TYPE, iri(classKind), null) > 0
  ));
}

function declaredSemanticProperty(store, predicateIri) {
  return predicateIri === RDF_TYPE.value || [RDF_PROPERTY, ...OWL_PROPERTY_KINDS].some((propertyKind) => (
    store.countQuads(iri(predicateIri), RDF_TYPE, iri(propertyKind), null) > 0
  ));
}

function metaClassIsSubclassOrSame(store, candidateClassIri, expectedClassIri, visited = new Set()) {
  if (candidateClassIri === expectedClassIri) return true;
  if (visited.has(candidateClassIri)) return false;
  const nextVisited = new Set(visited).add(candidateClassIri);
  return store.getObjects(iri(candidateClassIri), iri(RDFS_SUBCLASS_OF), null)
    .filter(({ termType }) => termType === 'NamedNode')
    .some(({ value }) => metaClassIsSubclassOrSame(store, value, expectedClassIri, nextVisited));
}

function resourceIsTypeThroughMetaModel(index, store, resourceIri, expectedClassIri) {
  if (index.isType(resourceIri, expectedClassIri)) return true;
  return index.values(resourceIri, RDF_TYPE.value)
    .some((actualClassIri) => metaClassIsSubclassOrSame(store, actualClassIri, expectedClassIri));
}

function metaResourceIsTypeThroughMetaModel(store, resourceIri, expectedClassIri) {
  return store.getObjects(iri(resourceIri), RDF_TYPE, null)
    .filter(({ termType }) => termType === 'NamedNode')
    .some(({ value }) => metaClassIsSubclassOrSame(store, value, expectedClassIri));
}

function valueDerivationExpression(metaModel, expressionIri, cache = new Map(), visiting = new Set()) {
  const { store } = metaModel;
  if (cache.has(expressionIri)) return cache.get(expressionIri);
  if (visiting.has(expressionIri)) {
    fail('VALUE_DERIVATION_EXPRESSION_CYCLE', `${expressionIri} forms a value-derivation cycle`);
  }
  const operatorIri = exactMetaIri(store, expressionIri, 'valueDerivationOperator',
    'VALUE_DERIVATION_OPERATOR_TERM_INVALID');
  if (!Object.values(VALUE_DERIVATION_OPERATOR).includes(operatorIri)) {
    fail('VALUE_DERIVATION_OPERATOR_UNCONTROLLED', `${expressionIri} uses ${operatorIri}`);
  }
  const inputScopeIri = exactMetaIri(store, expressionIri, 'valueDerivationInputScope',
    'VALUE_DERIVATION_INPUT_SCOPE_TERM_INVALID');
  if (!Object.values(VALUE_DERIVATION_INPUT_SCOPE).includes(inputScopeIri)) {
    fail('VALUE_DERIVATION_INPUT_SCOPE_UNCONTROLLED', `${expressionIri} uses ${inputScopeIri}`);
  }
  const nextVisiting = new Set(visiting).add(expressionIri);
  const operands = metaIriValues(store, expressionIri, 'valueDerivationOperand',
    'VALUE_DERIVATION_OPERAND_TERM_INVALID').map((operandIri) => {
    const indexes = metaObjectValues(store, operandIri, 'valueDerivationOperandIndex');
    const expressions = metaIriValues(store, operandIri, 'valueDerivationOperandExpression',
      'VALUE_DERIVATION_OPERAND_EXPRESSION_TERM_INVALID');
    if (indexes.length !== 1 || expressions.length !== 1 || !Number.isInteger(Number(indexes[0]))
      || Number(indexes[0]) < 1) {
      fail('VALUE_DERIVATION_OPERAND_INVALID', `${operandIri} must name one positive index and expression`);
    }
    return {
      expression: valueDerivationExpression(metaModel, expressions[0], cache, nextVisiting),
      index: Number(indexes[0]),
      operandIri,
    };
  }).sort((left, right) => left.index - right.index);
  if (new Set(operands.map(({ index }) => index)).size !== operands.length
    || !operands.every(({ index }, offset) => index === offset + 1)) {
    fail('VALUE_DERIVATION_OPERAND_INDEX_INVALID', `${expressionIri} operands must be contiguous from one`);
  }
  const predicateIris = metaIriValues(store, expressionIri, 'valueDerivationPredicate',
    'VALUE_DERIVATION_PREDICATE_TERM_INVALID');
  const classIris = metaIriValues(store, expressionIri, 'valueDerivationClass',
    'VALUE_DERIVATION_CLASS_TERM_INVALID');
  const allowedValueIris = metaIriValues(store, expressionIri, 'valueDerivationAllowedValue',
    'VALUE_DERIVATION_ALLOWED_VALUE_TERM_INVALID');
  const pathSteps = metaIriValues(store, expressionIri, 'valueDerivationPathStep',
    'VALUE_DERIVATION_PATH_STEP_TERM_INVALID').map((stepIri) => {
    const indexes = metaObjectValues(store, stepIri, 'signalPathStepIndex');
    const predicates = metaIriValues(store, stepIri, 'signalPathStepPredicate',
      'VALUE_DERIVATION_PATH_PREDICATE_TERM_INVALID');
    const directions = metaIriValues(store, stepIri, 'signalPathStepDirection',
      'VALUE_DERIVATION_PATH_DIRECTION_TERM_INVALID');
    if (indexes.length !== 1 || predicates.length !== 1 || directions.length !== 1
      || !Number.isInteger(Number(indexes[0])) || Number(indexes[0]) < 1) {
      fail('VALUE_DERIVATION_PATH_STEP_INVALID', `${stepIri} has an invalid index, predicate or direction`);
    }
    if (!['urn:usf:permutationpathdirection:inbound', 'urn:usf:permutationpathdirection:outbound']
      .includes(directions[0])) {
      fail('VALUE_DERIVATION_PATH_DIRECTION_INVALID', `${stepIri} uses ${directions[0]}`);
    }
    return { directionIri: directions[0], index: Number(indexes[0]), predicateIri: predicates[0], stepIri };
  }).sort((left, right) => left.index - right.index);
  if (new Set(pathSteps.map(({ index }) => index)).size !== pathSteps.length
    || !pathSteps.every(({ index }, offset) => index === offset + 1)) {
    fail('VALUE_DERIVATION_PATH_STEP_INVALID', `${expressionIri} path indexes must be contiguous from one`);
  }
  const unary = new Set([
    VALUE_DERIVATION_OPERATOR.OUTBOUND, VALUE_DERIVATION_OPERATOR.INBOUND,
    VALUE_DERIVATION_OPERATOR.FILTER_TYPE_ANY, VALUE_DERIVATION_OPERATOR.FILTER_PATH_EXISTS,
    VALUE_DERIVATION_OPERATOR.FILTER_PATH_VALUE_IN,
  ]);
  const expectedOperands = [VALUE_DERIVATION_OPERATOR.SUBJECT, VALUE_DERIVATION_OPERATOR.CLASS_INSTANCES]
    .includes(operatorIri) ? [0, 0] : operatorIri === VALUE_DERIVATION_OPERATOR.UNION ? [2, Infinity]
      : unary.has(operatorIri) ? [1, 1] : [-1, -1];
  if (operands.length < expectedOperands[0] || operands.length > expectedOperands[1]) {
    fail('VALUE_DERIVATION_OPERATOR_ARITY_INVALID', `${expressionIri} has ${operands.length} operands`);
  }
  const predicateRequired = [VALUE_DERIVATION_OPERATOR.OUTBOUND, VALUE_DERIVATION_OPERATOR.INBOUND]
    .includes(operatorIri);
  if (predicateIris.length !== (predicateRequired ? 1 : 0)) {
    fail('VALUE_DERIVATION_PREDICATE_CARDINALITY', `${expressionIri} predicate cardinality is invalid`);
  }
  if (predicateIris.some((predicateIri) => !declaredSemanticProperty(store, predicateIri))
    || pathSteps.some(({ predicateIri }) => !declaredSemanticProperty(store, predicateIri))) {
    fail('VALUE_DERIVATION_PREDICATE_UNDECLARED', `${expressionIri} references an undeclared predicate`);
  }
  const classRequirement = operatorIri === VALUE_DERIVATION_OPERATOR.CLASS_INSTANCES ? [1, 1]
    : operatorIri === VALUE_DERIVATION_OPERATOR.FILTER_TYPE_ANY ? [1, Infinity] : [0, 0];
  if (classIris.length < classRequirement[0] || classIris.length > classRequirement[1]) {
    fail('VALUE_DERIVATION_CLASS_CARDINALITY', `${expressionIri} class cardinality is invalid`);
  }
  if (classIris.some((classIri) => !declaredSemanticClass(store, classIri))) {
    fail('VALUE_DERIVATION_CLASS_UNDECLARED', `${expressionIri} references an undeclared class`);
  }
  const classClosures = metaIriValues(store, expressionIri, 'valueDerivationClassClosure',
    'VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH').map((closureIri) => {
    const closure = metaModel.familyRegistry.classClosures.get(closureIri);
    if (!closure) fail('VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH', `${expressionIri} references ${closureIri}`);
    return closure;
  });
  const classBearing = [VALUE_DERIVATION_OPERATOR.CLASS_INSTANCES, VALUE_DERIVATION_OPERATOR.FILTER_TYPE_ANY]
    .includes(operatorIri);
  const closureRoots = uniqueSorted(classClosures.map(({ rootClassIri }) => rootClassIri));
  if ((classBearing && canonicalJson(closureRoots) !== canonicalJson(classIris))
    || (!classBearing && classClosures.length !== 0)) {
    fail('VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH', `${expressionIri} class closures differ from its operator classes`);
  }
  const filterPathRequired = [VALUE_DERIVATION_OPERATOR.FILTER_PATH_EXISTS,
    VALUE_DERIVATION_OPERATOR.FILTER_PATH_VALUE_IN].includes(operatorIri);
  if ((filterPathRequired && pathSteps.length === 0) || (!filterPathRequired && pathSteps.length !== 0)) {
    fail('VALUE_DERIVATION_FILTER_PATH_INVALID', `${expressionIri} filter path cardinality is invalid`);
  }
  const allowedRequired = operatorIri === VALUE_DERIVATION_OPERATOR.FILTER_PATH_VALUE_IN;
  if ((allowedRequired && allowedValueIris.length === 0) || (!allowedRequired && allowedValueIris.length !== 0)) {
    fail('VALUE_DERIVATION_ALLOWED_VALUE_INVALID', `${expressionIri} allowed-value cardinality is invalid`);
  }
  const record = {
    allowedValueIris,
    canonicalName: exactMetaValue(store, expressionIri, 'canonicalName', 'VALUE_DERIVATION_NAME_CARDINALITY'),
    classClosureDigests: classClosures.map(({ digest }) => digest),
    classIris,
    expressionIri,
    inputScopeIri,
    operands: operands.map(({ expression, index }) => ({ expression: expression.record, index })),
    operatorIri,
    pathSteps: pathSteps.map(({ directionIri, index, predicateIri }) => ({ directionIri, index, predicateIri })),
    predicateIri: predicateIris[0] ?? null,
    schemaVersion: 2,
  };
  const expression = Object.freeze({
    ...record,
    classClosures,
    digest: sha256(canonicalJson(record)),
    operands: operands.map(({ expression, index }) => ({ expression, index })),
    pathSteps,
    record,
    transitiveClassClosureDigests: uniqueSorted([
      ...classClosures.map(({ digest }) => digest),
      ...operands.flatMap(({ expression: operand }) => operand.transitiveClassClosureDigests),
    ]),
    transitivePredicateIris: uniqueSorted([
      ...predicateIris,
      ...pathSteps.map(({ predicateIri }) => predicateIri),
      ...operands.flatMap(({ expression: operand }) => operand.transitivePredicateIris),
      ...(operatorIri === VALUE_DERIVATION_OPERATOR.CLASS_INSTANCES ? [RDF_TYPE.value] : []),
    ]),
  });
  cache.set(expressionIri, expression);
  return expression;
}

function valueSourceDerivationRecord(metaModel, sourceIri) {
  const { store } = metaModel;
  const roots = metaIriValues(store, sourceIri, 'valueSourceDerivationRoot',
    'VALUE_SOURCE_DERIVATION_ROOT_TERM_INVALID');
  const subjectClasses = metaIriValues(store, sourceIri, 'valueSourceSubjectClass',
    'VALUE_SOURCE_SUBJECT_CLASS_TERM_INVALID');
  const terminalClasses = metaIriValues(store, sourceIri, 'valueSourceTerminalClass',
    'VALUE_SOURCE_TERMINAL_CLASS_TERM_INVALID');
  const terminalKinds = metaIriValues(store, sourceIri, 'valueSourceTerminalKind',
    'VALUE_SOURCE_TERMINAL_KIND_TERM_INVALID');
  if (roots.length !== 1) fail('VALUE_SOURCE_DERIVATION_ROOT_CARDINALITY', `${sourceIri} must name one root`);
  if (subjectClasses.length !== 1) fail('VALUE_SOURCE_SUBJECT_CLASS_CARDINALITY', `${sourceIri} must name one subject class`);
  if (terminalClasses.length === 0) fail('VALUE_SOURCE_TERMINAL_CLASS_ABSENT', `${sourceIri} has no terminal class`);
  if (canonicalJson(terminalKinds) !== canonicalJson([VALUE_TERMINAL_KIND.NAMED_NODE])) {
    fail('VALUE_SOURCE_TERMINAL_KIND_INVALID', `${sourceIri} must return named nodes`);
  }
  if (!declaredSemanticClass(store, subjectClasses[0])) {
    fail('VALUE_SOURCE_SUBJECT_CLASS_UNDECLARED', `${sourceIri} subject class is not declared`);
  }
  if (terminalClasses.some((classIri) => !declaredSemanticClass(store, classIri))) {
    fail('VALUE_SOURCE_TERMINAL_CLASS_UNDECLARED', `${sourceIri} references an undeclared terminal class`);
  }
  const root = valueDerivationExpression(metaModel, roots[0]);
  const declaredPredicates = metaObjectValues(store, sourceIri, 'valueSourceDerivationPredicate');
  if (canonicalJson(declaredPredicates) !== canonicalJson(root.transitivePredicateIris)) {
    fail('VALUE_SOURCE_DERIVATION_PREDICATE_MISMATCH', `${sourceIri} predicate summary differs from its expression`, {
      actual: declaredPredicates,
      expected: root.transitivePredicateIris,
    });
  }
  const sourceRecord = {
    derivationPredicateIris: declaredPredicates,
    rootDigest: root.digest,
    rootIri: roots[0],
    classClosureDigests: root.transitiveClassClosureDigests,
    schemaVersion: 2,
    sourceIri,
    subjectClassIri: subjectClasses[0],
    terminalClassIris: terminalClasses,
    terminalKindIris: terminalKinds,
  };
  const digest = sha256(canonicalJson(sourceRecord));
  const subjectClassClosure = metaModel.familyRegistry.classClosuresByRoot.get(subjectClasses[0]);
  const terminalClassClosures = terminalClasses.map((classIri) => metaModel.familyRegistry.classClosuresByRoot.get(classIri));
  if (!subjectClassClosure || terminalClassClosures.some((closure) => !closure)) {
    fail('VALUE_SOURCE_SUBJECT_CLASS_CLOSURE_MISMATCH', `${sourceIri} lacks explicit subject or terminal closures`);
  }
  return Object.freeze({
    digest,
    root,
    rootIri: roots[0],
    sourceRecord,
    subjectClassClosure,
    subjectClassIri: subjectClasses[0],
    terminalClassClosures,
    terminalClasses,
  });
}

function loadValueSourceDerivation(metaModel, sourceIri) {
  const { store } = metaModel;
  const definition = valueSourceDerivationRecord(metaModel, sourceIri);
  const storedRootDigests = metaObjectValues(store, definition.rootIri, 'valueDerivationDigest');
  if (canonicalJson(storedRootDigests) !== canonicalJson([definition.root.digest])) {
    fail('VALUE_DERIVATION_DIGEST_MISMATCH', `${definition.rootIri} digest does not bind its recursive expression`, {
      actual: storedRootDigests,
      expected: definition.root.digest,
    });
  }
  const storedSourceDigests = metaObjectValues(store, sourceIri, 'valueSourceDigest');
  if (canonicalJson(storedSourceDigests) !== canonicalJson([definition.digest])) {
    fail('VALUE_SOURCE_DIGEST_MISMATCH', `${sourceIri} digest does not bind its derivation`, {
      actual: storedSourceDigests,
      expected: definition.digest,
    });
  }
  return definition;
}

function derivationScopeActive(inputScopeIri, authorityInputs) {
  if (inputScopeIri === VALUE_DERIVATION_INPUT_SCOPE.ALL) return true;
  const foundation = VERIFIED_FOUNDATION_FIXTURE_INPUTS.has(authorityInputs);
  return foundation ? inputScopeIri === VALUE_DERIVATION_INPUT_SCOPE.FOUNDATION_FIXTURE
    : inputScopeIri === VALUE_DERIVATION_INPUT_SCOPE.LIVE_AUTHORITY;
}

function traverseDerivationPath(index, initial, pathSteps) {
  let frontier = uniqueSorted(initial);
  for (const { directionIri, predicateIri } of pathSteps) {
    frontier = directionIri === 'urn:usf:permutationpathdirection:outbound'
      ? uniqueSorted(frontier.flatMap((value) => index.objects(value, predicateIri).map((object) => {
        if (object.type !== 'iri') fail('VALUE_DERIVATION_LITERAL_RESULT_PROHIBITED', `${predicateIri} returned a literal`);
        return object.value;
      })))
      : uniqueSorted(frontier.flatMap((value) => index.subjects(predicateIri, value)));
  }
  return frontier;
}

function evaluateValueDerivation(expression, authorityInputs, subjectIri) {
  if (!derivationScopeActive(expression.inputScopeIri, authorityInputs)) return [];
  const { index } = authorityInputs;
  const operandValues = expression.operands.map(({ expression: operand }) =>
    evaluateValueDerivation(operand, authorityInputs, subjectIri));
  switch (expression.operatorIri) {
    case VALUE_DERIVATION_OPERATOR.SUBJECT:
      return [subjectIri];
    case VALUE_DERIVATION_OPERATOR.CLASS_INSTANCES:
      return closureInstances(authorityInputs, expression.classClosures);
    case VALUE_DERIVATION_OPERATOR.OUTBOUND:
      return traverseDerivationPath(index, operandValues[0], [{
        directionIri: 'urn:usf:permutationpathdirection:outbound', predicateIri: expression.predicateIri,
      }]);
    case VALUE_DERIVATION_OPERATOR.INBOUND:
      return traverseDerivationPath(index, operandValues[0], [{
        directionIri: 'urn:usf:permutationpathdirection:inbound', predicateIri: expression.predicateIri,
      }]);
    case VALUE_DERIVATION_OPERATOR.UNION:
      return uniqueSorted(operandValues.flat());
    case VALUE_DERIVATION_OPERATOR.FILTER_TYPE_ANY:
      return operandValues[0].filter((value) => resourceHasClosureType(index, value, expression.classClosures));
    case VALUE_DERIVATION_OPERATOR.FILTER_PATH_EXISTS:
      return operandValues[0].filter((value) => traverseDerivationPath(index, [value], expression.pathSteps).length > 0);
    case VALUE_DERIVATION_OPERATOR.FILTER_PATH_VALUE_IN: {
      const allowed = new Set(expression.allowedValueIris);
      return operandValues[0].filter((value) => traverseDerivationPath(index, [value], expression.pathSteps)
        .some((candidate) => allowed.has(candidate)));
    }
    default:
      fail('VALUE_DERIVATION_OPERATOR_UNCONTROLLED', `unsupported operator ${expression.operatorIri}`);
  }
}

function semanticValueSource(metaModel, authorityInputs, subjectIri, sourceIri) {
  const definition = loadValueSourceDerivation(metaModel, sourceIri);
  if (!resourceHasClosureType(authorityInputs.index, subjectIri, [definition.subjectClassClosure])) {
    fail('VALUE_SOURCE_SUBJECT_CLASS_MISMATCH', `${subjectIri} is not a ${definition.subjectClassIri}`);
  }
  const values = uniqueSorted(evaluateValueDerivation(definition.root, authorityInputs, subjectIri));
  const invalid = values.filter((value) => !definition.terminalClassClosures.some((closure) => (
    closure.rootClassIri === OWL_CLASS ? authorityInputs.index.projectedClassIris.has(value)
      : resourceHasClosureType(authorityInputs.index, value, [closure])
        || (VERIFIED_FOUNDATION_FIXTURE_INPUTS.has(authorityInputs)
          && metaResourceHasClosureType(metaModel.store, value, [closure]))
  )));
  if (invalid.length > 0) {
    fail('VALUE_SOURCE_TERMINAL_TYPE_MISMATCH', `${sourceIri} returned values outside its terminal classes`, {
      invalid,
      terminalClasses: definition.terminalClasses,
    });
  }
  return values;
}

function registeredSubjectSelector(metaModel, authorityInputs, subjectIri, sourceIri) {
  const selectorIris = metaObjectValues(metaModel.store, sourceIri, 'valueSourceSelector');
  if (selectorIris.length !== 1) {
    fail('VALUE_SOURCE_SELECTOR_CARDINALITY_INVALID', `${sourceIri} must name one ordered selector`);
  }
  const selectorIri = selectorIris[0];
  const selectorDefinition = metaModel.familyRegistry.selectors.get(selectorIri);
  if (!selectorDefinition) fail('VALUE_SOURCE_SELECTOR_UNKNOWN', `${sourceIri} references ${selectorIri}`);
  const subjectClasses = metaObjectValues(metaModel.store, selectorIri, 'selectorSubjectClass');
  const foundationInputs = VERIFIED_FOUNDATION_FIXTURE_INPUTS.has(authorityInputs);
  const classAvailable = (classIri) => authorityInputs.index.projectedClassIris.has(classIri)
    || (foundationInputs && declaredSemanticClass(metaModel.store, classIri));
  const predicateAvailable = (predicateIri) => authorityInputs.index.projectedPredicateIris.has(predicateIri)
    || (foundationInputs && declaredSemanticProperty(metaModel.store, predicateIri));
  if (subjectClasses.length !== 1 || !classAvailable(subjectClasses[0])) {
    fail('AUTHORITY_SELECTOR_SUBJECT_CLASS_NOT_PROJECTED', `${selectorIri} subject class is absent from the projection`);
  }
  if (!resourceHasClosureType(authorityInputs.index, subjectIri, [selectorDefinition.subjectClassClosure])) {
    fail('VALUE_SOURCE_SELECTOR_SUBJECT_CLASS_MISMATCH', `${subjectIri} is not a ${subjectClasses[0]}`);
  }
  const stepIris = metaObjectValues(metaModel.store, selectorIri, 'selectorPathStep');
  const steps = stepIris.map((stepIri) => {
    const indexes = metaObjectValues(metaModel.store, stepIri, 'signalPathStepIndex');
    const predicates = metaObjectValues(metaModel.store, stepIri, 'signalPathStepPredicate');
    const directions = metaObjectValues(metaModel.store, stepIri, 'signalPathStepDirection');
    if (indexes.length !== 1 || predicates.length !== 1 || directions.length !== 1) {
      fail('VALUE_SOURCE_SELECTOR_PATH_INVALID', `${stepIri} must have one index, predicate and direction`);
    }
    return { direction: directions[0], index: Number(indexes[0]), predicate: predicates[0], stepIri };
  }).sort((left, right) => left.index - right.index);
  if (steps.length === 0 || !steps.every(({ index }, offset) => index === offset + 1)) {
    fail('VALUE_SOURCE_SELECTOR_PATH_INVALID', `${selectorIri} path must be contiguous from one`);
  }
  const declaredPredicates = metaObjectValues(metaModel.store, sourceIri, 'valueSourceDerivationPredicate');
  const pathPredicates = uniqueSorted(steps.map(({ predicate }) => predicate));
  if (canonicalJson(declaredPredicates) !== canonicalJson(pathPredicates)) {
    fail('VALUE_SOURCE_SELECTOR_PREDICATE_MISMATCH', `${sourceIri} predicate summary differs from its ordered path`, {
      declaredPredicates,
      pathPredicates,
    });
  }
  let selected = [subjectIri];
  for (const { direction, predicate, stepIri } of steps) {
    if (!predicateAvailable(predicate)) {
      fail('AUTHORITY_SELECTOR_PATH_PREDICATE_NOT_PROJECTED', `${predicate} is absent from the authority projection`);
    }
    if (direction === 'urn:usf:permutationpathdirection:outbound') {
      selected = uniqueSorted(selected.flatMap((value) => authorityInputs.index.values(value, predicate)));
    } else if (direction === 'urn:usf:permutationpathdirection:inbound') {
      selected = uniqueSorted(selected.flatMap((value) => authorityInputs.index.subjects(predicate, value)));
    } else {
      fail('VALUE_SOURCE_SELECTOR_DIRECTION_INVALID', `${stepIri} uses ${direction}`);
    }
  }
  const terminalClasses = metaObjectValues(metaModel.store, selectorIri, 'selectorTerminalClass');
  if (terminalClasses.length !== 1) {
    fail('VALUE_SOURCE_SELECTOR_TERMINAL_CLASS_INVALID', `${selectorIri} must name one terminal class`);
  }
  if (!classAvailable(terminalClasses[0])) {
    fail('AUTHORITY_SELECTOR_TERMINAL_CLASS_NOT_PROJECTED', `${terminalClasses[0]} is absent from the authority projection`);
  }
  const invalid = selected.filter((value) => (
    !resourceHasClosureType(authorityInputs.index, value, [selectorDefinition.terminalClassClosure])
      && !(foundationInputs && metaResourceHasClosureType(
        metaModel.store, value, [selectorDefinition.terminalClassClosure],
      ))
  ));
  if (invalid.length > 0) {
    fail('VALUE_SOURCE_SELECTOR_TERMINAL_TYPE_MISMATCH', `${selectorIri} selected values outside its terminal class`, {
      invalid,
      terminalClassIri: terminalClasses[0],
    });
  }
  return selected;
}

function familyDimensions(metaModel, familyIri) {
  const { store } = metaModel;
  const bindings = metaObjects(store, familyIri, 'hasFamilyDimensionBinding').map(({ value }) => value);
  if (bindings.length === 0) fail('FAMILY_DIMENSION_BINDING_ABSENT', `${familyIri} has no dimension bindings`);
  const resolved = bindings.map((binding) => {
    const positionValues = metaObjectValues(store, binding, 'dimensionPosition');
    const dimensions = metaObjectValues(store, binding, 'bindsDimension');
    if (positionValues.length !== 1 || dimensions.length !== 1) {
      fail('FAMILY_DIMENSION_BINDING_CARDINALITY', `${binding} must have one position and one dimension`);
    }
    const position = Number(positionValues[0]);
    if (!Number.isInteger(position) || position < 1) fail('DIMENSION_POSITION_INVALID', `${binding} position is invalid`);
    const dimension = dimensions[0];
    const keys = metaObjectValues(store, dimension, 'permutationDimensionKey');
    if (keys.length !== 1 || keys[0].length === 0) fail('DIMENSION_KEY_CARDINALITY', `${dimension} must have one key`);
    const axisClassClosures = ownerClassClosures(metaModel, binding, 'dimensionAxisClassClosure',
      'DIMENSION_AXIS_CLASS_CLOSURE_MISMATCH');
    return {
      axisClassClosureDigests: axisClassClosures.map(({ digest }) => digest),
      axisClassClosures,
      binding,
      dimension,
      key: keys[0],
      position,
    };
  }).sort((left, right) => left.position - right.position);
  const positions = resolved.map(({ position }) => position);
  if (new Set(positions).size !== positions.length) fail('DIMENSION_POSITION_DUPLICATE', `${familyIri} repeats a position`);
  if (!positions.every((position, index) => position === index + 1)) fail('DIMENSION_POSITION_NONCONTIGUOUS', `${familyIri} positions are not 1..N`);
  const dimensionIris = resolved.map(({ dimension }) => dimension);
  const keys = resolved.map(({ key }) => key);
  if (new Set(dimensionIris).size !== dimensionIris.length || new Set(keys).size !== keys.length) {
    fail('FAMILY_DIMENSION_DUPLICATE', `${familyIri} repeats a dimension or dimension key`);
  }
  return resolved;
}

function resolveDomain(metaModel, authorityInputs, subjectIri, descriptor) {
  const { store } = metaModel;
  const sources = metaObjectValues(store, descriptor.dimension, 'dimensionValueSource');
  if (sources.length !== 1) fail('DIMENSION_VALUE_SOURCE_CARDINALITY', `${descriptor.dimension} must have one source`);
  const source = sources[0];
  const kinds = metaObjectValues(store, source, 'valueSourceKind');
  if (kinds.length !== 1 || !Object.values(SOURCE_KIND).includes(kinds[0])) {
    fail('DIMENSION_SOURCE_KIND_INVALID', `${source} has an unsupported source kind`, { kinds });
  }
  const scopes = metaObjectValues(store, source, 'valueSourceScope');
  if (scopes.length !== 1 || !Object.values(SOURCE_SCOPE).includes(scopes[0])) {
    fail('DIMENSION_SOURCE_SCOPE_INVALID', `${source} must declare one controlled source scope`, { scopes });
  }
  const sourceScope = scopes[0];
  const allowedScopes = {
    [SOURCE_KIND.CLASS_INSTANCES]: [SOURCE_SCOPE.AUTHORITY_INSTANCE_SET, SOURCE_SCOPE.FOUNDATION_CATALOGUE],
    [SOURCE_KIND.CONTROLLED_LIST]: [SOURCE_SCOPE.FOUNDATION_CATALOGUE],
    [SOURCE_KIND.DERIVED_SELECTOR]: [SOURCE_SCOPE.CAPABILITY_RELATIONSHIP, SOURCE_SCOPE.DOWNSTREAM_CLOSURE,
      SOURCE_SCOPE.REGISTERED_SUBJECT_RELATIONSHIP],
  };
  if (!allowedScopes[kinds[0]].includes(sourceScope)) {
    fail('DIMENSION_SOURCE_SCOPE_KIND_MISMATCH', `${source} scope is incompatible with ${kinds[0]}`);
  }

  let values = [];
  let sourcePlane;
  if (kinds[0] === SOURCE_KIND.CONTROLLED_LIST) {
    const members = metaObjectValues(store, descriptor.dimension, 'hasDimensionValue');
    const keyed = members.map((valueIri) => {
      if (!has(store, iri(valueIri), RDF_TYPE, term('PermutationDimensionValue'))) {
        fail('DIMENSION_VALUE_TYPE_INVALID', `${valueIri} is not a PermutationDimensionValue`);
      }
      const keys = metaObjectValues(store, valueIri, 'dimensionValueKey');
      if (keys.length !== 1 || keys[0].length === 0) fail('DIMENSION_VALUE_KEY_CARDINALITY', `${valueIri} must have one key`);
      return { iri: valueIri, key: keys[0] };
    }).sort((left, right) => compareCodeUnits(left.key, right.key) || compareCodeUnits(left.iri, right.iri));
    if (new Set(keyed.map(({ key }) => key)).size !== keyed.length) {
      fail('DIMENSION_VALUE_KEY_DUPLICATE', `${descriptor.dimension} repeats a controlled key`);
    }
    values = keyed.map(({ iri: valueIri }) => valueIri);
    sourcePlane = 'CANDIDATE_META_MODEL';
  } else if (kinds[0] === SOURCE_KIND.CLASS_INSTANCES) {
    const classIris = metaObjectValues(store, source, 'valueSourceClassIri');
    if (classIris.length !== 1) fail('CLASS_SOURCE_IRI_CARDINALITY', `${source} must name one class`);
    const classIri = classIris[0];
    const closureRoots = uniqueSorted(descriptor.axisClassClosures.map(({ rootClassIri }) => rootClassIri));
    if (canonicalJson(closureRoots) !== canonicalJson([classIri])) {
      fail('DIMENSION_AXIS_CLASS_CLOSURE_MISMATCH', `${descriptor.binding} closure root differs from ${classIri}`);
    }
    const candidates = uniqueSorted(descriptor.axisClassClosures
      .flatMap(({ memberClassIris }) => memberClassIris.flatMap((member) => metaInstances(store, member))));
    if (sourceScope === SOURCE_SCOPE.FOUNDATION_CATALOGUE) {
      values = candidates;
      sourcePlane = candidates.length > 0 ? 'CANDIDATE_FOUNDATION_CATALOGUE' : 'FOUNDATION_CATALOGUE_EMPTY';
    } else if (VERIFIED_FOUNDATION_FIXTURE_INPUTS.has(authorityInputs)) {
      values = closureInstances(authorityInputs, descriptor.axisClassClosures);
      sourcePlane = values.length > 0 ? FOUNDATION_FIXTURE_SCOPE : 'FOUNDATION_CONFORMANCE_FIXTURE_EMPTY';
    } else {
      const authorityValues = closureInstances(authorityInputs, descriptor.axisClassClosures);
      for (const closure of descriptor.axisClassClosures) {
        for (const member of closure.memberClassIris) {
          if (authorityInputs.index.projectedClassIris.has(member)
            || authorityInputs.index.operationClasses.has(member)) {
            assertSourceAuthorityAgreement(store, authorityInputs.index, member,
              authorityInputs.index.instances(member));
          }
        }
      }
      values = authorityValues;
      sourcePlane = authorityValues.length > 0 ? 'LIVE_AUTHORITY' : 'LIVE_AUTHORITY_EMPTY';
    }
  } else {
    const valueSourceSelectors = metaObjectValues(store, source, 'valueSourceSelector');
    const valueSourceRoots = metaObjectValues(store, source, 'valueSourceDerivationRoot');
    const derivationPredicates = metaObjectValues(store, source, 'valueSourceDerivationPredicate');
    if (derivationPredicates.length === 0 && valueSourceRoots.length === 0) {
      fail('DERIVED_SELECTOR_PREDICATE_ABSENT', `${source} has no declared semantic derivation predicate`);
    }
    if (sourceScope === SOURCE_SCOPE.REGISTERED_SUBJECT_RELATIONSHIP) {
      if (valueSourceRoots.length !== 0) {
        fail('VALUE_SOURCE_DERIVATION_MODE_CONFLICT', `${source} carries both path and expression bindings`);
      }
      values = registeredSubjectSelector(metaModel, authorityInputs, subjectIri, source);
    } else {
      if (valueSourceSelectors.length !== 0) {
        fail('VALUE_SOURCE_SELECTOR_SCOPE_INVALID', `${source} uses an ordered selector outside registered-subject scope`);
      }
      if (valueSourceRoots.length !== 1) {
        fail('VALUE_SOURCE_DERIVATION_ROOT_CARDINALITY', `${source} must name one semantic derivation root`);
      }
      values = semanticValueSource(metaModel, authorityInputs, subjectIri, source);
    }
    sourcePlane = VERIFIED_FOUNDATION_FIXTURE_INPUTS.has(authorityInputs)
      ? FOUNDATION_FIXTURE_SCOPE
      : sourceScope === SOURCE_SCOPE.DOWNSTREAM_CLOSURE
        ? 'DOWNSTREAM_CLOSURE_DERIVATION'
        : 'LIVE_AUTHORITY_DERIVATION';
  }

  values = uniqueSorted(values);
  return {
    ...descriptor,
    source,
    sourceKind: kinds[0],
    classClosureDigests: descriptor.axisClassClosureDigests,
    sourcePlane,
    sourceScope,
    valueCount: values.length,
    values,
    valueSetDigest: fullDigest({
      dimension: descriptor.dimension,
      classClosureDigests: descriptor.axisClassClosureDigests,
      source,
      sourceKind: kinds[0],
      sourcePlane,
      sourceScope,
      values,
    }),
  };
}

export function canonicalCellIdentity(familyIri, subjectIri, dimensionBindings) {
  const ordered = [...dimensionBindings].sort((left, right) => left.position - right.position);
  const positions = ordered.map(({ position }) => position);
  const dimensions = ordered.map(({ dimension }) => dimension);
  const keys = ordered.map(({ key }) => key);
  if (!positions.every((position, index) => Number.isInteger(position) && position === index + 1)) {
    fail('CELL_DIMENSION_POSITION_INVALID', 'cell identity requires contiguous positions 1..N');
  }
  if (new Set(dimensions).size !== dimensions.length || new Set(keys).size !== keys.length) {
    fail('DUPLICATE_DIMENSION_BINDING', 'cell identity repeats a dimension or dimension key');
  }
  const parts = [
    `family=${encodeURIComponent(familyIri)}`,
    `subject=${encodeURIComponent(subjectIri)}`,
    ...ordered.map(({ key, value }) => `${key}=${encodeURIComponent(value)}`),
  ];
  const stableKey = parts.join('|');
  const digest = sha256(stableKey);
  return {
    cellDigest: digest,
    cellIri: `${PERMUTATION_CELL_PREFIX}${digest.slice('sha256:'.length)}`,
    identityAlgorithm: 'family-subject-ordered-dimension-identity-v1',
    stableKey,
  };
}

const exactFamily = Object.freeze({
  operationPermission: `${PERMUTATION_FAMILY_PREFIX}operationpermissionatom`,
  operationRole: `${PERMUTATION_FAMILY_PREFIX}operationroleconditionprofile`,
  permissionRoleTenant: `${PERMUTATION_FAMILY_PREFIX}permissionatomroletenantboundary`,
});
const PERMISSION_ATOM_MISSING_PROPERTIES = Object.freeze([
  'action',
  'auditCategory',
  'resourceClass',
  'selectorKind',
  'tenantBoundary',
]);

function collectPermissionAtomCandidate(candidateMap, cell) {
  if (cell.family !== exactFamily.operationPermission
    || ![DISPOSITIONS.required, DISPOSITIONS.allowed].includes(cell.disposition)) return;
  const sourcePermission = cell.dimensionBindings.find(({ key }) => key === 'permissionatom')?.value;
  const operation = cell.dimensionBindings.find(({ key }) => key === 'operation')?.value;
  if (!sourcePermission || !operation) {
    fail('PERMISSION_ATOM_SOURCE_CELL_INVALID', `${cell.cellIri} lacks operation or source permission`);
  }
  const candidateKey = canonicalJson({ capability: cell.capability, sourcePermission });
  if (!candidateMap.has(candidateKey)) {
    candidateMap.set(candidateKey, {
      authorityDigest: cell.authorityDigest,
      capability: cell.capability,
      operations: new Set(),
      sourceCells: new Set(),
      sourcePermission,
    });
  }
  const candidate = candidateMap.get(candidateKey);
  candidate.operations.add(operation);
  candidate.sourceCells.add(cell.cellIri);
}

function finalisePermissionAtomCandidates(candidateMap, sourceCellCount) {
  const candidates = [...candidateMap.values()].map((candidate) => {
    const candidateCore = {
      capability: candidate.capability,
      sourcePermission: candidate.sourcePermission,
    };
    return {
      authorising: false,
      authorityDigest: candidate.authorityDigest,
      candidateDigest: fullDigest(candidateCore),
      candidateKey: canonicalJson(candidateCore),
      capability: candidate.capability,
      derivationState: 'INCOMPLETE_REQUIRED_PROPERTIES',
      missingProperties: [...PERMISSION_ATOM_MISSING_PROPERTIES],
      operations: [...candidate.operations].sort(),
      sourceCells: [...candidate.sourceCells].sort(),
      sourcePermission: candidate.sourcePermission,
    };
  }).sort((left, right) => compareCodeUnits(left.candidateKey, right.candidateKey));
  const gaps = candidates.map((candidate) => ({
    candidateDigest: candidate.candidateDigest,
    code: 'PERMISSION_ATOM_REQUIRED_PROPERTIES_UNDERIVED',
    missingProperties: [...candidate.missingProperties],
  }));
  return {
    candidateCount: candidates.length,
    candidates,
    candidateSetDigest: fullDigest(candidates),
    gaps,
    recordKind: 'USF_PERMISSION_ATOM_CANDIDATE_SET',
    schemaVersion: 1,
    sourceCellCount,
  };
}

function dispositionForCell(familyIri, dimensions, authorityInputs) {
  const value = (key) => dimensions.find((dimension) => dimension.key === key)?.value;
  const provenance = {
    authorityDigest: authorityInputs.authorityDigest,
    authorityPacketDigest: authorityInputs.authorityPacketDigest,
    authorityProjectionDigest: authorityInputs.authorityProjectionDigest,
  };
  if (familyIri === exactFamily.operationPermission) {
    const operation = value('operation');
    const permission = value('permissionatom');
    const requiredPermissions = authorityInputs.index.values(operation, `${O}requiresPermission`);
    if (requiredPermissions.includes(permission)) {
      return { iri: DISPOSITIONS.required, provenance, reasonCode: 'EXACT_REQUIRES_PERMISSION_BINDING' };
    }
    return {
      applicabilityProof: fullDigest({ operation, requiredPermissions }),
      iri: DISPOSITIONS.notApplicable,
      provenance,
      rationale: 'The exact authority requiresPermission set does not contain this permission.',
      reasonCode: 'OPERATION_DOES_NOT_REQUIRE_PERMISSION',
    };
  }
  if (familyIri === exactFamily.operationRole || familyIri === exactFamily.permissionRoleTenant) {
    const operation = value('operation');
    const explicitPermission = value('permissionatom');
    const requiredPermissions = explicitPermission
      ? [explicitPermission]
      : operation ? authorityInputs.index.values(operation, `${O}requiresPermission`) : [];
    const role = value('role');
    const grants = role ? authorityInputs.index.values(role, `${O}grantsPermission`) : [];
    if (operation && authorityInputs.index.values(operation, `${O}coordinatorOnly`).includes('true')) {
      return { iri: DISPOSITIONS.forbidden, provenance, reasonCode: 'FORBIDDEN_BY_COORDINATOR_ONLY' };
    }
    if (requiredPermissions.length > 0 && requiredPermissions.every((permission) => grants.includes(permission))) {
      return { iri: DISPOSITIONS.required, provenance, reasonCode: 'EXACT_ROLE_GRANT_BINDING' };
    }
    return { iri: DISPOSITIONS.unresolved, provenance, reasonCode: 'ROLE_GRANT_ABSENCE_IS_NOT_NON_APPLICABILITY' };
  }
  return { iri: DISPOSITIONS.unresolved, provenance, reasonCode: 'FAMILY_DISPOSITION_RULE_PENDING' };
}

function cartesianProduct(domains, callback) {
  if (domains.length === 0) return callback([]);
  if (domains.some(({ values }) => values.length === 0)) return;
  const indexes = new Array(domains.length).fill(0);
  while (true) {
    callback(indexes.map((index, position) => domains[position].values[index]));
    let position = indexes.length - 1;
    while (position >= 0) {
      indexes[position] += 1;
      if (indexes[position] < domains[position].values.length) break;
      indexes[position] = 0;
      position -= 1;
    }
    if (position < 0) break;
  }
}

function resolveFamilyPlan(metaModel, authorityInputs, record) {
  const { store } = metaModel;
  const familyNames = metaObjectValues(store, record.family, 'canonicalName');
  if (familyNames.length !== 1 || familyNames[0] !== record.canonicalName) {
    fail('CENSUS_FAMILY_IDENTITY_MISMATCH', `${record.family} does not match census canonical identity`);
  }
  const subject = record.subject;
  const descriptors = familyDimensions(metaModel, record.family);
  const domains = descriptors.map((descriptor) => resolveDomain(metaModel, authorityInputs, subject, descriptor));
  const emptyDomains = domains.filter(({ values }) => values.length === 0);
  const expectedCellCount = domains.reduce((product, domain) => product * domain.values.length, 1);
  if (emptyDomains.length > 0) {
    return {
      domains,
      expectedCellCount: 0,
      gaps: emptyDomains.map((domain) => ({
        capability: record.capability ?? null,
        code: 'REQUIRED_FINITE_DOMAIN_EMPTY',
        dimension: domain.dimension,
        dimensionKey: domain.key,
        family: record.family,
        source: domain.source,
        sourceKind: domain.sourceKind,
        sourcePlane: domain.sourcePlane,
        subject,
        subjectClass: record.subjectClass,
      })),
    };
  }
  return { domains, expectedCellCount, gaps: [] };
}

function visitFamilyCells(metaModel, authorityInputs, record, visitor) {
  const plan = resolveFamilyPlan(metaModel, authorityInputs, record);
  const { domains, expectedCellCount, gaps } = plan;
  if (gaps.length > 0) return { generatedCellCount: 0, ...plan };
  let generatedCellCount = 0;
  cartesianProduct(domains, (combination) => {
    const dimensionBindings = domains.map((domain, index) => ({
      dimension: domain.dimension,
      key: domain.key,
      position: domain.position,
      value: combination[index],
      valueSetDigest: domain.valueSetDigest,
    }));
    const subject = record.subject;
    const identity = canonicalCellIdentity(record.family, subject, dimensionBindings);
    const disposition = dispositionForCell(record.family, dimensionBindings, authorityInputs);
    visitor({
      ...identity,
      authorityDigest: authorityInputs.authorityDigest,
      capability: record.capability ?? null,
      dimensionBindings,
      dimensionKeys: dimensionBindings.map(({ key }) => key),
      dimensionValues: dimensionBindings.map(({ value }) => value),
      disposition: disposition.iri,
      dispositions: [disposition],
      family: record.family,
      subject,
      familyCanonicalName: record.canonicalName,
    });
    generatedCellCount += 1;
  });
  return { domains, expectedCellCount, gaps, generatedCellCount };
}

function generateFamilyCells(metaModel, authorityInputs, record) {
  const cells = [];
  const generated = visitFamilyCells(metaModel, authorityInputs, record, (cell) => cells.push(cell));
  return { cells, ...generated };
}

function validateCensus(census, authorityInputs, metaModel) {
  if (census?.recordKind !== 'USF_PERMUTATION_FAMILY_CENSUS' || census.schemaVersion !== 4) {
    fail('CENSUS_SCHEMA_INVALID', 'census must use the authority-bound v4 explicit-class-closure schema');
  }
  if (census.authorityDigest !== authorityInputs.authorityDigest
    || census.authorityPacketDigest !== authorityInputs.authorityPacketDigest
    || census.authorityProjectionDigest !== authorityInputs.authorityProjectionDigest) {
    fail('CENSUS_INPUT_BINDING_MISMATCH', 'census input bindings do not match verified authority inputs');
  }
  if (fullDigest(census.records) !== census.recordsDigest) fail('CENSUS_DIGEST_MISMATCH', 'census records digest is stale');
  const expectedCensusDigest = fullDigest({
    authorityDigest: census.authorityDigest,
    authorityPacketDigest: census.authorityPacketDigest,
    authorityProjectionDigest: census.authorityProjectionDigest,
    dispositionCounts: census.dispositionCounts,
    expectedPairCount: census.expectedPairCount,
    familyCount: census.familyCount,
    familyRegistryDigest: census.familyRegistryDigest,
    pairSetDigest: census.pairSetDigest,
    recordsDigest: census.recordsDigest,
    subjectCount: census.subjectCount,
    subjectCountsByRegistration: census.subjectCountsByRegistration,
    subjectSetDigestsByRegistration: census.subjectSetDigestsByRegistration,
    subjectClassClosureDigestsByRegistration: census.subjectClassClosureDigestsByRegistration,
  });
  if (expectedCensusDigest !== census.censusDigest) fail('CENSUS_DIGEST_MISMATCH', 'census descriptor digest is stale');
  const families = metaModel.familyRegistry.families;
  if (census.familyCount !== families.length) {
    fail('CENSUS_FAMILY_COUNT_MISMATCH', 'census family count differs from the current semantic registry');
  }
  const expectedSubjectCountsByRegistration = {};
  const expectedSubjectSetDigestsByRegistration = {};
  const expectedSubjectClassClosureDigestsByRegistration = {};
  const expectedPairs = [];
  const expectedSubjects = new Set();
  for (const family of families) {
    const subjects = instancesForClassClosure(authorityInputs.index, family.subjectClassClosure);
    const registration = family.registrationIri;
    if (Object.hasOwn(expectedSubjectCountsByRegistration, registration)) {
      if (expectedSubjectClassClosureDigestsByRegistration[registration] !== family.subjectClassClosure.digest) {
        fail('CENSUS_REGISTRATION_CLASS_CLOSURE_CONFLICT', `${registration} resolves to conflicting class closures`);
      }
    } else {
      expectedSubjectCountsByRegistration[registration] = subjects.length;
      expectedSubjectSetDigestsByRegistration[registration] = fullDigest(subjects);
      expectedSubjectClassClosureDigestsByRegistration[registration] = family.subjectClassClosure.digest;
    }
    for (const subject of subjects) {
      expectedSubjects.add(subject);
      expectedPairs.push(`${family.iri}\u0000${subject}`);
    }
  }
  expectedPairs.sort(compareCodeUnits);
  if (canonicalJson(census.subjectCountsByRegistration) !== canonicalJson(expectedSubjectCountsByRegistration)
    || canonicalJson(census.subjectSetDigestsByRegistration) !== canonicalJson(expectedSubjectSetDigestsByRegistration)
    || canonicalJson(census.subjectClassClosureDigestsByRegistration)
      !== canonicalJson(expectedSubjectClassClosureDigestsByRegistration)) {
    fail('CENSUS_SUBJECT_REGISTRATION_COUNT_MISMATCH',
      'census registration counts, subject-set digests or class-closure digests differ from authority');
  }
  if (census.subjectCount !== expectedSubjects.size) {
    fail('CENSUS_SUBJECT_COUNT_MISMATCH', 'census unique subject count differs from authority');
  }
  for (const record of census.records) {
    if (typeof record.subject !== 'string' || record.subject.length === 0) {
      fail('CENSUS_RECORD_SUBJECT_MISSING', `${record.family ?? 'unknown family'} has no exact subject`);
    }
    if (typeof record.subjectClass !== 'string' || record.subjectClass.length === 0) {
      fail('CENSUS_RECORD_SUBJECT_CLASS_MISSING', `${record.family ?? 'unknown family'} / ${record.subject} has no subject class`);
    }
    const family = metaModel.familyRegistry.families.find(({ iri: familyIri }) => familyIri === record.family);
    if (!family
      || family.registrationIri !== record.registrationIri
      || family.subjectClassIri !== record.subjectClass
      || family.subjectClassClosure.digest !== record.subjectClassClosureDigest
      || !isTypeInClassClosure(authorityInputs.index, record.subject, family.subjectClassClosure)) {
      fail('CENSUS_RECORD_SUBJECT_CLASS_MISMATCH', `${record.family} / ${record.subject} does not match its registered subject class`);
    }
    const capabilityFamily = family.subjectClassIri === `${O}Capability`;
    if ((capabilityFamily && record.capability !== record.subject)
      || (!capabilityFamily && record.capability !== null)) {
      fail('CENSUS_RECORD_CAPABILITY_BINDING_INVALID', `${record.family} / ${record.subject} has an invalid compatibility capability`);
    }
    const expectedContract = capabilityFamily ? contractForCapability(authorityInputs.index, record.subject) : null;
    if (record.contract !== expectedContract) {
      fail('CENSUS_RECORD_CONTRACT_BINDING_INVALID', `${record.family} / ${record.subject} has an invalid contract binding`);
    }
  }
  const pairs = census.records.map((record) => `${record.family}\u0000${record.subject}`);
  if (new Set(pairs).size !== pairs.length) fail('CENSUS_PAIR_DUPLICATE', 'census repeats a family-subject pair');
  const actualPairs = [...pairs].sort(compareCodeUnits);
  const expectedPairSet = new Set(expectedPairs);
  const actualPairSet = new Set(actualPairs);
  const missingPairs = expectedPairs.filter((pair) => !actualPairSet.has(pair));
  if (missingPairs.length > 0) fail('CENSUS_PAIR_MISSING', 'census omits expected family-subject pairs', { missingPairs });
  const extraPairs = actualPairs.filter((pair) => !expectedPairSet.has(pair));
  if (extraPairs.length > 0) fail('CENSUS_PAIR_EXTRA', 'census contains unexpected family-subject pairs', { extraPairs });
  if (census.expectedPairCount !== expectedPairs.length
    || census.pairSetDigest !== fullDigest(expectedPairs)) {
    fail('CENSUS_PAIR_SET_BINDING_MISMATCH', 'census pair-set binding is stale');
  }
  const expectedDispositionCounts = census.records.reduce((counts, { disposition }) => {
    counts[disposition] = (counts[disposition] ?? 0) + 1;
    return counts;
  }, {});
  if (canonicalJson(census.dispositionCounts) !== canonicalJson(expectedDispositionCounts)) {
    fail('CENSUS_DISPOSITION_COUNT_MISMATCH', 'census disposition counts do not match its records');
  }
}

export function generateUniverse({ authorityInputs, census, repositoryRoot }) {
  const verified = assertVerifiedAuthorityInputs(authorityInputs);
  const metaModel = loadPermutationMetaModel(repositoryRoot);
  validateCensus(census, verified, metaModel);
  const requiredRecords = census.records.filter(({ disposition }) => disposition === 'MATRIX_REQUIRED');
  const cells = [];
  const domainRecords = [];
  const gaps = [];
  const expectedCountsByPair = [];
  for (const record of requiredRecords) {
    const generated = generateFamilyCells(metaModel, verified, record);
    // Avoid variadic Array#push: complete finite domains can legitimately
    // produce more arguments than V8's call stack permits.
    for (const cell of generated.cells) cells.push(cell);
    for (const domain of generated.domains) {
      domainRecords.push({
        capability: record.capability,
        family: record.family,
        subject: record.subject,
        ...domain,
        values: undefined,
      });
    }
    for (const gap of generated.gaps) gaps.push(gap);
    expectedCountsByPair.push({
      capability: record.capability,
      expectedCellCount: generated.expectedCellCount,
      family: record.family,
      generatedCellCount: generated.cells.length,
      subject: record.subject,
    });
  }
  const identityKeys = cells.map(({ stableKey }) => stableKey);
  if (new Set(identityKeys).size !== identityKeys.length) fail('CELL_IDENTITY_DUPLICATE', 'generated stable keys are not unique');
  const cellIris = cells.map(({ cellIri }) => cellIri);
  if (new Set(cellIris).size !== cellIris.length) fail('CELL_IDENTITY_DUPLICATE', 'generated cell IRIs are not unique');
  const dispositionCounts = Object.fromEntries(Object.values(DISPOSITIONS).map((value) => [value, 0]));
  for (const cell of cells) dispositionCounts[cell.disposition] += 1;
  const familiesGenerated = new Set(cells.map(({ family }) => family)).size;
  const cellsDigest = fullDigest(cells);
  const inputBindings = {
    authorityDigest: verified.authorityDigest,
    authorityPacketDigest: verified.authorityPacketDigest,
    authorityProjectionDigest: verified.authorityProjectionDigest,
    familyCensusDigest: census.censusDigest,
    metaModelDigest: metaModel.digest,
  };
  return {
    authorityDigest: verified.authorityDigest,
    cellCount: cells.length,
    cells,
    cellsDigest,
    dispositionCounts,
    domainRecords,
    expectedCountsByPair,
    familiesGenerated,
    familyCensusDigest: census.censusDigest,
    gaps,
    inputBindings,
    recordKind: 'USF_PERMUTATION_CELL_UNIVERSE',
    schemaVersion: 2,
    structuralVerdict: gaps.length === 0 ? 'GENERATOR_STRUCTURAL_INVARIANTS_PASS' : 'GENERATOR_STRUCTURAL_GAPS',
    universeDigest: fullDigest({ cellsDigest, dispositionCounts, expectedCountsByPair, gaps, inputBindings }),
  };
}

export function planUniverse({ authorityInputs, census, repositoryRoot }) {
  const verified = assertVerifiedAuthorityInputs(authorityInputs);
  const metaModel = loadPermutationMetaModel(repositoryRoot);
  validateCensus(census, verified, metaModel);
  const requiredRecords = census.records.filter(({ disposition }) => disposition === 'MATRIX_REQUIRED');
  const expectedCountsByPair = [];
  const domainRecords = [];
  const gaps = [];
  let totalExpectedCellCount = 0;
  for (const record of requiredRecords) {
    const plan = resolveFamilyPlan(metaModel, verified, record);
    totalExpectedCellCount += plan.expectedCellCount;
    for (const gap of plan.gaps) gaps.push(gap);
    for (const domain of plan.domains) {
      const { values: omitted, ...descriptor } = domain;
      domainRecords.push({ capability: record.capability, family: record.family, subject: record.subject, ...descriptor });
    }
    expectedCountsByPair.push({
      capability: record.capability,
      expectedCellCount: plan.expectedCellCount,
      family: record.family,
      subject: record.subject,
    });
  }
  return {
    applicabilityRuleDigest: metaModel.coverageRules.digest,
    authorityDigest: verified.authorityDigest,
    coverageRules: metaModel.coverageRules,
    domainRecords,
    expectedCountsByPair,
    finiteDomainDigest: fullDigest(domainRecords),
    gaps,
    inputBindings: {
      authorityDigest: verified.authorityDigest,
      authorityPacketDigest: verified.authorityPacketDigest,
      authorityProjectionDigest: verified.authorityProjectionDigest,
      familyCensusDigest: census.censusDigest,
      metaModelDigest: metaModel.digest,
      publicationBudgetPolicyDigest: metaModel.publicationBudgetPolicy.digest,
    },
    recordKind: 'USF_PERMUTATION_UNIVERSE_PLAN',
    publicationBudgetPolicy: metaModel.publicationBudgetPolicy,
    requiredPairCount: requiredRecords.length,
    schemaVersion: 1,
    totalExpectedCellCount,
  };
}

const groupedGapProjection = (gaps, keyFor, projectKey) => {
  const groups = new Map();
  for (const gap of gaps) {
    const key = keyFor(gap);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(gap);
  }
  return [...groups.entries()].sort(([left], [right]) => compareCodeUnits(left, right))
    .map(([key, members]) => ({
      ...projectKey(key, members),
      capabilities: uniqueSorted(members.map(({ capability }) => capability).filter((value) => value !== null)),
      count: members.length,
      dimensions: uniqueSorted(members.map(({ dimensionKey }) => dimensionKey)),
      families: uniqueSorted(members.map(({ family }) => family)),
      subjects: uniqueSorted(members.map(({ subject }) => subject)),
    }));
};

export function buildDispositionGapReport(plan) {
  const gaps = [...plan.gaps].sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  const missingDecisionCode = (gap) => gap.sourceKind === SOURCE_KIND.DERIVED_SELECTOR
    ? `EXPLICIT_${gap.dimensionKey.toUpperCase()}_DERIVATION_REQUIRED`
    : gap.sourceKind === SOURCE_KIND.CLASS_INSTANCES
      ? `PUBLISHED_${gap.dimensionKey.toUpperCase()}_VOCABULARY_REQUIRED`
      : `CONTROLLED_${gap.dimensionKey.toUpperCase()}_DOMAIN_REQUIRED`;
  const expectedCountsByFamily = Object.entries(plan.expectedCountsByPair.reduce((counts, record) => {
    counts[record.family] = (counts[record.family] ?? 0) + record.expectedCellCount;
    return counts;
  }, {})).sort(([left], [right]) => compareCodeUnits(left, right))
    .map(([family, expectedCellCount]) => ({ expectedCellCount, family }));
  const reportCore = {
    authorityDigest: plan.authorityDigest,
    byCapability: groupedGapProjection(gaps.filter(({ capability }) => capability !== null), ({ capability }) => capability,
      (capability) => ({ capability })),
    byFamily: groupedGapProjection(gaps, ({ family }) => family,
      (family) => ({ family })),
    byMissingAuthoritySignal: groupedGapProjection(
      gaps,
      ({ dimensionKey, source, sourcePlane }) => `${dimensionKey}\u0000${source}\u0000${sourcePlane}`,
      (key) => {
        const [dimensionKey, source, sourcePlane] = key.split('\u0000');
        return { dimensionKey, source, sourcePlane };
      },
    ),
    byMissingSemanticDecision: groupedGapProjection(
      gaps,
      missingDecisionCode,
      (missingSemanticDecision) => ({ missingSemanticDecision }),
    ),
    bySubject: groupedGapProjection(gaps, ({ subject }) => subject,
      (subject, members) => ({ subject, subjectClass: members[0].subjectClass })),
    expectedCountsByFamily,
    gapCount: gaps.length,
    gaps,
    gapSetDigest: fullDigest(gaps),
    inputBindings: plan.inputBindings,
    planDigest: fullDigest(plan),
    requiredPairCount: plan.requiredPairCount,
    totalExpectedCellCount: plan.totalExpectedCellCount,
    verdict: 'PERMUTATION_CLOSURE_INCOMPLETE',
  };
  return {
    ...reportCore,
    recordKind: 'USF_PERMUTATION_DISPOSITION_GAP_REPORT',
    reportDigest: fullDigest(reportCore),
    schemaVersion: 1,
  };
}

function writeAddressedSegment(repositoryRoot, lines, filePrefix = 'permutation-cell-segment') {
  if (!/^[a-z0-9-]+$/.test(filePrefix)) fail('CELL_SEGMENT_PREFIX_INVALID', 'segment prefix is invalid');
  const content = lines.join('');
  const contentDigest = sha256(content);
  const compressed = gzipSync(Buffer.from(content), { level: 9, mtime: 0 });
  const digest = sha256(compressed);
  const fileName = `${filePrefix}-${digest.slice('sha256:'.length)}.ndjson.gz`;
  const relativePath = join('.work', 'generated', fileName);
  const absolutePath = join(repositoryRoot, relativePath);
  if (existsSync(absolutePath)) {
    if (sha256(readFileSync(absolutePath)) !== digest) {
      fail('CELL_SEGMENT_CONTENT_ADDRESS_COLLISION', `${relativePath} bytes do not match its address`);
    }
  } else {
    writeFileSync(absolutePath, compressed);
  }
  return {
    byteCount: compressed.byteLength,
    cellCount: lines.length,
    compression: 'GZIP_LEVEL_9_MTIME_0',
    contentDigest,
    digest,
    path: relativePath,
    uncompressedByteCount: Buffer.byteLength(content),
  };
}

export function generateUniverseManifest({
  authorityInputs,
  census,
  repositoryRoot,
  segmentCellLimit = 10_000,
}) {
  if (!Number.isInteger(segmentCellLimit) || segmentCellLimit < 1) {
    fail('CELL_SEGMENT_LIMIT_INVALID', 'segmentCellLimit must be a positive integer');
  }
  const verified = assertVerifiedAuthorityInputs(authorityInputs);
  const metaModel = loadPermutationMetaModel(repositoryRoot);
  validateCensus(census, verified, metaModel);
  mkdirSync(join(repositoryRoot, '.work', 'generated'), { recursive: true });

  const requiredRecords = census.records.filter(({ disposition }) => disposition === 'MATRIX_REQUIRED');
  const cellSegments = [];
  const domainRecords = [];
  const expectedCountsByPair = [];
  const familiesGenerated = new Set();
  const gaps = [];
  const seenCellIris = new Set();
  const permissionAtomCandidateMap = new Map();
  let permissionAtomSourceCellCount = 0;
  const dispositionCounts = Object.fromEntries(Object.values(DISPOSITIONS).map((value) => [value, 0]));
  const cellsHash = createHash('sha256');
  const stableKeysHash = createHash('sha256');
  let cellCount = 0;
  let segmentLines = [];
  let segmentFirstCellIri;
  let segmentLastCellIri;

  const flushSegment = () => {
    if (segmentLines.length === 0) return;
    const descriptor = writeAddressedSegment(repositoryRoot, segmentLines);
    cellSegments.push({
      ...descriptor,
      firstCellIri: segmentFirstCellIri,
      index: cellSegments.length,
      lastCellIri: segmentLastCellIri,
    });
    segmentLines = [];
    segmentFirstCellIri = undefined;
    segmentLastCellIri = undefined;
  };

  for (const record of requiredRecords) {
    const generated = visitFamilyCells(metaModel, verified, record, (cell) => {
      if (seenCellIris.has(cell.cellIri)) {
        fail('CELL_IDENTITY_DUPLICATE', `generated cell IRI ${cell.cellIri} is not unique`);
      }
      seenCellIris.add(cell.cellIri);
      dispositionCounts[cell.disposition] += 1;
      familiesGenerated.add(cell.family);
      if (cell.family === exactFamily.operationPermission
        && [DISPOSITIONS.required, DISPOSITIONS.allowed].includes(cell.disposition)) {
        collectPermissionAtomCandidate(permissionAtomCandidateMap, cell);
        permissionAtomSourceCellCount += 1;
      }
      const line = `${canonicalJson(cell)}\n`;
      cellsHash.update(line);
      stableKeysHash.update(`${cell.stableKey}\n`);
      if (segmentLines.length === 0) segmentFirstCellIri = cell.cellIri;
      segmentLastCellIri = cell.cellIri;
      segmentLines.push(line);
      cellCount += 1;
      if (segmentLines.length === segmentCellLimit) flushSegment();
    });
    for (const domain of generated.domains) {
      const { values, ...descriptor } = domain;
      domainRecords.push({ capability: record.capability, family: record.family, subject: record.subject, ...descriptor });
    }
    for (const gap of generated.gaps) gaps.push(gap);
    if (generated.generatedCellCount !== generated.expectedCellCount) {
      fail('GENERATED_CARDINALITY_MISMATCH', `${record.family} / ${record.capability} generated an inexact product`);
    }
    expectedCountsByPair.push({
      capability: record.capability,
      expectedCellCount: generated.expectedCellCount,
      family: record.family,
      generatedCellCount: generated.generatedCellCount,
      subject: record.subject,
    });
  }
  flushSegment();

  const cellsDigest = `sha256:${cellsHash.digest('hex')}`;
  const stableKeySequenceDigest = `sha256:${stableKeysHash.digest('hex')}`;
  const inputBindings = {
    authorityDigest: verified.authorityDigest,
    authorityPacketDigest: verified.authorityPacketDigest,
    authorityProjectionDigest: verified.authorityProjectionDigest,
    familyCensusDigest: census.censusDigest,
    metaModelDigest: metaModel.digest,
    publicationBudgetPolicyDigest: metaModel.publicationBudgetPolicy.digest,
    ...sourceAlgorithmBindings(repositoryRoot, metaModel.coverageRules.digest),
  };
  const structuralVerdict = gaps.length === 0
    ? 'GENERATOR_STRUCTURAL_INVARIANTS_PASS'
    : 'GENERATOR_STRUCTURAL_GAPS';
  const permissionAtomCandidateSet = finalisePermissionAtomCandidates(
    permissionAtomCandidateMap,
    permissionAtomSourceCellCount,
  );
  const descriptor = {
    cellCount,
    cellSegments,
    cellsDigest,
    dispositionCounts,
    domainRecords,
    finiteDomainDigest: fullDigest(domainRecords),
    expectedCountsByPair,
    familiesGenerated: familiesGenerated.size,
    familyCensusDigest: census.censusDigest,
    gaps,
    inputBindings,
    permissionAtomCandidateCount: permissionAtomCandidateSet.candidateCount,
    permissionAtomCandidateSet,
    permissionAtomSourceCellCount,
    segmentCellLimit,
    segmentFormat: 'CANONICAL_JSON_LINES_UTF8_GZIP_V1',
    stableKeySequenceDigest,
    structuralVerdict,
  };
  return {
    authorityDigest: verified.authorityDigest,
    ...descriptor,
    recordKind: 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST',
    schemaVersion: 3,
    universeDigest: fullDigest(descriptor),
  };
}

export function closureClassificationForDisposition(disposition) {
  if ([DISPOSITIONS.required, DISPOSITIONS.allowed].includes(disposition)) {
    return Object.freeze({ applicability: 'APPLICABLE', representation: 'OPERATIONAL_CELL', satisfiability: 'SATISFIABLE' });
  }
  if (disposition === DISPOSITIONS.forbidden) {
    return Object.freeze({ applicability: 'APPLICABLE', representation: 'RULE_COVERED', satisfiability: 'UNSATISFIABLE' });
  }
  if (disposition === DISPOSITIONS.notApplicable) {
    return Object.freeze({ applicability: 'NOT_APPLICABLE', representation: 'RULE_COVERED', satisfiability: 'NOT_APPLICABLE' });
  }
  if ([DISPOSITIONS.deferred, DISPOSITIONS.unresolved].includes(disposition)) {
    return Object.freeze({ applicability: 'UNDETERMINED', representation: 'PENDING_REGION', satisfiability: 'UNDETERMINED' });
  }
  fail('PERMUTATION_CELL_DISPOSITION_INVALID', `unknown disposition ${disposition}`);
}

function cellDomainScope(cell) {
  if (!Array.isArray(cell.dimensionBindings) || cell.dimensionBindings.length === 0) {
    fail('PERMUTATION_CELL_SHAPE_INVALID', `${cell.cellIri ?? 'cell'} has no dimension bindings`);
  }
  return cell.dimensionBindings.map(({ dimension, key, position, valueSetDigest }) => ({
    dimension,
    key,
    position,
    valueSetDigest,
  }));
}

function exactCellDisposition(cell) {
  if (!cell.disposition || !Array.isArray(cell.dispositions) || cell.dispositions.length !== 1
    || cell.dispositions[0].iri !== cell.disposition) {
    fail('PERMUTATION_CELL_DISPOSITION_INVALID', `${cell.cellIri ?? 'cell'} does not have one exact disposition`);
  }
  return cell.dispositions[0];
}

function authorityBackedCoverageRule(cell, authorityInputs, coverageRules) {
  const assignment = exactCellDisposition(cell);
  const registeredRule = coverageRules?.records?.find(({ disposition, families, reasonCode }) => (
    disposition === cell.disposition && reasonCode === assignment.reasonCode && families.includes(cell.family)
  ));
  if (!registeredRule) {
    fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_SCOPE_INVALID', `${assignment.reasonCode} is outside its registered family scope`);
  }
  const binding = (key) => cell.dimensionBindings.find((candidate) => candidate.key === key)?.value;
  const operation = binding('operation');
  if (assignment.reasonCode === 'OPERATION_DOES_NOT_REQUIRE_PERMISSION'
    && cell.disposition === DISPOSITIONS.notApplicable) {
    if (registeredRule.ruleKind !== 'AUTHORITY_SET_NON_MEMBERSHIP'
      || registeredRule.predicate !== `${O}requiresPermission`
      || registeredRule.testedDimensionKey !== 'permissionatom') {
      fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', `${registeredRule.resource} has unsupported semantics`);
    }
    const testedValue = binding('permissionatom');
    const authorityValues = authorityInputs.index.values(operation, `${O}requiresPermission`);
    const applicabilityProof = fullDigest({ operation, requiredPermissions: authorityValues });
    if (!operation || !testedValue || authorityValues.includes(testedValue)
      || assignment.applicabilityProof !== applicabilityProof) {
      fail('PERMUTATION_SYMBOLIC_REGION_COVERAGE_MISMATCH', `${cell.cellIri} has an invalid authority non-membership proof`);
    }
    return {
      anchor: operation,
      applicabilityProof,
      authorityValueSetDigest: fullDigest(authorityValues),
      authorityValues,
      predicate: `${O}requiresPermission`,
      semanticRule: registeredRule.resource,
      semanticRuleDigest: registeredRule.declaredDigest,
      ruleKind: 'AUTHORITY_SET_NON_MEMBERSHIP',
      testedDimensionKey: 'permissionatom',
    };
  }
  if (assignment.reasonCode === 'FORBIDDEN_BY_COORDINATOR_ONLY'
    && cell.disposition === DISPOSITIONS.forbidden) {
    if (registeredRule.ruleKind !== 'AUTHORITY_BOOLEAN_TRUE_GUARD'
      || registeredRule.predicate !== `${O}coordinatorOnly`
      || registeredRule.testedDimensionKey !== 'operation') {
      fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', `${registeredRule.resource} has unsupported semantics`);
    }
    const authorityValues = authorityInputs.index.values(operation, `${O}coordinatorOnly`);
    if (!operation || !authorityValues.includes('true')) {
      fail('PERMUTATION_SYMBOLIC_REGION_COVERAGE_MISMATCH', `${cell.cellIri} lacks the coordinator-only guard`);
    }
    return {
      anchor: operation,
      authorityValueSetDigest: fullDigest(authorityValues),
      authorityValues,
      predicate: `${O}coordinatorOnly`,
      semanticRule: registeredRule.resource,
      semanticRuleDigest: registeredRule.declaredDigest,
      ruleKind: 'AUTHORITY_BOOLEAN_TRUE_GUARD',
      testedDimensionKey: 'operation',
    };
  }
  fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', `${assignment.reasonCode} is not a registered symbolic coverage rule`);
}

function addRegionMember(regions, core, stableKey) {
  const regionKey = canonicalJson(core);
  if (!regions.has(regionKey)) {
    regions.set(regionKey, { core, count: 0, hash: createHash('sha256'), regionKey });
  }
  const region = regions.get(regionKey);
  region.count += 1;
  region.hash.update(`${stableKey}\n`);
}

function finaliseRegions(regions) {
  return [...regions.values()].map(({ core, count, hash, regionKey }) => {
    const coveredStableKeySequenceDigest = `sha256:${hash.digest('hex')}`;
    const record = {
      ...core,
      coveredCellCount: count,
      coveredStableKeySequenceDigest,
      regionKey,
    };
    return { ...record, regionDigest: fullDigest(record) };
  }).sort((left, right) => compareCodeUnits(left.regionKey, right.regionKey));
}

function assertExactSparsePartition({
  closureCounts,
  dispositionCounts,
  pendingCoverageRegions,
  ruleCoverageRegions,
}) {
  const operationalCellCount = closureCounts?.representation?.operationalCell;
  const ruleCoveredCellCount = closureCounts?.representation?.ruleCovered;
  const pendingCoveredCellCount = closureCounts?.representation?.pendingRegionMember;
  const rawCandidateCount = closureCounts?.rawCandidateCount;
  const pendingRegionTotal = pendingCoverageRegions
    .reduce((sum, region) => sum + region.coveredCellCount, 0);
  const ruleRegionTotal = ruleCoverageRegions
    .reduce((sum, region) => sum + region.coveredCellCount, 0);
  if (![operationalCellCount, ruleCoveredCellCount, pendingCoveredCellCount, rawCandidateCount]
    .every((value) => Number.isSafeInteger(value) && value >= 0)
    || rawCandidateCount !== operationalCellCount + ruleCoveredCellCount + pendingCoveredCellCount
    || operationalCellCount !== dispositionCounts[DISPOSITIONS.required] + dispositionCounts[DISPOSITIONS.allowed]
    || ruleCoveredCellCount !== dispositionCounts[DISPOSITIONS.forbidden] + dispositionCounts[DISPOSITIONS.notApplicable]
    || pendingCoveredCellCount !== dispositionCounts[DISPOSITIONS.deferred] + dispositionCounts[DISPOSITIONS.unresolved]
    || ruleRegionTotal !== ruleCoveredCellCount
    || pendingRegionTotal !== pendingCoveredCellCount) {
    fail('PERMUTATION_SPARSE_PARTITION_MISMATCH', 'sparse partition does not exactly cover the raw universe');
  }
}

function publicationBudget({
  liveTripleCount,
  operationalCellCount,
  pendingRegionCount,
  providerEdgeLimit,
  publicationReserve,
  ruleRegionCount,
  policy,
}) {
  for (const [name, value] of Object.entries({ liveTripleCount, providerEdgeLimit, publicationReserve })) {
    if (!Number.isSafeInteger(value) || value < 0) fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', `${name} is invalid`);
  }
  if (providerEdgeLimit < 1 || publicationReserve >= providerEdgeLimit) {
    fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'provider limit and reserve do not leave usable capacity');
  }
  if (!policy || policy.hardStatementLimit !== providerEdgeLimit
    || policy.reserveStatementCount !== publicationReserve
    || policy.maximumProjectedStatementCount !== providerEdgeLimit - publicationReserve
    || policy.failClosed !== true || !/^sha256:[0-9a-f]{64}$/.test(policy.digest || '')) {
    fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'runtime budget does not match the current semantic policy');
  }
  for (const [name, value] of Object.entries({ operationalCellCount, pendingRegionCount, ruleRegionCount })) {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', `${name} is invalid`);
    }
  }
  const encodingPolicy = policy.encodingPolicy;
  const candidateTripleUpperBound = encodingPolicy.fixedManifestTripleUpperBound
    + operationalCellCount * encodingPolicy.operationalCellTripleUpperBound
    + (pendingRegionCount + ruleRegionCount) * encodingPolicy.regionTripleUpperBound;
  const maximumProjectedTripleCount = policy.maximumProjectedStatementCount;
  const projectedTripleUpperBound = liveTripleCount + candidateTripleUpperBound;
  if (![candidateTripleUpperBound, maximumProjectedTripleCount, projectedTripleUpperBound]
    .every(Number.isSafeInteger)) {
    fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'publication budget arithmetic exceeds safe integer bounds');
  }
  const core = {
    candidateTripleUpperBound,
    encodingPolicy,
    liveTripleCount,
    maximumProjectedTripleCount,
    projectedTripleUpperBound,
    policyDigest: policy.digest,
    policyIri: policy.policyIri,
    provider: policy.provider,
    providerEdgeLimit,
    publicationReserve,
    exactCandidateGraphGate: 'REQUIRED_BEFORE_AUTHORITY_TRANSACTION',
  };
  if (projectedTripleUpperBound > maximumProjectedTripleCount) {
    fail('PERMUTATION_PUBLICATION_BUDGET_EXCEEDED', 'sparse projection exceeds the reserved provider capacity', core);
  }
  return { ...core, budgetDigest: fullDigest(core), result: 'PREFLIGHT_PASS' };
}

export function generateSparseSymbolicManifest({
  authorityInputs,
  census,
  liveTripleCount,
  providerEdgeLimit,
  publicationReserve,
  rawManifest,
  rawManifestDigest,
  repositoryRoot,
  segmentCellLimit = 10_000,
}) {
  const verified = assertVerifiedAuthorityInputs(authorityInputs);
  const currentPlan = planUniverse({ authorityInputs: verified, census, repositoryRoot });
  if (rawManifest?.recordKind !== 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST' || rawManifest.schemaVersion !== 3) {
    fail('PERMUTATION_SPARSE_PROJECTION_SCHEMA_INVALID', 'raw universe manifest is not schema v3');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(rawManifestDigest || '')
    || rawManifest.authorityDigest !== verified.authorityDigest
    || rawManifest.inputBindings?.authorityDigest !== verified.authorityDigest
    || rawManifest.inputBindings?.authorityPacketDigest !== verified.authorityPacketDigest
    || rawManifest.inputBindings?.authorityProjectionDigest !== verified.authorityProjectionDigest) {
    fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', 'raw manifest authority binding is invalid');
  }
  const {
    authorityDigest: ignoredAuthorityDigest,
    recordKind: rawRecordKind,
    schemaVersion: rawSchemaVersion,
    universeDigest: rawUniverseDigest,
    ...rawDescriptor
  } = rawManifest;
  if (rawRecordKind !== 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST'
    || rawSchemaVersion !== 3
    || fullDigest(rawDescriptor) !== rawUniverseDigest) {
    fail('PERMUTATION_RAW_UNIVERSE_BINDING_MISMATCH', 'raw universe descriptor digest is invalid');
  }
  if (rawManifest.familyCensusDigest !== census.censusDigest
    || rawManifest.inputBindings?.familyCensusDigest !== census.censusDigest
    || rawManifest.inputBindings?.metaModelDigest !== currentPlan.inputBindings.metaModelDigest
    || rawManifest.inputBindings?.publicationBudgetPolicyDigest !== currentPlan.publicationBudgetPolicy.digest
    || rawManifest.finiteDomainDigest !== currentPlan.finiteDomainDigest
    || canonicalJson(rawManifest.expectedCountsByPair) !== canonicalJson(currentPlan.expectedCountsByPair.map((record) => ({
      ...record,
      generatedCellCount: record.expectedCellCount,
    })))
    || canonicalJson(rawManifest.gaps) !== canonicalJson(currentPlan.gaps)) {
    fail('PERMUTATION_RAW_UNIVERSE_BINDING_MISMATCH', 'raw universe census, meta-model or finite domains are stale');
  }
  const sourceBindings = sourceAlgorithmBindings(repositoryRoot, currentPlan.applicabilityRuleDigest);
  for (const [field, value] of Object.entries(sourceBindings)) {
    if (rawManifest.inputBindings?.[field] !== value) {
      fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', `raw manifest ${field} is stale`);
    }
  }
  if (!Number.isInteger(segmentCellLimit) || segmentCellLimit < 1) {
    fail('CELL_SEGMENT_LIMIT_INVALID', 'segmentCellLimit must be a positive integer');
  }

  const generatedRoot = resolve(repositoryRoot, '.work', 'generated');
  const operationalSegments = [];
  const ruleRegions = new Map();
  const pendingRegions = new Map();
  const operationalHash = createHash('sha256');
  const operationalStableKeyHash = createHash('sha256');
  const rawCellsHash = createHash('sha256');
  const rawStableKeyHash = createHash('sha256');
  const observedDispositionCounts = Object.fromEntries(Object.values(DISPOSITIONS).map((value) => [value, 0]));
  const closureCounts = {
    applicability: { applicable: 0, notApplicable: 0, undetermined: 0 },
    rawCandidateCount: 0,
    representation: { operationalCell: 0, pendingRegionMember: 0, ruleCovered: 0 },
    satisfiability: { notApplicable: 0, satisfiable: 0, undetermined: 0, unsatisfiable: 0 },
  };
  let operationalLines = [];
  let firstOperationalCellIri;
  let lastOperationalCellIri;

  const flushOperational = () => {
    if (operationalLines.length === 0) return;
    const descriptor = writeAddressedSegment(repositoryRoot, operationalLines, 'permutation-operational-cell-segment');
    operationalSegments.push({
      ...descriptor,
      firstCellIri: firstOperationalCellIri,
      index: operationalSegments.length,
      lastCellIri: lastOperationalCellIri,
    });
    operationalLines = [];
    firstOperationalCellIri = undefined;
    lastOperationalCellIri = undefined;
  };

  for (const [segmentIndex, segment] of (rawManifest.cellSegments ?? []).entries()) {
    const absolutePath = resolve(repositoryRoot, segment.path);
    if (!absolutePath.startsWith(`${generatedRoot}/`)
      || basename(absolutePath) !== `permutation-cell-segment-${segment.digest?.slice('sha256:'.length)}.ndjson.gz`
      || !existsSync(absolutePath) || !lstatSync(absolutePath).isFile() || lstatSync(absolutePath).isSymbolicLink()
      || realpathSync(absolutePath) !== absolutePath) {
      fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', `raw segment ${segmentIndex} path is invalid`);
    }
    const compressed = readFileSync(absolutePath);
    if (sha256(compressed) !== segment.digest || compressed.byteLength !== segment.byteCount) {
      fail('PERMUTATION_INPUT_DIGEST_MISMATCH', `raw segment ${segmentIndex} compressed binding differs`);
    }
    const content = gunzipSync(compressed);
    if (sha256(content) !== segment.contentDigest || content.byteLength !== segment.uncompressedByteCount
      || content.at(-1) !== 10 || segment.compression !== 'GZIP_LEVEL_9_MTIME_0') {
      fail('PERMUTATION_INPUT_DIGEST_MISMATCH', `raw segment ${segmentIndex} content binding differs`);
    }
    const lines = content.subarray(0, content.length - 1).toString('utf8').split('\n');
    if (segment.index !== segmentIndex || lines.length !== segment.cellCount) {
      fail('PERMUTATION_SPARSE_PARTITION_MISMATCH', `raw segment ${segmentIndex} cardinality differs`);
    }
    let firstCellIri;
    let lastCellIri;
    for (const line of lines) {
      const cell = JSON.parse(line);
      if (canonicalJson(cell) !== line) {
        fail('PERMUTATION_CELL_ENCODING_NON_CANONICAL', `${cell.cellIri ?? 'cell'} is not canonical JSON`);
      }
      if (firstCellIri === undefined) firstCellIri = cell.cellIri;
      lastCellIri = cell.cellIri;
      rawCellsHash.update(`${line}\n`);
      rawStableKeyHash.update(`${cell.stableKey}\n`);
      const assignment = exactCellDisposition(cell);
      const classification = closureClassificationForDisposition(cell.disposition);
      observedDispositionCounts[cell.disposition] += 1;
      closureCounts.rawCandidateCount += 1;
      if (classification.applicability === 'APPLICABLE') closureCounts.applicability.applicable += 1;
      else if (classification.applicability === 'NOT_APPLICABLE') closureCounts.applicability.notApplicable += 1;
      else closureCounts.applicability.undetermined += 1;
      if (classification.satisfiability === 'SATISFIABLE') closureCounts.satisfiability.satisfiable += 1;
      else if (classification.satisfiability === 'UNSATISFIABLE') closureCounts.satisfiability.unsatisfiable += 1;
      else if (classification.satisfiability === 'NOT_APPLICABLE') closureCounts.satisfiability.notApplicable += 1;
      else closureCounts.satisfiability.undetermined += 1;

      if (classification.representation === 'OPERATIONAL_CELL') {
        closureCounts.representation.operationalCell += 1;
        const canonicalLine = `${canonicalJson(cell)}\n`;
        operationalHash.update(canonicalLine);
        operationalStableKeyHash.update(`${cell.stableKey}\n`);
        if (operationalLines.length === 0) firstOperationalCellIri = cell.cellIri;
        lastOperationalCellIri = cell.cellIri;
        operationalLines.push(canonicalLine);
        if (operationalLines.length === segmentCellLimit) flushOperational();
      } else if (classification.representation === 'RULE_COVERED') {
        closureCounts.representation.ruleCovered += 1;
        const core = {
          authorising: false,
          authorityDigest: verified.authorityDigest,
          capability: cell.capability,
          coverageBasis: 'AUTHORITY_BACKED_RULE',
          disposition: cell.disposition,
          domainScope: cellDomainScope(cell),
          family: cell.family,
          reasonCode: assignment.reasonCode,
          rule: authorityBackedCoverageRule(cell, verified, currentPlan.coverageRules),
        };
        addRegionMember(ruleRegions, core, cell.stableKey);
      } else {
        if (cell.disposition === DISPOSITIONS.deferred) {
          fail('PERMUTATION_DEFERRED_WITHOUT_AUTHORITY_PROVENANCE', `${cell.cellIri} has no registered authority deferral rule`);
        }
        closureCounts.representation.pendingRegionMember += 1;
        const core = {
          authorising: false,
          authorityDigest: verified.authorityDigest,
          capability: cell.capability,
          coverageBasis: 'EXACT_LOCAL_IDENTITY_SEQUENCE',
          disposition: cell.disposition,
          domainScope: cellDomainScope(cell),
          family: cell.family,
          provenance: assignment.provenance,
          reasonCode: assignment.reasonCode,
          regionKind: cell.disposition === DISPOSITIONS.deferred ? 'DEFERRED' : 'UNRESOLVED',
        };
        addRegionMember(pendingRegions, core, cell.stableKey);
      }
    }
    if (segment.firstCellIri !== firstCellIri || segment.lastCellIri !== lastCellIri) {
      fail('PERMUTATION_RAW_UNIVERSE_BINDING_MISMATCH', `raw segment ${segmentIndex} boundary differs`);
    }
  }
  flushOperational();

  if (`sha256:${rawCellsHash.digest('hex')}` !== rawManifest.cellsDigest
    || `sha256:${rawStableKeyHash.digest('hex')}` !== rawManifest.stableKeySequenceDigest) {
    fail('PERMUTATION_RAW_UNIVERSE_BINDING_MISMATCH', 'raw universe sequence digest differs');
  }

  const ruleCoverageRegions = finaliseRegions(ruleRegions);
  const pendingCoverageRegions = finaliseRegions(pendingRegions);
  const operationalCellCount = closureCounts.representation.operationalCell;
  const ruleCoveredCellCount = closureCounts.representation.ruleCovered;
  const pendingCoveredCellCount = closureCounts.representation.pendingRegionMember;
  if (closureCounts.rawCandidateCount !== rawManifest.cellCount
    || canonicalJson(observedDispositionCounts) !== canonicalJson(rawManifest.dispositionCounts)) {
    fail('PERMUTATION_SPARSE_PARTITION_MISMATCH', 'raw universe summary differs from sparse reconstruction');
  }
  assertExactSparsePartition({
    closureCounts,
    dispositionCounts: observedDispositionCounts,
    pendingCoverageRegions,
    ruleCoverageRegions,
  });
  const budget = publicationBudget({
    liveTripleCount,
    operationalCellCount,
    pendingRegionCount: pendingCoverageRegions.length,
    providerEdgeLimit,
    publicationReserve,
    ruleRegionCount: ruleCoverageRegions.length,
    policy: currentPlan.publicationBudgetPolicy,
  });
  const inputBindings = {
    ...rawManifest.inputBindings,
    finiteDomainDigest: rawManifest.finiteDomainDigest,
    rawManifestDigest,
    rawUniverseDigest: rawManifest.universeDigest,
    sourceAuthorityTripleCount: liveTripleCount,
  };
  const publicationBoundary = {
    fullProjectionRdfPublication: 'PROHIBITED',
    fullProjectionStorageClass: 'SESSION_LOCAL_CONTENT_ADDRESSED_PROJECTION',
    individualPendingCellRdfPublication: 'PROHIBITED',
    individualRuleCoveredCellRdfPublication: 'PROHIBITED',
    permittedRdfResourceKinds: [
      'AGGREGATE_PROOF_BINDING',
      'OPERATIONAL_CELL',
      'PENDING_COVERAGE_REGION',
      'RULE_COVERAGE_REGION',
    ],
    sparseProjectionState: 'CANDIDATE_NOT_AUTHORITY_ADMITTED',
  };
  const descriptor = {
    applicabilityRuleDigest: currentPlan.applicabilityRuleDigest,
    closureCounts,
    inputBindings,
    operationalCellCount,
    operationalCellSegments: operationalSegments,
    operationalCellsDigest: `sha256:${operationalHash.digest('hex')}`,
    operationalSegmentCellLimit: segmentCellLimit,
    operationalSegmentFormat: 'CANONICAL_JSON_LINES_UTF8_GZIP_V1',
    operationalStableKeySequenceDigest: `sha256:${operationalStableKeyHash.digest('hex')}`,
    pendingCoverageRegions,
    pendingCoveredCellCount,
    pendingRegionCount: pendingCoverageRegions.length,
    pendingRegionsDigest: fullDigest(pendingCoverageRegions),
    publicationBoundary,
    publicationBudget: budget,
    rawCandidateCount: closureCounts.rawCandidateCount,
    ruleCoverageRegions,
    ruleCoveredCellCount,
    ruleRegionCount: ruleCoverageRegions.length,
    ruleRegionsDigest: fullDigest(ruleCoverageRegions),
  };
  const sparseVerdict = pendingCoveredCellCount > 0 || (rawManifest.gaps?.length ?? 0) > 0
    ? 'PERMUTATION_CLOSURE_INCOMPLETE'
    : 'SPARSE_SYMBOLIC_INVARIANTS_PASS';
  const sparseCore = { ...descriptor, verdict: sparseVerdict };
  return {
    authorityDigest: verified.authorityDigest,
    ...descriptor,
    recordKind: 'USF_PERMUTATION_SPARSE_SYMBOLIC_MANIFEST',
    schemaVersion: 1,
    sparseManifestDigest: fullDigest(sparseCore),
    verdict: sparseVerdict,
  };
}

export function derivePermissionAtomCandidates(universe) {
  const candidateMap = new Map();
  let sourceCellCount = 0;
  for (const cell of universe.cells ?? []) {
    if (cell.family === exactFamily.operationPermission
      && [DISPOSITIONS.required, DISPOSITIONS.allowed].includes(cell.disposition)) {
      collectPermissionAtomCandidate(candidateMap, cell);
      sourceCellCount += 1;
    }
  }
  return finalisePermissionAtomCandidates(candidateMap, sourceCellCount);
}

export function assessFoundationDomainClosure({ foundationFixtureInputs, repositoryRoot }) {
  const fixture = assertFoundationFixtureInputs(foundationFixtureInputs);
  const metaModel = loadPermutationMetaModel(repositoryRoot);
  const structuralProjection = buildFoundationStructuralProjection(metaModel, fixture);
  const assessmentInputs = Object.freeze({ ...fixture, index: structuralProjection.index });
  VERIFIED_FOUNDATION_FIXTURE_INPUTS.add(assessmentInputs);
  const families = metaModel.familyRegistry.families.map(({ iri: familyIri }) => familyIri);
  const familiesByIri = new Map(metaModel.familyRegistry.families.map((family) => [family.iri, family]));
  const coveredFamilies = metaObjectValues(
    fixture.store,
    fixture.foundationFixtureRoot,
    'foundationFixtureCoversFamily',
  );
  const diagnostics = [];
  const add = (code, details = {}) => diagnostics.push({ ...details, code });
  if (canonicalJson(coveredFamilies) !== canonicalJson(families)) {
    add('FOUNDATION_FIXTURE_FAMILY_COVERAGE_MISMATCH', { coveredFamilies, families });
  }
  const primarySubjects = fixture.foundationFixturePrimarySubjects;
  const primaryAndProjectedSubjects = uniqueSorted(primarySubjects.flatMap((subject) => [
    subject,
    ...(structuralProjection.projectedBySource.get(subject) ?? []),
  ]));
  const registrations = new Map(metaModel.familyRegistry.families.map((family) => [family.registrationIri, family]));
  const primarySubjectsByRegistration = new Map();
  for (const [registrationIri, family] of registrations) {
    const matches = primaryAndProjectedSubjects.filter((subject) => (
      isTypeInClassClosure(structuralProjection.index, subject, family.subjectClassClosure)
    ));
    if (matches.length === 0) {
      add('FOUNDATION_FIXTURE_PRIMARY_SUBJECT_CLASS_ABSENT', {
        classClosureDigest: family.subjectClassClosure.digest,
        registrationIri,
        subjectClass: family.subjectClassIri,
      });
    } else primarySubjectsByRegistration.set(registrationIri, matches);
  }
  const unmatchedPrimarySubjects = primarySubjects.filter((subject) => (
    ![subject, ...(structuralProjection.projectedBySource.get(subject) ?? [])].some((candidate) => (
      metaModel.familyRegistry.families.some((family) => (
        isTypeInClassClosure(structuralProjection.index, candidate, family.subjectClassClosure)
      ))
    ))
  ));
  if (unmatchedPrimarySubjects.length > 0 || primarySubjectsByRegistration.size !== registrations.size) {
    add('FOUNDATION_FIXTURE_PRIMARY_SUBJECT_SET_INVALID', {
      primarySubjects,
      registeredSubjectRegistrations: [...registrations.keys()].sort(compareCodeUnits),
      unmatchedPrimarySubjects,
    });
  }
  const classSources = metaInstances(metaModel.store, `${O}DimensionValueSource`)
    .flatMap((source) => metaObjectValues(metaModel.store, source, 'valueSourceClassIri')
      .map((classIri) => ({ classIri, source })));
  for (const { classIri, source } of classSources) {
    if (!metaModel.store.getQuads(iri(classIri), RDF_TYPE, iri('http://www.w3.org/2002/07/owl#Class'), null).length) {
      add('FOUNDATION_VALUE_SOURCE_CLASS_UNDECLARED', { classIri, source });
    }
  }
  const familyRecords = [];
  const uniqueDimensions = new Set();
  let dimensionBindingOccurrenceCount = 0;
  let totalCombinationCount = 0;
  for (const family of families) {
      const familyDefinition = familiesByIri.get(family);
      const names = metaObjectValues(metaModel.store, family, 'canonicalName');
      if (names.length !== 1) {
        add('FOUNDATION_FAMILY_IDENTITY_INVALID', { family });
        continue;
      }
      const subjectClass = familyDefinition?.subjectClassIri ?? null;
      const candidateSubjects = familyDefinition
        ? primarySubjectsByRegistration.get(familyDefinition.registrationIri) ?? [] : [];
      if (candidateSubjects.length === 0) {
        add('FOUNDATION_FIXTURE_PRIMARY_SUBJECT_MISSING', { family, subjectClass });
        continue;
      }
      const candidatePlans = [];
      for (const subject of candidateSubjects) {
        try {
          candidatePlans.push({
            plan: resolveFamilyPlan(metaModel, assessmentInputs, {
              canonicalName: names[0],
              family,
              subject,
            }),
            subject,
          });
        } catch (error) {
          add(error.code ?? 'FOUNDATION_FAMILY_GENERATION_FAILED', {
            details: error.details ?? {},
            family,
            message: error.message,
            subject,
          });
        }
      }
      const completeWitnesses = candidatePlans.filter(({ plan }) => (
        plan.gaps.length === 0 && plan.expectedCellCount > 0
      ));
      if (completeWitnesses.length > 1) {
        add('FOUNDATION_FIXTURE_FAMILY_WITNESS_CARDINALITY', {
          family,
          matches: completeWitnesses.map(({ subject }) => subject),
          subjectClass,
        });
        continue;
      }
      const selected = completeWitnesses[0] ?? (candidatePlans.length === 1 ? candidatePlans[0] : null);
      if (!selected) {
        add('FOUNDATION_FIXTURE_FAMILY_WITNESS_MISSING', {
          candidateSubjects,
          family,
          subjectClass,
        });
        continue;
      }
      const { plan, subject: primarySubject } = selected;
      for (const gap of plan.gaps) add('FOUNDATION_FINITE_DOMAIN_EMPTY', gap);
      if (!Number.isSafeInteger(plan.expectedCellCount)) {
        add('FOUNDATION_DOMAIN_CARDINALITY_OVERFLOW', { family });
      }
      if (plan.expectedCellCount === 0) add('FOUNDATION_FAMILY_ZERO_COMBINATION', { family });
      for (const { dimension } of plan.domains) uniqueDimensions.add(dimension);
      dimensionBindingOccurrenceCount += plan.domains.length;
      totalCombinationCount += plan.expectedCellCount;
      const dimensions = plan.domains.map(({ values: omittedValues, ...domain }) => domain);
      const familyCore = {
        canonicalName: names[0],
        combinationCount: plan.expectedCellCount,
        dimensionCount: dimensions.length,
        dimensions,
        domainClosureComplete: plan.gaps.length === 0,
        family,
        subject: primarySubject,
        subjectClass,
      };
      familyRecords.push({ ...familyCore, familyDomainDigest: fullDigest(familyCore) });
  }
  familyRecords.sort((left, right) => compareCodeUnits(left.family, right.family));
  diagnostics.sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  const foundationDomainClosureComplete = diagnostics.length === 0;
  const core = {
    authorising: false,
    baselineAuthorityBinding: fixture.baselineAuthorityBinding,
    diagnostics,
    dimensionBindingOccurrenceCount,
    familyCount: families.length,
    familyRecords,
    fixtureInputDigest: fixture.fixtureInputDigest,
    fixtureDigest: fixture.foundationFixtureDigest,
    fixtureFileDigest: fixture.foundationFixtureFileDigest,
    fixturePath: fixture.foundationFixturePath,
    fixtureProjectionDigest: fixture.foundationFixtureProjectionDigest,
    foundationConformanceOnly: true,
    foundationStructuralProjectionDigest: structuralProjection.projectionDigest,
    foundationStructuralProjectionRecordCount: structuralProjection.projectedRecordCount,
    foundationStructuralProjectionRuleSetDigest: metaModel.foundationProjectionRules.digest,
    foundationDomainClosureComplete,
    foundationVerdict: foundationDomainClosureComplete
      ? 'FOUNDATION_DOMAIN_CLOSURE_COMPLETE'
      : 'FOUNDATION_DOMAIN_CLOSURE_INCOMPLETE',
    inputMode: FOUNDATION_FIXTURE_SCOPE,
    metaModelDigest: metaModel.digest,
    nonClaims: fixture.nonClaims,
    permutationClosureVerdict: 'PERMUTATION_CLOSURE_NOT_ASSESSED',
    programmePermutationClosureVerdict: 'PERMUTATION_CLOSURE_INCOMPLETE',
    recordKind: 'USF_FOUNDATION_DOMAIN_CLOSURE_ASSESSMENT',
    schemaVersion: 2,
    sourceClassCount: classSources.length,
    totalCombinationCount,
    uniqueDimensionCount: uniqueDimensions.size,
  };
  return {
    ...core,
    assessmentDigest: fullDigest(core),
  };
}

export const universeGeneratorInternals = Object.freeze({
  authorityBackedCoverageRule,
  assertExactSparsePartition,
  buildFoundationStructuralProjection,
  cellDomainScope,
  dispositionForCell,
  evaluateValueDerivation,
  familyDimensions,
  finaliseRegions,
  generateFamilyCells,
  foundationFixtureDigest,
  loadFoundationProjectionRules,
  loadPermutationMetaModel,
  loadValueSourceDerivation,
  publicationBudget,
  resolveDomain,
  semanticValueSource,
  sourceAlgorithmBindings,
  validateCensus,
  valueDerivationExpression,
  valueSourceDerivationRecord,
});

function exactArg(name) {
  const prefix = `--${name}=`;
  const matches = process.argv.filter((value) => value.startsWith(prefix));
  if (matches.length !== 1) fail('EXACT_INPUT_PATH_REQUIRED', `exactly one ${prefix}<value> argument is required`);
  return matches[0].slice(prefix.length);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const authorityInputs = loadVerifiedAuthorityInputs({
    authorityDigest: exactArg('authority-digest'),
    authorityPacketDigest: exactArg('authority-packet-digest'),
    authorityPacketPath: resolve(repositoryRoot, exactArg('authority-packet')),
    authorityProjectionDigest: exactArg('authority-projection-digest'),
    authorityProjectionPath: resolve(repositoryRoot, exactArg('authority-projection')),
  });
  if (process.argv.includes('--foundation-only')) {
    const foundationFixtureInputs = loadFoundationFixtureInputs({ authorityInputs, repositoryRoot });
    const assessment = assessFoundationDomainClosure({ foundationFixtureInputs, repositoryRoot });
    const content = `${canonicalJson(assessment)}\n`;
    const outputPath = join('.work', 'generated', `foundation-domain-closure-assessment-${sha256(content).slice('sha256:'.length)}.json`);
    mkdirSync(dirname(join(repositoryRoot, outputPath)), { recursive: true });
    writeFileSync(join(repositoryRoot, outputPath), content);
    process.stdout.write(`${canonicalJson({
      assessmentDigest: assessment.assessmentDigest,
      emptyDomainCount: assessment.diagnostics.length,
      familyCount: assessment.familyCount,
      foundationVerdict: assessment.foundationVerdict,
      outputPath,
      totalCombinationCount: assessment.familyRecords.reduce((sum, family) => sum + family.combinationCount, 0),
    })}\n`);
  } else {
    const censusPath = resolve(repositoryRoot, exactArg('census'));
    const censusDigest = exactArg('census-digest');
    if (sha256(readFileSync(censusPath)) !== censusDigest) fail('CENSUS_FILE_DIGEST_MISMATCH', 'census file bytes do not match');
    const census = JSON.parse(readFileSync(censusPath, 'utf8'));
    if (process.argv.includes('--sparse-from-manifest')) {
    const rawManifestPath = resolve(repositoryRoot, exactArg('raw-manifest'));
    const rawManifestDigest = exactArg('raw-manifest-digest');
    const rawManifestBytes = readFileSync(rawManifestPath);
    if (sha256(rawManifestBytes) !== rawManifestDigest) {
      fail('UNIVERSE_MANIFEST_FILE_DIGEST_MISMATCH', 'raw manifest file bytes do not match');
    }
    const exactIntegerArg = (name) => {
      const value = Number(exactArg(name));
      if (!Number.isSafeInteger(value) || value < 0) fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', `${name} is invalid`);
      return value;
    };
    const sparseManifest = generateSparseSymbolicManifest({
      authorityInputs,
      census,
      liveTripleCount: exactIntegerArg('live-triple-count'),
      providerEdgeLimit: exactIntegerArg('provider-edge-limit'),
      publicationReserve: exactIntegerArg('publication-reserve'),
      rawManifest: JSON.parse(rawManifestBytes.toString('utf8')),
      rawManifestDigest,
      repositoryRoot,
    });
    const content = `${canonicalJson(sparseManifest)}\n`;
    const outputPath = join('.work', 'generated', `permutation-sparse-symbolic-manifest-${sha256(content).slice('sha256:'.length)}.json`);
    mkdirSync(dirname(join(repositoryRoot, outputPath)), { recursive: true });
    writeFileSync(join(repositoryRoot, outputPath), content);
    process.stdout.write(`${canonicalJson({
      operationalCellCount: sparseManifest.operationalCellCount,
      outputPath,
      pendingCoveredCellCount: sparseManifest.pendingCoveredCellCount,
      pendingRegionCount: sparseManifest.pendingRegionCount,
      projectedTripleUpperBound: sparseManifest.publicationBudget.projectedTripleUpperBound,
      rawCandidateCount: sparseManifest.rawCandidateCount,
      ruleCoveredCellCount: sparseManifest.ruleCoveredCellCount,
      ruleRegionCount: sparseManifest.ruleRegionCount,
      sparseManifestDigest: sparseManifest.sparseManifestDigest,
      verdict: sparseManifest.verdict,
    })}\n`);
    } else if (process.argv.includes('--plan-only')) {
    const plan = planUniverse({ authorityInputs, census, repositoryRoot });
    const report = buildDispositionGapReport(plan);
    const content = `${canonicalJson(report)}\n`;
    const outputPath = join('.work', 'generated', `permutation-disposition-gap-report-${sha256(content).slice('sha256:'.length)}.json`);
    mkdirSync(dirname(join(repositoryRoot, outputPath)), { recursive: true });
    writeFileSync(join(repositoryRoot, outputPath), content);
    process.stdout.write(`${canonicalJson({
      finiteDomainGapCount: plan.gaps.length,
      outputPath,
      reportDigest: report.reportDigest,
      requiredPairCount: plan.requiredPairCount,
      totalExpectedCellCount: plan.totalExpectedCellCount,
      verdict: report.verdict,
    })}\n`);
    } else {
    const universe = generateUniverseManifest({ authorityInputs, census, repositoryRoot });
    const content = `${canonicalJson(universe)}\n`;
    const outputPath = join('.work', 'generated', `permutation-cell-universe-manifest-${sha256(content).slice('sha256:'.length)}.json`);
    mkdirSync(dirname(join(repositoryRoot, outputPath)), { recursive: true });
    writeFileSync(join(repositoryRoot, outputPath), content);
    process.stdout.write(`${canonicalJson({
      cellCount: universe.cellCount,
      cellSegmentCount: universe.cellSegments.length,
      familiesGenerated: universe.familiesGenerated,
      finiteDomainGapCount: universe.gaps.length,
      outputPath,
      permissionAtomCandidateCount: universe.permissionAtomCandidateCount,
      permissionAtomSourceCellCount: universe.permissionAtomSourceCellCount,
      structuralVerdict: universe.structuralVerdict,
      universeDigest: universe.universeDigest,
    })}\n`);
    }
  }
}
