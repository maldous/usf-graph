// Independent permutation-universe verifier.
//
// This module intentionally does not import the universe generator or any of
// its expansion helpers. It reconstructs finite domains, identities and
// dispositions from the verified authority projection and the bounded
// permutation meta-model, ontology and shape files, then compares that reconstruction with every
// byte in the generated segmented universe.

import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import N3 from 'n3';
import {
  canonicalJson,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import {
  AuthorityProjectionIndex,
  assertVerifiedAuthorityInputs,
  loadVerifiedAuthorityInputs,
} from './family-census.mjs';

const O = 'urn:usf:ontology:';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const RDF_PROPERTY = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#Property';
const RDFS_CLASS = 'http://www.w3.org/2000/01/rdf-schema#Class';
const RDFS_SUBCLASS_OF = 'http://www.w3.org/2000/01/rdf-schema#subClassOf';
const OWL_CLASS = 'http://www.w3.org/2002/07/owl#Class';
const OWL_PROPERTY_KINDS = Object.freeze([
  'http://www.w3.org/2002/07/owl#AnnotationProperty',
  'http://www.w3.org/2002/07/owl#DatatypeProperty',
  'http://www.w3.org/2002/07/owl#ObjectProperty',
]);
const CELL_PREFIX = 'urn:usf:permutationcell:';
const FAMILY_PREFIX = 'urn:usf:permutationfamily:';
const FOUNDATION_FIXTURE_RELATIVE_PATH = 'semantic-model/fixtures/conforming/universal-service-foundation.trig';
const FOUNDATION_FIXTURE_SCOPE = 'FOUNDATION_CONFORMANCE_FIXTURE';
const VERIFIED_FOUNDATION_PROOF_INPUTS = new WeakSet();
const modulePath = fileURLToPath(import.meta.url);
const generatorPath = join(dirname(modulePath), 'universe-generator.mjs');
const ALGORITHM_DEPENDENCY_FILES = Object.freeze([
  'assurance/permutation-closure/family-census.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation.mjs',
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
const META_MODEL_GRAPHS = new Set([
  'urn:usf:graph:permutation-actions',
  'urn:usf:graph:permutation-families',
  'urn:usf:graph:permutation-transports',
  'urn:usf:graph:permutation-vocabulary',
  'urn:usf:graph:vocabulary',
]);
const META_MODEL_FILE_GRAPHS = Object.freeze({
  'semantic-model/ontology.ttl': 'urn:usf:graph:ontology',
  'semantic-model/vocabulary.ttl': 'urn:usf:graph:vocabulary',
});
const SOURCE_KIND = new Set(['classinstances', 'controlledlist', 'derivedselector']);
const SOURCE_SCOPE = new Set([
  'urn:usf:dimensionvaluesourcescope:authorityinstanceset',
  'urn:usf:dimensionvaluesourcescope:capabilityrelationship',
  'urn:usf:dimensionvaluesourcescope:downstreamclosure',
  'urn:usf:dimensionvaluesourcescope:foundationcatalogue',
  'urn:usf:dimensionvaluesourcescope:registeredsubjectrelationship',
]);
const DERIVATION_OPERATOR = new Set([
  'urn:usf:permutationvaluederivationoperator:classinstances',
  'urn:usf:permutationvaluederivationoperator:filterpathexists',
  'urn:usf:permutationvaluederivationoperator:filterpathvaluein',
  'urn:usf:permutationvaluederivationoperator:filtertypeany',
  'urn:usf:permutationvaluederivationoperator:inbound',
  'urn:usf:permutationvaluederivationoperator:outbound',
  'urn:usf:permutationvaluederivationoperator:subject',
  'urn:usf:permutationvaluederivationoperator:union',
]);
const DERIVATION_SCOPE = new Set([
  'urn:usf:permutationvaluederivationinputscope:all',
  'urn:usf:permutationvaluederivationinputscope:foundationconformancefixture',
  'urn:usf:permutationvaluederivationinputscope:liveauthority',
]);
const NAMED_NODE_TERMINAL = 'urn:usf:permutationvalueterminalkind:namednode';
const CLASS_CLOSURE_POLICIES = Object.freeze({
  exact: 'urn:usf:classclosurepolicy:exactdeclaredclass',
  transitive: 'urn:usf:classclosurepolicy:declaredtransitivesubclass',
});
const DISPOSITIONS = Object.freeze({
  allowed: 'urn:usf:permutationclosuredisposition:allowed',
  deferred: 'urn:usf:permutationclosuredisposition:deferred',
  forbidden: 'urn:usf:permutationclosuredisposition:forbidden',
  notApplicable: 'urn:usf:permutationclosuredisposition:notapplicable',
  required: 'urn:usf:permutationclosuredisposition:required',
  unresolved: 'urn:usf:permutationclosuredisposition:unresolved',
});
const DISPOSITION_SET = new Set(Object.values(DISPOSITIONS));
const EXACT_FAMILY = Object.freeze({
  operationPermission: `${FAMILY_PREFIX}operationpermissionatom`,
  operationRole: `${FAMILY_PREFIX}operationroleconditionprofile`,
  permissionRoleTenant: `${FAMILY_PREFIX}permissionatomroletenantboundary`,
});
const PERMISSION_ATOM_MISSING_PROPERTIES = Object.freeze([
  'action', 'auditCategory', 'resourceClass', 'selectorKind', 'tenantBoundary',
]);
const compareCodeUnits = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const uniqueSorted = (values) => [...new Set(values)].sort();
const fullDigest = (value) => sha256(canonicalJson(value));
function sourceAlgorithmBindings(applicabilityRuleDigest) {
  const repositoryRoot = resolve(dirname(modulePath), '..', '..');
  const dependencySources = ALGORITHM_DEPENDENCY_FILES.map((path) => ({
    digest: sha256(readFileSync(resolve(repositoryRoot, path))),
    path,
  }));
  return {
    applicabilityRuleDigest,
    dependencySourceDigest: fullDigest(dependencySources),
    generatorDigest: sha256(readFileSync(generatorPath)),
    independentVerifierDigest: sha256(readFileSync(modulePath)),
  };
}

class ProofInputError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'ProofInputError';
    this.code = code;
    this.details = details;
  }
}

const fail = (code, message, details = {}) => {
  throw new ProofInputError(code, message, details);
};

function diagnosticCollector() {
  const records = new Map();
  return {
    add(code, item = {}, severity = 'ERROR') {
      if (!records.has(code)) records.set(code, { code, count: 0, items: [], severity });
      const record = records.get(code);
      record.count += 1;
      if (record.items.length < 25) record.items.push(item);
    },
    list() {
      return [...records.values()].sort((left, right) => compareCodeUnits(left.code, right.code));
    },
  };
}

function classifyUniverseKeys(expectedKeys, actualKeys) {
  const diagnostics = diagnosticCollector();
  const expected = new Set(expectedKeys);
  const actual = new Set();
  for (const stableKey of actualKeys) {
    if (actual.has(stableKey)) diagnostics.add('PERMUTATION_UNIVERSE_DUPLICATE_CELL', { stableKey });
    actual.add(stableKey);
    if (!expected.has(stableKey)) diagnostics.add('PERMUTATION_UNIVERSE_EXTRA_CELL', { stableKey });
  }
  for (const stableKey of expected) {
    if (!actual.has(stableKey)) diagnostics.add('PERMUTATION_UNIVERSE_MISSING_CELL', { stableKey });
  }
  if (expected.size > 0 && actualKeys.length === 0) diagnostics.add('PERMUTATION_UNIVERSE_EMPTY');
  return diagnostics.list();
}

function loadIndependentMetaModel(repositoryRoot) {
  const store = new N3.Store();
  const sourceFiles = [];
  for (const path of META_MODEL_FILES) {
    const bytes = readFileSync(join(repositoryRoot, path));
    sourceFiles.push({ digest: sha256(bytes), path });
    const quads = new N3.Parser({ format: path.endsWith('.trig') ? 'application/trig' : 'text/turtle' })
      .parse(bytes.toString('utf8'));
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
  const classClosures = loadIndependentClassClosures(store);
  const metaModel = {
    classClosures,
    coverageRules: loadIndependentCoverageRules(store),
    digest: fullDigest(sourceFiles),
    foundationProjectionRules: loadIndependentFoundationProjectionRules(store),
    publicationBudgetPolicy: loadIndependentPublicationBudgetPolicy(store),
    sourceFiles,
    store,
  };
  metaModel.selectors = loadIndependentSelectors(metaModel);
  metaModel.rules = loadIndependentApplicabilityRules(metaModel);
  metaModel.familyRegistry = reconstructIndependentFamilyRegistry(metaModel);
  return metaModel;
}

const objects = (store, subject, predicate) => store.getQuads(
  N3.DataFactory.namedNode(subject),
  N3.DataFactory.namedNode(predicate.startsWith('urn:') || predicate.startsWith('http') ? predicate : `${O}${predicate}`),
  null,
  null,
).map(({ object }) => object);
const values = (store, subject, predicate) => uniqueSorted(objects(store, subject, predicate).map(({ value }) => value));
const iriValues = (store, subject, predicate) => {
  const found = objects(store, subject, predicate);
  if (found.some(({ termType }) => termType !== 'NamedNode')) {
    fail('PERMUTATION_META_MODEL_INVALID', `${subject} ${predicate} must contain only IRIs`);
  }
  return uniqueSorted(found.map(({ value }) => value));
};
const metaInstances = (store, classIri) => uniqueSorted(store.getQuads(
  null,
  N3.DataFactory.namedNode(RDF_TYPE),
  N3.DataFactory.namedNode(classIri),
  null,
).filter(({ graph }) => META_MODEL_GRAPHS.has(graph.value)).map(({ subject }) => subject.value));

const fixtureQuadRecord = ({ subject, predicate, object, graph }) => [
  subject.value,
  predicate.value,
  object.termType === 'NamedNode' ? 'iri' : 'literal',
  object.value,
  object.termType === 'Literal' ? object.datatype.value : null,
  object.termType === 'Literal' && object.language ? object.language : null,
  graph.value,
];

function independentFoundationFixtureDigest(quads) {
  return fullDigest(quads
    .filter(({ predicate }) => predicate.value !== `${O}foundationFixtureDigest`)
    .map(fixtureQuadRecord)
    .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right))));
}

function isFoundationProofInputs(inputs) {
  return Boolean(inputs && VERIFIED_FOUNDATION_PROOF_INPUTS.has(inputs));
}

function loadIndependentFoundationFixture({ authorityInputs, repositoryRoot }) {
  const authority = assertVerifiedAuthorityInputs(authorityInputs);
  const fixturePath = resolve(repositoryRoot, FOUNDATION_FIXTURE_RELATIVE_PATH);
  const authorisedRoot = resolve(repositoryRoot, 'semantic-model', 'fixtures', 'conforming');
  if (!existsSync(fixturePath) || !lstatSync(fixturePath).isFile() || lstatSync(fixturePath).isSymbolicLink()
    || !realpathSync(fixturePath).startsWith(`${realpathSync(authorisedRoot)}/`)) {
    fail('FOUNDATION_FIXTURE_PATH_INVALID', 'the independent proof requires the canonical regular fixture file');
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
    || quads.some(({ graph }) => graph.termType !== 'NamedNode')) {
    fail('FOUNDATION_FIXTURE_GRAPH_INVALID', 'fixture statements must occupy one explicit named graph');
  }
  if (quads.some(({ subject, predicate, object }) => subject.termType !== 'NamedNode'
    || predicate.termType !== 'NamedNode'
    || !['NamedNode', 'Literal'].includes(object.termType))) {
    fail('FOUNDATION_FIXTURE_TERM_INVALID', 'fixture terms must be canonical named nodes or literals');
  }
  const named = N3.DataFactory.namedNode;
  const store = new N3.Store(quads);
  const roots = uniqueSorted(store.getQuads(null, named(RDF_TYPE), named(`${O}FoundationConformanceFixture`), null)
    .map(({ subject }) => subject.value));
  if (roots.length !== 1) fail('FOUNDATION_FIXTURE_ROOT_CARDINALITY', 'fixture must have exactly one root');
  const fixtureRoot = roots[0];
  if (canonicalJson(values(store, fixtureRoot, 'foundationConformanceOnly')) !== canonicalJson(['true'])) {
    fail('FOUNDATION_FIXTURE_SCOPE_INVALID', 'fixture must be explicitly conformance-only');
  }
  const primaryCapabilities = values(store, fixtureRoot, 'foundationFixturePrimaryCapability');
  if (primaryCapabilities.length !== 1
    || store.getQuads(named(primaryCapabilities[0]), named(RDF_TYPE), named(`${O}Capability`), null).length !== 1) {
    fail('FOUNDATION_FIXTURE_PRIMARY_CAPABILITY_INVALID', 'fixture root must select one explicitly typed primary capability');
  }
  const primarySubjects = values(store, fixtureRoot, 'foundationFixturePrimarySubject');
  if (primarySubjects.length === 0 || new Set(primarySubjects).size !== primarySubjects.length
    || !primarySubjects.includes(primaryCapabilities[0])) {
    fail('FOUNDATION_FIXTURE_PRIMARY_SUBJECT_SET_INVALID',
      'fixture root must select a unique primary subject set containing its primary capability');
  }
  const digestStatements = store.getQuads(null, named(`${O}foundationFixtureDigest`), null, null);
  const semanticDigest = independentFoundationFixtureDigest(quads);
  if (digestStatements.length !== 1 || digestStatements[0].subject.value !== fixtureRoot
    || digestStatements[0].object.value !== semanticDigest) {
    fail('FOUNDATION_FIXTURE_DIGEST_MISMATCH', 'fixture semantic digest is absent, duplicated or stale');
  }
  const prohibitedPredicates = new Set([
    `${O}grantsPermission`, `${O}cellTokenScope`, `${O}pathTokenScope`, `${O}profileScope`, `${O}scopePermissionAtom`,
    `${O}cellAuthorityDigest`, `${O}reachabilityAuthorityDigest`, `${O}cellAuthorisationPath`, `${O}cellPermissionAtom`,
  ]);
  const prohibitedTypes = new Set([
    `${O}AuthorisationPath`, `${O}PermissionAtom`, `${O}PermissionAtomCandidate`, `${O}RolePermissionDisposition`, `${O}TokenScope`,
  ]);
  const operationalTypes = new Set([...prohibitedTypes, `${O}ActionReachability`, `${O}PermutationCell`]);
  const ontology = new N3.Store(new N3.Parser({ format: 'text/turtle' })
    .parse(readFileSync(resolve(repositoryRoot, 'semantic-model', 'ontology.ttl'), 'utf8')));
  const domainPredicate = named('http://www.w3.org/2000/01/rdf-schema#domain');
  const rangePredicate = named('http://www.w3.org/2000/01/rdf-schema#range');
  if (quads.some(({ predicate, object }) => prohibitedPredicates.has(predicate.value)
    || (predicate.value === RDF_TYPE && operationalTypes.has(object.value))
    || ontology.getQuads(predicate, domainPredicate, null, null).some(({ object: domain }) => operationalTypes.has(domain.value))
    || (object.termType === 'NamedNode'
      && ontology.getQuads(predicate, rangePredicate, null, null).some(({ object: range }) => operationalTypes.has(range.value))))) {
    fail('FOUNDATION_FIXTURE_AUTHORISATION_PROHIBITED', 'fixture cannot carry operational authorisation state');
  }
  const triples = quads.map(fixtureQuadRecord).map((record) => record.slice(0, 6))
    .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  if (new Set(triples.map((record) => canonicalJson(record))).size !== triples.length) {
    fail('FOUNDATION_FIXTURE_TRIPLE_DUPLICATE', 'fixture contains duplicate semantic statements');
  }
  const projectedClassIris = uniqueSorted(quads
    .filter(({ predicate, object }) => predicate.value === RDF_TYPE && object.termType === 'NamedNode')
    .map(({ object }) => object.value));
  const projectedPredicateIris = uniqueSorted(quads.map(({ predicate }) => predicate.value));
  const operationClassBindings = [[`${O}Operation`, null]];
  for (const operationClass of [`${O}Command`, `${O}GatewayOperation`, `${O}Operation`, `${O}Query`]) {
    for (const operation of uniqueSorted(store.getQuads(null, named(RDF_TYPE), named(operationClass), null)
      .map(({ subject }) => subject.value))) {
      operationClassBindings.push([operationClass, operation]);
    }
  }
  operationClassBindings.sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  const fixtureProjection = {
    gatewayOperationCapabilityBindings: [],
    operationClassBindings,
    projectedClassIris,
    projectedPredicateIris,
    triples,
  };
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
    foundationFixtureProjectionDigest: fullDigest(fixtureProjection),
    foundationFixtureRoot: fixtureRoot,
    foundationFixturePrimaryCapability: primaryCapabilities[0],
    foundationFixturePrimarySubjects: primarySubjects,
    foundationConformanceOnly: true,
    inputMode: FOUNDATION_FIXTURE_SCOPE,
    nonClaims,
    purpose: 'FINITE_DOMAIN_EXPRESSIBILITY_ONLY',
    recordKind: 'USF_FOUNDATION_CONFORMANCE_FIXTURE_INPUT',
    schemaVersion: 2,
  };
  const fixture = Object.freeze({
    ...core,
    fixtureInputDigest: fullDigest(core),
    fixtureProjection,
    index: new AuthorityProjectionIndex(fixtureProjection),
    store,
  });
  VERIFIED_FOUNDATION_PROOF_INPUTS.add(fixture);
  return fixture;
}

function oneIndependentValue(store, subject, predicate, code) {
  const found = values(store, subject, predicate);
  if (found.length !== 1) fail(code, `${subject} must have exactly one ${predicate}`);
  return found[0];
}

function oneIndependentIri(store, subject, predicate, code) {
  const found = iriValues(store, subject, predicate);
  if (found.length !== 1) fail(code, `${subject} must have exactly one IRI-valued ${predicate}`);
  return found[0];
}

function independentlyDeclaredClass(store, classIri) {
  return classIri === OWL_CLASS || [OWL_CLASS, RDFS_CLASS].some((kind) => (
    store.countQuads(N3.DataFactory.namedNode(classIri), N3.DataFactory.namedNode(RDF_TYPE),
      N3.DataFactory.namedNode(kind), null) > 0
  ));
}

function independentlyDeclaredProperty(store, predicateIri) {
  return predicateIri === RDF_TYPE || [RDF_PROPERTY, ...OWL_PROPERTY_KINDS].some((kind) => (
    store.countQuads(N3.DataFactory.namedNode(predicateIri), N3.DataFactory.namedNode(RDF_TYPE),
      N3.DataFactory.namedNode(kind), null) > 0
  ));
}

function independentClassClosureCanonicalRecord({ rootClassIri, policyIri, memberClassIris, subclassEdges }) {
  return {
    memberClassIris,
    policyIri,
    rootClassIri,
    schemaVersion: 1,
    subclassEdges,
  };
}

function independentlyReconstructClassClosure(store, rootClassIri, policyIri) {
  if (!independentlyDeclaredClass(store, rootClassIri)) {
    fail('CLASS_CLOSURE_ROOT_UNDECLARED', `${rootClassIri} is not a declared named class`);
  }
  if (![CLASS_CLOSURE_POLICIES.exact, CLASS_CLOSURE_POLICIES.transitive].includes(policyIri)) {
    fail('CLASS_CLOSURE_POLICY_UNCONTROLLED', `${rootClassIri} uses ${policyIri}`);
  }
  const members = new Set([rootClassIri]);
  const active = new Set();
  const visit = (classIri) => {
    if (active.has(classIri)) fail('CLASS_CLOSURE_CYCLE', `${rootClassIri} contains a cycle at ${classIri}`);
    active.add(classIri);
    const children = store.getSubjects(
      N3.DataFactory.namedNode(RDFS_SUBCLASS_OF), N3.DataFactory.namedNode(classIri), null,
    ).filter(({ termType }) => termType === 'NamedNode').map(({ value }) => value).sort(compareCodeUnits);
    for (const child of children) {
      if (!independentlyDeclaredClass(store, child)) {
        fail('CLASS_CLOSURE_ROOT_UNDECLARED', `${child} is not a declared named class`);
      }
      if (!members.has(child)) {
        members.add(child);
        visit(child);
      } else if (active.has(child)) {
        fail('CLASS_CLOSURE_CYCLE', `${rootClassIri} contains a cycle at ${child}`);
      }
    }
    active.delete(classIri);
  };
  if (policyIri === CLASS_CLOSURE_POLICIES.transitive) visit(rootClassIri);
  const memberClassIris = [...members].sort(compareCodeUnits);
  const memberSet = new Set(memberClassIris);
  const subclassEdges = policyIri === CLASS_CLOSURE_POLICIES.exact ? [] : store
    .getQuads(null, N3.DataFactory.namedNode(RDFS_SUBCLASS_OF), null, null)
    .filter(({ subject, object }) => subject.termType === 'NamedNode' && object.termType === 'NamedNode'
      && memberSet.has(subject.value) && memberSet.has(object.value))
    .map(({ subject, object }) => [subject.value, object.value])
    .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  return { memberClassIris, subclassEdges };
}

function loadIndependentClassClosures(store) {
  const byIri = new Map();
  const byRoot = new Map();
  for (const closureIri of metaInstances(store, `${O}PermutationClassClosure`)) {
    const rootClassIri = oneIndependentIri(store, closureIri, 'classClosureRootClass',
      'CLASS_CLOSURE_ROOT_CARDINALITY');
    const policyIri = oneIndependentIri(store, closureIri, 'classClosurePolicy',
      'CLASS_CLOSURE_POLICY_MISSING');
    const reconstructed = independentlyReconstructClassClosure(store, rootClassIri, policyIri);
    const declaredMembers = iriValues(store, closureIri, 'classClosureMemberClass');
    const missing = reconstructed.memberClassIris.filter((member) => !declaredMembers.includes(member));
    const unexpected = declaredMembers.filter((member) => !reconstructed.memberClassIris.includes(member));
    if (missing.length) fail('CLASS_CLOSURE_MEMBER_MISSING', `${closureIri} omits members`, { missing });
    if (unexpected.length) fail('CLASS_CLOSURE_MEMBER_UNEXPECTED', `${closureIri} has extra members`, { unexpected });
    const memberSetDigest = fullDigest(declaredMembers);
    const edgeSetDigest = fullDigest(reconstructed.subclassEdges);
    const closureDigest = fullDigest(independentClassClosureCanonicalRecord({
      memberClassIris: declaredMembers,
      policyIri,
      rootClassIri,
      subclassEdges: reconstructed.subclassEdges,
    }));
    if (oneIndependentValue(store, closureIri, 'classClosureMemberSetDigest',
      'CLASS_CLOSURE_MEMBER_SET_DIGEST_MISMATCH') !== memberSetDigest) {
      fail('CLASS_CLOSURE_MEMBER_SET_DIGEST_MISMATCH', `${closureIri} member digest differs`);
    }
    if (oneIndependentValue(store, closureIri, 'classClosureEdgeSetDigest',
      'CLASS_CLOSURE_EDGE_SET_DIGEST_MISMATCH') !== edgeSetDigest) {
      fail('CLASS_CLOSURE_EDGE_SET_DIGEST_MISMATCH', `${closureIri} edge digest differs`);
    }
    if (oneIndependentValue(store, closureIri, 'classClosureDigest',
      'CLASS_CLOSURE_DIGEST_MISMATCH') !== closureDigest) {
      fail('CLASS_CLOSURE_DIGEST_MISMATCH', `${closureIri} closure digest differs`);
    }
    if (byRoot.has(rootClassIri)) fail('CLASS_CLOSURE_POLICY_MULTIPLE', `${rootClassIri} has multiple closures`);
    const closure = Object.freeze({
      digest: closureDigest,
      edgeSetDigest,
      iri: closureIri,
      memberClassIris: Object.freeze(declaredMembers),
      memberSetDigest,
      policyIri,
      rootClassIri,
      subclassEdges: Object.freeze(reconstructed.subclassEdges),
    });
    byIri.set(closureIri, closure);
    byRoot.set(rootClassIri, closure);
  }
  return Object.freeze({ byIri, byRoot, closures: Object.freeze([...byIri.values()]) });
}

function independentOwnerClassClosures(metaModel, ownerIri, predicate, expectedRootIris, code) {
  const closureIris = iriValues(metaModel.store, ownerIri, predicate);
  if (closureIris.length === 0) fail('CLASS_CLOSURE_POLICY_MISSING', `${ownerIri} has no ${predicate}`);
  const closures = closureIris.map((closureIri) => {
    const closure = metaModel.classClosures.byIri.get(closureIri);
    if (!closure) fail(code, `${ownerIri} references unknown closure ${closureIri}`);
    return closure;
  });
  const roots = uniqueSorted(closures.map(({ rootClassIri }) => rootClassIri));
  if (expectedRootIris && canonicalJson(roots) !== canonicalJson(uniqueSorted(expectedRootIris))) {
    fail(code, `${ownerIri} closure roots differ`, { actual: roots, expected: uniqueSorted(expectedRootIris) });
  }
  return closures;
}

function independentResourceHasClosureType(index, resourceIri, closures) {
  return closures.some(({ memberClassIris }) => memberClassIris.some((classIri) => index.isType(resourceIri, classIri)));
}

function independentMetaResourceHasClosureType(store, resourceIri, closures) {
  const exactTypes = new Set(objects(store, resourceIri, RDF_TYPE).map(({ value }) => value));
  return closures.some(({ memberClassIris }) => memberClassIris.some((classIri) => exactTypes.has(classIri)));
}

function independentClosureInstances(authorityInputs, closures) {
  const foundation = isFoundationProofInputs(authorityInputs);
  const output = [];
  for (const closure of closures) {
    for (const classIri of closure.memberClassIris) {
      const projected = authorityInputs.index.projectedClassIris.has(classIri)
        || authorityInputs.index.operationClasses.has(classIri);
      if (!projected) {
        if (foundation) continue;
        fail('CLASS_CLOSURE_MEMBER_NOT_PROJECTED', `${closure.iri} member ${classIri} is absent`);
      }
      output.push(...authorityInputs.index.instances(classIri));
    }
  }
  return uniqueSorted(output);
}

const INDEPENDENT_SELECTOR_AGGREGATIONS = new Set([
  'urn:usf:permutationsignalaggregation:countdistinct',
  'urn:usf:permutationsignalaggregation:distinctvalues',
]);
const INDEPENDENT_PATH_DIRECTIONS = new Set([
  'urn:usf:permutationpathdirection:inbound',
  'urn:usf:permutationpathdirection:outbound',
]);
const INDEPENDENT_APPLICABILITY_OPERATORS = Object.freeze({
  allOf: 'urn:usf:permutationapplicabilityoperator:allof',
  anyOf: 'urn:usf:permutationapplicabilityoperator:anyof',
  countAtLeast: 'urn:usf:permutationapplicabilityoperator:countatleast',
  countExactly: 'urn:usf:permutationapplicabilityoperator:countexactly',
  not: 'urn:usf:permutationapplicabilityoperator:not',
  true: 'urn:usf:permutationapplicabilityoperator:true',
  valueEquals: 'urn:usf:permutationapplicabilityoperator:valueequals',
  valueInDeclaredSet: 'urn:usf:permutationapplicabilityoperator:valueindeclaredset',
});
const INDEPENDENT_APPLICABILITY_OPERATOR_SET = new Set(Object.values(INDEPENDENT_APPLICABILITY_OPERATORS));

function independentCanonicalRdfTerm(term) {
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

function loadIndependentSelectors(metaModel) {
  const selectors = new Map();
  for (const selectorIri of metaInstances(metaModel.store, `${O}PermutationSignalSelector`)) {
    const steps = iriValues(metaModel.store, selectorIri, 'selectorPathStep').map((stepIri) => {
      const rawIndex = oneIndependentValue(metaModel.store, stepIri, 'signalPathStepIndex',
        'SELECTOR_STEP_INDEX_INVALID');
      const index = Number(rawIndex);
      const directionIri = oneIndependentIri(metaModel.store, stepIri, 'signalPathStepDirection',
        'SELECTOR_STEP_DIRECTION_CARDINALITY');
      const predicateIri = oneIndependentIri(metaModel.store, stepIri, 'signalPathStepPredicate',
        'SELECTOR_STEP_PREDICATE_CARDINALITY');
      if (!Number.isSafeInteger(index) || index < 1) {
        fail('SELECTOR_STEP_INDEX_INVALID', `${stepIri} has an invalid index`);
      }
      if (!INDEPENDENT_PATH_DIRECTIONS.has(directionIri)) {
        fail('SELECTOR_STEP_DIRECTION_UNCONTROLLED', `${stepIri} uses ${directionIri}`);
      }
      if (!independentlyDeclaredProperty(metaModel.store, predicateIri)) {
        fail('SELECTOR_STEP_PREDICATE_UNDECLARED', `${stepIri} uses ${predicateIri}`);
      }
      return { directionIri, index, predicateIri, stepIri };
    }).sort((left, right) => left.index - right.index);
    if (steps.length === 0 || !steps.every(({ index }, offset) => index === offset + 1)) {
      fail(steps.length === 0 ? 'SELECTOR_PATH_EMPTY' : 'SELECTOR_PATH_INDEX_INVALID',
        `${selectorIri} has no exact contiguous path`);
    }
    const subjectClassIri = oneIndependentIri(metaModel.store, selectorIri, 'selectorSubjectClass',
      'SELECTOR_SUBJECT_CLASS_CARDINALITY');
    const terminalClassIri = oneIndependentIri(metaModel.store, selectorIri, 'selectorTerminalClass',
      'SELECTOR_TERMINAL_CLASS_CARDINALITY');
    const [subjectClassClosure] = independentOwnerClassClosures(
      metaModel, selectorIri, 'selectorSubjectClassClosure', [subjectClassIri],
      'SELECTOR_SUBJECT_CLASS_CLOSURE_MISMATCH',
    );
    const [terminalClassClosure] = independentOwnerClassClosures(
      metaModel, selectorIri, 'selectorTerminalClassClosure', [terminalClassIri],
      'SELECTOR_TERMINAL_CLASS_CLOSURE_MISMATCH',
    );
    const aggregationIri = oneIndependentIri(metaModel.store, selectorIri, 'selectorAggregation',
      'SELECTOR_AGGREGATION_CARDINALITY');
    if (!INDEPENDENT_SELECTOR_AGGREGATIONS.has(aggregationIri)) {
      fail('SELECTOR_AGGREGATION_UNCONTROLLED', `${selectorIri} uses ${aggregationIri}`);
    }
    const record = {
      aggregationIri,
      canonicalName: oneIndependentValue(metaModel.store, selectorIri, 'canonicalName',
        'SELECTOR_NAME_CARDINALITY'),
      schemaVersion: 2,
      selectorIri,
      steps: steps.map(({ directionIri, index, predicateIri }) => ({ directionIri, index, predicateIri })),
      subjectClassIri,
      subjectClassClosureDigest: subjectClassClosure.digest,
      terminalClassIri,
      terminalClassClosureDigest: terminalClassClosure.digest,
    };
    const digest = fullDigest(record);
    if (oneIndependentValue(metaModel.store, selectorIri, 'selectorDigest', 'SELECTOR_DIGEST_CARDINALITY') !== digest) {
      fail('SELECTOR_DIGEST_MISMATCH', `${selectorIri} has a stale digest`);
    }
    selectors.set(selectorIri, Object.freeze({
      ...record,
      digest,
      steps: Object.freeze(steps),
      subjectClassClosure,
      terminalClassClosure,
    }));
  }
  return selectors;
}

function loadIndependentApplicabilityRules(metaModel) {
  const clauseCache = new Map();
  const clauseRecord = (clauseIri, visiting = new Set()) => {
    if (clauseCache.has(clauseIri)) return clauseCache.get(clauseIri);
    if (visiting.has(clauseIri)) fail('APPLICABILITY_EXPRESSION_CYCLE', `${clauseIri} is cyclic`);
    const operatorIri = oneIndependentIri(metaModel.store, clauseIri, 'applicabilityClauseOperator',
      'APPLICABILITY_OPERATOR_CARDINALITY');
    if (!INDEPENDENT_APPLICABILITY_OPERATOR_SET.has(operatorIri)) {
      fail('APPLICABILITY_OPERATOR_UNSUPPORTED', `${clauseIri} uses ${operatorIri}`);
    }
    const selectorIris = iriValues(metaModel.store, clauseIri, 'applicabilitySignalSelector');
    const thresholdValues = values(metaModel.store, clauseIri, 'applicabilityThreshold');
    const expectedValues = objects(metaModel.store, clauseIri, 'applicabilityExpectedValue')
      .map(independentCanonicalRdfTerm)
      .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
    if (new Set(expectedValues.map(canonicalJson)).size !== expectedValues.length) {
      fail('APPLICABILITY_EXPECTED_VALUE_INVALID', `${clauseIri} repeats an expected value`);
    }
    const next = new Set(visiting).add(clauseIri);
    const operands = iriValues(metaModel.store, clauseIri, 'applicabilityClauseOperand').map((operandIri) => {
      const index = Number(oneIndependentValue(metaModel.store, operandIri, 'applicabilityOperandIndex',
        'APPLICABILITY_OPERAND_INDEX_INVALID'));
      const childIri = oneIndependentIri(metaModel.store, operandIri, 'applicabilityOperandClause',
        'APPLICABILITY_OPERAND_CLAUSE_CARDINALITY');
      if (!Number.isSafeInteger(index) || index < 1) {
        fail('APPLICABILITY_OPERAND_INDEX_INVALID', `${operandIri} has an invalid index`);
      }
      return { childIri, index };
    }).sort((left, right) => left.index - right.index);
    if (!operands.every(({ index }, offset) => index === offset + 1)) {
      fail('APPLICABILITY_OPERAND_INDEX_INVALID', `${clauseIri} operand indexes are not contiguous`);
    }
    const selectorRequired = [INDEPENDENT_APPLICABILITY_OPERATORS.countAtLeast,
      INDEPENDENT_APPLICABILITY_OPERATORS.countExactly, INDEPENDENT_APPLICABILITY_OPERATORS.valueEquals,
      INDEPENDENT_APPLICABILITY_OPERATORS.valueInDeclaredSet].includes(operatorIri);
    const thresholdRequired = [INDEPENDENT_APPLICABILITY_OPERATORS.countAtLeast,
      INDEPENDENT_APPLICABILITY_OPERATORS.countExactly].includes(operatorIri);
    const expectedRequired = [INDEPENDENT_APPLICABILITY_OPERATORS.valueEquals,
      INDEPENDENT_APPLICABILITY_OPERATORS.valueInDeclaredSet].includes(operatorIri);
    const operandRange = operatorIri === INDEPENDENT_APPLICABILITY_OPERATORS.not ? [1, 1]
      : [INDEPENDENT_APPLICABILITY_OPERATORS.allOf, INDEPENDENT_APPLICABILITY_OPERATORS.anyOf]
        .includes(operatorIri) ? [2, Number.POSITIVE_INFINITY] : [0, 0];
    if (selectorIris.length !== (selectorRequired ? 1 : 0)) {
      fail('APPLICABILITY_SELECTOR_CARDINALITY_INVALID', `${clauseIri} selector cardinality is invalid`);
    }
    if (thresholdValues.length !== (thresholdRequired ? 1 : 0)) {
      fail('APPLICABILITY_THRESHOLD_INVALID', `${clauseIri} threshold cardinality is invalid`);
    }
    if ((expectedRequired && expectedValues.length < 1) || (!expectedRequired && expectedValues.length !== 0)
      || (operatorIri === INDEPENDENT_APPLICABILITY_OPERATORS.valueEquals && expectedValues.length !== 1)
      || operands.length < operandRange[0] || operands.length > operandRange[1]) {
      fail('APPLICABILITY_OPERATOR_ARITY_INVALID', `${clauseIri} operator contract is invalid`);
    }
    const selectorIri = selectorIris[0] ?? null;
    const selector = selectorIri ? metaModel.selectors.get(selectorIri) : null;
    if (selectorIri && !selector) fail('APPLICABILITY_SELECTOR_UNKNOWN', `${clauseIri} uses ${selectorIri}`);
    const threshold = thresholdRequired ? Number(thresholdValues[0]) : null;
    if (thresholdRequired && (!Number.isSafeInteger(threshold) || threshold < 0)) {
      fail('APPLICABILITY_THRESHOLD_INVALID', `${clauseIri} threshold is invalid`);
    }
    const record = Object.freeze({
      canonicalName: oneIndependentValue(metaModel.store, clauseIri, 'canonicalName',
        'APPLICABILITY_CLAUSE_NAME_CARDINALITY'),
      clauseIri,
      expectedValues,
      operands: operands.map(({ childIri, index }) => ({ clause: clauseRecord(childIri, next), index })),
      operatorIri,
      selectorDigest: selector?.digest ?? null,
      selectorIri,
      threshold,
    });
    clauseCache.set(clauseIri, record);
    return record;
  };
  const rules = new Map();
  for (const ruleIri of metaInstances(metaModel.store, `${O}PermutationApplicabilityRule`)) {
    const record = {
      canonicalName: oneIndependentValue(metaModel.store, ruleIri, 'canonicalName',
        'APPLICABILITY_RULE_NAME_CARDINALITY'),
      rootClause: clauseRecord(oneIndependentIri(metaModel.store, ruleIri, 'applicabilityRootClause',
        'APPLICABILITY_ROOT_CARDINALITY')),
      ruleIri,
      satisfiedDispositionIri: oneIndependentIri(metaModel.store, ruleIri, 'applicabilitySatisfiedDisposition',
        'APPLICABILITY_SATISFIED_DISPOSITION_CARDINALITY'),
      schemaVersion: 1,
      unsatisfiedDispositionIri: oneIndependentIri(metaModel.store, ruleIri, 'applicabilityUnsatisfiedDisposition',
        'APPLICABILITY_UNSATISFIED_DISPOSITION_CARDINALITY'),
      unsatisfiedReasonIri: oneIndependentIri(metaModel.store, ruleIri, 'applicabilityUnsatisfiedReason',
        'APPLICABILITY_UNSATISFIED_REASON_CARDINALITY'),
    };
    const ruleDigest = fullDigest(record);
    if (oneIndependentValue(metaModel.store, ruleIri, 'applicabilityRuleDigest',
      'APPLICABILITY_RULE_DIGEST_CARDINALITY') !== ruleDigest) {
      fail('RULE_DIGEST_MISMATCH', `${ruleIri} has a stale digest`);
    }
    rules.set(ruleIri, Object.freeze({ ...record, ruleDigest }));
  }
  return rules;
}

function loadIndependentFoundationProjectionRules(store) {
  const identityModes = new Set([
    'urn:usf:foundationprojectionidentitymode:digestshadow',
    'urn:usf:foundationprojectionidentitymode:sourcealias',
  ]);
  const permittedTargets = new Set([`${O}ActionReachability`, `${O}PermissionAtom`, `${O}PermutationCell`]);
  const prohibitedTargets = new Set([
    `${O}cellAuthorityDigest`, `${O}cellDigest`, `${O}cellProofResult`, `${O}cellProvenanceRule`,
    `${O}reachabilityAuthorityDigest`, `${O}reachabilityDigest`,
  ]);
  const domain = 'http://www.w3.org/2000/01/rdf-schema#domain';
  const rules = metaInstances(store, `${O}FoundationConformanceProjectionRule`).map((ruleIri) => {
    const sourceClass = oneIndependentIri(
      store, ruleIri, 'foundationProjectionSourceClass', 'FOUNDATION_PROJECTION_RULE_CARDINALITY',
    );
    const targetClass = oneIndependentIri(
      store, ruleIri, 'foundationProjectionTargetClass', 'FOUNDATION_PROJECTION_RULE_CARDINALITY',
    );
    const identityMode = oneIndependentIri(
      store, ruleIri, 'foundationProjectionIdentityMode', 'FOUNDATION_PROJECTION_RULE_CARDINALITY',
    );
    const structuralOnly = oneIndependentValue(
      store, ruleIri, 'foundationProjectionStructuralOnly', 'FOUNDATION_PROJECTION_RULE_CARDINALITY',
    ) === 'true';
    const sourceIsFixture = store.countQuads(
      N3.DataFactory.namedNode(sourceClass),
      N3.DataFactory.namedNode(RDFS_SUBCLASS_OF),
      N3.DataFactory.namedNode(`${O}Fixture`),
      null,
    ) === 1;
    const targetIsExactOwlClass = store.countQuads(
      N3.DataFactory.namedNode(targetClass),
      N3.DataFactory.namedNode(RDF_TYPE),
      N3.DataFactory.namedNode(OWL_CLASS),
      null,
    ) === 1;
    if (!identityModes.has(identityMode) || !structuralOnly || !permittedTargets.has(targetClass)
      || !sourceIsFixture || !targetIsExactOwlClass) {
      fail('FOUNDATION_PROJECTION_RULE_SCOPE_INVALID', `${ruleIri} is not a bounded structural projection`);
    }
    const mappingIris = iriValues(store, ruleIri, 'foundationProjectionPredicateMapping');
    const mappings = mappingIris.map((mappingIri) => {
      const rawPosition = oneIndependentValue(
        store, mappingIri, 'foundationProjectionMappingPosition', 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE',
      );
      const position = Number(rawPosition);
      const sourcePredicate = oneIndependentIri(
        store, mappingIri, 'foundationProjectionSourcePredicate', 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE',
      );
      const targetPredicate = oneIndependentIri(
        store, mappingIri, 'foundationProjectionTargetPredicate', 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE',
      );
      const mappingCore = { position, sourcePredicate, targetPredicate };
      const mappingDigest = oneIndependentValue(
        store, mappingIri, 'foundationProjectionMappingDigest', 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE',
      );
      const exactSourceDomain = values(store, sourcePredicate, domain);
      const exactTargetDomain = values(store, targetPredicate, domain);
      if (!Number.isSafeInteger(position) || position < 1
        || !independentlyDeclaredProperty(store, sourcePredicate)
        || !independentlyDeclaredProperty(store, targetPredicate)
        || prohibitedTargets.has(targetPredicate)
        || canonicalJson(exactSourceDomain) !== canonicalJson([sourceClass])
        || canonicalJson(exactTargetDomain) !== canonicalJson([targetClass])) {
        fail('FOUNDATION_PROJECTION_DOMAIN_RANGE_MISMATCH', `${mappingIri} is not class-bound`);
      }
      if (mappingDigest !== fullDigest(mappingCore)) {
        fail('FOUNDATION_PROJECTION_DIGEST_MISMATCH', `${mappingIri} digest is stale`);
      }
      return { ...mappingCore, mappingDigest, mappingIri };
    }).sort((left, right) => left.position - right.position);
    const positionsAreExact = mappings.every(({ position }, index) => position === index + 1);
    const mappingsAreUnique = new Set(mappings.map(({ sourcePredicate }) => sourcePredicate)).size === mappings.length
      && new Set(mappings.map(({ targetPredicate }) => targetPredicate)).size === mappings.length;
    const isAlias = identityMode.endsWith(':sourcealias');
    const sourceAliasMappingAllowed = isAlias
      && sourceClass === `${O}FoundationPermissionAtomWitness`
      && targetClass === `${O}PermissionAtom`;
    if (!positionsAreExact || !mappingsAreUnique || (!isAlias && mappings.length === 0)
      || (isAlias && ((mappings.length !== 0 && !sourceAliasMappingAllowed)
        || (sourceAliasMappingAllowed && mappings.length === 0)))) {
      fail('FOUNDATION_PROJECTION_MAPPING_INCOMPLETE', `${ruleIri} has no exact ordered mapping set`);
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
    const ruleDigest = oneIndependentValue(
      store, ruleIri, 'foundationProjectionRuleDigest', 'FOUNDATION_PROJECTION_RULE_CARDINALITY',
    );
    if (ruleDigest !== fullDigest(core)) {
      fail('FOUNDATION_PROJECTION_DIGEST_MISMATCH', `${ruleIri} digest is stale`);
    }
    return { ...core, ruleDigest, ruleIri };
  }).sort((left, right) => compareCodeUnits(left.ruleIri, right.ruleIri));
  if (rules.length === 0 || new Set(rules.map(({ targetClass }) => targetClass)).size !== rules.length) {
    fail('FOUNDATION_PROJECTION_RULE_CARDINALITY', 'each structural target class must have one rule');
  }
  const specification = rules.map(({ ruleDigest, ruleIri, ...rule }) => ({ ...rule, ruleDigest }));
  return { digest: fullDigest(specification), records: rules, specification };
}

function independentlyBuildFoundationStructuralProjection(metaModel, fixture) {
  const tripleMap = new Map(fixture.fixtureProjection.triples
    .map((record) => [canonicalJson(record), record]));
  const emittedMap = new Map();
  const projectedBySource = new Map();
  for (const rule of metaModel.foundationProjectionRules.records) {
    const sources = uniqueSorted(fixture.store.getQuads(
      null,
      N3.DataFactory.namedNode(RDF_TYPE),
      N3.DataFactory.namedNode(rule.sourceClass),
      null,
    ).map(({ subject }) => subject.value));
    for (const source of sources) {
      const target = rule.identityMode.endsWith(':sourcealias')
        ? source
        : `urn:usf:foundationprojection:${fullDigest({
          ruleDigest: rule.ruleDigest,
          source,
          targetClass: rule.targetClass,
        }).slice('sha256:'.length)}`;
      if (!projectedBySource.has(source)) projectedBySource.set(source, new Set());
      projectedBySource.get(source).add(target);
      const emit = (record) => {
        const key = canonicalJson(record);
        tripleMap.set(key, record);
        emittedMap.set(key, record);
      };
      emit([target, RDF_TYPE, 'iri', rule.targetClass, null, null]);
      for (const mapping of rule.mappings) {
        const objectsForMapping = fixture.store.getQuads(
          N3.DataFactory.namedNode(source),
          N3.DataFactory.namedNode(mapping.sourcePredicate),
          null,
          null,
        ).map(({ object }) => object);
        if (objectsForMapping.length === 0
          || objectsForMapping.some(({ termType }) => termType !== 'NamedNode')) {
          fail('FOUNDATION_PROJECTION_MAPPING_INCOMPLETE',
            `${source} lacks named-node values for ${mapping.sourcePredicate}`);
        }
        for (const object of objectsForMapping) {
          emit([target, mapping.targetPredicate, 'iri', object.value, null, null]);
        }
      }
    }
  }
  const projection = {
    gatewayOperationCapabilityBindings: fixture.fixtureProjection.gatewayOperationCapabilityBindings,
    operationClassBindings: fixture.fixtureProjection.operationClassBindings,
    projectedClassIris: uniqueSorted([
      ...fixture.fixtureProjection.projectedClassIris,
      ...metaModel.foundationProjectionRules.records.map(({ targetClass }) => targetClass),
    ]),
    projectedPredicateIris: uniqueSorted([
      ...fixture.fixtureProjection.projectedPredicateIris,
      ...metaModel.foundationProjectionRules.records.flatMap(({ mappings }) => (
        mappings.map(({ targetPredicate }) => targetPredicate)
      )),
    ]),
    triples: [...tripleMap.values()]
      .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right))),
  };
  const projectionCore = {
    foundationFixtureInputDigest: fixture.fixtureInputDigest,
    projectionRuleSetDigest: metaModel.foundationProjectionRules.digest,
    projectedRecordCount: emittedMap.size,
    projection,
    recordKind: 'USF_FOUNDATION_STRUCTURAL_SELECTOR_PROJECTION',
    structuralOnly: true,
  };
  return {
    ...projectionCore,
    index: new AuthorityProjectionIndex(projection),
    projectedBySource: new Map([...projectedBySource]
      .map(([source, targets]) => [source, [...targets].sort(compareCodeUnits)])),
    projectionDigest: fullDigest(projectionCore),
  };
}

function loadIndependentCoverageRules(store) {
  const records = metaInstances(store, `${O}PermutationCoverageRule`).map((resource) => {
    const record = {
      disposition: oneIndependentValue(store, resource, 'coverageRuleDisposition', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
      families: values(store, resource, 'coverageRuleForFamily'),
      predicate: oneIndependentValue(store, resource, 'coverageRuleAuthorityPredicate', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
      reasonCode: oneIndependentValue(store, resource, 'coverageRuleReasonCode', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
      ruleKind: oneIndependentValue(store, resource, 'coverageRuleKind', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
      testedDimensionKey: oneIndependentValue(store, resource, 'coverageRuleTestedDimensionKey', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED'),
    };
    const declaredDigest = oneIndependentValue(store, resource, 'coverageRuleDigest', 'PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED');
    if (record.families.length === 0 || declaredDigest !== fullDigest(record)) {
      fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', `${resource} has an invalid family set or digest`);
    }
    return { ...record, declaredDigest, resource };
  }).sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  if (records.length === 0) fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', 'no symbolic coverage rules are registered');
  const specification = records.map(({ declaredDigest: omittedDigest, resource: omittedResource, ...record }) => record);
  return { digest: fullDigest(specification), records, specification };
}

function loadIndependentPublicationBudgetPolicy(store) {
  const universes = metaInstances(store, `${O}PermutationUniverse`);
  if (universes.length !== 1) fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'exactly one permutation universe is required');
  const universe = universes[0];
  if (oneIndependentValue(store, universe, 'universeClosureRepresentation', 'PERMUTATION_PUBLICATION_BUDGET_INVALID')
    !== 'urn:usf:permutationclosurerepresentation:sparsesymbolic') {
    fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'universe does not use sparse symbolic closure');
  }
  const policyIri = oneIndependentValue(store, universe, 'universePublicationBudget', 'PERMUTATION_PUBLICATION_BUDGET_INVALID');
  const integer = (predicate) => {
    const result = Number(oneIndependentValue(store, policyIri, predicate, 'PERMUTATION_PUBLICATION_BUDGET_INVALID'));
    if (!Number.isSafeInteger(result) || result < 0) fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', `${predicate} is invalid`);
    return result;
  };
  const core = {
    encodingPolicy: {
      fixedManifestTripleUpperBound: integer('publicationFixedManifestStatementUpperBound'),
      operationalCellTripleUpperBound: integer('publicationOperationalCellStatementUpperBound'),
      regionTripleUpperBound: integer('publicationCoverageRegionStatementUpperBound'),
    },
    failClosed: oneIndependentValue(store, policyIri, 'publicationBudgetFailClosed', 'PERMUTATION_PUBLICATION_BUDGET_INVALID') === 'true',
    hardStatementLimit: integer('publicationHardStatementLimit'),
    maximumProjectedStatementCount: integer('publicationMaximumProjectedStatementCount'),
    policyIri,
    provider: oneIndependentValue(store, policyIri, 'publicationBudgetForProvider', 'PERMUTATION_PUBLICATION_BUDGET_INVALID'),
    reserveStatementCount: integer('publicationReservedStatementCount'),
  };
  const declaredDigest = oneIndependentValue(store, policyIri, 'publicationBudgetDigest', 'PERMUTATION_PUBLICATION_BUDGET_INVALID');
  if (!core.failClosed || core.hardStatementLimit !== 1_000_000
    || core.maximumProjectedStatementCount !== core.hardStatementLimit - core.reserveStatementCount
    || declaredDigest !== fullDigest(core)) {
    fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', 'publication budget policy or digest is invalid');
  }
  return { ...core, digest: declaredDigest };
}

function contractForCapability(index, capability) {
  const contracts = index.values(capability, `${O}hasContract`);
  if (contracts.length !== 1) fail('PERMUTATION_META_MODEL_INVALID', `${capability} has ${contracts.length} contracts`);
  return contracts[0];
}

function operationClosure(authorityInputs) {
  const projection = isFoundationProofInputs(authorityInputs)
    ? authorityInputs.fixtureProjection
    : authorityInputs.authorityProjection;
  const bindings = projection.operationClassBindings ?? [];
  const classes = uniqueSorted(bindings.map(([operationClass]) => operationClass));
  const operations = new Set(bindings.flatMap(([, operation]) => operation === null ? [] : [operation]));
  if (!classes.includes(`${O}Operation`)) fail('PERMUTATION_META_MODEL_INVALID', 'Operation root is absent');
  return { classes, operations };
}

function operationsForCapability(authorityInputs, capability) {
  const { index } = authorityInputs;
  const contract = contractForCapability(index, capability);
  const interfaces = index.subjects(`${O}interfaceForContract`, contract);
  const interfaceOperations = interfaces.flatMap((surface) => index.values(surface, `${O}hasOperation`));
  const gateways = index.gatewayOperationsByCapability.get(capability) ?? [];
  const selected = uniqueSorted([...interfaceOperations, ...gateways]);
  const closure = operationClosure(authorityInputs);
  for (const operation of selected) {
    if (!closure.operations.has(operation)) {
      fail('PERMUTATION_META_MODEL_INVALID', `${operation} is outside the Operation closure`);
    }
  }
  return selected;
}

function reconstructDerivation(metaModel, expressionIri, cache = new Map(), stack = new Set()) {
  const { store } = metaModel;
  if (cache.has(expressionIri)) return cache.get(expressionIri);
  if (stack.has(expressionIri)) fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} is cyclic`);
  const operatorIri = oneIndependentIri(store, expressionIri, 'valueDerivationOperator',
    'PERMUTATION_META_MODEL_INVALID');
  const inputScopeIri = oneIndependentIri(store, expressionIri, 'valueDerivationInputScope',
    'PERMUTATION_META_MODEL_INVALID');
  if (!DERIVATION_OPERATOR.has(operatorIri) || !DERIVATION_SCOPE.has(inputScopeIri)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} uses an uncontrolled operator or scope`);
  }
  const next = new Set(stack).add(expressionIri);
  const operands = iriValues(store, expressionIri, 'valueDerivationOperand').map((operandIri) => {
    const indexValues = values(store, operandIri, 'valueDerivationOperandIndex');
    const childValues = iriValues(store, operandIri, 'valueDerivationOperandExpression');
    if (indexValues.length !== 1 || childValues.length !== 1 || !Number.isInteger(Number(indexValues[0]))
      || Number(indexValues[0]) < 1) {
      fail('PERMUTATION_META_MODEL_INVALID', `${operandIri} has an invalid operand binding`);
    }
    return { child: reconstructDerivation(metaModel, childValues[0], cache, next), index: Number(indexValues[0]) };
  }).sort((left, right) => left.index - right.index);
  if (!operands.every(({ index }, offset) => index === offset + 1)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} operand indexes are not contiguous`);
  }
  const predicateIris = iriValues(store, expressionIri, 'valueDerivationPredicate');
  const classIris = iriValues(store, expressionIri, 'valueDerivationClass');
  const allowedValueIris = iriValues(store, expressionIri, 'valueDerivationAllowedValue');
  const pathSteps = iriValues(store, expressionIri, 'valueDerivationPathStep').map((stepIri) => {
    const indexes = values(store, stepIri, 'signalPathStepIndex');
    const predicates = iriValues(store, stepIri, 'signalPathStepPredicate');
    const directions = iriValues(store, stepIri, 'signalPathStepDirection');
    if (indexes.length !== 1 || predicates.length !== 1 || directions.length !== 1
      || !Number.isInteger(Number(indexes[0])) || Number(indexes[0]) < 1) {
      fail('PERMUTATION_META_MODEL_INVALID', `${stepIri} has invalid path metadata`);
    }
    return { directionIri: directions[0], index: Number(indexes[0]), predicateIri: predicates[0] };
  }).sort((left, right) => left.index - right.index);
  if (!pathSteps.every(({ index }, offset) => index === offset + 1)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} path indexes are not contiguous`);
  }
  const zero = new Set([
    'urn:usf:permutationvaluederivationoperator:subject',
    'urn:usf:permutationvaluederivationoperator:classinstances',
  ]);
  const unary = new Set([
    'urn:usf:permutationvaluederivationoperator:outbound',
    'urn:usf:permutationvaluederivationoperator:inbound',
    'urn:usf:permutationvaluederivationoperator:filtertypeany',
    'urn:usf:permutationvaluederivationoperator:filterpathexists',
    'urn:usf:permutationvaluederivationoperator:filterpathvaluein',
  ]);
  if ((zero.has(operatorIri) && operands.length !== 0)
    || (unary.has(operatorIri) && operands.length !== 1)
    || (operatorIri.endsWith(':union') && operands.length < 2)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} operator arity is invalid`);
  }
  const traversal = operatorIri.endsWith(':outbound') || operatorIri.endsWith(':inbound');
  if (predicateIris.length !== (traversal ? 1 : 0)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} predicate cardinality is invalid`);
  }
  if (predicateIris.some((predicateIri) => !independentlyDeclaredProperty(store, predicateIri))
    || pathSteps.some(({ predicateIri }) => !independentlyDeclaredProperty(store, predicateIri))) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} references an undeclared predicate`);
  }
  const classInstances = operatorIri.endsWith(':classinstances');
  const typeFilter = operatorIri.endsWith(':filtertypeany');
  if ((classInstances && classIris.length !== 1) || (typeFilter && classIris.length < 1)
    || (!classInstances && !typeFilter && classIris.length !== 0)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} class cardinality is invalid`);
  }
  if (classIris.some((classIri) => !independentlyDeclaredClass(store, classIri))) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} references an undeclared class`);
  }
  const classClosureIris = iriValues(store, expressionIri, 'valueDerivationClassClosure');
  const classClosures = classIris.length > 0 ? independentOwnerClassClosures(
    metaModel, expressionIri, 'valueDerivationClassClosure', classIris,
    'VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH',
  ) : [];
  if (classIris.length === 0 && classClosureIris.length > 0) {
    fail('VALUE_DERIVATION_CLASS_CLOSURE_MISMATCH', `${expressionIri} carries closures without classes`);
  }
  const pathFilter = operatorIri.endsWith(':filterpathexists') || operatorIri.endsWith(':filterpathvaluein');
  const valueFilter = operatorIri.endsWith(':filterpathvaluein');
  if ((pathFilter && pathSteps.length < 1) || (!pathFilter && pathSteps.length !== 0)
    || (valueFilter && allowedValueIris.length < 1) || (!valueFilter && allowedValueIris.length !== 0)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${expressionIri} filter contract is invalid`);
  }
  const record = {
    allowedValueIris,
    canonicalName: oneIndependentValue(store, expressionIri, 'canonicalName', 'PERMUTATION_META_MODEL_INVALID'),
    classClosureDigests: classClosures.map(({ digest }) => digest),
    classIris,
    expressionIri,
    inputScopeIri,
    operands: operands.map(({ child, index }) => ({ expression: child.record, index })),
    operatorIri,
    pathSteps,
    predicateIri: predicateIris[0] ?? null,
    schemaVersion: 2,
  };
  const expression = {
    ...record,
    allowed: new Set(allowedValueIris),
    children: operands.map(({ child }) => child),
    digest: fullDigest(record),
    record,
    classClosures,
    transitiveClassClosureDigests: uniqueSorted([
      ...classClosures.map(({ digest }) => digest),
      ...operands.flatMap(({ child }) => child.transitiveClassClosureDigests),
    ]),
    transitivePredicateIris: uniqueSorted([
      ...predicateIris,
      ...pathSteps.map(({ predicateIri }) => predicateIri),
      ...operands.flatMap(({ child }) => child.transitivePredicateIris),
      ...(classInstances ? [RDF_TYPE] : []),
    ]),
  };
  cache.set(expressionIri, expression);
  return expression;
}

function independentSourceDerivation(metaModel, source) {
  const roots = iriValues(metaModel.store, source, 'valueSourceDerivationRoot');
  const subjectClasses = iriValues(metaModel.store, source, 'valueSourceSubjectClass');
  const terminalClasses = iriValues(metaModel.store, source, 'valueSourceTerminalClass');
  const terminalKinds = iriValues(metaModel.store, source, 'valueSourceTerminalKind');
  if (roots.length !== 1 || subjectClasses.length !== 1 || terminalClasses.length < 1
    || canonicalJson(terminalKinds) !== canonicalJson([NAMED_NODE_TERMINAL])) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} has an incomplete derivation contract`);
  }
  if (!independentlyDeclaredClass(metaModel.store, subjectClasses[0])
    || terminalClasses.some((classIri) => !independentlyDeclaredClass(metaModel.store, classIri))) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} references an undeclared class`);
  }
  const root = reconstructDerivation(metaModel, roots[0]);
  const declaredPredicates = iriValues(metaModel.store, source, 'valueSourceDerivationPredicate');
  if (canonicalJson(declaredPredicates) !== canonicalJson(root.transitivePredicateIris)
    || canonicalJson(values(metaModel.store, roots[0], 'valueDerivationDigest')) !== canonicalJson([root.digest])) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} derivation digest or predicate closure is invalid`);
  }
  const sourceRecord = {
    classClosureDigests: root.transitiveClassClosureDigests,
    derivationPredicateIris: declaredPredicates,
    rootDigest: root.digest,
    rootIri: roots[0],
    schemaVersion: 2,
    sourceIri: source,
    subjectClassIri: subjectClasses[0],
    terminalClassIris: terminalClasses,
    terminalKindIris: terminalKinds,
  };
  const sourceDigest = fullDigest(sourceRecord);
  if (canonicalJson(values(metaModel.store, source, 'valueSourceDigest')) !== canonicalJson([sourceDigest])) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} value-source digest is invalid`);
  }
  const subjectClassClosure = metaModel.classClosures.byRoot.get(subjectClasses[0]);
  const terminalClassClosures = terminalClasses.map((classIri) => metaModel.classClosures.byRoot.get(classIri));
  if (!subjectClassClosure || terminalClassClosures.some((closure) => !closure)) {
    fail('VALUE_SOURCE_SUBJECT_CLASS_CLOSURE_MISMATCH', `${source} lacks explicit subject or terminal closures`);
  }
  return {
    root,
    sourceDigest,
    sourceRecord,
    subjectClass: subjectClasses[0],
    subjectClassClosure,
    terminalClasses,
    terminalClassClosures,
  };
}

function reconstructIndependentFamilyRegistry(metaModel) {
  const allowedPlanes = new Set([
    'urn:usf:permutationfamilyplane:assuranceobligation',
    'urn:usf:permutationfamilyplane:runtimebehaviour',
  ]);
  const families = metaInstances(metaModel.store, `${O}PermutationFamily`).map((familyIri) => {
    const registrationIri = oneIndependentIri(metaModel.store, familyIri, 'familySubjectRegistration',
      'FAMILY_SUBJECT_REGISTRATION_CARDINALITY');
    const subjectClassIri = oneIndependentIri(metaModel.store, registrationIri, 'registeredSubjectClass',
      'REGISTERED_SUBJECT_CLASS_CARDINALITY');
    const subjectClosures = independentOwnerClassClosures(
      metaModel, registrationIri, 'subjectClassClosure', [subjectClassIri],
      'REGISTERED_SUBJECT_CLASS_CLOSURE_MISMATCH',
    );
    if (subjectClosures.length !== 1) {
      fail('REGISTERED_SUBJECT_CLASS_CLOSURE_MISMATCH', `${registrationIri} must bind one closure`);
    }
    const subjectClassClosure = subjectClosures[0];
    const planeIri = oneIndependentIri(metaModel.store, registrationIri, 'registeredFamilyPlane',
      'REGISTERED_FAMILY_PLANE_CARDINALITY');
    if (!allowedPlanes.has(planeIri)) {
      fail('REGISTERED_FAMILY_PLANE_UNCONTROLLED', `${registrationIri} uses ${planeIri}`);
    }
    const ruleIri = oneIndependentIri(metaModel.store, familyIri, 'familyApplicabilityRule',
      'FAMILY_APPLICABILITY_RULE_CARDINALITY');
    const rule = metaModel.rules.get(ruleIri);
    if (!rule) fail('FAMILY_APPLICABILITY_RULE_UNKNOWN', `${familyIri} uses ${ruleIri}`);
    const dimensions = iriValues(metaModel.store, familyIri, 'hasFamilyDimensionBinding').map((bindingIri) => {
      const dimensionIri = oneIndependentIri(metaModel.store, bindingIri, 'bindsDimension',
        'FAMILY_DIMENSION_CARDINALITY');
      const sourceIri = oneIndependentIri(metaModel.store, dimensionIri, 'dimensionValueSource',
        'FAMILY_DIMENSION_VALUE_SOURCE_CARDINALITY');
      const position = Number(oneIndependentValue(metaModel.store, bindingIri, 'dimensionPosition',
        'FAMILY_DIMENSION_POSITION_INVALID'));
      if (!Number.isSafeInteger(position) || position < 1) {
        fail('FAMILY_DIMENSION_POSITION_INVALID', `${bindingIri} has an invalid position`);
      }
      const sourceKind = oneIndependentValue(metaModel.store, sourceIri, 'valueSourceKind',
        'VALUE_SOURCE_KIND_CARDINALITY_INVALID');
      const sourceScopeIri = oneIndependentIri(metaModel.store, sourceIri, 'valueSourceScope',
        'VALUE_SOURCE_SCOPE_CARDINALITY_INVALID');
      if (!SOURCE_KIND.has(sourceKind) || !SOURCE_SCOPE.has(sourceScopeIri)) {
        fail('PERMUTATION_META_MODEL_INVALID', `${sourceIri} uses an uncontrolled source kind or scope`);
      }
      const declaredValues = iriValues(metaModel.store, dimensionIri, 'hasDimensionValue')
        .map((valueIri) => {
          if (!metaInstances(metaModel.store, `${O}PermutationDimensionValue`).includes(valueIri)) {
            fail('DIMENSION_VALUE_TYPE_INVALID', `${valueIri} is not a PermutationDimensionValue`);
          }
          const key = oneIndependentValue(metaModel.store, valueIri, 'dimensionValueKey',
            'DIMENSION_VALUE_KEY_CARDINALITY');
          if (key.length === 0) {
            fail('DIMENSION_VALUE_KEY_CARDINALITY', `${valueIri} has an empty declared key`);
          }
          return { iri: valueIri, key };
        }).sort((left, right) => compareCodeUnits(left.key, right.key)
          || compareCodeUnits(left.iri, right.iri));
      if (new Set(declaredValues.map(({ key }) => key)).size !== declaredValues.length) {
        fail('DIMENSION_VALUE_KEY_DUPLICATE', `${dimensionIri} repeats a declared value key`);
      }
      if (sourceKind === 'controlledlist' && declaredValues.length === 0) {
        fail('CONTROLLED_DIMENSION_VALUE_SET_EMPTY', `${dimensionIri} has no controlled values`);
      }
      const declaredValueSetDigest = declaredValues.length > 0 ? fullDigest(declaredValues) : null;
      const controlledValues = sourceKind === 'controlledlist' ? declaredValues : [];
      const controlledValueSetDigest = sourceKind === 'controlledlist' ? declaredValueSetDigest : null;
      const valueSelectorIris = iriValues(metaModel.store, sourceIri, 'valueSourceSelector');
      const derivationRootIris = iriValues(metaModel.store, sourceIri, 'valueSourceDerivationRoot');
      if (valueSelectorIris.length > 1 || derivationRootIris.length > 1) {
        fail('VALUE_SOURCE_DERIVATION_MODE_CONFLICT', `${sourceIri} has ambiguous derivation bindings`);
      }
      const valueSelectorIri = valueSelectorIris[0] ?? null;
      const valueDerivationRootIri = derivationRootIris[0] ?? null;
      const registeredScope = 'urn:usf:dimensionvaluesourcescope:registeredsubjectrelationship';
      if ((valueSelectorIri && (sourceKind !== 'derivedselector' || sourceScopeIri !== registeredScope))
        || (!valueSelectorIri && sourceScopeIri === registeredScope)
        || (valueDerivationRootIri && (sourceKind !== 'derivedselector' || sourceScopeIri === registeredScope))
        || (sourceKind === 'derivedselector' && sourceScopeIri !== registeredScope && !valueDerivationRootIri)
        || (sourceKind !== 'derivedselector' && (valueSelectorIri || valueDerivationRootIri))) {
        fail('VALUE_SOURCE_DERIVATION_MODE_CONFLICT', `${sourceIri} has an invalid derivation mode`);
      }
      const selector = valueSelectorIri ? metaModel.selectors.get(valueSelectorIri) : null;
      if (valueSelectorIri && !selector) fail('VALUE_SOURCE_SELECTOR_UNKNOWN', `${sourceIri} uses ${valueSelectorIri}`);
      if (selector && selector.aggregationIri !== 'urn:usf:permutationsignalaggregation:distinctvalues') {
        fail('VALUE_SOURCE_SELECTOR_AGGREGATION_INVALID', `${valueSelectorIri} must return distinct values`);
      }
      const derivationPredicateIris = iriValues(metaModel.store, sourceIri, 'valueSourceDerivationPredicate');
      if (selector && canonicalJson(derivationPredicateIris)
        !== canonicalJson(uniqueSorted(selector.steps.map(({ predicateIri }) => predicateIri)))) {
        fail('VALUE_SOURCE_SELECTOR_PREDICATE_MISMATCH', `${sourceIri} selector predicates differ`);
      }
      let expectedAxisRoots;
      if (sourceKind === 'controlledlist') expectedAxisRoots = [`${O}PermutationDimensionValue`];
      else if (sourceKind === 'classinstances') {
        expectedAxisRoots = [oneIndependentValue(metaModel.store, sourceIri, 'valueSourceClassIri',
          'CLASS_SOURCE_IRI_CARDINALITY')];
      } else if (selector) expectedAxisRoots = [selector.terminalClassIri];
      else expectedAxisRoots = iriValues(metaModel.store, sourceIri, 'valueSourceTerminalClass');
      const axisClassClosures = independentOwnerClassClosures(
        metaModel, bindingIri, 'dimensionAxisClassClosure', expectedAxisRoots,
        'DIMENSION_AXIS_CLASS_CLOSURE_MISMATCH',
      ).sort((left, right) => compareCodeUnits(left.iri, right.iri));
      const sourceDerivation = valueDerivationRootIri ? independentSourceDerivation(metaModel, sourceIri) : null;
      return {
        axisClassClosureDigests: axisClassClosures.map(({ digest }) => digest),
        bindingIri,
        controlledValueSetDigest,
        controlledValues,
        declaredValueSetDigest,
        declaredValues,
        derivationPredicateIris,
        dimensionIri,
        key: oneIndependentValue(metaModel.store, dimensionIri, 'permutationDimensionKey',
          'FAMILY_DIMENSION_KEY_CARDINALITY'),
        position,
        sourceKind,
        sourceIri,
        sourceScopeIri,
        valueDerivationRootIri,
        valueSelectorDigest: selector?.digest ?? null,
        valueSelectorIri,
        valueSourceDigest: sourceDerivation?.sourceDigest ?? null,
      };
    }).sort((left, right) => left.position - right.position);
    if (dimensions.length === 0 || !dimensions.every(({ position }, offset) => position === offset + 1)) {
      fail(dimensions.length === 0 ? 'FAMILY_DIMENSION_SET_EMPTY' : 'FAMILY_DIMENSION_POSITION_INVALID',
        `${familyIri} has no exact ordered dimensions`);
    }
    if (new Set(dimensions.map(({ dimensionIri }) => dimensionIri)).size !== dimensions.length
      || new Set(dimensions.map(({ key }) => key)).size !== dimensions.length) {
      fail('FAMILY_DIMENSION_DUPLICATE', `${familyIri} repeats a dimension or key`);
    }
    return {
      canonicalName: oneIndependentValue(metaModel.store, familyIri, 'canonicalName',
        'FAMILY_NAME_CARDINALITY'),
      dimensions,
      familyIri,
      planeIri,
      registrationIri,
      ruleDigest: rule.ruleDigest,
      ruleIri,
      subjectClassIri,
      subjectClassClosureDigest: subjectClassClosure.digest,
    };
  }).sort((left, right) => compareCodeUnits(left.familyIri, right.familyIri));
  const registryRecord = {
    families,
    classClosures: [...metaModel.classClosures.closures].map((closure) => ({
      closureDigest: closure.digest,
      closureIri: closure.iri,
      edgeSetDigest: closure.edgeSetDigest,
      memberSetDigest: closure.memberSetDigest,
      policyIri: closure.policyIri,
      rootClassIri: closure.rootClassIri,
    })).sort((left, right) => compareCodeUnits(left.closureIri, right.closureIri)),
    schemaVersion: 5,
  };
  return Object.freeze({
    families: Object.freeze(families),
    familiesByIri: new Map(families.map((family) => [family.familyIri, family])),
    registryDigest: fullDigest(registryRecord),
    registryRecord: Object.freeze(registryRecord),
  });
}

function proofScopeActive(scope, authorityInputs) {
  if (scope.endsWith(':all')) return true;
  return isFoundationProofInputs(authorityInputs)
    ? scope.endsWith(':foundationconformancefixture') : scope.endsWith(':liveauthority');
}

function independentPath(index, valuesToTraverse, steps) {
  let frontier = uniqueSorted(valuesToTraverse);
  for (const step of steps) {
    if (step.directionIri.endsWith(':outbound')) {
      frontier = uniqueSorted(frontier.flatMap((value) => index.objects(value, step.predicateIri).map((object) => {
        if (object.type !== 'iri') fail('PERMUTATION_META_MODEL_INVALID', `${step.predicateIri} returned a literal`);
        return object.value;
      })));
    } else if (step.directionIri.endsWith(':inbound')) {
      frontier = uniqueSorted(frontier.flatMap((value) => index.subjects(step.predicateIri, value)));
    } else {
      fail('PERMUTATION_META_MODEL_INVALID', `${step.directionIri} is not a path direction`);
    }
  }
  return frontier;
}

function independentlyEvaluateDerivation(expression, authorityInputs, subject) {
  if (!proofScopeActive(expression.inputScopeIri, authorityInputs)) return [];
  const childSets = expression.children.map((child) => independentlyEvaluateDerivation(child, authorityInputs, subject));
  const index = authorityInputs.index;
  if (expression.operatorIri.endsWith(':subject')) return [subject];
  if (expression.operatorIri.endsWith(':classinstances')) {
    return independentClosureInstances(authorityInputs, expression.classClosures);
  }
  if (expression.operatorIri.endsWith(':outbound')) return independentPath(index, childSets[0], [{
    directionIri: 'urn:usf:permutationpathdirection:outbound', predicateIri: expression.predicateIri,
  }]);
  if (expression.operatorIri.endsWith(':inbound')) return independentPath(index, childSets[0], [{
    directionIri: 'urn:usf:permutationpathdirection:inbound', predicateIri: expression.predicateIri,
  }]);
  if (expression.operatorIri.endsWith(':union')) return uniqueSorted(childSets.flat());
  if (expression.operatorIri.endsWith(':filtertypeany')) {
    return childSets[0].filter((value) => independentResourceHasClosureType(index, value, expression.classClosures));
  }
  if (expression.operatorIri.endsWith(':filterpathexists')) {
    return childSets[0].filter((value) => independentPath(index, [value], expression.pathSteps).length > 0);
  }
  if (expression.operatorIri.endsWith(':filterpathvaluein')) {
    return childSets[0].filter((value) => independentPath(index, [value], expression.pathSteps)
      .some((result) => expression.allowed.has(result)));
  }
  fail('PERMUTATION_META_MODEL_INVALID', `${expression.operatorIri} cannot be evaluated`);
}

function independentlyResolveSemanticSource(metaModel, authorityInputs, subject, source) {
  const definition = independentSourceDerivation(metaModel, source);
  if (!independentResourceHasClosureType(authorityInputs.index, subject, [definition.subjectClassClosure])) {
    fail('PERMUTATION_META_MODEL_INVALID', `${subject} is outside ${definition.subjectClass}`);
  }
  const domain = uniqueSorted(independentlyEvaluateDerivation(definition.root, authorityInputs, subject));
  if (domain.some((value) => !definition.terminalClassClosures.some((closure) =>
    closure.rootClassIri === OWL_CLASS ? authorityInputs.index.projectedClassIris.has(value)
      : independentResourceHasClosureType(authorityInputs.index, value, [closure])
        || (isFoundationProofInputs(authorityInputs)
          && independentMetaResourceHasClosureType(metaModel.store, value, [closure]))))) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} returned a value outside its terminal classes`);
  }
  return domain;
}

function familyDimensions(metaModel, family) {
  const { store } = metaModel;
  const bindings = values(store, family, 'hasFamilyDimensionBinding');
  if (bindings.length === 0) fail('PERMUTATION_META_MODEL_INVALID', `${family} has no dimensions`);
  const descriptors = bindings.map((binding) => {
    const positions = values(store, binding, 'dimensionPosition');
    const dimensions = values(store, binding, 'bindsDimension');
    if (positions.length !== 1 || dimensions.length !== 1) {
      fail('PERMUTATION_META_MODEL_INVALID', `${binding} has invalid cardinality`);
    }
    const position = Number(positions[0]);
    const dimension = dimensions[0];
    const keys = values(store, dimension, 'permutationDimensionKey');
    if (!Number.isInteger(position) || position < 1 || keys.length !== 1 || keys[0].length === 0) {
      fail('PERMUTATION_META_MODEL_INVALID', `${binding} has an invalid position or key`);
    }
    const sourceIris = values(store, dimension, 'dimensionValueSource');
    if (sourceIris.length !== 1) fail('PERMUTATION_META_MODEL_INVALID', `${dimension} has no exact source`);
    const source = sourceIris[0];
    const kinds = values(store, source, 'valueSourceKind');
    const scopes = values(store, source, 'valueSourceScope');
    if (kinds.length !== 1 || scopes.length !== 1) {
      fail('PERMUTATION_META_MODEL_INVALID', `${source} has no exact kind or scope`);
    }
    let expectedRoots;
    if (kinds[0] === 'controlledlist') expectedRoots = [`${O}PermutationDimensionValue`];
    else if (kinds[0] === 'classinstances') expectedRoots = values(store, source, 'valueSourceClassIri');
    else if (kinds[0] === 'derivedselector'
      && scopes[0] === 'urn:usf:dimensionvaluesourcescope:registeredsubjectrelationship') {
      const selectorIris = iriValues(store, source, 'valueSourceSelector');
      expectedRoots = selectorIris.length === 1
        ? iriValues(store, selectorIris[0], 'selectorTerminalClass') : [];
    } else if (kinds[0] === 'derivedselector') {
      expectedRoots = iriValues(store, source, 'valueSourceTerminalClass');
    } else expectedRoots = [];
    const axisClassClosures = independentOwnerClassClosures(
      metaModel, binding, 'dimensionAxisClassClosure', expectedRoots,
      'DIMENSION_AXIS_CLASS_CLOSURE_MISMATCH',
    );
    return {
      axisClassClosureDigests: axisClassClosures.map(({ digest }) => digest),
      axisClassClosures,
      binding,
      dimension,
      key: keys[0],
      position,
    };
  }).sort((left, right) => left.position - right.position);
  if (!descriptors.every(({ position }, index) => position === index + 1)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${family} positions are not contiguous`);
  }
  if (new Set(descriptors.map(({ dimension }) => dimension)).size !== descriptors.length
    || new Set(descriptors.map(({ key }) => key)).size !== descriptors.length) {
    fail('PERMUTATION_META_MODEL_INVALID', `${family} repeats a dimension or key`);
  }
  return descriptors;
}

function independentFamilySubjectDefinition(metaModel, family) {
  const registrations = iriValues(metaModel.store, family, 'familySubjectRegistration');
  if (registrations.length !== 1) {
    fail('PERMUTATION_META_MODEL_INVALID', `${family} has no exact subject registration`);
  }
  const registrationIri = registrations[0];
  const subjectClasses = iriValues(metaModel.store, registrationIri, 'registeredSubjectClass');
  if (subjectClasses.length !== 1) {
    fail('PERMUTATION_META_MODEL_INVALID', `${registrationIri} has no exact subject class`);
  }
  const subjectClassClosure = independentOwnerClassClosures(
    metaModel, registrationIri, 'subjectClassClosure', subjectClasses,
    'REGISTERED_SUBJECT_CLASS_CLOSURE_MISMATCH',
  )[0];
  return { registrationIri, subjectClassClosure, subjectClassIri: subjectClasses[0] };
}

function independentlyTraverseValueSource(metaModel, authorityInputs, subject, source) {
  const selectorIris = values(metaModel.store, source, 'valueSourceSelector');
  if (selectorIris.length !== 1) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} must name one value-source selector`);
  }
  const selector = selectorIris[0];
  const subjectClasses = values(metaModel.store, selector, 'selectorSubjectClass');
  const foundationInputs = isFoundationProofInputs(authorityInputs);
  const classAvailable = (classIri) => authorityInputs.index.projectedClassIris.has(classIri)
    || (foundationInputs && independentlyDeclaredClass(metaModel.store, classIri));
  const predicateAvailable = (predicateIri) => authorityInputs.index.projectedPredicateIris.has(predicateIri)
    || (foundationInputs && independentlyDeclaredProperty(metaModel.store, predicateIri));
  if (subjectClasses.length !== 1 || !classAvailable(subjectClasses[0])) {
    fail('AUTHORITY_SELECTOR_SUBJECT_CLASS_NOT_PROJECTED', `${selector} subject class is absent from the projection`);
  }
  const subjectClosures = independentOwnerClassClosures(
    metaModel, selector, 'selectorSubjectClassClosure', subjectClasses,
    'SELECTOR_SUBJECT_CLASS_CLOSURE_MISMATCH',
  );
  if (!independentResourceHasClosureType(authorityInputs.index, subject, subjectClosures)) {
    fail('VALUE_SOURCE_SELECTOR_SUBJECT_CLASS_MISMATCH', `${subject} is not a ${subjectClasses[0]}`);
  }
  const steps = values(metaModel.store, selector, 'selectorPathStep').map((step) => {
    const positions = values(metaModel.store, step, 'signalPathStepIndex');
    const predicates = values(metaModel.store, step, 'signalPathStepPredicate');
    const directions = values(metaModel.store, step, 'signalPathStepDirection');
    if (positions.length !== 1 || predicates.length !== 1 || directions.length !== 1) {
      fail('PERMUTATION_META_MODEL_INVALID', `${step} path metadata is incomplete`);
    }
    return { direction: directions[0], position: Number(positions[0]), predicate: predicates[0], step };
  }).sort((left, right) => left.position - right.position);
  if (steps.length === 0 || !steps.every(({ position }, index) => position === index + 1)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${selector} path is not finite and contiguous`);
  }
  const declaredPredicates = values(metaModel.store, source, 'valueSourceDerivationPredicate');
  const traversedPredicates = uniqueSorted(steps.map(({ predicate }) => predicate));
  if (canonicalJson(declaredPredicates) !== canonicalJson(traversedPredicates)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} predicate summary differs from its selector path`);
  }
  let frontier = [subject];
  for (const { direction, predicate, step } of steps) {
    if (!predicateAvailable(predicate)) {
      fail('AUTHORITY_SELECTOR_PATH_PREDICATE_NOT_PROJECTED', `${predicate} is absent from the authority projection`);
    }
    if (direction === 'urn:usf:permutationpathdirection:outbound') {
      frontier = uniqueSorted(frontier.flatMap((node) => authorityInputs.index.values(node, predicate)));
    } else if (direction === 'urn:usf:permutationpathdirection:inbound') {
      frontier = uniqueSorted(frontier.flatMap((node) => authorityInputs.index.subjects(predicate, node)));
    } else {
      fail('PERMUTATION_META_MODEL_INVALID', `${step} has an uncontrolled path direction`);
    }
  }
  const terminalClasses = values(metaModel.store, selector, 'selectorTerminalClass');
  if (terminalClasses.length !== 1 || !classAvailable(terminalClasses[0])) {
    fail('AUTHORITY_SELECTOR_TERMINAL_CLASS_NOT_PROJECTED', `${selector} terminal class is absent from the projection`);
  }
  const terminalClosures = independentOwnerClassClosures(
    metaModel, selector, 'selectorTerminalClassClosure', terminalClasses,
    'SELECTOR_TERMINAL_CLASS_CLOSURE_MISMATCH',
  );
  if (frontier.some((node) => !independentResourceHasClosureType(
    authorityInputs.index, node, terminalClosures,
  ) && !(foundationInputs && independentMetaResourceHasClosureType(metaModel.store, node, terminalClosures)))) {
    fail('PERMUTATION_META_MODEL_INVALID', `${selector} selected a value outside its terminal class`);
  }
  return frontier;
}

function resolveDomain(metaModel, authorityInputs, subject, descriptor) {
  const { store } = metaModel;
  const sources = values(store, descriptor.dimension, 'dimensionValueSource');
  if (sources.length !== 1) fail('PERMUTATION_META_MODEL_INVALID', `${descriptor.dimension} does not have one source`);
  const source = sources[0];
  const kinds = values(store, source, 'valueSourceKind');
  if (kinds.length !== 1 || !SOURCE_KIND.has(kinds[0])) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} has an invalid source kind`);
  }
  const scopes = values(store, source, 'valueSourceScope');
  if (scopes.length !== 1 || !SOURCE_SCOPE.has(scopes[0])) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} has no exact controlled source scope`);
  }
  const sourceScope = scopes[0];
  const allowedScopes = {
    classinstances: new Set([
      'urn:usf:dimensionvaluesourcescope:authorityinstanceset',
      'urn:usf:dimensionvaluesourcescope:foundationcatalogue',
    ]),
    controlledlist: new Set(['urn:usf:dimensionvaluesourcescope:foundationcatalogue']),
    derivedselector: new Set([
      'urn:usf:dimensionvaluesourcescope:capabilityrelationship',
      'urn:usf:dimensionvaluesourcescope:downstreamclosure',
      'urn:usf:dimensionvaluesourcescope:registeredsubjectrelationship',
    ]),
  };
  if (!allowedScopes[kinds[0]].has(sourceScope)) {
    fail('PERMUTATION_META_MODEL_INVALID', `${source} source kind and scope disagree`);
  }
  let domainValues;
  let sourcePlane;
  if (kinds[0] === 'controlledlist') {
    const members = values(store, descriptor.dimension, 'hasDimensionValue');
    const keyed = members.map((member) => {
      if (!metaInstances(store, `${O}PermutationDimensionValue`).includes(member)) {
        fail('PERMUTATION_META_MODEL_INVALID', `${member} is not a PermutationDimensionValue`);
      }
      const keys = values(store, member, 'dimensionValueKey');
      if (keys.length !== 1 || keys[0].length === 0) fail('PERMUTATION_META_MODEL_INVALID', `${member} has no exact key`);
      return { iri: member, key: keys[0] };
    }).sort((left, right) => compareCodeUnits(left.key, right.key) || compareCodeUnits(left.iri, right.iri));
    if (new Set(keyed.map(({ key }) => key)).size !== keyed.length) {
      fail('PERMUTATION_META_MODEL_INVALID', `${descriptor.dimension} repeats a controlled key`);
    }
    domainValues = keyed.map(({ iri }) => iri);
    sourcePlane = 'CANDIDATE_META_MODEL';
  } else if (kinds[0] === 'classinstances') {
    const classes = values(store, source, 'valueSourceClassIri');
    if (classes.length !== 1) fail('PERMUTATION_META_MODEL_INVALID', `${source} does not name one class`);
    const closureRoots = uniqueSorted(descriptor.axisClassClosures.map(({ rootClassIri }) => rootClassIri));
    if (canonicalJson(closureRoots) !== canonicalJson(classes)) {
      fail('DIMENSION_AXIS_CLASS_CLOSURE_MISMATCH', `${descriptor.binding} closure roots differ`);
    }
    const candidateValues = uniqueSorted(descriptor.axisClassClosures.flatMap(({ memberClassIris }) => (
      memberClassIris.flatMap((classIri) => metaInstances(store, classIri))
    )));
    if (sourceScope === 'urn:usf:dimensionvaluesourcescope:foundationcatalogue') {
      domainValues = candidateValues;
      sourcePlane = candidateValues.length > 0 ? 'CANDIDATE_FOUNDATION_CATALOGUE' : 'FOUNDATION_CATALOGUE_EMPTY';
    } else if (isFoundationProofInputs(authorityInputs)) {
      domainValues = independentClosureInstances(authorityInputs, descriptor.axisClassClosures);
      sourcePlane = domainValues.length > 0 ? FOUNDATION_FIXTURE_SCOPE : 'FOUNDATION_CONFORMANCE_FIXTURE_EMPTY';
    } else {
      const authorityValues = independentClosureInstances(authorityInputs, descriptor.axisClassClosures);
      domainValues = authorityValues;
      sourcePlane = authorityValues.length > 0 ? 'LIVE_AUTHORITY' : 'LIVE_AUTHORITY_EMPTY';
    }
  } else {
    const sourceSelectors = values(store, source, 'valueSourceSelector');
    const sourceRoots = values(store, source, 'valueSourceDerivationRoot');
    const derivationPredicates = values(store, source, 'valueSourceDerivationPredicate');
    if (derivationPredicates.length === 0 && sourceRoots.length === 0) {
      fail('PERMUTATION_META_MODEL_INVALID', `${source} has no declared derivation predicate`);
    }
    if (sourceScope === 'urn:usf:dimensionvaluesourcescope:registeredsubjectrelationship') {
      if (sourceRoots.length !== 0) {
        fail('PERMUTATION_META_MODEL_INVALID', `${source} has conflicting derivation modes`);
      }
      domainValues = independentlyTraverseValueSource(metaModel, authorityInputs, subject, source);
    } else {
      if (sourceSelectors.length !== 0) {
        fail('PERMUTATION_META_MODEL_INVALID', `${source} has a selector outside registered-subject scope`);
      }
      if (sourceRoots.length !== 1) {
        fail('PERMUTATION_META_MODEL_INVALID', `${source} has no exact semantic derivation root`);
      }
      domainValues = independentlyResolveSemanticSource(metaModel, authorityInputs, subject, source);
    }
    sourcePlane = isFoundationProofInputs(authorityInputs)
      ? FOUNDATION_FIXTURE_SCOPE
      : sourceScope === 'urn:usf:dimensionvaluesourcescope:downstreamclosure'
        ? 'DOWNSTREAM_CLOSURE_DERIVATION'
        : 'LIVE_AUTHORITY_DERIVATION';
  }
  domainValues = uniqueSorted(domainValues);
  return {
    ...descriptor,
    classClosureDigests: descriptor.axisClassClosureDigests,
    source,
    sourceKind: kinds[0],
    sourcePlane,
    sourceScope,
    valueCount: domainValues.length,
    values: domainValues,
    valueSetDigest: fullDigest({
      classClosureDigests: descriptor.axisClassClosureDigests,
      dimension: descriptor.dimension,
      source,
      sourceKind: kinds[0],
      sourcePlane,
      sourceScope,
      values: domainValues,
    }),
  };
}

function reconstructFoundationDomainAssessment({ authorityInputs, repositoryRoot }) {
  const fixture = loadIndependentFoundationFixture({ authorityInputs, repositoryRoot });
  const metaModel = loadIndependentMetaModel(repositoryRoot);
  const structuralProjection = independentlyBuildFoundationStructuralProjection(metaModel, fixture);
  const assessmentInputs = Object.freeze({ ...fixture, index: structuralProjection.index });
  VERIFIED_FOUNDATION_PROOF_INPUTS.add(assessmentInputs);
  const families = metaInstances(metaModel.store, `${O}PermutationFamily`);
  const coveredFamilies = values(
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
  const familySubjects = new Map(families.map((family) => [family,
    independentFamilySubjectDefinition(metaModel, family)]));
  const registrations = new Map([...familySubjects.values()].map((definition) => [
    definition.registrationIri, definition,
  ]));
  const primarySubjectsByRegistration = new Map();
  for (const [registrationIri, definition] of registrations) {
    const matches = primaryAndProjectedSubjects.filter((subject) => independentResourceHasClosureType(
      structuralProjection.index, subject, [definition.subjectClassClosure],
    ));
    if (matches.length === 0) add('FOUNDATION_FIXTURE_PRIMARY_SUBJECT_CLASS_ABSENT', {
      classClosureDigest: definition.subjectClassClosure.digest,
      registrationIri,
      subjectClass: definition.subjectClassIri,
    });
    else primarySubjectsByRegistration.set(registrationIri, matches);
  }
  const unmatchedPrimarySubjects = primarySubjects.filter((subject) => (
    ![subject, ...(structuralProjection.projectedBySource.get(subject) ?? [])].some((candidate) => (
      [...familySubjects.values()].some((definition) => independentResourceHasClosureType(
        structuralProjection.index, candidate, [definition.subjectClassClosure],
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
    .flatMap((source) => values(metaModel.store, source, 'valueSourceClassIri')
      .map((classIri) => ({ classIri, source })));
  for (const { classIri, source } of classSources) {
    if (!metaModel.store.getQuads(
      N3.DataFactory.namedNode(classIri),
      N3.DataFactory.namedNode(RDF_TYPE),
      N3.DataFactory.namedNode('http://www.w3.org/2002/07/owl#Class'),
      null,
    ).length) {
      add('FOUNDATION_VALUE_SOURCE_CLASS_UNDECLARED', { classIri, source });
    }
  }
  const familyRecords = [];
  const uniqueDimensions = new Set();
  let dimensionBindingOccurrenceCount = 0;
  let totalCombinationCount = 0;
  for (const family of families) {
      const names = values(metaModel.store, family, 'canonicalName');
      if (names.length !== 1) {
        add('FOUNDATION_FAMILY_IDENTITY_INVALID', { family });
        continue;
      }
      const familySubject = familySubjects.get(family);
      const subjectClass = familySubject?.subjectClassIri ?? null;
      const candidateSubjects = familySubject
        ? primarySubjectsByRegistration.get(familySubject.registrationIri) ?? [] : [];
      if (candidateSubjects.length === 0) {
        add('FOUNDATION_FIXTURE_PRIMARY_SUBJECT_MISSING', { family, subjectClass });
        continue;
      }
      const candidateDomains = [];
      for (const subject of candidateSubjects) {
        try {
          const domains = familyDimensions(metaModel, family)
            .map((descriptor) => resolveDomain(metaModel, assessmentInputs, subject, descriptor));
          candidateDomains.push({ domains, subject });
        } catch (error) {
          add(error.code ?? 'FOUNDATION_FAMILY_GENERATION_FAILED', { family, message: error.message, subject });
        }
      }
      const completeWitnesses = candidateDomains.filter(({ domains }) => (
        domains.length > 0 && domains.every(({ values: domainValues }) => domainValues.length > 0)
      ));
      if (completeWitnesses.length > 1) {
        add('FOUNDATION_FIXTURE_FAMILY_WITNESS_CARDINALITY', {
          family,
          matches: completeWitnesses.map(({ subject }) => subject),
          subjectClass,
        });
        continue;
      }
      const selected = completeWitnesses[0] ?? (candidateDomains.length === 1 ? candidateDomains[0] : null);
      if (!selected) {
        add('FOUNDATION_FIXTURE_FAMILY_WITNESS_MISSING', {
          candidateSubjects,
          family,
          subjectClass,
        });
        continue;
      }
      const { domains, subject: primarySubject } = selected;
      const emptyDomains = domains.filter(({ values: domainValues }) => domainValues.length === 0);
      for (const domain of emptyDomains) {
        add('FOUNDATION_FINITE_DOMAIN_EMPTY', {
          capability: subjectClass === `${O}Capability` ? primarySubject : null,
          dimension: domain.dimension,
          dimensionKey: domain.key,
          family,
          source: domain.source,
          sourceKind: domain.sourceKind,
          sourcePlane: domain.sourcePlane,
          subject: primarySubject,
        });
      }
      const combinationCount = emptyDomains.length > 0
        ? 0
        : domains.reduce((product, domain) => product * domain.values.length, 1);
      if (!Number.isSafeInteger(combinationCount)) add('FOUNDATION_DOMAIN_CARDINALITY_OVERFLOW', { family });
      if (combinationCount === 0) add('FOUNDATION_FAMILY_ZERO_COMBINATION', { family });
      for (const { dimension } of domains) uniqueDimensions.add(dimension);
      dimensionBindingOccurrenceCount += domains.length;
      totalCombinationCount += combinationCount;
      if (!Number.isSafeInteger(totalCombinationCount)) {
        add('FOUNDATION_DOMAIN_CARDINALITY_OVERFLOW', { field: 'totalCombinationCount' });
      }
      const dimensions = domains.map(({ values: omittedValues, ...domain }) => domain);
      const familyCore = {
        canonicalName: names[0],
        combinationCount,
        dimensionCount: dimensions.length,
        dimensions,
        domainClosureComplete: emptyDomains.length === 0,
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
  return { core, fixture, metaModel };
}

function foundationProofResult(assessment, expectedCore, diagnostics) {
  const diagnosticRecords = diagnostics.list();
  const errorCount = diagnosticRecords.reduce((sum, record) => sum + record.count, 0);
  const reconstructed = expectedCore ?? {};
  const verdict = errorCount > 0
    ? 'FOUNDATION_DOMAIN_CLOSURE_PROOF_FAIL'
    : reconstructed.foundationDomainClosureComplete
      ? 'FOUNDATION_DOMAIN_CLOSURE_PROOF_PASS'
      : 'FOUNDATION_DOMAIN_CLOSURE_PROOF_INCOMPLETE';
  const core = {
    assessmentDigest: assessment?.assessmentDigest,
    authorising: false,
    baselineAuthorityBinding: reconstructed.baselineAuthorityBinding ?? assessment?.baselineAuthorityBinding,
    diagnostics: diagnosticRecords,
    fixtureDigest: reconstructed.fixtureDigest ?? assessment?.fixtureDigest,
    fixtureInputDigest: reconstructed.fixtureInputDigest ?? assessment?.fixtureInputDigest,
    fixtureProjectionDigest: reconstructed.fixtureProjectionDigest ?? assessment?.fixtureProjectionDigest,
    foundationStructuralProjectionDigest: reconstructed.foundationStructuralProjectionDigest
      ?? assessment?.foundationStructuralProjectionDigest,
    foundationStructuralProjectionRecordCount: reconstructed.foundationStructuralProjectionRecordCount
      ?? assessment?.foundationStructuralProjectionRecordCount,
    foundationStructuralProjectionRuleSetDigest: reconstructed.foundationStructuralProjectionRuleSetDigest
      ?? assessment?.foundationStructuralProjectionRuleSetDigest,
    foundationVerdict: reconstructed.foundationVerdict ?? assessment?.foundationVerdict,
    metaModelDigest: reconstructed.metaModelDigest ?? assessment?.metaModelDigest,
    permutationClosureVerdict: 'PERMUTATION_CLOSURE_NOT_ASSESSED',
    programmePermutationClosureVerdict: 'PERMUTATION_CLOSURE_INCOMPLETE',
    recordKind: 'USF_FOUNDATION_DOMAIN_CLOSURE_INDEPENDENT_PROOF',
    results: {
      dimensionBindingOccurrenceCount: reconstructed.dimensionBindingOccurrenceCount ?? 0,
      emptyDomainCount: (reconstructed.diagnostics ?? [])
        .filter(({ code }) => code === 'FOUNDATION_FINITE_DOMAIN_EMPTY').length,
      familyCount: reconstructed.familyCount ?? 0,
      reconstructionMismatchCount: diagnosticRecords
        .filter(({ code }) => code === 'FOUNDATION_ASSESSMENT_RECONSTRUCTION_MISMATCH')
        .reduce((sum, record) => sum + record.count, 0),
      uniqueDimensionCount: reconstructed.uniqueDimensionCount ?? 0,
    },
    schemaVersion: 2,
    verdict,
  };
  return { ...core, proofDigest: fullDigest(core) };
}

export function proveFoundationDomainClosureAssessment({ assessment, authorityInputs, repositoryRoot }) {
  const verified = assertVerifiedAuthorityInputs(authorityInputs);
  const diagnostics = diagnosticCollector();
  const expectedKeys = [
    'assessmentDigest', 'authorising', 'baselineAuthorityBinding', 'diagnostics',
    'dimensionBindingOccurrenceCount', 'familyCount', 'familyRecords', 'fixtureDigest',
    'fixtureFileDigest', 'fixtureInputDigest', 'fixturePath', 'fixtureProjectionDigest',
    'foundationConformanceOnly', 'foundationDomainClosureComplete', 'foundationVerdict',
    'foundationStructuralProjectionDigest', 'foundationStructuralProjectionRecordCount',
    'foundationStructuralProjectionRuleSetDigest',
    'inputMode', 'metaModelDigest', 'nonClaims', 'permutationClosureVerdict',
    'programmePermutationClosureVerdict', 'recordKind', 'schemaVersion', 'sourceClassCount',
    'totalCombinationCount', 'uniqueDimensionCount',
  ];
  if (!assessment || typeof assessment !== 'object'
    || canonicalJson(Object.keys(assessment).sort()) !== canonicalJson(expectedKeys.sort())
    || assessment.recordKind !== 'USF_FOUNDATION_DOMAIN_CLOSURE_ASSESSMENT'
    || assessment.schemaVersion !== 2
    || assessment.inputMode !== FOUNDATION_FIXTURE_SCOPE
    || assessment.authorising !== false
    || assessment.foundationConformanceOnly !== true
    || !/^sha256:[0-9a-f]{64}$/u.test(assessment.foundationStructuralProjectionDigest ?? '')
    || !/^sha256:[0-9a-f]{64}$/u.test(assessment.foundationStructuralProjectionRuleSetDigest ?? '')
    || !Number.isSafeInteger(assessment.foundationStructuralProjectionRecordCount)
    || assessment.foundationStructuralProjectionRecordCount < 0
    || !Array.isArray(assessment.familyRecords)
    || !Array.isArray(assessment.diagnostics)) {
    diagnostics.add('FOUNDATION_ASSESSMENT_SCHEMA_INVALID');
    return foundationProofResult(assessment, null, diagnostics);
  }
  const { assessmentDigest, ...assessmentCore } = assessment;
  if (assessmentDigest !== fullDigest(assessmentCore)) {
    diagnostics.add('FOUNDATION_ASSESSMENT_DIGEST_MISMATCH', { field: 'assessmentDigest' });
    return foundationProofResult(assessment, null, diagnostics);
  }
  for (const record of assessment.familyRecords) {
    const { familyDomainDigest, ...familyCore } = record;
    if (familyDomainDigest !== fullDigest(familyCore)) {
      diagnostics.add('FOUNDATION_ASSESSMENT_DIGEST_MISMATCH', { family: record.family, field: 'familyDomainDigest' });
    }
  }
  if (diagnostics.list().length > 0) return foundationProofResult(assessment, null, diagnostics);

  let reconstructed;
  try {
    reconstructed = reconstructFoundationDomainAssessment({ authorityInputs: verified, repositoryRoot });
  } catch (error) {
    if (error instanceof ProofInputError) throw error;
    diagnostics.add('FOUNDATION_ASSESSMENT_INDEPENDENT_PROOF_FAILED', { message: error.message });
    return foundationProofResult(assessment, null, diagnostics);
  }
  const expectedCore = reconstructed.core;
  const bindingFields = [
    'baselineAuthorityBinding', 'fixtureDigest', 'fixtureFileDigest', 'fixtureInputDigest',
    'fixturePath', 'fixtureProjectionDigest', 'foundationStructuralProjectionDigest',
    'foundationStructuralProjectionRecordCount', 'foundationStructuralProjectionRuleSetDigest',
    'metaModelDigest',
  ];
  for (const field of bindingFields) {
    if (canonicalJson(assessment[field]) !== canonicalJson(expectedCore[field])) {
      diagnostics.add('FOUNDATION_ASSESSMENT_INPUT_BINDING_MISMATCH', { field });
    }
  }
  if (expectedCore.baselineAuthorityBinding.authorityDigest !== verified.authorityDigest) {
    diagnostics.add('FOUNDATION_ASSESSMENT_INPUT_BINDING_MISMATCH', { field: 'authorityDigest' });
  }
  const reconstructionFields = Object.keys(expectedCore).filter((field) => !bindingFields.includes(field));
  for (const field of reconstructionFields) {
    if (canonicalJson(assessment[field]) !== canonicalJson(expectedCore[field])) {
      diagnostics.add('FOUNDATION_ASSESSMENT_RECONSTRUCTION_MISMATCH', {
        actualDigest: fullDigest(assessment[field]),
        expectedDigest: fullDigest(expectedCore[field]),
        field,
      });
    }
  }
  return foundationProofResult(assessment, expectedCore, diagnostics);
}

function independentIdentity(family, capability, bindings) {
  const ordered = [...bindings].sort((left, right) => left.position - right.position);
  if (!ordered.every(({ position }, index) => Number.isInteger(position) && position === index + 1)) {
    fail('PERMUTATION_CELL_SHAPE_INVALID', 'cell positions are not contiguous');
  }
  if (new Set(ordered.map(({ dimension }) => dimension)).size !== ordered.length
    || new Set(ordered.map(({ key }) => key)).size !== ordered.length) {
    fail('PERMUTATION_CELL_SHAPE_INVALID', 'cell repeats a dimension or key');
  }
  const stableKey = [
    `family=${encodeURIComponent(family)}`,
    `subject=${encodeURIComponent(capability)}`,
    ...ordered.map(({ key, value }) => `${key}=${encodeURIComponent(value)}`),
  ].join('|');
  const cellDigest = sha256(stableKey);
  return {
    cellDigest,
    cellIri: `${CELL_PREFIX}${cellDigest.slice('sha256:'.length)}`,
    identityAlgorithm: 'family-subject-ordered-dimension-identity-v1',
    stableKey,
  };
}

function independentDisposition(family, bindings, authorityInputs) {
  const value = (key) => bindings.find((binding) => binding.key === key)?.value;
  const provenance = {
    authorityDigest: authorityInputs.authorityDigest,
    authorityPacketDigest: authorityInputs.authorityPacketDigest,
    authorityProjectionDigest: authorityInputs.authorityProjectionDigest,
  };
  if (family === EXACT_FAMILY.operationPermission) {
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
  if (family === EXACT_FAMILY.operationRole || family === EXACT_FAMILY.permissionRoleTenant) {
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

function independentClosureClassification(disposition) {
  if ([DISPOSITIONS.required, DISPOSITIONS.allowed].includes(disposition)) {
    return { applicability: 'APPLICABLE', representation: 'OPERATIONAL_CELL', satisfiability: 'SATISFIABLE' };
  }
  if (disposition === DISPOSITIONS.forbidden) {
    return { applicability: 'APPLICABLE', representation: 'RULE_COVERED', satisfiability: 'UNSATISFIABLE' };
  }
  if (disposition === DISPOSITIONS.notApplicable) {
    return { applicability: 'NOT_APPLICABLE', representation: 'RULE_COVERED', satisfiability: 'NOT_APPLICABLE' };
  }
  if ([DISPOSITIONS.deferred, DISPOSITIONS.unresolved].includes(disposition)) {
    return { applicability: 'UNDETERMINED', representation: 'PENDING_REGION', satisfiability: 'UNDETERMINED' };
  }
  fail('PERMUTATION_CELL_DISPOSITION_INVALID', `unknown disposition ${disposition}`);
}

function independentDomainScope(cell) {
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

function independentCoverageRule(cell, authorityInputs, coverageRules) {
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
  fail('PERMUTATION_SYMBOLIC_COVERAGE_RULE_UNREGISTERED', `${assignment.reasonCode} is not independently registered`);
}

function addRegionMember(regions, core, stableKey) {
  const regionKey = canonicalJson(core);
  if (!regions.has(regionKey)) regions.set(regionKey, { core, count: 0, hash: createHash('sha256'), regionKey });
  const region = regions.get(regionKey);
  region.count += 1;
  region.hash.update(`${stableKey}\n`);
}

function finaliseRegions(regions) {
  return [...regions.values()].map(({ core, count, hash, regionKey }) => {
    const record = {
      ...core,
      coveredCellCount: count,
      coveredStableKeySequenceDigest: `sha256:${hash.digest('hex')}`,
      regionKey,
    };
    return { ...record, regionDigest: fullDigest(record) };
  }).sort((left, right) => compareCodeUnits(left.regionKey, right.regionKey));
}

function independentPublicationBudget({
  liveTripleCount,
  operationalCellCount,
  pendingRegionCount,
  providerEdgeLimit,
  publicationReserve,
  ruleRegionCount,
  policy,
}) {
  for (const [name, value] of Object.entries({
    liveTripleCount,
    operationalCellCount,
    pendingRegionCount,
    providerEdgeLimit,
    publicationReserve,
    ruleRegionCount,
  })) {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail('PERMUTATION_PUBLICATION_BUDGET_INVALID', `${name} is invalid`);
    }
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
  const encodingPolicy = policy.encodingPolicy;
  const candidateTripleUpperBound = encodingPolicy.fixedManifestTripleUpperBound
    + operationalCellCount * encodingPolicy.operationalCellTripleUpperBound
    + (pendingRegionCount + ruleRegionCount) * encodingPolicy.regionTripleUpperBound;
  const maximumProjectedTripleCount = policy.maximumProjectedStatementCount;
  const projectedTripleUpperBound = liveTripleCount + candidateTripleUpperBound;
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
  return {
    ...core,
    budgetDigest: fullDigest(core),
    result: projectedTripleUpperBound <= maximumProjectedTripleCount ? 'PREFLIGHT_PASS' : 'REJECTED',
  };
}

function* cartesian(domains) {
  if (domains.length === 0) {
    yield [];
    return;
  }
  if (domains.some(({ values: domainValues }) => domainValues.length === 0)) return;
  const indexes = new Array(domains.length).fill(0);
  while (true) {
    yield indexes.map((index, position) => domains[position].values[index]);
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

function reconstruct(metaModel, authorityInputs, census) {
  const plans = [];
  const domainRecords = [];
  const expectedCountsByPair = [];
  const gaps = [];
  const pairIndex = new Map();
  let cellCount = 0;
  for (const record of census.records.filter(({ disposition }) => disposition === 'MATRIX_REQUIRED')) {
    const familyNames = values(metaModel.store, record.family, 'canonicalName');
    if (familyNames.length !== 1 || familyNames[0] !== record.canonicalName) {
      fail('PERMUTATION_META_MODEL_INVALID', `${record.family} canonical name differs from census`);
    }
    const subject = record.subject;
    const domains = familyDimensions(metaModel, record.family)
      .map((descriptor) => resolveDomain(metaModel, authorityInputs, subject, descriptor));
    const empty = domains.filter(({ values: domainValues }) => domainValues.length === 0);
    const expectedCellCount = empty.length > 0
      ? 0
      : domains.reduce((product, domain) => product * domain.values.length, 1);
    const plan = { domains, expectedCellCount, record };
    plans.push(plan);
    pairIndex.set(`${record.family}\u0000${subject}`, plan);
    cellCount += expectedCellCount;
    for (const domain of domains) {
      const { values: omitted, ...descriptor } = domain;
      domainRecords.push({ capability: record.capability, family: record.family, subject, ...descriptor });
    }
    for (const domain of empty) {
      gaps.push({
        capability: record.capability,
        code: 'REQUIRED_FINITE_DOMAIN_EMPTY',
        dimension: domain.dimension,
        dimensionKey: domain.key,
        family: record.family,
        source: domain.source,
        sourceKind: domain.sourceKind,
        sourcePlane: domain.sourcePlane,
        subject,
        subjectClass: record.subjectClass,
      });
    }
    expectedCountsByPair.push({
      capability: record.capability,
      expectedCellCount,
      family: record.family,
      generatedCellCount: expectedCellCount,
      subject,
    });
  }
  return { cellCount, domainRecords, expectedCountsByPair, gaps, pairIndex, plans };
}

function* expectedKeys(plans) {
  for (const { domains, record } of plans) {
    for (const combination of cartesian(domains)) {
      const bindings = domains.map((domain, index) => ({
        dimension: domain.dimension,
        key: domain.key,
        position: domain.position,
        value: combination[index],
        valueSetDigest: domain.valueSetDigest,
      }));
      yield independentIdentity(record.family, record.subject, bindings).stableKey;
    }
  }
}

function inspectCell(cell, plan, authorityInputs, diagnostics, index) {
  if (!plan || !Array.isArray(cell.dimensionBindings)) {
    diagnostics.add('PERMUTATION_CELL_SHAPE_INVALID', { index, stableKey: cell?.stableKey });
    return null;
  }
  if (typeof cell.subject !== 'string' || cell.subject.length === 0) {
    diagnostics.add('PERMUTATION_CELL_SUBJECT_ABSENT', { index, stableKey: cell?.stableKey });
    return null;
  }
  if (cell.subject !== plan.record.subject) {
    diagnostics.add('PERMUTATION_CELL_SUBJECT_MISMATCH', {
      actual: cell.subject,
      expected: plan.record.subject,
      index,
      stableKey: cell.stableKey,
    });
  }
  const expectedBindings = plan.domains.map((domain) => ({
    dimension: domain.dimension,
    key: domain.key,
    position: domain.position,
    valueSetDigest: domain.valueSetDigest,
  }));
  const actualDescriptors = cell.dimensionBindings.map(({ dimension, key, position, valueSetDigest }) => ({
    dimension, key, position, valueSetDigest,
  }));
  if (canonicalJson(actualDescriptors) !== canonicalJson(expectedBindings)
    || !cell.dimensionBindings.every((binding, bindingIndex) => plan.domains[bindingIndex]?.values.includes(binding.value))) {
    diagnostics.add('PERMUTATION_CELL_SHAPE_INVALID', {
      capability: cell.capability,
      family: cell.family,
      index,
      stableKey: cell.stableKey,
    });
  }
  let identity;
  try {
    identity = independentIdentity(cell.family, cell.subject, cell.dimensionBindings);
  } catch (error) {
    diagnostics.add(error.code ?? 'PERMUTATION_CELL_SHAPE_INVALID', { index, stableKey: cell.stableKey });
    return null;
  }
  if (identity.stableKey !== cell.stableKey
    || identity.cellDigest !== cell.cellDigest
    || identity.cellIri !== cell.cellIri
    || identity.identityAlgorithm !== cell.identityAlgorithm) {
    diagnostics.add('PERMUTATION_CELL_IDENTITY_INVALID', {
      actual: cell.stableKey,
      expected: identity.stableKey,
      index,
    });
  }
  if (cell.authorityDigest !== authorityInputs.authorityDigest
    || cell.familyCanonicalName !== plan.record.canonicalName
    || canonicalJson(cell.dimensionKeys) !== canonicalJson(cell.dimensionBindings.map(({ key }) => key))
    || canonicalJson(cell.dimensionValues) !== canonicalJson(cell.dimensionBindings.map(({ value }) => value))) {
    diagnostics.add('PERMUTATION_CELL_SHAPE_INVALID', { index, stableKey: identity.stableKey });
  }
  if (!Array.isArray(cell.dispositions) || cell.dispositions.length === 0 || !cell.disposition) {
    diagnostics.add('PERMUTATION_CELL_DISPOSITION_ABSENT', { index, stableKey: identity.stableKey });
  } else if (cell.dispositions.length !== 1) {
    diagnostics.add('PERMUTATION_CELL_DISPOSITION_MULTIPLE', { index, stableKey: identity.stableKey });
  } else if (!DISPOSITION_SET.has(cell.disposition) || cell.dispositions[0].iri !== cell.disposition) {
    diagnostics.add('PERMUTATION_CELL_DISPOSITION_INVALID', { index, stableKey: identity.stableKey });
  } else {
    const expectedDisposition = independentDisposition(cell.family, cell.dimensionBindings, authorityInputs);
    if (canonicalJson(cell.dispositions[0]) !== canonicalJson(expectedDisposition)) {
      diagnostics.add('PERMUTATION_CELL_DISPOSITION_MISMATCH', {
        actual: cell.dispositions[0],
        expected: expectedDisposition,
        index,
        stableKey: identity.stableKey,
      });
    }
  }
  return identity;
}

function candidateSetFromCells(candidateMap, sourceCellCount) {
  const candidates = [...candidateMap.values()].map((candidate) => {
    const candidateCore = { capability: candidate.capability, sourcePermission: candidate.sourcePermission };
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
  return {
    candidateCount: candidates.length,
    candidates,
    candidateSetDigest: fullDigest(candidates),
    gaps: candidates.map((candidate) => ({
      candidateDigest: candidate.candidateDigest,
      code: 'PERMISSION_ATOM_REQUIRED_PROPERTIES_UNDERIVED',
      missingProperties: [...candidate.missingProperties],
    })),
    recordKind: 'USF_PERMISSION_ATOM_CANDIDATE_SET',
    schemaVersion: 1,
    sourceCellCount,
  };
}

function independentSelectorValue(authorityInputs, selector, subject) {
  if (!independentResourceHasClosureType(authorityInputs.index, subject, [selector.subjectClassClosure])) {
    fail('PERMUTATION_CENSUS_SUBJECT_CLASS_MISMATCH', `${subject} is outside ${selector.subjectClassIri}`);
  }
  let frontier = [subject];
  for (const step of selector.steps) {
    frontier = step.directionIri === 'urn:usf:permutationpathdirection:outbound'
      ? uniqueSorted(frontier.flatMap((value) => authorityInputs.index.values(value, step.predicateIri)))
      : uniqueSorted(frontier.flatMap((value) => authorityInputs.index.subjects(step.predicateIri, value)));
  }
  frontier = frontier.filter((value) => independentResourceHasClosureType(
    authorityInputs.index, value, [selector.terminalClassClosure],
  ));
  return selector.aggregationIri === 'urn:usf:permutationsignalaggregation:countdistinct'
    ? frontier.length : frontier;
}

function independentExpectedValue(value) {
  return canonicalJson(typeof value === 'string' ? { termType: 'NamedNode', value } : value);
}

function independentApplicabilityValue(clause, selectorValues, observed = new Map()) {
  const selectorValue = clause.selectorIri ? selectorValues.get(clause.selectorIri) : undefined;
  if (clause.selectorIri) {
    if (selectorValue === undefined) fail('AUTHORITY_SIGNAL_MISSING', `${clause.selectorIri} has no value`);
    observed.set(clause.selectorIri, selectorValue);
  }
  switch (clause.operatorIri) {
    case INDEPENDENT_APPLICABILITY_OPERATORS.true: return true;
    case INDEPENDENT_APPLICABILITY_OPERATORS.allOf:
      return clause.operands.map(({ clause: child }) => (
        independentApplicabilityValue(child, selectorValues, observed)
      )).every(Boolean);
    case INDEPENDENT_APPLICABILITY_OPERATORS.anyOf:
      return clause.operands.map(({ clause: child }) => (
        independentApplicabilityValue(child, selectorValues, observed)
      )).some(Boolean);
    case INDEPENDENT_APPLICABILITY_OPERATORS.not:
      return !independentApplicabilityValue(clause.operands[0].clause, selectorValues, observed);
    case INDEPENDENT_APPLICABILITY_OPERATORS.countAtLeast: {
      const count = Array.isArray(selectorValue) ? selectorValue.length : Number(selectorValue);
      return Number.isSafeInteger(count) && count >= clause.threshold;
    }
    case INDEPENDENT_APPLICABILITY_OPERATORS.countExactly: {
      const count = Array.isArray(selectorValue) ? selectorValue.length : Number(selectorValue);
      return Number.isSafeInteger(count) && count === clause.threshold;
    }
    case INDEPENDENT_APPLICABILITY_OPERATORS.valueEquals:
      return (Array.isArray(selectorValue) ? selectorValue : [selectorValue])
        .some((value) => independentExpectedValue(value) === canonicalJson(clause.expectedValues[0]));
    case INDEPENDENT_APPLICABILITY_OPERATORS.valueInDeclaredSet: {
      const expected = new Set(clause.expectedValues.map(canonicalJson));
      return (Array.isArray(selectorValue) ? selectorValue : [selectorValue])
        .some((value) => expected.has(independentExpectedValue(value)));
    }
    default: fail('APPLICABILITY_OPERATOR_UNSUPPORTED', clause.operatorIri);
  }
}

function independentRuleSelectors(clause, output = new Set()) {
  if (clause.selectorIri) output.add(clause.selectorIri);
  for (const { clause: child } of clause.operands) independentRuleSelectors(child, output);
  return output;
}

function reconstructIndependentCensus(authorityInputs, metaModel) {
  const subjectCountsByRegistration = {};
  const subjectSetDigestsByRegistration = {};
  const subjectClassClosureDigestsByRegistration = {};
  const subjectsByRegistration = new Map();
  const registrations = new Map();
  for (const family of metaModel.familyRegistry.families) {
    const closure = metaModel.classClosures.byRoot.get(family.subjectClassIri);
    if (!closure || closure.digest !== family.subjectClassClosureDigest) {
      fail('PERMUTATION_CENSUS_SUBJECT_CLASS_MISMATCH', `${family.registrationIri} closure differs`);
    }
    const prior = registrations.get(family.registrationIri);
    if (prior && (prior.subjectClassIri !== family.subjectClassIri || prior.closure.digest !== closure.digest)) {
      fail('PERMUTATION_CENSUS_SUBJECT_CLASS_MISMATCH', `${family.registrationIri} is contradictory`);
    }
    registrations.set(family.registrationIri, { closure, subjectClassIri: family.subjectClassIri });
  }
  for (const [registrationIri, { closure }] of [...registrations].sort(([left], [right]) => compareCodeUnits(left, right))) {
    const subjects = independentClosureInstances(authorityInputs, [closure]);
    subjectsByRegistration.set(registrationIri, subjects);
    subjectCountsByRegistration[registrationIri] = subjects.length;
    subjectSetDigestsByRegistration[registrationIri] = fullDigest(subjects);
    subjectClassClosureDigestsByRegistration[registrationIri] = closure.digest;
  }
  const records = [];
  const allSubjects = new Set();
  const dispositionCounts = { MATRIX_NOT_APPLICABLE: 0, MATRIX_REQUIRED: 0 };
  for (const family of metaModel.familyRegistry.families) {
    const rule = metaModel.rules.get(family.ruleIri);
    for (const subject of subjectsByRegistration.get(family.registrationIri)) {
      allSubjects.add(subject);
      const selectorValues = new Map([...independentRuleSelectors(rule.rootClause)].sort(compareCodeUnits)
        .map((selectorIri) => [selectorIri,
          independentSelectorValue(authorityInputs, metaModel.selectors.get(selectorIri), subject)]));
      const observed = new Map();
      const applicable = independentApplicabilityValue(rule.rootClause, selectorValues, observed);
      const disposition = applicable ? 'MATRIX_REQUIRED' : 'MATRIX_NOT_APPLICABLE';
      dispositionCounts[disposition] += 1;
      const signals = Object.fromEntries([...observed].map(([selectorIri, value]) => [
        metaModel.selectors.get(selectorIri).canonicalName, value,
      ]).sort(([left], [right]) => compareCodeUnits(left, right)));
      const capabilityFamily = family.subjectClassIri === `${O}Capability`;
      records.push({
        capability: capabilityFamily ? subject : null,
        contract: capabilityFamily ? contractForCapability(authorityInputs.index, subject) : null,
        family: family.familyIri,
        familyKey: family.canonicalName,
        canonicalName: family.canonicalName,
        disposition,
        reasonCode: applicable ? null : rule.unsatisfiedReasonIri,
        registrationIri: family.registrationIri,
        ruleDigest: family.ruleDigest,
        signals,
        subject,
        subjectClass: family.subjectClassIri,
        subjectClassClosureDigest: family.subjectClassClosureDigest,
        provenance: {
          authorityDigest: authorityInputs.authorityDigest,
          authorityProjectionDigest: authorityInputs.authorityProjectionDigest,
          familyRegistryDigest: metaModel.familyRegistry.registryDigest,
          kind: 'LIVE_AUTHORITY_PROJECTION',
          signalKeys: Object.keys(signals).sort(compareCodeUnits),
        },
      });
    }
  }
  records.sort((left, right) => compareCodeUnits(canonicalJson([left.family, left.subject]),
    canonicalJson([right.family, right.subject])));
  const pairKeys = records.map(({ family, subject }) => `${family}\u0000${subject}`);
  return {
    dispositionCounts,
    expectedPairCount: pairKeys.length,
    familyCount: metaModel.familyRegistry.families.length,
    pairSetDigest: fullDigest(pairKeys),
    records,
    recordsDigest: fullDigest(records),
    subjectClassClosureDigestsByRegistration,
    subjectCount: allSubjects.size,
    subjectCountsByRegistration,
    subjectSetDigestsByRegistration,
  };
}

function validateCensus(census, authorityInputs, metaModel) {
  if (census?.recordKind !== 'USF_PERMUTATION_FAMILY_CENSUS' || census.schemaVersion !== 4
    || !Array.isArray(census.records)) {
    fail('PERMUTATION_INPUT_SCHEMA_INVALID', 'census schema is not registered-subject v4');
  }
  if (census.authorityDigest !== authorityInputs.authorityDigest
    || census.authorityPacketDigest !== authorityInputs.authorityPacketDigest
    || census.authorityProjectionDigest !== authorityInputs.authorityProjectionDigest) {
    fail('PERMUTATION_INPUT_BINDING_MISMATCH', 'census authority bindings differ');
  }
  if (census.familyRegistryDigest !== metaModel.familyRegistry.registryDigest) {
    fail('PERMUTATION_INPUT_BINDING_MISMATCH', 'census family registry differs from independent reconstruction');
  }
  if (fullDigest(census.records) !== census.recordsDigest) {
    fail('PERMUTATION_INPUT_DIGEST_MISMATCH', 'census records digest differs');
  }
  const expectedDigest = fullDigest({
    authorityDigest: census.authorityDigest,
    authorityPacketDigest: census.authorityPacketDigest,
    authorityProjectionDigest: census.authorityProjectionDigest,
    familyRegistryDigest: census.familyRegistryDigest,
    dispositionCounts: census.dispositionCounts,
    expectedPairCount: census.expectedPairCount,
    familyCount: census.familyCount,
    recordsDigest: census.recordsDigest,
    pairSetDigest: census.pairSetDigest,
    subjectCount: census.subjectCount,
    subjectCountsByRegistration: census.subjectCountsByRegistration,
    subjectSetDigestsByRegistration: census.subjectSetDigestsByRegistration,
    subjectClassClosureDigestsByRegistration: census.subjectClassClosureDigestsByRegistration,
  });
  if (census.censusDigest !== expectedDigest) {
    fail('PERMUTATION_INPUT_DIGEST_MISMATCH', 'census descriptor digest differs');
  }
  const expected = reconstructIndependentCensus(authorityInputs, metaModel);
  const suppliedPairs = census.records.map(({ family, subject }) => `${family}\u0000${subject}`);
  if (new Set(suppliedPairs).size !== suppliedPairs.length) {
    fail('PERMUTATION_INPUT_SCHEMA_INVALID', 'census has duplicate pairs');
  }
  const expectedPairs = expected.records.map(({ family, subject }) => `${family}\u0000${subject}`);
  const suppliedPairSet = new Set(suppliedPairs);
  const expectedPairSet = new Set(expectedPairs);
  const missingPairs = expectedPairs.filter((pair) => !suppliedPairSet.has(pair));
  const extraPairs = suppliedPairs.filter((pair) => !expectedPairSet.has(pair));
  if (missingPairs.length) {
    fail('PERMUTATION_CENSUS_REGION_MISSING', 'census omits independently reconstructed subject-family regions', {
      missingPairCount: missingPairs.length,
      missingPairDigest: fullDigest(missingPairs),
    });
  }
  if (extraPairs.length) {
    fail('PERMUTATION_CENSUS_REGION_EXTRA', 'census adds subject-family regions absent from independent reconstruction', {
      extraPairCount: extraPairs.length,
      extraPairDigest: fullDigest(extraPairs),
    });
  }
  for (const field of [
    'dispositionCounts', 'expectedPairCount', 'familyCount', 'pairSetDigest', 'recordsDigest',
    'subjectClassClosureDigestsByRegistration', 'subjectCount', 'subjectCountsByRegistration',
    'subjectSetDigestsByRegistration',
  ]) {
    if (canonicalJson(census[field]) !== canonicalJson(expected[field])) {
      fail(field === 'recordsDigest' || field === 'pairSetDigest'
        ? 'PERMUTATION_INPUT_DIGEST_MISMATCH' : 'PERMUTATION_INPUT_BINDING_MISMATCH',
      `census ${field} differs from independent reconstruction`, { field });
    }
  }
  if (canonicalJson(census.records) !== canonicalJson(expected.records)) {
    const mismatchIndex = census.records.findIndex((record, index) => (
      canonicalJson(record) !== canonicalJson(expected.records[index])
    ));
    fail('PERMUTATION_CENSUS_RECORD_MISMATCH', 'census records differ from independent reconstruction', {
      actual: census.records[mismatchIndex] ?? null,
      expected: expected.records[mismatchIndex] ?? null,
      index: mismatchIndex,
    });
  }
}

export function proveUniverseManifest({ manifest, census, authorityInputs, repositoryRoot }) {
  const diagnostics = diagnosticCollector();
  let verified;
  let metaModel;
  let expected;
  try {
    verified = assertVerifiedAuthorityInputs(authorityInputs);
    if (manifest?.recordKind !== 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST' || manifest.schemaVersion !== 3) {
      fail('PERMUTATION_INPUT_SCHEMA_INVALID', 'universe manifest schema is not v3');
    }
    metaModel = loadIndependentMetaModel(repositoryRoot);
    validateCensus(census, verified, metaModel);
    const bindings = manifest.inputBindings ?? {};
    const algorithmBindings = sourceAlgorithmBindings(metaModel.coverageRules.digest);
    if (manifest.authorityDigest !== verified.authorityDigest
      || bindings.authorityDigest !== verified.authorityDigest
      || bindings.authorityPacketDigest !== verified.authorityPacketDigest
      || bindings.authorityProjectionDigest !== verified.authorityProjectionDigest
      || bindings.familyCensusDigest !== census.censusDigest
      || manifest.familyCensusDigest !== census.censusDigest
      || bindings.metaModelDigest !== metaModel.digest
      || bindings.publicationBudgetPolicyDigest !== metaModel.publicationBudgetPolicy.digest
      || Object.entries(algorithmBindings).some(([field, value]) => bindings[field] !== value)) {
      fail('PERMUTATION_INPUT_BINDING_MISMATCH', 'manifest input bindings differ');
    }
    expected = reconstruct(metaModel, verified, census);
    if (manifest.finiteDomainDigest !== fullDigest(expected.domainRecords)) {
      fail('PERMUTATION_INPUT_DIGEST_MISMATCH', 'finite domain digest differs');
    }
  } catch (error) {
    diagnostics.add(error.code ?? 'PERMUTATION_INPUT_SCHEMA_INVALID', error.details ?? { message: error.message });
    return finalProof(manifest, census, diagnostics.list(), {
      actualCellCount: 0,
      expectedCellCount: 0,
      unresolvedCount: 0,
    });
  }

  for (const gap of expected.gaps) diagnostics.add('REQUIRED_FINITE_DOMAIN_EMPTY', gap, 'INCOMPLETE');
  if (canonicalJson(manifest.domainRecords) !== canonicalJson(expected.domainRecords)) {
    diagnostics.add('PERMUTATION_DOMAIN_RECORD_MISMATCH', {
      actualDigest: fullDigest(manifest.domainRecords),
      expectedDigest: fullDigest(expected.domainRecords),
    });
  }
  if (canonicalJson(manifest.expectedCountsByPair) !== canonicalJson(expected.expectedCountsByPair)
    || canonicalJson(manifest.gaps) !== canonicalJson(expected.gaps)) {
    diagnostics.add('PERMUTATION_SUMMARY_MISMATCH', { field: 'expectedCountsByPair/gaps' });
  }

  const expectedIterator = expectedKeys(expected.plans);
  const expectedKeysHash = createHash('sha256');
  const actualKeysHash = createHash('sha256');
  const dispositionCounts = Object.fromEntries(Object.values(DISPOSITIONS).map((iri) => [iri, 0]));
  const families = new Set();
  const cellsHash = createHash('sha256');
  const permissionCandidates = new Map();
  let permissionSourceCellCount = 0;
  let actualCellCount = 0;
  let orderMismatchRecorded = false;
  const generatedRoot = resolve(repositoryRoot, '.work', 'generated');

  for (const [segmentIndex, segment] of (manifest.cellSegments ?? []).entries()) {
    try {
      const absolutePath = resolve(repositoryRoot, segment.path);
      if (!absolutePath.startsWith(`${generatedRoot}/`)
        || basename(absolutePath) !== `permutation-cell-segment-${segment.digest?.slice('sha256:'.length)}.ndjson.gz`
        || !existsSync(absolutePath) || !lstatSync(absolutePath).isFile() || lstatSync(absolutePath).isSymbolicLink()
        || realpathSync(absolutePath) !== absolutePath) {
        fail('PERMUTATION_INPUT_BINDING_MISMATCH', 'segment path is outside the authorised generated root or address');
      }
      const compressed = readFileSync(absolutePath);
      if (sha256(compressed) !== segment.digest || compressed.byteLength !== segment.byteCount) {
        fail('PERMUTATION_INPUT_DIGEST_MISMATCH', 'segment compressed bytes differ');
      }
      const content = gunzipSync(compressed);
      if (sha256(content) !== segment.contentDigest || content.byteLength !== segment.uncompressedByteCount
        || content.at(-1) !== 10 || segment.compression !== 'GZIP_LEVEL_9_MTIME_0') {
        fail('PERMUTATION_INPUT_DIGEST_MISMATCH', 'segment content or compression binding differs');
      }
      cellsHash.update(content);
      const lines = content.subarray(0, content.length - 1).toString('utf8').split('\n');
      if (lines.length !== segment.cellCount || segment.index !== segmentIndex) {
        fail('PERMUTATION_SUMMARY_MISMATCH', 'segment count or index differs');
      }
      let firstCellIri;
      let lastCellIri;
      for (const line of lines) {
        const cell = JSON.parse(line);
        if (firstCellIri === undefined) firstCellIri = cell.cellIri;
        lastCellIri = cell.cellIri;
        const plan = typeof cell.subject === 'string'
          ? expected.pairIndex.get(`${cell.family}\u0000${cell.subject}`) : null;
        const identity = inspectCell(cell, plan, verified, diagnostics, actualCellCount);
        const stableKey = identity?.stableKey ?? cell.stableKey;
        actualKeysHash.update(`${stableKey}\n`);
        const expectedNext = expectedIterator.next();
        if (expectedNext.done) {
          diagnostics.add('PERMUTATION_UNIVERSE_EXTRA_CELL', { stableKey });
        } else {
          expectedKeysHash.update(`${expectedNext.value}\n`);
        }
        if (!expectedNext.done && !orderMismatchRecorded && expectedNext.value !== stableKey) {
          diagnostics.add('PERMUTATION_CELL_ORDER_MISMATCH', {
            actual: stableKey,
            expected: expectedNext.value,
            index: actualCellCount,
          });
          orderMismatchRecorded = true;
        }
        if (DISPOSITION_SET.has(cell.disposition)) dispositionCounts[cell.disposition] += 1;
        families.add(cell.family);
        if (cell.family === EXACT_FAMILY.operationPermission
          && [DISPOSITIONS.required, DISPOSITIONS.allowed].includes(cell.disposition)) {
          const sourcePermission = cell.dimensionBindings.find(({ key }) => key === 'permissionatom')?.value;
          const operation = cell.dimensionBindings.find(({ key }) => key === 'operation')?.value;
          const candidateKey = canonicalJson({ capability: cell.capability, sourcePermission });
          if (!permissionCandidates.has(candidateKey)) {
            permissionCandidates.set(candidateKey, {
              authorityDigest: verified.authorityDigest,
              capability: cell.capability,
              operations: new Set(),
              sourceCells: new Set(),
              sourcePermission,
            });
          }
          permissionCandidates.get(candidateKey).operations.add(operation);
          permissionCandidates.get(candidateKey).sourceCells.add(cell.cellIri);
          permissionSourceCellCount += 1;
        }
        actualCellCount += 1;
      }
      if (segment.firstCellIri !== firstCellIri || segment.lastCellIri !== lastCellIri) {
        fail('PERMUTATION_SUMMARY_MISMATCH', 'segment boundary identity differs');
      }
    } catch (error) {
      diagnostics.add(error.code ?? 'PERMUTATION_INPUT_SCHEMA_INVALID', {
        message: error.message,
        segmentIndex,
      });
    }
  }

  for (let next = expectedIterator.next(); !next.done; next = expectedIterator.next()) {
    expectedKeysHash.update(`${next.value}\n`);
    diagnostics.add('PERMUTATION_UNIVERSE_MISSING_CELL', { stableKey: next.value });
  }
  if (actualCellCount === 0 && expected.cellCount > 0) diagnostics.add('PERMUTATION_UNIVERSE_EMPTY');
  const cellsDigest = `sha256:${cellsHash.digest('hex')}`;
  const expectedStableKeySequenceDigest = `sha256:${expectedKeysHash.digest('hex')}`;
  const actualStableKeySequenceDigest = `sha256:${actualKeysHash.digest('hex')}`;
  if (expectedStableKeySequenceDigest !== actualStableKeySequenceDigest
    && !orderMismatchRecorded) {
    diagnostics.add('PERMUTATION_CELL_ORDER_MISMATCH', {
      actual: actualStableKeySequenceDigest,
      expected: expectedStableKeySequenceDigest,
    });
  }
  const candidateSet = candidateSetFromCells(permissionCandidates, permissionSourceCellCount);
  const expectedStructuralVerdict = expected.gaps.length === 0
    ? 'GENERATOR_STRUCTURAL_INVARIANTS_PASS'
    : 'GENERATOR_STRUCTURAL_GAPS';
  if (manifest.cellCount !== actualCellCount
    || manifest.cellCount !== expected.cellCount
    || manifest.cellsDigest !== cellsDigest
    || manifest.stableKeySequenceDigest !== actualStableKeySequenceDigest
    || canonicalJson(manifest.dispositionCounts) !== canonicalJson(dispositionCounts)
    || manifest.familiesGenerated !== families.size
    || manifest.structuralVerdict !== expectedStructuralVerdict
    || manifest.permissionAtomCandidateCount !== candidateSet.candidateCount
    || manifest.permissionAtomSourceCellCount !== candidateSet.sourceCellCount
    || canonicalJson(manifest.permissionAtomCandidateSet) !== canonicalJson(candidateSet)) {
    diagnostics.add('PERMUTATION_SUMMARY_MISMATCH', { field: 'aggregate manifest summary' });
  }
  const { authorityDigest, recordKind, schemaVersion, universeDigest, ...descriptor } = manifest;
  if (recordKind !== 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST'
    || schemaVersion !== 3
    || fullDigest(descriptor) !== universeDigest) {
    diagnostics.add('PERMUTATION_INPUT_DIGEST_MISMATCH', { field: 'universeDigest' });
  }
  const unresolvedCount = dispositionCounts[DISPOSITIONS.unresolved];
  if (unresolvedCount > 0) {
    diagnostics.add('PERMUTATION_UNIVERSE_UNRESOLVED', { unresolvedCount }, 'INCOMPLETE');
  }
  return finalProof(manifest, census, diagnostics.list(), {
    actualCellCount,
    actualStableKeySequenceDigest,
    cellsDigest,
    dispositionCounts,
    expectedCellCount: expected.cellCount,
    expectedStableKeySequenceDigest,
    permissionAtomCandidateCount: candidateSet.candidateCount,
    requiredFiniteDomainGapCount: expected.gaps.length,
    unresolvedCount,
  });
}

function assertRawProofSuitableForSparse(rawProof, rawManifest, authorityInputs) {
  if (rawProof?.recordKind !== 'USF_PERMUTATION_UNIVERSE_INDEPENDENT_PROOF'
    || rawProof.schemaVersion !== 2
    || rawProof.authorityDigest !== authorityInputs.authorityDigest
    || rawProof.universeDigest !== rawManifest.universeDigest) {
    fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', 'raw independent proof binding is invalid');
  }
  const { proofDigest, recordKind, schemaVersion, ...proofCore } = rawProof;
  if (recordKind !== 'USF_PERMUTATION_UNIVERSE_INDEPENDENT_PROOF'
    || schemaVersion !== 2
    || fullDigest(proofCore) !== proofDigest) {
    fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', 'raw independent proof digest is invalid');
  }
  const permittedIncompleteCodes = new Set([
    'PERMUTATION_UNIVERSE_UNRESOLVED',
    'REQUIRED_FINITE_DOMAIN_EMPTY',
  ]);
  const invalidDiagnostics = (rawProof.diagnostics ?? [])
    .filter(({ code }) => !permittedIncompleteCodes.has(code));
  if (invalidDiagnostics.length > 0) {
    fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', 'raw proof contains structural defects', {
      diagnosticCodes: invalidDiagnostics.map(({ code }) => code).sort(),
    });
  }
}

function finalSparseProof(sparseManifest, rawManifest, rawProof, diagnostics, results) {
  const errorCount = diagnostics
    .filter(({ severity }) => severity === 'ERROR')
    .reduce((sum, { count }) => sum + count, 0);
  const incomplete = (results.pendingCoveredCellCount ?? 0) > 0
    || (results.requiredFiniteDomainGapCount ?? 0) > 0;
  const verdict = errorCount > 0
    ? 'INVARIANTS_FAILED'
    : incomplete
      ? 'PERMUTATION_CLOSURE_INCOMPLETE'
      : 'SPARSE_SYMBOLIC_INVARIANTS_PASS';
  const bindings = sparseManifest?.inputBindings ?? {};
  const proofCore = {
    applicabilityRuleDigest: sparseManifest?.applicabilityRuleDigest,
    authorityDigest: sparseManifest?.authorityDigest,
    diagnostics,
    finiteDomainDigest: bindings.finiteDomainDigest,
    generatorDigest: bindings.generatorDigest,
    independentVerifierDigest: bindings.independentVerifierDigest,
    rawManifestDigest: bindings.rawManifestDigest,
    rawProofDigest: rawProof?.proofDigest,
    rawUniverseDigest: rawManifest?.universeDigest,
    results,
    sparseManifestDigest: sparseManifest?.sparseManifestDigest,
    verdict,
  };
  return {
    ...proofCore,
    proofDigest: fullDigest(proofCore),
    recordKind: 'USF_PERMUTATION_SPARSE_SYMBOLIC_INDEPENDENT_PROOF',
    schemaVersion: 1,
  };
}

export function proveSparseSymbolicManifest({
  authorityInputs,
  rawManifest,
  rawManifestDigest,
  rawProof,
  repositoryRoot,
  sparseManifest,
}) {
  const diagnostics = diagnosticCollector();
  const emptyResults = {
    operationalCellCount: 0,
    pendingCoveredCellCount: 0,
    rawCandidateCount: 0,
    requiredFiniteDomainGapCount: rawManifest?.gaps?.length ?? 0,
    ruleCoveredCellCount: 0,
  };
  let verified;
  let metaModel;
  try {
    verified = assertVerifiedAuthorityInputs(authorityInputs);
    metaModel = loadIndependentMetaModel(repositoryRoot);
    if (sparseManifest?.recordKind !== 'USF_PERMUTATION_SPARSE_SYMBOLIC_MANIFEST'
      || sparseManifest.schemaVersion !== 1
      || rawManifest?.recordKind !== 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST'
      || rawManifest.schemaVersion !== 3) {
      fail('PERMUTATION_SPARSE_PROJECTION_SCHEMA_INVALID', 'sparse or raw manifest schema is invalid');
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(rawManifestDigest || '')) {
      fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', 'raw manifest file digest is invalid');
    }
    assertRawProofSuitableForSparse(rawProof, rawManifest, verified);
    const bindings = sparseManifest.inputBindings ?? {};
    const algorithms = sourceAlgorithmBindings(metaModel.coverageRules.digest);
    const expectedBindings = {
      ...rawManifest.inputBindings,
      finiteDomainDigest: rawManifest.finiteDomainDigest,
      rawManifestDigest,
      rawUniverseDigest: rawManifest.universeDigest,
      sourceAuthorityTripleCount: sparseManifest.publicationBudget?.liveTripleCount,
    };
    if (sparseManifest.authorityDigest !== verified.authorityDigest
      || canonicalJson(bindings) !== canonicalJson(expectedBindings)
      || rawManifest.inputBindings?.metaModelDigest !== metaModel.digest
      || rawManifest.inputBindings?.publicationBudgetPolicyDigest !== metaModel.publicationBudgetPolicy.digest
      || Object.entries(algorithms).some(([field, value]) => bindings[field] !== value)
      || sparseManifest.applicabilityRuleDigest !== algorithms.applicabilityRuleDigest) {
      fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', 'sparse manifest input bindings differ');
    }
  } catch (error) {
    diagnostics.add(error.code ?? 'PERMUTATION_SPARSE_PROJECTION_SCHEMA_INVALID', error.details ?? { message: error.message });
    return finalSparseProof(sparseManifest, rawManifest, rawProof, diagnostics.list(), emptyResults);
  }

  const ruleRegions = new Map();
  const pendingRegions = new Map();
  const operationalHash = createHash('sha256');
  const operationalStableKeyHash = createHash('sha256');
  const observedDispositionCounts = Object.fromEntries(Object.values(DISPOSITIONS).map((value) => [value, 0]));
  const expectedClosureCounts = {
    applicability: { applicable: 0, notApplicable: 0, undetermined: 0 },
    rawCandidateCount: 0,
    representation: { operationalCell: 0, pendingRegionMember: 0, ruleCovered: 0 },
    satisfiability: { notApplicable: 0, satisfiable: 0, undetermined: 0, unsatisfiable: 0 },
  };
  const generatedRoot = resolve(repositoryRoot, '.work', 'generated');

  try {
    for (const [segmentIndex, segment] of (rawManifest.cellSegments ?? []).entries()) {
      const absolutePath = resolve(repositoryRoot, segment.path);
      if (!absolutePath.startsWith(`${generatedRoot}/`)
        || basename(absolutePath) !== `permutation-cell-segment-${segment.digest?.slice('sha256:'.length)}.ndjson.gz`
        || !existsSync(absolutePath) || !lstatSync(absolutePath).isFile() || lstatSync(absolutePath).isSymbolicLink()
        || realpathSync(absolutePath) !== absolutePath) {
        fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', `raw segment ${segmentIndex} path is invalid`);
      }
      const compressed = readFileSync(absolutePath);
      const content = gunzipSync(compressed);
      if (sha256(compressed) !== segment.digest || compressed.byteLength !== segment.byteCount
        || sha256(content) !== segment.contentDigest || content.byteLength !== segment.uncompressedByteCount
        || content.at(-1) !== 10 || segment.compression !== 'GZIP_LEVEL_9_MTIME_0') {
        fail('PERMUTATION_INPUT_DIGEST_MISMATCH', `raw segment ${segmentIndex} byte binding differs`);
      }
      const lines = content.subarray(0, content.length - 1).toString('utf8').split('\n');
      if (segment.index !== segmentIndex || lines.length !== segment.cellCount) {
        fail('PERMUTATION_SPARSE_PARTITION_MISMATCH', `raw segment ${segmentIndex} cardinality differs`);
      }
      for (const line of lines) {
        const cell = JSON.parse(line);
        if (canonicalJson(cell) !== line) {
          fail('PERMUTATION_CELL_ENCODING_NON_CANONICAL', `${cell.cellIri ?? 'cell'} is not canonical JSON`);
        }
        const assignment = exactCellDisposition(cell);
        const classification = independentClosureClassification(cell.disposition);
        observedDispositionCounts[cell.disposition] += 1;
        expectedClosureCounts.rawCandidateCount += 1;
        if (classification.applicability === 'APPLICABLE') expectedClosureCounts.applicability.applicable += 1;
        else if (classification.applicability === 'NOT_APPLICABLE') expectedClosureCounts.applicability.notApplicable += 1;
        else expectedClosureCounts.applicability.undetermined += 1;
        if (classification.satisfiability === 'SATISFIABLE') expectedClosureCounts.satisfiability.satisfiable += 1;
        else if (classification.satisfiability === 'UNSATISFIABLE') expectedClosureCounts.satisfiability.unsatisfiable += 1;
        else if (classification.satisfiability === 'NOT_APPLICABLE') expectedClosureCounts.satisfiability.notApplicable += 1;
        else expectedClosureCounts.satisfiability.undetermined += 1;

        if (classification.representation === 'OPERATIONAL_CELL') {
          expectedClosureCounts.representation.operationalCell += 1;
          operationalHash.update(`${line}\n`);
          operationalStableKeyHash.update(`${cell.stableKey}\n`);
        } else if (classification.representation === 'RULE_COVERED') {
          expectedClosureCounts.representation.ruleCovered += 1;
          addRegionMember(ruleRegions, {
            authorising: false,
            authorityDigest: verified.authorityDigest,
            capability: cell.capability,
            coverageBasis: 'AUTHORITY_BACKED_RULE',
            disposition: cell.disposition,
            domainScope: independentDomainScope(cell),
            family: cell.family,
            reasonCode: assignment.reasonCode,
            rule: independentCoverageRule(cell, verified, metaModel.coverageRules),
          }, cell.stableKey);
        } else {
          expectedClosureCounts.representation.pendingRegionMember += 1;
          addRegionMember(pendingRegions, {
            authorising: false,
            authorityDigest: verified.authorityDigest,
            capability: cell.capability,
            coverageBasis: 'EXACT_LOCAL_IDENTITY_SEQUENCE',
            disposition: cell.disposition,
            domainScope: independentDomainScope(cell),
            family: cell.family,
            provenance: assignment.provenance,
            reasonCode: assignment.reasonCode,
            regionKind: cell.disposition === DISPOSITIONS.deferred ? 'DEFERRED' : 'UNRESOLVED',
          }, cell.stableKey);
        }
      }
    }
  } catch (error) {
    diagnostics.add(error.code ?? 'PERMUTATION_SPARSE_PROJECTION_SCHEMA_INVALID', error.details ?? { message: error.message });
  }

  const expectedRuleRegions = finaliseRegions(ruleRegions);
  const expectedPendingRegions = finaliseRegions(pendingRegions);
  const expectedOperationalCellsDigest = `sha256:${operationalHash.digest('hex')}`;
  const expectedOperationalStableKeySequenceDigest = `sha256:${operationalStableKeyHash.digest('hex')}`;
  const operationalCellCount = expectedClosureCounts.representation.operationalCell;
  const ruleCoveredCellCount = expectedClosureCounts.representation.ruleCovered;
  const pendingCoveredCellCount = expectedClosureCounts.representation.pendingRegionMember;

  if (canonicalJson(observedDispositionCounts) !== canonicalJson(rawManifest.dispositionCounts)
    || expectedClosureCounts.rawCandidateCount !== rawManifest.cellCount
    || expectedClosureCounts.rawCandidateCount !== operationalCellCount + ruleCoveredCellCount + pendingCoveredCellCount
    || operationalCellCount !== observedDispositionCounts[DISPOSITIONS.required] + observedDispositionCounts[DISPOSITIONS.allowed]
    || ruleCoveredCellCount !== observedDispositionCounts[DISPOSITIONS.forbidden] + observedDispositionCounts[DISPOSITIONS.notApplicable]
    || pendingCoveredCellCount !== observedDispositionCounts[DISPOSITIONS.deferred] + observedDispositionCounts[DISPOSITIONS.unresolved]) {
    diagnostics.add('PERMUTATION_SPARSE_PARTITION_MISMATCH', { field: 'closure partition' });
  }

  let executedOperationalCellCount = 0;
  const executedContentHash = createHash('sha256');
  const executedStableKeyHash = createHash('sha256');
  const segmentCellLimit = sparseManifest.operationalSegmentCellLimit;
  if (!Number.isSafeInteger(segmentCellLimit) || segmentCellLimit < 1
    || sparseManifest.operationalSegmentFormat !== 'CANONICAL_JSON_LINES_UTF8_GZIP_V1') {
    diagnostics.add('PERMUTATION_SPARSE_PROJECTION_SCHEMA_INVALID', { field: 'operational segment policy' });
  } else if ((sparseManifest.operationalCellSegments ?? []).length !== Math.ceil(operationalCellCount / segmentCellLimit)) {
    diagnostics.add('PERMUTATION_SPARSE_OPERATIONAL_PROJECTION_MISMATCH', { field: 'segment count' });
  }
  const segmentPaths = new Set();
  for (const [segmentIndex, segment] of (sparseManifest.operationalCellSegments ?? []).entries()) {
    try {
      const absolutePath = resolve(repositoryRoot, segment.path);
      if (!absolutePath.startsWith(`${generatedRoot}/`)
        || basename(absolutePath) !== `permutation-operational-cell-segment-${segment.digest?.slice('sha256:'.length)}.ndjson.gz`
        || !existsSync(absolutePath) || !lstatSync(absolutePath).isFile() || lstatSync(absolutePath).isSymbolicLink()
        || realpathSync(absolutePath) !== absolutePath || segmentPaths.has(absolutePath)) {
        fail('PERMUTATION_SPARSE_OPERATIONAL_PROJECTION_MISMATCH', `operational segment ${segmentIndex} path is invalid`);
      }
      segmentPaths.add(absolutePath);
      const compressed = readFileSync(absolutePath);
      const content = gunzipSync(compressed);
      if (sha256(compressed) !== segment.digest || compressed.byteLength !== segment.byteCount
        || sha256(content) !== segment.contentDigest || content.byteLength !== segment.uncompressedByteCount
        || content.at(-1) !== 10 || segment.compression !== 'GZIP_LEVEL_9_MTIME_0') {
        fail('PERMUTATION_SPARSE_OPERATIONAL_PROJECTION_MISMATCH', `operational segment ${segmentIndex} byte binding differs`);
      }
      const lines = content.subarray(0, content.length - 1).toString('utf8').split('\n');
      const expectedSegmentCount = Math.min(segmentCellLimit, operationalCellCount - segmentIndex * segmentCellLimit);
      if (segment.index !== segmentIndex || lines.length !== segment.cellCount || lines.length !== expectedSegmentCount) {
        fail('PERMUTATION_SPARSE_OPERATIONAL_PROJECTION_MISMATCH', `operational segment ${segmentIndex} cardinality differs`);
      }
      let firstCellIri;
      let lastCellIri;
      for (const line of lines) {
        const cell = JSON.parse(line);
        if (canonicalJson(cell) !== line
          || independentClosureClassification(cell.disposition).representation !== 'OPERATIONAL_CELL') {
          fail('PERMUTATION_SPARSE_OPERATIONAL_PROJECTION_MISMATCH', `${cell.cellIri ?? 'cell'} is not an operational cell`);
        }
        if (firstCellIri === undefined) firstCellIri = cell.cellIri;
        lastCellIri = cell.cellIri;
        executedContentHash.update(`${line}\n`);
        executedStableKeyHash.update(`${cell.stableKey}\n`);
        executedOperationalCellCount += 1;
      }
      if (segment.firstCellIri !== firstCellIri || segment.lastCellIri !== lastCellIri) {
        fail('PERMUTATION_SPARSE_OPERATIONAL_PROJECTION_MISMATCH', `operational segment ${segmentIndex} boundary differs`);
      }
    } catch (error) {
      diagnostics.add(error.code ?? 'PERMUTATION_SPARSE_OPERATIONAL_PROJECTION_MISMATCH', {
        message: error.message,
        segmentIndex,
      });
    }
  }
  const executedOperationalCellsDigest = `sha256:${executedContentHash.digest('hex')}`;
  const executedOperationalStableKeySequenceDigest = `sha256:${executedStableKeyHash.digest('hex')}`;
  if (executedOperationalCellCount !== operationalCellCount
    || executedOperationalCellsDigest !== expectedOperationalCellsDigest
    || executedOperationalStableKeySequenceDigest !== expectedOperationalStableKeySequenceDigest
    || sparseManifest.operationalCellCount !== operationalCellCount
    || sparseManifest.operationalCellsDigest !== expectedOperationalCellsDigest
    || sparseManifest.operationalStableKeySequenceDigest !== expectedOperationalStableKeySequenceDigest) {
    diagnostics.add('PERMUTATION_SPARSE_OPERATIONAL_PROJECTION_MISMATCH', { field: 'executed operational byte set' });
  }

  if (canonicalJson(sparseManifest.ruleCoverageRegions) !== canonicalJson(expectedRuleRegions)
    || sparseManifest.ruleRegionCount !== expectedRuleRegions.length
    || sparseManifest.ruleCoveredCellCount !== ruleCoveredCellCount
    || sparseManifest.ruleRegionsDigest !== fullDigest(expectedRuleRegions)) {
    diagnostics.add('PERMUTATION_SYMBOLIC_REGION_COVERAGE_MISMATCH', { field: 'rule regions' });
  }
  if (canonicalJson(sparseManifest.pendingCoverageRegions) !== canonicalJson(expectedPendingRegions)
    || sparseManifest.pendingRegionCount !== expectedPendingRegions.length
    || sparseManifest.pendingCoveredCellCount !== pendingCoveredCellCount
    || sparseManifest.pendingRegionsDigest !== fullDigest(expectedPendingRegions)) {
    diagnostics.add('PERMUTATION_PENDING_REGION_COVERAGE_MISMATCH', { field: 'pending regions' });
  }
  if (canonicalJson(sparseManifest.closureCounts) !== canonicalJson(expectedClosureCounts)
    || sparseManifest.rawCandidateCount !== expectedClosureCounts.rawCandidateCount) {
    diagnostics.add('PERMUTATION_SPARSE_PARTITION_MISMATCH', { field: 'aggregate closure counts' });
  }

  const expectedBoundary = {
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
  if (canonicalJson(sparseManifest.publicationBoundary) !== canonicalJson(expectedBoundary)) {
    diagnostics.add('PERMUTATION_RDF_PUBLICATION_POLICY_INVALID');
  }
  try {
    const expectedBudget = independentPublicationBudget({
      liveTripleCount: sparseManifest.publicationBudget?.liveTripleCount,
      operationalCellCount,
      pendingRegionCount: expectedPendingRegions.length,
      providerEdgeLimit: sparseManifest.publicationBudget?.providerEdgeLimit,
      publicationReserve: sparseManifest.publicationBudget?.publicationReserve,
      ruleRegionCount: expectedRuleRegions.length,
      policy: metaModel.publicationBudgetPolicy,
    });
    if (expectedBudget.result !== 'PREFLIGHT_PASS') {
      diagnostics.add('PERMUTATION_PUBLICATION_BUDGET_EXCEEDED', expectedBudget);
    } else if (canonicalJson(sparseManifest.publicationBudget) !== canonicalJson(expectedBudget)) {
      diagnostics.add('PERMUTATION_PUBLICATION_BUDGET_INVALID', { field: 'budget witness' });
    }
  } catch (error) {
    diagnostics.add(error.code ?? 'PERMUTATION_PUBLICATION_BUDGET_INVALID', error.details ?? { message: error.message });
  }

  const {
    authorityDigest,
    recordKind,
    schemaVersion,
    sparseManifestDigest,
    verdict,
    ...descriptor
  } = sparseManifest;
  const expectedVerdict = pendingCoveredCellCount > 0 || (rawManifest.gaps?.length ?? 0) > 0
    ? 'PERMUTATION_CLOSURE_INCOMPLETE'
    : 'SPARSE_SYMBOLIC_INVARIANTS_PASS';
  if (authorityDigest !== verified.authorityDigest
    || recordKind !== 'USF_PERMUTATION_SPARSE_SYMBOLIC_MANIFEST'
    || schemaVersion !== 1
    || fullDigest({ ...descriptor, verdict }) !== sparseManifestDigest
    || verdict !== expectedVerdict) {
    diagnostics.add('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', { field: 'descriptor digest or verdict' });
  }

  return finalSparseProof(sparseManifest, rawManifest, rawProof, diagnostics.list(), {
    applicabilityCounts: expectedClosureCounts.applicability,
    operationalCellCount,
    operationalCellsDigest: expectedOperationalCellsDigest,
    pendingCoveredCellCount,
    pendingRegionCount: expectedPendingRegions.length,
    rawCandidateCount: expectedClosureCounts.rawCandidateCount,
    requiredFiniteDomainGapCount: rawManifest.gaps?.length ?? 0,
    ruleCoveredCellCount,
    ruleRegionCount: expectedRuleRegions.length,
    satisfiabilityCounts: expectedClosureCounts.satisfiability,
  });
}

function rawProofVerdict(diagnostics, results) {
  const errorCount = diagnostics
    .filter(({ severity }) => severity === 'ERROR')
    .reduce((sum, { count }) => sum + count, 0);
  const incompleteCount = diagnostics
    .filter(({ severity }) => severity === 'INCOMPLETE')
    .reduce((sum, { count }) => sum + count, 0);
  return errorCount > 0
    ? 'INVARIANTS_FAILED'
    : incompleteCount > 0 || results.unresolvedCount > 0
      ? 'PERMUTATION_CLOSURE_INCOMPLETE'
      : 'PERMUTATION_CLOSURE_COMPLETE';
}

function finalProof(manifest, census, diagnostics, results) {
  const verdict = rawProofVerdict(diagnostics, results);
  const proofCore = {
    authorityDigest: manifest?.authorityDigest,
    censusDigest: census?.censusDigest,
    diagnostics,
    results,
    universeDigest: manifest?.universeDigest,
    verdict,
  };
  return {
    ...proofCore,
    proofDigest: fullDigest(proofCore),
    recordKind: 'USF_PERMUTATION_UNIVERSE_INDEPENDENT_PROOF',
    schemaVersion: 2,
  };
}

export function proofSummary(proof) {
  const count = (code) => proof.diagnostics.find((diagnostic) => diagnostic.code === code)?.count ?? 0;
  return {
    absentDispositions: count('PERMUTATION_CELL_DISPOSITION_ABSENT'),
    actualCellCount: proof.results.actualCellCount,
    duplicateCells: count('PERMUTATION_UNIVERSE_DUPLICATE_CELL'),
    expectedCellCount: proof.results.expectedCellCount,
    extraCells: count('PERMUTATION_UNIVERSE_EXTRA_CELL'),
    invalidDispositions: count('PERMUTATION_CELL_DISPOSITION_INVALID'),
    missingCells: count('PERMUTATION_UNIVERSE_MISSING_CELL'),
    multipleDispositions: count('PERMUTATION_CELL_DISPOSITION_MULTIPLE'),
    requiredFiniteDomainGaps: proof.results.requiredFiniteDomainGapCount,
    unresolvedCells: proof.results.unresolvedCount,
    verdict: proof.verdict,
  };
}

export const universeProofInternals = Object.freeze({
  classifyUniverseKeys,
  diagnosticCollector,
  independentClosureClassification,
  independentCoverageRule,
  independentPublicationBudget,
  independentIdentity,
  inspectCell,
  loadIndependentMetaModel,
  rawProofVerdict,
  reconstructIndependentCensus,
  reconstructFoundationDomainAssessment,
  reconstructIndependentFamilyRegistry,
  validateCensus,
});

function exactArg(name) {
  const prefix = `--${name}=`;
  const matches = process.argv.filter((value) => value.startsWith(prefix));
  if (matches.length !== 1) fail('EXACT_INPUT_PATH_REQUIRED', `exactly one ${prefix}<value> argument is required`);
  return matches[0].slice(prefix.length);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
    const authorityInputs = loadVerifiedAuthorityInputs({
      authorityDigest: exactArg('authority-digest'),
      authorityPacketDigest: exactArg('authority-packet-digest'),
      authorityPacketPath: resolve(repositoryRoot, exactArg('authority-packet')),
      authorityProjectionDigest: exactArg('authority-projection-digest'),
      authorityProjectionPath: resolve(repositoryRoot, exactArg('authority-projection')),
    });
    let proof;
    let filePrefix;
    if (process.argv.includes('--foundation-only')) {
      const assessmentPath = resolve(repositoryRoot, exactArg('foundation-assessment'));
      const assessmentDigest = exactArg('foundation-assessment-digest');
      const assessmentBytes = readFileSync(assessmentPath);
      if (sha256(assessmentBytes) !== assessmentDigest) {
        fail('FOUNDATION_ASSESSMENT_FILE_DIGEST_MISMATCH', 'foundation assessment file bytes do not match');
      }
      proof = proveFoundationDomainClosureAssessment({
        assessment: JSON.parse(assessmentBytes.toString('utf8')),
        authorityInputs,
        repositoryRoot,
      });
      filePrefix = 'foundation-domain-closure-proof';
    } else {
      const censusPath = resolve(repositoryRoot, exactArg('census'));
      const censusDigest = exactArg('census-digest');
      const manifestPath = resolve(repositoryRoot, exactArg('manifest'));
      const manifestDigest = exactArg('manifest-digest');
      const censusBytes = readFileSync(censusPath);
      const manifestBytes = readFileSync(manifestPath);
      if (sha256(censusBytes) !== censusDigest) fail('CENSUS_FILE_DIGEST_MISMATCH', 'census file bytes do not match');
      if (sha256(manifestBytes) !== manifestDigest) fail('UNIVERSE_MANIFEST_FILE_DIGEST_MISMATCH', 'manifest file bytes do not match');
      const census = JSON.parse(censusBytes.toString('utf8'));
      const manifest = JSON.parse(manifestBytes.toString('utf8'));
      const rawProof = proveUniverseManifest({ authorityInputs, census, manifest, repositoryRoot });
      proof = rawProof;
      filePrefix = 'permutation-universe-proof';
      const sparseManifestArguments = process.argv.filter((value) => value.startsWith('--sparse-manifest='));
      if (sparseManifestArguments.length > 0) {
      const sparseManifestPath = resolve(repositoryRoot, exactArg('sparse-manifest'));
      const sparseManifestDigest = exactArg('sparse-manifest-digest');
      const sparseManifestBytes = readFileSync(sparseManifestPath);
      if (sha256(sparseManifestBytes) !== sparseManifestDigest) {
        fail('PERMUTATION_SPARSE_MANIFEST_BINDING_MISMATCH', 'sparse manifest file bytes do not match');
      }
        proof = proveSparseSymbolicManifest({
        authorityInputs,
        rawManifest: manifest,
        rawManifestDigest: manifestDigest,
        rawProof,
        repositoryRoot,
        sparseManifest: JSON.parse(sparseManifestBytes.toString('utf8')),
      });
        filePrefix = 'permutation-sparse-symbolic-proof';
      }
    }
    const content = `${canonicalJson(proof)}\n`;
    const outputPath = join('.work', 'generated', `${filePrefix}-${sha256(content).slice('sha256:'.length)}.json`);
    mkdirSync(dirname(join(repositoryRoot, outputPath)), { recursive: true });
    writeFileSync(join(repositoryRoot, outputPath), content);
    process.stdout.write(`${canonicalJson({
      outputPath,
      proofDigest: proof.proofDigest,
      summary: proof.recordKind === 'USF_PERMUTATION_UNIVERSE_INDEPENDENT_PROOF'
        ? proofSummary(proof)
        : proof.results,
      verdict: proof.verdict,
    })}\n`);
  } catch (error) {
    process.stderr.write(`${error.code ?? error.name}:${error.message}\n`);
    process.exitCode = 1;
  }
}
