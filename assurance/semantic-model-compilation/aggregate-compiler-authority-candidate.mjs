import { createHash } from 'node:crypto';

import {
  AGGREGATE_ALGORITHM_DIGEST,
  AGGREGATE_ALGORITHM_VERSION,
  AGGREGATE_REPOSITORY,
  COMPONENT_PROOFS,
  COMPONENT_SET_DIGEST,
} from './aggregate-compiler-proof.mjs';
import { AGGREGATE_RESULT_IRI } from './aggregate-compiler-proof-command.mjs';
import {
  AUTHORITY_ALGORITHM,
  AUTHORITY_FINGERPRINT,
  AUTHORITY_PRINCIPAL,
  AUTHORITY_SIGNING_IDENTITY,
  SEMANTIC_PROOF_PROTOCOL,
  assertSemanticProofPublicationReceipt,
  canonicalJson,
  ownerAssignmentCandidateDigest,
  publicationReceiptDigest,
  sourceScopeDigest,
} from '../../processes/semantic-assurance/semantic-proof-v1.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const RFC3339_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/;
const PLACEHOLDER = /(?:^|[^a-z0-9])(todo|tbd|placeholder|changeme)(?:$|[^a-z0-9])/i;

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const XSD_BOOLEAN = 'http://www.w3.org/2001/XMLSchema#boolean';
const XSD_DATETIME = 'http://www.w3.org/2001/XMLSchema#dateTime';
const XSD_INTEGER = 'http://www.w3.org/2001/XMLSchema#integer';
const XSD_ANY_URI = 'http://www.w3.org/2001/XMLSchema#anyURI';
const USF = 'urn:usf:ontology:';

const GRAPH_AUTHORITY = 'urn:usf:graph:authority';
const GRAPH_CAPABILITIES = 'urn:usf:graph:capabilities';
const GRAPH_PROOFS = 'urn:usf:graph:proofs';
const CONTRACT = 'urn:usf:semanticcontract:compilersemanticenforcement';
const PROTOCOL_IRI = 'urn:usf:semanticproofprotocol:v1';
const PROVISIONAL_RESULT = 'urn:usf:proofresult:compilersemanticenforcementaggregateprepublication';
const AGGREGATE_OBLIGATION = 'urn:usf:proofobligation:compilersemanticenforcementaggregate';
const AGGREGATE_ALGORITHM = 'urn:usf:proofalgorithm:compilersemanticenforcementaggregate';
const AGGREGATE_VERSION = 'urn:usf:proofalgorithmversion:compilersemanticenforcementaggregate-v2_1_0';
const PROVISIONAL_PROOF = 'urn:usf:proof:compilersemanticenforcementaggregateprepublication';
const PROVISIONAL_EXECUTION = 'urn:usf:proofexecution:compilersemanticenforcementaggregateprepublication';
const PROVISIONAL_EVALUATION = 'urn:usf:proofevaluation:compilersemanticenforcementaggregateprepublication';
const FINAL_PROOF = 'urn:usf:proof:compilersemanticenforcementaggregate';
const FINAL_EXECUTION = 'urn:usf:proofexecution:compilersemanticenforcementaggregate';
const FINAL_EVALUATION = 'urn:usf:proofevaluation:compilersemanticenforcementaggregate';
const REEVALUATION = 'urn:usf:postpublicationreevaluation:compilersemanticenforcementaggregate';
const VERIFIER = 'urn:usf:semanticproofverifier:semanticproofv1';
const VERIFIER_IDENTITY = 'urn:usf:semanticproofverifieridentity:semanticproofv1';
const VALIDATION_PRODUCER = 'urn:usf:validationproducer:compilersemanticenforcementaggregate';
const EVIDENCE_ADMISSION_PATH = 'urn:usf:evidenceadmissionpath:compilersemanticenforcementaggregate';
const VALIDATION_EXECUTION = 'urn:usf:validationexecution:compilersemanticenforcementaggregate';
const VALIDATION_EVALUATION = 'urn:usf:validationevaluation:compilersemanticenforcementaggregate';
const VALIDATION_RESULT = 'urn:usf:validationresult:compilersemanticenforcementaggregate';
const VALIDATION_OBLIGATION = 'urn:usf:validationobligation:compilersemanticenforcement';
const VALIDATION_BINDING = 'urn:usf:validationselfpublicationbinding:compilersemanticenforcementaggregate';
const VALIDATION_RULE = 'urn:usf:authoritybindingrule:validationnonpublicationdependencyclosure';
const SELF_PUBLICATION_RULE = 'urn:usf:authoritybindingrule:selfpublicationclosure';
const PROVISIONAL_BINDING = 'urn:usf:proofauthoritybinding:compilersemanticenforcementaggregateprepublication';
const FINAL_BINDING = 'urn:usf:proofauthoritybinding:compilersemanticenforcementaggregate';
const DEPENDENCY_DIGEST_ALGORITHM = 'sha256-rdfc10-nonpublication-graph-inventory-v1';
const AGGREGATE_RUNG = 'urn:usf:proofrung:behaviour';
const AGGREGATE_PROVIDER_MODE = 'urn:usf:providermode:liveauthoritycontrol';
const AGGREGATE_ENVIRONMENT = 'urn:usf:environment:authoritycontrol';
const AGGREGATE_EVIDENCE_REQUIREMENTS = Object.freeze([
  'urn:usf:evidencerequirement:compilerliveauthoritytransactionvalidation',
  'urn:usf:evidencerequirement:compilersemanticvalidation',
  'urn:usf:evidencerequirement:importedauthoritycounterfactualadequacy',
]);
const AGGREGATE_ASSURANCE_CELLS = Object.freeze([
  'urn:usf:assurancecell:behaviourhermetichermetic',
  'urn:usf:assurancecell:behaviourliveauthoritycontrol',
  'urn:usf:assurancecell:contracthermetichermetic',
]);
const EXCLUDED_AUTHORITY_GRAPHS = Object.freeze([
  'urn:usf:graph:capabilities',
  'urn:usf:graph:derived:coverage',
  'urn:usf:graph:derived:evidence',
  'urn:usf:graph:derived:obligations',
  'urn:usf:graph:derived:readiness',
  'urn:usf:graph:derived:surfaces',
  'urn:usf:graph:evidence',
  'urn:usf:graph:proofs',
]);

const OWNER_SCOPES = Object.freeze({
  providerconfigurationplane: Object.freeze({
    assignment: 'urn:usf:ownerassignment:providerconfigurationplane:matthewaldous',
    domain: 'urn:usf:capabilityowner:providerconfigurationplane',
    evidenceAdmissionPath: 'urn:usf:evidenceadmissionpath:ownerassignment:providerconfigurationplane:matthewaldous',
    repository: 'maldous/usf-factory',
    validationProducer: 'urn:usf:validationproducer:ownerassignment:providerconfigurationplane:matthewaldous',
    verification: 'urn:usf:semanticproofverification:ownerassignment:providerconfigurationplane:matthewaldous',
    verificationAdmission: 'urn:usf:semanticproofverificationadmission:ownerassignment:providerconfigurationplane:matthewaldous',
    verificationDescriptor: 'urn:usf:semanticproofcasdescriptor:ownerassignment:providerconfigurationplane:matthewaldous',
  }),
  semanticmodelcompilation: Object.freeze({
    assignment: 'urn:usf:ownerassignment:semanticmodelcompilation:matthewaldous',
    domain: 'urn:usf:capabilityowner:semanticmodelcompilation',
    evidenceAdmissionPath: 'urn:usf:evidenceadmissionpath:ownerassignment:semanticmodelcompilation:matthewaldous',
    repository: AGGREGATE_REPOSITORY,
    validationProducer: 'urn:usf:validationproducer:ownerassignment:semanticmodelcompilation:matthewaldous',
    verification: 'urn:usf:semanticproofverification:ownerassignment:semanticmodelcompilation:matthewaldous',
    verificationAdmission: 'urn:usf:semanticproofverificationadmission:ownerassignment:semanticmodelcompilation:matthewaldous',
    verificationDescriptor: 'urn:usf:semanticproofcasdescriptor:ownerassignment:semanticmodelcompilation:matthewaldous',
  }),
});
const OWNER_SCOPE_KEYS = Object.freeze(Object.keys(OWNER_SCOPES).sort());

const PENDING_KEYS = ['aggregateResult', 'evaluatedAuthorityDigest', 'evaluationReceiptDigest', 'executionReceiptDigest',
  'ok', 'proofCurrentness', 'resultState', 'selectable', 'state'];
const AGGREGATE_KEYS = ['evaluation', 'evaluationDigest', 'passed', 'proofCurrentness', 'resultState', 'selectable'];
const EVALUATION_KEYS = ['algorithmDigest', 'algorithmVersion', 'authorityDigest', 'componentSetDigest', 'components',
  'evaluatedAt', 'evidenceSetDigest', 'phase', 'postPublicationReevaluation', 'sourceBinding', 'sourceBindingDigest'];
const SOURCE_KEYS = ['head', 'reachableFrom', 'repository', 'sourcePaths', 'sourceScopeDigest', 'tree'];
const COMPONENT_KEYS = ['currentness', 'dimension', 'evidenceReferences', 'historicalResult', 'obligation', 'result'];
const REEVALUATION_PACKAGE_KEYS = ['candidateDigest', 'evaluatedAuthorityDigest', 'evaluationReceiptDigest',
  'executionReceiptDigest', 'ok', 'operation', 'protocol', 'state'];
const REEVALUATION_EXECUTION_KEYS = ['algorithmDigest', 'algorithmVersion', 'authorityAfterDigest', 'completedAt',
  'componentSetDigest', 'evidenceSetDigest', 'publicationReceiptDigest', 'schema', 'sourceBindingDigest', 'startedAt'];
const REEVALUATION_EVALUATION_KEYS = ['algorithmDigest', 'algorithmVersion', 'authorityAfterDigest', 'componentSetDigest',
  'evaluatedAt', 'evidenceSetDigest', 'executionReceiptDigest', 'publicationReceiptDigest', 'resultState', 'schema',
  'sourceBindingDigest'];
const OWNER_KEYS = ['admission', 'assignment', 'descriptor', 'verification', 'verifier'];
const ASSIGNMENT_KEYS = ['authorityPreDigest', 'candidateDigest', 'envelopeDigest', 'sourcePaths', 'sourceScopeDigest'];
const VERIFICATION_KEYS = ['receiptDigest', 'verifiedAt'];
const ADMISSION_KEYS = ['receiptDigest'];
const DESCRIPTOR_KEYS = ['byteLength', 'digest', 'mediaType', 'receiptDigest'];
const VERIFIER_KEYS = ['identityDigest', 'implementationRelease', 'sourceHead', 'sourcePaths', 'sourceScopeDigest',
  'sourceTree', 'trustAnchorDigest'];
const CURRENTNESS_BINDING_KEYS = ['prospectiveAuthorityInventory'];
const INVENTORY_RECORD_KEYS = ['graph', 'sha256', 'triples'];
const BASE_DELTA_KEYS = ['authorityPreDigest', 'bytesBase64', 'candidateDigest', 'exactCandidateStateVerified',
  'mediaType', 'state', 'validationReceiptDigest'];
const RECEIPT_DESCRIPTOR_KEYS = ['byteLength', 'bytesBase64', 'digest', 'iri', 'mediaType',
  'persistenceReceiptDigest'];
const COMPILER_VALIDATION_KEYS = ['authorityAfterDigest', 'authorityBeforeDigest', 'candidateDigest', 'conforms',
  'evaluatedAt', 'evaluationReceiptDigest', 'executionReceiptDigest', 'schema', 'sourceBindingDigest',
  'validationReportDigest'];
const COMPILER_VALIDATION_PACKAGE_KEYS = ['descriptor', 'receipt'];
const STAGE2_KEYS = ['compilerValidation', 'evaluationReceipt', 'evaluationReceiptDescriptor', 'executionReceipt',
  'executionReceiptDescriptor', 'package', 'publicationReceipt'];

const ALLOWED_DEEP_KEYS = new Set([
  ...PENDING_KEYS, ...AGGREGATE_KEYS, ...EVALUATION_KEYS, ...SOURCE_KEYS, ...COMPONENT_KEYS,
  'admittedEvidence', 'authorityBindingDigest', 'authorityDigest', 'bytesBase64', 'component', 'digest',
  'evaluatedAt', 'evidenceSet', 'historicalResultDigest', 'invalidated', 'iri', 'observedAt',
  'projectionReceiptDigest', 'proof', 'proofAlgorithm', 'proofAlgorithmSourceDigest', 'proofAlgorithmVersion',
  'proofAlgorithmVersionIdentifier', 'proofEvaluation', 'proofExecution', 'proofState', 'resultState', 'schema',
  'snapshotDigest', 'supersededBy', 'validFrom', 'validUntil', 'dimension', 'obligation', 'result',
]);

function fail(code, detail) {
  const error = new Error(`${code}: ${detail}`);
  error.code = code;
  throw error;
}

function exactKeys(value, keys, code, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    fail(code, `${label} has a non-canonical schema`);
  }
}

function digest(value, label) {
  if (!SHA256.test(value || '') || value === `sha256:${'0'.repeat(64)}`) fail('CANDIDATE_DIGEST_INVALID', label);
  return value;
}

function gitObject(value, label) {
  if (!GIT_OBJECT.test(value || '') || value === '0'.repeat(40)) fail('CANDIDATE_SOURCE_BINDING_INVALID', label);
  return value;
}

function time(value, label) {
  if (!RFC3339_SECOND.test(value || '') || !Number.isFinite(Date.parse(value))) fail('CANDIDATE_TIME_INVALID', label);
  return value;
}

function paths(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.some((path) => typeof path !== 'string' || !SAFE_PATH.test(path))) {
    fail('CANDIDATE_SOURCE_SCOPE_INVALID', label);
  }
  const canonical = [...new Set(value)].sort();
  if (canonicalJson(value) !== canonicalJson(canonical)) fail('CANDIDATE_SOURCE_SCOPE_INVALID', `${label} is not canonical`);
  return canonical;
}

function rejectPlaceholders(value, path = 'input') {
  if (typeof value === 'string' && PLACEHOLDER.test(value)) fail('CANDIDATE_PLACEHOLDER_REJECTED', path);
  if (Array.isArray(value)) value.forEach((child, index) => rejectPlaceholders(child, `${path}[${index}]`));
  else if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) rejectPlaceholders(child, `${path}.${key}`);
  }
}

function rejectUnknownDeep(value, path = 'pending') {
  if (Array.isArray(value)) return value.forEach((child, index) => rejectUnknownDeep(child, `${path}[${index}]`));
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (!ALLOWED_DEEP_KEYS.has(key)) fail('CANDIDATE_PACKAGE_UNKNOWN_FIELD', `${path}.${key}`);
    rejectUnknownDeep(child, `${path}.${key}`);
  }
}

function sha256Bytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function sha256Json(value) {
  return sha256Bytes(Buffer.from(canonicalJson(value), 'utf8'));
}

function validatePending(pending) {
  exactKeys(pending, PENDING_KEYS, 'CANDIDATE_PENDING_SCHEMA_INVALID', 'pending package');
  rejectUnknownDeep(pending);
  if (pending.ok !== true || pending.state !== 'PENDING_PREPARATION' || pending.proofCurrentness !== 'PENDING'
      || pending.resultState !== 'PENDING' || pending.selectable !== false) {
    fail('CANDIDATE_PENDING_STATE_INVALID', 'pending package is not fail-closed');
  }
  digest(pending.evaluatedAuthorityDigest, 'pending authority');
  digest(pending.executionReceiptDigest, 'pending execution receipt');
  digest(pending.evaluationReceiptDigest, 'pending evaluation receipt');
  exactKeys(pending.aggregateResult, AGGREGATE_KEYS, 'CANDIDATE_PENDING_SCHEMA_INVALID', 'aggregate result');
  const aggregate = pending.aggregateResult;
  if (aggregate.passed !== false || aggregate.selectable !== false || aggregate.proofCurrentness !== 'PENDING'
      || aggregate.resultState !== 'PENDING') fail('CANDIDATE_PENDING_STATE_INVALID', 'aggregate result');
  exactKeys(aggregate.evaluation, EVALUATION_KEYS, 'CANDIDATE_PENDING_SCHEMA_INVALID', 'aggregate evaluation');
  const evaluation = aggregate.evaluation;
  if (evaluation.phase !== 'PRE_PUBLICATION_PREPARATION' || evaluation.postPublicationReevaluation !== null
      || evaluation.algorithmVersion !== AGGREGATE_ALGORITHM_VERSION
      || evaluation.algorithmDigest !== AGGREGATE_ALGORITHM_DIGEST
      || evaluation.componentSetDigest !== COMPONENT_SET_DIGEST
      || evaluation.authorityDigest !== pending.evaluatedAuthorityDigest) {
    fail('CANDIDATE_PENDING_BINDING_INVALID', 'algorithm, component set, phase or authority');
  }
  digest(evaluation.evidenceSetDigest, 'aggregate evidence set');
  time(evaluation.evaluatedAt, 'pending evaluatedAt');
  exactKeys(evaluation.sourceBinding, SOURCE_KEYS, 'CANDIDATE_PENDING_SCHEMA_INVALID', 'source binding');
  const source = evaluation.sourceBinding;
  gitObject(source.head, 'source head');
  gitObject(source.tree, 'source tree');
  if (source.repository !== AGGREGATE_REPOSITORY || !/^refs\/(heads|remotes|tags)\/[A-Za-z0-9._/-]+$/.test(source.reachableFrom || '')) {
    fail('CANDIDATE_SOURCE_BINDING_INVALID', 'repository or reachable ref');
  }
  paths(source.sourcePaths, 'aggregate source paths');
  if (source.sourceScopeDigest !== sourceScopeDigest(source.sourcePaths)) fail('CANDIDATE_SOURCE_BINDING_INVALID', 'source scope digest');
  digest(evaluation.sourceBindingDigest, 'source binding digest');
  if (!Array.isArray(evaluation.components) || evaluation.components.length !== COMPONENT_PROOFS.length) {
    fail('CANDIDATE_COMPONENT_SET_INVALID', 'cardinality');
  }
  const actual = evaluation.components.map((component) => {
    exactKeys(component, COMPONENT_KEYS, 'CANDIDATE_COMPONENT_SET_INVALID', 'component');
    if (!Array.isArray(component.evidenceReferences) || component.evidenceReferences.length === 0) {
      fail('CANDIDATE_COMPONENT_SET_INVALID', `${component.result} evidence`);
    }
    return { dimension: component.dimension, obligation: component.obligation, result: component.result };
  }).sort((left, right) => left.obligation.localeCompare(right.obligation));
  const expected = COMPONENT_PROOFS.map(({ dimension, obligation, result }) => ({ dimension, obligation, result }))
    .sort((left, right) => left.obligation.localeCompare(right.obligation));
  if (canonicalJson(actual) !== canonicalJson(expected)) fail('CANDIDATE_COMPONENT_SET_INVALID', 'exact four mappings');
  if (aggregate.evaluationDigest !== sha256Json(evaluation)) fail('CANDIDATE_PENDING_BINDING_INVALID', 'evaluation digest');
  rejectPlaceholders(pending);
  return pending;
}

function validateOwner(owner, pending, scope) {
  exactKeys(owner, OWNER_KEYS, 'CANDIDATE_OWNER_SCHEMA_INVALID', 'owner authority');
  exactKeys(owner.assignment, ASSIGNMENT_KEYS, 'CANDIDATE_OWNER_SCHEMA_INVALID', 'owner assignment');
  exactKeys(owner.verification, VERIFICATION_KEYS, 'CANDIDATE_OWNER_SCHEMA_INVALID', 'owner verification');
  exactKeys(owner.admission, ADMISSION_KEYS, 'CANDIDATE_OWNER_SCHEMA_INVALID', 'verification admission');
  exactKeys(owner.descriptor, DESCRIPTOR_KEYS, 'CANDIDATE_OWNER_SCHEMA_INVALID', 'CAS descriptor');
  exactKeys(owner.verifier, VERIFIER_KEYS, 'CANDIDATE_OWNER_SCHEMA_INVALID', 'external verifier');
  const assignmentPaths = paths(owner.assignment.sourcePaths, 'owner assignment paths');
  if (owner.assignment.authorityPreDigest !== pending.evaluatedAuthorityDigest
      || owner.assignment.sourceScopeDigest !== sourceScopeDigest(assignmentPaths)
      || owner.assignment.candidateDigest !== ownerAssignmentCandidateDigest({
        authorityDomain: scope.domain, principal: AUTHORITY_PRINCIPAL, repository: scope.repository,
        sourcePaths: assignmentPaths,
      })) fail('CANDIDATE_OWNER_BINDING_INVALID', 'assignment scope, authority or candidate');
  if (scope.repository === AGGREGATE_REPOSITORY
      && owner.assignment.sourceScopeDigest !== pending.aggregateResult.evaluation.sourceBinding.sourceScopeDigest) {
    fail('CANDIDATE_OWNER_BINDING_INVALID', 'semantic compilation assignment must cover the evaluated graph source scope');
  }
  for (const [label, value] of Object.entries({
    assignmentCandidate: owner.assignment.candidateDigest, assignmentEnvelope: owner.assignment.envelopeDigest,
    verificationReceipt: owner.verification.receiptDigest, admissionReceipt: owner.admission.receiptDigest,
    descriptorDigest: owner.descriptor.digest, descriptorReceipt: owner.descriptor.receiptDigest,
    verifierIdentity: owner.verifier.identityDigest, trustAnchor: owner.verifier.trustAnchorDigest,
    verifierScope: owner.verifier.sourceScopeDigest,
  })) digest(value, label);
  time(owner.verification.verifiedAt, 'owner verification time');
  if (!Number.isSafeInteger(owner.descriptor.byteLength) || owner.descriptor.byteLength <= 0
      || owner.descriptor.mediaType !== 'application/json') fail('CANDIDATE_OWNER_BINDING_INVALID', 'CAS descriptor');
  gitObject(owner.verifier.sourceHead, 'verifier source head');
  gitObject(owner.verifier.sourceTree, 'verifier source tree');
  const verifierPaths = paths(owner.verifier.sourcePaths, 'verifier source paths');
  if (owner.verifier.sourceScopeDigest !== sourceScopeDigest(verifierPaths)
      || typeof owner.verifier.implementationRelease !== 'string' || owner.verifier.implementationRelease.length === 0) {
    fail('CANDIDATE_OWNER_BINDING_INVALID', 'external verifier');
  }
  rejectPlaceholders(owner);
  return owner;
}

function validateOwners(owners, pending) {
  exactKeys(owners, OWNER_SCOPE_KEYS, 'CANDIDATE_OWNER_SCHEMA_INVALID', 'owner authority scopes');
  const validated = Object.fromEntries(OWNER_SCOPE_KEYS.map((key) => [key, validateOwner(owners[key], pending, OWNER_SCOPES[key])]));
  const verifier = canonicalJson(validated[OWNER_SCOPE_KEYS[0]].verifier);
  if (OWNER_SCOPE_KEYS.some((key) => canonicalJson(validated[key].verifier) !== verifier)) {
    fail('CANDIDATE_OWNER_BINDING_INVALID', 'both owner assignments must use the same canonical external verifier');
  }
  const unique = (selector, label) => {
    const values = OWNER_SCOPE_KEYS.map((key) => selector(validated[key]));
    if (new Set(values).size !== values.length) fail('CANDIDATE_OWNER_BINDING_INVALID', `${label} must be independently scoped`);
  };
  unique((owner) => owner.assignment.candidateDigest, 'assignment candidates');
  unique((owner) => owner.assignment.envelopeDigest, 'assignment envelopes');
  unique((owner) => owner.verification.receiptDigest, 'verification receipts');
  unique((owner) => owner.admission.receiptDigest, 'admission receipts');
  unique((owner) => owner.descriptor.digest, 'verification descriptors');
  return validated;
}

function validateCurrentnessBinding(binding) {
  exactKeys(binding, CURRENTNESS_BINDING_KEYS, 'CANDIDATE_CURRENTNESS_BINDING_INVALID', 'currentness binding');
  if (!Array.isArray(binding.prospectiveAuthorityInventory) || binding.prospectiveAuthorityInventory.length === 0) {
    fail('CANDIDATE_CURRENTNESS_BINDING_INVALID', 'prospective authority inventory is absent');
  }
  const observed = new Set();
  const prospectiveAuthorityInventory = binding.prospectiveAuthorityInventory.map((record) => {
    exactKeys(record, INVENTORY_RECORD_KEYS, 'CANDIDATE_CURRENTNESS_BINDING_INVALID', 'authority inventory record');
    if (typeof record.graph !== 'string' || record.graph.length === 0 || observed.has(record.graph)
        || !Number.isSafeInteger(record.triples) || record.triples < 0) {
      fail('CANDIDATE_CURRENTNESS_BINDING_INVALID', 'prospective authority inventory is malformed or duplicated');
    }
    digest(record.sha256, `${record.graph} prospective graph digest`);
    observed.add(record.graph);
    return Object.freeze({ graph: record.graph, sha256: record.sha256, triples: record.triples });
  }).sort((left, right) => left.graph.localeCompare(right.graph));
  if (canonicalJson(binding.prospectiveAuthorityInventory) !== canonicalJson(prospectiveAuthorityInventory)) {
    fail('CANDIDATE_CURRENTNESS_BINDING_INVALID', 'prospective authority inventory is not canonical');
  }
  return Object.freeze({
    dependencySetDigest: nonPublicationDependencySetDigest(prospectiveAuthorityInventory),
    prospectiveAuthorityInventory: Object.freeze(prospectiveAuthorityInventory),
  });
}

function nonPublicationDependencySetDigest(inventory) {
  const excluded = new Set(EXCLUDED_AUTHORITY_GRAPHS);
  if (!excluded.has(GRAPH_PROOFS)) fail('CANDIDATE_CURRENTNESS_BINDING_INVALID', 'digest-carrying graph is not excluded');
  const graphs = inventory.filter(({ graph }) => !excluded.has(graph))
    .map(({ graph, sha256, triples }) => ({ graph, sha256, triples }));
  return sha256Json({
    algorithm: DEPENDENCY_DIGEST_ALGORITHM,
    excludedGraphs: EXCLUDED_AUTHORITY_GRAPHS,
    graphs,
  });
}

function parseCanonicalBaseDelta(base, authorityPreDigest) {
  exactKeys(base, BASE_DELTA_KEYS, 'CANDIDATE_BASE_DELTA_INVALID', 'base semantic delta');
  digest(base.candidateDigest, 'base semantic delta candidate');
  digest(base.validationReceiptDigest, 'base semantic delta validation receipt');
  if (base.authorityPreDigest !== authorityPreDigest || base.exactCandidateStateVerified !== true
      || base.mediaType !== 'application/rdf-patch' || base.state !== 'VALIDATED_ROLLBACK') {
    fail('CANDIDATE_BASE_DELTA_INVALID', 'base delta is not compiler-validated against D0');
  }
  let bytes;
  try {
    bytes = Buffer.from(base.bytesBase64, 'base64');
  } catch {
    fail('CANDIDATE_BASE_DELTA_INVALID', 'base delta bytes');
  }
  if (bytes.length === 0 || bytes.toString('base64') !== base.bytesBase64
      || sha256Bytes(bytes) !== base.candidateDigest) {
    fail('CANDIDATE_BASE_DELTA_INVALID', 'base delta byte binding');
  }
  const lines = bytes.toString('utf8').split('\n');
  if (lines.at(-1) !== '' || lines.shift() !== `# ${SEMANTIC_PROOF_PROTOCOL} canonical-rdf-patch-v1 base`) {
    fail('CANDIDATE_BASE_DELTA_INVALID', 'base delta canonical header');
  }
  lines.pop();
  const deletions = [];
  const additions = [];
  let additionsStarted = false;
  for (const line of lines) {
    if (line.startsWith('D ')) {
      if (additionsStarted) fail('CANDIDATE_BASE_DELTA_INVALID', 'deletion follows addition');
      deletions.push(line.slice(2));
    } else if (line.startsWith('A ')) {
      additionsStarted = true;
      additions.push(line.slice(2));
    } else {
      fail('CANDIDATE_BASE_DELTA_INVALID', 'unsupported patch operation');
    }
  }
  if (additions.length === 0 || deletions.some((line) => additions.includes(line))
      || new Set(deletions).size !== deletions.length || new Set(additions).size !== additions.length
      || canonicalJson(deletions) !== canonicalJson([...deletions].sort())
      || canonicalJson(additions) !== canonicalJson([...additions].sort())) {
    fail('CANDIDATE_BASE_DELTA_INVALID', 'base delta is empty, mixed, duplicated or non-canonical');
  }
  rejectPlaceholders(base);
  return { additions, deletions };
}

function mergeBaseDelta(base, generated) {
  const conflicts = [
    ...base.additions.filter((line) => generated.additions.includes(line) || generated.deletions.includes(line)),
    ...base.deletions.filter((line) => generated.deletions.includes(line) || generated.additions.includes(line)),
  ];
  if (conflicts.length > 0) fail('CANDIDATE_BASE_DELTA_CONFLICT', conflicts.sort()[0]);
  return {
    additions: [...base.additions, ...generated.additions],
    deletions: [...base.deletions, ...generated.deletions],
  };
}

function validateReceiptDescriptor(descriptor, expectedIri, expectedValue = null) {
  exactKeys(descriptor, RECEIPT_DESCRIPTOR_KEYS, 'CANDIDATE_RECEIPT_DESCRIPTOR_INVALID', expectedIri);
  if (descriptor.iri !== expectedIri || descriptor.mediaType !== 'application/json'
      || !Number.isSafeInteger(descriptor.byteLength) || descriptor.byteLength <= 0) {
    fail('CANDIDATE_RECEIPT_DESCRIPTOR_INVALID', `${expectedIri} metadata`);
  }
  digest(descriptor.digest, `${expectedIri} digest`);
  digest(descriptor.persistenceReceiptDigest, `${expectedIri} persistence receipt`);
  let bytes;
  try {
    bytes = Buffer.from(descriptor.bytesBase64, 'base64');
  } catch {
    fail('CANDIDATE_RECEIPT_DESCRIPTOR_INVALID', `${expectedIri} bytes`);
  }
  if (bytes.length !== descriptor.byteLength || bytes.toString('base64') !== descriptor.bytesBase64
      || sha256Bytes(bytes) !== descriptor.digest) {
    fail('CANDIDATE_RECEIPT_DESCRIPTOR_INVALID', `${expectedIri} byte binding`);
  }
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('CANDIDATE_RECEIPT_DESCRIPTOR_INVALID', `${expectedIri} JSON`);
  }
  if (canonicalJson(value) !== bytes.toString('utf8')
      || (expectedValue !== null && canonicalJson(value) !== canonicalJson(expectedValue))) {
    fail('CANDIDATE_RECEIPT_DESCRIPTOR_INVALID', `${expectedIri} canonical receipt binding`);
  }
  return { descriptor, value };
}

function validateStage2(stage2, pending) {
  exactKeys(stage2, STAGE2_KEYS,
    'CANDIDATE_REEVALUATION_SCHEMA_INVALID', 'stage-2 input');
  exactKeys(stage2.package, REEVALUATION_PACKAGE_KEYS, 'CANDIDATE_REEVALUATION_SCHEMA_INVALID', 'reevaluation package');
  exactKeys(stage2.executionReceipt, REEVALUATION_EXECUTION_KEYS,
    'CANDIDATE_REEVALUATION_SCHEMA_INVALID', 'reevaluation execution receipt');
  exactKeys(stage2.evaluationReceipt, REEVALUATION_EVALUATION_KEYS,
    'CANDIDATE_REEVALUATION_SCHEMA_INVALID', 'reevaluation evaluation receipt');
  try {
    assertSemanticProofPublicationReceipt(stage2.publicationReceipt);
  } catch (error) {
    fail('CANDIDATE_REEVALUATION_BINDING_INVALID', `publication receipt: ${error.message}`);
  }
  exactKeys(stage2.compilerValidation, COMPILER_VALIDATION_PACKAGE_KEYS,
    'CANDIDATE_REEVALUATION_SCHEMA_INVALID', 'compiler validation package');
  exactKeys(stage2.compilerValidation.receipt, COMPILER_VALIDATION_KEYS,
    'CANDIDATE_REEVALUATION_SCHEMA_INVALID', 'compiler validation receipt');
  const pkg = stage2.package;
  const execution = stage2.executionReceipt;
  const evaluation = stage2.evaluationReceipt;
  const receiptDigest = publicationReceiptDigest(stage2.publicationReceipt);
  if (pkg.ok !== true || pkg.operation !== 'produce_initial' || pkg.protocol !== SEMANTIC_PROOF_PROTOCOL
      || pkg.state !== 'REEVALUATION_CANDIDATE_PREPARED'
      || pkg.candidateDigest !== stage2.publicationReceipt.candidate_digest
      || pkg.evaluatedAuthorityDigest !== stage2.publicationReceipt.authority_after_digest
      || stage2.publicationReceipt.authority_before_digest !== pending.evaluatedAuthorityDigest
      || stage2.publicationReceipt.publication_phase !== 'initial'
      || stage2.publicationReceipt.terminal_state !== 'PENDING') {
    fail('CANDIDATE_REEVALUATION_BINDING_INVALID', 'publication transition');
  }
  if (pkg.executionReceiptDigest !== sha256Json(execution) || pkg.evaluationReceiptDigest !== sha256Json(evaluation)
      || execution.schema !== 'aggregate-post-publication-execution-v1'
      || evaluation.schema !== 'aggregate-post-publication-evaluation-v1'
      || evaluation.resultState !== 'passed' || evaluation.executionReceiptDigest !== pkg.executionReceiptDigest
      || execution.publicationReceiptDigest !== receiptDigest || evaluation.publicationReceiptDigest !== receiptDigest
      || execution.authorityAfterDigest !== pkg.evaluatedAuthorityDigest
      || evaluation.authorityAfterDigest !== pkg.evaluatedAuthorityDigest
      || execution.algorithmDigest !== AGGREGATE_ALGORITHM_DIGEST
      || evaluation.algorithmDigest !== AGGREGATE_ALGORITHM_DIGEST
      || execution.algorithmVersion !== AGGREGATE_ALGORITHM_VERSION
      || evaluation.algorithmVersion !== AGGREGATE_ALGORITHM_VERSION
      || execution.componentSetDigest !== COMPONENT_SET_DIGEST
      || evaluation.componentSetDigest !== COMPONENT_SET_DIGEST
      || execution.sourceBindingDigest !== pending.aggregateResult.evaluation.sourceBindingDigest
      || evaluation.sourceBindingDigest !== pending.aggregateResult.evaluation.sourceBindingDigest
      || execution.evidenceSetDigest !== pending.aggregateResult.evaluation.evidenceSetDigest
      || evaluation.evidenceSetDigest !== pending.aggregateResult.evaluation.evidenceSetDigest) {
    fail('CANDIDATE_REEVALUATION_BINDING_INVALID', 'receipt closure');
  }
  const executionDescriptor = validateReceiptDescriptor(stage2.executionReceiptDescriptor,
    'urn:usf:validationevidence:compilersemanticenforcementaggregateexecution', execution).descriptor;
  const evaluationDescriptor = validateReceiptDescriptor(stage2.evaluationReceiptDescriptor,
    'urn:usf:validationevidence:compilersemanticenforcementaggregateevaluation', evaluation).descriptor;
  if (executionDescriptor.digest !== pkg.executionReceiptDigest
      || evaluationDescriptor.digest !== pkg.evaluationReceiptDigest) {
    fail('CANDIDATE_REEVALUATION_BINDING_INVALID', 'reevaluation descriptor digest closure');
  }
  const compilerValidation = stage2.compilerValidation.receipt;
  const compilerDescriptor = validateReceiptDescriptor(stage2.compilerValidation.descriptor,
    'urn:usf:validationevidence:compilersemanticenforcementcompilervalidation', compilerValidation).descriptor;
  for (const [label, value] of Object.entries({
    compilerExecution: compilerValidation.executionReceiptDigest,
    compilerEvaluation: compilerValidation.evaluationReceiptDigest,
    compilerReport: compilerValidation.validationReportDigest,
  })) digest(value, label);
  time(compilerValidation.evaluatedAt, 'compiler validation evaluatedAt');
  if (compilerValidation.schema !== 'semantic-authority-compiler-validation-v1'
      || compilerValidation.conforms !== true
      || compilerValidation.authorityBeforeDigest !== pending.evaluatedAuthorityDigest
      || compilerValidation.authorityAfterDigest !== pkg.evaluatedAuthorityDigest
      || compilerValidation.candidateDigest !== stage2.publicationReceipt.candidate_digest
      || compilerValidation.sourceBindingDigest !== pending.aggregateResult.evaluation.sourceBindingDigest
      || Date.parse(compilerValidation.evaluatedAt) > Date.parse(stage2.publicationReceipt.published_at)) {
    fail('CANDIDATE_REEVALUATION_BINDING_INVALID', 'persisted compiler validation closure');
  }
  time(execution.startedAt, 'reevaluation startedAt');
  time(execution.completedAt, 'reevaluation completedAt');
  time(evaluation.evaluatedAt, 'reevaluation evaluatedAt');
  if (!(Date.parse(stage2.publicationReceipt.published_at) < Date.parse(execution.startedAt)
      && Date.parse(execution.startedAt) <= Date.parse(execution.completedAt)
      && Date.parse(execution.completedAt) <= Date.parse(evaluation.evaluatedAt))) {
    fail('CANDIDATE_REEVALUATION_BINDING_INVALID', 'time order');
  }
  rejectPlaceholders(stage2);
  return Object.freeze({ ...stage2, validatedDescriptors: Object.freeze({
    compiler: compilerDescriptor, evaluation: evaluationDescriptor, execution: executionDescriptor,
  }) });
}

const iri = (value) => `<${value}>`;
const literal = (value) => JSON.stringify(String(value));
const typed = (value, datatype) => `${literal(value)}^^${iri(datatype)}`;
const q = (subject, predicate, object, graph) => `${iri(subject)} ${iri(predicate)} ${object} ${iri(graph)} .`;
const type = (subject, classIri, graph) => q(subject, RDF_TYPE, iri(classIri), graph);
const add = (lines, subject, predicate, object, graph = GRAPH_PROOFS) => lines.push(q(subject, `${USF}${predicate}`, object, graph));

function materializeEvidenceAdmissionPath(additions, {
  admissionPath, producer, release, repository, sourceHead, sourcePaths, sourceScope, sourceTree,
}) {
  additions.push(type(producer, `${USF}ValidationProducer`, GRAPH_PROOFS));
  for (const [predicate, object] of [
    ['validationProducerRepository', literal(repository)], ['validationProducerRelease', literal(release)],
    ['validationProducerSourceHead', literal(sourceHead)], ['validationProducerSourceTree', literal(sourceTree)],
    ['validationProducerSourceScopeDigest', literal(sourceScope)],
  ]) add(additions, producer, predicate, object);
  for (const path of sourcePaths) add(additions, producer, 'validationProducerSourcePath', literal(path));
  additions.push(type(admissionPath, `${USF}EvidenceAdmissionPath`, GRAPH_PROOFS));
  add(additions, admissionPath, 'admissionPathForProducer', iri(producer));
  add(additions, admissionPath, 'admissionPathRepository', literal(repository));
  add(additions, admissionPath, 'admissionPathSourceHead', literal(sourceHead));
  add(additions, admissionPath, 'admissionPathSourceTree', literal(sourceTree));
  add(additions, admissionPath, 'admissionPathSourceScopeDigest', literal(sourceScope));
  for (const path of sourcePaths) add(additions, admissionPath, 'admissionPathSourcePath', literal(path));
}

function ownerTriples(owner, scope, { includeVerifier }) {
  const additions = [];
  const { assignment, domain, evidenceAdmissionPath, repository, validationProducer, verification,
    verificationAdmission, verificationDescriptor } = scope;
  additions.push(type(assignment, `${USF}OwnerAssignment`, GRAPH_AUTHORITY));
  add(additions, assignment, 'authorityPrincipal', iri(AUTHORITY_PRINCIPAL), GRAPH_AUTHORITY);
  add(additions, assignment, 'authoritySigningIdentity', iri(AUTHORITY_SIGNING_IDENTITY), GRAPH_AUTHORITY);
  add(additions, assignment, 'authorityDomain', iri(domain), GRAPH_AUTHORITY);
  add(additions, assignment, 'authorityRepository', literal(repository), GRAPH_AUTHORITY);
  add(additions, assignment, 'sourceScopeDigest', literal(owner.assignment.sourceScopeDigest), GRAPH_AUTHORITY);
  add(additions, assignment, 'assignmentCandidateDigest', literal(owner.assignment.candidateDigest), GRAPH_AUTHORITY);
  add(additions, assignment, 'assignmentAuthorityPreDigest', literal(owner.assignment.authorityPreDigest), GRAPH_AUTHORITY);
  add(additions, assignment, 'signedEnvelopeDigest', literal(owner.assignment.envelopeDigest), GRAPH_AUTHORITY);
  add(additions, assignment, 'assignmentState', literal('active'), GRAPH_AUTHORITY);
  add(additions, assignment, 'hasAdmittedEnvelopeVerification', iri(verification), GRAPH_AUTHORITY);
  for (const path of owner.assignment.sourcePaths) add(additions, assignment, 'ownerAssignmentSourcePath', literal(path), GRAPH_AUTHORITY);

  additions.push(type(verification, `${USF}SemanticProofEnvelopeVerification`, GRAPH_AUTHORITY));
  for (const [predicate, object] of [
    ['verificationForOwnerAssignment', iri(assignment)], ['verifiedBySemanticProofProtocol', iri(PROTOCOL_IRI)],
    ['verifiedAuthorityPrincipal', iri(AUTHORITY_PRINCIPAL)], ['verifiedAuthoritySigningIdentity', iri(AUTHORITY_SIGNING_IDENTITY)],
    ['verifiedAuthorityDomain', iri(domain)], ['verifiedAuthorityRepository', literal(repository)],
    ['verifiedSourceScopeDigest', literal(owner.assignment.sourceScopeDigest)],
    ['verifiedAssignmentCandidateDigest', literal(owner.assignment.candidateDigest)],
    ['verifiedAssignmentAuthorityPreDigest', literal(owner.assignment.authorityPreDigest)],
    ['verifiedEnvelopeDigest', literal(owner.assignment.envelopeDigest)],
    ['envelopeVerificationState', iri('urn:usf:resultstate:passed')], ['verifiedByExternalVerifier', iri(VERIFIER)],
    ['hasEnvelopeVerificationAdmission', iri(verificationAdmission)], ['verificationCASDescriptor', iri(verificationDescriptor)],
    ['envelopeVerifiedAt', typed(owner.verification.verifiedAt, XSD_DATETIME)],
    ['envelopeVerificationReceiptDigest', literal(owner.verification.receiptDigest)],
  ]) add(additions, verification, predicate, object, GRAPH_AUTHORITY);
  for (const path of owner.assignment.sourcePaths) add(additions, verification, 'verifiedOwnerAssignmentSourcePath', literal(path), GRAPH_AUTHORITY);

  if (includeVerifier) {
    additions.push(type(VERIFIER_IDENTITY, `${USF}SemanticProofExternalVerifierIdentity`, GRAPH_AUTHORITY));
    add(additions, VERIFIER_IDENTITY, 'externalVerifierIdentityDigest', literal(owner.verifier.identityDigest), GRAPH_AUTHORITY);
    add(additions, VERIFIER_IDENTITY, 'externalVerifierTrustAnchorDigest', literal(owner.verifier.trustAnchorDigest), GRAPH_AUTHORITY);
    additions.push(type(VERIFIER, `${USF}SemanticProofExternalVerifier`, GRAPH_AUTHORITY));
    add(additions, VERIFIER, 'externalVerifierIdentity', iri(VERIFIER_IDENTITY), GRAPH_AUTHORITY);
    add(additions, VERIFIER, 'externalVerifierImplementationRelease', literal(owner.verifier.implementationRelease), GRAPH_AUTHORITY);
    add(additions, VERIFIER, 'externalVerifierRepository', literal(AGGREGATE_REPOSITORY), GRAPH_AUTHORITY);
    add(additions, VERIFIER, 'externalVerifierSourceHead', literal(owner.verifier.sourceHead), GRAPH_AUTHORITY);
    add(additions, VERIFIER, 'externalVerifierSourceTree', literal(owner.verifier.sourceTree), GRAPH_AUTHORITY);
    add(additions, VERIFIER, 'externalVerifierSourceScopeDigest', literal(owner.verifier.sourceScopeDigest), GRAPH_AUTHORITY);
    for (const path of owner.verifier.sourcePaths) add(additions, VERIFIER, 'externalVerifierSourcePath', literal(path), GRAPH_AUTHORITY);
  }

  additions.push(type(verificationDescriptor, `${USF}SemanticProofVerificationCASDescriptor`, GRAPH_AUTHORITY));
  add(additions, verificationDescriptor, 'semanticProofCASDigest', literal(owner.descriptor.digest), GRAPH_AUTHORITY);
  add(additions, verificationDescriptor, 'semanticProofCASByteLength',
    typed(owner.descriptor.byteLength, XSD_INTEGER), GRAPH_AUTHORITY);
  add(additions, verificationDescriptor, 'semanticProofCASMediaType', literal(owner.descriptor.mediaType), GRAPH_AUTHORITY);
  add(additions, verificationDescriptor, 'semanticProofCASVerificationState', iri('urn:usf:resultstate:passed'), GRAPH_AUTHORITY);
  add(additions, verificationDescriptor, 'semanticProofCASDescriptorReceiptDigest', literal(owner.descriptor.receiptDigest), GRAPH_AUTHORITY);
  additions.push(type(verificationAdmission, `${USF}SemanticProofEnvelopeVerificationAdmission`, GRAPH_AUTHORITY));
  add(additions, verificationAdmission, 'admitsEnvelopeVerification', iri(verification), GRAPH_AUTHORITY);
  add(additions, verificationAdmission, 'verificationAdmissionUsesEvidencePath', iri(evidenceAdmissionPath), GRAPH_AUTHORITY);
  add(additions, verificationAdmission, 'admittedVerificationCASDescriptor', iri(verificationDescriptor), GRAPH_AUTHORITY);
  add(additions, verificationAdmission, 'verificationAdmissionState', iri('urn:usf:resultstate:passed'), GRAPH_AUTHORITY);
  add(additions, verificationAdmission, 'verificationAdmissionReceiptDigest', literal(owner.admission.receiptDigest), GRAPH_AUTHORITY);
  materializeEvidenceAdmissionPath(additions, {
    admissionPath: evidenceAdmissionPath,
    producer: validationProducer,
    release: owner.verifier.implementationRelease,
    repository: AGGREGATE_REPOSITORY,
    sourceHead: owner.verifier.sourceHead,
    sourcePaths: owner.verifier.sourcePaths,
    sourceScope: owner.verifier.sourceScopeDigest,
    sourceTree: owner.verifier.sourceTree,
  });
  return additions;
}

function aggregateFoundation(additions, pending, currentnessBinding) {
  const evaluation = pending.aggregateResult.evaluation;
  const source = evaluation.sourceBinding;
  additions.push(type(AGGREGATE_ALGORITHM, `${USF}ProofAlgorithm`, GRAPH_PROOFS));
  additions.push(type(AGGREGATE_ALGORITHM, `${USF}AggregateProofAlgorithm`, GRAPH_PROOFS));
  add(additions, AGGREGATE_ALGORITHM, 'canonicalName', literal('compilersemanticenforcementaggregate'));
  add(additions, AGGREGATE_ALGORITHM, 'proofAlgorithmSourcePath',
    literal('assurance/semantic-model-compilation/aggregate-compiler-proof.mjs'));
  add(additions, AGGREGATE_ALGORITHM, 'proofAlgorithmSourceDigest', literal(AGGREGATE_ALGORITHM_DIGEST));
  add(additions, AGGREGATE_ALGORITHM, 'currentAlgorithmSourceDigest', literal(AGGREGATE_ALGORITHM_DIGEST));
  add(additions, AGGREGATE_ALGORITHM, 'currentAlgorithmVersion', iri(AGGREGATE_VERSION));
  add(additions, AGGREGATE_ALGORITHM, 'currentImplementationSourceSetDigest', literal(evaluation.sourceBindingDigest));
  add(additions, AGGREGATE_ALGORITHM, 'currentDependencySetDigest', literal(currentnessBinding.dependencySetDigest));
  add(additions, AGGREGATE_ALGORITHM, 'currentDependencyDigestAlgorithm', literal(DEPENDENCY_DIGEST_ALGORITHM));
  add(additions, AGGREGATE_ALGORITHM, 'requiresGraphSourceBinding', typed(true, XSD_BOOLEAN));
  additions.push(type(AGGREGATE_VERSION, `${USF}ProofAlgorithmVersion`, GRAPH_PROOFS));
  add(additions, AGGREGATE_VERSION, 'canonicalName', literal('compilersemanticenforcementaggregatev210'));
  add(additions, AGGREGATE_VERSION, 'proofAlgorithmVersionOf', iri(AGGREGATE_ALGORITHM));
  add(additions, AGGREGATE_VERSION, 'proofAlgorithmVersionIdentifier', literal(AGGREGATE_ALGORITHM_VERSION));
  additions.push(type(AGGREGATE_OBLIGATION, `${USF}AggregateProofObligation`, GRAPH_PROOFS));
  add(additions, AGGREGATE_OBLIGATION, 'canonicalName', literal('compilersemanticenforcementaggregate'));
  add(additions, AGGREGATE_OBLIGATION, 'obligationFor', iri(CONTRACT));
  add(additions, AGGREGATE_OBLIGATION, 'obligationEffect', iri('urn:usf:obligationeffect:blocking'));
  add(additions, AGGREGATE_OBLIGATION, 'requiresRung', iri(AGGREGATE_RUNG));
  add(additions, AGGREGATE_OBLIGATION, 'derivedFrom', iri(CONTRACT));
  for (const cell of AGGREGATE_ASSURANCE_CELLS) {
    add(additions, AGGREGATE_OBLIGATION, 'usesAssuranceCell', iri(cell));
  }
  for (const requirement of AGGREGATE_EVIDENCE_REQUIREMENTS) {
    add(additions, AGGREGATE_OBLIGATION, 'requiresEvidence', iri(requirement));
  }
  add(additions, AGGREGATE_OBLIGATION, 'componentSetDigest', literal(COMPONENT_SET_DIGEST));
  for (const component of COMPONENT_PROOFS) {
    const requirement = `urn:usf:componentproofrequirement:compilersemanticenforcementaggregate:${component.dimension}`;
    additions.push(type(requirement, `${USF}ComponentProofRequirement`, GRAPH_PROOFS));
    add(additions, requirement, 'canonicalName',
      literal(`compilersemanticenforcementaggregate${component.dimension}`));
    add(additions, requirement, 'componentObligation', iri(component.obligation));
    add(additions, requirement, 'componentProofResult', iri(component.result));
    add(additions, requirement, 'componentDimension', literal(component.dimension));
    add(additions, AGGREGATE_OBLIGATION, 'requiresComponentProof', iri(requirement));
    add(additions, component.obligation, 'satisfiedByProofResult', iri(component.result));
    add(additions, component.result, 'proofResultForObligation', iri(component.obligation));
  }
  return { evaluation, source };
}

function admittedAggregateEvidence(evaluation) {
  const evidence = evaluation.components.flatMap((component) => component.currentness.admittedEvidence);
  const keyed = new Map(evidence.map((item) => [`${item.iri}\0${item.digest}`, item]));
  return [...keyed.values()].sort((left, right) => left.iri.localeCompare(right.iri) || left.digest.localeCompare(right.digest));
}

function materializeAggregateProof(additions, {
  confidenceState = 'warranted', evaluation, proof, execution, proofEvaluation, result, source,
  materializeEvidenceApplicability = true,
}) {
  additions.push(type(proof, `${USF}Proof`, GRAPH_PROOFS));
  add(additions, proof, 'canonicalName', literal(proof === PROVISIONAL_PROOF
    ? 'compilersemanticenforcementaggregateprepublication' : 'compilersemanticenforcementaggregate'));
  add(additions, proof, 'atRung', iri(AGGREGATE_RUNG));
  add(additions, proof, 'usesProviderMode', iri(AGGREGATE_PROVIDER_MODE));
  add(additions, proof, 'inEnvironment', iri(AGGREGATE_ENVIRONMENT));
  add(additions, proof, 'exercises', iri(CONTRACT));
  add(additions, proof, 'provesSubject', iri(CONTRACT));
  additions.push(type(execution, `${USF}ProofExecution`, GRAPH_PROOFS));
  additions.push(type(execution, `${USF}AggregateProofExecution`, GRAPH_PROOFS));
  add(additions, execution, 'canonicalName', literal(execution === PROVISIONAL_EXECUTION
    ? 'compilersemanticenforcementaggregateprepublication' : 'compilersemanticenforcementaggregate'));
  add(additions, execution, 'executesProof', iri(proof));
  add(additions, execution, 'producesResult', iri(result));
  additions.push(type(proofEvaluation, `${USF}ProofEvaluation`, GRAPH_PROOFS));
  additions.push(type(proofEvaluation, `${USF}AggregateProofEvaluation`, GRAPH_PROOFS));
  add(additions, proofEvaluation, 'canonicalName', literal(proofEvaluation === PROVISIONAL_EVALUATION
    ? 'compilersemanticenforcementaggregateprepublication' : 'compilersemanticenforcementaggregate'));
  add(additions, proofEvaluation, 'evaluatesObligation', iri(AGGREGATE_OBLIGATION));
  add(additions, proofEvaluation, 'producesProofResult', iri(result));
  add(additions, result, 'canonicalName', literal(result === PROVISIONAL_RESULT
    ? 'compilersemanticenforcementaggregateprepublication' : 'compilersemanticenforcementaggregate'));
  for (const evidence of admittedAggregateEvidence(evaluation)) {
    add(additions, result, 'usesAdmittedEvidence', iri(evidence.iri));
    add(additions, result, 'confidenceBasis', iri(evidence.iri));
    if (materializeEvidenceApplicability) {
      add(additions, evidence.iri, 'applicableToObligation', iri(AGGREGATE_OBLIGATION));
    }
  }
  add(additions, result, 'evidenceSetDigest', literal(evaluation.evidenceSetDigest));
  add(additions, result, 'implementationSourceSetDigest', literal(evaluation.sourceBindingDigest));
  add(additions, result, 'proofProducerCommit', literal(source.head));
  add(additions, result, 'proofProducerTree', literal(source.tree));
  add(additions, result, 'evaluatedByValidator', iri('urn:usf:validatorrule:validateassuranceconformance'));
  add(additions, result, 'proofExecutionEnvironment', iri(AGGREGATE_ENVIRONMENT));
  add(additions, result, 'usesProviderMode', iri(AGGREGATE_PROVIDER_MODE));
  add(additions, result, 'inEnvironment', iri(AGGREGATE_ENVIRONMENT));
  add(additions, result, 'claimedRung', iri(AGGREGATE_RUNG));
  add(additions, result, 'observedRung', iri(AGGREGATE_RUNG));
  add(additions, result, 'hasFreshness', iri('urn:usf:freshness:fresh'));
  add(additions, result, 'hasConfidenceState', iri(`urn:usf:proofconfidencestate:${confidenceState}`));
  for (const condition of ['evidenceinvalidated', 'evidencestale', 'authoritydigestchanged']) {
    add(additions, result, 'hasInvalidationCondition', iri(`urn:usf:proofinvalidationcondition:${condition}`));
  }
}

function materializeProofAuthorityBinding(additions, {
  authorityBindingEvidenceDigest, binding, dependencySetDigest, evaluatedAuthorityDigest, result,
  reevaluationState,
}) {
  additions.push(type(binding, `${USF}ProofAuthorityBinding`, GRAPH_PROOFS));
  add(additions, binding, 'canonicalName', literal(binding === PROVISIONAL_BINDING
    ? 'compilersemanticenforcementaggregateprepublication' : 'compilersemanticenforcementaggregate'));
  add(additions, binding, 'bindingEvaluatedAuthorityDigest', literal(evaluatedAuthorityDigest));
  add(additions, binding, 'bindingDependencySetDigest', literal(dependencySetDigest));
  add(additions, binding, 'bindingDependencyDigestAlgorithm', literal(DEPENDENCY_DIGEST_ALGORITHM));
  add(additions, binding, 'usesAuthorityBindingRule', iri(SELF_PUBLICATION_RULE));
  add(additions, binding, 'requiresPostPublicationReevaluation', typed(true, XSD_BOOLEAN));
  add(additions, binding, 'authorityBindingEvidenceDigest', literal(authorityBindingEvidenceDigest));
  add(additions, binding, 'hasPostPublicationReevaluationState', iri(`urn:usf:proofreevaluationstate:${reevaluationState}`));
  if (reevaluationState === 'successful') {
    add(additions, binding, 'reevaluationDependencySetDigest', literal(dependencySetDigest));
  }
  for (const graph of EXCLUDED_AUTHORITY_GRAPHS) add(additions, binding, 'excludedAuthorityGraphIri', typed(graph, XSD_ANY_URI));
  add(additions, result, 'hasAuthorityBinding', iri(binding));
}

function materializeAggregateValidationInfrastructure(additions, source) {
  materializeEvidenceAdmissionPath(additions, {
    admissionPath: EVIDENCE_ADMISSION_PATH,
    producer: VALIDATION_PRODUCER,
    release: AGGREGATE_ALGORITHM_VERSION,
    repository: AGGREGATE_REPOSITORY,
    sourceHead: source.head,
    sourcePaths: source.sourcePaths,
    sourceScope: source.sourceScopeDigest,
    sourceTree: source.tree,
  });
}

function stage1Patch(pending, owners, currentnessBinding) {
  const deletions = [
    ...COMPONENT_PROOFS.map(({ result }) =>
      q(CONTRACT, `${USF}reliesOnProofResult`, iri(result), GRAPH_CAPABILITIES)),
    q(CONTRACT, `${USF}hasActivationState`, iri('urn:usf:contractactivationstate:active'), GRAPH_CAPABILITIES),
  ];
  const additions = OWNER_SCOPE_KEYS.flatMap((key, index) => ownerTriples(owners[key], OWNER_SCOPES[key], {
    includeVerifier: index === 0,
  }));
  const { evaluation, source } = aggregateFoundation(additions, pending, currentnessBinding);
  materializeAggregateValidationInfrastructure(additions, source);
  additions.push(type(SELF_PUBLICATION_RULE, `${USF}AuthorityBindingRule`, GRAPH_PROOFS));
  additions.push(type(VALIDATION_RULE, `${USF}AuthorityBindingRule`, GRAPH_PROOFS));
  add(additions, VALIDATION_RULE, 'canonicalName', literal('validationnonpublicationdependencyclosure'));
  materializeAggregateProof(additions, {
    confidenceState: 'unknown', evaluation, execution: PROVISIONAL_EXECUTION, proof: PROVISIONAL_PROOF,
    proofEvaluation: PROVISIONAL_EVALUATION, result: PROVISIONAL_RESULT, source,
  });
  additions.push(type(PROVISIONAL_RESULT, `${USF}ProofResult`, GRAPH_PROOFS));
  additions.push(type(PROVISIONAL_RESULT, `${USF}PrePublicationAggregateProofResult`, GRAPH_PROOFS));
  for (const [predicate, object] of [
    ['proofResultForObligation', iri(AGGREGATE_OBLIGATION)], ['resultForProof', iri(PROVISIONAL_PROOF)],
    ['usesProofAlgorithm', iri(AGGREGATE_ALGORITHM)], ['usesAlgorithmVersion', iri(AGGREGATE_VERSION)],
    ['componentSetDigest', literal(COMPONENT_SET_DIGEST)], ['aggregateAlgorithmDigest', literal(AGGREGATE_ALGORITHM_DIGEST)],
    ['aggregateSourceHead', literal(source.head)], ['aggregateAuthorityDigest', literal(evaluation.authorityDigest)],
    ['dependencySetDigest', literal(currentnessBinding.dependencySetDigest)],
    ['dependencyDigestAlgorithm', literal(DEPENDENCY_DIGEST_ALGORITHM)],
    ['evaluatedAt', typed(evaluation.evaluatedAt, XSD_DATETIME)], ['resultState', iri('urn:usf:resultstate:notrun')],
  ]) add(additions, PROVISIONAL_RESULT, predicate, object);
  materializeProofAuthorityBinding(additions, {
    authorityBindingEvidenceDigest: pending.executionReceiptDigest,
    binding: PROVISIONAL_BINDING,
    dependencySetDigest: currentnessBinding.dependencySetDigest,
    evaluatedAuthorityDigest: evaluation.authorityDigest,
    reevaluationState: 'pending',
    result: PROVISIONAL_RESULT,
  });
  add(additions, CONTRACT, 'hasActivationState',
    iri('urn:usf:contractactivationstate:proofblocked'), GRAPH_CAPABILITIES);
  add(additions, CONTRACT, 'reliesOnProofResult', iri(PROVISIONAL_RESULT), GRAPH_CAPABILITIES);
  return { additions, deletions };
}

function stage2Patch(pending, owners, stage2, currentnessBinding) {
  const stage1 = stage1Patch(pending, owners, currentnessBinding);
  const transientContractFacts = new Set([
    q(CONTRACT, `${USF}reliesOnProofResult`, iri(PROVISIONAL_RESULT), GRAPH_CAPABILITIES),
    q(CONTRACT, `${USF}hasActivationState`,
      iri('urn:usf:contractactivationstate:proofblocked'), GRAPH_CAPABILITIES),
  ]);
  const additions = stage1.additions.filter((line) => !transientContractFacts.has(line));
  const deletions = [
    q(CONTRACT, `${USF}reliesOnProofResult`, iri(PROVISIONAL_RESULT), GRAPH_CAPABILITIES),
    q(CONTRACT, `${USF}hasActivationState`,
      iri('urn:usf:contractactivationstate:proofblocked'), GRAPH_CAPABILITIES),
    ...COMPONENT_PROOFS.flatMap(({ obligation, result }) => [
      q(CONTRACT, `${USF}reliesOnProofResult`, iri(result), GRAPH_CAPABILITIES),
      q(CONTRACT, `${USF}mandatoryProofObligation`, iri(obligation), GRAPH_CAPABILITIES),
    ]),
  ];
  const evaluation = pending.aggregateResult.evaluation;
  const source = evaluation.sourceBinding;
  materializeAggregateProof(additions, {
    evaluation, execution: FINAL_EXECUTION, proof: FINAL_PROOF, proofEvaluation: FINAL_EVALUATION,
    result: AGGREGATE_RESULT_IRI, source, materializeEvidenceApplicability: false,
  });
  additions.push(type(AGGREGATE_RESULT_IRI, `${USF}ProofResult`, GRAPH_PROOFS));
  additions.push(type(AGGREGATE_RESULT_IRI, `${USF}PostPublicationAggregateProofResult`, GRAPH_PROOFS));
  for (const [predicate, object] of [
    ['proofResultForObligation', iri(AGGREGATE_OBLIGATION)], ['resultForProof', iri(FINAL_PROOF)],
    ['usesProofAlgorithm', iri(AGGREGATE_ALGORITHM)], ['usesAlgorithmVersion', iri(AGGREGATE_VERSION)],
    ['componentSetDigest', literal(COMPONENT_SET_DIGEST)], ['aggregateAlgorithmDigest', literal(AGGREGATE_ALGORITHM_DIGEST)],
    ['aggregateSourceHead', literal(source.head)], ['aggregateAuthorityDigest', literal(stage2.package.evaluatedAuthorityDigest)],
    ['dependencySetDigest', literal(currentnessBinding.dependencySetDigest)],
    ['dependencyDigestAlgorithm', literal(DEPENDENCY_DIGEST_ALGORITHM)],
    ['evaluatedAt', typed(stage2.evaluationReceipt.evaluatedAt, XSD_DATETIME)],
    ['resultState', iri('urn:usf:resultstate:passed')],
    ['hasProofResultState', iri('urn:usf:proofresultstate:successful')],
    ['hasPostPublicationReevaluation', iri(REEVALUATION)],
  ]) add(additions, AGGREGATE_RESULT_IRI, predicate, object);
  materializeProofAuthorityBinding(additions, {
    authorityBindingEvidenceDigest: stage2.package.evaluationReceiptDigest,
    binding: FINAL_BINDING,
    dependencySetDigest: currentnessBinding.dependencySetDigest,
    evaluatedAuthorityDigest: stage2.package.evaluatedAuthorityDigest,
    reevaluationState: 'successful',
    result: AGGREGATE_RESULT_IRI,
  });
  additions.push(type(REEVALUATION, `${USF}PostPublicationReevaluation`, GRAPH_PROOFS));
  add(additions, REEVALUATION, 'canonicalName', literal('compilersemanticenforcementaggregate'));
  for (const [predicate, object] of [
    ['reevaluatesProofResult', iri(PROVISIONAL_RESULT)], ['reevaluationProducesProofResult', iri(AGGREGATE_RESULT_IRI)],
    ['reevaluationAuthorityDigest', literal(stage2.package.evaluatedAuthorityDigest)],
    ['reevaluationSourceHead', literal(source.head)], ['reevaluationAlgorithmDigest', literal(AGGREGATE_ALGORITHM_DIGEST)],
    ['reevaluationComponentSetDigest', literal(COMPONENT_SET_DIGEST)],
    ['reevaluationResultState', iri('urn:usf:resultstate:passed')],
    ['reevaluationEvaluatedAt', typed(stage2.evaluationReceipt.evaluatedAt, XSD_DATETIME)],
    ['reevaluationExecutionReceiptDigest', literal(stage2.package.executionReceiptDigest)],
    ['reevaluationEvaluationReceiptDigest', literal(stage2.package.evaluationReceiptDigest)],
  ]) add(additions, REEVALUATION, predicate, object);
  add(additions, CONTRACT, 'hasActivationState',
    iri('urn:usf:contractactivationstate:active'), GRAPH_CAPABILITIES);
  add(additions, CONTRACT, 'mandatoryProofObligation', iri(AGGREGATE_OBLIGATION), GRAPH_CAPABILITIES);
  add(additions, CONTRACT, 'reliesOnProofResult', iri(AGGREGATE_RESULT_IRI), GRAPH_CAPABILITIES);

  // This compiler descriptor closes the already-settled D0 -> D1 validation;
  // it is therefore immutable input to D2 rather than a self-reference to the
  // D1 -> D2 validation performed after these candidate bytes are frozen.
  const descriptors = [
    stage2.validatedDescriptors.compiler,
    stage2.validatedDescriptors.execution,
    stage2.validatedDescriptors.evaluation,
  ];
  const compilerValidation = stage2.compilerValidation.receipt;
  additions.push(type(VALIDATION_EXECUTION, `${USF}ValidationExecution`, GRAPH_PROOFS));
  add(additions, VALIDATION_EXECUTION, 'canonicalName', literal('compilersemanticenforcementaggregate'));
  add(additions, VALIDATION_EXECUTION, 'validationExecutedByProducer', iri(VALIDATION_PRODUCER));
  add(additions, VALIDATION_EXECUTION, 'validationUsesEvidenceAdmissionPath', iri(EVIDENCE_ADMISSION_PATH));
  add(additions, VALIDATION_EXECUTION, 'validationExecutionReceiptDigest', literal(compilerValidation.executionReceiptDigest));
  additions.push(type(VALIDATION_EVALUATION, `${USF}ValidationEvaluation`, GRAPH_PROOFS));
  add(additions, VALIDATION_EVALUATION, 'canonicalName', literal('compilersemanticenforcementaggregate'));
  add(additions, VALIDATION_EVALUATION, 'validationEvaluationOfExecution', iri(VALIDATION_EXECUTION));
  add(additions, VALIDATION_EVALUATION, 'validationEvaluationReceiptDigest', literal(compilerValidation.evaluationReceiptDigest));
  additions.push(type(VALIDATION_RESULT, `${USF}ValidationResult`, GRAPH_PROOFS));
  add(additions, VALIDATION_RESULT, 'canonicalName', literal('compilersemanticenforcementaggregate'));
  add(additions, VALIDATION_RESULT, 'resultState', iri('urn:usf:resultstate:passed'));
  add(additions, VALIDATION_RESULT, 'hasFreshness', iri('urn:usf:freshness:fresh'));
  add(additions, VALIDATION_RESULT, 'validationResultOfEvaluation', iri(VALIDATION_EVALUATION));
  add(additions, VALIDATION_RESULT, 'hasValidationSelfPublicationAuthorityBinding', iri(VALIDATION_BINDING));
  add(additions, VALIDATION_OBLIGATION, 'satisfiedByValidationResult', iri(VALIDATION_RESULT));
  for (const descriptor of descriptors) {
    additions.push(type(descriptor.iri, `${USF}ValidationEvidence`, GRAPH_PROOFS));
    add(additions, descriptor.iri, 'canonicalName', literal(descriptor.iri.split(':').at(-1)));
    add(additions, descriptor.iri, 'validationEvidenceForExecution', iri(VALIDATION_EXECUTION));
    add(additions, descriptor.iri, 'validationEvidenceAdmittedThrough', iri(EVIDENCE_ADMISSION_PATH));
    add(additions, descriptor.iri, 'contentDigest', literal(descriptor.digest));
    add(additions, descriptor.iri, 'validationEvidencePersistenceReceiptDigest', literal(descriptor.persistenceReceiptDigest));
  }
  additions.push(type(VALIDATION_BINDING, `${USF}ValidationSelfPublicationBinding`, GRAPH_PROOFS));
  add(additions, VALIDATION_BINDING, 'canonicalName', literal('compilersemanticenforcementaggregate'));
  for (const [predicate, object] of [
    ['authorityBindingForValidationResult', iri(VALIDATION_RESULT)],
    ['authorityBindingValidationProducer', iri(VALIDATION_PRODUCER)],
    ['authorityBindingEvidenceAdmissionPath', iri(EVIDENCE_ADMISSION_PATH)],
    ['validationStageOneEvaluatedAuthorityDigest', literal(stage2.publicationReceipt.authority_before_digest)],
    ['validationNonPublicationDependencySetDigest', literal(currentnessBinding.dependencySetDigest)],
    ['validationNonPublicationDependencyDigestAlgorithm', literal(DEPENDENCY_DIGEST_ALGORITHM)],
    ['validationPostPublicationReevaluationState', iri('urn:usf:resultstate:passed')],
    ['validationStageOneSettledAuthorityDigest', literal(stage2.publicationReceipt.authority_after_digest)],
    ['validationReevaluationDependencyDigest', literal(currentnessBinding.dependencySetDigest)],
    ['validationBindingExecutionReceiptDigest', literal(compilerValidation.executionReceiptDigest)],
    ['validationBindingEvaluationReceiptDigest', literal(compilerValidation.evaluationReceiptDigest)],
    ['validationBindingProducerRelease', literal(AGGREGATE_ALGORITHM_VERSION)],
    ['validationBindingRepository', literal(AGGREGATE_REPOSITORY)],
    ['validationBindingSourceHead', literal(source.head)], ['validationBindingSourceTree', literal(source.tree)],
    ['validationBindingSourceScopeDigest', literal(source.sourceScopeDigest)],
    ['validationUsesAuthorityBindingRule', iri(VALIDATION_RULE)],
    ['validationRequiresPostPublicationReevaluation', typed(true, XSD_BOOLEAN)],
    ['validationBindingEnvelopeVerification', iri(OWNER_SCOPES.semanticmodelcompilation.verification)],
    ['validationBindingExternalVerifier', iri(VERIFIER)],
    ['validationBindingVerificationCASDescriptor', iri(OWNER_SCOPES.semanticmodelcompilation.verificationDescriptor)],
  ]) add(additions, VALIDATION_BINDING, predicate, object);
  for (const path of source.sourcePaths) add(additions, VALIDATION_BINDING, 'validationBindingSourcePath', literal(path));
  return { additions, deletions };
}

function canonicalPatch(stage, deletions, additions) {
  if (new Set(deletions).size !== deletions.length || new Set(additions).size !== additions.length) {
    fail('CANDIDATE_DUPLICATE_QUAD', stage);
  }
  const overlap = deletions.filter((line) => additions.includes(line));
  if (overlap.length > 0) fail('CANDIDATE_CONTRADICTORY_QUAD', overlap[0]);
  return Buffer.from([
    `# ${SEMANTIC_PROOF_PROTOCOL} canonical-rdf-patch-v1 ${stage}`,
    ...[...deletions].sort().map((line) => `D ${line}`),
    ...[...additions].sort().map((line) => `A ${line}`),
    '',
  ].join('\n'), 'utf8');
}

export function materializeAggregateCompilerAuthorityCandidate(input) {
  exactKeys(input, input?.stage === 'stage1' ? ['baseSemanticDelta', 'currentnessBinding', 'ownerAuthority', 'pendingPackage', 'stage']
    : ['currentnessBinding', 'ownerAuthority', 'pendingPackage', 'stage', 'stage2Package'],
  'CANDIDATE_INPUT_SCHEMA_INVALID', 'input');
  if (input.stage !== 'stage1' && input.stage !== 'stage2') fail('CANDIDATE_STAGE_INVALID', String(input.stage));
  const pending = validatePending(input.pendingPackage);
  const owners = validateOwners(input.ownerAuthority, pending);
  const currentnessBinding = validateCurrentnessBinding(input.currentnessBinding);
  let patch;
  if (input.stage === 'stage1') {
    const base = parseCanonicalBaseDelta(input.baseSemanticDelta, pending.evaluatedAuthorityDigest);
    patch = mergeBaseDelta(base, stage1Patch(pending, owners, currentnessBinding));
  }
  else {
    const stage2 = validateStage2(input.stage2Package, pending);
    patch = stage2Patch(pending, owners, stage2, currentnessBinding);
  }
  const bytes = canonicalPatch(input.stage, patch.deletions, patch.additions);
  return Object.freeze({
    bytes,
    candidateDigest: sha256Bytes(bytes),
    mediaType: 'application/rdf-patch',
    protocol: SEMANTIC_PROOF_PROTOCOL,
    stage: input.stage,
  });
}

export const aggregateCompilerAuthorityCandidateInternals = Object.freeze({
  AGGREGATE_OBLIGATION,
  ASSIGNMENT: OWNER_SCOPES.semanticmodelcompilation.assignment,
  FINAL_BINDING,
  OWNER_SCOPES,
  PROVISIONAL_RESULT,
  VALIDATION_RESULT,
  nonPublicationDependencySetDigest,
  sha256Bytes,
  sha256Json,
});
