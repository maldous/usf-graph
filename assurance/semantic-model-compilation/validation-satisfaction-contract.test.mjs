import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import N3 from 'n3';

// Structural assurance for the ValidationObligation satisfaction contract in
// semantic-model/shapes/lifecycle.ttl. Adversarial counterexample testing found
// the PR #14 contract accepted malformed satisfaction states; every assertion
// below pins one strengthening so it cannot silently regress. This file reads
// tracked semantic-model source only: no network, no child process, no SHACL
// engine.

const SH = 'http://www.w3.org/ns/shacl#';
const O = 'urn:usf:ontology:';
const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
const XSD = 'http://www.w3.org/2001/XMLSchema#';
const named = N3.DataFactory.namedNode;

const OBLIGATION_STATE_SHAPE = 'urn:usf:shape:validationobligationstate';
const RESULT_BINDING_SHAPE = 'urn:usf:shape:validationresultbinding';
const ACTIVATION_SHAPE = 'urn:usf:shape:activatedvalidationobligation';
const IMPLEMENTABLE_STATE_SHAPE = 'urn:usf:shape:implementablestatedefinition';
const PROOF_AUTHORITY_BINDING_SHAPE = 'urn:usf:shacl:ProofAuthorityBindingShape';
const NONCLAIM = 'urn:usf:nonclaim:controlplanereceiptdoesnotsatisfyvalidation';

function parseTurtle(relativePath) {
  const url = new URL(relativePath, import.meta.url);
  const store = new N3.Store();
  store.addQuads(new N3.Parser({ baseIRI: url.href }).parse(readFileSync(url, 'utf8')));
  return store;
}

const lifecycleShapes = parseTurtle('../../semantic-model/shapes/lifecycle.ttl');
const assuranceShapes = parseTurtle('../../semantic-model/shapes/assurance.ttl');
const ontology = parseTurtle('../../semantic-model/ontology.ttl');
const vocabulary = parseTurtle('../../semantic-model/vocabulary.ttl');

const objects = (store, subject, predicate) => store.getObjects(subject, named(predicate), null);
const values = (store, subject, predicate) => objects(store, subject, predicate).map(({ value }) => value);

function only(store, subject, predicate) {
  const found = objects(store, subject, predicate);
  assert.equal(found.length, 1, `${predicate} must have exactly one value`);
  return found[0];
}

function propertyShape(store, shapeIri, pathIri) {
  const matching = objects(store, named(shapeIri), `${SH}property`)
    .filter((node) => values(store, node, `${SH}path`).includes(pathIri));
  assert.equal(matching.length, 1, `${shapeIri} must carry exactly one property shape for ${pathIri}`);
  return matching[0];
}

function rdfList(store, head) {
  const members = [];
  let node = head;
  while (node && node.value !== `${RDF}nil`) {
    members.push(only(store, node, `${RDF}first`).value);
    node = only(store, node, `${RDF}rest`);
  }
  return members;
}

function sparqlText(store, shapeIri) {
  const constraints = objects(store, named(shapeIri), `${SH}sparql`);
  assert.equal(constraints.length, 1, `${shapeIri} must carry exactly one sh:sparql constraint`);
  return {
    select: only(store, constraints[0], `${SH}select`).value,
    message: only(store, constraints[0], `${SH}message`).value,
  };
}

test('a ValidationObligation may be satisfied by at most one ValidationResult', () => {
  const shape = propertyShape(lifecycleShapes, OBLIGATION_STATE_SHAPE, `${O}satisfiedByValidationResult`);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}maxCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}minCount`), [],
    'satisfaction stays optional: an unsatisfied obligation is the normal state');
  assert.match(only(lifecycleShapes, shape, `${SH}message`).value, /must not be satisfied by more than one/u);
});

test('the activation-state enumeration equals exactly the declared vocabulary values', () => {
  const shape = propertyShape(lifecycleShapes, OBLIGATION_STATE_SHAPE, `${O}hasValidationActivationState`);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}minCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}maxCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}class`), [`${O}ValidationObligationActivationState`]);
  const enumerated = rdfList(lifecycleShapes, only(lifecycleShapes, shape, `${SH}in`));
  const declared = vocabulary
    .getSubjects(named(`${RDF}type`), named(`${O}ValidationObligationActivationState`), null)
    .map(({ value }) => value);
  assert.equal(declared.length, 3);
  assert.deepEqual([...enumerated].sort(), [...declared].sort(),
    'sh:in must not drift from the ValidationObligationActivationState values in vocabulary.ttl');
  assert.deepEqual(enumerated, [
    'urn:usf:validationactivationstate:reserved',
    'urn:usf:validationactivationstate:activated',
    'urn:usf:validationactivationstate:blocked',
  ]);
});

test('a satisfying result declares exactly one result state and it is passed', () => {
  const shape = propertyShape(lifecycleShapes, RESULT_BINDING_SHAPE, `${O}resultState`);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}minCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}maxCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}hasValue`), ['urn:usf:resultstate:passed']);
});

test('cited validation evidence must be an EvidenceResult', () => {
  const shape = propertyShape(lifecycleShapes, RESULT_BINDING_SHAPE, `${O}usesAdmittedValidationEvidence`);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}minCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}class`), [`${O}EvidenceResult`]);
});

test('the evaluated authority digest is an exact sha256 string', () => {
  const shape = propertyShape(lifecycleShapes, RESULT_BINDING_SHAPE, `${O}validationEvaluatedAuthorityDigest`);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}minCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}maxCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}datatype`), [`${XSD}string`]);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}pattern`), ['^sha256:[0-9a-f]{64}$']);
});

test('the evaluated source head is an exact forty-hex commit string', () => {
  const shape = propertyShape(lifecycleShapes, RESULT_BINDING_SHAPE, `${O}validationEvaluatedSourceHead`);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}minCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}maxCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}datatype`), [`${XSD}string`]);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}pattern`), ['^[0-9a-f]{40}$']);
});

test('satisfaction carries the same self-publication closure as proof authority binding', () => {
  const path = `${O}requiresPostPublicationReevaluation`;
  const shape = propertyShape(lifecycleShapes, RESULT_BINDING_SHAPE, path);
  const proofShape = propertyShape(assuranceShapes, PROOF_AUTHORITY_BINDING_SHAPE, path);
  for (const constraint of [`${SH}minCount`, `${SH}maxCount`, `${SH}datatype`, `${SH}hasValue`]) {
    assert.deepEqual(values(lifecycleShapes, shape, constraint),
      values(assuranceShapes, proofShape, constraint), constraint);
  }
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}minCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}maxCount`), ['1']);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}datatype`), [`${XSD}boolean`]);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}hasValue`), ['true']);
});

test('the satisfying-result SPARQL constraint closes evidence, circularity and digest agreement', () => {
  const { select, message } = sparqlText(lifecycleShapes, RESULT_BINDING_SHAPE);
  for (const prefix of [
    'PREFIX usf: <urn:usf:ontology:>',
    'PREFIX admission: <urn:usf:evidenceadmissionstate:>',
    'PREFIX freshnessstate: <urn:usf:evidencefreshnessstate:>',
    'PREFIX integritystate: <urn:usf:evidenceintegritystate:>',
    'PREFIX resultstate: <urn:usf:resultstate:>',
    'PREFIX es: <urn:usf:evidencestage:>',
  ]) {
    assert.equal(select.includes(prefix), true, prefix);
  }
  for (const clause of [
    '$this usf:resultForValidationObligation ?o ; usf:usesAdmittedValidationEvidence ?e .',
    '?e usf:hasAdmissionState admission:admitted',
    'usf:hasFreshnessState freshnessstate:fresh',
    'usf:hasIntegrityState integritystate:valid',
    'usf:withinValidityScope true',
    'usf:applicableToObligation ?o',
    'usf:evidenceStage es:emitted, es:collected, es:normalised, es:ingested, es:signed, es:integrityverified',
    'usf:collectedBy ?collection',
    'usf:normalisedBy ?normalisation',
    'usf:ingestedBy ?ingestion',
    'usf:evidenceSignature ?signature',
    'usf:evidenceChecksum ?checksum',
    '?collection a usf:EvidenceCollection',
    '?normalisation a usf:EvidenceNormalisation',
    '?ingestion a usf:EvidenceIngestion',
    '?signature a usf:Signature',
    '?checksum a usf:Checksum',
    '?verification a usf:IntegrityVerification ; usf:verifiesEvidence ?e ; usf:verificationState resultstate:passed',
    'EXISTS {$this usf:usesAdmittedValidationEvidence $this}',
    '|| ?e = ?o',
    '$this usf:validationEvaluatedAuthorityDigest ?d . ?e usf:evaluatedAuthorityDigest ?ed . FILTER (?d != ?ed)',
  ]) {
    assert.equal(select.includes(clause), true, clause);
  }
  assert.equal(message.includes(NONCLAIM), true,
    'the structured constraint must name the nonclaim whose prose it enforces');
});

test('an activated obligation shape exists, targets ValidationObligation and demands activation authority', () => {
  assert.deepEqual(values(lifecycleShapes, named(ACTIVATION_SHAPE), `${RDF}type`), [`${SH}NodeShape`]);
  assert.deepEqual(values(lifecycleShapes, named(ACTIVATION_SHAPE), `${SH}targetClass`), [`${O}ValidationObligation`]);
  const { select } = sparqlText(lifecycleShapes, ACTIVATION_SHAPE);
  for (const clause of [
    '$this usf:hasValidationActivationState <urn:usf:validationactivationstate:activated> .',
    'NOT EXISTS {$this usf:validationActivationAuthority ?authority}',
    'EXISTS {$this usf:validationActivationAuthority ?authority, ?otherAuthority . FILTER (?authority != ?otherAuthority)}',
    'NOT EXISTS {$this usf:validationActivatedAt ?activatedAt}',
    'EXISTS {$this usf:validationActivatedAt ?activatedAt, ?otherActivatedAt . FILTER (?activatedAt != ?otherActivatedAt)}',
    'NOT EXISTS {$this usf:validationActivationReason ?reason}',
    'NOT EXISTS {$this usf:validationActivationPrerequisite ?requirement}',
    '?requirement usf:satisfiedByEvidence ?evidence',
    '?evidence usf:hasAdmissionState admission:admitted ; usf:hasFreshnessState freshnessstate:fresh ; usf:hasIntegrityState integritystate:valid',
  ]) {
    assert.equal(select.includes(clause), true, clause);
  }
});

test('the realisation-predecessor property shape carries a real constraint', () => {
  const shape = propertyShape(lifecycleShapes, IMPLEMENTABLE_STATE_SHAPE, `${O}allowsRealisationPredecessor`);
  assert.deepEqual(values(lifecycleShapes, shape, `${SH}class`), [`${O}RealisationState`]);
  assert.equal(lifecycleShapes.getQuads(shape, null, null, null).length > 1, true,
    'a property shape with only sh:path constrains nothing and vacuously covers its term');
});

test('activation authority and activation time are declared functional and reserved', () => {
  for (const [term, kind, range] of [
    [`${O}validationActivationAuthority`, 'http://www.w3.org/2002/07/owl#ObjectProperty', `${O}Entity`],
    [`${O}validationActivatedAt`, 'http://www.w3.org/2002/07/owl#DatatypeProperty', `${XSD}dateTime`],
  ]) {
    const declared = values(ontology, named(term), `${RDF}type`);
    assert.equal(declared.includes(kind), true, term);
    assert.equal(declared.includes('http://www.w3.org/2002/07/owl#FunctionalProperty'), true, term);
    assert.deepEqual(values(ontology, named(term), 'http://www.w3.org/2000/01/rdf-schema#domain'),
      [`${O}ValidationObligation`], term);
    assert.deepEqual(values(ontology, named(term), 'http://www.w3.org/2000/01/rdf-schema#range'), [range], term);
    assert.deepEqual(values(ontology, named(term), `${O}termUsageState`),
      ['urn:usf:termusagestate:reservedfuturescope'], term);
    assert.equal(values(ontology, named(term), `${O}termUsageRationale`).length, 1, term);
  }
});

test('evidence supersession is dispositioned in both directions', () => {
  for (const term of [`${O}supersedesEvidence`, `${O}isSupersededByEvidence`]) {
    assert.deepEqual(values(ontology, named(term), `${O}termUsageState`),
      ['urn:usf:termusagestate:reservedfuturescope'], term);
  }
  assert.equal(values(ontology, named(`${O}supersedesEvidence`), `${O}termUsageRationale`).length, 1);
});
