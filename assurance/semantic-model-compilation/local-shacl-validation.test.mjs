import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { DataFactory, Parser, Store } from 'n3';

import {
  effectiveLocalShaclPythonSource,
  localShaclPythonSource,
  runLocalShaclValidation,
  validateLocalShaclRuntime,
} from './local-shacl-validation.mjs';

const roots = [];
const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url));
const { namedNode } = DataFactory;
const USF = 'urn:usf:ontology:';
const usf = (local) => namedNode(`${USF}${local}`);
const ACCEPTED = namedNode('urn:usf:decisionstate:accepted');
const PROVIDER_FORMATS = Object.freeze([
  'environmentvariableexample',
  'markdowncommonmark',
  'pythonsource311',
  'yamlconfiguration12',
]);
const PROVIDER_CONFIGURATION_FORMATS = Object.freeze([
  'environmentvariableexample',
  'markdowncommonmark',
  'pythonsource311',
  'sqltext',
  'yamlconfiguration12',
]);
const GRAPH_FORMATS = Object.freeze([
  'ecmascriptmodule2024',
  'graphqlschema',
  'javascriptmodule2024',
  'jsondata8259',
  'markdowncommonmark',
  'openapijson',
  'rdfdatasettrig11',
  'rdfgraphturtle11',
  'shellscriptposix',
  'sparqlquery11current',
  'sqltext',
  'yamlconfiguration12',
]);

function representationAuthorityStore() {
  const store = new Store();
  for (const [path, format] of [
    ['semantic-model/contracts/materialisation.trig', 'application/trig'],
    ['semantic-model/realisation/bindings.trig', 'application/trig'],
    ['semantic-model/shapes/materialisation.ttl', 'text/turtle'],
  ]) {
    store.addQuads(new Parser({ format }).parse(readFileSync(join(repositoryRoot, path), 'utf8')));
  }
  return store;
}

function decisionRepresentationRecord(store, decision) {
  const paths = store.getObjects(decision, usf('authorisesSourcePath'), null)
    .map(({ value }) => value).sort();
  const formats = store.getObjects(decision, usf('authorisesRepresentationFormat'), null)
    .map((format) => {
      const extensions = store.getObjects(format, usf('canonicalExtension'), null);
      return {
        extension: extensions.length === 1 ? extensions[0].value : null,
        id: format.value.replace('urn:usf:representationformat:', ''),
        valid: store.has(format, namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'), usf('RepresentationFormat'), null)
          && extensions.length === 1,
      };
    })
    .sort((left, right) => left.id.localeCompare(right.id));
  return {
    paths,
    formats,
    invalidFormats: formats.filter(({ valid }) => !valid).map(({ id }) => id),
  };
}

function uncoveredExactFiles(record) {
  return record.paths.filter(
    (path) => /\.[a-z0-9]+$/u.test(path)
      && !record.formats.some(({ extension }) => path.endsWith(extension)),
  );
}

function runtimeFixture() {
  const root = mkdtempSync(join(tmpdir(), 'local-shacl-runtime-'));
  const resolvedExecutablePath = join(root, 'python3.11');
  const executablePath = resolvedExecutablePath;
  writeFileSync(resolvedExecutablePath, '# deterministic local SHACL runtime fixture\n', { mode: 0o500 });
  const executableDigest = `sha256:${createHash('sha256').update(readFileSync(resolvedExecutablePath)).digest('hex')}`;
  roots.push(root);
  return { executablePath, resolvedExecutablePath, executableDigest };
}

test.after(() => roots.forEach((root) => rmSync(root, { recursive: true, force: true })));

test('accepts only an exact Python launcher, resolved executable and digest binding', () => {
  const runtime = runtimeFixture();
  assert.deepEqual(validateLocalShaclRuntime(runtime), runtime);
  assert.throws(() => validateLocalShaclRuntime(), /absolute launcher and resolved executable paths/);
  assert.throws(() => validateLocalShaclRuntime({ ...runtime, executableDigest: `sha256:${'0'.repeat(64)}` }), /digest mismatch/);
});

test('rejects a launcher whose resolved executable differs from its binding', () => {
  const runtime = runtimeFixture();
  const other = runtimeFixture();
  assert.throws(() => validateLocalShaclRuntime({
    ...runtime,
    resolvedExecutablePath: other.resolvedExecutablePath,
  }), /resolve to its declared executable/);
});

function pythonTuple(source, name) {
  const startMarker = `${name} = (\n`;
  const start = source.indexOf(startMarker);
  const end = source.indexOf('\n)\n', start + startMarker.length);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  return source.slice(start + startMarker.length, end);
}

function plantedFixtureSource() {
  const start = effectiveLocalShaclPythonSource.indexOf('def planted_fixture_evidence(');
  const end = effectiveLocalShaclPythonSource.indexOf('\ndef main():\n', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  return effectiveLocalShaclPythonSource.slice(start, end);
}

function assertPlantedFixtureContractBinding() {
  const source = plantedFixtureSource();
  const expectedCalls = source.match(/^\s+expected\(.+\)$/gmu) ?? [];
  const positiveCalls = expectedCalls.filter((line) => line.endsWith(', [])'));
  assert.equal(expectedCalls.length, 25);
  assert.equal(positiveCalls.length, 7);
  assert.equal(expectedCalls.length - positiveCalls.length, 18);
  for (const binding of [
    'USF.candidateFamilyMissingTermCount, Literal(missing_count, datatype=rdflib.XSD.integer)',
    'USF.candidateFamilyEmptyAxisCount, Literal(0, datatype=rdflib.XSD.integer)',
    'USF.reviewedRelationshipActiveOccurrenceCount, Literal(1, datatype=rdflib.XSD.integer)',
  ]) {
    assert.equal((source.match(new RegExp(binding.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'gu')) ?? []).length, 1);
  }
  assert.equal(source.includes('rdflib.XSD.nonNegativeInteger'), false);
  assert.equal(source.includes(
    '"contractConforms": missing_expected_count == 0 and unexpected_code_count == 0 and multiple_code_count == 0 and not unrecognised_results and not conforms,'
  ), true);
  assert.equal(source.includes(
    'raise RuntimeError("PLANTED_FIXTURE_CONTRACT_FAILED:" + canonical_json(core))'
  ), true);
  assert.equal((effectiveLocalShaclPythonSource.match(/planted_fixtures = planted_fixture_evidence/gu) ?? []).length, 1);
  assert.equal((effectiveLocalShaclPythonSource.match(/"plantedFixtureEvidence": planted_fixtures/gu) ?? []).length, 1);
}

function plantedFixtureTestMode(environment) {
  return environment.USF_LOCAL_SHACL_TEST_PYTHON
    ? 'EXECUTE_PINNED_RUNTIME'
    : 'VERIFY_EMBEDDED_CONTRACT';
}

test('effective focus policy closes structured permutation ownership in exact directions', () => {
  const rawForward = pythonTuple(localShaclPythonSource, 'FORWARD_PREDICATES');
  const forward = pythonTuple(effectiveLocalShaclPythonSource, 'FORWARD_PREDICATES');
  const inverse = pythonTuple(effectiveLocalShaclPythonSource, 'INVERSE_PREDICATES');
  const shared = [
    'familySubjectRegistration',
    'familyApplicabilityRule',
    'hasFamilyDimensionBinding',
    'bindsDimension',
    'dimensionValueSource',
    'valueSourceSelector',
    'valueSourceDerivationRoot',
    'valueDerivationOperand',
    'valueDerivationOperandExpression',
    'valueDerivationPathStep',
    'applicabilityRootClause',
    'applicabilityClauseOperand',
    'applicabilityOperandClause',
    'applicabilitySignalSelector',
    'selectorPathStep',
  ];
  for (const predicate of shared) {
    assert.equal(rawForward.includes(`"${predicate}"`), false, predicate);
    assert.equal((forward.match(new RegExp(`"${predicate}"`, 'gu')) ?? []).length, 1, predicate);
    assert.equal((inverse.match(new RegExp(`"${predicate}"`, 'gu')) ?? []).length, 1, predicate);
  }
  assert.equal(forward.includes('"familyOfUniverse"'), false,
    'one family focus must not expand through the universe to every family');
  assert.equal(inverse.includes('"familyOfUniverse"'), true,
    'a universe focus must discover each owned family');
  assert.equal(forward.includes('"universePublicationBudget"'), true);
  assert.equal(inverse.includes('"universePublicationBudget"'), true);
});

test('effective harness binds one in-memory planted-fixture contract with exact precedence codes', () => {
  assert.equal(localShaclPythonSource.includes('def planted_fixture_evidence('), false);
  assert.equal((effectiveLocalShaclPythonSource.match(/def planted_fixture_evidence\(/gu) ?? []).length, 1);
  assert.equal((effectiveLocalShaclPythonSource.match(/planted_fixtures = planted_fixture_evidence/gu) ?? []).length, 1);
  assert.equal((effectiveLocalShaclPythonSource.match(/"plantedFixtureEvidence": planted_fixtures/gu) ?? []).length, 1);
  for (const code of [
    'UNIVERSAL_REVIEW_TERM_ABSENT',
    'PERMUTATION_REVIEW_TERM_ALGORITHM_ABSENT',
    'PERMUTATION_REVIEW_TERM_SET_MISMATCH',
    'PERMUTATION_FAMILY_SIGNATURE_SUBJECT_ABSENT',
    'PERMUTATION_FAMILY_SIGNATURE_COMPONENT_MISMATCH',
    'UNIVERSAL_CANDIDATE_SUBJECT_ABSENT',
    'UNIVERSAL_CANDIDATE_KIND_ABSENT',
    'UNIVERSAL_CANDIDATE_ENDPOINT_MODE_INVALID',
    'UNIVERSAL_CANDIDATE_FORM_COMPONENT_CONFLICT',
    'UNIVERSAL_CANDIDATE_WARRANTED_WITH_GAPS',
    'UNIVERSAL_CANDIDATE_AUTHORISATION_PROHIBITED',
    'PERMUTATION_RELATIONSHIP_REVIEW_SIGNATURE_ABSENT',
    'PERMUTATION_RELATIONSHIP_REVIEW_AUTHORISATION_PROHIBITED',
  ]) {
    assert.equal(effectiveLocalShaclPythonSource.includes(code), true, code);
  }
  assert.equal(effectiveLocalShaclPythonSource.includes('"fixtureIsolation": "IN_MEMORY_UNPUBLISHED_CANDIDATE"'), true);
  assert.equal(effectiveLocalShaclPythonSource.includes('focus_nodes=focus_nodes'), true);
  assert.equal(effectiveLocalShaclPythonSource.includes('unexpectedCodeCount'), true);
  assert.equal(effectiveLocalShaclPythonSource.includes('multipleCodeCount'), true);
});

test('planted-fixture regression selects executable and child-process-free branches exactly', () => {
  assert.equal(plantedFixtureTestMode({}), 'VERIFY_EMBEDDED_CONTRACT');
  assert.equal(plantedFixtureTestMode({ USF_HERMETIC_TEST_MODE: '1' }), 'VERIFY_EMBEDDED_CONTRACT');
  assert.equal(plantedFixtureTestMode({
    USF_HERMETIC_TEST_MODE: '1',
    USF_LOCAL_SHACL_TEST_PYTHON: '/pinned/python',
  }), 'EXECUTE_PINNED_RUNTIME');
});

test('effective harness executes the planted-fixture contract against registered graph and shapes', {
  timeout: 600_000,
}, () => {
  assertPlantedFixtureContractBinding();
  if (plantedFixtureTestMode(process.env) === 'VERIFY_EMBEDDED_CONTRACT') return;
  const executablePath = process.env.USF_LOCAL_SHACL_TEST_PYTHON;
  const resolvedExecutablePath = realpathSync(executablePath);
  const executableDigest = `sha256:${createHash('sha256').update(readFileSync(resolvedExecutablePath)).digest('hex')}`;
  const evidence = JSON.parse(runLocalShaclValidation({
    repositoryRoot,
    runtime: { executablePath, resolvedExecutablePath, executableDigest },
    arguments: [
      '--expect-no-service',
      '--focus',
      'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation',
    ],
  }));
  assert.deepEqual({
    caseCount: evidence.plantedFixtureEvidence.caseCount,
    contractConforms: evidence.plantedFixtureEvidence.contractConforms,
    missingExpectedCount: evidence.plantedFixtureEvidence.missingExpectedCount,
    multipleCodeCount: evidence.plantedFixtureEvidence.multipleCodeCount,
    rawValidationConforms: evidence.plantedFixtureEvidence.rawValidationConforms,
    unexpectedCodeCount: evidence.plantedFixtureEvidence.unexpectedCodeCount,
    unrecognisedResultCount: evidence.plantedFixtureEvidence.unrecognisedResultCount,
  }, {
    caseCount: 25,
    contractConforms: true,
    missingExpectedCount: 0,
    multipleCodeCount: 0,
    rawValidationConforms: false,
    unexpectedCodeCount: 0,
    unrecognisedResultCount: 0,
  });
  assert.equal(evidence.plantedFixtureEvidenceDigest, evidence.plantedFixtureEvidence.evidenceDigest);
});

test('effective harness isolates optional review observations from authored semantic inputs', () => {
  assert.equal(localShaclPythonSource.includes('"reviewGraphs"'), false);
  assert.equal(effectiveLocalShaclPythonSource.includes(
    'for group in ("definitionGraphs", "authoredGraphs", "reviewGraphs", "derivedGraphs"):'
  ), true);
  assert.equal(effectiveLocalShaclPythonSource.includes(
    'if group in ("definitionGraphs", "authoredGraphs"):'
  ), true);
  assert.equal(effectiveLocalShaclPythonSource.includes(
    'if manifest.get("reviewGraphs", []):'
  ), true);
  assert.equal(effectiveLocalShaclPythonSource.includes('"AFFECTED_REVIEW_ENRICHED"'), true);
  assert.equal(effectiveLocalShaclPythonSource.includes(
    '"reviewEnrichedDataTripleCount": len(review_data)'
  ), true);
});

test('review and candidate authorisation guards use SHACL-SPARQL-compatible predicate filters', () => {
  const shapes = readFileSync(new URL('../../semantic-model/shapes/permutation.ttl', import.meta.url), 'utf8');
  assert.equal(shapes.includes('VALUES ?predicate { usf:establishesSemanticTruth'), false);
  assert.equal((shapes.match(/FILTER \(\?predicate IN \(usf:establishesSemanticTruth,/gu) ?? []).length, 5);
});

function publisherImplementationStore() {
  return new Store(new Parser({ format: 'application/trig' }).parse(
    readFileSync(join(repositoryRoot, 'semantic-model/assurance/proofs.trig'), 'utf8'),
  ));
}

function authoredPublisherImplementations(store) {
  return store.getSubjects(
    namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
    usf('PublisherImplementation'),
    null,
  );
}

// The live model requires canonicalName to equal the IRI's local segment. That rule lives in
// shapes.ttl and is only enforced at publication, where it surfaces as
// "V1_LIFECYCLE_FAILED: authored state failed SHACL validation" after the proof work has
// already run. Check it here for the identities this repository authors, so the mismatch is
// caught locally instead of at the end of a publication.
test('authored coordination identities name themselves after their IRI local segment', () => {
  const store = publisherImplementationStore();
  const rdfType = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const classes = [
    'PublisherImplementation', 'ClosureExecutorImplementation',
    'EvidenceAdmissionProducerIdentity',
  ];
  let checked = 0;
  for (const className of classes) {
    for (const subject of store.getSubjects(rdfType, usf(className), null)) {
      const names = store.getObjects(subject, usf('canonicalName'), null);
      assert.equal(names.length, 1, subject.value);
      assert.equal(names[0].value, subject.value.split(':').pop(),
        `${subject.value}: canonicalName must equal the IRI local segment`);
      checked += 1;
    }
  }
  assert.ok(checked >= 3, 'all three coordination identities must be authored');
});

// The Factory-side closure executor identity: src/** scope only, digests recomputed from the
// exact committed bytes, and never overlapping the publisher or proof-algorithm spaces.
test('every authored closure executor binds src paths and exact digests from committed bytes', () => {
  const store = publisherImplementationStore();
  const rdfType = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const executors = store.getSubjects(rdfType, usf('ClosureExecutorImplementation'), null);
  assert.ok(executors.length > 0, 'at least one closure executor must be authored');
  const stable = (value) => (Array.isArray(value)
    ? value.map(stable)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort(
        (l, r) => Buffer.compare(Buffer.from(l), Buffer.from(r)),
      ).map((k) => [k, stable(value[k])]))
      : value);
  const digestOf = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  for (const executor of executors) {
    const sole = (predicate) => {
      const values = store.getObjects(executor, usf(predicate), null);
      assert.equal(values.length, 1, `${executor.value} ${predicate}`);
      return values[0].value;
    };
    assert.equal(sole('closureExecutorRepository'), 'maldous/usf-factory');
    assert.match(sole('closureExecutorSourceCommit'), /^[0-9a-f]{40}$/u);
    assert.match(sole('closureExecutorSourceTree'), /^[0-9a-f]{40}$/u);
    const commandPath = sole('closureExecutorCommandPath');
    assert.match(commandPath, /^src\/usf_factory\/[A-Za-z0-9._/-]+$/u);
    const paths = store.getObjects(executor, usf('closureExecutorImplementationSourcePath'), null)
      .map(({ value }) => value);
    assert.ok(paths.length > 0, executor.value);
    for (const path of paths) assert.match(path, /^src\/usf_factory\/[A-Za-z0-9._/-]+$/u);
    assert.ok(paths.includes(commandPath),
      `${executor.value}: the command must be part of its own implementation set`);
    // The executor lives in the Factory repository, so its bytes are not in this tree; the
    // digests are shape-checked here and byte-verified by the publication reader against the
    // plan's exact Factory deployment.
    assert.match(sole('closureExecutorCommandDigest'), /^sha256:[0-9a-f]{64}$/u);
    assert.match(sole('closureExecutorImplementationSourceSetDigest'), /^sha256:[0-9a-f]{64}$/u);
    assert.equal(store.getQuads(executor, rdfType, usf('PublisherImplementation'), null).length, 0);
    assert.equal(store.getQuads(executor, rdfType, usf('ProofAlgorithm'), null).length, 0);
    assert.equal(store.getObjects(executor, usf('publisherSourcePath'), null).length, 0);
    assert.equal(store.getObjects(executor, usf('proofAlgorithmSourcePath'), null).length, 0);
    void stable; void digestOf;
  }
});

// The evidence-admission producer identity: its identity digest is recomputed from the exact
// committed bytes of the paths authority declares, and must never be the source scope digest.
test('every authored admission producer identity binds an exact implementation source set', () => {
  const store = publisherImplementationStore();
  const rdfType = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const identities = store.getSubjects(rdfType, usf('EvidenceAdmissionProducerIdentity'), null);
  assert.ok(identities.length > 0, 'at least one producer identity must be authored');
  const stable = (value) => (Array.isArray(value)
    ? value.map(stable)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort(
        (l, r) => Buffer.compare(Buffer.from(l), Buffer.from(r)),
      ).map((k) => [k, stable(value[k])]))
      : value);
  const digestOf = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  for (const identity of identities) {
    const sole = (predicate) => {
      const values = store.getObjects(identity, usf(predicate), null);
      assert.equal(values.length, 1, `${identity.value} ${predicate}`);
      return values[0].value;
    };
    assert.equal(sole('admissionProducerRepository'), 'maldous/usf-graph');
    assert.match(sole('admissionProducerValidationProducer'), /^urn:usf:validationproducer:/u);
    assert.match(sole('admissionProducerEvidenceAdmissionPath'),
      /^urn:usf:evidenceadmissionpath:/u);
    const scopeDigest = sole('admissionProducerSourceScopeDigest');
    const setDigest = sole('admissionProducerImplementationSourceSetDigest');
    assert.match(scopeDigest, /^sha256:[0-9a-f]{64}$/u);
    assert.notEqual(setDigest, scopeDigest,
      'a source scope digest is shared with other subjects and cannot be a producer identity');
    const records = store
      .getObjects(identity, usf('admissionProducerImplementationSourcePath'), null)
      .map(({ value }) => value)
      .sort((l, r) => Buffer.compare(Buffer.from(l), Buffer.from(r)))
      .map((path) => {
        const bytes = readFileSync(join(repositoryRoot, path));
        return { byteSize: bytes.length, digest: digestOf(bytes), path };
      });
    assert.ok(records.length > 0, identity.value);
    assert.equal(setDigest, digestOf(Buffer.from(JSON.stringify(stable(records)))),
      `${identity.value}: identity digest must be the exact committed byte set`);
  }
});

// (1) processes/** is the intended scope for a publisher implementation identity, and it is
// the ONLY scope: an assurance/** path here would mean the concept had drifted into the
// proof-algorithm space it deliberately does not occupy.
test('every authored publisher implementation uses a processes path for its command and its source set', () => {
  const store = publisherImplementationStore();
  const publishers = authoredPublisherImplementations(store);
  assert.ok(publishers.length > 0, 'at least one publisher implementation must be authored');
  for (const publisher of publishers) {
    const sourcePaths = store.getObjects(publisher, usf('publisherSourcePath'), null);
    assert.equal(sourcePaths.length, 1, publisher.value);
    assert.match(sourcePaths[0].value, /^processes\/[A-Za-z0-9._/-]+$/u, publisher.value);
    const implementationPaths = store.getObjects(
      publisher, usf('publisherImplementationSourcePath'), null,
    );
    assert.ok(implementationPaths.length > 0, publisher.value);
    for (const path of implementationPaths) {
      assert.match(path.value, /^processes\/[A-Za-z0-9._/-]+$/u, `${publisher.value} ${path.value}`);
    }
    assert.ok(
      implementationPaths.some((path) => path.value === sourcePaths[0].value),
      `${publisher.value}: the command module must be part of its own implementation set`,
    );
  }
});

// (2) The source path, command digest and implementation source set digest are mandatory and
// EXACT: each is recomputed here from the committed bytes, in the same framing the model uses
// for every implementation source set digest, so a stale or invented digest cannot survive.
test('every authored publisher implementation binds exact command and implementation set digests', () => {
  const store = publisherImplementationStore();
  const publishers = authoredPublisherImplementations(store);
  assert.ok(publishers.length > 0);
  const stable = (value) => (Array.isArray(value)
    ? value.map(stable)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort(
        (left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)),
      ).map((key) => [key, stable(value[key])]))
      : value);
  const digestOf = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  for (const publisher of publishers) {
    const sourcePath = store.getObjects(publisher, usf('publisherSourcePath'), null)[0].value;
    const commandDigests = store.getObjects(publisher, usf('publisherCommandDigest'), null);
    assert.equal(commandDigests.length, 1, publisher.value);
    assert.equal(
      commandDigests[0].value,
      digestOf(readFileSync(join(repositoryRoot, sourcePath))),
      `${publisher.value}: command digest must be the exact committed bytes`,
    );
    const setDigests = store.getObjects(
      publisher, usf('publisherImplementationSourceSetDigest'), null,
    );
    assert.equal(setDigests.length, 1, publisher.value);
    const records = store.getObjects(publisher, usf('publisherImplementationSourcePath'), null)
      .map((path) => path.value)
      .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      .map((path) => {
        const bytes = readFileSync(join(repositoryRoot, path));
        return { byteSize: bytes.length, digest: digestOf(bytes), path };
      });
    assert.equal(
      setDigests[0].value,
      digestOf(Buffer.from(JSON.stringify(stable(records)))),
      `${publisher.value}: implementation set digest must be the exact committed byte set`,
    );
  }
});

// (3) ProofAlgorithm remains assurance/**-only. The publisher concept exists precisely so
// that constraint did not have to be widened, so no subject may hold both types and no
// publisher may appear in the proof-algorithm space.
test('publisher implementations never occupy the assurance-only proof algorithm space', () => {
  const store = publisherImplementationStore();
  const rdfType = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const publishers = authoredPublisherImplementations(store);
  for (const publisher of publishers) {
    assert.equal(
      store.getQuads(publisher, rdfType, usf('ProofAlgorithm'), null).length,
      0,
      `${publisher.value}: must not also be a proof algorithm`,
    );
    assert.equal(
      store.getObjects(publisher, usf('proofAlgorithmSourcePath'), null).length,
      0,
      `${publisher.value}: must not carry a proof algorithm source path`,
    );
  }
  const shapes = readFileSync(
    join(repositoryRoot, 'semantic-model/shapes/assurance.ttl'), 'utf8',
  );
  assert.match(shapes, /sh:targetClass usf:PublisherImplementation;\n\s+sh:closed true;/u,
    'the publisher implementation shape must stay closed');
  const validation = readFileSync(
    join(repositoryRoot, 'assurance/semantic-model-compilation/local-shacl-validation.test.mjs'),
    'utf8',
  );
  assert.match(validation, /\/\^assurance\\\/\[A-Za-z0-9\._\/-\]\+\$\/u/u,
    'the assurance-only proof algorithm path rule must remain in force');
});

test('every authored proof algorithm uses a Graph assurance path and exact current source digest', () => {
  const store = new Store(new Parser({ format: 'application/trig' }).parse(
    readFileSync(join(repositoryRoot, 'semantic-model/assurance/proofs.trig'), 'utf8'),
  ));
  const proofAlgorithm = usf('ProofAlgorithm');
  const rdfType = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const algorithms = store.getSubjects(rdfType, proofAlgorithm, null);
  assert.ok(algorithms.length > 0);
  for (const algorithm of algorithms) {
    const paths = store.getObjects(algorithm, usf('proofAlgorithmSourcePath'), null);
    assert.equal(paths.length, 1, algorithm.value);
    assert.match(paths[0].value, /^assurance\/[A-Za-z0-9._/-]+$/u, algorithm.value);
    const currentDigests = store.getObjects(algorithm, usf('currentAlgorithmSourceDigest'), null);
    if (!currentDigests.length) continue;
    assert.equal(currentDigests.length, 1, algorithm.value);
    const observed = `sha256:${createHash('sha256')
      .update(readFileSync(join(repositoryRoot, paths[0].value))).digest('hex')}`;
    assert.equal(currentDigests[0].value, observed, algorithm.value);
  }
});

test('every accepted mutable-source decision carries applicable representation authority', () => {
  const store = representationAuthorityStore();
  const decisions = [...new Set(
    store.getSubjects(usf('authorisesSourcePath'), null, null)
      .filter((decision) => store.has(decision, usf('decisionState'), ACCEPTED, null))
      .map(({ value }) => value),
  )].sort();
  assert.equal(decisions.length, 7);
  for (const value of decisions) {
    const record = decisionRepresentationRecord(store, namedNode(value));
    assert.ok(record.paths.length > 0, value);
    assert.ok(record.formats.length > 0, value);
    assert.deepEqual(record.invalidFormats, [], value);
    assert.deepEqual(uncoveredExactFiles(record), [], value);
  }
});

test('provider and graph decisions retain their exact bounded format sets', () => {
  const store = representationAuthorityStore();
  const decision = (name) => decisionRepresentationRecord(
    store,
    namedNode(`urn:usf:realisationdecision:${name}`),
  );
  for (const [name, expectedFormats] of [
    ['providerconfigurationplanefactoryworkforce', PROVIDER_CONFIGURATION_FORMATS],
    ['providerenvironmentclassificationfactoryworkforce', PROVIDER_FORMATS],
    ['servicecatalogandproviderintegrationmodelfactoryworkforce', PROVIDER_FORMATS],
  ]) {
    const record = decision(name);
    assert.deepEqual(record.formats.map(({ id }) => id), expectedFormats, name);
    assert.ok(record.paths.includes('src/usf_factory/providers'), name);
    assert.ok(record.paths.includes('.env.example'), name);
    for (const removed of expectedFormats) {
      assert.notDeepEqual(
        record.formats.filter(({ id }) => id !== removed).map(({ id }) => id),
        expectedFormats,
        `${name}:${removed}`,
      );
    }
  }
  for (const name of [
    'repositoryarchitectureandnaming',
    'semanticauthoritycontrolselection',
    'semanticmodelcompilationrealisation',
  ]) {
    const record = decision(name);
    assert.deepEqual(record.formats.map(({ id }) => id), GRAPH_FORMATS, name);
    for (const removed of GRAPH_FORMATS) {
      assert.notDeepEqual(
        record.formats.filter(({ id }) => id !== removed).map(({ id }) => id),
        GRAPH_FORMATS,
        `${name}:${removed}`,
      );
    }
  }
});

test('exact suffix omissions and invalid format identities fail the applicability rule', () => {
  const store = representationAuthorityStore();
  const providerDecision = namedNode(
    'urn:usf:realisationdecision:providerconfigurationplanefactoryworkforce',
  );
  const provider = decisionRepresentationRecord(store, providerDecision);
  for (const [format, path] of [
    ['pythonsource311', 'src/usf_factory/engine.py'],
    ['environmentvariableexample', '.env.example'],
    ['markdowncommonmark', 'docs/security.md'],
    ['yamlconfiguration12', 'config/providers.yaml'],
  ]) {
    const reduced = {
      ...provider,
      formats: provider.formats.filter(({ id }) => id !== format),
    };
    assert.ok(uncoveredExactFiles(reduced).includes(path), `${format}:${path}`);
  }
  assert.deepEqual(uncoveredExactFiles({ ...provider, formats: [] }), provider.paths.filter(
    (path) => /\.[a-z0-9]+$/u.test(path),
  ));

  const invalidStore = new Store(store.getQuads(null, null, null, null));
  invalidStore.addQuad(
    providerDecision,
    usf('authorisesRepresentationFormat'),
    namedNode('urn:usf:representationformat:undeclaredbogus'),
  );
  const ambiguous = namedNode('urn:usf:representationformat:ambiguousformat');
  invalidStore.addQuad(providerDecision, usf('authorisesRepresentationFormat'), ambiguous);
  invalidStore.addQuad(
    ambiguous,
    namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
    usf('RepresentationFormat'),
  );
  invalidStore.addQuad(ambiguous, usf('canonicalExtension'), DataFactory.literal('.one'));
  invalidStore.addQuad(ambiguous, usf('canonicalExtension'), DataFactory.literal('.two'));
  assert.deepEqual(
    decisionRepresentationRecord(invalidStore, providerDecision).invalidFormats,
    ['ambiguousformat', 'undeclaredbogus'],
  );
});

test('repository architecture decision covers every globally tracked representation edition', () => {
  const store = representationAuthorityStore();
  const architecture = decisionRepresentationRecord(
    store,
    namedNode('urn:usf:realisationdecision:repositoryarchitectureandnaming'),
  );
  const tracked = new Set();
  for (const { subject: rule } of store.getQuads(null, usf('trackedRepresentation'), DataFactory.literal(true), null)) {
    for (const { object: format } of store.getQuads(rule, usf('usesRepresentationFormat'), null, null)) {
      tracked.add(format.value.replace('urn:usf:representationformat:', ''));
    }
  }
  assert.deepEqual([...tracked].sort(), GRAPH_FORMATS);
  assert.deepEqual(architecture.formats.map(({ id }) => id), [...tracked].sort());
});
