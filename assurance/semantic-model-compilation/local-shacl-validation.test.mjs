import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  effectiveLocalShaclPythonSource,
  localShaclPythonSource,
  runLocalShaclValidation,
  validateLocalShaclRuntime,
} from './local-shacl-validation.mjs';

const roots = [];
const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url));

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
