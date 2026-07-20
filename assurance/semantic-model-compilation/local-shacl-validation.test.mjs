import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  effectiveLocalShaclPythonSource,
  localShaclPythonSource,
  validateLocalShaclRuntime,
} from './local-shacl-validation.mjs';

const roots = [];

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
    'UNIVERSAL_CANDIDATE_WARRANTED_WITH_GAPS',
    'UNIVERSAL_CANDIDATE_AUTHORISATION_PROHIBITED',
  ]) {
    assert.equal(effectiveLocalShaclPythonSource.includes(code), true, code);
  }
  assert.equal(effectiveLocalShaclPythonSource.includes('"fixtureIsolation": "IN_MEMORY_UNPUBLISHED_CANDIDATE"'), true);
  assert.equal(effectiveLocalShaclPythonSource.includes('focus_nodes=focus_nodes'), true);
  assert.equal(effectiveLocalShaclPythonSource.includes('unexpectedCodeCount'), true);
  assert.equal(effectiveLocalShaclPythonSource.includes('multipleCodeCount'), true);
});

test('review and candidate authorisation guards use SHACL-SPARQL-compatible predicate filters', () => {
  const shapes = readFileSync(new URL('../../semantic-model/shapes/permutation.ttl', import.meta.url), 'utf8');
  assert.equal(shapes.includes('VALUES ?predicate { usf:establishesSemanticTruth'), false);
  assert.equal((shapes.match(/FILTER \(\?predicate IN \(usf:establishesSemanticTruth,/gu) ?? []).length, 4);
});
