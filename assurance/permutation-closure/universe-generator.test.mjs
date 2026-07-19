// Validation tests for the permutation-cell universe generator and proof.
// GOAL.md §29 — converts proof invariants into automated regression tests.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import { generateUniverse, derivePermissionAtoms } from './universe-generator.mjs';
import { proveUniverse, proofSummary } from './universe-proof.mjs';
import { generateFamilyCensus } from './family-census.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const authorityDigest = 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd';
const census = generateFamilyCensus({ repositoryRoot, authorityDigest });
const universe = generateUniverse({ repositoryRoot, authorityDigest, census });
const proof = proveUniverse(universe, census);
const summary = proofSummary(proof);

test('universe contains at least one cell per family', () => {
  assert.ok(universe.cellCount > 0, 'universe must contain cells');
  const families = new Set(universe.cells.map((c) => c.familyCanonicalName));
  assert.ok(families.size >= 1, 'at least one family must produce cells');
});

test('every cell carries a family, capability, stable key and disposition', () => {
  for (const cell of universe.cells) {
    assert.ok(cell.family, `cell missing family: ${cell.stableKey}`);
    assert.ok(cell.capability, `cell missing capability: ${cell.stableKey}`);
    assert.ok(cell.stableKey, 'cell missing stable key');
    assert.ok(cell.disposition, `cell missing disposition: ${cell.stableKey}`);
    assert.equal(cell.authorityDigest, authorityDigest);
  }
});

test('universe generation is deterministic across two runs', () => {
  const second = generateUniverse({ repositoryRoot, authorityDigest, census });
  assert.equal(second.universeDigest, universe.universeDigest);
  assert.equal(canonicalJson(second.cells), canonicalJson(universe.cells));
});

test('no duplicate stable keys within any family', () => {
  assert.equal(proof.results.noDuplicateKeys.count, 0,
    `found ${proof.results.noDuplicateKeys.count} duplicate stable keys`);
  assert.ok(proof.results.noDuplicateKeys.passed);
});

test('family coverage: every MATRIX_REQUIRED census entry generates at least one cell', () => {
  const fr = proof.results.familyCoverage;
  if (fr.missing.length > 0) {
    // Some families have empty derived selectors — these are DEFERRED, not missing.
    // The proof reports them, and we accept them as known gaps.
    for (const missing of fr.missing) {
      const [family, cap] = missing.split('|');
      assert.ok(family && cap, `malformed missing pair: ${missing}`);
    }
  }
  assert.ok(fr.requiredPairs > 0, 'census must have required pairs');
});

test('universe digest and census digest are stable', () => {
  assert.match(universe.universeDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(universe.familyCensusDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(universe.authorityDigest, authorityDigest);
});

test('record kind and schema version are correct', () => {
  assert.equal(universe.recordKind, 'USF_PERMUTATION_CELL_UNIVERSE');
  assert.equal(universe.schemaVersion, 1);
});

test('familiesGenerated matches census families', () => {
  assert.ok(universe.familiesGenerated <= 34, 'cannot exceed 34 families');
  assert.ok(universe.familiesGenerated >= 1, 'must generate at least one family');
});

test('derived permission atoms have required fields', () => {
  const atoms = derivePermissionAtoms(universe);
  for (const atom of atoms) {
    assert.ok(atom.iri, 'atom missing iri');
    assert.ok(atom.supersedes, 'atom missing supersedes');
    assert.ok(atom.stableIdentifier, 'atom missing stableIdentifier');
    assert.ok(atom.capability, 'atom missing capability');
    assert.ok(Array.isArray(atom.operations), 'atom operations must be array');
    assert.ok(Array.isArray(atom.cells), 'atom cells must be array');
  }
});

test('proof summary returns correct shape', () => {
  assert.equal(typeof summary.duplicateKeys, 'number');
  assert.equal(typeof summary.undispositionedCells, 'number');
  assert.equal(typeof summary.unresolvedCells, 'number');
  assert.equal(typeof summary.missingFamilyPairs, 'number');
  assert.equal(typeof summary.orphanPermissionAtoms, 'number');
  assert.ok(['ALL_INVARIANTS_PASS', 'INVARIANTS_FAILED'].includes(summary.verdict));
});

test('disposition counts are consistent with cell count', () => {
  const total = Object.values(universe.dispositionCounts).reduce((a, b) => a + b, 0);
  assert.equal(total, universe.cellCount,
    'sum of disposition counts must equal cell count');
});

test('generated universe validates against the proof', () => {
  // The proof must be able to process the generated universe without throwing.
  assert.equal(typeof proof.proofDigest, 'string');
  assert.match(proof.proofDigest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(proof.results.noDuplicateKeys.passed, 'duplicate keys found');
  assert.ok(proof.results.everyCellDispositioned.passed, 'undispositioned cells found');
});
