// GOAL.md §15-16: structural assertions over the finite permutation-family
// meta-model instances in semantic-model/permutation/families.trig. Loads the
// TriG with n3 and checks it against the authoritative 34-family census.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import N3 from 'n3';
import { censusFamilies } from './family-census.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');
const TRIG = resolve(REPO, 'semantic-model', 'permutation', 'families.trig');
const AUTHORITY_DIGEST = 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd';

const O = 'urn:usf:ontology:';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const keyOf = (part) => part.trim().toLowerCase().replace(/[^a-z0-9]/g, '');

const quads = new N3.Parser({ format: 'application/trig' }).parse(readFileSync(TRIG, 'utf8'));

const inGraph = quads.every((q) => q.graph.value === 'urn:usf:graph:permutation-families');
const subjectsOfType = (cls) => quads
  .filter((q) => q.predicate.value === RDF_TYPE && q.object.value === O + cls)
  .map((q) => q.subject.value);
const objectsOf = (subject, predicate) => quads
  .filter((q) => q.subject.value === subject && q.predicate.value === O + predicate)
  .map((q) => q.object);
const oneLiteral = (subject, predicate) => {
  const found = objectsOf(subject, predicate);
  assert.equal(found.length, 1, `expected exactly one ${predicate} on ${subject}`);
  return found[0].value;
};

test('every quad lives in the permutation-families named graph', () => {
  assert.ok(inGraph, 'all quads must be in <urn:usf:graph:permutation-families>');
});

test('no duplicate typed IRIs', () => {
  for (const cls of ['PermutationUniverse', 'PermutationFamily', 'PermutationFamilyDimensionBinding',
    'PermutationDimension', 'DimensionValueSource', 'PermutationDimensionValue']) {
    const iris = subjectsOfType(cls);
    assert.equal(new Set(iris).size, iris.length, `duplicate ${cls} IRI`);
  }
});

test('exactly one universe carrying the exact authority digest', () => {
  const universes = subjectsOfType('PermutationUniverse');
  assert.deepEqual(universes, ['urn:usf:permutationuniverse:closure']);
  assert.equal(oneLiteral(universes[0], 'canonicalName'), 'closure');
  assert.equal(oneLiteral(universes[0], 'universeAuthorityDigest'), AUTHORITY_DIGEST);
});

test('exactly 34 permutation families', () => {
  assert.equal(subjectsOfType('PermutationFamily').length, 34);
  assert.equal(censusFamilies.length, 34);
});

test('each family binds its census dimensions with matching keys and positions', () => {
  for (const family of censusFamilies) {
    const iri = `urn:usf:permutationfamily:${family.canonicalName}`;
    assert.ok(subjectsOfType('PermutationFamily').includes(iri), `missing family ${iri}`);
    assert.equal(oneLiteral(iri, 'definition'), family.title);
    assert.equal(oneLiteral(iri, 'familySubjectKind'), 'capability');
    assert.equal(oneLiteral(iri, 'familyStableKeyAlgorithm'), 'sorted-dimension-key-join-v1');
    assert.equal(oneLiteral(iri, 'familyGenerationAlgorithm'), 'assurance/permutation-closure/universe-generator.mjs');
    assert.equal(oneLiteral(iri, 'familyPartitionRule'), 'by-family-and-capability');
    assert.deepEqual(
      objectsOf(iri, 'familyClosureRequirement').map((t) => t.value).sort(),
      ['deferred-requires-authority', 'unresolved=0'],
    );

    const expectedKeys = family.orderedDimensions.map(keyOf);
    const bindings = objectsOf(iri, 'hasFamilyDimensionBinding').map((t) => t.value);
    assert.equal(bindings.length, expectedKeys.length, `binding count for ${family.canonicalName}`);

    const observed = bindings.map((binding) => {
      const position = Number(oneLiteral(binding, 'dimensionPosition'));
      const dimension = objectsOf(binding, 'bindsDimension');
      assert.equal(dimension.length, 1, `one bindsDimension on ${binding}`);
      assert.equal(oneLiteral(binding, 'dimensionConditionallyActive'), 'false');
      const dimKey = oneLiteral(dimension[0].value, 'permutationDimensionKey');
      return { position, dimKey, binding };
    }).sort((a, b) => a.position - b.position);

    assert.deepEqual(observed.map((o) => o.position), expectedKeys.map((_, i) => i + 1),
      `1-based contiguous positions for ${family.canonicalName}`);
    assert.deepEqual(observed.map((o) => o.dimKey), expectedKeys,
      `ordered dimension keys for ${family.canonicalName}`);
    observed.forEach((o, i) => {
      assert.equal(o.binding, `urn:usf:permutationfamilydimensionbinding:${family.canonicalName}-${i + 1}-${expectedKeys[i]}`,
        `binding IRI shape for ${family.canonicalName} position ${i + 1}`);
    });
  }
});

test('every bound dimension exists with exactly one value source', () => {
  const dimensions = new Set(subjectsOfType('PermutationDimension'));
  const sources = new Set(subjectsOfType('DimensionValueSource'));
  const boundDimensions = new Set(
    subjectsOfType('PermutationFamilyDimensionBinding')
      .flatMap((binding) => objectsOf(binding, 'bindsDimension').map((t) => t.value)),
  );
  assert.ok(boundDimensions.size > 0);
  for (const dimension of boundDimensions) {
    assert.ok(dimensions.has(dimension), `dimension ${dimension} not declared`);
    const source = objectsOf(dimension, 'dimensionValueSource');
    assert.equal(source.length, 1, `exactly one value source on ${dimension}`);
    assert.ok(sources.has(source[0].value), `value source ${source[0].value} not declared`);
    const kind = oneLiteral(source[0].value, 'valueSourceKind');
    assert.ok(['classinstances', 'controlledlist', 'derivedselector'].includes(kind),
      `value source kind ${kind}`);
    if (kind === 'classinstances') {
      assert.equal(objectsOf(source[0].value, 'valueSourceClassIri').length, 1,
        `classinstances source ${source[0].value} needs a class IRI`);
    }
  }
});

test('every controlledlist dimension enumerates >=2 values; delegationmode/legalholdstate exactly 2', () => {
  const controlled = subjectsOfType('DimensionValueSource')
    .filter((source) => oneLiteral(source, 'valueSourceKind') === 'controlledlist');
  assert.ok(controlled.length > 0);
  for (const source of controlled) {
    const key = oneLiteral(source, 'canonicalName');
    const dimension = `urn:usf:permutationdimension:closure${key}`;
    const values = objectsOf(dimension, 'hasDimensionValue').map((t) => t.value);
    assert.ok(values.length >= 2, `controlledlist ${key} needs >=2 values, has ${values.length}`);
    for (const value of values) {
      assert.equal(subjectsOfType('PermutationDimensionValue').includes(value), true,
        `value ${value} must be a PermutationDimensionValue`);
      assert.equal(objectsOf(value, 'dimensionValueKey').length, 1, `one value key on ${value}`);
    }
    if (key === 'delegationmode' || key === 'legalholdstate') {
      assert.equal(values.length, 2, `${key} must have exactly 2 values`);
    }
  }
});
