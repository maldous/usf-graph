// GOAL.md §15-16: structural assertions over the finite permutation-family
// meta-model instances in semantic-model/permutation/families.trig. Loads the
// TriG with n3 and checks it against the semantic family registry.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import N3 from 'n3';
import {
  FAMILY_PLANES,
  loadPermutationFamilyRegistry,
  selectorCanonicalRecord,
} from './family-registry.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');
const TRIG = resolve(REPO, 'semantic-model', 'permutation', 'families.trig');
const VOCABULARY = resolve(REPO, 'semantic-model', 'permutation', 'closure-vocabulary.trig');
const ONTOLOGY = resolve(REPO, 'semantic-model', 'ontology.ttl');
const O = 'urn:usf:ontology:';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const digest = (value) => `sha256:${createHash('sha256').update(JSON.stringify(stable(value))).digest('hex')}`;

const quads = new N3.Parser({ format: 'application/trig' }).parse(readFileSync(TRIG, 'utf8'));
const vocabularyQuads = new N3.Parser({ format: 'application/trig' })
  .parse(readFileSync(VOCABULARY, 'utf8'));
const allQuads = [...quads, ...vocabularyQuads];
const familyRegistry = loadPermutationFamilyRegistry({ repositoryRoot: REPO });
const censusFamilies = familyRegistry.families;

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
const allSubjectsOfType = (cls) => allQuads
  .filter((q) => q.predicate.value === RDF_TYPE && q.object.value === O + cls)
  .map((q) => q.subject.value);
const allObjectsOf = (subject, predicate) => allQuads
  .filter((q) => q.subject.value === subject && q.predicate.value === O + predicate)
  .map((q) => q.object);

function withRegistryMutation(transform, callback) {
  const root = mkdtempSync(join(tmpdir(), 'usf-family-registry-'));
  try {
    const target = join(root, 'semantic-model', 'permutation');
    mkdirSync(target, { recursive: true });
    writeFileSync(join(root, 'semantic-model', 'ontology.ttl'), readFileSync(ONTOLOGY));
    writeFileSync(join(target, 'closure-vocabulary.trig'), readFileSync(VOCABULARY));
    writeFileSync(join(target, 'families.trig'), transform(readFileSync(TRIG, 'utf8')));
    return callback(root);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

const expectRegistryCode = (transform, code) => withRegistryMutation(transform, (root) => {
  assert.throws(
    () => loadPermutationFamilyRegistry({ repositoryRoot: root, verifyStoredDigests: false }),
    (error) => error?.code === code,
  );
});

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

test('exactly one authority-neutral universe definition', () => {
  const universes = subjectsOfType('PermutationUniverse');
  assert.deepEqual(universes, ['urn:usf:permutationuniverse:closure']);
  assert.equal(oneLiteral(universes[0], 'canonicalName'), 'closure');
  assert.deepEqual(objectsOf(universes[0], 'universeAuthorityDigest'), [],
    'the live authority digest belongs in generated provenance, not authored meta-model identity');
});

test('universe selects sparse symbolic closure and one fail-closed provider budget', () => {
  const universe = 'urn:usf:permutationuniverse:closure';
  assert.deepEqual(objectsOf(universe, 'universeClosureRepresentation').map(({ value }) => value),
    ['urn:usf:permutationclosurerepresentation:sparsesymbolic']);
  const policyIri = 'urn:usf:permutationpublicationbudget:stardogcloudfreeauthoritycapacity';
  assert.deepEqual(objectsOf(universe, 'universePublicationBudget').map(({ value }) => value), [policyIri]);
  const policy = {
    encodingPolicy: {
      fixedManifestTripleUpperBound: Number(oneLiteral(policyIri, 'publicationFixedManifestStatementUpperBound')),
      operationalCellTripleUpperBound: Number(oneLiteral(policyIri, 'publicationOperationalCellStatementUpperBound')),
      regionTripleUpperBound: Number(oneLiteral(policyIri, 'publicationCoverageRegionStatementUpperBound')),
    },
    failClosed: oneLiteral(policyIri, 'publicationBudgetFailClosed') === 'true',
    hardStatementLimit: Number(oneLiteral(policyIri, 'publicationHardStatementLimit')),
    maximumProjectedStatementCount: Number(oneLiteral(policyIri, 'publicationMaximumProjectedStatementCount')),
    policyIri,
    provider: oneLiteral(policyIri, 'publicationBudgetForProvider'),
    reserveStatementCount: Number(oneLiteral(policyIri, 'publicationReservedStatementCount')),
  };
  assert.equal(policy.hardStatementLimit, 1_000_000);
  assert.equal(policy.maximumProjectedStatementCount, 800_000);
  assert.equal(policy.reserveStatementCount, 200_000);
  assert.equal(policy.failClosed, true);
  assert.equal(oneLiteral(policyIri, 'publicationBudgetDigest'), digest(policy));
});

test('symbolic coverage rules are exact, authority-backed and digest-bound', () => {
  const rules = subjectsOfType('PermutationCoverageRule').sort();
  assert.deepEqual(rules, [
    'urn:usf:permutationcoveragerule:coordinatoronlyroleforbidden',
    'urn:usf:permutationcoveragerule:operationdoesnotrequirepermission',
  ]);
  for (const rule of rules) {
    const record = {
      disposition: objectsOf(rule, 'coverageRuleDisposition')[0].value,
      families: objectsOf(rule, 'coverageRuleForFamily').map(({ value }) => value).sort(),
      predicate: oneLiteral(rule, 'coverageRuleAuthorityPredicate'),
      reasonCode: oneLiteral(rule, 'coverageRuleReasonCode'),
      ruleKind: oneLiteral(rule, 'coverageRuleKind'),
      testedDimensionKey: oneLiteral(rule, 'coverageRuleTestedDimensionKey'),
    };
    assert.ok(record.families.length > 0);
    assert.equal(oneLiteral(rule, 'coverageRuleDigest'), digest(record));
    assert.ok(['urn:usf:ontology:requiresPermission', 'urn:usf:ontology:coordinatorOnly'].includes(record.predicate));
  }
});

test('the census and semantic registry expose the same exact permutation-family set', () => {
  assert.deepEqual(censusFamilies.map(({ iri }) => iri).sort(), subjectsOfType('PermutationFamily').sort());
  assert.ok(censusFamilies.length > 0);
});

test('structured registry digests and runtime-assurance planes close independently', () => {
  assert.equal(familyRegistry.selectors.size, subjectsOfType('PermutationSignalSelector').length);
  assert.equal(familyRegistry.rules.size, subjectsOfType('PermutationApplicabilityRule').length);
  assert.equal(familyRegistry.registryDigest, digest(familyRegistry.registryRecord));
  assert.equal(familyRegistry.registryRecord.schemaVersion, 4);
  for (const family of familyRegistry.families) {
    const authoredBindingIris = objectsOf(family.iri, 'hasFamilyDimensionBinding')
      .map(({ value }) => value).sort();
    assert.deepEqual(family.bindings.map(({ bindingIri }) => bindingIri).sort(), authoredBindingIris,
      `${family.iri} must preserve exact authored dimension-binding identities`);
    assert.equal(new Set(family.bindings.map(({ bindingIri }) => bindingIri)).size, family.bindings.length);
  }
  const dimensionMutation = structuredClone(familyRegistry.registryRecord);
  dimensionMutation.families[0].dimensions[0].dimensionIri += ':mutation';
  assert.notEqual(digest(dimensionMutation), familyRegistry.registryDigest,
    'registry digest must bind every ordered family dimension');
  const bindingIdentityMutation = structuredClone(familyRegistry.registryRecord);
  bindingIdentityMutation.families[0].dimensions[0].bindingIri += ':mutation';
  assert.notEqual(digest(bindingIdentityMutation), familyRegistry.registryDigest,
    'registry digest must bind every authored dimension-binding identity');
  const assuranceFamilies = censusFamilies
    .filter(({ planeIri }) => planeIri === FAMILY_PLANES.assurance)
    .map(({ iri }) => iri);
  assert.deepEqual(assuranceFamilies, [
    'urn:usf:permutationfamily:actionreachabilitycapabilityoperationstate',
    'urn:usf:permutationfamily:actionreachabilityconditionprofile',
    'urn:usf:permutationfamily:actionreachabilitypermissionatom',
    'urn:usf:permutationfamily:actionreachabilityprincipalkind',
    'urn:usf:permutationfamily:actionreachabilityrole',
    'urn:usf:permutationfamily:bindingoptioncomponentproviderportprovidermodeenvironmentbindingstate',
    'urn:usf:permutationfamily:candidatecredibilityassessmentevaluationoptionstate',
    'urn:usf:permutationfamily:candidatesearchspacerealisationclass',
    'urn:usf:permutationfamily:capabilitypositivepermutationcell',
    'urn:usf:permutationfamily:capabilityprovidermodeproofrungenvironmentclass',
    'urn:usf:permutationfamily:compatibilitycontractsourceversiontargetversionstate',
    'urn:usf:permutationfamily:componentresponsibilitycomponentrequirementowner',
    'urn:usf:permutationfamily:composedrealisationoptioncomponentresponsibilityinterfaceenvironmentbinding',
    'urn:usf:permutationfamily:criterionassessmentevaluationoptioncriterionresult',
    'urn:usf:permutationfamily:criterionrequirementevaluationcriterionapplicability',
    'urn:usf:permutationfamily:decisionevaluationclosurestate',
    'urn:usf:permutationfamily:evidencerequirementprovidermodeenvironmentclassstage',
    'urn:usf:permutationfamily:evidenceresultadmissionfreshnessintegrity',
    'urn:usf:permutationfamily:evidencescopemanifestclassificationprovideridentity',
    'urn:usf:permutationfamily:foundationactionreachabilitywitnesscapabilityroleoperationpermissionstate',
    'urn:usf:permutationfamily:foundationrequiredpermutationwitnesssubjectfamilydispositionassurance',
    'urn:usf:permutationfamily:observabilitysignalauditeventcorrelation',
    'urn:usf:permutationfamily:optioncomponentdependencysharedinterface',
    'urn:usf:permutationfamily:optioncomponentidentityrole',
    'urn:usf:permutationfamily:proofobligationrungevidencerequirement',
    'urn:usf:permutationfamily:proofresultstateconfidenceobligation',
    'urn:usf:permutationfamily:readinessgateresultstatereason',
    'urn:usf:permutationfamily:readinessgatetargetkind',
    'urn:usf:permutationfamily:realisationoptionrealisationclass',
    'urn:usf:permutationfamily:rejectionreasonoptionrejectionevaluationoptioncriterionduration',
    'urn:usf:permutationfamily:selectedcomponentadaptermappingoptioncomponenttargetkindadapterstate',
    'urn:usf:permutationfamily:selectedcomponentdependencybindingmappingoptioncomponenttargetkindbindingstate',
    'urn:usf:permutationfamily:selectedcomponentimplementationmappingoptioncomponenttargetkindimplementationstate',
    'urn:usf:permutationfamily:selectedcomponentproviderbindingmappingoptioncomponenttargetkindbindingstate',
    'urn:usf:permutationfamily:selectedoptionrealisationmappingdecisionevaluationoptionrealisationstate',
    'urn:usf:permutationfamily:tokenprofiletemplateclaimconstraint',
    'urn:usf:permutationfamily:tokenprofiletemplatesecuritybindingprofileissueraudiencelifetimeauthenticationproofrevocationdelegation',
    'urn:usf:permutationfamily:validatorruleseverity',
  ]);
  assert.equal(censusFamilies.filter(({ planeIri }) => planeIri === FAMILY_PLANES.runtime).length,
    censusFamilies.length - assuranceFamilies.length);
  assert.ok(new Set(censusFamilies.map(({ registrationIri }) => registrationIri)).size >= 1);
  assert.ok(new Set(censusFamilies.map(({ subjectClassIri }) => subjectClassIri)).size >= 1);

  for (const selector of familyRegistry.selectors.values()) {
    assert.equal(selector.digest, digest(selectorCanonicalRecord(selector)));
    const mutated = selectorCanonicalRecord(selector);
    mutated.steps = mutated.steps.map((step, index) => index === 0
      ? { ...step, predicateIri: `${step.predicateIri}:mutation` }
      : step);
    assert.notEqual(digest(mutated), selector.digest);
  }
  for (const rule of familyRegistry.rules.values()) {
    const canonicalRule = {
      canonicalName: rule.canonicalName,
      rootClause: rule.rootClause,
      ruleIri: rule.ruleIri,
      satisfiedDispositionIri: rule.satisfiedDispositionIri,
      schemaVersion: 1,
      unsatisfiedDispositionIri: rule.unsatisfiedDispositionIri,
      unsatisfiedReasonIri: rule.unsatisfiedReasonIri,
    };
    assert.equal(digest(canonicalRule), rule.ruleDigest);
    assert.notEqual(digest({ ...canonicalRule, unsatisfiedReasonIri: `${rule.unsatisfiedReasonIri}:mutation` }),
      rule.ruleDigest);
  }
});

test('registry rejects orphan resources, unsupported operators and expression cycles specifically', () => {
  expectRegistryCode((source) => source.replace(/\n\}\s*$/u, `
prule:orphan a usf:PermutationApplicabilityRule;
    usf:canonicalName "orphan";
    usf:applicabilityRootClause pclause:true;
    usf:applicabilitySatisfiedDisposition frd:matrixrequired;
    usf:applicabilityUnsatisfiedDisposition frd:matrixnotapplicable;
    usf:applicabilityUnsatisfiedReason par:subjectclassmismatch;
    usf:applicabilityRuleDigest "sha256:${'0'.repeat(64)}".
}
`), 'ORPHAN_APPLICABILITY_RULE');
  expectRegistryCode((source) => source.replace(
    'pclause:true a usf:PermutationApplicabilityClause; usf:canonicalName "true"; usf:applicabilityClauseOperator pao:true.',
    'pclause:true a usf:PermutationApplicabilityClause; usf:canonicalName "true"; usf:applicabilityClauseOperator <urn:usf:permutationapplicabilityoperator:unsupported>.',
  ), 'APPLICABILITY_OPERATOR_UNSUPPORTED');
  expectRegistryCode((source) => source.replace(
    'usf:applicabilityOperandClause pclause:interfaces.',
    'usf:applicabilityOperandClause pclause:anyinterfacesgateway.',
  ), 'APPLICABILITY_EXPRESSION_CYCLE');
});

test('applicability operator contracts reject each structural defect with its exact code', () => {
  const anyLine = 'pclause:anyinterfacesgateway a usf:PermutationApplicabilityClause; usf:canonicalName "anyinterfacesgateway"; usf:applicabilityClauseOperator pao:anyof; usf:applicabilityClauseOperand poperand:anyinterfacesgateway1, poperand:anyinterfacesgateway2.';
  expectRegistryCode((source) => source.replace(anyLine,
    'pclause:anyinterfacesgateway a usf:PermutationApplicabilityClause; usf:canonicalName "anyinterfacesgateway"; usf:applicabilityClauseOperator pao:not.'),
  'APPLICABILITY_OPERATOR_ARITY_INVALID');
  expectRegistryCode((source) => source.replace(anyLine,
    'pclause:anyinterfacesgateway a usf:PermutationApplicabilityClause; usf:canonicalName "anyinterfacesgateway"; usf:applicabilityClauseOperator pao:anyof; usf:applicabilityClauseOperand poperand:anyinterfacesgateway1.'),
  'APPLICABILITY_OPERATOR_ARITY_INVALID');
  const countLine = 'pclause:interfaces a usf:PermutationApplicabilityClause; usf:canonicalName "interfaces"; usf:applicabilityClauseOperator pao:countatleast; usf:applicabilitySignalSelector pselector:interfaces; usf:applicabilityThreshold 1.';
  expectRegistryCode((source) => source.replace(countLine,
    'pclause:interfaces a usf:PermutationApplicabilityClause; usf:canonicalName "interfaces"; usf:applicabilityClauseOperator pao:countatleast; usf:applicabilitySignalSelector pselector:interfaces, pselector:ports; usf:applicabilityThreshold 1.'),
  'APPLICABILITY_SELECTOR_CARDINALITY_INVALID');
  expectRegistryCode((source) => source.replace(countLine,
    'pclause:interfaces a usf:PermutationApplicabilityClause; usf:canonicalName "interfaces"; usf:applicabilityClauseOperator pao:countatleast; usf:applicabilitySignalSelector pselector:interfaces; usf:applicabilityThreshold 1, 2.'),
  'APPLICABILITY_THRESHOLD_INVALID');
  expectRegistryCode((source) => source.replace(countLine,
    'pclause:interfaces a usf:PermutationApplicabilityClause; usf:canonicalName "interfaces"; usf:applicabilityClauseOperator pao:valueequals; usf:applicabilitySignalSelector pselector:interfaces; usf:applicabilityExpectedValue usf:Interface, usf:Port.'),
  'APPLICABILITY_EXPECTED_VALUE_INVALID');
});

test('heterogeneous subject registrations remain independent and selector class mismatch fails closed', () => {
  const registration = `psr:roleruntime a usf:PermutationSubjectRegistration;
    usf:canonicalName "roleruntime";
    usf:registeredSubjectClass usf:Role;
    usf:subjectClassClosure pcc:role;
    usf:registeredFamilyPlane pfp:runtimebehaviour.\n`;
  const rebound = (source, family) => source
    .replace('psr:capabilityassurance a usf:PermutationSubjectRegistration;', `${registration}\npsr:capabilityassurance a usf:PermutationSubjectRegistration;`)
    .replace(`${family} usf:familySubjectRegistration psr:capabilityruntime;`,
      `${family} usf:familySubjectRegistration psr:roleruntime;`);
  withRegistryMutation((source) => rebound(source, 'pf:capabilityresourceaction'), (root) => {
    const registry = loadPermutationFamilyRegistry({ repositoryRoot: root, verifyStoredDigests: false });
    assert.equal(registry.families.find(({ iri }) => iri === 'urn:usf:permutationfamily:capabilityresourceaction')
      .subjectClassIri, `${O}Role`);
    assert.notEqual(registry.registryDigest, familyRegistry.registryDigest);
  });
  expectRegistryCode((source) => rebound(source, 'pf:capabilityinterfaceoperation'),
    'SELECTOR_REGISTRATION_CLASS_MISMATCH');
});

test('each family binds its registry dimensions with matching keys and positions', () => {
  for (const family of censusFamilies) {
    const iri = family.iri;
    assert.ok(subjectsOfType('PermutationFamily').includes(iri), `missing family ${iri}`);
    assert.ok(oneLiteral(iri, 'definition').length > 0);
    assert.equal(oneLiteral(iri, 'familyStableKeyAlgorithm'), 'family-subject-ordered-dimension-identity-v1');
    assert.deepEqual(objectsOf(iri, 'familySubjectKind'), []);
    assert.deepEqual(objectsOf(iri, 'familyGenerationAlgorithm'), []);
    assert.deepEqual(objectsOf(iri, 'familyPartitionRule'), []);
    assert.deepEqual(
      objectsOf(iri, 'familyClosureRequirement').map((t) => t.value).sort(),
      ['deferred-requires-authority', 'unresolved=0'],
    );

    const expectedKeys = family.orderedDimensions;
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
      const canonicalName = `${family.canonicalName}${i + 1}${expectedKeys[i]}`;
      assert.equal(o.binding, `urn:usf:permutationfamilydimensionbinding:${canonicalName}`,
        `binding IRI shape for ${family.canonicalName} position ${i + 1}`);
      assert.equal(oneLiteral(o.binding, 'canonicalName'), canonicalName,
        `binding canonical name for ${family.canonicalName} position ${i + 1}`);
    });
  }
});

test('governed permutation identities conform to the nonhyphenated naming rule', () => {
  for (const cls of ['PermutationFamilyDimensionBinding', 'PermutationDimensionValue']) {
    for (const iri of subjectsOfType(cls)) {
      const localName = iri.slice(iri.lastIndexOf(':') + 1);
      assert.match(localName, /^[a-z0-9]+$/, `${cls} IRI local name ${localName}`);
    }
  }
});

test('permission dimensions do not require already-final PermissionAtom instances', () => {
  const permissionSource = 'urn:usf:dimensionvaluesource:permissionatom';
  assert.equal(oneLiteral(permissionSource, 'valueSourceKind'), 'classinstances');
  assert.equal(oneLiteral(permissionSource, 'valueSourceClassIri'), 'urn:usf:ontology:Permission');
  for (const source of ['eventconsumepermission', 'eventpublishpermission', 'eventsubscribepermission']) {
    assert.equal(oneLiteral(`urn:usf:dimensionvaluesource:${source}`, 'valueSourceKind'), 'derivedselector');
    assert.equal(objectsOf(`urn:usf:dimensionvaluesource:${source}`, 'valueSourceClassIri').length, 0);
  }
  assert.equal(
    quads.filter((quad) => quad.predicate.value === O + 'valueSourceClassIri'
      && quad.object.value === 'urn:usf:ontology:PermissionAtom').length,
    0,
  );
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

test('all registered dimension sources have one compatible controlled source scope', () => {
  const expectedScopes = new Map([
    ['classinstances', new Set([
      'urn:usf:dimensionvaluesourcescope:authorityinstanceset',
      'urn:usf:dimensionvaluesourcescope:foundationcatalogue',
    ])],
    ['controlledlist', new Set(['urn:usf:dimensionvaluesourcescope:foundationcatalogue'])],
    ['derivedselector', new Set([
      'urn:usf:dimensionvaluesourcescope:capabilityrelationship',
      'urn:usf:dimensionvaluesourcescope:downstreamclosure',
      'urn:usf:dimensionvaluesourcescope:registeredsubjectrelationship',
    ])],
  ]);
  const sources = subjectsOfType('DimensionValueSource').sort();
  assert.ok(sources.length > 0);
  for (const source of sources) {
    const kind = oneLiteral(source, 'valueSourceKind');
    const scopes = objectsOf(source, 'valueSourceScope').map(({ value }) => value);
    assert.equal(scopes.length, 1, `${source} must have one valueSourceScope`);
    assert.ok(expectedScopes.get(kind)?.has(scopes[0]), `${source} has incompatible ${kind}/${scopes[0]}`);
  }
  const kindCounts = Object.fromEntries([...expectedScopes.keys()].map((kind) => [kind,
    sources.filter((source) => oneLiteral(source, 'valueSourceKind') === kind).length]));
  assert.equal(Object.values(kindCounts).reduce((sum, count) => sum + count, 0), sources.length);
  assert.ok(Object.values(kindCounts).every((count) => count > 0));
  const scopeCounts = {};
  for (const source of sources) {
    const scope = objectsOf(source, 'valueSourceScope')[0].value;
    scopeCounts[scope] = (scopeCounts[scope] ?? 0) + 1;
  }
  assert.equal(Object.values(scopeCounts).reduce((sum, count) => sum + count, 0), sources.length);
  assert.ok(Object.values(scopeCounts).every((count) => count > 0));
});

test('every derived source has one explicit semantic execution mode and digest-bound closure', () => {
  const derived = subjectsOfType('DimensionValueSource')
    .filter((source) => oneLiteral(source, 'valueSourceKind') === 'derivedselector')
    .sort();
  assert.ok(derived.length > 0);
  for (const source of derived) {
    const predicates = objectsOf(source, 'valueSourceDerivationPredicate').map(({ value }) => value);
    assert.equal(new Set(predicates).size, predicates.length, `${source} repeats a derivation predicate`);
    const selectors = objectsOf(source, 'valueSourceSelector');
    const roots = objectsOf(source, 'valueSourceDerivationRoot');
    assert.equal(selectors.length + roots.length, 1, `${source} must use one declarative execution mode`);
    if (roots.length === 1) {
      assert.equal(objectsOf(source, 'valueSourceSubjectClass').length, 1, `${source} subject class`);
      assert.ok(objectsOf(source, 'valueSourceTerminalClass').length >= 1, `${source} terminal class`);
      assert.deepEqual(objectsOf(source, 'valueSourceTerminalKind').map(({ value }) => value),
        ['urn:usf:permutationvalueterminalkind:namednode']);
      assert.match(oneLiteral(source, 'valueSourceDigest'), /^sha256:[0-9a-f]{64}$/u);
      assert.match(oneLiteral(roots[0].value, 'valueDerivationDigest'), /^sha256:[0-9a-f]{64}$/u);
    }
  }
  assert.ok(derived.flatMap((source) => objectsOf(source, 'valueSourceDerivationPredicate')).length > 0);
  const structured = derived.filter((source) => objectsOf(source, 'valueSourceSelector').length > 0);
  assert.ok(structured.length > 0);
  assert.equal(structured.every((source) => objectsOf(source, 'valueSourceSelector').length === 1), true);
  const expressions = derived.filter((source) => objectsOf(source, 'valueSourceDerivationRoot').length > 0);
  assert.ok(expressions.length > 0);
  assert.ok(subjectsOfType('PermutationValueDerivation').length >= expressions.length);
  assert.ok(subjectsOfType('PermutationValueDerivationOperand').length >= expressions.length);
  assert.deepEqual(
    objectsOf('urn:usf:dimensionvaluesource:positivepermutationcell', 'valueSourceDerivationPredicate')
      .map(({ value }) => value).sort(),
    [
      'urn:usf:ontology:cellDisposition',
      'urn:usf:ontology:cellForCapability',
    ],
  );
});

test('service lifecycle catalogue is the exact finite 20-obligation foundation domain', () => {
  const values = objectsOf('urn:usf:permutationdimension:closurelifecycleobligation', 'hasDimensionValue')
    .map(({ value }) => value);
  const keys = values.map((value) => oneLiteral(value, 'dimensionValueKey')).sort();
  assert.deepEqual(keys, [
    'backup', 'becomeready', 'configure', 'decommission', 'drain', 'failover', 'initialise',
    'migrate', 'pause', 'reconcile', 'recover', 'restart', 'restore', 'rollback',
    'rotatecredentials', 'scale', 'serve', 'start', 'stop', 'upgrade',
  ]);
  for (const value of values) {
    assert.ok(subjectsOfType('LifecycleObligationKind').includes(value),
      `${value} must be a LifecycleObligationKind`);
    const key = oneLiteral(value, 'dimensionValueKey');
    assert.equal(value, `urn:usf:permutationdimensionvalue:lifecycleobligation${key}`);
    assert.equal(oneLiteral(value, 'canonicalName'), `lifecycleobligation${key}`);
  }
});

test('condition, reachability and token foundation catalogues are finite and digest-bound', () => {
  const catalogues = [
    ['AuthorisationConditionClause', 13, 'conditionClauseDigest'],
    ['AuthorisationConditionProfile', 11, 'conditionProfileDigest'],
    ['ActionReachabilityState', 8, null],
    ['TokenClaimConstraintTemplate', 25, 'claimConstraintTemplateDigest'],
    ['TokenProfileTemplate', 6, 'tokenProfileTemplateDigest'],
    ['TokenProfileTemplateSecurityBinding', 5, 'tokenProfileTemplateSecurityBindingDigest'],
    ['TokenLifetimePolicy', 4, null],
    ['RevocationPolicy', 2, null],
    ['DelegationConstraint', 2, null],
  ];
  for (const [cls, count, digestPredicate] of catalogues) {
    const resources = [...new Set(allSubjectsOfType(cls))].sort();
    assert.equal(resources.length, count, `${cls} catalogue cardinality`);
    if (digestPredicate) {
      for (const resource of resources) {
        const values = allObjectsOf(resource, digestPredicate).map(({ value }) => value);
        assert.equal(values.length, 1, `${resource} needs one ${digestPredicate}`);
        assert.match(values[0], /^sha256:[0-9a-f]{64}$/);
      }
    }
  }
});

test('token-family domains use non-authorising templates rather than operational scopes', () => {
  const tokenTemplateFamily = 'urn:usf:permutationfamily:tokenprofiletemplateclaimconstraint';
  const tokenSecurityFamily = 'urn:usf:permutationfamily:tokenprofiletemplatesecuritybindingprofileissueraudiencelifetimeauthenticationproofrevocationdelegation';
  assert.ok(subjectsOfType('PermutationFamily').includes(tokenTemplateFamily));
  assert.ok(subjectsOfType('PermutationFamily').includes(tokenSecurityFamily));
  assert.equal(subjectsOfType('PermutationFamily')
    .includes('urn:usf:permutationfamily:tokenprofilepermissionatomclaimconstraint'), false);
  const boundDimensionIris = [tokenTemplateFamily, tokenSecurityFamily]
    .flatMap((family) => objectsOf(family, 'hasFamilyDimensionBinding'))
    .flatMap(({ value: binding }) => objectsOf(binding, 'bindsDimension'))
    .map(({ value }) => value);
  const boundSourceClasses = boundDimensionIris
    .flatMap((dimension) => objectsOf(dimension, 'dimensionValueSource'))
    .flatMap(({ value: source }) => objectsOf(source, 'valueSourceSelector'))
    .flatMap(({ value: selector }) => objectsOf(selector, 'selectorTerminalClass'))
    .map(({ value }) => value);
  assert.equal(boundSourceClasses.includes('urn:usf:ontology:PermissionAtom'), false);
  assert.equal(boundSourceClasses.includes('urn:usf:ontology:TokenScope'), false);
  assert.ok(boundSourceClasses.includes('urn:usf:ontology:TokenClaimConstraintTemplate'));
  assert.ok(boundSourceClasses.includes('urn:usf:ontology:TokenProfileTemplate'));
  assert.equal(allSubjectsOfType('TokenScope').length, 0, 'foundation catalogue must not mint operational token scopes');
  assert.equal(allSubjectsOfType('PermissionAtom').length, 0,
    'foundation token-template catalogue must not mint operational permission atoms');
});
