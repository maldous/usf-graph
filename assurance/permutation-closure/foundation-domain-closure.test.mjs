import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import N3 from 'n3';
import {
  canonicalJson,
  loadSemanticStore,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import { loadVerifiedAuthorityInputs } from './family-census.mjs';
import {
  assessFoundationDomainClosure,
  generateUniverse,
  loadFoundationFixtureInputs,
  universeGeneratorInternals,
} from './universe-generator.mjs';
import { proveFoundationDomainClosureAssessment } from './universe-proof.mjs';
import {
  buildCurrentFoundationGapRemediationInventory,
  buildFoundationGapRemediationInventory,
  foundationGapRemediationInternals,
} from './foundation-gap-remediation.mjs';

const O = 'urn:usf:ontology:';
const AUTHORITY = 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd';
const temporaryRoots = [];
const digestValue = (value) => sha256(canonicalJson(value));

function expectCode(callback, code) {
  assert.throws(callback, (error) => error?.code === code && error.message.startsWith(`${code}:`));
}

function writeAddressedJson(root, stem, value) {
  const bytes = Buffer.from(JSON.stringify(value));
  const digest = sha256(bytes);
  const path = join(root, `${stem}-${digest.slice('sha256:'.length)}.json`);
  writeFileSync(path, bytes);
  return { digest, path };
}

function temporaryFixtureRepository(transform) {
  const root = mkdtempSync(join(tmpdir(), 'usf-foundation-fixture-'));
  temporaryRoots.push(root);
  const fixtureDirectory = join(root, 'semantic-model', 'fixtures', 'conforming');
  mkdirSync(fixtureDirectory, { recursive: true });
  writeFileSync(join(root, 'semantic-model', 'ontology.ttl'), readFileSync(join(
    process.cwd(),
    'semantic-model',
    'ontology.ttl',
  )));
  const source = readFileSync(join(
    process.cwd(),
    'semantic-model',
    'fixtures',
    'conforming',
    'universal-service-foundation.trig',
  ), 'utf8');
  writeFileSync(join(fixtureDirectory, 'universal-service-foundation.trig'), transform(source));
  return root;
}

function verifiedAuthorityInputs() {
  const root = mkdtempSync(join(tmpdir(), 'usf-foundation-authority-'));
  temporaryRoots.push(root);
  const packet = {
    activeIdentities: { contractCount: 1 },
    authorityDigest: AUTHORITY,
    controlledDimensions: { roles: [] },
    liveSignals: {
      capabilities: 1,
      environmentClasses: 0,
      events: 0,
      gatewayOperations: 0,
      operationTypes: { Command: 0, Query: 0 },
      permissions: 0,
      ports: 0,
      roles: 0,
      states: 0,
      transitions: 0,
    },
    packetSchemaVersion: 1,
    recordKind: 'USF_PERMUTATION_AUTHORITY_INPUT_PACKET',
  };
  const packetFile = writeAddressedJson(root, 'packet', packet);
  const type = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
  const projectionCore = {
    authorityDigest: AUTHORITY,
    gatewayOperationCapabilityBindings: [],
    operationClassBindings: [[`${O}Operation`, null]],
    projectedClassIris: [
      `${O}Capability`, `${O}Command`, `${O}EnvironmentClass`, `${O}Event`, `${O}GatewayOperation`,
      `${O}Permission`, `${O}Port`, `${O}Query`, `${O}Role`, `${O}SemanticContract`, `${O}State`, `${O}Transition`,
    ].sort(),
    projectedPredicateIris: [type].sort(),
    projectionMethod: 'BOUNDED_USF_MCP_SELECT',
    recordKind: 'USF_PERMUTATION_AUTHORITY_PROJECTION',
    schemaVersion: 1,
    triples: [
      ['urn:test:capability', type, 'iri', `${O}Capability`, null, null],
      ['urn:test:contract', type, 'iri', `${O}SemanticContract`, null, null],
    ].sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right), 'en')),
  };
  const projectionFile = writeAddressedJson(root, 'projection', {
    ...projectionCore,
    basePacketDigest: packetFile.digest,
  });
  return loadVerifiedAuthorityInputs({
    authorityDigest: AUTHORITY,
    authorityPacketDigest: packetFile.digest,
    authorityPacketPath: packetFile.path,
    authorityProjectionDigest: projectionFile.digest,
    authorityProjectionPath: projectionFile.path,
  });
}

after(() => {
  for (const root of temporaryRoots) rmSync(root, { force: true, recursive: true });
});

test('universal fixture is non-authorising, digest-bound and exercises every registered family', () => {
  const repositoryRoot = process.cwd();
  const fixturePath = join(repositoryRoot, 'semantic-model/fixtures/conforming/universal-service-foundation.trig');
  const quads = new N3.Parser({ format: 'application/trig' }).parse(readFileSync(fixturePath, 'utf8'));
  assert.equal(quads.some(({ predicate }) => predicate.value === `${O}grantsPermission`), false);
  assert.equal(quads.some(({ predicate, object }) => predicate.value === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'
    && object.value === `${O}TokenScope`), false);
  for (const operationalClass of ['ActionReachability', 'PermissionAtom', 'PermutationCell']) {
    assert.equal(quads.some(({ predicate, object }) => (
      predicate.value === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'
      && object.value === `${O}${operationalClass}`
    )), false, `${operationalClass} must not be authored in the conformance fixture`);
  }
  const declaredDigest = quads.find(({ predicate }) => predicate.value === `${O}foundationFixtureDigest`)?.object.value;
  assert.equal(declaredDigest, universeGeneratorInternals.foundationFixtureDigest(quads));

  const authorityInputs = verifiedAuthorityInputs();
  const fixture = loadFoundationFixtureInputs({
    authorityInputs,
    repositoryRoot,
  });
  assert.equal(fixture.foundationFixturePrimaryCapability, 'urn:usf:foundationfixture:capability');
  assert.equal(new Set(fixture.foundationFixturePrimarySubjects).size,
    fixture.foundationFixturePrimarySubjects.length);
  assert.ok(fixture.foundationFixturePrimarySubjects.includes(fixture.foundationFixturePrimaryCapability));
  assert.ok(fixture.index.instances(`${O}Capability`).length > 1,
    'auxiliary process-owned capabilities must coexist without replacing the selected primary capability');
  const assessment = assessFoundationDomainClosure({ foundationFixtureInputs: fixture, repositoryRoot });
  const metaModel = universeGeneratorInternals.loadPermutationMetaModel(repositoryRoot);
  const exactDomainValues = (familyIri, subject) => Object.fromEntries(
    universeGeneratorInternals.familyDimensions(metaModel, familyIri).map((descriptor) => [
      descriptor.key,
      universeGeneratorInternals.resolveDomain(metaModel, fixture, subject, descriptor).values,
    ]),
  );
  assert.equal(metaModel.familyRegistry.families.some(({ iri }) => (
    iri === 'urn:usf:permutationfamily:operationsourcestatetargetstate'
  )), false);
  assert.deepEqual(exactDomainValues(
    'urn:usf:permutationfamily:transitionfromstatetostate',
    'urn:usf:foundationfixture:completetransition',
  ), {
    fromstate: ['urn:usf:foundationfixture:pendingstate'],
    tostate: ['urn:usf:foundationfixture:completedstate'],
  });
  assert.deepEqual(exactDomainValues(
    'urn:usf:permutationfamily:eventproducerentity',
    'urn:usf:foundationfixture:event',
  ), { producerentity: ['urn:usf:foundationfixture:httpapiservice'] });
  assert.deepEqual(exactDomainValues(
    'urn:usf:permutationfamily:eventconsumerentity',
    'urn:usf:foundationfixture:event',
  ), { consumerentity: ['urn:usf:foundationfixture:eventconsumerworker'] });
  const declaredEventParticipants = exactDomainValues(
    'urn:usf:permutationfamily:eventpublisherconsumerdeliverysemantics',
    'urn:usf:foundationfixture:event',
  );
  assert.deepEqual(declaredEventParticipants.publisher, ['urn:usf:foundationfixture:capability']);
  assert.deepEqual(declaredEventParticipants.consumer, ['urn:usf:foundationfixture:capability']);
  assert.equal(declaredEventParticipants.publisher.includes('urn:usf:foundationfixture:httpapiservice'), false);
  assert.equal(declaredEventParticipants.consumer.includes('urn:usf:foundationfixture:eventconsumerworker'), false);
  const structuralProjection = universeGeneratorInternals.buildFoundationStructuralProjection(metaModel, fixture);
  const repeatedProjection = universeGeneratorInternals.buildFoundationStructuralProjection(metaModel, fixture);
  assert.equal(structuralProjection.projectionDigest, repeatedProjection.projectionDigest);
  assert.equal(structuralProjection.projectedRecordCount, 16);
  assert.deepEqual(structuralProjection.index.values(
    'urn:usf:foundationfixture:resourcereadpermissionatomwitness', `${O}atomLifecycleRestriction`,
  ), ['urn:usf:foundationfixture:pendingstate']);
  assert.deepEqual(structuralProjection.index.values(
    'urn:usf:foundationfixture:resourcereadpermissionatomwitness', `${O}atomTransportRestriction`,
  ), ['urn:usf:transport:http']);
  assert.equal(structuralProjection.projectionDigest, assessment.foundationStructuralProjectionDigest);
  assert.equal(structuralProjection.projectedRecordCount,
    assessment.foundationStructuralProjectionRecordCount);
  assert.equal(metaModel.foundationProjectionRules.digest,
    assessment.foundationStructuralProjectionRuleSetDigest);
  assert.equal(fixture.store.getQuads(
    N3.DataFactory.namedNode(structuralProjection.projectionDigest), null, null, null,
  ).length, 0, 'the digest-bound structural projection must remain ephemeral');
  const capabilityDomains = assessment.familyRecords
    .filter(({ subjectClass }) => subjectClass === `${O}Capability`)
    .flatMap(({ family, subject }) => (
    universeGeneratorInternals.familyDimensions(metaModel, family)
      .filter(({ key }) => key === 'capability')
      .map((descriptor) => universeGeneratorInternals.resolveDomain(
        metaModel,
        fixture,
        subject,
        descriptor,
      ))
    ));
  assert.ok(capabilityDomains.length > 0);
  assert.equal(capabilityDomains.every(({ values }) => canonicalJson(values)
    === canonicalJson([fixture.foundationFixturePrimaryCapability])), true,
  'auxiliary process-owned capabilities must never enter the selected subject capability axis');
  assert.equal(assessment.foundationVerdict, 'FOUNDATION_DOMAIN_CLOSURE_COMPLETE');
  assert.equal(assessment.permutationClosureVerdict, 'PERMUTATION_CLOSURE_NOT_ASSESSED');
  assert.equal(assessment.programmePermutationClosureVerdict, 'PERMUTATION_CLOSURE_INCOMPLETE');
  assert.equal(assessment.authorising, false);
  const typedCount = (className) => new Set(metaModel.store.getSubjects(
    N3.DataFactory.namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
    N3.DataFactory.namedNode(`${O}${className}`),
    null,
  ).map(({ value }) => value)).size;
  assert.equal(assessment.familyCount, typedCount('PermutationFamily'));
  assert.equal(assessment.familyRecords.length, assessment.familyCount);
  assert.equal(assessment.diagnostics.length, 0);
  assert.equal(assessment.uniqueDimensionCount, typedCount('PermutationDimension'));
  assert.equal(assessment.dimensionBindingOccurrenceCount, typedCount('PermutationFamilyDimensionBinding'));
  assert.ok(assessment.familyRecords.every(({ combinationCount, domainClosureComplete }) => combinationCount > 0
    && domainClosureComplete));
  assert.equal(assessment.familyRecords.find(({ family }) => family
    === 'urn:usf:permutationfamily:composedrealisationoptioncomponentresponsibilityinterfaceenvironmentbinding')
    .combinationCount, 1);
  assert.equal(assessment.familyRecords.find(({ family }) => family
    === 'urn:usf:permutationfamily:portactionprovidermodeenvironmentbindingstate')
    .combinationCount, 13);
  assert.equal(Object.hasOwn(assessment, 'dispositionCounts'), false);
  assert.equal(Object.hasOwn(assessment, 'fixtureCellCount'), false);
  assert.equal(Object.hasOwn(assessment, 'cells'), false);
  assert.match(assessment.assessmentDigest, /^sha256:[0-9a-f]{64}$/);

  const proof = proveFoundationDomainClosureAssessment({ assessment, authorityInputs, repositoryRoot });
  assert.equal(proof.verdict, 'FOUNDATION_DOMAIN_CLOSURE_PROOF_PASS', JSON.stringify(proof.diagnostics));
  assert.equal(proof.authorising, false);
  assert.equal(proof.diagnostics.length, 0);
  assert.equal(proof.foundationStructuralProjectionDigest,
    assessment.foundationStructuralProjectionDigest);
  assert.equal(proof.foundationStructuralProjectionRecordCount,
    assessment.foundationStructuralProjectionRecordCount);
  assert.equal(proof.foundationStructuralProjectionRuleSetDigest,
    assessment.foundationStructuralProjectionRuleSetDigest);
  assert.deepEqual(proof.results, {
    dimensionBindingOccurrenceCount: assessment.dimensionBindingOccurrenceCount,
    emptyDomainCount: 0,
    familyCount: assessment.familyCount,
    reconstructionMismatchCount: 0,
    uniqueDimensionCount: assessment.uniqueDimensionCount,
  });
  assert.match(proof.proofDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(readFileSync(join(
    repositoryRoot,
    'assurance/permutation-closure/universe-proof.mjs',
  ), 'utf8').includes("from './universe-generator.mjs'"), false);

  const projectionBindingForgeries = [
    ['foundationStructuralProjectionDigest', `sha256:${'1'.repeat(64)}`],
    ['foundationStructuralProjectionRecordCount', assessment.foundationStructuralProjectionRecordCount + 1],
    ['foundationStructuralProjectionRuleSetDigest', `sha256:${'2'.repeat(64)}`],
  ];
  for (const [field, value] of projectionBindingForgeries) {
    const forgedBinding = structuredClone(assessment);
    forgedBinding[field] = value;
    const { assessmentDigest: omittedDigest, ...forgedBindingCore } = forgedBinding;
    forgedBinding.assessmentDigest = digestValue(forgedBindingCore);
    const bindingProof = proveFoundationDomainClosureAssessment({
      assessment: forgedBinding,
      authorityInputs,
      repositoryRoot,
    });
    assert.equal(bindingProof.verdict, 'FOUNDATION_DOMAIN_CLOSURE_PROOF_FAIL', field);
    assert.deepEqual(bindingProof.diagnostics.map(({ code }) => code), [
      'FOUNDATION_ASSESSMENT_INPUT_BINDING_MISMATCH',
    ], field);
    assert.deepEqual(bindingProof.diagnostics[0].items, [{ field }]);
  }
  for (const invalidProjectionBinding of [
    (() => {
      const value = structuredClone(assessment);
      delete value.foundationStructuralProjectionDigest;
      return value;
    })(),
    { ...assessment, foundationStructuralProjectionDigest: 'sha256:malformed' },
    { ...assessment, foundationStructuralProjectionRecordCount: -1 },
    { ...assessment, foundationStructuralProjectionRecordCount: 1.5 },
  ]) {
    const invalidProof = proveFoundationDomainClosureAssessment({
      assessment: invalidProjectionBinding,
      authorityInputs,
      repositoryRoot,
    });
    assert.equal(invalidProof.verdict, 'FOUNDATION_DOMAIN_CLOSURE_PROOF_FAIL');
    assert.deepEqual(invalidProof.diagnostics.map(({ code }) => code), [
      'FOUNDATION_ASSESSMENT_SCHEMA_INVALID',
    ]);
  }

  const positiveCellFamily = 'urn:usf:permutationfamily:capabilitypositivepermutationcell';
  const positiveCellDescriptor = universeGeneratorInternals.familyDimensions(metaModel, positiveCellFamily)[0];
  const livePositiveDomain = universeGeneratorInternals.resolveDomain(
    metaModel,
    authorityInputs,
    'urn:test:capability',
    positiveCellDescriptor,
  );
  assert.equal(livePositiveDomain.valueCount, 0);
  assert.deepEqual(livePositiveDomain.values, []);
  assert.equal(livePositiveDomain.sourcePlane, 'DOWNSTREAM_CLOSURE_DERIVATION');

  const missingMappingFixture = loadFoundationFixtureInputs({ authorityInputs, repositoryRoot });
  const requiredSubjectQuad = missingMappingFixture.store.getQuads(
    null,
    N3.DataFactory.namedNode(`${O}foundationPermutationForSubject`),
    null,
    null,
  )[0];
  assert.ok(requiredSubjectQuad);
  missingMappingFixture.store.removeQuad(requiredSubjectQuad);
  expectCode(() => universeGeneratorInternals.buildFoundationStructuralProjection(
    metaModel,
    missingMappingFixture,
  ), 'FOUNDATION_PROJECTION_MAPPING_INCOMPLETE');

  const staleDigestMetaModel = universeGeneratorInternals.loadPermutationMetaModel(repositoryRoot);
  const mapping = staleDigestMetaModel.store.getSubjects(
    N3.DataFactory.namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
    N3.DataFactory.namedNode(`${O}FoundationConformancePredicateMapping`),
    null,
  )[0];
  const mappingDigestQuad = staleDigestMetaModel.store.getQuads(
    mapping,
    N3.DataFactory.namedNode(`${O}foundationProjectionMappingDigest`),
    null,
    null,
  )[0];
  assert.ok(mappingDigestQuad);
  staleDigestMetaModel.store.removeQuad(mappingDigestQuad);
  staleDigestMetaModel.store.addQuad(N3.DataFactory.quad(
    mappingDigestQuad.subject,
    mappingDigestQuad.predicate,
    N3.DataFactory.literal(`sha256:${'0'.repeat(64)}`),
    mappingDigestQuad.graph,
  ));
  expectCode(() => universeGeneratorInternals.loadFoundationProjectionRules(
    staleDigestMetaModel.store,
  ), 'FOUNDATION_PROJECTION_DIGEST_MISMATCH');

  expectCode(() => assessFoundationDomainClosure({
    foundationFixtureInputs: { ...fixture },
    repositoryRoot,
  }), 'FOUNDATION_FIXTURE_INPUT_UNVERIFIED');
  expectCode(() => generateUniverse({ authorityInputs: fixture, census: {}, repositoryRoot }), 'UNVERIFIED_AUTHORITY_INPUTS');
  expectCode(() => proveFoundationDomainClosureAssessment({
    assessment,
    authorityInputs: { ...authorityInputs },
    repositoryRoot,
  }), 'UNVERIFIED_AUTHORITY_INPUTS');

  const stale = structuredClone(assessment);
  stale.familyRecords[0].combinationCount += 1;
  const staleProof = proveFoundationDomainClosureAssessment({ assessment: stale, authorityInputs, repositoryRoot });
  assert.equal(staleProof.verdict, 'FOUNDATION_DOMAIN_CLOSURE_PROOF_FAIL');
  assert.deepEqual(staleProof.diagnostics.map(({ code }) => code), ['FOUNDATION_ASSESSMENT_DIGEST_MISMATCH']);

  const forged = structuredClone(assessment);
  forged.familyRecords[0].combinationCount += 1;
  const { familyDomainDigest: omittedFamilyDigest, ...forgedFamilyCore } = forged.familyRecords[0];
  forged.familyRecords[0].familyDomainDigest = digestValue(forgedFamilyCore);
  const { assessmentDigest: omittedAssessmentDigest, ...forgedCore } = forged;
  forged.assessmentDigest = digestValue(forgedCore);
  const forgedProof = proveFoundationDomainClosureAssessment({ assessment: forged, authorityInputs, repositoryRoot });
  assert.equal(forgedProof.verdict, 'FOUNDATION_DOMAIN_CLOSURE_PROOF_FAIL');
  assert.deepEqual(forgedProof.diagnostics.map(({ code }) => code), ['FOUNDATION_ASSESSMENT_RECONSTRUCTION_MISMATCH']);
  assert.equal(forgedProof.diagnostics[0].items[0].field, 'familyRecords');

  const keys = Object.keys(foundationGapRemediationInternals.remediationRules).sort();
  const syntheticGaps = keys.map((dimensionKey) => {
    const lookupKey = foundationGapRemediationInternals.remediationRules[dimensionKey]
      .replacementDimensionKey ?? dimensionKey;
    const family = assessment.familyRecords.find(({ dimensions }) => dimensions
      .some(({ key }) => key === lookupKey));
    const dimension = family?.dimensions.find(({ key }) => key === lookupKey);
    assert.ok(family && dimension, `foundation assessment must exercise ${dimensionKey}`);
    return {
      capability: 'urn:usf:fixture:capability',
      code: 'REQUIRED_FINITE_DOMAIN_EMPTY',
      dimension: dimension.dimension,
      dimensionKey,
      family: family.family,
      source: dimension.source,
      sourceKind: dimension.sourceKind,
      sourcePlane: 'LEGACY_EMPTY',
    };
  });
  const remediation = buildFoundationGapRemediationInventory({
    foundationAssessment: assessment,
    legacyManifest: {
      gaps: syntheticGaps,
      recordKind: 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST',
      universeDigest: `sha256:${'1'.repeat(64)}`,
    },
  });
  assert.equal(remediation.findingCount, keys.length);
  assert.equal(remediation.findings.every(({ foundationCauseResolved, resultingFoundationValueCount }) => (
    foundationCauseResolved && resultingFoundationValueCount > 0
  )), true);
  assert.equal(remediation.programmePermutationClosureVerdict, 'PERMUTATION_CLOSURE_INCOMPLETE');
  assert.match(remediation.inventoryDigest, /^sha256:[0-9a-f]{64}$/);

  const currentGaps = syntheticGaps.filter(({ dimensionKey }) => [
    'actionreachability', 'consumer', 'lifecycleobligation',
  ].includes(dimensionKey)).map((gap) => ({
    ...gap,
    sourcePlane: gap.dimensionKey === 'actionreachability'
      ? 'DOWNSTREAM_CLOSURE_DERIVATION'
      : 'LIVE_AUTHORITY_DERIVATION',
  }));
  const current = buildCurrentFoundationGapRemediationInventory({
    foundationAssessment: assessment,
    gapReport: {
      gapSetDigest: digestValue(currentGaps),
      gaps: currentGaps,
      planDigest: `sha256:${'2'.repeat(64)}`,
      recordKind: 'USF_PERMUTATION_DISPOSITION_GAP_REPORT',
      reportDigest: `sha256:${'3'.repeat(64)}`,
    },
  });
  assert.deepEqual(current.rootCauseCounts, {
    AUTHORITY_DECISION_REQUIRED: 1,
    CAPABILITY_SPECIFIC_SEMANTIC_MODELLING: 1,
    DOWNSTREAM_DOMAIN_REQUIRING_FOUNDATION_VOCABULARY: 1,
  });
  assert.equal(current.findingCount, 3);
  assert.equal(current.programmePermutationClosureVerdict, 'PERMUTATION_CLOSURE_INCOMPLETE');
});

test('foundation primary capability selection rejects missing, multiple and untyped values with one exact code', () => {
  const authorityInputs = verifiedAuthorityInputs();
  const declaration = '    usf:foundationFixturePrimaryCapability fx:capability;';
  const cases = [
    ['', 'missing'],
    ['    usf:foundationFixturePrimaryCapability fx:capability, fx:eventconsumercapability;', 'multiple'],
    ['    usf:foundationFixturePrimaryCapability fx:untypedcapability;', 'untyped'],
  ];
  for (const [replacement, identifier] of cases) {
    const repositoryRoot = temporaryFixtureRepository((source) => {
      assert.equal(source.includes(declaration), true);
      return source.replace(declaration, replacement);
    });
    assert.throws(
      () => loadFoundationFixtureInputs({ authorityInputs, repositoryRoot }),
      (error) => error?.code === 'FOUNDATION_FIXTURE_PRIMARY_CAPABILITY_INVALID'
        && error.message.startsWith('FOUNDATION_FIXTURE_PRIMARY_CAPABILITY_INVALID:'),
      identifier,
    );
  }
});

test('capability and process boundaries have accountable ownership and finite baseline lifecycle obligations', () => {
  const { store } = loadSemanticStore(process.cwd());
  const named = N3.DataFactory.namedNode;
  const type = named('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const ontology = 'urn:usf:ontology:';
  const objects = (subject, predicate) => [...new Set(store.getObjects(
    named(subject),
    named(`${ontology}${predicate}`),
    null,
  ).map(({ value }) => value))].sort();
  const instances = (className) => [...new Set(store.getSubjects(
    type,
    named(`${ontology}${className}`),
    null,
  ).map(({ value }) => value))].sort();
  const capabilities = instances('Capability');
  const processes = instances('DeployableProcess');
  assert.equal(capabilities.length, 64);
  assert.equal(processes.length, 6);
  const baseline = [
    'initialise', 'configure', 'start', 'becomeready', 'drain', 'stop',
  ].map((name) => `urn:usf:permutationdimensionvalue:lifecycleobligation${name}`).sort();
  for (const capability of capabilities) {
    const accountable = objects(capability, 'accountableProcessBoundary');
    assert.equal(accountable.length, 1, capability);
    assert.equal(processes.includes(accountable[0]), true, capability);
    assert.equal(objects(capability, 'participatesInProcess').includes(accountable[0]), true, capability);
    assert.equal(objects(accountable[0], 'processOwnsCapability').includes(capability), true, capability);
  }
  for (const process of processes) {
    const boundaryClasses = objects(process, 'processBoundaryClass');
    const ownedCapabilities = objects(process, 'processOwnsCapability');
    assert.equal(boundaryClasses.length, 1, process);
    assert.ok(ownedCapabilities.length > 0, process);
    assert.equal(ownedCapabilities.every((capability) => objects(process, 'processForCapability').includes(capability)), true, process);
    assert.equal(baseline.every((obligation) => objects(process, 'processLifecycleObligation').includes(obligation)), true, process);
    assert.ok(objects(process, 'processTenantSecuritySeparationRequirement').length === 1, process);
  }
  assert.deepEqual(objects('urn:usf:deployableprocess:semanticassurance', 'processBoundaryClass'), [
    'urn:usf:processboundaryclass:assurancecontrolplane',
  ]);
  assert.deepEqual(objects('urn:usf:deployableprocess:scheduletriggering', 'processOwnsCapability'), [
    'urn:usf:capability:scheduledjobsbuiltinontheeventsubstrate',
  ]);
});
