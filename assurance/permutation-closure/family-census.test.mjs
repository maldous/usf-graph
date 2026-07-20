import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import {
  canonicalJson,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import {
  DISPOSITIONS,
  censusFamilies,
  computeCapabilitySignals,
  evaluateFamilyApplicability,
  familyRegistry,
  generateFamilyCensus,
  loadVerifiedAuthorityInputs,
} from './family-census.mjs';
import { universeProofInternals } from './universe-proof.mjs';

const O = 'urn:usf:ontology:';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const XSD_BOOLEAN = 'http://www.w3.org/2001/XMLSchema#boolean';
const AUTHORITY_DIGEST = `sha256:${'a'.repeat(64)}`;
const roots = [];
after(() => roots.forEach((root) => rmSync(root, { force: true, recursive: true })));

const addressedJson = (root, kind, value) => {
  const content = `${canonicalJson(value)}\n`;
  const digest = sha256(content);
  const path = join(root, `${kind}-${digest.slice('sha256:'.length)}.json`);
  writeFileSync(path, content);
  return { digest, path };
};
const tripleKey = (triple) => canonicalJson(triple);
const iriTriple = (subject, predicate, object) => [subject, predicate, 'iri', object, null, null];
const literalTriple = (subject, predicate, value, datatype = null) => [subject, predicate, 'literal', value, datatype, null];

function projectionFixture({ gatewayOnly = false } = {}) {
  const capability = 'urn:test:capability';
  const contract = 'urn:test:contract';
  const query = 'urn:test:query';
  const command = 'urn:test:command';
  const gateway = 'urn:test:gateway';
  const permissionOne = 'urn:test:permission:one';
  const permissionTwo = 'urn:test:permission:two';
  const roleOne = 'urn:usf:role:one';
  const roleTwo = 'urn:usf:role:two';
  const interfaceIri = 'urn:test:interface';
  const optionComponent = 'urn:test:optioncomponent';
  const composedOption = 'urn:test:composedoption';
  const binding = 'urn:test:binding';
  const port = 'urn:test:port';
  const triples = [
    iriTriple(capability, RDF_TYPE, `${O}Capability`),
    iriTriple(capability, `${O}hasContract`, contract),
    iriTriple(contract, RDF_TYPE, `${O}SemanticContract`),
    iriTriple(gateway, RDF_TYPE, `${O}GatewayOperation`),
    literalTriple(gateway, `${O}coordinatorOnly`, 'true', XSD_BOOLEAN),
    iriTriple(gateway, `${O}requiresPermission`, permissionOne),
    iriTriple(gateway, `${O}requiresPermission`, permissionTwo),
    iriTriple(permissionOne, RDF_TYPE, `${O}Permission`),
    iriTriple(permissionTwo, RDF_TYPE, `${O}Permission`),
    iriTriple(roleOne, RDF_TYPE, `${O}Role`),
    iriTriple(roleOne, `${O}grantsPermission`, permissionOne),
    iriTriple(roleTwo, RDF_TYPE, `${O}Role`),
    iriTriple('urn:test:environmentclass', RDF_TYPE, `${O}EnvironmentClass`),
    iriTriple(optionComponent, RDF_TYPE, `${O}OptionComponent`),
    iriTriple(optionComponent, `${O}componentForOption`, composedOption),
    iriTriple(composedOption, RDF_TYPE, `${O}ComposedRealisationOption`),
    iriTriple(binding, RDF_TYPE, `${O}Binding`),
    iriTriple(binding, `${O}bindsPort`, port),
    iriTriple(port, RDF_TYPE, `${O}Port`),
  ];
  if (!gatewayOnly) {
    triples.push(
      iriTriple(interfaceIri, RDF_TYPE, `${O}Interface`),
      iriTriple(interfaceIri, `${O}interfaceForContract`, contract),
      iriTriple(interfaceIri, `${O}hasOperation`, query),
      iriTriple(interfaceIri, `${O}hasOperation`, command),
      iriTriple(query, RDF_TYPE, `${O}Query`),
      iriTriple(command, RDF_TYPE, `${O}Command`),
    );
  }
  const projectedClassIris = unique([
    'Capability', 'Command', 'EnvironmentClass', 'Event', 'GatewayOperation', 'Permission',
    'Port', 'Query', 'Role', 'SemanticContract', 'State', 'Transition',
  ].map((name) => `${O}${name}`).concat([...familyRegistry.selectors.values()].flatMap((selector) => [
    selector.subjectClassIri,
    selector.terminalClassIri,
  ])).concat(censusFamilies.flatMap(({ subjectClassClosure }) => subjectClassClosure.memberClassIris)));
  const projectedPredicateIris = unique([
    ...triples.map(([, predicate]) => predicate),
    ...[...familyRegistry.selectors.values()].flatMap(({ steps }) => steps.map(({ predicateIri }) => predicateIri)),
  ]);
  const operationClassBindings = [
    [`${O}Command`, gatewayOnly ? null : command],
    [`${O}GatewayOperation`, gateway],
    [`${O}Operation`, null],
    [`${O}Query`, gatewayOnly ? null : query],
  ].sort((left, right) => tripleKey(left).localeCompare(tripleKey(right), 'en'));
  return {
    identifiers: { binding, capability, command, contract, gateway, optionComponent, permissionOne,
      permissionTwo, port, query, roleOne, roleTwo },
    projection: {
      authorityDigest: AUTHORITY_DIGEST,
      basePacketDigest: null,
      gatewayOperationCapabilityBindings: [[capability, gateway, 'urn:test:graph']],
      operationClassBindings,
      projectedClassIris,
      projectedPredicateIris,
      projectionMethod: 'BOUNDED_USF_MCP_SELECT',
      recordKind: 'USF_PERMUTATION_AUTHORITY_PROJECTION',
      schemaVersion: 1,
      triples: triples.sort((left, right) => tripleKey(left).localeCompare(tripleKey(right), 'en')),
    },
  };
}

const unique = (values) => [...new Set(values)].sort();

function buildFixture({ gatewayOnly = false, mutatePacket, mutateProjection } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'usf-permutation-authority-'));
  roots.push(root);
  const { identifiers, projection } = projectionFixture({ gatewayOnly });
  const packet = {
    activeIdentities: { contractCount: 1 },
    authorityDigest: AUTHORITY_DIGEST,
    controlledDimensions: { roles: ['one', 'two'] },
    liveSignals: {
      capabilities: 1,
      environmentClasses: 1,
      events: 0,
      gatewayOperations: 1,
      operationTypes: { Command: gatewayOnly ? 0 : 1, Query: gatewayOnly ? 0 : 1 },
      permissions: 2,
      ports: 1,
      roles: 2,
      states: 0,
      transitions: 0,
    },
    packetSchemaVersion: 1,
    recordKind: 'USF_PERMUTATION_AUTHORITY_INPUT_PACKET',
  };
  mutatePacket?.(packet);
  const packetFile = addressedJson(root, 'packet', packet);
  projection.basePacketDigest = packetFile.digest;
  mutateProjection?.(projection);
  const projectionFile = addressedJson(root, 'projection', projection);
  return {
    authorityInputs: () => loadVerifiedAuthorityInputs({
      authorityDigest: AUTHORITY_DIGEST,
      authorityPacketDigest: packetFile.digest,
      authorityPacketPath: packetFile.path,
      authorityProjectionDigest: projectionFile.digest,
      authorityProjectionPath: projectionFile.path,
    }),
    identifiers,
    packetFile,
    projectionFile,
    root,
  };
}

const expectCode = (callback, code) => assert.throws(callback, (error) => error?.code === code);

test('census family registry is ordered, digest-bound and free of delivery ordinals', () => {
  assert.ok(censusFamilies.length > 0);
  assert.equal(familyRegistry.registryDigest, sha256(canonicalJson(familyRegistry.registryRecord)));
  assert.deepEqual(censusFamilies.map(({ key }) => key),
    [...censusFamilies.map(({ key }) => key)].sort());
  assert.equal(censusFamilies.some(({ key }) => /^f[0-9]+$/u.test(key)), false);
  for (const family of censusFamilies) {
    assert.ok(Object.isFrozen(family));
    assert.equal(family.iri, `urn:usf:permutationfamily:${family.canonicalName}`);
    assert.ok(family.orderedDimensions.length >= 1);
  }
});

test('verified exact packet and projection produce a deterministic registered-subject v4 class-closure census', () => {
  const fixture = buildFixture();
  const authorityInputs = fixture.authorityInputs();
  const first = generateFamilyCensus({ authorityInputs });
  const second = generateFamilyCensus({ authorityInputs });
  assert.equal(first.schemaVersion, 4);
  const expectedSubjects = new Set(censusFamilies.flatMap(({ subjectClassClosure }) => (
    subjectClassClosure.memberClassIris.flatMap((classIri) => authorityInputs.index.instances(classIri))
  )));
  assert.equal(first.subjectCount, expectedSubjects.size);
  assert.equal(first.familyCount, censusFamilies.length);
  const expectedPairCount = censusFamilies.reduce((sum, family) => sum
    + new Set(family.subjectClassClosure.memberClassIris
      .flatMap((classIri) => authorityInputs.index.instances(classIri))).size, 0);
  assert.equal(first.records.length, expectedPairCount);
  assert.equal(first.authorityDigest, AUTHORITY_DIGEST);
  assert.equal(first.authorityPacketDigest, fixture.packetFile.digest);
  assert.equal(first.authorityProjectionDigest, fixture.projectionFile.digest);
  assert.equal(first.familyRegistryDigest, familyRegistry.registryDigest);
  assert.equal(first.censusDigest, second.censusDigest);
  assert.equal(canonicalJson(first), canonicalJson(second));
  const independentMetaModel = universeProofInternals.loadIndependentMetaModel(process.cwd());
  assert.equal(independentMetaModel.familyRegistry.registryDigest, familyRegistry.registryDigest);
  assert.deepEqual(independentMetaModel.familyRegistry.registryRecord, familyRegistry.registryRecord);
  for (const family of independentMetaModel.familyRegistry.families) {
    const sourceFamily = familyRegistry.families.find(({ iri }) => iri === family.familyIri);
    assert.deepEqual(family.dimensions.map(({ bindingIri }) => bindingIri),
      sourceFamily.bindings.map(({ bindingIri }) => bindingIri),
      `${family.familyIri} independent reconstruction must preserve exact binding IRIs`);
  }
  assert.doesNotThrow(() => universeProofInternals.validateCensus(
    first,
    authorityInputs,
    independentMetaModel,
  ));
  const expectedCountsByRegistration = Object.fromEntries([...new Set(censusFamilies
    .map(({ registrationIri }) => registrationIri))].sort().map((registrationIri) => {
    const family = censusFamilies.find((candidate) => candidate.registrationIri === registrationIri);
    const subjects = new Set(family.subjectClassClosure.memberClassIris
      .flatMap((classIri) => authorityInputs.index.instances(classIri)));
    return [registrationIri, subjects.size];
  }));
  assert.deepEqual(first.subjectCountsByRegistration, expectedCountsByRegistration);
  assert.equal(first.records.some(({ subjectClass }) => subjectClass === `${O}DeployableProcess`), false);
  for (const record of first.records) {
    const family = censusFamilies.find(({ iri }) => iri === record.family);
    assert.equal(record.subjectClass, family.subjectClassIri);
    assert.equal(record.registrationIri, family.registrationIri);
    assert.equal(record.subjectClassClosureDigest, family.subjectClassClosure.digest);
    if (record.subjectClass === `${O}Capability`) {
      assert.equal(record.subject, fixture.identifiers.capability);
      assert.equal(record.capability, record.subject);
      assert.equal(record.contract, fixture.identifiers.contract);
    } else {
      assert.equal(record.capability, null);
      assert.equal(record.contract, null);
      assert.equal(family.subjectClassClosure.memberClassIris.some((classIri) => (
        authorityInputs.index.isType(record.subject, classIri)
      )), true);
    }
  }
  assert.equal(Object.values(first.dispositionCounts).reduce((sum, count) => sum + count, 0),
    first.records.length);
});

test('gateway ownership and multiple permission bindings remain exact', () => {
  const fixture = buildFixture({ gatewayOnly: true });
  const authorityInputs = fixture.authorityInputs();
  const signals = computeCapabilitySignals(authorityInputs, fixture.identifiers.capability);
  assert.equal(signals.interfaces, 0);
  assert.equal(signals.operations, 0);
  assert.equal(signals.gatewayoperations, 1);
  assert.deepEqual(authorityInputs.index.values(
    fixture.identifiers.gateway,
    `${O}requiresPermission`,
  ), [fixture.identifiers.permissionOne, fixture.identifiers.permissionTwo]);
  for (const key of [
    'capabilityinterfaceoperation',
    'operationpermissionatom',
    'operationroleconditionprofile',
    'permissionatomroletenantboundary',
    'permissionatomprincipalkindenvironmentclass',
    'permissionatomresourceselectorkind',
    'operationexpectedoutcomeerrorclass',
    'apicommandratelimitpolicypermissionatomtenantboundary',
    'permissionatomdelegationmodeauthenticationstrength',
    'operationratelimitclassquotastateoutcome',
  ]) {
    assert.equal(evaluateFamilyApplicability(key, signals).disposition, DISPOSITIONS.required, key);
  }
});

test('independent reconstruction rejects a digest-consistent census with one required region removed', () => {
  const fixture = buildFixture();
  const authorityInputs = fixture.authorityInputs();
  const current = generateFamilyCensus({ authorityInputs });
  const records = current.records.slice(0, -1);
  const pairKeys = records.map(({ family, subject }) => `${family}\u0000${subject}`);
  const dispositionCounts = Object.fromEntries(Object.keys(current.dispositionCounts)
    .sort().map((key) => [key, records.filter(({ disposition }) => disposition === key).length]));
  const subjectsByRegistration = new Map();
  const closureByRegistration = new Map();
  for (const record of records) {
    if (!subjectsByRegistration.has(record.registrationIri)) {
      subjectsByRegistration.set(record.registrationIri, new Set());
    }
    subjectsByRegistration.get(record.registrationIri).add(record.subject);
    closureByRegistration.set(record.registrationIri, record.subjectClassClosureDigest);
  }
  const subjectCountsByRegistration = Object.fromEntries([...subjectsByRegistration]
    .sort(([left], [right]) => left.localeCompare(right, 'en'))
    .map(([registrationIri, subjects]) => [registrationIri, subjects.size]));
  const subjectSetDigestsByRegistration = Object.fromEntries([...subjectsByRegistration]
    .sort(([left], [right]) => left.localeCompare(right, 'en'))
    .map(([registrationIri, subjects]) => [registrationIri,
      sha256(canonicalJson([...subjects].sort()))]));
  const subjectClassClosureDigestsByRegistration = Object.fromEntries([...closureByRegistration]
    .sort(([left], [right]) => left.localeCompare(right, 'en')));
  const descriptorCore = {
    authorityDigest: current.authorityDigest,
    authorityPacketDigest: current.authorityPacketDigest,
    authorityProjectionDigest: current.authorityProjectionDigest,
    familyRegistryDigest: current.familyRegistryDigest,
    dispositionCounts,
    expectedPairCount: records.length,
    familyCount: new Set(records.map(({ family }) => family)).size,
    recordsDigest: sha256(canonicalJson(records)),
    pairSetDigest: sha256(canonicalJson(pairKeys)),
    subjectCount: new Set(records.map(({ subject }) => subject)).size,
    subjectCountsByRegistration,
    subjectSetDigestsByRegistration,
    subjectClassClosureDigestsByRegistration,
  };
  const forged = {
    ...current,
    ...descriptorCore,
    records,
    censusDigest: sha256(canonicalJson(descriptorCore)),
  };
  assert.equal(forged.recordsDigest, sha256(canonicalJson(forged.records)));
  assert.equal(forged.censusDigest, sha256(canonicalJson(descriptorCore)));
  expectCode(() => universeProofInternals.validateCensus(forged, authorityInputs,
    universeProofInternals.loadIndependentMetaModel(process.cwd())),
  'PERMUTATION_CENSUS_REGION_MISSING');
});

test('semantic rules preserve permission and transition-specific false reasons', () => {
  const emptySignals = Object.fromEntries([...familyRegistry.selectors.values()]
    .map(({ canonicalName }) => [canonicalName, canonicalName === 'secretclassifications' ? [] : 0]));
  for (const key of [
    'permissionatomroletenantboundary',
    'permissionatomprincipalkindenvironmentclass',
    'permissionatomresourceselectorkind',
    'permissionatomdelegationmodeauthenticationstrength',
  ]) {
    const result = evaluateFamilyApplicability(key, emptySignals);
    assert.equal(result.disposition, DISPOSITIONS.notApplicable);
    assert.equal(result.reasonIri, 'urn:usf:permutationapplicabilityreason:nopermissionatomsdeclared');
  }
  const transition = evaluateFamilyApplicability(
    'transitiontriggerpermissionatomprincipalkind', emptySignals,
  );
  assert.equal(transition.disposition, DISPOSITIONS.notApplicable);
  assert.equal(transition.reasonIri, 'urn:usf:permutationapplicabilityreason:notransitionsdeclared');
});

test('forged authority object is rejected', () => {
  expectCode(() => generateFamilyCensus({ authorityInputs: {} }), 'UNVERIFIED_AUTHORITY_INPUTS');
});

test('stale packet bytes are rejected before semantic use', () => {
  const fixture = buildFixture();
  expectCode(() => loadVerifiedAuthorityInputs({
    authorityDigest: AUTHORITY_DIGEST,
    authorityPacketDigest: `sha256:${'b'.repeat(64)}`,
    authorityPacketPath: fixture.packetFile.path,
    authorityProjectionDigest: fixture.projectionFile.digest,
    authorityProjectionPath: fixture.projectionFile.path,
  }), 'AUTHORITY_PACKET_FILE_DIGEST_MISMATCH');
});

test('corrupt packet JSON is rejected with its exact code', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-permutation-corrupt-'));
  roots.push(root);
  const bytes = '{';
  const digest = sha256(bytes);
  const packetPath = join(root, `packet-${digest.slice('sha256:'.length)}.json`);
  writeFileSync(packetPath, bytes);
  const fixture = buildFixture();
  expectCode(() => loadVerifiedAuthorityInputs({
    authorityDigest: AUTHORITY_DIGEST,
    authorityPacketDigest: digest,
    authorityPacketPath: packetPath,
    authorityProjectionDigest: fixture.projectionFile.digest,
    authorityProjectionPath: fixture.projectionFile.path,
  }), 'AUTHORITY_PACKET_JSON_INVALID');
});

test('wrong live authority digest is rejected', () => {
  const fixture = buildFixture();
  expectCode(() => loadVerifiedAuthorityInputs({
    authorityDigest: `sha256:${'c'.repeat(64)}`,
    authorityPacketDigest: fixture.packetFile.digest,
    authorityPacketPath: fixture.packetFile.path,
    authorityProjectionDigest: fixture.projectionFile.digest,
    authorityProjectionPath: fixture.projectionFile.path,
  }), 'AUTHORITY_DIGEST_MISMATCH');
});

test('non-MCP projection provenance is rejected', () => {
  const fixture = buildFixture({ mutateProjection: (projection) => { projection.projectionMethod = 'LOCAL_RDF_SCAN'; } });
  expectCode(fixture.authorityInputs, 'AUTHORITY_PROJECTION_PROVENANCE_INVALID');
});

test('duplicate gateway binding reaches its exact diagnostic', () => {
  const fixture = buildFixture({ mutateProjection: (projection) => {
    projection.gatewayOperationCapabilityBindings.push([...projection.gatewayOperationCapabilityBindings[0]]);
  } });
  expectCode(fixture.authorityInputs, 'AUTHORITY_GATEWAY_BINDING_INVALID');
});

test('malformed operation binding reaches its exact diagnostic', () => {
  const fixture = buildFixture({ mutateProjection: (projection) => {
    projection.operationClassBindings[0] = ['urn:test:malformed'];
    projection.operationClassBindings.sort((left, right) => tripleKey(left).localeCompare(tripleKey(right), 'en'));
  } });
  expectCode(fixture.authorityInputs, 'AUTHORITY_OPERATION_CLASS_BINDING_INVALID');
});

test('missing Operation root reaches its exact diagnostic', () => {
  const fixture = buildFixture({ mutateProjection: (projection) => {
    projection.operationClassBindings = projection.operationClassBindings
      .filter(([operationClass]) => operationClass !== `${O}Operation`);
  } });
  expectCode(fixture.authorityInputs, 'OPERATION_CLASS_CLOSURE_INVALID');
});

test('packet/projection cardinality drift is rejected', () => {
  const fixture = buildFixture({ mutatePacket: (packet) => { packet.liveSignals.permissions = 3; } });
  expectCode(fixture.authorityInputs, 'AUTHORITY_PACKET_PROJECTION_MISMATCH');
});

test('role identity drift is rejected independently of count', () => {
  const fixture = buildFixture({ mutatePacket: (packet) => { packet.controlledDimensions.roles = ['one', 'three']; } });
  expectCode(fixture.authorityInputs, 'AUTHORITY_PACKET_PROJECTION_MISMATCH');
});
