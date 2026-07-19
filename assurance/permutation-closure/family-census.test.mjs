import assert from 'node:assert/strict';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import {
  DISPOSITIONS,
  censusFamilies,
  evaluateFamilyApplicability,
  generateFamilyCensus,
} from './family-census.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const authorityDigest = `sha256:${'0'.repeat(64)}`;
const census = generateFamilyCensus({ repositoryRoot, authorityDigest });
const recordFor = (capability, family) => census.records.find(
  (record) => record.capability === capability && record.family === family,
);

test('census families are the 34 GOAL §16 families in order', () => {
  assert.equal(censusFamilies.length, 34);
  assert.ok(Object.isFrozen(censusFamilies));
  assert.deepEqual(
    censusFamilies.map(({ key }) => key),
    Array.from({ length: 34 }, (_, index) => `f${String(index + 1).padStart(2, '0')}`),
  );
  assert.equal(censusFamilies[0].title, 'Capability × Resource × Action');
  assert.equal(censusFamilies[0].canonicalName, 'capabilityresourceaction');
  assert.deepEqual([...censusFamilies[0].orderedDimensions], ['Capability', 'Resource', 'Action']);
  assert.equal(censusFamilies[11].key, 'f12');
  assert.equal(censusFamilies[11].title, 'Event × Publisher × Consumer × DeliverySemantics');
  assert.equal(censusFamilies[33].title, 'Operation × RateLimitClass × QuotaState × Outcome');
  for (const family of censusFamilies) {
    assert.ok(Object.isFrozen(family));
    assert.equal(family.canonicalName, family.title.toLowerCase().replace(/[^a-z0-9]/g, ''));
    assert.ok(family.orderedDimensions.length >= 2);
    assert.equal(typeof family.applicabilitySignal, 'string');
  }
});

test('every capability yields exactly one disposition per family', () => {
  assert.equal(census.recordKind, 'USF_PERMUTATION_FAMILY_CENSUS');
  assert.equal(census.schemaVersion, 1);
  assert.equal(census.authorityDigest, authorityDigest);
  assert.equal(census.subjectCount, 64);
  assert.equal(census.familyCount, 34);
  assert.equal(census.records.length, 64 * 34);
  const seen = new Set();
  for (const record of census.records) {
    const cell = `${record.capability}|${record.family}`;
    assert.ok(!seen.has(cell), `duplicate census cell ${cell}`);
    seen.add(cell);
  }
  const capabilities = new Set(census.records.map(({ capability }) => capability));
  assert.equal(capabilities.size, 64);
  assert.equal(
    census.dispositionCounts[DISPOSITIONS.required] + census.dispositionCounts[DISPOSITIONS.notApplicable],
    64 * 34,
  );
});

test('no record lacks a disposition and every MATRIX_NOT_APPLICABLE record carries a reason code', () => {
  for (const record of census.records) {
    assert.ok(
      record.disposition === DISPOSITIONS.required || record.disposition === DISPOSITIONS.notApplicable,
      `record ${record.capability}/${record.family} lacks a controlled disposition`,
    );
    assert.ok(record.contract.startsWith('urn:usf:semanticcontract:'));
    if (record.disposition === DISPOSITIONS.notApplicable) {
      assert.match(record.reasonCode, /^NO_[A-Z_]+_DECLARED$/);
      assert.ok(
        Object.values(record.signals).every((count) => Number.isInteger(count)),
        'not-applicable records must carry the observed signal proof',
      );
    } else {
      assert.equal(record.reasonCode, null);
    }
  }
});

test('census generation is deterministic across runs', () => {
  const second = generateFamilyCensus({ repositoryRoot, authorityDigest });
  assert.equal(second.censusDigest, census.censusDigest);
  assert.equal(canonicalJson(second), canonicalJson(census));
});

test('event-declaring capability has f12 MATRIX_REQUIRED', () => {
  // The task packet nominated urn:usf:capability:eventbusdurablequeuesdlqredrive
  // as the f12 fixture, but the authored model declares no usf:eventForContract
  // or usf:messageForContract for its contract; the observed-signal census must
  // report that honestly (asserted below). The workflow engine capability is
  // the signal-rich event fixture actually present in the model.
  const record = recordFor('urn:usf:capability:workflowenginescheduledjobsapprovals', 'f12');
  assert.ok(record, 'workflow engine capability missing from census');
  assert.equal(record.disposition, DISPOSITIONS.required);
  assert.equal(record.reasonCode, null);
  assert.ok(record.signals.events > 0);
});

test('event bus capability census follows its observed signals', () => {
  const port = recordFor('urn:usf:capability:eventbusdurablequeuesdlqredrive', 'f11');
  assert.equal(port.disposition, DISPOSITIONS.required);
  const event = recordFor('urn:usf:capability:eventbusdurablequeuesdlqredrive', 'f12');
  assert.equal(event.disposition, DISPOSITIONS.notApplicable);
  assert.equal(event.reasonCode, 'NO_EVENTS_DECLARED');
  assert.deepEqual(event.signals, { events: 0, messages: 0 });
});

test('capability without UI has f18 MATRIX_NOT_APPLICABLE with a reason code', () => {
  const record = recordFor('urn:usf:capability:semanticmodelcompilation', 'f18');
  assert.ok(record, 'semantic model compilation capability missing from census');
  assert.equal(record.disposition, DISPOSITIONS.notApplicable);
  assert.equal(record.reasonCode, 'NO_UI_SURFACES_DECLARED');
  assert.deepEqual(record.signals, { uiSurfaces: 0, routes: 0 });
});

test('unconditional families are MATRIX_REQUIRED for every capability', () => {
  for (const family of ['f01', 'f23', 'f24', 'f25', 'f26']) {
    for (const record of census.records.filter((candidate) => candidate.family === family)) {
      assert.equal(record.disposition, DISPOSITIONS.required, `${record.capability} ${family}`);
    }
  }
});

test('evaluateFamilyApplicability applies the explicit rule table', () => {
  const zeroSignals = Object.fromEntries([
    'interfaces', 'operations', 'gatewayOperations', 'ports', 'events', 'messages', 'states',
    'transitions', 'workflows', 'scheduledWorkflows', 'dataModels', 'configurationKeys',
    'secretConfigurationKeys', 'uiSurfaces', 'routes', 'forms', 'viewModels',
    'auditEmittingOperations', 'providerModePermits', 'externalDependencyPorts',
  ].map((key) => [key, 0]));
  assert.equal(evaluateFamilyApplicability('f01', zeroSignals).disposition, DISPOSITIONS.required);
  const notApplicable = evaluateFamilyApplicability('f12', zeroSignals);
  assert.equal(notApplicable.disposition, DISPOSITIONS.notApplicable);
  assert.equal(notApplicable.reasonCode, 'NO_EVENTS_DECLARED');
  const required = evaluateFamilyApplicability('f12', { ...zeroSignals, events: 2 });
  assert.equal(required.disposition, DISPOSITIONS.required);
  assert.equal(required.reasonCode, null);
  assert.deepEqual(required.observedSignals, { events: 2, messages: 0 });
  assert.throws(() => evaluateFamilyApplicability('f99', zeroSignals), /unknown census family/);
});
