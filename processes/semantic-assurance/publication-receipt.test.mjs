import assert from 'node:assert/strict';
import test from 'node:test';

import {
  PUBLICATION_MODES,
  PUBLICATION_RECEIPT_SCHEMA_VERSION,
  REJECTED_RECEIPT_FIELDS,
  WITNESS_ALGORITHM,
  WITNESS_PHASES,
  WITNESS_TOTAL_SOURCE,
  assertSupportedPublicationReceipt,
  settledAuthorityDigest,
} from './publication-receipt.mjs';
import { authorityWitness } from './semantic-bootstrap-packet.mjs';
import { readSemanticAuthorityWitness, semanticAuthorityInventoryDigest } from './semantic-authority-gateway.mjs';

const ORIGINAL = `sha256:${'a1'.repeat(32)}`;
const PUBLISHED = `sha256:${'b2'.repeat(32)}`;
const OTHER = `sha256:${'c3'.repeat(32)}`;
const phase = (digest, graphCount = 40, triples = 107_219) => ({ digest, graphCount, triples });

// A complete, well-formed receipt. Every case below mutates exactly one thing, so
// each rejection is attributable to that one thing.
function validateReceipt(overrides = {}, witnessOverrides = {}) {
  return {
    receiptSchemaVersion: PUBLICATION_RECEIPT_SCHEMA_VERSION,
    mode: 'validate',
    ok: true,
    authorityWitness: {
      algorithm: WITNESS_ALGORITHM,
      totalSource: WITNESS_TOTAL_SOURCE,
      expected: ORIGINAL,
      evaluated: ORIGINAL,
      beforePublication: phase(ORIGINAL),
      afterPublication: phase(ORIGINAL),
      settled: { ...phase(ORIGINAL), stable: true },
      ...witnessOverrides,
    },
    ...overrides,
  };
}

// commit mode legitimately moves authority, so before differs from after/settled.
function commitReceipt(witnessOverrides = {}) {
  return {
    receiptSchemaVersion: PUBLICATION_RECEIPT_SCHEMA_VERSION,
    mode: 'commit',
    ok: true,
    authorityWitness: {
      algorithm: WITNESS_ALGORITHM,
      totalSource: WITNESS_TOTAL_SOURCE,
      expected: ORIGINAL,
      evaluated: ORIGINAL,
      beforePublication: phase(ORIGINAL),
      afterPublication: phase(PUBLISHED),
      settled: { ...phase(PUBLISHED), stable: true },
      ...witnessOverrides,
    },
  };
}

test('a well-formed receipt is accepted in both modes and yields exactly one authority digest', () => {
  assert.equal(settledAuthorityDigest(validateReceipt()), ORIGINAL);
  assert.equal(settledAuthorityDigest(commitReceipt()), PUBLISHED);
  assert.deepEqual([...PUBLICATION_MODES], ['validate', 'commit']);
});

// --- the review finding: stability must be proven, never trusted ---------------

test('forged stable:true is rejected when the phase witnesses disagree', () => {
  // Different digests, stability asserted by the receipt about itself.
  assert.throws(() => assertSupportedPublicationReceipt(commitReceipt({
    afterPublication: phase(PUBLISHED),
    settled: { ...phase(OTHER), stable: true },
  })), /settled witness does not equal the post-publication witness/);
  // And the accessor cannot be used to sidestep the guard.
  assert.throws(() => settledAuthorityDigest(commitReceipt({
    afterPublication: phase(PUBLISHED),
    settled: { ...phase(OTHER), stable: true },
  })), /settled witness does not equal the post-publication witness/);
});

test('equal digests with different counts are not stable', () => {
  for (const settled of [
    { ...phase(PUBLISHED, 39, 107_219), stable: true },
    { ...phase(PUBLISHED, 40, 107_218), stable: true },
    { ...phase(PUBLISHED, 0, 0), stable: true },
  ]) {
    assert.throws(
      () => assertSupportedPublicationReceipt(commitReceipt({ afterPublication: phase(PUBLISHED), settled })),
      /settled witness does not equal the post-publication witness/,
      JSON.stringify(settled),
    );
  }
});

test('a declared stable flag must agree with the derived result and is never evidence', () => {
  // Genuinely stable phases but the receipt declares otherwise: still rejected,
  // because a receipt that contradicts itself is not a receipt to act on.
  for (const declared of [false, 'true', 0, null]) {
    assert.throws(() => assertSupportedPublicationReceipt(validateReceipt({}, {
      settled: { ...phase(ORIGINAL), stable: declared },
    })), /settled\.stable declares .* but the phase records derive true/, String(declared));
  }
  // Omitting the flag entirely is fine: stability is derived, not read.
  const withoutFlag = validateReceipt({}, { settled: phase(ORIGINAL) });
  assert.equal(settledAuthorityDigest(withoutFlag), ORIGINAL);
});

// --- digest syntax, algorithm and counts --------------------------------------

test('every digest must be exact lowercase sha256 hex', () => {
  const bad = [
    `sha256:${'A1'.repeat(32)}`, // uppercase hex
    `SHA256:${'a1'.repeat(32)}`, // uppercase scheme
    `sha256:${'a1'.repeat(31)}`, // too short
    `sha256:${'a1'.repeat(33)}`, // too long
    `sha256:${'g1'.repeat(32)}`, // non-hex
    'a1'.repeat(32), // no prefix
    `sha1:${'a1'.repeat(32)}`,
    `sha256:${'a1'.repeat(32)} `,
    '', null, undefined, 42, {},
  ];
  for (const value of bad) {
    for (const field of ['expected', 'evaluated']) {
      assert.throws(
        () => assertSupportedPublicationReceipt(validateReceipt({}, { [field]: value })),
        /is not an exact lowercase sha256/,
        `${field}=${JSON.stringify(value ?? null)}`,
      );
    }
    for (const phaseName of WITNESS_PHASES) {
      const broken = phaseName === 'settled' ? { digest: value, graphCount: 40, triples: 1 } : { digest: value, graphCount: 40, triples: 1 };
      assert.throws(
        () => assertSupportedPublicationReceipt(validateReceipt({}, { [phaseName]: broken })),
        /is not an exact lowercase sha256/,
        `${phaseName}=${JSON.stringify(value ?? null)}`,
      );
    }
  }
});

test('graph and triple counts must be non-negative safe integers', () => {
  for (const value of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 2, '40', null, undefined, true, {}]) {
    for (const key of ['graphCount', 'triples']) {
      assert.throws(() => assertSupportedPublicationReceipt(validateReceipt({}, {
        settled: { ...phase(ORIGINAL), [key]: value, stable: true },
      })), /is not a non-negative safe integer/, `${key}=${JSON.stringify(value ?? null)}`);
    }
  }
});

test('the witness algorithm must be exactly the published one', () => {
  for (const algorithm of [undefined, null, '', 'sha256-rdfc10-graph-inventory-v1', 'sha256', 'SHA256-RDFC10-GRAPH-INVENTORY-V2']) {
    assert.throws(
      () => assertSupportedPublicationReceipt(validateReceipt({}, { algorithm })),
      /witness algorithm must be sha256-rdfc10-graph-inventory-v2/,
      String(algorithm),
    );
  }
});

test('a witness total that did not come from the canonical inventory is rejected', () => {
  for (const source of [undefined, null, 'db.size', 'server-statement-statistic', 'connectivity']) {
    assert.throws(
      () => assertSupportedPublicationReceipt(validateReceipt({}, { totalSource: source })),
      /witness total must be derived from canonical-graph-inventory/,
      String(source),
    );
  }
  assert.throws(() => assertSupportedPublicationReceipt(validateReceipt({ authorityWitness: undefined })), /has no authority witness/);
  for (const witness of [null, 'witness', 42, []]) {
    assert.throws(() => assertSupportedPublicationReceipt(validateReceipt({ authorityWitness: witness })), /has no authority witness/);
  }
});

test('every witness phase must be present and structurally complete', () => {
  for (const phaseName of WITNESS_PHASES) {
    for (const broken of [undefined, null, 'digest', 42, [], {}, { digest: ORIGINAL }, { graphCount: 1, triples: 1 }]) {
      assert.throws(
        () => assertSupportedPublicationReceipt(validateReceipt({}, { [phaseName]: broken })),
        /witness phase .* (is absent or not an object|digest is not an exact|graphCount is not a non-negative|triples is not a non-negative)/,
        `${phaseName}: ${JSON.stringify(broken ?? null)}`,
      );
    }
  }
});

// --- mode-specific authority relationships ------------------------------------

test('expected, evaluated and beforePublication must describe one operation', () => {
  // beforePublication is the compare-and-swap target the publication asserted.
  assert.throws(() => assertSupportedPublicationReceipt(commitReceipt({
    beforePublication: phase(OTHER),
  })), /beforePublication .* does not equal the expected authority/);
  // The compiler must have evaluated the authority it was told to expect.
  assert.throws(() => assertSupportedPublicationReceipt(commitReceipt({
    evaluated: OTHER,
  })), /evaluated .* does not equal the expected authority/);
  assert.throws(() => assertSupportedPublicationReceipt(validateReceipt({}, {
    expected: OTHER,
  })), /beforePublication .* does not equal the expected authority/);
});

test('validate mode must prove authority was restored after rollback', () => {
  // A validate receipt whose settled authority is not the original means the
  // rollback did not restore it, whatever else the receipt claims.
  assert.throws(() => assertSupportedPublicationReceipt(validateReceipt({}, {
    afterPublication: phase(PUBLISHED),
    settled: { ...phase(PUBLISHED), stable: true },
  })), /validate mode did not restore the original authority/);
  // commit mode legitimately moves authority, so the same shape is accepted there.
  assert.equal(settledAuthorityDigest(commitReceipt()), PUBLISHED);
});

test('the publication mode must be an explicit known mode', () => {
  for (const mode of [undefined, null, '', 'dry-run', 'COMMIT', 'apply', 42]) {
    assert.throws(() => assertSupportedPublicationReceipt(validateReceipt({ mode })), /mode must be one of validate, commit/, String(mode));
  }
});

// --- superseded fields and schema versions ------------------------------------

test('a receipt carrying superseded server-count fields is rejected, not tolerated', () => {
  for (const field of REJECTED_RECEIPT_FIELDS) {
    assert.throws(
      () => assertSupportedPublicationReceipt(validateReceipt({ [field]: 'anything' })),
      /carries superseded fields that are not authority witnesses/,
      field,
    );
  }
  // The historical receipt shape in full: rejected on version before any field.
  assert.throws(() => assertSupportedPublicationReceipt({
    mode: 'commit',
    ok: true,
    postAuthorityDigest: `sha256:${'f0'.repeat(32)}`,
    postTriples: 110_537,
  }), /schema is unsupported/);
});

test('an unsupported, absent, older or newer receipt schema fails closed', () => {
  for (const version of [undefined, null, 0, 1, 3, 99, '2', {}, []]) {
    assert.throws(
      () => assertSupportedPublicationReceipt(validateReceipt({ receiptSchemaVersion: version })),
      /schema is unsupported/,
      JSON.stringify(version ?? null),
    );
  }
  for (const value of [undefined, null, 'receipt', 42, []]) {
    assert.throws(() => assertSupportedPublicationReceipt(value), /is absent or not an object/);
  }
});

// --- the witness itself remains content-only ----------------------------------

test('an incorrect or drifting server count cannot alter the witness digest', async () => {
  const content = new Map([
    ['urn:usf:graph:a', '<urn:subject:a> <urn:predicate:value> "a" .\n'],
    ['urn:usf:graph:b', '<urn:subject:b> <urn:predicate:value> "b" .\n'],
  ]);
  const select = async () => [...content.keys()].map((graph) => ({ g: { value: graph } }));
  const construct = async (sparql) => content.get([...content.keys()].find((graph) => sparql.includes(`<${graph}>`)));

  const counts = [2, 110_537, 0, 999_999, -1];
  const digests = new Set();
  const totals = new Set();
  for (const count of counts) {
    let calls = 0;
    const client = { size: async () => { calls += 1; return count; }, connectivity: async () => count, select, construct };
    const gatewayWitness = await readSemanticAuthorityWitness(client);
    const bootstrapWitness = await authorityWitness(client);
    digests.add(gatewayWitness.digest);
    digests.add(`sha256:${bootstrapWitness.digest}`);
    totals.add(gatewayWitness.triples);
    totals.add(bootstrapWitness.triples);
    assert.equal(calls, 0, `server count was read for total=${count}`);
    assert.equal(gatewayWitness.totalSource, WITNESS_TOTAL_SOURCE);
    assert.equal(bootstrapWitness.totalSource, WITNESS_TOTAL_SOURCE);
  }
  assert.equal(digests.size, 1, 'digest changed with the server count');
  assert.deepEqual([...totals], [2], 'total is the inventory sum, not the server count');

  content.set('urn:usf:graph:b', '<urn:subject:b> <urn:predicate:value> "changed" .\n');
  const moved = await readSemanticAuthorityWitness({ select, construct });
  assert.equal([...digests][0] === moved.digest, false);
});

test('the witness total equals the inventory sum, which is what the digest folds', async () => {
  const content = new Map([
    ['urn:usf:graph:a', '<urn:s:a> <urn:p> "1" .\n<urn:s:a2> <urn:p> "2" .\n'],
    ['urn:usf:graph:b', '<urn:s:b> <urn:p> "3" .\n'],
  ]);
  const witness = await readSemanticAuthorityWitness({
    select: async () => [...content.keys()].map((graph) => ({ g: { value: graph } })),
    construct: async (sparql) => content.get([...content.keys()].find((graph) => sparql.includes(`<${graph}>`))),
  });
  const sum = witness.inventory.reduce((total, record) => total + record.triples, 0);
  assert.equal(witness.triples, sum);
  assert.equal(witness.triples, 3);
  assert.equal(witness.digest, semanticAuthorityInventoryDigest(witness.inventory, sum));
  assert.notEqual(witness.digest, semanticAuthorityInventoryDigest(witness.inventory, sum + 1));
});
