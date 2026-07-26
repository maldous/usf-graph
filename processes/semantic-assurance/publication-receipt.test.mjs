import assert from 'node:assert/strict';
import test from 'node:test';

import {
  PUBLICATION_RECEIPT_SCHEMA_VERSION,
  REJECTED_RECEIPT_FIELDS,
  WITNESS_PHASES,
  WITNESS_TOTAL_SOURCE,
  assertSupportedPublicationReceipt,
  settledAuthorityDigest,
} from './publication-receipt.mjs';
import { authorityWitness } from './semantic-bootstrap-packet.mjs';
import { readSemanticAuthorityWitness, semanticAuthorityInventoryDigest } from './semantic-authority-gateway.mjs';

const digestOf = (hex) => `sha256:${String(hex).padEnd(64, '0')}`;

function receipt(overrides = {}, witnessOverrides = {}) {
  const phase = { digest: digestOf('ab'), graphCount: 2, triples: 3 };
  return {
    receiptSchemaVersion: PUBLICATION_RECEIPT_SCHEMA_VERSION,
    mode: 'commit',
    ok: true,
    authorityWitness: {
      algorithm: 'sha256-rdfc10-graph-inventory-v2',
      totalSource: WITNESS_TOTAL_SOURCE,
      beforePublication: { ...phase },
      afterPublication: { ...phase },
      settled: { ...phase, stable: true },
      ...witnessOverrides,
    },
    ...overrides,
  };
}

test('a well-formed receipt is accepted and yields exactly one authority digest', () => {
  const accepted = assertSupportedPublicationReceipt(receipt());
  assert.equal(accepted.authorityWitness.totalSource, WITNESS_TOTAL_SOURCE);
  assert.equal(settledAuthorityDigest(receipt()), digestOf('ab'));
});

// The core R5 adversarial case: the server's statement count is wrong, changing,
// or absent, while the graph content is byte-identical. The witness must not move.
test('an incorrect or drifting server count cannot alter the witness digest', async () => {
  const content = new Map([
    ['urn:usf:graph:a', '<urn:subject:a> <urn:predicate:value> "a" .\n'],
    ['urn:usf:graph:b', '<urn:subject:b> <urn:predicate:value> "b" .\n'],
  ]);
  const select = async () => [...content.keys()].map((graph) => ({ g: { value: graph } }));
  const construct = async (sparql) => content.get([...content.keys()].find((graph) => sparql.includes(`<${graph}>`)));

  // Every reading reports a different, and mostly wrong, server total. One of
  // them is the transient over-count that produced the superseded receipt digest.
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
    // The witness must not even consult the statistic.
    assert.equal(calls, 0, `server count was read for total=${count}`);
    assert.equal(gatewayWitness.totalSource, WITNESS_TOTAL_SOURCE);
    assert.equal(bootstrapWitness.totalSource, WITNESS_TOTAL_SOURCE);
  }
  assert.equal(digests.size, 1, 'digest changed with the server count');
  assert.deepEqual([...totals], [2], 'total is the inventory sum, not the server count');

  // And the digest still tracks content: change one graph, digest moves.
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
  // Folding any other total would produce a different digest — which is exactly
  // how the superseded receipt digest arose.
  assert.notEqual(witness.digest, semanticAuthorityInventoryDigest(witness.inventory, sum + 1));
});

test('a receipt carrying superseded server-count fields is rejected, not tolerated', () => {
  for (const field of REJECTED_RECEIPT_FIELDS) {
    assert.throws(
      () => assertSupportedPublicationReceipt(receipt({ [field]: 'anything' })),
      /superseded fields that are not authority witnesses/,
      field,
    );
  }
  // The historical shape in full.
  assert.throws(() => assertSupportedPublicationReceipt({
    mode: 'commit',
    ok: true,
    postAuthorityDigest: digestOf('f0b212be'),
    postTriples: 110_537,
  }), /unsupported publication receipt schema/);
});

test('an unsupported, absent, older or newer receipt schema fails closed', () => {
  for (const version of [undefined, null, 0, 1, 3, '2', {}]) {
    assert.throws(
      () => assertSupportedPublicationReceipt(receipt({ receiptSchemaVersion: version })),
      /unsupported publication receipt schema/,
      JSON.stringify(version ?? null),
    );
  }
  for (const value of [undefined, null, 'receipt', 42, []]) {
    assert.throws(() => assertSupportedPublicationReceipt(value), /absent or not an object/);
  }
});

test('a receipt whose total did not come from the canonical inventory is rejected', () => {
  for (const source of [undefined, null, 'db.size', 'server-statement-statistic', 'connectivity']) {
    assert.throws(
      () => assertSupportedPublicationReceipt(receipt({}, { totalSource: source })),
      /witness total must be derived from canonical-graph-inventory/,
      String(source),
    );
  }
  assert.throws(() => assertSupportedPublicationReceipt(receipt({ authorityWitness: undefined })), /no authority witness/);
});

test('every witness phase must be present and exact', () => {
  for (const phase of WITNESS_PHASES) {
    for (const broken of [
      undefined,
      { digest: 'not-a-digest', graphCount: 1, triples: 1 },
      { digest: digestOf('ab'), graphCount: -1, triples: 1 },
      { digest: digestOf('ab'), graphCount: 1, triples: 1.5 },
      { digest: digestOf('ab'), graphCount: 1 },
    ]) {
      const witnessOverrides = { [phase]: broken === undefined ? undefined : { ...broken, ...(phase === 'settled' ? { stable: true } : {}) } };
      assert.throws(
        () => assertSupportedPublicationReceipt(receipt({}, witnessOverrides)),
        new RegExp(`witness phase ${phase} is absent or malformed`),
        `${phase}: ${JSON.stringify(broken ?? null)}`,
      );
    }
  }
});

test('a settled witness that never stabilised is rejected', () => {
  for (const stable of [undefined, false, 'true', null]) {
    assert.throws(
      () => assertSupportedPublicationReceipt(receipt({}, {
        settled: { digest: digestOf('ab'), graphCount: 2, triples: 3, stable },
      })),
      /settled witness is not stable/,
      String(stable),
    );
  }
  // A settled digest differing from the post-publication reading is exactly the
  // unstable case the receipt now reports instead of hiding.
  assert.throws(() => assertSupportedPublicationReceipt(receipt({}, {
    afterPublication: { digest: digestOf('ab'), graphCount: 2, triples: 3 },
    settled: { digest: digestOf('cd'), graphCount: 2, triples: 3, stable: false },
  })), /settled witness is not stable/);
});

test('the only accessor for current authority runs the full guard', () => {
  assert.throws(() => settledAuthorityDigest(receipt({ postTriples: 1 })), /superseded fields/);
  assert.throws(() => settledAuthorityDigest(receipt({ receiptSchemaVersion: 1 })), /unsupported publication receipt schema/);
});
