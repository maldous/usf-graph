import assert from 'node:assert/strict';
import test from 'node:test';

import {
  StardogSemanticAuthorityError,
  createStardogSemanticAuthorityClient,
} from './semantic-authority.mjs';

const digest = `sha256:${'a'.repeat(64)}`;

function configuration(authentication = { mode: 'token', tokenReference: 'secret://semantic-authority/token' }) {
  return { accessMode: 'live', expectedAuthorityDigest: digest, endpoint: 'https://authority.example.test', database: 'USF', authentication };
}

function fakeSdk(overrides = {}) {
  class Connection {
    constructor(options) { this.options = options; fakeSdk.connection = this; }
  }
  const ok = { ok: true };
  return {
    Connection,
    db: {
      size: async () => ({ ok: true, body: 42 }),
      transaction: {
        begin: async () => ({ ok: true, transactionId: 'transaction' }),
        commit: async () => ok,
        rollback: async () => ok,
      },
      add: async () => ok,
      icv: {
        validateInTx: async () => ({ ok: true, body: true }),
        reportInTx: async () => ({ ok: true, body: 'report' }),
        validate: async () => ({ ok: true, body: true }),
        report: async () => ({ ok: true, body: 'report' }),
      },
      ...overrides.db,
    },
    query: {
      executeInTransaction: async () => ({ ok: true, body: { results: { bindings: [] } } }),
      execute: async () => ({ ok: true, body: { results: { bindings: [] } } }),
      ...overrides.query,
    },
  };
}

test('binds an explicitly resolved token without exposing a global clear operation', async () => {
  const sdk = fakeSdk();
  const client = createStardogSemanticAuthorityClient({ sdk, configuration: configuration(), resolveSecret: () => 'token-value' });
  assert.equal(client.expectedAuthorityDigest, digest);
  assert.equal(await client.connectivity(), 42);
  assert.equal(await client.begin(), 'transaction');
  assert.equal('clear' in client, false);
  assert.equal('clearDatabase' in client, false);
});

test('supports explicit basic-auth secret references', async () => {
  const sdk = fakeSdk();
  const authentication = { mode: 'basic', usernameReference: 'secret://semantic-authority/username', passwordReference: 'secret://semantic-authority/password' };
  const client = createStardogSemanticAuthorityClient({ sdk, configuration: configuration(authentication), resolveSecret: (reference) => reference.split('/').at(-1) });
  assert.equal(await client.size(), 42);
});

test('rejects invalid named graphs before any mutation call', async () => {
  const client = createStardogSemanticAuthorityClient({ sdk: fakeSdk(), configuration: configuration(), resolveSecret: () => 'token-value' });
  await assert.rejects(() => client.clearGraphs('transaction', ['not an iri']), /invalid named-graph IRI/);
  await assert.rejects(() => client.clearGraphs('transaction', []), /explicit named-graph IRIs/);
});

test('fails closed with redacted operational errors', async () => {
  const sdk = fakeSdk({ db: { size: async () => ({ ok: false, status: 401 }) } });
  const client = createStardogSemanticAuthorityClient({ sdk, configuration: configuration(), resolveSecret: () => 'sensitive-token' });
  await assert.rejects(() => client.connectivity(), (error) => error instanceof StardogSemanticAuthorityError && error.status === 401 && !error.message.includes('sensitive-token'));
});

const shaclReport = (conforms) => ({
  '@graph': [{
    '@type': 'sh:ValidationReport',
    'sh:conforms': { '@value': conforms },
  }],
});

test('resolves a non-true transaction response through the explicit conforming SHACL report', async () => {
  let reports = 0;
  const sdk = fakeSdk({ db: { icv: {
    validateInTx: async () => ({ ok: true, body: false }),
    reportInTx: async () => { reports += 1; return { ok: true, body: shaclReport(true) }; },
    validate: async () => ({ ok: true, body: true }),
    report: async () => ({ ok: true, body: shaclReport(true) }),
  } } });
  const client = createStardogSemanticAuthorityClient({ sdk, configuration: configuration(), resolveSecret: () => 'token-value' });
  const shapes = [{ file: 'shape.ttl', content: '@prefix sh: <http://www.w3.org/ns/shacl#> .' }];
  assert.equal(await client.validateInTransaction('transaction', shapes), true);
  const receipt = await client.validateInTransactionWithReceipt('transaction', shapes);
  assert.equal(receipt.conforms, true);
  assert.equal(receipt.validatedDocumentCount, 1);
  assert.match(receipt.validatedDocumentSetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(receipt.observationSetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(receipt.receiptDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(reports, 2);
});

test('returns false only for an explicit nonconforming SHACL report and fails closed on ambiguity', async () => {
  const make = (body) => createStardogSemanticAuthorityClient({
    sdk: fakeSdk({ db: { icv: {
      validateInTx: async () => ({ ok: true, body: false }),
      reportInTx: async () => ({ ok: true, body }),
      validate: async () => ({ ok: true, body: false }),
      report: async () => ({ ok: true, body }),
    } } }),
    configuration: configuration(),
    resolveSecret: () => 'token-value',
  });
  assert.equal(await make(shaclReport(false)).validateInTransaction('transaction', 'shape'), false);
  await assert.rejects(() => make({ '@graph': [] }).validateInTransaction('transaction', 'shape'), /explicit SHACL conformance result/);
});
