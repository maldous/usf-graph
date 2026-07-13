import assert from 'node:assert/strict';
import test from 'node:test';
import { classifySparql } from '../src/sparql-guard.js';
import { makeRedactor, callTool, cappedSelect, TOOLS } from '../src/mcp.js';
import { validContractRef, authorityDigest, bootstrapPacket } from '../src/bootstrap.js';

test('read-only query forms are accepted', () => {
  assert.equal(classifySparql('SELECT ?s WHERE { ?s ?p ?o }').form, 'SELECT');
  assert.equal(classifySparql('ASK { ?s ?p ?o }').form, 'ASK');
  assert.equal(classifySparql('CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }').form, 'CONSTRUCT');
  assert.equal(classifySparql('DESCRIBE <urn:usf:x>').form, 'DESCRIBE');
  assert.equal(
    classifySparql('PREFIX usf: <urn:usf:ontology:>\nSELECT ?s WHERE { ?s a usf:Service }').form,
    'SELECT'
  );
});

test('every mutation operation is rejected, fail-closed', () => {
  for (const op of [
    'INSERT DATA { <urn:a> <urn:b> <urn:c> }',
    'DELETE WHERE { ?s ?p ?o }',
    'DELETE { ?s ?p ?o } INSERT { ?s ?p ?o } WHERE { ?s ?p ?o }',
    'LOAD <urn:g>',
    'CLEAR GRAPH <urn:g>',
    'DROP GRAPH <urn:g>',
    'CREATE GRAPH <urn:g>',
    'COPY <urn:a> TO <urn:b>',
    'MOVE <urn:a> TO <urn:b>',
    'ADD <urn:a> TO <urn:b>',
    'WITH <urn:g> DELETE {} WHERE {}',
    '',
    'not a query at all',
  ]) {
    assert.equal(classifySparql(op).readOnly, false, `should reject: ${op}`);
  }
});

test('a mutation keyword inside a literal or comment does not fool the guard', () => {
  // DELETE lives only in a string literal -> still a read.
  assert.equal(classifySparql('SELECT ?s WHERE { ?s rdfs:label "please DELETE me" }').form, 'SELECT');
  // A real DELETE after a comment line -> still rejected.
  assert.equal(classifySparql('# harmless comment\nDELETE WHERE { ?s ?p ?o }').readOnly, false);
  // A prefixed local name merely containing a keyword is fine.
  assert.equal(classifySparql('SELECT ?x WHERE { ?x usf:createdAt ?t }').form, 'SELECT');
});

test('usf_query refuses mutations before touching Stardog', async () => {
  let touched = false;
  const client = { select: async () => { touched = true; return []; } };
  await assert.rejects(
    () => callTool('usf_query', { sparql: 'DROP GRAPH <urn:g>' }, { client, config: {} }),
    /refused: mutation keyword DROP/
  );
  assert.equal(touched, false);
});

test('a broad SELECT gets a server-side LIMIT; existing LIMIT/VALUES are untouched', async () => {
  assert.match(cappedSelect('SELECT ?s WHERE { ?s ?p ?o }'), /LIMIT 201$/);
  const withLimit = 'SELECT ?s WHERE { ?s ?p ?o } LIMIT 5';
  assert.equal(cappedSelect(withLimit), withLimit);
  const withInnerLimit = 'SELECT ?s WHERE { { SELECT ?s WHERE { ?s ?p ?o } LIMIT 10 } }';
  assert.equal(cappedSelect(withInnerLimit), withInnerLimit);
  const withValues = 'SELECT ?s WHERE { ?s ?p ?o } VALUES ?s { <urn:a> }';
  assert.equal(cappedSelect(withValues), withValues);
  // and the tool actually sends the capped query to Stardog
  let sent = null;
  const client = { select: async (q) => { sent = q; return []; } };
  await callTool('usf_query', { sparql: 'SELECT ?s WHERE { ?s ?p ?o }' }, { client, config: {} });
  assert.match(sent, /LIMIT 201$/);
});

test('usf_query caps SELECT rows and reports truncation', async () => {
  const many = Array.from({ length: 300 }, (_, i) => ({ s: { value: `urn:${i}` } }));
  const client = { select: async () => many };
  const out = await callTool('usf_query', { sparql: 'SELECT ?s WHERE { ?s ?p ?o }' }, { client, config: {} });
  assert.equal(out.form, 'SELECT');
  assert.equal(out.truncated, true);
  assert.equal(out.rowCount, 200);
  assert.equal(out.bindings.length, 200);
});

test('usf_health reports size through the client', async () => {
  const client = { size: async () => 577473 };
  const config = { endpoint: 'https://x', database: 'USF', auth: { kind: 'token' } };
  const out = await callTool('usf_health', {}, { client, config });
  assert.equal(out.triples, 577473);
  assert.equal(out.ok, true);
  assert.equal(out.database, 'USF');
});

test('redactor removes the live token from output', () => {
  const redact = makeRedactor({ auth: { kind: 'token', token: 'super-secret-token-abc123' } });
  const text = redact('error: token super-secret-token-abc123 rejected');
  assert.equal(text.includes('super-secret-token-abc123'), false);
  assert.match(text, /\*\*\*/);
});

test('tool names are model-callable (no dots)', () => {
  for (const t of TOOLS) assert.match(t.name, /^[a-z0-9_]+$/);
});

test('contract references are validated (blocks SPARQL injection)', () => {
  assert.equal(validContractRef('abacpolicydecisionpoint'), true);
  assert.equal(validContractRef('urn:usf:contract:foo'), true);
  assert.equal(validContractRef('x"} ; DROP GRAPH <urn:g>'), false);
  assert.equal(validContractRef('has space'), false);
  assert.equal(validContractRef(''), false);
});

test('authority digest is deterministic and order-independent', () => {
  const a = authorityDigest([{ graph: 'g:a', triples: 1 }, { graph: 'g:b', triples: 2 }], 3);
  const b = authorityDigest([{ graph: 'g:b', triples: 2 }, { graph: 'g:a', triples: 1 }], 3);
  assert.equal(a, b);
  assert.notEqual(a, authorityDigest([{ graph: 'g:a', triples: 9 }], 9));
});

test('bootstrap contract packet assembles the traceability chain', async () => {
  const client = {
    select: async (q) => {
      if (q.includes('LIMIT 1')) return [{ c: { value: 'urn:usf:contract:x' }, cn: { value: 'x' }, state: { value: 'urn:usf:lifecycle:active' } }];
      if (q.includes('asserts')) return [
        { rel: { value: 'urn:usf:ontology:asserts' }, cn: { value: 'urn:usf:claim:c1' } },
        { rel: { value: 'urn:usf:ontology:disclaims' }, cn: { value: 'urn:usf:nonclaim:n1' } },
      ];
      if (q.includes('declaresFacet')) return [{ kind: { value: 'urn:usf:facetkind:security' }, status: { value: 'urn:usf:facetstatus:asserted' }, stmt: { value: 'must encrypt' } }];
      if (q.includes('realisesContract')) return [{ state: { value: 'urn:usf:realisationstate:realised' }, impl: { value: 'urn:usf:impl:i1' } }];
      if (q.includes('obligationFor')) return [{ type: { value: 'urn:usf:ontology:ProofObligation' }, rung: { value: 'urn:usf:rung:unit' } }];
      return [];
    },
  };
  const ctx = { client, config: { endpoint: 'https://x', database: 'USF', auth: { kind: 'token' } } };
  const packet = await bootstrapPacket(ctx, { contract: 'x' });
  assert.equal(packet.found, true);
  assert.equal(packet.contract.canonicalName, 'x');
  assert.equal(packet.contract.lifecycleState, 'active');
  assert.deepEqual(packet.claims, ['c1']);
  assert.deepEqual(packet.nonClaims, ['n1']);
  assert.equal(packet.facets[0].kind, 'security');
  assert.equal(packet.realisations[0].state, 'realised');
  assert.equal(packet.obligations[0].type, 'ProofObligation');
});

test('bootstrap refuses an injecting contract reference before querying', async () => {
  let touched = false;
  const client = { select: async () => { touched = true; return []; } };
  await assert.rejects(
    () => bootstrapPacket({ client, config: {} }, { contract: 'x"} ; DROP GRAPH <urn:g>' }),
    /invalid contract reference/
  );
  assert.equal(touched, false);
});

test('standard discovery probes get empty results, not method-not-found', async () => {
  // Codex probes resources/templates/prompts regardless of advertised
  // capabilities; a -32601 there surfaces as discovery errors in the agent.
  const { PassThrough } = await import('node:stream');
  const { runMcpServer } = await import('../src/mcp.js');
  const env = { ...process.env };
  process.env.STARDOG_SERVER = 'https://example.stardog.cloud:5820';
  process.env.STARDOG_TOKEN = 'test-token';
  const input = new PassThrough();
  const output = new PassThrough();
  const done = runMcpServer({ input, output });
  for (const [id, method] of [
    [1, 'initialize'], [2, 'resources/list'], [3, 'resources/templates/list'],
    [4, 'prompts/list'], [5, 'no/such/method'],
  ]) {
    input.write(JSON.stringify({ jsonrpc: '2.0', id, method, params: {} }) + '\n');
  }
  input.end();
  await done;
  process.env = env;
  const replies = output.read().toString().trim().split('\n').map((l) => JSON.parse(l));
  const byId = Object.fromEntries(replies.map((r) => [r.id, r]));
  assert.deepEqual(byId[2].result, { resources: [] });
  assert.deepEqual(byId[3].result, { resourceTemplates: [] });
  assert.deepEqual(byId[4].result, { prompts: [] });
  assert.equal(byId[5].error.code, -32601);
});
