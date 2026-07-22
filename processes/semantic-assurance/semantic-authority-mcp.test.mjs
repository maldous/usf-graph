import assert from 'node:assert/strict';
import test from 'node:test';
import { classifySparql } from './sparql-guard.mjs';
import { makeRedactor, callTool, cappedSelect, TOOLS } from './semantic-authority-mcp.mjs';
import { BOOTSTRAP_TRACE, MAX_BOOTSTRAP_BINDINGS, MAX_BOOTSTRAP_BYTES, MAX_BOOTSTRAP_DEPTH, validContractRef, authorityDigest, authorityWitness, bootstrapPacket } from './semantic-bootstrap-packet.mjs';

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
  assert.deepEqual(TOOLS.map((tool) => tool.name), [
    'usf_health', 'usf_query', 'usf_bootstrap', 'usf_layout_context',
    'usf_layout_plan', 'usf_layout_validate', 'usf_materialise',
    'usf_artifact_describe', 'usf_artifact_verify', 'usf_contract_project',
    'usf_work_plan', 'usf_evidence_admit', 'usf_proof_evaluate',
    'usf_validation_record',
  ]);
  const workPlan = TOOLS.find((tool) => tool.name === 'usf_work_plan');
  assert.deepEqual(workPlan.inputSchema.properties.offset, {
    type: 'integer', minimum: 0, maximum: 10000,
  });
});

test('lifecycle mutation tools advertise the boundary but refuse direct RDF mutation', async () => {
  for (const name of ['usf_evidence_admit', 'usf_proof_evaluate', 'usf_validation_record']) {
    await assert.rejects(
      () => callTool(name, { authorityDigest: `sha256:${'0'.repeat(64)}`, semanticResource: 'urn:usf:test' }, { client: {}, config: {} }),
      /coordinator-only.*compiler.*single transaction/,
    );
  }
});

test('contract references are validated (blocks SPARQL injection)', () => {
  assert.equal(validContractRef('abacpolicydecisionpoint'), true);
  assert.equal(validContractRef('urn:usf:contract:foo'), true);
  assert.equal(validContractRef('x"} ; DROP GRAPH <urn:g>'), false);
  assert.equal(validContractRef('has space'), false);
  assert.equal(validContractRef(''), false);
});

test('authority digest is deterministic and order-independent', () => {
  const a = authorityDigest([{ graph: 'g:a', sha256: 'a', triples: 1 }, { graph: 'g:b', sha256: 'b', triples: 2 }], 3);
  const b = authorityDigest([{ graph: 'g:b', sha256: 'b', triples: 2 }, { graph: 'g:a', sha256: 'a', triples: 1 }], 3);
  assert.equal(a, b);
  assert.notEqual(a, authorityDigest([{ graph: 'g:a', sha256: 'a', triples: 9 }], 9));
  assert.notEqual(a, authorityDigest([{ graph: 'g:a', sha256: 'changed', triples: 1 }, { graph: 'g:b', sha256: 'b', triples: 2 }], 3));
});

test('authority witness changes after an equal-cardinality semantic substitution', async () => {
  let object = 'first';
  const client = {
    size: async () => 1,
    select: async () => [{ g: { value: 'urn:g' } }],
    construct: async () => `<urn:s> <urn:p> "${object}" .\n`,
  };
  const first = await authorityWitness(client);
  object = 'second';
  const second = await authorityWitness(client);
  assert.equal(first.triples, second.triples);
  assert.equal(first.inventory[0].triples, second.inventory[0].triples);
  assert.notEqual(first.digest, second.digest);
});

test('bootstrap contract packet assembles the traceability chain', async () => {
  const client = {
    size: async () => 3,
    construct: async () => '<urn:s> <urn:p> "first" .\n',
    select: async (q) => {
      if (q.includes('SELECT DISTINCT ?g')) return [{ g: { value: 'urn:g' } }];
      if (q.includes('SELECT ?c ?cn')) return [{ c: { value: 'urn:usf:contract:x' }, cn: { value: 'x' }, state: { value: 'urn:usf:contractactivationstate:active' } }];
      if (q.includes('?relation ?id')) return [
        { relation: { value: 'urn:usf:ontology:asserts' }, id: { value: 'urn:usf:claim:c1' }, canonicalName: { value: 'c1' } },
        { relation: { value: 'urn:usf:ontology:disclaims' }, id: { value: 'urn:usf:nonclaim:n1' }, canonicalName: { value: 'n1' } },
      ];
      if (q.includes('a <urn:usf:ontology:EvidenceRequirement>')) return [{ id: { value: 'urn:usf:evidencerequirement:e1' } }];
      if (q.includes('a <urn:usf:ontology:EvidenceResult>')) return [{ id: { value: 'urn:usf:evidenceresult:e1' }, admission: { value: 'urn:usf:evidenceadmissionstate:admitted' } }];
      if (q.includes('a <urn:usf:ontology:ProofObligation>')) return [{ id: { value: 'urn:usf:proofobligation:p1' }, requirement: { value: 'urn:usf:evidencerequirement:e1' } }];
      if (q.includes('a <urn:usf:ontology:ProofEvaluation>')) return [{ id: { value: 'urn:usf:proofevaluation:p1' }, obligation: { value: 'urn:usf:proofobligation:p1' } }];
      if (q.includes('a <urn:usf:ontology:ProofResult>')) return [{ id: { value: 'urn:usf:proofresult:p1' }, state: { value: 'urn:usf:proofresultstate:successful' }, evidenceSetDigest: { value: 'sha256:e1' } }];
      if (q.includes('a <urn:usf:ontology:Realisation>')) return [{ id: { value: 'urn:usf:realisation:r1' }, state: { value: 'urn:usf:realisationstate:implementable' }, decision: { value: 'urn:usf:decision:d1' }, path: { value: 'census/local-semantic-validation' } }];
      if (q.includes('authorisedByDecision')) return [{ id: { value: 'urn:usf:decision:d1' }, state: { value: 'urn:usf:decisionstate:accepted' }, path: { value: 'census/local-semantic-validation' }, type: { value: 'urn:usf:ontology:Implementation' } }];
      if (q.includes('a <urn:usf:ontology:ValidationObligation>')) return [{ id: { value: 'urn:usf:validationobligation:v1' } }];
      if (q.includes('a <urn:usf:ontology:ValidationExecution>')) return [];
      if (q.includes('a <urn:usf:ontology:ValidationResult>')) return [{
        id: { value: 'urn:usf:validationresult:v1' },
        execution: { value: 'urn:usf:validationexecution:v1' },
        state: { value: 'urn:usf:resultstate:passed' },
        evidence: { value: 'urn:usf:evidenceresult:v1' },
        evidenceType: { value: 'urn:usf:ontology:ValidationEvidence' },
        admission: { value: 'urn:usf:evidenceadmissionstate:admitted' },
        freshness: { value: 'urn:usf:evidencefreshnessstate:fresh' },
        integrity: { value: 'urn:usf:evidenceintegritystate:valid' },
        within: { value: 'true' },
        applicable: { value: 'urn:usf:validationobligation:v1' },
        obligation: { value: 'urn:usf:validationobligation:v1' },
      }];
      if (q.includes('declaresFacet')) return [{ id: { value: 'urn:usf:facet:f1' }, kind: { value: 'urn:usf:facetkind:security' }, statement: { value: 'must encrypt' } }];
      return [];
    },
  };
  const ctx = { client, config: { endpoint: 'https://x', database: 'USF', auth: { kind: 'token' } } };
  const packet = await bootstrapPacket(ctx, { contract: 'x' });
  assert.equal(packet.found, true);
  assert.equal(packet.traceability, BOOTSTRAP_TRACE);
  assert.equal(packet.contracts[0].canonicalName, 'x');
  assert.equal(packet.contracts[0].activationState, 'active');
  assert.equal(packet.contracts[0].actionable, true);
  assert.equal(packet.claims[0].id, 'urn:usf:claim:c1');
  assert.equal(packet.evidenceRequirements[0].id, 'urn:usf:evidencerequirement:e1');
  assert.equal(packet.evidenceResults[0].admissionState, 'admitted');
  assert.equal(packet.proofResults[0].evidenceSetDigest, 'sha256:e1');
  assert.equal(packet.validationObligations[0].id, 'urn:usf:validationobligation:v1');
  assert.equal(packet.validationResults[0].current, true);
  assert.equal(packet.bounds.maximumTraversalDepth, MAX_BOOTSTRAP_DEPTH);
  assert.ok(packet.serializedBytes <= MAX_BOOTSTRAP_BYTES);
  assert.ok(packet.bindingCount <= MAX_BOOTSTRAP_BINDINGS);
});

test('bootstrap continuation is deterministic and invalidates after digest change', async () => {
  let triples = 60;
  const claims = Array.from({ length: 80 }, (_, index) => ({ relation: { value: 'urn:usf:ontology:asserts' }, id: { value: `urn:usf:claim:c${index}` }, canonicalName: { value: `c${index}` } }));
  const client = {
    size: async () => triples,
    construct: async () => `<urn:s> <urn:p> "${triples}" .\n`,
    select: async (q) => {
      if (q.includes('SELECT DISTINCT ?g')) return [{ g: { value: 'urn:g' } }];
      if (q.includes('SELECT ?c ?cn')) return [{ c: { value: 'urn:usf:contract:x' }, cn: { value: 'x' }, state: { value: 'urn:usf:contractactivationstate:active' } }];
      if (q.includes('?relation ?id')) return claims;
      return [];
    },
  };
  const ctx = { client, config: { database: 'USF' } };
  const first = await bootstrapPacket(ctx, { contract: 'x' });
  const repeat = await bootstrapPacket(ctx, { contract: 'x' });
  assert.equal(first.truncated, true);
  assert.equal(first.continuation, repeat.continuation);
  assert.ok(first.serializedBytes <= MAX_BOOTSTRAP_BYTES);
  const second = await bootstrapPacket(ctx, { contract: 'x', continuation: first.continuation });
  assert.notEqual(second.claims[0]?.id, first.claims[0]?.id);
  triples = 61;
  await assert.rejects(() => bootstrapPacket(ctx, { contract: 'x', continuation: first.continuation }), /authority digest no longer matches/);
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
  const { runMcpServer } = await import('./semantic-authority-mcp.mjs');
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
