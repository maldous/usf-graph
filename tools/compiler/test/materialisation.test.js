import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  applyLayoutPlan, createLayoutPlan, digest, layoutContext, refuseLifecycleMutation,
  sourceDigest, validateLayoutPlan, verifyArtifact,
} from '../src/materialisation.js';

const contract = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const family = 'urn:usf:artefactfamily:compiler';
const format = 'urn:usf:representationformat:ecmascriptmodule';
const role = 'urn:usf:pathrole:compilersource';

function binding(value) { return { value }; }
function fakeClient({ descriptor } = {}) {
  return {
    size: async () => 10,
    select: async (query) => {
      if (query.includes('COUNT(*) AS ?triples')) return [{ g: binding('urn:g'), triples: binding('10') }];
      if (query.includes('?canonicalName ?lifecycle')) return [{
        canonicalName: binding('repositoryexternalartefactmaterialisation'),
        lifecycle: binding('urn:usf:semanticlifecyclestate:active'),
        activation: binding('urn:usf:contractactivationstate:active'),
        proof: binding('urn:usf:proofresult:repositoryexternalartefactmaterialisation'),
        proofState: binding('urn:usf:proofresultstate:successful'),
        decision: binding('urn:usf:realisationdecision:repositoryexternalartefactmaterialisation'),
        decisionState: binding('urn:usf:decisionstate:accepted'),
        authorisedPath: binding('tools/compiler'),
      }];
      if (query.includes('a <urn:usf:ontology:PathRole>')) return [{ role: binding(role), canonicalName: binding('compilersource'), parent: binding('tools/compiler'), onDemand: binding('true') }];
      if (query.includes('a <urn:usf:ontology:ArtefactFamily>')) return [{ family: binding(family), familyName: binding('compiler'), storage: binding('urn:usf:storageclass:gittrackedsource'), pathRole: binding(role), format: binding(format), namingPattern: binding('^[A-Za-z0-9._-]+$') }];
      if (query.includes('ExternalPayloadDescriptor')) return descriptor ? [Object.fromEntries(Object.entries(descriptor).map(([key, item]) => [key, binding(item)]))] : [];
      return [];
    },
  };
}

test('layout context is live-digest-bound and exposes active proof and authorised paths', async () => {
  const context = await layoutContext({ client: fakeClient() });
  assert.match(context.authorityDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(context.contract.activationState, 'urn:usf:contractactivationstate:active');
  assert.equal(context.contract.proofResultState, 'urn:usf:proofresultstate:successful');
  assert.deepEqual(context.authorisedPaths, ['tools/compiler']);
});

test('layout plan validates exact content, path role, family, format, digest and authority', async () => {
  const ctx = { client: fakeClient() };
  const content = 'export const value = 1;\n';
  const operations = [{ action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'tools/compiler/src/value.js', pathRole: role, representationFormat: format }];
  const plan = await createLayoutPlan(ctx, { contract, operations });
  assert.equal((await validateLayoutPlan(ctx, plan)).ok, true);
  const tampered = structuredClone(plan);
  tampered.operations[0].content = 'different';
  const validation = await validateLayoutPlan(ctx, tampered);
  assert.equal(validation.ok, false);
  assert.ok(validation.failures.some((finding) => finding.code === 'operation-content-mismatch'));
});

test('materialiser defaults to dry-run and apply is coordinator-only and idempotent', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-'));
  try {
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const content = 'export const value = 1;\n';
    const plan = await createLayoutPlan(ctx, { operations: [{ action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'tools/compiler/src/value.js', pathRole: role, representationFormat: format }] });
    assert.equal((await applyLayoutPlan(ctx, { plan })).dryRun, true);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.equal(readFileSync(join(root, 'tools/compiler/src/value.js'), 'utf8'), content);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    await assert.rejects(() => applyLayoutPlan({ ...ctx, coordinator: false }, { plan, apply: true }), /coordinator-only/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('materialiser replaces only an exact prior digest and rolls the plan back on failure', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-rollback-'));
  try {
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const existing = join(root, 'tools/compiler/src/existing.js');
    mkdirSync(join(root, 'tools/compiler/src'), { recursive: true });
    writeFileSync(existing, 'prior\n');
    const replacement = 'replacement\n';
    const plan = await createLayoutPlan(ctx, { operations: [
      { action: 'write-file', artefactFamily: family, content: 'new\n', contentDigest: digest('new\n'), contentEncoding: 'utf8', index: 0, path: 'tools/compiler/src/new.js', pathRole: role, representationFormat: format },
      { action: 'write-file', artefactFamily: family, content: replacement, contentDigest: digest(replacement), contentEncoding: 'utf8', index: 1, path: 'tools/compiler/src/existing.js', pathRole: role, representationFormat: format, sourceDigest: digest('prior\n') },
    ] });
    writeFileSync(existing, 'concurrent-change\n');
    await assert.rejects(() => applyLayoutPlan(ctx, { plan, apply: true }), /source digest mismatch/);
    assert.equal(existsSync(join(root, 'tools/compiler/src/new.js')), false);
    assert.equal(readFileSync(existing, 'utf8'), 'concurrent-change\n');
    writeFileSync(existing, 'prior\n');
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.equal(readFileSync(existing, 'utf8'), replacement);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('bounded plans may reference exact write bytes from the operator-local CAS', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-cas-'));
  const casRoot = mkdtempSync(join(tmpdir(), 'usf-materialise-content-'));
  try {
    const content = Buffer.alloc(70_000, 7);
    const contentDigest = digest(content);
    const hex = contentDigest.slice(7);
    const stored = join(casRoot, 'sha256', hex.slice(0, 2), hex);
    mkdirSync(join(casRoot, 'sha256', hex.slice(0, 2)), { recursive: true });
    writeFileSync(stored, content);
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true, casRoot };
    const plan = await createLayoutPlan(ctx, { operations: [{
      action: 'write-file', artefactFamily: family, contentDigest,
      contentLocator: `cas://sha256/${hex}`, fileMode: '0644', index: 0,
      path: 'tools/compiler/src/large.js', pathRole: role, representationFormat: format,
    }] });
    assert.ok(Buffer.byteLength(JSON.stringify(plan)) < 65_536);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.deepEqual(readFileSync(join(root, 'tools/compiler/src/large.js')), content);
    writeFileSync(stored, 'tampered');
    const otherRoot = mkdtempSync(join(tmpdir(), 'usf-materialise-content-tamper-'));
    try {
      await assert.rejects(() => applyLayoutPlan({ ...ctx, repositoryRoot: otherRoot }, { plan, apply: true }), /content digest mismatch/);
    } finally { rmSync(otherRoot, { recursive: true, force: true }); }
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(casRoot, { recursive: true, force: true });
  }
});

test('move and delete operations require exact source digests', async () => {
  const ctx = { client: fakeClient() };
  const bad = await createLayoutPlan(ctx, { operations: [{ action: 'move-path', index: 0, path: 'tools/compiler/next', pathRole: role, sourcePath: 'compiler' }] }).catch((error) => error);
  assert.match(bad.message, /operation-source-digest/);
});

test('plans reject root-role descendants, forbidden segments and family naming violations', async () => {
  const rootRole = 'urn:usf:pathrole:repositoryroot';
  const rootFamily = 'urn:usf:artefactfamily:repositorydocumentation';
  const rootFormat = 'urn:usf:representationformat:markdown';
  const client = fakeClient();
  const originalSelect = client.select;
  client.select = async (query) => {
    if (query.includes('a <urn:usf:ontology:PathRole>')) return [{ role: binding(rootRole), canonicalName: binding('repositoryroot'), parent: binding('.'), onDemand: binding('true') }];
    if (query.includes('a <urn:usf:ontology:ArtefactFamily>')) return [{ family: binding(rootFamily), familyName: binding('repositorydocumentation'), storage: binding('urn:usf:storageclass:gittrackedsource'), pathRole: binding(rootRole), format: binding(rootFormat), namingPattern: binding('^[A-Za-z0-9._-]+$') }];
    return originalSelect(query);
  };
  const make = (path) => createLayoutPlan({ client }, { operations: [{ action: 'write-file', artefactFamily: rootFamily, content: '# x\n', contentDigest: digest('# x\n'), contentEncoding: 'utf8', index: 0, path, pathRole: rootRole, representationFormat: rootFormat }] });
  await assert.rejects(() => make('docs/README.md'), /operation-root-descendant/);
  await assert.rejects(() => make('v2/README.md'), /operation-path/);
  await assert.rejects(() => make('bad name.md'), /operation-filename/);
});

test('operator-local CAS verification checks Stardog digest and byte size', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-cas-'));
  try {
    const bytes = Buffer.from('immutable evidence');
    const contentDigest = digest(bytes);
    const hex = contentDigest.slice(7);
    const path = join(root, 'sha256', hex.slice(0, 2), hex);
    mkdirSync(join(root, 'sha256', hex.slice(0, 2)), { recursive: true });
    writeFileSync(path, bytes);
    const descriptor = {
      id: 'urn:usf:externalpayloaddescriptor:test', family, format,
      mediaType: 'application/octet-stream', byteSize: String(bytes.length),
      locator: `cas://sha256/${hex}`, artifactType: 'urn:usf:artefacttype:test',
      storageClass: 'urn:usf:storageclass:contentaddressedobjectstorage',
    };
    const result = await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root }, { digest: contentDigest });
    assert.equal(result.verified, true);
    writeFileSync(path, 'mutated');
    assert.equal((await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root }, { digest: contentDigest })).verified, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('direct lifecycle mutation is always refused at the agent MCP boundary', () => {
  assert.throws(() => refuseLifecycleMutation('usf.evidence.admit'), /compiler.*single transaction/);
});

test('source digests distinguish exact file and deterministic tree state', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-source-digest-'));
  try {
    writeFileSync(join(root, 'a'), 'one');
    const first = sourceDigest(root);
    writeFileSync(join(root, 'a'), 'two');
    assert.notEqual(sourceDigest(root), first);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
