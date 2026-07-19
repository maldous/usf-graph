import assert from 'node:assert/strict';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  applyLayoutPlan, createLayoutPlan, digest, layoutContext, materialisationInternals, refuseLifecycleMutation,
  planWork, projectContract, sourceDigest, validateLayoutPlan, verifyArtifact,
} from './repository-materialisation-gateway.mjs';

const contract = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const family = 'urn:usf:artefactfamily:compiler';
const format = 'urn:usf:representationformat:ecmascriptmodule';
const role = 'urn:usf:pathrole:compilersource';

function binding(value) { return { value }; }
function defaultContractRows() {
  return [{
    canonicalName: binding('repositoryexternalartefactmaterialisation'),
    lifecycle: binding('urn:usf:semanticlifecyclestate:active'),
    activation: binding('urn:usf:contractactivationstate:active'),
    proof: binding('urn:usf:proofresult:repositoryexternalartefactmaterialisation'),
    proofState: binding('urn:usf:proofresultstate:successful'),
    decision: binding('urn:usf:realisationdecision:repositoryexternalartefactmaterialisation'),
    decisionState: binding('urn:usf:decisionstate:accepted'),
    authorisedPath: binding('capabilities/semantic-model-compilation'),
  }];
}
function fakeClient({ descriptor, contractRows = defaultContractRows() } = {}) {
  return {
    size: async () => 10,
    construct: async () => '<urn:s> <urn:p> "materialisation" .\n',
    select: async (query) => {
      if (query.includes('COUNT(*) AS ?count')) return [{ count: binding('1') }];
      if (query.includes('SELECT DISTINCT ?g')) return [{ g: binding('urn:g') }];
      if (query.includes('?canonicalName ?lifecycle')) return contractRows;
      if (query.includes('a <urn:usf:ontology:PathRole>')) return [{ role: binding(role), canonicalName: binding('compilersource'), parent: binding('capabilities/semantic-model-compilation'), onDemand: binding('true') }];
      if (query.includes('a <urn:usf:ontology:ArtefactFamily>')) return [{ family: binding(family), familyName: binding('compiler'), storage: binding('urn:usf:storageclass:gittrackedsource'), pathRole: binding(role), format: binding(format), namingPattern: binding('^[A-Za-z0-9._-]+$') }];
      if (query.includes('ExternalPayloadDescriptor')) return descriptor ? [Object.fromEntries(Object.entries(descriptor).map(([key, item]) => [key, binding(item)]))] : [];
      return [];
    },
  };
}

test('layout context is live-digest-bound and exposes active proof and authorised paths', async () => {
  const context = await layoutContext({ client: fakeClient() });
  assert.match(context.authorityDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(context.authorityDigestAlgorithm, 'sha256-rdfc10-graph-inventory-v2');
  assert.deepEqual(context.authorityGraphInventory, [{
    graph: 'urn:g',
    sha256: context.authorityGraphInventory[0].sha256,
    triples: 1,
  }]);
  assert.match(context.authorityGraphInventory[0].sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(context.contract.activationState, 'urn:usf:contractactivationstate:active');
  assert.equal(context.contract.proofResultState, 'urn:usf:proofresultstate:successful');
  assert.equal(context.acceptedDecisionCount, 1);
  assert.deepEqual(context.authorisedPaths, ['capabilities/semantic-model-compilation']);
});

test('layout context rejects a truncated materialisation-rule projection', async () => {
  const client = fakeClient();
  const select = client.select;
  client.select = async (query) => query.includes('COUNT(*) AS ?count')
    ? [{ count: binding('2') }]
    : select(query);
  await assert.rejects(() => layoutContext({ client }), /rule projection is incomplete/);
});

test('plans require one accepted decision, its authorised paths, and an exact plan digest', async () => {
  const content = 'export const value = 1;\n';
  const operation = { action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/value.mjs', pathRole: role, representationFormat: format };
  const plan = await createLayoutPlan({ client: fakeClient() }, { contract, operations: [operation] });

  const missingDigest = structuredClone(plan);
  delete missingDigest.planDigest;
  assert.ok((await validateLayoutPlan({ client: fakeClient() }, missingDigest)).failures.some((finding) => finding.code === 'plan-digest'));

  const draftRows = defaultContractRows();
  draftRows[0].decisionState = binding('urn:usf:decisionstate:draft');
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: draftRows }) }, plan)).failures.some((finding) => finding.code === 'plan-decision-not-uniquely-accepted'));

  const pathlessRows = defaultContractRows();
  delete pathlessRows[0].authorisedPath;
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: pathlessRows }) }, plan)).failures.some((finding) => finding.code === 'operation-decision-path'));

  const second = { ...defaultContractRows()[0], decision: binding('urn:usf:realisationdecision:other') };
  assert.ok((await validateLayoutPlan({ client: fakeClient({ contractRows: [...defaultContractRows(), second] }) }, plan)).failures.some((finding) => finding.code === 'plan-decision-not-uniquely-accepted'));
});

test('layout plan validates exact content, path role, family, format, digest and authority', async () => {
  const ctx = { client: fakeClient() };
  const content = 'export const value = 1;\n';
  const operations = [{ action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/value.mjs', pathRole: role, representationFormat: format }];
  const plan = await createLayoutPlan(ctx, { contract, operations });
  assert.equal((await validateLayoutPlan(ctx, plan)).ok, true);
  const tampered = structuredClone(plan);
  tampered.operations[0].content = 'different';
  const validation = await validateLayoutPlan(ctx, tampered);
  assert.equal(validation.ok, false);
  assert.ok(validation.failures.some((finding) => finding.code === 'operation-content-mismatch'));
});

test('contract projection includes focused validation obligations beyond bootstrap pagination', async () => {
  const client = fakeClient();
  const originalSelect = client.select;
  client.select = async (query) => {
    if (query.includes('a <urn:usf:ontology:ValidationObligation>')) return [{ id: binding('urn:usf:validationobligation:v1') }];
    return originalSelect(query);
  };
  const packet = await projectContract({ client }, { contract });
  assert.deepEqual(packet.validationObligations, ['urn:usf:validationobligation:v1']);
  assert.ok(packet.semanticIdentifiers.includes('urn:usf:validationobligation:v1'));
});

test('work planning accepts only passing validation backed by current applicable evidence', async () => {
  let workQuery;
  const client = fakeClient();
  const originalSelect = client.select;
  client.select = async (query) => {
    if (query.includes('SELECT ?gap ?subject')) {
      workQuery = query;
      return [{ gap: binding('missing-current-passing-validation'), subject: binding('urn:usf:validationobligation:v1') }];
    }
    return originalSelect(query);
  };
  const result = await planWork({ client }, { contract });
  assert.equal(result.gaps[0].type, 'missing-current-passing-validation');
  for (const required of [
    'entersEvidenceLifecycleAs', 'ValidationEvidence', 'evidenceadmissionstate:admitted',
    'evidencefreshnessstate:fresh', 'evidenceintegritystate:valid', 'withinValidityScope',
    'applicableToObligation',
  ]) assert.match(workQuery, new RegExp(required));
});

test("proof-blocked contract projection is available but grants no materialisation authority", async () => {
  const packet = await projectContract({ client: fakeClient({ contractRows: [{
    canonicalName: binding("compilersemanticenforcement"),
    lifecycle: binding("urn:usf:semanticlifecyclestate:planned"),
    activation: binding("urn:usf:contractactivationstate:proofblocked"),
  }] }) }, { contract: "urn:usf:semanticcontract:compilersemanticenforcement" });
  assert.equal(packet.contractState.proof, null);
  assert.equal(packet.contractState.decision, null);
  assert.deepEqual(packet.authorisedActions, []);
  assert.deepEqual(packet.authorisedPaths, []);
  assert.deepEqual(packet.authorisedFormats, []);
});

test('model-incomplete contract projection is available with null lifecycle and activation and no authority grants', async () => {
  const packet = await projectContract({ client: fakeClient({ contractRows: [{
    canonicalName: binding('universalservicefoundationscopeandprinciples'),
  }] }) }, { contract: 'urn:usf:semanticcontract:universalservicefoundationscopeandprinciples' });
  assert.equal(packet.contractState.lifecycle, null);
  assert.equal(packet.contractState.activation, null);
  assert.equal(packet.contractState.proof, null);
  assert.equal(packet.contractState.decision, null);
  assert.deepEqual(packet.authorisedActions, []);
  assert.deepEqual(packet.authorisedPaths, []);
  assert.deepEqual(packet.authorisedFormats, []);
});

test('materialiser defaults to dry-run and apply is coordinator-only and idempotent', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-'));
  try {
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const content = 'export const value = 1;\n';
    const plan = await createLayoutPlan(ctx, { operations: [{ action: 'write-file', artefactFamily: family, content, contentDigest: digest(content), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/value.mjs', pathRole: role, representationFormat: format }] });
    assert.equal((await applyLayoutPlan(ctx, { plan })).dryRun, true);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.equal(readFileSync(join(root, 'capabilities/semantic-model-compilation/value.mjs'), 'utf8'), content);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    await assert.rejects(() => applyLayoutPlan({ ...ctx, coordinator: false }, { plan, apply: true }), /coordinator-only/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('materialiser replaces only an exact prior digest and rolls the plan back on failure', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-rollback-'));
  try {
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const existing = join(root, 'capabilities/semantic-model-compilation/existing.js');
    mkdirSync(join(root, 'capabilities/semantic-model-compilation'), { recursive: true });
    writeFileSync(existing, 'prior\n');
    const replacement = 'replacement\n';
    const plan = await createLayoutPlan(ctx, { operations: [
      { action: 'write-file', artefactFamily: family, content: 'new\n', contentDigest: digest('new\n'), contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/new.js', pathRole: role, representationFormat: format },
      { action: 'write-file', artefactFamily: family, content: replacement, contentDigest: digest(replacement), contentEncoding: 'utf8', index: 1, path: 'capabilities/semantic-model-compilation/existing.js', pathRole: role, representationFormat: format, sourceDigest: digest('prior\n') },
    ] });
    writeFileSync(existing, 'concurrent-change\n');
    await assert.rejects(() => applyLayoutPlan(ctx, { plan, apply: true }), /source digest mismatch/);
    assert.equal(existsSync(join(root, 'capabilities/semantic-model-compilation/new.js')), false);
    assert.equal(readFileSync(existing, 'utf8'), 'concurrent-change\n');
    writeFileSync(existing, 'prior\n');
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.equal(readFileSync(existing, 'utf8'), replacement);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('delete rollback restores exact file and directory types, bytes, and modes after a later failure', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-delete-mode-'));
  try {
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const source = join(root, 'capabilities/semantic-model-compilation/mode.js');
    const directory = join(root, 'capabilities/semantic-model-compilation/mode-directory');
    const blocker = join(root, 'capabilities/semantic-model-compilation/blocker.js');
    mkdirSync(join(root, 'capabilities/semantic-model-compilation'), { recursive: true });
    mkdirSync(directory, { mode: 0o711 });
    writeFileSync(source, 'exact prior bytes\n', { mode: 0o640 });
    writeFileSync(blocker, 'concurrent bytes\n');
    chmodSync(source, 0o640);
    chmodSync(directory, 0o711);
    const plan = await createLayoutPlan(ctx, { operations: [
      { action: 'delete-path', index: 0, path: 'capabilities/semantic-model-compilation/mode.js', pathRole: role, sourceDigest: sourceDigest(source) },
      { action: 'delete-path', index: 1, path: 'capabilities/semantic-model-compilation/mode-directory', pathRole: role, sourceDigest: sourceDigest(directory) },
      {
        action: 'write-file', artefactFamily: family, content: 'replacement\n', contentDigest: digest('replacement\n'),
        contentEncoding: 'utf8', index: 2, path: 'capabilities/semantic-model-compilation/blocker.js', pathRole: role,
        representationFormat: format, sourceDigest: digest('stale bytes\n'),
      },
    ] });
    await assert.rejects(() => applyLayoutPlan(ctx, { plan, apply: true }), /source digest mismatch/);
    assert.equal(lstatSync(source).isFile(), true);
    assert.equal(readFileSync(source, 'utf8'), 'exact prior bytes\n');
    assert.equal(lstatSync(source).mode & 0o7777, 0o640);
    assert.equal(lstatSync(directory).isDirectory(), true);
    assert.equal(lstatSync(directory).mode & 0o7777, 0o711);
    assert.equal(readFileSync(blocker, 'utf8'), 'concurrent bytes\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
});


// The hermetic test runtime forbids symlink creation entirely (Node
// --permission grants no global fs.write), and its snapshot builder rejects
// symbolic links, so the traversal attack is structurally excluded there.
// Assert that stronger runtime guarantee explicitly when fixture symlinks
// cannot exist; otherwise exercise the gateway rejection directly.
function fixtureSymlink(target, path) {
  try {
    symlinkSync(target, path, 'dir');
    return true;
  } catch (error) {
    if (error.code !== 'ERR_ACCESS_DENIED' || !process.permission) throw error;
    assert.equal(process.permission.has('fs.write'), false);
    return false;
  }
}

test('materialiser rejects symbolic-link traversal for repository and CAS paths', async () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-materialise-symlink-'));
  const outside = mkdtempSync(join(tmpdir(), 'usf-materialise-outside-'));
  try {
    mkdirSync(join(root, 'capabilities'), { recursive: true });
    if (!fixtureSymlink(outside, join(root, 'capabilities/semantic-model-compilation'))) return;
    const ctx = { client: fakeClient(), repositoryRoot: root, coordinator: true };
    const content = 'export const escaped = true;\n';
    const plan = await createLayoutPlan(ctx, { operations: [{
      action: 'write-file', artefactFamily: family, content, contentDigest: digest(content),
      contentEncoding: 'utf8', index: 0, path: 'capabilities/semantic-model-compilation/escaped.js',
      pathRole: role, representationFormat: format,
    }] });
    await assert.rejects(() => applyLayoutPlan(ctx, { plan, apply: true }), /traverses a symbolic link/);
    assert.equal(existsSync(join(outside, 'src/escaped.js')), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('rollback failures preserve the primary error and every undo error', () => {
  const primary = new Error('primary');
  assert.throws(
    () => materialisationInternals.rethrowWithRollback(primary, [() => { throw new Error('undo'); }]),
    (error) => error instanceof AggregateError
      && error.errors[0] === primary
      && error.errors[1].message === 'undo'
      && error.cause === primary,
  );
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
      path: 'capabilities/semantic-model-compilation/large.js', pathRole: role, representationFormat: format,
    }] });
    assert.ok(Buffer.byteLength(JSON.stringify(plan)) < 65_536);
    assert.equal((await applyLayoutPlan(ctx, { plan, apply: true })).applied, true);
    assert.deepEqual(readFileSync(join(root, 'capabilities/semantic-model-compilation/large.js')), content);
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
  const bad = await createLayoutPlan(ctx, { operations: [{ action: 'move-path', index: 0, path: 'capabilities/semantic-model-compilation/next', pathRole: role, sourcePath: 'compiler' }] }).catch((error) => error);
  assert.match(bad.message, /operation-source-digest/);
});

test('plans reject root-role descendants, forbidden segments and family naming violations', async () => {
  const rootRole = 'urn:usf:pathrole:repositoryroot';
  const rootFamily = 'urn:usf:artefactfamily:repositorydocumentation';
  const rootFormat = 'urn:usf:representationformat:markdown';
  const client = fakeClient();
  const originalSelect = client.select;
  client.select = async (query) => {
    if (query.includes('COUNT(*) AS ?count')) return [{ count: binding('1') }];
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
    const external = join(root, 'external-object');
    writeFileSync(external, bytes);
    unlinkSync(path);
    if (fixtureSymlink(external, path)) {
      const symlinked = await verifyArtifact({ client: fakeClient({ descriptor }), casRoot: root }, { digest: contentDigest });
      assert.equal(symlinked.verified, false);
      assert.equal(symlinked.code, 'artifact-not-regular-file');
      unlinkSync(path);
    }
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
