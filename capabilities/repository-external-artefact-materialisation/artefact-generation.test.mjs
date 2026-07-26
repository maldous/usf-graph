import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DataFactory, Parser } from 'n3';

import { loadManifest } from '../semantic-model-compilation/manifest.mjs';
import { loadAuthorityDataset } from '../semantic-model-compilation/authority-dataset.mjs';
import { buildGenerationPlan } from './artefact-generation-plan.mjs';
import { generateAuthority, resolveProvenanceDigest } from './artefact-generation.mjs';
import {
  buildGenerationAuthorityBinding,
  generationAuthorityBindingDigest,
} from './generation-authority-binding.mjs';
import { GENERATED_OUTPUT_ROOT } from './generated-output-validation/index.mjs';

const REPOSITORY_ROOT = join(import.meta.dirname, '..', '..');
const dataset = () => loadAuthorityDataset(loadManifest(join(REPOSITORY_ROOT, 'semantic-model')));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

// One dataset load serves every read-only assertion: parsing the authored set is
// the expensive part and none of these tests mutate it.
const shared = { ...dataset(), get dataset() { return shared; } };

test('the registered authored set yields a complete generation plan', () => {
  const plan = buildGenerationPlan(shared.store);
  assert.deepEqual(plan.obligations, [], 'declared generation must carry no incompleteness obligation');
  assert.equal(plan.complete, true);
  assert.equal(plan.plans, plan.outputs.length, 'every artefact plan must resolve exactly one output');
  assert.ok(plan.outputs.length > 0);
  // Every declared destination is a generated-untracked projection path, and no
  // two plans may claim the same one.
  const paths = plan.outputs.map((output) => output.path);
  assert.equal(new Set(paths).size, paths.length, 'output paths must be unique');
  for (const path of paths) assert.ok(path.startsWith(`${GENERATED_OUTPUT_ROOT}/`), path);
  for (const output of plan.outputs) {
    assert.match(output.component, /^urn:usf:generator:[a-z]+$/);
    // Planned subjects are not all `urn:usf:artefact:` — workflow templates are
    // declared under `urn:usf:template:` and are planned the same way. Assert the
    // authority namespace rather than inventing a narrower one.
    assert.match(output.artefact, /^urn:usf:[a-z]+:[a-z0-9]+$/);
  }
});

// The historical defect class that blocked this generator: an artefact plan or
// generator that does not fully determine its own output. Each fixture must be
// rejected with its exact obligation kinds rather than generating anything.
const DEFECTS = [
  ['artefact-plan-missing-owner', ['missing-plan-owner', 'plan-owner-cardinality']],
  ['artefact-plan-missing-path', ['invalid-path', 'missing-canonical-path', 'plan-path-cardinality']],
  ['incomplete-generator', ['incomplete-generator', 'missing-semantic-input-query']],
];

for (const [fixture, expectedKinds] of DEFECTS) {
  test(`generation is refused for the ${fixture} defect`, () => {
    const { store } = dataset();
    const quads = new Parser({ format: 'application/trig', baseIRI: 'urn:usf:' })
      .parse(readFileSync(join(import.meta.dirname, 'generation-defect-fixtures', `${fixture}.trig`), 'utf8'))
      .map((quad) => DataFactory.quad(quad.subject, quad.predicate, quad.object, quad.graph));
    store.addQuads(quads);
    const plan = buildGenerationPlan(store);
    assert.equal(plan.complete, false, 'a defective plan must never be complete');
    assert.deepEqual([...new Set(plan.obligations.map((item) => item.kind))].sort(), expectedKinds);
  });
}

test('generation materialises every determinate artefact and reuses an unchanged rerun', () => {
  // TMPDIR is the only writable root under the assurance gate, so both the
  // output tree and the generator's own staging directory live there.
  const workspace = mkdtempSync(join(tmpdir(), 'usf-artefact-generation-'));
  try {
    const first = generateAuthority({
      store: shared.store,
      outputDir: join(workspace, 'first'),
      mode: 'full',
      signingKeyPath: null,
    });
    assert.equal(first.ok, true);
    // No authorised release signing key is supplied here, so the four release
    // integrity artefacts are reported unresolved rather than silently emitted
    // unsigned — and the determinate projections still materialise.
    assert.equal(first.releaseIntegrity, 'absent-no-authorised-signing-key');
    assert.deepEqual(first.unresolvedReleaseArtefacts, [
      `${GENERATED_OUTPUT_ROOT}/release/attestation.json`,
      `${GENERATED_OUTPUT_ROOT}/release/checksums.json`,
      `${GENERATED_OUTPUT_ROOT}/release/manifest.json`,
      `${GENERATED_OUTPUT_ROOT}/release/signature.json`,
    ]);
    assert.ok(first.outputCount > 0);
    assert.equal(first.reused, 0, 'a full clean-room run reuses nothing');
    assert.equal(first.changed, first.outputCount);
    // Every reported artefact exists at its declared path with its reported digest.
    for (const record of first.files) {
      assert.equal(sha256(readFileSync(join(workspace, 'first', record.path))), record.sha256, record.path);
    }

    const rerunDir = join(workspace, 'rerun');
    cpSync(join(workspace, 'first'), rerunDir, { recursive: true });
    const second = generateAuthority({
      store: shared.store,
      outputDir: rerunDir,
      mode: 'incremental',
      signingKeyPath: null,
    });
    assert.equal(second.outputCount, first.outputCount);
    assert.equal(second.reused, first.outputCount, 'an unchanged rerun must reuse every artefact');
    assert.equal(second.changed, 0, 'an unchanged rerun must regenerate nothing');
    assert.equal(second.aggregateDigest, first.aggregateDigest);
    assert.equal(second.authorityDigest, first.authorityDigest);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test('a changed semantic input invalidates only the authority-bound artefacts', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'usf-artefact-generation-change-'));
  try {
    const first = generateAuthority({
      store: shared.store,
      outputDir: join(workspace, 'base'),
      mode: 'full',
      signingKeyPath: null,
    });
    const changedDir = join(workspace, 'changed');
    cpSync(join(workspace, 'base'), changedDir, { recursive: true });
    // One added triple is enough to move the source digest. Renderings that embed
    // the authority digest must regenerate; renderings that are independent of it
    // must still be reused byte-for-byte.
    const { store } = dataset();
    store.addQuad(DataFactory.quad(
      DataFactory.namedNode('urn:usf:test:generationchangeprobe'),
      DataFactory.namedNode('urn:usf:ontology:canonicalName'),
      DataFactory.literal('generationchangeprobe'),
      DataFactory.namedNode('urn:usf:graph:tests'),
    ));
    const second = generateAuthority({
      store,
      outputDir: changedDir,
      mode: 'incremental',
      signingKeyPath: null,
    });
    assert.notEqual(second.authorityDigest, first.authorityDigest, 'the source digest must move');
    assert.notEqual(second.aggregateDigest, first.aggregateDigest);
    assert.ok(second.changed > 0, 'authority-bound artefacts must regenerate');
    assert.ok(second.reused > 0, 'authority-independent artefacts must still be reused');
    assert.equal(second.reused + second.changed, second.outputCount);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test('generated provenance requires a validated binding receipt, not a syntactically valid digest', () => {
  // A bare digest argument proved nothing: any 64 hex characters bound every
  // artefact to a state nobody had checked was live, current, or the one this
  // source tree projects. A binding is now a receipt validated against what the
  // generator itself observes.
  const local = resolveProvenanceDigest(shared.store, undefined);
  assert.equal(local.bound, false);
  assert.equal(local.algorithm, 'sha256-sorted-quads-local');
  assert.equal(local.binding, null);
  assert.match(local.digest, /^[0-9a-f]{64}$/);

  const dataset = shared.dataset;
  const observedSource = {
    sourceCommit: 'a'.repeat(40),
    sourceTree: 'b'.repeat(40),
  };
  const inventory = [
    { graph: 'urn:usf:graph:one', sha256: `sha256:${'1'.repeat(64)}`, triples: 7 },
    { graph: 'urn:usf:graph:two', sha256: `sha256:${'2'.repeat(64)}`, triples: 5 },
  ];
  const receipt = buildGenerationAuthorityBinding({
    authorityDigest: `sha256:${'0c'.repeat(32)}`,
    graphCount: 2,
    tripleTotal: 12,
    graphInventory: inventory,
    dataset,
    ...observedSource,
    sourceLiveDrift: { checked: true, mismatchedGraphs: [], graphCount: 2 },
    derivedSnapshot: { checked: true, deterministic: true, written: [] },
    observedAt: '2026-07-26T00:00:00Z',
  });

  const bound = resolveProvenanceDigest(shared.store, receipt, { dataset, observedSource });
  assert.equal(bound.bound, true);
  assert.equal(bound.algorithm, 'sha256-rdfc10-graph-inventory-v2');
  assert.equal(bound.digest, '0c'.repeat(32));
  assert.equal(bound.binding.receiptDigest, receipt.receiptDigest);

  // A bare digest string is no longer a binding at all.
  for (const naked of [`sha256:${'0c'.repeat(32)}`, '0c'.repeat(32), '', 'not-a-digest']) {
    assert.throws(
      () => resolveProvenanceDigest(shared.store, naked, { dataset, observedSource }),
      /generation authority binding/,
      `accepted a naked witness: ${naked}`,
    );
  }

  // Each rejection the receipt contract owes, exercised by its exact code.
  const reject = (mutate, code) => {
    const mutated = mutate({ ...receipt });
    assert.throws(
      () => resolveProvenanceDigest(shared.store, mutated, { dataset, observedSource }),
      (error) => error.detail?.bindingFailureCode === code || new RegExp(code).test(error.message),
      `expected ${code}`,
    );
  };
  const resign = (draft) => ({ ...draft, receiptDigest: generationAuthorityBindingDigest(draft) });
  reject((draft) => resign({ ...draft, schemaVersion: 99 }), 'unsupported-schema-version');
  reject((draft) => resign({ ...draft, authorityDigestAlgorithm: 'sha256-sorted-quads-local' }), 'unsupported-authority-algorithm');
  reject((draft) => resign({ ...draft, authorityDigest: 'sha256:zz' }), 'malformed-digest');
  reject((draft) => resign({ ...draft, tripleTotal: -1 }), 'malformed-count');
  reject((draft) => resign({ ...draft, tripleTotal: 999 }), 'inconsistent-inventory-total');
  reject((draft) => resign({ ...draft, graphCount: 3 }), 'inconsistent-inventory-total');
  reject((draft) => resign({ ...draft, generationInputDigest: `sha256:${'f'.repeat(64)}` }), 'generation-input-mismatch');
  reject((draft) => resign({ ...draft, generationInputGraphs: ['urn:usf:graph:absent'] }), 'generation-input-mismatch');
  reject((draft) => resign({ ...draft, sourceCommit: 'c'.repeat(40) }), 'source-identity-mismatch');
  reject((draft) => resign({ ...draft, sourceTree: 'd'.repeat(40) }), 'source-identity-mismatch');
  reject((draft) => resign({ ...draft, sourceLiveDrift: { checked: true, mismatchedGraphs: ['urn:usf:graph:one'], graphCount: 2 } }), 'source-live-drift');
  reject((draft) => resign({ ...draft, sourceLiveDrift: { checked: false, mismatchedGraphs: [], graphCount: 2 } }), 'drift-unchecked');
  reject((draft) => resign({ ...draft, derivedSnapshot: { checked: true, deterministic: false } }), 'derived-snapshot-unproven');
  // A forged field with the original digest left in place must not pass.
  reject((draft) => ({ ...draft, tripleTotal: 12, observedAt: '2020-01-01T00:00:00Z' }), 'receipt-digest-mismatch');
});

test('a bound generation reports the receipt it was bound by, and an offline one reports that it is unbound', () => {
  const dataset = shared.dataset;
  const observedSource = { sourceCommit: 'a'.repeat(40), sourceTree: 'b'.repeat(40) };
  const receipt = buildGenerationAuthorityBinding({
    authorityDigest: `sha256:${'0c'.repeat(32)}`,
    graphCount: 1,
    tripleTotal: 3,
    graphInventory: [{ graph: 'urn:usf:graph:one', sha256: `sha256:${'1'.repeat(64)}`, triples: 3 }],
    dataset,
    ...observedSource,
    sourceLiveDrift: { checked: true, mismatchedGraphs: [], graphCount: 1 },
    derivedSnapshot: { checked: true, deterministic: true, written: [] },
    observedAt: '2026-07-26T00:00:00Z',
  });
  const workspace = mkdtempSync(join(tmpdir(), 'usf-artefact-generation-witness-'));
  try {
    const result = generateAuthority({
      store: shared.store,
      dataset,
      observedSource,
      outputDir: join(workspace, 'bound'),
      mode: 'full',
      signingKeyPath: null,
      authorityBinding: receipt,
    });
    assert.equal(result.authorityWitnessBound, true);
    assert.equal(result.authorityDigestAlgorithm, 'sha256-rdfc10-graph-inventory-v2');
    assert.equal(result.authorityDigest, '0c'.repeat(32));
    assert.equal(result.authorityBindingReceiptDigest, receipt.receiptDigest);
    assert.equal(result.generationInputDigest, dataset.inputDigest);
    assert.equal(result.sourceCommit, observedSource.sourceCommit);
    // Every JSON projection embeds the bound witness, not the local digest.
    const projection = JSON.parse(
      readFileSync(join(workspace, 'bound', `${GENERATED_OUTPUT_ROOT}/semantic-authority/authority.json`), 'utf8'),
    );
    assert.equal(projection.authorityDigest, '0c'.repeat(32));

    // Offline generation stays available and says plainly that it is unbound.
    const offline = generateAuthority({
      store: shared.store,
      dataset,
      outputDir: join(workspace, 'offline'),
      mode: 'full',
      signingKeyPath: null,
    });
    assert.equal(offline.authorityWitnessBound, false);
    assert.equal(offline.authorityDigestAlgorithm, 'sha256-sorted-quads-local');
    assert.equal(offline.authorityBindingReceiptDigest, null);
    assert.notEqual(offline.authorityDigest, '0c'.repeat(32));
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});
