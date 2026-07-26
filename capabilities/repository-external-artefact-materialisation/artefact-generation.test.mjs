import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DataFactory, Parser } from 'n3';

import { loadManifest } from '../semantic-model-compilation/manifest.mjs';
import { loadAuthorityDataset } from './authority-dataset.mjs';
import { buildGenerationPlan } from './artefact-generation-plan.mjs';
import { generateAuthority } from './artefact-generation.mjs';
import { GENERATED_OUTPUT_ROOT } from './generated-output-validation/index.mjs';

const REPOSITORY_ROOT = join(import.meta.dirname, '..', '..');
const dataset = () => loadAuthorityDataset(loadManifest(join(REPOSITORY_ROOT, 'semantic-model')));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

// One dataset load serves every read-only assertion: parsing the authored set is
// the expensive part and none of these tests mutate it.
const shared = dataset();

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
