// The canonical authority-dataset loader is the ONE loader, and every dataset it
// returns says exactly which graphs it holds.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { loadManifest } from './manifest.mjs';
import {
  AUTHORITY_DATASET_SCOPES,
  DEFAULT_SCOPE,
  GENERATION_INPUT_DIGEST_ALGORITHM,
  generationInputDigest,
  loadAuthorityDataset,
} from './authority-dataset.mjs';
import { compareGeneratorProjections } from '../repository-external-artefact-materialisation/generator-projection-parity.mjs';
import { generatorSelection } from '../repository-external-artefact-materialisation/artefact-generation.mjs';
import { buildGenerationPlan } from '../repository-external-artefact-materialisation/artefact-generation-plan.mjs';

const REPOSITORY_ROOT = join(import.meta.dirname, '..', '..');
const manifest = () => loadManifest(join(REPOSITORY_ROOT, 'semantic-model'));

function sourceFiles(root, accumulated = []) {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const path = join(root, entry.name);
    if (entry.isDirectory()) sourceFiles(path, accumulated);
    else if (entry.name.endsWith('.mjs')) accumulated.push(path);
  }
  return accumulated;
}

test('exactly one authority-dataset loader implementation exists', () => {
  const declaring = sourceFiles(REPOSITORY_ROOT)
    .filter((path) => /^export function loadAuthorityDataset\b/m.test(readFileSync(path, 'utf8')))
    .map((path) => relative(REPOSITORY_ROOT, path))
    .sort();
  assert.deepEqual(declaring, ['capabilities/semantic-model-compilation/authority-dataset.mjs']);
});

test('the retired loader paths are gone', () => {
  // Checked by directory listing rather than stat: under the hermetic runner's
  // permission model a stat of an absent path can be refused before it is found
  // to be absent, which would pass for the wrong reason.
  for (const retired of [
    'processes/semantic-assurance',
    'capabilities/repository-external-artefact-materialisation',
  ]) {
    assert.equal(
      readdirSync(join(REPOSITORY_ROOT, retired)).includes('authority-dataset.mjs'),
      false,
      `${retired}/authority-dataset.mjs still exists`,
    );
  }
});

test('every dataset declares the graph subset it actually holds', () => {
  const dataset = loadAuthorityDataset(manifest());
  assert.equal(dataset.scope.name, DEFAULT_SCOPE);
  assert.deepEqual([...dataset.scope.sections], ['definitions', 'authored', 'shapes', 'derived']);
  // A scope must say what it leaves out, so nothing can call it "the complete
  // live authority" by omission.
  assert.ok(Object.keys(dataset.scope.omits).includes('review'));
  assert.equal(dataset.graphCount, dataset.graphInventory.length);
  assert.ok(dataset.graphInventory.every((record) => record.graph.startsWith('urn:usf:graph:')));
  assert.equal(dataset.inputDigestAlgorithm, GENERATION_INPUT_DIGEST_ALGORITHM);
  assert.match(dataset.inputDigest, /^sha256:[0-9a-f]{64}$/);
});

test('an unknown scope fails closed rather than defaulting to everything', () => {
  assert.throws(() => loadAuthorityDataset(manifest(), { scope: 'everything' }), /unknown authority dataset scope/);
});

test('the generation-input digest is reproducible across loads', () => {
  // Blank nodes make a quad-level digest unstable between parses, so the input
  // digest is taken over registered source bytes. Two loads must agree exactly.
  const first = loadAuthorityDataset(manifest());
  const second = loadAuthorityDataset(manifest());
  assert.equal(first.inputDigest, second.inputDigest);
  assert.equal(first.inputDigest, generationInputDigest([...first.sourceEntries]));
  assert.notEqual(first.inputDigest, loadAuthorityDataset(manifest(), { scope: 'authored-only-superseded' }).inputDigest);
});

test('the generation input is not an authored-only subset', () => {
  // The regression this closes: `urn:usf:generator:proof` selects
  // usf:ProofObligation, and the great majority of published obligations are
  // rule output in a derived graph. An authored-only input answered that
  // generator's query with a fraction of the published answer.
  const current = loadAuthorityDataset(manifest());
  const superseded = loadAuthorityDataset(manifest(), { scope: 'authored-only-superseded' });
  const proof = 'urn:usf:generator:proof';
  const currentCount = generatorSelection(current.store, proof).subjects.length;
  const supersededCount = generatorSelection(superseded.store, proof).subjects.length;
  assert.ok(
    currentCount > supersededCount,
    `generation input must see more than the authored-only subset (${currentCount} vs ${supersededCount})`,
  );
  assert.ok(current.quads > superseded.quads);
});

test('projection parity compares the generator selection against the published answer', async () => {
  const dataset = loadAuthorityDataset(manifest());
  const plan = buildGenerationPlan(dataset.store);
  const components = [...new Set(plan.outputs.map((output) => output.component))];

  // A client that answers each declared semanticInputQuery with exactly what the
  // generator selects locally: parity must hold.
  const agreeing = {
    select: async (query) => {
      const component = components.find((candidate) => generatorSelection(dataset.store, candidate).query === query);
      return generatorSelection(dataset.store, component).subjects
        .map((subject) => ({ resource: { value: subject.value } }));
    },
  };
  const agreed = await compareGeneratorProjections({ store: dataset.store, client: agreeing });
  assert.equal(agreed.ok, true, JSON.stringify(agreed.disagreements.slice(0, 3)));
  assert.equal(agreed.agreeingCount, agreed.generatorCount);

  // A client that withholds one published resource must be caught, not tolerated.
  const withholding = {
    select: async (query) => (await agreeing.select(query)).slice(1),
  };
  const withheld = await compareGeneratorProjections({ store: dataset.store, client: withholding });
  assert.equal(withheld.ok, false);
  assert.ok(withheld.disagreements.some((item) => item.code === 'generator-projection-missing-live'));

  // A client that publishes a resource the local source cannot produce is the
  // authored-only-subset defect, and must also fail.
  const extra = {
    select: async (query) => [...await agreeing.select(query), { resource: { value: 'urn:usf:proofobligation:unpublishedlocally' } }],
  };
  const extras = await compareGeneratorProjections({ store: dataset.store, client: extra });
  assert.equal(extras.ok, false);
  assert.ok(extras.disagreements.some((item) => item.code === 'generator-projection-missing-locally'));
});
