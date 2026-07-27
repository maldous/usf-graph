// Artefact generation command: materialise the graph-declared generated
// projections (ArtefactPlan -> Artefact -> Generator) from registered authored
// semantic source.
//
// This is the canonical generator entrypoint. It replaces the retired
// tools/compiler/src/cli.js `generate` command with no change to the generation
// contract: the same generation plan, the same per-generator semanticInputQuery
// resolution, the same renderers, the same byte-identity reuse and the same
// release integrity chain.
//
// Read-only with respect to semantic authority: nothing here mutates Stardog.
// The generated tree is a projection, is lower authority than its semantic
// inputs, and claims no validation.
//
//   node processes/semantic-assurance/artefact-generation-command.mjs \
//     --output <directory> [--mode full|incremental] [--signing-key <PEM path>]
//
// `plan` reports the declared inventory and any incompleteness obligations
// without writing anything.
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadManifest } from '../../capabilities/semantic-model-compilation/manifest.mjs';
import { loadAuthorityDataset } from '../../capabilities/semantic-model-compilation/authority-dataset.mjs';
import { buildGenerationPlan } from '../../capabilities/repository-external-artefact-materialisation/artefact-generation-plan.mjs';
import { generateAuthority, verifyOutput } from '../../capabilities/repository-external-artefact-materialisation/artefact-generation.mjs';
import {
  buildGenerationAuthorityBinding,
  observeGitSource,
} from '../../capabilities/repository-external-artefact-materialisation/generation-authority-binding.mjs';

export function repositoryRoot() {
  return resolve(fileURLToPath(import.meta.url), '../../..');
}

export function loadRegisteredAuthority(root = repositoryRoot(), options = {}) {
  return loadAuthorityDataset(loadManifest(join(root, 'semantic-model')), options);
}

function optional(name) {
  const prefix = `--${name}=`;
  const inline = process.argv.filter((value) => value.startsWith(prefix));
  if (inline.length > 1) throw new Error(`at most one ${prefix}<value> is permitted`);
  if (inline.length === 1) return inline[0].slice(prefix.length);
  const at = process.argv.indexOf(`--${name}`);
  return at >= 0 ? process.argv[at + 1] ?? null : null;
}

// Produce the structured binding receipt from live observations. This is the
// ONLY producer: it reads the live witness, the source/live drift result and the
// derived-snapshot determinism result, and binds them to the exact commit, tree
// and generation input the generator will read.
export async function buildAuthorityBinding({ root = repositoryRoot(), client, observedAt } = {}) {
  const { authorityWitness } = await import('./semantic-bootstrap-packet.mjs');
  const { checkDrift } = await import('./semantic-authority-drift.mjs');
  const manifest = loadManifest(join(root, 'semantic-model'));
  const dataset = loadAuthorityDataset(manifest);
  const witness = await authorityWitness(client);
  const drift = await checkDrift({ manifest, live: client });
  // Derived determinism: the registered derived snapshots already on disk must
  // be exactly what live rule output produces. checkDrift compares them graph by
  // graph, so a derived mismatch is a drift mismatch and cannot pass silently.
  const derivedGraphs = new Set(manifest.derived.map((entry) => entry.graph));
  const derivedMismatched = drift.mismatched.filter((graph) => derivedGraphs.has(graph));
  const closingWitness = await authorityWitness(client);
  if (closingWitness.digest !== witness.digest || closingWitness.triples !== witness.triples) {
    throw new Error('live authority changed while building the generation authority binding');
  }
  return buildGenerationAuthorityBinding({
    authorityDigest: `sha256:${witness.digest}`,
    graphCount: witness.inventory.length,
    tripleTotal: witness.triples,
    graphInventory: witness.inventory.map((record) => ({
      graph: record.graph,
      sha256: `sha256:${record.sha256}`,
      triples: record.triples,
    })),
    dataset,
    ...observeGitSource(root),
    sourceLiveDrift: {
      checked: true,
      mismatchedGraphs: [...drift.mismatched],
      graphCount: witness.inventory.length,
    },
    derivedSnapshot: {
      checked: true,
      deterministic: derivedMismatched.length === 0,
      graphs: [...derivedGraphs].sort(),
      mismatchedGraphs: derivedMismatched,
    },
    observedAt: observedAt ?? new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  });
}

export function runArtefactGenerationCommand(command) {
  const dataset = loadRegisteredAuthority();
  if (command === 'plan') {
    const plan = buildGenerationPlan(dataset.store);
    const byComponent = {};
    for (const output of plan.outputs) byComponent[output.component] = (byComponent[output.component] ?? 0) + 1;
    return {
      command,
      registeredFiles: dataset.files,
      quads: dataset.quads,
      generationInputScope: dataset.scope.name,
      generationInputGraphCount: dataset.graphCount,
      generationInputDigest: dataset.inputDigest,
      plans: plan.plans,
      outputs: plan.outputs.length,
      complete: plan.complete,
      obligationCount: plan.obligations.length,
      obligations: plan.obligations.slice(0, 25),
      generators: Object.keys(byComponent).sort(),
      outputsByGenerator: byComponent,
    };
  }
  if (command === 'generate') {
    const outputDir = optional('output');
    if (!outputDir) throw new Error('generate requires --output <directory>');
    // --authority-binding names a structured binding receipt. It replaces the
    // former --authority-witness-digest, which accepted any syntactically valid
    // 64 hex characters and bound every projection to a state nobody had checked
    // was live, current, or the one this source tree projects. The receipt is
    // validated against the dataset actually loaded and the commit and tree
    // actually read; only then is the output authority-bound.
    //
    // Omitting it still produces the complete deliverable offline, reported with
    // authorityWitnessBound=false so a consumer can refuse it for production
    // materialisation.
    const bindingPath = optional('authority-binding');
    const authorityBinding = bindingPath
      ? JSON.parse(readFileSync(resolve(bindingPath), 'utf8'))
      : undefined;
    const result = generateAuthority({
      store: dataset.store,
      dataset,
      observedSource: authorityBinding ? observeGitSource(repositoryRoot()) : undefined,
      outputDir,
      mode: optional('mode') ?? 'full',
      signingKeyPath: optional('signing-key'),
      authorityBinding,
    });
    return { command, ...result, files: undefined, fileCount: result.files?.length ?? result.outputCount };
  }
  if (command === 'verify-output') {
    const outputDir = optional('output');
    if (!outputDir) throw new Error('verify-output requires --output <directory>');
    return { command, ...verifyOutput(outputDir, true, optional('expected-key-fingerprint')) };
  }
  throw new Error(`unknown command: ${command ?? '<none>'} (expected plan, generate or verify-output)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = runArtefactGenerationCommand(process.argv[2]);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.complete === false) process.exitCode = 1;
}
