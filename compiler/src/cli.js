#!/usr/bin/env node
// Command-line entry point for the USF semantic compiler.
//
//   node src/cli.js check     local manifest + graph checks (no network)
//   node src/cli.js compile   transactionally provision the graph into Stardog
//   node src/cli.js verify    read-only conformance report as JSON
//
// All output is structured JSON on stdout. Credentials are never printed.

import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { loadConfig, describeConfig } from './config.js';
import { loadManifest } from './manifest.js';
import { createClient } from './stardog.js';
import { checkLocal, compile, verify, verificationConforms, CompilerError } from './compiler.js';
import { verifyFixtures } from './fixture-harness.js';
import { loadAuthorityDataset } from './authority-dataset.js';
import { buildGenerationPlan } from './generation-plan.js';
import { collectObservedEntry } from './source-observer.js';
import { generateAuthority, verifyOutput } from './generate.js';
import {
  createLiveAttestation,
  observeLiveDrift,
  snapshotDerivedGraphs,
  verifyLiveAttestation,
} from './live-attestation.js';

const GRAPH_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'graph');

function emit(obj) {
  process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
}

async function main() {
  const command = process.argv[2];

  if (command === 'check') {
    const manifest = loadManifest(GRAPH_DIR);
    const summary = checkLocal(manifest);
    emit({ command, ...summary });
    return 0;
  }

  if (command === 'plan') {
    const manifest = loadManifest(GRAPH_DIR);
    checkLocal(manifest);
    const dataset = loadAuthorityDataset(manifest);
    const plan = buildGenerationPlan(dataset.store);
    emit({ command, dataset: { files: dataset.files, quads: dataset.quads, counts: dataset.counts }, ...plan });
    return plan.complete ? 0 : 1;
  }

  if (command === 'snapshot-observed') {
    const manifest = loadManifest(GRAPH_DIR);
    checkLocal(manifest);
    const snapshots = [];
    for (const entry of manifest.observed) {
      if (!entry.path) throw new CompilerError(`observed collector has no snapshot path: ${entry.collector}`, { phase: 'snapshot-observed' });
      const collection = await collectObservedEntry({ manifest, entry });
      writeFileSync(entry.path, collection.content, 'utf8');
      snapshots.push({ graph: entry.graph, file: entry.file, sources: collection.sourceCount, triples: collection.tripleCount, observationSetDigest: collection.observationSetDigest, excludedCarrierPaths: collection.excludedCarrierPaths });
    }
    emit({ command, snapshots });
    return 0;
  }

  if (command === 'generate') {
    const outputAt = process.argv.indexOf('--output');
    const modeAt = process.argv.indexOf('--mode');
    const signingAt = process.argv.indexOf('--signing-key');
    const sourceRootAt = process.argv.indexOf('--source-root');
    if (outputAt < 0 || !process.argv[outputAt + 1]) throw new CompilerError('generate requires --output <directory>', { phase: 'generate:configuration' });
    const manifest = loadManifest(GRAPH_DIR);
    checkLocal(manifest);
    const dataset = loadAuthorityDataset(manifest);
    emit({ command, ...generateAuthority({ store: dataset.store, outputDir: process.argv[outputAt + 1], mode: modeAt >= 0 ? process.argv[modeAt + 1] : 'full', signingKeyPath: signingAt >= 0 ? process.argv[signingAt + 1] : null, sourceRoot: sourceRootAt >= 0 ? process.argv[sourceRootAt + 1] : join(GRAPH_DIR, '..', '..', '..') }) });
    return 0;
  }

  if (command === 'verify-output') {
    const outputAt = process.argv.indexOf('--output');
    const fingerprintAt = process.argv.indexOf('--expected-key-fingerprint');
    if (outputAt < 0 || !process.argv[outputAt + 1]) throw new CompilerError('verify-output requires --output <directory>', { phase: 'verify-output:configuration' });
    emit({ command, ...verifyOutput(process.argv[outputAt + 1], true, fingerprintAt >= 0 ? process.argv[fingerprintAt + 1] : null) });
    return 0;
  }

  if (command === 'compile') {
    const config = loadConfig();
    const manifest = loadManifest(GRAPH_DIR);
    const client = createClient(config);
    const result = await compile({ manifest, client });
    emit({ command, target: describeConfig(config), ...result });
    return 0;
  }

  if (command === 'snapshot-derived') {
    const config = loadConfig();
    const manifest = loadManifest(GRAPH_DIR);
    checkLocal(manifest);
    const client = createClient(config);
    emit({ command, target: describeConfig(config), ...await snapshotDerivedGraphs({ manifest, client }) });
    return 0;
  }

  if (command === 'verify-fixtures') {
    const config = loadConfig();
    const manifest = loadManifest(GRAPH_DIR);
    checkLocal(manifest);
    const client = createClient(config);
    const result = await verifyFixtures({ manifest, client });
    emit({ command, target: describeConfig(config), ...result });
    return result.ok ? 0 : 1;
  }

  if (command === 'drift-live') {
    const config = loadConfig();
    const manifest = loadManifest(GRAPH_DIR);
    const client = createClient(config);
    const result = await observeLiveDrift({ manifest, client });
    emit({ command, target: describeConfig(config), ...result });
    return result.conforms ? 0 : 1;
  }

  if (command === 'attest-live') {
    const outputAt = process.argv.indexOf('--output');
    const signingAt = process.argv.indexOf('--signing-key');
    if (outputAt < 0 || !process.argv[outputAt + 1] || signingAt < 0 || !process.argv[signingAt + 1]) {
      throw new CompilerError('attest-live requires --output <external-file> --signing-key <ed25519-private-key>', { phase: 'attest:configuration' });
    }
    const config = loadConfig();
    const manifest = loadManifest(GRAPH_DIR);
    const client = createClient(config);
    const result = await createLiveAttestation({
      manifest,
      client,
      repoRoot: join(GRAPH_DIR, '..', '..', '..'),
      target: describeConfig(config),
      signingKeyPath: process.argv[signingAt + 1],
      outputPath: process.argv[outputAt + 1],
    });
    emit({ command, target: describeConfig(config), ...result });
    return 0;
  }

  if (command === 'verify-live-attestation') {
    const inputAt = process.argv.indexOf('--input');
    const fingerprintAt = process.argv.indexOf('--expected-key-fingerprint');
    if (inputAt < 0 || !process.argv[inputAt + 1] || fingerprintAt < 0 || !process.argv[fingerprintAt + 1]) {
      throw new CompilerError('verify-live-attestation requires --input <file> --expected-key-fingerprint <sha256>', { phase: 'attest:verify' });
    }
    const config = loadConfig();
    const manifest = loadManifest(GRAPH_DIR);
    const client = createClient(config);
    const result = await verifyLiveAttestation({
      inputPath: process.argv[inputAt + 1],
      expectedKeyFingerprint: process.argv[fingerprintAt + 1],
      manifest,
      client,
      repoRoot: join(GRAPH_DIR, '..', '..', '..'),
    });
    emit({ command, target: describeConfig(config), ...result });
    return result.ok ? 0 : 1;
  }

  if (command === 'verify') {
    const config = loadConfig();
    const manifest = loadManifest(GRAPH_DIR);
    const client = createClient(config);
    const report = await verify({ manifest, client });
    emit({ command, target: describeConfig(config), ...report });
    return verificationConforms(report) ? 0 : 1;
  }

  if (command === 'mcp') {
    // Read-only Stardog MCP server on stdio. It owns stdout for JSON-RPC, so it
    // must not go through emit(); it returns when stdin closes.
    const { runMcpServer } = await import('./mcp.js');
    await runMcpServer();
    return 0;
  }

  process.stderr.write('usage: cli.js <check|plan|snapshot-observed|snapshot-derived|generate|verify-output|compile|verify|verify-fixtures|drift-live|attest-live|verify-live-attestation|mcp>\n');
  return 2;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    if (err instanceof CompilerError) {
      const { name, message, phase, failures, violations, count, obligations, report } = err;
      emit({ ok: false, error: name, phase, message, failures, violations, count, obligations, report });
    } else {
      // Config and adapter errors are already credential-free by construction.
      emit({ ok: false, error: err.name || 'Error', message: err.message });
    }
    process.exit(1);
  });
