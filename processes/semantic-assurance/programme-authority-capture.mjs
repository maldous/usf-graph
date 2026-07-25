// Mechanical capture of the live authority binding for programme state
// generation.
//
// This is the only sanctioned producer of the programme authority-binding
// manifest. It reads live semantic authority through the approved boundary —
// the same validated connection configuration, read gateway and RDFC-1.0 graph
// inventory witness that back the usf MCP server — and records the captured
// identity together with the exact wave artefact set bound to it.
//
// Capture is fail-closed: if any presented wave artefact does not already bind
// the captured authority identity, no manifest is written. That ordering is
// deliberate. The wave is regenerated against current authority first, and only
// then can a manifest exist that lets the checkpoint generator run.
//
// This process performs no mutation. It issues read-only SELECT and CONSTRUCT
// queries and writes one content-addressed file under .work/generated.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig, describeConfig } from '../../configuration/semantic-assurance/stardog-connection.mjs';
import { createClient } from '../../provider-bindings/stardog/stardog-read-gateway.mjs';
import { readSemanticAuthorityWitness } from './semantic-authority-gateway.mjs';
import {
  AUTHORITY_BINDING_RECORD_KIND,
  AUTHORITY_BINDING_SCHEMA_VERSION,
  AUTHORITY_WITNESS_ALGORITHM,
  AuthorityBindingError,
  bindingDigest,
  canonicalBindingBytes,
  graphInventoryDigest,
  readAuthorityField,
  validateAuthorityBindingManifest,
} from '../../capabilities/semantic-model-compilation/programme-authority-binding.mjs';

const DEFAULT_AUTHORITY_FIELD = 'authorityDigest';

function fail(code, message, details) {
  throw new AuthorityBindingError(code, message, details);
}

// Build the manifest from an already-read witness plus the presented wave
// artefacts. Kept pure so tests can exercise every rejection path without a
// live endpoint.
export function buildAuthorityBindingManifest({
  capturedAt,
  database,
  endpoint,
  readArtefact,
  toolDigest,
  waveArtefacts,
  witness,
}) {
  if (!witness || typeof witness !== 'object') fail('AUTHORITY_CAPTURE_WITNESS_ABSENT', 'authority witness is required');
  if (witness.algorithm !== AUTHORITY_WITNESS_ALGORITHM) {
    fail('AUTHORITY_CAPTURE_ALGORITHM_UNSUPPORTED', 'witness algorithm is not the supported inventory witness', {
      algorithm: witness.algorithm,
    });
  }
  const digest = witness.digest;
  const inventory = (witness.inventory ?? []).map(({ graph, sha256, triples }) => ({ graph, sha256, triples }));
  if (inventory.length === 0) fail('AUTHORITY_CAPTURE_INVENTORY_EMPTY', 'witness inventory is empty');

  const bound = [];
  const divergent = [];
  for (const { role, path, authorityField = DEFAULT_AUTHORITY_FIELD } of waveArtefacts) {
    const bytes = readArtefact(path);
    const fileDigest = bindingDigest(bytes);
    let record;
    try {
      record = JSON.parse(bytes.toString('utf8'));
    } catch {
      fail('AUTHORITY_CAPTURE_ARTEFACT_MALFORMED', 'wave artefact is not valid JSON', { path, role });
    }
    const observed = readAuthorityField(record, authorityField);
    if (authorityField === null) {
      // Declared as carrying no authority field of its own. Confirm that is
      // actually true, so a mis-declaration cannot skip a real binding.
      if (typeof record?.authorityDigest === 'string') {
        fail('AUTHORITY_CAPTURE_FIELD_DECLARATION_INVALID', 'artefact declared bound-by-reference carries an authority digest', {
          path,
          role,
        });
      }
    } else if (observed !== digest) {
      divergent.push({ authorityField, observed: observed ?? null, role });
    }
    bound.push({ authorityField, fileDigest, path, role });
  }
  if (divergent.length > 0) {
    fail('AUTHORITY_CAPTURE_WAVE_DIVERGENT', 'wave artefacts do not bind the captured authority identity; regenerate the wave first', {
      capturedAuthorityDigest: digest,
      divergent: divergent.sort((left, right) => left.role.localeCompare(right.role)),
    });
  }

  const manifest = {
    authority: {
      database,
      digest,
      digestAlgorithm: AUTHORITY_WITNESS_ALGORITHM,
      endpoint,
      graphCount: inventory.length,
      graphInventory: inventory,
      graphInventoryDigest: graphInventoryDigest(inventory),
      tripleCount: witness.triples,
    },
    capture: {
      capturedAt,
      method: 'USF_SEMANTIC_AUTHORITY_GATEWAY_WITNESS',
      toolDigest,
      witnessSource: 'readSemanticAuthorityWitness',
    },
    recordKind: AUTHORITY_BINDING_RECORD_KIND,
    schemaVersion: AUTHORITY_BINDING_SCHEMA_VERSION,
    waveArtefacts: bound.sort((left, right) => left.role.localeCompare(right.role)),
  };
  validateAuthorityBindingManifest(manifest);
  return manifest;
}

function parseWaveArguments(argv) {
  const prefix = '--wave-artefact=';
  const parsed = argv.filter((argument) => argument.startsWith(prefix)).map((argument) => {
    const raw = argument.slice(prefix.length);
    const separator = raw.indexOf('=');
    if (separator <= 0) {
      fail('AUTHORITY_CAPTURE_WAVE_ARGUMENT_INVALID', 'expected --wave-artefact=<role>=<path>[:<field>]', { argument });
    }
    const role = raw.slice(0, separator);
    const remainder = raw.slice(separator + 1);
    const fieldSeparator = remainder.lastIndexOf(':');
    const hasField = fieldSeparator > 0 && !remainder.slice(fieldSeparator + 1).includes('/');
    const declaredField = hasField ? remainder.slice(fieldSeparator + 1) : DEFAULT_AUTHORITY_FIELD;
    return {
      // "none" declares an artefact that carries no authority field of its own.
      authorityField: declaredField === 'none' ? null : declaredField,
      path: hasField ? remainder.slice(0, fieldSeparator) : remainder,
      role,
    };
  });
  if (parsed.length === 0) {
    fail('AUTHORITY_CAPTURE_WAVE_REQUIRED', 'at least one --wave-artefact=<role>=<path> is required');
  }
  return parsed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
    const toolDigest = bindingDigest(readFileSync(fileURLToPath(import.meta.url)));
    const config = loadConfig();
    const described = describeConfig(config);
    const witness = await readSemanticAuthorityWitness(createClient(config));
    const manifest = buildAuthorityBindingManifest({
      capturedAt: new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z'),
      database: described.database,
      endpoint: described.endpoint,
      readArtefact: (path) => {
        const resolved = resolve(repositoryRoot, path);
        if (!resolved.startsWith(`${repositoryRoot}/`)) {
          fail('AUTHORITY_CAPTURE_PATH_ESCAPE', 'wave artefact path escapes the repository', { path });
        }
        return readFileSync(resolved);
      },
      toolDigest,
      waveArtefacts: parseWaveArguments(process.argv),
      witness,
    });
    const bytes = canonicalBindingBytes(manifest);
    const digest = bindingDigest(bytes);
    const outputPath = join('.work', 'generated', `programme-authority-binding-${digest.slice('sha256:'.length)}.json`);
    mkdirSync(dirname(join(repositoryRoot, outputPath)), { recursive: true });
    writeFileSync(join(repositoryRoot, outputPath), bytes);
    process.stdout.write(`${JSON.stringify({
      authorityDigest: manifest.authority.digest,
      command: 'programme-authority-capture',
      graphCount: manifest.authority.graphCount,
      manifestDigest: digest,
      outputPath,
      tripleCount: manifest.authority.tripleCount,
      waveArtefactCount: manifest.waveArtefacts.length,
    })}\n`);
  } catch (error) {
    process.stderr.write(`${error.code ?? error.name}: ${error.message}\n`);
    process.exitCode = 1;
  }
}
