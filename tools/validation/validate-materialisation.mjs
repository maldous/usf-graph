#!/usr/bin/env node
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadConfig } from '../compiler/src/config.js';
import { createClient } from '../compiler/src/stardog.js';
import { projectContract, validateLayoutPlan, verifyArtifact } from '../compiler/src/materialisation.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

function schemaFiles(path) {
  return readdirSync(path, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)).flatMap((entry) => {
    const child = join(path, entry.name);
    return entry.isDirectory() ? schemaFiles(child) : entry.name.endsWith('.schema.json') ? [child] : [];
  });
}

function validateSchemas() {
  const ids = new Set();
  const files = schemaFiles(join(root, 'schemas'));
  for (const file of files) {
    const schema = JSON.parse(readFileSync(file, 'utf8'));
    if (schema.$schema !== 'https://json-schema.org/draft/2020-12/schema') throw new Error(`${file}: unexpected JSON Schema dialect`);
    if (typeof schema.$id !== 'string' || ids.has(schema.$id)) throw new Error(`${file}: missing or duplicate schema identifier`);
    if (schema.additionalProperties !== false) throw new Error(`${file}: root must fail closed on unknown properties`);
    ids.add(schema.$id);
  }
  return { ok: true, code: 'SCHEMAS_VALID', schemaCount: files.length, schemaIds: [...ids].sort() };
}

function liveContext() {
  const config = loadConfig();
  return { client: createClient(config), config, casRoot: process.env.USF_CAS_ROOT || null };
}

try {
  const [command, value] = process.argv.slice(2);
  let result;
  if (command === 'schemas') result = validateSchemas();
  else if (command === 'plan' && value) result = await validateLayoutPlan(liveContext(), JSON.parse(readFileSync(resolve(value), 'utf8')));
  else if (command === 'artifact' && value) result = await verifyArtifact(liveContext(), { digest: value });
  else if (command === 'packet') result = await projectContract(liveContext(), { contract: value });
  else throw new Error('usage: validate-materialisation.mjs schemas | plan FILE | artifact DIGEST | packet [CONTRACT]');
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.ok === false || result.verified === false) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
