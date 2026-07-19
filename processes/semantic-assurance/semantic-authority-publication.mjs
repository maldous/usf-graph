// Coordinator-only publication entrypoint for the canonical semantic-model
// compiler. Publishes registered authored semantic source through one
// validated Stardog transaction; --mode=validate performs the full
// validate-and-rollback pass and --mode=commit performs the accepted
// publication. Credentials come only from the environment.
import stardog from 'stardog';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pathToFileURL } from 'node:url';

// Live SHACL validation of a full candidate can exceed the native fetch
// dispatcher's default headers timeout; wait for the semantic store instead
// of failing at the transport layer.
try { await fetch('http://127.0.0.1:1/', { signal: AbortSignal.timeout(20) }); } catch { /* initialise the dispatcher only */ }
const dispatcherSymbol = Symbol.for('undici.globalDispatcher.1');
const currentDispatcher = globalThis[dispatcherSymbol];
if (!currentDispatcher) throw new Error('global fetch dispatcher unavailable; cannot extend validation timeout');
globalThis[dispatcherSymbol] = new currentDispatcher.constructor({ headersTimeout: 0, bodyTimeout: 0 });

const { createStardogSemanticAuthorityClient } = await import('../../provider-bindings/stardog/semantic-authority.mjs');
const { validateSemanticAuthorityConfiguration } = await import('../../configuration/semantic-assurance/semantic-authority.mjs');
const { readSemanticAuthorityWitness } = await import('./semantic-authority-gateway.mjs');
const { createSemanticModelCompilationCommand } = await import('./semantic-model-compilation-command.mjs');

function requiredArgument(name) {
  const prefix = `--${name}=`;
  const matches = process.argv.filter((value) => value.startsWith(prefix));
  if (matches.length !== 1 || matches[0].length === prefix.length) throw new Error(`exactly one explicit ${prefix}<value> is required`);
  return matches[0].slice(prefix.length);
}

export async function runPublication({ mode, expectedAuthorityDigest }) {
  if (!['validate', 'commit'].includes(mode)) throw new Error('mode must be validate or commit');
  const { STARDOG_SERVER, STARDOG_DATABASE, STARDOG_TOKEN } = process.env;
  if (!STARDOG_SERVER || !STARDOG_DATABASE || !STARDOG_TOKEN) throw new Error('STARDOG_SERVER, STARDOG_DATABASE and STARDOG_TOKEN are required in the environment');
  const TOKEN_REFERENCE = 'secret://semantic-authority/token';
  const configuration = validateSemanticAuthorityConfiguration({
    accessMode: 'live',
    expectedAuthorityDigest,
    endpoint: STARDOG_SERVER,
    database: STARDOG_DATABASE,
    authentication: { mode: 'token', tokenReference: TOKEN_REFERENCE },
  });
  const client = createStardogSemanticAuthorityClient({
    sdk: stardog,
    configuration,
    resolveSecret: (reference) => {
      if (reference !== TOKEN_REFERENCE) throw new Error('unexpected secret reference');
      return STARDOG_TOKEN;
    },
  });
  const command = createSemanticModelCompilationCommand({
    client,
    readAuthorityWitness: readSemanticAuthorityWitness,
    repositoryRoot: resolve(fileURLToPath(import.meta.url), '../../..'),
  });
  const result = await command.execute({ expectedAuthorityDigest, publicationMode: mode });
  const after = await readSemanticAuthorityWitness(client);
  return Object.freeze({
    mode,
    ok: result.ok,
    commitOutcome: result.commitOutcome,
    contaminationCount: result.contaminationCount,
    graphsCleared: result.graphsCleared,
    authoredLoaded: result.authoredLoaded,
    shapesLoaded: result.shapesLoaded,
    evaluatedAuthorityDigest: result.evaluatedAuthorityDigest,
    postAuthorityDigest: after.digest || after.authorityDigest,
    postTriples: after.triples ?? null,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await runPublication({
    mode: requiredArgument('mode'),
    expectedAuthorityDigest: requiredArgument('authority-digest'),
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.ok) process.exitCode = 1;
}
