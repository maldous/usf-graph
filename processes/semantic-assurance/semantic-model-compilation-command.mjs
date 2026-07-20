import { lstatSync, realpathSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

import { compile, CompilerError } from '../../capabilities/semantic-model-compilation/compiler.mjs';
import { loadManifest } from '../../capabilities/semantic-model-compilation/manifest.mjs';

export const SEMANTIC_MODEL_PATH = 'semantic-model';
const SHA256 = /^sha256:[0-9a-f]{64}$/;

function digest(value) {
  const observed = value?.digest || value?.authorityDigest;
  if (typeof observed !== 'string') throw new CompilerError('authority witness is missing its digest', { phase: 'authority:witness' });
  return observed.startsWith('sha256:') ? observed : `sha256:${observed}`;
}

function semanticModelDirectory(repositoryRoot) {
  const root = realpathSync(repositoryRoot);
  const candidate = resolve(root, SEMANTIC_MODEL_PATH);
  const repositoryRelative = relative(root, candidate);
  if (repositoryRelative !== SEMANTIC_MODEL_PATH || repositoryRelative.startsWith(`..${sep}`)) {
    throw new CompilerError('semantic model path escapes the repository', { phase: 'compile:configuration' });
  }
  if (lstatSync(candidate).isSymbolicLink()) throw new CompilerError('semantic model path must not be a symbolic link', { phase: 'compile:configuration' });
  const canonical = realpathSync(candidate);
  if (relative(root, canonical) !== SEMANTIC_MODEL_PATH) throw new CompilerError('semantic model path resolves outside its canonical repository role', { phase: 'compile:configuration' });
  return canonical;
}

export function createSemanticModelCompilationCommand({
  client,
  readAuthorityWitness,
  repositoryRoot,
  loadManifestFunction = loadManifest,
  compileFunction = compile,
}) {
  if (!client || typeof client.connectivity !== 'function') throw new TypeError('semantic authority client is required');
  if (typeof readAuthorityWitness !== 'function') throw new TypeError('authority witness reader is required');
  if (typeof repositoryRoot !== 'string') throw new TypeError('repository root is required');

  return Object.freeze({
    async execute({ expectedAuthorityDigest, publicationMode = 'validate' }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before compilation', {
          phase: 'authority:drift',
          expectedAuthorityDigest,
          observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      const result = await compileFunction({
        authorityWitness: beforeWitness,
        client,
        manifest,
        publicationBudgetPolicy: manifest.publicationBudget,
        publicationMode,
      });
      if (publicationMode === 'validate') {
        const after = digest(await readAuthorityWitness(client));
        if (after !== before) throw new CompilerError('validate-only compilation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      return Object.freeze({
        ...result,
        evaluatedAuthorityDigest: before,
        semanticModelPath: SEMANTIC_MODEL_PATH,
      });
    },
  });
}

export const semanticModelCompilationCommandInternals = Object.freeze({ digest, semanticModelDirectory });
