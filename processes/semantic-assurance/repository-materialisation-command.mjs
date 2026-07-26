import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import {
  canonicalJson,
  validateMaterialisationPlan,
} from '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';

// Non-mutating plan diagnostics only.
//
// This command used to offer `dry-run` and `apply` over an authority projection
// read from a FILE, so a hand-written projection could drive a coordinator apply
// without any live authority decision. That made it a second executable
// materialisation path alongside the canonical gateway.
//
// Materialisation apply is now available solely through
// processes/semantic-assurance/repository-materialisation-gateway.mjs, where
// realisationVerdict brackets the complete semantic read with before/after
// inventory witnesses, every plan surface consumes that verdict, and apply
// re-proves the witness immediately before the first mutation and again after the
// last one. A structural regression fails if an apply capability reappears outside
// it.
const readJson = (path, label) => {
  if (!path) throw new Error(`${label} path is required`);
  return JSON.parse(readFileSync(path, 'utf8'));
};

export function runRepositoryMaterialisationCommand(argv, output = process.stdout) {
  const [command, authorityPath, planPath] = argv;
  if (command !== 'validate') {
    throw new Error(
      'command must be validate; dry-run and apply are only available through the '
      + 'canonical materialisation gateway under a digest-stable realisation verdict',
    );
  }
  const authority = readJson(authorityPath, 'authority projection');
  const plan = readJson(planPath, 'materialisation plan');
  const result = validateMaterialisationPlan(authority, plan);
  output.write(`${canonicalJson(result)}\n`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = runRepositoryMaterialisationCommand(process.argv.slice(2));
    if (result.ok === false) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
