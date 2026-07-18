import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import {
  canonicalJson,
  materialisePlan,
  validateMaterialisationPlan,
} from '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';

const readJson = (path, label) => {
  if (!path) throw new Error(`${label} path is required`);
  return JSON.parse(readFileSync(path, 'utf8'));
};

export function runRepositoryMaterialisationCommand(argv, output = process.stdout) {
  const [command, authorityPath, planPath, repositoryRoot, casRoot] = argv;
  const authority = readJson(authorityPath, 'authority projection');
  const plan = readJson(planPath, 'materialisation plan');
  let result;
  if (command === 'validate') result = validateMaterialisationPlan(authority, plan);
  else if (command === 'dry-run') result = materialisePlan({ authority, plan, repositoryRoot, casRoot, apply: false });
  else if (command === 'apply') result = materialisePlan({ authority, plan, repositoryRoot, casRoot, apply: true });
  else throw new Error('command must be validate, dry-run or apply');
  output.write(`${canonicalJson(result)}\n`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = runRepositoryMaterialisationCommand(process.argv.slice(2));
    if (result.validation?.ok === false || result.ok === false) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
