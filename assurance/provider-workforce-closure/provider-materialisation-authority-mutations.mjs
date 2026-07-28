import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from 'node:path';
import { spawnSync } from 'node:child_process';

import {
  inspectPinnedPythonRuntime,
  spawnPinnedLocalShaclRuntime,
  validateLocalShaclRuntime,
} from '../semantic-model-compilation/local-shacl-validation.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const PYTHON_ARGUMENT_PREFIX = Object.freeze(['-I', '-S', '-']);
const PYTHON_WORKING_DIRECTORY = '/';
const ISOLATED_SITE_BOOTSTRAP = 'import sys\nsys.path.insert(0, sys.argv.pop(1))\n';
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const exactKeys = (value, expected) => value && typeof value === 'object' && !Array.isArray(value)
  && canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort());

const EXPECTED_NODE_DEPENDENCY_EVIDENCE = Object.freeze({
  schemaVersion: 1,
  rootPackage: 'n3',
  nodeVersion: '22.23.1',
  executableDigest: 'sha256:93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068',
  systemObjectCount: 7,
  systemObjectSetDigest: 'sha256:8ccc776eccd2957c5e52e5e35ae7e311716e20de0b251424e600305b7fce335e',
  packageLockDigest: 'sha256:e0f320742ed96b54765a39ccac219c05d72b61c4b8805b42e57b7e9e14cecde5',
  packages: Object.freeze([
    Object.freeze({ byteSetDigest: 'sha256:e2175a0928f0f9e65b04f6f96c88c28a0eb2b9fd0c5feb176c0b9403c27258d5', fileCount: 14, name: 'abort-controller', version: '3.0.0' }),
    Object.freeze({ byteSetDigest: 'sha256:457cd55fa8403d3eb7af65dbacc44fd27fc8cd0eab4f9214541811f9c6e2f46d', fileCount: 6, name: 'base64-js', version: '1.5.1' }),
    Object.freeze({ byteSetDigest: 'sha256:cec6bc16225337081aaff04f39924b78b44a6d4271d4beb2af86abd6cfb4a1a0', fileCount: 6, name: 'buffer', version: '6.0.3' }),
    Object.freeze({ byteSetDigest: 'sha256:a90a0678a6d7d2aee7c3a5a6c229ad1d7482a89b7f13632ab0a7d85559543b31', fileCount: 10, name: 'event-target-shim', version: '5.0.1' }),
    Object.freeze({ byteSetDigest: 'sha256:06e000873e10b7861b2201e64fab727b3ee91e448fac4385e3ab94f288ccffbb', fileCount: 32, name: 'events', version: '3.3.0' }),
    Object.freeze({ byteSetDigest: 'sha256:8d7e733b4a7b80bbede3103b1c7304ee4d781f70ec05f01a5c9b8dcc61fad9e0', fileCount: 5, name: 'ieee754', version: '1.2.1' }),
    Object.freeze({ byteSetDigest: 'sha256:0bec16a473e76bbb673da9170ce360ee49136fa472add6c5b09935973e2c1c86', fileCount: 34, name: 'n3', version: '2.1.1' }),
    Object.freeze({ byteSetDigest: 'sha256:e1bb70a734fe9480d1ec56efd8f889144cef15cd707ca6a1e996362168ce2c90', fileCount: 7, name: 'process', version: '0.11.10' }),
    Object.freeze({ byteSetDigest: 'sha256:6f1104921f45877fc4339be142062e0796548d87c38f2161f1ef4960fa8759a1', fileCount: 35, name: 'readable-stream', version: '4.7.0' }),
    Object.freeze({ byteSetDigest: 'sha256:256550e9afa169219e122c186930a14882a2b2fbfe28557eb5ae668dc2ae3751', fileCount: 5, name: 'safe-buffer', version: '5.2.1' }),
    Object.freeze({ byteSetDigest: 'sha256:3b72575555c05c83b6612ece259cf1fa99efd11de3f6d065384ad4015db35f44', fileCount: 4, name: 'string_decoder', version: '1.3.0' }),
  ]),
  byteSetDigest: 'sha256:b6186e1029889dec349f186b024836b63cc4e67a39db9abb5c74698341d1f0b8',
});

const EXPECTED_PYTHON_DEPENDENCY_BYTE_SETS = Object.freeze([
  Object.freeze({ byteSetDigest: 'sha256:d84b76a11d3bf44112b31cedc6fcf691f0d1af7374d21813ddd0821ffe9c3d4b', fileCount: 19, name: 'importlib_metadata', version: '9.0.0' }),
  Object.freeze({ byteSetDigest: 'sha256:868d5c034038c6cc77d1cd3c798d07dc70b39a475648859e13c2563ed801d134', fileCount: 17, name: 'owlrl', version: '7.6.2' }),
  Object.freeze({ byteSetDigest: 'sha256:410054f1476d5f1c7abd3c85ea246313186bb003672dc5395a9ba65e4672381e', fileCount: 28, name: 'packaging', version: '26.2' }),
  Object.freeze({ byteSetDigest: 'sha256:58ace01edd6a0bf20c5372fabb87dd27dd44521f86f98d160f8bed9e31653eab', fileCount: 11, name: 'prettytable', version: '3.18.0' }),
  Object.freeze({ byteSetDigest: 'sha256:155b0d3574fd4594252e925ad26f262a171511fc2a889aac7795137a14af8820', fileCount: 24, name: 'pyparsing', version: '3.3.2' }),
  Object.freeze({ byteSetDigest: 'sha256:2550e5ddbcbeb6cb7fac246eb9318356142887c8fdaf306ee4465f1a19ed20cb', fileCount: 86, name: 'pyshacl', version: '0.40.0' }),
  Object.freeze({ byteSetDigest: 'sha256:40abaf36ef913ca4342a2b8214f66ef680a33b6af601b93fca85ae720976d010', fileCount: 26, name: 'PyYAML', version: '6.0.3' }),
  Object.freeze({ byteSetDigest: 'sha256:b49b35470619eff88f9e174e870486bc64afba763d466e271608020b25a27aed', fileCount: 150, name: 'rdflib', version: '7.6.0' }),
  Object.freeze({ byteSetDigest: 'sha256:572d08b6177a0d6197db4c0f2c97d225df2d8bc985a2e68e75958d043765113e', fileCount: 53, name: 'wcwidth', version: '0.8.2' }),
  Object.freeze({ byteSetDigest: 'sha256:53ba7f91f8878126ecb692e69da09d447dd6482c2e74902d8c1bd220625c41c7', fileCount: 13, name: 'zipp', version: '4.1.0' }),
]);
const EXPECTED_PYTHON_DEPENDENCY_BYTE_SET_DIGEST = 'sha256:86d9f76eadf8feafaf8394e41133cf7118ae0fde3a3e3874428bfecdc8869d8e';

function packageFiles(root, current = root, records = []) {
  const entries = readdirSync(current, { withFileTypes: true })
    .sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)));
  for (const entry of entries) {
    const path = join(current, entry.name);
    const status = lstatSync(path);
    if (status.isSymbolicLink()) throw new Error('NODE_DEPENDENCY_SYMLINK_PROHIBITED');
    if (status.isDirectory()) {
      packageFiles(root, path, records);
    } else if (status.isFile()) {
      records.push({
        path: relative(root, path).replaceAll('\\', '/'),
        digest: sha256(readFileSync(path)),
        byteSize: status.size,
      });
    } else {
      throw new Error('NODE_DEPENDENCY_SPECIAL_FILE_PROHIBITED');
    }
  }
  return records;
}

function inspectNodeDependencyEvidence({
  repositoryRoot,
  rootPackage = 'n3',
  resolvePackageJson = null,
}) {
  const root = realpathSync(repositoryRoot);
  const require = createRequire(import.meta.url);
  const resolver = resolvePackageJson ?? ((name) => require.resolve(`${name}/package.json`));
  const packages = new Map();
  const inspect = (name) => {
    if (packages.has(name)) return;
    const packageJsonPath = realpathSync(resolver(name));
    const packageRoot = dirname(packageJsonPath);
    const repositoryRelativeRoot = relative(root, packageRoot).replaceAll('\\', '/');
    if (repositoryRelativeRoot.startsWith('../') || !repositoryRelativeRoot.startsWith('node_modules/')) {
      throw new Error(`NODE_DEPENDENCY_OUTSIDE_REPOSITORY_${name}`);
    }
    const manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
    const files = packageFiles(packageRoot);
    packages.set(name, {
      byteSetDigest: sha256(canonicalJson(files)),
      fileCount: files.length,
      name,
      version: manifest.version,
    });
    for (const dependency of Object.keys(manifest.dependencies ?? {}).sort()) inspect(dependency);
  };
  inspect(rootPackage);
  const records = [...packages.values()]
    .sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)));
  const executablePath = realpathSync(process.execPath);
  const systemPaths = new Set();
  for (const line of readFileSync('/proc/self/maps', 'utf8').split('\n')) {
    const path = line.trim().split(/\s+/).at(-1);
    if (!path?.startsWith('/')) continue;
    try {
      const resolvedPath = realpathSync(path);
      if (resolvedPath !== executablePath) systemPaths.add(resolvedPath);
    } catch {
      // Anonymous, deleted, or concurrently unmapped entries are not file-backed runtime dependencies.
    }
  }
  const systemObjects = [...systemPaths]
    .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
    .map((path) => ({
      path,
      digest: sha256(readFileSync(path)),
      byteSize: lstatSync(path).size,
    }));
  return Object.freeze({
    schemaVersion: 1,
    rootPackage,
    nodeVersion: process.versions.node,
    executableDigest: sha256(readFileSync(executablePath)),
    systemObjectCount: systemObjects.length,
    systemObjectSetDigest: sha256(canonicalJson(systemObjects)),
    packageLockDigest: sha256(readFileSync(join(root, 'package-lock.json'))),
    packages: records,
    byteSetDigest: sha256(canonicalJson(records)),
  });
}

export function verifyProviderProofNodeDependencyEvidence(evidence, { repositoryRoot = null } = {}) {
  if (canonicalJson(evidence) !== canonicalJson(EXPECTED_NODE_DEPENDENCY_EVIDENCE)) {
    throw new Error('NODE_DEPENDENCY_EVIDENCE_MISMATCH');
  }
  if (repositoryRoot !== null
    && canonicalJson(inspectNodeDependencyEvidence({ repositoryRoot }))
      !== canonicalJson(EXPECTED_NODE_DEPENDENCY_EVIDENCE)) {
    throw new Error('NODE_DEPENDENCY_BYTE_SET_MISMATCH');
  }
  return Object.freeze(evidence);
}

export function inspectProviderProofNodeDependencies({ repositoryRoot }) {
  const evidence = inspectNodeDependencyEvidence({ repositoryRoot });
  return verifyProviderProofNodeDependencyEvidence(evidence);
}

export function normaliseDeterministicPytestOutput(stdout) {
  const lines = Buffer.from(stdout).toString('utf8').split(/\r?\n/).filter((line) => line.length > 0);
  const progressLines = lines.filter((line) => /^\.+\s+\[\s*\d+%\]$/.test(line));
  const runtimeLines = lines.filter((line) => line.startsWith('USF_PYTEST_RUNTIME_EVIDENCE='));
  const summaryLines = lines.filter((line) => /^\d+ passed in \d+(?:\.\d+)?s$/.test(line));
  const unknownLines = lines.filter((line) => !progressLines.includes(line)
    && !runtimeLines.includes(line) && !summaryLines.includes(line));
  if (!progressLines.length
    || progressLines.at(-1)?.match(/\[\s*(\d+)%\]$/)?.[1] !== '100'
    || progressLines.some((line) => !/^\.+\s+\[\s*\d+%\]$/.test(line))
    || runtimeLines.length > 1
    || summaryLines.length > 1
    || unknownLines.length > 0) {
    throw new Error('PYTEST_PROGRESS_OUTPUT_INVALID');
  }
  let runtimeEvidence = null;
  if (runtimeLines.length === 1) {
    try {
      runtimeEvidence = JSON.parse(runtimeLines[0].slice('USF_PYTEST_RUNTIME_EVIDENCE='.length));
    } catch {
      throw new Error('PYTEST_RUNTIME_EVIDENCE_JSON_INVALID');
    }
    if (!exactKeys(runtimeEvidence, [
      'mappedSystemObjectCount',
      'mappedSystemObjectSetDigest',
      'siteCustomizationLoaded',
    ])
      || !Number.isSafeInteger(runtimeEvidence.mappedSystemObjectCount)
      || runtimeEvidence.mappedSystemObjectCount < 1
      || !SHA256.test(runtimeEvidence.mappedSystemObjectSetDigest || '')
      || runtimeEvidence.siteCustomizationLoaded !== false) {
      throw new Error('PYTEST_RUNTIME_EVIDENCE_INVALID');
    }
  }
  const completedCaseCount = progressLines
    .reduce((count, line) => count + line.slice(0, line.indexOf(' ')).length, 0);
  const summaryPassedCount = summaryLines.length === 1
    ? Number(summaryLines[0].match(/^(\d+) passed/)?.[1])
    : completedCaseCount;
  if (summaryPassedCount !== completedCaseCount) throw new Error('PYTEST_SUMMARY_COUNT_MISMATCH');
  return Buffer.from(canonicalJson({
    schemaVersion: 2,
    normalisation: 'PYTEST_DOT_PROGRESS_AND_RUNTIME_V2',
    completedCaseCount,
    progressLines,
    runtimeEvidence,
    summaryPassedCount,
  }));
}

export const PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS = Object.freeze([
  'semantic-model/manifest.yaml',
  'semantic-model/ontology.ttl',
  'semantic-model/taxonomy.ttl',
  'semantic-model/vocabulary.ttl',
  'semantic-model/authority.ttl',
  'semantic-model/registry.ttl',
  'semantic-model/environments.ttl',
  'semantic-model/claims.ttl',
  'semantic-model/contracts/capabilities.trig',
  'semantic-model/contracts/policies.trig',
  'semantic-model/contracts/interfaces.trig',
  'semantic-model/contracts/interactions.trig',
  'semantic-model/contracts/platform.trig',
  'semantic-model/contracts/data.trig',
  'semantic-model/contracts/signals.trig',
  'semantic-model/contracts/experience.trig',
  'semantic-model/assurance/proofs.trig',
  'semantic-model/assurance/evidence.trig',
  'semantic-model/assurance/controls.trig',
  'semantic-model/assurance/tests.trig',
  'semantic-model/realisation/bindings.trig',
  'semantic-model/execution/agents.trig',
  'semantic-model/execution/validators.trig',
  'semantic-model/assurance/enterprise.trig',
  'semantic-model/assurance/profiles.trig',
  'semantic-model/assurance/gates.trig',
  'semantic-model/contracts/ui.trig',
  'semantic-model/realisation/renderers.trig',
  'semantic-model/contracts/generation.trig',
  'semantic-model/contracts/semantic-depth.trig',
  'semantic-model/contracts/materialisation.trig',
  'semantic-model/permutation/closure-vocabulary.trig',
  'semantic-model/permutation/action-catalogue.trig',
  'semantic-model/permutation/transport-catalogue.trig',
  'semantic-model/permutation/families.trig',
  'semantic-model/derived/obligations.trig',
  'semantic-model/derived/evidence.trig',
  'semantic-model/derived/surfaces.trig',
  'semantic-model/derived/coverage.trig',
  'semantic-model/derived/readiness.trig',
  'semantic-model/shapes/materialisation.ttl',
  'semantic-model/rules/integrity.rq',
  'semantic-model/shapes/lifecycle.ttl',
  'semantic-model/rules/lifecycle.rq',
].sort());

export const PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS = Object.freeze([
  '.env.example',
  'config/budgets.yaml',
  'config/providers.yaml',
  'config/qualification-suite.yaml',
  'config/routing.yaml',
  'config/safe-adaptive-execution.yaml',
  'config/safety.yaml',
  'config/workforce-policy.yaml',
  'scripts/check-provider-env.py',
  'scripts/import-provider-env.py',
  'scripts/run-safe-adaptive.sh',
  'scripts/supervise-safe-adaptive.sh',
  'src/usf_factory/accounting.py',
  'src/usf_factory/accounting_models.py',
  'src/usf_factory/accounting_runtime.py',
  'src/usf_factory/activation.py',
  'src/usf_factory/adaptive_execution.py',
  'src/usf_factory/admission.py',
  'src/usf_factory/agent_runtime.py',
  'src/usf_factory/bootstrap.py',
  'src/usf_factory/budget.py',
  'src/usf_factory/capabilities.py',
  'src/usf_factory/cli.py',
  'src/usf_factory/config.py',
  'src/usf_factory/context.py',
  'src/usf_factory/eligibility.py',
  'src/usf_factory/engine.py',
  'src/usf_factory/enums.py',
  'src/usf_factory/errors.py',
  'src/usf_factory/event_store.py',
  'src/usf_factory/identity_evidence.py',
  'src/usf_factory/lazy_qualification.py',
  'src/usf_factory/model_market.py',
  'src/usf_factory/model_market_runtime.py',
  'src/usf_factory/model_registry.py',
  'src/usf_factory/models.py',
  'src/usf_factory/paths.py',
  'src/usf_factory/prompt_cache.py',
  'src/usf_factory/probes.py',
  'src/usf_factory/probing.py',
  'src/usf_factory/provider_eval.py',
  'src/usf_factory/providers/anthropic.py',
  'src/usf_factory/providers/base.py',
  'src/usf_factory/providers/cli_adapters.py',
  'src/usf_factory/providers/codex_containment.py',
  'src/usf_factory/providers/__init__.py',
  'src/usf_factory/providers/ollama.py',
  'src/usf_factory/providers/openai_compatible.py',
  'src/usf_factory/providers/registry.py',
  'src/usf_factory/qualification.py',
  'src/usf_factory/review.py',
  'src/usf_factory/roster.py',
  'src/usf_factory/run_authorization.py',
  'src/usf_factory/runtime.py',
  'src/usf_factory/secrets.py',
  'src/usf_factory/selection.py',
  'src/usf_factory/supervised_scheduler.py',
  'src/usf_factory/workforce.py',
  'src/usf_factory/workforce_policy.py',
  'src/usf_factory/workers.py',
]);

export const PROVIDER_WORKFORCE_PROOF_INPUT_PATHS = Object.freeze([
  '.gitignore',
  'config/data-egress-policy.yaml',
  'config/task-classes.yaml',
  'config/trust-policy.yaml',
  'pyproject.toml',
  'qualifications/holdout/holdout-v1.yaml',
  'qualifications/implementation-review.yaml',
  'qualifications/rdf-owl-shacl.yaml',
  'qualifications/semantic-planning.yaml',
  'src/usf_factory/__init__.py',
  'src/usf_factory/authority.py',
  'src/usf_factory/canonical.py',
  'src/usf_factory/cas_resolution.py',
  'src/usf_factory/clock.py',
  'src/usf_factory/deadlines.py',
  'src/usf_factory/graph_contract.py',
  'src/usf_factory/ids.py',
  'src/usf_factory/isolation.py',
  'src/usf_factory/token_efficiency.py',
  'tests/conftest.py',
  'tests/test_free_tier_classification.py',
  'tests/test_model_market.py',
  'tests/test_provider_contact_exclusions.py',
  'tests/test_secrets.py',
  'tests/test_workforce_bootstrap.py',
  'tests/test_workforce_policy.py',
]);

export const PROVIDER_MATERIALISATION_MUTATION_CASES = Object.freeze([
  ['scope-mode-provider-flip', 'materialisation-contract-scope-mode', 'materialisationcontractscopemodeinvalid'],
  ['scope-mode-legacy-flip', 'materialisation-contract-scope-mode', 'materialisationcontractscopemodeinvalid'],
  ['effective-decision-missing', 'decision-scoped-materialisation-effective-decision', 'decisionscopedmaterialisationeffectivedecisioninvalid'],
  ['effective-decision-substitution', 'decision-scoped-materialisation-effective-decision', 'decisionscopedmaterialisationeffectivedecisioninvalid'],
  ['repository-wrong-single', 'decision-scoped-materialisation-repository', 'decisionscopedmaterialisationrepositoryinvalid'],
  ['repository-extra', 'decision-scoped-materialisation-repository', 'decisionscopedmaterialisationrepositoryinvalid'],
  ['directory-wrong-single', 'decision-scoped-materialisation-directory-set', 'decisionscopedmaterialisationdirectorysetinvalid'],
  ['directory-extra-normalised', 'decision-scoped-materialisation-directory-set', 'decisionscopedmaterialisationdirectorysetinvalid'],
  ['directory-path-overlap', 'decision-scoped-materialisation-directory', 'decisionscopedmaterialisationpathinvalid'],
  ['exact-path-missing', 'decision-scoped-materialisation-path-set', 'decisionscopedmaterialisationpathsetinvalid'],
  ['exact-path-extra-normalised', 'decision-scoped-materialisation-path-set', 'decisionscopedmaterialisationpathsetinvalid'],
  ['family-missing', 'decision-scoped-materialisation-family-set', 'decisionscopedmaterialisationfamilysetinvalid'],
  ['family-extra', 'decision-scoped-materialisation-family-set', 'decisionscopedmaterialisationfamilysetinvalid'],
  ['rule-role-substitution', 'decision-scoped-materialisation-rule', 'decisionscopedmaterialisationruleinvalid'],
  ['rule-second', 'decision-scoped-materialisation-rule', 'decisionscopedmaterialisationruleinvalid'],
  ['rule-identity-substitution', 'decision-scoped-materialisation-rule', 'decisionscopedmaterialisationruleinvalid'],
  ['rule-storage-substitution', 'decision-scoped-materialisation-rule', 'decisionscopedmaterialisationruleinvalid'],
  ['rule-extension-missing', 'decision-scoped-materialisation-rule', 'decisionscopedmaterialisationruleinvalid'],
  ['rule-extension-duplicate', 'decision-scoped-materialisation-rule', 'decisionscopedmaterialisationruleinvalid'],
  ['rule-naming-substitution', 'decision-scoped-materialisation-rule', 'decisionscopedmaterialisationruleinvalid'],
  ['rule-naming-pattern-substitution', 'decision-scoped-materialisation-naming-pattern', 'decisionscopedmaterialisationnamingpatterninvalid'],
  ['legacy-directory', 'decision-scoped-materialisation-legacy', 'legacymaterialisationdecisionhasscopedpermission'],
  ['legacy-action', 'decision-scoped-materialisation-legacy', 'legacymaterialisationdecisionhasscopedpermission'],
  ['legacy-family', 'decision-scoped-materialisation-legacy', 'legacymaterialisationdecisionhasscopedpermission'],
  ['unexpected-action', 'decision-scoped-materialisation-action', 'decisionscopedmaterialisationpermissionambiguous'],
  ['non-scoped-directory-substitution', 'Implementable realisation requires', 'implementationpathunauthorised'],
].map(([id, expectedShaclCode, expectedIntegrityCode]) => Object.freeze({
  id,
  expectedShaclCode,
  expectedIntegrityCode,
})));

export function prepareExactSessionOutputRoot({
  repositoryRoot,
  requestedOutputRoot,
  clear = false,
}) {
  if (!isAbsolute(repositoryRoot || '') || !isAbsolute(requestedOutputRoot || '')) {
    throw new TypeError('session output repository and requested paths must be absolute');
  }
  const root = realpathSync(repositoryRoot);
  const sessionRoot = resolve(root, '.work');
  const outputRoot = resolve(requestedOutputRoot);
  if (dirname(outputRoot) !== sessionRoot) throw new Error('OUTPUT_ROOT_NOT_DIRECT_SESSION_CHILD');
  if (!existsSync(sessionRoot)) mkdirSync(sessionRoot, { recursive: false, mode: 0o700 });
  const sessionStat = lstatSync(sessionRoot);
  if (sessionStat.isSymbolicLink() || !sessionStat.isDirectory() || realpathSync(sessionRoot) !== sessionRoot) {
    throw new Error('SESSION_ROOT_NOT_EXACT_DIRECTORY');
  }
  if (existsSync(outputRoot)) {
    const outputStat = lstatSync(outputRoot);
    if (outputStat.isSymbolicLink() || !outputStat.isDirectory() || dirname(realpathSync(outputRoot)) !== sessionRoot) {
      throw new Error('OUTPUT_ROOT_NOT_EXACT_DIRECTORY');
    }
    if (clear) rmSync(outputRoot, { recursive: true, force: false });
  }
  if (!existsSync(outputRoot)) mkdirSync(outputRoot, { recursive: false, mode: 0o700 });
  const finalStat = lstatSync(outputRoot);
  if (finalStat.isSymbolicLink() || !finalStat.isDirectory() || dirname(realpathSync(outputRoot)) !== sessionRoot) {
    throw new Error('OUTPUT_ROOT_NOT_EXACT_DIRECTORY');
  }
  return realpathSync(outputRoot);
}

export function verifyProviderMaterialisationAuthorityMutationEvidence(evidence, { repositoryRoot = null } = {}) {
  if (!exactKeys(evidence, [
    'schemaVersion',
    'evidenceScope',
    'caseCount',
    'passedCaseCount',
    'baselineIntegrityRowCount',
    'baselineIntegrityDigest',
    'sourceRecords',
    'sourceSetDigest',
    'pythonDependencyByteSets',
    'pythonDependencyByteSetDigest',
    'mappedSystemObjectCount',
    'mappedSystemObjectSetDigest',
    'siteCustomizationLoaded',
    'cases',
    'caseSetDigest',
    'evidenceDigest',
    'runtime',
  ])) throw new Error('MATERIALISATION_MUTATION_EVIDENCE_FIELDS_INVALID');
  if (evidence.schemaVersion !== 2
    || evidence.evidenceScope !== 'HERMETIC_UNPUBLISHED_MUTATION_FIXTURE'
    || evidence.caseCount !== PROVIDER_MATERIALISATION_MUTATION_CASES.length
    || evidence.passedCaseCount !== PROVIDER_MATERIALISATION_MUTATION_CASES.length
    || evidence.baselineIntegrityRowCount !== 0
    || evidence.baselineIntegrityDigest !== sha256(canonicalJson([]))
    || !Number.isSafeInteger(evidence.mappedSystemObjectCount)
    || evidence.mappedSystemObjectCount < 1
    || !SHA256.test(evidence.mappedSystemObjectSetDigest || '')
    || evidence.siteCustomizationLoaded !== false) {
    throw new Error('MATERIALISATION_MUTATION_EVIDENCE_HEADER_INVALID');
  }
  if (!Array.isArray(evidence.cases)
    || evidence.cases.length !== PROVIDER_MATERIALISATION_MUTATION_CASES.length) {
    throw new Error('MATERIALISATION_MUTATION_CASE_SET_INVALID');
  }
  evidence.cases.forEach((record, index) => {
    const expected = PROVIDER_MATERIALISATION_MUTATION_CASES[index];
    if (!exactKeys(record, [
      'id',
      'expectedShaclCode',
      'expectedIntegrityCode',
      'observedShaclCodeDigest',
      'observedIntegrityCodeDigest',
      'shaclMatched',
      'integrityMatched',
    ])
      || record.id !== expected.id
      || record.expectedShaclCode !== expected.expectedShaclCode
      || record.expectedIntegrityCode !== expected.expectedIntegrityCode
      || !SHA256.test(record.observedShaclCodeDigest || '')
      || !SHA256.test(record.observedIntegrityCodeDigest || '')
      || record.shaclMatched !== true
      || record.integrityMatched !== true) {
      throw new Error(`MATERIALISATION_MUTATION_CASE_INVALID_${expected.id}`);
    }
  });
  if (evidence.caseSetDigest !== sha256(canonicalJson(evidence.cases))) {
    throw new Error('MATERIALISATION_MUTATION_CASE_SET_DIGEST_MISMATCH');
  }
  if (!Array.isArray(evidence.sourceRecords)
    || evidence.sourceRecords.length !== PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS.length) {
    throw new Error('MATERIALISATION_MUTATION_SOURCE_SET_INVALID');
  }
  evidence.sourceRecords.forEach((record, index) => {
    const expectedPath = PROVIDER_MATERIALISATION_MUTATION_SOURCE_PATHS[index];
    if (!exactKeys(record, ['path', 'digest'])
      || record.path !== expectedPath
      || !SHA256.test(record.digest || '')) {
      throw new Error(`MATERIALISATION_MUTATION_SOURCE_INVALID_${expectedPath}`);
    }
    if (repositoryRoot !== null
      && record.digest !== sha256(readFileSync(`${repositoryRoot}/${expectedPath}`))) {
      throw new Error(`MATERIALISATION_MUTATION_SOURCE_DIGEST_MISMATCH_${expectedPath}`);
    }
  });
  if (evidence.sourceSetDigest !== sha256(canonicalJson(evidence.sourceRecords))) {
    throw new Error('MATERIALISATION_MUTATION_SOURCE_SET_DIGEST_MISMATCH');
  }
  if (canonicalJson(evidence.pythonDependencyByteSets) !== canonicalJson(EXPECTED_PYTHON_DEPENDENCY_BYTE_SETS)
    || evidence.pythonDependencyByteSetDigest !== EXPECTED_PYTHON_DEPENDENCY_BYTE_SET_DIGEST
    || evidence.pythonDependencyByteSetDigest !== sha256(canonicalJson(evidence.pythonDependencyByteSets))) {
    throw new Error('MATERIALISATION_MUTATION_PYTHON_DEPENDENCY_SET_MISMATCH');
  }
  const { evidenceDigest, runtime, ...core } = evidence;
  if (!SHA256.test(evidenceDigest || '') || evidenceDigest !== sha256(canonicalJson(core))) {
    throw new Error('MATERIALISATION_MUTATION_EVIDENCE_DIGEST_MISMATCH');
  }
  if (!exactKeys(runtime, ['executablePath', 'resolvedExecutablePath', 'executableDigest'])
    || typeof runtime.executablePath !== 'string'
    || !isAbsolute(runtime.executablePath)
    || typeof runtime.resolvedExecutablePath !== 'string'
    || !isAbsolute(runtime.resolvedExecutablePath)
    || !SHA256.test(runtime.executableDigest || '')) {
    throw new Error('MATERIALISATION_MUTATION_RUNTIME_INVALID');
  }
  return evidence;
}

const PYTHON_SOURCE = String.raw`
import hashlib
import importlib.metadata
import json
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1]).resolve()
MODEL = ROOT / "semantic-model"
EXPECTED_DEPENDENCY_BYTE_SETS = [
    {"byteSetDigest": "sha256:d84b76a11d3bf44112b31cedc6fcf691f0d1af7374d21813ddd0821ffe9c3d4b", "fileCount": 19, "name": "importlib_metadata", "version": "9.0.0"},
    {"byteSetDigest": "sha256:868d5c034038c6cc77d1cd3c798d07dc70b39a475648859e13c2563ed801d134", "fileCount": 17, "name": "owlrl", "version": "7.6.2"},
    {"byteSetDigest": "sha256:410054f1476d5f1c7abd3c85ea246313186bb003672dc5395a9ba65e4672381e", "fileCount": 28, "name": "packaging", "version": "26.2"},
    {"byteSetDigest": "sha256:58ace01edd6a0bf20c5372fabb87dd27dd44521f86f98d160f8bed9e31653eab", "fileCount": 11, "name": "prettytable", "version": "3.18.0"},
    {"byteSetDigest": "sha256:155b0d3574fd4594252e925ad26f262a171511fc2a889aac7795137a14af8820", "fileCount": 24, "name": "pyparsing", "version": "3.3.2"},
    {"byteSetDigest": "sha256:2550e5ddbcbeb6cb7fac246eb9318356142887c8fdaf306ee4465f1a19ed20cb", "fileCount": 86, "name": "pyshacl", "version": "0.40.0"},
    {"byteSetDigest": "sha256:40abaf36ef913ca4342a2b8214f66ef680a33b6af601b93fca85ae720976d010", "fileCount": 26, "name": "PyYAML", "version": "6.0.3"},
    {"byteSetDigest": "sha256:b49b35470619eff88f9e174e870486bc64afba763d466e271608020b25a27aed", "fileCount": 150, "name": "rdflib", "version": "7.6.0"},
    {"byteSetDigest": "sha256:572d08b6177a0d6197db4c0f2c97d225df2d8bc985a2e68e75958d043765113e", "fileCount": 53, "name": "wcwidth", "version": "0.8.2"},
    {"byteSetDigest": "sha256:53ba7f91f8878126ecb692e69da09d447dd6482c2e74902d8c1bd220625c41c7", "fileCount": 13, "name": "zipp", "version": "4.1.0"},
]


def stable(value):
    if isinstance(value, list):
        return [stable(item) for item in value]
    if isinstance(value, dict):
        return {key: stable(value[key]) for key in sorted(value)}
    return value


def canonical_json(value):
    return json.dumps(stable(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return "sha256:" + hashlib.sha256(value).hexdigest()


def dependency_bytes():
    records = []
    for name in (
        "importlib_metadata", "owlrl", "packaging", "prettytable", "pyparsing",
        "pyshacl", "PyYAML", "rdflib", "wcwidth", "zipp",
    ):
        distribution = importlib.metadata.distribution(name)
        files = []
        for relative_path in distribution.files or []:
            path_text = str(relative_path).replace("\\", "/")
            if "/__pycache__/" in f"/{path_text}" or path_text.endswith((".pyc", ".pyo")):
                continue
            path = pathlib.Path(distribution.locate_file(relative_path))
            if path.is_file() and not path.is_symlink():
                files.append({"path": path_text, "digest": sha256(path.read_bytes())})
        files.sort(key=lambda item: item["path"])
        records.append({
            "name": name,
            "version": distribution.version,
            "fileCount": len(files),
            "byteSetDigest": sha256(canonical_json(files)),
        })
    return records


DEPENDENCY_BYTE_SETS = dependency_bytes()
if DEPENDENCY_BYTE_SETS != EXPECTED_DEPENDENCY_BYTE_SETS:
    raise RuntimeError(
        "PYTHON_DEPENDENCY_BYTE_SET_MISMATCH:"
        + canonical_json({"expected": EXPECTED_DEPENDENCY_BYTE_SETS, "actual": DEPENDENCY_BYTE_SETS})
    )

import rdflib
import yaml
from pyshacl import validate
from rdflib import Dataset, Graph, Literal, URIRef
from rdflib.namespace import RDF, SH, XSD

USF = rdflib.Namespace("urn:usf:ontology:")
CONTRACT = URIRef("urn:usf:semanticcontract:providerconfigurationplane")
LEGACY_CONTRACT = URIRef("urn:usf:semanticcontract:repositoryexternalartefactmaterialisation")
DECISION = URIRef("urn:usf:realisationdecision:providerconfigurationplanefactoryworkforce")
LEGACY_DECISION = URIRef("urn:usf:realisationdecision:repositoryarchitectureandnaming")
COMPILER_DECISION = URIRef("urn:usf:realisationdecision:semanticauthoritycontrolselection")
ONTOLOGY = URIRef("urn:usf:ontology")
BINDINGS_GRAPH = URIRef("urn:usf:graph:bindings")
MATERIALISATION_GRAPH = URIRef("urn:usf:graph:materialisation")
CAPABILITIES_GRAPH = URIRef("urn:usf:graph:capabilities")


def load_dataset():
    manifest = yaml.safe_load((MODEL / "manifest.yaml").read_text(encoding="utf-8"))
    result = Dataset(default_union=True)
    for group in ("definitionGraphs", "authoredGraphs", "derivedGraphs"):
        for entry in manifest.get(group, []):
            path = MODEL / entry["file"]
            parsed = Dataset(default_union=True)
            parsed.parse(path, format="trig" if path.suffix == ".trig" else "turtle")
            target = result.graph(URIRef(entry["graph"]))
            for subject, predicate, obj, _ in parsed.quads((None, None, None, None)):
                target.add((subject, predicate, obj))
    return result


def load_shapes():
    shapes = Graph()
    shapes.parse(MODEL / "shapes/materialisation.ttl", format="turtle")
    shapes.parse(MODEL / "shapes/lifecycle.ttl", format="turtle")
    return shapes


def clone_dataset(source):
    result = Dataset(default_union=True)
    for subject, predicate, obj, graph in source.quads((None, None, None, None)):
        result.graph(graph).add((subject, predicate, obj))
    return result


def union_graph(dataset):
    graph = Graph()
    for subject, predicate, obj, _ in dataset.quads((None, None, None, None)):
        graph.add((subject, predicate, obj))
    return graph


def replace_object(dataset, subject, predicate, old, new):
    matched = list(dataset.quads((subject, predicate, old, None)))
    if not matched:
        raise RuntimeError("MUTATION_SOURCE_ABSENT:" + str(subject) + ":" + str(predicate))
    for s, p, o, graph in matched:
        dataset.graph(graph).remove((s, p, o))
        dataset.graph(graph).add((s, p, new))


def remove_all(dataset, subject, predicate, obj=None):
    matched = list(dataset.quads((subject, predicate, obj, None)))
    if not matched:
        raise RuntimeError("MUTATION_SOURCE_ABSENT:" + str(subject) + ":" + str(predicate))
    for s, p, o, graph in matched:
        dataset.graph(graph).remove((s, p, o))


def add(dataset, graph, subject, predicate, obj):
    dataset.graph(graph).add((subject, predicate, obj))


def shacl_messages(dataset, shapes, focus):
    _, report, _ = validate(
        union_graph(dataset),
        shacl_graph=shapes,
        advanced=True,
        abort_on_first=False,
        allow_infos=False,
        allow_warnings=False,
        focus_nodes=[focus],
        iterate_rules=False,
        inplace=False,
        meta_shacl=False,
    )
    return sorted({
        str(report.value(result, SH.resultMessage) or "")
        for result in report.subjects(RDF.type, SH.ValidationResult)
    })


def integrity_rows(dataset, queries):
    return sorted({
        (str(row.violation), str(row.subject))
        for query in queries
        for row in dataset.query(query)
    })


def provider_mode_flip(dataset):
    replace_object(dataset, CONTRACT, USF.decisionScopedMaterialisationRequired, Literal(True), Literal(False))
    for predicate in (USF.authorisesSourceDirectory, USF.authorisesMaterialisationAction, USF.authorisesArtefactFamily):
        remove_all(dataset, DECISION, predicate)


def legacy_mode_flip(dataset):
    replace_object(dataset, LEGACY_CONTRACT, USF.decisionScopedMaterialisationRequired, Literal(False), Literal(True))


def effective_missing(dataset):
    remove_all(dataset, CONTRACT, USF.effectiveRealisationDecision)


def effective_substitution(dataset):
    replacement = URIRef("urn:usf:realisationdecision:structurallysimilarproviderdecision")
    replace_object(dataset, CONTRACT, USF.effectiveRealisationDecision, DECISION, replacement)


def repository_wrong(dataset):
    replace_object(dataset, DECISION, USF.authorisesRepository, Literal("maldous/usf-factory"), Literal("maldous/not-usf-factory"))


def repository_extra(dataset):
    add(dataset, BINDINGS_GRAPH, DECISION, USF.authorisesRepository, Literal("maldous/not-usf-factory"))


def directory_wrong(dataset):
    replace_object(dataset, DECISION, USF.authorisesSourceDirectory, Literal("src/usf_factory/providers"), Literal("src/usf_factory/provider_plugins"))


def directory_extra(dataset):
    add(dataset, BINDINGS_GRAPH, DECISION, USF.authorisesSourceDirectory, Literal("src/usf_factory/runtime"))


def directory_overlap(dataset):
    add(dataset, BINDINGS_GRAPH, DECISION, USF.authorisesSourcePath, Literal("src/usf_factory/providers"))


def exact_path_missing(dataset):
    remove_all(dataset, DECISION, USF.authorisesSourcePath, Literal("config/providers.yaml"))


def exact_path_extra(dataset):
    add(dataset, BINDINGS_GRAPH, DECISION, USF.authorisesSourcePath, Literal("src/usf_factory/credentials.py"))


def family_missing(dataset):
    remove_all(dataset, DECISION, USF.authorisesArtefactFamily, URIRef("urn:usf:artefactfamily:factoryenvironmentexample"))


def family_extra(dataset):
    add(dataset, BINDINGS_GRAPH, DECISION, USF.authorisesArtefactFamily, URIRef("urn:usf:artefactfamily:localcoderealisation"))


def rule_role_substitution(dataset):
    replace_object(
        dataset,
        URIRef("urn:usf:materialisationrule:factorypythonpackagerealisation"),
        USF.usesPathRole,
        URIRef("urn:usf:pathrole:factorypythonpackagesource"),
        URIRef("urn:usf:pathrole:factoryproviderworkforcetestsource"),
    )


def rule_second(dataset):
    add(
        dataset,
        MATERIALISATION_GRAPH,
        URIRef("urn:usf:artefactfamily:factorypythonpackagerealisation"),
        USF.usesMaterialisationRule,
        URIRef("urn:usf:materialisationrule:factorypythontestrealisation"),
    )


def rule_identity_substitution(dataset):
    family = URIRef("urn:usf:artefactfamily:factorypythonpackagerealisation")
    original = URIRef("urn:usf:materialisationrule:factorypythonpackagerealisation")
    replacement = URIRef("urn:usf:materialisationrule:structurallyidenticalsubstitute")
    replace_object(dataset, family, USF.usesMaterialisationRule, original, replacement)
    source = list(dataset.quads((original, None, None, None)))
    if not source:
        raise RuntimeError("MUTATION_SOURCE_ABSENT:" + str(original))
    for _, predicate, obj, graph in source:
        dataset.graph(graph).add((replacement, predicate, obj))


def rule_storage_substitution(dataset):
    replace_object(
        dataset,
        URIRef("urn:usf:materialisationrule:factorypythonpackagerealisation"),
        USF.usesStorageClass,
        URIRef("urn:usf:storageclass:gittrackedsource"),
        URIRef("urn:usf:storageclass:contentaddressedobjectstorage"),
    )


def extension_missing(dataset):
    remove_all(
        dataset,
        URIRef("urn:usf:representationformat:python311source"),
        USF.canonicalExtension,
        Literal(".py"),
    )


def extension_duplicate(dataset):
    add(
        dataset,
        MATERIALISATION_GRAPH,
        URIRef("urn:usf:representationformat:python311source"),
        USF.canonicalExtension,
        Literal(".pyx"),
    )


def naming_substitution(dataset):
    replace_object(
        dataset,
        URIRef("urn:usf:materialisationrule:factorypythonpackagerealisation"),
        USF.usesNamingRule,
        URIRef("urn:usf:namingrule:factorypythonmodule"),
        URIRef("urn:usf:namingrule:factorypythontest"),
    )


def naming_pattern_substitution(dataset):
    replace_object(
        dataset,
        URIRef("urn:usf:namingrule:factorypythonmodule"),
        USF.filenamePattern,
        Literal("^(?:__init__|[a-z][a-z0-9]*(?:_[a-z0-9]+)*)[.]py$"),
        Literal("^[a-z][a-z0-9_]*[.]py$"),
    )


def legacy_directory(dataset):
    add(dataset, MATERIALISATION_GRAPH, LEGACY_DECISION, USF.authorisesSourceDirectory, Literal("semantic-model"))


def legacy_action(dataset):
    add(dataset, MATERIALISATION_GRAPH, LEGACY_DECISION, USF.authorisesMaterialisationAction, Literal("write-file"))


def legacy_family(dataset):
    add(dataset, MATERIALISATION_GRAPH, LEGACY_DECISION, USF.authorisesArtefactFamily, URIRef("urn:usf:artefactfamily:factoryconfiguration"))


def unexpected_action(dataset):
    add(dataset, BINDINGS_GRAPH, DECISION, USF.authorisesMaterialisationAction, Literal("delete-path"))


def non_scoped_directory_substitution(dataset):
    path = Literal("configuration/semantic-assurance")
    remove_all(dataset, COMPILER_DECISION, USF.authorisesSourcePath, path)
    add(dataset, BINDINGS_GRAPH, COMPILER_DECISION, USF.authorisesSourceDirectory, path)


CASES = (
    ("scope-mode-provider-flip", CONTRACT, provider_mode_flip, "materialisation-contract-scope-mode", "materialisationcontractscopemodeinvalid"),
    ("scope-mode-legacy-flip", LEGACY_CONTRACT, legacy_mode_flip, "materialisation-contract-scope-mode", "materialisationcontractscopemodeinvalid"),
    ("effective-decision-missing", CONTRACT, effective_missing, "decision-scoped-materialisation-effective-decision", "decisionscopedmaterialisationeffectivedecisioninvalid"),
    ("effective-decision-substitution", CONTRACT, effective_substitution, "decision-scoped-materialisation-effective-decision", "decisionscopedmaterialisationeffectivedecisioninvalid"),
    ("repository-wrong-single", CONTRACT, repository_wrong, "decision-scoped-materialisation-repository", "decisionscopedmaterialisationrepositoryinvalid"),
    ("repository-extra", CONTRACT, repository_extra, "decision-scoped-materialisation-repository", "decisionscopedmaterialisationrepositoryinvalid"),
    ("directory-wrong-single", CONTRACT, directory_wrong, "decision-scoped-materialisation-directory-set", "decisionscopedmaterialisationdirectorysetinvalid"),
    ("directory-extra-normalised", CONTRACT, directory_extra, "decision-scoped-materialisation-directory-set", "decisionscopedmaterialisationdirectorysetinvalid"),
    ("directory-path-overlap", CONTRACT, directory_overlap, "decision-scoped-materialisation-directory", "decisionscopedmaterialisationpathinvalid"),
    ("exact-path-missing", DECISION, exact_path_missing, "decision-scoped-materialisation-path-set", "decisionscopedmaterialisationpathsetinvalid"),
    ("exact-path-extra-normalised", DECISION, exact_path_extra, "decision-scoped-materialisation-path-set", "decisionscopedmaterialisationpathsetinvalid"),
    ("family-missing", CONTRACT, family_missing, "decision-scoped-materialisation-family-set", "decisionscopedmaterialisationfamilysetinvalid"),
    ("family-extra", CONTRACT, family_extra, "decision-scoped-materialisation-family-set", "decisionscopedmaterialisationfamilysetinvalid"),
    ("rule-role-substitution", CONTRACT, rule_role_substitution, "decision-scoped-materialisation-rule", "decisionscopedmaterialisationruleinvalid"),
    ("rule-second", CONTRACT, rule_second, "decision-scoped-materialisation-rule", "decisionscopedmaterialisationruleinvalid"),
    ("rule-identity-substitution", CONTRACT, rule_identity_substitution, "decision-scoped-materialisation-rule", "decisionscopedmaterialisationruleinvalid"),
    ("rule-storage-substitution", CONTRACT, rule_storage_substitution, "decision-scoped-materialisation-rule", "decisionscopedmaterialisationruleinvalid"),
    ("rule-extension-missing", CONTRACT, extension_missing, "decision-scoped-materialisation-rule", "decisionscopedmaterialisationruleinvalid"),
    ("rule-extension-duplicate", CONTRACT, extension_duplicate, "decision-scoped-materialisation-rule", "decisionscopedmaterialisationruleinvalid"),
    ("rule-naming-substitution", CONTRACT, naming_substitution, "decision-scoped-materialisation-rule", "decisionscopedmaterialisationruleinvalid"),
    ("rule-naming-pattern-substitution", CONTRACT, naming_pattern_substitution, "decision-scoped-materialisation-naming-pattern", "decisionscopedmaterialisationnamingpatterninvalid"),
    ("legacy-directory", LEGACY_CONTRACT, legacy_directory, "decision-scoped-materialisation-legacy", "legacymaterialisationdecisionhasscopedpermission"),
    ("legacy-action", LEGACY_CONTRACT, legacy_action, "decision-scoped-materialisation-legacy", "legacymaterialisationdecisionhasscopedpermission"),
    ("legacy-family", LEGACY_CONTRACT, legacy_family, "decision-scoped-materialisation-legacy", "legacymaterialisationdecisionhasscopedpermission"),
    ("unexpected-action", CONTRACT, unexpected_action, "decision-scoped-materialisation-action", "decisionscopedmaterialisationpermissionambiguous"),
    ("non-scoped-directory-substitution", ONTOLOGY, non_scoped_directory_substitution, "Implementable realisation requires", "implementationpathunauthorised"),
)


def main():
    baseline = load_dataset()
    shapes = load_shapes()
    integrity_sources = [
        (MODEL / "rules/integrity.rq").read_text(encoding="utf-8"),
        (MODEL / "rules/lifecycle.rq").read_text(encoding="utf-8"),
    ]
    baseline_integrity = integrity_rows(baseline, integrity_sources)
    if baseline_integrity:
        raise RuntimeError("MATERIALISATION_MUTATION_BASELINE_INTEGRITY_INVALID:" + canonical_json(baseline_integrity))
    records = []
    for identifier, focus, mutate, shacl_code, integrity_code in CASES:
        candidate = clone_dataset(baseline)
        mutate(candidate)
        messages = shacl_messages(candidate, shapes, focus)
        rows = integrity_rows(candidate, integrity_sources)
        observed_integrity = sorted({code for code, _ in rows})
        shacl_matched = any(shacl_code in message for message in messages)
        integrity_matched = integrity_code in observed_integrity
        record = {
            "id": identifier,
            "expectedShaclCode": shacl_code,
            "expectedIntegrityCode": integrity_code,
            "observedShaclCodeDigest": sha256(canonical_json(messages)),
            "observedIntegrityCodeDigest": sha256(canonical_json(observed_integrity)),
            "shaclMatched": shacl_matched,
            "integrityMatched": integrity_matched,
        }
        if not shacl_matched or not integrity_matched:
            raise RuntimeError("MATERIALISATION_MUTATION_CASE_FAILED:" + canonical_json({
                **record,
                "messages": messages,
                "integrityCodes": observed_integrity,
            }))
        records.append(record)
    manifest_path = MODEL / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    source_paths = {manifest_path}
    for group in ("definitionGraphs", "authoredGraphs", "derivedGraphs"):
        source_paths.update(MODEL / entry["file"] for entry in manifest.get(group, []))
    source_paths.update({
        MODEL / "shapes/materialisation.ttl",
        MODEL / "rules/integrity.rq",
        MODEL / "shapes/lifecycle.ttl",
        MODEL / "rules/lifecycle.rq",
    })
    source_records = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "digest": sha256(path.read_bytes()),
        }
        for path in sorted(source_paths, key=lambda item: item.as_posix().encode("utf-8"))
    ]
    mapped_paths = set()
    for line in pathlib.Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        mapped_path = " ".join(fields[5:]) if len(fields) >= 6 else ""
        if mapped_path.startswith("/") and mapped_path.endswith(" (deleted)"):
            raise RuntimeError("MAPPED_RUNTIME_OBJECT_DELETED:" + mapped_path)
        if mapped_path.startswith("/"):
            path = pathlib.Path(mapped_path).resolve(strict=True)
            if not path.is_file():
                raise RuntimeError("MAPPED_RUNTIME_OBJECT_NOT_FILE:" + mapped_path)
            mapped_paths.add(path)
    mapped_records = [
        {
            "path": path.as_posix(),
            "digest": sha256(path.read_bytes()),
            "byteSize": path.stat().st_size,
        }
        for path in sorted(mapped_paths, key=lambda item: item.as_posix().encode("utf-8"))
    ]
    core = {
        "schemaVersion": 2,
        "evidenceScope": "HERMETIC_UNPUBLISHED_MUTATION_FIXTURE",
        "caseCount": len(records),
        "passedCaseCount": sum(1 for item in records if item["shaclMatched"] and item["integrityMatched"]),
        "baselineIntegrityRowCount": len(baseline_integrity),
        "baselineIntegrityDigest": sha256(canonical_json(baseline_integrity)),
        "sourceRecords": source_records,
        "sourceSetDigest": sha256(canonical_json(source_records)),
        "pythonDependencyByteSets": DEPENDENCY_BYTE_SETS,
        "pythonDependencyByteSetDigest": sha256(canonical_json(DEPENDENCY_BYTE_SETS)),
        "mappedSystemObjectCount": len(mapped_records),
        "mappedSystemObjectSetDigest": sha256(canonical_json(mapped_records)),
        "siteCustomizationLoaded": "sitecustomize" in sys.modules or "usercustomize" in sys.modules,
        "cases": records,
        "caseSetDigest": sha256(canonical_json(records)),
    }
    result = {**core, "evidenceDigest": sha256(canonical_json(core))}
    print(canonical_json(result))


try:
    main()
except Exception as error:
    print(error.__class__.__name__ + ":" + str(error), file=sys.stderr)
    sys.exit(1)
`;

export function runProviderMaterialisationAuthorityMutations({
  repositoryRoot,
  runtime,
}) {
  if (!isAbsolute(repositoryRoot || '')) throw new TypeError('repository root must be absolute');
  const binding = validateLocalShaclRuntime(runtime);
  const runtimeEvidenceBefore = inspectPinnedPythonRuntime(binding);
  const sitePackages = join(runtimeEvidenceBefore.venvPrefix, 'lib', 'python3.11', 'site-packages');
  const result = spawnPinnedLocalShaclRuntime(binding, [...PYTHON_ARGUMENT_PREFIX, sitePackages, repositoryRoot], {
    cwd: PYTHON_WORKING_DIRECTORY,
    encoding: 'utf8',
    env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PATH: '/usr/bin:/bin', TZ: 'UTC' },
    input: `${ISOLATED_SITE_BOOTSTRAP}${PYTHON_SOURCE}`,
    maxBuffer: 64 * 1024 * 1024,
    timeout: 1_800_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`provider materialisation authority mutation proof failed (${result.status}): ${result.stderr.trim()}`);
  }
  if (result.signal) throw new Error(`provider materialisation authority mutation proof terminated by ${result.signal}`);
  const runtimeEvidenceAfter = inspectPinnedPythonRuntime(binding);
  if (canonicalJson(runtimeEvidenceAfter) !== canonicalJson(runtimeEvidenceBefore)) {
    throw new Error('PROVIDER_MATERIALISATION_MUTATION_RUNTIME_DEPENDENCY_CLOSURE_MOVED');
  }
  const parsed = JSON.parse(result.stdout);
  if (!Number.isSafeInteger(parsed.mappedSystemObjectCount)
    || !SHA256.test(parsed.mappedSystemObjectSetDigest || '')
    || parsed.siteCustomizationLoaded !== false) {
    throw new Error('PROVIDER_MATERIALISATION_MUTATION_WORKLOAD_RUNTIME_EVIDENCE_INVALID');
  }
  return Object.freeze(verifyProviderMaterialisationAuthorityMutationEvidence({
    ...parsed,
    runtime: Object.freeze({
      executablePath: runtime.executablePath,
      resolvedExecutablePath: binding.resolvedExecutablePath,
      executableDigest: binding.executableDigest,
    }),
  }, { repositoryRoot }));
}

export const providerMaterialisationAuthorityMutationInternals = Object.freeze({
  pythonSourceDigest: sha256(PYTHON_SOURCE),
  pythonArgumentPrefix: PYTHON_ARGUMENT_PREFIX,
  pythonWorkingDirectory: PYTHON_WORKING_DIRECTORY,
  expectedNodeDependencyEvidence: EXPECTED_NODE_DEPENDENCY_EVIDENCE,
  expectedPythonDependencyByteSets: EXPECTED_PYTHON_DEPENDENCY_BYTE_SETS,
  expectedPythonDependencyByteSetDigest: EXPECTED_PYTHON_DEPENDENCY_BYTE_SET_DIGEST,
  inspectNodeDependencyEvidence,
});
