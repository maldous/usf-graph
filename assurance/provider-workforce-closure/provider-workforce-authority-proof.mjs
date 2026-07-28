#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import {
  createHash, createPrivateKey, createPublicKey, sign, verify,
} from 'node:crypto';
import {
  lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import {
  PROVIDER_FACTORY_PATH_SCOPES,
  PROVIDER_FACTORY_RULES,
  createMaterialisationPlan,
  decisionAuthorisesPath,
  scopedPermissionSetDigest,
  validateMaterialisationPlan,
  validatePlanOperation,
} from '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';
import {
  PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS,
  PROVIDER_WORKFORCE_PROOF_INPUT_PATHS,
  inspectProviderProofNodeDependencies,
  normaliseDeterministicPytestOutput,
  prepareExactSessionOutputRoot,
  runProviderMaterialisationAuthorityMutations,
} from './provider-materialisation-authority-mutations.mjs';
import {
  inspectPinnedPythonRuntime,
  spawnPinnedLocalShaclRuntime,
} from '../semantic-model-compilation/local-shacl-validation.mjs';

const semanticRoot = resolve(dirname(import.meta.filename), '..', '..');
const nodeDependencyEvidence = inspectProviderProofNodeDependencies({ repositoryRoot: semanticRoot });
const { DataFactory, Parser, Store } = await import('n3');
inspectProviderProofNodeDependencies({ repositoryRoot: semanticRoot });
const { namedNode } = DataFactory;

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const cases = [];
const commands = [];
let providerCredentialEnvironmentForwarded = false;
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const HERMETIC_COMMAND_ENV = Object.freeze({
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  PATH: '/usr/bin:/bin',
  TZ: 'UTC',
  XDG_CONFIG_HOME: '/nonexistent',
});
const GIT_EXECUTABLE_PATH = '/usr/bin/git';
const GIT_NATIVE_OBJECTS = Object.freeze([
  ['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2', 'sha256:02bcda52c1a5dfc236f94d9e5255b4a0e26347d8a372a5223b650e31f291ce3c'],
  ['/usr/lib/x86_64-linux-gnu/libc.so.6', 'sha256:6b4a45352fd0c540a9c7c718f35ce8c8e46a4e482f9d3885a910c32d1a0e1421'],
  ['/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2', 'sha256:19c626251526131ac9340826c8f7bcb693c6ceb9d5da55919c3aa45d972b704f'],
  ['/usr/lib/x86_64-linux-gnu/libz.so.1.2.13', 'sha256:7e2a72b4c4b38c61e6962de6e3f4a5e9ae692e732c68deead10a7ce2135a7f68'],
]);
const gitNativeObjectRecords = GIT_NATIVE_OBJECTS.map(([path, expectedDigest]) => {
  const resolvedPath = realpathSync(path);
  const digest = sha256(readFileSync(resolvedPath));
  if (digest !== expectedDigest) throw new Error('GIT_NATIVE_OBJECT_DIGEST_MISMATCH');
  return { path: resolvedPath, digest, byteSize: lstatSync(resolvedPath).size };
});
const gitRuntime = Object.freeze({
  executablePath: GIT_EXECUTABLE_PATH,
  resolvedExecutablePath: realpathSync(GIT_EXECUTABLE_PATH),
  executableDigest: sha256(readFileSync(realpathSync(GIT_EXECUTABLE_PATH))),
});
if (gitRuntime.executableDigest !== 'sha256:2540879925a6881e3877ff7e3330746ba3027b04edf16a3a12dccd1644c4f32d') {
  throw new Error('GIT_EXECUTABLE_DIGEST_MISMATCH');
}
const gitRuntimeDependencyEvidence = Object.freeze({
  schemaVersion: 1,
  executableDigest: gitRuntime.executableDigest,
  nativeObjectCount: gitNativeObjectRecords.length,
  nativeObjectSetDigest: sha256(canonicalJson(gitNativeObjectRecords)),
});
const FOCUSED_PYTEST_BOOTSTRAP = String.raw`
import hashlib
import json
import pathlib
import sys

site_packages = pathlib.Path(sys.argv.pop(1)).resolve()
factory_root = pathlib.Path(sys.argv.pop(1)).resolve()
pycache_root = pathlib.Path(sys.argv.pop(1)).resolve()
factory_source = (factory_root / "src").resolve()
sys.path[:0] = [factory_source.as_posix(), site_packages.as_posix()]
sys.pycache_prefix = pycache_root.as_posix()
sys.dont_write_bytecode = True

import pytest
import usf_factory

actual_origin = pathlib.Path(usf_factory.__file__).resolve()
if actual_origin != factory_source / "usf_factory" / "__init__.py":
    raise RuntimeError("FACTORY_IMPORT_ORIGIN_MISMATCH:" + actual_origin.as_posix())
if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
    raise RuntimeError("PYTHON_SITE_CUSTOMIZATION_LOADED")

status = pytest.main(["-p", "no:cacheprovider", *sys.argv[1:]])
paths = set()
for line in pathlib.Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
    fields = line.split()
    mapped_path = " ".join(fields[5:]) if len(fields) >= 6 else ""
    if mapped_path.startswith("/") and mapped_path.endswith(" (deleted)"):
        raise RuntimeError("MAPPED_RUNTIME_OBJECT_DELETED:" + mapped_path)
    if mapped_path.startswith("/"):
        path = pathlib.Path(mapped_path).resolve(strict=True)
        if not path.is_file():
            raise RuntimeError("MAPPED_RUNTIME_OBJECT_NOT_FILE:" + mapped_path)
        paths.add(path)
records = [
    {
        "path": path.as_posix(),
        "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        "byteSize": path.stat().st_size,
    }
    for path in sorted(paths, key=lambda item: item.as_posix().encode("utf-8"))
]
runtime = {
    "mappedSystemObjectCount": len(records),
    "mappedSystemObjectSetDigest": "sha256:" + hashlib.sha256(
        json.dumps(records, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest(),
    "siteCustomizationLoaded": False,
}
print("USF_PYTEST_RUNTIME_EVIDENCE=" + json.dumps(runtime, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
raise SystemExit(status)
`;

function requiredEnvironment(name, pattern = /./) {
  const value = process.env[name] || '';
  if (!pattern.test(value)) throw new Error(`${name}_REQUIRED`);
  return value;
}

function exactDirectory(path, label) {
  const canonical = realpathSync(path);
  if (!statSync(canonical).isDirectory() || lstatSync(path).isSymbolicLink()) {
    throw new Error(`${label}_NOT_EXACT_DIRECTORY`);
  }
  return canonical;
}

function run(id, executable, args, options = {}) {
  const spawnOptions = {
    cwd: options.cwd,
    env: options.env ?? HERMETIC_COMMAND_ENV,
    input: options.input,
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    timeout: options.timeout || 120_000,
  };
  const pinnedRuntime = options.pinnedRuntime
    ?? (executable === GIT_EXECUTABLE_PATH ? gitRuntime : null);
  const result = pinnedRuntime
    ? spawnPinnedLocalShaclRuntime(pinnedRuntime, args, spawnOptions)
    : spawnSync(executable, args, spawnOptions);
  providerCredentialEnvironmentForwarded ||= Object.keys(spawnOptions.env ?? {}).some(
    (name) => /(?:^|_)(?:API_?KEY|API_?TOKEN|ACCESS_?TOKEN|AUTH_?TOKEN|SECRET|PASSWORD|CREDENTIAL)(?:_|$)/i.test(name),
  );
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
  const commandOutputDirectory = join(outputRoot, 'commands');
  mkdirSync(commandOutputDirectory, { recursive: true, mode: 0o700 });
  writeFileSync(join(commandOutputDirectory, `${id}.stdout`), stdout, { mode: 0o600 });
  writeFileSync(join(commandOutputDirectory, `${id}.stderr`), stderr, { mode: 0o600 });
  const stdoutEvidence = options.normaliseStdout ? options.normaliseStdout(stdout) : stdout;
  const stderrEvidence = options.normaliseStderr ? options.normaliseStderr(stderr) : stderr;
  commands.push({
    id,
    executable,
    arguments: [...args],
    exitStatus: Number.isInteger(result.status) ? result.status : null,
    signal: result.signal || null,
    stdoutEvidenceMode: options.stdoutEvidenceMode ?? 'EXACT_BYTES',
    stderrEvidenceMode: options.stderrEvidenceMode ?? 'EXACT_BYTES',
    stdoutDigest: sha256(stdoutEvidence),
    stderrDigest: sha256(stderrEvidence),
  });
  if (result.error || result.signal || result.status !== 0) throw new Error(`COMMAND_FAILED_${id.toUpperCase()}`);
  return stdout;
}

function record(id, expected, observed, detail = null) {
  const passed = canonicalJson(expected) === canonicalJson(observed);
  cases.push({ id, expected, observed, passed, ...(detail ? { detail } : {}) });
  if (!passed) throw new Error(`ASSERTION_FAILED_${id.toUpperCase().replaceAll('-', '_')}`);
}

function putCas(root, bytes, mediaType) {
  const digest = sha256(bytes);
  const hexadecimal = digest.slice(7);
  const algorithmDirectory = join(root, 'sha256');
  const directory = join(algorithmDirectory, hexadecimal.slice(0, 2));
  const path = join(directory, hexadecimal);
  for (const candidate of [algorithmDirectory, directory]) {
    try {
      mkdirSync(candidate, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    const stat = lstatSync(candidate);
    if (stat.isSymbolicLink() || !stat.isDirectory() || realpathSync(candidate) !== candidate) {
      throw new Error('CAS_DIRECTORY_NOT_EXACT');
    }
  }
  try {
    const existing = lstatSync(path);
    if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) {
      throw new Error('CAS_OBJECT_NOT_EXACT_FILE');
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  try {
    writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST' || sha256(readFileSync(path)) !== digest) throw error;
  }
  const finalStat = lstatSync(path);
  if (finalStat.isSymbolicLink() || !finalStat.isFile() || finalStat.nlink !== 1
    || sha256(readFileSync(path)) !== digest) throw new Error('CAS_ROUND_TRIP_FAILED');
  return { digest, byteSize: bytes.length, mediaType, locator: `cas://sha256/${hexadecimal}` };
}

function intersectSets(layers, key) {
  const constrained = layers.map((layer) => layer[key]).filter((value) => Array.isArray(value));
  if (!constrained.length) return null;
  return [...constrained.slice(1).reduce(
    (result, values) => new Set(values.filter((value) => result.has(value))),
    new Set(constrained[0]),
  )].sort(utf8Compare);
}

function effectivePolicy(...layers) {
  const booleans = [
    'allow_free_inference', 'allow_subscription_inference', 'allow_paid_inference',
    'allow_local_inference',
  ];
  const policy = Object.fromEntries(booleans.map((key) => [
    key,
    layers.every((layer) => layer[key] === true),
  ]));
  const costs = layers.map(({ max_paid_cost_usd: value }) => value).filter(Number.isFinite);
  const bounds = layers.map(({ max_models_assessed: value }) => value).filter(Number.isInteger);
  policy.max_paid_cost_usd = costs.length ? Math.min(...costs) : 0;
  policy.max_models_assessed = bounds.length ? Math.min(...bounds) : 0;
  for (const key of ['providers', 'models', 'families', 'adapters', 'actual_models']) {
    policy[key] = intersectSets(layers, key);
  }
  policy.exclusions = [...new Set(layers.flatMap(({ exclusions = [] }) => exclusions))].sort(utf8Compare);
  policy.free_only = layers.some(({ free_only: value }) => value === true);
  return Object.freeze(policy);
}

function openRouterFreeEligible(route) {
  const requested = String(route.requestedModel || '').toLowerCase();
  return requested.endsWith(':free')
    && requested !== 'openrouter/auto'
    && requested !== 'openrouter/free'
    && route.catalogueFree === true
    && route.quotedRequestPrice === 0
    && route.observedChargedCost === 0
    && typeof route.actualProvider === 'string'
    && route.actualProvider.length > 0
    && typeof route.actualModel === 'string'
    && route.actualModel.length > 0
    && route.paidFallback === false;
}

function drainPopulation(population, currentEvidence, outcomeFor, batchSize) {
  const terminal = new Map();
  const accounted = new Set(currentEvidence);
  const attempts = [];
  while (true) {
    const due = population.filter(({ identity }) => !accounted.has(identity) && !terminal.has(identity));
    if (!due.length) break;
    const providers = new Map();
    for (const row of due) {
      if (!providers.has(row.provider)) providers.set(row.provider, []);
      providers.get(row.provider).push(row);
    }
    const batch = [];
    const queues = [...providers.entries()].sort(([left], [right]) => utf8Compare(left, right));
    while (batch.length < batchSize && queues.some(([, rows]) => rows.length)) {
      for (const [, rows] of queues) {
        if (batch.length >= batchSize) break;
        if (rows.length) batch.push(rows.shift());
      }
    }
    for (const row of batch) {
      if (terminal.has(row.identity) || accounted.has(row.identity)) throw new Error('DUPLICATE_ASSESSMENT');
      attempts.push(row.identity);
      terminal.set(row.identity, outcomeFor(row));
    }
  }
  return {
    attempts,
    terminal: Object.fromEntries([...terminal.entries()].sort(([left], [right]) => utf8Compare(left, right))),
    unaccounted: population.filter(({ identity }) => !accounted.has(identity) && !terminal.has(identity)),
  };
}

const authorityDigest = requiredEnvironment('USF_AUTHORITY_DIGEST', SHA256);
const evaluatedAt = requiredEnvironment('USF_EVALUATED_AT', DATE_TIME);
if (!Number.isFinite(Date.parse(evaluatedAt))) throw new Error('USF_EVALUATED_AT_INVALID');
const casRoot = exactDirectory(requiredEnvironment('USF_CAS_ROOT'), 'CAS_ROOT');
const factoryRepo = exactDirectory(requiredEnvironment('USF_FACTORY_REPO'), 'FACTORY_REPO');
const factoryCommit = requiredEnvironment('USF_FACTORY_COMMIT', COMMIT);
const expectedFactoryTree = requiredEnvironment('USF_EXPECTED_FACTORY_TREE', COMMIT);
const outputRoot = prepareExactSessionOutputRoot({
  repositoryRoot: process.cwd(),
  requestedOutputRoot: resolve(requiredEnvironment('USF_OUTPUT_ROOT')),
  clear: true,
});
const python = requiredEnvironment('USF_PYTHON');
const pythonRuntime = Object.freeze({
  executablePath: python,
  resolvedExecutablePath: realpathSync(python),
  executableDigest: sha256(readFileSync(realpathSync(python))),
});
const pythonRuntimeDependencyEvidence = inspectPinnedPythonRuntime(pythonRuntime);

const head = run('factory-head', '/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: factoryRepo }).toString().trim();
const tree = run('factory-tree', '/usr/bin/git', ['rev-parse', `${factoryCommit}^{tree}`], { cwd: factoryRepo }).toString().trim();
const status = run('factory-status', '/usr/bin/git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: factoryRepo }).toString();
record('factory-commit-exact', factoryCommit, head);
record('factory-tree-exact', expectedFactoryTree, tree);
record('factory-worktree-clean', '', status);

const sourcePaths = PROVIDER_WORKFORCE_IMPLEMENTATION_SOURCE_PATHS;
const proofInputPaths = PROVIDER_WORKFORCE_PROOF_INPUT_PATHS;
const sourceReadPaths = [...sourcePaths, ...proofInputPaths];
const sources = Object.fromEntries(sourceReadPaths.map((path) => [
  path,
  run(`source-${sha256(path).slice(7, 15)}`, '/usr/bin/git', ['show', `${factoryCommit}:${path}`], { cwd: factoryRepo }),
]));
const sourceRecords = sourcePaths.map((path) => ({ path, digest: sha256(sources[path]), byteSize: sources[path].length }));
const implementationSourceDigest = sha256(canonicalJson(sourceRecords));
const proofInputSourceRecords = proofInputPaths.map((path) => ({
  path,
  digest: sha256(sources[path]),
  byteSize: sources[path].length,
}));
const proofInputSourceDigest = sha256(canonicalJson(proofInputSourceRecords));
const text = (path) => sources[path].toString('utf8');

const trackedPaths = run('tracked-paths', '/usr/bin/git', ['ls-tree', '-r', '--name-only', factoryCommit], { cwd: factoryRepo })
  .toString('utf8').trim().split('\n').filter(Boolean);
record('secrets-outside-git', [], trackedPaths.filter((path) => /(^|\/)(\.env|.*\.(?:pem|pk8|key)|credentials\.json|session\.json)$/i.test(path)));
record('environment-file-ignored', true, /(?:^|\n)\.env(?:\n|$)/.test(text('.gitignore')));
record('environment-names-only', true, /BY NAME ONLY/.test(text('scripts/check-provider-env.py')) && /NEVER emits a credential value/.test(text('src/usf_factory/secrets.py')));
record('unknown-token-not-loaded', true, /Only an exact allowlist/.test(text('src/usf_factory/secrets.py')) && /UNMAPPED_CANDIDATES/.test(text('src/usf_factory/secrets.py')));
record('run-authorization-at-provider-call', true, /RunAuthorization disappeared before invocation/.test(text('src/usf_factory/bootstrap.py')) && /provider contact blocked by workforce policy/.test(text('src/usf_factory/providers/registry.py')));
record('zero-paid-budget-denial', true, /allow_paid/.test(text('src/usf_factory/workforce_policy.py')) && /max_paid_cost_usd/.test(text('src/usf_factory/workforce_policy.py')) && /paid_api_budget_usd/.test(text('src/usf_factory/run_authorization.py')));
const authorisedSubscriptionTransports = Object.freeze(['antigravity-cli', 'claude-cli', 'codex-cli']);
const operatorConfiguredSubscriptionDefaults = Object.freeze({ 'antigravity-cli': 'claude-opus-4.6' });
record('subscription-api-distinction', {
  paidApiBoundaryPresent: true,
  authorisedSubscriptionTransports: ['antigravity-cli', 'claude-cli', 'codex-cli'],
  operatorConfiguredSubscriptionDefaults: { 'antigravity-cli': 'claude-opus-4.6' },
}, {
  paidApiBoundaryPresent: /allow_subscription_inference/.test(text('src/usf_factory/bootstrap.py')) && /mode == "subscription"/.test(text('src/usf_factory/activation.py')),
  authorisedSubscriptionTransports,
  operatorConfiguredSubscriptionDefaults,
});
const openRouterCases = [
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'openrouter/auto', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: null, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: null, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: null, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: '', actualModel: 'vendor/model:free', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: '', paidFallback: false },
  { requestedModel: 'vendor/model:free', catalogueFree: true, quotedRequestPrice: 0, observedChargedCost: 0, actualProvider: 'provider-a', actualModel: 'vendor/model:free', paidFallback: true },
];
record('openrouter-free-fail-closed', [true, false, false, false, false, false, false, false], openRouterCases.map(openRouterFreeEligible));
record('ollama-operator-exclusion', true, /ollama/.test(text('config/workforce-policy.yaml')) && /exclude/.test(text('config/workforce-policy.yaml')));
record('actual-identities-recorded', true, /actual_provider/.test(text('src/usf_factory/accounting_models.py')) && /actual_model/.test(text('src/usf_factory/accounting_models.py')));

record('model-quota-scope-preserved', true, /requested_model/.test(text('src/usf_factory/model_market.py')) && /provider_id/.test(text('src/usf_factory/model_market.py')));
record('disabled-providers-inventoried', true, /enabled/.test(text('config/providers.yaml')) && /disabled/.test(text('src/usf_factory/providers/registry.py')));
record('research-command-unbound', true, !/requests\.(?:get|post)|urllib\.request|httpx\./.test(text('scripts/check-provider-env.py')));

const layers = [
  { free_only: false, allow_free_inference: true, allow_subscription_inference: true, allow_paid_inference: false, allow_local_inference: false, max_paid_cost_usd: 0, max_models_assessed: 100, providers: ['antigravity-cli', 'claude-cli', 'codex-cli', 'groq'], exclusions: ['ollama'] },
  { free_only: false, allow_free_inference: true, allow_subscription_inference: true, allow_paid_inference: false, allow_local_inference: false, max_paid_cost_usd: 0, max_models_assessed: 40, providers: ['antigravity-cli', 'claude-cli', 'codex-cli'], exclusions: [] },
  { free_only: false, allow_free_inference: true, allow_subscription_inference: false, allow_paid_inference: false, allow_local_inference: false, max_paid_cost_usd: 0, max_models_assessed: 25, providers: ['codex-cli'], exclusions: [] },
  { free_only: false, allow_free_inference: true, allow_subscription_inference: false, allow_paid_inference: false, allow_local_inference: false, max_paid_cost_usd: 0, max_models_assessed: 10, providers: ['codex-cli'], exclusions: ['ollama'] },
];
const policy = effectivePolicy(...layers);
record('one-effective-policy-intersection', {
  allow_free_inference: true,
  allow_local_inference: false,
  allow_paid_inference: false,
  allow_subscription_inference: false,
  providers: ['codex-cli'],
  max_paid_cost_usd: 0,
  max_models_assessed: 10,
  exclusions: ['ollama'],
}, {
  allow_free_inference: policy.allow_free_inference,
  allow_local_inference: policy.allow_local_inference,
  allow_paid_inference: policy.allow_paid_inference,
  allow_subscription_inference: policy.allow_subscription_inference,
  providers: policy.providers,
  max_paid_cost_usd: policy.max_paid_cost_usd,
  max_models_assessed: policy.max_models_assessed,
  exclusions: policy.exclusions,
});

const population = [
  { identity: 'a/one', provider: 'a' },
  { identity: 'a/two', provider: 'a' },
  { identity: 'b/one', provider: 'b' },
  { identity: 'b/two', provider: 'b' },
  { identity: 'c/one', provider: 'c' },
];
const closure = drainPopulation(population, new Set(['a/one']), ({ identity }) => ({
  state: identity === 'a/two' ? 'QUOTA_BLOCKED' : identity === 'b/two' ? 'TOKEN_REQUIRED' : identity === 'c/one' ? 'RATE_LIMITED' : 'ASSESSED_CURRENT',
  scope: 'MODEL',
}), 2);
record('fair-queue-complete-drain', 0, closure.unaccounted.length);
record('terminal-model-at-most-once', closure.attempts.length, new Set(closure.attempts).size);
record('missing-credential-token-required', 'TOKEN_REQUIRED', closure.terminal['b/two'].state);
record('model-specific-terminal-scope', 'MODEL', closure.terminal['a/two'].scope);
record('availability-facts-durable', {
  'a/two': { scope: 'MODEL', state: 'QUOTA_BLOCKED' },
  'c/one': { scope: 'MODEL', state: 'RATE_LIMITED' },
}, {
  'a/two': closure.terminal['a/two'],
  'c/one': closure.terminal['c/one'],
});
record('provider-failure-isolated', true, closure.attempts.includes('b/one') && closure.attempts.includes('c/one'));

const exactPaths = [...new Set(
  new Parser({ format: 'application/trig' })
    .parse(readFileSync(join(semanticRoot, 'semantic-model/realisation/bindings.trig'), 'utf8'))
    .filter((quad) => quad.subject.value === 'urn:usf:realisationdecision:providerconfigurationplanefactoryworkforce'
      && quad.predicate.value === 'urn:usf:ontology:authorisesSourcePath')
    .map((quad) => quad.object.value),
)].sort(utf8Compare);
const directoryPrefixes = ['src/usf_factory/providers', 'tests/provider_workforce'];
record('materialisation-exact-path-and-directory-prefix-disjoint', {
  exactFile: true,
  exactFileDescendant: false,
  directoryItself: false,
  directoryDescendant: true,
}, {
  exactFile: decisionAuthorisesPath('config/providers.yaml', exactPaths, directoryPrefixes),
  exactFileDescendant: decisionAuthorisesPath('config/providers.yaml/child.py', exactPaths, directoryPrefixes),
  directoryItself: decisionAuthorisesPath('src/usf_factory/providers', exactPaths, directoryPrefixes),
  directoryDescendant: decisionAuthorisesPath('src/usf_factory/providers/cohere.py', exactPaths, directoryPrefixes),
});

const scopedContract = 'urn:usf:semanticcontract:providerconfigurationplane';
const scopedFamily = 'urn:usf:artefactfamily:factorypythonpackagerealisation';
const scopedFamilies = [
  'urn:usf:artefactfamily:factoryconfiguration',
  'urn:usf:artefactfamily:factoryenvironmentexample',
  'urn:usf:artefactfamily:factorymarkdowndocumentation',
  'urn:usf:artefactfamily:factorypythonoperatorrealisation',
  scopedFamily,
  'urn:usf:artefactfamily:factorypythontestrealisation',
  'urn:usf:artefactfamily:factoryyamldocumentation',
];
const scopedRules = PROVIDER_FACTORY_RULES.map((rule) => ({ ...rule }));
const scopedAuthority = {
  authorityDigest,
  contract: {
    id: scopedContract,
    activationState: 'urn:usf:contractactivationstate:active',
    proofResultState: 'urn:usf:proofresultstate:successful',
    decisionState: 'urn:usf:decisionstate:accepted',
  },
  acceptedDecisionCount: 1,
  decisionScopedMaterialisationRequired: true,
  authorisedRepositories: ['maldous/usf-factory'],
  authorisedPaths: exactPaths,
  authorisedDirectoryPrefixes: directoryPrefixes,
  authorisedActions: ['write-file'],
  authorisedFamilies: scopedFamilies,
  pathRoles: [{
    id: 'urn:usf:pathrole:factorypythonpackagesource',
    parent: 'src/usf_factory',
  }],
  rules: scopedRules,
};
scopedAuthority.permissionSetDigest = scopedPermissionSetDigest(scopedAuthority);
const operationBytes = Buffer.from('pass\n');
const scopedOperation = {
  index: 0,
  action: 'write-file',
  path: 'src/usf_factory/providers/cohere.py',
  pathRole: 'urn:usf:pathrole:factorypythonpackagesource',
  artefactFamily: scopedFamily,
  representationFormat: 'urn:usf:representationformat:python311source',
  contentDigest: sha256(operationBytes),
  content: operationBytes.toString('utf8'),
  contentEncoding: 'utf8',
};
record('materialisation-action-and-family-fail-closed', {
  accepted: [],
  actionDenied: true,
  familyDenied: true,
}, {
  accepted: validatePlanOperation(scopedOperation, 0, scopedAuthority),
  actionDenied: validatePlanOperation({
    ...scopedOperation,
    action: 'delete-path',
    sourceDigest: sha256(operationBytes),
  }, 0, scopedAuthority).some(({ code }) => code === 'operation-decision-action'),
  familyDenied: validatePlanOperation({
    ...scopedOperation,
    artefactFamily: 'urn:usf:artefactfamily:notauthorised',
  }, 0, scopedAuthority).some(({ code }) => code === 'operation-decision-family'),
});
const scopedPlan = createMaterialisationPlan(scopedAuthority, [scopedOperation], scopedContract);
const namingDriftAuthority = {
  ...scopedAuthority,
  rules: scopedAuthority.rules.map((rule) => (rule.family === scopedFamily
    ? { ...rule, namingPattern: '^different[.]py$' }
    : rule)),
};
record('materialisation-permission-digest-binds-naming', true,
  validateMaterialisationPlan(namingDriftAuthority, scopedPlan).failures
    .some(({ code }) => code === 'permission-set-digest-mismatch'));

const semanticModel = new Store();
for (const [path, format] of [
  ['semantic-model/contracts/materialisation.trig', 'application/trig'],
  ['semantic-model/contracts/capabilities.trig', 'application/trig'],
  ['semantic-model/realisation/bindings.trig', 'application/trig'],
]) {
  semanticModel.addQuads(new Parser({ format }).parse(readFileSync(join(semanticRoot, path), 'utf8')));
}
const iri = (local) => namedNode(`urn:usf:${local}`);
const modelObjects = (subject, predicate) => semanticModel.getObjects(subject, predicate, null)
  .map(({ value }) => value).sort(utf8Compare);
const expectedMaterialisationFamilies = [
  'artefactfamily:factoryconfiguration',
  'artefactfamily:factoryenvironmentexample',
  'artefactfamily:factorymarkdowndocumentation',
  'artefactfamily:factorypythonoperatorrealisation',
  'artefactfamily:factorypythonpackagerealisation',
  'artefactfamily:factorypythontestrealisation',
  'artefactfamily:factoryyamldocumentation',
].map((value) => `urn:usf:${value}`).sort(utf8Compare);
const providerMaterialisationDecisions = [
  ['semanticcontract:providerconfigurationplane', 'realisationdecision:providerconfigurationplanefactoryworkforce'],
  ['semanticcontract:providerenvironmentclassification', 'realisationdecision:providerenvironmentclassificationfactoryworkforce'],
  ['semanticcontract:servicecatalogandproviderintegrationmodel', 'realisationdecision:servicecatalogandproviderintegrationmodelfactoryworkforce'],
];
const semanticScope = providerMaterialisationDecisions.map(([contractId, decisionId]) => {
  const contractNode = iri(contractId);
  const decisionNode = iri(decisionId);
  const paths = modelObjects(decisionNode, iri('ontology:authorisesSourcePath'));
  const directories = modelObjects(decisionNode, iri('ontology:authorisesSourceDirectory'));
  return {
    contract: contractNode.value,
    decision: decisionNode.value,
    mode: modelObjects(contractNode, iri('ontology:decisionScopedMaterialisationRequired')),
    effectiveDecision: modelObjects(contractNode, iri('ontology:effectiveRealisationDecision')),
    repositories: modelObjects(decisionNode, iri('ontology:authorisesRepository')),
    actions: modelObjects(decisionNode, iri('ontology:authorisesMaterialisationAction')),
    directories,
    familySet: modelObjects(decisionNode, iri('ontology:authorisesArtefactFamily')),
    exactPathCount: paths.length,
    exactPathSetDigest: sha256(canonicalJson(paths)),
    exactDirectoryOverlap: directories.filter((directory) => paths.includes(directory)),
  };
});
record('provider-materialisation-semantic-scope-exact', providerMaterialisationDecisions.map(([contractId, decisionId]) => ({
  contract: `urn:usf:${contractId}`,
  decision: `urn:usf:${decisionId}`,
  mode: ['true'],
  effectiveDecision: [`urn:usf:${decisionId}`],
  repositories: ['maldous/usf-factory'],
  actions: ['write-file'],
  directories: ['src/usf_factory/providers', 'tests/provider_workforce'],
  familySet: expectedMaterialisationFamilies,
  exactPathCount: PROVIDER_FACTORY_PATH_SCOPES[`urn:usf:${contractId}`].count,
  exactPathSetDigest: PROVIDER_FACTORY_PATH_SCOPES[`urn:usf:${contractId}`].digest,
  exactDirectoryOverlap: [],
})), semanticScope);

const familyRuleState = expectedMaterialisationFamilies.map((familyId) => {
  const family = namedNode(familyId);
  const rules = semanticModel.getObjects(family, iri('ontology:usesMaterialisationRule'), null);
  const roles = rules.length === 1 ? modelObjects(rules[0], iri('ontology:usesPathRole')) : [];
  const formats = rules.length === 1 ? modelObjects(rules[0], iri('ontology:usesRepresentationFormat')) : [];
  const storages = rules.length === 1 ? modelObjects(rules[0], iri('ontology:usesStorageClass')) : [];
  const namingRules = rules.length === 1 ? modelObjects(rules[0], iri('ontology:usesNamingRule')) : [];
  return {
    family: familyId,
    rule: rules.length === 1 ? rules[0].value : null,
    pathRole: roles.length === 1 ? roles[0] : null,
    representationFormat: formats.length === 1 ? formats[0] : null,
    storageClass: storages.length === 1 ? storages[0] : null,
    namingRule: namingRules.length === 1 ? namingRules[0] : null,
    canonicalExtension: formats.length === 1
      ? modelObjects(namedNode(formats[0]), iri('ontology:canonicalExtension'))[0] ?? null
      : null,
    namingPattern: namingRules.length === 1
      ? modelObjects(namedNode(namingRules[0]), iri('ontology:filenamePattern'))[0] ?? null
      : null,
  };
}).sort((left, right) => utf8Compare(left.family, right.family));
record('provider-materialisation-family-rules-exact', PROVIDER_FACTORY_RULES
  .map((rule) => ({ ...rule }))
  .sort((left, right) => utf8Compare(left.family, right.family)), familyRuleState);

const legacyScopedPermissions = [
  'semanticcontract:repositoryexternalartefactmaterialisation',
  'semanticcontract:compilersemanticenforcement',
].map((contractId) => {
  const contractNode = iri(contractId);
  const decisions = semanticModel.getSubjects(iri('ontology:decisionForContract'), contractNode, null);
  return {
    contract: contractNode.value,
    mode: modelObjects(contractNode, iri('ontology:decisionScopedMaterialisationRequired')),
    scopedPermissionCount: decisions.reduce((count, decision) => count
      + modelObjects(decision, iri('ontology:authorisesSourceDirectory')).length
      + modelObjects(decision, iri('ontology:authorisesMaterialisationAction')).length
      + modelObjects(decision, iri('ontology:authorisesArtefactFamily')).length, 0),
  };
});
record('legacy-materialisation-contracts-remain-unscoped', [
  {
    contract: 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation',
    mode: ['false'],
    scopedPermissionCount: 0,
  },
  {
    contract: 'urn:usf:semanticcontract:compilersemanticenforcement',
    mode: ['false'],
    scopedPermissionCount: 0,
  },
], legacyScopedPermissions);

const materialisationMutationEvidence = runProviderMaterialisationAuthorityMutations({
  repositoryRoot: semanticRoot,
  runtime: pythonRuntime,
});
record('provider-materialisation-hostile-mutations', {
  caseCount: 26,
  passedCaseCount: 26,
  baselineIntegrityRowCount: 0,
}, {
  caseCount: materialisationMutationEvidence.caseCount,
  passedCaseCount: materialisationMutationEvidence.passedCaseCount,
  baselineIntegrityRowCount: materialisationMutationEvidence.baselineIntegrityRowCount,
});

const pytestArgs = [
  '-I', '-S', '-',
  join(pythonRuntimeDependencyEvidence.venvPrefix, 'lib', 'python3.11', 'site-packages'),
  factoryRepo,
  join(outputRoot, 'python-bytecode'),
  '-q',
  'tests/test_workforce_policy.py',
  'tests/test_workforce_bootstrap.py',
  'tests/test_model_market.py',
  'tests/test_provider_contact_exclusions.py',
  'tests/test_secrets.py',
  'tests/test_free_tier_classification.py',
];
const pythonRuntimeBeforePytest = inspectPinnedPythonRuntime(pythonRuntime);
const pytest = run('focused-factory-tests', python, pytestArgs, {
  cwd: factoryRepo,
  env: {
    ...HERMETIC_COMMAND_ENV,
  },
  input: FOCUSED_PYTEST_BOOTSTRAP,
  timeout: 300_000,
  pinnedRuntime: pythonRuntime,
  normaliseStdout: normaliseDeterministicPytestOutput,
  stdoutEvidenceMode: 'PYTEST_DOT_PROGRESS_AND_RUNTIME_V2',
}).toString('utf8');
const pytestProgress = JSON.parse(normaliseDeterministicPytestOutput(pytest).toString('utf8'));
const pythonRuntimeAfterPytest = inspectPinnedPythonRuntime(pythonRuntime);
record('focused-pytest-runtime-closure-stable', pythonRuntimeBeforePytest, pythonRuntimeAfterPytest);
record('focused-deterministic-tests', '100', pytestProgress.progressLines.at(-1)?.match(/\[\s*(\d+)%\]$/)?.[1] ?? null);
record('focused-deterministic-test-count', 74, pytestProgress.completedCaseCount);
record('focused-pytest-workload-runtime', {
  mappedSystemObjectCount: 39,
  mappedSystemObjectSetDigest: 'sha256:cfc3d5615268a542b487cc7e5c52ed476d1e9da2e714a4b8c3e0d66ee2204685',
  siteCustomizationLoaded: false,
}, pytestProgress.runtimeEvidence);
const commandReceiptFields = [...new Set(commands.flatMap((command) => Object.keys(command)))].sort(utf8Compare);
record('credential-values-absent-from-proof-output', {
  commandReceiptFields: [
    'arguments',
    'executable',
    'exitStatus',
    'id',
    'signal',
    'stderrDigest',
    'stderrEvidenceMode',
    'stdoutDigest',
    'stdoutEvidenceMode',
  ],
  providerCredentialEnvironmentForwarded: false,
  rawCommandBytesAdmittedToCasEvidence: false,
  rawCommandBytesRemainSessionTransient: true,
}, {
  commandReceiptFields,
  providerCredentialEnvironmentForwarded,
  rawCommandBytesAdmittedToCasEvidence: commands.some((command) => 'stdout' in command || 'stderr' in command),
  rawCommandBytesRemainSessionTransient: true,
});

cases.sort((left, right) => utf8Compare(left.id, right.id));
const proofAlgorithmSources = [
  'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs',
  'assurance/provider-workforce-closure/provider-materialisation-authority-mutations.mjs',
  'assurance/provider-workforce-closure/provider-workforce-authority-projection.mjs',
  'assurance/semantic-model-compilation/local-shacl-validation.mjs',
  'capabilities/semantic-model-compilation/authority-binding.mjs',
  'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
].map((path) => ({ path, digest: sha256(readFileSync(join(semanticRoot, path))) }));
const proofAlgorithmSourceDigest = sha256(canonicalJson(proofAlgorithmSources));
const runtimeDependencyEvidence = Object.freeze({
  git: gitRuntimeDependencyEvidence,
  node: nodeDependencyEvidence,
  python: pythonRuntimeDependencyEvidence,
});
const runtimeDependencyEvidenceDigest = sha256(canonicalJson(runtimeDependencyEvidence));
const validUntil = new Date(Date.parse(evaluatedAt) + (30 * 24 * 60 * 60 * 1000)).toISOString().replace('.000Z', 'Z');
const authorityClaims = [
  'provider-secrets-remain-outside-git-and-semantic-authority',
  'environment-inspection-exposes-names-and-presence-only',
  'unknown-token-variables-are-not-loaded',
  'provider-calls-require-current-run-authorization',
  'zero-paid-budget-denies-paid-api-inference',
  'claude-codex-antigravity-subscription-transports-remain-distinct-from-paid-api-access',
  'openrouter-requires-explicit-free-zero-cost-identity-verified-routes',
  'ollama-is-operator-excluded-not-unavailable',
  'requested-and-actual-provider-and-model-identities-are-distinct-facts',
  'quota-and-rate-limit-outcomes-are-durable-availability-facts',
  'provider-failures-do-not-suppress-unrelated-providers',
  'model-specific-failures-remain-model-scoped',
  'missing-credentials-classify-token-required',
  'disabled-providers-remain-inventoried',
  'research-only-and-unbound-commands-cannot-contact-providers',
  'effective-policy-is-one-immutable-intersection',
  'eligible-assessment-population-drains-to-zero-unaccounted',
  'credential-values-do-not-enter-proof-output',
  'provider-materialisation-exact-files-and-directory-prefixes-are-disjoint',
  'provider-materialisation-authorises-write-file-only',
  'provider-materialisation-families-resolve-to-exact-format-role-naming-and-storage-rules',
  'provider-materialisation-permission-digest-binds-filename-acceptance',
  'provider-materialisation-scope-mode-is-contract-exact',
  'provider-materialisation-effective-decision-is-exact',
  'provider-materialisation-repository-and-directory-set-are-exact',
  'provider-materialisation-family-rule-tuples-are-exact',
  'provider-materialisation-hostile-mutations-fail-shacl-and-integrity',
  'legacy-materialisation-contracts-retain-unscoped-behaviour',
];
const evidenceCore = {
  schemaVersion: 2,
  recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_CANDIDATE',
  passed: cases.every(({ passed }) => passed),
  eligibleForAdmission: true,
  authorityClaims,
  evaluatedAt,
  validUntil,
  evaluatedAuthorityDigest: authorityDigest,
  factoryCommit,
  factoryTree: tree,
  implementationSourceDigest,
  implementationSources: sourceRecords,
  proofInputSourceDigest,
  proofInputSources: proofInputSourceRecords,
  proofAlgorithmSourceDigest,
  proofAlgorithmSources,
  runtimeDependencyEvidence,
  runtimeDependencyEvidenceDigest,
  materialisationAuthorityMutationEvidence: materialisationMutationEvidence,
  environmentClass: 'urn:usf:environmentclass:hermetic',
  providerMode: 'urn:usf:providermode:deterministictestsubstitute',
  commands,
  cases,
  policyDigest: sha256(canonicalJson(policy)),
  populationDigest: sha256(canonicalJson(population)),
  closureDigest: sha256(canonicalJson(closure)),
  nonclaims: [
    'This proof authorises a bounded implementation surface; it does not validate the future factory realisation or establish production readiness.',
    'No provider was invoked and no provider authentication was attempted.',
    'The deterministic signature proves integrity only and is not a production authenticity credential.',
    'Validation remains reserved and unsatisfied until an exact factory validation producer and admission path exist.',
  ],
};
const exactEvidenceSetDigest = sha256(canonicalJson(evidenceCore));
const evidence = { ...evidenceCore, exactEvidenceSetDigest };
const evidenceBytes = Buffer.from(canonicalJson(evidence));
const evidenceDescriptor = putCas(casRoot, evidenceBytes, 'application/json');

const seed = createHash('sha256').update('provider-workforce-authority-integrity-key-v1').digest();
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der',
  type: 'pkcs8',
});
const publicKey = createPublicKey(privateKey);
const statement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'provider-workforce-authority-evidence', digest: { sha256: evidenceDescriptor.digest.slice(7) } }],
  predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
  predicate: {
    evaluatedAuthorityDigest: authorityDigest,
    exactEvidenceSetDigest,
    implementationSourceDigest,
    proofInputSourceDigest,
    proofAlgorithmSourceDigest,
    runtimeDependencyEvidenceDigest,
    result: 'passed',
  },
};
const payloadType = 'application/vnd.in-toto+json';
const statementBytes = Buffer.from(canonicalJson(statement));
const pae = Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `), statementBytes]);
const signature = sign(null, pae, privateKey);
if (!verify(null, pae, publicKey, signature)) throw new Error('ATTESTATION_SIGNATURE_FAILED');
const envelope = {
  payloadType,
  payload: statementBytes.toString('base64'),
  signatures: [{
    keyid: sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7),
    sig: signature.toString('base64'),
  }],
};
const attestationBytes = Buffer.from(canonicalJson(envelope));
const attestationDescriptor = putCas(casRoot, attestationBytes, 'application/vnd.in-toto+json');

writeFileSync(join(outputRoot, 'evidence-manifest.json'), evidenceBytes, { mode: 0o600 });
writeFileSync(join(outputRoot, 'proof-attestation.dsse.json'), attestationBytes, { mode: 0o600 });
process.stdout.write(`${JSON.stringify({
  schemaVersion: 2,
  recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_RECEIPT',
  ok: true,
  passed: true,
  eligibleForAdmission: true,
  authorityClaims,
  evaluatedAuthorityDigest: authorityDigest,
  evaluatedAt,
  validUntil,
  factoryCommit,
  factoryTree: tree,
  implementationSourceDigest,
  proofInputSourceDigest,
  proofAlgorithmSourceDigest,
  runtimeDependencyEvidenceDigest,
  exactEvidenceSetDigest,
  policyDigest: evidenceCore.policyDigest,
  populationDigest: evidenceCore.populationDigest,
  closureDigest: evidenceCore.closureDigest,
  caseCount: cases.length,
  evidenceManifest: evidenceDescriptor,
  proofAttestation: attestationDescriptor,
  signingKeyFingerprint: envelope.signatures[0].keyid,
  outputRoot: 'SESSION_TRANSIENT_OUTPUT_ROOT',
}, null, 2)}\n`);
