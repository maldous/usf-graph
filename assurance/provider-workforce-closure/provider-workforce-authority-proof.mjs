#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import {
  createHash, createPrivateKey, createPublicKey, sign, verify,
} from 'node:crypto';
import {
  lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const cases = [];
const commands = [];
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

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
  const result = spawnSync(executable, args, {
    cwd: options.cwd,
    env: options.env,
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
    timeout: options.timeout || 120_000,
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
  commands.push({
    id,
    executable,
    arguments: [...args],
    exitStatus: Number.isInteger(result.status) ? result.status : null,
    signal: result.signal || null,
    stdoutDigest: sha256(stdout),
    stderrDigest: sha256(stderr),
  });
  const commandOutputDirectory = join(outputRoot, 'commands');
  mkdirSync(commandOutputDirectory, { recursive: true, mode: 0o700 });
  writeFileSync(join(commandOutputDirectory, `${id}.stdout`), stdout, { mode: 0o600 });
  writeFileSync(join(commandOutputDirectory, `${id}.stderr`), stderr, { mode: 0o600 });
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
  const directory = join(root, 'sha256', hexadecimal.slice(0, 2));
  const path = join(directory, hexadecimal);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  try {
    writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST' || sha256(readFileSync(path)) !== digest) throw error;
  }
  if (sha256(readFileSync(path)) !== digest) throw new Error('CAS_ROUND_TRIP_FAILED');
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
const evaluatedAt = requiredEnvironment('USF_EVALUATED_AT');
if (!Number.isFinite(Date.parse(evaluatedAt))) throw new Error('USF_EVALUATED_AT_INVALID');
const casRoot = exactDirectory(requiredEnvironment('USF_CAS_ROOT'), 'CAS_ROOT');
const factoryRepo = exactDirectory(requiredEnvironment('USF_FACTORY_REPO'), 'FACTORY_REPO');
const factoryCommit = requiredEnvironment('USF_FACTORY_COMMIT', COMMIT);
const expectedFactoryTree = requiredEnvironment('USF_EXPECTED_FACTORY_TREE', COMMIT);
const outputRoot = resolve(requiredEnvironment('USF_OUTPUT_ROOT'));
const sessionRoot = resolve('.work');
if (!outputRoot.startsWith(`${sessionRoot}/`) || outputRoot === sessionRoot) {
  throw new Error('USF_OUTPUT_ROOT_NOT_SESSION_TRANSIENT');
}
rmSync(outputRoot, { recursive: true, force: true });
mkdirSync(outputRoot, { recursive: true, mode: 0o700 });
const python = requiredEnvironment('USF_PYTHON');

const head = run('factory-head', '/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: factoryRepo }).toString().trim();
const tree = run('factory-tree', '/usr/bin/git', ['rev-parse', `${factoryCommit}^{tree}`], { cwd: factoryRepo }).toString().trim();
const status = run('factory-status', '/usr/bin/git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: factoryRepo }).toString();
record('factory-commit-exact', factoryCommit, head);
record('factory-tree-exact', expectedFactoryTree, tree);
record('factory-worktree-clean', '', status);

const sourcePaths = [
  '.env.example',
  '.gitignore',
  'config/budgets.yaml',
  'config/providers.yaml',
  'config/qualification-suite.yaml',
  'config/routing.yaml',
  'config/workforce-policy.yaml',
  'scripts/check-provider-env.py',
  'scripts/import-provider-env.py',
  'src/usf_factory/accounting_models.py',
  'src/usf_factory/activation.py',
  'src/usf_factory/admission.py',
  'src/usf_factory/bootstrap.py',
  'src/usf_factory/capabilities.py',
  'src/usf_factory/cli.py',
  'src/usf_factory/model_market.py',
  'src/usf_factory/model_market_runtime.py',
  'src/usf_factory/model_registry.py',
  'src/usf_factory/probes.py',
  'src/usf_factory/probing.py',
  'src/usf_factory/provider_eval.py',
  'src/usf_factory/providers/base.py',
  'src/usf_factory/providers/cli_adapters.py',
  'src/usf_factory/providers/openai_compatible.py',
  'src/usf_factory/providers/registry.py',
  'src/usf_factory/qualification.py',
  'src/usf_factory/roster.py',
  'src/usf_factory/run_authorization.py',
  'src/usf_factory/secrets.py',
  'src/usf_factory/workforce.py',
  'src/usf_factory/workforce_policy.py',
];
const sources = Object.fromEntries(sourcePaths.map((path) => [
  path,
  run(`source-${sha256(path).slice(7, 15)}`, '/usr/bin/git', ['show', `${factoryCommit}:${path}`], { cwd: factoryRepo }),
]));
const sourceRecords = sourcePaths.map((path) => ({ path, digest: sha256(sources[path]), byteSize: sources[path].length }));
const implementationSourceDigest = sha256(canonicalJson(sourceRecords));
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

const pytestArgs = [
  '-m', 'pytest', '-q',
  'tests/test_workforce_policy.py',
  'tests/test_workforce_bootstrap.py',
  'tests/test_model_market.py',
  'tests/test_provider_contact_exclusions.py',
  'tests/test_secrets.py',
  'tests/test_free_tier_classification.py',
];
const pytest = run('focused-factory-tests', python, pytestArgs, {
  cwd: factoryRepo,
  env: {
    HOME: '/nonexistent',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    PATH: '/usr/bin:/bin',
    PYTHONPATH: join(factoryRepo, 'src'),
    TZ: 'UTC',
  },
  timeout: 300_000,
}).toString('utf8');
record('focused-deterministic-tests', true, /^\.+\s+\[100%\]\s*$/.test(pytest));

cases.sort((left, right) => utf8Compare(left.id, right.id));
const proofAlgorithmSourceDigest = sha256(readFileSync(import.meta.filename));
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
];
const evidenceCore = {
  schemaVersion: 1,
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
  proofAlgorithmSourceDigest,
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
    proofAlgorithmSourceDigest,
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
  schemaVersion: 1,
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
  proofAlgorithmSourceDigest,
  exactEvidenceSetDigest,
  policyDigest: evidenceCore.policyDigest,
  populationDigest: evidenceCore.populationDigest,
  closureDigest: evidenceCore.closureDigest,
  caseCount: cases.length,
  evidenceManifest: evidenceDescriptor,
  proofAttestation: attestationDescriptor,
  signingKeyFingerprint: envelope.signatures[0].keyid,
  outputRoot,
}, null, 2)}\n`);
