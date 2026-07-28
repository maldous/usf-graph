import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';

import {
  FOCUSED_PYTEST_BOOTSTRAP,
  cacheResiduePaths,
  createPoisonPytestPlugin,
  createReadOnlyPythonSourceSnapshot,
  snapshotRepositoryTree,
  subscriptionPaidBoundarySourceEvidence,
  verifyPythonSourceSnapshot,
} from './provider-workforce-authority-proof.mjs';
import {
  inspectPinnedPythonRuntime,
  spawnPinnedLocalShaclRuntime,
} from '../semantic-model-compilation/local-shacl-validation.mjs';

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const pinnedPythonPath = process.env.USF_PYTHON || '/root/usf-factory/.venv/bin/python';
const boundaryFixture = Object.freeze({
  activationSource: `def _mode_for(auth_mode, model_row):
    if auth_mode == AuthMode.LOCAL:
        return "free"
    if auth_mode == AuthMode.OIDC_CLI:
        return "subscription"
    if model_row.get("free") is True:
        return "free"
    return "paid"
`,
  bootstrapSource: `def _auth_for(mode, policy, max_cost_usd):
    return InferenceAuthorization(
        allow_inference=True,
        allow_subscription_inference=policy.allow_subscription
        and mode == InferenceMode.SUBSCRIPTION.value,
        allow_paid_inference=policy.allow_paid and mode == InferenceMode.PAID.value,
        max_cost_usd=max_cost_usd,
    )
`,
  providerEvaluationSource: `async def evaluate_provider(ctx, cfg, auth):
    if rep.mode == "subscription" and not auth.allow_subscription_inference:
        return blocked()
    if rep.mode == "paid" and not auth.allow_paid_inference:
        return paid_blocked()
    if rep.mode == "paid" and auth.max_cost_usd <= 0:
        return paid_blocked()
    reported = usage.provider_reported_cost
    paid = reported if rep.mode == "paid" else 0.0
    sub = reported if rep.mode == "subscription" else 0.0
    return paid, sub
`,
  paidBudgetTestSource: `def test_subscription_value_not_against_paid_budget(ctx):
    ev = evaluate_provider(
        ctx,
        EvalAuth(
            allow_inference=True,
            allow_subscription_inference=True,
            max_cost_usd=0.0,
        ),
    )
    assert ev.paid_api_spend_usd == 0.0
    assert ev.subscription_reported_value_usd == 0.06
`,
});

function exactRuntime() {
  assert.equal(existsSync(pinnedPythonPath), true, `pinned Python is required at ${pinnedPythonPath}`);
  const resolvedExecutablePath = realpathSync(pinnedPythonPath);
  return Object.freeze({
    executablePath: pinnedPythonPath,
    resolvedExecutablePath,
    executableDigest: sha256(readFileSync(resolvedExecutablePath)),
  });
}

test('focused pytest disables a discoverable poison plugin and leaves no cache in the factory tree', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-pytest-isolation-'));
  try {
    const factoryRoot = join(root, 'factory');
    const outputRoot = join(root, 'output');
    const factoryPackage = join(factoryRoot, 'src', 'usf_factory');
    const testsRoot = join(factoryRoot, 'tests');
    mkdirSync(factoryPackage, { recursive: true, mode: 0o700 });
    mkdirSync(testsRoot, { recursive: true, mode: 0o700 });
    mkdirSync(outputRoot, { recursive: false, mode: 0o700 });
    writeFileSync(join(factoryPackage, '__init__.py'), '__all__ = []\n', { mode: 0o600 });
    writeFileSync(join(testsRoot, 'test_isolation.py'), 'def test_isolated():\n    assert True\n', { mode: 0o600 });

    const runtime = exactRuntime();
    const runtimeEvidence = inspectPinnedPythonRuntime(runtime);
    const sourceSnapshot = createReadOnlyPythonSourceSnapshot({
      runtimeEvidence,
      destination: join(outputRoot, 'python-runtime-source-snapshot'),
    });
    const manifestPath = join(outputRoot, 'python-runtime-source-manifest.json');
    writeFileSync(manifestPath, JSON.stringify({
      schemaVersion: 1,
      ...sourceSnapshot.evidence,
      sources: sourceSnapshot.sources.map(({
        sourcePath, snapshotPath, digest,
      }) => ({
        sourcePath, snapshotPath, digest,
      })),
    }), { mode: 0o400 });
    const poison = createPoisonPytestPlugin(outputRoot);
    const isolationEvidencePath = join(outputRoot, 'pytest-isolation-evidence.json');
    const before = snapshotRepositoryTree(factoryRoot);
    const result = spawnPinnedLocalShaclRuntime(runtime, [
      '-I', '-S', '-',
      sourceSnapshot.stdlibSnapshotRoot,
      sourceSnapshot.sitePackagesRoot,
      factoryRoot,
      join(outputRoot, 'python-bytecode'),
      manifestPath,
      poison.poisonRoot,
      poison.marker,
      isolationEvidencePath,
      '-q',
      'tests/test_isolation.py',
    ], {
      cwd: factoryRoot,
      encoding: 'utf8',
      env: {
        HOME: '/nonexistent',
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        PATH: '/usr/bin:/bin',
        PYTHONDONTWRITEBYTECODE: '1',
        PYTHONPYCACHEPREFIX: join(outputRoot, 'python-bytecode'),
        PYTEST_DISABLE_PLUGIN_AUTOLOAD: '1',
        TZ: 'UTC',
        XDG_CONFIG_HOME: '/nonexistent',
      },
      input: FOCUSED_PYTEST_BOOTSTRAP,
      maxBuffer: 16 * 1024 * 1024,
      timeout: 120_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /1 passed/);
    assert.equal(existsSync(poison.marker), false);
    assert.equal(verifyPythonSourceSnapshot(sourceSnapshot), true);
    const isolationEvidence = JSON.parse(readFileSync(isolationEvidencePath, 'utf8'));
    assert.deepEqual({
      pluginAutoloadDisabled: isolationEvidence.pluginAutoloadDisabled,
      poisonPluginDiscoverable: isolationEvidence.poisonPluginDiscoverable,
      poisonPluginLoaded: isolationEvidence.poisonPluginLoaded,
    }, {
      pluginAutoloadDisabled: true,
      poisonPluginDiscoverable: true,
      poisonPluginLoaded: false,
    });
    const after = snapshotRepositoryTree(factoryRoot);
    assert.equal(after.structuralDigest, before.structuralDigest);
    assert.equal(after.identityDigest, before.identityDigest);
    assert.deepEqual(cacheResiduePaths(after), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('factory tree evidence detects cache residue and create-remove history', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-pytest-cache-tree-'));
  try {
    writeFileSync(join(root, 'source.py'), 'value = 1\n', { mode: 0o600 });
    const before = snapshotRepositoryTree(root);
    const pycache = join(root, '__pycache__');
    const pytestCache = join(root, '.pytest_cache', 'v');
    mkdirSync(pycache, { recursive: false, mode: 0o700 });
    mkdirSync(pytestCache, { recursive: true, mode: 0o700 });
    writeFileSync(join(pycache, 'source.pyc'), 'poison', { mode: 0o600 });
    writeFileSync(join(pytestCache, 'cache'), 'poison', { mode: 0o600 });
    const poisoned = snapshotRepositoryTree(root);
    assert.deepEqual(cacheResiduePaths(poisoned), [
      '.pytest_cache',
      '.pytest_cache/v',
      '.pytest_cache/v/cache',
      '__pycache__',
      '__pycache__/source.pyc',
    ]);
    rmSync(pycache, { recursive: true, force: false });
    rmSync(dirname(pytestCache), { recursive: true, force: false });
    const restored = snapshotRepositoryTree(root);
    assert.equal(restored.structuralDigest, before.structuralDigest);
    assert.notEqual(restored.identityDigest, before.identityDigest);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('subscription and paid source evidence fails closed on removed or conflated boundaries', () => {
  assert.equal(subscriptionPaidBoundarySourceEvidence(boundaryFixture).passed, true);
  const adversarial = [
    {
      ...boundaryFixture,
      activationSource: boundaryFixture.activationSource.replace(
        '    if auth_mode == AuthMode.OIDC_CLI:\n        return "subscription"\n',
        '',
      ),
    },
    {
      ...boundaryFixture,
      bootstrapSource: boundaryFixture.bootstrapSource.replace(
        'InferenceMode.SUBSCRIPTION.value',
        'InferenceMode.PAID.value',
      ),
    },
    {
      ...boundaryFixture,
      bootstrapSource: boundaryFixture.bootstrapSource.replace(
        '        allow_paid_inference=policy.allow_paid and mode == InferenceMode.PAID.value,\n',
        '',
      ),
    },
    {
      ...boundaryFixture,
      providerEvaluationSource: boundaryFixture.providerEvaluationSource.replace(
        'paid = reported if rep.mode == "paid" else 0.0',
        'paid = reported if rep.mode in ("paid", "subscription") else 0.0',
      ),
    },
    {
      ...boundaryFixture,
      paidBudgetTestSource: boundaryFixture.paidBudgetTestSource.replace(
        '    assert ev.paid_api_spend_usd == 0.0\n',
        '',
      ),
    },
  ];
  assert.deepEqual(
    adversarial.map((fixture) => subscriptionPaidBoundarySourceEvidence(fixture).passed),
    [false, false, false, false, false],
  );
});
