import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { discoverTestInventory, TEST_PROFILES } from '../../assurance/semantic-model-compilation/test-runner.mjs';
import { compilerProofCommandInternals, compilerProofSourcePaths, runCompilerProof } from './compiler-proof-command.mjs';

const authorityDigest = `sha256:${'a'.repeat(64)}`;
const configuration = Object.freeze({
  accessMode: 'live',
  expectedAuthorityDigest: authorityDigest,
  endpoint: 'https://authority.example.invalid',
  database: 'USF',
  authentication: Object.freeze({ mode: 'token', tokenReference: 'secret://semantic-authority/token' }),
});
const resolveSecret = () => 'opaque-test-secret';
const runtimeRoots = [];

function localShaclRuntimeFixture() {
  const root = mkdtempSync(join(tmpdir(), 'compiler-proof-shacl-runtime-'));
  const resolvedExecutablePath = join(root, 'python3.11');
  const executablePath = resolvedExecutablePath;
  writeFileSync(resolvedExecutablePath, '# deterministic compiler proof runtime fixture\n', { mode: 0o500 });
  runtimeRoots.push(root);
  return {
    executablePath,
    resolvedExecutablePath,
    executableDigest: `sha256:${createHash('sha256').update(readFileSync(resolvedExecutablePath)).digest('hex')}`,
  };
}

test.after(() => runtimeRoots.forEach((root) => rmSync(root, { recursive: true, force: true })));

test('requires an explicit authority-control binding before any proof work', async () => {
  await assert.rejects(() => runCompilerProof({ authorityDigest }), /explicit live authority-control binding/);
  await assert.rejects(() => runCompilerProof({
    authorityDigest,
    authorityControl: { configuration: { ...configuration, expectedAuthorityDigest: `sha256:${'b'.repeat(64)}` }, resolveSecret },
  }), /exact proof authority digest/);
  await assert.rejects(() => runCompilerProof({
    authorityDigest,
    authorityControl: { configuration },
  }), /explicit secret resolver/);
  assert.throws(() => compilerProofCommandInternals.validateAuthorityControlBinding({
    configuration: {
      accessMode: 'verified-export',
      expectedAuthorityDigest: authorityDigest,
      exportDigest: `sha256:${'c'.repeat(64)}`,
      exportLocator: `cas://sha256/${'c'.repeat(64)}`,
    },
    resolveSecret,
  }, authorityDigest), /live access mode/);
});

test('accepts only the exact configuration and explicit secret resolver pair without ambient configuration', () => {
  const prior = process.env.STARDOG_SERVER;
  process.env.STARDOG_SERVER = 'http://poisoned.invalid';
  const binding = Object.freeze({ configuration, resolveSecret });
  const observed = compilerProofCommandInternals.validateAuthorityControlBinding(binding, authorityDigest);
  assert.equal(observed.configuration.endpoint, configuration.endpoint);
  assert.equal(observed.resolveSecret, resolveSecret);
  if (prior === undefined) delete process.env.STARDOG_SERVER;
  else process.env.STARDOG_SERVER = prior;
  assert.equal(compilerProofSourcePaths.some((path) => path.startsWith('tools/compiler/') || path === 'tools/validation/validate-graph.sh'), false);
  assert.throws(() => compilerProofCommandInternals.validateLocalShaclRuntime(), /absolute launcher and resolved executable paths/);
  const runtime = localShaclRuntimeFixture();
  assert.equal(compilerProofCommandInternals.validateLocalShaclRuntime(runtime).executableDigest, runtime.executableDigest);
  const shaclScope = compilerProofCommandInternals.deriveRegisteredShaclScope(process.cwd());
  assert.ok(shaclScope.registeredSparqlConstraintCount > 0);
  assert.ok(shaclScope.shapeSourceFileCount > 0);
  assert.match(shaclScope.registeredConstraintSetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(shaclScope.shapeSourceSetDigest, /^sha256:[0-9a-f]{64}$/);
});

test('binds every discovered semantic-assurance test into the immutable proof source inventory', () => {
  const inventory = discoverTestInventory({
    repositoryRoot: process.cwd(),
    authorisedRoots: TEST_PROFILES['semantic-assurance'],
  });
  assert.equal(
    compilerProofCommandInternals.validateCompilerProofSourceInventory(
      compilerProofSourcePaths,
      inventory,
    ),
    inventory,
  );
  const omitted = compilerProofSourcePaths.filter(
    (path) => path !== 'processes/semantic-assurance/repository-materialisation-gateway.test.mjs',
  );
  assert.throws(
    () => compilerProofCommandInternals.validateCompilerProofSourceInventory(omitted, inventory),
    /compiler proof source inventory omits discovered tests: processes\/semantic-assurance\/repository-materialisation-gateway\.test\.mjs/,
  );
  for (const path of [
    'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
    'configuration/semantic-assurance/stardog-connection.mjs',
    'processes/semantic-assurance/repository-materialisation-command.mjs',
    'processes/semantic-assurance/repository-materialisation-gateway.mjs',
    'processes/semantic-assurance/semantic-authority-mcp.mjs',
    'processes/semantic-assurance/semantic-bootstrap-packet.mjs',
    'processes/semantic-assurance/sparql-guard.mjs',
    'provider-bindings/stardog/stardog-read-gateway.mjs',
  ]) {
    assert.equal(compilerProofSourcePaths.includes(path), true, path);
  }
});
