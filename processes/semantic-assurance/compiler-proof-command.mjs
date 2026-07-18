import stardog from 'stardog';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

import { evaluateCompilerSemanticEnforcement } from '../../assurance/semantic-model-compilation/compiler-proof.mjs';
import { discoverTestInventory, executeTestInventory, TEST_PROFILES } from '../../assurance/semantic-model-compilation/test-runner.mjs';
import { createStardogSemanticAuthorityClient } from '../../provider-bindings/stardog/semantic-authority.mjs';
import { authorityWitness } from '../../tools/compiler/src/bootstrap.js';
import { loadConfig } from '../../tools/compiler/src/config.js';

export const compilerProofSourcePaths = Object.freeze([
  'package.json',
  'package-lock.json',
  'capabilities/semantic-model-compilation/compiler.mjs',
  'capabilities/semantic-model-compilation/compiler.test.mjs',
  'capabilities/semantic-model-compilation/manifest.mjs',
  'capabilities/semantic-model-compilation/origin-independence.mjs',
  'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
  'configuration/semantic-assurance/semantic-authority.mjs',
  'configuration/semantic-assurance/semantic-authority.test.mjs',
  'provider-bindings/stardog/semantic-authority.mjs',
  'provider-bindings/stardog/semantic-authority.test.mjs',
  'processes/semantic-assurance/compiler-proof-command.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.test.mjs',
  'processes/semantic-assurance/repository-materialisation-command.mjs',
  'processes/semantic-assurance/repository-materialisation-command.test.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.test.mjs',
  'assurance/semantic-model-compilation/compiler-proof.mjs',
  'assurance/semantic-model-compilation/compiler-proof.test.mjs',
  'assurance/semantic-model-compilation/test-launcher.mjs',
  'assurance/semantic-model-compilation/test-runner.mjs',
  'assurance/semantic-model-compilation/test-runner.test.mjs',
  'tools/compiler/src/bootstrap.js',
  'tools/compiler/src/config.js',
  'tools/compiler/src/live-attestation.js',
  'tools/compiler/src/manifest.js',
  'tools/chroot/bootstrap.sh',
  'tools/validation/validate-graph.sh',
  'semantic-model/manifest.yaml',
]);

const SHACL_FOCUS_ROOTS = Object.freeze([
  'urn:usf:capability:semanticmodelcompilation',
  'urn:usf:semanticcontract:compilersemanticenforcement',
  'urn:usf:realisation:semanticcontractcompilersemanticenforcement',
  'urn:usf:implementation:semanticmodelcompiler',
  'urn:usf:port:semanticauthoritycontrol',
  'urn:usf:proofalgorithm:compilersemanticenforcement',
  'urn:usf:externalpayloaddescriptor:compilerhermeticsubstituteevidence',
  'urn:usf:externalpayloaddescriptor:compilerliveauthoritycontrolevidence',
  'urn:usf:externalpayloaddescriptor:compilerhermeticsubstituteattestation',
  'urn:usf:externalpayloaddescriptor:compilerliveauthoritycontrolattestation',
  'urn:usf:externalpayloaddescriptor:compilersemanticenforcementattestation',
]);
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

export async function runCompilerProof({
  authorityDigest,
  evaluatedAt,
  repositoryRoot,
  casRoot = '/var/lib/usf-cas',
  operational,
}) {
  const testInventory = discoverTestInventory({
    repositoryRoot,
    authorisedRoots: TEST_PROFILES['semantic-assurance'],
  });
  const testPaths = testInventory.records.map(({ path }) => path);
  const substituteSourcePaths = [
    'capabilities/semantic-model-compilation/compiler.test.mjs',
    'provider-bindings/stardog/semantic-authority.test.mjs',
    'processes/semantic-assurance/semantic-model-compilation-command.test.mjs',
    'processes/semantic-assurance/semantic-authority-gateway.test.mjs',
  ];
  const runFocusedTests = async () => {
    const { output, ...result } = executeTestInventory(testInventory, {
      repositoryRoot,
      snapshotPaths: ['assurance', 'capabilities', 'configuration', 'node_modules', 'package-lock.json', 'package.json', 'processes', 'provider-bindings', 'semantic-model'],
      snapshotExclusions: ['node_modules/.bin'],
    });
    return result;
  };
  const runLocalCompatibleShacl = async () => {
    const script = resolve(repositoryRoot, 'tools/validation/validate-graph.sh');
    const args = [script, 'shacl-affected', '--expect-no-service', ...SHACL_FOCUS_ROOTS.flatMap((root) => ['--focus', root])];
    const execute = () => execFileSync('/bin/bash', args, {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        TZ: 'UTC',
      },
    });
    const first = execute();
    const second = execute();
    if (first !== second) throw new Error('local SHACL deterministic regeneration produced different bytes');
    const deterministicOutputDigest = sha256(first);
    return Object.freeze({
      deterministicRegenerationCount: 2,
      deterministicOutputDigest,
      firstOutputDigest: sha256(first),
      secondOutputDigest: sha256(second),
      evidence: JSON.parse(first),
    });
  };
  const createLiveClient = async () => {
    const settings = operational ?? loadConfig();
    const tokenReference = 'secret://semantic-authority/token';
    const usernameReference = 'secret://semantic-authority/username';
    const passwordReference = 'secret://semantic-authority/password';
    const authentication = settings.auth.kind === 'token'
      ? { mode: 'token', tokenReference }
      : { mode: 'basic', usernameReference, passwordReference };
    const secrets = new Map(settings.auth.kind === 'token'
      ? [[tokenReference, settings.auth.token]]
      : [[usernameReference, settings.auth.username], [passwordReference, settings.auth.password]]);
    return createStardogSemanticAuthorityClient({
      sdk: stardog,
      configuration: {
        accessMode: 'live',
        expectedAuthorityDigest: authorityDigest,
        endpoint: settings.endpoint,
        database: settings.database,
        authentication,
      },
      resolveSecret: (reference) => secrets.get(reference),
    });
  };
  return evaluateCompilerSemanticEnforcement({
    authorityDigest,
    evaluatedAt,
    repositoryRoot,
    casRoot,
    createLiveClient,
    readAuthorityWitness: authorityWitness,
    sourcePaths: compilerProofSourcePaths,
    proofAlgorithmPath: 'assurance/semantic-model-compilation/compiler-proof.mjs',
    testPaths,
    substituteSourcePaths,
    runFocusedTests,
    runLocalCompatibleShacl,
  });
}
