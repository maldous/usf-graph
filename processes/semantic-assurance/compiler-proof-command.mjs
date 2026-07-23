import stardog from 'stardog';
import { readFileSync } from 'node:fs';
import { extname, join } from 'node:path';
import { Parser, Store } from 'n3';
import { parse as parseYaml } from 'yaml';

import { evaluateCompilerSemanticEnforcement } from '../../assurance/semantic-model-compilation/compiler-proof.mjs';
import { runLocalShaclValidation, validateLocalShaclRuntime } from '../../assurance/semantic-model-compilation/local-shacl-validation.mjs';
import {
  canonicalJson,
  evaluationInternals,
  loadSemanticStore,
  realisationOptionShaclFocusRoots,
  runRealisationOptionClosure,
  sha256,
} from '../../assurance/semantic-model-compilation/realisation-option-evaluation.mjs';
import { discoverTestInventory, executeTestInventory, TEST_PROFILES } from '../../assurance/semantic-model-compilation/test-runner.mjs';
import { createStardogSemanticAuthorityClient } from '../../provider-bindings/stardog/semantic-authority.mjs';
import { validateSemanticAuthorityConfiguration } from '../../configuration/semantic-assurance/semantic-authority.mjs';
import { readSemanticAuthorityWitness } from './semantic-authority-gateway.mjs';

export const compilerProofSourcePaths = Object.freeze([
  '.github/workflows/validate-spec.yml',
  'package.json',
  'package-lock.json',
  'capabilities/semantic-model-compilation/compiler.mjs',
  'capabilities/semantic-model-compilation/compiler.test.mjs',
  'capabilities/semantic-model-compilation/manifest.mjs',
  'capabilities/semantic-model-compilation/origin-independence.mjs',
  'configuration/semantic-assurance/semantic-authority.mjs',
  'configuration/semantic-assurance/semantic-authority.test.mjs',
  'provider-bindings/stardog/semantic-authority.mjs',
  'provider-bindings/stardog/semantic-authority.test.mjs',
  'processes/semantic-assurance/compiler-proof-command.mjs',
  'processes/semantic-assurance/compiler-proof-command.test.mjs',
  'processes/semantic-assurance/repository-materialisation-command.test.mjs',
  'processes/semantic-assurance/repository-materialisation-gateway.test.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.test.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.test.mjs',
  'processes/semantic-assurance/semantic-authority-mcp.test.mjs',
  'assurance/semantic-model-compilation/compiler-proof.mjs',
  'assurance/semantic-model-compilation/compiler-proof.test.mjs',
  'assurance/semantic-model-compilation/test-launcher.mjs',
  'assurance/semantic-model-compilation/test-runner.mjs',
  'assurance/semantic-model-compilation/test-runner.test.mjs',
  'assurance/semantic-model-compilation/local-shacl-validation.mjs',
  'assurance/semantic-model-compilation/local-shacl-validation.test.mjs',
  'assurance/semantic-model-compilation/local-shacl-dependencies.json',
  'assurance/semantic-model-compilation/realisation-option-acquisition.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation-evidence.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation.test.mjs',
  'semantic-model/manifest.yaml',
]);

export const SHACL_FOCUS_ROOTS = Object.freeze([
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
  'urn:usf:realisationdecision:repositoryarchitectureandnaming',
  'urn:usf:realisationdecision:semanticmodelcompilationrealisation',
  'urn:usf:realisationdecision:semanticauthoritycontrolselection',
]);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));

function deriveRegisteredShaclScope(repositoryRoot) {
  const manifest = parseYaml(readFileSync(join(repositoryRoot, 'semantic-model', 'manifest.yaml'), 'utf8'));
  if (!Array.isArray(manifest?.shapeGraphs) || manifest.shapeGraphs.length < 1) throw new Error('semantic manifest has no registered SHACL graphs');
  const store = new Store();
  const sourceRecords = [];
  for (const entry of manifest.shapeGraphs) {
    const path = join(repositoryRoot, 'semantic-model', entry.file);
    const format = extname(path) === '.trig' ? 'application/trig' : 'text/turtle';
    const bytes = readFileSync(path);
    store.addQuads(new Parser({ format, baseIRI: 'urn:usf:' }).parse(bytes.toString('utf8')));
    sourceRecords.push({ path: `semantic-model/${entry.file}`, digest: sha256(bytes) });
  }
  sourceRecords.sort((left, right) => utf8Compare(left.path, right.path));
  const iri = evaluationInternals.iri;
  const SH = 'http://www.w3.org/ns/shacl#';
  const objects = (subject, local) => store.getObjects(subject, iri(`${SH}${local}`), null);
  const one = (subject, local, fallback = null) => {
    const values = objects(subject, local);
    if (values.length > 1) throw new Error(`registered SHACL ${local} cardinality is ambiguous for ${subject.value}`);
    return values[0] || fallback;
  };
  const prefixContext = (shape, constraint) => {
    const contexts = new Map([...objects(constraint, 'prefixes'), ...objects(shape, 'prefixes')]
      .map((value) => [`${value.termType}:${value.value}`, value]));
    const prefixes = {};
    for (const context of [...contexts.values()].sort((left, right) => utf8Compare(left.value, right.value))) {
      for (const declaration of objects(context, 'declare')) {
        const prefix = one(declaration, 'prefix');
        const namespace = one(declaration, 'namespace');
        if (!prefix || !namespace) throw new Error('registered SHACL prefix declaration is incomplete');
        if (Object.hasOwn(prefixes, prefix.value) && prefixes[prefix.value] !== namespace.value) {
          throw new Error(`registered SHACL prefix declaration conflicts for ${prefix.value}`);
        }
        prefixes[prefix.value] = namespace.value;
      }
    }
    return prefixes;
  };
  const descriptors = store.getQuads(null, iri(`${SH}sparql`), null, null).map(({ subject: shape, object: constraint }) => {
    const query = one(constraint, 'select');
    if (!query) throw new Error(`registered SHACL constraint has no select query for ${shape.value}`);
    const prefixes = prefixContext(shape, constraint);
    const record = {
      owningShape: shape.value,
      queryDigest: sha256(query.value),
      messages: objects(constraint, 'message').map(({ value }) => value).sort(utf8Compare),
      severity: (one(constraint, 'severity') || one(shape, 'severity') || iri(`${SH}Violation`)).value,
      deactivated: (one(constraint, 'deactivated')?.value || 'false').toLowerCase(),
      prefixContextDigest: sha256(canonicalJson(prefixes)),
    };
    return { ...record, identity: sha256(canonicalJson(record)) };
  }).sort((left, right) => utf8Compare(left.identity, right.identity));
  if (new Set(descriptors.map(({ identity }) => identity)).size !== descriptors.length) throw new Error('registered SHACL constraint identity is ambiguous');
  return Object.freeze({
    registeredSparqlConstraintCount: descriptors.length,
    registeredConstraintSetDigest: sha256(canonicalJson(descriptors)),
    shapeSourceFileCount: sourceRecords.length,
    shapeSourceSetDigest: sha256(canonicalJson(sourceRecords)),
  });
}

function validateAuthorityControlBinding(authorityControl, authorityDigest) {
  if (!SHA256.test(authorityDigest || '')) throw new TypeError('proof authority digest must be exact');
  if (!authorityControl || typeof authorityControl !== 'object') throw new TypeError('explicit live authority-control binding is required');
  if (typeof authorityControl.resolveSecret !== 'function') throw new TypeError('live authority-control binding requires an explicit secret resolver');
  const configuration = validateSemanticAuthorityConfiguration(authorityControl.configuration);
  if (configuration.accessMode !== 'live') throw new TypeError('compiler proof authority-control binding must use live access mode');
  if (configuration.expectedAuthorityDigest !== authorityDigest) throw new TypeError('live authority-control binding must use the exact proof authority digest');
  return Object.freeze({ configuration, resolveSecret: authorityControl.resolveSecret });
}

function validateCompilerProofSourceInventory(sourcePaths, testInventory) {
  if (!Array.isArray(sourcePaths) || !Array.isArray(testInventory?.records)) {
    throw new TypeError('compiler proof source and discovered test inventories are required');
  }
  const sources = new Set(sourcePaths);
  const missing = testInventory.records
    .map(({ path }) => path)
    .filter((path) => !sources.has(path));
  if (missing.length > 0) {
    throw new Error(`compiler proof source inventory omits discovered tests: ${missing.join(',')}`);
  }
  return testInventory;
}

export async function runCompilerProof({
  authorityDigest,
  evaluatedAt,
  repositoryRoot,
  casRoot = '/var/lib/usf-cas',
  authorityControl,
  localShaclRuntime,
}) {
  const binding = validateAuthorityControlBinding(authorityControl, authorityDigest);
  const shaclRuntime = validateLocalShaclRuntime(localShaclRuntime);
  const semanticStore = loadSemanticStore(repositoryRoot).store;
  const signingIdentity = evaluationInternals.iri('urn:usf:signingidentity:realisationoptionevaluationintegrity');
  const signerFingerprint = evaluationInternals.objects(semanticStore, signingIdentity, evaluationInternals.term('signingKeyFingerprint'))[0]?.value;
  const realisationOptionClosure = runRealisationOptionClosure(repositoryRoot, casRoot, { authorityDigest, signerFingerprint });
  if (!realisationOptionClosure.ok) throw new Error('realisation option evaluation closure must pass before compiler proof execution');
  const optionEvaluationRoots = realisationOptionShaclFocusRoots(semanticStore);
  const focusRoots = [...new Set([...SHACL_FOCUS_ROOTS, ...optionEvaluationRoots])].sort();
  const registeredShaclScope = deriveRegisteredShaclScope(repositoryRoot);
  const expectedLocalShaclScope = Object.freeze({
    ...registeredShaclScope,
    focusRootCount: focusRoots.length,
    focusRootDigest: sha256(JSON.stringify(focusRoots)),
  });
  const testInventory = validateCompilerProofSourceInventory(compilerProofSourcePaths, discoverTestInventory({
    repositoryRoot,
    authorisedRoots: TEST_PROFILES['semantic-assurance'],
  }));
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
      snapshotPaths: ['.github', 'assurance', 'capabilities', 'configuration', 'node_modules', 'package-lock.json', 'package.json', 'processes', 'provider-bindings', 'semantic-model'],
      snapshotExclusions: ['node_modules/.bin'],
    });
    return result;
  };
  const runLocalCompatibleShacl = async () => {
    const validationArguments = ['--expect-no-service', ...focusRoots.flatMap((root) => ['--focus', root])];
    const execute = () => runLocalShaclValidation({ repositoryRoot, runtime: shaclRuntime, arguments: validationArguments });
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
      expectedScope: expectedLocalShaclScope,
    });
  };
  const createLiveClient = async () => createStardogSemanticAuthorityClient({
    sdk: stardog,
    configuration: binding.configuration,
    resolveSecret: binding.resolveSecret,
  });
  return evaluateCompilerSemanticEnforcement({
    authorityDigest,
    evaluatedAt,
    repositoryRoot,
    casRoot,
    createLiveClient,
    readAuthorityWitness: readSemanticAuthorityWitness,
    sourcePaths: compilerProofSourcePaths,
    proofAlgorithmPath: 'assurance/semantic-model-compilation/compiler-proof.mjs',
    testPaths,
    substituteSourcePaths,
    runFocusedTests,
    runLocalCompatibleShacl,
    realisationOptionClosure,
  });
}


export const compilerProofCommandInternals = Object.freeze({
  deriveRegisteredShaclScope,
  validateAuthorityControlBinding,
  validateCompilerProofSourceInventory,
  validateLocalShaclRuntime,
});
