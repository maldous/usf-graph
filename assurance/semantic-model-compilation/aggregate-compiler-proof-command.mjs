import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadConfig } from '../../configuration/semantic-assurance/stardog-connection.mjs';
import { createClient } from '../../provider-bindings/stardog/stardog-read-gateway.mjs';
import { authorityWitness } from '../../processes/semantic-assurance/semantic-bootstrap-packet.mjs';
import { projectContract } from '../../processes/semantic-assurance/repository-materialisation-gateway.mjs';
import {
  assertInitialProjectionObservation,
  assertInitialReevaluationPreparation,
  assertPostPublicationTerminalState,
  assertSemanticProofPublicationReceipt,
  canonicalJson as semanticProofCanonicalJson,
  publicationReceiptDigest as semanticProofPublicationReceiptDigest,
} from '../../processes/semantic-assurance/semantic-proof-v1.mjs';
import {
  AGGREGATE_ALGORITHM_DIGEST,
  AGGREGATE_ALGORITHM_VERSION,
  AGGREGATE_REPOSITORY,
  COMPONENT_PROOFS,
  COMPONENT_SET_DIGEST,
  ORPHANED_ATTESTATION_DIGEST,
  aggregateCompilerProofInternals,
  evaluateAggregateCompilerProof,
} from './aggregate-compiler-proof.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const RFC3339_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CONTRACT = 'urn:usf:semanticcontract:compilersemanticenforcement';
export const AGGREGATE_RESULT_IRI = 'urn:usf:proofresult:compilersemanticenforcementaggregate';
export const DEFAULT_AGGREGATE_REACHABLE_REF = 'refs/remotes/origin/main';
export const AGGREGATE_REVIEWED_SOURCE_PATHS = Object.freeze([
  'assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.test.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof-command.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof-command.test.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof.test.mjs',
  'package-lock.json',
  'package.json',
  'processes/semantic-assurance/compiler-proof-command.mjs',
  'processes/semantic-assurance/proof-currentness.mjs',
  'processes/semantic-assurance/proof-currentness.test.mjs',
  'processes/semantic-assurance/repository-materialisation-gateway.mjs',
  'processes/semantic-assurance/repository-materialisation-gateway.test.mjs',
  'processes/semantic-assurance/semantic-authority-publication.mjs',
  'processes/semantic-assurance/semantic-authority-publication.test.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.test.mjs',
  'processes/semantic-assurance/semantic-proof-v1.mjs',
  'processes/semantic-assurance/semantic-proof-v1.test.mjs',
  'semantic-model/assurance/evidence.trig',
  'semantic-model/assurance/proofs.trig',
  'semantic-model/authority.ttl',
  'semantic-model/contracts/capabilities.trig',
  'semantic-model/manifest.yaml',
  'semantic-model/ontology.ttl',
  'semantic-model/permutation/families.trig',
  'semantic-model/realisation/bindings.trig',
  'semantic-model/rules/evidence.rq',
  'semantic-model/shapes/assurance.ttl',
  'semantic-model/vocabulary.ttl',
]);

const AUTHORITY_SOURCE_PATH = 'semantic-model/authority.ttl';
const RECEIPT_DESCRIPTOR_KEYS = Object.freeze([
  'byteLength', 'bytesBase64', 'digest', 'iri', 'mediaType', 'persistenceReceiptDigest',
]);
const COMPILER_VALIDATION_KEYS = Object.freeze([
  'authorityAfterDigest', 'authorityBeforeDigest', 'candidateDigest', 'conforms', 'evaluatedAt',
  'evaluationReceiptDigest', 'executionReceiptDigest', 'schema', 'sourceBindingDigest',
  'validationReportDigest',
]);
const STAGE2_PACKAGE_KEYS = Object.freeze([
  'compilerValidation', 'evaluationReceipt', 'evaluationReceiptDescriptor', 'executionReceipt',
  'executionReceiptDescriptor', 'package', 'publicationReceipt',
]);
const EXECUTION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementaggregateexecution';
const EVALUATION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementaggregateevaluation';
const COMPILER_VALIDATION_EVIDENCE_IRI =
  'urn:usf:validationevidence:compilersemanticenforcementcompilervalidation';

const COMPONENT_VALUES = COMPONENT_PROOFS.map(({ result }) => `<${result}>`).join(' ');
export const COMPONENT_FACTS_QUERY = `# aggregate-component-facts-v1
SELECT ?result ?obligation ?proofState ?resultState ?resultFreshness ?proof ?execution ?proofEvaluation
       ?executionProof ?evaluationObligation
       ?algorithm ?algorithmVersion ?algorithmVersionIdentifier ?algorithmSourceDigest
       ?historicalAuthorityDigest ?resultEvaluatedAt ?invalidatedAt ?supersededBy
       ?evidence ?evidenceDigest ?admissionState ?evidenceFreshness ?evidenceFreshnessState
       ?integrityState ?evidenceStage ?withinValidityScope ?validFrom ?validUntil
WHERE {
  VALUES ?result { ${COMPONENT_VALUES} }
  ?result <urn:usf:ontology:proofResultForObligation> ?obligation ;
          <urn:usf:ontology:hasProofResultState> ?proofState ;
          <urn:usf:ontology:resultState> ?resultState ;
          <urn:usf:ontology:hasFreshness> ?resultFreshness ;
          <urn:usf:ontology:resultForProof> ?proof ;
          <urn:usf:ontology:usesProofAlgorithm> ?algorithm ;
          <urn:usf:ontology:usesAlgorithmVersion> ?algorithmVersion ;
          <urn:usf:ontology:hasAuthorityBinding> ?authorityBinding ;
          <urn:usf:ontology:evaluatedAt> ?resultEvaluatedAt ;
          <urn:usf:ontology:usesAdmittedEvidence> ?evidence .
  ?execution <urn:usf:ontology:producesResult> ?result .
  ?execution <urn:usf:ontology:executesProof> ?executionProof .
  ?proofEvaluation <urn:usf:ontology:producesProofResult> ?result .
  ?proofEvaluation <urn:usf:ontology:evaluatesObligation> ?evaluationObligation .
  ?algorithm <urn:usf:ontology:proofAlgorithmSourceDigest> ?algorithmSourceDigest .
  ?algorithmVersion <urn:usf:ontology:proofAlgorithmVersionIdentifier> ?algorithmVersionIdentifier ;
                    <urn:usf:ontology:proofAlgorithmVersionOf> ?algorithm .
  ?authorityBinding <urn:usf:ontology:bindingEvaluatedAuthorityDigest> ?historicalAuthorityDigest .
  ?evidence <urn:usf:ontology:contentDigest> ?evidenceDigest ;
            <urn:usf:ontology:hasAdmissionState> ?admissionState ;
            <urn:usf:ontology:hasFreshness> ?evidenceFreshness ;
            <urn:usf:ontology:hasFreshnessState> ?evidenceFreshnessState ;
            <urn:usf:ontology:hasIntegrityState> ?integrityState ;
            <urn:usf:ontology:evidenceStage> ?evidenceStage ;
            <urn:usf:ontology:withinValidityScope> ?withinValidityScope ;
            <urn:usf:ontology:validUntil> ?validUntil .
  OPTIONAL { ?evidence <urn:usf:ontology:validFrom> ?validFrom }
  OPTIONAL { ?result <urn:usf:ontology:invalidatedAt> ?invalidatedAt }
  OPTIONAL { ?result <urn:usf:ontology:supersededBy> ?supersededBy }
}
ORDER BY ?result ?evidence ?invalidatedAt ?supersededBy`;

export const COMPONENT_FACT_COUNT_QUERY = `# aggregate-component-fact-count-v1
SELECT (COUNT(*) AS ?count) WHERE { { ${COMPONENT_FACTS_QUERY.slice(COMPONENT_FACTS_QUERY.indexOf('WHERE {') + 7, COMPONENT_FACTS_QUERY.lastIndexOf('}\nORDER BY'))} } }`;

export const CONTRACT_SELECTION_QUERY = `# aggregate-contract-selection-v1
SELECT DISTINCT ?result WHERE {
  <${CONTRACT}> <urn:usf:ontology:reliesOnProofResult> ?result .
} ORDER BY ?result`;

export const INITIAL_PROVISIONAL_PROJECTION_QUERY = `# aggregate-initial-provisional-projection-v1
SELECT ?result ?provisional ?current WHERE {
  <${CONTRACT}> <urn:usf:ontology:reliesOnProofResult> ?result .
  BIND(EXISTS { ?result a <urn:usf:ontology:PrePublicationAggregateProofResult> } AS ?provisional)
  BIND(EXISTS { ?result a <urn:usf:ontology:PostPublicationAggregateProofResult> } AS ?current)
} ORDER BY ?result`;

export const TRUSTED_TIME_QUERY = '# aggregate-trusted-time-v1\nSELECT (NOW() AS ?now) WHERE {}';

export const AGGREGATE_LIVE_BINDINGS_QUERY = `# aggregate-live-reevaluation-bindings-v1
SELECT ?result ?reevaluation ?evaluatedAuthorityDigest ?executionReceiptDigest ?evaluationReceiptDigest WHERE {
  <${CONTRACT}> <urn:usf:ontology:reliesOnProofResult> ?result .
  ?result a <urn:usf:ontology:PostPublicationAggregateProofResult> ;
          <urn:usf:ontology:hasPostPublicationReevaluation> ?reevaluation .
  ?reevaluation <urn:usf:ontology:reevaluationProducesProofResult> ?result ;
                <urn:usf:ontology:reevaluationAuthorityDigest> ?evaluatedAuthorityDigest ;
                <urn:usf:ontology:reevaluationExecutionReceiptDigest> ?executionReceiptDigest ;
                <urn:usf:ontology:reevaluationEvaluationReceiptDigest> ?evaluationReceiptDigest .
} ORDER BY ?result ?reevaluation`;

export const FINAL_VALIDATION_BINDINGS_QUERY = `# aggregate-final-validation-bindings-v1
SELECT ?validationResult ?resultState ?validationEvaluation ?validationExecution
       ?executionReceiptDigest ?evaluationReceiptDigest ?bindingExecutionReceiptDigest
       ?bindingEvaluationReceiptDigest ?stageOneEvaluatedAuthorityDigest ?reevaluationState
       ?producer ?admissionPath ?validationEvidence ?validationEvidenceDigest WHERE {
  ?obligation a <urn:usf:ontology:ValidationObligation> ;
              <urn:usf:ontology:validationForContract> <${CONTRACT}> ;
              <urn:usf:ontology:satisfiedByValidationResult> ?validationResult .
  ?validationResult <urn:usf:ontology:resultState> ?resultState ;
                    <urn:usf:ontology:validationResultOfEvaluation> ?validationEvaluation ;
                    <urn:usf:ontology:hasValidationSelfPublicationAuthorityBinding> ?binding .
  ?validationEvaluation <urn:usf:ontology:validationEvaluationOfExecution> ?validationExecution ;
                        <urn:usf:ontology:validationEvaluationReceiptDigest> ?evaluationReceiptDigest .
  ?validationExecution <urn:usf:ontology:validationExecutionReceiptDigest> ?executionReceiptDigest ;
                       <urn:usf:ontology:validationExecutedByProducer> ?producer ;
                       <urn:usf:ontology:validationUsesEvidenceAdmissionPath> ?admissionPath .
  ?validationEvidence a <urn:usf:ontology:ValidationEvidence> ;
                      <urn:usf:ontology:validationEvidenceForExecution> ?validationExecution ;
                      <urn:usf:ontology:validationEvidenceAdmittedThrough> ?admissionPath ;
                      <urn:usf:ontology:contentDigest> ?validationEvidenceDigest .
  ?binding <urn:usf:ontology:validationBindingExecutionReceiptDigest> ?bindingExecutionReceiptDigest ;
           <urn:usf:ontology:validationBindingEvaluationReceiptDigest> ?bindingEvaluationReceiptDigest ;
           <urn:usf:ontology:validationStageOneEvaluatedAuthorityDigest> ?stageOneEvaluatedAuthorityDigest ;
           <urn:usf:ontology:validationPostPublicationReevaluationState> ?reevaluationState .
} ORDER BY ?validationResult ?validationEvidence`;

const canonicalJson = aggregateCompilerProofInternals.canonicalJson;
const sha256Bytes = aggregateCompilerProofInternals.sha256Bytes;

function fail(code, detail) {
  const error = new Error(`${code}: ${detail}`);
  error.code = code;
  throw error;
}

function digest(value, label) {
  if (!SHA256.test(value || '')) fail('AGGREGATE_PRODUCER_DIGEST_INVALID', label);
  return value;
}

function timestamp(value, label) {
  if (!RFC3339_SECOND.test(value || '') || !Number.isFinite(Date.parse(value))) {
    fail('AGGREGATE_PRODUCER_TIME_INVALID', label);
  }
  return value;
}

function binding(row, field) {
  const value = row?.[field];
  if (value === undefined || value === null) return null;
  return typeof value === 'object' && Object.hasOwn(value, 'value') ? value.value : value;
}

function exactScalar(rows, field, result, { optional = false } = {}) {
  const values = [...new Set(rows.map((row) => binding(row, field)).filter((value) => value !== null))];
  if (values.length === 0 && optional) return null;
  if (values.length !== 1) fail('AGGREGATE_PRODUCER_FACT_AMBIGUOUS', `${result} ${field}`);
  return values[0];
}

function stateSuffix(value, expected, label) {
  if (value !== expected) fail('AGGREGATE_PRODUCER_STATE_INVALID', label);
}

function normalizedWitness(value) {
  if (!value || typeof value !== 'object') fail('AGGREGATE_PRODUCER_AUTHORITY_WITNESS_INVALID', 'absent witness');
  const observedDigest = String(value.digest || '');
  const authorityDigest = observedDigest.startsWith('sha256:') ? observedDigest : `sha256:${observedDigest}`;
  digest(authorityDigest, 'authority witness');
  if (value.totalSource !== undefined && value.totalSource !== 'canonical-graph-inventory') {
    fail('AGGREGATE_PRODUCER_AUTHORITY_WITNESS_INVALID', 'non-canonical triple total');
  }
  const inventory = Array.isArray(value.inventory)
    ? value.inventory.map(({ graph, digest: graphDigest, triples }) => ({ graph, digest: graphDigest, triples }))
    : null;
  return Object.freeze({ digest: authorityDigest, inventory, triples: value.triples ?? null });
}

async function stableAuthorityRead(dependencies, requestedDigest, operation) {
  digest(requestedDigest, 'requested authority digest');
  const before = normalizedWitness(await dependencies.readAuthorityWitness(dependencies.client));
  if (before.digest !== requestedDigest) fail('AGGREGATE_PRODUCER_STALE_AUTHORITY', `${before.digest} != ${requestedDigest}`);
  const value = await operation(before);
  const after = normalizedWitness(await dependencies.readAuthorityWitness(dependencies.client));
  if (canonicalJson(after) !== canonicalJson(before)) fail('AGGREGATE_PRODUCER_AUTHORITY_DRIFT', 'live witness changed during read');
  return value;
}

function assertDirectory(path, label) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail('AGGREGATE_PRODUCER_CAS_UNSAFE', label);
}

function canonicalCasRoot(casRoot) {
  if (typeof casRoot !== 'string' || !isAbsolute(casRoot)) fail('AGGREGATE_PRODUCER_CAS_UNSAFE', 'CAS root must be absolute');
  assertDirectory(casRoot, 'CAS root');
  return realpathSync(casRoot);
}

function ensureDirectory(path, root) {
  const parent = dirname(path);
  if (parent !== path && !existsSync(parent)) ensureDirectory(parent, root);
  if (!existsSync(path)) mkdirSync(path, { mode: 0o755 });
  assertDirectory(path, 'CAS directory');
  const resolved = realpathSync(path);
  const rel = relative(root, resolved);
  if (rel.startsWith('..') || isAbsolute(rel)) fail('AGGREGATE_PRODUCER_CAS_UNSAFE', 'CAS directory escaped root');
}

function casPath(casRoot, contentDigest) {
  digest(contentDigest, 'CAS object digest');
  const hex = contentDigest.slice(7);
  return join(casRoot, 'sha256', hex.slice(0, 2), hex);
}

function readCasBytes(casRoot, contentDigest) {
  if (contentDigest === ORPHANED_ATTESTATION_DIGEST) fail('AGGREGATE_ORPHAN_EVIDENCE_REJECTED', contentDigest);
  const root = canonicalCasRoot(casRoot);
  const path = casPath(root, contentDigest);
  const rel = relative(root, path);
  if (rel.startsWith('..') || isAbsolute(rel) || rel.split(sep).includes('..')) {
    fail('AGGREGATE_PRODUCER_CAS_UNSAFE', contentDigest);
  }
  assertDirectory(join(root, 'sha256'), 'CAS algorithm directory');
  assertDirectory(dirname(path), 'CAS prefix directory');
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) fail('AGGREGATE_PRODUCER_CAS_UNSAFE', contentDigest);
  if (realpathSync(path) !== path) fail('AGGREGATE_PRODUCER_CAS_UNSAFE', 'CAS object is not physically contained');
  const bytes = readFileSync(path);
  if (sha256Bytes(bytes) !== contentDigest) fail('AGGREGATE_EVIDENCE_DIGEST_MISMATCH', contentDigest);
  return bytes;
}

function writeCasBytes(casRoot, bytes, syncDescriptor = fsyncSync) {
  const root = canonicalCasRoot(casRoot);
  const contentDigest = sha256Bytes(bytes);
  const path = casPath(root, contentDigest);
  ensureDirectory(dirname(path), root);
  if (existsSync(path)) {
    const existing = readCasBytes(root, contentDigest);
    if (!existing.equals(bytes)) fail('AGGREGATE_PRODUCER_CAS_COLLISION', contentDigest);
    return Object.freeze({ bytesBase64: bytes.toString('base64'), digest: contentDigest });
  }
  const temporary = join(dirname(path), `.${contentDigest.slice(7)}.${randomUUID()}.tmp`);
  let descriptor;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    writeFileSync(descriptor, bytes);
    syncDescriptor(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    chmodSync(temporary, 0o444);
    renameSync(temporary, path);
    const directoryDescriptor = openSync(dirname(path), 'r');
    try { syncDescriptor(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { unlinkSync(temporary); } catch (unlinkError) { if (unlinkError.code !== 'ENOENT') throw unlinkError; }
    throw error;
  }
  return Object.freeze({ bytesBase64: bytes.toString('base64'), digest: contentDigest });
}

function writeCanonicalRecord(casRoot, value, syncDescriptor) {
  return writeCasBytes(casRoot, Buffer.from(canonicalJson(value), 'utf8'), syncDescriptor);
}

function git(repositoryPath, args) {
  const result = spawnSync('/usr/bin/git', ['-C', repositoryPath, ...args], {
    encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }, maxBuffer: 1024 * 1024,
  });
  if (result.status !== 0) fail('AGGREGATE_PRODUCER_SOURCE_INVALID', args.join(' '));
  return result.stdout.trim();
}

function gitSourceBinding(repositoryPath, reachableFrom) {
  if (!isAbsolute(repositoryPath) || !/^refs\/(heads|remotes|tags)\/[A-Za-z0-9._/-]+$/.test(reachableFrom || '')) {
    fail('AGGREGATE_PRODUCER_SOURCE_INVALID', 'repository path or reachable ref');
  }
  const head = git(repositoryPath, ['rev-parse', '--verify', 'HEAD^{commit}']);
  const tree = git(repositoryPath, ['rev-parse', '--verify', `${head}^{tree}`]);
  if (!GIT_OBJECT.test(head) || !GIT_OBJECT.test(tree)) fail('AGGREGATE_PRODUCER_SOURCE_INVALID', 'Git object identity');
  git(repositoryPath, ['rev-parse', '--verify', `${reachableFrom}^{commit}`]);
  git(repositoryPath, ['merge-base', '--is-ancestor', head, reachableFrom]);
  for (const path of AGGREGATE_REVIEWED_SOURCE_PATHS) git(repositoryPath, ['cat-file', '-e', `${head}:${path}`]);
  return Object.freeze({
    head,
    reachableFrom,
    repository: AGGREGATE_REPOSITORY,
    sourcePaths: AGGREGATE_REVIEWED_SOURCE_PATHS,
    sourceScopeDigest: aggregateCompilerProofInternals.sourceScopeDigest(AGGREGATE_REVIEWED_SOURCE_PATHS),
    tree,
  });
}

function gitSourceText(repositoryPath, head, path) {
  if (!GIT_OBJECT.test(head || '') || !AGGREGATE_REVIEWED_SOURCE_PATHS.includes(path)) {
    fail('AGGREGATE_PRODUCER_SOURCE_INVALID', 'source text binding');
  }
  return git(repositoryPath, ['show', `${head}:${path}`]);
}

function assertAuthoritySourceReady(source) {
  if (typeof source !== 'string' || source.length === 0) {
    fail('AGGREGATE_PRODUCER_SOURCE_INVALID', 'authority source unavailable');
  }
  if (source.includes('urn:usf:ontology:OwnerAssignment')
      && /urn:usf:ontology:assignmentState>\s+"pending-verification"/.test(source)) {
    fail('AGGREGATE_PRODUCER_SOURCE_INVALID', 'pending OwnerAssignment in source authority');
  }
}

function validateInjectedSourceBinding(value, expectedReachableFrom) {
  exactObjectKeys(value, [
    'head', 'reachableFrom', 'repository', 'sourcePaths', 'sourceScopeDigest', 'tree',
  ], 'injected source binding');
  if (!GIT_OBJECT.test(value.head || '') || !GIT_OBJECT.test(value.tree || '')
      || value.reachableFrom !== expectedReachableFrom || value.repository !== AGGREGATE_REPOSITORY
      || canonicalJson(value.sourcePaths) !== canonicalJson(AGGREGATE_REVIEWED_SOURCE_PATHS)
      || value.sourceScopeDigest
        !== aggregateCompilerProofInternals.sourceScopeDigest(AGGREGATE_REVIEWED_SOURCE_PATHS)) {
    fail('AGGREGATE_PRODUCER_SOURCE_INVALID', 'injected source binding');
  }
  return Object.freeze({
    head: value.head,
    reachableFrom: value.reachableFrom,
    repository: value.repository,
    sourcePaths: AGGREGATE_REVIEWED_SOURCE_PATHS,
    sourceScopeDigest: value.sourceScopeDigest,
    tree: value.tree,
  });
}

async function operationSourceBinding(dependencies) {
  let value;
  try {
    value = await dependencies.resolveSourceBinding({
      reachableFrom: dependencies.reachableFrom,
      repositoryPath: dependencies.repositoryPath,
      sourcePaths: AGGREGATE_REVIEWED_SOURCE_PATHS,
    });
  } catch (error) {
    if (error?.code?.startsWith('AGGREGATE_')) throw error;
    fail('AGGREGATE_PRODUCER_SOURCE_UNAVAILABLE', error?.message || 'source binding dependency failed');
  }
  const sourceBinding = validateInjectedSourceBinding(value, dependencies.reachableFrom);
  let authoritySource;
  try {
    authoritySource = await dependencies.readSourceText({
      head: sourceBinding.head,
      path: AUTHORITY_SOURCE_PATH,
      repositoryPath: dependencies.repositoryPath,
    });
  } catch (error) {
    if (error?.code?.startsWith('AGGREGATE_')) throw error;
    fail('AGGREGATE_PRODUCER_SOURCE_UNAVAILABLE', error?.message || 'source text dependency failed');
  }
  assertAuthoritySourceReady(authoritySource);
  return sourceBinding;
}

async function queryComponentRows(client) {
  const [countRows, rows] = await Promise.all([
    client.select(COMPONENT_FACT_COUNT_QUERY),
    client.select(COMPONENT_FACTS_QUERY),
  ]);
  if (!Array.isArray(countRows) || countRows.length !== 1 || !Array.isArray(rows)) {
    fail('AGGREGATE_PRODUCER_FACT_SET_INVALID', 'component query result');
  }
  const count = Number(binding(countRows[0], 'count'));
  if (!Number.isSafeInteger(count) || count !== rows.length || count < COMPONENT_PROOFS.length) {
    fail('AGGREGATE_PRODUCER_FACT_SET_INVALID', 'component query count');
  }
  return rows;
}

async function readTrustedTime(client) {
  const rows = await client.select(TRUSTED_TIME_QUERY);
  if (!Array.isArray(rows) || rows.length !== 1) fail('AGGREGATE_PRODUCER_TRUSTED_TIME_INVALID', 'NOW() cardinality');
  const observed = binding(rows[0], 'now');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(observed)
      || !Number.isFinite(Date.parse(observed))) {
    fail('AGGREGATE_PRODUCER_TIME_INVALID', 'Stardog trusted time');
  }
  return timestamp(new Date(Date.parse(observed)).toISOString().replace(/\.\d{3}Z$/, 'Z'), 'Stardog trusted time');
}

function normalizeFacts(rows, casRoot, observedAt, evaluatedAt, authorityDigest, writeRecord) {
  const expectedResults = new Set(COMPONENT_PROOFS.map(({ result }) => result));
  const rowResults = new Set(rows.map((row) => binding(row, 'result')));
  if ([...rowResults].some((result) => !expectedResults.has(result))) {
    fail('AGGREGATE_UNEXPECTED_COMPONENT', [...rowResults].filter((result) => !expectedResults.has(result)).join(','));
  }
  const components = [];
  for (const expected of COMPONENT_PROOFS) {
    const resultRows = rows.filter((row) => binding(row, 'result') === expected.result);
    if (resultRows.length === 0) fail('AGGREGATE_MISSING_COMPONENT', expected.result);
    const obligation = exactScalar(resultRows, 'obligation', expected.result);
    if (obligation !== expected.obligation) fail('AGGREGATE_HISTORICAL_RESULT_IDENTITY_MISMATCH', expected.result);
    const proofStateIri = exactScalar(resultRows, 'proofState', expected.result);
    const resultStateIri = exactScalar(resultRows, 'resultState', expected.result);
    stateSuffix(proofStateIri, 'urn:usf:proofresultstate:successful', `${expected.result} proof state`);
    stateSuffix(resultStateIri, 'urn:usf:resultstate:passed', `${expected.result} result state`);
    stateSuffix(exactScalar(resultRows, 'resultFreshness', expected.result), 'urn:usf:freshness:fresh', `${expected.result} freshness`);
    if (exactScalar(resultRows, 'invalidatedAt', expected.result, { optional: true }) !== null) {
      fail('AGGREGATE_COMPONENT_INVALIDATED', expected.result);
    }
    if (exactScalar(resultRows, 'supersededBy', expected.result, { optional: true }) !== null) {
      fail('AGGREGATE_COMPONENT_SUPERSESSION_UNRESOLVED', expected.result);
    }
    const historicalAuthorityDigest = digest(
      exactScalar(resultRows, 'historicalAuthorityDigest', expected.result), `${expected.result} historical authority`,
    );
    const resultEvaluatedAt = timestamp(exactScalar(resultRows, 'resultEvaluatedAt', expected.result), `${expected.result} evaluatedAt`);
    const algorithm = exactScalar(resultRows, 'algorithm', expected.result);
    const algorithmVersion = exactScalar(resultRows, 'algorithmVersion', expected.result);
    const algorithmSourceDigest = digest(
      exactScalar(resultRows, 'algorithmSourceDigest', expected.result), `${expected.result} algorithm source`,
    );
    exactScalar(resultRows, 'algorithmVersionIdentifier', expected.result);
    const proof = exactScalar(resultRows, 'proof', expected.result);
    const execution = exactScalar(resultRows, 'execution', expected.result);
    const proofEvaluation = exactScalar(resultRows, 'proofEvaluation', expected.result);
    const executionProof = exactScalar(resultRows, 'executionProof', expected.result);
    const evaluationObligation = exactScalar(resultRows, 'evaluationObligation', expected.result);
    if (executionProof !== proof || evaluationObligation !== obligation) {
      fail('AGGREGATE_HISTORICAL_RESULT_IDENTITY_MISMATCH', `${expected.result} execution/evaluation`);
    }
    const byEvidence = new Map();
    for (const row of resultRows) {
      const iri = binding(row, 'evidence');
      if (!iri) fail('AGGREGATE_EVIDENCE_MISSING', expected.result);
      byEvidence.set(iri, [...(byEvidence.get(iri) || []), row]);
    }
    const evidenceReferences = [];
    let validUntil = null;
    for (const [iri, evidenceRows] of [...byEvidence].sort(([left], [right]) => left.localeCompare(right))) {
      const evidenceDigest = digest(exactScalar(evidenceRows, 'evidenceDigest', iri), `${iri} content`);
      if (evidenceDigest === ORPHANED_ATTESTATION_DIGEST) fail('AGGREGATE_ORPHAN_EVIDENCE_REJECTED', iri);
      stateSuffix(exactScalar(evidenceRows, 'admissionState', iri), 'urn:usf:evidenceadmissionstate:admitted', `${iri} admission`);
      stateSuffix(exactScalar(evidenceRows, 'evidenceFreshness', iri), 'urn:usf:freshness:fresh', `${iri} freshness`);
      stateSuffix(exactScalar(evidenceRows, 'evidenceFreshnessState', iri), 'urn:usf:evidencefreshnessstate:fresh', `${iri} freshness state`);
      stateSuffix(exactScalar(evidenceRows, 'integrityState', iri), 'urn:usf:evidenceintegritystate:valid', `${iri} integrity`);
      const evidenceStages = new Set(evidenceRows.map((row) => binding(row, 'evidenceStage')).filter(Boolean));
      if (!evidenceStages.has('urn:usf:evidencestage:integrityverified')) {
        fail('AGGREGATE_PRODUCER_STATE_INVALID', `${iri} integrity-verified stage`);
      }
      stateSuffix(exactScalar(evidenceRows, 'withinValidityScope', iri), 'true', `${iri} validity scope`);
      const evidenceValidUntil = timestamp(exactScalar(evidenceRows, 'validUntil', iri), `${iri} validUntil`);
      const evidenceValidFrom = exactScalar(evidenceRows, 'validFrom', iri, { optional: true });
      if (evidenceValidFrom !== null) timestamp(evidenceValidFrom, `${iri} validFrom`);
      if (Date.parse(evidenceValidUntil) <= Date.parse(evaluatedAt)
          || (evidenceValidFrom !== null && Date.parse(evidenceValidFrom) > Date.parse(observedAt))) {
        fail('AGGREGATE_COMPONENT_STALE', iri);
      }
      if (validUntil === null || evidenceValidUntil < validUntil) validUntil = evidenceValidUntil;
      const bytes = readCasBytes(casRoot, evidenceDigest);
      evidenceReferences.push({ bytesBase64: bytes.toString('base64'), digest: evidenceDigest, iri });
    }
    const evidenceDescriptors = evidenceReferences.map(({ digest: evidenceDigest, iri }) => ({ digest: evidenceDigest, iri }));
    const historicalResult = writeRecord({
      authorityBindingDigest: historicalAuthorityDigest,
      component: expected,
      evaluatedAt: resultEvaluatedAt,
      evidenceSet: evidenceDescriptors,
      proof,
      proofEvaluation,
      proofExecution: execution,
      proofState: 'successful',
      resultState: 'passed',
      schema: 'usf-component-proof-result-v1',
      sourceBinding: {
        proofAlgorithm: algorithm,
        proofAlgorithmSourceDigest: algorithmSourceDigest,
        proofAlgorithmVersion: algorithmVersion,
      },
    });
    const snapshot = writeRecord({
      admittedEvidence: evidenceDescriptors,
      authorityDigest,
      componentResult: expected.result,
      historicalResultDigest: historicalResult.digest,
      invalidated: false,
      observedAt,
      proofState: 'successful',
      resultState: 'passed',
      schema: 'usf-authority-component-currentness-v1',
      supersededBy: null,
      validFrom: resultEvaluatedAt,
      validUntil,
    });
    const projectionReceipt = writeRecord({
      authorityDigest,
      componentResult: expected.result,
      producedAt: observedAt,
      producer: 'urn:usf:validationproducer:authoritycurrentnessprojection',
      schema: 'usf-authority-currentness-projection-receipt-v1',
      snapshotDigest: snapshot.digest,
    });
    components.push({
      currentness: { projectionReceipt, snapshot },
      dimension: expected.dimension,
      evidenceReferences,
      historicalResult,
      obligation: expected.obligation,
      result: expected.result,
    });
  }
  aggregateCompilerProofInternals.aggregateEvidenceDescriptors(components.map(({ evidenceReferences, result }) => ({
    descriptors: evidenceReferences.map(({ digest: evidenceDigest, iri }) => ({ digest: evidenceDigest, iri })),
    result,
  })));
  return components;
}

async function readFacts(dependencies, requestedAuthorityDigest) {
  return stableAuthorityRead(dependencies, requestedAuthorityDigest, async () => {
    const [rows, evaluatedAt] = await Promise.all([
      queryComponentRows(dependencies.client), readTrustedTime(dependencies.client),
    ]);
    return Object.freeze({
      components: normalizeFacts(rows, dependencies.casRoot, evaluatedAt, evaluatedAt, requestedAuthorityDigest,
        dependencies.writeRecord),
      evaluatedAt,
    });
  });
}

function reevaluationBindings(components, binding) {
  const descriptors = aggregateCompilerProofInternals.aggregateEvidenceDescriptors(
    components.map(({ evidenceReferences, result }) => ({
      descriptors: evidenceReferences.map(({ digest: evidenceDigest, iri }) => ({ digest: evidenceDigest, iri })),
      result,
    })),
  );
  return Object.freeze({
    evidenceSetDigest: aggregateCompilerProofInternals.descriptorSetDigest(descriptors),
    sourceBindingDigest: aggregateCompilerProofInternals.sourceBindingDigest(binding),
  });
}

function semanticProofReceiptBlob(casRoot, receipt, syncDescriptor) {
  assertSemanticProofPublicationReceipt(receipt);
  const bytes = Buffer.from(`${semanticProofCanonicalJson(receipt)}\n`, 'utf8');
  const expectedDigest = semanticProofPublicationReceiptDigest(receipt);
  const blob = writeCasBytes(casRoot, bytes, syncDescriptor);
  if (blob.digest !== expectedDigest) fail('AGGREGATE_PRODUCER_RECEIPT_INVALID', 'publication receipt digest');
  return blob;
}

function readSemanticProofReceiptBlob(casRoot, receiptDigest) {
  const bytes = readCasBytes(casRoot, receiptDigest);
  const text = bytes.toString('utf8');
  if (!text.endsWith('\n') || text.endsWith('\n\n')) {
    fail('AGGREGATE_PRODUCER_RECEIPT_INVALID', 'publication receipt LF framing');
  }
  let receipt;
  try { receipt = JSON.parse(text.slice(0, -1)); } catch { fail('AGGREGATE_PRODUCER_RECEIPT_INVALID', 'publication receipt JSON'); }
  if (`${semanticProofCanonicalJson(receipt)}\n` !== text
      || semanticProofPublicationReceiptDigest(receipt) !== receiptDigest) {
    fail('AGGREGATE_PRODUCER_RECEIPT_INVALID', 'publication receipt canonicality');
  }
  assertSemanticProofPublicationReceipt(receipt);
  return Object.freeze({ blob: Object.freeze({ bytesBase64: bytes.toString('base64'), digest: receiptDigest }), receipt });
}

function readCanonicalRecord(casRoot, recordDigest, label) {
  const bytes = readCasBytes(casRoot, recordDigest);
  const text = bytes.toString('utf8');
  let value;
  try { value = JSON.parse(text); } catch { fail('AGGREGATE_PRODUCER_RECORD_INVALID', `${label} JSON`); }
  if (canonicalJson(value) !== text) fail('AGGREGATE_PRODUCER_RECORD_INVALID', `${label} canonicality`);
  return Object.freeze({ bytes, value });
}

function exactObjectKeys(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('AGGREGATE_PRODUCER_RECORD_INVALID', label);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    fail('AGGREGATE_PRODUCER_RECORD_INVALID', `${label} fields`);
  }
}

function readReceiptDescriptor(casRoot, descriptor, expectedIri, expectedDigest = null) {
  exactObjectKeys(descriptor, RECEIPT_DESCRIPTOR_KEYS, `${expectedIri} descriptor`);
  if (descriptor.iri !== expectedIri || descriptor.mediaType !== 'application/json'
      || !Number.isSafeInteger(descriptor.byteLength) || descriptor.byteLength <= 0) {
    fail('AGGREGATE_PRODUCER_RECEIPT_DESCRIPTOR_INVALID', `${expectedIri} metadata`);
  }
  digest(descriptor.digest, `${expectedIri} digest`);
  digest(descriptor.persistenceReceiptDigest, `${expectedIri} persistence receipt`);
  if (expectedDigest !== null && descriptor.digest !== expectedDigest) {
    fail('AGGREGATE_PRODUCER_RECEIPT_DESCRIPTOR_INVALID', `${expectedIri} digest binding`);
  }
  const bytes = readCasBytes(casRoot, descriptor.digest);
  readCasBytes(casRoot, descriptor.persistenceReceiptDigest);
  if (bytes.length !== descriptor.byteLength || bytes.toString('base64') !== descriptor.bytesBase64) {
    fail('AGGREGATE_PRODUCER_RECEIPT_DESCRIPTOR_INVALID', `${expectedIri} byte binding`);
  }
  const record = readCanonicalRecord(casRoot, descriptor.digest, `${expectedIri} receipt`).value;
  return Object.freeze({ descriptor, record });
}

function assembleStage2Package(casRoot, {
  compilerValidation,
  evaluationReceiptDescriptor,
  executionReceiptDescriptor,
  pending,
  publicationReceipt,
  stage1Preparation,
}) {
  exactObjectKeys(compilerValidation, ['descriptor', 'receipt'], 'compiler validation package');
  exactObjectKeys(compilerValidation.receipt, COMPILER_VALIDATION_KEYS, 'compiler validation receipt');
  const preparation = assertInitialReevaluationPreparation(stage1Preparation);
  assertSemanticProofPublicationReceipt(publicationReceipt);
  exactObjectKeys(pending, [
    'aggregateResult', 'evaluatedAuthorityDigest', 'evaluationReceiptDigest', 'executionReceiptDigest',
    'ok', 'proofCurrentness', 'resultState', 'selectable', 'state',
  ], 'pending aggregate package');
  const execution = readReceiptDescriptor(
    casRoot, executionReceiptDescriptor, EXECUTION_EVIDENCE_IRI, preparation.executionReceiptDigest,
  ).record;
  const evaluation = readReceiptDescriptor(
    casRoot, evaluationReceiptDescriptor, EVALUATION_EVIDENCE_IRI, preparation.evaluationReceiptDigest,
  ).record;
  const compiler = readReceiptDescriptor(
    casRoot, compilerValidation.descriptor, COMPILER_VALIDATION_EVIDENCE_IRI,
  ).record;
  if (canonicalJson(compiler) !== canonicalJson(compilerValidation.receipt)) {
    fail('AGGREGATE_PRODUCER_COMPILER_VALIDATION_INVALID', 'descriptor receipt mismatch');
  }
  for (const field of ['executionReceiptDigest', 'evaluationReceiptDigest', 'validationReportDigest']) {
    readCasBytes(casRoot, digest(compiler[field], `compiler validation ${field}`));
  }
  const sourceBindingDigest = pending.aggregateResult?.evaluation?.sourceBindingDigest;
  digest(sourceBindingDigest, 'pending source binding');
  const publicationDigest = semanticProofPublicationReceiptDigest(publicationReceipt);
  readSemanticProofReceiptBlob(casRoot, publicationDigest);
  if (compiler.schema !== 'semantic-authority-compiler-validation-v1' || compiler.conforms !== true
      || compiler.authorityBeforeDigest !== pending.evaluatedAuthorityDigest
      || compiler.authorityAfterDigest !== preparation.evaluatedAuthorityDigest
      || compiler.candidateDigest !== preparation.candidateDigest
      || compiler.sourceBindingDigest !== sourceBindingDigest
      || publicationReceipt.authority_before_digest !== pending.evaluatedAuthorityDigest
      || publicationReceipt.authority_after_digest !== preparation.evaluatedAuthorityDigest
      || publicationReceipt.candidate_digest !== preparation.candidateDigest
      || publicationReceipt.publication_phase !== 'initial'
      || publicationReceipt.terminal_state !== 'PENDING'
      || execution.publicationReceiptDigest !== publicationDigest
      || evaluation.publicationReceiptDigest !== publicationDigest
      || evaluation.executionReceiptDigest !== preparation.executionReceiptDigest
      || execution.authorityAfterDigest !== preparation.evaluatedAuthorityDigest
      || evaluation.authorityAfterDigest !== preparation.evaluatedAuthorityDigest
      || execution.sourceBindingDigest !== sourceBindingDigest
      || evaluation.sourceBindingDigest !== sourceBindingDigest) {
    fail('AGGREGATE_PRODUCER_FINAL_PACKAGE_INVALID', 'stage-1 lifecycle receipt closure');
  }
  timestamp(compiler.evaluatedAt, 'compiler validation evaluatedAt');
  const value = {
    compilerValidation,
    evaluationReceipt: evaluation,
    evaluationReceiptDescriptor,
    executionReceipt: execution,
    executionReceiptDescriptor,
    package: preparation,
    publicationReceipt,
  };
  exactObjectKeys(value, STAGE2_PACKAGE_KEYS, 'stage-2 package');
  return deepFreeze(value);
}

function validateStage1Receipts(casRoot, preparation, expectedAuthorityDigest, expectedSourceBindingDigest) {
  const execution = readCanonicalRecord(casRoot, preparation.executionReceiptDigest, 'stage-1 execution receipt').value;
  exactObjectKeys(execution, [
    'algorithmDigest', 'algorithmVersion', 'authorityAfterDigest', 'completedAt', 'componentSetDigest',
    'evidenceSetDigest', 'publicationReceiptDigest', 'schema', 'sourceBindingDigest', 'startedAt',
  ], 'stage-1 execution receipt');
  const evaluation = readCanonicalRecord(casRoot, preparation.evaluationReceiptDigest, 'stage-1 evaluation receipt').value;
  exactObjectKeys(evaluation, [
    'algorithmDigest', 'algorithmVersion', 'authorityAfterDigest', 'componentSetDigest', 'evaluatedAt',
    'evidenceSetDigest', 'executionReceiptDigest', 'publicationReceiptDigest', 'resultState', 'schema',
    'sourceBindingDigest',
  ], 'stage-1 evaluation receipt');
  for (const record of [execution, evaluation]) {
    if (record.algorithmDigest !== AGGREGATE_ALGORITHM_DIGEST
        || record.algorithmVersion !== AGGREGATE_ALGORITHM_VERSION
        || record.authorityAfterDigest !== expectedAuthorityDigest
        || record.componentSetDigest !== COMPONENT_SET_DIGEST
        || record.sourceBindingDigest !== expectedSourceBindingDigest) {
      fail('AGGREGATE_PRODUCER_STAGE1_PREPARATION_INVALID', 'execution/evaluation protocol binding');
    }
  }
  if (execution.schema !== 'aggregate-post-publication-execution-v1'
      || evaluation.schema !== 'aggregate-post-publication-evaluation-v1'
      || evaluation.resultState !== 'passed'
      || evaluation.executionReceiptDigest !== preparation.executionReceiptDigest
      || evaluation.evidenceSetDigest !== execution.evidenceSetDigest
      || evaluation.publicationReceiptDigest !== execution.publicationReceiptDigest
      || evaluation.sourceBindingDigest !== execution.sourceBindingDigest
      || evaluation.evaluatedAt !== execution.completedAt
      || execution.startedAt !== execution.completedAt) {
    fail('AGGREGATE_PRODUCER_STAGE1_PREPARATION_INVALID', 'execution/evaluation receipt schema');
  }
  timestamp(execution.startedAt, 'stage-1 execution startedAt');
  timestamp(execution.completedAt, 'stage-1 execution completedAt');
  timestamp(evaluation.evaluatedAt, 'stage-1 evaluation evaluatedAt');
  digest(execution.evidenceSetDigest, 'stage-1 evidence set');
  digest(execution.publicationReceiptDigest, 'stage-1 publication receipt');
  return Object.freeze({ evaluation, execution, publicationReceiptDigest: execution.publicationReceiptDigest });
}

function validateFinalValidationEvidence(casRoot, rows, expectedAuthorityDigest) {
  if (!Array.isArray(rows) || rows.length === 0) fail('AGGREGATE_PRODUCER_VALIDATION_EVIDENCE_INVALID', 'absent closure');
  const validationResult = exactScalar(rows, 'validationResult', 'validation');
  const validationEvaluation = exactScalar(rows, 'validationEvaluation', validationResult);
  const validationExecution = exactScalar(rows, 'validationExecution', validationResult);
  const executionReceiptDigest = digest(exactScalar(rows, 'executionReceiptDigest', validationResult), 'validation execution receipt');
  const evaluationReceiptDigest = digest(exactScalar(rows, 'evaluationReceiptDigest', validationResult), 'validation evaluation receipt');
  const producer = exactScalar(rows, 'producer', validationResult);
  const admissionPath = exactScalar(rows, 'admissionPath', validationResult);
  if (exactScalar(rows, 'resultState', validationResult) !== 'urn:usf:resultstate:passed'
      || exactScalar(rows, 'reevaluationState', validationResult) !== 'urn:usf:resultstate:passed'
      || exactScalar(rows, 'stageOneEvaluatedAuthorityDigest', validationResult) !== expectedAuthorityDigest
      || exactScalar(rows, 'bindingExecutionReceiptDigest', validationResult) !== executionReceiptDigest
      || exactScalar(rows, 'bindingEvaluationReceiptDigest', validationResult) !== evaluationReceiptDigest) {
    fail('AGGREGATE_PRODUCER_VALIDATION_EVIDENCE_INVALID', 'graph receipt bindings');
  }
  const evidence = [...new Map(rows.map((row) => {
    const iri = binding(row, 'validationEvidence');
    const evidenceDigest = digest(binding(row, 'validationEvidenceDigest'), `${iri} validation evidence`);
    readCasBytes(casRoot, evidenceDigest);
    return [`${iri}\u0000${evidenceDigest}`, { digest: evidenceDigest, iri }];
  })).values()].sort((left, right) => left.iri.localeCompare(right.iri));
  const execution = readCanonicalRecord(casRoot, executionReceiptDigest, 'validation execution receipt').value;
  exactObjectKeys(execution, ['admissionPath', 'authorityDigest', 'evidence', 'execution', 'producer', 'schema'],
    'validation execution receipt');
  const evaluation = readCanonicalRecord(casRoot, evaluationReceiptDigest, 'validation evaluation receipt').value;
  exactObjectKeys(evaluation, [
    'authorityDigest', 'evaluation', 'executionReceiptDigest', 'resultState', 'schema', 'validationResult',
  ], 'validation evaluation receipt');
  if (execution.schema !== 'usf-validation-execution-receipt-v1'
      || execution.authorityDigest !== expectedAuthorityDigest || execution.execution !== validationExecution
      || execution.producer !== producer || execution.admissionPath !== admissionPath
      || canonicalJson(execution.evidence) !== canonicalJson(evidence)
      || evaluation.schema !== 'usf-validation-evaluation-receipt-v1'
      || evaluation.authorityDigest !== expectedAuthorityDigest || evaluation.evaluation !== validationEvaluation
      || evaluation.validationResult !== validationResult || evaluation.executionReceiptDigest !== executionReceiptDigest
      || evaluation.resultState !== 'passed') {
    fail('AGGREGATE_PRODUCER_VALIDATION_EVIDENCE_INVALID', 'CAS receipt semantic bindings');
  }
  return Object.freeze({ evaluationReceiptDigest, executionReceiptDigest, evidence });
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

export function createAggregateCompilerProofProducer({
  evaluateProof = evaluateAggregateCompilerProof,
  resolveSourceBinding = ({ repositoryPath: path, reachableFrom: ref }) => gitSourceBinding(path, ref),
  readSourceText = ({ repositoryPath: path, head, path: sourcePath }) => gitSourceText(path, head, sourcePath),
  client,
  readAuthorityWitness,
  contractProjector,
  casRoot,
  repositoryPath,
  reachableFrom = DEFAULT_AGGREGATE_REACHABLE_REF,
  aggregateResultIri = AGGREGATE_RESULT_IRI,
  syncDescriptor = fsyncSync,
} = {}) {
  if (!client || typeof client.select !== 'function' || typeof readAuthorityWitness !== 'function'
      || typeof contractProjector !== 'function' || typeof resolveSourceBinding !== 'function'
      || typeof readSourceText !== 'function'
      || typeof evaluateProof !== 'function' || typeof syncDescriptor !== 'function') {
    fail('AGGREGATE_PRODUCER_DEPENDENCY_INVALID',
      'read-only client, witness, projector, source binding, source text and evaluator are required');
  }
  const writeRecord = (value) => writeCanonicalRecord(casRoot, value, syncDescriptor);
  canonicalCasRoot(casRoot);
  const dependencies = Object.freeze({
    casRoot, client, contractProjector, evaluateProof, readAuthorityWitness, reachableFrom,
    readSourceText, repositoryPath, resolveSourceBinding, writeRecord,
  });

  return Object.freeze({
    async observeInitialProjection({ requestedAuthorityDigest }) {
      return stableAuthorityRead(dependencies, requestedAuthorityDigest, async () => {
        const [projection, rows, observedAt] = await Promise.all([
          contractProjector(client, CONTRACT),
          client.select(INITIAL_PROVISIONAL_PROJECTION_QUERY),
          readTrustedTime(client),
        ]);
        if (!Array.isArray(rows) || rows.length !== 1
            || binding(rows[0], 'provisional') !== 'true' || binding(rows[0], 'current') !== 'false'
            || projection?.proofCurrentness?.state !== 'PENDING'
            || projection?.actionState !== 'UNRESOLVED_FAIL_CLOSED') {
          fail('AGGREGATE_PRODUCER_INITIAL_PROJECTION_INVALID', 'D1 is not one provisional PENDING aggregate');
        }
        const selectedProvisionalAggregateResult = binding(rows[0], 'result');
        const observationReceipt = writeRecord({
          actionState: 'UNRESOLVED_FAIL_CLOSED',
          authorityDigest: requestedAuthorityDigest,
          currentProofResults: 0,
          directProvisionalAggregateSelections: 1,
          observedAt,
          proofCurrentness: 'PENDING',
          schema: 'aggregate-initial-projection-observation-receipt-v1',
          selectedProvisionalAggregateResult,
        });
        return assertInitialProjectionObservation(Object.freeze({
          actionState: 'UNRESOLVED_FAIL_CLOSED',
          authorityDigest: requestedAuthorityDigest,
          currentProofResults: 0,
          directProvisionalAggregateSelections: 1,
          observationReceiptDigest: observationReceipt.digest,
          ok: true,
          operation: 'observe_initial',
          proofCurrentness: 'PENDING',
          selectedProvisionalAggregateResult,
        }));
      });
    },

    async preparePending({ requestedAuthorityDigest }) {
      const aggregateSourceBinding = await operationSourceBinding(dependencies);
      const { components, evaluatedAt } = await readFacts(dependencies, requestedAuthorityDigest);
      const aggregate = evaluateProof({
        authorityDigest: requestedAuthorityDigest,
        components,
        evaluatedAt,
        phase: 'pre-publication',
        sourceBinding: aggregateSourceBinding,
        sourceRepositoryPath: repositoryPath,
      });
      const executionReceipt = writeRecord({
        algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
        algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
        authorityDigest: requestedAuthorityDigest,
        completedAt: evaluatedAt,
        componentSetDigest: COMPONENT_SET_DIGEST,
        evaluationDigest: aggregate.evaluationDigest,
        schema: 'aggregate-pending-execution-v1',
        sourceBindingDigest: aggregate.evaluation.sourceBindingDigest,
        startedAt: evaluatedAt,
      });
      const evaluationReceipt = writeRecord({
        evaluatedAt,
        evaluationDigest: aggregate.evaluationDigest,
        executionReceiptDigest: executionReceipt.digest,
        proofCurrentness: aggregate.proofCurrentness,
        resultState: aggregate.resultState,
        schema: 'aggregate-pending-evaluation-v1',
        selectable: aggregate.selectable,
      });
      return deepFreeze({
        aggregateResult: aggregate,
        evaluatedAuthorityDigest: requestedAuthorityDigest,
        evaluationReceiptDigest: evaluationReceipt.digest,
        executionReceiptDigest: executionReceipt.digest,
        ok: true,
        proofCurrentness: 'PENDING',
        resultState: 'PENDING',
        selectable: false,
        state: 'PENDING_PREPARATION',
      });
    },

    async produceInitial({ requestedAuthorityDigest, candidateDigest, pendingPublicationReceipt }) {
      digest(candidateDigest, 'stage-1 candidate digest');
      const publicationReceipt = semanticProofReceiptBlob(casRoot, pendingPublicationReceipt, syncDescriptor);
      if (pendingPublicationReceipt.publication_phase !== 'initial'
          || pendingPublicationReceipt.authority_after_digest !== requestedAuthorityDigest
          || pendingPublicationReceipt.candidate_digest !== candidateDigest) {
        fail('AGGREGATE_PRODUCER_RECEIPT_BINDING_MISMATCH', 'stage-1 receipt, authority and candidate');
      }
      const aggregateSourceBinding = await operationSourceBinding(dependencies);
      const { components, evaluatedAt } = await readFacts(dependencies, requestedAuthorityDigest);
      const bindings = reevaluationBindings(components, aggregateSourceBinding);
      const executionReceipt = writeRecord({
        algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
        algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
        authorityAfterDigest: requestedAuthorityDigest,
        completedAt: evaluatedAt,
        componentSetDigest: COMPONENT_SET_DIGEST,
        evidenceSetDigest: bindings.evidenceSetDigest,
        publicationReceiptDigest: publicationReceipt.digest,
        schema: 'aggregate-post-publication-execution-v1',
        sourceBindingDigest: bindings.sourceBindingDigest,
        startedAt: evaluatedAt,
      });
      const evaluationReceipt = writeRecord({
        algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
        algorithmVersion: AGGREGATE_ALGORITHM_VERSION,
        authorityAfterDigest: requestedAuthorityDigest,
        componentSetDigest: COMPONENT_SET_DIGEST,
        evaluatedAt,
        evidenceSetDigest: bindings.evidenceSetDigest,
        executionReceiptDigest: executionReceipt.digest,
        publicationReceiptDigest: publicationReceipt.digest,
        resultState: 'passed',
        schema: 'aggregate-post-publication-evaluation-v1',
        sourceBindingDigest: bindings.sourceBindingDigest,
      });
      const aggregate = evaluateProof({
        authorityDigest: requestedAuthorityDigest,
        components,
        evaluatedAt,
        phase: 'post-publication',
        postPublicationReevaluation: { evaluationReceipt, executionReceipt, publicationReceipt },
        sourceBinding: aggregateSourceBinding,
        sourceRepositoryPath: repositoryPath,
      });
      if (aggregate.passed !== true || aggregate.selectable !== true
          || aggregate.proofCurrentness !== 'CURRENT') {
        fail('AGGREGATE_PRODUCER_INITIAL_REEVALUATION_INVALID', 'stage-1 aggregate reevaluation did not pass');
      }
      const preparation = deepFreeze({
        candidateDigest,
        evaluatedAuthorityDigest: requestedAuthorityDigest,
        evaluationReceiptDigest: evaluationReceipt.digest,
        executionReceiptDigest: executionReceipt.digest,
        ok: true,
        operation: 'produce_initial',
        protocol: 'semantic-proof-v1',
        state: 'REEVALUATION_CANDIDATE_PREPARED',
      });
      return assertInitialReevaluationPreparation(preparation);
    },

    async prepareFinalPackage(input) {
      return assembleStage2Package(casRoot, input);
    },

    async produceTerminal({ requestedAuthorityDigest, expectedStage1AuthorityDigest, stage1Preparation }) {
      digest(requestedAuthorityDigest, 'final authority digest');
      digest(expectedStage1AuthorityDigest, 'stage-1 authority digest');
      const preparation = assertInitialReevaluationPreparation(stage1Preparation);
      if (requestedAuthorityDigest === expectedStage1AuthorityDigest
          || preparation.evaluatedAuthorityDigest !== expectedStage1AuthorityDigest) {
        fail('AGGREGATE_PRODUCER_STAGE1_PREPARATION_INVALID', 'stage-1 reevaluation package bindings');
      }
      const terminalSourceBinding = await operationSourceBinding(dependencies);
      const stage1Receipts = validateStage1Receipts(
        casRoot, preparation, expectedStage1AuthorityDigest,
        aggregateCompilerProofInternals.sourceBindingDigest(terminalSourceBinding),
      );
      const { receipt: initialReceipt } = readSemanticProofReceiptBlob(
        casRoot, stage1Receipts.publicationReceiptDigest,
      );
      if (initialReceipt.authority_after_digest !== expectedStage1AuthorityDigest
          || initialReceipt.candidate_digest !== preparation.candidateDigest) {
        fail('AGGREGATE_PRODUCER_STAGE1_PREPARATION_INVALID', 'stage-1 publication receipt bindings');
      }
      const live = await stableAuthorityRead(dependencies, requestedAuthorityDigest, async () => {
        const [projection, selectionRows, receiptBindingRows, validationRows, observedAt] = await Promise.all([
          contractProjector(client, CONTRACT),
          client.select(CONTRACT_SELECTION_QUERY),
          client.select(AGGREGATE_LIVE_BINDINGS_QUERY),
          client.select(FINAL_VALIDATION_BINDINGS_QUERY),
          readTrustedTime(client),
        ]);
        return { observedAt, projection, receiptBindingRows, selectionRows, validationRows };
      });
      validateFinalValidationEvidence(casRoot, live.validationRows, expectedStage1AuthorityDigest);
      const selections = [...new Set(live.selectionRows.map((row) => binding(row, 'result')).filter(Boolean))];
      const liveResult = exactScalar(live.receiptBindingRows, 'result', aggregateResultIri);
      const liveEvaluatedAuthorityDigest = exactScalar(live.receiptBindingRows, 'evaluatedAuthorityDigest', aggregateResultIri);
      const liveExecutionReceiptDigest = exactScalar(live.receiptBindingRows, 'executionReceiptDigest', aggregateResultIri);
      const liveEvaluationReceiptDigest = exactScalar(live.receiptBindingRows, 'evaluationReceiptDigest', aggregateResultIri);
      if (selections.length !== 1 || selections[0] !== aggregateResultIri || liveResult !== aggregateResultIri
          || liveEvaluatedAuthorityDigest !== expectedStage1AuthorityDigest
          || liveExecutionReceiptDigest !== preparation.executionReceiptDigest
          || liveEvaluationReceiptDigest !== preparation.evaluationReceiptDigest
          || live.projection?.proofCurrentness?.proofResult !== aggregateResultIri
          || live.projection?.proofCurrentness?.state !== 'CURRENT'
          || live.projection?.actionState !== 'PROCEED') {
        fail('AGGREGATE_PRODUCER_TERMINAL_PROJECTION_INVALID', 'final authority did not preserve the stage-1 CURRENT/PROCEED aggregate');
      }
      return assertPostPublicationTerminalState(Object.freeze({
        actionState: 'PROCEED',
        authorityAfterDigest: requestedAuthorityDigest,
        currentProofResults: 1,
        evaluatedAuthorityDigest: expectedStage1AuthorityDigest,
        evaluationReceiptDigest: preparation.evaluationReceiptDigest,
        executionReceiptDigest: preparation.executionReceiptDigest,
        ok: true,
        operation: 'verify_reevaluation',
        proofCurrentness: 'CURRENT',
        selectedAggregateResult: aggregateResultIri,
      }));
    },
  });
}

export function createLiveAggregateCompilerProofDependencies({
  casRoot = '/var/lib/usf-cas',
  repositoryPath = resolve(dirname(fileURLToPath(import.meta.url)), '../..'),
  reachableFrom = DEFAULT_AGGREGATE_REACHABLE_REF,
  env = process.env,
} = {}) {
  const mutableClient = createClient(loadConfig(env));
  const client = Object.freeze({
    construct: (...args) => mutableClient.construct(...args),
    select: (...args) => mutableClient.select(...args),
  });
  return Object.freeze({
    casRoot,
    client,
    contractProjector: (readOnlyClient, contract) => projectContract({ client: readOnlyClient }, { contract }),
    readAuthorityWitness: authorityWitness,
    reachableFrom,
    repositoryPath,
  });
}

function argumentsFrom(argv) {
  const values = Object.fromEntries(argv.map((argument) => {
    const match = /^--([a-z-]+)=(.+)$/.exec(argument);
    if (!match) fail('AGGREGATE_PRODUCER_ARGUMENT_INVALID', argument);
    return [match[1], match[2]];
  }));
  return values;
}

export async function runAggregateCompilerProofCommand(argv = process.argv.slice(2), env = process.env) {
  const args = argumentsFrom(argv);
  const dependencies = createLiveAggregateCompilerProofDependencies({
    casRoot: args['cas-root'], env, reachableFrom: args['reachable-ref'], repositoryPath: args['repository-root'],
  });
  const producer = createAggregateCompilerProofProducer(dependencies);
  if (args.phase === 'pending') {
    return producer.preparePending({ requestedAuthorityDigest: args['authority-digest'] });
  }
  if (args.phase === 'initial') {
    const pendingPublicationReceipt = JSON.parse(readFileSync(args['pending-publication-receipt-path'], 'utf8'));
    return producer.produceInitial({
      candidateDigest: args['candidate-digest'], pendingPublicationReceipt,
      requestedAuthorityDigest: args['authority-digest'],
    });
  }
  if (args.phase === 'terminal') {
    const stage1Preparation = JSON.parse(readFileSync(args['stage1-preparation-path'], 'utf8'));
    return producer.produceTerminal({
      expectedStage1AuthorityDigest: args['expected-stage1-authority-digest'],
      requestedAuthorityDigest: args['authority-digest'], stage1Preparation,
    });
  }
  fail('AGGREGATE_PRODUCER_ARGUMENT_INVALID', 'phase must be pending, initial or terminal');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runAggregateCompilerProofCommand().then(
    (result) => process.stdout.write(`${canonicalJson(result)}\n`),
    (error) => { process.stderr.write(`${error.code || 'AGGREGATE_PRODUCER_FAILED'}: ${error.message}\n`); process.exitCode = 1; },
  );
}

export const aggregateCompilerProofCommandInternals = Object.freeze({
  normalizeFacts,
  readCasBytes,
  sourceBinding: gitSourceBinding,
  stableAuthorityRead,
  writeCanonicalRecord,
});
