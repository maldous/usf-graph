import { spawnSync } from 'node:child_process';
import {
  createHash, createPrivateKey, createPublicKey, randomUUID, sign, verify,
} from 'node:crypto';
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
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { Parser } from 'n3';
import { createGraphOwnershipObserver } from '../../processes/semantic-assurance/semantic-authority-mcp.mjs';
import { fileURLToPath } from 'node:url';

import { loadConfig } from '../../configuration/semantic-assurance/stardog-connection.mjs';
import { createClient } from '../../provider-bindings/stardog/stardog-read-gateway.mjs';
import { authorityWitness } from '../../processes/semantic-assurance/semantic-bootstrap-packet.mjs';
import { projectContract } from '../../processes/semantic-assurance/repository-materialisation-gateway.mjs';
import { createCasEvidenceStore } from '../../processes/semantic-assurance/semantic-authority-publication.mjs';
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
  SHARED_HERMETIC_EVIDENCE,
  SHARED_LIVE_AUTHORITY_EVIDENCE,
  aggregateCompilerProofInternals,
  evaluateAggregateCompilerProof,
} from './aggregate-compiler-proof.mjs';
import {
  materializeAggregateCompilerAuthorityCandidateV2,
} from './aggregate-compiler-authority-candidate.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const RFC3339_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/;
const CONTRACT = 'urn:usf:semanticcontract:compilersemanticenforcement';
const DEPENDENT_VALIDATION_CONTRACT = 'urn:usf:semanticcontract:providerconfigurationplane';
const DEPENDENT_VALIDATION_OBLIGATION = 'urn:usf:validationobligation:providerconfigurationplane';
const DEPENDENT_VALIDATION_RESULT = 'urn:usf:validationresult:factoryproviderv3implementation';
const DEPENDENT_VALIDATION_PRODUCER_REPOSITORY = 'maldous/usf-factory';
const DEPENDENT_VALIDATION_ADMISSION_REPOSITORY = 'maldous/usf-graph';
const CHECKPOINT_VALIDATION_CONTRACT = 'urn:usf:semanticcontract:backupandrestore';
const CHECKPOINT_VALIDATION_OBLIGATION =
  'urn:usf:validationobligation:backupandrestoreeventhistorycheckpointpruning';
const CHECKPOINT_VALIDATION_RESULT = 'urn:usf:validationresult:eventhistorycheckpointpruning';
const CHECKPOINT_VALIDATION_PRODUCER_REPOSITORY = 'maldous/usf-factory';
const CHECKPOINT_VALIDATION_ADMISSION_REPOSITORY = 'maldous/usf-graph';
const CHECKPOINT_PRODUCER_SOURCE_PATHS = Object.freeze([
  'src/usf_factory/cli.py',
  'src/usf_factory/event_store.py',
  'src/usf_factory/maintenance.py',
  'src/usf_factory/v3_events.py',
  'tests/test_v3_event_store.py',
  'tests/test_v3_maintenance.py',
]);
const DEPENDENT_PROOF_RESULTS = Object.freeze([
  'urn:usf:proofresult:factoryproviderv3implementation',
  'urn:usf:proofresult:providerworkforceauthorityproviderconfigurationplane',
]);
const DEPENDENT_PROOF_OBLIGATIONS = Object.freeze([
  'urn:usf:proofobligation:factoryproviderv3implementation',
  'urn:usf:proofobligation:p7515b7117898c8bf9cedd38642fd544b19bd241c7e53cf392161edda5065843f',
]);
export const AGGREGATE_RESULT_IRI = 'urn:usf:proofresult:compilersemanticenforcementaggregate';
export const PROVISIONAL_AGGREGATE_RESULT_IRI =
  'urn:usf:proofresult:compilersemanticenforcementaggregateprepublication';
export const DEFAULT_AGGREGATE_REACHABLE_REF = 'refs/remotes/origin/main';
export const AGGREGATE_REVIEWED_SOURCE_PATHS = Object.freeze([
  'assurance/permutation-closure/authority-capture-scope.json',
  'assurance/permutation-closure/foundation-domain-closure.test.mjs',
  'assurance/permutation-closure/foundation-gap-remediation.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-authority-candidate.test.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof-command.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof-command.test.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof.mjs',
  'assurance/semantic-model-compilation/aggregate-compiler-proof.test.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation-evidence.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation.test.mjs',
  'capabilities/repository-external-artefact-materialisation/generated-command-execution.test.mjs',
  'capabilities/semantic-model-compilation/authority-binding.mjs',
  'capabilities/semantic-model-compilation/compiler.mjs',
  'capabilities/semantic-model-compilation/programme-authority-binding.test.mjs',
  'operations/programme/update-checkpoint.mjs',
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
  'processes/semantic-assurance/semantic-proof-v2.mjs',
  'processes/semantic-assurance/semantic-proof-v2.test.mjs',
  'semantic-model/assurance/evidence.trig',
  'semantic-model/assurance/proofs.trig',
  'semantic-model/authority.ttl',
  'semantic-model/contracts/capabilities.trig',
  'semantic-model/contracts/materialisation.trig',
  'semantic-model/manifest.yaml',
  'semantic-model/ontology.ttl',
  'semantic-model/permutation/families.trig',
  'semantic-model/realisation/bindings.trig',
  'semantic-model/rules/evidence.rq',
  'semantic-model/shapes/assurance.ttl',
  'semantic-model/vocabulary.ttl',
]);

// A separate Factory subject from the Release/Signing V2 integration scope.
// This admits checkpoint/archive/hot-store machinery only and never authorizes
// a production pruning transaction.
export const EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS = Object.freeze([
  'src/usf_factory/cli.py',
  'src/usf_factory/event_store.py',
  'src/usf_factory/maintenance.py',
  'src/usf_factory/v3_events.py',
  'tests/test_v3_event_store.py',
  'tests/test_v3_maintenance.py',
]);
export const EVENT_HISTORY_CHECKPOINT_DEPENDENCY_PATHS = Object.freeze([
  'pyproject.toml',
  'requirements.lock',
  'scripts/admission-critical.sh',
  'scripts/verify-ci.sh',
  'scripts/verify.sh',
  'src/usf_factory/migrations.py',
  'src/usf_factory/sql_migrations/0001_event_authority_and_projections.sql',
  'src/usf_factory/sql_migrations/0002_provider_programme_and_execution.sql',
  'src/usf_factory/sql_migrations/0003_cas_retention_and_backups.sql',
  'src/usf_factory/sql_migrations/0004_provider_refresh_epochs.sql',
  'src/usf_factory/sql_migrations/0005_execution_routing_claim_identity.sql',
]);

const AUTHORITY_SOURCE_PATH = 'semantic-model/authority.ttl';
// A component evidence window that has closed cannot be repaired by publishing,
// because the warrant read that refuses it is a PRE-publication read of live
// authority: preparePending -> readFacts -> stableAuthorityRead asserts the live
// witness equals the pre-publication digest and then queries that authority, so
// a refreshed record in the candidate is only visible to the post-publication
// read in produceInitial. Expiry was therefore an unrecoverable liveness trap.
// The renewal path below closes it without weakening anything: it accepts only a
// record the signed candidate itself asserts for the same evidence identity, and
// verifies strictly more about it than the live-record path verifies. This source
// path is already inside AGGREGATE_REVIEWED_SOURCE_PATHS, so the renewal
// introduces no new input, no new trust source and no producer bypass.
const EVIDENCE_SOURCE_PATH = 'semantic-model/assurance/evidence.trig';
// Exactly the component evidence identities the compiler proof itself produces.
// Nothing else is renewable, so the renewal path can never reach an evidence
// identity the compiler proof cannot re-produce.
const RENEWABLE_COMPONENT_EVIDENCE = Object.freeze([...new Set(
  [...SHARED_HERMETIC_EVIDENCE, ...SHARED_LIVE_AUTHORITY_EVIDENCE].map(({ iri }) => iri),
)].sort());
const ONTOLOGY = 'urn:usf:ontology:';
const RENEWAL_PREDICATES = Object.freeze({
  [`${ONTOLOGY}contentDigest`]: 'contentDigest',
  [`${ONTOLOGY}collectedAt`]: 'collectedAt',
  [`${ONTOLOGY}validUntil`]: 'validUntil',
  [`${ONTOLOGY}hasAdmissionState`]: 'admissionState',
  [`${ONTOLOGY}hasFreshness`]: 'freshness',
  [`${ONTOLOGY}hasFreshnessState`]: 'freshnessState',
  [`${ONTOLOGY}hasIntegrityState`]: 'integrityState',
  [`${ONTOLOGY}withinValidityScope`]: 'withinValidityScope',
});
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
       ?integrityState ?evidenceStage ?withinValidityScope ?validFrom ?validUntil ?collectedAt
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
  OPTIONAL { ?evidence <urn:usf:ontology:collectedAt> ?collectedAt }
  OPTIONAL { ?result <urn:usf:ontology:invalidatedAt> ?invalidatedAt }
  OPTIONAL { ?result <urn:usf:ontology:supersededBy> ?supersededBy }
}
ORDER BY ?result ?evidence ?invalidatedAt ?supersededBy`;

export const COMPONENT_FACT_COUNT_QUERY = `# aggregate-component-fact-count-v1
SELECT (COUNT(*) AS ?count) WHERE { { ${COMPONENT_FACTS_QUERY.slice(COMPONENT_FACTS_QUERY.indexOf('WHERE {') + 7, COMPONENT_FACTS_QUERY.lastIndexOf('}\nORDER BY'))} } }`;

export const DEPENDENT_VALIDATION_FACTS_QUERY = `# aggregate-dependent-validation-facts-v1
SELECT ?result ?obligation ?resultState ?resultAuthorityDigest ?resultSourceHead
       ?evaluation ?evaluationReceiptDigest ?execution ?executionReceiptDigest
       ?producer ?producerRelease ?producerRepository ?producerSourceHead ?producerSourceTree
       ?producerSourceScopeDigest ?producerSourcePath
       ?admissionPath ?admissionProducer ?admissionRepository ?admissionSourceHead ?admissionSourceTree
       ?admissionSourceScopeDigest ?admissionSourcePath ?validationEvidence WHERE {
  BIND(<${DEPENDENT_VALIDATION_RESULT}> AS ?result)
  BIND(<${DEPENDENT_VALIDATION_OBLIGATION}> AS ?obligation)
  ?obligation a <urn:usf:ontology:ValidationObligation> ;
              <urn:usf:ontology:validationForContract> <${DEPENDENT_VALIDATION_CONTRACT}> ;
              <urn:usf:ontology:satisfiedByValidationResult> ?result .
  ?result <urn:usf:ontology:resultForValidationObligation> ?obligation ;
          <urn:usf:ontology:resultState> ?resultState ;
          <urn:usf:ontology:validationEvaluatedAuthorityDigest> ?resultAuthorityDigest ;
          <urn:usf:ontology:validationEvaluatedSourceHead> ?resultSourceHead ;
          <urn:usf:ontology:validationResultOfEvaluation> ?evaluation .
  ?evaluation a <urn:usf:ontology:ValidationEvaluation> ;
              <urn:usf:ontology:validationEvaluationOfExecution> ?execution ;
              <urn:usf:ontology:validationEvaluationReceiptDigest> ?evaluationReceiptDigest .
  ?execution a <urn:usf:ontology:ValidationExecution> ;
             <urn:usf:ontology:executesValidation> ?obligation ;
             <urn:usf:ontology:producesValidationResult> ?result ;
             <urn:usf:ontology:validationExecutionReceiptDigest> ?executionReceiptDigest ;
             <urn:usf:ontology:validationExecutedByProducer> ?producer ;
             <urn:usf:ontology:validationUsesEvidenceAdmissionPath> ?admissionPath .
  ?validationEvidence a <urn:usf:ontology:ValidationEvidence> ;
                      <urn:usf:ontology:validationEvidenceForExecution> ?execution ;
                      <urn:usf:ontology:validationEvidenceAdmittedThrough> ?admissionPath .
  ?producer a <urn:usf:ontology:ValidationProducer> ;
            <urn:usf:ontology:validationProducerRelease> ?producerRelease ;
            <urn:usf:ontology:validationProducerRepository> ?producerRepository ;
            <urn:usf:ontology:validationProducerSourceHead> ?producerSourceHead ;
            <urn:usf:ontology:validationProducerSourceTree> ?producerSourceTree ;
            <urn:usf:ontology:validationProducerSourceScopeDigest> ?producerSourceScopeDigest ;
            <urn:usf:ontology:validationProducerSourcePath> ?producerSourcePath .
  ?admissionPath a <urn:usf:ontology:EvidenceAdmissionPath> ;
                 <urn:usf:ontology:admissionPathForProducer> ?admissionProducer ;
                 <urn:usf:ontology:admissionPathRepository> ?admissionRepository ;
                 <urn:usf:ontology:admissionPathSourceHead> ?admissionSourceHead ;
                 <urn:usf:ontology:admissionPathSourceTree> ?admissionSourceTree ;
                 <urn:usf:ontology:admissionPathSourceScopeDigest> ?admissionSourceScopeDigest ;
                 <urn:usf:ontology:admissionPathSourcePath> ?admissionSourcePath .
}
ORDER BY ?producerSourcePath ?admissionSourcePath ?validationEvidence`;

export const CHECKPOINT_VALIDATION_FACTS_QUERY = DEPENDENT_VALIDATION_FACTS_QUERY
  .replace('aggregate-dependent-validation-facts-v1', 'aggregate-checkpoint-validation-facts-v1')
  .replace(DEPENDENT_VALIDATION_RESULT, CHECKPOINT_VALIDATION_RESULT)
  .replace(DEPENDENT_VALIDATION_OBLIGATION, CHECKPOINT_VALIDATION_OBLIGATION)
  .replace(DEPENDENT_VALIDATION_CONTRACT, CHECKPOINT_VALIDATION_CONTRACT);

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
       ?bindingEvaluationReceiptDigest ?stageOneSettledAuthorityDigest ?reevaluationState
       ?producer ?admissionPath ?validationEvidence ?validationEvidenceDigest
       ?compilerValidationEvidence ?compilerValidationEvidenceDigest WHERE {
  ?obligation a <urn:usf:ontology:ValidationObligation> ;
              <urn:usf:ontology:validationForContract> <${CONTRACT}> ;
              <urn:usf:ontology:satisfiedByValidationResult> ?validationResult .
  ?validationResult <urn:usf:ontology:resultState> ?resultState ;
                    <urn:usf:ontology:validationResultOfEvaluation> ?validationEvaluation ;
                    <urn:usf:ontology:hasValidationSelfPublicationAuthorityBinding> ?binding ;
                    <urn:usf:ontology:entersEvidenceLifecycleAs> ?compilerValidationEvidence ;
                    <urn:usf:ontology:usesAdmittedValidationEvidence> ?validationEvidence .
  ?validationEvaluation <urn:usf:ontology:validationEvaluationOfExecution> ?validationExecution ;
                        <urn:usf:ontology:validationEvaluationReceiptDigest> ?evaluationReceiptDigest .
  ?validationExecution <urn:usf:ontology:validationExecutionReceiptDigest> ?executionReceiptDigest ;
                       <urn:usf:ontology:validationExecutedByProducer> ?producer ;
                       <urn:usf:ontology:validationUsesEvidenceAdmissionPath> ?admissionPath .
  ?validationEvidence a <urn:usf:ontology:EvidenceResult> ;
                      <urn:usf:ontology:contentDigest> ?validationEvidenceDigest .
  ?compilerValidationEvidence a <urn:usf:ontology:ValidationEvidence> ;
                              <urn:usf:ontology:validationEvidenceForExecution> ?validationExecution ;
                              <urn:usf:ontology:validationEvidenceAdmittedThrough> ?admissionPath ;
                              <urn:usf:ontology:contentDigest> ?compilerValidationEvidenceDigest .
  FILTER (?validationEvidence != ?compilerValidationEvidence)
  ?binding <urn:usf:ontology:validationBindingExecutionReceiptDigest> ?bindingExecutionReceiptDigest ;
           <urn:usf:ontology:validationBindingEvaluationReceiptDigest> ?bindingEvaluationReceiptDigest ;
           <urn:usf:ontology:validationStageOneSettledAuthorityDigest> ?stageOneSettledAuthorityDigest ;
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

export function eventHistoryCheckpointImplementationScopeDigest(
  paths = EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS,
) {
  const actual = [...paths].sort();
  if (new Set(actual).size !== EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS.length
      || canonicalJson(actual) !== canonicalJson(EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS)) {
    fail('EVENT_HISTORY_CHECKPOINT_SOURCE_SCOPE_NOT_EXACT', actual.join(','));
  }
  return aggregateCompilerProofInternals.sourceScopeDigest(actual);
}

export function assertEventHistoryCheckpointWorktreeBinding(input) {
  const expectedKeys = [
    'candidateCommit', 'candidateTree', 'expectedTree', 'protectedCommit', 'protectedTree',
    'status', 'worktreeHead',
  ];
  if (canonicalJson(Object.keys(input || {}).sort()) !== canonicalJson(expectedKeys)) {
    fail('EVENT_HISTORY_CHECKPOINT_SOURCE_BINDING_NOT_CLOSED', Object.keys(input || {}).sort().join(','));
  }
  for (const [name, value] of Object.entries(input).filter(([name]) => name !== 'status')) {
    if (!GIT_OBJECT.test(value || '')) {
      fail('EVENT_HISTORY_CHECKPOINT_SOURCE_IDENTITY_INVALID', name);
    }
  }
  // Execute the owner/service gate from the exact owner-signed candidate.  A
  // protected merge commit may lawfully preserve the reviewed tree while
  // carrying only GitHub provenance; binding the runtime to that commit would
  // make Factory's owner-signature checks attest the wrong source identity.
  if (input.worktreeHead !== input.candidateCommit) {
    fail('EVENT_HISTORY_CHECKPOINT_FACTORY_WORKTREE_HEAD_MISMATCH', input.worktreeHead);
  }
  if (input.candidateTree !== input.expectedTree || input.protectedTree !== input.expectedTree) {
    fail(
      'EVENT_HISTORY_CHECKPOINT_FACTORY_TREE_IDENTITY_MISMATCH',
      `${input.candidateTree}/${input.protectedTree}`,
    );
  }
  if (input.status !== '') fail('EVENT_HISTORY_CHECKPOINT_FACTORY_WORKTREE_NOT_CLEAN', input.status);
  return true;
}

export function eventHistoryCheckpointPythonPath(factoryRepository, value) {
  const expected = join(factoryRepository, '.venv', 'bin', 'python');
  if (!isAbsolute(value || '') || resolve(value) !== expected) {
    fail('EVENT_HISTORY_CHECKPOINT_PYTHON_SOURCE_MISMATCH', value || 'absent');
  }
  return expected;
}

export function eventHistoryCheckpointGpgHome(env = process.env) {
  const value = env.GNUPGHOME || (env.HOME ? join(env.HOME, '.gnupg') : '');
  if (!isAbsolute(value)) {
    fail('EVENT_HISTORY_CHECKPOINT_GPG_HOME_INVALID', value || 'absent');
  }
  let info;
  try {
    info = lstatSync(value);
  } catch {
    fail('EVENT_HISTORY_CHECKPOINT_GPG_HOME_INVALID', 'missing');
  }
  if (info.isSymbolicLink() || !info.isDirectory()) {
    fail('EVENT_HISTORY_CHECKPOINT_GPG_HOME_INVALID', 'type');
  }
  return realpathSync(value);
}

export function eventHistoryCheckpointFactoryEnvironment(factoryRepository, python, env = process.env) {
  const exactPython = eventHistoryCheckpointPythonPath(factoryRepository, python);
  const nodeDirectory = dirname(realpathSync(process.execPath));
  return Object.freeze({
    ...env,
    PATH: `${dirname(exactPython)}:${nodeDirectory}:/usr/bin:/bin`,
    PYTHONPATH: join(factoryRepository, 'src'),
    TZ: 'UTC',
  });
}

export function eventHistoryCheckpointEvidenceCore(input) {
  const expectedKeys = [
    'authorityDigest', 'candidateCommit', 'commands', 'dependencyRecords', 'evaluatedAt',
    'factoryTree', 'implementationRecords', 'proofAlgorithmSourceDigest', 'protectedCommit',
    'validUntil',
  ];
  const actualKeys = Object.keys(input || {}).sort();
  if (canonicalJson(actualKeys) !== canonicalJson(expectedKeys)) {
    fail('EVENT_HISTORY_CHECKPOINT_EVIDENCE_INPUT_NOT_CLOSED', actualKeys.join(','));
  }
  if (!SHA256.test(input.authorityDigest || '')
      || !SHA256.test(input.proofAlgorithmSourceDigest || '')
      || !GIT_OBJECT.test(input.candidateCommit || '')
      || !GIT_OBJECT.test(input.protectedCommit || '')
      || !GIT_OBJECT.test(input.factoryTree || '')
      || !RFC3339_SECOND.test(input.evaluatedAt || '')
      || !RFC3339_SECOND.test(input.validUntil || '')
      || Date.parse(input.validUntil) <= Date.parse(input.evaluatedAt)) {
    fail('EVENT_HISTORY_CHECKPOINT_EVIDENCE_IDENTITY_INVALID', 'digest, source or time');
  }
  const validateRecords = (records, paths, label) => {
    if (!Array.isArray(records)
        || canonicalJson(records.map(({ path }) => path)) !== canonicalJson(paths)) {
      fail('EVENT_HISTORY_CHECKPOINT_EVIDENCE_SOURCE_SET_INVALID', label);
    }
    for (const record of records) {
      if (canonicalJson(Object.keys(record).sort()) !== canonicalJson(['byteSize', 'digest', 'path'])
          || !paths.includes(record.path) || !SHA256.test(record.digest || '')
          || !Number.isSafeInteger(record.byteSize) || record.byteSize < 1) {
        fail('EVENT_HISTORY_CHECKPOINT_EVIDENCE_SOURCE_SET_INVALID', `${label}:${record.path || ''}`);
      }
    }
  };
  validateRecords(input.implementationRecords, EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS, 'implementation');
  validateRecords(input.dependencyRecords, EVENT_HISTORY_CHECKPOINT_DEPENDENCY_PATHS, 'dependency');
  const requiredValidationCommands = new Set([
    'focused-checkpoint-pruning', 'admission-critical', 'complete-owner-service-gate',
  ]);
  if (!Array.isArray(input.commands) || input.commands.length === 0) {
    fail('EVENT_HISTORY_CHECKPOINT_EVIDENCE_COMMAND_SET_INVALID', 'absent');
  }
  const commandIds = new Set();
  for (const command of input.commands) {
    if (canonicalJson(Object.keys(command || {}).sort())
          !== canonicalJson(['arguments', 'executable', 'exitStatus', 'id', 'signal', 'stderrDigest', 'stdoutDigest'])
        || typeof command.id !== 'string' || !/^[a-z0-9-]+$/u.test(command.id)
        || commandIds.has(command.id) || !isAbsolute(command.executable || '')
        || !Array.isArray(command.arguments) || command.arguments.some((value) => typeof value !== 'string')
        || !(command.exitStatus === null || Number.isSafeInteger(command.exitStatus))
        || !(command.signal === null || typeof command.signal === 'string')
        || !SHA256.test(command.stdoutDigest || '') || !SHA256.test(command.stderrDigest || '')) {
      fail('EVENT_HISTORY_CHECKPOINT_EVIDENCE_COMMAND_SET_INVALID', command?.id || 'record');
    }
    commandIds.add(command.id);
  }
  if ([...requiredValidationCommands].some((id) => !commandIds.has(id))) {
    fail('EVENT_HISTORY_CHECKPOINT_EVIDENCE_COMMAND_SET_INVALID', 'required validation command');
  }
  const passed = input.commands.every(({ exitStatus }) => exitStatus === 0);
  return Object.freeze({
    schemaVersion: 1,
    recordKind: 'USF_FACTORY_EVENT_HISTORY_CHECKPOINT_PRUNING_EVIDENCE_CANDIDATE',
    passed,
    eligibleForAdmission: passed,
    evaluatedAt: input.evaluatedAt,
    validUntil: input.validUntil,
    evaluatedAuthorityDigest: input.authorityDigest,
    factoryCandidateCommit: input.candidateCommit,
    factoryProtectedCommit: input.protectedCommit,
    factoryTree: input.factoryTree,
    sourceScopeDigest: eventHistoryCheckpointImplementationScopeDigest(),
    implementationSourceSetDigest: sha256Bytes(Buffer.from(canonicalJson(input.implementationRecords))),
    implementationSources: input.implementationRecords,
    dependencySetDigest: sha256Bytes(Buffer.from(canonicalJson(input.dependencyRecords))),
    dependencies: input.dependencyRecords,
    proofAlgorithmSourceDigest: input.proofAlgorithmSourceDigest,
    environmentClass: 'urn:usf:environmentclass:hermetic',
    providerMode: 'urn:usf:providermode:deterministictestsubstitute',
    commands: input.commands,
    authorityClaims: [
      'event verification is ordered and bounded-memory',
      'authority bindings are resolved from one immutable timeline',
      'stream heads are resolved by one bounded scan',
      'signed cold archives preserve exact canonical event bytes and order',
      'authenticated checkpoints bind frontier history, projections, CAS, schema, migrations, and sources',
      'checkpoint plus verified tail projection replay equals the current authenticated state',
      'archive plus tail restore preserves full genesis verification',
      'hot-store installation is journaled, fork-rejecting, and same-device preflighted before mutation',
      'tail-event and post-checkpoint projection corruption fail closed',
    ],
    nonclaims: [
      'This evidence admits machinery only and does not authorize production pruning.',
      'No live Factory database, Graph authority, CAS object, checkpoint, archive, or projection was mutated by this proof.',
      'No provider was contacted and no provider output or usage evidence was created.',
      'V2 remains inactive and no V2 grant or publication is issued by this proof.',
      'BAU, P2, live checkpoint equivalence, live backup, and live restore remain separate operational obligations.',
    ],
    productionWrites: 0,
    providerContacts: 0,
  });
}

function eventHistoryCheckpointCommand(commandLog, outputRoot, id, executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
    timeout: options.timeout ?? 900_000,
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
  commandLog.push(Object.freeze({
    id, executable, arguments: [...args],
    exitStatus: Number.isInteger(result.status) ? result.status : null,
    signal: result.signal || null,
    stdoutDigest: sha256Bytes(stdout), stderrDigest: sha256Bytes(stderr),
  }));
  const directory = join(outputRoot, 'commands');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(join(directory, `${id}.stdout`), stdout, { mode: 0o600 });
  writeFileSync(join(directory, `${id}.stderr`), stderr, { mode: 0o600 });
  if (result.error || result.signal || result.status !== 0) {
    fail('EVENT_HISTORY_CHECKPOINT_COMMAND_FAILED', id);
  }
  return stdout;
}

function eventHistoryCheckpointSigningKey(path) {
  if (!isAbsolute(path)) fail('EVENT_HISTORY_CHECKPOINT_SIGNING_KEY_INVALID', 'path');
  const info = lstatSync(path);
  if (info.isSymbolicLink() || !info.isFile() || (info.mode & 0o777) !== 0o600) {
    fail('EVENT_HISTORY_CHECKPOINT_SIGNING_KEY_INVALID', 'type or mode');
  }
  const key = createPrivateKey({ key: readFileSync(path), format: 'der', type: 'pkcs8' });
  if (key.asymmetricKeyType !== 'ed25519') {
    fail('EVENT_HISTORY_CHECKPOINT_SIGNING_KEY_INVALID', 'algorithm');
  }
  return key;
}

export function runEventHistoryCheckpointEvidence(args, env = process.env) {
  const required = [
    'authority-digest', 'candidate-commit', 'cas-root', 'evaluated-at', 'factory-repository',
    'factory-tree', 'output-root', 'protected-commit', 'python', 'signing-key', 'valid-until',
  ];
  if (canonicalJson(Object.keys(args).sort()) !== canonicalJson(required)) {
    fail('EVENT_HISTORY_CHECKPOINT_ARGUMENTS_INVALID', Object.keys(args).sort().join(','));
  }
  const root = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
  const factoryRepository = realpathSync(args['factory-repository']);
  if (lstatSync(args['factory-repository']).isSymbolicLink()
      || !lstatSync(factoryRepository).isDirectory()) {
    fail('EVENT_HISTORY_CHECKPOINT_FACTORY_REPOSITORY_INVALID', args['factory-repository']);
  }
  const python = eventHistoryCheckpointPythonPath(factoryRepository, args.python);
  if (!existsSync(python)) fail('EVENT_HISTORY_CHECKPOINT_PYTHON_SOURCE_MISMATCH', 'missing');
  const casRoot = canonicalCasRoot(args['cas-root']);
  const outputRoot = resolve(args['output-root']);
  const sessionRoot = resolve(root, '.work');
  if (!outputRoot.startsWith(`${sessionRoot}${sep}`) || outputRoot === sessionRoot) {
    fail('EVENT_HISTORY_CHECKPOINT_OUTPUT_ROOT_INVALID', outputRoot);
  }
  rmSync(outputRoot, { recursive: true, force: true });
  mkdirSync(outputRoot, { recursive: true, mode: 0o700 });
  const authorityDigest = digest(args['authority-digest'], 'event-history authority');
  const privateKey = eventHistoryCheckpointSigningKey(args['signing-key']);
  const publicKey = createPublicKey(privateKey);
  const evidenceStore = createCasEvidenceStore(casRoot);
  const candidateCommit = args['candidate-commit'];
  const protectedCommit = args['protected-commit'];
  const expectedTree = args['factory-tree'];
  if (!GIT_OBJECT.test(candidateCommit) || !GIT_OBJECT.test(protectedCommit)
      || !GIT_OBJECT.test(expectedTree)) {
    fail('EVENT_HISTORY_CHECKPOINT_SOURCE_IDENTITY_INVALID', 'commit or tree');
  }
  const evaluatedAt = timestamp(args['evaluated-at'], 'event-history evaluated-at');
  const validUntil = timestamp(args['valid-until'], 'event-history valid-until');
  if (Date.parse(validUntil) <= Date.parse(evaluatedAt)) {
    fail('EVENT_HISTORY_CHECKPOINT_TIME_INVALID', 'valid-until');
  }
  const commands = [];
  const runGit = (id, gitArgs) => eventHistoryCheckpointCommand(
    commands, outputRoot, id, '/usr/bin/git', gitArgs, { cwd: factoryRepository },
  );
  runGit('candidate-signature', ['verify-commit', candidateCommit]);
  runGit('protected-signature', ['verify-commit', protectedCommit]);
  runGit('candidate-ancestry', ['merge-base', '--is-ancestor', candidateCommit, protectedCommit]);
  const worktreeHead = runGit('factory-worktree-head', ['rev-parse', 'HEAD']).toString().trim();
  const candidateTree = runGit('candidate-tree', ['rev-parse', `${candidateCommit}^{tree}`]).toString().trim();
  const protectedTree = runGit('protected-tree', ['rev-parse', `${protectedCommit}^{tree}`]).toString().trim();
  runGit('reviewed-tree-preserved', ['diff', '--exit-code', `${candidateCommit}^{tree}`, `${protectedCommit}^{tree}`]);
  const status = runGit('factory-worktree-status', ['status', '--porcelain=v1', '--untracked-files=all']).toString();
  assertEventHistoryCheckpointWorktreeBinding({
    candidateCommit, candidateTree, expectedTree, protectedCommit, protectedTree, status, worktreeHead,
  });
  const records = (paths) => paths.map((path) => {
    const bytes = runGit(`source-${sha256Bytes(Buffer.from(path)).slice(7, 19)}`, ['show', `${protectedCommit}:${path}`]);
    return Object.freeze({ path, digest: sha256Bytes(bytes), byteSize: bytes.length });
  });
  const implementationRecords = records(EVENT_HISTORY_CHECKPOINT_IMPLEMENTATION_PATHS);
  const dependencyRecords = records(EVENT_HISTORY_CHECKPOINT_DEPENDENCY_PATHS);
  const sourceBoundEnvironment = eventHistoryCheckpointFactoryEnvironment(
    factoryRepository, python, env,
  );
  const hermeticEnvironment = Object.freeze({
    GNUPGHOME: eventHistoryCheckpointGpgHome(env), HOME: '/nonexistent',
    LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PATH: '/usr/bin:/bin',
    PYTHONPATH: join(factoryRepository, 'src'), TZ: 'UTC',
  });
  eventHistoryCheckpointCommand(commands, outputRoot, 'focused-checkpoint-pruning', python,
    ['-m', 'pytest', '-q', 'tests/test_v3_event_store.py', 'tests/test_v3_maintenance.py'],
    { cwd: factoryRepository, env: hermeticEnvironment, timeout: 900_000 });
  eventHistoryCheckpointCommand(commands, outputRoot, 'admission-critical', '/usr/bin/bash',
    ['scripts/admission-critical.sh'],
    { cwd: factoryRepository, env: sourceBoundEnvironment, timeout: 900_000 });
  eventHistoryCheckpointCommand(commands, outputRoot, 'complete-owner-service-gate', '/usr/bin/bash',
    ['scripts/verify.sh', '--fresh', '--attest'],
    { cwd: factoryRepository, env: sourceBoundEnvironment, timeout: 1_800_000 });
  const proofAlgorithmSourceDigest = sha256Bytes(readFileSync(fileURLToPath(import.meta.url)));
  const core = eventHistoryCheckpointEvidenceCore({
    authorityDigest, candidateCommit, commands, dependencyRecords, evaluatedAt, factoryTree: expectedTree,
    implementationRecords, proofAlgorithmSourceDigest, protectedCommit, validUntil,
  });
  const exactEvidenceSetDigest = sha256Bytes(Buffer.from(canonicalJson(core)));
  const evidence = Object.freeze({ ...core, exactEvidenceSetDigest });
  const evidenceRecord = evidenceStore.persist(Buffer.from(canonicalJson(evidence)));
  const statement = Object.freeze({
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'factory-event-history-checkpoint-pruning-evidence', digest: { sha256: evidenceRecord.digest.slice(7) } }],
    predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
    predicate: {
      evaluatedAuthorityDigest: authorityDigest, exactEvidenceSetDigest,
      implementationSourceSetDigest: core.implementationSourceSetDigest,
      dependencySetDigest: core.dependencySetDigest, proofAlgorithmSourceDigest, result: 'passed',
    },
  });
  const payloadType = 'application/vnd.in-toto+json';
  const statementBytes = Buffer.from(canonicalJson(statement));
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `), statementBytes,
  ]);
  const signature = sign(null, pae, privateKey);
  if (!verify(null, pae, publicKey, signature)) {
    fail('EVENT_HISTORY_CHECKPOINT_ATTESTATION_SIGNATURE_FAILED', 'self-verification');
  }
  const signingKeyFingerprint = sha256Bytes(publicKey.export({ type: 'spki', format: 'der' }));
  const envelope = Object.freeze({
    payloadType, payload: statementBytes.toString('base64'),
    signatures: [{ keyid: signingKeyFingerprint.slice(7), sig: signature.toString('base64') }],
  });
  const attestationRecord = evidenceStore.persist(Buffer.from(canonicalJson(envelope)));
  writeFileSync(join(outputRoot, 'evidence-manifest.json'), Buffer.from(canonicalJson(evidence)), { mode: 0o600 });
  writeFileSync(join(outputRoot, 'proof-attestation.dsse.json'), Buffer.from(canonicalJson(envelope)), { mode: 0o600 });
  return Object.freeze({
    schemaVersion: 1, recordKind: 'USF_FACTORY_EVENT_HISTORY_CHECKPOINT_PRUNING_EVIDENCE_RECEIPT',
    ok: true, eligibleForAdmission: true, evaluatedAuthorityDigest: authorityDigest,
    evaluatedAt, validUntil, factoryCandidateCommit: candidateCommit, factoryProtectedCommit: protectedCommit,
    factoryTree: expectedTree, sourceScopeDigest: core.sourceScopeDigest,
    implementationSourceSetDigest: core.implementationSourceSetDigest,
    dependencySetDigest: core.dependencySetDigest, proofAlgorithmSourceDigest, exactEvidenceSetDigest,
    evidenceManifest: {
      digest: evidenceRecord.digest, byteSize: evidenceRecord.size,
      mediaType: 'application/json', locator: `cas://sha256/${evidenceRecord.digest.slice(7)}`,
    },
    proofAttestation: {
      digest: attestationRecord.digest, byteSize: attestationRecord.size,
      mediaType: payloadType, locator: `cas://sha256/${attestationRecord.digest.slice(7)}`,
    },
    signingKeyFingerprint, productionWrites: 0, providerContacts: 0, outputRoot,
  });
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

/**
 * Read the evidence records the signed candidate asserts, for the exact evidence
 * identities whose live window may have closed. Parsed from the authored TriG at
 * the resolved source head, never from the working tree, so a renewal can only
 * come from reviewed, signed bytes.
 */
export function parseCandidateEvidenceRecords(sourceText, iris) {
  // Never throws. A renewal is an optional repair path, so anything that makes it
  // unusable — absent, unparsable, or a non-single-valued assertion — must leave
  // the caller with the historical AGGREGATE_COMPONENT_STALE verdict rather than
  // introduce a new observable outcome.
  if (typeof sourceText !== 'string' || sourceText.length === 0) return null;
  const wanted = new Set(iris);
  let quads;
  try {
    quads = new Parser({ format: 'application/trig' }).parse(sourceText);
  } catch {
    return null;
  }
  const records = new Map();
  const rejected = new Set();
  for (const quad of quads) {
    if (!wanted.has(quad.subject.value)) continue;
    const field = RENEWAL_PREDICATES[quad.predicate.value];
    if (!field) continue;
    const record = records.get(quad.subject.value) || {};
    if (Object.hasOwn(record, field) && record[field] !== quad.object.value) {
      rejected.add(quad.subject.value);
      continue;
    }
    record[field] = quad.object.value;
    records.set(quad.subject.value, record);
  }
  for (const iri of rejected) records.delete(iri);
  return records;
}

/**
 * Accept a renewal for one component evidence identity whose live window has
 * closed. Every condition is independently established; any shortfall fails
 * closed as AGGREGATE_COMPONENT_STALE, so behaviour with no renewal present is
 * exactly the historical behaviour.
 */
function acceptComponentEvidenceRenewal({
  iri, renewalSource, casRoot, evaluatedAt, liveValidUntil, liveCollectedAt, authorityDigest, batch,
}) {
  const stale = () => fail('AGGREGATE_COMPONENT_STALE', iri);
  // Local, non-throwing validators: every shortfall on the renewal path must
  // surface as AGGREGATE_COMPONENT_STALE, never as a different code, so a
  // malformed renewal is observationally identical to no renewal at all.
  const asDigest = (value) => (SHA256.test(value || '') ? value : stale());
  const asTime = (value) => (RFC3339_SECOND.test(value || '') && Number.isFinite(Date.parse(value))
    ? value : stale());
  if (!renewalSource) stale();
  // Parsed lazily and once: when no component window has closed the candidate
  // evidence source is never parsed at all, so the non-renewal path is
  // bit-for-bit the historical path.
  if (batch.records === undefined) {
    batch.records = parseCandidateEvidenceRecords(renewalSource.text, RENEWABLE_COMPONENT_EVIDENCE);
  }
  const candidate = batch.records === null ? undefined : batch.records.get(iri);
  if (!candidate) stale();
  // The renewal must present the same admitted, fresh, integral, in-scope state
  // the live-record path requires. A renewal may not relax any of them.
  if (candidate.admissionState !== 'urn:usf:evidenceadmissionstate:admitted'
      || candidate.freshness !== 'urn:usf:freshness:fresh'
      || candidate.freshnessState !== 'urn:usf:evidencefreshnessstate:fresh'
      || candidate.integrityState !== 'urn:usf:evidenceintegritystate:valid'
      || candidate.withinValidityScope !== 'true') {
    stale();
  }
  // Windows: open now, strictly newer than the record it renews, not
  // future-dated, and never longer than the window it replaces. The live
  // collectedAt is required, so a record with no measurable window cannot be
  // silently widened.
  const collectedAt = asTime(candidate.collectedAt);
  const validUntil = asTime(candidate.validUntil);
  if (liveCollectedAt === null) stale();
  const renewedWindow = Date.parse(validUntil) - Date.parse(collectedAt);
  const priorWindow = Date.parse(liveValidUntil) - Date.parse(liveCollectedAt);
  if (Date.parse(validUntil) <= Date.parse(evaluatedAt)
      || Date.parse(validUntil) <= Date.parse(liveValidUntil)
      || Date.parse(collectedAt) <= Date.parse(liveCollectedAt)
      || Date.parse(collectedAt) > Date.parse(evaluatedAt)
      || !(renewedWindow > 0) || renewedWindow > priorWindow) {
    stale();
  }
  // Identity: the asserted digest must name bytes that exist in CAS and hash to
  // it (readCasBytes enforces both), and those bytes must be a self-consistent
  // evidence manifest whose embedded evidenceDigest is the digest of the rest.
  const contentDigest = asDigest(candidate.contentDigest);
  if (contentDigest === ORPHANED_ATTESTATION_DIGEST) fail('AGGREGATE_ORPHAN_EVIDENCE_REJECTED', iri);
  // Any failure to establish the renewal bytes is a stale component, never a new
  // observable code: the renewal path must be indistinguishable from no renewal
  // whenever it does not fully verify. The orphan guard is deliberate and is the
  // same rejection the live-record path raises for that digest.
  let bytes;
  try {
    bytes = readCasBytes(casRoot, contentDigest);
  } catch (error) {
    if (error?.code === 'AGGREGATE_ORPHAN_EVIDENCE_REJECTED') throw error;
    stale();
  }
  let payload;
  try {
    payload = JSON.parse(bytes.toString('utf8'));
  } catch {
    stale();
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) stale();
  const { evidenceDigest: embedded, ...core } = payload;
  if (!SHA256.test(embedded || '')
      || sha256Bytes(Buffer.from(canonicalJson(core), 'utf8')) !== embedded) {
    stale();
  }
  // Provenance: the re-run must have been evaluated against the exact
  // pre-publication authority this operation is evaluating, must post-date the
  // window it renews, and every renewal in one batch must come from a single
  // proof run under one algorithm.
  const proofAlgorithmDigest = asDigest(core.proofAlgorithmDigest);
  const payloadEvaluatedAt = asTime(core.evaluatedAt);
  if (Date.parse(payloadEvaluatedAt) <= Date.parse(liveValidUntil)
      || Date.parse(payloadEvaluatedAt) > Date.parse(evaluatedAt)) {
    stale();
  }
  if (Object.hasOwn(core, 'evaluatedAuthorityDigest')
      && core.evaluatedAuthorityDigest !== authorityDigest) {
    stale();
  }
  if (batch.proofAlgorithmDigest === null) {
    batch.proofAlgorithmDigest = proofAlgorithmDigest;
    batch.implementationSourceDigest = asDigest(core.implementationSourceDigest);
  } else if (batch.proofAlgorithmDigest !== proofAlgorithmDigest
      || batch.implementationSourceDigest !== core.implementationSourceDigest) {
    stale();
  }
  batch.renewed.push({ collectedAt, contentDigest, iri, validUntil });
  return Object.freeze({ bytes, contentDigest, validUntil });
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

function exactPathSet(rows, field, label) {
  const values = [...new Set(rows.map((row) => binding(row, field)).filter(Boolean))].sort();
  if (values.length === 0 || values.some((value) => typeof value !== 'string' || !SAFE_PATH.test(value))) {
    fail('AGGREGATE_DEPENDENT_VALIDATION_INVALID', `${label} paths`);
  }
  return Object.freeze(values);
}

function normalizeDependentValidation(rows, casRoot, config = Object.freeze({
  admissionRepository: DEPENDENT_VALIDATION_ADMISSION_REPOSITORY,
  expectedProducerPaths: null,
  label: 'Factory Provider V3',
  obligation: DEPENDENT_VALIDATION_OBLIGATION,
  producerRepository: DEPENDENT_VALIDATION_PRODUCER_REPOSITORY,
  result: DEPENDENT_VALIDATION_RESULT,
})) {
  if (!Array.isArray(rows) || rows.length === 0) {
    fail('AGGREGATE_DEPENDENT_VALIDATION_INVALID', `absent ${config.label} validation closure`);
  }
  const result = exactScalar(rows, 'result', config.result);
  const obligation = exactScalar(rows, 'obligation', result);
  const evaluation = exactScalar(rows, 'evaluation', result);
  const execution = exactScalar(rows, 'execution', result);
  const producer = exactScalar(rows, 'producer', result);
  const admissionPath = exactScalar(rows, 'admissionPath', result);
  const producerSourcePaths = exactPathSet(rows, 'producerSourcePath', `${result} producer`);
  const admissionSourcePaths = exactPathSet(rows, 'admissionSourcePath', `${result} admission`);
  const validationEvidence = [...new Set(rows.map((row) => binding(row, 'validationEvidence')).filter(Boolean))].sort();
  const resultAuthorityDigest = digest(exactScalar(rows, 'resultAuthorityDigest', result), `${result} authority`);
  const executionReceiptDigest = digest(
    exactScalar(rows, 'executionReceiptDigest', result), `${result} execution receipt`,
  );
  const evaluationReceiptDigest = digest(
    exactScalar(rows, 'evaluationReceiptDigest', result), `${result} evaluation receipt`,
  );
  const producerSourceScopeDigest = digest(
    exactScalar(rows, 'producerSourceScopeDigest', result), `${result} producer source scope`,
  );
  const admissionSourceScopeDigest = digest(
    exactScalar(rows, 'admissionSourceScopeDigest', result), `${result} admission source scope`,
  );
  const producerRepository = exactScalar(rows, 'producerRepository', result);
  const admissionRepository = exactScalar(rows, 'admissionRepository', result);
  const resultSourceHead = exactScalar(rows, 'resultSourceHead', result);
  const producerSourceHead = exactScalar(rows, 'producerSourceHead', result);
  const producerSourceTree = exactScalar(rows, 'producerSourceTree', result);
  const admissionSourceHead = exactScalar(rows, 'admissionSourceHead', result);
  const admissionSourceTree = exactScalar(rows, 'admissionSourceTree', result);
  if (result !== config.result || obligation !== config.obligation
      || exactScalar(rows, 'resultState', result) !== 'urn:usf:resultstate:passed'
      || validationEvidence.length !== 1
      || producerRepository !== config.producerRepository
      || admissionRepository !== config.admissionRepository
      || producerRepository === admissionRepository
      || exactScalar(rows, 'admissionProducer', result) !== producer
      || resultSourceHead !== producerSourceHead
      || !GIT_OBJECT.test(producerSourceHead || '') || !GIT_OBJECT.test(producerSourceTree || '')
      || !GIT_OBJECT.test(admissionSourceHead || '') || !GIT_OBJECT.test(admissionSourceTree || '')
      || producerSourceScopeDigest !== aggregateCompilerProofInternals.sourceScopeDigest(producerSourcePaths)
      || admissionSourceScopeDigest !== aggregateCompilerProofInternals.sourceScopeDigest(admissionSourcePaths)
      || (config.expectedProducerPaths !== null
        && canonicalJson(producerSourcePaths) !== canonicalJson(config.expectedProducerPaths))) {
    fail('AGGREGATE_DEPENDENT_VALIDATION_INVALID', 'identity, state or source binding');
  }
  readCasBytes(casRoot, executionReceiptDigest);
  readCasBytes(casRoot, evaluationReceiptDigest);
  return deepFreeze({
    admission: {
      iri: admissionPath,
      repository: admissionRepository,
      sourceHead: admissionSourceHead,
      sourcePaths: admissionSourcePaths,
      sourceScopeDigest: admissionSourceScopeDigest,
      sourceTree: admissionSourceTree,
    },
    authorityDigest: resultAuthorityDigest,
    evaluation,
    evaluationReceiptDigest,
    evidence: validationEvidence,
    execution,
    executionReceiptDigest,
    obligation,
    producer: {
      iri: producer,
      release: exactScalar(rows, 'producerRelease', result),
      repository: producerRepository,
      sourceHead: producerSourceHead,
      sourcePaths: producerSourcePaths,
      sourceScopeDigest: producerSourceScopeDigest,
      sourceTree: producerSourceTree,
    },
    result,
    sourceHead: resultSourceHead,
  });
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

function normalizeFacts(rows, casRoot, observedAt, evaluatedAt, authorityDigest, writeRecord, renewalSource = null) {
  const expectedResults = new Set(COMPONENT_PROOFS.map(({ result }) => result));
  const rowResults = new Set(rows.map((row) => binding(row, 'result')));
  if ([...rowResults].some((result) => !expectedResults.has(result))) {
    fail('AGGREGATE_UNEXPECTED_COMPONENT', [...rowResults].filter((result) => !expectedResults.has(result)).join(','));
  }
  // One batch across every component, so a renewal set assembled from more than
  // one proof run — or under more than one algorithm — cannot be accepted.
  const batch = { implementationSourceDigest: null, proofAlgorithmDigest: null, records: undefined, renewed: [] };
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
      const evidenceCollectedAt = exactScalar(evidenceRows, 'collectedAt', iri, { optional: true });
      if (evidenceCollectedAt !== null) timestamp(evidenceCollectedAt, `${iri} collectedAt`);
      if (evidenceValidFrom !== null && Date.parse(evidenceValidFrom) > Date.parse(observedAt)) {
        fail('AGGREGATE_COMPONENT_STALE', iri);
      }
      let effectiveDigest = evidenceDigest;
      let effectiveValidUntil = evidenceValidUntil;
      let bytes;
      if (Date.parse(evidenceValidUntil) <= Date.parse(evaluatedAt)) {
        const renewal = acceptComponentEvidenceRenewal({
          authorityDigest, batch, casRoot, evaluatedAt, iri,
          liveCollectedAt: evidenceCollectedAt, liveValidUntil: evidenceValidUntil, renewalSource,
        });
        effectiveDigest = renewal.contentDigest;
        effectiveValidUntil = renewal.validUntil;
        bytes = renewal.bytes;
      } else {
        bytes = readCasBytes(casRoot, evidenceDigest);
      }
      if (validUntil === null || effectiveValidUntil < validUntil) validUntil = effectiveValidUntil;
      evidenceReferences.push({ bytesBase64: bytes.toString('base64'), digest: effectiveDigest, iri });
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

async function readFacts(dependencies, requestedAuthorityDigest, renewalSource = null) {
  return stableAuthorityRead(dependencies, requestedAuthorityDigest, async () => {
    const [rows, dependentValidationRows, evaluatedAt] = await Promise.all([
      queryComponentRows(dependencies.client), dependencies.client.select(DEPENDENT_VALIDATION_FACTS_QUERY),
      readTrustedTime(dependencies.client),
    ]);
    return Object.freeze({
      components: normalizeFacts(rows, dependencies.casRoot, evaluatedAt, evaluatedAt, requestedAuthorityDigest,
        dependencies.writeRecord, renewalSource),
      dependentValidation: normalizeDependentValidation(dependentValidationRows, dependencies.casRoot),
      evaluatedAt,
    });
  });
}

async function readDependentValidation(dependencies, requestedAuthorityDigest) {
  return stableAuthorityRead(dependencies, requestedAuthorityDigest, async () => {
    const [dependentRows, checkpointRows] = await Promise.all([
      dependencies.client.select(DEPENDENT_VALIDATION_FACTS_QUERY),
      dependencies.client.select(CHECKPOINT_VALIDATION_FACTS_QUERY),
    ]);
    return Object.freeze({
      checkpointValidation: normalizeDependentValidation(checkpointRows, dependencies.casRoot, {
        admissionRepository: CHECKPOINT_VALIDATION_ADMISSION_REPOSITORY,
        expectedProducerPaths: CHECKPOINT_PRODUCER_SOURCE_PATHS,
        label: 'event-history checkpoint pruning',
        obligation: CHECKPOINT_VALIDATION_OBLIGATION,
        producerRepository: CHECKPOINT_VALIDATION_PRODUCER_REPOSITORY,
        result: CHECKPOINT_VALIDATION_RESULT,
      }),
      dependentValidation: normalizeDependentValidation(dependentRows, dependencies.casRoot),
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
    'aggregateResult', 'checkpointValidation', 'dependentValidation', 'evaluatedAuthorityDigest',
    'evaluationReceiptDigest', 'executionReceiptDigest',
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
  const compilerValidationEvidence = exactScalar(rows, 'compilerValidationEvidence', validationResult);
  const compilerValidationEvidenceDigest = digest(
    exactScalar(rows, 'compilerValidationEvidenceDigest', validationResult), 'compiler validation evidence',
  );
  readCasBytes(casRoot, compilerValidationEvidenceDigest);
  if (exactScalar(rows, 'resultState', validationResult) !== 'urn:usf:resultstate:passed'
      || exactScalar(rows, 'reevaluationState', validationResult) !== 'urn:usf:resultstate:passed'
      || exactScalar(rows, 'stageOneSettledAuthorityDigest', validationResult) !== expectedAuthorityDigest
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
  if (evidence.some(({ iri }) => iri === compilerValidationEvidence)) {
    fail('AGGREGATE_PRODUCER_VALIDATION_EVIDENCE_INVALID', 'compiler evidence conflated with receipt evidence');
  }
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

function validateDependentTerminalProjection(projection, requestedAuthorityDigest) {
  const currentness = projection?.proofCurrentness;
  const proofResults = [...(currentness?.proofResults || [])].sort();
  const mandatoryObligations = [...(currentness?.mandatoryObligations || [])].sort();
  const mappings = [...(currentness?.obligationProofResults || [])]
    .map(({ obligation, proofResult }) => ({ obligation, proofResult }))
    .sort((left, right) => left.obligation.localeCompare(right.obligation));
  const perProof = [...(currentness?.perProof || [])]
    .sort((left, right) => left.proofResult.localeCompare(right.proofResult));
  const expectedMappings = DEPENDENT_PROOF_OBLIGATIONS.map((obligation, index) => ({
    obligation,
    proofResult: DEPENDENT_PROOF_RESULTS[index],
  })).sort((left, right) => left.obligation.localeCompare(right.obligation));
  const validationObligations = projection?.validationObligations || [];
  if (projection?.contract !== DEPENDENT_VALIDATION_CONTRACT
      || projection?.authorityDigest !== requestedAuthorityDigest
      || projection?.actionState !== 'PROCEED'
      || projection?.validationActionState !== 'PROCEED'
      || projection?.validationSatisfied !== true
      || !Array.isArray(projection?.actionStateReasons) || projection.actionStateReasons.length !== 0
      || !Array.isArray(projection?.validationGaps) || projection.validationGaps.length !== 0
      || currentness?.state !== 'CURRENT'
      || !Array.isArray(currentness?.reasons) || currentness.reasons.length !== 0
      || canonicalJson(proofResults) !== canonicalJson([...DEPENDENT_PROOF_RESULTS].sort())
      || canonicalJson(mandatoryObligations) !== canonicalJson([...DEPENDENT_PROOF_OBLIGATIONS].sort())
      || canonicalJson(mappings) !== canonicalJson(expectedMappings)
      || perProof.length !== DEPENDENT_PROOF_RESULTS.length
      || perProof.some((item) => item?.proofResultState !== 'urn:usf:proofresultstate:successful'
        || item?.currentAuthorityDigest !== requestedAuthorityDigest
        || !DEPENDENT_PROOF_RESULTS.includes(item?.proofResult)
        || !DEPENDENT_PROOF_OBLIGATIONS.includes(item?.obligation)
        || !SHA256.test(item?.algorithmSourceDigest || '')
        || !SHA256.test(item?.implementationSourceSetDigest || '')
        || !SHA256.test(item?.dependencySetDigest || '')
        || !SHA256.test(item?.evidenceSetDigest || '')
        || !SHA256.test(item?.evaluatedAuthorityDigest || '')
        || !SHA256.test(item?.settledAuthorityDigest || '')
        || item?.reevaluationState !== 'urn:usf:proofreevaluationstate:successful')
      || validationObligations.length !== 1
      || validationObligations[0]?.id !== DEPENDENT_VALIDATION_OBLIGATION
      || validationObligations[0]?.satisfactionCurrent !== true
      || validationObligations[0]?.recordedSatisfactionCount !== 1) {
    fail('AGGREGATE_PRODUCER_TERMINAL_DEPENDENT_CLOSURE_INVALID',
      'provider configuration plane is not exactly 2-obligation/2-proof CURRENT with current validation');
  }
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function isPendingInitialProjection(projection, selectedResult) {
  const currentness = projection?.proofCurrentness;
  const contractState = projection?.contractState;
  const reasons = currentness?.reasons;
  const perProof = currentness?.perProof;
  const proofResults = currentness?.proofResults;
  return selectedResult === PROVISIONAL_AGGREGATE_RESULT_IRI
    && projection?.actionState === 'BLOCK'
    && contractState?.lifecycle === 'urn:usf:semanticlifecyclestate:active'
    && contractState?.activation === 'urn:usf:contractactivationstate:proofblocked'
    && contractState?.decision === 'urn:usf:decisionstate:accepted'
    && contractState?.proof === null
    && currentness?.state === 'STALE_BLOCK'
    && currentness?.stateIri === 'urn:usf:proofcurrentnessstate:staleblock'
    && Array.isArray(proofResults)
    && proofResults.length === 1
    && proofResults[0] === PROVISIONAL_AGGREGATE_RESULT_IRI
    && Array.isArray(perProof)
    && perProof.length === 1
    && perProof[0]?.proofResult === PROVISIONAL_AGGREGATE_RESULT_IRI
    && perProof[0]?.reevaluationState === 'urn:usf:proofreevaluationstate:pending'
    && perProof[0]?.currentAuthorityDigest === projection?.authorityDigest
    && Array.isArray(reasons)
    && reasons.length === 2
    && new Set(reasons).size === 2
    && reasons.includes('proof-currentness-ambiguous')
    && reasons.includes('proof-currentness-unresolved');
}

function exactV2Keys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    fail('AGGREGATE_V2_CANDIDATE_INPUT_INVALID', `${label} is not the closed protocol shape`);
  }
}

/**
 * Build the exact C1/C2 candidate pair for a prospective V2 publication.
 *
 * This is deliberately a pure coordination core: D1 is supplied by the
 * canonical no-write publication preview and C2 binds that exact authority
 * plus its exact dependency identity set.  No CAS, journal, claim, grant,
 * signature, nonce or clock service is available to this function.
 */
export function prepareAggregateCompilerAuthorityCandidatesV2(input) {
  exactV2Keys(input, ['d1_observation', 'frozen_inputs'], 'V2 candidate preparation');
  exactV2Keys(input.frozen_inputs, [
    'compiler_identity',
    'd0_authority_digest',
    'evidence_dependency_digests',
    'external_attestation_identities',
    'protocol',
    'release_subject_digest',
    'source_identities',
  ], 'V2 frozen candidate inputs');
  exactV2Keys(input.d1_observation,
    ['authority_digest', 'dependency_identity_digests'], 'V2 D1 observation');
  const c1 = materializeAggregateCompilerAuthorityCandidateV2({
    ...input.frozen_inputs,
    d1_binding: null,
    stage: 'C1',
  });
  const c2 = materializeAggregateCompilerAuthorityCandidateV2({
    ...input.frozen_inputs,
    d1_binding: {
      authority_digest: input.d1_observation.authority_digest,
      c1_candidate_digest: c1.candidateDigest,
      dependency_identity_digests: input.d1_observation.dependency_identity_digests,
    },
    stage: 'C2',
  });
  const c2Core = JSON.parse(c2.identityBytes.toString('utf8'));
  if (c1.externalAttestationSetRootDigest !== c2.externalAttestationSetRootDigest
      || c1.candidateGeneratorImplementationDigest
        !== c2.candidateGeneratorImplementationDigest
      || c1.candidateCommandDigest !== c2.candidateCommandDigest) {
    fail('AGGREGATE_V2_CANDIDATE_INPUT_INVALID', 'C1/C2 frozen candidate identities differ');
  }
  return Object.freeze({
    schema: 'usf-aggregate-compiler-prospective-candidates-v2',
    protocol: 'semantic-proof-v2',
    release_subject_digest: input.frozen_inputs.release_subject_digest,
    d0_authority_digest: input.frozen_inputs.d0_authority_digest,
    d1_authority_digest: input.d1_observation.authority_digest,
    d1_dependency_identity_digests: Object.freeze([
      ...input.d1_observation.dependency_identity_digests,
    ]),
    d1_dependency_set_digest: c2Core.d1_binding.dependency_set_digest,
    external_attestation_set_root_digest: c1.externalAttestationSetRootDigest,
    candidate_generator_implementation_digest: c1.candidateGeneratorImplementationDigest,
    candidate_command_digest: c1.candidateCommandDigest,
    c1,
    c2,
    production_cas_write_operations: 0,
    production_journal_write_operations: 0,
    production_stardog_write_operations: 0,
    authorization_issued: 0,
    publication_performed: 0,
  });
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
        const selectedProvisionalAggregateResult = Array.isArray(rows) && rows.length === 1
          ? binding(rows[0], 'result') : null;
        if (!Array.isArray(rows) || rows.length !== 1
            || binding(rows[0], 'provisional') !== 'true' || binding(rows[0], 'current') !== 'false'
            || !isPendingInitialProjection(projection, selectedProvisionalAggregateResult)) {
          fail('AGGREGATE_PRODUCER_INITIAL_PROJECTION_INVALID', 'D1 is not one provisional PENDING aggregate');
        }
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
      // Renewals are read from the same reviewed, signed source head the source
      // binding already resolved and verified. Only consulted for an evidence
      // identity whose live window has already closed.
      let candidateEvidenceSource;
      try {
        candidateEvidenceSource = await dependencies.readSourceText({
          head: aggregateSourceBinding.head,
          path: EVIDENCE_SOURCE_PATH,
          repositoryPath: dependencies.repositoryPath,
        });
      } catch (error) {
        if (error?.code?.startsWith('AGGREGATE_')) throw error;
        fail('AGGREGATE_PRODUCER_SOURCE_UNAVAILABLE', error?.message || 'candidate evidence source dependency failed');
      }
      const { components, dependentValidation, evaluatedAt } = await readFacts(
        dependencies, requestedAuthorityDigest, Object.freeze({ text: candidateEvidenceSource }),
      );
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
        dependentValidation,
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

    async refreshDependentValidation({ requestedAuthorityDigest }) {
      digest(requestedAuthorityDigest, 'dependent validation authority');
      return readDependentValidation(dependencies, requestedAuthorityDigest);
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
        const [projection, dependentProjection, selectionRows, receiptBindingRows, validationRows, observedAt] = await Promise.all([
          contractProjector(client, CONTRACT),
          contractProjector(client, DEPENDENT_VALIDATION_CONTRACT),
          client.select(CONTRACT_SELECTION_QUERY),
          client.select(AGGREGATE_LIVE_BINDINGS_QUERY),
          client.select(FINAL_VALIDATION_BINDINGS_QUERY),
          readTrustedTime(client),
        ]);
        return { dependentProjection, observedAt, projection, receiptBindingRows, selectionRows, validationRows };
      });
      validateFinalValidationEvidence(casRoot, live.validationRows, expectedStage1AuthorityDigest);
      validateDependentTerminalProjection(live.dependentProjection, requestedAuthorityDigest);
      const selections = [...new Set(live.selectionRows.map((row) => binding(row, 'result')).filter(Boolean))];
      const liveResult = exactScalar(live.receiptBindingRows, 'result', aggregateResultIri);
      const liveEvaluatedAuthorityDigest = exactScalar(live.receiptBindingRows, 'evaluatedAuthorityDigest', aggregateResultIri);
      const liveExecutionReceiptDigest = exactScalar(live.receiptBindingRows, 'executionReceiptDigest', aggregateResultIri);
      const liveEvaluationReceiptDigest = exactScalar(live.receiptBindingRows, 'evaluationReceiptDigest', aggregateResultIri);
      const projectedProofResults = Array.isArray(live.projection?.proofCurrentness?.proofResults)
        ? live.projection.proofCurrentness.proofResults : [];
      const projectedAggregateResults = Array.isArray(live.projection?.proofCurrentness?.perProof)
        ? live.projection.proofCurrentness.perProof.filter((item) => item?.proofResult === aggregateResultIri)
        : [];
      if (selections.length !== 1 || selections[0] !== aggregateResultIri || liveResult !== aggregateResultIri
          || liveEvaluatedAuthorityDigest !== expectedStage1AuthorityDigest
          || liveExecutionReceiptDigest !== preparation.executionReceiptDigest
          || liveEvaluationReceiptDigest !== preparation.evaluationReceiptDigest
          || projectedProofResults.length !== 1 || projectedProofResults[0] !== aggregateResultIri
          || projectedAggregateResults.length !== 1
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
  // The owner boundary refuses when it cannot observe ownership. This live
  // assurance command therefore supplies the same composition-root observer the
  // MCP server uses; without it an absent observation would previously have
  // resolved to V1, a V1 recreation route reachable from a production command.
  const observeGraphOwnership = createGraphOwnershipObserver(env);
  const observeGraphRuntimeOwnership = () => observeGraphOwnership(client);
  return Object.freeze({
    casRoot,
    client,
    contractProjector: (readOnlyClient, contract) => projectContract(
      { client: readOnlyClient, observeGraphRuntimeOwnership },
      { contract },
    ),
    observeGraphRuntimeOwnership,
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
  if (args.phase === 'event-history-checkpoint-pruning') {
    return runEventHistoryCheckpointEvidence(
      Object.fromEntries(Object.entries(args).filter(([key]) => key !== 'phase')),
      env,
    );
  }
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
  fail(
    'AGGREGATE_PRODUCER_ARGUMENT_INVALID',
    'phase must be event-history-checkpoint-pruning, pending, initial or terminal',
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runAggregateCompilerProofCommand().then(
    (result) => process.stdout.write(`${canonicalJson(result)}\n`),
    (error) => { process.stderr.write(`${error.code || 'AGGREGATE_PRODUCER_FAILED'}: ${error.message}\n`); process.exitCode = 1; },
  );
}

export const aggregateCompilerProofCommandInternals = Object.freeze({
  RENEWABLE_COMPONENT_EVIDENCE,
  acceptComponentEvidenceRenewal,
  newRenewalBatch: () => ({
    implementationSourceDigest: null, proofAlgorithmDigest: null, records: undefined, renewed: [],
  }),
  normalizeFacts,
  readCasBytes,
  sourceBinding: gitSourceBinding,
  stableAuthorityRead,
  writeCanonicalRecord,
});
