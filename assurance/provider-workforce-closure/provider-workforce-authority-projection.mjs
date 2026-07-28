#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify,
} from 'node:crypto';
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  authorityDependencySetDigest,
} from '../../capabilities/semantic-model-compilation/authority-binding.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const PROVIDER_PROOF_PATH = 'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs';
const EVIDENCE_START = '# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE';
const EVIDENCE_END = '# END GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE';
const PROOF_START = '# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF';
const PROOF_END = '# END GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF';
const EVIDENCE_RESOURCE = '<urn:usf:externalpayloaddescriptor:providerworkforceauthorityevidence>';
const PROOF_RESOURCE = '<urn:usf:proofalgorithm:providerworkforceauthority>';
export const PROVIDER_WORKFORCE_REQUIRED_CLAIMS = Object.freeze([
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
]);
export const PROVIDER_WORKFORCE_REQUIRED_CASES = Object.freeze([
  'factory-commit-exact',
  'factory-tree-exact',
  'factory-worktree-clean',
  'secrets-outside-git',
  'environment-file-ignored',
  'environment-names-only',
  'unknown-token-not-loaded',
  'run-authorization-at-provider-call',
  'zero-paid-budget-denial',
  'subscription-api-distinction',
  'openrouter-free-fail-closed',
  'ollama-operator-exclusion',
  'actual-identities-recorded',
  'model-quota-scope-preserved',
  'disabled-providers-inventoried',
  'research-command-unbound',
  'one-effective-policy-intersection',
  'fair-queue-complete-drain',
  'terminal-model-at-most-once',
  'missing-credential-token-required',
  'model-specific-terminal-scope',
  'availability-facts-durable',
  'provider-failure-isolated',
  'materialisation-exact-path-and-directory-prefix-disjoint',
  'materialisation-action-and-family-fail-closed',
  'materialisation-permission-digest-binds-naming',
  'provider-materialisation-semantic-scope-exact',
  'provider-materialisation-family-rules-exact',
  'legacy-materialisation-contracts-remain-unscoped',
  'provider-materialisation-hostile-mutations',
  'focused-deterministic-tests',
]);
const CONTRACTS = Object.freeze([
  Object.freeze({
    name: 'providerconfigurationplane',
    obligation: 'urn:usf:proofobligation:p7515b7117898c8bf9cedd38642fd544b19bd241c7e53cf392161edda5065843f',
    requirement: 'urn:usf:evidencerequirement:e8c6928a56f67bd7f0f379b43c026dc28acb991e045faceaae1160d13b2513050',
  }),
  Object.freeze({
    name: 'providerenvironmentclassification',
    obligation: 'urn:usf:proofobligation:p6fdcab8c78bc4d0a1ae49ebd9f1fae6d3ea03eb61c4226889f14d8e05a32ef03',
    requirement: 'urn:usf:evidencerequirement:e6bc2d48a0f6eae6eb793d4d7e026ad38589542c1d9973bd21823196da9d38371',
  }),
  Object.freeze({
    name: 'servicecatalogandproviderintegrationmodel',
    obligation: 'urn:usf:proofobligation:p3d210ec339c9c829e5b031b079ff8a95257db4b539185d8dc88ff58d726a5ecf',
    requirement: 'urn:usf:evidencerequirement:e81267ee8b57d047d9f92772d4899a060dde3e01480d51c3f26c5ba2f86a7e11d',
  }),
]);
const EVALUATION_CRITERIA = Object.freeze([
  'acquisitionandtotalcost',
  'availabilityandrecovery',
  'backupandrestore',
  'behaviourcoverage',
  'continuityandreplacement',
  'dataownershipandtransactions',
  'environmentcompatibility',
  'evidenceandprooffeasibility',
  'hermeticsubstitutefeasibility',
  'identitypermissiontenancyandprivacy',
  'licencecompatibility',
  'maintenanceburden',
  'negativeerrorandrecoverybehaviour',
  'observability',
  'operationalcomplexity',
  'performanceandresourceuse',
  'portability',
  'productionshapedstagingfeasibility',
  'providercompatibility',
  'reliabilityandfailurehandling',
  'scalability',
  'securityarchitecture',
  'semanticcontractfit',
  'semanticderivation',
  'supplychainrisk',
  'testability',
  'updateandpatchpolicy',
  'upgradeandrollback',
  'vendorlockinandexit',
  'versionstability',
  'vulnerabilityexposure',
]);

const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const q = (value) => JSON.stringify(String(value));
const iri = (value) => `<${value}>`;
const assert = (condition, code) => {
  if (!condition) throw new Error(code);
};
const exactDigest = (value, code) => {
  assert(typeof value === 'string' && SHA256.test(value), code);
  return value;
};
const exactCommit = (value, code) => {
  assert(typeof value === 'string' && COMMIT.test(value), code);
  return value;
};
const exactDateTime = (value, code) => {
  assert(typeof value === 'string' && DATE_TIME.test(value) && Number.isFinite(Date.parse(value)), code);
  return value;
};
const exactStringSet = (actual, expected, code) => {
  assert(Array.isArray(actual)
    && actual.length === expected.length
    && new Set(actual).size === actual.length
    && canonicalJson([...actual].sort(utf8Compare)) === canonicalJson([...expected].sort(utf8Compare)), code);
};
function parseCanonicalJson(bytes, label) {
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`${label}_JSON_INVALID`);
  }
  assert(Buffer.from(canonicalJson(value)).equals(bytes), `${label}_NOT_CANONICAL_JSON`);
  return value;
}

function deterministicIntegrityPublicKey() {
  const seed = createHash('sha256').update('provider-workforce-authority-integrity-key-v1').digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(privateKey);
}

function descriptor(receipt, field, bytes, mediaType) {
  const label = field.replace(/[A-Z]/g, (value) => `_${value}`).toUpperCase();
  const value = receipt[field];
  assert(value && typeof value === 'object' && !Array.isArray(value), `${label}_DESCRIPTOR_MISSING`);
  const digest = exactDigest(value.digest, `${label}_DIGEST_INVALID`);
  assert(digest === sha256(bytes), `${label}_DIGEST_MISMATCH`);
  assert(value.byteSize === bytes.length, `${label}_BYTE_SIZE_MISMATCH`);
  assert(value.mediaType === mediaType, `${label}_MEDIA_TYPE_MISMATCH`);
  assert(value.locator === `cas://sha256/${digest.slice(7)}`, `${label}_LOCATOR_MISMATCH`);
  return Object.freeze({ digest, byteSize: bytes.length, mediaType, locator: value.locator });
}

function verifyEvidence(receipt, evidenceBytes) {
  const evidence = parseCanonicalJson(evidenceBytes, 'EVIDENCE');
  assert(evidence.schemaVersion === 1, 'EVIDENCE_SCHEMA_UNSUPPORTED');
  assert(evidence.recordKind === 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_CANDIDATE', 'EVIDENCE_KIND_INVALID');
  assert(evidence.passed === true && evidence.eligibleForAdmission === true, 'EVIDENCE_NOT_ELIGIBLE');
  exactStringSet(evidence.authorityClaims, PROVIDER_WORKFORCE_REQUIRED_CLAIMS, 'EVIDENCE_AUTHORITY_CLAIM_SET_MISMATCH');
  assert(canonicalJson(receipt.authorityClaims) === canonicalJson(evidence.authorityClaims),
    'RECEIPT_AUTHORITY_CLAIMS_MISMATCH');
  assert(Array.isArray(evidence.cases), 'EVIDENCE_CASES_INVALID');
  assert(evidence.cases.every((item) => item && item.passed === true && typeof item.id === 'string'), 'EVIDENCE_CASE_FAILED');
  exactStringSet(evidence.cases.map(({ id }) => id), PROVIDER_WORKFORCE_REQUIRED_CASES, 'EVIDENCE_CASE_SET_MISMATCH');
  assert(receipt.caseCount === evidence.cases.length, 'RECEIPT_CASE_COUNT_MISMATCH');
  assert(evidence.materialisationAuthorityMutationEvidence?.caseCount === 21
    && evidence.materialisationAuthorityMutationEvidence?.passedCaseCount === 21
    && evidence.materialisationAuthorityMutationEvidence?.baselineIntegrityRowCount === 0,
  'MATERIALISATION_MUTATION_EVIDENCE_INCOMPLETE');
  const exactEvidenceSetDigest = exactDigest(evidence.exactEvidenceSetDigest, 'EVIDENCE_SET_DIGEST_INVALID');
  const { exactEvidenceSetDigest: omitted, ...evidenceCore } = evidence;
  assert(exactEvidenceSetDigest === sha256(canonicalJson(evidenceCore)), 'EVIDENCE_SET_DIGEST_MISMATCH');
  assert(receipt.exactEvidenceSetDigest === exactEvidenceSetDigest, 'RECEIPT_EVIDENCE_SET_DIGEST_MISMATCH');
  for (const key of [
    'evaluatedAuthorityDigest',
    'implementationSourceDigest',
    'proofAlgorithmSourceDigest',
    'policyDigest',
    'populationDigest',
    'closureDigest',
  ]) {
    exactDigest(evidence[key], `EVIDENCE_${key.toUpperCase()}_INVALID`);
    assert(receipt[key] === evidence[key], `RECEIPT_${key.toUpperCase()}_MISMATCH`);
  }
  exactCommit(evidence.factoryCommit, 'FACTORY_COMMIT_INVALID');
  exactCommit(evidence.factoryTree, 'FACTORY_TREE_INVALID');
  assert(receipt.factoryCommit === evidence.factoryCommit, 'RECEIPT_FACTORY_COMMIT_MISMATCH');
  assert(receipt.factoryTree === evidence.factoryTree, 'RECEIPT_FACTORY_TREE_MISMATCH');
  exactDateTime(evidence.evaluatedAt, 'EVIDENCE_EVALUATED_AT_INVALID');
  exactDateTime(evidence.validUntil, 'EVIDENCE_VALID_UNTIL_INVALID');
  assert(receipt.evaluatedAt === evidence.evaluatedAt, 'RECEIPT_EVALUATED_AT_MISMATCH');
  assert(receipt.validUntil === evidence.validUntil, 'RECEIPT_VALID_UNTIL_MISMATCH');
  assert(Date.parse(evidence.validUntil) > Date.parse(evidence.evaluatedAt), 'EVIDENCE_VALIDITY_INTERVAL_INVALID');
  assert(evidence.environmentClass === 'urn:usf:environmentclass:hermetic', 'EVIDENCE_ENVIRONMENT_INVALID');
  assert(evidence.providerMode === 'urn:usf:providermode:deterministictestsubstitute', 'EVIDENCE_PROVIDER_MODE_INVALID');
  assert(Array.isArray(evidence.implementationSources) && evidence.implementationSources.length > 0, 'IMPLEMENTATION_SOURCES_EMPTY');
  assert(evidence.implementationSources.every(({ path, digest, byteSize }) => typeof path === 'string'
    && SHA256.test(digest) && Number.isInteger(byteSize) && byteSize >= 0), 'IMPLEMENTATION_SOURCE_RECORD_INVALID');
  assert(sha256(canonicalJson(evidence.implementationSources)) === evidence.implementationSourceDigest,
    'IMPLEMENTATION_SOURCE_SET_DIGEST_MISMATCH');
  assert(Array.isArray(evidence.proofAlgorithmSources) && evidence.proofAlgorithmSources.length > 0, 'PROOF_ALGORITHM_SOURCES_EMPTY');
  assert(evidence.proofAlgorithmSources.every(({ path, digest }) => typeof path === 'string'
    && path.startsWith('assurance/') && !path.startsWith('/') && !path.includes('..') && SHA256.test(digest)),
    'PROOF_ALGORITHM_SOURCE_RECORD_INVALID');
  assert(evidence.proofAlgorithmSources.some(({ path }) => path === PROVIDER_PROOF_PATH), 'PROOF_PRIMARY_SOURCE_MISSING');
  assert(sha256(canonicalJson(evidence.proofAlgorithmSources)) === evidence.proofAlgorithmSourceDigest,
    'PROOF_ALGORITHM_SOURCE_SET_DIGEST_MISMATCH');
  return Object.freeze(evidence);
}

function verifyAttestation(receipt, evidence, evidenceDescriptor, attestationBytes) {
  const envelope = parseCanonicalJson(attestationBytes, 'ATTESTATION');
  assert(envelope.payloadType === 'application/vnd.in-toto+json', 'ATTESTATION_PAYLOAD_TYPE_INVALID');
  assert(typeof envelope.payload === 'string', 'ATTESTATION_PAYLOAD_MISSING');
  assert(Array.isArray(envelope.signatures) && envelope.signatures.length === 1, 'ATTESTATION_SIGNATURE_COUNT_INVALID');
  const signature = envelope.signatures[0];
  assert(signature && typeof signature.keyid === 'string' && typeof signature.sig === 'string',
    'ATTESTATION_SIGNATURE_INVALID');
  const publicKey = deterministicIntegrityPublicKey();
  const keyid = sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7);
  assert(signature.keyid === keyid && receipt.signingKeyFingerprint === keyid, 'ATTESTATION_KEY_ID_MISMATCH');
  const statementBytes = Buffer.from(envelope.payload, 'base64');
  const statement = parseCanonicalJson(statementBytes, 'ATTESTATION_STATEMENT');
  const payloadType = envelope.payloadType;
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `),
    statementBytes,
  ]);
  assert(verify(null, pae, publicKey, Buffer.from(signature.sig, 'base64')), 'ATTESTATION_SIGNATURE_VERIFICATION_FAILED');
  assert(statement._type === 'https://in-toto.io/Statement/v1', 'ATTESTATION_STATEMENT_TYPE_INVALID');
  assert(statement.predicateType === 'https://in-toto.io/attestation/test-result/v0.1',
    'ATTESTATION_PREDICATE_TYPE_INVALID');
  assert(Array.isArray(statement.subject) && statement.subject.length === 1, 'ATTESTATION_SUBJECT_COUNT_INVALID');
  assert(statement.subject[0]?.name === 'provider-workforce-authority-evidence', 'ATTESTATION_SUBJECT_NAME_INVALID');
  assert(statement.subject[0]?.digest?.sha256 === evidenceDescriptor.digest.slice(7), 'ATTESTATION_SUBJECT_DIGEST_MISMATCH');
  assert(statement.predicate?.evaluatedAuthorityDigest === evidence.evaluatedAuthorityDigest,
    'ATTESTATION_AUTHORITY_DIGEST_MISMATCH');
  assert(statement.predicate?.exactEvidenceSetDigest === evidence.exactEvidenceSetDigest,
    'ATTESTATION_EVIDENCE_SET_DIGEST_MISMATCH');
  assert(statement.predicate?.implementationSourceDigest === evidence.implementationSourceDigest,
    'ATTESTATION_IMPLEMENTATION_DIGEST_MISMATCH');
  assert(statement.predicate?.proofAlgorithmSourceDigest === evidence.proofAlgorithmSourceDigest,
    'ATTESTATION_ALGORITHM_DIGEST_MISMATCH');
  assert(statement.predicate?.result === 'passed', 'ATTESTATION_RESULT_NOT_PASSED');
  return Object.freeze({ envelope, signature, statement });
}

function scopeManifest({ evidence, evidenceDescriptor, classification }) {
  const deterministic = classification === 'deterministicevaluation';
  const core = deterministic ? {
    classification,
    evidenceDigest: evidenceDescriptor.digest,
    proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
    authorityClaims: [...evidence.authorityClaims].sort(utf8Compare),
    caseIds: evidence.cases.map(({ id }) => id).sort(utf8Compare),
  } : {
    classification,
    evidenceDigest: evidenceDescriptor.digest,
    implementationSourceDigest: evidence.implementationSourceDigest,
    factoryCommit: evidence.factoryCommit,
    factoryTree: evidence.factoryTree,
    implementationSources: evidence.implementationSources,
  };
  return Object.freeze({
    classification,
    digest: sha256(canonicalJson(core)),
    providerIdentity: deterministic
      ? 'urn:usf:provideridentity:repositorylocalevaluator'
      : 'urn:usf:provideridentity:repositorylocalacquisition',
    claimBoundary: deterministic
      ? `Deterministic reference algorithms and ${evidence.cases.length} passing fail-closed boundary cases.`
      : `Exact clean factory commit and tree with ${evidence.implementationSources.length} digest-bound implementation sources.`,
    prohibitedClaim: deterministic
      ? 'Does not establish provider availability, authenticate an account, validate a future factory implementation, or establish production readiness.'
      : 'Does not admit mutable quota state, credentials, provider responses, external model identity or production validation.',
  });
}

function evidenceProjection({ receipt, evidence, evidenceDescriptor, attestationDescriptor, attestation }) {
  const contracts = CONTRACTS.map(({ name }) => iri(`urn:usf:semanticcontract:${name}`)).join(', ');
  const obligations = CONTRACTS.map(({ obligation }) => iri(obligation)).join(', ');
  const collections = CONTRACTS.map(({ name }) => iri(`urn:usf:evidencecollection:providerworkforceauthority${name}`)).join(', ');
  const criteria = EVALUATION_CRITERIA.map((name) => iri(`urn:usf:evaluationcriterion:${name}`)).join(', ');
  const deterministic = scopeManifest({ evidence, evidenceDescriptor, classification: 'deterministicevaluation' });
  const hermetic = scopeManifest({ evidence, evidenceDescriptor, classification: 'hermeticlocal' });
  const lines = [];
  lines.push(`${EVIDENCE_RESOURCE} a usf:ExternalPayloadDescriptor;`);
  lines.push('  usf:canonicalName "providerworkforceauthorityevidence";');
  lines.push('  usf:descriptorArtefactFamily <urn:usf:artefactfamily:evidencepayload>;');
  lines.push('  usf:descriptorRepresentationFormat <urn:usf:representationformat:jsondata8259>;');
  lines.push(`  usf:descriptorMediaType ${q(evidenceDescriptor.mediaType)};`);
  lines.push(`  usf:descriptorDigest ${q(evidenceDescriptor.digest)};`);
  lines.push(`  usf:descriptorByteSize ${evidenceDescriptor.byteSize};`);
  lines.push(`  usf:descriptorLocator ${q(evidenceDescriptor.locator)}^^xsd:anyURI;`);
  lines.push('  usf:descriptorArtefactType "urn:usf:artefacttype:providerworkforceauthorityevidence"^^xsd:anyURI;');
  lines.push('  usf:descriptorStorageClass <urn:usf:storageclass:contentaddressedobjectstorage>.');
  lines.push('<urn:usf:externalpayloaddescriptor:providerworkforceauthorityattestation> a usf:ExternalPayloadDescriptor;');
  lines.push('  usf:canonicalName "providerworkforceauthorityattestation";');
  lines.push('  usf:descriptorArtefactFamily <urn:usf:artefactfamily:proofexecutionattestation>;');
  lines.push('  usf:descriptorRepresentationFormat <urn:usf:representationformat:intotostatementjson>;');
  lines.push(`  usf:descriptorMediaType ${q(attestationDescriptor.mediaType)};`);
  lines.push(`  usf:descriptorDigest ${q(attestationDescriptor.digest)};`);
  lines.push(`  usf:descriptorByteSize ${attestationDescriptor.byteSize};`);
  lines.push(`  usf:descriptorLocator ${q(attestationDescriptor.locator)}^^xsd:anyURI;`);
  lines.push('  usf:descriptorArtefactType "urn:usf:artefacttype:providerworkforceauthorityattestation"^^xsd:anyURI;');
  lines.push('  usf:descriptorStorageClass <urn:usf:storageclass:contentaddressedobjectstorage>.');
  lines.push('<urn:usf:signingidentity:providerworkforceauthorityintegrity> a usf:SigningIdentity;');
  lines.push('  usf:canonicalName "providerworkforceauthorityintegrity";');
  lines.push(`  usf:signingKeyFingerprint ${q(receipt.signingKeyFingerprint)}.`);
  lines.push('<urn:usf:signature:providerworkforceauthorityattestation> a usf:Signature;');
  lines.push('  usf:canonicalName "providerworkforceauthorityattestation";');
  lines.push('  usf:artefactKind <urn:usf:artefactkind:signature>;');
  lines.push(`  usf:canonicalPath ${q(`${attestationDescriptor.locator}#signature`)};`);
  lines.push('  usf:governedByPathRule <urn:usf:pathrule:contentaddressedsignature>;');
  lines.push('  usf:signatureMethod <urn:usf:signaturemethod:enveloped>;');
  lines.push('  usf:signingPolicy <urn:usf:policy:hermeticevidenceattestation>;');
  lines.push('  usf:signedBy <urn:usf:signingidentity:providerworkforceauthorityintegrity>;');
  lines.push(`  usf:signatureValue ${q(attestation.signature.sig)}.`);
  lines.push('<urn:usf:checksum:providerworkforceauthorityevidence> a usf:Checksum;');
  lines.push('  usf:canonicalName "providerworkforceauthorityevidence";');
  lines.push('  usf:checksumAlgorithm <urn:usf:checksumalgorithm:sha256>;');
  lines.push(`  usf:checksumValue ${q(evidenceDescriptor.digest.slice(7))}.`);
  for (const [name, scope] of [['providerworkforcedeterministicevaluation', deterministic], ['providerworkforcehermeticlocal', hermetic]]) {
    lines.push(`<urn:usf:evidencescopemanifest:${name}> a usf:EvidenceScopeManifest;`);
    lines.push(`  usf:canonicalName ${q(name)};`);
    lines.push(`  usf:evidenceScopeClassification <urn:usf:evidencescopeclassification:${scope.classification}>;`);
    lines.push(`  usf:scopeProviderIdentity <${scope.providerIdentity}>;`);
    lines.push(`  usf:scopeManifestDigest ${q(scope.digest)};`);
    lines.push(`  usf:scopeDescriptorDigest ${q(evidenceDescriptor.digest)};`);
    lines.push(`  usf:scopeCollectorDigest ${q(evidence.proofAlgorithmSourceDigest)};`);
    lines.push(`  usf:scopeClaimBoundary ${q(scope.claimBoundary)};`);
    lines.push(`  usf:scopeProhibitedClaim ${q(scope.prohibitedClaim)};`);
    lines.push(`  usf:scopeSupportsCriterion ${criteria}.`);
  }
  lines.push('<urn:usf:validatorrule:validateproviderworkforceauthority> a usf:ValidatorRule;');
  lines.push('  usf:canonicalName "validateproviderworkforceauthority";');
  lines.push('  usf:resultCode "providerworkforceauthorityclosure";');
  lines.push('  usf:targetsGraph <urn:usf:namedgraph:capabilities>, <urn:usf:namedgraph:evidence>, <urn:usf:namedgraph:bindings>, <urn:usf:namedgraph:proofs>;');
  lines.push('  usf:validatorSeverity <urn:usf:severity:blocking>.');
  lines.push('evr:providerworkforceauthority a usf:EvidenceResult;');
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push('  usf:evidenceKind evk:runtimeproofevidence;');
  lines.push('  usf:hasFreshness fresh:fresh;');
  lines.push(`  usf:evidenceForContract ${contracts};`);
  lines.push(`  usf:evidenceFor ${contracts};`);
  lines.push(`  usf:contentDigest ${q(evidenceDescriptor.digest)};`);
  lines.push(`  usf:evaluatedAuthorityDigest ${q(evidence.evaluatedAuthorityDigest)};`);
  lines.push(`  usf:evidenceProducerDigest ${q(evidence.proofAlgorithmSourceDigest)};`);
  lines.push(`  usf:mediaType ${q(evidenceDescriptor.mediaType)};`);
  lines.push(`  usf:byteSize ${evidenceDescriptor.byteSize};`);
  lines.push(`  usf:storageLocator ${q(evidenceDescriptor.locator)}^^xsd:anyURI;`);
  lines.push('  usf:wasProducedBy <urn:usf:validatorrule:validateproviderworkforceauthority>;');
  lines.push(`  usf:collectedAt ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
  lines.push(`  usf:validUntil ${q(evidence.validUntil)}^^xsd:dateTime;`);
  lines.push('  usf:hasFreshnessPolicy <urn:usf:evidencefreshnesspolicy:providerworkforcethirtydays>;');
  lines.push('  usf:hasAdmissionState admission:admitted;');
  lines.push('  usf:hasFreshnessState freshnessstate:fresh;');
  lines.push('  usf:hasIntegrityState integritystate:valid;');
  lines.push('  usf:evidenceStage <urn:usf:evidencestage:emitted>, <urn:usf:evidencestage:collected>, <urn:usf:evidencestage:normalised>, <urn:usf:evidencestage:ingested>, <urn:usf:evidencestage:signed>, <urn:usf:evidencestage:integrityverified>;');
  lines.push('  usf:usesProviderMode pmode:deterministictestsubstitute;');
  lines.push('  usf:inEnvironment env:hermetic;');
  lines.push(`  usf:collectedBy ${collections};`);
  lines.push('  usf:normalisedBy <urn:usf:evidencenormalisation:providerworkforceauthority>;');
  lines.push('  usf:ingestedBy <urn:usf:evidenceingestion:providerworkforceauthority>;');
  lines.push('  usf:evidenceSignature <urn:usf:signature:providerworkforceauthorityattestation>;');
  lines.push('  usf:evidenceChecksum <urn:usf:checksum:providerworkforceauthorityevidence>;');
  lines.push('  usf:integrityVerification <urn:usf:integrityverification:providerworkforceauthority>;');
  lines.push(`  usf:applicableToObligation ${obligations};`);
  lines.push('  usf:withinValidityScope true.');
  lines.push('evr:providerworkforcedecisionevaluation a usf:EvidenceResult, usf:CompositeEvidenceResult;');
  lines.push('  usf:canonicalName "providerworkforcedecisionevaluation";');
  lines.push('  usf:evidenceKind evk:attestation;');
  lines.push('  usf:hasFreshness fresh:fresh;');
  lines.push(`  usf:evidenceForContract ${contracts};`);
  lines.push(`  usf:evidenceFor ${contracts};`);
  lines.push(`  usf:contentDigest ${q(evidenceDescriptor.digest)};`);
  lines.push(`  usf:evaluatedAuthorityDigest ${q(evidence.evaluatedAuthorityDigest)};`);
  lines.push(`  usf:evidenceProducerDigest ${q(evidence.proofAlgorithmSourceDigest)};`);
  lines.push(`  usf:mediaType ${q(evidenceDescriptor.mediaType)};`);
  lines.push(`  usf:byteSize ${evidenceDescriptor.byteSize};`);
  lines.push(`  usf:storageLocator ${q(evidenceDescriptor.locator)}^^xsd:anyURI;`);
  lines.push('  usf:wasProducedBy <urn:usf:validatorrule:validateproviderworkforceauthority>;');
  lines.push(`  usf:collectedAt ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
  lines.push(`  usf:validUntil ${q(evidence.validUntil)}^^xsd:dateTime;`);
  lines.push('  usf:hasFreshnessPolicy <urn:usf:evidencefreshnesspolicy:providerworkforcethirtydays>;');
  lines.push('  usf:hasAdmissionState admission:admitted;');
  lines.push('  usf:hasFreshnessState freshnessstate:fresh;');
  lines.push('  usf:hasIntegrityState integritystate:valid;');
  lines.push('  usf:evidenceStage <urn:usf:evidencestage:emitted>, <urn:usf:evidencestage:collected>, <urn:usf:evidencestage:normalised>, <urn:usf:evidencestage:ingested>, <urn:usf:evidencestage:signed>, <urn:usf:evidencestage:integrityverified>;');
  lines.push('  usf:collectedBy <urn:usf:evidencecollection:providerworkforcedecisionevaluation>;');
  lines.push('  usf:normalisedBy <urn:usf:evidencenormalisation:providerworkforceauthority>;');
  lines.push('  usf:ingestedBy <urn:usf:evidenceingestion:providerworkforceauthority>;');
  lines.push('  usf:evidenceSignature <urn:usf:signature:providerworkforceauthorityattestation>;');
  lines.push('  usf:evidenceChecksum <urn:usf:checksum:providerworkforceauthorityevidence>;');
  lines.push('  usf:integrityVerification <urn:usf:integrityverification:providerworkforcedecisionevaluation>;');
  lines.push('  usf:hasSupportingEvidenceManifest <urn:usf:evidencescopemanifest:providerworkforcedeterministicevaluation>, <urn:usf:evidencescopemanifest:providerworkforcehermeticlocal>;');
  lines.push('  usf:withinValidityScope true.');
  lines.push('<urn:usf:evidencefreshnesspolicy:providerworkforcethirtydays> a usf:EvidenceRetentionPolicy;');
  lines.push('  usf:canonicalName "providerworkforcethirtydays".');
  for (const name of ['providerworkforceauthority', 'providerworkforcedecisionevaluation']) {
    lines.push(`<urn:usf:evidenceadmission:${name}> a usf:EvidenceAdmission;`);
    lines.push(`  usf:canonicalName ${q(name)};`);
    lines.push(`  usf:admissionForEvidence evr:${name};`);
    lines.push('  usf:admissionDecidedByValidator <urn:usf:validatorrule:validateproviderworkforceauthority>.');
  }
  for (const { name, requirement } of CONTRACTS) {
    const collection = `providerworkforceauthority${name}`;
    lines.push(`<urn:usf:evidencecollection:${collection}> a usf:EvidenceCollection;`);
    lines.push(`  usf:canonicalName ${q(collection)};`);
    lines.push(`  usf:collectionForRequirement <${requirement}>;`);
    lines.push('  usf:collectedEvidence evr:providerworkforceauthority;');
    lines.push('  usf:collectsEvidence evr:providerworkforceauthority;');
    lines.push(`  usf:collectedOn ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
    lines.push(`  usf:sourceDigest ${q(receipt.dependencySetDigest)}.`);
  }
  lines.push('<urn:usf:evidencecollection:providerworkforcedecisionevaluation> a usf:EvidenceCollection;');
  lines.push('  usf:canonicalName "providerworkforcedecisionevaluation";');
  lines.push('  usf:collectedEvidence evr:providerworkforcedecisionevaluation;');
  lines.push('  usf:collectsEvidence evr:providerworkforcedecisionevaluation;');
  lines.push(`  usf:collectedOn ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
  lines.push(`  usf:sourceDigest ${q(receipt.dependencySetDigest)}.`);
  lines.push('<urn:usf:evidencenormalisation:providerworkforceauthority> a usf:EvidenceNormalisation;');
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push('  usf:normalisesEvidence evr:providerworkforceauthority, evr:providerworkforcedecisionevaluation.');
  lines.push('<urn:usf:evidenceingestion:providerworkforceauthority> a usf:EvidenceIngestion;');
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push('  usf:ingestsEvidence evr:providerworkforceauthority, evr:providerworkforcedecisionevaluation.');
  for (const name of ['providerworkforceauthority', 'providerworkforcedecisionevaluation']) {
    lines.push(`<urn:usf:integrityverification:${name}> a usf:IntegrityVerification;`);
    lines.push(`  usf:canonicalName ${q(name)};`);
    lines.push(`  usf:verifiesEvidence evr:${name};`);
    lines.push('  usf:verificationState <urn:usf:resultstate:passed>.');
  }
  return `${lines.join('\n')}\n`;
}

function proofProjection({
  evidence,
  evidenceDescriptor,
  attestationDescriptor,
  dependencySetDigest,
  dependencyDigestAlgorithm,
  proofProducerCommit,
  proofProducerTree,
  algorithmVersion,
  reevaluationState,
  settledAuthorityDigest,
  reevaluatedAt,
}) {
  const algorithmVersionIri = `urn:usf:proofalgorithmversion:providerworkforceauthority${evidence.proofAlgorithmSourceDigest.slice(7)}`;
  const primaryAlgorithmSourceDigest = evidence.proofAlgorithmSources
    .find(({ path }) => path === PROVIDER_PROOF_PATH).digest;
  const contracts = CONTRACTS.map(({ name }) => iri(`urn:usf:semanticcontract:${name}`)).join(', ');
  const excluded = SELF_PUBLICATION_EXCLUDED_GRAPHS.map((value) => `${q(value)}^^xsd:anyURI`).join(', ');
  const lines = [];
  lines.push('<urn:usf:nonclaim:providerworkforceproofisfactoryvalidation> a usf:NonClaim;');
  lines.push('  usf:canonicalName "providerworkforceproofisfactoryvalidation".');
  lines.push('<urn:usf:nonclaim:providerworkforceproofisproductionreadiness> a usf:NonClaim;');
  lines.push('  usf:canonicalName "providerworkforceproofisproductionreadiness".');
  lines.push(`${PROOF_RESOURCE} a usf:ProofAlgorithm;`);
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push(`  usf:proofAlgorithmSourcePath ${q(PROVIDER_PROOF_PATH)};`);
  lines.push(`  usf:proofAlgorithmSourceDigest ${q(primaryAlgorithmSourceDigest)};`);
  lines.push(`  usf:currentAlgorithmVersion <${algorithmVersionIri}>;`);
  lines.push(`  usf:currentAlgorithmSourceDigest ${q(primaryAlgorithmSourceDigest)};`);
  lines.push(`  usf:currentImplementationSourceSetDigest ${q(evidence.implementationSourceDigest)};`);
  lines.push(`  usf:currentDependencySetDigest ${q(dependencySetDigest)};`);
  lines.push(`  usf:currentDependencyDigestAlgorithm ${q(dependencyDigestAlgorithm)};`);
  lines.push('  usf:requiresGraphSourceBinding true.');
  lines.push(`<${algorithmVersionIri}> a usf:ProofAlgorithmVersion;`);
  lines.push(`  usf:canonicalName ${q(`providerworkforceauthority${evidence.proofAlgorithmSourceDigest.slice(7)}`)};`);
  lines.push('  usf:proofAlgorithmVersionOf <urn:usf:proofalgorithm:providerworkforceauthority>;');
  lines.push(`  usf:proofAlgorithmVersionIdentifier ${q(algorithmVersion)}.`);
  lines.push('<urn:usf:proof:providerworkforceauthority> a usf:Proof;');
  lines.push('  usf:canonicalName "providerworkforceauthority";');
  lines.push('  usf:atRung rung:behaviour;');
  lines.push('  usf:usesProviderMode pmode:deterministictestsubstitute;');
  lines.push('  usf:inEnvironment env:hermetic;');
  lines.push(`  usf:exercises ${contracts};`);
  lines.push(`  usf:provesSubject ${contracts}.`);
  for (const { name, obligation } of CONTRACTS) {
    const suffix = `providerworkforceauthority${name}`;
    const resultIri = `urn:usf:proofresult:${suffix}`;
    const bindingIri = `urn:usf:proofauthoritybinding:${suffix}`;
    lines.push(`<urn:usf:proofexecution:${suffix}> a usf:ProofExecution;`);
    lines.push(`  usf:canonicalName ${q(suffix)};`);
    lines.push('  usf:executesProof <urn:usf:proof:providerworkforceauthority>;');
    lines.push(`  usf:producesResult <${resultIri}>.`);
    lines.push(`<urn:usf:proofevaluation:${suffix}> a usf:ProofEvaluation;`);
    lines.push(`  usf:canonicalName ${q(suffix)};`);
    lines.push(`  usf:evaluatesObligation <${obligation}>;`);
    lines.push(`  usf:producesProofResult <${resultIri}>.`);
    lines.push(`<${resultIri}> a usf:ProofResult;`);
    lines.push(`  usf:canonicalName ${q(suffix)};`);
    lines.push('  usf:resultState rs:passed;');
    lines.push('  usf:resultForProof <urn:usf:proof:providerworkforceauthority>;');
    lines.push('  usf:claimedRung rung:behaviour;');
    lines.push('  usf:observedRung rung:behaviour;');
    lines.push('  usf:hasFreshness fresh:fresh;');
    lines.push('  usf:usesProviderMode pmode:deterministictestsubstitute;');
    lines.push('  usf:inEnvironment env:hermetic;');
    lines.push('  usf:hasProofResultState <urn:usf:proofresultstate:successful>;');
    lines.push(`  usf:proofResultForObligation <${obligation}>;`);
    lines.push('  usf:usesAdmittedEvidence <urn:usf:evidenceresult:providerworkforceauthority>;');
    lines.push(`  usf:evidenceSetDigest ${q(evidence.exactEvidenceSetDigest)};`);
    lines.push('  usf:usesProofAlgorithm <urn:usf:proofalgorithm:providerworkforceauthority>;');
    lines.push(`  usf:usesAlgorithmVersion <${algorithmVersionIri}>;`);
    lines.push(`  usf:implementationSourceSetDigest ${q(evidence.implementationSourceDigest)};`);
    lines.push(`  usf:dependencySetDigest ${q(dependencySetDigest)};`);
    lines.push(`  usf:dependencyDigestAlgorithm ${q(dependencyDigestAlgorithm)};`);
    lines.push(`  usf:proofProducerCommit ${q(proofProducerCommit)};`);
    lines.push(`  usf:proofProducerTree ${q(proofProducerTree)};`);
    lines.push('  usf:evaluatedByValidator <urn:usf:validatorrule:validateproviderworkforceauthority>;');
    lines.push('  usf:proofExecutionEnvironment env:hermetic;');
    lines.push('  usf:hasConfidenceState <urn:usf:proofconfidencestate:warranted>;');
    lines.push('  usf:confidenceBasis <urn:usf:evidenceresult:providerworkforceauthority>;');
    lines.push(`  usf:uncertaintyStatement ${q(`This result proves only the bounded provider-workforce authority claims observed at factory commit ${evidence.factoryCommit}; it does not validate the future provider expansion implementation or establish provider or production availability.`)};`);
    lines.push('  usf:proofNonclaim <urn:usf:nonclaim:providerworkforceproofisfactoryvalidation>, <urn:usf:nonclaim:providerworkforceproofisproductionreadiness>;');
    lines.push(`  usf:evaluatedAt ${q(evidence.evaluatedAt)}^^xsd:dateTime;`);
    lines.push(`  usf:hasAuthorityBinding <${bindingIri}>;`);
    lines.push('  usf:hasInvalidationCondition <urn:usf:proofinvalidationcondition:evidenceinvalidated>, <urn:usf:proofinvalidationcondition:evidencestale>, <urn:usf:proofinvalidationcondition:authoritydigestchanged>.');
    lines.push(`<${bindingIri}> a usf:ProofAuthorityBinding;`);
    lines.push(`  usf:canonicalName ${q(suffix)};`);
    lines.push(`  usf:bindingEvaluatedAuthorityDigest ${q(evidence.evaluatedAuthorityDigest)};`);
    lines.push(`  usf:bindingDependencySetDigest ${q(dependencySetDigest)};`);
    lines.push(`  usf:bindingDependencyDigestAlgorithm ${q(dependencyDigestAlgorithm)};`);
    lines.push('  usf:usesAuthorityBindingRule <urn:usf:authoritybindingrule:selfpublicationclosure>;');
    lines.push('  usf:requiresPostPublicationReevaluation true;');
    lines.push(`  usf:authorityBindingEvidenceDigest ${q(attestationDescriptor.digest)};`);
    lines.push(`  usf:hasPostPublicationReevaluationState <urn:usf:proofreevaluationstate:${reevaluationState}>;`);
    if (reevaluationState === 'successful') {
      lines.push(`  usf:reevaluationSettledAuthorityDigest ${q(settledAuthorityDigest)};`);
      lines.push(`  usf:reevaluationDependencySetDigest ${q(dependencySetDigest)};`);
      lines.push(`  usf:reevaluationEvidenceDigest ${q(attestationDescriptor.digest)};`);
      lines.push(`  usf:reevaluatedAt ${q(reevaluatedAt)}^^xsd:dateTime;`);
    }
    lines.push(`  usf:excludedAuthorityGraphIri ${excluded}.`);
  }
  return `${lines.join('\n')}\n`;
}

export function projectProviderWorkforceAuthorityReceipt({
  receipt,
  evidenceBytes,
  attestationBytes,
  authorityGraphInventory,
  dependencySetDigest: assertedDependencySetDigest = null,
  dependencyDigestAlgorithm = AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  proofProducerCommit,
  proofProducerTree,
  algorithmVersion,
  observedAt,
  reevaluationState = 'pending',
  settledAuthorityDigest = null,
  reevaluatedAt = null,
}) {
  assert(receipt && typeof receipt === 'object' && !Array.isArray(receipt), 'RECEIPT_INVALID');
  assert(receipt.schemaVersion === 1, 'RECEIPT_SCHEMA_UNSUPPORTED');
  assert(receipt.recordKind === 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_RECEIPT', 'RECEIPT_KIND_INVALID');
  assert(receipt.ok === true && receipt.passed === true && receipt.eligibleForAdmission === true, 'RECEIPT_NOT_ELIGIBLE');
  const dependencySetDigest = authorityDependencySetDigest(authorityGraphInventory);
  if (assertedDependencySetDigest !== null) {
    exactDigest(assertedDependencySetDigest, 'DEPENDENCY_SET_DIGEST_INVALID');
    assert(assertedDependencySetDigest === dependencySetDigest, 'DEPENDENCY_SET_DIGEST_MISMATCH');
  }
  assert(dependencyDigestAlgorithm === AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM, 'DEPENDENCY_DIGEST_ALGORITHM_INVALID');
  exactCommit(proofProducerCommit, 'PROOF_PRODUCER_COMMIT_INVALID');
  exactCommit(proofProducerTree, 'PROOF_PRODUCER_TREE_INVALID');
  assert(typeof algorithmVersion === 'string' && /^\d+\.\d+\.\d+$/.test(algorithmVersion), 'ALGORITHM_VERSION_INVALID');
  exactDateTime(observedAt, 'OBSERVED_AT_INVALID');
  assert(reevaluationState === 'pending' || reevaluationState === 'successful', 'REEVALUATION_STATE_INVALID');
  if (reevaluationState === 'successful') {
    exactDigest(settledAuthorityDigest, 'SETTLED_AUTHORITY_DIGEST_INVALID');
    exactDateTime(reevaluatedAt, 'REEVALUATED_AT_INVALID');
    assert(settledAuthorityDigest === receipt.evaluatedAuthorityDigest, 'SETTLED_AUTHORITY_DIGEST_MISMATCH');
  } else {
    assert(settledAuthorityDigest === null && reevaluatedAt === null, 'PENDING_REEVALUATION_HAS_SETTLED_FIELDS');
  }
  const evidenceDescriptor = descriptor(receipt, 'evidenceManifest', evidenceBytes, 'application/json');
  const attestationDescriptor = descriptor(receipt, 'proofAttestation', attestationBytes, 'application/vnd.in-toto+json');
  const evidence = verifyEvidence(receipt, evidenceBytes);
  assert(Date.parse(evidence.evaluatedAt) <= Date.parse(observedAt), 'EVIDENCE_NOT_YET_VALID');
  assert(Date.parse(observedAt) < Date.parse(evidence.validUntil), 'EVIDENCE_EXPIRED');
  if (reevaluationState === 'successful') {
    assert(Date.parse(reevaluatedAt) >= Date.parse(evidence.evaluatedAt)
      && Date.parse(reevaluatedAt) <= Date.parse(observedAt), 'REEVALUATED_AT_OUTSIDE_OBSERVATION');
  }
  const primaryAlgorithmSourceDigest = evidence.proofAlgorithmSources
    .find(({ path }) => path === PROVIDER_PROOF_PATH).digest;
  const attestation = verifyAttestation(receipt, evidence, evidenceDescriptor, attestationBytes);
  const enrichedReceipt = Object.freeze({ ...receipt, dependencySetDigest });
  const evidenceTurtle = evidenceProjection({
    receipt: enrichedReceipt,
    evidence,
    evidenceDescriptor,
    attestationDescriptor,
    attestation,
  });
  const proofsTurtle = proofProjection({
    evidence,
    evidenceDescriptor,
    attestationDescriptor,
    dependencySetDigest,
    dependencyDigestAlgorithm,
    proofProducerCommit,
    proofProducerTree,
    algorithmVersion,
    reevaluationState,
    settledAuthorityDigest,
    reevaluatedAt,
  });
  const metadataCore = {
    schemaVersion: 1,
    recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_RDF_PROJECTION',
    evidenceDigest: evidenceDescriptor.digest,
    attestationDigest: attestationDescriptor.digest,
    exactEvidenceSetDigest: evidence.exactEvidenceSetDigest,
    evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
    dependencySetDigest,
    dependencyDigestAlgorithm,
    implementationSourceDigest: evidence.implementationSourceDigest,
    proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
    primaryAlgorithmSourceDigest,
    proofProducerCommit,
    proofProducerTree,
    algorithmVersion,
    observedAt,
    reevaluationState,
    settledAuthorityDigest,
    reevaluatedAt,
    evidenceProjectionDigest: sha256(evidenceTurtle),
    proofProjectionDigest: sha256(proofsTurtle),
  };
  return Object.freeze({
    evidenceTurtle,
    proofsTurtle,
    metadata: Object.freeze({ ...metadataCore, projectionDigest: sha256(canonicalJson(metadataCore)) }),
  });
}

function replaceExactBlock(source, start, end, replacement, label) {
  const startIndex = source.indexOf(start);
  const secondStart = startIndex < 0 ? -1 : source.indexOf(start, startIndex + start.length);
  const endIndex = source.indexOf(end, startIndex + start.length);
  const secondEnd = endIndex < 0 ? -1 : source.indexOf(end, endIndex + end.length);
  assert(startIndex >= 0 && secondStart < 0 && endIndex > startIndex && secondEnd < 0, `${label}_MARKERS_INVALID`);
  return `${source.slice(0, startIndex).trimEnd()}\n\n${start}\n${replacement.trim()}\n${end}${source.slice(endIndex + end.length)}`;
}

const DEFAULT_FILE_OPERATIONS = Object.freeze({ renameSync, rmSync, writeFileSync });

function stageFile(path, bytes, mode, label, operations) {
  const staged = `${path}.provider-projection-${process.pid}-${label}`;
  operations.writeFileSync(staged, bytes, { flag: 'wx', mode });
  return staged;
}

export function replaceProviderWorkforceAuthorityProjection(
  repositoryRoot,
  projection,
  operations = DEFAULT_FILE_OPERATIONS,
) {
  const root = realpathSync(repositoryRoot);
  const evidencePath = join(root, 'semantic-model/assurance/evidence.trig');
  const proofsPath = join(root, 'semantic-model/assurance/proofs.trig');
  const stats = [];
  for (const path of [evidencePath, proofsPath]) {
    const stat = lstatSync(path);
    assert(!stat.isSymbolicLink() && stat.isFile() && stat.nlink === 1, 'PROJECTION_TARGET_NOT_EXACT_FILE');
    stats.push(stat);
  }
  const evidenceSource = readFileSync(evidencePath, 'utf8');
  const proofsSource = readFileSync(proofsPath, 'utf8');
  const nextEvidence = replaceExactBlock(
    evidenceSource,
    EVIDENCE_START,
    EVIDENCE_END,
    projection.evidenceTurtle,
    'EVIDENCE',
  );
  const nextProofs = replaceExactBlock(
    proofsSource,
    PROOF_START,
    PROOF_END,
    projection.proofsTurtle,
    'PROOF',
  );
  const evidenceStage = stageFile(evidencePath, nextEvidence, stats[0].mode & 0o777, 'evidence', operations);
  const proofStage = stageFile(proofsPath, nextProofs, stats[1].mode & 0o777, 'proof', operations);
  let evidenceReplaced = false;
  let proofReplaced = false;
  try {
    operations.renameSync(evidenceStage, evidencePath);
    evidenceReplaced = true;
    operations.renameSync(proofStage, proofsPath);
    proofReplaced = true;
    assert(sha256(readFileSync(evidencePath)) === sha256(nextEvidence), 'EVIDENCE_REPLACEMENT_VERIFICATION_FAILED');
    assert(sha256(readFileSync(proofsPath)) === sha256(nextProofs), 'PROOF_REPLACEMENT_VERIFICATION_FAILED');
  } catch (error) {
    const rollbackErrors = [];
    for (const [replaced, path, source, mode, label] of [
      [proofReplaced, proofsPath, proofsSource, stats[1].mode & 0o777, 'proof-rollback'],
      [evidenceReplaced, evidencePath, evidenceSource, stats[0].mode & 0o777, 'evidence-rollback'],
    ]) {
      if (!replaced) continue;
      let rollbackStage = null;
      try {
        rollbackStage = stageFile(path, source, mode, label, operations);
        operations.renameSync(rollbackStage, path);
        rollbackStage = null;
        assert(sha256(readFileSync(path)) === sha256(source), `${label.toUpperCase()}_VERIFICATION_FAILED`);
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      } finally {
        if (rollbackStage !== null) {
          try {
            operations.rmSync(rollbackStage, { force: true });
          } catch {
            // Preserve the primary rollback outcome.
          }
        }
      }
    }
    if (rollbackErrors.length) throw new AggregateError([error, ...rollbackErrors], 'PROJECTION_REPLACEMENT_AND_ROLLBACK_FAILED');
    throw error;
  } finally {
    for (const path of [evidenceStage, proofStage]) {
      try {
        operations.rmSync(path, { force: true });
      } catch {
        // A retained stage is inert and cannot replace a source without an
        // explicit later rename; do not mask the authoritative result.
      }
    }
  }
  return Object.freeze({
    evidencePath,
    proofsPath,
    evidenceSourceDigest: sha256(nextEvidence),
    proofSourceDigest: sha256(nextProofs),
  });
}

function parseArguments(argv) {
  const values = {};
  const flags = new Set();
  for (const argument of argv) {
    if (argument === '--apply') {
      flags.add('apply');
      continue;
    }
    const match = /^--([a-z0-9-]+)=(.*)$/.exec(argument);
    assert(match, `ARGUMENT_INVALID_${argument}`);
    assert(!(match[1] in values), `ARGUMENT_DUPLICATE_${match[1]}`);
    values[match[1]] = match[2];
  }
  return { values, flags };
}

function exactInputFile(path, label) {
  assert(typeof path === 'string' && path.length > 0, `${label}_PATH_REQUIRED`);
  assert(!lstatSync(path).isSymbolicLink() && statSync(path).isFile(), `${label}_NOT_EXACT_FILE`);
  return readFileSync(path);
}

function runCli() {
  const { values, flags } = parseArguments(process.argv.slice(2));
  const receiptBytes = exactInputFile(values.receipt, 'RECEIPT');
  let receipt;
  try {
    receipt = JSON.parse(receiptBytes.toString('utf8'));
  } catch {
    throw new Error('RECEIPT_JSON_INVALID');
  }
  const authorityInventory = JSON.parse(exactInputFile(values['authority-inventory'], 'AUTHORITY_INVENTORY').toString('utf8'));
  const projection = projectProviderWorkforceAuthorityReceipt({
    receipt,
    evidenceBytes: exactInputFile(values.evidence, 'EVIDENCE'),
    attestationBytes: exactInputFile(values.attestation, 'ATTESTATION'),
    authorityGraphInventory: authorityInventory.authorityGraphInventory
      || authorityInventory.inventory
      || authorityInventory.authority?.inventory
      || authorityInventory.authorityWitness?.inventory,
    dependencySetDigest: values['dependency-set-digest'],
    dependencyDigestAlgorithm: values['dependency-digest-algorithm'],
    proofProducerCommit: values['proof-producer-commit'],
    proofProducerTree: values['proof-producer-tree'],
    algorithmVersion: values['algorithm-version'],
    observedAt: values['observed-at'],
    reevaluationState: values['reevaluation-state'],
    settledAuthorityDigest: values['settled-authority-digest'] || null,
    reevaluatedAt: values['reevaluated-at'] || null,
  });
  const root = realpathSync(values['repository-root']);
  const outputRoot = resolve(values['output-root']);
  const generatedRoot = resolve(root, '.work');
  assert(outputRoot.startsWith(`${generatedRoot}/`), 'OUTPUT_ROOT_NOT_SESSION_TRANSIENT');
  mkdirSync(outputRoot, { recursive: true, mode: 0o700 });
  writeFileSync(join(outputRoot, 'provider-workforce-authority-evidence-projection.ttl'), projection.evidenceTurtle, { mode: 0o600 });
  writeFileSync(join(outputRoot, 'provider-workforce-authority-proof-projection.ttl'), projection.proofsTurtle, { mode: 0o600 });
  writeFileSync(join(outputRoot, 'provider-workforce-authority-projection.json'),
    `${canonicalJson(projection.metadata)}\n`, { mode: 0o600 });
  const applied = flags.has('apply')
    ? replaceProviderWorkforceAuthorityProjection(root, projection)
    : null;
  process.stdout.write(`${canonicalJson({ ...projection.metadata, applied })}\n`);
}

const mainPath = process.argv[1] ? realpathSync(process.argv[1]) : null;
if (mainPath === fileURLToPath(import.meta.url)) {
  try {
    runCli();
  } catch (error) {
    process.stderr.write(`${error.name}:${error.message}\n`);
    process.exitCode = 1;
  }
}
