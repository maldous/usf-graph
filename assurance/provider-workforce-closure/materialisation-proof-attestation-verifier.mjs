import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify,
} from 'node:crypto';

import {
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  SELF_PUBLICATION_RULE,
} from '../../capabilities/semantic-model-compilation/authority-binding.mjs';

export const MATERIALISATION_EVIDENCE_SCHEMA_VERSION = 4;
export const MATERIALISATION_RECEIPT_SCHEMA_VERSION = 2;
export const MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM =
  'sha256-rdfc10-managed-graph-inventory-v1';

const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const RAW_SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u;
const GRAPH_IRI = /^urn:usf:graph:[a-z0-9:._-]+$/u;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const EVIDENCE_MEDIA_TYPE = 'application/json';
const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
const PREDICATE_TYPE = 'https://in-toto.io/attestation/test-result/v0.1';
const SUBJECT_NAME = 'repository-materialisation-control-plane-evidence';

const utf8Compare = (left, right) => Buffer.compare(
  Buffer.from(String(left), 'utf8'),
  Buffer.from(String(right), 'utf8'),
);
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(
      Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]),
    )
    : value;
export const canonicalMaterialisationJson = (value) => JSON.stringify(stable(value));
export const canonicalMaterialisationReceiptBytes = (receipt) => Buffer.from(
  `${JSON.stringify(stable(receipt), null, 2)}\n`,
);
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function assert(condition, code) {
  if (!condition) throw new Error(code);
}

function exactObjectKeys(value, expected, code) {
  assert(value && typeof value === 'object' && !Array.isArray(value), code);
  const actual = Object.keys(value).sort(utf8Compare);
  const wanted = [...expected].sort(utf8Compare);
  assert(
    actual.length === wanted.length
      && actual.every((key, index) => key === wanted[index]),
    code,
  );
}

function exactDigest(value, code) {
  assert(typeof value === 'string' && SHA256.test(value), code);
  return value;
}

function exactCommit(value, code) {
  assert(typeof value === 'string' && COMMIT.test(value), code);
  return value;
}

function exactDateTime(value, code) {
  assert(typeof value === 'string' && DATE_TIME.test(value)
    && Number.isFinite(Date.parse(value)), code);
  return value;
}

function exactStringSet(value, expected, code) {
  assert(Array.isArray(value) && value.every((item) => typeof item === 'string'), code);
  const actual = [...value].sort(utf8Compare);
  const wanted = [...expected].sort(utf8Compare);
  assert(
    actual.length === wanted.length
      && new Set(actual).size === actual.length
      && actual.every((item, index) => item === wanted[index]),
    code,
  );
}

function parseCanonicalJson(bytes, label) {
  assert(Buffer.isBuffer(bytes), `${label}_BYTES_REQUIRED`);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`${label}_JSON_INVALID`);
  }
  assert(Buffer.from(canonicalMaterialisationJson(value)).equals(bytes),
    `${label}_NOT_CANONICAL_JSON`);
  return value;
}

function parseCanonicalReceipt(receipt, receiptBytes) {
  assert(receipt && typeof receipt === 'object' && !Array.isArray(receipt),
    'MATERIALISATION_RECEIPT_REQUIRED');
  assert(Buffer.isBuffer(receiptBytes), 'MATERIALISATION_RECEIPT_BYTES_REQUIRED');
  let parsed;
  try {
    parsed = JSON.parse(receiptBytes.toString('utf8'));
  } catch {
    throw new Error('MATERIALISATION_RECEIPT_JSON_INVALID');
  }
  assert(canonicalMaterialisationJson(parsed) === canonicalMaterialisationJson(receipt),
    'MATERIALISATION_RECEIPT_OBJECT_BYTES_MISMATCH');
  assert(canonicalMaterialisationReceiptBytes(parsed).equals(receiptBytes),
    'MATERIALISATION_RECEIPT_BYTES_NONCANONICAL');
  return parsed;
}

function exactBase64(value, code) {
  assert(typeof value === 'string' && value.length > 0
    && value.length % 4 === 0 && BASE64.test(value), code);
  const bytes = Buffer.from(value, 'base64');
  assert(bytes.toString('base64') === value, code);
  return bytes;
}

export function candidateAuthorityDigestFromGraphs(candidateGraphs) {
  assert(Array.isArray(candidateGraphs) && candidateGraphs.length > 0,
    'MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_EMPTY');
  const seen = new Set();
  let previous = null;
  let tripleTotal = 0;
  const records = candidateGraphs.map((record) => {
    exactObjectKeys(record, [
      'graph',
      'algorithm',
      'digestAlgorithm',
      'sha256',
      'triples',
    ], 'MATERIALISATION_CANDIDATE_GRAPH_FIELDS_INVALID');
    assert(typeof record.graph === 'string' && GRAPH_IRI.test(record.graph),
      'MATERIALISATION_CANDIDATE_GRAPH_IRI_INVALID');
    assert(previous === null || utf8Compare(previous, record.graph) < 0,
      'MATERIALISATION_CANDIDATE_GRAPH_ORDER_INVALID');
    assert(!seen.has(record.graph), 'MATERIALISATION_CANDIDATE_GRAPH_DUPLICATE');
    assert(record.algorithm === 'RDFC-1.0' && record.digestAlgorithm === 'sha256',
      'MATERIALISATION_CANDIDATE_GRAPH_ALGORITHM_INVALID');
    assert(typeof record.sha256 === 'string' && RAW_SHA256.test(record.sha256),
      'MATERIALISATION_CANDIDATE_GRAPH_DIGEST_INVALID');
    assert(Number.isSafeInteger(record.triples) && record.triples >= 0,
      'MATERIALISATION_CANDIDATE_GRAPH_TRIPLES_INVALID');
    tripleTotal += record.triples;
    assert(Number.isSafeInteger(tripleTotal),
      'MATERIALISATION_CANDIDATE_GRAPH_TRIPLE_TOTAL_INVALID');
    seen.add(record.graph);
    previous = record.graph;
    return Object.freeze({
      graph: record.graph,
      algorithm: record.algorithm,
      digestAlgorithm: record.digestAlgorithm,
      sha256: record.sha256,
      triples: record.triples,
    });
  });
  for (const graph of SELF_PUBLICATION_EXCLUDED_GRAPHS) {
    assert(seen.has(graph), `MATERIALISATION_CANDIDATE_EXCLUDED_GRAPH_ABSENT_${graph}`);
  }
  const body = records
    .map(({ graph, sha256: graphDigest, triples }) => `${graph}=${graphDigest}:${triples}`)
    .join('\n');
  return Object.freeze({
    algorithm: MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM,
    candidateAuthorityDigest: sha256(body),
    candidateGraphs: Object.freeze(records),
    graphCount: records.length,
    tripleTotal,
  });
}

export function candidateDependencyDigestFromGraphs(candidateGraphs) {
  const inventory = candidateAuthorityDigestFromGraphs(candidateGraphs);
  const excluded = new Set(SELF_PUBLICATION_EXCLUDED_GRAPHS);
  const body = inventory.candidateGraphs
    .filter(({ graph }) => !excluded.has(graph))
    .map(({ graph, sha256: graphDigest, triples }) => `${graph}=${graphDigest}:${triples}`)
    .join('\n');
  return Object.freeze({
    ...inventory,
    algorithm: AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
    candidateDependencySetDigest: sha256(`${AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM}\n${body}`),
  });
}

function deterministicIntegrityPublicKey() {
  const seed = createHash('sha256')
    .update('repository-materialisation-control-plane-integrity-key')
    .digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      seed,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(privateKey);
}

function verifyDescriptor(descriptor, bytes, mediaType, label) {
  exactObjectKeys(descriptor, ['digest', 'byteSize', 'mediaType', 'locator'],
    `${label}_DESCRIPTOR_FIELDS_INVALID`);
  const digest = exactDigest(descriptor.digest, `${label}_DIGEST_INVALID`);
  assert(digest === sha256(bytes), `${label}_DIGEST_MISMATCH`);
  assert(descriptor.byteSize === bytes.length, `${label}_BYTE_SIZE_MISMATCH`);
  assert(descriptor.mediaType === mediaType, `${label}_MEDIA_TYPE_MISMATCH`);
  assert(descriptor.locator === `cas://sha256/${digest.slice(7)}`,
    `${label}_LOCATOR_MISMATCH`);
  return Object.freeze({
    digest,
    byteSize: descriptor.byteSize,
    mediaType,
    locator: descriptor.locator,
  });
}

function verifyReceipt(receipt) {
  exactObjectKeys(receipt, [
    'schemaVersion',
    'recordKind',
    'ok',
    'passed',
    'eligibleForAdmission',
    'authorityClaims',
    'evaluatedAuthorityDigest',
    'graphCommit',
    'graphTree',
    'signatureVerification',
    'runner',
    'toolchainDigest',
    'commandResults',
    'candidateGraphInventoryAlgorithm',
    'candidateAuthorityDigest',
    'candidateDependencySetDigest',
    'exactEvidenceSetDigest',
    'implementationSourceDigest',
    'proofAlgorithmSourceDigest',
    'evidenceManifest',
    'proofAttestation',
    'signingKeyFingerprint',
    'caseCount',
    'negativeCaseCount',
    'failureCount',
    'outputRoot',
  ], 'MATERIALISATION_RECEIPT_FIELDS_INVALID');
  assert(receipt.schemaVersion === MATERIALISATION_RECEIPT_SCHEMA_VERSION,
    'MATERIALISATION_RECEIPT_SCHEMA_UNSUPPORTED');
  assert(receipt.recordKind === 'USF_VALIDATION_EVIDENCE_CANDIDATE_RECEIPT',
    'MATERIALISATION_RECEIPT_KIND_INVALID');
  assert(receipt.ok === true && receipt.passed === true
    && receipt.eligibleForAdmission === false,
  'MATERIALISATION_RECEIPT_RESULT_INVALID');
  exactStringSet(receipt.authorityClaims, [], 'MATERIALISATION_RECEIPT_AUTHORITY_CLAIMS_INVALID');
  exactDigest(receipt.evaluatedAuthorityDigest,
    'MATERIALISATION_RECEIPT_AUTHORITY_DIGEST_INVALID');
  exactCommit(receipt.graphCommit, 'MATERIALISATION_RECEIPT_GRAPH_COMMIT_INVALID');
  exactCommit(receipt.graphTree, 'MATERIALISATION_RECEIPT_GRAPH_TREE_INVALID');
  exactDigest(receipt.toolchainDigest, 'MATERIALISATION_RECEIPT_TOOLCHAIN_DIGEST_INVALID');
  exactDigest(receipt.candidateAuthorityDigest,
    'MATERIALISATION_RECEIPT_CANDIDATE_AUTHORITY_DIGEST_INVALID');
  exactDigest(receipt.candidateDependencySetDigest,
    'MATERIALISATION_RECEIPT_CANDIDATE_DEPENDENCY_DIGEST_INVALID');
  exactDigest(receipt.exactEvidenceSetDigest,
    'MATERIALISATION_RECEIPT_EVIDENCE_SET_DIGEST_INVALID');
  exactDigest(receipt.implementationSourceDigest,
    'MATERIALISATION_RECEIPT_IMPLEMENTATION_DIGEST_INVALID');
  exactDigest(receipt.proofAlgorithmSourceDigest,
    'MATERIALISATION_RECEIPT_ALGORITHM_DIGEST_INVALID');
  assert(receipt.candidateGraphInventoryAlgorithm
    === MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM,
  'MATERIALISATION_RECEIPT_CANDIDATE_ALGORITHM_INVALID');
  assert(Array.isArray(receipt.commandResults),
    'MATERIALISATION_RECEIPT_COMMAND_RESULTS_INVALID');
  assert(Number.isSafeInteger(receipt.caseCount) && receipt.caseCount > 0
    && Number.isSafeInteger(receipt.negativeCaseCount)
    && receipt.negativeCaseCount >= 0
    && receipt.negativeCaseCount <= receipt.caseCount
    && receipt.failureCount === 0,
  'MATERIALISATION_RECEIPT_CASE_COUNTS_INVALID');
  assert(typeof receipt.outputRoot === 'string' && receipt.outputRoot.length > 0,
    'MATERIALISATION_RECEIPT_OUTPUT_ROOT_INVALID');
  return receipt;
}

function verifyEvidence(receipt, evidenceBytes) {
  const evidence = parseCanonicalJson(evidenceBytes, 'MATERIALISATION_EVIDENCE');
  exactObjectKeys(evidence, [
    'schemaVersion',
    'recordKind',
    'passed',
    'eligibleForAdmission',
    'authorityClaims',
    'evaluatedAt',
    'evaluatedAuthorityDigest',
    'graphCommit',
    'graphTree',
    'signatureVerification',
    'runner',
    'toolchain',
    'toolchainDigest',
    'validationCommands',
    'commandResults',
    'candidateGraphInventoryAlgorithm',
    'candidateGraphs',
    'candidateAuthorityDigest',
    'candidateDependencySetDigest',
    'dependencyDigestAlgorithm',
    'authorityBindingRule',
    'excludedAuthorityGraphs',
    'implementationSourceDigest',
    'implementationSources',
    'proofAlgorithmSourceDigest',
    'environmentClass',
    'providerMode',
    'cases',
    'measurements',
    'nonclaims',
    'exactEvidenceSetDigest',
  ], 'MATERIALISATION_EVIDENCE_FIELDS_INVALID');
  assert(evidence.schemaVersion === MATERIALISATION_EVIDENCE_SCHEMA_VERSION,
    'MATERIALISATION_EVIDENCE_SCHEMA_UNSUPPORTED');
  assert(evidence.recordKind === 'USF_VALIDATION_EVIDENCE_CANDIDATE',
    'MATERIALISATION_EVIDENCE_KIND_INVALID');
  assert(evidence.passed === true && evidence.eligibleForAdmission === false,
    'MATERIALISATION_EVIDENCE_RESULT_INVALID');
  exactStringSet(evidence.authorityClaims, [],
    'MATERIALISATION_EVIDENCE_AUTHORITY_CLAIMS_INVALID');
  exactDateTime(evidence.evaluatedAt, 'MATERIALISATION_EVIDENCE_EVALUATED_AT_INVALID');
  exactDigest(evidence.evaluatedAuthorityDigest,
    'MATERIALISATION_EVIDENCE_AUTHORITY_DIGEST_INVALID');
  exactCommit(evidence.graphCommit, 'MATERIALISATION_EVIDENCE_GRAPH_COMMIT_INVALID');
  exactCommit(evidence.graphTree, 'MATERIALISATION_EVIDENCE_GRAPH_TREE_INVALID');
  exactDigest(evidence.toolchainDigest, 'MATERIALISATION_EVIDENCE_TOOLCHAIN_DIGEST_INVALID');
  exactDigest(evidence.implementationSourceDigest,
    'MATERIALISATION_EVIDENCE_IMPLEMENTATION_DIGEST_INVALID');
  exactDigest(evidence.proofAlgorithmSourceDigest,
    'MATERIALISATION_EVIDENCE_ALGORITHM_DIGEST_INVALID');
  assert(evidence.candidateGraphInventoryAlgorithm
    === MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM,
  'MATERIALISATION_EVIDENCE_CANDIDATE_ALGORITHM_INVALID');
  assert(evidence.dependencyDigestAlgorithm === AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
    'MATERIALISATION_EVIDENCE_DEPENDENCY_ALGORITHM_INVALID');
  assert(evidence.authorityBindingRule === SELF_PUBLICATION_RULE,
    'MATERIALISATION_EVIDENCE_AUTHORITY_BINDING_RULE_INVALID');
  exactStringSet(evidence.excludedAuthorityGraphs, SELF_PUBLICATION_EXCLUDED_GRAPHS,
    'MATERIALISATION_EVIDENCE_EXCLUDED_GRAPH_SET_INVALID');
  assert(Array.isArray(evidence.cases) && evidence.cases.length > 0,
    'MATERIALISATION_EVIDENCE_CASES_INVALID');
  assert(evidence.cases.every((item) => item && typeof item === 'object'
    && typeof item.id === 'string' && item.id.length > 0 && item.passed === true),
  'MATERIALISATION_EVIDENCE_CASE_FAILED');
  assert(new Set(evidence.cases.map(({ id }) => id)).size === evidence.cases.length,
    'MATERIALISATION_EVIDENCE_CASE_ID_DUPLICATE');
  exactObjectKeys(evidence.measurements, [
    'candidateGraphCount',
    'focusedTestCount',
    'materialisationRuleCount',
    'pathRoleCount',
  ], 'MATERIALISATION_EVIDENCE_MEASUREMENTS_FIELDS_INVALID');
  assert(Number.isSafeInteger(evidence.measurements.candidateGraphCount)
    && Number.isSafeInteger(evidence.measurements.focusedTestCount)
    && Number.isSafeInteger(evidence.measurements.materialisationRuleCount)
    && Number.isSafeInteger(evidence.measurements.pathRoleCount)
    && evidence.measurements.focusedTestCount > 0
    && evidence.measurements.materialisationRuleCount > 0
    && evidence.measurements.pathRoleCount > 0,
  'MATERIALISATION_EVIDENCE_MEASUREMENTS_INVALID');
  assert(evidence.environmentClass === 'urn:usf:environmentclass:hermetic'
    && evidence.providerMode === 'urn:usf:providermode:deterministictestsubstitute',
  'MATERIALISATION_EVIDENCE_EXECUTION_CLASS_INVALID');
  assert(Array.isArray(evidence.validationCommands)
    && Array.isArray(evidence.commandResults)
    && Array.isArray(evidence.implementationSources)
    && evidence.implementationSources.length > 0
    && Array.isArray(evidence.nonclaims)
    && evidence.nonclaims.every((item) => typeof item === 'string'),
  'MATERIALISATION_EVIDENCE_COLLECTION_INVALID');

  const inventory = candidateDependencyDigestFromGraphs(evidence.candidateGraphs);
  assert(evidence.measurements.candidateGraphCount === inventory.graphCount,
    'MATERIALISATION_EVIDENCE_CANDIDATE_GRAPH_COUNT_MISMATCH');
  assert(evidence.candidateAuthorityDigest === inventory.candidateAuthorityDigest,
    'MATERIALISATION_EVIDENCE_CANDIDATE_AUTHORITY_DIGEST_MISMATCH');
  assert(evidence.candidateDependencySetDigest === inventory.candidateDependencySetDigest,
    'MATERIALISATION_EVIDENCE_CANDIDATE_DEPENDENCY_DIGEST_MISMATCH');

  const exactEvidenceSetDigest = exactDigest(
    evidence.exactEvidenceSetDigest,
    'MATERIALISATION_EVIDENCE_SET_DIGEST_INVALID',
  );
  const { exactEvidenceSetDigest: omitted, ...evidenceCore } = evidence;
  assert(exactEvidenceSetDigest === sha256(canonicalMaterialisationJson(evidenceCore)),
    'MATERIALISATION_EVIDENCE_SET_DIGEST_MISMATCH');

  for (const key of [
    'evaluatedAuthorityDigest',
    'graphCommit',
    'graphTree',
    'toolchainDigest',
    'candidateGraphInventoryAlgorithm',
    'candidateAuthorityDigest',
    'candidateDependencySetDigest',
    'exactEvidenceSetDigest',
    'implementationSourceDigest',
    'proofAlgorithmSourceDigest',
  ]) {
    assert(receipt[key] === evidence[key],
      `MATERIALISATION_RECEIPT_EVIDENCE_${key.toUpperCase()}_MISMATCH`);
  }
  assert(canonicalMaterialisationJson(receipt.authorityClaims)
    === canonicalMaterialisationJson(evidence.authorityClaims),
  'MATERIALISATION_RECEIPT_EVIDENCE_AUTHORITY_CLAIMS_MISMATCH');
  assert(canonicalMaterialisationJson(receipt.signatureVerification)
    === canonicalMaterialisationJson(evidence.signatureVerification),
  'MATERIALISATION_RECEIPT_EVIDENCE_SIGNATURE_VERIFICATION_MISMATCH');
  assert(canonicalMaterialisationJson(receipt.runner)
    === canonicalMaterialisationJson(evidence.runner),
  'MATERIALISATION_RECEIPT_EVIDENCE_RUNNER_MISMATCH');
  assert(canonicalMaterialisationJson(receipt.commandResults)
    === canonicalMaterialisationJson(evidence.commandResults),
  'MATERIALISATION_RECEIPT_EVIDENCE_COMMAND_RESULTS_MISMATCH');
  assert(receipt.caseCount === evidence.cases.length
    && receipt.negativeCaseCount
      === evidence.cases.filter(({ negative }) => negative === true).length
    && receipt.failureCount === evidence.cases.filter(({ passed }) => passed !== true).length,
  'MATERIALISATION_RECEIPT_EVIDENCE_CASE_COUNTS_MISMATCH');
  return Object.freeze({ evidence, inventory });
}

function verifyAttestation({
  receipt,
  evidence,
  evidenceDescriptor,
  attestationBytes,
}) {
  const envelope = parseCanonicalJson(attestationBytes, 'MATERIALISATION_ATTESTATION');
  exactObjectKeys(envelope, ['payloadType', 'payload', 'signatures'],
    'MATERIALISATION_ATTESTATION_FIELDS_INVALID');
  assert(envelope.payloadType === PAYLOAD_TYPE,
    'MATERIALISATION_ATTESTATION_PAYLOAD_TYPE_INVALID');
  assert(Array.isArray(envelope.signatures) && envelope.signatures.length === 1,
    'MATERIALISATION_ATTESTATION_SIGNATURE_COUNT_INVALID');
  const signature = envelope.signatures[0];
  exactObjectKeys(signature, ['keyid', 'sig'],
    'MATERIALISATION_ATTESTATION_SIGNATURE_FIELDS_INVALID');
  const publicKey = deterministicIntegrityPublicKey();
  const expectedKeyId = sha256(
    publicKey.export({ type: 'spki', format: 'der' }),
  ).slice(7);
  assert(signature.keyid === expectedKeyId
    && receipt.signingKeyFingerprint === expectedKeyId,
  'MATERIALISATION_ATTESTATION_KEY_ID_MISMATCH');
  const signatureBytes = exactBase64(
    signature.sig,
    'MATERIALISATION_ATTESTATION_SIGNATURE_BASE64_INVALID',
  );
  const statementBytes = exactBase64(
    envelope.payload,
    'MATERIALISATION_ATTESTATION_PAYLOAD_BASE64_INVALID',
  );
  const statement = parseCanonicalJson(
    statementBytes,
    'MATERIALISATION_ATTESTATION_STATEMENT',
  );
  const pae = Buffer.concat([
    Buffer.from(
      `DSSEv1 ${Buffer.byteLength(PAYLOAD_TYPE)} ${PAYLOAD_TYPE} ${statementBytes.length} `,
    ),
    statementBytes,
  ]);
  assert(verify(null, pae, publicKey, signatureBytes),
    'MATERIALISATION_ATTESTATION_SIGNATURE_VERIFICATION_FAILED');
  exactObjectKeys(statement, ['_type', 'subject', 'predicateType', 'predicate'],
    'MATERIALISATION_ATTESTATION_STATEMENT_FIELDS_INVALID');
  assert(statement._type === STATEMENT_TYPE,
    'MATERIALISATION_ATTESTATION_STATEMENT_TYPE_INVALID');
  assert(statement.predicateType === PREDICATE_TYPE,
    'MATERIALISATION_ATTESTATION_PREDICATE_TYPE_INVALID');
  assert(Array.isArray(statement.subject) && statement.subject.length === 1,
    'MATERIALISATION_ATTESTATION_SUBJECT_COUNT_INVALID');
  exactObjectKeys(statement.subject[0], ['name', 'digest'],
    'MATERIALISATION_ATTESTATION_SUBJECT_FIELDS_INVALID');
  exactObjectKeys(statement.subject[0].digest, ['sha256'],
    'MATERIALISATION_ATTESTATION_SUBJECT_DIGEST_FIELDS_INVALID');
  assert(statement.subject[0].name === SUBJECT_NAME,
    'MATERIALISATION_ATTESTATION_SUBJECT_NAME_INVALID');
  assert(statement.subject[0].digest.sha256 === evidenceDescriptor.digest.slice(7),
    'MATERIALISATION_ATTESTATION_SUBJECT_DIGEST_MISMATCH');
  exactObjectKeys(statement.predicate, [
    'evidenceSchemaVersion',
    'evaluatedAuthorityDigest',
    'candidateGraphInventoryAlgorithm',
    'candidateAuthorityDigest',
    'candidateDependencySetDigest',
    'exactEvidenceSetDigest',
    'implementationSourceDigest',
    'proofAlgorithmSourceDigest',
    'result',
  ], 'MATERIALISATION_ATTESTATION_PREDICATE_FIELDS_INVALID');
  assert(statement.predicate.evidenceSchemaVersion
    === MATERIALISATION_EVIDENCE_SCHEMA_VERSION,
  'MATERIALISATION_ATTESTATION_EVIDENCE_SCHEMA_MISMATCH');
  for (const key of [
    'evaluatedAuthorityDigest',
    'candidateGraphInventoryAlgorithm',
    'candidateAuthorityDigest',
    'candidateDependencySetDigest',
    'exactEvidenceSetDigest',
    'implementationSourceDigest',
    'proofAlgorithmSourceDigest',
  ]) {
    assert(statement.predicate[key] === evidence[key],
      `MATERIALISATION_ATTESTATION_${key.toUpperCase()}_MISMATCH`);
    assert(statement.predicate[key] === receipt[key],
      `MATERIALISATION_ATTESTATION_RECEIPT_${key.toUpperCase()}_MISMATCH`);
  }
  assert(statement.predicate.result === 'passed',
    'MATERIALISATION_ATTESTATION_RESULT_INVALID');
  return Object.freeze({ envelope, signature, statement });
}

export function verifyMaterialisationProofAttestation({
  receipt,
  receiptBytes,
  evidenceBytes,
  attestationBytes,
}) {
  const parsedReceipt = verifyReceipt(parseCanonicalReceipt(receipt, receiptBytes));
  const evidenceDescriptor = verifyDescriptor(
    parsedReceipt.evidenceManifest,
    evidenceBytes,
    EVIDENCE_MEDIA_TYPE,
    'MATERIALISATION_EVIDENCE',
  );
  const attestationDescriptor = verifyDescriptor(
    parsedReceipt.proofAttestation,
    attestationBytes,
    PAYLOAD_TYPE,
    'MATERIALISATION_ATTESTATION',
  );
  const verifiedEvidence = verifyEvidence(parsedReceipt, evidenceBytes);
  const attestation = verifyAttestation({
    receipt: parsedReceipt,
    evidence: verifiedEvidence.evidence,
    evidenceDescriptor,
    attestationBytes,
  });
  return Object.freeze({
    receipt: Object.freeze(parsedReceipt),
    evidence: verifiedEvidence.evidence,
    statement: attestation.statement,
    candidateGraphs: verifiedEvidence.inventory.candidateGraphs,
    candidateGraphInventoryAlgorithm:
      MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM,
    candidateAuthorityDigest:
      verifiedEvidence.inventory.candidateAuthorityDigest,
    candidateDependencySetDigest:
      verifiedEvidence.inventory.candidateDependencySetDigest,
    evidenceDescriptor,
    attestationDescriptor,
    signingKeyFingerprint: attestation.signature.keyid,
  });
}
