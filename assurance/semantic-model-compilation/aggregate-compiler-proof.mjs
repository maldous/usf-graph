import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { isAbsolute, posix } from 'node:path';
import { TextDecoder } from 'node:util';

import {
  assertSemanticProofPublicationReceipt,
  canonicalJson as semanticProofCanonicalJson,
  publicationReceiptDigest as semanticProofPublicationReceiptDigest,
  sourceScopeDigest as semanticProofSourceScopeDigest,
} from '../../processes/semantic-assurance/semantic-proof-v1.mjs';

export const AGGREGATE_ALGORITHM_VERSION = '2.1.0';
export const AGGREGATE_REPOSITORY = 'maldous/usf-graph';
export const GIT_EXECUTABLE = '/usr/bin/git';
export const ORPHANED_ATTESTATION_DIGEST = 'sha256:a7148e9b618f5dda16b588e45739742e0aa6ea0ae34dd5639daa41a6eed8224d';
export const SHARED_HERMETIC_RESULTS = Object.freeze([
  'urn:usf:proofresult:compilercontractbehaviour',
  'urn:usf:proofresult:compilerhermeticsubstitute',
]);
export const SHARED_HERMETIC_EVIDENCE = Object.freeze([
  Object.freeze({
    iri: 'urn:usf:evidenceresult:compilerhermeticsubstituteruntime',
    digest: 'sha256:ac5490b46604ca6eb25d739248eb9fb6a188dd7d587edf6215c61b1a593f787c',
  }),
  Object.freeze({
    iri: 'urn:usf:evidenceresult:compilerhermeticsubstitutevalidation',
    digest: 'sha256:ac5490b46604ca6eb25d739248eb9fb6a188dd7d587edf6215c61b1a593f787c',
  }),
]);
export const SHARED_LIVE_AUTHORITY_RESULTS = Object.freeze([
  'urn:usf:proofresult:compilerliveauthoritycontrol',
]);
export const SHARED_LIVE_AUTHORITY_EVIDENCE = Object.freeze([
  Object.freeze({
    iri: 'urn:usf:evidenceresult:compilerliveauthorityruntime',
    digest: 'sha256:164c0f372063fe1b0addd39127a5380bcf15e3db5014283a9a62a671f41aff55',
  }),
  Object.freeze({
    iri: 'urn:usf:evidenceresult:compilerliveauthoritytransactionvalidation',
    digest: 'sha256:164c0f372063fe1b0addd39127a5380bcf15e3db5014283a9a62a671f41aff55',
  }),
]);
export const COMPONENT_PROOFS = Object.freeze([
  Object.freeze({
    dimension: 'compilercontractbehaviour',
    obligation: 'urn:usf:proofobligation:p10cc239b81b3890d5714e8996d369bd08394965220eae7c34aa7c3ccbfc2467b',
    result: 'urn:usf:proofresult:compilercontractbehaviour',
  }),
  Object.freeze({
    dimension: 'hermeticsubstitutebehaviour',
    obligation: 'urn:usf:proofobligation:compilersemantics',
    result: 'urn:usf:proofresult:compilerhermeticsubstitute',
  }),
  Object.freeze({
    dimension: 'importedauthoritycounterfactualadequacy',
    obligation: 'urn:usf:proofobligation:importedauthoritycounterfactualadequacy',
    result: 'urn:usf:proofresult:importedauthoritycounterfactualadequacy',
  }),
  Object.freeze({
    dimension: 'liveauthoritycontrol',
    obligation: 'urn:usf:proofobligation:compilerliveauthoritycontrol',
    result: 'urn:usf:proofresult:compilerliveauthoritycontrol',
  }),
]);

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const IRI = /^[a-z][a-z0-9+.-]*:[^\s]+$/i;
const RFC3339_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CURRENTNESS_PRODUCER = 'urn:usf:validationproducer:authoritycurrentnessprojection';
const HISTORICAL_RESULT_SCHEMA = 'usf-component-proof-result-v1';
const CURRENTNESS_SCHEMA = 'usf-authority-component-currentness-v1';
const CURRENTNESS_RECEIPT_SCHEMA = 'usf-authority-currentness-projection-receipt-v1';
const REEVALUATION_EXECUTION_SCHEMA = 'aggregate-post-publication-execution-v1';
const REEVALUATION_EVALUATION_SCHEMA = 'aggregate-post-publication-evaluation-v1';

const stable = (value) => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256Bytes = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const sha256 = (value) => sha256Bytes(Buffer.from(value, 'utf8'));

export const AGGREGATE_ALGORITHM = Object.freeze({
  algorithm: 'compiler-four-component-authority-currentness-v2',
  authority_currentness_snapshot_required: true,
  complete_set_enforcing: true,
  component_proofs: COMPONENT_PROOFS,
  deterministic: true,
  duplicate_evidence_rejecting: true,
  evidence_bytes_digest_recomputed: true,
  historical_result_bindings_preserved: true,
  post_publication_reevaluation_required_for_selection: true,
  source_repository: AGGREGATE_REPOSITORY,
  source_tree_and_reachability_verified: true,
  version: AGGREGATE_ALGORITHM_VERSION,
});
export const AGGREGATE_ALGORITHM_DIGEST = sha256(canonicalJson(AGGREGATE_ALGORITHM));
export const COMPONENT_SET_DIGEST = sha256(canonicalJson(COMPONENT_PROOFS));

function fail(code, detail) {
  const error = new Error(`${code}: ${detail}`);
  error.code = code;
  throw error;
}

function plainObject(value, code, detail) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) fail(code, detail);
  return value;
}

function exactKeys(value, keys, code, detail) {
  plainObject(value, code, detail);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(code, `${detail}; expected ${expected.join(',')}, received ${actual.join(',')}`);
  }
}

function validTime(value, code, detail) {
  if (!RFC3339_SECOND.test(value || '')) fail(code, detail);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)
      || new Date(milliseconds).toISOString().replace('.000Z', 'Z') !== value) fail(code, detail);
  return milliseconds;
}

function decodeCanonicalBase64(value, code, detail) {
  if (typeof value !== 'string' || value.length === 0) fail(code, detail);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || bytes.toString('base64') !== value) fail(code, detail);
  return bytes;
}

function canonicalJsonBlob(blob, label) {
  exactKeys(blob, ['bytesBase64', 'digest'], 'AGGREGATE_IMMUTABLE_RECORD_INVALID', label);
  if (!SHA256.test(blob.digest || '')) fail('AGGREGATE_IMMUTABLE_RECORD_INVALID', `${label} digest`);
  const bytes = decodeCanonicalBase64(blob.bytesBase64, 'AGGREGATE_IMMUTABLE_RECORD_INVALID', `${label} bytes`);
  const actualDigest = sha256Bytes(bytes);
  if (actualDigest !== blob.digest) fail('AGGREGATE_IMMUTABLE_RECORD_DIGEST_MISMATCH', label);
  let value;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = JSON.parse(text);
  } catch {
    fail('AGGREGATE_IMMUTABLE_RECORD_INVALID', `${label} is not canonical UTF-8 JSON`);
  }
  if (canonicalJson(value) !== text) fail('AGGREGATE_IMMUTABLE_RECORD_NONCANONICAL', label);
  plainObject(value, 'AGGREGATE_IMMUTABLE_RECORD_INVALID', label);
  return { digest: actualDigest, value };
}

function semanticProofPublicationReceiptBlob(blob) {
  exactKeys(blob, ['bytesBase64', 'digest'], 'AGGREGATE_PUBLICATION_RECEIPT_INVALID', 'publication receipt');
  if (!SHA256.test(blob.digest || '')) fail('AGGREGATE_PUBLICATION_RECEIPT_INVALID', 'publication receipt digest');
  const bytes = decodeCanonicalBase64(blob.bytesBase64,
    'AGGREGATE_PUBLICATION_RECEIPT_INVALID', 'publication receipt bytes');
  const actualDigest = sha256Bytes(bytes);
  if (actualDigest !== blob.digest) fail('AGGREGATE_IMMUTABLE_RECORD_DIGEST_MISMATCH', 'publication receipt');
  let receipt;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!text.endsWith('\n') || text.endsWith('\n\n')) throw new Error('receipt LF framing is invalid');
    receipt = JSON.parse(text.slice(0, -1));
  } catch {
    fail('AGGREGATE_PUBLICATION_RECEIPT_INVALID', 'publication receipt is not LF-framed canonical UTF-8 JSON');
  }
  if (`${semanticProofCanonicalJson(receipt)}\n` !== text
      || semanticProofPublicationReceiptDigest(receipt) !== actualDigest) {
    fail('AGGREGATE_PUBLICATION_RECEIPT_NONCANONICAL', 'publication receipt');
  }
  if (!Object.hasOwn(receipt, 'published_at')) {
    fail('AGGREGATE_PUBLICATION_RECEIPT_INVALID', 'published_at is required');
  }
  try {
    assertSemanticProofPublicationReceipt(receipt);
  } catch (fullReceiptError) {
    const protocolReceiptFields = { ...receipt };
    delete protocolReceiptFields.published_at;
    try {
      assertSemanticProofPublicationReceipt(protocolReceiptFields);
    } catch {
      fail('AGGREGATE_PUBLICATION_RECEIPT_INVALID', fullReceiptError.message);
    }
  }
  return { digest: actualDigest, value: receipt };
}

function normalizedDescriptors(descriptors) {
  return descriptors.map(({ iri, digest }) => ({ iri, digest }))
    .sort((left, right) => left.iri.localeCompare(right.iri) || left.digest.localeCompare(right.digest));
}

function descriptorSetDigest(descriptors) {
  return sha256(canonicalJson(normalizedDescriptors(descriptors)));
}

function sourceBindingDigest(sourceBinding) {
  return sha256(canonicalJson(sourceBinding));
}

export function productionGitSourceBindingDependency({ args, executable, repositoryPath }) {
  if (executable !== GIT_EXECUTABLE) fail('AGGREGATE_GIT_EXECUTABLE_INVALID', String(executable));
  let executableStat;
  try {
    executableStat = lstatSync(GIT_EXECUTABLE);
  } catch {
    fail('AGGREGATE_GIT_EXECUTABLE_INVALID', GIT_EXECUTABLE);
  }
  if (!executableStat.isFile() || executableStat.uid !== 0 || (executableStat.mode & 0o022) !== 0
      || (executableStat.mode & 0o111) === 0) {
    fail('AGGREGATE_GIT_EXECUTABLE_INVALID', GIT_EXECUTABLE);
  }
  const result = spawnSync(GIT_EXECUTABLE, ['-C', repositoryPath, ...args], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
  });
  if (result.error) fail('AGGREGATE_SOURCE_DEPENDENCY_FAILURE', result.error.message);
  return { status: result.status, stderr: result.stderr, stdout: result.stdout };
}

function git(repositoryPath, args, code, detail, sourceBindingDependency) {
  if (typeof sourceBindingDependency !== 'function') {
    fail('AGGREGATE_SOURCE_DEPENDENCY_INVALID', 'source-binding dependency must be callable');
  }
  let result;
  try {
    result = sourceBindingDependency(Object.freeze({
      args: Object.freeze([...args]),
      executable: GIT_EXECUTABLE,
      repositoryPath,
    }));
  } catch (error) {
    fail('AGGREGATE_SOURCE_DEPENDENCY_FAILURE', error.message);
  }
  exactKeys(result, ['status', 'stderr', 'stdout'],
    'AGGREGATE_SOURCE_DEPENDENCY_INVALID', 'source-binding dependency response');
  if (!Number.isInteger(result.status) || typeof result.stderr !== 'string' || typeof result.stdout !== 'string') {
    fail('AGGREGATE_SOURCE_DEPENDENCY_INVALID', 'source-binding dependency response types');
  }
  if (result.status !== 0) fail(code, detail);
  return result.stdout.trim();
}

function normalizeSourceBinding(sourceBinding, repositoryPath, sourceBindingDependency) {
  exactKeys(sourceBinding, ['head', 'reachableFrom', 'repository', 'sourcePaths', 'sourceScopeDigest', 'tree'],
    'AGGREGATE_SOURCE_BINDING_INVALID', 'aggregate source binding');
  if (sourceBinding.repository !== AGGREGATE_REPOSITORY) {
    fail('AGGREGATE_SOURCE_REPOSITORY_MISMATCH', sourceBinding.repository || 'absent');
  }
  if (!GIT_OBJECT.test(sourceBinding.head || '') || !GIT_OBJECT.test(sourceBinding.tree || '')) {
    fail('AGGREGATE_SOURCE_BINDING_INVALID', 'HEAD and tree must be exact Git object IDs');
  }
  if (typeof sourceBinding.reachableFrom !== 'string'
      || !/^refs\/(heads|remotes|tags)\/[A-Za-z0-9._/-]+$/.test(sourceBinding.reachableFrom)
      || sourceBinding.reachableFrom.includes('..')) {
    fail('AGGREGATE_SOURCE_BINDING_INVALID', 'reachable ref must be an exact full ref');
  }
  if (!Array.isArray(sourceBinding.sourcePaths) || sourceBinding.sourcePaths.length === 0) {
    fail('AGGREGATE_SOURCE_SCOPE_INVALID', 'source paths are absent');
  }
  const sourcePaths = sourceBinding.sourcePaths.map((path) => {
    if (typeof path !== 'string' || path.length === 0 || path.includes('\\') || path.includes(':')
        || path.startsWith('/') || posix.normalize(path) !== path || path === '.' || path.startsWith('../')) {
      fail('AGGREGATE_SOURCE_SCOPE_INVALID', String(path));
    }
    return path;
  });
  const sortedPaths = [...sourcePaths].sort();
  if (new Set(sourcePaths).size !== sourcePaths.length
      || sourcePaths.some((path, index) => path !== sortedPaths[index])) {
    fail('AGGREGATE_SOURCE_SCOPE_INVALID', 'source paths must be unique and canonically ordered');
  }
  const expectedScopeDigest = semanticProofSourceScopeDigest(sourcePaths);
  if (sourceBinding.sourceScopeDigest !== expectedScopeDigest) {
    fail('AGGREGATE_SOURCE_SCOPE_DIGEST_MISMATCH', sourceBinding.sourceScopeDigest || 'absent');
  }
  if (typeof repositoryPath !== 'string' || !isAbsolute(repositoryPath)) {
    fail('AGGREGATE_SOURCE_REPOSITORY_INVALID', 'an absolute repository path is required');
  }
  const resolvedHead = git(repositoryPath, ['rev-parse', '--verify', `${sourceBinding.head}^{commit}`],
    'AGGREGATE_SOURCE_HEAD_UNREACHABLE', sourceBinding.head, sourceBindingDependency);
  if (resolvedHead !== sourceBinding.head) fail('AGGREGATE_SOURCE_HEAD_UNREACHABLE', sourceBinding.head);
  git(repositoryPath, ['rev-parse', '--verify', `${sourceBinding.reachableFrom}^{commit}`],
    'AGGREGATE_SOURCE_REF_UNREACHABLE', sourceBinding.reachableFrom, sourceBindingDependency);
  git(repositoryPath, ['merge-base', '--is-ancestor', sourceBinding.head, sourceBinding.reachableFrom],
    'AGGREGATE_SOURCE_HEAD_UNREACHABLE', `${sourceBinding.head} from ${sourceBinding.reachableFrom}`,
    sourceBindingDependency);
  const resolvedTree = git(repositoryPath, ['rev-parse', `${sourceBinding.head}^{tree}`],
    'AGGREGATE_SOURCE_TREE_MISMATCH', sourceBinding.head, sourceBindingDependency);
  if (resolvedTree !== sourceBinding.tree) fail('AGGREGATE_SOURCE_TREE_MISMATCH', sourceBinding.tree);
  for (const path of sourcePaths) {
    git(repositoryPath, ['cat-file', '-e', `${sourceBinding.head}:${path}`],
      'AGGREGATE_SOURCE_SCOPE_UNREACHABLE', path, sourceBindingDependency);
  }
  return {
    head: sourceBinding.head,
    reachableFrom: sourceBinding.reachableFrom,
    repository: sourceBinding.repository,
    sourcePaths,
    sourceScopeDigest: expectedScopeDigest,
    tree: sourceBinding.tree,
  };
}

function normalizeHistoricalSourceBinding(value, result) {
  exactKeys(value, ['proofAlgorithm', 'proofAlgorithmSourceDigest', 'proofAlgorithmVersion'],
    'AGGREGATE_HISTORICAL_SOURCE_BINDING_INVALID', result);
  if (!IRI.test(value.proofAlgorithm || '') || !IRI.test(value.proofAlgorithmVersion || '')
      || !SHA256.test(value.proofAlgorithmSourceDigest || '')) {
    fail('AGGREGATE_HISTORICAL_SOURCE_BINDING_INVALID', result);
  }
  return { ...value };
}

function normalizeEvidence(evidence, componentResult) {
  exactKeys(evidence, ['bytesBase64', 'digest', 'iri'], 'AGGREGATE_EVIDENCE_INVALID', componentResult);
  if (!IRI.test(evidence.iri || '') || !SHA256.test(evidence.digest || '')) {
    fail('AGGREGATE_EVIDENCE_INVALID', componentResult);
  }
  if (evidence.digest === ORPHANED_ATTESTATION_DIGEST) {
    fail('AGGREGATE_ORPHAN_EVIDENCE_REJECTED', evidence.iri);
  }
  const bytes = decodeCanonicalBase64(evidence.bytesBase64, 'AGGREGATE_EVIDENCE_INVALID', evidence.iri);
  const actualDigest = sha256Bytes(bytes);
  if (actualDigest !== evidence.digest) fail('AGGREGATE_EVIDENCE_DIGEST_MISMATCH', evidence.iri);
  return { bytesBase64: evidence.bytesBase64, digest: actualDigest, iri: evidence.iri };
}

function aggregateEvidenceDescriptors(componentEvidence) {
  if (!Array.isArray(componentEvidence)) {
    fail('AGGREGATE_EVIDENCE_SET_INVALID', 'component evidence must be an array');
  }
  const occurrences = [];
  for (const entry of componentEvidence) {
    exactKeys(entry, ['descriptors', 'result'], 'AGGREGATE_EVIDENCE_SET_INVALID', 'component evidence');
    if (!IRI.test(entry.result || '') || !Array.isArray(entry.descriptors)) {
      fail('AGGREGATE_EVIDENCE_SET_INVALID', entry.result || 'unknown result');
    }
    for (const descriptor of entry.descriptors) {
      exactKeys(descriptor, ['digest', 'iri'], 'AGGREGATE_EVIDENCE_SET_INVALID', entry.result);
      if (!IRI.test(descriptor.iri || '') || !SHA256.test(descriptor.digest || '')) {
        fail('AGGREGATE_EVIDENCE_SET_INVALID', entry.result);
      }
      occurrences.push({ digest: descriptor.digest, iri: descriptor.iri, result: entry.result });
    }
  }

  const sharingGroups = [
    { evidence: SHARED_HERMETIC_EVIDENCE, results: SHARED_HERMETIC_RESULTS },
    { evidence: SHARED_LIVE_AUTHORITY_EVIDENCE, results: SHARED_LIVE_AUTHORITY_RESULTS },
  ];
  const allowedIriCounts = new Map();
  const allowedDigestCounts = new Map();
  for (const group of sharingGroups) {
    const sharedIris = new Set(group.evidence.map(({ iri }) => iri));
    const sharedDigests = new Set(group.evidence.map(({ digest }) => digest));
    const allowedResults = new Set(group.results);
    const sharedTouched = occurrences.some(({ iri, digest: evidenceDigest }) => (
      sharedIris.has(iri) || sharedDigests.has(evidenceDigest)
    ));
    if (!sharedTouched) continue;
    for (const occurrence of occurrences) {
      if (!sharedIris.has(occurrence.iri) && !sharedDigests.has(occurrence.digest)) continue;
      const exactDescriptor = group.evidence.some(({ iri, digest: evidenceDigest }) => (
        iri === occurrence.iri && evidenceDigest === occurrence.digest
      ));
      if (!exactDescriptor || !allowedResults.has(occurrence.result)) {
        fail('AGGREGATE_SHARED_EVIDENCE_SUBSTITUTED', `${occurrence.result} ${occurrence.iri} ${occurrence.digest}`);
      }
    }
    for (const descriptor of group.evidence) {
      const exactOccurrences = occurrences.filter(({ iri, digest: evidenceDigest }) => (
        iri === descriptor.iri && evidenceDigest === descriptor.digest
      ));
      const resultSet = new Set(exactOccurrences.map(({ result }) => result));
      if (exactOccurrences.length !== group.results.length
          || resultSet.size !== group.results.length
          || group.results.some((result) => !resultSet.has(result))) {
        fail('AGGREGATE_SHARED_EVIDENCE_INCOMPLETE', descriptor.iri);
      }
      allowedIriCounts.set(descriptor.iri, group.results.length);
    }
    for (const evidenceDigest of sharedDigests) {
      const descriptorCount = group.evidence.filter(({ digest }) => digest === evidenceDigest).length;
      allowedDigestCounts.set(evidenceDigest, descriptorCount * group.results.length);
    }
  }

  const byIri = new Map();
  const byDigest = new Map();
  for (const occurrence of occurrences) {
    byIri.set(occurrence.iri, [...(byIri.get(occurrence.iri) || []), occurrence]);
    byDigest.set(occurrence.digest, [...(byDigest.get(occurrence.digest) || []), occurrence]);
  }
  for (const [iri, matches] of byIri) {
    if (matches.length > 1 && matches.length !== allowedIriCounts.get(iri)) {
      fail('AGGREGATE_DUPLICATE_EVIDENCE', iri);
    }
  }
  for (const [evidenceDigest, matches] of byDigest) {
    if (matches.length > 1 && matches.length !== allowedDigestCounts.get(evidenceDigest)) {
      fail('AGGREGATE_DUPLICATE_EVIDENCE', evidenceDigest);
    }
  }

  const unique = new Map();
  for (const { iri, digest: evidenceDigest } of occurrences) {
    unique.set(`${iri}\u0000${evidenceDigest}`, { digest: evidenceDigest, iri });
  }
  return normalizedDescriptors([...unique.values()]);
}

function normalizeHistoricalResult(blob, expected, evidenceDigest) {
  const record = canonicalJsonBlob(blob, `${expected.result} historical result`);
  const value = record.value;
  exactKeys(value, [
    'authorityBindingDigest', 'component', 'evaluatedAt', 'evidenceSet', 'proof',
    'proofEvaluation', 'proofExecution', 'proofState', 'resultState', 'schema', 'sourceBinding',
  ], 'AGGREGATE_HISTORICAL_RESULT_INVALID', expected.result);
  if (value.schema !== HISTORICAL_RESULT_SCHEMA) fail('AGGREGATE_HISTORICAL_RESULT_INVALID', expected.result);
  exactKeys(value.component, ['dimension', 'obligation', 'result'],
    'AGGREGATE_HISTORICAL_RESULT_INVALID', expected.result);
  if (canonicalJson(value.component) !== canonicalJson(expected)) {
    fail('AGGREGATE_HISTORICAL_RESULT_IDENTITY_MISMATCH', expected.result);
  }
  if (!SHA256.test(value.authorityBindingDigest || '') || !IRI.test(value.proof || '')
      || !IRI.test(value.proofExecution || '') || !IRI.test(value.proofEvaluation || '')
      || !Array.isArray(value.evidenceSet)) {
    fail('AGGREGATE_HISTORICAL_RESULT_BINDING_MISMATCH', expected.result);
  }
  validTime(value.evaluatedAt, 'AGGREGATE_HISTORICAL_RESULT_INVALID', `${expected.result} evaluatedAt`);
  for (const descriptor of value.evidenceSet) {
    exactKeys(descriptor, ['digest', 'iri'], 'AGGREGATE_HISTORICAL_RESULT_INVALID', expected.result);
    if (!IRI.test(descriptor.iri || '') || !SHA256.test(descriptor.digest || '')) {
      fail('AGGREGATE_HISTORICAL_RESULT_INVALID', expected.result);
    }
  }
  const evidenceSet = normalizedDescriptors(value.evidenceSet);
  if (canonicalJson(value.evidenceSet) !== canonicalJson(evidenceSet)
      || descriptorSetDigest(evidenceSet) !== evidenceDigest) {
    fail('AGGREGATE_HISTORICAL_RESULT_BINDING_MISMATCH', expected.result);
  }
  if (value.proofState !== 'successful' || value.resultState !== 'passed') {
    fail('AGGREGATE_COMPONENT_FAILED', expected.result);
  }
  return {
    digest: record.digest,
    authorityBindingDigest: value.authorityBindingDigest,
    component: { ...value.component },
    evaluatedAt: value.evaluatedAt,
    evidenceSet,
    proof: value.proof,
    proofEvaluation: value.proofEvaluation,
    proofExecution: value.proofExecution,
    proofState: value.proofState,
    resultState: value.resultState,
    sourceBinding: normalizeHistoricalSourceBinding(value.sourceBinding, expected.result),
  };
}

function normalizeCurrentness(currentness, expected, historicalResult, evidenceDescriptors,
  authorityDigest, evaluatedAtMilliseconds) {
  exactKeys(currentness, ['projectionReceipt', 'snapshot'],
    'AGGREGATE_CURRENTNESS_SNAPSHOT_INVALID', expected.result);
  const snapshotRecord = canonicalJsonBlob(currentness.snapshot, `${expected.result} currentness snapshot`);
  const snapshot = snapshotRecord.value;
  exactKeys(snapshot, [
    'admittedEvidence', 'authorityDigest', 'componentResult', 'historicalResultDigest',
    'invalidated', 'observedAt', 'proofState', 'resultState', 'schema', 'supersededBy',
    'validFrom', 'validUntil',
  ], 'AGGREGATE_CURRENTNESS_SNAPSHOT_INVALID', expected.result);
  if (snapshot.schema !== CURRENTNESS_SCHEMA || snapshot.componentResult !== expected.result
      || snapshot.historicalResultDigest !== historicalResult.digest) {
    fail('AGGREGATE_CURRENTNESS_SNAPSHOT_INVALID', expected.result);
  }
  if (snapshot.authorityDigest !== authorityDigest) {
    fail('AGGREGATE_CURRENTNESS_AUTHORITY_MISMATCH', expected.result);
  }
  if (!Array.isArray(snapshot.admittedEvidence)) {
    fail('AGGREGATE_CURRENTNESS_EVIDENCE_MISMATCH', expected.result);
  }
  for (const descriptor of snapshot.admittedEvidence) {
    exactKeys(descriptor, ['digest', 'iri'], 'AGGREGATE_CURRENTNESS_EVIDENCE_MISMATCH', expected.result);
    if (!IRI.test(descriptor.iri || '') || !SHA256.test(descriptor.digest || '')) {
      fail('AGGREGATE_CURRENTNESS_EVIDENCE_MISMATCH', expected.result);
    }
  }
  const admittedEvidence = normalizedDescriptors(snapshot.admittedEvidence);
  if (canonicalJson(admittedEvidence) !== canonicalJson(normalizedDescriptors(evidenceDescriptors))) {
    fail('AGGREGATE_CURRENTNESS_EVIDENCE_MISMATCH', expected.result);
  }
  if (snapshot.proofState !== 'successful' || snapshot.resultState !== 'passed') {
    fail('AGGREGATE_COMPONENT_FAILED', expected.result);
  }
  if (snapshot.invalidated !== false) fail('AGGREGATE_COMPONENT_INVALIDATED', expected.result);
  if (snapshot.supersededBy !== null) fail('AGGREGATE_COMPONENT_SUPERSESSION_UNRESOLVED', expected.result);
  const observedAt = validTime(snapshot.observedAt, 'AGGREGATE_CURRENTNESS_SNAPSHOT_INVALID', expected.result);
  const validFrom = validTime(snapshot.validFrom, 'AGGREGATE_CURRENTNESS_SNAPSHOT_INVALID', expected.result);
  const validUntil = validTime(snapshot.validUntil, 'AGGREGATE_CURRENTNESS_SNAPSHOT_INVALID', expected.result);
  if (validFrom > observedAt || observedAt > evaluatedAtMilliseconds || evaluatedAtMilliseconds >= validUntil) {
    fail('AGGREGATE_COMPONENT_STALE', expected.result);
  }
  const projectionRecord = canonicalJsonBlob(currentness.projectionReceipt,
    `${expected.result} currentness projection receipt`);
  const projection = projectionRecord.value;
  exactKeys(projection, [
    'authorityDigest', 'componentResult', 'producedAt', 'producer', 'schema', 'snapshotDigest',
  ], 'AGGREGATE_CURRENTNESS_RECEIPT_INVALID', expected.result);
  if (projection.schema !== CURRENTNESS_RECEIPT_SCHEMA || projection.producer !== CURRENTNESS_PRODUCER
      || projection.authorityDigest !== authorityDigest || projection.componentResult !== expected.result
      || projection.snapshotDigest !== snapshotRecord.digest || projection.producedAt !== snapshot.observedAt) {
    fail('AGGREGATE_CURRENTNESS_RECEIPT_INVALID', expected.result);
  }
  validTime(projection.producedAt, 'AGGREGATE_CURRENTNESS_RECEIPT_INVALID', expected.result);
  return {
    admittedEvidence,
    authorityDigest,
    historicalResultDigest: historicalResult.digest,
    invalidated: false,
    observedAt: snapshot.observedAt,
    projectionReceiptDigest: projectionRecord.digest,
    proofState: snapshot.proofState,
    resultState: snapshot.resultState,
    snapshotDigest: snapshotRecord.digest,
    supersededBy: null,
    validFrom: snapshot.validFrom,
    validUntil: snapshot.validUntil,
  };
}

function normalizeComponents(components, authorityDigest, evaluatedAtMilliseconds) {
  if (!Array.isArray(components)) fail('AGGREGATE_COMPONENT_SET_INVALID', 'components must be an array');
  for (const component of components) {
    exactKeys(component, ['currentness', 'dimension', 'evidenceReferences', 'historicalResult', 'obligation', 'result'],
      'AGGREGATE_COMPONENT_INVALID', 'component');
  }
  const obligations = components.map(({ obligation }) => obligation);
  const results = components.map(({ result }) => result);
  if (new Set(obligations).size !== obligations.length || new Set(results).size !== results.length) {
    fail('AGGREGATE_DUPLICATE_COMPONENT', 'component obligations and results must be unique');
  }
  const expectedByObligation = new Map(COMPONENT_PROOFS.map((item) => [item.obligation, item]));
  for (const component of components) {
    const expected = expectedByObligation.get(component.obligation);
    if (!expected || expected.result !== component.result || expected.dimension !== component.dimension) {
      fail('AGGREGATE_UNEXPECTED_COMPONENT', component.obligation || component.result || 'unknown');
    }
  }
  const missing = COMPONENT_PROOFS.filter((expected) => !components.some(({ obligation }) => obligation === expected.obligation));
  if (missing.length > 0) fail('AGGREGATE_MISSING_COMPONENT', missing.map(({ obligation }) => obligation).join(','));
  if (components.length !== COMPONENT_PROOFS.length) fail('AGGREGATE_COMPONENT_CARDINALITY', String(components.length));

  const normalized = components.map((component) => {
    if (!Array.isArray(component.evidenceReferences) || component.evidenceReferences.length === 0) {
      fail('AGGREGATE_EVIDENCE_MISSING', component.result);
    }
    const evidenceReferences = component.evidenceReferences.map((evidence) => normalizeEvidence(evidence, component.result));
    evidenceReferences.sort((left, right) => left.iri.localeCompare(right.iri));
    const evidenceDigest = descriptorSetDigest(evidenceReferences);
    const expected = expectedByObligation.get(component.obligation);
    const historicalResult = normalizeHistoricalResult(component.historicalResult, expected, evidenceDigest);
    const currentness = normalizeCurrentness(component.currentness, expected, historicalResult,
      evidenceReferences, authorityDigest, evaluatedAtMilliseconds);
    return {
      currentness,
      dimension: component.dimension,
      evidenceReferences,
      historicalResult,
      obligation: component.obligation,
      result: component.result,
    };
  }).sort((left, right) => left.obligation.localeCompare(right.obligation));
  const aggregateEvidence = aggregateEvidenceDescriptors(normalized.map(({ evidenceReferences, result }) => ({
    descriptors: evidenceReferences.map(({ digest: evidenceDigest, iri }) => ({ digest: evidenceDigest, iri })),
    result,
  })));
  return { components: normalized, evidenceSetDigest: descriptorSetDigest(aggregateEvidence) };
}

function assertReevaluationBindings(value, context, label) {
  if (value.authorityAfterDigest !== context.authorityDigest
      || value.publicationReceiptDigest !== context.publicationReceiptDigest
      || value.algorithmVersion !== AGGREGATE_ALGORITHM_VERSION
      || value.algorithmDigest !== AGGREGATE_ALGORITHM_DIGEST
      || value.componentSetDigest !== COMPONENT_SET_DIGEST
      || value.evidenceSetDigest !== context.evidenceSetDigest
      || value.sourceBindingDigest !== context.sourceBindingDigest) {
    fail('AGGREGATE_POST_PUBLICATION_BINDING_MISMATCH', label);
  }
}

function normalizePostPublicationReevaluation(postPublicationReevaluation, context) {
  exactKeys(postPublicationReevaluation, ['evaluationReceipt', 'executionReceipt', 'publicationReceipt'],
    'AGGREGATE_POST_PUBLICATION_REEVALUATION_REQUIRED', 'immutable reevaluation receipts are absent');
  const publicationRecord = semanticProofPublicationReceiptBlob(postPublicationReevaluation.publicationReceipt);
  const publication = publicationRecord.value;
  if (publication.protocol !== 'semantic-proof-v1' || publication.publication_phase !== 'initial'
      || publication.terminal_state !== 'PENDING'
      || publication.publication_outcome !== 'committed_pending_reevaluation'
      || publication.grant_consumed !== true
      || !SHA256.test(publication.authority_before_digest || '')
      || !SHA256.test(publication.candidate_digest || '')
      || publication.authority_after_digest !== context.authorityDigest
      || publication.authority_before_digest === publication.authority_after_digest) {
    fail('AGGREGATE_PUBLICATION_RECEIPT_INVALID', 'authority transition is not exact');
  }
  const publishedAt = validTime(publication.published_at,
    'AGGREGATE_PUBLICATION_RECEIPT_INVALID', 'published_at');
  const bindingContext = { ...context, publicationReceiptDigest: publicationRecord.digest };

  const executionRecord = canonicalJsonBlob(postPublicationReevaluation.executionReceipt,
    'post-publication execution receipt');
  const execution = executionRecord.value;
  exactKeys(execution, [
    'algorithmDigest', 'algorithmVersion', 'authorityAfterDigest', 'completedAt', 'componentSetDigest',
    'evidenceSetDigest', 'publicationReceiptDigest', 'schema', 'sourceBindingDigest', 'startedAt',
  ], 'AGGREGATE_POST_PUBLICATION_EXECUTION_INVALID', 'post-publication execution receipt');
  if (execution.schema !== REEVALUATION_EXECUTION_SCHEMA) {
    fail('AGGREGATE_POST_PUBLICATION_EXECUTION_INVALID', execution.schema || 'absent');
  }
  assertReevaluationBindings(execution, bindingContext, 'execution receipt');
  const startedAt = validTime(execution.startedAt, 'AGGREGATE_POST_PUBLICATION_ORDER_INVALID', 'startedAt');
  const completedAt = validTime(execution.completedAt, 'AGGREGATE_POST_PUBLICATION_ORDER_INVALID', 'completedAt');

  const evaluationRecord = canonicalJsonBlob(postPublicationReevaluation.evaluationReceipt,
    'post-publication evaluation receipt');
  const evaluation = evaluationRecord.value;
  exactKeys(evaluation, [
    'algorithmDigest', 'algorithmVersion', 'authorityAfterDigest', 'componentSetDigest', 'evaluatedAt',
    'evidenceSetDigest', 'executionReceiptDigest', 'publicationReceiptDigest', 'resultState', 'schema',
    'sourceBindingDigest',
  ], 'AGGREGATE_POST_PUBLICATION_EVALUATION_INVALID', 'post-publication evaluation receipt');
  if (evaluation.schema !== REEVALUATION_EVALUATION_SCHEMA || evaluation.resultState !== 'passed'
      || evaluation.executionReceiptDigest !== executionRecord.digest) {
    fail('AGGREGATE_POST_PUBLICATION_EVALUATION_INVALID', 'evaluation does not bind a passing execution');
  }
  assertReevaluationBindings(evaluation, bindingContext, 'evaluation receipt');
  const reevaluatedAt = validTime(evaluation.evaluatedAt,
    'AGGREGATE_POST_PUBLICATION_ORDER_INVALID', 'reevaluatedAt');
  if (evaluation.evaluatedAt !== context.evaluatedAt
      || !(publishedAt < startedAt && startedAt <= completedAt && completedAt <= reevaluatedAt)) {
    fail('AGGREGATE_POST_PUBLICATION_ORDER_INVALID', 'receipt-linked execution and evaluation are not ordered');
  }
  for (const component of context.components) {
    const observedAt = validTime(component.currentness.observedAt,
      'AGGREGATE_CURRENTNESS_SNAPSHOT_INVALID', component.result);
    if (observedAt < startedAt || observedAt > completedAt) {
      fail('AGGREGATE_CURRENTNESS_NOT_POST_PUBLICATION', component.result);
    }
  }
  return {
    authorityAfterDigest: publication.authority_after_digest,
    authorityPreDigest: publication.authority_before_digest,
    candidateDigest: publication.candidate_digest,
    evaluatedAt: evaluation.evaluatedAt,
    evaluationReceiptDigest: evaluationRecord.digest,
    executionReceiptDigest: executionRecord.digest,
    publicationReceiptDigest: publicationRecord.digest,
    publicationPhase: publication.publication_phase,
    publishedAt: publication.published_at,
  };
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

export function evaluateAggregateCompilerProof({
  components,
  authorityDigest,
  sourceBinding,
  sourceRepositoryPath,
  sourceBindingDependency = productionGitSourceBindingDependency,
  evaluatedAt,
  algorithmVersion = AGGREGATE_ALGORITHM_VERSION,
  phase,
  postPublicationReevaluation = null,
}) {
  if (!SHA256.test(authorityDigest || '')) fail('AGGREGATE_AUTHORITY_DIGEST_INVALID', 'authority digest must be exact');
  const evaluatedAtMilliseconds = validTime(evaluatedAt, 'AGGREGATE_EVALUATED_AT_INVALID', 'evaluation time');
  if (algorithmVersion !== AGGREGATE_ALGORITHM_VERSION) fail('AGGREGATE_ALGORITHM_VERSION_MISMATCH', String(algorithmVersion));
  if (phase !== 'pre-publication' && phase !== 'post-publication') {
    fail('AGGREGATE_PHASE_INVALID', String(phase));
  }
  const normalizedSourceBinding = normalizeSourceBinding(
    sourceBinding, sourceRepositoryPath, sourceBindingDependency,
  );
  const normalized = normalizeComponents(components, authorityDigest, evaluatedAtMilliseconds);
  const bindingDigest = sourceBindingDigest(normalizedSourceBinding);
  const commonEvaluation = {
    algorithmDigest: AGGREGATE_ALGORITHM_DIGEST,
    algorithmVersion,
    authorityDigest,
    componentSetDigest: COMPONENT_SET_DIGEST,
    components: normalized.components,
    evaluatedAt,
    evidenceSetDigest: normalized.evidenceSetDigest,
    sourceBinding: normalizedSourceBinding,
    sourceBindingDigest: bindingDigest,
  };
  if (phase === 'pre-publication') {
    if (postPublicationReevaluation !== null) {
      fail('AGGREGATE_PREPARATION_REEVALUATION_FORBIDDEN', 'pre-publication preparation cannot carry a reevaluation');
    }
    const evaluation = { ...commonEvaluation, phase: 'PRE_PUBLICATION_PREPARATION', postPublicationReevaluation: null };
    return deepFreeze({
      evaluation,
      evaluationDigest: sha256(canonicalJson(evaluation)),
      passed: false,
      proofCurrentness: 'PENDING',
      resultState: 'PENDING',
      selectable: false,
    });
  }
  if (postPublicationReevaluation === null) {
    fail('AGGREGATE_POST_PUBLICATION_REEVALUATION_REQUIRED', 'passing selection requires reevaluation receipts');
  }
  const postPublication = normalizePostPublicationReevaluation(postPublicationReevaluation, {
    authorityDigest,
    components: normalized.components,
    evaluatedAt,
    evidenceSetDigest: normalized.evidenceSetDigest,
    sourceBindingDigest: bindingDigest,
  });
  const evaluation = {
    ...commonEvaluation,
    phase: 'POST_PUBLICATION_REEVALUATION',
    postPublicationReevaluation: postPublication,
  };
  return deepFreeze({
    evaluation,
    evaluationDigest: sha256(canonicalJson(evaluation)),
    passed: true,
    proofCurrentness: 'CURRENT',
    resultState: 'PASSED',
    selectable: true,
  });
}

export const aggregateCompilerProofInternals = Object.freeze({
  aggregateEvidenceDescriptors,
  canonicalJson,
  descriptorSetDigest,
  sha256,
  sha256Bytes,
  sourceBindingDigest,
  sourceScopeDigest: semanticProofSourceScopeDigest,
});
