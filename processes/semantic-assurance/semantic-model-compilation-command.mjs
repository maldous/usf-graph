import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { DataFactory, Parser, Store, Writer } from 'n3';

import {
  canonicalGraphDigest,
  canonicalInventoryGraphDigest,
  canonicalNQuads,
  checkLocal,
  compile,
  CompilerError,
  shapeConstraints,
} from '../../capabilities/semantic-model-compilation/compiler.mjs';
import {
  integrityRules,
  loadManifest,
  managedGraphs,
} from '../../capabilities/semantic-model-compilation/manifest.mjs';
export const SEMANTIC_MODEL_PATH = 'semantic-model';
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_OBJECT = /^[0-9a-f]{40}$/;
const PATCH_HEADER = /^# semantic-proof-v1 canonical-rdf-patch-v1 (base|stage1|stage2)$/;
const EXTERNAL_AUTHORITY_DELTA_SCHEMA = 'usf-external-authority-conflict-resolution-delta-v1';
const EXTERNAL_AUTHORITY_PROOF_SCHEMA = 'usf-authority-conflict-proof-decision-v1';
const EXTERNAL_AUTHORITY_DOMAIN = 'urn:usf:capabilityowner:semanticmodelcompilation';
const AUTHORITY_FINGERPRINT = 'B6CBC89C7978AF26F53C33A197E5F20D2A340E5D';
const AUTHORITY_PRINCIPAL = 'urn:usf:principal:matthewaldous';
const AUTHORITY_SIGNING_IDENTITY = 'urn:usf:signingidentity:matthewaldoussemanticproofv1';
const EXTERNAL_AUTHORITY_ARTIFACT_ROLES = Object.freeze(['inventory', 'operations', 'proof', 'review']);
const EXTERNAL_AUTHORITY_EVIDENCE_ROLES = Object.freeze(['inventory', 'operations', 'review']);
const EXTERNAL_AUTHORITY_NONCLAIMS = Object.freeze([
  'NO_FACTORY_MUTATION',
  'NO_PRODUCTION_PRUNING',
  'NO_PROVIDER_CONTACT',
  'NO_V2_ACTIVATION',
  'NO_DEPLOYMENT',
]);
const REQUIRED_HISTORY_MODE = ['lin', 'ear'].join('');
const ONE_PARENT_HISTORY_SHAPE = ['one-parent-lin', 'ear'].join('');
const NQUADS = 'application/n-quads';
const NTRIPLES = 'application/n-triples';
const TURTLE = 'text/turtle';
const { defaultGraph, namedNode, quad } = DataFactory;

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object' && !Buffer.isBuffer(value)
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function exactCandidateBytes(value, expectedDigest) {
  if (!Buffer.isBuffer(value) || value.length === 0) {
    throw new CompilerError('canonical RDF Patch candidate bytes are required', { phase: 'candidate:configuration' });
  }
  const observedDigest = sha256(value);
  if (expectedDigest !== undefined && observedDigest !== expectedDigest) {
    throw new CompilerError('canonical RDF Patch bytes do not match the accepted candidate digest', {
      phase: 'candidate:digest', expectedCandidateDigest: expectedDigest, observedCandidateDigest: observedDigest,
    });
  }
  return Object.freeze({ bytes: Buffer.from(value), digest: observedDigest });
}

function parseCanonicalPatch(
  value,
  expectedDigest,
  allowedGraphs,
  allowedStages = new Set(['stage1', 'stage2']),
) {
  const candidate = exactCandidateBytes(value, expectedDigest);
  const text = candidate.bytes.toString('utf8');
  if (!candidate.bytes.equals(Buffer.from(text, 'utf8')) || text.includes('\r') || !text.endsWith('\n')) {
    throw new CompilerError('candidate is not canonical UTF-8 RDF Patch', { phase: 'candidate:parse' });
  }
  const lines = text.split('\n');
  const header = lines.shift();
  const patchHeader = PATCH_HEADER.exec(header || '');
  if (!patchHeader || !allowedStages.has(patchHeader[1]) || lines.pop() !== '' || lines.length === 0) {
    throw new CompilerError('candidate does not use canonical-rdf-patch-v1', { phase: 'candidate:parse' });
  }
  const operations = lines.map((line) => {
    const match = /^([AD]) (.+)$/.exec(line);
    if (!match) throw new CompilerError('candidate contains a malformed RDF Patch operation', { phase: 'candidate:parse' });
    let parsed;
    try {
      parsed = new Parser({ format: NQUADS, blankNodePrefix: '' }).parse(`${match[2]}\n`);
    } catch (error) {
      throw new CompilerError(`candidate contains invalid N-Quads: ${error.message}`, { phase: 'candidate:parse' });
    }
    if (parsed.length !== 1 || parsed[0].graph.termType !== 'NamedNode'
        || [parsed[0].subject, parsed[0].object].some((term) => term.termType === 'BlankNode'
          && !/^c14n[0-9]+$/.test(term.value))
        || !allowedGraphs.has(parsed[0].graph.value)) {
      throw new CompilerError('candidate operation must be one canonical quad in a managed named graph', { phase: 'candidate:scope' });
    }
    return Object.freeze({ action: match[1], line: match[2], value: parsed[0] });
  });
  const deletions = operations.filter(({ action }) => action === 'D');
  const additions = operations.filter(({ action }) => action === 'A');
  const canonicalLines = [
    header,
    ...deletions.map(({ line }) => `D ${line}`).sort(),
    ...additions.map(({ line }) => `A ${line}`).sort(),
    '',
  ];
  if (canonicalLines.join('\n') !== text
      || new Set(operations.map(({ action, line }) => `${action} ${line}`)).size !== operations.length
      || deletions.some(({ line }) => additions.some((entry) => entry.line === line))) {
    throw new CompilerError('candidate RDF Patch is not canonical, unique and contradiction-free', { phase: 'candidate:canonicality' });
  }
  return Object.freeze({ ...candidate, additions, deletions, operations });
}

function exactObjectKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    throw new CompilerError(`${label} has an invalid closed schema`, { phase: 'candidate:external-authority-delta' });
  }
}

function exactSortedUniqueStrings(value, pattern, label, { minimum = 1 } = {}) {
  if (!Array.isArray(value) || value.length < minimum || value.some((item) => typeof item !== 'string' || !pattern.test(item))
      || canonicalJson(value) !== canonicalJson([...new Set(value)].sort())) {
    throw new CompilerError(`${label} must be an exact sorted unique set`, { phase: 'candidate:external-authority-delta' });
  }
  return Object.freeze([...value]);
}

function exactCanonicalRepositoryPaths(value, label, { minimum = 1 } = {}) {
  const paths = exactSortedUniqueStrings(value, /^[A-Za-z0-9._/-]+$/, label, { minimum });
  if (paths.some((path) => path.startsWith('/')
      || path.split('/').some((part) => part === '' || part === '.' || part === '..'))) {
    throw new CompilerError(`${label} contains a non-canonical repository-relative path`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  return paths;
}

function externalAuthoritySourceScopeDigest(paths) {
  const canonicalPaths = exactCanonicalRepositoryPaths(paths, 'external authority source paths');
  return sha256(Buffer.from(canonicalJson(canonicalPaths), 'utf8'));
}

function missingExternalAuthorityProofVerifier() {
  throw new CompilerError('external authority proof approval verifier is required', {
    phase: 'candidate:external-authority-delta',
  });
}

async function resolveExternalAuthorityTrustedNow(operationTrustedNow, configuredTrustedNow) {
  let observed = operationTrustedNow ?? configuredTrustedNow;
  if (observed === null || observed === undefined) {
    throw new CompilerError('external authority proof validation requires trusted current time', {
      phase: 'candidate:external-authority-delta',
    });
  }
  if (typeof observed === 'function') observed = await observed();
  const date = observed instanceof Date ? new Date(observed.getTime()) : new Date(observed);
  if (!Number.isFinite(date.getTime())) {
    throw new CompilerError('external authority proof trusted current time is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return date;
}

function parseCanonicalJsonArtifact(bytes, label) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2) {
    throw new CompilerError(`${label} bytes are required`, { phase: 'candidate:external-authority-delta' });
  }
  const text = bytes.toString('utf8');
  if (!bytes.equals(Buffer.from(text, 'utf8')) || text.includes('\r') || !text.endsWith('\n')) {
    throw new CompilerError(`${label} is not canonical UTF-8 JSON with terminal LF`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new CompilerError(`${label} is not JSON: ${error.message}`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  const canonicalBytes = Buffer.from(`${JSON.stringify(stable(value), null, 2)}\n`, 'utf8');
  if (!canonicalBytes.equals(bytes)) {
    throw new CompilerError(`${label} is not stable-key canonical JSON`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  return Object.freeze({
    byteSize: bytes.length,
    bytes: Buffer.from(bytes),
    digest: sha256(bytes),
    jcsDigest: sha256(Buffer.from(canonicalJson(value), 'utf8')),
    value,
  });
}

function exactArtifactDescriptor(value, observed, label) {
  exactObjectKeys(value, ['byteSize', 'digest', 'jcsDigest'], label);
  if (value.byteSize !== observed.byteSize || value.digest !== observed.digest
      || value.jcsDigest !== observed.jcsDigest) {
    throw new CompilerError(`${label} does not bind the exact canonical artifact bytes`, {
      phase: 'candidate:external-authority-delta',
    });
  }
}

function validateExternalAuthorityOperations(artifact, repository, contentStore = null) {
  const operations = artifact.value;
  if (!Array.isArray(operations) || operations.length < 1 || operations.length > 256) {
    throw new CompilerError('external authority operations must be a bounded canonical array', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const paths = [];
  for (const [index, operation] of operations.entries()) {
    const inline = Object.hasOwn(operation, 'content') || Object.hasOwn(operation, 'contentEncoding');
    const located = Object.hasOwn(operation, 'contentLocator');
    exactObjectKeys(operation, inline && !located ? [
      'action', 'artefactFamily', 'content', 'contentDigest', 'contentEncoding', 'index',
      'path', 'pathRole', 'representationFormat', 'sourceDigest',
    ] : !inline && located ? [
      'action', 'artefactFamily', 'contentDigest', 'contentLocator', 'index',
      'path', 'pathRole', 'representationFormat', 'sourceDigest',
    ] : [], 'external authority write operation');
    let contentBytes;
    if (inline && !located && operation.contentEncoding === 'utf8'
        && typeof operation.content === 'string' && operation.content.length > 0) {
      contentBytes = Buffer.from(operation.content, 'utf8');
    } else if (!inline && located && SHA256.test(operation.contentDigest || '')
        && operation.contentLocator === `cas://sha256/${operation.contentDigest.slice(7)}`
        && contentStore && typeof contentStore.read === 'function' && typeof contentStore.verify === 'function') {
      const receipt = contentStore.verify(operation.contentDigest);
      const read = contentStore.read(operation.contentDigest);
      if (receipt?.digest === operation.contentDigest && Number.isSafeInteger(receipt.size)
          && Buffer.isBuffer(read) && read.length > 0 && read.length === receipt.size
          && sha256(read) === operation.contentDigest) contentBytes = read;
    }
    if (operation.action !== 'write-file' || operation.index !== index
        || !Buffer.isBuffer(contentBytes)
        || typeof operation.path !== 'string'
        || !/^[A-Za-z0-9._/-]+$/.test(operation.path)
        || operation.path.startsWith('/')
        || operation.path.split('/').some((part) => part === '' || part === '.' || part === '..')
        || !SHA256.test(operation.sourceDigest || '')
        || sha256(contentBytes) !== operation.contentDigest
        || !/^urn:usf:artefactfamily:[a-z0-9]+$/.test(operation.artefactFamily || '')
        || !/^urn:usf:pathrole:[a-z0-9]+$/.test(operation.pathRole || '')
        || !/^urn:usf:representationformat:[a-z0-9]+$/.test(operation.representationFormat || '')) {
      throw new CompilerError('external authority write operation is not exact and preimage-bound', {
        phase: 'candidate:external-authority-delta', index,
      });
    }
    paths.push(operation.path);
  }
  if (canonicalJson(paths) !== canonicalJson([...new Set(paths)].sort())) {
    throw new CompilerError('external authority operation paths must be sorted and unique', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const requestedFormats = [...new Set(operations.map(({ representationFormat }) => representationFormat))].sort();
  const operationDigest = sha256(Buffer.from(canonicalJson({
    operations: stable(operations), repository, schemaVersion: 1,
  }), 'utf8'));
  return Object.freeze({
    operationDigest,
    operations: Object.freeze(operations.map((operation) => Object.freeze({ ...operation }))),
    requestedActions: Object.freeze(['write-file']),
    requestedFormats: Object.freeze(requestedFormats),
    requestedPaths: Object.freeze(paths),
  });
}

function validateExternalAuthorityInventory(artifact, {
  authorityDigest,
  conflictBinding,
  correctionCandidateDigest,
  operations,
  predecessorSourceHead,
  predecessorSourceTree,
  repository,
}) {
  const inventory = artifact.value;
  exactObjectKeys(inventory, [
    'authority', 'candidate_source', 'corrections', 'current_execution_boundary', 'nonclaims',
    'owner_precedent', 'predecessor_request', 'proof_preflight', 'protected_graph_source',
    'required_authority_actions', 'required_validation_invariants', 'schema', 'source_scope',
    'status', 'supporting_integrity_corrections',
  ], 'external authority inventory');
  if (inventory.schema !== 'usf-repository-materialisation-semantic-correction-authority-request-v3'
      || inventory.status !== 'REFERENCE_ONLY_VALIDATION_EVIDENCE_CANDIDATE_AWAITING_EXACT_CONFLICT_RESOLUTION'
      || artifact.digest !== correctionCandidateDigest) {
    throw new CompilerError('external authority inventory identity or status is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  exactObjectKeys(inventory.authority, ['digest', 'graph_count', 'triple_count'], 'external authority inventory authority');
  exactObjectKeys(inventory.protected_graph_source, ['commit', 'parent', 'required_history', 'tree'],
    'external authority inventory protected source');
  exactObjectKeys(inventory.candidate_source, [
    'added_path_count', 'changed_path_count', 'deleted_path_count', 'focused_verification',
    'history_shape', 'predecessor_commit', 'predecessor_tree', 'repository', 'source_records',
    'staged_deletions', 'staged_insertions', 'staged_successor_tree',
  ], 'external authority inventory candidate source');
  exactObjectKeys(inventory.source_scope, [
    'authority_projection_additions', 'current_path_count', 'current_scope_digest',
    'successor_path_count', 'successor_scope_digest',
  ], 'external authority inventory source scope');
  exactObjectKeys(inventory.current_execution_boundary, [
    'action_state', 'execution_scope_digest', 'execution_scope_iri', 'execution_scope_projection_digest',
    'maximum_repository_writes', 'mode', 'permitted_effect', 'repository_mutation_permitted',
    'status', 'unresolved_validation_obligations', 'validation_satisfied', 'write_paths',
  ], 'external authority inventory execution boundary');
  const sourceRecords = inventory.candidate_source.source_records;
  if (!Array.isArray(sourceRecords) || sourceRecords.length !== operations.operations.length) {
    throw new CompilerError('external authority inventory source-record cardinality is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const [index, record] of sourceRecords.entries()) {
    exactObjectKeys(record, ['mode', 'path', 'predecessor_digest', 'successor_digest'],
      'external authority inventory source record');
    const operation = operations.operations[index];
    if (record.mode !== '100644' || record.path !== operation.path
        || record.predecessor_digest !== operation.sourceDigest
        || record.successor_digest !== operation.contentDigest) {
      throw new CompilerError('external authority inventory source record differs from the exact operation', {
        phase: 'candidate:external-authority-delta', index,
      });
    }
  }
  const obligations = inventory.corrections.map((correction) => {
    if (!correction || typeof correction !== 'object' || Array.isArray(correction)
        || correction.status !== 'REFERENCE_ONLY_CANDIDATE'
        || !/^urn:usf:validationobligation:[a-z0-9]+$/.test(correction.obligation || '')) {
      throw new CompilerError('external authority inventory correction is not reference-only and obligation-bound', {
        phase: 'candidate:external-authority-delta',
      });
    }
    return correction.obligation;
  }).sort();
  if (inventory.authority.digest !== authorityDigest
      || inventory.protected_graph_source.commit !== predecessorSourceHead
      || inventory.protected_graph_source.tree !== predecessorSourceTree
      || inventory.protected_graph_source.required_history !== REQUIRED_HISTORY_MODE
      || inventory.candidate_source.predecessor_commit !== predecessorSourceHead
      || inventory.candidate_source.predecessor_tree !== predecessorSourceTree
      || inventory.candidate_source.repository !== repository
      || inventory.candidate_source.staged_successor_tree !== conflictBinding.successorSourceTree
      || inventory.candidate_source.added_path_count !== 0
      || inventory.candidate_source.deleted_path_count !== 0
      || inventory.candidate_source.changed_path_count !== operations.operations.length
      || inventory.candidate_source.history_shape !== ONE_PARENT_HISTORY_SHAPE
      || inventory.source_scope.successor_scope_digest !== conflictBinding.sourceScopeDigest
      || inventory.source_scope.successor_path_count !== conflictBinding.sourcePaths.length
      || inventory.current_execution_boundary.repository_mutation_permitted !== false
      || inventory.current_execution_boundary.maximum_repository_writes !== 0
      || inventory.current_execution_boundary.validation_satisfied !== false
      || inventory.current_execution_boundary.write_paths.length !== 0
      || canonicalJson(obligations) !== canonicalJson(conflictBinding.validationObligations)
      || canonicalJson(inventory.current_execution_boundary.unresolved_validation_obligations)
        !== canonicalJson(conflictBinding.validationObligations)) {
    throw new CompilerError('external authority inventory does not bind the exact fail-closed correction boundary', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return inventory;
}

function validateExternalAuthorityReview(artifact, inventoryArtifact, {
  authorityDigest,
  conflictBinding,
  operations,
  predecessorSourceHead,
  predecessorSourceTree,
}) {
  const review = artifact.value;
  exactObjectKeys(review, [
    'authorshipIndependence', 'candidateSource', 'currentExecutionBoundary',
    'governanceIndependentReviewSatisfied', 'liveAuthority', 'nonclaims', 'obligations',
    'publicationReadiness', 'request', 'reviewArtifactStorageClass', 'schema',
    'sourceOrAuthorityMutationPerformed', 'verdict', 'verification',
  ], 'external authority independent review');
  exactObjectKeys(review.liveAuthority, ['digest', 'digestAlgorithm', 'graphCount', 'stableAcrossReview', 'tripleCount'],
    'external authority review live authority');
  exactObjectKeys(review.authorshipIndependence, [
    'candidateDerivationParticipation', 'priorReviewConclusionsUsed', 'reviewDerivation', 'reviewerRole',
  ], 'external authority review independence');
  exactObjectKeys(review.request, ['byteCount', 'jcsSha256', 'path', 'rawSha256', 'schema', 'status', 'terminalLf'],
    'external authority review request binding');
  exactObjectKeys(review.candidateSource, [
    'baseCommit', 'baseParent', 'baseTree', 'changedPaths', 'sourceRecordCount',
    'sourceRecordsExact', 'sourceRecordsJcsSha256', 'stagedDeletions', 'stagedInsertions',
    'stagedSuccessorTree', 'trackedDeltaExact', 'trackedPathAdditions', 'trackedPathDeletions',
  ], 'external authority review candidate source');
  exactObjectKeys(review.obligations, [
    'currentValidationResultCounts', 'requiredAuthorityActionCount',
    'requiredValidationInvariantCount', 'targetValidationObligations',
  ], 'external authority review obligations');
  const zeroCounts = Object.fromEntries(conflictBinding.validationObligations.map((iri) => [iri, 0]));
  if (review.schema !== 'usf-semantic-adequacy-review-core-v1'
      || review.verdict !== 'ACCEPTED'
      || review.governanceIndependentReviewSatisfied !== true
      || review.sourceOrAuthorityMutationPerformed !== false
      || review.liveAuthority.digest !== authorityDigest
      || review.liveAuthority.stableAcrossReview !== true
      || review.authorshipIndependence.candidateDerivationParticipation !== false
      || review.authorshipIndependence.priorReviewConclusionsUsed !== false
      || review.authorshipIndependence.reviewerRole !== 'independent-usf-semantic-reviewer'
      || review.request.rawSha256 !== inventoryArtifact.digest
      || review.request.jcsSha256 !== inventoryArtifact.jcsDigest
      || review.request.byteCount !== inventoryArtifact.byteSize
      || review.request.terminalLf !== true
      || review.candidateSource.baseCommit !== predecessorSourceHead
      || review.candidateSource.baseTree !== predecessorSourceTree
      || review.candidateSource.stagedSuccessorTree !== conflictBinding.successorSourceTree
      || review.candidateSource.sourceRecordCount !== operations.operations.length
      || review.candidateSource.sourceRecordsExact !== true
      || review.candidateSource.trackedDeltaExact !== true
      || review.candidateSource.trackedPathAdditions !== 0
      || review.candidateSource.trackedPathDeletions !== 0
      || canonicalJson(review.candidateSource.changedPaths) !== canonicalJson(operations.requestedPaths)
      || canonicalJson(review.obligations.targetValidationObligations)
        !== canonicalJson(conflictBinding.validationObligations)
      || canonicalJson(review.obligations.currentValidationResultCounts) !== canonicalJson(zeroCounts)
      || review.publicationReadiness
        !== 'NOT_READY_REFERENCE_ONLY_AWAITING_OWNER_DECISION_PROOF_AND_V1_PUBLICATION') {
    throw new CompilerError('external authority review is not exact, independent and accepted', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return review;
}

function validateExternalAuthorityProof(artifact, inputs, {
  authorityDigest,
  conflictBinding,
  correctionCandidateDigest,
  now,
  ownerAssignmentIri,
  predecessorSourceHead,
  predecessorSourceTree,
  repository,
}) {
  const value = artifact.value;
  exactObjectKeys(value, [
    'artifacts', 'authorityDigest', 'candidateDigest', 'conflict', 'decision',
    'evidenceSetDigest', 'nonclaims', 'proof', 'repository', 'review', 'schema', 'source',
  ], 'external authority proof decision');
  exactObjectKeys(value.artifacts, EXTERNAL_AUTHORITY_EVIDENCE_ROLES,
    'external authority proof input artifacts');
  exactObjectKeys(value.source, [
    'predecessorHead', 'predecessorTree', 'sourcePaths', 'sourceScopeDigest', 'successorTree',
  ], 'external authority proof source');
  exactObjectKeys(value.conflict, [
    'authorities', 'operationDigest', 'requestedActions', 'requestedEffects',
    'requestedFormats', 'requestedPaths', 'validationObligations',
  ], 'external authority proof conflict');
  exactObjectKeys(value.review, ['defectCount', 'digest', 'independent', 'state'],
    'external authority proof review conclusion');
  exactObjectKeys(value.proof, [
    'algorithmIri', 'algorithmVersionIri', 'evaluatedAt', 'obligationIri', 'resultState',
    'state', 'subjectCandidateDigest', 'validUntil',
  ], 'external authority proof result');
  exactObjectKeys(value.decision, ['ownerAssignmentIri', 'rationale', 'state'],
    'external authority owner decision');
  for (const role of EXTERNAL_AUTHORITY_EVIDENCE_ROLES) {
    exactArtifactDescriptor(value.artifacts[role], inputs.get(role),
      `external authority proof ${role} descriptor`);
  }
  const evidenceSetDigest = sha256(Buffer.from(canonicalJson(value.artifacts), 'utf8'));
  const observedNow = now instanceof Date ? now.getTime() : Date.parse(now);
  const evaluated = Date.parse(value.proof.evaluatedAt);
  const validUntil = Date.parse(value.proof.validUntil);
  if (value.schema !== EXTERNAL_AUTHORITY_PROOF_SCHEMA
      || value.authorityDigest !== authorityDigest
      || value.repository !== repository
      || value.candidateDigest !== correctionCandidateDigest
      || value.source.predecessorHead !== predecessorSourceHead
      || value.source.predecessorTree !== predecessorSourceTree
      || value.source.successorTree !== conflictBinding.successorSourceTree
      || value.source.sourceScopeDigest !== conflictBinding.sourceScopeDigest
      || canonicalJson(value.source.sourcePaths) !== canonicalJson(conflictBinding.sourcePaths)
      || canonicalJson(value.conflict.authorities) !== canonicalJson(conflictBinding.conflictingAuthorities)
      || value.conflict.operationDigest !== conflictBinding.operationDigest
      || canonicalJson(value.conflict.requestedActions) !== canonicalJson(conflictBinding.requestedActions)
      || canonicalJson(value.conflict.requestedEffects) !== canonicalJson(conflictBinding.requestedEffects)
      || canonicalJson(value.conflict.requestedFormats) !== canonicalJson(conflictBinding.requestedFormats)
      || canonicalJson(value.conflict.requestedPaths) !== canonicalJson(conflictBinding.requestedPaths)
      || canonicalJson(value.conflict.validationObligations)
        !== canonicalJson(conflictBinding.validationObligations)
      || value.evidenceSetDigest !== evidenceSetDigest
      || value.review.digest !== inputs.get('review').digest
      || value.review.state !== 'ACCEPTED'
      || value.review.independent !== true
      || value.review.defectCount !== 0
      || value.proof.state !== 'PASSED'
      || value.proof.resultState !== 'SUCCESSFUL'
      || value.proof.subjectCandidateDigest !== correctionCandidateDigest
      || value.proof.obligationIri !== 'urn:usf:proofobligation:compilersemanticenforcementaggregate'
      || value.proof.algorithmIri !== 'urn:usf:proofalgorithm:compilersemanticenforcementaggregate'
      || value.proof.algorithmVersionIri !== 'urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210'
      || !Number.isFinite(observedNow) || !Number.isFinite(evaluated) || !Number.isFinite(validUntil)
      || evaluated > observedNow || validUntil <= observedNow || validUntil <= evaluated
      || value.decision.state !== 'ACCEPTED'
      || value.decision.ownerAssignmentIri !== ownerAssignmentIri
      || typeof value.decision.rationale !== 'string' || value.decision.rationale.length < 1
      || canonicalJson(value.nonclaims) !== canonicalJson(EXTERNAL_AUTHORITY_NONCLAIMS)) {
    throw new CompilerError('external authority proof/decision is not exact, current and owner-authored', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return Object.freeze({ evidenceSetDigest, evaluatedAt: value.proof.evaluatedAt, validUntil: value.proof.validUntil, value });
}

function validateExternalAuthorityArtifacts({
  artifacts,
  authorityDigest,
  conflictBinding,
  correctionCandidateDigest,
  now,
  ownerAssignmentIri,
  predecessorSourceHead,
  predecessorSourceTree,
  proofApprovalEnvelope,
  repository,
  operationContentStore = null,
  trustAnchor,
  verifyProofApprovalEnvelope = missingExternalAuthorityProofVerifier,
}) {
  if (!(artifacts instanceof Map)
      || canonicalJson([...artifacts.keys()].sort()) !== canonicalJson(EXTERNAL_AUTHORITY_ARTIFACT_ROLES)) {
    throw new CompilerError('external authority artifact role set is incomplete', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const parsed = new Map([...artifacts].map(([role, bytes]) => [
    role, parseCanonicalJsonArtifact(bytes, `external authority ${role} artifact`),
  ]));
  const operations = validateExternalAuthorityOperations(parsed.get('operations'), repository, operationContentStore);
  if (operations.operationDigest !== conflictBinding.operationDigest
      || canonicalJson(operations.requestedActions) !== canonicalJson(conflictBinding.requestedActions)
      || canonicalJson(operations.requestedFormats) !== canonicalJson(conflictBinding.requestedFormats)
      || canonicalJson(operations.requestedPaths) !== canonicalJson(conflictBinding.requestedPaths)
      || externalAuthoritySourceScopeDigest(conflictBinding.sourcePaths) !== conflictBinding.sourceScopeDigest) {
    throw new CompilerError('external authority operation or source-scope digest was not derived from canonical bytes', {
      phase: 'candidate:external-authority-delta',
    });
  }
  validateExternalAuthorityInventory(parsed.get('inventory'), {
    authorityDigest, conflictBinding, correctionCandidateDigest, operations,
    predecessorSourceHead, predecessorSourceTree, repository,
  });
  validateExternalAuthorityReview(parsed.get('review'), parsed.get('inventory'), {
    authorityDigest, conflictBinding, operations, predecessorSourceHead, predecessorSourceTree,
  });
  const proof = validateExternalAuthorityProof(parsed.get('proof'), parsed, {
    authorityDigest, conflictBinding, correctionCandidateDigest, now, ownerAssignmentIri,
    predecessorSourceHead, predecessorSourceTree, repository,
  });
  let verifiedApproval;
  try {
    verifiedApproval = verifyProofApprovalEnvelope(proofApprovalEnvelope, {
      authorityDomain: EXTERNAL_AUTHORITY_DOMAIN,
      authorityPreDigest: authorityDigest,
      candidateDigest: parsed.get('proof').digest,
      claimType: 'candidate_approval',
      expectedSingleUse: false,
      now,
      repository,
      sourcePaths: conflictBinding.sourcePaths,
      ...(trustAnchor === undefined ? {} : { trustAnchor }),
    });
  } catch (error) {
    throw new CompilerError(`external authority proof owner approval is invalid: ${error.message}`, {
      phase: 'candidate:external-authority-delta',
    });
  }
  const approvalExpiresAt = Date.parse(verifiedApproval.expires_at);
  if (verifiedApproval.fingerprint !== AUTHORITY_FINGERPRINT
      || verifiedApproval.principal !== AUTHORITY_PRINCIPAL
      || verifiedApproval.signing_identity !== AUTHORITY_SIGNING_IDENTITY
      || verifiedApproval.claim_type !== 'candidate_approval'
      || verifiedApproval.authority_domain !== EXTERNAL_AUTHORITY_DOMAIN
      || verifiedApproval.authority_pre_digest !== authorityDigest
      || verifiedApproval.repository !== repository
      || verifiedApproval.source_scope_digest !== conflictBinding.sourceScopeDigest
      || verifiedApproval.candidate_digest !== parsed.get('proof').digest
      || verifiedApproval.single_use !== false
      || !Number.isFinite(approvalExpiresAt)
      || approvalExpiresAt < Date.parse(proof.validUntil)) {
    throw new CompilerError('external authority proof owner approval does not bind the proof lifetime and identity', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return Object.freeze({ artifacts: parsed, operations, proof, verifiedApproval });
}

function conflictBindingFromProofDocument(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !value.conflict || !value.source || !value.decision) {
    throw new CompilerError('external authority proof does not contain a conflict/source/decision binding', {
      phase: 'candidate:external-authority-delta',
    });
  }
  return Object.freeze({
    conflictingAuthorities: value.conflict.authorities,
    operationDigest: value.conflict.operationDigest,
    requestedActions: value.conflict.requestedActions,
    requestedEffects: value.conflict.requestedEffects,
    requestedFormats: value.conflict.requestedFormats,
    requestedPaths: value.conflict.requestedPaths,
    sourcePaths: value.source.sourcePaths,
    sourceScopeDigest: value.source.sourceScopeDigest,
    successorSourceTree: value.source.successorTree,
    validationObligations: value.conflict.validationObligations,
  });
}

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const USF = 'urn:usf:ontology:';

function patchHas(patch, subject, predicate, object) {
  return patch.additions.some(({ value }) => value.subject.value === subject
    && value.predicate.value === predicate && value.object.value === object);
}

function requirePatchTriple(patch, subject, predicate, object, label) {
  if (!patchHas(patch, subject, predicate, object)) {
    throw new CompilerError(`external authority delta is missing exact ${label}`, {
      phase: 'candidate:external-authority-delta', subject, predicate, object,
    });
  }
}

const EXTERNAL_AUTHORITY_ROLE_PREDICATES = Object.freeze({
  conflict: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}conflictAuthorityDigest`,
    `${USF}conflictingAuthority`, `${USF}conflictRepository`, `${USF}conflictOperationDigest`,
    `${USF}conflictCandidateDigest`, `${USF}conflictPredecessorSourceHead`,
    `${USF}conflictPredecessorSourceTree`, `${USF}conflictSuccessorSourceTree`,
    `${USF}conflictSourceScopeDigest`, `${USF}conflictSourcePath`,
    `${USF}conflictRequestedAction`, `${USF}conflictRequestedPath`,
    `${USF}conflictRequestedRepresentationFormat`, `${USF}conflictRequestedEffect`,
    `${USF}conflictBlockedByValidationObligation`,
  ]),
  review: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}hasSemanticAdequacyReviewState`,
    `${USF}reviewedAuthorityDigest`, `${USF}reviewedInventoryDigest`, `${USF}reviewedItemCount`,
    `${USF}usesDispositionInventoryDescriptor`, `${USF}usesIndependentReviewDescriptor`,
    `${USF}usesSemanticAdequacyProofDescriptor`,
  ]),
  resolution: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}decisionRationale`,
    `${USF}semanticCorrectionDecisionState`, `${USF}decisionBasedOnSemanticAdequacyReview`,
    `${USF}warrantedBySemanticAdequacyProof`, `${USF}resolvesAuthorityConflict`,
    `${USF}authorityConflictResolutionOwnerAssignment`,
  ]),
  proof: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}atRung`, `${USF}exercises`,
    `${USF}inEnvironment`, `${USF}provesSubject`, `${USF}usesProviderMode`,
  ]),
  proofResult: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}claimedRung`, `${USF}observedRung`,
    `${USF}hasFreshness`, `${USF}hasProofResultState`, `${USF}inEnvironment`,
    `${USF}resultState`, `${USF}resultForProof`, `${USF}usesProviderMode`,
    `${USF}proofExecutionEnvironment`, `${USF}evidenceSetDigest`, `${USF}evaluatedAt`,
    `${USF}uncertaintyStatement`, `${USF}hasInvalidationCondition`,
    `${USF}proofResultForObligation`, `${USF}usesAdmittedEvidence`,
    `${USF}usesProofAlgorithm`, `${USF}usesAlgorithmVersion`,
    `${USF}evaluatedByValidator`, `${USF}hasConfidenceState`, `${USF}confidenceBasis`,
  ]),
  descriptor: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}descriptorArtefactFamily`,
    `${USF}descriptorRepresentationFormat`, `${USF}descriptorMediaType`,
    `${USF}descriptorDigest`, `${USF}descriptorByteSize`, `${USF}descriptorLocator`,
    `${USF}descriptorArtefactType`, `${USF}descriptorStorageClass`,
  ]),
  disposition: new Set([
    `${USF}reviewedInSemanticAdequacyReview`, `${USF}semanticAdequacyDisposition`,
    `${USF}authorisedBySemanticCorrectionDecision`, `${USF}sourceItemDigest`,
    `${USF}finalCanonicalSemanticItem`,
  ]),
  evidence: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}evidenceKind`, `${USF}usesProviderMode`,
    `${USF}inEnvironment`, `${USF}hasFreshness`, `${USF}evidenceFor`, `${USF}evidenceForContract`,
    `${USF}contentDigest`, `${USF}mediaType`, `${USF}byteSize`,
    `${USF}storageLocator`, `${USF}wasProducedBy`, `${USF}collectedAt`, `${USF}validUntil`,
    `${USF}hasFreshnessPolicy`, `${USF}hasAdmissionState`, `${USF}hasFreshnessState`,
    `${USF}hasIntegrityState`, `${USF}concernsSemanticSubject`, `${USF}evidenceStage`,
    `${USF}collectedBy`, `${USF}normalisedBy`, `${USF}ingestedBy`, `${USF}evidenceSignature`,
    `${USF}evidenceChecksum`, `${USF}integrityVerification`, `${USF}applicableToObligation`,
    `${USF}withinValidityScope`,
  ]),
  collection: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}collectionForRequirement`,
    `${USF}collectedEvidence`, `${USF}collectsEvidence`, `${USF}collectedOn`, `${USF}sourceDigest`,
  ]),
  normalisation: new Set([RDF_TYPE, `${USF}canonicalName`, `${USF}normalisesEvidence`]),
  ingestion: new Set([RDF_TYPE, `${USF}canonicalName`, `${USF}ingestsEvidence`]),
  integrity: new Set([RDF_TYPE, `${USF}canonicalName`, `${USF}verifiesEvidence`, `${USF}verificationState`]),
  checksum: new Set([RDF_TYPE, `${USF}canonicalName`, `${USF}checksumAlgorithm`, `${USF}checksumValue`]),
  signature: new Set([
    RDF_TYPE, `${USF}canonicalName`, `${USF}artefactKind`, `${USF}canonicalPath`,
    `${USF}governedByPathRule`, `${USF}signatureMethod`, `${USF}signingPolicy`,
    `${USF}signedBy`, `${USF}signatureValue`,
  ]),
});

const EXTERNAL_AUTHORITY_MULTI_PREDICATES = Object.freeze({
  conflict: new Set([
    `${USF}conflictingAuthority`, `${USF}conflictSourcePath`, `${USF}conflictRequestedAction`,
    `${USF}conflictRequestedPath`, `${USF}conflictRequestedRepresentationFormat`,
    `${USF}conflictRequestedEffect`, `${USF}conflictBlockedByValidationObligation`,
  ]),
  proof: new Set([`${USF}exercises`]),
  proofResult: new Set([
    `${USF}hasInvalidationCondition`, `${USF}usesAdmittedEvidence`, `${USF}confidenceBasis`,
  ]),
  evidence: new Set([`${USF}evidenceForContract`, `${USF}evidenceStage`]),
});

function exactPatchObjects(patch, subject, predicate) {
  return patch.additions
    .filter(({ value: item }) => item.subject.value === subject && item.predicate.value === predicate)
    .map(({ value: item }) => item.object.value);
}

function assertExternalAuthorityClosedShape(patch, value, verifiedArtifacts, artifactValidation) {
  const roots = [...verifiedArtifacts.keys()].sort();
  const proofLinks = exactPatchObjects(patch, value.proofResultIri, `${USF}resultForProof`);
  if (proofLinks.length !== 1 || !/^urn:usf:proof:[a-z0-9]+$/.test(proofLinks[0])) {
    throw new CompilerError('external authority delta proof identity is not exact', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const proofIri = proofLinks[0];
  const descriptorSubjects = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}descriptorDigest`
      && roots.includes(item.object.value))
    .map(({ value: item }) => item.subject.value))].sort();
  if (descriptorSubjects.length !== roots.length
      || descriptorSubjects.some((item) => !/^urn:usf:externalpayloaddescriptor:[a-z0-9]+$/.test(item))) {
    throw new CompilerError('external authority delta descriptor identities are not one-to-one with CAS roots', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const dispositionSubjects = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}reviewedInSemanticAdequacyReview`
      && item.object.value === value.reviewIri)
    .map(({ value: item }) => item.subject.value))].sort();
  if (dispositionSubjects.some((item) => !/^urn:usf:historicalitem:[0-9a-f]{64}$/.test(item))) {
    throw new CompilerError('external authority delta review disposition identity is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const evidenceSubjects = [...new Set(exactPatchObjects(
    patch,
    value.proofResultIri,
    `${USF}usesAdmittedEvidence`,
  ))].sort();
  if (evidenceSubjects.length !== 3
      || evidenceSubjects.some((item) => !/^urn:usf:evidenceresult:[a-z0-9]+$/.test(item))) {
    throw new CompilerError('external authority delta requires exactly three admitted proof evidence subjects', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const linkedSubjects = (predicate, pattern, label) => {
    const subjects = [...new Set(evidenceSubjects.flatMap((evidence) => exactPatchObjects(
      patch,
      evidence,
      predicate,
    )))].sort();
    if (subjects.length === 0 || subjects.some((item) => !pattern.test(item))) {
      throw new CompilerError(`external authority delta ${label} identity is invalid`, {
        phase: 'candidate:external-authority-delta',
      });
    }
    return subjects;
  };
  const collectionSubjects = linkedSubjects(`${USF}collectedBy`, /^urn:usf:evidencecollection:[a-z0-9]+$/, 'collection');
  const normalisationSubjects = linkedSubjects(`${USF}normalisedBy`, /^urn:usf:evidencenormalisation:[a-z0-9]+$/, 'normalisation');
  const ingestionSubjects = linkedSubjects(`${USF}ingestedBy`, /^urn:usf:evidenceingestion:[a-z0-9]+$/, 'ingestion');
  const integritySubjects = linkedSubjects(`${USF}integrityVerification`, /^urn:usf:integrityverification:[a-z0-9]+$/, 'integrity verification');
  const checksumSubjects = linkedSubjects(`${USF}evidenceChecksum`, /^urn:usf:checksum:[a-z0-9]+$/, 'checksum');
  const signatureSubjects = linkedSubjects(`${USF}evidenceSignature`, /^urn:usf:signature:[a-z0-9]+$/, 'signature');
  if ([collectionSubjects, normalisationSubjects, ingestionSubjects, integritySubjects, checksumSubjects]
    .some((subjects) => subjects.length !== evidenceSubjects.length)
      || signatureSubjects.length !== 1) {
    throw new CompilerError('external authority delta evidence lifecycle is not one-to-one with one shared signature', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const roleBySubject = new Map([
    [value.conflictIri, 'conflict'], [value.reviewIri, 'review'],
    [value.resolutionIri, 'resolution'], [value.proofResultIri, 'proofResult'], [proofIri, 'proof'],
    ...descriptorSubjects.map((item) => [item, 'descriptor']),
    ...dispositionSubjects.map((item) => [item, 'disposition']),
    ...evidenceSubjects.map((item) => [item, 'evidence']),
    ...collectionSubjects.map((item) => [item, 'collection']),
    ...normalisationSubjects.map((item) => [item, 'normalisation']),
    ...ingestionSubjects.map((item) => [item, 'ingestion']),
    ...integritySubjects.map((item) => [item, 'integrity']),
    ...checksumSubjects.map((item) => [item, 'checksum']),
    ...signatureSubjects.map((item) => [item, 'signature']),
  ]);
  const expectedRoleCount = 5 + descriptorSubjects.length + dispositionSubjects.length
    + evidenceSubjects.length + collectionSubjects.length + normalisationSubjects.length
    + ingestionSubjects.length + integritySubjects.length + checksumSubjects.length
    + signatureSubjects.length;
  if (roleBySubject.size !== expectedRoleCount) {
    throw new CompilerError('external authority delta semantic roles overlap', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const cardinality = new Map();
  const observedPredicates = new Map();
  for (const { value: item } of patch.additions) {
    const role = roleBySubject.get(item.subject.value);
    if (!role || !EXTERNAL_AUTHORITY_ROLE_PREDICATES[role].has(item.predicate.value)) {
      throw new CompilerError('external authority delta contains an unrelated semantic operation', {
        phase: 'candidate:external-authority-delta',
        predicate: item.predicate.value,
        subject: item.subject.value,
      });
    }
    const key = `${item.subject.value}\u0000${item.predicate.value}`;
    if (!observedPredicates.has(item.subject.value)) observedPredicates.set(item.subject.value, new Set());
    observedPredicates.get(item.subject.value).add(item.predicate.value);
    cardinality.set(key, (cardinality.get(key) || 0) + 1);
    if (!EXTERNAL_AUTHORITY_MULTI_PREDICATES[role]?.has(item.predicate.value)
        && cardinality.get(key) > 1) {
      throw new CompilerError('external authority delta contains an ambiguous singleton property', {
        phase: 'candidate:external-authority-delta',
        predicate: item.predicate.value,
        subject: item.subject.value,
      });
    }
  }
  for (const [subject, role] of roleBySubject) {
    const expected = [...EXTERNAL_AUTHORITY_ROLE_PREDICATES[role]].sort();
    const observed = [...(observedPredicates.get(subject) || [])].sort();
    if (canonicalJson(observed) !== canonicalJson(expected)) {
      throw new CompilerError('external authority delta semantic role is incomplete', {
        phase: 'candidate:external-authority-delta', expected, observed, role, subject,
      });
    }
  }
  const requireExactObjects = (subject, predicate, expected, label) => {
    const observed = exactPatchObjects(patch, subject, predicate).sort();
    const values = [...expected].sort();
    if (canonicalJson(observed) !== canonicalJson(values)) {
      throw new CompilerError(`external authority delta ${label} is not exact`, {
        phase: 'candidate:external-authority-delta', expected: values, observed, predicate, subject,
      });
    }
  };
  requireExactObjects(proofIri, RDF_TYPE, [`${USF}Proof`], 'proof type');
  requireExactObjects(proofIri, `${USF}atRung`, ['urn:usf:proofrung:behaviour'], 'proof rung');
  requireExactObjects(proofIri, `${USF}usesProviderMode`, ['urn:usf:providermode:deterministictestsubstitute'], 'proof provider mode');
  requireExactObjects(proofIri, `${USF}inEnvironment`, ['urn:usf:environment:hermetic'], 'proof environment');
  requireExactObjects(proofIri, `${USF}exercises`, ['urn:usf:semanticcontract:compilersemanticenforcement'], 'proof contract');
  requireExactObjects(value.proofResultIri, RDF_TYPE, [`${USF}ProofResult`], 'proof-result type');
  for (const [predicate, expected, label] of [
    [`${USF}resultState`, 'urn:usf:resultstate:passed', 'proof result state'],
    [`${USF}hasProofResultState`, 'urn:usf:proofresultstate:successful', 'proof success state'],
    [`${USF}claimedRung`, 'urn:usf:proofrung:behaviour', 'claimed rung'],
    [`${USF}observedRung`, 'urn:usf:proofrung:behaviour', 'observed rung'],
    [`${USF}hasFreshness`, 'urn:usf:freshness:fresh', 'proof freshness'],
    [`${USF}usesProviderMode`, 'urn:usf:providermode:deterministictestsubstitute', 'proof-result provider mode'],
    [`${USF}inEnvironment`, 'urn:usf:environment:hermetic', 'proof-result environment'],
    [`${USF}proofExecutionEnvironment`, 'urn:usf:environment:hermetic', 'proof execution environment'],
    [`${USF}proofResultForObligation`, 'urn:usf:proofobligation:compilersemanticenforcementaggregate', 'proof obligation'],
    [`${USF}usesProofAlgorithm`, 'urn:usf:proofalgorithm:compilersemanticenforcementaggregate', 'proof algorithm'],
    [`${USF}usesAlgorithmVersion`, 'urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210', 'proof algorithm version'],
    [`${USF}evaluatedByValidator`, 'urn:usf:validatorrule:validateassuranceconformance', 'proof validator'],
    [`${USF}hasConfidenceState`, 'urn:usf:proofconfidencestate:warranted', 'proof confidence'],
  ]) requireExactObjects(value.proofResultIri, predicate, [expected], label);
  for (const subject of descriptorSubjects) {
    const digests = exactPatchObjects(patch, subject, `${USF}descriptorDigest`);
    if (digests.length !== 1 || !roots.includes(digests[0])) {
      throw new CompilerError('external authority delta descriptor root is ambiguous', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
    const byteSizes = exactPatchObjects(patch, subject, `${USF}descriptorByteSize`);
    const locators = exactPatchObjects(patch, subject, `${USF}descriptorLocator`);
    if (byteSizes.length !== 1 || Number(byteSizes[0]) !== verifiedArtifacts.get(digests[0]).byteSize
        || locators.length !== 1 || locators[0] !== `cas://sha256/${digests[0].slice(7)}`) {
      throw new CompilerError('external authority delta descriptor does not bind exact CAS bytes', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
    for (const [predicate, expected, label] of [
      [RDF_TYPE, `${USF}ExternalPayloadDescriptor`, 'descriptor type'],
      [`${USF}descriptorArtefactFamily`, 'urn:usf:artefactfamily:evidencepayload', 'descriptor family'],
      [`${USF}descriptorRepresentationFormat`, 'urn:usf:representationformat:jsondata8259', 'descriptor format'],
      [`${USF}descriptorMediaType`, 'application/json', 'descriptor media type'],
      [`${USF}descriptorStorageClass`, 'urn:usf:storageclass:contentaddressedobjectstorage', 'descriptor storage class'],
    ]) requireExactObjects(subject, predicate, [expected], label);
  }
  const reviewDescriptorSubjects = [
    `${USF}usesDispositionInventoryDescriptor`, `${USF}usesIndependentReviewDescriptor`,
    `${USF}usesSemanticAdequacyProofDescriptor`,
  ].flatMap((predicate) => exactPatchObjects(patch, value.reviewIri, predicate)).sort();
  const reviewedRoles = new Set(['inventory', 'proof', 'review']);
  const expectedReviewDescriptorSubjects = descriptorSubjects.filter((subject) => {
    const digest = exactPatchObjects(patch, subject, `${USF}descriptorDigest`)[0];
    return reviewedRoles.has(verifiedArtifacts.get(digest).role);
  }).sort();
  if (canonicalJson(reviewDescriptorSubjects) !== canonicalJson(expectedReviewDescriptorSubjects)) {
    throw new CompilerError('external authority delta review does not bind its exact inventory/review/proof descriptors', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const descriptorByDigest = new Map(descriptorSubjects.map((subject) => {
    const digests = exactPatchObjects(patch, subject, `${USF}descriptorDigest`);
    return [digests[0], subject];
  }));
  const evidenceDigests = evidenceSubjects.map((subject) => {
    const digests = exactPatchObjects(patch, subject, `${USF}contentDigest`);
    if (digests.length !== 1 || !descriptorByDigest.has(digests[0])) {
      throw new CompilerError('external authority delta evidence does not bind one review descriptor digest', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
    const concerns = exactPatchObjects(patch, subject, `${USF}concernsSemanticSubject`);
    const stages = exactPatchObjects(patch, subject, `${USF}evidenceStage`).sort();
    const requiredStages = [
      'collected', 'emitted', 'ingested', 'integrityverified', 'normalised', 'signed',
    ].map((name) => `urn:usf:evidencestage:${name}`).sort();
    if (concerns.length !== 1 || concerns[0] !== value.reviewIri
        || canonicalJson(stages) !== canonicalJson(requiredStages)) {
      throw new CompilerError('external authority delta evidence review binding or lifecycle stages are incomplete', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
    return digests[0];
  }).sort();
  const expectedEvidenceDigests = roots.filter((root) => EXTERNAL_AUTHORITY_EVIDENCE_ROLES
    .includes(verifiedArtifacts.get(root).role)).sort();
  if (canonicalJson(evidenceDigests) !== canonicalJson(expectedEvidenceDigests)) {
    throw new CompilerError('external authority delta proof evidence is not the exact inventory/operations/review set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const confidenceBasis = exactPatchObjects(patch, value.proofResultIri, `${USF}confidenceBasis`).sort();
  if (canonicalJson(confidenceBasis) !== canonicalJson(evidenceSubjects)) {
    throw new CompilerError('external authority delta proof confidence is not bound to its exact evidence set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const evidenceSetDigests = exactPatchObjects(patch, value.proofResultIri, `${USF}evidenceSetDigest`);
  if (evidenceSetDigests.length !== 1
      || evidenceSetDigests[0] !== artifactValidation.proof.evidenceSetDigest) {
    throw new CompilerError('external authority delta proof evidence-set digest is not exact', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const evidence of evidenceSubjects) {
    const contentDigest = exactPatchObjects(patch, evidence, `${USF}contentDigest`)[0];
    const byteSizes = exactPatchObjects(patch, evidence, `${USF}byteSize`);
    const locators = exactPatchObjects(patch, evidence, `${USF}storageLocator`);
    const checksum = exactPatchObjects(patch, evidence, `${USF}evidenceChecksum`)[0];
    const checksumValue = exactPatchObjects(patch, checksum, `${USF}checksumValue`);
    if (byteSizes.length !== 1 || Number(byteSizes[0]) !== verifiedArtifacts.get(contentDigest).byteSize
        || locators.length !== 1 || locators[0] !== `cas://sha256/${contentDigest.slice(7)}`
        || checksumValue.length !== 1 || checksumValue[0] !== contentDigest.slice(7)) {
      throw new CompilerError('external authority delta evidence checksum does not match its content digest', {
        phase: 'candidate:external-authority-delta', evidence,
      });
    }
    for (const [predicate, expected, label] of [
      [RDF_TYPE, `${USF}EvidenceResult`, 'evidence type'],
      [`${USF}evidenceKind`, 'urn:usf:evidencekind:semanticreviewevidence', 'evidence kind'],
      [`${USF}usesProviderMode`, 'urn:usf:providermode:deterministictestsubstitute', 'evidence provider mode'],
      [`${USF}inEnvironment`, 'urn:usf:environment:hermetic', 'evidence environment'],
      [`${USF}hasFreshness`, 'urn:usf:freshness:fresh', 'evidence freshness'],
      [`${USF}evidenceFor`, value.conflictIri, 'evidence subject'],
      [`${USF}evidenceForContract`, 'urn:usf:semanticcontract:compilersemanticenforcement', 'evidence contract'],
      [`${USF}mediaType`, 'application/json', 'evidence media type'],
      [`${USF}wasProducedBy`, 'urn:usf:validatorrule:validateassuranceconformance', 'evidence validator'],
      [`${USF}hasFreshnessPolicy`, 'urn:usf:evidencefreshnesspolicy:semanticadequacyreviewauthoritybound', 'evidence freshness policy'],
      [`${USF}hasAdmissionState`, 'urn:usf:evidenceadmissionstate:admitted', 'evidence admission state'],
      [`${USF}hasFreshnessState`, 'urn:usf:evidencefreshnessstate:fresh', 'evidence freshness state'],
      [`${USF}hasIntegrityState`, 'urn:usf:evidenceintegritystate:valid', 'evidence integrity state'],
      [`${USF}applicableToObligation`, 'urn:usf:proofobligation:compilersemanticenforcementaggregate', 'evidence obligation'],
      [`${USF}withinValidityScope`, 'true', 'evidence validity scope'],
    ]) requireExactObjects(evidence, predicate, [expected], label);
    for (const [predicate, rolePredicate] of [
      [`${USF}collectedBy`, `${USF}collectedEvidence`],
      [`${USF}normalisedBy`, `${USF}normalisesEvidence`],
      [`${USF}ingestedBy`, `${USF}ingestsEvidence`],
      [`${USF}integrityVerification`, `${USF}verifiesEvidence`],
    ]) {
      const lifecycle = exactPatchObjects(patch, evidence, predicate);
      if (lifecycle.length !== 1 || !patchHas(patch, lifecycle[0], rolePredicate, evidence)) {
        throw new CompilerError('external authority delta evidence lifecycle does not point back to its evidence', {
          phase: 'candidate:external-authority-delta', evidence, predicate,
        });
      }
    }
  }
  for (const subject of collectionSubjects) {
    requireExactObjects(subject, RDF_TYPE, [`${USF}EvidenceCollection`], 'collection type');
    requireExactObjects(subject, `${USF}collectionForRequirement`, ['urn:usf:evidencerequirement:compilersemanticvalidation'], 'collection requirement');
  }
  for (const subject of normalisationSubjects) requireExactObjects(subject, RDF_TYPE, [`${USF}EvidenceNormalisation`], 'normalisation type');
  for (const subject of ingestionSubjects) requireExactObjects(subject, RDF_TYPE, [`${USF}EvidenceIngestion`], 'ingestion type');
  for (const subject of integritySubjects) {
    requireExactObjects(subject, RDF_TYPE, [`${USF}IntegrityVerification`], 'integrity type');
    requireExactObjects(subject, `${USF}verificationState`, ['urn:usf:resultstate:passed'], 'integrity state');
  }
  for (const subject of checksumSubjects) {
    requireExactObjects(subject, RDF_TYPE, [`${USF}Checksum`], 'checksum type');
    requireExactObjects(subject, `${USF}checksumAlgorithm`, ['urn:usf:checksumalgorithm:sha256'], 'checksum algorithm');
  }
  const signature = signatureSubjects[0];
  for (const [predicate, expected, label] of [
    [RDF_TYPE, `${USF}Signature`, 'signature type'],
    [`${USF}artefactKind`, 'urn:usf:artefactkind:signature', 'signature artefact kind'],
    [`${USF}governedByPathRule`, 'urn:usf:pathrule:contentaddressedsignature', 'signature path rule'],
    [`${USF}signatureMethod`, 'urn:usf:signaturemethod:detached', 'signature method'],
    [`${USF}signingPolicy`, 'urn:usf:policy:hermeticevidenceattestation', 'signature policy'],
  ]) requireExactObjects(signature, predicate, [expected], label);
  const signedBy = exactPatchObjects(patch, signature, `${USF}signedBy`);
  const signatureValue = exactPatchObjects(patch, signature, `${USF}signatureValue`);
  if (signedBy.length !== 1 || signedBy[0] !== AUTHORITY_SIGNING_IDENTITY
      || signatureValue.length !== 1
      || signatureValue[0] !== artifactValidation.proofApprovalEnvelope.signature) {
    throw new CompilerError('external authority delta signature identity or value is invalid', {
      phase: 'candidate:external-authority-delta', signature,
    });
  }
  const proofDescriptor = exactPatchObjects(patch, value.reviewIri, `${USF}usesSemanticAdequacyProofDescriptor`);
  const proofRoot = proofDescriptor.length === 1
    ? exactPatchObjects(patch, proofDescriptor[0], `${USF}descriptorDigest`)
    : [];
  requireExactObjects(signature, `${USF}canonicalPath`, proofRoot.length === 1
    ? [`cas://sha256/${proofRoot[0].slice(7)}#signature`]
    : [], 'signature canonical path');
  const reviewCounts = exactPatchObjects(patch, value.reviewIri, `${USF}reviewedItemCount`);
  if (reviewCounts.length > 0
      && (reviewCounts.length !== 1 || Number(reviewCounts[0]) !== dispositionSubjects.length)) {
    throw new CompilerError('external authority delta review item count is not exact', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const subject of dispositionSubjects) {
    const suffix = subject.slice('urn:usf:historicalitem:'.length);
    const sourceDigests = exactPatchObjects(patch, subject, `${USF}sourceItemDigest`);
    const decisions = exactPatchObjects(patch, subject, `${USF}authorisedBySemanticCorrectionDecision`);
    if (sourceDigests.length !== 1 || sourceDigests[0] !== `sha256:${suffix}`
        || decisions.length !== 1 || decisions[0] !== value.resolutionIri) {
      throw new CompilerError('external authority delta review disposition is not decision-bound', {
        phase: 'candidate:external-authority-delta', subject,
      });
    }
  }
  return proofIri;
}

function assertExternalAuthorityDelta({
  value,
  expectedAuthorityDigest,
  expectedSource,
  evidenceStore,
  allowedGraphs,
  now = null,
  trustAnchor,
  verifyProofApprovalEnvelope = missingExternalAuthorityProofVerifier,
}) {
  exactObjectKeys(value, [
    'artifactDescriptors', 'authorityDigest', 'casRootDigests', 'conflictIri', 'correctionCandidateDigest',
    'ownerAssignmentIri', 'patchBytesBase64', 'patchDigest', 'predecessorSourceHead',
    'predecessorSourceTree', 'proofApprovalEnvelope', 'proofResultIri', 'repository', 'resolutionIri', 'reviewIri',
    'schema', 'permittedOperations',
  ], 'external authority delta');
  if (value.schema !== EXTERNAL_AUTHORITY_DELTA_SCHEMA || value.authorityDigest !== expectedAuthorityDigest
      || !expectedSource || value.repository !== expectedSource.repository
      || value.predecessorSourceHead !== expectedSource.head
      || value.predecessorSourceTree !== expectedSource.tree
      || !GIT_OBJECT.test(value.predecessorSourceHead || '') || !GIT_OBJECT.test(value.predecessorSourceTree || '')
      || !SHA256.test(value.correctionCandidateDigest || '')
      || !SHA256.test(value.patchDigest || '')) {
    throw new CompilerError('external authority delta does not bind the exact authority and source predecessor', {
      phase: 'candidate:external-authority-delta',
    });
  }
  for (const [name, iri] of Object.entries({
    conflict: value.conflictIri,
    owner: value.ownerAssignmentIri,
    proof: value.proofResultIri,
    resolution: value.resolutionIri,
    review: value.reviewIri,
  })) {
    const pattern = name === 'owner'
      ? /^urn:usf:ownerassignment:[a-z0-9:]+$/
      : /^urn:usf:[a-z0-9]+:[a-z0-9]+$/;
    if (typeof iri !== 'string' || !pattern.test(iri)) {
      throw new CompilerError(`external authority delta ${name} IRI is invalid`, {
        phase: 'candidate:external-authority-delta',
      });
    }
  }
  let bytes;
  try {
    bytes = Buffer.from(value.patchBytesBase64, 'base64');
  } catch {
    throw new CompilerError('external authority delta patch is not base64', { phase: 'candidate:external-authority-delta' });
  }
  if (bytes.toString('base64') !== value.patchBytesBase64 || sha256(bytes) !== value.patchDigest) {
    throw new CompilerError('external authority delta patch bytes or digest are not canonical', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const patch = parseCanonicalPatch(bytes, value.patchDigest, allowedGraphs, new Set(['base']));
  if (patch.deletions.length !== 0) {
    throw new CompilerError('external authority delta must be additive', { phase: 'candidate:external-authority-delta' });
  }
  const permittedOperations = exactSortedUniqueStrings(
    value.permittedOperations,
    /^[AD] .+$/,
    'external authority delta permitted operations',
  );
  const observedOperations = patch.operations.map(({ action, line }) => `${action} ${line}`).sort();
  if (canonicalJson(permittedOperations) !== canonicalJson(observedOperations)) {
    throw new CompilerError('external authority delta exceeds its exact permitted operation set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const roots = exactSortedUniqueStrings(value.casRootDigests, SHA256, 'external authority delta CAS roots', { minimum: 3 });
  if (!evidenceStore || typeof evidenceStore.verify !== 'function' || typeof evidenceStore.read !== 'function') {
    throw new CompilerError('external authority delta requires the canonical CAS reader and verifier', {
      phase: 'candidate:external-authority-delta',
    });
  }
  if (!Array.isArray(value.artifactDescriptors)
      || value.artifactDescriptors.length !== EXTERNAL_AUTHORITY_ARTIFACT_ROLES.length) {
    throw new CompilerError('external authority delta artifact descriptor set is incomplete', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const descriptorByRole = new Map();
  for (const descriptor of value.artifactDescriptors) {
    exactObjectKeys(descriptor, ['byteSize', 'digest', 'jcsDigest', 'role'],
      'external authority delta artifact descriptor');
    if (!EXTERNAL_AUTHORITY_ARTIFACT_ROLES.includes(descriptor.role)
        || descriptorByRole.has(descriptor.role)
        || !SHA256.test(descriptor.digest || '') || !SHA256.test(descriptor.jcsDigest || '')
        || !Number.isSafeInteger(descriptor.byteSize) || descriptor.byteSize < 1) {
      throw new CompilerError('external authority delta artifact descriptor is invalid', {
        phase: 'candidate:external-authority-delta',
      });
    }
    descriptorByRole.set(descriptor.role, descriptor);
  }
  if (canonicalJson([...descriptorByRole.keys()].sort()) !== canonicalJson(EXTERNAL_AUTHORITY_ARTIFACT_ROLES)
      || canonicalJson([...descriptorByRole.values()].map(({ digest: item }) => item).sort())
        !== canonicalJson(roots)) {
    throw new CompilerError('external authority delta artifact descriptors do not equal the CAS root set', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const verifiedArtifacts = new Map();
  const artifactBytes = new Map();
  for (const role of EXTERNAL_AUTHORITY_ARTIFACT_ROLES) {
    const descriptor = descriptorByRole.get(role);
    const verified = evidenceStore.verify(descriptor.digest);
    const read = evidenceStore.read(descriptor.digest);
    if (!verified || verified.digest !== descriptor.digest || !Number.isSafeInteger(verified.size)
        || verified.size !== descriptor.byteSize || !Buffer.isBuffer(read)
        || read.length !== descriptor.byteSize || sha256(read) !== descriptor.digest) {
      throw new CompilerError('external authority delta CAS verifier returned an invalid receipt', {
        phase: 'candidate:external-authority-delta', root: descriptor.digest,
      });
    }
    const parsed = parseCanonicalJsonArtifact(read, `external authority ${role} CAS artifact`);
    if (parsed.jcsDigest !== descriptor.jcsDigest) {
      throw new CompilerError('external authority delta CAS artifact JCS digest is invalid', {
        phase: 'candidate:external-authority-delta', root: descriptor.digest,
      });
    }
    verifiedArtifacts.set(descriptor.digest, Object.freeze({ byteSize: descriptor.byteSize, role }));
    artifactBytes.set(role, read);
  }
  const proofDocument = parseCanonicalJsonArtifact(artifactBytes.get('proof'),
    'external authority proof CAS artifact').value;
  const conflictBinding = conflictBindingFromProofDocument(proofDocument);
  const artifactValidation = validateExternalAuthorityArtifacts({
    artifacts: artifactBytes,
    authorityDigest: expectedAuthorityDigest,
    conflictBinding,
    correctionCandidateDigest: value.correctionCandidateDigest,
    now,
    ownerAssignmentIri: value.ownerAssignmentIri,
    predecessorSourceHead: expectedSource.head,
    predecessorSourceTree: expectedSource.tree,
    proofApprovalEnvelope: value.proofApprovalEnvelope,
    repository: expectedSource.repository,
    operationContentStore: evidenceStore,
    trustAnchor,
    verifyProofApprovalEnvelope,
  });
  const descriptorRoots = [...new Set(patch.additions
    .filter(({ value: item }) => item.predicate.value === `${USF}descriptorDigest` && SHA256.test(item.object.value))
    .map(({ value: item }) => item.object.value))].sort();
  if (canonicalJson(descriptorRoots) !== canonicalJson(roots)) {
    throw new CompilerError('external authority delta CAS roots do not equal its descriptor closure', {
      phase: 'candidate:external-authority-delta',
    });
  }

  const closedProofIri = assertExternalAuthorityClosedShape(
    patch,
    value,
    verifiedArtifacts,
    Object.freeze({ ...artifactValidation, proofApprovalEnvelope: value.proofApprovalEnvelope }),
  );

  requirePatchTriple(patch, value.conflictIri, RDF_TYPE, `${USF}AssuranceFinding`, 'authority-conflict type');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictAuthorityDigest`, expectedAuthorityDigest, 'authority digest');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictCandidateDigest`, value.correctionCandidateDigest, 'correction candidate digest');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictRepository`, value.repository, 'repository');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictPredecessorSourceHead`, expectedSource.head, 'predecessor head');
  requirePatchTriple(patch, value.conflictIri, `${USF}conflictPredecessorSourceTree`, expectedSource.tree, 'predecessor tree');
  requirePatchTriple(patch, value.reviewIri, RDF_TYPE, `${USF}SemanticAdequacyReview`, 'review type');
  requirePatchTriple(patch, value.reviewIri, `${USF}hasSemanticAdequacyReviewState`, 'urn:usf:semanticadequacyreviewstate:accepted', 'accepted review');
  requirePatchTriple(patch, value.reviewIri, `${USF}reviewedAuthorityDigest`, expectedAuthorityDigest, 'review authority');
  requirePatchTriple(patch, value.reviewIri, `${USF}reviewedInventoryDigest`, value.correctionCandidateDigest, 'review candidate');
  requirePatchTriple(patch, value.proofResultIri, RDF_TYPE, `${USF}ProofResult`, 'proof-result type');
  requirePatchTriple(patch, value.proofResultIri, `${USF}hasProofResultState`, 'urn:usf:proofresultstate:successful', 'successful proof');
  if (!patchHas(patch, closedProofIri, `${USF}provesSubject`, value.conflictIri)) {
    throw new CompilerError('external authority delta proof does not prove the exact conflict', {
      phase: 'candidate:external-authority-delta',
    });
  }
  requirePatchTriple(patch, value.resolutionIri, RDF_TYPE, `${USF}SemanticCorrectionDecision`, 'resolution type');
  requirePatchTriple(patch, value.resolutionIri, `${USF}resolvesAuthorityConflict`, value.conflictIri, 'resolved conflict');
  requirePatchTriple(patch, value.resolutionIri, `${USF}semanticCorrectionDecisionState`, 'urn:usf:semanticcorrectiondecisionstate:accepted', 'accepted resolution');
  requirePatchTriple(patch, value.resolutionIri, `${USF}decisionBasedOnSemanticAdequacyReview`, value.reviewIri, 'resolution review');
  requirePatchTriple(patch, value.resolutionIri, `${USF}warrantedBySemanticAdequacyProof`, value.proofResultIri, 'resolution proof');
  requirePatchTriple(patch, value.resolutionIri, `${USF}authorityConflictResolutionOwnerAssignment`, value.ownerAssignmentIri, 'resolution owner');
  return Object.freeze({
    casRootDigests: roots,
    conflictIri: value.conflictIri,
    correctionCandidateDigest: value.correctionCandidateDigest,
    patch,
    patchDigest: value.patchDigest,
    resolutionIri: value.resolutionIri,
    reviewIri: value.reviewIri,
    proofResultIri: value.proofResultIri,
  });
}

function createExternalAuthorityDeltaPackage({
  artifacts,
  authorityDigest,
  conflictBinding,
  correctionCandidateDigest,
  now = null,
  ownerAssignmentIri,
  predecessorSourceHead,
  predecessorSourceTree,
  proofApprovalEnvelope,
  repository,
  operationContentStore = null,
  trustAnchor,
  verifyProofApprovalEnvelope = missingExternalAuthorityProofVerifier,
}) {
  if (!SHA256.test(authorityDigest || '') || !SHA256.test(correctionCandidateDigest || '')
      || !GIT_OBJECT.test(predecessorSourceHead || '') || !GIT_OBJECT.test(predecessorSourceTree || '')
      || typeof repository !== 'string' || repository.length === 0
      || !/^urn:usf:ownerassignment:[a-z0-9:]+$/.test(ownerAssignmentIri || '')) {
    throw new CompilerError('external authority package inputs are not canonical', {
      phase: 'candidate:external-authority-delta',
    });
  }
  exactObjectKeys(conflictBinding, [
    'conflictingAuthorities', 'operationDigest', 'requestedActions', 'requestedEffects',
    'requestedFormats', 'requestedPaths', 'sourcePaths', 'sourceScopeDigest',
    'successorSourceTree', 'validationObligations',
  ], 'external authority conflict binding');
  const authorities = exactSortedUniqueStrings(
    conflictBinding.conflictingAuthorities,
    /^urn:usf:semanticcontract:[a-z0-9]+$/,
    'external authority conflicting authorities',
    { minimum: 2 },
  );
  const requestedActions = exactSortedUniqueStrings(
    conflictBinding.requestedActions,
    /^(create-directory|write-file|move-path|delete-path)$/,
    'external authority requested actions',
  );
  const requestedEffects = exactSortedUniqueStrings(
    conflictBinding.requestedEffects,
    /^urn:usf:obligationeffect:[a-z0-9]+$/,
    'external authority requested effects',
  );
  const requestedFormats = exactSortedUniqueStrings(
    conflictBinding.requestedFormats,
    /^urn:usf:representationformat:[a-z0-9]+$/,
    'external authority requested formats',
  );
  const requestedPaths = exactCanonicalRepositoryPaths(
    conflictBinding.requestedPaths,
    'external authority requested paths',
  );
  const sourcePaths = exactCanonicalRepositoryPaths(
    conflictBinding.sourcePaths,
    'external authority source paths',
  );
  const validationObligations = exactSortedUniqueStrings(
    conflictBinding.validationObligations,
    /^urn:usf:validationobligation:[a-z0-9]+$/,
    'external authority validation obligations',
  );
  if (!SHA256.test(conflictBinding.operationDigest || '')
      || !SHA256.test(conflictBinding.sourceScopeDigest || '')
      || !GIT_OBJECT.test(conflictBinding.successorSourceTree || '')) {
    throw new CompilerError('external authority conflict digest binding is invalid', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const expectedRoles = EXTERNAL_AUTHORITY_ARTIFACT_ROLES;
  if (!Array.isArray(artifacts) || artifacts.length !== expectedRoles.length) {
    throw new CompilerError('external authority package requires inventory, operations, review and proof artifacts', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const artifactByRole = new Map();
  for (const artifact of artifacts) {
    exactObjectKeys(artifact, ['bytes', 'role'], 'external authority artifact');
    if (!expectedRoles.includes(artifact.role) || artifactByRole.has(artifact.role)
        || !Buffer.isBuffer(artifact.bytes) || artifact.bytes.length < 2) {
      throw new CompilerError('external authority artifact identity is invalid', {
        phase: 'candidate:external-authority-delta',
      });
    }
    artifactByRole.set(artifact.role, Buffer.from(artifact.bytes));
  }
  if (canonicalJson([...artifactByRole.keys()].sort()) !== canonicalJson(expectedRoles)) {
    throw new CompilerError('external authority artifact role set is incomplete', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const artifactValidation = validateExternalAuthorityArtifacts({
    artifacts: artifactByRole,
    authorityDigest,
    conflictBinding,
    correctionCandidateDigest,
    now,
    ownerAssignmentIri,
    predecessorSourceHead,
    predecessorSourceTree,
    proofApprovalEnvelope,
    repository,
    operationContentStore,
    trustAnchor,
    verifyProofApprovalEnvelope,
  });
  const artifactRecords = new Map([...artifactValidation.artifacts].map(([role, artifact]) => [
    role,
    Object.freeze({ byteSize: artifact.byteSize, digest: artifact.digest, jcsDigest: artifact.jcsDigest, role }),
  ]));
  const roots = [...artifactRecords.values()].map(({ digest: item }) => item).sort();
  if (new Set(roots).size !== roots.length) {
    throw new CompilerError('external authority artifacts must have distinct content identities', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const suffix = correctionCandidateDigest.slice(7);
  const slug = `repositorymaterialisationvalidationcorrection${suffix}`;
  const conflictIri = `urn:usf:authorityconflict:${slug}`;
  const resolutionIri = `urn:usf:semanticcorrectiondecision:${slug}`;
  const reviewIri = `urn:usf:semanticadequacyreview:${slug}`;
  const proofIri = `urn:usf:proof:${slug}`;
  const proofResultIri = `urn:usf:proofresult:${slug}`;
  const signatureIri = `urn:usf:signature:${slug}`;
  const proofArtifact = artifactRecords.get('proof');
  const evaluatedAt = artifactValidation.proof.evaluatedAt;
  const validUntil = artifactValidation.proof.validUntil;
  const signatureValue = proofApprovalEnvelope.signature;
  const proofsGraph = 'urn:usf:graph:proofs';
  const evidenceGraph = 'urn:usf:graph:evidence';
  const literal = (item) => JSON.stringify(item);
  const iri = (item) => `<${item}>`;
  const line = (subject, predicate, object, graph) => `${iri(subject)} ${iri(predicate)} ${object} ${iri(graph)} .`;
  const type = (subject, object, graph) => line(subject, RDF_TYPE, iri(object), graph);
  const quads = [];
  const add = (subject, predicate, object, graph = proofsGraph) => quads.push(line(subject, predicate, object, graph));
  quads.push(type(conflictIri, `${USF}AssuranceFinding`, proofsGraph));
  add(conflictIri, `${USF}canonicalName`, literal(slug));
  add(conflictIri, `${USF}conflictAuthorityDigest`, literal(authorityDigest));
  for (const item of authorities) add(conflictIri, `${USF}conflictingAuthority`, iri(item));
  add(conflictIri, `${USF}conflictRepository`, literal(repository));
  add(conflictIri, `${USF}conflictOperationDigest`, literal(conflictBinding.operationDigest));
  add(conflictIri, `${USF}conflictCandidateDigest`, literal(correctionCandidateDigest));
  add(conflictIri, `${USF}conflictPredecessorSourceHead`, literal(predecessorSourceHead));
  add(conflictIri, `${USF}conflictPredecessorSourceTree`, literal(predecessorSourceTree));
  add(conflictIri, `${USF}conflictSuccessorSourceTree`, literal(conflictBinding.successorSourceTree));
  add(conflictIri, `${USF}conflictSourceScopeDigest`, literal(conflictBinding.sourceScopeDigest));
  for (const item of sourcePaths) add(conflictIri, `${USF}conflictSourcePath`, literal(item));
  for (const item of requestedActions) add(conflictIri, `${USF}conflictRequestedAction`, literal(item));
  for (const item of requestedPaths) add(conflictIri, `${USF}conflictRequestedPath`, literal(item));
  for (const item of requestedFormats) add(conflictIri, `${USF}conflictRequestedRepresentationFormat`, iri(item));
  for (const item of requestedEffects) add(conflictIri, `${USF}conflictRequestedEffect`, iri(item));
  for (const item of validationObligations) add(conflictIri, `${USF}conflictBlockedByValidationObligation`, iri(item));

  const descriptorFor = (role) => {
    const artifact = artifactRecords.get(role);
    return `urn:usf:externalpayloaddescriptor:${role}${artifact.digest.slice(7)}`;
  };
  quads.push(type(reviewIri, `${USF}SemanticAdequacyReview`, proofsGraph));
  add(reviewIri, `${USF}canonicalName`, literal(slug));
  add(reviewIri, `${USF}reviewedAuthorityDigest`, literal(authorityDigest));
  add(reviewIri, `${USF}reviewedInventoryDigest`, literal(correctionCandidateDigest));
  add(reviewIri, `${USF}reviewedItemCount`, '"1"^^<http://www.w3.org/2001/XMLSchema#integer>');
  add(reviewIri, `${USF}hasSemanticAdequacyReviewState`, iri('urn:usf:semanticadequacyreviewstate:accepted'));
  add(reviewIri, `${USF}usesDispositionInventoryDescriptor`, iri(descriptorFor('inventory')));
  add(reviewIri, `${USF}usesIndependentReviewDescriptor`, iri(descriptorFor('review')));
  add(reviewIri, `${USF}usesSemanticAdequacyProofDescriptor`, iri(descriptorFor('proof')));

  quads.push(type(proofIri, `${USF}Proof`, proofsGraph));
  add(proofIri, `${USF}canonicalName`, literal(slug));
  add(proofIri, `${USF}atRung`, iri('urn:usf:proofrung:behaviour'));
  add(proofIri, `${USF}usesProviderMode`, iri('urn:usf:providermode:deterministictestsubstitute'));
  add(proofIri, `${USF}inEnvironment`, iri('urn:usf:environment:hermetic'));
  add(proofIri, `${USF}exercises`, iri('urn:usf:semanticcontract:compilersemanticenforcement'));
  add(proofIri, `${USF}provesSubject`, iri(conflictIri));

  quads.push(type(proofResultIri, `${USF}ProofResult`, proofsGraph));
  add(proofResultIri, `${USF}canonicalName`, literal(slug));
  add(proofResultIri, `${USF}resultState`, iri('urn:usf:resultstate:passed'));
  add(proofResultIri, `${USF}resultForProof`, iri(proofIri));
  add(proofResultIri, `${USF}claimedRung`, iri('urn:usf:proofrung:behaviour'));
  add(proofResultIri, `${USF}observedRung`, iri('urn:usf:proofrung:behaviour'));
  add(proofResultIri, `${USF}hasFreshness`, iri('urn:usf:freshness:fresh'));
  add(proofResultIri, `${USF}usesProviderMode`, iri('urn:usf:providermode:deterministictestsubstitute'));
  add(proofResultIri, `${USF}inEnvironment`, iri('urn:usf:environment:hermetic'));
  add(proofResultIri, `${USF}hasProofResultState`, iri('urn:usf:proofresultstate:successful'));
  add(proofResultIri, `${USF}proofResultForObligation`, iri('urn:usf:proofobligation:compilersemanticenforcementaggregate'));
  add(proofResultIri, `${USF}evidenceSetDigest`, literal(artifactValidation.proof.evidenceSetDigest));
  add(proofResultIri, `${USF}usesProofAlgorithm`, iri('urn:usf:proofalgorithm:compilersemanticenforcementaggregate'));
  add(proofResultIri, `${USF}usesAlgorithmVersion`, iri('urn:usf:proofalgorithmversion:compilersemanticenforcementaggregatev210'));
  add(proofResultIri, `${USF}evaluatedByValidator`, iri('urn:usf:validatorrule:validateassuranceconformance'));
  add(proofResultIri, `${USF}proofExecutionEnvironment`, iri('urn:usf:environment:hermetic'));
  add(proofResultIri, `${USF}hasConfidenceState`, iri('urn:usf:proofconfidencestate:warranted'));
  add(proofResultIri, `${USF}uncertaintyStatement`, literal('This proof is bounded to the exact authority-conflict request, accepted independent review, canonical proof receipt and prospective source identity. It does not authorize pruning, Factory mutation, V2 activation, deployment or provider contact.'));
  add(proofResultIri, `${USF}evaluatedAt`, `"${evaluatedAt}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`);
  for (const item of ['authoritydigestchanged', 'evidenceinvalidated', 'evidencestale']) {
    add(proofResultIri, `${USF}hasInvalidationCondition`, iri(`urn:usf:proofinvalidationcondition:${item}`));
  }

  for (const role of expectedRoles) {
    const artifact = artifactRecords.get(role);
    const hex = artifact.digest.slice(7);
    const descriptor = descriptorFor(role);
    const evidence = `urn:usf:evidenceresult:${role}${hex}`;
    const collection = `urn:usf:evidencecollection:${role}${hex}`;
    const normalisation = `urn:usf:evidencenormalisation:${role}${hex}`;
    const ingestion = `urn:usf:evidenceingestion:${role}${hex}`;
    const integrity = `urn:usf:integrityverification:${role}${hex}`;
    const checksum = `urn:usf:checksum:${role}${hex}`;
    quads.push(type(descriptor, `${USF}ExternalPayloadDescriptor`, evidenceGraph));
    add(descriptor, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(descriptor, `${USF}descriptorArtefactFamily`, iri('urn:usf:artefactfamily:evidencepayload'), evidenceGraph);
    add(descriptor, `${USF}descriptorRepresentationFormat`, iri('urn:usf:representationformat:jsondata8259'), evidenceGraph);
    add(descriptor, `${USF}descriptorMediaType`, literal('application/json'), evidenceGraph);
    add(descriptor, `${USF}descriptorDigest`, literal(artifact.digest), evidenceGraph);
    add(descriptor, `${USF}descriptorByteSize`, `"${artifact.byteSize}"^^<http://www.w3.org/2001/XMLSchema#integer>`, evidenceGraph);
    add(descriptor, `${USF}descriptorLocator`, `"cas://sha256/${hex}"^^<http://www.w3.org/2001/XMLSchema#anyURI>`, evidenceGraph);
    add(descriptor, `${USF}descriptorArtefactType`, `"urn:usf:artefacttype:semanticadequacy${role}"^^<http://www.w3.org/2001/XMLSchema#anyURI>`, evidenceGraph);
    add(descriptor, `${USF}descriptorStorageClass`, iri('urn:usf:storageclass:contentaddressedobjectstorage'), evidenceGraph);
    if (!EXTERNAL_AUTHORITY_EVIDENCE_ROLES.includes(role)) continue;
    add(proofResultIri, `${USF}usesAdmittedEvidence`, iri(evidence));
    add(proofResultIri, `${USF}confidenceBasis`, iri(evidence));
    quads.push(type(evidence, `${USF}EvidenceResult`, evidenceGraph));
    add(evidence, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(evidence, `${USF}evidenceKind`, iri('urn:usf:evidencekind:semanticreviewevidence'), evidenceGraph);
    add(evidence, `${USF}usesProviderMode`, iri('urn:usf:providermode:deterministictestsubstitute'), evidenceGraph);
    add(evidence, `${USF}inEnvironment`, iri('urn:usf:environment:hermetic'), evidenceGraph);
    add(evidence, `${USF}hasFreshness`, iri('urn:usf:freshness:fresh'), evidenceGraph);
    add(evidence, `${USF}evidenceFor`, iri(conflictIri), evidenceGraph);
    add(evidence, `${USF}evidenceForContract`, iri('urn:usf:semanticcontract:compilersemanticenforcement'), evidenceGraph);
    add(evidence, `${USF}contentDigest`, literal(artifact.digest), evidenceGraph);
    add(evidence, `${USF}mediaType`, literal('application/json'), evidenceGraph);
    add(evidence, `${USF}byteSize`, `"${artifact.byteSize}"^^<http://www.w3.org/2001/XMLSchema#integer>`, evidenceGraph);
    add(evidence, `${USF}storageLocator`, `"cas://sha256/${hex}"^^<http://www.w3.org/2001/XMLSchema#anyURI>`, evidenceGraph);
    add(evidence, `${USF}wasProducedBy`, iri('urn:usf:validatorrule:validateassuranceconformance'), evidenceGraph);
    add(evidence, `${USF}collectedAt`, `"${evaluatedAt}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`, evidenceGraph);
    add(evidence, `${USF}validUntil`, `"${validUntil}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`, evidenceGraph);
    add(evidence, `${USF}hasFreshnessPolicy`, iri('urn:usf:evidencefreshnesspolicy:semanticadequacyreviewauthoritybound'), evidenceGraph);
    add(evidence, `${USF}hasAdmissionState`, iri('urn:usf:evidenceadmissionstate:admitted'), evidenceGraph);
    add(evidence, `${USF}hasFreshnessState`, iri('urn:usf:evidencefreshnessstate:fresh'), evidenceGraph);
    add(evidence, `${USF}hasIntegrityState`, iri('urn:usf:evidenceintegritystate:valid'), evidenceGraph);
    add(evidence, `${USF}concernsSemanticSubject`, iri(reviewIri), evidenceGraph);
    for (const stage of ['emitted', 'collected', 'normalised', 'ingested', 'signed', 'integrityverified']) {
      add(evidence, `${USF}evidenceStage`, iri(`urn:usf:evidencestage:${stage}`), evidenceGraph);
    }
    add(evidence, `${USF}collectedBy`, iri(collection), evidenceGraph);
    add(evidence, `${USF}normalisedBy`, iri(normalisation), evidenceGraph);
    add(evidence, `${USF}ingestedBy`, iri(ingestion), evidenceGraph);
    add(evidence, `${USF}evidenceSignature`, iri(signatureIri), evidenceGraph);
    add(evidence, `${USF}evidenceChecksum`, iri(checksum), evidenceGraph);
    add(evidence, `${USF}integrityVerification`, iri(integrity), evidenceGraph);
    add(evidence, `${USF}applicableToObligation`, iri('urn:usf:proofobligation:compilersemanticenforcementaggregate'), evidenceGraph);
    add(evidence, `${USF}withinValidityScope`, '"true"^^<http://www.w3.org/2001/XMLSchema#boolean>', evidenceGraph);
    quads.push(type(collection, `${USF}EvidenceCollection`, evidenceGraph));
    add(collection, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(collection, `${USF}collectionForRequirement`, iri('urn:usf:evidencerequirement:compilersemanticvalidation'), evidenceGraph);
    add(collection, `${USF}collectedEvidence`, iri(evidence), evidenceGraph);
    add(collection, `${USF}collectsEvidence`, iri(evidence), evidenceGraph);
    add(collection, `${USF}collectedOn`, `"${evaluatedAt}"^^<http://www.w3.org/2001/XMLSchema#dateTime>`, evidenceGraph);
    add(collection, `${USF}sourceDigest`, literal(artifact.digest), evidenceGraph);
    quads.push(type(normalisation, `${USF}EvidenceNormalisation`, evidenceGraph));
    add(normalisation, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(normalisation, `${USF}normalisesEvidence`, iri(evidence), evidenceGraph);
    quads.push(type(ingestion, `${USF}EvidenceIngestion`, evidenceGraph));
    add(ingestion, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(ingestion, `${USF}ingestsEvidence`, iri(evidence), evidenceGraph);
    quads.push(type(integrity, `${USF}IntegrityVerification`, evidenceGraph));
    add(integrity, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(integrity, `${USF}verifiesEvidence`, iri(evidence), evidenceGraph);
    add(integrity, `${USF}verificationState`, iri('urn:usf:resultstate:passed'), evidenceGraph);
    quads.push(type(checksum, `${USF}Checksum`, evidenceGraph));
    add(checksum, `${USF}canonicalName`, literal(`${role}${hex}`), evidenceGraph);
    add(checksum, `${USF}checksumAlgorithm`, iri('urn:usf:checksumalgorithm:sha256'), evidenceGraph);
    add(checksum, `${USF}checksumValue`, literal(hex), evidenceGraph);
  }
  quads.push(type(signatureIri, `${USF}Signature`, evidenceGraph));
  add(signatureIri, `${USF}canonicalName`, literal(slug), evidenceGraph);
  add(signatureIri, `${USF}artefactKind`, iri('urn:usf:artefactkind:signature'), evidenceGraph);
  add(signatureIri, `${USF}canonicalPath`, literal(`cas://sha256/${proofArtifact.digest.slice(7)}#signature`), evidenceGraph);
  add(signatureIri, `${USF}governedByPathRule`, iri('urn:usf:pathrule:contentaddressedsignature'), evidenceGraph);
  add(signatureIri, `${USF}signatureMethod`, iri('urn:usf:signaturemethod:detached'), evidenceGraph);
  add(signatureIri, `${USF}signingPolicy`, iri('urn:usf:policy:hermeticevidenceattestation'), evidenceGraph);
  add(signatureIri, `${USF}signedBy`, iri(AUTHORITY_SIGNING_IDENTITY), evidenceGraph);
  add(signatureIri, `${USF}signatureValue`, literal(signatureValue), evidenceGraph);

  quads.push(type(resolutionIri, `${USF}SemanticCorrectionDecision`, proofsGraph));
  add(resolutionIri, `${USF}canonicalName`, literal(slug));
  add(resolutionIri, `${USF}decisionRationale`, literal(artifactValidation.proof.value.decision.rationale));
  add(resolutionIri, `${USF}semanticCorrectionDecisionState`, iri('urn:usf:semanticcorrectiondecisionstate:accepted'));
  add(resolutionIri, `${USF}decisionBasedOnSemanticAdequacyReview`, iri(reviewIri));
  add(resolutionIri, `${USF}warrantedBySemanticAdequacyProof`, iri(proofResultIri));
  add(resolutionIri, `${USF}resolvesAuthorityConflict`, iri(conflictIri));
  add(resolutionIri, `${USF}authorityConflictResolutionOwnerAssignment`, iri(ownerAssignmentIri));

  const historical = `urn:usf:historicalitem:${suffix}`;
  add(historical, `${USF}sourceItemDigest`, literal(correctionCandidateDigest));
  add(historical, `${USF}reviewedInSemanticAdequacyReview`, iri(reviewIri));
  add(historical, `${USF}semanticAdequacyDisposition`, iri('urn:usf:semanticadequacydisposition:independentlywarrantedretained'));
  add(historical, `${USF}authorisedBySemanticCorrectionDecision`, iri(resolutionIri));
  add(historical, `${USF}finalCanonicalSemanticItem`, iri(conflictIri));

  const sortedQuads = [...new Set(quads)].sort();
  if (sortedQuads.length !== quads.length) {
    throw new CompilerError('external authority package contains duplicate semantic operations', {
      phase: 'candidate:external-authority-delta',
    });
  }
  const patchBytes = Buffer.from([
    '# semantic-proof-v1 canonical-rdf-patch-v1 base',
    ...sortedQuads.map((item) => `A ${item}`),
    '',
  ].join('\n'));
  return Object.freeze({
    artifactDescriptors: Object.freeze([...artifactRecords.values()]
      .map((descriptor) => Object.freeze({ ...descriptor })).sort((left, right) => left.role.localeCompare(right.role))),
    authorityDigest,
    casRootDigests: Object.freeze(roots),
    conflictIri,
    correctionCandidateDigest,
    ownerAssignmentIri,
    patchBytesBase64: patchBytes.toString('base64'),
    patchDigest: sha256(patchBytes),
    permittedOperations: Object.freeze(sortedQuads.map((item) => `A ${item}`)),
    predecessorSourceHead,
    predecessorSourceTree,
    proofApprovalEnvelope,
    proofResultIri,
    repository,
    resolutionIri,
    reviewIri,
    schema: EXTERNAL_AUTHORITY_DELTA_SCHEMA,
  });
}

function triple(item) {
  return quad(item.subject, item.predicate, item.object, defaultGraph());
}

async function graphText(store) {
  return new Promise((resolveText, reject) => {
    const writer = new Writer({ format: 'N-Triples' });
    writer.addQuads(store.getQuads(null, null, null, null));
    writer.end((error, output) => error ? reject(error) : resolveText(output));
  });
}

async function nquadsText(quads) {
  return new Promise((resolveText, reject) => {
    const writer = new Writer({ format: 'N-Quads' });
    writer.addQuads(quads);
    writer.end((error, output) => error ? reject(error) : resolveText(output));
  });
}

async function readCanonicalStores(client, transaction, graphs) {
  const graphNames = [...new Set(graphs)].sort();
  const dataset = [];
  for (const graph of graphNames) {
    const content = await client.constructInTransaction(
      transaction,
      `CONSTRUCT { ?s ?p ?o } WHERE { GRAPH <${graph}> { ?s ?p ?o } }`,
    );
    let values;
    try {
      values = new Parser({ format: TURTLE, baseIRI: 'urn:usf:' }).parse(content || '');
    } catch (error) {
      throw new CompilerError(`managed graph could not be isolated for candidate application: ${error.message}`, {
        phase: 'candidate:isolation', graph,
      });
    }
    dataset.push(...values.map((item) => quad(item.subject, item.predicate, item.object, namedNode(graph))));
  }
  const canonical = await canonicalNQuads(await nquadsText(dataset));
  const stores = new Map(graphNames.map((graph) => [graph, new Store()]));
  for (const item of new Parser({ format: NQUADS, blankNodePrefix: '' }).parse(canonical)) {
    stores.get(item.graph.value).addQuad(triple(item));
  }
  return Object.freeze({ canonical, stores });
}

async function readAffectedStores(client, transaction, patch) {
  return (await readCanonicalStores(
    client,
    transaction,
    patch.operations.map(({ value }) => value.graph.value),
  )).stores;
}

async function replaceStores(client, transaction, stores) {
  const graphs = [...stores.keys()].sort();
  await client.clearGraphs(transaction, graphs);
  for (const graph of graphs) {
    const content = await graphText(stores.get(graph));
    if (content.trim()) await client.addData(transaction, content, NTRIPLES, graph);
  }
}

async function applyDesiredPatch(client, transaction, patch) {
  const stores = await readAffectedStores(client, transaction, patch);
  for (const { value } of patch.deletions) stores.get(value.graph.value).removeQuad(triple(value));
  for (const { value } of patch.additions) stores.get(value.graph.value).addQuad(triple(value));
  await replaceStores(client, transaction, stores);
}

function canonicalCombinedPatch(stage, before, after) {
  const prior = new Set(before.split('\n').filter(Boolean));
  const target = new Set(after.split('\n').filter(Boolean));
  const deletions = [...prior].filter((line) => !target.has(line)).sort();
  const additions = [...target].filter((line) => !prior.has(line)).sort();
  if (deletions.length + additions.length === 0) {
    throw new CompilerError('combined semantic candidate contains no authority transition', { phase: 'candidate:source-delta' });
  }
  if (!['base', 'stage1', 'stage2'].includes(stage)) {
    throw new CompilerError('combined semantic candidate stage is invalid', { phase: 'candidate:source-delta' });
  }
  return Buffer.from([
    `# semantic-proof-v1 canonical-rdf-patch-v1 ${stage}`,
    ...deletions.map((line) => `D ${line}`),
    ...additions.map((line) => `A ${line}`),
    '',
  ].join('\n'), 'utf8');
}

async function composeSourceCandidate({
  client,
  manifest,
  generatedPatch = null,
  preservedPatch = null,
  validationContextPatch = null,
  authorityWitness,
  compileFunction,
  stage,
}) {
  const graphs = [...managedGraphs(manifest)].sort();
  let beforeDataset;
  let targetDataset;
  let generatedApplied = false;
  let validationContextBaseline = null;
  const overrides = {
    async begin() {
      const transaction = await client.begin();
      beforeDataset = await readCanonicalStores(client, transaction, graphs);
      return transaction;
    },
    async validateInTransactionWithReceipt(transaction, shapes) {
      if (!generatedApplied) {
        if (preservedPatch) await applyDesiredPatch(client, transaction, preservedPatch);
        if (generatedPatch) await applyDesiredPatch(client, transaction, generatedPatch);
        if (validationContextPatch) {
          validationContextBaseline = await readAffectedStores(client, transaction, validationContextPatch);
          await applyDesiredPatch(client, transaction, validationContextPatch);
        }
        generatedApplied = true;
      }
      return client.validateInTransactionWithReceipt(transaction, shapes);
    },
    async rollback(transaction) {
      if (generatedApplied && !targetDataset) {
        if (validationContextBaseline) await replaceStores(client, transaction, validationContextBaseline);
        targetDataset = await readCanonicalStores(client, transaction, graphs);
      }
      return client.rollback(transaction);
    },
    async commit() {
      throw new CompilerError('source candidate composition must never commit', { phase: 'candidate:source-delta' });
    },
  };
  const compositionClient = new Proxy(Object.create(null), {
    get(_target, property) {
      if (Object.hasOwn(overrides, property)) return overrides[property];
      const value = Reflect.get(client, property, client);
      return typeof value === 'function' ? value.bind(client) : value;
    },
    set() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
    defineProperty() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
    deleteProperty() { throw new CompilerError('source candidate composition client is read-only', { phase: 'candidate:source-delta' }); },
  });
  const sourceValidation = await compileFunction({
    authorityWitness,
    client: compositionClient,
    manifest,
    publicationBudgetPolicy: manifest.publicationBudget,
    publicationMode: 'validate',
  });
  if (!beforeDataset || !targetDataset || generatedApplied !== true || sourceValidation?.ok !== true) {
    throw new CompilerError('full source candidate could not be constructed and validated', { phase: 'candidate:source-delta' });
  }
  const candidateStage = stage || PATCH_HEADER.exec(generatedPatch?.bytes.toString('utf8').split('\n', 1)[0])?.[1];
  const bytes = canonicalCombinedPatch(candidateStage, beforeDataset.canonical, targetDataset.canonical);
  const combined = candidateStage === 'base'
    ? Object.freeze({ bytes, digest: sha256(bytes) })
    : parseCanonicalPatch(bytes, undefined, new Set(graphs));
  for (const operation of [...(preservedPatch?.operations || []), ...(generatedPatch?.operations || [])]) {
    const targetStore = targetDataset.stores.get(operation.value.graph.value);
    const present = targetStore?.has(
      operation.value.subject, operation.value.predicate, operation.value.object, null,
    ) === true;
    if ((operation.action === 'A') !== present) {
      const operationLabel = `${operation.action} ${operation.line}`;
      throw new CompilerError(`generated aggregate intent was not preserved by full source composition: ${operationLabel}`, {
        phase: 'candidate:source-delta', operation: operationLabel,
      });
    }
  }
  return Object.freeze({
    bytes: combined.bytes,
    digest: combined.digest,
    sourceValidation: Object.freeze(sourceValidation.liveValidation || {}),
  });
}

function patchState(stores, patch) {
  const present = ({ value }) => stores.get(value.graph.value).has(
    value.subject, value.predicate, value.object, null,
  );
  const pre = patch.deletions.every(present) && patch.additions.every((entry) => !present(entry));
  const post = patch.deletions.every((entry) => !present(entry)) && patch.additions.every(present);
  return pre && !post ? 'pre' : post && !pre ? 'post' : 'mixed';
}

async function inspectPatchState(client, patch) {
  let transaction;
  try {
    transaction = await client.begin();
    const stores = await readAffectedStores(client, transaction, patch);
    const state = patchState(stores, patch);
    await client.rollback(transaction);
    transaction = null;
    return state;
  } finally {
    if (transaction) await client.rollback(transaction);
  }
}

async function compilePatch({ client, manifest, patch, publicationMode, readText = readFileSync }) {
  let transaction;
  try {
    transaction = await client.begin();
    const stores = await readAffectedStores(client, transaction, patch);
    if (patchState(stores, patch) !== 'pre') {
      throw new CompilerError('candidate does not match the exact live pre-state', { phase: 'candidate:precondition' });
    }
    for (const { value } of patch.deletions) stores.get(value.graph.value).removeQuad(triple(value));
    for (const { value } of patch.additions) stores.get(value.graph.value).addQuad(triple(value));
    if (patchState(stores, patch) !== 'post') {
      throw new CompilerError('candidate post-state could not be constructed exactly', { phase: 'candidate:postcondition' });
    }
    await replaceStores(client, transaction, stores);
    const shapes = shapeConstraints(manifest);
    const validation = await client.validateInTransactionWithReceipt(transaction, shapes);
    if (validation?.conforms !== true) {
      const report = await client.reportInTransaction(transaction, shapes);
      throw new CompilerError('RDF Patch candidate failed live SHACL validation', {
        phase: 'candidate:shacl', report,
      });
    }
    for (const rule of integrityRules(manifest)) {
      const violations = await client.selectInTransaction(transaction, readText(rule.path, 'utf8'));
      if (violations.length > 0) {
        throw new CompilerError('RDF Patch candidate failed semantic integrity validation', {
          phase: 'candidate:integrity', integrityRule: rule.file, violations: violations.slice(0, 20),
        });
      }
    }
    const projectedStatements = Number.isSafeInteger(manifest.publicationBudget?.maximumProjectedStatementCount)
      ? manifest.publicationBudget.maximumProjectedStatementCount
      : null;
    if (projectedStatements === null) {
      throw new CompilerError('candidate publication budget policy is unavailable', { phase: 'candidate:budget' });
    }
    if (publicationMode === 'validate') {
      await client.rollback(transaction);
      transaction = null;
      return Object.freeze({
        ok: true,
        liveValidation: Object.freeze(validation),
        commitOutcome: Object.freeze({
          candidateDigest: patch.digest,
          exactCandidateStateVerified: true,
          state: 'VALIDATED_ROLLBACK',
        }),
      });
    }
    await client.commit(transaction);
    transaction = null;
    return Object.freeze({
      ok: true,
      liveValidation: Object.freeze(validation),
      commitOutcome: Object.freeze({
        candidateDigest: patch.digest,
        exactCandidateStateVerified: true,
        state: 'COMMITTED',
      }),
    });
  } catch (error) {
    if (transaction) {
      try { await client.rollback(transaction); } catch { /* preserve the primary failure */ }
    }
    if (error instanceof CompilerError) throw error;
    throw new CompilerError(error.message, { phase: 'candidate:transaction' });
  }
}

function digest(value) {
  const observed = value?.digest || value?.authorityDigest;
  if (typeof observed !== 'string') throw new CompilerError('authority witness is missing its digest', { phase: 'authority:witness' });
  return observed.startsWith('sha256:') ? observed : `sha256:${observed}`;
}

function semanticModelDirectory(repositoryRoot) {
  const root = realpathSync(repositoryRoot);
  const candidate = resolve(root, SEMANTIC_MODEL_PATH);
  const repositoryRelative = relative(root, candidate);
  if (repositoryRelative !== SEMANTIC_MODEL_PATH || repositoryRelative.startsWith(`..${sep}`)) {
    throw new CompilerError('semantic model path escapes the repository', { phase: 'compile:configuration' });
  }
  if (lstatSync(candidate).isSymbolicLink()) throw new CompilerError('semantic model path must not be a symbolic link', { phase: 'compile:configuration' });
  const canonical = realpathSync(candidate);
  if (relative(root, canonical) !== SEMANTIC_MODEL_PATH) throw new CompilerError('semantic model path resolves outside its canonical repository role', { phase: 'compile:configuration' });
  return canonical;
}

function validationEvidence(result, authorityDigest, candidateDigest) {
  if (!result?.liveValidation || result.liveValidation.conforms !== true) {
    throw new CompilerError('candidate validation returned no conforming provider receipt', { phase: 'candidate:validation-receipt' });
  }
  const record = Object.freeze({
    authorityDigest,
    candidateDigest,
    providerValidationReceipt: result.liveValidation,
    schema: 'semantic-authority-compiler-validation-report-v1',
    state: result.commitOutcome.state,
  });
  const bytes = Buffer.from(`${canonicalJson(record)}\n`, 'utf8');
  return Object.freeze({ bytes, digest: sha256(bytes), record });
}

function sourceValidationEvidence(sourceValidation, authorityDigest, candidateDigest) {
  if (!sourceValidation || sourceValidation.derived?.conforms !== true) {
    throw new CompilerError('base source preparation returned no real derived validation receipt', {
      phase: 'candidate:validation-receipt',
    });
  }
  const record = Object.freeze({
    authorityDigest,
    candidateDigest,
    providerValidationReceipt: sourceValidation,
    schema: 'semantic-authority-compiler-source-validation-report-v1',
    state: 'VALIDATED_ROLLBACK',
  });
  const bytes = Buffer.from(canonicalJson(record), 'utf8');
  return Object.freeze({ bytes, digest: sha256(bytes), record });
}

export function createSemanticModelCompilationCommand({
  client,
  readAuthorityWitness,
  repositoryRoot,
  loadManifestFunction = loadManifest,
  compileFunction = compile,
  checkLocalFunction = checkLocal,
  externalAuthorityTrustAnchor,
  trustedNow = null,
  verifyExternalAuthorityProofApproval = missingExternalAuthorityProofVerifier,
}) {
  if (!client || typeof client.connectivity !== 'function') throw new TypeError('semantic authority client is required');
  if (typeof readAuthorityWitness !== 'function') throw new TypeError('authority witness reader is required');
  if (typeof repositoryRoot !== 'string') throw new TypeError('repository root is required');

  return Object.freeze({
    requiresCandidateBytes: true,

    async validateExternalAuthorityDelta({
      expectedAuthorityDigest,
      evidenceStore,
      expectedSource,
      externalAuthorityDelta,
      trustedNow: operationTrustedNow = null,
    }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) {
        throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      }
      const before = digest(await readAuthorityWitness(client));
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before external delta validation', { phase: 'authority:drift' });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const observedNow = await resolveExternalAuthorityTrustedNow(operationTrustedNow, trustedNow);
      const external = assertExternalAuthorityDelta({
        value: externalAuthorityDelta,
        expectedAuthorityDigest,
        expectedSource,
        evidenceStore,
        allowedGraphs: new Set(managedGraphs(manifest)),
        now: observedNow,
        trustAnchor: externalAuthorityTrustAnchor,
        verifyProofApprovalEnvelope: verifyExternalAuthorityProofApproval,
      });
      if (await inspectPatchState(client, external.patch) !== 'pre') {
        throw new CompilerError('external authority delta is not an unused exact live pre-state', {
          phase: 'candidate:external-authority-delta-replay',
        });
      }
      if (digest(await readAuthorityWitness(client)) !== before) {
        throw new CompilerError('external delta validation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      return Object.freeze({
        casRootDigests: external.casRootDigests,
        conflictIri: external.conflictIri,
        correctionCandidateDigest: external.correctionCandidateDigest,
        patchDigest: external.patchDigest,
        proofResultIri: external.proofResultIri,
        resolutionIri: external.resolutionIri,
        reviewIri: external.reviewIri,
      });
    },

    async prepareSourceDelta({
      expectedAuthorityDigest,
      evidenceStore = null,
      expectedSource = null,
      externalAuthorityDelta = null,
      validationAuthorityContext = null,
      trustedNow: operationTrustedNow = null,
    }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) throw new CompilerError('semantic authority drifted before base source preparation', { phase: 'authority:drift' });
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const observedNow = externalAuthorityDelta === null
        ? null
        : await resolveExternalAuthorityTrustedNow(operationTrustedNow, trustedNow);
      const external = externalAuthorityDelta === null ? null : assertExternalAuthorityDelta({
        value: externalAuthorityDelta,
        expectedAuthorityDigest,
        expectedSource,
        evidenceStore,
        allowedGraphs: new Set(managedGraphs(manifest)),
        now: observedNow,
        trustAnchor: externalAuthorityTrustAnchor,
        verifyProofApprovalEnvelope: verifyExternalAuthorityProofApproval,
      });
      if (external !== null && await inspectPatchState(client, external.patch) !== 'pre') {
        throw new CompilerError('external authority delta is not an unused exact live pre-state', {
          phase: 'candidate:external-authority-delta-replay',
        });
      }
      let validationContextPatch = null;
      if (validationAuthorityContext !== null) {
        exactObjectKeys(validationAuthorityContext, ['bytesBase64', 'digest'], 'validation authority context');
        const contextBytes = Buffer.from(validationAuthorityContext.bytesBase64, 'base64');
        if (contextBytes.toString('base64') !== validationAuthorityContext.bytesBase64) {
          throw new CompilerError('validation authority context bytes are not canonical base64', {
            phase: 'candidate:source-delta',
          });
        }
        validationContextPatch = parseCanonicalPatch(
          contextBytes, validationAuthorityContext.digest, new Set(managedGraphs(manifest)), new Set(['base']),
        );
        if (validationContextPatch.deletions.length !== 0) {
          throw new CompilerError('validation authority context must remain additive', {
            phase: 'candidate:source-delta',
          });
        }
      }
      const prepared = await composeSourceCandidate({
        client,
        manifest,
        generatedPatch: external?.patch || null,
        validationContextPatch,
        authorityWitness: beforeWitness,
        compileFunction,
        stage: 'base',
      });
      if (digest(await readAuthorityWitness(client)) !== before) {
        throw new CompilerError('base source preparation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      const validation = sourceValidationEvidence(prepared.sourceValidation, before, prepared.digest);
      return Object.freeze({
        baseSemanticDelta: Object.freeze({
          authorityPreDigest: before,
          bytesBase64: prepared.bytes.toString('base64'),
          candidateDigest: prepared.digest,
          exactCandidateStateVerified: true,
          mediaType: 'application/rdf-patch',
          state: 'VALIDATED_ROLLBACK',
          validationReceiptDigest: validation.digest,
        }),
        externalAuthorityDelta: external === null ? null : Object.freeze({
          casRootDigests: external.casRootDigests,
          conflictIri: external.conflictIri,
          correctionCandidateDigest: external.correctionCandidateDigest,
          patchDigest: external.patchDigest,
          proofResultIri: external.proofResultIri,
          resolutionIri: external.resolutionIri,
          reviewIri: external.reviewIri,
        }),
        preservedAuthorityDelta: external === null ? null : Object.freeze({
          bytesBase64: external.patch.bytes.toString('base64'),
          digest: external.patch.digest,
        }),
        validationEvidence: validation,
      });
    },

    async composeCandidate({ generatedCandidateBytes, expectedAuthorityDigest, preservedAuthorityDelta = null }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before source candidate composition', {
          phase: 'authority:drift', expectedAuthorityDigest, observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const allowedGraphs = new Set(managedGraphs(manifest));
      const generatedPatch = parseCanonicalPatch(generatedCandidateBytes, undefined, allowedGraphs);
      let preservedPatch = null;
      if (preservedAuthorityDelta !== null) {
        exactObjectKeys(preservedAuthorityDelta, ['bytesBase64', 'digest'], 'preserved authority delta');
        const preservedBytes = Buffer.from(preservedAuthorityDelta.bytesBase64, 'base64');
        if (preservedBytes.toString('base64') !== preservedAuthorityDelta.bytesBase64) {
          throw new CompilerError('preserved authority delta bytes are not canonical base64', {
            phase: 'candidate:external-authority-delta',
          });
        }
        preservedPatch = parseCanonicalPatch(
          preservedBytes,
          preservedAuthorityDelta.digest,
          allowedGraphs,
          new Set(['base']),
        );
        if (preservedPatch.deletions.length !== 0) {
          throw new CompilerError('preserved authority delta must remain additive', {
            phase: 'candidate:external-authority-delta',
          });
        }
      }
      const combined = await composeSourceCandidate({
        client, manifest, generatedPatch, preservedPatch, authorityWitness: beforeWitness, compileFunction,
      });
      const after = digest(await readAuthorityWitness(client));
      if (after !== before) throw new CompilerError('source candidate composition changed semantic authority', { phase: 'authority:validate-drift' });
      return combined;
    },

    async previewCandidateInventory({ candidateBytes, candidateDigest, expectedAuthorityDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      if (digest(await readAuthorityWitness(client)) !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before candidate preview', { phase: 'authority:drift' });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const patch = parseCanonicalPatch(candidateBytes, candidateDigest, new Set(managedGraphs(manifest)));
      let transaction;
      try {
        transaction = await client.begin();
        const current = await readCanonicalStores(client, transaction, managedGraphs(manifest));
        if (patchState(current.stores, patch) !== 'pre') {
          throw new CompilerError('candidate preview does not match the exact live pre-state', { phase: 'candidate:precondition' });
        }
        for (const { value } of patch.deletions) current.stores.get(value.graph.value).removeQuad(triple(value));
        for (const { value } of patch.additions) current.stores.get(value.graph.value).addQuad(triple(value));
        if (patchState(current.stores, patch) !== 'post') {
          throw new CompilerError('candidate preview could not construct the exact target state', { phase: 'candidate:postcondition' });
        }
        const inventory = [];
        for (const [graph, store] of [...current.stores.entries()].sort(([left], [right]) => left.localeCompare(right))) {
          const record = await canonicalInventoryGraphDigest(graph, await graphText(store));
          inventory.push(Object.freeze({ graph, sha256: `sha256:${record.sha256}`, triples: record.triples }));
        }
        await client.rollback(transaction);
        transaction = null;
        return Object.freeze({ candidateDigest: patch.digest, inventory: Object.freeze(inventory) });
      } finally {
        if (transaction) await client.rollback(transaction);
      }
    },

    async inspectCandidateState({ candidateBytes, candidateDigest }) {
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      checkLocalFunction(manifest);
      const patch = parseCanonicalPatch(candidateBytes, candidateDigest, new Set(managedGraphs(manifest)));
      return Object.freeze({ candidateDigest: patch.digest, state: await inspectPatchState(client, patch) });
    },

    async execute({ expectedAuthorityDigest, publicationMode = 'validate', candidateBytes, candidateDigest }) {
      if (!SHA256.test(expectedAuthorityDigest || '')) throw new CompilerError('expected authority digest is required', { phase: 'authority:configuration' });
      const beforeWitness = await readAuthorityWitness(client);
      const before = digest(beforeWitness);
      if (before !== expectedAuthorityDigest) {
        throw new CompilerError('semantic authority drifted before compilation', {
          phase: 'authority:drift',
          expectedAuthorityDigest,
          observedAuthorityDigest: before,
        });
      }
      const manifest = loadManifestFunction(semanticModelDirectory(repositoryRoot));
      if (candidateBytes !== undefined || candidateDigest !== undefined) {
        checkLocalFunction(manifest);
        const patch = parseCanonicalPatch(candidateBytes, candidateDigest, new Set(managedGraphs(manifest)));
        const result = await compilePatch({ client, manifest, patch, publicationMode });
        if (publicationMode === 'validate') {
          const after = digest(await readAuthorityWitness(client));
          if (after !== before) throw new CompilerError('validate-only RDF Patch changed semantic authority', { phase: 'authority:validate-drift' });
        }
        return Object.freeze({
          ...result,
          evaluatedAuthorityDigest: before,
          semanticModelPath: SEMANTIC_MODEL_PATH,
          validationEvidence: validationEvidence(result, before, patch.digest),
        });
      }
      const result = await compileFunction({
        authorityWitness: beforeWitness,
        client,
        manifest,
        publicationBudgetPolicy: manifest.publicationBudget,
        publicationMode,
      });
      if (publicationMode === 'validate') {
        const after = digest(await readAuthorityWitness(client));
        if (after !== before) throw new CompilerError('validate-only compilation changed semantic authority', { phase: 'authority:validate-drift' });
      }
      return Object.freeze({
        ...result,
        evaluatedAuthorityDigest: before,
        semanticModelPath: SEMANTIC_MODEL_PATH,
      });
    },
  });
}

export const semanticModelCompilationCommandInternals = Object.freeze({
  assertExternalAuthorityDelta,
  createExternalAuthorityDeltaPackage,
  digest,
  exactCandidateBytes,
  canonicalCombinedPatch,
  composeSourceCandidate,
  parseCanonicalPatch,
  patchState,
  semanticModelDirectory,
});
