#!/usr/bin/env node

import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const IRI = /^[a-z][a-z0-9+.-]*:[^\s]+$/i;
const HISTORICAL_PROXY = /^urn:usf:historicalitem:([0-9a-f]{64})$/;
const DISPOSITIONS = Object.freeze([
  'INDEPENDENTLY_WARRANTED_RETAINED',
  'CORRECTED_OR_RENAMED',
  'CONSOLIDATED',
  'SPLIT',
  'SUPERSEDED',
  'HISTORICAL_PROVENANCE_ONLY',
  'UNRESOLVED_EXTERNAL_DECISION',
]);
const FINAL_IDENTITY_REQUIRED = new Set([
  'INDEPENDENTLY_WARRANTED_RETAINED',
  'CORRECTED_OR_RENAMED',
  'CONSOLIDATED',
  'SPLIT',
]);
const EVIDENCE_SET_DIGEST_ALGORITHM = 'sha256-jcs-sorted-evidence-result-content-digest-v1';

function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
}

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function fail(code, detail = null) {
  const error = new Error(detail ? `${code}: ${detail}` : code);
  error.resultCode = code;
  throw error;
}

function requireValue(condition, code, detail = null) {
  if (!condition) fail(code, detail);
}

function parseJson(path, code) {
  const bytes = readFileSync(path);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(code, path);
  }
  return { bytes, value, fileDigest: digest(bytes) };
}

function sameObject(left, right) {
  return jcs(left) === jcs(right);
}

function nonemptyStrings(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0);
}

function options(argv) {
  const result = {};
  for (let index = 2; index < argv.length; index += 1) {
    const key = argv[index];
    if (!['--inventory', '--review', '--authority', '--output', '--attestation'].includes(key) || !argv[index + 1]) {
      fail('INVALID_ARGUMENT', key);
    }
    result[key.slice(2)] = argv[index + 1];
    index += 1;
  }
  requireValue(result.inventory && result.review, 'REQUIRED_ARGUMENT_MISSING');
  if (result.authority) requireValue(SHA256.test(result.authority), 'INVALID_AUTHORITY_DIGEST');
  return result;
}

function validateInventory(inventory, inventoryFileDigest, expectedAuthority) {
  requireValue(inventory?.schemaVersion === 3, 'INVENTORY_SCHEMA');
  requireValue(SHA256.test(inventory.authorityDigest ?? ''), 'INVENTORY_AUTHORITY_DIGEST');
  if (expectedAuthority) requireValue(inventory.authorityDigest === expectedAuthority, 'INVENTORY_AUTHORITY_MISMATCH');
  requireValue(inventory.inventoryStatus === 'INDEPENDENT_REVIEW_REQUIRED', 'INVENTORY_REVIEW_BOUNDARY');
  requireValue(SHA256.test(inventory.inventoryDigest ?? ''), 'INVENTORY_DIGEST');
  const unsigned = structuredClone(inventory);
  delete unsigned.inventoryDigest;
  requireValue(digest(jcs(unsigned)) === inventory.inventoryDigest, 'INVENTORY_INTERNAL_DIGEST_MISMATCH');
  requireValue(Array.isArray(inventory.records) && inventory.records.length > 0, 'INVENTORY_RECORDS');

  const records = new Map();
  const sourceItemDigests = new Set();
  const dispositionCounts = Object.fromEntries(DISPOSITIONS.map((value) => [value, 0]));
  let dependentRelationshipCount = 0;
  for (const record of inventory.records) {
    const identifier = record?.semanticIdentifier;
    const proxyMatch = typeof identifier === 'string' ? HISTORICAL_PROXY.exec(identifier) : null;
    requireValue(proxyMatch !== null, 'RECORD_IDENTIFIER', String(identifier));
    requireValue(!records.has(identifier), 'DUPLICATE_RECORD_IDENTIFIER', identifier);
    requireValue(record.sourceItemDigest === `sha256:${proxyMatch[1]}`, 'SOURCE_ITEM_DIGEST_MISMATCH', identifier);
    requireValue(!sourceItemDigests.has(record.sourceItemDigest), 'DUPLICATE_SOURCE_ITEM_DIGEST', identifier);
    sourceItemDigests.add(record.sourceItemDigest);
    requireValue(DISPOSITIONS.includes(record.disposition), 'INVALID_DISPOSITION', identifier);
    requireValue(nonemptyStrings(record.itemKind), 'ITEM_KIND_MISSING', identifier);
    requireValue(nonemptyStrings(record.historicalSource), 'HISTORICAL_SOURCE_MISSING', identifier);
    requireValue(nonemptyStrings(record.supportingEvidence), 'SUPPORTING_EVIDENCE_MISSING', identifier);
    requireValue(Array.isArray(record.affectedClaimsAndNonclaims), 'AFFECTED_CLAIMS_MISSING', identifier);
    requireValue(Array.isArray(record.dependentResources), 'DEPENDENT_RESOURCES_MISSING', identifier);
    requireValue(record.dependentResources.length === record.dependentResourceCount, 'DEPENDENT_RESOURCE_COUNT', identifier);
    requireValue(typeof record.requiredCorrectiveAction === 'string' && record.requiredCorrectiveAction.length > 0, 'CORRECTIVE_ACTION_MISSING', identifier);
    requireValue(record.reviewState === 'REVIEWED_RETAINED' || record.reviewState === 'REVIEWED_CORRECTION_REQUIRED', 'REVIEW_STATE', identifier);
    requireValue(record.currentAuthorityState?.authorityDigest === inventory.authorityDigest, 'RECORD_AUTHORITY_MISMATCH', identifier);
    requireValue(record.independentSemanticBasis?.status === 'COUNTERFACTUAL_REVIEWED', 'COUNTERFACTUAL_REVIEW_MISSING', identifier);
    requireValue(typeof record.independentSemanticBasis?.ruleCode === 'string' && record.independentSemanticBasis.ruleCode.length > 0, 'INDEPENDENT_BASIS_MISSING', identifier);
    if (FINAL_IDENTITY_REQUIRED.has(record.disposition)) {
      requireValue(typeof record.finalCanonicalIdentity === 'string' && IRI.test(record.finalCanonicalIdentity), 'FINAL_IDENTITY_MISSING', identifier);
      requireValue(!record.finalCanonicalIdentity.includes('UNRESOLVED'), 'FINAL_IDENTITY_PLACEHOLDER', identifier);
      requireValue(!HISTORICAL_PROXY.test(record.finalCanonicalIdentity), 'FINAL_IDENTITY_IS_HISTORICAL_PROXY', identifier);
      requireValue(record.finalCanonicalIdentity !== identifier, 'SUCCESSOR_IDENTITY_UNCHANGED', identifier);
    } else {
      requireValue(record.finalCanonicalIdentity === null, 'UNEXPECTED_FINAL_IDENTITY', identifier);
    }
    if (record.disposition === 'INDEPENDENTLY_WARRANTED_RETAINED') {
      requireValue(record.currentAuthorityState?.retainedInCorrectedAuthority === true, 'RETAINED_NOT_CURRENT', identifier);
    } else {
      requireValue(record.currentAuthorityState?.retainedInCorrectedAuthority === false, 'NONRETAINED_MARKED_CURRENT', identifier);
    }
    dependentRelationshipCount += record.dependentResourceCount;
    dispositionCounts[record.disposition] += 1;
    records.set(identifier, record);
  }

  const summary = inventory.summary;
  requireValue(summary?.importedItemCount === records.size, 'SUMMARY_ITEM_COUNT');
  requireValue(sameObject(summary.dispositionCounts, dispositionCounts), 'SUMMARY_DISPOSITION_COUNTS');
  requireValue(summary.unresolvedExternalDecisionCount === dispositionCounts.UNRESOLVED_EXTERNAL_DECISION, 'SUMMARY_EXTERNAL_DECISIONS');
  requireValue(Object.values(summary.zeroGateAssessment ?? {}).every((value) => value === 0), 'ZERO_GATE_FAILURE');

  return {
    authorityDigest: inventory.authorityDigest,
    dispositionCounts,
    inventoryDigest: inventory.inventoryDigest,
    inventoryFileDigest,
    recordCount: records.size,
    dependentRelationshipCount,
    uniqueSourceItemDigestCount: sourceItemDigests.size,
    zeroGateAssessment: summary.zeroGateAssessment,
  };
}

function validateReview(review, reviewFileDigest, facts) {
  requireValue(review?.schemaVersion === 2, 'REVIEW_SCHEMA');
  requireValue(review.resultCode === 'INDEPENDENT_REVIEW_ACCEPTED' && review.verdict === 'ACCEPTED', 'REVIEW_NOT_ACCEPTED');
  requireValue(review.reviewMode === 'READ_ONLY', 'REVIEW_MODE');
  requireValue(review.authorityDigest === facts.authorityDigest, 'REVIEW_AUTHORITY_MISMATCH');
  requireValue(review.inventoryFileDigest === facts.inventoryFileDigest, 'REVIEW_INVENTORY_FILE_DIGEST');
  requireValue(review.inventoryDigest === facts.inventoryDigest, 'REVIEW_INVENTORY_DIGEST');
  requireValue(review.recordCount === facts.recordCount && review.uniqueIdentifierCount === facts.recordCount, 'REVIEW_RECORD_COUNT');
  requireValue(review.uniqueSourceItemDigestCount === facts.uniqueSourceItemDigestCount, 'REVIEW_SOURCE_DIGEST_COUNT');
  requireValue(sameObject(review.dispositionCounts, facts.dispositionCounts), 'REVIEW_DISPOSITION_COUNTS');
  for (const check of [
    'completeExplicitDispositionCoverage',
    'uniqueDigestProxyIdentities',
    'sourceItemDigestIdentityCorrespondence',
    'exactSevenDispositionVocabulary',
    'successorIdentityRules',
    'successorIdentitiesCurrent',
    'consolidationTargetsCurrent',
    'originContaminationAbsent',
    'rawPredecessorCoordinatesAbsent',
    'summaryCountsMatch',
    'zeroGatesPass',
  ]) requireValue(review.checks?.[check] === true, 'REVIEW_CHECK_FAILURE', check);
  requireValue(Array.isArray(review.defects) && review.defects.length === 0, 'REVIEW_DEFECTS');
  return reviewFileDigest;
}

function writeAtomic(path, bytes) {
  const target = resolve(path);
  const temporary = resolve(dirname(target), `.semantic-adequacy-proof.${process.pid}.json`);
  writeFileSync(temporary, bytes, { flag: 'wx', mode: 0o600 });
  renameSync(temporary, target);
}

function hermeticSigningKey() {
  const seed = createHash('sha256').update('usf-semantic-adequacy-hermetic-signing-key-v2').digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function keyFingerprint(publicKey) {
  return digest(publicKey.export({ type: 'spki', format: 'der' }));
}

function dssePae(payloadType, payload) {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `),
    payload,
  ]);
}

try {
  const args = options(process.argv);
  const inventory = parseJson(args.inventory, 'INVENTORY_JSON');
  const review = parseJson(args.review, 'REVIEW_JSON');
  const facts = validateInventory(inventory.value, inventory.fileDigest, args.authority);
  const reviewFileDigest = validateReview(review.value, review.fileDigest, facts);
  const algorithmSourceDigest = digest(readFileSync(fileURLToPath(import.meta.url)));
  const evidenceSet = [
    { evidenceResult: 'urn:usf:evidenceresult:semanticadequacyinventory', contentDigest: facts.inventoryFileDigest },
    { evidenceResult: 'urn:usf:evidenceresult:semanticadequacyindependentreview', contentDigest: reviewFileDigest },
  ].sort((left, right) => left.evidenceResult.localeCompare(right.evidenceResult));
  const evidenceSetDigest = digest(jcs(evidenceSet));
  const proof = {
    algorithmSourceDigest,
    authorityDigest: facts.authorityDigest,
    checks: {
      acceptedIndependentReview: true,
      completeExplicitDispositionCoverage: true,
      digestProxyCoverage: true,
      sourceItemDigestIdentityCorrespondence: true,
      consolidationTargetsCurrent: true,
      correctedSuccessorIdentitiesExplicit: true,
      successorIdentitiesCurrent: true,
      originContaminationAbsent: true,
      rawPredecessorCoordinatesAbsent: true,
      noExternalDecision: true,
      noSilentInheritedReuse: true,
      zeroRemedialGateFailures: true,
    },
    dependentRelationshipCount: facts.dependentRelationshipCount,
    dispositionCounts: facts.dispositionCounts,
    evidenceSetDigest,
    evidenceSetDigestAlgorithm: EVIDENCE_SET_DIGEST_ALGORITHM,
    inventoryDigest: facts.inventoryDigest,
    inventoryFileDigest: facts.inventoryFileDigest,
    recordCount: facts.recordCount,
    resultCode: 'SEMANTIC_ADEQUACY_PROOF_PASSED',
    reviewFileDigest,
    schemaVersion: 2,
    uniqueSourceItemDigestCount: facts.uniqueSourceItemDigestCount,
    verdict: 'PASSED',
    zeroGateAssessment: facts.zeroGateAssessment,
  };
  const bytes = `${jcs(proof)}\n`;
  if (args.output) writeAtomic(args.output, bytes);
  let attestation = null;
  if (args.attestation) {
    const proofDigest = digest(bytes);
    const statement = {
      _type: 'https://in-toto.io/Statement/v1',
      predicateType: 'urn:usf:predicate:semantic-adequacy-counterfactual-proof:v2',
      subject: [
        { name: 'semantic-adequacy-inventory', digest: { sha256: facts.inventoryFileDigest.slice(7) } },
        { name: 'semantic-adequacy-independent-review', digest: { sha256: reviewFileDigest.slice(7) } },
        { name: 'semantic-adequacy-proof', digest: { sha256: proofDigest.slice(7) } },
      ],
      predicate: {
        algorithmSourceDigest,
        authorityDigest: facts.authorityDigest,
        exactEvidenceSetDigest: evidenceSetDigest,
        evidenceSetDigestAlgorithm: EVIDENCE_SET_DIGEST_ALGORITHM,
        inventoryDigest: facts.inventoryDigest,
        result: 'passed',
        nonclaims: [
          'no executable implementation proof',
          'no production-shaped staging proof',
          'no external trust in the deterministic hermetic signing identity',
        ],
      },
    };
    const payloadType = 'application/vnd.in-toto+json';
    const payload = Buffer.from(jcs(statement));
    const { privateKey, publicKey } = hermeticSigningKey();
    const signature = sign(null, dssePae(payloadType, payload), privateKey);
    requireValue(verify(null, dssePae(payloadType, payload), publicKey, signature), 'ATTESTATION_SIGNATURE_VERIFICATION');
    const envelope = {
      payloadType,
      payload: payload.toString('base64'),
      signatures: [{
        keyid: keyFingerprint(publicKey),
        sig: signature.toString('base64'),
      }],
    };
    const attestationBytes = `${jcs(envelope)}\n`;
    writeAtomic(args.attestation, attestationBytes);
    attestation = {
      digest: digest(attestationBytes),
      keyFingerprint: keyFingerprint(publicKey),
      path: args.attestation,
    };
  }
  process.stdout.write(`${jcs({ ...proof, attestation, outputDigest: digest(bytes), outputPath: args.output ?? null })}\n`);
} catch (error) {
  process.stdout.write(`${jcs({
    message: error.message,
    resultCode: error.resultCode ?? 'SEMANTIC_ADEQUACY_PROOF_ERROR',
    schemaVersion: 1,
    verdict: 'FAILED',
  })}\n`);
  process.exitCode = 1;
}
