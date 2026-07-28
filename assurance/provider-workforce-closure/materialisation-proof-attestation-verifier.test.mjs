import assert from 'node:assert/strict';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from 'node:crypto';
import test from 'node:test';

import {
  MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM,
  MATERIALISATION_EVIDENCE_SCHEMA_VERSION,
  MATERIALISATION_RECEIPT_SCHEMA_VERSION,
  candidateDependencyDigestFromGraphs,
  canonicalMaterialisationJson,
  canonicalMaterialisationReceiptBytes,
  verifyMaterialisationProofAttestation,
} from './materialisation-proof-attestation-verifier.mjs';
import {
  AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
  SELF_PUBLICATION_EXCLUDED_GRAPHS,
  SELF_PUBLICATION_RULE,
} from '../../capabilities/semantic-model-compilation/authority-binding.mjs';

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const graphCompare = (left, right) => Buffer.compare(
  Buffer.from(left.graph, 'utf8'),
  Buffer.from(right.graph, 'utf8'),
);

function deterministicIntegrityPrivateKey() {
  const seed = createHash('sha256')
    .update('repository-materialisation-control-plane-integrity-key')
    .digest();
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      seed,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
}

function candidateGraphs() {
  return [
    'urn:usf:graph:authority',
    ...SELF_PUBLICATION_EXCLUDED_GRAPHS,
  ].sort().map((graph, index) => ({
    graph,
    algorithm: 'RDFC-1.0',
    digestAlgorithm: 'sha256',
    sha256: createHash('sha256').update(`graph-${index}`).digest('hex'),
    triples: index + 1,
  })).sort(graphCompare);
}

function descriptor(bytes, mediaType) {
  const digest = sha256(bytes);
  return {
    digest,
    byteSize: bytes.length,
    mediaType,
    locator: `cas://sha256/${digest.slice(7)}`,
  };
}

function fixture({
  mutateEvidenceCore = null,
  mutateStatement = null,
  mutateReceipt = null,
} = {}) {
  const graphs = candidateGraphs();
  const inventory = candidateDependencyDigestFromGraphs(graphs);
  const signatureVerification = {
    state: 'verified',
    signingKeyFingerprint: 'A'.repeat(40),
    primaryKeyFingerprint: 'B'.repeat(40),
  };
  const runner = {
    sourcePath: 'assurance/semantic-model-compilation/materialisation-proof.mjs',
    sourceDigest: `sha256:${'1'.repeat(64)}`,
  };
  const commandResults = [{
    id: 'fixture-command',
    executable: '/usr/bin/true',
    arguments: [],
    exitStatus: 0,
    signal: null,
    stdoutDigest: sha256(''),
    stderrDigest: sha256(''),
  }];
  const cases = [
    {
      id: 'positive-case',
      expected: true,
      observed: true,
      passed: true,
      negative: false,
    },
    {
      id: 'negative-case',
      expected: 'rejected',
      observed: 'rejected',
      passed: true,
      negative: true,
    },
  ];
  const evidenceCore = {
    schemaVersion: MATERIALISATION_EVIDENCE_SCHEMA_VERSION,
    recordKind: 'USF_VALIDATION_EVIDENCE_CANDIDATE',
    passed: true,
    eligibleForAdmission: false,
    authorityClaims: [],
    evaluatedAt: '2026-07-28T00:00:00Z',
    evaluatedAuthorityDigest: `sha256:${'2'.repeat(64)}`,
    graphCommit: '3'.repeat(40),
    graphTree: '4'.repeat(40),
    signatureVerification,
    runner,
    toolchain: { node: { version: 'v22.23.1' } },
    toolchainDigest: `sha256:${'5'.repeat(64)}`,
    validationCommands: [{ executable: '/usr/bin/true', arguments: [] }],
    commandResults,
    candidateGraphInventoryAlgorithm:
      MATERIALISATION_CANDIDATE_GRAPH_INVENTORY_ALGORITHM,
    candidateGraphs: graphs,
    candidateAuthorityDigest: inventory.candidateAuthorityDigest,
    candidateDependencySetDigest: inventory.candidateDependencySetDigest,
    dependencyDigestAlgorithm: AUTHORITY_DEPENDENCY_DIGEST_ALGORITHM,
    authorityBindingRule: SELF_PUBLICATION_RULE,
    excludedAuthorityGraphs: [...SELF_PUBLICATION_EXCLUDED_GRAPHS],
    implementationSourceDigest: `sha256:${'6'.repeat(64)}`,
    implementationSources: [{
      path: 'assurance/semantic-model-compilation/materialisation-proof.mjs',
      digest: `sha256:${'7'.repeat(64)}`,
    }],
    proofAlgorithmSourceDigest: `sha256:${'8'.repeat(64)}`,
    environmentClass: 'urn:usf:environmentclass:hermetic',
    providerMode: 'urn:usf:providermode:deterministictestsubstitute',
    cases,
    measurements: {
      candidateGraphCount: graphs.length,
      focusedTestCount: 1,
      materialisationRuleCount: 1,
      pathRoleCount: 1,
    },
    nonclaims: ['fixture evidence is not semantic authority'],
  };
  if (mutateEvidenceCore) mutateEvidenceCore(evidenceCore);
  const exactEvidenceSetDigest = sha256(canonicalMaterialisationJson(evidenceCore));
  const evidence = { ...evidenceCore, exactEvidenceSetDigest };
  const evidenceBytes = Buffer.from(canonicalMaterialisationJson(evidence));
  const evidenceManifest = descriptor(evidenceBytes, 'application/json');

  const privateKey = deterministicIntegrityPrivateKey();
  const publicKey = createPublicKey(privateKey);
  const keyid = sha256(
    publicKey.export({ type: 'spki', format: 'der' }),
  ).slice(7);
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{
      name: 'repository-materialisation-control-plane-evidence',
      digest: { sha256: evidenceManifest.digest.slice(7) },
    }],
    predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
    predicate: {
      evidenceSchemaVersion: evidence.schemaVersion,
      evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
      candidateGraphInventoryAlgorithm: evidence.candidateGraphInventoryAlgorithm,
      candidateAuthorityDigest: evidence.candidateAuthorityDigest,
      candidateDependencySetDigest: evidence.candidateDependencySetDigest,
      exactEvidenceSetDigest: evidence.exactEvidenceSetDigest,
      implementationSourceDigest: evidence.implementationSourceDigest,
      proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
      result: 'passed',
    },
  };
  if (mutateStatement) mutateStatement(statement);
  const payloadType = 'application/vnd.in-toto+json';
  const statementBytes = Buffer.from(canonicalMaterialisationJson(statement));
  const pae = Buffer.concat([
    Buffer.from(
      `DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `,
    ),
    statementBytes,
  ]);
  const envelope = {
    payloadType,
    payload: statementBytes.toString('base64'),
    signatures: [{
      keyid,
      sig: sign(null, pae, privateKey).toString('base64'),
    }],
  };
  const attestationBytes = Buffer.from(canonicalMaterialisationJson(envelope));
  const proofAttestation = descriptor(
    attestationBytes,
    'application/vnd.in-toto+json',
  );

  const receipt = {
    schemaVersion: MATERIALISATION_RECEIPT_SCHEMA_VERSION,
    recordKind: 'USF_VALIDATION_EVIDENCE_CANDIDATE_RECEIPT',
    ok: true,
    passed: true,
    eligibleForAdmission: false,
    authorityClaims: [],
    evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
    graphCommit: evidence.graphCommit,
    graphTree: evidence.graphTree,
    signatureVerification,
    runner,
    toolchainDigest: evidence.toolchainDigest,
    commandResults,
    candidateGraphInventoryAlgorithm: evidence.candidateGraphInventoryAlgorithm,
    candidateAuthorityDigest: evidence.candidateAuthorityDigest,
    candidateDependencySetDigest: evidence.candidateDependencySetDigest,
    exactEvidenceSetDigest: evidence.exactEvidenceSetDigest,
    implementationSourceDigest: evidence.implementationSourceDigest,
    proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
    evidenceManifest,
    proofAttestation,
    signingKeyFingerprint: keyid,
    caseCount: evidence.cases.length,
    negativeCaseCount: evidence.cases.filter(({ negative }) => negative).length,
    failureCount: 0,
    outputRoot: '/tmp/usf-materialisation-control-plane-proof-fixture',
  };
  if (mutateReceipt) mutateReceipt(receipt);
  return {
    receipt,
    receiptBytes: canonicalMaterialisationReceiptBytes(receipt),
    evidence,
    evidenceBytes,
    statement,
    envelope,
    attestationBytes,
  };
}

function verify(input) {
  return verifyMaterialisationProofAttestation(input);
}

test('verifies canonical materialisation receipt, evidence, DSSE signature and all digest bindings', () => {
  const input = fixture();
  const result = verify(input);
  assert.equal(
    result.candidateAuthorityDigest,
    input.evidence.candidateAuthorityDigest,
  );
  assert.equal(
    result.candidateDependencySetDigest,
    input.evidence.candidateDependencySetDigest,
  );
  assert.equal(result.candidateGraphs.length, input.evidence.candidateGraphs.length);
  assert.equal(result.signingKeyFingerprint, input.receipt.signingKeyFingerprint);
});

test('rejects the pre-evolution evidence and receipt schemas', () => {
  const oldEvidence = fixture({
    mutateEvidenceCore: (evidence) => { evidence.schemaVersion = 3; },
  });
  assert.throws(() => verify(oldEvidence), /MATERIALISATION_EVIDENCE_SCHEMA_UNSUPPORTED/u);

  const oldReceipt = fixture({
    mutateReceipt: (receipt) => { receipt.schemaVersion = 1; },
  });
  assert.throws(() => verify(oldReceipt), /MATERIALISATION_RECEIPT_SCHEMA_UNSUPPORTED/u);
});

test('independently rejects a candidate graph digest change even when the manifest and DSSE are rebound', () => {
  const input = fixture({
    mutateEvidenceCore: (evidence) => {
      evidence.candidateGraphs[0].sha256 = 'f'.repeat(64);
    },
  });
  assert.throws(
    () => verify(input),
    /MATERIALISATION_EVIDENCE_CANDIDATE_AUTHORITY_DIGEST_MISMATCH/u,
  );
});

test('independently rejects a candidate dependency digest change', () => {
  const input = fixture({
    mutateEvidenceCore: (evidence) => {
      evidence.candidateDependencySetDigest = `sha256:${'9'.repeat(64)}`;
    },
  });
  assert.throws(
    () => verify(input),
    /MATERIALISATION_EVIDENCE_CANDIDATE_DEPENDENCY_DIGEST_MISMATCH/u,
  );
});

test('rejects unsorted, duplicate, incomplete and structurally widened candidate inventories', () => {
  const unsorted = fixture({
    mutateEvidenceCore: (evidence) => {
      [evidence.candidateGraphs[0], evidence.candidateGraphs[1]]
        = [evidence.candidateGraphs[1], evidence.candidateGraphs[0]];
    },
  });
  assert.throws(
    () => verify(unsorted),
    /MATERIALISATION_CANDIDATE_GRAPH_ORDER_INVALID/u,
  );

  const duplicate = fixture({
    mutateEvidenceCore: (evidence) => {
      evidence.candidateGraphs[1] = structuredClone(evidence.candidateGraphs[0]);
    },
  });
  assert.throws(
    () => verify(duplicate),
    /MATERIALISATION_CANDIDATE_GRAPH_(?:ORDER_INVALID|DUPLICATE)/u,
  );

  const missingExcluded = fixture({
    mutateEvidenceCore: (evidence) => {
      evidence.candidateGraphs = evidence.candidateGraphs.filter(
        ({ graph }) => graph !== SELF_PUBLICATION_EXCLUDED_GRAPHS[0],
      );
      evidence.measurements.candidateGraphCount -= 1;
    },
  });
  assert.throws(
    () => verify(missingExcluded),
    /MATERIALISATION_CANDIDATE_EXCLUDED_GRAPH_ABSENT_/u,
  );

  const extraField = fixture({
    mutateEvidenceCore: (evidence) => {
      evidence.candidateGraphs[0].unbound = true;
    },
  });
  assert.throws(
    () => verify(extraField),
    /MATERIALISATION_CANDIDATE_GRAPH_FIELDS_INVALID/u,
  );
});

test('rejects candidate graph algorithm and triple-count substitutions', () => {
  const algorithm = fixture({
    mutateEvidenceCore: (evidence) => {
      evidence.candidateGraphs[0].algorithm = 'RDFC-1.1';
    },
  });
  assert.throws(
    () => verify(algorithm),
    /MATERIALISATION_CANDIDATE_GRAPH_ALGORITHM_INVALID/u,
  );

  const triples = fixture({
    mutateEvidenceCore: (evidence) => {
      evidence.candidateGraphs[0].triples = -1;
    },
  });
  assert.throws(
    () => verify(triples),
    /MATERIALISATION_CANDIDATE_GRAPH_TRIPLES_INVALID/u,
  );
});

test('rejects receipt-to-evidence authority and dependency binding drift', () => {
  const authority = fixture({
    mutateReceipt: (receipt) => {
      receipt.candidateAuthorityDigest = `sha256:${'a'.repeat(64)}`;
    },
  });
  assert.throws(
    () => verify(authority),
    /MATERIALISATION_RECEIPT_EVIDENCE_CANDIDATEAUTHORITYDIGEST_MISMATCH/u,
  );

  const dependency = fixture({
    mutateReceipt: (receipt) => {
      receipt.candidateDependencySetDigest = `sha256:${'b'.repeat(64)}`;
    },
  });
  assert.throws(
    () => verify(dependency),
    /MATERIALISATION_RECEIPT_EVIDENCE_CANDIDATEDEPENDENCYSETDIGEST_MISMATCH/u,
  );
});

test('rejects DSSE predicate drift even when it is signed by the deterministic integrity key', () => {
  const input = fixture({
    mutateStatement: (statement) => {
      statement.predicate.candidateAuthorityDigest = `sha256:${'c'.repeat(64)}`;
    },
  });
  assert.throws(
    () => verify(input),
    /MATERIALISATION_ATTESTATION_CANDIDATEAUTHORITYDIGEST_MISMATCH/u,
  );
});

test('rejects a DSSE signature substitution', () => {
  const input = fixture();
  const envelope = structuredClone(input.envelope);
  const signature = Buffer.from(envelope.signatures[0].sig, 'base64');
  signature[0] ^= 0xff;
  envelope.signatures[0].sig = signature.toString('base64');
  input.attestationBytes = Buffer.from(canonicalMaterialisationJson(envelope));
  input.receipt.proofAttestation = descriptor(
    input.attestationBytes,
    'application/vnd.in-toto+json',
  );
  input.receiptBytes = canonicalMaterialisationReceiptBytes(input.receipt);
  assert.throws(
    () => verify(input),
    /MATERIALISATION_ATTESTATION_SIGNATURE_VERIFICATION_FAILED/u,
  );
});

test('rejects noncanonical evidence, attestation and receipt serialisations', () => {
  const evidence = fixture();
  evidence.evidenceBytes = Buffer.from(JSON.stringify(evidence.evidence, null, 2));
  evidence.receipt.evidenceManifest = descriptor(
    evidence.evidenceBytes,
    'application/json',
  );
  evidence.receiptBytes = canonicalMaterialisationReceiptBytes(evidence.receipt);
  assert.throws(
    () => verify(evidence),
    /MATERIALISATION_EVIDENCE_NOT_CANONICAL_JSON/u,
  );

  const attestation = fixture();
  attestation.attestationBytes = Buffer.from(
    JSON.stringify(attestation.envelope, null, 2),
  );
  attestation.receipt.proofAttestation = descriptor(
    attestation.attestationBytes,
    'application/vnd.in-toto+json',
  );
  attestation.receiptBytes = canonicalMaterialisationReceiptBytes(attestation.receipt);
  assert.throws(
    () => verify(attestation),
    /MATERIALISATION_ATTESTATION_NOT_CANONICAL_JSON/u,
  );

  const receipt = fixture();
  receipt.receiptBytes = Buffer.from(`${JSON.stringify(receipt.receipt)}\n`);
  assert.throws(
    () => verify(receipt),
    /MATERIALISATION_RECEIPT_BYTES_NONCANONICAL/u,
  );
});

test('rejects descriptor, subject, predicate-shape and manifest-shape tampering', () => {
  const descriptorTamper = fixture();
  descriptorTamper.receipt.evidenceManifest.byteSize += 1;
  descriptorTamper.receiptBytes = canonicalMaterialisationReceiptBytes(
    descriptorTamper.receipt,
  );
  assert.throws(
    () => verify(descriptorTamper),
    /MATERIALISATION_EVIDENCE_BYTE_SIZE_MISMATCH/u,
  );

  const subject = fixture({
    mutateStatement: (statement) => {
      statement.subject[0].name = 'different-subject';
    },
  });
  assert.throws(
    () => verify(subject),
    /MATERIALISATION_ATTESTATION_SUBJECT_NAME_INVALID/u,
  );

  const predicateShape = fixture({
    mutateStatement: (statement) => {
      statement.predicate.unbound = true;
    },
  });
  assert.throws(
    () => verify(predicateShape),
    /MATERIALISATION_ATTESTATION_PREDICATE_FIELDS_INVALID/u,
  );

  const evidenceShape = fixture({
    mutateEvidenceCore: (evidence) => {
      evidence.unbound = true;
    },
  });
  assert.throws(
    () => verify(evidenceShape),
    /MATERIALISATION_EVIDENCE_FIELDS_INVALID/u,
  );
});

test('rejects exact-evidence-set and case-count tampering', () => {
  const exactSet = fixture();
  exactSet.evidence.exactEvidenceSetDigest = `sha256:${'d'.repeat(64)}`;
  exactSet.evidenceBytes = Buffer.from(
    canonicalMaterialisationJson(exactSet.evidence),
  );
  exactSet.receipt.evidenceManifest = descriptor(
    exactSet.evidenceBytes,
    'application/json',
  );
  exactSet.receipt.exactEvidenceSetDigest = exactSet.evidence.exactEvidenceSetDigest;
  exactSet.receiptBytes = canonicalMaterialisationReceiptBytes(exactSet.receipt);
  assert.throws(
    () => verify(exactSet),
    /MATERIALISATION_EVIDENCE_SET_DIGEST_MISMATCH/u,
  );

  const caseCount = fixture({
    mutateReceipt: (receipt) => { receipt.caseCount += 1; },
  });
  assert.throws(
    () => verify(caseCount),
    /MATERIALISATION_RECEIPT_EVIDENCE_CASE_COUNTS_MISMATCH/u,
  );
});
