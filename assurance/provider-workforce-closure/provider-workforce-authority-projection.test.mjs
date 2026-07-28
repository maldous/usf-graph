import assert from 'node:assert/strict';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Parser } from 'n3';

import { authorityDependencySetDigest } from '../../capabilities/semantic-model-compilation/authority-binding.mjs';
import {
  PROVIDER_WORKFORCE_REQUIRED_CASES,
  PROVIDER_WORKFORCE_REQUIRED_CLAIMS,
  projectProviderWorkforceAuthorityReceipt,
  replaceProviderWorkforceAuthorityProjection,
} from './provider-workforce-authority-projection.mjs';

const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

const AUTHORITY_GRAPH_INVENTORY = Object.freeze([
  'urn:usf:graph:capabilities',
  'urn:usf:graph:derived:coverage',
  'urn:usf:graph:derived:evidence',
  'urn:usf:graph:derived:obligations',
  'urn:usf:graph:derived:readiness',
  'urn:usf:graph:derived:surfaces',
  'urn:usf:graph:evidence',
  'urn:usf:graph:proofs',
  'urn:usf:graph:ontology',
].map((graph, index) => Object.freeze({
  graph,
  sha256: `sha256:${String(index + 1).padStart(2, '0').repeat(32)}`,
  triples: index + 10,
})));
const DEPENDENCY_SET_DIGEST = authorityDependencySetDigest(AUTHORITY_GRAPH_INVENTORY);
const OPTIONS = Object.freeze({
  authorityGraphInventory: AUTHORITY_GRAPH_INVENTORY,
  dependencySetDigest: DEPENDENCY_SET_DIGEST,
  dependencyDigestAlgorithm: 'sha256-rdfc10-nonpublication-graph-inventory-v1',
  proofProducerCommit: '11'.repeat(20),
  proofProducerTree: '22'.repeat(20),
  algorithmVersion: '2.0.0',
  observedAt: '2026-07-28T07:30:00Z',
  reevaluationState: 'pending',
});
function fixture({
  primaryProofPath = 'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs',
  claims = PROVIDER_WORKFORCE_REQUIRED_CLAIMS,
  caseIds = PROVIDER_WORKFORCE_REQUIRED_CASES,
  mutationPassedCaseCount = 21,
} = {}) {
  const implementationSources = [{
    path: 'src/usf_factory/providers/registry.py',
    digest: `sha256:${'55'.repeat(32)}`,
    byteSize: 81,
  }];
  const proofAlgorithmSources = [
    {
      path: primaryProofPath,
      digest: `sha256:${'66'.repeat(32)}`,
    },
    {
      path: 'assurance/provider-workforce-closure/provider-materialisation-authority-mutations.mjs',
      digest: `sha256:${'77'.repeat(32)}`,
    },
  ];
  const evidenceCore = {
    schemaVersion: 1,
    recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_CANDIDATE',
    passed: true,
    eligibleForAdmission: true,
    authorityClaims: [...claims],
    evaluatedAt: '2026-07-28T07:00:00Z',
    validUntil: '2026-08-27T07:00:00Z',
    evaluatedAuthorityDigest: `sha256:${'88'.repeat(32)}`,
    factoryCommit: '33'.repeat(20),
    factoryTree: '44'.repeat(20),
    implementationSourceDigest: sha256(canonicalJson(implementationSources)),
    implementationSources,
    proofAlgorithmSourceDigest: sha256(canonicalJson(proofAlgorithmSources)),
    proofAlgorithmSources,
    materialisationAuthorityMutationEvidence: {
      caseCount: 21,
      passedCaseCount: mutationPassedCaseCount,
      baselineIntegrityRowCount: 0,
    },
    environmentClass: 'urn:usf:environmentclass:hermetic',
    providerMode: 'urn:usf:providermode:deterministictestsubstitute',
    commands: [],
    cases: caseIds.map((id) => ({
      id, expected: true, observed: true, passed: true,
    })),
    policyDigest: `sha256:${'99'.repeat(32)}`,
    populationDigest: `sha256:${'aa'.repeat(32)}`,
    closureDigest: `sha256:${'bb'.repeat(32)}`,
    nonclaims: ['No production readiness claim.'],
  };
  const exactEvidenceSetDigest = sha256(canonicalJson(evidenceCore));
  const evidence = { ...evidenceCore, exactEvidenceSetDigest };
  const evidenceBytes = Buffer.from(canonicalJson(evidence));
  const seed = createHash('sha256').update('provider-workforce-authority-integrity-key-v1').digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'provider-workforce-authority-evidence', digest: { sha256: sha256(evidenceBytes).slice(7) } }],
    predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
    predicate: {
      evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
      exactEvidenceSetDigest,
      implementationSourceDigest: evidence.implementationSourceDigest,
      proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
      result: 'passed',
    },
  };
  const payloadType = 'application/vnd.in-toto+json';
  const statementBytes = Buffer.from(canonicalJson(statement));
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${statementBytes.length} `),
    statementBytes,
  ]);
  const signature = sign(null, pae, privateKey);
  const envelope = {
    payloadType,
    payload: statementBytes.toString('base64'),
    signatures: [{
      keyid: sha256(publicKey.export({ type: 'spki', format: 'der' })).slice(7),
      sig: signature.toString('base64'),
    }],
  };
  const attestationBytes = Buffer.from(canonicalJson(envelope));
  const descriptor = (bytes, mediaType) => ({
    digest: sha256(bytes),
    byteSize: bytes.length,
    mediaType,
    locator: `cas://sha256/${sha256(bytes).slice(7)}`,
  });
  const receipt = {
    schemaVersion: 1,
    recordKind: 'USF_PROVIDER_WORKFORCE_AUTHORITY_EVIDENCE_RECEIPT',
    ok: true,
    passed: true,
    eligibleForAdmission: true,
    authorityClaims: evidence.authorityClaims,
    evaluatedAuthorityDigest: evidence.evaluatedAuthorityDigest,
    evaluatedAt: evidence.evaluatedAt,
    validUntil: evidence.validUntil,
    factoryCommit: evidence.factoryCommit,
    factoryTree: evidence.factoryTree,
    implementationSourceDigest: evidence.implementationSourceDigest,
    proofAlgorithmSourceDigest: evidence.proofAlgorithmSourceDigest,
    exactEvidenceSetDigest,
    policyDigest: evidence.policyDigest,
    populationDigest: evidence.populationDigest,
    closureDigest: evidence.closureDigest,
    caseCount: evidence.cases.length,
    evidenceManifest: descriptor(evidenceBytes, 'application/json'),
    proofAttestation: descriptor(attestationBytes, 'application/vnd.in-toto+json'),
    signingKeyFingerprint: envelope.signatures[0].keyid,
    outputRoot: '.work/provider-proof',
  };
  return { receipt, evidenceBytes, attestationBytes };
}

function project(input = fixture(), options = {}) {
  return projectProviderWorkforceAuthorityReceipt({
    ...input,
    ...OPTIONS,
    ...options,
  });
}

const prefixes = `
@prefix admission: <urn:usf:evidenceadmissionstate:>.
@prefix env: <urn:usf:environment:>.
@prefix evk: <urn:usf:evidencekind:>.
@prefix evr: <urn:usf:evidenceresult:>.
@prefix fresh: <urn:usf:freshness:>.
@prefix freshnessstate: <urn:usf:evidencefreshnessstate:>.
@prefix integritystate: <urn:usf:evidenceintegritystate:>.
@prefix pmode: <urn:usf:providermode:>.
@prefix rs: <urn:usf:resultstate:>.
@prefix rung: <urn:usf:proofrung:>.
@prefix usf: <urn:usf:ontology:>.
@prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
`;

test('projects a verified receipt deterministically into parseable evidence and proof RDF', () => {
  const first = project();
  const second = project();
  assert.deepEqual(second, first);
  assert.doesNotThrow(() => new Parser({ format: 'text/turtle' }).parse(`${prefixes}\n${first.evidenceTurtle}`));
  assert.doesNotThrow(() => new Parser({ format: 'text/turtle' }).parse(`${prefixes}\n${first.proofsTurtle}`));
  assert.match(first.evidenceTurtle, /providerworkforceauthorityevidence/);
  assert.match(first.proofsTurtle, /proofreevaluationstate:pending/);
  assert.doesNotMatch(first.proofsTurtle, /reevaluationSettledAuthorityDigest/);
  assert.match(first.proofsTurtle, new RegExp(DEPENDENCY_SET_DIGEST));
  assert.match(first.proofsTurtle, new RegExp(`sha256:${'66'.repeat(32)}`));
  assert.equal(first.metadata.primaryAlgorithmSourceDigest, `sha256:${'66'.repeat(32)}`);
  assert.match(first.proofsTurtle, /provider-materialisation-authority-mutations[.]mjs|providerworkforceauthority/);
  assert.match(first.metadata.projectionDigest, /^sha256:[0-9a-f]{64}$/);
});

test('successful post-publication projection requires and records an exact settled binding', () => {
  const input = fixture();
  const result = project(input, {
    reevaluationState: 'successful',
    settledAuthorityDigest: input.receipt.evaluatedAuthorityDigest,
    reevaluatedAt: '2026-07-28T07:20:00Z',
  });
  assert.match(result.proofsTurtle, /proofreevaluationstate:successful/);
  assert.match(result.proofsTurtle, /reevaluationSettledAuthorityDigest/);
  assert.match(result.proofsTurtle, /reevaluationDependencySetDigest/);
  assert.match(result.proofsTurtle, /reevaluationEvidenceDigest/);
  assert.throws(() => project(input, {
    reevaluationState: 'successful',
    settledAuthorityDigest: `sha256:${'cc'.repeat(32)}`,
    reevaluatedAt: '2026-07-28T07:20:00Z',
  }), /SETTLED_AUTHORITY_DIGEST_MISMATCH/);
});

test('rejects a changed evidence payload instead of projecting receipt assertions', () => {
  const input = fixture();
  const changed = Buffer.from(input.evidenceBytes);
  changed[changed.length - 2] ^= 1;
  assert.throws(() => project({ ...input, evidenceBytes: changed }), /EVIDENCE_MANIFEST_DIGEST_MISMATCH/);
});

test('rejects an invalid DSSE signature even when the descriptor is recomputed', () => {
  const input = fixture();
  const envelope = JSON.parse(input.attestationBytes.toString('utf8'));
  const signature = Buffer.from(envelope.signatures[0].sig, 'base64');
  signature[0] ^= 1;
  envelope.signatures[0].sig = signature.toString('base64');
  const attestationBytes = Buffer.from(canonicalJson(envelope));
  const digest = sha256(attestationBytes);
  input.receipt.proofAttestation = {
    ...input.receipt.proofAttestation,
    digest,
    byteSize: attestationBytes.length,
    locator: `cas://sha256/${digest.slice(7)}`,
  };
  assert.throws(() => project({ ...input, attestationBytes }), /ATTESTATION_SIGNATURE_VERIFICATION_FAILED/);
});

test('rejects receipt-to-evidence binding drift', () => {
  const input = fixture();
  input.receipt.caseCount += 1;
  assert.throws(() => project(input), /RECEIPT_CASE_COUNT_MISMATCH/);
  const other = fixture();
  other.receipt.policyDigest = `sha256:${'cc'.repeat(32)}`;
  assert.throws(() => project(other), /RECEIPT_POLICYDIGEST_MISMATCH/);
});

test('does not promote an incomplete claim, case, or hostile-mutation set', () => {
  assert.throws(() => project(fixture({
    claims: PROVIDER_WORKFORCE_REQUIRED_CLAIMS.slice(0, -1),
  })), /EVIDENCE_AUTHORITY_CLAIM_SET_MISMATCH/);
  assert.throws(() => project(fixture({
    caseIds: PROVIDER_WORKFORCE_REQUIRED_CASES.slice(0, -1),
  })), /EVIDENCE_CASE_SET_MISMATCH/);
  assert.throws(() => project(fixture({
    mutationPassedCaseCount: 20,
  })), /MATERIALISATION_MUTATION_EVIDENCE_INCOMPLETE/);
});

test('pending projection rejects invented settled re-evaluation facts', () => {
  const input = fixture();
  assert.throws(() => project(input, {
    settledAuthorityDigest: input.receipt.evaluatedAuthorityDigest,
  }), /PENDING_REEVALUATION_HAS_SETTLED_FIELDS/);
});

test('derives the dependency-set digest from the exact authority graph inventory', () => {
  assert.equal(project().metadata.dependencySetDigest, DEPENDENCY_SET_DIGEST);
  assert.throws(() => project(fixture(), {
    dependencySetDigest: `sha256:${'cc'.repeat(32)}`,
  }), /DEPENDENCY_SET_DIGEST_MISMATCH/);
  assert.throws(() => project(fixture(), {
    authorityGraphInventory: AUTHORITY_GRAPH_INVENTORY.filter(({ graph }) => graph !== 'urn:usf:graph:proofs'),
  }), /excluded authority graph absent/);
});

test('requires the evidence validity window to contain the canonical observation time', () => {
  assert.throws(() => project(fixture(), {
    observedAt: '2026-07-28T06:59:59Z',
  }), /EVIDENCE_NOT_YET_VALID/);
  assert.throws(() => project(fixture(), {
    observedAt: '2026-08-27T07:00:00Z',
  }), /EVIDENCE_EXPIRED/);
});

test('rejects session-specific absolute proof source paths', () => {
  const input = fixture({
    primaryProofPath: '/tmp/worktree/assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs',
  });
  assert.throws(() => project(input), /PROOF_ALGORITHM_SOURCE_RECORD_INVALID/);
});

test('exact block replacement changes only the provider evidence and terminal proof blocks', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-provider-projection-'));
  try {
    const assurance = join(root, 'semantic-model/assurance');
    mkdirSync(assurance, { recursive: true });
    const evidencePath = join(assurance, 'evidence.trig');
    const proofPath = join(assurance, 'proofs.trig');
    writeFileSync(evidencePath, `@prefix usf: <urn:usf:ontology:>.\n<urn:keep:evidence> a usf:Policy.\n# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE\n<urn:old:evidence> a usf:Policy.\n# END GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE\n<urn:keep:evidence-tail> a usf:Policy.\n`);
    writeFileSync(proofPath, `@prefix usf: <urn:usf:ontology:>.\n<urn:keep:proof> a usf:Policy.\n# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF\n<urn:old:proof> a usf:Policy.\n# END GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF\n<urn:keep:proof-tail> a usf:Policy.\n}\n`);
    const result = replaceProviderWorkforceAuthorityProjection(root, project());
    assert.match(readFileSync(evidencePath, 'utf8'), /<urn:keep:evidence>/);
    assert.match(readFileSync(evidencePath, 'utf8'), /providerworkforcedecisionevaluation/);
    assert.match(readFileSync(evidencePath, 'utf8'), /<urn:keep:evidence-tail>/);
    assert.match(readFileSync(proofPath, 'utf8'), /<urn:keep:proof>/);
    assert.match(readFileSync(proofPath, 'utf8'), /proofreevaluationstate:pending/);
    assert.match(readFileSync(proofPath, 'utf8'), /<urn:keep:proof-tail>/);
    assert.match(result.evidenceSourceDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(result.proofSourceDigest, /^sha256:[0-9a-f]{64}$/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('paired source replacement rolls the first file back when the second rename fails', () => {
  const root = mkdtempSync(join(tmpdir(), 'usf-provider-projection-rollback-'));
  try {
    const assurance = join(root, 'semantic-model/assurance');
    mkdirSync(assurance, { recursive: true });
    const evidencePath = join(assurance, 'evidence.trig');
    const proofPath = join(assurance, 'proofs.trig');
    const evidenceBefore = '@prefix usf: <urn:usf:ontology:>.\n# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE\n<urn:old:evidence> a usf:Policy.\n# END GENERATED PROVIDER-WORKFORCE AUTHORITY EVIDENCE\n';
    const proofBefore = '@prefix usf: <urn:usf:ontology:>.\n# BEGIN GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF\n<urn:old:proof> a usf:Policy.\n# END GENERATED PROVIDER-WORKFORCE AUTHORITY PROOF\n}\n';
    writeFileSync(evidencePath, evidenceBefore);
    writeFileSync(proofPath, proofBefore);
    let renameCount = 0;
    const operations = {
      writeFileSync,
      rmSync,
      renameSync(source, target) {
        renameCount += 1;
        if (renameCount === 2) throw new Error('PLANTED_SECOND_RENAME_FAILURE');
        renameSync(source, target);
      },
    };
    assert.throws(() => replaceProviderWorkforceAuthorityProjection(root, project(), operations),
      /PLANTED_SECOND_RENAME_FAILURE/);
    assert.equal(readFileSync(evidencePath, 'utf8'), evidenceBefore);
    assert.equal(readFileSync(proofPath, 'utf8'), proofBefore);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
