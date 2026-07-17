#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const repo = resolve(process.env.USF_REPO || '/usf');
const expectedAuthority = (process.env.USF_AUTHORITY_DIGEST || '').replace(/^sha256:/, '');
if (!/^[0-9a-f]{64}$/.test(expectedAuthority)) throw new Error('USF_AUTHORITY_DIGEST is required');
const source = (name) => pathToFileURL(join(repo, `tools/compiler/src/${name}`));
const { authorityWitness, bootstrapPacket, validContractRef } = await import(source('bootstrap.js'));
const { loadConfig } = await import(source('config.js'));
const { createClient } = await import(source('stardog.js'));
const { digest, jcs, projectContract } = await import(source('materialisation.js'));
const config = loadConfig();
const client = createClient(config);
const live = { client, config };
const contract = 'urn:usf:semanticcontract:bootstrappacket';
const task = 'Validate bounded digest-bound bootstrap semantics.';
const root = '/tmp/usf-bootstrap-packet-proof';
const casRoot = join(root, 'cas');
rmSync(root, { recursive: true, force: true });
mkdirSync(casRoot, { recursive: true });
const sha = (value) => createHash('sha256').update(value).digest('hex');
const cases = [];
const payloads = [];
const measurements = {};
function record(id, expected, observed, negative = false) {
  const passed = expected === observed;
  cases.push({ id, expected, observed, passed, negative });
  if (!passed) throw new Error(`${id}: expected ${expected}, observed ${observed}`);
}
function put(bytes, mediaType) {
  const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const hex = sha(value);
  const path = join(casRoot, 'sha256', hex.slice(0, 2), hex);
  mkdirSync(dirname(path), { recursive: true });
  if (!existsSync(path)) writeFileSync(path, value, { flag: 'wx' });
  if (!readFileSync(path).equals(value)) throw new Error('local CAS round-trip failed');
  const descriptor = { digest: `sha256:${hex}`, byteSize: value.length, mediaType, locator: `cas://sha256/${hex}` };
  payloads.push(descriptor);
  return descriptor;
}

const witness = await authorityWitness(client);
record('authority-digest', expectedAuthority, witness.digest);
const first = await bootstrapPacket(live, { contract, task });
const repeat = await bootstrapPacket(live, { contract, task });
record('packet-found', true, first.found);
record('trace-order', 'model -> evidence -> proof -> contract -> realisation -> validation', first.traceability);
record('packet-authority', expectedAuthority, first.authority.digest);
record('packet-determinism', digest(jcs(first)), digest(jcs(repeat)));
record('packet-byte-bound', 'bounded', first.serializedBytes <= first.bounds.maximumSerializedBytes ? 'bounded' : 'unbounded');
record('packet-binding-bound', 'bounded', first.bindingCount <= first.bounds.maximumBindings ? 'bounded' : 'unbounded');
record('packet-depth-bound', 3, first.bounds.maximumTraversalDepth);
record('packet-complete', 'complete', first.truncated === false && first.continuation === null ? 'complete' : 'partial');
record('claim-boundary', 'present', first.claims.some((item) => item.id === 'urn:usf:claim:semanticfirstlifecycle') ? 'present' : 'missing');
record('nonclaim-boundary', 'present', first.nonClaims.some((item) => item.id === 'urn:usf:nonclaim:bootstrapexceptionisimplementationauthority') ? 'present' : 'missing');
record('evidence-requirements', 3, first.evidenceRequirements.length);
record('proof-obligation-rows', 3, first.proofObligations.length);
record('proof-blocked-nonauthority', false, first.contracts[0]?.actionable, true);
record('open-gap-codes', 'complete', ['contract-proof-blocked', 'evidence-unavailable', 'proof-result-unavailable', 'realisation-not-implementable', 'validation-result-unavailable'].every((code) => first.openGaps.some((gap) => gap.code === code)) ? 'complete' : 'incomplete');

const projection = await projectContract(live, { contract, objective: 'Prove, activate, realise, and validate the bounded digest-bound bootstrap packet contract.' });
record('projection-proof-absent', 'absent', projection.contractState.proof == null ? 'absent' : 'present', true);
record('projection-decision-absent', 'absent', projection.contractState.decision == null ? 'absent' : 'present', true);
record('projection-authority-denied', 'denied', projection.authorisedActions.length + projection.authorisedPaths.length + projection.authorisedFormats.length === 0 ? 'denied' : 'granted', true);
record('injection-reference', false, validContractRef('x"} ; DROP GRAPH <urn:g>'), true);

const unitOutput = execFileSync('node', ['--test', 'test/mcp.test.js'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const unitTests = Number(unitOutput.match(/# tests ([0-9]+)/)?.[1] || 0);
record('bootstrap-unit-suite', 'passed', unitTests > 0 && /# fail 0/.test(unitOutput) ? 'passed' : 'failed');
measurements.bootstrapUnitTests = unitTests;
const fixtureOutput = execFileSync('npm', ['run', 'verify:fixtures'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const fixtureReport = JSON.parse(fixtureOutput.slice(fixtureOutput.indexOf('{')));
record('bootstrap-semantic-fixtures', 'passed', fixtureReport.ok && fixtureReport.fixtureCount >= 23 ? 'passed' : 'failed', true);
measurements.annotatedFixtures = fixtureReport.fixtureCount;
measurements.bindingCount = first.bindingCount;
measurements.serializedBytes = first.serializedBytes;
measurements.packetDigest = projection.packetDigest;
measurements.packetItems = projection.itemCount;

cases.sort((left, right) => left.id.localeCompare(right.id));
const observationSetDigest = digest(jcs(cases));
const evidenceIdentifiers = [
  'urn:usf:evidenceresult:bootstrappacketvalidation',
  'urn:usf:evidenceresult:bootstrappacketruntimeproof',
];
const exactEvidenceSetDigests = {
  bootstrappacketsemantics: digest(jcs(evidenceIdentifiers)),
  derivedbootstrappacketsemantics: digest(jcs([evidenceIdentifiers[1]])),
};
const manifest = {
  schemaVersion: 1, authorityDigest: `sha256:${expectedAuthority}`, contract,
  observationSetDigest, evidenceIdentifiers, exactEvidenceSetDigests,
  cases, measurements,
  criticalDigests: {
    'tools/compiler/src/bootstrap.js': `sha256:${sha(readFileSync(join(repo, 'tools/compiler/src/bootstrap.js')))}`,
    'tools/compiler/src/materialisation.js': `sha256:${sha(readFileSync(join(repo, 'tools/compiler/src/materialisation.js')))}`,
    'tools/compiler/test/mcp.test.js': `sha256:${sha(readFileSync(join(repo, 'tools/compiler/test/mcp.test.js')))}`,
  },
};
const manifestBytes = jcs(manifest);
const manifestPayload = put(manifestBytes, 'application/json');
writeFileSync(join(root, 'evidence-manifest.json'), manifestBytes);
const seed = createHash('sha256').update('usf-bootstrap-packet-proof-test-key').digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const statement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'bootstrap-packet-evidence', digest: { sha256: manifestPayload.digest.slice(7) } }],
  predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
  predicate: { authorityDigest: `sha256:${expectedAuthority}`, exactEvidenceSetDigests, observationSetDigest, result: 'passed' },
};
const payloadType = 'application/vnd.in-toto+json';
const statementBytes = Buffer.from(jcs(statement));
const pae = (type, bytes) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${bytes.length} `), bytes]);
const signature = sign(null, pae(payloadType, statementBytes), privateKey);
const envelope = { payloadType, payload: statementBytes.toString('base64'), signatures: [{ keyid: sha(publicKey.export({ type: 'spki', format: 'der' })), sig: signature.toString('base64') }] };
if (!verify(null, pae(payloadType, statementBytes), publicKey, signature)) throw new Error('proof signature is invalid');
const attestationBytes = jcs(envelope);
const attestationPayload = put(attestationBytes, 'application/vnd.in-toto+json');
writeFileSync(join(root, 'proof-attestation.dsse.json'), attestationBytes);
process.stdout.write(`${JSON.stringify({
  ok: cases.every((item) => item.passed), authorityDigest: `sha256:${expectedAuthority}`,
  evidenceManifestDigest: manifestPayload.digest, evidenceManifestBytes: manifestPayload.byteSize,
  exactEvidenceSetDigests, observationSetDigest,
  proofAttestationDigest: attestationPayload.digest, proofAttestationBytes: attestationPayload.byteSize,
  signingKeyFingerprint: envelope.signatures[0].keyid,
  caseCount: cases.length, negativeCaseCount: cases.filter((item) => item.negative).length,
  failureCount: cases.filter((item) => !item.passed).length,
}, null, 2)}\n`);
