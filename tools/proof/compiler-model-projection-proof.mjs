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
const { authorityWitness } = await import(source('bootstrap.js'));
const { loadConfig } = await import(source('config.js'));
const { createClient } = await import(source('stardog.js'));
const { digest, jcs, projectContract } = await import(source('materialisation.js'));
const config = loadConfig(); const client = createClient(config); const live = { client, config };
const compilerContract = 'urn:usf:semanticcontract:compilersemanticenforcement';
const modelContract = 'urn:usf:semanticcontract:universalservicefoundationscopeandprinciples';
const root = '/tmp/usf-compiler-model-projection-proof'; const casRoot = join(root, 'cas');
rmSync(root, { recursive: true, force: true }); mkdirSync(casRoot, { recursive: true });
const sha = (value) => createHash('sha256').update(value).digest('hex');
const cases = []; const payloads = []; const measurements = {};
function record(id, expected, observed, negative = false) { const passed = expected === observed; cases.push({ id, expected, observed, passed, negative }); if (!passed) throw new Error(`${id}: expected ${expected}, observed ${observed}`); }
function put(bytes, mediaType) { const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes); const hex = sha(value); const path = join(casRoot, 'sha256', hex.slice(0, 2), hex); mkdirSync(dirname(path), { recursive: true }); if (!existsSync(path)) writeFileSync(path, value, { flag: 'wx' }); if (!readFileSync(path).equals(value)) throw new Error('CAS round-trip failed'); const descriptor = { digest: `sha256:${hex}`, byteSize: value.length, mediaType, locator: `cas://sha256/${hex}` }; payloads.push(descriptor); return descriptor; }

const witness = await authorityWitness(client);
record('authority-digest', expectedAuthority, witness.digest);
const active = await projectContract(live, { contract: compilerContract, objective: 'Validate compiler model-incomplete contract projection.' });
record('compiler-active', 'urn:usf:contractactivationstate:active', active.contractState.activation);
record('compiler-proof-successful', 'urn:usf:proofresultstate:successful', active.contractState.proof);
record('compiler-decision-accepted', 'urn:usf:decisionstate:accepted', active.contractState.decision);
record('compiler-authorised-paths', 'present', active.authorisedPaths.includes('tools/compiler') && active.authorisedPaths.includes('tools/proof') ? 'present' : 'missing');

const packet = await projectContract(live, { contract: modelContract, objective: 'Determine warranted terminal classification for the root model-incomplete contract.' });
record('model-lifecycle', 'urn:usf:semanticlifecyclestate:draft', packet.contractState.lifecycle);
record('model-activation-absent', 'absent', packet.contractState.activation == null ? 'absent' : 'present', true);
record('model-proof-absent', 'absent', packet.contractState.proof == null ? 'absent' : 'present', true);
record('model-decision-absent', 'absent', packet.contractState.decision == null ? 'absent' : 'present', true);
record('model-actions-denied', 'denied', packet.authorisedActions.length === 0 ? 'denied' : 'granted', true);
record('model-paths-denied', 'denied', packet.authorisedPaths.length === 0 ? 'denied' : 'granted', true);
record('model-formats-denied', 'denied', packet.authorisedFormats.length === 0 ? 'denied' : 'granted', true);
record('model-claims-visible', 'visible', packet.claims.length === 13 ? 'visible' : 'missing');
record('model-nonclaims-visible', 'visible', packet.nonclaims.length === 19 ? 'visible' : 'missing');
record('model-obligations-visible', 'visible', packet.acceptanceObligations.length === 2 ? 'visible' : 'missing');
record('model-packet-bounds', 'bounded', packet.serializedBytes <= 65536 && packet.itemCount <= 256 ? 'bounded' : 'unbounded');
let missing = 'accepted';
try { await projectContract(live, { contract: 'urn:usf:semanticcontract:doesnotexist', objective: 'negative' }); } catch (error) { missing = /does not exist in live authority/.test(String(error?.message || error)) ? 'rejected' : 'unexpected'; }
record('unknown-contract', 'rejected', missing, true);

const check = JSON.parse(execFileSync('node', [join(repo, 'tools/compiler/src/cli.js'), 'check'], { encoding: 'utf8' }));
record('compiler-check', 'passed', check.ok ? 'passed' : 'failed');
const testsOutput = execFileSync('npm', ['test'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const compilerTests = Number(testsOutput.match(/tests ([0-9]+)/)?.[1] || 0);
record('compiler-tests', 'passed', compilerTests > 0 && /fail 0/.test(testsOutput) ? 'passed' : 'failed');
const fixturesOutput = execFileSync('npm', ['run', 'verify:fixtures'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const fixtureReport = JSON.parse(fixturesOutput.slice(fixturesOutput.indexOf('{')));
record('semantic-fixtures', 'passed', fixtureReport.ok && fixtureReport.fixtureCount >= 23 ? 'passed' : 'failed', true);
measurements.compilerTests = compilerTests; measurements.annotatedFixtures = fixtureReport.fixtureCount;
measurements.modelPacketDigest = packet.packetDigest; measurements.modelPacketItems = packet.itemCount; measurements.modelPacketBytes = packet.serializedBytes;
const criticalPaths = ['tools/compiler/src/bootstrap.js', 'tools/compiler/src/compiler.js', 'tools/compiler/src/materialisation.js', 'tools/compiler/src/stardog.js', 'tools/compiler/test/materialisation.test.js'];
const criticalDigests = Object.fromEntries(criticalPaths.map((path) => [path, `sha256:${sha(readFileSync(join(repo, path)))}`]));
cases.sort((left, right) => left.id.localeCompare(right.id));
const observationSetDigest = digest(jcs(cases));
const evidenceIdentifiers = ['urn:usf:evidenceresult:compilersemanticenforcementmodelprojectionvalidation', 'urn:usf:evidenceresult:compilersemanticenforcementmodelprojectionruntimeproof'];
const exactEvidenceSetDigests = {
  compilersemantics: digest(jcs(evidenceIdentifiers)),
  derivedcompilersemantics: digest(jcs([evidenceIdentifiers[1]])),
};
const manifest = { schemaVersion: 1, authorityDigest: `sha256:${expectedAuthority}`, contract: compilerContract, subject: modelContract,
  observationSetDigest, evidenceIdentifiers, exactEvidenceSetDigests, cases, measurements, criticalDigests };
const manifestBytes = jcs(manifest); const manifestPayload = put(manifestBytes, 'application/json'); writeFileSync(join(root, 'evidence-manifest.json'), manifestBytes);
const seed = createHash('sha256').update('usf-compiler-model-projection-proof-test-key').digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const statement = { _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'compiler-model-projection-evidence', digest: { sha256: manifestPayload.digest.slice(7) } }],
  predicateType: 'https://in-toto.io/attestation/test-result/v0.1', predicate: { authorityDigest: `sha256:${expectedAuthority}`, exactEvidenceSetDigests, observationSetDigest, result: 'passed' } };
const payloadType = 'application/vnd.in-toto+json'; const statementBytes = Buffer.from(jcs(statement));
const pae = (type, bytes) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${bytes.length} `), bytes]);
const signature = sign(null, pae(payloadType, statementBytes), privateKey);
const envelope = { payloadType, payload: statementBytes.toString('base64'), signatures: [{ keyid: sha(publicKey.export({ type: 'spki', format: 'der' })), sig: signature.toString('base64') }] };
if (!verify(null, pae(payloadType, statementBytes), publicKey, signature)) throw new Error('proof signature invalid');
const attestationBytes = jcs(envelope); const attestationPayload = put(attestationBytes, 'application/vnd.in-toto+json'); writeFileSync(join(root, 'proof-attestation.dsse.json'), attestationBytes);
process.stdout.write(`${JSON.stringify({ ok: cases.every((item) => item.passed), authorityDigest: `sha256:${expectedAuthority}`,
  evidenceManifestDigest: manifestPayload.digest, evidenceManifestBytes: manifestPayload.byteSize, exactEvidenceSetDigests, observationSetDigest,
  proofAttestationDigest: attestationPayload.digest, proofAttestationBytes: attestationPayload.byteSize, signingKeyFingerprint: envelope.signatures[0].keyid,
  caseCount: cases.length, negativeCaseCount: cases.filter((item) => item.negative).length, failureCount: cases.filter((item) => !item.passed).length }, null, 2)}\n`);
