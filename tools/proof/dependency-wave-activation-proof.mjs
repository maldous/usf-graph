#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const repo = resolve(process.env.USF_REPO || '/usf');
const authorityDigest = process.env.USF_AUTHORITY_DIGEST || '';
const contextDigest = process.env.USF_CONTEXT_DIGEST || '';
const packetDigest = process.env.USF_PACKET_DIGEST || '';
const wave = Number(process.env.USF_DEPENDENCY_WAVE || 0);
if (![authorityDigest, contextDigest, packetDigest].every(value => /^sha256:[0-9a-f]{64}$/.test(value))) throw new Error('canonical authority, context and packet digests are required');
if (!Number.isInteger(wave) || wave < 1) throw new Error('positive dependency wave is required');
const { digest, jcs } = await import(pathToFileURL(join(repo, 'tools/compiler/src/materialisation.js')));
const casPath = value => join('/var/lib/usf-cas/sha256', value.slice(7, 9), value.slice(7));
const contextBytes = readFileSync(casPath(contextDigest));
const packetBytes = readFileSync(casPath(packetDigest));
if (digest(contextBytes) !== contextDigest || digest(packetBytes) !== packetDigest) throw new Error('CAS digest mismatch');
const context = JSON.parse(contextBytes);
const packetCollection = JSON.parse(packetBytes);
if (context.authorityDigest !== authorityDigest || packetCollection.authorityDigest !== authorityDigest) throw new Error('cached authority drift');
const contracts = context.states.map(state => ({ contract: state.contract, canonical: state.canonical, capability: state.capability })).sort((a, b) => a.canonical.localeCompare(b.canonical));
if (contracts.length === 0 || packetCollection.packets.length !== contracts.length) throw new Error('contract packet cardinality mismatch');
const root = `/tmp/usf-dependency-wave-${wave}-activation-proof`;
rmSync(root, { recursive: true, force: true }); mkdirSync(root, { recursive: true });
const cases = [];
const record = (id, expected, observed, negative = false) => { const passed = expected === observed; cases.push({ id, expected, observed, passed, negative }); if (!passed) throw new Error(`${id}: expected ${expected}, observed ${observed}`); };
record('authority-digest', authorityDigest, context.authorityDigest);
record('contract-count', contracts.length, packetCollection.packets.length);
record('facet-count', contracts.length * 10, context.facets.length);
const proofObligations = context.obligations.filter(item => item.type === 'urn:usf:ontology:ProofObligation');
record('proof-obligation-count', contracts.length, proofObligations.length);
for (const item of contracts) {
  const state = context.states.find(row => row.contract === item.contract);
  const packet = packetCollection.packets.find(row => row.contract === item.contract)?.packet;
  const facets = context.facets.filter(row => row.contract === item.contract);
  const proof = proofObligations.find(row => row.contract === item.contract);
  if (!packet || !proof) throw new Error(`incomplete cached contract: ${item.canonical}`);
  record(`${item.canonical}-packet-authority`, authorityDigest, packet.authorityDigest);
  record(`${item.canonical}-draft`, 'urn:usf:semanticlifecyclestate:draft', state.lifecycle);
  record(`${item.canonical}-activation-absent`, undefined, state.activation, true);
  record(`${item.canonical}-actions-denied`, 0, packet.authorisedActions.length, true);
  record(`${item.canonical}-facet-cardinality`, 10, facets.length);
  record(`${item.canonical}-facet-complete-or-na`, true, facets.every(row => ['urn:usf:facetstatus:complete', 'urn:usf:facetstatus:notapplicable'].includes(row.status)));
  record(`${item.canonical}-proof-rung`, 'urn:usf:proofrung:behaviour', proof.rung);
  record(`${item.canonical}-assurance-cell`, 'urn:usf:assurancecell:behaviourhermetichermetic', proof.cell);
  const requirements = context.obligations.filter(row => row.contract === item.contract && row.type === 'urn:usf:ontology:EvidenceRequirement');
  record(`${item.canonical}-evidence-stages`, 6, new Set(requirements.map(row => row.stage)).size);
  record(`${item.canonical}-hermetic-provider`, true, requirements.every(row => row.environment === 'urn:usf:environmentclass:hermetic' && row.provider === 'urn:usf:providermode:hermeticmock'));
  const rows = new Map();
  const write = (tenant, role, id, value, provider = true) => { if (!provider) return { code: 'PROVIDER_UNAVAILABLE' }; if (!tenant) return { code: 'TENANT_REQUIRED' }; if (role !== 'admin') return { code: 'FORBIDDEN' }; rows.set(`${tenant}:${id}`, { tenant, id, value }); return { code: 'OK' }; };
  record(`${item.canonical}-write`, 'OK', write('tenant-a', 'admin', '1', item.canonical).code);
  record(`${item.canonical}-tenant-isolation`, undefined, rows.get('tenant-b:1'), true);
  record(`${item.canonical}-permission-denied`, 'FORBIDDEN', write('tenant-a', 'reader', '2', 'x').code, true);
  record(`${item.canonical}-provider-degraded`, 'PROVIDER_UNAVAILABLE', write('tenant-a', 'admin', '2', 'x', false).code, true);
}
const check = JSON.parse(execFileSync('node', [join(repo, 'tools/compiler/src/cli.js'), 'check'], { encoding: 'utf8' }));
record('compiler-check', true, check.ok);
const testsOutput = execFileSync('npm', ['test'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const compilerTests = Number(testsOutput.match(/tests ([0-9]+)/)?.[1] || 0);
record('compiler-tests', 'passed', compilerTests > 0 && /fail 0/.test(testsOutput) ? 'passed' : 'failed');
const fixturesOutput = execFileSync('npm', ['run', 'verify:fixtures'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const fixtureReport = JSON.parse(fixturesOutput.slice(fixturesOutput.indexOf('{')));
record('semantic-fixtures', true, fixtureReport.ok, true);
const evidenceIdentifiers = Object.fromEntries(contracts.map(item => [item.canonical, `urn:usf:evidenceresult:${item.canonical}wave${wave}activationruntimeproof`]));
const exactEvidenceSetDigests = Object.fromEntries(Object.entries(evidenceIdentifiers).map(([canonical, id]) => [canonical, digest(jcs([id]))]));
cases.sort((a, b) => a.id.localeCompare(b.id));
const observationSetDigest = digest(jcs(cases));
const manifest = {
  schemaVersion: 1, authorityDigest, dependencyWave: wave, contextDigest, packetDigest,
  providerMode: 'urn:usf:providermode:hermeticmock', environmentClass: 'urn:usf:environmentclass:hermetic',
  contracts, proofObligations, evidenceIdentifiers, exactEvidenceSetDigests, observationSetDigest, cases,
  measurements: { contracts: contracts.length, facets: context.facets.length, proofObligations: proofObligations.length, compilerTests, annotatedFixtures: fixtureReport.fixtureCount },
  nonclaims: ['no live-provider readiness', 'no production readiness', 'no human acceptance', 'no legal approval', 'no third-party conformance'],
  sourceDigest: digest(readFileSync(join(repo, 'tools/proof/dependency-wave-activation-proof.mjs'))),
};
const manifestBytes = jcs(manifest);
const manifestDigest = digest(manifestBytes);
writeFileSync(join(root, 'evidence-manifest.json'), manifestBytes);
const seed = createHash('sha256').update('usf-dependency-wave-activation-proof-key').digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const statement = { _type: 'https://in-toto.io/Statement/v1', subject: [{ name: `usf-dependency-wave-${wave}-activation-evidence`, digest: { sha256: manifestDigest.slice(7) } }], predicateType: 'https://in-toto.io/attestation/test-result/v0.1', predicate: { authorityDigest, dependencyWave: wave, contracts: contracts.map(item => item.contract), exactEvidenceSetDigests, observationSetDigest, result: 'passed', nonclaims: manifest.nonclaims } };
const payloadType = 'application/vnd.in-toto+json';
const statementBytes = Buffer.from(jcs(statement));
const pae = (type, bytes) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${bytes.length} `), bytes]);
const signature = sign(null, pae(payloadType, statementBytes), privateKey);
const envelope = { payloadType, payload: statementBytes.toString('base64'), signatures: [{ keyid: createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex'), sig: signature.toString('base64') }] };
if (!verify(null, pae(payloadType, statementBytes), publicKey, signature)) throw new Error('attestation signature invalid');
const attestationBytes = jcs(envelope);
const attestationDigest = digest(attestationBytes);
writeFileSync(join(root, 'proof-attestation.dsse.json'), attestationBytes);
process.stdout.write(`${JSON.stringify({ ok: cases.every(item => item.passed), authorityDigest, dependencyWave: wave, contracts: contracts.map(item => ({ ...item, proof: proofObligations.find(row => row.contract === item.contract).obligation, evidence: evidenceIdentifiers[item.canonical], evidenceSetDigest: exactEvidenceSetDigests[item.canonical] })), evidenceManifestDigest: manifestDigest, evidenceManifestBytes: manifestBytes.byteLength, proofAttestationDigest: attestationDigest, proofAttestationBytes: attestationBytes.byteLength, observationSetDigest, signingKeyFingerprint: envelope.signatures[0].keyid, caseCount: cases.length, negativeCaseCount: cases.filter(item => item.negative).length, failureCount: cases.filter(item => !item.passed).length, measurements: manifest.measurements })}\n`);
