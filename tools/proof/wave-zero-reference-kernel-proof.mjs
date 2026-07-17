#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';

const repo = resolve(process.env.USF_REPO || '/usf');
const authority = process.env.USF_AUTHORITY_DIGEST || '';
if (!/^sha256:[0-9a-f]{64}$/.test(authority)) throw new Error('USF_AUTHORITY_DIGEST is required');
const { digest, jcs } = await import(pathToFileURL(join(repo, 'tools/compiler/src/materialisation.js')));
const root = '/tmp/usf-wave-zero-reference-kernel-proof';
const casRoot = join(root, 'cas');
rmSync(root, { recursive: true, force: true });
mkdirSync(casRoot, { recursive: true });
const sha = value => createHash('sha256').update(value).digest('hex');
const cases = [];
const payloads = [];
const record = (id, expected, observed, negative = false) => {
  const passed = expected === observed;
  cases.push({ id, expected, observed, passed, negative });
  if (!passed) throw new Error(`${id}: expected ${expected}, observed ${observed}`);
};
const put = (bytes, mediaType) => {
  const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const hex = sha(value);
  const path = join(casRoot, 'sha256', hex.slice(0, 2), hex);
  mkdirSync(dirname(path), { recursive: true });
  if (!existsSync(path)) writeFileSync(path, value, { flag: 'wx' });
  if (!readFileSync(path).equals(value)) throw new Error('CAS round-trip failed');
  const descriptor = { digest: `sha256:${hex}`, byteSize: value.length, mediaType, locator: `cas://sha256/${hex}` };
  payloads.push(descriptor);
  return descriptor;
};

const mcp = spawn('node', ['tools/compiler/src/mcp.js'], { cwd: repo, env: { ...process.env, USF_CAS_ROOT: '/var/lib/usf-cas' }, stdio: ['pipe', 'pipe', 'inherit'] });
let nextId = 0;
let buffer = '';
const pending = new Map();
mcp.stdout.setEncoding('utf8');
mcp.stdout.on('data', chunk => {
  buffer += chunk;
  for (;;) {
    const at = buffer.indexOf('\n');
    if (at < 0) break;
    const line = buffer.slice(0, at);
    buffer = buffer.slice(at + 1);
    if (!line.trim()) continue;
    const message = JSON.parse(line);
    const waiter = pending.get(message.id);
    if (waiter) { pending.delete(message.id); waiter(message); }
  }
});
const request = (name, args) => {
  const id = ++nextId;
  const response = new Promise(resolveResponse => pending.set(id, resolveResponse));
  mcp.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } })}\n`);
  return response;
};
const value = response => {
  const text = response.result?.content?.[0]?.text;
  if (response.error || response.result?.isError || !text) throw new Error(text || JSON.stringify(response.error));
  return JSON.parse(text);
};

const activationManifestDigest = 'fc2f5278251798877974ab5448d2261d2711d01055d687af6b157bd6e5825492';
const packetCollectionDigest = '92340e7c7ec1f6cf1f62481d92edda3d123de945438b099e18f4e339cc34bdfa';
const contextDigest = '1c4c14f3e53ae9aa4f3c26904d21a89fc0c92807a13d2909f389e0d49703609f';
const casPath = hex => join('/var/lib/usf-cas/sha256', hex.slice(0, 2), hex);
const activationBytes = readFileSync(casPath(activationManifestDigest));
const packetBytes = readFileSync(casPath(packetCollectionDigest));
const contextBytes = readFileSync(casPath(contextDigest));
record('activation-manifest-digest', activationManifestDigest, sha(activationBytes));
record('packet-collection-digest', packetCollectionDigest, sha(packetBytes));
record('contract-context-digest', contextDigest, sha(contextBytes));
const activation = JSON.parse(activationBytes);
const packetCollection = JSON.parse(packetBytes);
const context = JSON.parse(contextBytes);
record('contract-count', 18, activation.contracts.length);
record('packet-count', 18, packetCollection.packets.length);
record('facet-count', 180, context.facets.length);
record('context-authority', authority, context.authorityDigest);
record('packet-authority', authority, packetCollection.authorityDigest);

const layout = value(await request('usf_layout_context', { contract: 'urn:usf:semanticcontract:accessibilitya11ygate' }));
record('live-authority', authority, layout.authorityDigest);
record('contract-active', 'urn:usf:contractactivationstate:active', layout.contract.activationState);
record('contract-proof-successful', 'urn:usf:proofresultstate:successful', layout.contract.proofResultState);
record('decision-accepted', 1, layout.acceptedDecisionCount);
record('realisations-authorised', true, layout.authorisedPaths.includes('realisations'));

for (const { canonical, contract } of activation.contracts) {
  const packetEntry = packetCollection.packets.find(item => item.canonical === canonical && item.contract === contract);
  if (!packetEntry) throw new Error(`packet missing: ${canonical}`);
  const packet = packetEntry.packet;
  record(`${canonical}-packet-authority`, authority, packet.authorityDigest);
  record(`${canonical}-packet-active`, 'urn:usf:contractactivationstate:active', packet.contractState.activation);
  record(`${canonical}-packet-proof`, 'urn:usf:proofresultstate:successful', packet.contractState.proof);
  record(`${canonical}-packet-decision`, 'urn:usf:decisionstate:accepted', packet.contractState.decision);
  record(`${canonical}-write-authorised`, true, packet.authorisedActions.includes('write-file'));
  record(`${canonical}-path-authorised`, true, packet.authorisedPaths.includes('realisations'));
}

const sources = [
  ['realisations/reference-kernel/package.json', 'ea825f9330f2e15eaad4482850f05e6feebf58cdb0459d1ba8f5a406ce32d8e5'],
  ['realisations/reference-kernel/src/index.js', '689c008e306a5a82721dd244b0f799f734dd8b5cd14753204aa19cb9647f7934'],
  ['realisations/reference-kernel/test/reference-kernel.test.js', '9596847c3ab26b7ca1acd86051cdce43356955ac9ee7cfb955afb6ee0c750ce3'],
];
for (const [path, expected] of sources) record(`source-digest:${path}`, expected, sha(readFileSync(join(repo, path))));
const packageJson = JSON.parse(readFileSync(join(repo, sources[0][0]), 'utf8'));
record('runtime-dependency-count', 0, Object.keys(packageJson.dependencies ?? {}).length, true);
record('development-dependency-count', 0, Object.keys(packageJson.devDependencies ?? {}).length, true);
const implementationText = readFileSync(join(repo, sources[1][0]), 'utf8');
record('credential-literal-count', 0, (implementationText.match(/(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|sk-[A-Za-z0-9]{20,})/g) ?? []).length, true);
const handlerStart = implementationText.indexOf('const handlers = Object.freeze({');
const handlerEnd = implementationText.indexOf('\n});', handlerStart);
record('contract-handler-count', 18, (implementationText.slice(handlerStart, handlerEnd).match(/^  [a-z][a-z0-9]+: /gm) ?? []).length);

const testOutput = execFileSync('node', ['--test', 'test/reference-kernel.test.js'], { cwd: join(repo, 'realisations/reference-kernel'), encoding: 'utf8' });
const kernelTests = Number(testOutput.match(/# tests ([0-9]+)/)?.[1] || 0);
const kernelPass = Number(testOutput.match(/# pass ([0-9]+)/)?.[1] || 0);
const kernelFail = Number(testOutput.match(/# fail ([0-9]+)/)?.[1] || -1);
record('kernel-test-count', 28, kernelTests);
record('kernel-test-pass', 28, kernelPass);
record('kernel-test-fail', 0, kernelFail, true);
const plantedDefects = (readFileSync(join(repo, sources[2][0]), 'utf8').match(/\['[a-z0-9]+', input =>/g) ?? []).length;
record('planted-defect-count', 18, plantedDefects, true);

const check = JSON.parse(execFileSync('node', [join(repo, 'tools/compiler/src/cli.js'), 'check'], { encoding: 'utf8' }));
record('compiler-check', true, check.ok);
const compilerOutput = execFileSync('npm', ['test'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const compilerTests = Number(compilerOutput.match(/# tests ([0-9]+)/)?.[1] || 0);
record('compiler-tests-pass', true, compilerTests > 0 && /# fail 0/.test(compilerOutput));
const fixturesOutput = execFileSync('npm', ['run', 'verify:fixtures'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const fixtureReport = JSON.parse(fixturesOutput.slice(fixturesOutput.indexOf('{')));
record('semantic-fixtures-pass', true, fixtureReport.ok, true);

const evidenceIdentifiers = {};
const validationIdentifiers = {};
const proofResultIdentifiers = {};
const exactEvidenceSetDigests = {};
for (const { canonical } of activation.contracts) {
  const validationEvidence = `urn:usf:evidenceresult:${canonical}wavezeroreferencekernelvalidation`;
  const runtimeEvidence = `urn:usf:evidenceresult:${canonical}wavezeroreferencekernelruntimeproof`;
  evidenceIdentifiers[canonical] = { validationEvidence, runtimeEvidence };
  validationIdentifiers[canonical] = `urn:usf:validationresult:${canonical}wavezeroreferencekernel`;
  proofResultIdentifiers[canonical] = `urn:usf:proofresult:${canonical}wavezeroreferencekernel`;
  exactEvidenceSetDigests[canonical] = digest(jcs([runtimeEvidence, validationEvidence].sort()));
}
cases.sort((a, b) => a.id.localeCompare(b.id));
const observationSetDigest = digest(jcs(cases));
const sourceDigests = Object.fromEntries(sources.map(([path]) => [path, `sha256:${sha(readFileSync(join(repo, path)))}`]));
const sbom = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: '@usf/reference-kernel',
  documentNamespace: `urn:usf:sbom:reference-kernel:${sha(Buffer.from(jcs(sourceDigests)))}`,
  packages: [{ SPDXID: 'SPDXRef-Package-reference-kernel', name: '@usf/reference-kernel', versionInfo: packageJson.version, downloadLocation: 'NOASSERTION', filesAnalyzed: true }],
  files: sources.map(([path]) => ({ SPDXID: `SPDXRef-File-${sha(path).slice(0, 16)}`, fileName: path, checksums: [{ algorithm: 'SHA256', checksumValue: sourceDigests[path].slice(7) }] })),
  relationships: [{ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-Package-reference-kernel' }],
};
const sbomBytes = Buffer.from(jcs(sbom));
const sbomPayload = put(sbomBytes, 'application/spdx+json');
writeFileSync(join(root, 'reference-kernel.spdx.json'), sbomBytes);
const manifest = {
  schemaVersion: 1,
  authorityDigest: authority,
  contractContextDigest: `sha256:${contextDigest}`,
  packetCollectionDigest: `sha256:${packetCollectionDigest}`,
  realisation: 'urn:usf:implementation:sharedhermeticreferencekernel',
  providerMode: 'urn:usf:providermode:hermeticmock',
  environmentClass: 'urn:usf:environmentclass:hermetic',
  contracts: activation.contracts,
  sourceDigests,
  sbom: sbomPayload,
  evidenceIdentifiers,
  validationIdentifiers,
  proofResultIdentifiers,
  exactEvidenceSetDigests,
  observationSetDigest,
  cases,
  measurements: { kernelTests, plantedDefects, compilerTests, annotatedFixtures: fixtureReport.fixtureCount, contracts: activation.contracts.length, facets: context.facets.length },
  nonclaims: ['no live-provider readiness', 'no production readiness', 'no accessibility compliance', 'no human acceptance', 'no launch i18n', 'no UI product parity'],
};
const manifestBytes = Buffer.from(jcs(manifest));
const manifestPayload = put(manifestBytes, 'application/json');
writeFileSync(join(root, 'evidence-manifest.json'), manifestBytes);
const seed = createHash('sha256').update('usf-wave-zero-reference-kernel-proof-key').digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const statement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'usf-wave-zero-reference-kernel-evidence', digest: { sha256: manifestPayload.digest.slice(7) } }],
  predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
  predicate: { authorityDigest: authority, contracts: activation.contracts.map(item => item.contract), realisation: manifest.realisation, exactEvidenceSetDigests, validationIdentifiers, proofResultIdentifiers, observationSetDigest, result: 'passed', nonclaims: manifest.nonclaims },
};
const payloadType = 'application/vnd.in-toto+json';
const statementBytes = Buffer.from(jcs(statement));
const pae = (type, bytes) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${bytes.length} `), bytes]);
const signature = sign(null, pae(payloadType, statementBytes), privateKey);
const envelope = { payloadType, payload: statementBytes.toString('base64'), signatures: [{ keyid: sha(publicKey.export({ type: 'spki', format: 'der' })), sig: signature.toString('base64') }] };
if (!verify(null, pae(payloadType, statementBytes), publicKey, signature)) throw new Error('proof signature invalid');
const attestationBytes = Buffer.from(jcs(envelope));
const attestationPayload = put(attestationBytes, 'application/vnd.in-toto+json');
writeFileSync(join(root, 'proof-attestation.dsse.json'), attestationBytes);
mcp.stdin.end();
mcp.kill('SIGTERM');
process.stdout.write(`${JSON.stringify({ ok: cases.every(item => item.passed), authorityDigest: authority, evidenceManifestDigest: manifestPayload.digest, evidenceManifestBytes: manifestPayload.byteSize, proofAttestationDigest: attestationPayload.digest, proofAttestationBytes: attestationPayload.byteSize, sbomDigest: sbomPayload.digest, sbomBytes: sbomPayload.byteSize, observationSetDigest, signingKeyFingerprint: envelope.signatures[0].keyid, caseCount: cases.length, negativeCaseCount: cases.filter(item => item.negative).length, failureCount: cases.filter(item => !item.passed).length, measurements: manifest.measurements })}\n`);
