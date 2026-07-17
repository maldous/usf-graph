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
const wave = process.env.USF_WAVE_CANONICAL || '';
if (!/^[a-z0-9]+$/.test(wave)) throw new Error('USF_WAVE_CANONICAL is required');
const requiredHex = name => { const value = process.env[name] || ''; if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`${name} is required`); return value; };
const requiredCount = name => { const value = Number(process.env[name]); if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} is required`); return value; };
const root = `/tmp/usf-${wave}-reference-kernel-proof`;
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

const activationManifestDigest = requiredHex('USF_ACTIVATION_MANIFEST_DIGEST');
const packetCollectionDigest = requiredHex('USF_PACKET_COLLECTION_DIGEST');
const contextDigest = requiredHex('USF_CONTEXT_DIGEST');
const expectedContracts = requiredCount('USF_EXPECTED_CONTRACTS');
const expectedFacets = requiredCount('USF_EXPECTED_FACETS');
const expectedHandlers = requiredCount('USF_EXPECTED_HANDLERS');
const expectedTests = requiredCount('USF_EXPECTED_TESTS');
const expectedDefects = requiredCount('USF_EXPECTED_DEFECTS');
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
record('contract-count', expectedContracts, activation.contracts.length);
record('packet-count', expectedContracts, packetCollection.packets.length);
record('facet-count', expectedFacets, context.facets.length);
record('context-authority', authority, context.authorityDigest);
record('packet-authority', authority, packetCollection.authorityDigest);

const layout = value(await request('usf_layout_context', { contract: activation.contracts[0].contract }));
record('live-authority', authority, layout.authorityDigest);
record('contract-active', 'urn:usf:contractactivationstate:active', layout.contract.activationState);
record('contract-proof-successful', 'urn:usf:proofresultstate:successful', layout.contract.proofResultState);
record('decision-accepted', 1, layout.acceptedDecisionCount);
record('realisations-authorised', true, layout.authorisedPaths.includes('realisations'));

for (const { canonical, contract } of activation.contracts) {
  const packetEntry = packetCollection.packets.find(item => item.contract === contract && (!item.canonical || item.canonical === canonical));
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
  ['realisations/reference-kernel/package.json', requiredHex('USF_PACKAGE_DIGEST')],
  ['realisations/reference-kernel/src/index.js', requiredHex('USF_SOURCE_DIGEST')],
  ['realisations/reference-kernel/test/reference-kernel.test.js', requiredHex('USF_TEST_DIGEST')],
];
for (const [path, expected] of sources) record(`source-digest:${path}`, expected, sha(readFileSync(join(repo, path))));
const packageJson = JSON.parse(readFileSync(join(repo, sources[0][0]), 'utf8'));
record('runtime-dependency-count', 0, Object.keys(packageJson.dependencies ?? {}).length, true);
record('development-dependency-count', 0, Object.keys(packageJson.devDependencies ?? {}).length, true);
const implementationText = readFileSync(join(repo, sources[1][0]), 'utf8');
record('credential-literal-count', 0, (implementationText.match(/(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|sk-[A-Za-z0-9]{20,})/g) ?? []).length, true);
const handlerStart = implementationText.indexOf('const handlers = Object.freeze({');
const handlerEnd = implementationText.indexOf('\n});', handlerStart);
record('contract-handler-count', expectedHandlers, (implementationText.slice(handlerStart, handlerEnd).match(/^  [a-z][a-z0-9]+: /gm) ?? []).length);

const testOutput = execFileSync('node', ['--test', 'test/reference-kernel.test.js'], { cwd: join(repo, 'realisations/reference-kernel'), encoding: 'utf8' });
const kernelTests = Number(testOutput.match(/# tests ([0-9]+)/)?.[1] || 0);
const kernelPass = Number(testOutput.match(/# pass ([0-9]+)/)?.[1] || 0);
const kernelFail = Number(testOutput.match(/# fail ([0-9]+)/)?.[1] || -1);
record('kernel-test-count', expectedTests, kernelTests);
record('kernel-test-pass', expectedTests, kernelPass);
record('kernel-test-fail', 0, kernelFail, true);
const plantedDefects = (readFileSync(join(repo, sources[2][0]), 'utf8').match(/\['[a-z0-9]+', input =>/g) ?? []).length;
record('planted-defect-count', expectedDefects, plantedDefects, true);

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
  const validationEvidence = `urn:usf:evidenceresult:${canonical}${wave}referencekernelvalidation`;
  const runtimeEvidence = `urn:usf:evidenceresult:${canonical}${wave}referencekernelruntimeproof`;
  evidenceIdentifiers[canonical] = { validationEvidence, runtimeEvidence };
  validationIdentifiers[canonical] = `urn:usf:validationresult:${canonical}${wave}referencekernel`;
  proofResultIdentifiers[canonical] = `urn:usf:proofresult:${canonical}${wave}referencekernel`;
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
const seed = createHash('sha256').update(`usf-${wave}-reference-kernel-proof-key`).digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const statement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: `usf-${wave}-reference-kernel-evidence`, digest: { sha256: manifestPayload.digest.slice(7) } }],
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
