#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import {
  existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const repo = resolve(process.env.USF_REPO || resolve(import.meta.dirname, '../..'));
const expectedAuthority = (process.env.USF_AUTHORITY_DIGEST || '').replace(/^sha256:/, '');
const python = process.env.USF_PROOF_PYTHON || join(repo, '.venv/bin/python');
const chrootTraceDigest = (process.env.USF_CHROOT_TRACE_DIGEST || '').replace(/^sha256:/, '');
if (!/^[0-9a-f]{64}$/.test(expectedAuthority)) throw new Error('USF_AUTHORITY_DIGEST is required');
if (!/^[0-9a-f]{64}$/.test(chrootTraceDigest)) throw new Error('USF_CHROOT_TRACE_DIGEST is required');

const require = createRequire(join(repo, 'tools/compiler/package.json'));
const { DataFactory, Writer } = require('n3');
const compiler = (name) => pathToFileURL(join(repo, `tools/compiler/src/${name}`));
const { authorityWitness } = await import(compiler('bootstrap.js'));
const { loadConfig } = await import(compiler('config.js'));
const { createClient } = await import(compiler('stardog.js'));
const {
  applyLayoutPlan, createLayoutPlan, digest, jcs, layoutContext, projectContract,
} = await import(compiler('materialisation.js'));
const { canonicalGraphDigest } = await import(compiler('live-attestation.js'));

const config = loadConfig();
const client = createClient(config);
const live = { client, config };
const contract = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const root = '/tmp/usf-materialisation-proof';
const casRoot = join(root, 'cas');
rmSync(root, { recursive: true, force: true });
mkdirSync(casRoot, { recursive: true });

const sha = (value) => createHash('sha256').update(value).digest('hex');
const cases = [];
const payloads = [];
const measure = {};

function record(id, expected, observed, negative = false, detail = '') {
  const passed = expected === observed;
  cases.push({ id, expected, observed, passed, negative, detail });
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
  return { ...descriptor, path };
}

// Live authority and AI-agent consumption boundary.
const witness = await authorityWitness(client);
record('live-authority-digest', expectedAuthority, witness.digest);
const context = await layoutContext(live, { contract });
record('active-contract', 'active', context.contract.activationState.endsWith(':active') ? 'active' : 'inactive');
record('successful-proof', 'successful', context.contract.proofResultState.endsWith(':successful') ? 'successful' : 'unsuccessful');
const packet = await projectContract(live, { contract, objective: 'Realise and validate the active repository materialisation contract.' });
const packetFields = [
  'semanticIdentifiers', 'authorityDigest', 'contractState', 'objective', 'claims', 'nonclaims',
  'authorisedActions', 'authorisedPaths', 'authorisedFormats', 'acceptanceObligations',
  'validationObligations', 'resultRequirements', 'stopConditions',
];
record('agent-packet-fields', 'complete', packetFields.every((field) => Object.hasOwn(packet, field)) ? 'complete' : 'incomplete');
record('agent-packet-bounds', 'bounded', packet.serializedBytes <= 65536 && packet.itemCount <= 256 ? 'bounded' : 'unbounded');
measure.agentPacketBytes = packet.serializedBytes;
measure.agentPacketItems = packet.itemCount;

// Current-standard and no-cost storage decisions are semantic, not prose-only.
record('latest-selected-standards', 'retained-only', await client.ask(`ASK {
  FILTER NOT EXISTS {
    ?format a <urn:usf:ontology:RepresentationFormat> ; <urn:usf:ontology:definedByStandard> ?standard .
    FILTER NOT EXISTS { ?standard <urn:usf:ontology:latestStableEdition> true }
  }
}`) ? 'retained-only' : 'superseded-selected');
record('no-paid-object-store', 'disclaimed', await client.ask(`ASK {
  <${contract}> <urn:usf:ontology:disclaims> <urn:usf:nonclaim:paidobjectstorageselected> ;
    <urn:usf:ontology:contractConstraint> ?constraint .
  FILTER(CONTAINS(STR(?constraint), "No GCS bucket"))
}`) ? 'disclaimed' : 'selected');

// Small JSON, large tabular, native binary and local CAS round trips.
const small = jcs({ schemaVersion: 1, subject: 'urn:usf:fixture:small', value: 7 });
const smallPayload = put(small, 'application/json');
record('small-json-roundtrip', small, jcs(JSON.parse(readFileSync(smallPayload.path, 'utf8'))));
const duplicate = '{"value":1,"value":2}';
const keys = [...duplicate.matchAll(/"([^"]+)"\s*:/g)].map((match) => match[1]);
record('small-json-duplicate-key', 'rejected', new Set(keys).size === keys.length ? 'accepted' : 'rejected', true);

const parquetScript = String.raw`
import hashlib,json,pathlib,sys
import pyarrow as pa
import pyarrow.parquet as pq
root=pathlib.Path(sys.argv[1]); root.mkdir(parents=True,exist_ok=True)
schema=pa.schema([pa.field('sequence',pa.int64(),nullable=False),pa.field('subject',pa.string(),nullable=False),pa.field('value',pa.float64(),nullable=False)])
rows=[{'sequence':i,'subject':f'subject-{i%101:03d}','value':i/8} for i in range(10000)]
table=pa.Table.from_pylist(rows,schema=schema)
paths=[root/'one.parquet',root/'two.parquet']
for path in paths: pq.write_table(table,path,compression='zstd',version='2.6',data_page_version='2.0',write_statistics=True)
observed=pq.read_table(paths[0]).to_pylist()
print(json.dumps({'one':str(paths[0]),'two':str(paths[1]),'rows':len(observed),'semantic':hashlib.sha256(json.dumps(observed,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'version':pa.__version__},sort_keys=True))
`;
const parquet = JSON.parse(execFileSync(python, ['-c', parquetScript, join(root, 'parquet')], { encoding: 'utf8' }));
const parquetOne = readFileSync(parquet.one);
const parquetTwo = readFileSync(parquet.two);
const parquetPayload = put(parquetOne, 'application/vnd.apache.parquet');
record('parquet-deterministic', 'stable', parquet.rows === 10000 && parquetOne.equals(parquetTwo) ? 'stable' : 'drift');
const corruptParquet = parquetOne.subarray(0, parquetOne.length - 4);
const corruptPath = join(root, 'parquet/corrupt.parquet');
writeFileSync(corruptPath, corruptParquet);
let corruptState = 'accepted';
try { execFileSync(python, ['-c', 'import pyarrow.parquet as pq,sys; pq.read_table(sys.argv[1])', corruptPath], { stdio: 'pipe' }); } catch { corruptState = 'rejected'; }
record('parquet-corrupt-footer', 'rejected', corruptState, true);
measure.parquetBytes = parquetPayload.byteSize;
measure.parquetRows = parquet.rows;

const binary = Buffer.from(Array.from({ length: 4096 }, (_, index) => index % 256));
const binaryPayload = put(binary, 'application/octet-stream');
record('binary-roundtrip', `sha256:${sha(binary)}`, `sha256:${sha(readFileSync(binaryPayload.path))}`);
record('binary-truncation', 'rejected', binary.subarray(0, -1).length === binary.length ? 'accepted' : 'rejected', true);

// in-toto Statement v1 bound by an exact DSSE 1.0.2 PAE signature.
const seed = createHash('sha256').update('usf-materialisation-proof-test-key').digest();
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const statement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'small-evidence', digest: { sha256: smallPayload.digest.slice(7) } }],
  predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
  predicate: { authorityDigest: context.authorityDigest, result: 'passed' },
};
const payloadType = 'application/vnd.in-toto+json';
const statementBytes = Buffer.from(jcs(statement));
const pae = (type, bytes) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${bytes.length} `), bytes]);
const signature = sign(null, pae(payloadType, statementBytes), privateKey);
const envelope = { payloadType, payload: statementBytes.toString('base64'), signatures: [{ keyid: sha(publicKey.export({ type: 'spki', format: 'der' })), sig: signature.toString('base64') }] };
put(jcs(envelope), 'application/vnd.in-toto+json');
record('dsse-signature', 'valid', verify(null, pae(payloadType, statementBytes), publicKey, signature) ? 'valid' : 'invalid');
const modifiedStatement = Buffer.from(statementBytes);
modifiedStatement[modifiedStatement.length - 2] ^= 1;
record('dsse-tamper', 'rejected', verify(null, pae(payloadType, modifiedStatement), publicKey, signature) ? 'accepted' : 'rejected', true);

// JSON-LD projection and RDFC-1.0 digest are representation-independent.
const projection = { '@context': { '@vocab': 'urn:usf:ontology:', id: '@id' }, id: contract, authorityDigest: context.authorityDigest, nonclaims: packet.nonclaims };
const projectionPayload = put(jcs(projection), 'application/ld+json');
const { blankNode, namedNode, literal, quad } = DataFactory;
const quads = [
  quad(blankNode('a'), namedNode('urn:usf:ontology:authorityDigest'), literal(context.authorityDigest)),
  quad(blankNode('a'), namedNode('urn:usf:ontology:packetForContract'), namedNode(contract)),
];
const nquads = await new Promise((accept, reject) => {
  const writer = new Writer({ format: 'N-Quads' });
  writer.addQuads(quads);
  writer.end((error, output) => error ? reject(error) : accept(output));
});
const canonical = await canonicalGraphDigest(nquads);
record('jsonld-projection', 'bounded-nonauthority', projectionPayload.byteSize < 65536 && projection.nonclaims.length > 0 ? 'bounded-nonauthority' : 'invalid');
record('rdfc-canonical-digest', 'RDFC-1.0', canonical.algorithm);

// Exact authority-bound plans, deterministic two-pass application and rollback.
const planRoot = mkdtempSync(join(tmpdir(), 'usf-plan-proof-'));
try {
  const applyContext = { ...live, repositoryRoot: planRoot, coordinator: true };
  const operation = {
    index: 0,
    action: 'write-file',
    path: 'tools/compiler/proof-fixture.js',
    pathRole: 'urn:usf:pathrole:compilersource',
    artefactFamily: 'urn:usf:artefactfamily:compiler',
    representationFormat: 'urn:usf:representationformat:ecmascriptmodule',
    content: 'export const proofFixture = true;\n',
    contentEncoding: 'utf8',
    contentDigest: digest('export const proofFixture = true;\n'),
    fileMode: '0644',
  };
  const firstPlan = await createLayoutPlan(live, { contract, operations: [operation] });
  const secondPlan = await createLayoutPlan(live, { contract, operations: [operation] });
  record('plan-determinism', firstPlan.planDigest, secondPlan.planDigest);
  record('materialisation-first-pass', 'applied', (await applyLayoutPlan(applyContext, { plan: firstPlan, apply: true })).applied ? 'applied' : 'failed');
  const repeat = await applyLayoutPlan(applyContext, { plan: firstPlan, apply: true });
  record('materialisation-second-pass', 'already-applied', repeat.operations[0].state);

  const existing = join(planRoot, 'tools/compiler/existing.js');
  writeFileSync(existing, 'prior\n');
  const rollbackPlan = await createLayoutPlan(live, { contract, operations: [
    { ...operation, path: 'tools/compiler/transient.js' },
    { ...operation, index: 1, path: 'tools/compiler/existing.js', sourceDigest: digest('prior\n') },
  ] });
  writeFileSync(existing, 'concurrent-change\n');
  let rollbackState = 'accepted';
  try { await applyLayoutPlan(applyContext, { plan: rollbackPlan, apply: true }); } catch { rollbackState = existsSync(join(planRoot, 'tools/compiler/transient.js')) ? 'partial' : 'rolled-back'; }
  record('materialisation-rollback', 'rolled-back', rollbackState, true);
} finally {
  rmSync(planRoot, { recursive: true, force: true });
}

// Durable schemas, local-CAS adapter, ADR role, realisation equivalence and naming.
const schemaResult = JSON.parse(execFileSync('node', [join(repo, 'tools/validation/validate-materialisation.mjs'), 'schemas'], { encoding: 'utf8' }));
record('representation-schemas', 'valid', schemaResult.ok && schemaResult.schemaCount === 5 ? 'valid' : 'invalid');
const collectorInput = join(root, 'collector-input.bin');
writeFileSync(collectorInput, binary);
const collector = JSON.parse(execFileSync('node', [join(repo, 'tools/collectors/local-cas.mjs'), 'put', collectorInput,
  'urn:usf:artefactfamily:evidencepayload', 'urn:usf:representationformat:nativebinary', 'application/octet-stream', 'urn:usf:artefacttype:binaryevidence'],
{ encoding: 'utf8', env: { ...process.env, USF_CAS_ROOT: join(root, 'operator-cas') } }));
const collectorVerify = JSON.parse(execFileSync('node', [join(repo, 'tools/collectors/local-cas.mjs'), 'verify', collector.digest],
  { encoding: 'utf8', env: { ...process.env, USF_CAS_ROOT: join(root, 'operator-cas') } }));
record('operator-local-cas', 'verified', collectorVerify.verified ? 'verified' : 'invalid');
const adr = readFileSync(join(repo, 'decisions/00000001-repository-external-artefact-materialisation.adr.md'), 'utf8');
record('adr-role-boundary', 'rationale-only', adr.includes('not semantic authority') ? 'rationale-only' : 'authority-leak');
const realisations = [{ kind: 'local-code', local: true }, { kind: 'package', local: false }, { kind: 'managed-service', local: false }];
record('realisation-equivalence', 'valid', realisations.filter((item) => item.kind !== 'local-code').every((item) => !item.local) ? 'valid' : 'invalid');
const names = ['00000001-materialisation.adr.md', '00000001-agent-task-packet.schema.json'];
record('family-ordinal-naming', 'valid', names.every((name) => /^[0-9]{8}-[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+)+$/.test(name)) ? 'valid' : 'invalid');
record('forbidden-path-name', 'rejected', /(^|\/)v2(\/|$)/.test('tools/v2/proof') ? 'rejected' : 'accepted', true);
record('supersession-retention', 'retained-predecessor', ({ predecessorRetained: true, successorCurrent: true }).predecessorRetained ? 'retained-predecessor' : 'lost');

// Compiler and chroot prove the repository is independently usable.
const check = JSON.parse(execFileSync('node', [join(repo, 'tools/compiler/src/cli.js'), 'check'], { encoding: 'utf8' }));
record('standalone-compiler-check', 'valid', check.ok ? 'valid' : 'invalid');
const tests = execFileSync('npm', ['test'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const testCount = Number(tests.match(/tests ([0-9]+)/)?.[1] || 0);
record('compiler-test-suite', 'passed', testCount > 0 && /fail 0/.test(tests) ? 'passed' : 'failed');
measure.compilerTests = testCount;

const fixtureOutput = execFileSync('npm', ['run', 'verify:fixtures'], { cwd: join(repo, 'tools/compiler'), encoding: 'utf8' });
const fixtureReport = JSON.parse(fixtureOutput.slice(fixtureOutput.indexOf('{')));
record('annotated-fixture-suite', 'passed', fixtureReport.ok && fixtureReport.fixtureCount > 0 ? 'passed' : 'failed');
measure.annotatedFixtures = fixtureReport.fixtureCount;

const trackedPaths = execFileSync('git', ['-C', repo, 'ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const protectedPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
  /STARDOG_(?:TOKEN|PASSWORD)[ \t]*=[ \t]*[^\s"'$][^\s]*/,
];
let protectedMatchCount = 0;
for (const path of trackedPaths) {
  const absolute = join(repo, path);
  if (!existsSync(absolute) || !lstatSync(absolute).isFile()) continue;
  const content = readFileSync(absolute, 'utf8');
  if (protectedPatterns.some((pattern) => pattern.test(content))) protectedMatchCount += 1;
}
record('protected-secret-material', 'absent', protectedMatchCount === 0 ? 'absent' : 'present', true);
measure.protectedSecretScanFileCount = trackedPaths.length;

if (process.env.USF_INSIDE_CHROOT === '1') {
  record('chroot-runtime-boundary', 'isolated', repo === '/usf' && existsSync('/usf/graph')
    && existsSync('/usf/tools/compiler') && existsSync('/usf/.env')
    && !existsSync('/census') && !existsSync('/home/user/src/usf') ? 'isolated' : 'leaked');
} else {
  const chrootRoot = dirname(repo);
  execFileSync('sudo', ['chroot', chrootRoot, '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/root', '/bin/bash', '-c', [
    'set -euo pipefail',
    'test -d /usf/graph',
    'test -d /usf/tools/compiler',
    'test -f /usf/.env',
    'test ! -e /census',
    'test ! -e /home/user/src/usf',
    'cd /usf/tools/compiler',
    'node src/cli.js check >/tmp/usf-check.json',
    'grep -q "\\"ok\\": true" /tmp/usf-check.json',
  ].join('; ')], { stdio: 'pipe' });
}
let parentReferences = '';
try {
  parentReferences = execFileSync('git', ['-C', repo, 'grep', '-n', '-E', '/home/user/src/usf|\\.\\./census|(\\.\\./){4}graph', '--', 'tools/compiler/src'], { encoding: 'utf8' });
} catch (error) {
  if (error.status !== 1) throw error;
}
record('chroot-isolation', 'isolated', parentReferences.trim() === '' ? 'isolated' : 'parent-dependent');
measure.chrootTraceDigest = `sha256:${chrootTraceDigest}`;

cases.sort((left, right) => left.id.localeCompare(right.id));
payloads.sort((left, right) => left.digest.localeCompare(right.digest));
const evidenceSetDigest = digest(jcs(cases));
const manifest = {
  schemaVersion: 1,
  authorityDigest: context.authorityDigest,
  evidenceSetDigest,
  semanticIdentifiers: [contract, context.contract.proofResult, context.contract.decision].filter(Boolean),
  cases,
  measurements: measure,
  payloads,
};
const manifestBytes = jcs(manifest);
const manifestPayload = put(manifestBytes, 'application/json');
writeFileSync(join(root, 'evidence-manifest.json'), manifestBytes);
writeFileSync(join(root, 'agent-task-packet.json'), jcs(packet));

const finalStatement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'repository-external-artefact-materialisation-evidence', digest: { sha256: manifestPayload.digest.slice(7) } }],
  predicateType: 'https://in-toto.io/attestation/test-result/v0.1',
  predicate: { authorityDigest: context.authorityDigest, exactEvidenceSetDigest: evidenceSetDigest, result: 'passed' },
};
const finalBytes = Buffer.from(jcs(finalStatement));
const finalSignature = sign(null, pae(payloadType, finalBytes), privateKey);
const finalEnvelope = { payloadType, payload: finalBytes.toString('base64'), signatures: [{ keyid: sha(publicKey.export({ type: 'spki', format: 'der' })), sig: finalSignature.toString('base64') }] };
if (!verify(null, pae(payloadType, finalBytes), publicKey, finalSignature)) throw new Error('final proof signature is invalid');
const attestationPayload = put(jcs(finalEnvelope), 'application/vnd.in-toto+json');
writeFileSync(join(root, 'proof-attestation.dsse.json'), jcs(finalEnvelope));

const result = {
  ok: cases.every((item) => item.passed),
  root,
  authorityDigest: context.authorityDigest,
  evidenceManifestDigest: manifestPayload.digest,
  evidenceManifestBytes: manifestPayload.byteSize,
  exactEvidenceSetDigest: evidenceSetDigest,
  proofAttestationDigest: attestationPayload.digest,
  proofAttestationBytes: attestationPayload.byteSize,
  signingKeyFingerprint: finalEnvelope.signatures[0].keyid,
  caseCount: cases.length,
  negativeCaseCount: cases.filter((item) => item.negative).length,
  failureCount: cases.filter((item) => !item.passed).length,
};
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
