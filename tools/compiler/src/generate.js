import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import {
  existsSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { DataFactory } from 'n3';
import { canonicalResource, literalValue, oneObject, subjectsOfType, USF } from './authority-dataset.js';
import { requireCompleteGenerationPlan } from './generation-plan.js';
import { CompilerError } from './compiler.js';
import { GENERATED_RELEASE_ROOT, validateGeneratedOutput } from './validators/index.js';

const { namedNode } = DataFactory;
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const stableJson = (value) => `${JSON.stringify(value, null, 2)}\n`;
const canonical = (value) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

function authorityDigest(store) {
  const rows = store.getQuads(null, null, null, null).map((q) =>
    [q.subject.termType, q.subject.value, q.predicate.value, q.object.termType, q.object.value, q.graph.value].join('\u0000')
  );
  return sha256(rows.sort().join('\n'));
}

function componentQuery(store, component) {
  const query = literalValue(oneObject(store, namedNode(component), namedNode(`${USF}semanticInputQuery`)));
  const match = query?.match(/^\s*SELECT\s+\?resource\s+WHERE\s*\{([\s\S]*)\}\s*$/i);
  if (!match) throw new CompilerError(`unsupported semantic input query for ${component}`, { phase: 'generate:query', component, query });
  const statements = match[1].split('.').map((item) => item.trim()).filter(Boolean);
  const constraints = [];
  for (const statement of statements) {
    if (!statement.startsWith('?resource ')) throw new CompilerError(`unsupported semantic input query for ${component}`, { phase: 'generate:query', component, query, statement });
    const clauses = statement.slice('?resource '.length).split(';').map((item) => item.trim()).filter(Boolean);
    for (const clause of clauses) {
      const triple = clause.match(/^(a|<([^>]+)>)\s+<([^>]+)>$/);
      if (!triple) throw new CompilerError(`unsupported semantic input query for ${component}`, { phase: 'generate:query', component, query, clause });
      constraints.push({ predicate: triple[1] === 'a' ? RDF_TYPE : triple[2], object: triple[3] });
    }
  }
  const type = constraints.find((item) => item.predicate === RDF_TYPE);
  if (!type || !constraints.length) throw new CompilerError(`unsupported semantic input query for ${component}`, { phase: 'generate:query', component, query });
  return { query, classIri: type.object, constraints };
}

function projection(store, output, sourceDigest) {
  const selected = componentQuery(store, output.component);
  const selectedSubjects = subjectsOfType(store, selected.classIri)
    .filter((subject) => selected.constraints.every((constraint) =>
      store.countQuads(subject, namedNode(constraint.predicate), namedNode(constraint.object), null) > 0
    ));
  const requested = new Set(output.semanticResources ?? []);
  const subjects = requested.size ? selectedSubjects.filter((subject) => requested.has(subject.value)) : selectedSubjects;
  if (requested.size && subjects.length !== requested.size) throw new CompilerError('artifact plan selects a semantic resource outside its generator query', {
    phase: 'generate:plan-semantics', component: output.component, plan: output.plan, requested: [...requested], matched: subjects.map((subject) => subject.value),
  });
  const obligations = [];
  const generatable = subjects.filter((subject) => {
    if (selected.classIri !== `${USF}SemanticContract`) return true;
    const lifecycle = store.getObjects(subject, namedNode(`${USF}semanticLifecycleState`), null);
    if (lifecycle.length !== 1) {
      obligations.push({ subject: subject.value, predicate: `${USF}semanticLifecycleState`, expected: 'exactly-one', observed: lifecycle.length });
      return false;
    }
    if (['deprecated', 'retired', 'replaced'].includes(lifecycle[0].value.split(':').at(-1))) return false;
    for (const facet of store.getObjects(subject, namedNode(`${USF}declaresFacet`), null)) {
      const statuses = store.getObjects(facet, namedNode(`${USF}facetStatus`), null);
      const statements = store.getObjects(facet, namedNode(`${USF}facetStatement`), null);
      const kind = store.getObjects(facet, namedNode(`${USF}facetKind`), null)[0]?.value ?? null;
      if (statuses.length !== 1 || statements.length !== 1) {
        obligations.push({ subject: subject.value, facet: facet.value, facetKind: kind, expected: 'one-status-and-statement', observed: { statuses: statuses.length, statements: statements.length } });
      } else if (statuses[0].value === 'urn:usf:facetstatus:gap') {
        obligations.push({ subject: subject.value, facet: facet.value, facetKind: kind, status: 'gap', statement: statements[0].value });
      }
    }
    return true;
  });
  if (obligations.length) throw new CompilerError(`semantic input has ${obligations.length} unresolved contract facet obligations for ${output.component}`, {
    phase: 'generate:missing-semantics', component: output.component, classIri: selected.classIri, obligations,
  });
  const resources = generatable
    .sort((a, b) => a.value.localeCompare(b.value))
    .map((subject) => canonicalResource(store, subject));
  if (!resources.length) throw new CompilerError(`semantic input query produced no resources for ${output.component}`, {
    phase: 'generate:missing-semantics',
    component: output.component,
    classIri: selected.classIri,
    obligation: { classIri: selected.classIri, output: output.artefact },
  });
  if (output.component === 'urn:usf:generator:semanticcontract') {
    if (subjects.length !== 1) throw new CompilerError('semantic contract output requires exactly one planned contract', {
      phase: 'generate:plan-semantics', component: output.component, plan: output.plan, observed: subjects.length,
    });
    const subject = subjects[0];
    const canonicalName = literalValue(oneObject(store, subject, namedNode(`${USF}canonicalName`)));
    const lifecycleState = oneObject(store, subject, namedNode(`${USF}semanticLifecycleState`))?.value.split(':').at(-1);
    const facets = store.getObjects(subject, namedNode(`${USF}declaresFacet`), null).map((facet) => ({
      id: facet.value,
      kind: oneObject(store, facet, namedNode(`${USF}facetKind`))?.value,
      status: oneObject(store, facet, namedNode(`${USF}facetStatus`))?.value.split(':').at(-1),
      statement: literalValue(oneObject(store, facet, namedNode(`${USF}facetStatement`))),
    })).sort((a, b) => a.kind.localeCompare(b.kind));
    return { schemaVersion: 1, authorityDigest: sourceDigest, id: subject.value, canonicalName, lifecycleState, facets,
      nonClaims: ['generated projection is lower authority than its semantic inputs'] };
  }
  return {
    schemaVersion: 1,
    authorityDigest: sourceDigest,
    artefact: output.artefact,
    artefactKind: output.artefactKind,
    component: output.component,
    semanticInputQuery: selected.query,
    resources,
    nonClaims: ['generated projection is lower authority than its semantic inputs'],
  };
}

function releaseAuthority(store, output) {
  const component = namedNode(output.component);
  const identities = store.getObjects(component, namedNode(`${USF}authorisedSigningIdentity`), null);
  if (identities.length !== 1) throw new CompilerError('release generator requires exactly one authorised signing identity', {
    phase: 'generate:signing-authority', component: output.component, observed: identities.length,
  });
  const fingerprint = literalValue(oneObject(store, identities[0], namedNode(`${USF}signingKeyFingerprint`)));
  if (!fingerprint || !/^[0-9a-f]{64}$/.test(fingerprint)) throw new CompilerError('authorised signing identity has no valid key fingerprint', {
    phase: 'generate:signing-authority', signingIdentity: identities[0].value,
  });
  const versions = subjectsOfType(store, `${USF}Version`).filter((subject) =>
    store.countQuads(subject, namedNode(`${USF}versionOf`), namedNode(output.artefact), null) === 1
  );
  if (versions.length !== 1) throw new CompilerError('release manifest requires exactly one governed version', {
    phase: 'generate:release-version', artefact: output.artefact, observed: versions.length,
  });
  const version = literalValue(oneObject(store, versions[0], namedNode(`${USF}versionIdentifier`)));
  if (!version || !/^\d+\.\d+\.\d+(?:[+-][0-9A-Za-z.-]+)?$/.test(version)) throw new CompilerError('governed release version is not SemVer-shaped', {
    phase: 'generate:release-version', versionResource: versions[0].value,
  });
  return { signingIdentity: identities[0].value, signingKeyFingerprint: fingerprint, versionResource: versions[0].value, version };
}

function render(output, data) {
  if (output.path.endsWith('/contracts/schemas/compiler-output.schema.json')) {
    return stableJson({
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: 'urn:usf:generated:schema:compiler-output',
      title: 'USF generated semantic projection',
      type: 'object',
      required: ['schemaVersion', 'authorityDigest', 'artefact', 'component', 'resources'],
      properties: {
        schemaVersion: { const: 1 }, authorityDigest: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        artefact: { type: 'string' }, component: { type: 'string' }, resources: { type: 'array' },
      },
      additionalProperties: true,
    });
  }
  if (output.path.endsWith('/contracts/schemas/semantic-contract.schema.json')) {
    return stableJson({
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: 'urn:usf:generated:schema:semantic-contract',
      title: 'USF generated semantic contract', type: 'object',
      required: ['schemaVersion', 'authorityDigest', 'id', 'canonicalName', 'lifecycleState', 'facets', 'nonClaims'],
      properties: {
        schemaVersion: { const: 1 }, authorityDigest: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        id: { type: 'string', pattern: '^urn:usf:semanticcontract:[a-z0-9]+$' }, canonicalName: { type: 'string', pattern: '^[a-z0-9]+$' },
        lifecycleState: { enum: ['proposed', 'planned', 'draft', 'active', 'deferred'] },
        facets: { type: 'array', minItems: 10, maxItems: 10, items: { type: 'object', required: ['id', 'kind', 'status', 'statement'],
          properties: { id: { type: 'string' }, kind: { type: 'string' }, status: { enum: ['complete', 'notapplicable'] }, statement: { type: 'string', minLength: 1 } }, additionalProperties: false } },
        nonClaims: { type: 'array', items: { type: 'string' } },
      }, additionalProperties: false,
    });
  }
  if (output.path.endsWith('/interface-models/schemas/rendererinput.schema.json')) {
    return stableJson({
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: 'urn:usf:generated:schema:renderer-input',
      title: 'USF framework-neutral renderer input',
      type: 'object',
      required: ['schemaVersion', 'authorityDigest', 'artefact', 'component', 'resources'],
      properties: {
        schemaVersion: { const: 1 },
        authorityDigest: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        artefact: { type: 'string', format: 'uri' },
        component: { type: 'string', format: 'uri' },
        resources: { type: 'array', items: { type: 'object' } },
        nonClaims: { type: 'array', items: { type: 'string' } },
      },
      additionalProperties: false,
    });
  }
  if (output.path.endsWith('/contracts/openapi/openapi.json')) {
    return stableJson({ openapi: '3.1.0', info: { title: 'USF generated foundation contract projection', version: '0.1.0' }, paths: {},
      'x-usf-authority-digest': data.authorityDigest, 'x-usf-semantic-resources': data.resources,
      'x-usf-nonclaims': ['no HTTP path is emitted without authored HTTP method and route semantics'] });
  }
  if (output.path.endsWith('/source/package.json')) {
    return stableJson({ name: 'semantic-projection', version: '0.1.0', private: true, type: 'module',
      scripts: { test: 'node --test ../assurance/tests/generated.test.mjs', validate: 'node ../assurance/proof/evidence-pipeline.mjs verify', proof: 'node ../assurance/proof/evidence-pipeline.mjs collect' } });
  }
  if (output.path.endsWith('/source/implementation-obligations.mjs')) {
    return `// Generated obligations only; no domain behaviour is invented.\nexport default ${JSON.stringify(data.resources, null, 2)};\n`;
  }
  if (output.path.endsWith('/assurance/tests/generated.test.mjs')) {
    return `import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport obligations from '../../source/implementation-obligations.mjs';\ntest('generated obligations are explicit',()=>assert.ok(Array.isArray(obligations)&&obligations.length>0));\n`;
  }
  if (output.path.endsWith('/assurance/proof/evidence-pipeline.mjs')) {
    return `import fs from 'node:fs';\nimport crypto from 'node:crypto';\nconst mode=process.argv[2];\nconst manifest=JSON.parse(fs.readFileSync(new URL('../../release/manifest.json',import.meta.url)));\nconst digest=(p)=>crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../../'+p,import.meta.url))).digest('hex');\nconst failures=manifest.files.filter(f=>digest(f.path)!==f.sha256);\nif(failures.length){console.error(JSON.stringify({status:'fail',failures}));process.exit(1)}\nconsole.log(JSON.stringify({status:'pass',mode,checked:manifest.files.length}));\n`;
  }
  if (/\/automation\/(?:proof-anchor|validate-spec)\.yaml$/.test(output.path)) {
    return `name: semantic-projection-validation\non:\n  push:\npermissions:\n  contents: read\nconcurrency:\n  group: semantic-projection-\${{ github.sha }}\n  cancel-in-progress: false\njobs:\n  validate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n        with:\n          node-version: '22'\n      - run: npm test --prefix tools/compiler\n`;
  }
  if (output.path.endsWith('.graphql')) {
    return `# Generated framework-neutral contract projection.\nscalar USFSemanticResource\ntype Query { semanticResources: [USFSemanticResource!]! }\n`;
  }
  if (output.path.endsWith('.md')) {
    return `# Generated USF architecture projection\n\nAuthority digest: ${data.authorityDigest}\n\nResources: ${data.resources.length}\n\nThis generated report is lower authority than the graph.\n`;
  }
  if (output.path.endsWith('.mjs')) return `export default ${JSON.stringify(data, null, 2)};\n`;
  return stableJson(data);
}

function write(root, relativePath, content, reuseRoot = null) {
  const target = join(root, relativePath);
  mkdirSync(dirname(target), { recursive: true });
  const digest = sha256(content);
  const prior = reuseRoot ? join(reuseRoot, relativePath) : null;
  if (prior && existsSync(prior) && sha256(readFileSync(prior)) === digest) {
    copyFileSync(prior, target);
    return { path: relativePath, bytes: Buffer.byteLength(content), sha256: digest, reused: true };
  }
  writeFileSync(target, content, { encoding: 'utf8', mode: relativePath.endsWith('.mjs') ? 0o755 : 0o644 });
  return { path: relativePath, bytes: Buffer.byteLength(content), sha256: digest, reused: false };
}

export function generateAuthority({ store, outputDir, mode = 'full', signingKeyPath }) {
  if (!['full', 'incremental'].includes(mode)) throw new CompilerError(`unsupported generation mode: ${mode}`, { phase: 'generate:configuration' });
  const target = resolve(outputDir);
  if (mode === 'full' && existsSync(target)) throw new CompilerError('full generation requires an absent output directory', { phase: 'generate:clean-room', outputDir: target });
  const plan = requireCompleteGenerationPlan(store);
  const sourceDigest = authorityDigest(store);
  mkdirSync(dirname(target), { recursive: true });
  const old = mode === 'incremental' && existsSync(target) ? verifyOutput(target, false) : null;
  const reuseRoot = old ? target : null;
  const staging = mkdtempSync(join(dirname(target) || tmpdir(), '.usf-generation-'));
  const release = plan.outputs.filter((item) => item.component === 'urn:usf:generator:release');
  const ordinary = plan.outputs.filter((item) => item.component !== 'urn:usf:generator:release');
  const files = [];
  try {
    for (const output of ordinary) {
      const data = projection(store, output, sourceDigest);
      const content = render(output, data);
      files.push(write(staging, output.path, content, reuseRoot));
    }
    const generatedRelease = release.filter((item) => !/(?:manifest|checksums|signature|attestation)\.json$/.test(item.path));
    for (const output of generatedRelease) {
      const base = projection(store, output, sourceDigest);
      const content = output.path.endsWith('/sbom.json')
        ? stableJson({ bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, components: files.map((f) => ({ type: 'file', name: f.path, hashes: [{ alg: 'SHA-256', content: f.sha256 }] })) })
        : stableJson({ ...base, materials: files.map((f) => ({ path: f.path, sha256: f.sha256 })) });
      files.push(write(staging, output.path, content, reuseRoot));
    }
    const checksumOutput = release.find((item) => item.path.endsWith('/checksums.json'));
    if (!checksumOutput) throw new CompilerError('release checksum artefact is absent from semantic plan', { phase: 'generate:release' });
    files.push(write(staging, checksumOutput.path, stableJson({ algorithm: 'sha256', files: [...files].map(({ reused, ...record }) => record).sort((a, b) => a.path.localeCompare(b.path)) }), reuseRoot));
    const manifestOutput = release.find((item) => item.path.endsWith('/manifest.json'));
    if (!manifestOutput) throw new CompilerError('release manifest artefact is absent from semantic plan', { phase: 'generate:release' });
    const releaseAuthorityContract = releaseAuthority(store, manifestOutput);
    const manifestFiles = [...files].map(({ reused, ...record }) => record).sort((a, b) => a.path.localeCompare(b.path));
    const manifest = { schemaVersion: 1, compilerVersion: '0.1.0', releaseVersion: releaseAuthorityContract.version,
      releaseVersionResource: releaseAuthorityContract.versionResource, authorityDigest: sourceDigest, files: manifestFiles };
    const manifestContent = stableJson(manifest);
    write(staging, manifestOutput.path, manifestContent);
    const signatureOutput = release.find((item) => item.path.endsWith('/signature.json'));
    const attestationOutput = release.find((item) => item.path.endsWith('/attestation.json'));
    if (!signatureOutput || !attestationOutput) throw new CompilerError('release signature or attestation artefact is absent from semantic plan', { phase: 'generate:release' });
    if (!signingKeyPath) throw new CompilerError('release signing requires --signing-key <PEM path>', { phase: 'generate:signing' });
    const privateKey = createPrivateKey(readFileSync(resolve(signingKeyPath)));
    const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
    const fingerprint = sha256(createPublicKey(privateKey).export({ type: 'spki', format: 'der' }));
    if (fingerprint !== releaseAuthorityContract.signingKeyFingerprint) throw new CompilerError('release key is not authorised by graph authority', {
      phase: 'generate:signing-authority', expected: releaseAuthorityContract.signingKeyFingerprint, observed: fingerprint,
    });
    const signature = sign(null, Buffer.from(manifestContent), privateKey).toString('base64');
    write(staging, signatureOutput.path, stableJson({ algorithm: 'Ed25519', signedPath: manifestOutput.path, signedSha256: sha256(manifestContent), publicKey, publicKeyFingerprint: fingerprint, signingIdentity: releaseAuthorityContract.signingIdentity, signature }), reuseRoot);
    write(staging, attestationOutput.path, stableJson({ schemaVersion: 1, kind: 'cleanroomgeneration', authorityDigest: sourceDigest, manifestPath: manifestOutput.path, manifestSha256: sha256(manifestContent), signaturePath: signatureOutput.path, signingIdentity: releaseAuthorityContract.signingIdentity, signingIdentityFingerprint: fingerprint, releaseVersion: releaseAuthorityContract.version, verificationRequired: true, nonClaims: ['integrity proof is not production readiness or external certification'] }), reuseRoot);
    const verified = verifyOutput(staging, true, releaseAuthorityContract.signingKeyFingerprint);
    const backup = `${target}.previous-${process.pid}`;
    if (existsSync(backup)) rmSync(backup, { recursive: true, force: true });
    if (existsSync(target)) renameSync(target, backup);
    try {
      renameSync(staging, target);
      if (existsSync(backup)) rmSync(backup, { recursive: true, force: true });
    } catch (error) {
      if (existsSync(target)) rmSync(target, { recursive: true, force: true });
      if (existsSync(backup)) renameSync(backup, target);
      throw error;
    }
    const prior = new Map((old?.manifest?.files ?? []).map((f) => [f.path, f.sha256]));
    return { ok: true, mode, outputDir: target, authorityDigest: sourceDigest, outputCount: verified.manifest.files.length + 3,
      reused: files.filter((f) => f.reused).length, changed: verified.manifest.files.filter((f) => prior.get(f.path) !== f.sha256).length,
      aggregateDigest: sha256(verified.manifest.files.map((f) => `${f.path}\u0000${f.sha256}`).join('\n')) };
  } catch (error) {
    if (existsSync(staging)) rmSync(staging, { recursive: true, force: true });
    if (error instanceof CompilerError) throw error;
    throw new CompilerError(error.message, { phase: 'generate' });
  }
}

export function verifyOutput(outputDir, required = true, expectedPublicKeyFingerprint = null) {
  const root = resolve(outputDir);
  const manifestPath = join(root, GENERATED_RELEASE_ROOT, 'manifest.json');
  if (!existsSync(manifestPath)) {
    if (!required) return null;
    throw new CompilerError('generated release manifest is missing', { phase: 'verify-output' });
  }
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const failures = [];
  for (const record of manifest.files ?? []) {
    const target = join(root, record.path);
    if (!existsSync(target)) failures.push({ path: record.path, reason: 'missing' });
    else if (sha256(readFileSync(target)) !== record.sha256) failures.push({ path: record.path, reason: 'digest-mismatch' });
  }
  const manifestContent = readFileSync(manifestPath);
  const signatureRelativePath = `${GENERATED_RELEASE_ROOT}/signature.json`;
  const attestationRelativePath = `${GENERATED_RELEASE_ROOT}/attestation.json`;
  const signaturePath = join(root, signatureRelativePath);
  const attestationPath = join(root, attestationRelativePath);
  if (!existsSync(signaturePath)) failures.push({ path: signatureRelativePath, reason: 'missing' });
  if (!existsSync(attestationPath)) failures.push({ path: attestationRelativePath, reason: 'missing' });
  if (existsSync(signaturePath)) {
    try {
      const signature = JSON.parse(readFileSync(signaturePath, 'utf8'));
      const fingerprint = sha256(createPublicKey(signature.publicKey).export({ type: 'spki', format: 'der' }));
      if (signature.algorithm !== 'Ed25519' || signature.signedPath !== `${GENERATED_RELEASE_ROOT}/manifest.json` || signature.signedSha256 !== sha256(manifestContent)) failures.push({ path: signatureRelativePath, reason: 'signature-metadata-mismatch' });
      if (signature.publicKeyFingerprint !== fingerprint) failures.push({ path: signatureRelativePath, reason: 'public-key-fingerprint-mismatch' });
      if (expectedPublicKeyFingerprint && fingerprint !== expectedPublicKeyFingerprint) failures.push({ path: signatureRelativePath, reason: 'unexpected-signing-identity' });
      if (!verify(null, manifestContent, createPublicKey(signature.publicKey), Buffer.from(signature.signature, 'base64'))) failures.push({ path: signatureRelativePath, reason: 'signature-invalid' });
    } catch (error) { failures.push({ path: signatureRelativePath, reason: `invalid:${error.message}` }); }
  }
  if (existsSync(attestationPath)) {
    try {
      const attestation = JSON.parse(readFileSync(attestationPath, 'utf8'));
      if (attestation.manifestSha256 !== sha256(manifestContent) || attestation.authorityDigest !== manifest.authorityDigest || attestation.verificationRequired !== true) failures.push({ path: 'release/attestation.json', reason: 'attestation-mismatch' });
    } catch (error) { failures.push({ path: attestationRelativePath, reason: `invalid:${error.message}` }); }
  }
  if (failures.length) throw new CompilerError('generated output verification failed', { phase: 'verify-output', failures });
  const independent = validateGeneratedOutput(root, { expectedPublicKeyFingerprint });
  if (!independent.ok) throw new CompilerError('independent generated output validation failed', {
    phase: 'verify-output:independent', failures: independent.findings,
  });
  return { ok: true, manifest, checked: manifest.files.length, independent };
}

export const generatorInternals = { componentQuery, projection };
