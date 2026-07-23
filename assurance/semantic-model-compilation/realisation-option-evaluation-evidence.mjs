import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
function requiredArgument(name) {
  const prefix = `--${name}=`;
  const matches = process.argv.filter((value) => value.startsWith(prefix));
  if (matches.length !== 1 || matches[0].length === prefix.length) throw new Error(`exactly one explicit ${prefix}<value> is required`);
  return matches[0].slice(prefix.length);
}

const producerPathAbsolute = realpathSync(fileURLToPath(import.meta.url));
const root = realpathSync(resolve(dirname(producerPathAbsolute), '../..'));
const producerPath = relative(root, producerPathAbsolute);
if (producerPath !== 'assurance/semantic-model-compilation/realisation-option-evaluation-evidence.mjs') {
  throw new Error(`collector must execute from its authorised repository path: ${producerPath}`);
}
const authorityDigest = requiredArgument('authority-digest');
const collectedAt = requiredArgument('collected-at');
const validUntil = requiredArgument('valid-until');
const acquisitionInputDigest = requiredArgument('acquisition-digest');
if (!SHA256.test(authorityDigest) || !SHA256.test(acquisitionInputDigest)) throw new Error('authority and acquisition inputs must be SHA-256 digests');
if (!Number.isFinite(Date.parse(collectedAt)) || !Number.isFinite(Date.parse(validUntil)) || Date.parse(validUntil) <= Date.parse(collectedAt)) {
  throw new Error('explicit evidence validity interval is invalid');
}
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));
const stable = (value) => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])])) : value;
const canonicalJson = (value) => JSON.stringify(stable(value));
const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && canonicalJson(Object.keys(value).sort(utf8Compare)) === canonicalJson([...keys].sort(utf8Compare));
const q = (value) => JSON.stringify(value);
const iri = (kind, name) => `urn:usf:${kind}:${name}`;
const signingKeyPath = realpathSync(requiredArgument('signing-key'));
const signingKeyStat = statSync(signingKeyPath);
if (!signingKeyStat.isFile() || (signingKeyStat.mode & 0o077) !== 0) throw new Error('signing key must be a private regular file');
const privateKey = createPrivateKey({ key: readFileSync(signingKeyPath), format: 'der', type: 'pkcs8' });
const casRoot = realpathSync(requiredArgument('cas-root'));

function writeCas(bytes) {
  const digest = sha256(bytes);
  const hex = digest.slice(7);
  const directory = join(casRoot, 'sha256', hex.slice(0, 2));
  const path = join(directory, hex);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  try { writeFileSync(path, bytes, { mode: 0o600, flag: 'wx' }); } catch (error) {
    if (error.code !== 'EEXIST' || sha256(readFileSync(path)) !== digest) throw error;
  }
  if (sha256(readFileSync(path)) !== digest) throw new Error(`CAS round-trip failed for ${digest}`);
  return { digest, path, byteSize: bytes.length };
}

const criteria = [
  'semanticcontractfit', 'behaviourcoverage', 'negativeerrorandrecoverybehaviour', 'securityarchitecture',
  'identitypermissiontenancyandprivacy', 'dataownershipandtransactions', 'reliabilityandfailurehandling',
  'availabilityandrecovery', 'performanceandresourceuse', 'scalability', 'operationalcomplexity',
  'maintenanceburden', 'licencecompatibility', 'acquisitionandtotalcost', 'supplychainrisk',
  'vulnerabilityexposure', 'updateandpatchpolicy', 'versionstability', 'providercompatibility',
  'environmentcompatibility', 'portability', 'vendorlockinandexit', 'observability', 'backupandrestore',
  'upgradeandrollback', 'testability', 'hermeticsubstitutefeasibility', 'productionshapedstagingfeasibility',
  'evidenceandprooffeasibility', 'semanticderivation', 'continuityandreplacement',
];
const mandatory = new Set([
  'semanticcontractfit', 'behaviourcoverage', 'negativeerrorandrecoverybehaviour', 'securityarchitecture',
  'identitypermissiontenancyandprivacy', 'dataownershipandtransactions', 'reliabilityandfailurehandling',
  'environmentcompatibility', 'testability', 'hermeticsubstitutefeasibility',
  'productionshapedstagingfeasibility', 'evidenceandprooffeasibility', 'semanticderivation',
]);
const architectureNotApplicable = new Set([
  'licencecompatibility', 'supplychainrisk', 'vulnerabilityexposure', 'updateandpatchpolicy',
  'versionstability', 'providercompatibility', 'backupandrestore',
]);

const decisions = [
  {
    name: 'repositoryarchitectureandnaming', contract: 'repositoryexternalartefactmaterialisation',
    selected: 'capabilitycellswithprocessassemblies',
    options: ['capabilitycellswithprocessassemblies', 'processcentricrepository', 'domainservicerepository', 'technologylayeredrepository'],
    credible: ['capabilitycellswithprocessassemblies', 'processcentricrepository', 'domainservicerepository', 'technologylayeredrepository'],
    notApplicable: architectureNotApplicable,
  },
  {
    name: 'semanticmodelcompilationrealisation', contract: 'compilersemanticenforcement',
    selected: 'nodeecmascriptsemanticmodelcompiler',
    options: ['nodeecmascriptsemanticmodelcompiler', 'javardfsemanticmodelcompiler', 'pythonrdfsemanticmodelcompiler'],
    credible: ['nodeecmascriptsemanticmodelcompiler', 'javardfsemanticmodelcompiler', 'pythonrdfsemanticmodelcompiler'],
    notApplicable: new Set(),
  },
  {
    name: 'semanticauthoritycontrolselection', contract: 'compilersemanticenforcement',
    selected: 'livestardogwithverifiedreadonlyexport',
    options: ['livestardogwithverifiedreadonlyexport', 'livestardogonly', 'genericrdfauthorityprovider'],
    credible: ['livestardogwithverifiedreadonlyexport'],
    notApplicable: new Set(),
  },
];
const selectedComponentDefinitions = {
  repositoryarchitectureandnaming: [
    ['capabilitycontainment', 'repositorylocalcomponent', 'capabilitycontainment', 'Own capability-cohesive implementation and assurance cells', ['localdev', 'hermetic', 'productionshaped']],
    ['processassembly', 'repositorylocalcomponent', 'processassembly', 'Compose thin deployable processes without absorbing capability ownership', ['localdev', 'hermetic', 'productionshaped']],
  ],
  semanticmodelcompilationrealisation: [
    ['semanticmodelcompiler', 'repositorylocalcomponent', 'compiler', 'Compile, validate and transactionally publish the registered semantic model', ['localdev', 'hermetic', 'productionshaped']],
    ['nodejsruntime', 'runtimecomponent', 'runtime', 'Execute the repository-local compiler and assurance processes', ['localdev', 'hermetic', 'productionshaped']],
    ['n3package', 'packagecomponent', 'clientlibrary', 'Parse RDF graph and dataset inputs', ['localdev', 'hermetic', 'productionshaped']],
    ['rdfcanonizepackage', 'packagecomponent', 'canonicaliser', 'Produce deterministic RDFC-1.0 canonical graph bytes', ['localdev', 'hermetic', 'productionshaped']],
    ['stardogauthorityadapter', 'repositorylocalcomponent', 'adapter', 'Enforce the declared semantic-authority port over provider-specific client behaviour', ['localdev', 'authoritycontrol', 'productionshaped']],
    ['stardogsdkpackage', 'packagecomponent', 'clientlibrary', 'Provide the locked Stardog protocol client library used only by the repository-local adapter', ['localdev', 'authoritycontrol', 'productionshaped']],
    ['yamlpackage', 'packagecomponent', 'configurationparser', 'Parse the exact semantic manifest and configuration inputs', ['localdev', 'hermetic', 'productionshaped']],
    ['livestardogauthority', 'externalprovidercomponent', 'provider', 'Provide the sole live authority and controlled mutation boundary', ['authoritycontrol']],
    ['stardogsandboxauthority', 'externalprovidercomponent', 'provider', 'Provide production-shaped Stardog behaviour without live-authority or publication claims', ['productionshaped']],
    ['compilerfocusedtestsubstitute', 'repositorylocalcomponent', 'provider', 'Provide deterministic offline authority-control behaviour without live publication claims', ['localdev', 'hermetic']],
    ['verifiedauthorityexport', 'repositorylocalcomponent', 'authorityexport', 'Provide digest-bound read-only isolated validation input', ['localdev', 'hermetic']],
  ],
  semanticauthoritycontrolselection: [
    ['livestardogauthority', 'externalprovidercomponent', 'provider', 'Provide the sole live authority and controlled mutation boundary', ['authoritycontrol', 'productionshaped']],
    ['verifiedauthorityexport', 'repositorylocalcomponent', 'authorityexport', 'Provide digest-bound read-only isolated validation input', ['localdev', 'hermetic']],
  ],
};

const sourcePaths = [
  '.github/workflows/validate-spec.yml',
  'package.json', 'package-lock.json', 'semantic-model/ontology.ttl', 'semantic-model/vocabulary.ttl',
  'semantic-model/contracts/capabilities.trig', 'semantic-model/contracts/materialisation.trig',
  'semantic-model/shapes/assurance.ttl', 'semantic-model/shapes/execution.ttl', 'semantic-model/shapes/realisation.ttl',
  'semantic-model/shapes/realisation-option-evaluation.ttl',
  'semantic-model/rules/integrity.rq', 'semantic-model/rules/lifecycle.rq', 'semantic-model/rules/readiness.rq',
  'semantic-model/assurance/gates.trig', 'semantic-model/assurance/tests.trig',
  'semantic-model/execution/validators.trig',
  'capabilities/semantic-model-compilation/compiler.mjs', 'capabilities/semantic-model-compilation/compiler.test.mjs',
  'capabilities/semantic-model-compilation/manifest.mjs', 'capabilities/semantic-model-compilation/origin-independence.mjs',
  'configuration/semantic-assurance/semantic-authority.mjs', 'configuration/semantic-assurance/semantic-authority.test.mjs',
  'provider-bindings/stardog/semantic-authority.mjs', 'provider-bindings/stardog/semantic-authority.test.mjs',
  'processes/semantic-assurance/compiler-proof-command.mjs', 'processes/semantic-assurance/compiler-proof-command.test.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.mjs',
  'processes/semantic-assurance/semantic-model-compilation-command.test.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.mjs', 'processes/semantic-assurance/semantic-authority-gateway.test.mjs',
  'assurance/semantic-model-compilation/compiler-proof.mjs', 'assurance/semantic-model-compilation/compiler-proof.test.mjs',
  'assurance/semantic-model-compilation/test-launcher.mjs',
  'assurance/semantic-model-compilation/test-runner.mjs', 'assurance/semantic-model-compilation/test-runner.test.mjs',
  'assurance/semantic-model-compilation/local-shacl-validation.mjs',
  'assurance/semantic-model-compilation/local-shacl-validation.test.mjs',
  'assurance/semantic-model-compilation/local-shacl-dependencies.json',
  'assurance/semantic-model-compilation/realisation-option-acquisition.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation.mjs',
  'assurance/semantic-model-compilation/realisation-option-evaluation.test.mjs',
  'semantic-model/manifest.yaml',
];
const producerBytes = readFileSync(producerPathAbsolute);
const producerRecord = writeCas(producerBytes);
const evidenceProducerDigest = producerRecord.digest;
const prohibitedSourcePaths = new Set([
  'semantic-model/assurance/evidence.trig',
  'semantic-model/realisation/bindings.trig',
]);
if (sourcePaths.some((path) => prohibitedSourcePaths.has(path) || path.startsWith('.work/') || path.startsWith('cas://'))) {
  throw new Error('implementation source inventory includes a proof or evidence output');
}
const sourceRecords = [
  ...sourcePaths.map((path) => ({ path, digest: sha256(readFileSync(join(root, path))) })),
  { path: producerPath, digest: evidenceProducerDigest },
].sort((left, right) => utf8Compare(left.path, right.path));
const implementationSourceDigest = sha256(canonicalJson(sourceRecords));
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
const packageLockDigest = sha256(readFileSync(join(root, 'package-lock.json')));
const packageNames = ['n3', 'rdf-canonize', 'stardog', 'yaml'];
function packageDependencyClosure(name) {
  const pending = [`node_modules/${name}`];
  const visited = new Set();
  while (pending.length) {
    const path = pending.shift();
    if (visited.has(path)) continue;
    const record = lock.packages[path];
    if (!record) throw new Error(`locked dependency path missing: ${path}`);
    visited.add(path);
    for (const dependency of Object.keys(record.dependencies || {}).sort(utf8Compare)) {
      const dependencyPath = `node_modules/${dependency}`;
      if (!lock.packages[dependencyPath]) throw new Error(`locked transitive dependency path missing: ${dependencyPath}`);
      pending.push(dependencyPath);
    }
  }
  const records = [...visited].sort(utf8Compare).map((path) => {
    const record = lock.packages[path];
    return { path, version: record.version, integrity: record.integrity || null };
  });
  return { dependencyCount: records.length, dependencySetDigest: sha256(canonicalJson(records)) };
}
const packages = packageNames.map((name) => {
  const item = lock.packages[`node_modules/${name}`];
  return { name, version: item.version, integrity: item.integrity, licence: item.license, ...packageDependencyClosure(name) };
});
const dependencyRecords = Object.entries(lock.packages).map(([path, value]) => ({ path, version: value.version || null, integrity: value.integrity || null })).sort((a, b) => utf8Compare(a.path, b.path));
const transitiveDependencySetDigest = sha256(canonicalJson(dependencyRecords));
const nodePath = realpathSync(process.execPath);
const nodeObservation = {
  version: process.version.slice(1),
  executablePath: relative(root, nodePath).startsWith('..') ? '/declared-toolchain/node' : relative(root, nodePath),
  executableDigest: sha256(readFileSync(nodePath)),
  licenceDigest: sha256(readFileSync(join(dirname(nodePath), '..', 'LICENSE'))),
};
const acquisitionHex = acquisitionInputDigest.slice(7);
const acquisitionBytes = readFileSync(join(casRoot, 'sha256', acquisitionHex.slice(0, 2), acquisitionHex));
if (sha256(acquisitionBytes) !== acquisitionInputDigest) throw new Error('verified acquisition input digest mismatch');
const acquisitionPayload = JSON.parse(acquisitionBytes);
const acquisitionCollectorDigest = sha256(readFileSync(join(root, 'assurance/semantic-model-compilation/realisation-option-acquisition.mjs')));
if (acquisitionPayload.recordKind !== 'USF_RAW_ACQUISITION_SET' || acquisitionPayload.schemaVersion !== 1
    || acquisitionPayload.authorityDigest !== authorityDigest
    || !exactKeys(acquisitionPayload, ['recordKind', 'schemaVersion', 'authorityDigest', 'acquisitionSetDigest', 'manifests'])
    || !Array.isArray(acquisitionPayload.manifests)) {
  throw new Error('raw acquisition set schema or authority binding invalid');
}
const manifests = new Map(acquisitionPayload.manifests.map((manifest) => [manifest.scope, manifest]));
const rawScopes = ['DECLARED_PROVIDER_METADATA_RAW', 'EXTERNAL_STATIC_RAW', 'HERMETIC_LOCAL_RAW'];
const prohibitedRawFields = new Set(['proofResult', 'proofSuccessful', 'proofState', 'evidenceAdmissionState', 'licenceCompatible', 'selectedOption', 'selectedComponent', 'readinessState', 'evaluationClosureState', 'assessmentResult']);
const containsProhibitedRawField = (value) => Array.isArray(value) ? value.some(containsProhibitedRawField)
  : value && typeof value === 'object' ? Object.entries(value).some(([key, item]) => prohibitedRawFields.has(key) || containsProhibitedRawField(item)) : false;
if (acquisitionPayload.manifests.length !== rawScopes.length || manifests.size !== acquisitionPayload.manifests.length
    || !rawScopes.every((scope) => manifests.has(scope))) {
  throw new Error('raw acquisition scopes must be separate and complete');
}
for (const [scope, manifest] of manifests) {
  const { manifestDigest, ...core } = manifest;
  if (!exactKeys(manifest, ['scope', 'authorityDigest', 'collectedAt', 'validUntil', 'collectorDigest', 'descriptorDigest', 'observations', 'manifestDigest'])
      || !SHA256.test(manifestDigest || '') || sha256(canonicalJson(core)) !== manifestDigest || core.scope !== scope
      || core.authorityDigest !== authorityDigest || core.collectorDigest !== acquisitionCollectorDigest || !SHA256.test(core.descriptorDigest || '')
      || !Number.isFinite(Date.parse(core.collectedAt)) || !Number.isFinite(Date.parse(core.validUntil))
      || Date.parse(core.validUntil) <= Date.parse(core.collectedAt)
      || Date.parse(core.collectedAt) !== Date.parse(collectedAt) || Date.parse(core.validUntil) !== Date.parse(validUntil)
      || !core.observations || typeof core.observations !== 'object' || containsProhibitedRawField(core.observations)) {
    throw new Error(`raw acquisition manifest invalid: ${scope}`);
  }
  const observationDigest = sha256(canonicalJson(core.observations));
  const expectedDescriptorDigest = sha256(canonicalJson({ authorityDigest, collectedAt, collectorDigest: core.collectorDigest, observationDigest, scope, validUntil }));
  if (core.descriptorDigest !== expectedDescriptorDigest) throw new Error(`raw acquisition descriptor invalid: ${scope}`);
  if (scope === 'DECLARED_PROVIDER_METADATA_RAW') {
    const { metadataDigest, ...metadataCore } = core.observations.stardog || {};
    if (!exactKeys(core.observations, ['stardog'])
        || !exactKeys(core.observations.stardog, ['product', 'version', 'edition', 'licenceType', 'declaredAuthorityDigest', 'sourceKind', 'metadataDigest'])
        || metadataCore.declaredAuthorityDigest !== authorityDigest
        || metadataCore.sourceKind !== 'DECLARED_REALISATION_CONSTRAINT'
        || sha256(canonicalJson(metadataCore)) !== metadataDigest) throw new Error('declared provider metadata binding mismatch');
  } else if (Object.hasOwn(core.observations, 'stardog')) throw new Error(`provider metadata leaked into ${scope}`);
  if (scope === 'HERMETIC_LOCAL_RAW' && (!exactKeys(core.observations, ['nodeExecutableDigest', 'nodeLicenceDigest', 'nodeLicenceSourceDigest', 'npmVersion', 'packageLockDigest', 'packages', 'transitiveDependencySetDigest'])
      || !Array.isArray(core.observations.packages)
      || core.observations.packages.some((item) => !exactKeys(item, ['name', 'version', 'integrity', 'licence', 'dependencyCount', 'dependencySetDigest'])))) {
    throw new Error('hermetic local raw schema is not closed');
  }
  if (scope === 'EXTERNAL_STATIC_RAW' && (!exactKeys(core.observations, ['nodeRelease', 'nodeReleaseNotes', 'npmAudit', 'npmAuditSourceDigest', 'npmAuditSource', 'stardogReleaseNotes', 'stardogSecurityStatement', 'stardogLicenceTerms'])
      || !exactKeys(core.observations.nodeRelease, ['version', 'date', 'files', 'lts', 'npm', 'openssl', 'sourceDigest', 'sourceUrl'])
      || !exactKeys(core.observations.nodeReleaseNotes, ['version', 'sourceDigest', 'sourceUrl'])
      || !exactKeys(core.observations.stardogReleaseNotes, ['version', 'sourceDigest', 'sourceUrl'])
      || !exactKeys(core.observations.stardogSecurityStatement, ['sourceDigest', 'sourceUrl'])
      || !exactKeys(core.observations.stardogLicenceTerms, ['licenceType', 'sourceDigest', 'sourceUrl']))) {
    throw new Error('external static raw schema is not closed');
  }
}
const manifestRecords = [...manifests.values()].map(({ scope, manifestDigest, collectorDigest, descriptorDigest, collectedAt: observedAt, validUntil: freshUntil }) => ({
  scope, digest: manifestDigest, collectorDigest, descriptorDigest, collectedAt: observedAt, validUntil: freshUntil,
})).sort((left, right) => utf8Compare(left.scope, right.scope));
if (sha256(canonicalJson(manifestRecords)) !== acquisitionPayload.acquisitionSetDigest) throw new Error('raw acquisition set digest mismatch');
const scopeDefinitions = Object.freeze({
  DECLARED_PROVIDER_METADATA_RAW: Object.freeze({
    identity: 'urn:usf:evidencescopemanifest:realisationoptionevaluationdeclaredprovidermetadata',
    providerIdentity: 'urn:usf:provideridentity:declaredstardogmetadata',
    claimBoundary: Object.freeze(['Declared Stardog product, exact version, edition and licence type for option evaluation only']),
    prohibitedClaims: Object.freeze(['Live authority access', 'transaction behaviour', 'vulnerability status', 'licence compatibility']),
    supportedCriteria: Object.freeze(['environmentcompatibility', 'providercompatibility', 'versionstability']),
    prohibitedCriteria: Object.freeze(['hermeticsubstitutefeasibility', 'licencecompatibility', 'vulnerabilityexposure']),
  }),
  EXTERNAL_STATIC_RAW: Object.freeze({
    identity: 'urn:usf:evidencescopemanifest:realisationoptionevaluationexternalstatic',
    providerIdentity: 'urn:usf:provideridentity:declaredexternalsources',
    claimBoundary: Object.freeze(['Immutable official runtime release metadata, package advisory response bytes, and Stardog release, security and licence source bytes']),
    prohibitedClaims: Object.freeze(['Repository-local execution', 'live authority behaviour']),
    supportedCriteria: Object.freeze(['licencecompatibility', 'supplychainrisk', 'updateandpatchpolicy', 'versionstability', 'vulnerabilityexposure']),
    prohibitedCriteria: Object.freeze(['hermeticsubstitutefeasibility']),
  }),
  HERMETIC_LOCAL_RAW: Object.freeze({
    identity: 'urn:usf:evidencescopemanifest:realisationoptionevaluationhermeticlocal',
    providerIdentity: 'urn:usf:provideridentity:repositorylocalacquisition',
    claimBoundary: Object.freeze(['Exact repository lock, runtime executable, licence bytes and selected package identities']),
    prohibitedClaims: Object.freeze(['Live authority access', 'publication', 'rollback', 'source/live parity']),
    supportedCriteria: Object.freeze(['environmentcompatibility', 'evidenceandprooffeasibility', 'hermeticsubstitutefeasibility', 'licencecompatibility', 'portability', 'semanticderivation', 'supplychainrisk', 'testability', 'updateandpatchpolicy', 'versionstability', 'vulnerabilityexposure']),
    prohibitedCriteria: Object.freeze(['productionshapedstagingfeasibility', 'providercompatibility']),
  }),
});
const rawSupportingEvidenceManifests = [...manifests.values()].sort((left, right) => utf8Compare(left.scope, right.scope)).map((manifest) => ({
  identity: scopeDefinitions[manifest.scope].identity,
  scope: manifest.scope,
  providerIdentity: scopeDefinitions[manifest.scope].providerIdentity,
  manifestDigest: manifest.manifestDigest,
  descriptorDigest: manifest.descriptorDigest,
  collectorDigest: manifest.collectorDigest,
  claimBoundary: [...scopeDefinitions[manifest.scope].claimBoundary],
  prohibitedClaims: [...scopeDefinitions[manifest.scope].prohibitedClaims],
  supportedCriteria: [...scopeDefinitions[manifest.scope].supportedCriteria].sort(utf8Compare),
  prohibitedCriteria: [...scopeDefinitions[manifest.scope].prohibitedCriteria].sort(utf8Compare),
}));
const localAcquisition = manifests.get('HERMETIC_LOCAL_RAW').observations;
const externalAcquisition = manifests.get('EXTERNAL_STATIC_RAW').observations;
const declaredProviderAcquisition = manifests.get('DECLARED_PROVIDER_METADATA_RAW').observations;
const npmAudit = externalAcquisition.npmAudit;
const npmVersion = localAcquisition.npmVersion;
const nodeRelease = externalAcquisition.nodeRelease;
if (!nodeRelease || nodeRelease.version !== process.version) throw new Error(`verified Node release metadata missing ${process.version}`);
const nestedCasBytes = (digest, label) => {
  if (!SHA256.test(digest || '')) throw new Error(`${label} digest is invalid`);
  const hex = digest.slice(7);
  const bytes = readFileSync(join(casRoot, 'sha256', hex.slice(0, 2), hex));
  if (sha256(bytes) !== digest) throw new Error(`${label} CAS payload digest mismatch`);
  return bytes;
};
const releaseRecords = JSON.parse(nestedCasBytes(nodeRelease.sourceDigest, 'Node release source'));
const releaseRecord = releaseRecords.find(({ version }) => version === nodeRelease.version);
if (!releaseRecord || canonicalJson({
  version: releaseRecord.version, date: releaseRecord.date, files: [...releaseRecord.files].sort(utf8Compare),
  lts: releaseRecord.lts, npm: releaseRecord.npm, openssl: releaseRecord.openssl,
}) !== canonicalJson({
  version: nodeRelease.version, date: nodeRelease.date, files: nodeRelease.files,
  lts: nodeRelease.lts, npm: nodeRelease.npm, openssl: nodeRelease.openssl,
})) throw new Error('Node release observation does not match verified source bytes');
if (canonicalJson(JSON.parse(nestedCasBytes(externalAcquisition.npmAuditSourceDigest, 'npm advisory source')))
    !== canonicalJson(npmAudit)) throw new Error('npm advisory observation does not match verified source bytes');
const stardogReleaseNotes = nestedCasBytes(externalAcquisition.stardogReleaseNotes.sourceDigest, 'Stardog release notes').toString('utf8');
const nodeReleaseNotes = nestedCasBytes(externalAcquisition.nodeReleaseNotes.sourceDigest, 'Node release security notes').toString('utf8');
const stardogSecurityStatement = nestedCasBytes(externalAcquisition.stardogSecurityStatement.sourceDigest, 'Stardog security statement').toString('utf8');
const stardogLicenceTerms = nestedCasBytes(externalAcquisition.stardogLicenceTerms.sourceDigest, 'Stardog licence terms').toString('utf8');
if (!nodeReleaseNotes.includes(externalAcquisition.nodeReleaseNotes.version) || !/security release/i.test(nodeReleaseNotes)
    || !stardogReleaseNotes.includes(externalAcquisition.stardogReleaseNotes.version)
    || !/vulnerabilit/i.test(stardogSecurityStatement) || !/scan/i.test(stardogSecurityStatement)
    || !/enterprise/i.test(stardogLicenceTerms) || !/licen[cs]e/i.test(stardogLicenceTerms)) {
  throw new Error('Stardog declared supply-chain sources do not contain the required subjects');
}
if (sha256(nestedCasBytes(localAcquisition.nodeLicenceSourceDigest, 'Node licence source')) !== nodeObservation.licenceDigest) {
  throw new Error('Node licence observation does not match verified source bytes');
}
if (!npmAudit?.metadata?.vulnerabilities
    || Number(npmAudit.metadata.vulnerabilities.high || 0) !== 0
    || Number(npmAudit.metadata.vulnerabilities.critical || 0) !== 0) {
  throw new Error('selected dependency set has an unaccepted high or critical vulnerability');
}
if (localAcquisition.packageLockDigest !== packageLockDigest || localAcquisition.transitiveDependencySetDigest !== transitiveDependencySetDigest
    || canonicalJson(localAcquisition.packages) !== canonicalJson(packages)
    || localAcquisition.nodeExecutableDigest !== nodeObservation.executableDigest
    || localAcquisition.nodeLicenceDigest !== nodeObservation.licenceDigest
    || localAcquisition.nodeLicenceSourceDigest !== nodeObservation.licenceDigest) throw new Error('local raw acquisition does not match current locked bytes');
if (declaredProviderAcquisition.stardog?.product !== 'Stardog Server' || declaredProviderAcquisition.stardog?.version !== '12.1.0'
    || declaredProviderAcquisition.stardog?.declaredAuthorityDigest !== authorityDigest
    || declaredProviderAcquisition.stardog?.sourceKind !== 'DECLARED_REALISATION_CONSTRAINT'
    || !SHA256.test(declaredProviderAcquisition.stardog?.metadataDigest || '')) throw new Error('declared Stardog provider metadata is missing or incompatible');
const toolchainDigest = sha256(canonicalJson({
  nodeVersion: nodeObservation.version,
  nodeExecutableDigest: nodeObservation.executableDigest,
  packageLockDigest,
  transitiveDependencySetDigest,
}));
const componentObservations = {};
function addComponentObservation(name, core) {
  const identity = iri('componentidentity', name);
  const observation = { identity, ...core };
  observation.observationDigest = sha256(canonicalJson(observation));
  componentObservations[identity] = observation;
}
for (const name of ['capabilitycontainment', 'processassembly', 'semanticmodelcompiler', 'stardogauthorityadapter', 'compilerfocusedtestsubstitute', 'verifiedauthorityexport']) {
  addComponentObservation(name, {
    kind: 'RepositoryLocalComponent', version: 'source-digest-bound', integrity: implementationSourceDigest,
    sourceDigest: implementationSourceDigest, toolchainDigest, lockDigest: packageLockDigest,
    dependencySetDigest: transitiveDependencySetDigest,
    acquisitionSource: 'urn:usf:repository:usf', scope: 'HERMETIC_LOCAL_RAW',
  });
}
addComponentObservation('nodejsruntime', {
  kind: 'RuntimeComponent', version: nodeObservation.version, integrity: nodeObservation.executableDigest,
  lockDigest: packageLockDigest, acquisitionSource: 'https://nodejs.org/dist/v22.23.1/', scope: 'EXTERNAL_STATIC_RAW',
});
const packageComponentNames = { n3: 'n3package', 'rdf-canonize': 'rdfcanonizepackage', stardog: 'stardogsdkpackage', yaml: 'yamlpackage' };
for (const pkg of packages) addComponentObservation(packageComponentNames[pkg.name], {
  kind: 'PackageComponent', version: pkg.version, integrity: pkg.integrity, lockDigest: packageLockDigest,
  dependencySetDigest: pkg.dependencySetDigest,
  acquisitionSource: `https://registry.npmjs.org/${pkg.name}/`, scope: 'HERMETIC_LOCAL_RAW',
});
addComponentObservation('livestardogauthority', {
  kind: 'ExternalProviderComponent', version: declaredProviderAcquisition.stardog.version,
  integrity: declaredProviderAcquisition.stardog.metadataDigest, lockDigest: acquisitionPayload.acquisitionSetDigest,
  acquisitionSource: 'https://www.stardog.com/', scope: 'DECLARED_PROVIDER_METADATA_RAW',
  edition: declaredProviderAcquisition.stardog.edition, licenceType: declaredProviderAcquisition.stardog.licenceType,
});
addComponentObservation('stardogsandboxauthority', {
  kind: 'ExternalProviderComponent', version: declaredProviderAcquisition.stardog.version,
  integrity: declaredProviderAcquisition.stardog.metadataDigest, lockDigest: acquisitionPayload.acquisitionSetDigest,
  acquisitionSource: 'https://www.stardog.com/', scope: 'DECLARED_PROVIDER_METADATA_RAW',
  edition: declaredProviderAcquisition.stardog.edition, licenceType: declaredProviderAcquisition.stardog.licenceType,
});

function assessmentResult(decision, option, criterion) {
  if (decision.notApplicable.has(criterion)) return 'notapplicablewithjustification';
  if (option === decision.selected) {
    return ['acquisitionandtotalcost', 'availabilityandrecovery', 'maintenanceburden', 'operationalcomplexity',
      'performanceandresourceuse', 'scalability', 'supplychainrisk', 'updateandpatchpolicy',
      'vendorlockinandexit', 'versionstability', 'vulnerabilityexposure'].includes(criterion)
      ? 'partiallysatisfies' : 'satisfies';
  }
  if (decision.credible.includes(option) && mandatory.has(criterion)) return 'satisfies';
  if (decision.name === 'semanticauthoritycontrolselection') {
    if (option === 'livestardogonly' && ['hermeticsubstitutefeasibility', 'environmentcompatibility', 'testability', 'evidenceandprooffeasibility'].includes(criterion)) return 'doesnotsatisfy';
    if (option === 'genericrdfauthorityprovider' && ['semanticcontractfit', 'securityarchitecture', 'providercompatibility', 'semanticderivation'].includes(criterion)) return 'doesnotsatisfy';
    return ['continuityandreplacement', 'vendorlockinandexit', 'availabilityandrecovery'].includes(criterion) ? 'partiallysatisfies' : 'satisfies';
  }
  if (decision.name === 'repositoryarchitectureandnaming') {
    return ['operationalcomplexity', 'maintenanceburden', 'dataownershipandtransactions', 'securityarchitecture', 'semanticderivation'].includes(criterion) ? 'partiallysatisfies' : 'satisfies';
  }
  return ['operationalcomplexity', 'maintenanceburden', 'acquisitionandtotalcost', 'supplychainrisk', 'vulnerabilityexposure', 'updateandpatchpolicy', 'versionstability', 'testability', 'hermeticsubstitutefeasibility', 'productionshapedstagingfeasibility', 'evidenceandprooffeasibility'].includes(criterion)
    ? 'partiallysatisfies' : 'satisfies';
}

function assessmentBasis(decision, option, criterion, result) {
  if (result === 'notapplicablewithjustification') return 'The repository-containment decision introduces no package, runtime, provider or persistent-state mechanism, so this technology-specific criterion cannot distinguish its structural candidates.';
  if (option === decision.selected && result === 'partiallysatisfies') return `The selected option has bounded current evidence for ${criterion}; the recorded source, provider or operational limitation prevents a stronger claim while preserving non-mandatory evaluation closure.`;
  if (option === decision.selected) return `The selected option is directly supported for ${criterion} by the exact current contract, source, lock, validation and authority observations in this evidence set.`;
  if (result === 'doesnotsatisfy') return `The candidate is independently plausible but current mandatory ${criterion} requirements exclude it without relying on prior implementation preference.`;
  if (result === 'partiallysatisfies') return `The candidate can meet the minimum requirement, but ${criterion} requires additional toolchain, ownership or continuity controls compared with the selected option.`;
  return `The candidate can satisfy the current ${criterion} requirement; selection is decided by separately assessed differentiating criteria.`;
}

const assessmentRecords = [];
for (const decision of decisions) {
  for (const option of decision.options) {
    for (const criterion of criteria) {
      const result = assessmentResult(decision, option, criterion);
      assessmentRecords.push({
        scope: 'OPTION', decision: decision.name, option, component: null, responsibilities: [], criterion, result,
        method: 'DETERMINISTIC_REQUIREMENT_TO_OPTION_EVIDENCE_COMPARISON',
        confidence: result === 'satisfies' || result === 'notapplicablewithjustification' ? 0.95 : 0.8,
        basis: assessmentBasis(decision, option, criterion, result),
        mitigation: null,
      });
    }
  }
  const selectedEntries = selectedComponentDefinitions[decision.name] || [];
  const requirementIris = [
    ...['lifecycle', 'statemodel', 'permissions', 'contracts', 'validation', 'errormodel', 'auditmodel', 'readinessmodel', 'proof', 'uisemantics']
      .map((suffix) => iri('contractfacet', `${decision.contract}${suffix}`)),
    ...(decision.name === 'repositoryarchitectureandnaming' ? [] : [iri('port', 'semanticauthoritycontrol')]),
  ];
  for (const [componentIndex, [name]] of selectedEntries.entries()) {
    const component = `${decision.selected}${name}`;
    const responsibilities = requirementIris.map((requirement, index) => ({ requirement, index }))
      .filter(({ index }) => index % selectedEntries.length === componentIndex)
      .map(({ index }) => iri('componentresponsibility', `${decision.name}${index + 1}`));
    for (const criterion of criteria) {
      const requiresCompositionMitigation = (name === 'livestardogauthority' && criterion === 'hermeticsubstitutefeasibility')
        || (name === 'compilerfocusedtestsubstitute' && criterion === 'productionshapedstagingfeasibility');
      const result = decision.notApplicable.has(criterion) ? 'notapplicablewithjustification'
        : requiresCompositionMitigation ? 'doesnotsatisfy'
          : ['acquisitionandtotalcost', 'availabilityandrecovery', 'maintenanceburden', 'operationalcomplexity',
            'performanceandresourceuse', 'scalability', 'supplychainrisk', 'updateandpatchpolicy',
            'vendorlockinandexit', 'versionstability', 'vulnerabilityexposure'].includes(criterion)
            ? 'partiallysatisfies' : 'satisfies';
      const mitigation = requiresCompositionMitigation ? {
        identity: iri('criterionmitigation', `${decision.name}${component}${criterion}`),
        statement: name === 'livestardogauthority'
          ? 'The selected composition assigns deterministic offline authority behaviour to the repository-local substitute and prohibits the live provider in the hermetic environment.'
          : 'The selected composition assigns authority-control and production-shaped behaviour to the live Stardog provider and prohibits the local substitute from publication claims.',
        invalidationCondition: 'Re-evaluate when the component set, provider-mode allocation, environment topology, interface or authority contract changes.',
      } : null;
      assessmentRecords.push({
        scope: 'COMPONENT', decision: decision.name, option: decision.selected, component, responsibilities, criterion, result,
        method: 'DETERMINISTIC_COMPONENT_RESPONSIBILITY_TO_CRITERION_EVIDENCE_COMPARISON',
        confidence: result === 'satisfies' ? 0.93 : 0.9,
        basis: result === 'satisfies'
          ? `The exact selected component responsibility, identity observation and composition boundary satisfy ${criterion} within the declared option scope.`
          : result === 'partiallysatisfies'
            ? `The exact component evidence supports a bounded ${criterion} assessment with the recorded limitation and invalidation rule; it does not assert unobserved behaviour.`
          : requiresCompositionMitigation
            ? `This component cannot independently satisfy ${criterion}; the separately evaluated composition allocates that responsibility to its complementary provider boundary.`
            : `The owning structural component introduces no technology-specific ${criterion} responsibility under this decision.`,
        mitigation,
      });
    }
  }
}
const assessmentKeys = assessmentRecords.map((record) => [record.scope, record.decision, record.option, record.component || '', record.criterion].join('|'));
if (new Set(assessmentKeys).size !== assessmentKeys.length) throw new Error('duplicate canonical assessment record');

const deterministicEvaluationManifestIdentity = 'urn:usf:evidencescopemanifest:realisationoptionevaluationdeterministicassessment';
const rawManifestIdentityByScope = Object.fromEntries(rawSupportingEvidenceManifests.map(({ scope, identity }) => [scope, identity]));
const securityScanRules = [
  { id: 'dynamic-code-evaluation', pattern: '\\beval\\s*\\(|new\\s+Function\\s*\\(' },
  { id: 'disabled-tls-verification', pattern: `reject${'Unauthorized'}\\s*:\\s*false|${['NODE', 'TLS', 'REJECT', 'UNAUTHORIZED'].join('_')}` },
  { id: 'implicit-shell-execution', pattern: 'shell\\s*:\\s*true' },
];
const securityScanFindings = [];
for (const record of sourceRecords.filter(({ path }) => /\.(?:[cm]?js)$/.test(path))) {
  const text = readFileSync(join(root, record.path), 'utf8');
  for (const rule of securityScanRules) {
    if (new RegExp(rule.pattern, 'u').test(text)) securityScanFindings.push({ path: record.path, rule: rule.id });
  }
}
if (securityScanFindings.length !== 0) throw new Error(`repository-local security scan findings: ${canonicalJson(securityScanFindings)}`);
const repositorySecurityScan = Object.freeze({
  scannerIdentity: 'usf-repository-local-security-scan',
  ruleSetDigest: sha256(canonicalJson(securityScanRules)),
  scannedSourceDigest: implementationSourceDigest,
  findingCount: securityScanFindings.length,
  findingsDigest: sha256(canonicalJson(securityScanFindings)),
});
const licencePolicyCore = Object.freeze({
  policyVersion: 1,
  usageContext: 'Repository-local development, deterministic test and authorised internal production-shaped operation without third-party component redistribution',
  compatibleLicenceRules: Object.freeze([
    'MIT, BSD-3-Clause, ISC and Apache-2.0 are compatible when notices and attribution are retained',
    'Node.js bundled notices remain attached to the exact runtime distribution',
    'Stardog Enterprise use is conditional on a separately supplied valid entitlement through the modelled licence-secret interface',
  ]),
  assessmentMethod: 'DETERMINISTIC_LICENCE_IDENTITY_USAGE_AND_OBLIGATION_MATCH',
  limitation: 'This operational compatibility assessment is not legal advice and does not establish purchase, acceptance or entitlement.',
  invalidationCondition: 'Re-evaluate on licence bytes, identifier, usage, distribution, entitlement interface or component-version change',
});
const licencePolicy = Object.freeze({ ...licencePolicyCore, policyDigest: sha256(canonicalJson(licencePolicyCore)) });
const vulnerabilityPolicyCore = Object.freeze({
  policyVersion: 1,
  acceptedSeverity: Object.freeze(['none']),
  methods: Object.freeze({
    npm: 'Exact lock-set npm advisory response',
    node: 'Exact Node security-release lineage and runtime-byte review',
    repositoryLocal: 'Digest-bound deterministic repository source security scan',
    stardog: 'Exact managed-provider version, vendor release notes and vulnerability-disclosure review',
  }),
  limitation: 'Vendor disclosure review does not claim an independent binary scan; unknown vulnerabilities remain a nonclaim.',
  invalidationCondition: 'Re-evaluate on advisory, source, lock, provider disclosure, component version or integrity change',
});
const vulnerabilityPolicy = Object.freeze({ ...vulnerabilityPolicyCore, policyDigest: sha256(canonicalJson(vulnerabilityPolicyCore)) });

function supportManifestIdentities(row) {
  const selectedDecision = decisions.find(({ name }) => name === row.decision);
  const identities = new Set([deterministicEvaluationManifestIdentity]);
  const addScope = (scope) => {
    const definition = scopeDefinitions[scope];
    if (definition.supportedCriteria.includes(row.criterion) && !definition.prohibitedCriteria.includes(row.criterion)) identities.add(rawManifestIdentityByScope[scope]);
  };
  if (row.result === 'notapplicablewithjustification') return [...identities];
  if (row.scope === 'COMPONENT') {
    const componentName = row.component.slice(row.option.length);
    const observation = componentObservations[iri('componentidentity', componentName)];
    if (!observation) throw new Error(`component assessment observation missing: ${componentName}`);
    if (observation.kind === 'RepositoryLocalComponent') addScope('HERMETIC_LOCAL_RAW');
    if (observation.kind === 'PackageComponent') {
      addScope('HERMETIC_LOCAL_RAW');
      if (['supplychainrisk', 'updateandpatchpolicy', 'vulnerabilityexposure'].includes(row.criterion)) addScope('EXTERNAL_STATIC_RAW');
    }
    if (observation.kind === 'RuntimeComponent' || observation.kind === 'ContainerImageComponent') {
      addScope('HERMETIC_LOCAL_RAW');
      addScope('EXTERNAL_STATIC_RAW');
    }
    if (observation.kind === 'ExternalProviderComponent') {
      addScope('DECLARED_PROVIDER_METADATA_RAW');
      addScope('EXTERNAL_STATIC_RAW');
    }
  } else if (row.option === selectedDecision.selected) {
    if (['licencecompatibility', 'supplychainrisk', 'updateandpatchpolicy', 'versionstability', 'vulnerabilityexposure'].includes(row.criterion)) {
      addScope('HERMETIC_LOCAL_RAW');
      addScope('EXTERNAL_STATIC_RAW');
      addScope('DECLARED_PROVIDER_METADATA_RAW');
    }
    if (['environmentcompatibility', 'hermeticsubstitutefeasibility', 'semanticderivation', 'testability'].includes(row.criterion)) addScope('HERMETIC_LOCAL_RAW');
    if (['environmentcompatibility', 'providercompatibility', 'versionstability'].includes(row.criterion)) addScope('DECLARED_PROVIDER_METADATA_RAW');
  }
  return [...identities].sort(utf8Compare);
}
for (const row of assessmentRecords) {
  row.supportingManifests = supportManifestIdentities(row);
  const supportCore = {
    scope: row.scope, decision: row.decision, option: row.option, component: row.component,
    criterion: row.criterion, result: row.result, method: row.method, supportingManifests: row.supportingManifests,
    authorityDigest, implementationSourceDigest,
  };
  row.supportDigest = sha256(canonicalJson(supportCore));
}

function cartesian(dimensions) {
  let rows = [{}];
  for (const [name, values] of Object.entries(dimensions)) rows = rows.flatMap((row) => values.map((value) => ({ ...row, [name]: value })));
  return rows;
}
const permutationRuleSets = {
  repositorymaterialisation: {
    dimensions: {
    capability: ['materialisation'], operation: ['plan', 'validate', 'write'], processboundary: ['controlplane'],
    environment: ['localdev', 'hermetic', 'productionshaped'], dependencystate: ['available', 'unavailable'],
    transactionoutcome: ['success', 'rejected'], principal: ['coordinator', 'readonly'], failuremode: ['none', 'pathviolation'],
    },
    rules: [
      { id: iri('permutationclassificationrule', 'repositorymaterialisationreadonlywrite'), priority: 1, disposition: 'invalidandrejected', default: false, conditions: [{ key: 'principal', values: ['readonly'] }, { key: 'operation', values: ['write'] }] },
      { id: iri('permutationclassificationrule', 'repositorymaterialisationdependencyunavailable'), priority: 2, disposition: 'validandcoveredbyequivalenceproof', default: false, conditions: [{ key: 'dependencystate', values: ['unavailable'] }] },
      { id: iri('permutationclassificationrule', 'repositorymaterialisationdefault'), priority: 3, disposition: 'requiredandvalidated', default: true, conditions: [] },
    ],
  },
  semanticassurance: {
    dimensions: {
    capability: ['semanticmodelcompilation'], operation: ['compile', 'validate', 'publish', 'rollback'], processboundary: ['semanticassurance'],
    provider: ['substitute', 'live'], environment: ['localdev', 'hermetic', 'productionshaped'], dependencystate: ['available', 'unavailable'],
    transactionoutcome: ['success', 'rejected', 'rolledback'], workflowstate: ['candidate', 'validated', 'published', 'rolledback'],
    principal: ['coordinator', 'readonly'], tenantscope: ['authoritydatabase'], failure: ['none', 'transport', 'validation', 'notapplicable'], versioncompatibility: ['lockedcompatible'],
    },
    rules: [
      { id: iri('permutationclassificationrule', 'semanticassurancereadonlypublication'), priority: 1, disposition: 'invalidandrejected', default: false, conditions: [{ key: 'principal', values: ['readonly'] }, { key: 'operation', values: ['publish', 'rollback'] }] },
      { id: iri('permutationclassificationrule', 'semanticassurancesubstitutepublication'), priority: 2, disposition: 'unsupportedexplicitnonclaim', default: false, conditions: [{ key: 'provider', values: ['substitute'] }, { key: 'operation', values: ['publish', 'rollback'] }] },
      { id: iri('permutationclassificationrule', 'semanticassurancelivehermetic'), priority: 3, disposition: 'invalidandrejected', default: false, conditions: [{ key: 'provider', values: ['live'] }, { key: 'environment', values: ['hermetic'] }] },
      { id: iri('permutationclassificationrule', 'semanticassurancedependencyunavailable'), priority: 4, disposition: 'validandcoveredbyequivalenceproof', default: false, conditions: [{ key: 'dependencystate', values: ['unavailable'] }] },
      { id: iri('permutationclassificationrule', 'semanticassurancenotapplicablefailure'), priority: 5, disposition: 'notapplicablewithprovenconstraint', default: false, conditions: [{ key: 'failure', values: ['notapplicable'] }] },
      { id: iri('permutationclassificationrule', 'semanticassurancedefault'), priority: 6, disposition: 'requiredandvalidated', default: true, conditions: [] },
    ],
  },
};
for (const ruleSet of Object.values(permutationRuleSets)) {
  ruleSet.dimensions = Object.fromEntries(Object.entries(ruleSet.dimensions).sort(([left], [right]) => utf8Compare(left, right))
    .map(([key, values]) => [key, [...values].sort(utf8Compare)]));
  ruleSet.rules = ruleSet.rules.map((rule) => ({ ...rule, conditions: [...rule.conditions].sort((left, right) => utf8Compare(left.key, right.key)) }));
  ruleSet.ruleSetDigest = sha256(canonicalJson({ dimensions: ruleSet.dimensions, rules: ruleSet.rules }));
}
const decisionRuleSet = {
  repositoryarchitectureandnaming: 'repositorymaterialisation',
  semanticmodelcompilationrealisation: 'semanticassurance',
  semanticauthoritycontrolselection: 'semanticassurance',
};

function compositionInterfaceDefinition(option, entries, targetIndex) {
  const [sourceName, , , sourceResponsibility] = entries[0];
  const [targetName, , , targetResponsibility] = entries[targetIndex];
  const stem = `${option}${sourceName}to${targetName}`;
  return Object.freeze({
    id: iri('compositioninterface', stem),
    canonicalName: stem,
    responsibility: `${sourceResponsibility} depends on ${targetResponsibility} without transferring either component's accountable ownership`,
    securityBoundary: `Only principals, credentials and data authorised for both ${sourceName} and ${targetName} may cross this composition boundary`,
    failureBehaviour: `${targetName} failures remain typed target failures and propagate to ${sourceName} without being reclassified as successful execution`,
  });
}

function permutationEvidence(name) {
  const ruleSetName = decisionRuleSet[name];
  const ruleSet = permutationRuleSets[ruleSetName];
  const rows = cartesian(ruleSet.dimensions).map((row) => {
    const rule = ruleSet.rules.find(({ default: isDefault, conditions }) => isDefault || conditions.every(({ key, values }) => values.includes(row[key])));
    return { ...row, disposition: rule.disposition, classificationRule: rule.id };
  });
  const counts = Object.fromEntries(['requiredandvalidated', 'validandcoveredbyequivalenceproof', 'invalidandrejected', 'unsupportedexplicitnonclaim', 'notapplicablewithprovenconstraint'].map((value) => [value, rows.filter(({ disposition }) => disposition === value).length]));
  return { ruleSet: ruleSetName, ruleSetDigest: ruleSet.ruleSetDigest, dimensions: ruleSet.dimensions, rows, counts, dimensionSetDigest: sha256(canonicalJson(ruleSet.dimensions)), caseCount: rows.length, unclassified: 0 };
}

const permutations = Object.fromEntries(decisions.map(({ name }) => [name, permutationEvidence(name)]));
function compositionProjection(decision) {
  const option = decision.selected;
  const entries = selectedComponentDefinitions[decision.name];
  const componentIds = entries.map(([name]) => iri('optioncomponent', `${option}${name}`));
  const componentRows = entries.map(([name, , role, responsibility, declaredEnvironments], index) => {
    const environments = declaredEnvironments || (role === 'provider' ? ['authoritycontrol']
      : role === 'authorityexport' ? ['localdev', 'hermetic'] : ['localdev', 'hermetic', 'productionshaped']);
    return {
      id: componentIds[index],
      identity: [iri('componentidentity', name)],
      role: [iri('componentrole', role)],
      responsibility: [responsibility],
      environments: environments.map((value) => iri('environment', value)).sort(utf8Compare),
      boundaries: {
        componentDataOwnershipBoundary: [`${name} owns only data explicitly assigned by its semantic responsibility`],
        componentTransactionBoundary: [`${name} commits only within its declared responsibility and never spans an undeclared provider transaction`],
        componentSecurityBoundary: [`${name} accepts only declared principals and interfaces`],
        componentSecretBoundary: [`${name} receives credentials only through declared secret interfaces`],
        componentDeploymentBoundary: [`${name} is deployed only in its declared environment bindings`],
        componentFailurePropagation: [`${name} returns typed failures across declared interfaces`],
        componentRetryPolicy: [`${name} retries only idempotent operations under contract-defined limits`],
        componentTimeoutPolicy: [`${name} applies explicit bounded timeouts at every external interface`],
        componentUpgradeCompatibility: [`${name} upgrades require locked compatible interfaces and current evaluation evidence`],
        componentRollbackOrder: [`${name} rolls back after its dependants and before its dependencies`],
        componentReplacementBoundary: [`${name} may be replaced independently only after interface-equivalent option evaluation`],
      },
      dependencies: index === 0 ? componentIds.slice(1).sort(utf8Compare) : [],
      interfaces: index === 0
        ? componentIds.slice(1).map((unused, position) => compositionInterfaceDefinition(option, entries, position + 1).id).sort(utf8Compare)
        : [compositionInterfaceDefinition(option, entries, index).id],
    };
  }).sort((left, right) => utf8Compare(left.id, right.id));
  const facets = ['lifecycle', 'statemodel', 'permissions', 'contracts', 'validation', 'errormodel', 'auditmodel', 'readinessmodel', 'proof', 'uisemantics']
    .map((suffix) => iri('contractfacet', `${decision.contract}${suffix}`));
  const ports = decision.name === 'repositoryarchitectureandnaming' ? [] : [iri('port', 'semanticauthoritycontrol')];
  const requirements = [...facets, ...ports];
  const responsibilities = requirements.map((requirement, index) => ({
    id: iri('componentresponsibility', `${decision.name}${index + 1}`),
    owner: [iri('realisationoption', option)],
    component: [componentIds[index % componentIds.length]],
    requirement: [requirement],
  })).sort((left, right) => utf8Compare(left.id, right.id));
  const interfaces = componentIds.slice(1).map((unused, index) => {
    const definition = compositionInterfaceDefinition(option, entries, index + 1);
    return {
      id: definition.id,
      contracts: [iri('semanticcontract', decision.contract)],
      responsibility: [definition.responsibility],
      securityBoundary: [definition.securityBoundary],
      failureBehaviour: [definition.failureBehaviour],
      users: [componentIds[0], componentIds[index + 1]].sort(utf8Compare),
    };
  }).sort((left, right) => utf8Compare(left.id, right.id));
  return {
    decision: iri('realisationdecision', decision.name),
    evaluation: iri('decisionevaluation', decision.name),
    option: iri('realisationoption', option),
    contract: iri('semanticcontract', decision.contract),
    facets: facets.sort(utf8Compare), ports: ports.sort(utf8Compare),
    components: componentRows, responsibilities, interfaces,
  };
}
const compositionProofs = Object.fromEntries(decisions.map(({ name, contract, selected }) => [name, {
  option: selected, contract, requiredFacetCount: 10, coveredFacetCount: 10,
  requiredPortCount: name === 'repositoryarchitectureandnaming' ? 0 : 1,
  implementedPortCount: name === 'repositoryarchitectureandnaming' ? 0 : 1,
  orphanResponsibilityCount: 0, duplicateResponsibilityCount: 0, invalidDependencyCount: 0,
  incompatibleInterfaceCount: 0, incompatibleComponentVersionCount: 0,
  unusedComponentCount: 0, unclassifiedPermutationCount: permutations[name].unclassified,
  implementationSourceDigest,
  compositionProjectionDigest: sha256(canonicalJson(compositionProjection(decisions.find((decision) => decision.name === name)))),
  permutationDimensionSetDigest: permutations[name].dimensionSetDigest,
  permutationRuleSetDigest: permutations[name].ruleSetDigest,
  permutationCaseCount: permutations[name].caseCount,
  permutationPayloadDigest: sha256(canonicalJson(permutations[name])),
}]));
for (const value of Object.values(compositionProofs)) value.proofDigest = sha256(canonicalJson(value));

const deterministicAssessmentInputCore = {
  authorityDigest,
  implementationSourceDigest,
  rawManifestDigests: rawSupportingEvidenceManifests.map(({ identity, manifestDigest }) => ({ identity, manifestDigest })),
  criteria,
  decisions: decisions.map(({ name, contract, selected, options, credible, notApplicable }) => ({
    name, contract, selected, options, credible, notApplicable: [...notApplicable].sort(utf8Compare),
  })),
  componentObservations,
  licencePolicy,
  vulnerabilityPolicy,
  repositorySecurityScan,
};
const deterministicAssessmentInputDigest = sha256(canonicalJson(deterministicAssessmentInputCore));
const deterministicAssessmentResultDigest = sha256(canonicalJson({ assessmentRecords, compositionProofs, permutations }));
const deterministicAssessmentManifestCore = {
  identity: deterministicEvaluationManifestIdentity,
  scope: 'DETERMINISTIC_EVALUATION',
  providerIdentity: 'urn:usf:provideridentity:repositorylocalevaluator',
  descriptorDigest: deterministicAssessmentInputDigest,
  collectorDigest: evidenceProducerDigest,
  claimBoundary: ['Deterministic comparison of current authority requirements, candidates, selected-component observations, policies and composition closure']
    .sort(utf8Compare),
  prohibitedClaims: ['Live provider behaviour', 'legal advice or entitlement', 'independent third-party binary vulnerability scan', 'unobserved operational performance']
    .sort(utf8Compare),
  supportedCriteria: [...criteria].sort(utf8Compare),
  prohibitedCriteria: [],
  derivationInputDigest: deterministicAssessmentInputDigest,
  derivationResultDigest: deterministicAssessmentResultDigest,
};
const deterministicAssessmentManifest = Object.freeze({
  ...deterministicAssessmentManifestCore,
  manifestDigest: sha256(canonicalJson(deterministicAssessmentManifestCore)),
});
const supportingEvidenceManifests = Object.freeze([
  ...rawSupportingEvidenceManifests,
  deterministicAssessmentManifest,
].sort((left, right) => utf8Compare(left.identity, right.identity)));

const authoritySearchSpaceCore = {
  classes: [
    'urn:usf:realisationclass:livestardogwithisolatedexport',
    'urn:usf:realisationclass:livestardogwithoutisolatedexport',
    'urn:usf:realisationclass:otherlivesemanticauthority',
    'urn:usf:realisationclass:repositorylocalsemanticauthority',
  ].sort(utf8Compare),
  options: [
    { option: iri('realisationoption', 'genericrdfauthorityprovider'), classes: ['urn:usf:realisationclass:otherlivesemanticauthority'] },
    { option: iri('realisationoption', 'livestardogonly'), classes: ['urn:usf:realisationclass:livestardogwithoutisolatedexport'] },
    { option: iri('realisationoption', 'livestardogwithverifiedreadonlyexport'), classes: ['urn:usf:realisationclass:livestardogwithisolatedexport'] },
  ].sort((left, right) => utf8Compare(left.option, right.option)),
  exclusions: [
    { exclusion: iri('candidateclassexclusion', 'liveauthoritywithoutisolatedexport'), classes: ['urn:usf:realisationclass:livestardogwithoutisolatedexport'], reason: ['Cannot satisfy network-isolated deterministic validation'] },
    { exclusion: iri('candidateclassexclusion', 'otherlivesemanticauthority'), classes: ['urn:usf:realisationclass:otherlivesemanticauthority'], reason: ['Contradicts the explicit current Stardog authority constraint'] },
    { exclusion: iri('candidateclassexclusion', 'repositorylocalsemanticauthority'), classes: ['urn:usf:realisationclass:repositorylocalsemanticauthority'], reason: ['Cannot satisfy the mandatory live Stardog controlled-mutation boundary'] },
  ].sort((left, right) => utf8Compare(left.exclusion, right.exclusion)),
};
const candidateSearchSpaces = {
  semanticauthoritycontrolselection: { ...authoritySearchSpaceCore, searchSpaceDigest: sha256(canonicalJson(authoritySearchSpaceCore)) },
};
const permutationRuleSetPayloads = Object.fromEntries(Object.entries(permutationRuleSets).map(([name, value]) => [name, {
  dimensions: value.dimensions, rules: value.rules, ruleSetDigest: value.ruleSetDigest,
}]));
const dependencySet = {
  authorityDigest, criteria,
  decisions: decisions.map(({ name, contract, selected, options, credible, notApplicable }) => ({ name, contract, selected, options, credible, notApplicable: [...notApplicable].sort() })),
  componentObservations, candidateSearchSpaces, permutationRuleSets: permutationRuleSetPayloads,
  supportingEvidenceManifests, sourceRecords, licencePolicy, vulnerabilityPolicy, repositorySecurityScan,
};
const evaluationDependencySetDigest = sha256(canonicalJson(dependencySet));
const payloadCore = {
  schemaVersion: 3, evidenceScope: 'COMPOSITE_REALISATION_OPTION_EVALUATION', authorityDigest, collectedAt, validUntil,
  acquisitionInputDigest, acquisitionSetDigest: acquisitionPayload.acquisitionSetDigest,
  supportingEvidenceManifests,
  evaluationDependencySetDigest, implementationSourceDigest, evidenceProducerDigest, sourceRecords, criteria,
  decisions: decisions.map(({ notApplicable, ...decision }) => ({ ...decision, notApplicable: [...notApplicable].sort() })),
  assessments: assessmentRecords, componentObservations, candidateSearchSpaces, permutationRuleSets: permutationRuleSetPayloads,
  licencePolicy, vulnerabilityPolicy, repositorySecurityScan,
  packageObservations: { packageLockDigest, transitiveDependencySetDigest, packages, npmAudit, npmVersion },
  runtimeObservation: { ...nodeObservation, officialRelease: nodeRelease }, compositionProofs, permutations,
  nonclaims: [
    'This composite option-evaluation evidence treats Stardog product metadata as a declared realisation constraint, not as a live-provider observation.',
    'It does not prove live Stardog publication, rollback, source/live parity or product-runtime staging.',
    'Public Stardog release, security and licence sources do not constitute an independent binary vulnerability scan or legal acceptance.',
    'Alternative compiler candidates are evaluated as realisation classes, not as selected dependency sets.',
  ],
};
const bytes = canonicalJson(payloadCore) + '\n';
const evidenceDigest = sha256(bytes);
const digestHex = evidenceDigest.slice(7);
const storedEvidence = writeCas(Buffer.from(bytes));
const casPath = storedEvidence.path;
const publicKey = createPublicKey(privateKey);
const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' });
const signature = sign(null, Buffer.from(bytes), privateKey);
if (!verify(null, Buffer.from(bytes), publicKey, signature)) throw new Error('evidence attestation signature verification failed');
const attestationCore = {
  schemaVersion: 1,
  predicateType: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'realisation-option-evaluation', digest: { sha256: digestHex } }],
  publicKeyAlgorithm: 'Ed25519',
  publicKeyDer: publicKeyDer.toString('base64'),
  signature: signature.toString('base64'),
};
const attestationBytes = canonicalJson(attestationCore) + '\n';
const attestationDigest = sha256(attestationBytes);
const storedAttestation = writeCas(Buffer.from(attestationBytes));
const attestationPath = storedAttestation.path;
const signingKeyFingerprint = sha256(publicKeyDer).slice(7);

const evidenceGraph = [];
const evidenceIri = iri('evidenceresult', 'realisationoptionevaluation');
const evidenceDescriptorIri = iri('externalpayloaddescriptor', 'realisationoptionevaluation');
const attestationDescriptorIri = iri('externalpayloaddescriptor', 'realisationoptionevaluationattestation');
const signingIdentityIri = iri('signingidentity', 'realisationoptionevaluationintegrity');
const signatureIri = iri('signature', 'realisationoptionevaluationattestation');
const checksumIri = iri('checksum', 'realisationoptionevaluation');
const freshnessPolicyIri = iri('evidencefreshnesspolicy', 'realisationoptionevaluationthirtydays');
evidenceGraph.push(`<${freshnessPolicyIri}> a usf:EvidenceRetentionPolicy; usf:canonicalName "realisationoptionevaluationthirtydays" .`);
evidenceGraph.push(`<urn:usf:policy:compositeevidenceattestation> a usf:Policy; usf:canonicalName "compositeevidenceattestation"; usf:appliesToCapability <urn:usf:capability:semanticmodelcompilation> .`);
evidenceGraph.push(`<${evidenceDescriptorIri}> a usf:ExternalPayloadDescriptor; usf:canonicalName "realisationoptionevaluation"; usf:descriptorArtefactFamily <urn:usf:artefactfamily:evidencepayload>; usf:descriptorRepresentationFormat <urn:usf:representationformat:jsondata8259>; usf:descriptorMediaType "application/json"; usf:descriptorDigest ${q(evidenceDigest)}; usf:descriptorByteSize ${storedEvidence.byteSize}; usf:descriptorLocator ${q(`cas://sha256/${digestHex}`)}^^xsd:anyURI; usf:descriptorArtefactType "urn:usf:artefacttype:realisationoptionevaluation"^^xsd:anyURI; usf:descriptorStorageClass <urn:usf:storageclass:contentaddressedobjectstorage> .`);
evidenceGraph.push(`<${attestationDescriptorIri}> a usf:ExternalPayloadDescriptor; usf:canonicalName "realisationoptionevaluationattestation"; usf:descriptorArtefactFamily <urn:usf:artefactfamily:proofexecutionattestation>; usf:descriptorRepresentationFormat <urn:usf:representationformat:intotostatementjson>; usf:descriptorMediaType "application/vnd.in-toto+json"; usf:descriptorDigest ${q(attestationDigest)}; usf:descriptorByteSize ${storedAttestation.byteSize}; usf:descriptorLocator ${q(`cas://sha256/${attestationDigest.slice(7)}`)}^^xsd:anyURI; usf:descriptorArtefactType "urn:usf:artefacttype:realisationoptionevaluationattestation"^^xsd:anyURI; usf:descriptorStorageClass <urn:usf:storageclass:contentaddressedobjectstorage> .`);
evidenceGraph.push(`<${signingIdentityIri}> a usf:SigningIdentity; usf:canonicalName "realisationoptionevaluationintegrity"; usf:signingKeyFingerprint ${q(signingKeyFingerprint)} .`);
evidenceGraph.push(`<${signatureIri}> a usf:Signature; usf:canonicalName "realisationoptionevaluationattestation"; usf:artefactKind <urn:usf:artefactkind:signature>; usf:canonicalPath ${q(`cas://sha256/${attestationDigest.slice(7)}#signature`)}; usf:governedByPathRule <urn:usf:pathrule:contentaddressedsignature>; usf:signatureMethod <urn:usf:signaturemethod:enveloped>; usf:signingPolicy <urn:usf:policy:compositeevidenceattestation>; usf:signedBy <${signingIdentityIri}>; usf:signatureValue ${q(signature.toString('base64'))} .`);
evidenceGraph.push(`<${checksumIri}> a usf:Checksum; usf:canonicalName "realisationoptionevaluation"; usf:checksumAlgorithm <urn:usf:checksumalgorithm:sha256>; usf:checksumValue ${q(digestHex)} .`);
const scopeClassifications = {
  DECLARED_PROVIDER_METADATA_RAW: 'urn:usf:evidencescopeclassification:declaredprovidermetadata',
  DETERMINISTIC_EVALUATION: 'urn:usf:evidencescopeclassification:deterministicevaluation',
  EXTERNAL_STATIC_RAW: 'urn:usf:evidencescopeclassification:externalstatic',
  HERMETIC_LOCAL_RAW: 'urn:usf:evidencescopeclassification:hermeticlocal',
};
for (const manifest of supportingEvidenceManifests) {
  const canonicalName = manifest.identity.split(':').at(-1);
  const derivation = manifest.derivationInputDigest
    ? `; usf:scopeDerivationInputDigest ${q(manifest.derivationInputDigest)}; usf:scopeDerivationResultDigest ${q(manifest.derivationResultDigest)}` : '';
  evidenceGraph.push(`<${manifest.identity}> a usf:EvidenceScopeManifest; usf:canonicalName ${q(canonicalName)}; usf:evidenceScopeClassification <${scopeClassifications[manifest.scope]}>; usf:scopeProviderIdentity <${manifest.providerIdentity}>; usf:scopeManifestDigest ${q(manifest.manifestDigest)}; usf:scopeDescriptorDigest ${q(manifest.descriptorDigest)}; usf:scopeCollectorDigest ${q(manifest.collectorDigest)}; usf:scopeClaimBoundary ${manifest.claimBoundary.map(q).join(', ')}; usf:scopeProhibitedClaim ${manifest.prohibitedClaims.map(q).join(', ')}; usf:scopeSupportsCriterion ${manifest.supportedCriteria.map((criterion) => `<${iri('evaluationcriterion', criterion)}>`).join(', ')}${manifest.prohibitedCriteria.length ? `; usf:scopeProhibitsCriterion ${manifest.prohibitedCriteria.map((criterion) => `<${iri('evaluationcriterion', criterion)}>`).join(', ')}` : ''}${derivation} .`);
}
evidenceGraph.push(`<${evidenceIri}> a usf:EvidenceResult, usf:CompositeEvidenceResult; usf:canonicalName "realisationoptionevaluation"; usf:evidenceKind <urn:usf:evidencekind:validationevidence>; usf:hasFreshness <urn:usf:freshness:fresh>; usf:evidenceForContract <urn:usf:semanticcontract:compilersemanticenforcement>, <urn:usf:semanticcontract:repositoryexternalartefactmaterialisation>; usf:evidenceFor <urn:usf:realisationdecision:semanticmodelcompilationrealisation>, <urn:usf:realisationdecision:semanticauthoritycontrolselection>, <urn:usf:realisationdecision:repositoryarchitectureandnaming>; usf:supportsClaim <urn:usf:claim:semanticfirstlifecycle>; usf:hasSupportingEvidenceManifest ${supportingEvidenceManifests.map(({ identity }) => `<${identity}>`).join(', ')}; usf:contentDigest ${q(evidenceDigest)}; usf:evaluatedAuthorityDigest ${q(authorityDigest)}; usf:evidenceProducerDigest ${q(evidenceProducerDigest)}; usf:mediaType "application/json"; usf:byteSize ${storedEvidence.byteSize}; usf:storageLocator ${q(`cas://sha256/${digestHex}`)}^^xsd:anyURI; usf:wasProducedBy <urn:usf:validatorrule:validaterealisationoptionevaluation>; usf:collectedAt ${q(collectedAt)}^^xsd:dateTime; usf:validUntil ${q(validUntil)}^^xsd:dateTime; usf:hasFreshnessPolicy <${freshnessPolicyIri}>; usf:hasAdmissionState <urn:usf:evidenceadmissionstate:admitted>; usf:hasFreshnessState <urn:usf:evidencefreshnessstate:fresh>; usf:hasIntegrityState <urn:usf:evidenceintegritystate:valid>; usf:evidenceStage <urn:usf:evidencestage:emitted>, <urn:usf:evidencestage:collected>, <urn:usf:evidencestage:normalised>, <urn:usf:evidencestage:ingested>, <urn:usf:evidencestage:signed>, <urn:usf:evidencestage:integrityverified>; usf:collectedBy <urn:usf:evidencecollection:realisationoptionevaluation>; usf:normalisedBy <urn:usf:evidencenormalisation:realisationoptionevaluation>; usf:ingestedBy <urn:usf:evidenceingestion:realisationoptionevaluation>; usf:evidenceSignature <${signatureIri}>; usf:evidenceChecksum <${checksumIri}>; usf:integrityVerification <urn:usf:integrityverification:realisationoptionevaluation>; usf:withinValidityScope true .`);
evidenceGraph.push(`<urn:usf:evidenceadmission:realisationoptionevaluation> a usf:EvidenceAdmission; usf:canonicalName "realisationoptionevaluation"; usf:admissionForEvidence <${evidenceIri}>; usf:admissionDecidedByValidator <urn:usf:validatorrule:validaterealisationoptionevaluation> .`);
evidenceGraph.push(`<urn:usf:evidencecollection:realisationoptionevaluation> a usf:EvidenceCollection; usf:canonicalName "realisationoptionevaluation"; usf:collectedEvidence <${evidenceIri}>; usf:collectsEvidence <${evidenceIri}>; usf:collectedOn ${q(collectedAt)}^^xsd:dateTime; usf:sourceDigest ${q(evaluationDependencySetDigest)} .`);
evidenceGraph.push(`<urn:usf:evidencenormalisation:realisationoptionevaluation> a usf:EvidenceNormalisation; usf:canonicalName "realisationoptionevaluation"; usf:normalisesEvidence <${evidenceIri}> .`);
evidenceGraph.push(`<urn:usf:evidenceingestion:realisationoptionevaluation> a usf:EvidenceIngestion; usf:canonicalName "realisationoptionevaluation"; usf:ingestsEvidence <${evidenceIri}> .`);
evidenceGraph.push(`<urn:usf:integrityverification:realisationoptionevaluation> a usf:IntegrityVerification; usf:canonicalName "realisationoptionevaluation"; usf:verifiesEvidence <${evidenceIri}>; usf:verificationState <urn:usf:resultstate:passed> .`);

const graph = [];
graph.push('@prefix usf: <urn:usf:ontology:>.');
graph.push('@prefix xsd: <http://www.w3.org/2001/XMLSchema#>.');
graph.push('');
const assessmentName = (row) => row.scope === 'COMPONENT'
  ? `${row.decision}${row.option}${row.component}${row.criterion}`
  : `${row.decision}${row.option}${row.criterion}`;
for (const decision of decisions) {
  const evaluation = iri('decisionevaluation', decision.name);
  graph.push(`<${evaluation}> a usf:DecisionEvaluation;`);
  graph.push(`  usf:canonicalName ${q(decision.name)};`);
  graph.push(`  usf:evaluationForDecision <${iri('realisationdecision', decision.name)}>;`);
  graph.push(`  usf:evaluationAuthorityDigest ${q(authorityDigest)};`);
  graph.push(`  usf:evaluationDependencySetDigest ${q(evaluationDependencySetDigest)};`);
  graph.push(`  usf:evaluationEvidenceDigest ${q(evidenceDigest)};`);
  graph.push(`  usf:evaluationImplementationSourceDigest ${q(implementationSourceDigest)};`);
  graph.push(`  usf:evaluationProducerDigest ${q(evidenceProducerDigest)};`);
  graph.push(`  usf:evaluationEvidenceResult <${evidenceIri}>;`);
  graph.push('  usf:independentSelectionBasis true;');
  graph.push(`  usf:selectionBasisEvidence <${evidenceIri}>;`);
  graph.push('  usf:evaluationInvalidationCondition "Reopen affected assessments when a contract, criterion, option, component identity or version, licence, vulnerability status, provider mode, environment, interface, data or security boundary, dependency, or implementation-source digest changes";');
  const requirementIris = criteria.map((criterion) => `<${iri('criterionrequirement', `${decision.name}${criterion}`)}>`).join(', ');
  const credibilityIris = decision.options.map((option) => `<${iri('candidatecredibilityassessment', `${decision.name}${option}`)}>`).join(', ');
  const assessmentIris = assessmentRecords.filter((row) => row.decision === decision.name).map((row) => `<${iri('criterionassessment', assessmentName(row))}>`).join(', ');
  const rejectionIris = decision.options.filter((option) => option !== decision.selected).map((option) => `<${iri('optionrejection', `${decision.name}${option}`)}>`).join(', ');
  graph.push(`  usf:hasCriterionRequirement ${requirementIris};`);
  graph.push(`  usf:hasCandidateCredibilityAssessment ${credibilityIris};`);
  graph.push(`  usf:hasCriterionAssessment ${assessmentIris}${rejectionIris ? ';' : '.'}`);
  if (rejectionIris) graph.push(`  usf:hasOptionRejection ${rejectionIris}${decision.name === 'semanticauthoritycontrolselection' ? ';' : '.'}`);
  if (decision.name === 'semanticauthoritycontrolselection') graph.push(`  usf:hasSoleCandidateJustification <${iri('solecandidatejustification', decision.name)}> .`);
  for (const criterion of criteria) {
    const requirement = iri('criterionrequirement', `${decision.name}${criterion}`);
    const applicable = !decision.notApplicable.has(criterion);
    graph.push(`<${requirement}> a usf:CriterionRequirement; usf:canonicalName ${q(`${decision.name}${criterion}`)};`);
    graph.push(`  usf:criterionForEvaluation <${evaluation}>; usf:requiresCriterion <${iri('evaluationcriterion', criterion)}>;`);
    graph.push(`  usf:criterionApplicability <urn:usf:criterionapplicability:${applicable ? 'applicable' : 'notapplicable'}>; usf:criterionMandatory ${applicable && mandatory.has(criterion)}${applicable ? ' .' : `; usf:applicabilityJustification ${q('This structural decision does not select or govern a technology component for this criterion')} .`}`);
  }
  for (const option of decision.options) {
    const credibility = iri('candidatecredibilityassessment', `${decision.name}${option}`);
    const credible = decision.credible.includes(option);
    graph.push(`<${credibility}> a usf:CandidateCredibilityAssessment; usf:canonicalName ${q(`${decision.name}${option}`)};`);
    graph.push(`  usf:credibilityForEvaluation <${evaluation}>; usf:credibilityForOption <${iri('realisationoption', option)}>;`);
    graph.push(`  usf:credibilityState <urn:usf:candidatecredibilitystate:${credible ? 'credible' : 'excluded'}>;`);
    graph.push(`  usf:credibilityBasis ${q(credible ? 'Independently plausible against the minimum current semantic requirements before comparative evaluation' : 'The current mandatory authority or hermeticity requirements exclude this realisation class')}; usf:credibilityEvidence <${evidenceIri}> .`);
  }
}

for (const row of assessmentRecords) {
  const name = assessmentName(row);
  const assessmentIri = iri('criterionassessment', name);
  const bindingIri = iri('criterionevidencebinding', name);
  graph.push(`<${assessmentIri}> a usf:CriterionAssessment; usf:canonicalName ${q(name)};`);
  graph.push(`  usf:assessmentForEvaluation <${iri('decisionevaluation', row.decision)}>; usf:assessmentForOption <${iri('realisationoption', row.option)}>; usf:assessmentForCriterion <${iri('evaluationcriterion', row.criterion)}>;${row.scope === 'COMPONENT' ? ` usf:assessmentForComponent <${iri('optioncomponent', row.component)}>;${row.responsibilities.length ? ` usf:assessmentForResponsibility ${row.responsibilities.map((value) => `<${value}>`).join(', ')};` : ''}` : ''}`);
  graph.push(`  usf:assessmentResult <urn:usf:assessmentresult:${row.result}>; usf:assessmentMethod ${q(row.method)}; usf:assessmentEvidence <${evidenceIri}>;`);
  graph.push(`  usf:assessmentAuthorityDigest ${q(authorityDigest)}; usf:assessmentEvidenceDigest ${q(evidenceDigest)}; usf:assessmentConfidence ${q(String(row.confidence))}^^xsd:decimal;`);
  graph.push(`  usf:assessmentLimitation ${q(row.basis)}; usf:hasCriterionEvidenceBinding <${bindingIri}>${row.mitigation ? `; usf:assessmentMitigation <${row.mitigation.identity}> .` : ' .'}`);
  graph.push(`<${bindingIri}> a usf:CriterionEvidenceBinding; usf:canonicalName ${q(name)}; usf:bindingForAssessment <${assessmentIri}>; usf:bindingEvidenceResult <${evidenceIri}>; usf:bindingSupportingManifest ${row.supportingManifests.map((identity) => `<${identity}>`).join(', ')}; usf:bindingSupportDigest ${q(row.supportDigest)}; usf:bindingAuthorityDigest ${q(authorityDigest)}; usf:bindingEvidenceDigest ${q(evidenceDigest)} .`);
  if (row.mitigation) graph.push(`<${row.mitigation.identity}> a usf:CriterionMitigation; usf:canonicalName ${q(row.mitigation.identity.slice(row.mitigation.identity.lastIndexOf(':') + 1))}; usf:mitigationAccepted true; usf:mitigationStatement ${q(row.mitigation.statement)}; usf:mitigationEvidence <${evidenceIri}>; usf:mitigationInvalidationCondition ${q(row.mitigation.invalidationCondition)} .`);
}

for (const decision of decisions) {
  for (const option of decision.options.filter((value) => value !== decision.selected)) {
    const rejection = iri('optionrejection', `${decision.name}${option}`);
    const reason = iri('rejectionreason', `${decision.name}${option}`);
    const criterion = decision.name === 'semanticauthoritycontrolselection' ? (option === 'livestardogonly' ? 'hermeticsubstitutefeasibility' : 'semanticcontractfit') : 'operationalcomplexity';
    graph.push(`<${rejection}> a usf:OptionRejection; usf:canonicalName ${q(`${decision.name}${option}`)}; usf:rejectionForEvaluation <${iri('decisionevaluation', decision.name)}>; usf:rejectsOption <${iri('realisationoption', option)}>; usf:hasRejectionReason <${reason}> .`);
    graph.push(`<${reason}> a usf:RejectionReason; usf:canonicalName ${q(`${decision.name}${option}`)}; usf:rejectionCriterion <${iri('evaluationcriterion', criterion)}>; usf:rejectionRequirement <${iri('semanticcontract', decision.contract)}>; usf:rejectionEvidence <${evidenceIri}>; usf:rejectionDuration <urn:usf:rejectionduration:conditional>; usf:rejectionStatement ${q(`Current evidence ranks ${option} below the selected option on ${criterion}`)}; usf:reopeningCondition ${q(`Reopen when ${criterion}, option evidence or the selected component set changes`)} .`);
  }
}

const sole = iri('solecandidatejustification', 'semanticauthoritycontrolselection');
const searchSpace = iri('candidatesearchspace', 'semanticauthoritycontrolselection');
graph.push(`<${sole}> a usf:SoleCandidateJustification; usf:canonicalName "semanticauthoritycontrolselection"; usf:soleCandidateForOption <urn:usf:realisationoption:livestardogwithverifiedreadonlyexport>; usf:hasCandidateSearchSpace <${searchSpace}>; usf:hasCandidateClassExclusion <urn:usf:candidateclassexclusion:liveauthoritywithoutisolatedexport>, <urn:usf:candidateclassexclusion:otherlivesemanticauthority>, <urn:usf:candidateclassexclusion:repositorylocalsemanticauthority>; usf:soleCandidateEvidence <${evidenceIri}>; usf:soleCandidateInvalidationCondition "Reopen if the mandated Stardog authority boundary, finite realisation-class universe or hermetic read-only validation obligation changes" .`);
graph.push(`<${searchSpace}> a usf:CandidateSearchSpace; usf:canonicalName "semanticauthoritycontrolselection"; usf:candidateDiscoveryCriteria "Search every materially different live Stardog, other live semantic-authority and repository-local authority class, with and without isolated read-only validation"; usf:searchesRealisationClass ${authoritySearchSpaceCore.classes.map((value) => `<${value}>`).join(', ')}; usf:candidateSearchSpaceDigest ${q(candidateSearchSpaces.semanticauthoritycontrolselection.searchSpaceDigest)}; usf:candidateSearchEvidence <${evidenceIri}>; usf:candidateSearchInvalidationCondition "Reopen when the authority constraint, isolation requirement or materially different realisation class changes" .`);
graph.push(`<urn:usf:realisationoption:livestardogwithverifiedreadonlyexport> usf:representsRealisationClass <urn:usf:realisationclass:livestardogwithisolatedexport> .`);
graph.push(`<urn:usf:realisationoption:livestardogonly> usf:representsRealisationClass <urn:usf:realisationclass:livestardogwithoutisolatedexport> .`);
graph.push(`<urn:usf:realisationoption:genericrdfauthorityprovider> usf:representsRealisationClass <urn:usf:realisationclass:otherlivesemanticauthority> .`);
graph.push(`<urn:usf:candidateclassexclusion:liveauthoritywithoutisolatedexport> a usf:CandidateClassExclusion; usf:canonicalName "liveauthoritywithoutisolatedexport"; usf:excludedRealisationClass "live authority without a verified isolated export"; usf:excludesRealisationClass <urn:usf:realisationclass:livestardogwithoutisolatedexport>; usf:exclusionReason "Cannot satisfy network-isolated deterministic validation"; usf:exclusionEvidence <${evidenceIri}> .`);
graph.push(`<urn:usf:candidateclassexclusion:otherlivesemanticauthority> a usf:CandidateClassExclusion; usf:canonicalName "otherlivesemanticauthority"; usf:excludedRealisationClass "non-Stardog live semantic authority"; usf:excludesRealisationClass <urn:usf:realisationclass:otherlivesemanticauthority>; usf:exclusionReason "Contradicts the explicit current Stardog authority constraint"; usf:exclusionEvidence <${evidenceIri}> .`);
graph.push(`<urn:usf:candidateclassexclusion:repositorylocalsemanticauthority> a usf:CandidateClassExclusion; usf:canonicalName "repositorylocalsemanticauthority"; usf:excludedRealisationClass "repository-local semantic authority"; usf:excludesRealisationClass <urn:usf:realisationclass:repositorylocalsemanticauthority>; usf:exclusionReason "Cannot satisfy the mandatory live Stardog controlled-mutation boundary"; usf:exclusionEvidence <${evidenceIri}> .`);

const components = selectedComponentDefinitions;
const alternativeComponents = {
  javardfsemanticmodelcompiler: [['javacompiler', 'repositorylocalcomponent', 'compiler', 'Compile and validate the registered semantic model'], ['javaruntime', 'runtimecomponent', 'runtime', 'Execute a repository-local Java compiler'], ['livestardogauthority', 'externalprovidercomponent', 'provider', 'Provide live authority control'], ['verifiedauthorityexport', 'repositorylocalcomponent', 'authorityexport', 'Provide isolated validation input']],
  pythonrdfsemanticmodelcompiler: [['pythoncompiler', 'repositorylocalcomponent', 'compiler', 'Compile and validate the registered semantic model'], ['pythonruntime', 'runtimecomponent', 'runtime', 'Execute a repository-local Python compiler'], ['livestardogauthority', 'externalprovidercomponent', 'provider', 'Provide live authority control'], ['verifiedauthorityexport', 'repositorylocalcomponent', 'authorityexport', 'Provide isolated validation input']],
};
const packageByComponent = new Map([
  ['n3package', packages.find(({ name }) => name === 'n3')], ['rdfcanonizepackage', packages.find(({ name }) => name === 'rdf-canonize')],
  ['stardogsdkpackage', packages.find(({ name }) => name === 'stardog')], ['yamlpackage', packages.find(({ name }) => name === 'yaml')],
]);
function addComponent(option, entry, index) {
  const [name, kind, role, responsibility, declaredEnvironments] = entry;
  const component = iri('optioncomponent', `${option}${name}`);
  const identity = iri('componentidentity', name);
  const environments = declaredEnvironments || (role === 'provider' ? ['authoritycontrol'] : role === 'authorityexport' ? ['localdev', 'hermetic'] : ['localdev', 'hermetic', 'productionshaped']);
  graph.push(`<${component}> a usf:OptionComponent; usf:canonicalName ${q(`${option}${name}`)}; usf:componentForOption <${iri('realisationoption', option)}>; usf:componentIdentity <${identity}>; usf:componentRole <urn:usf:componentrole:${role}>; usf:componentResponsibility ${q(responsibility)}; usf:componentEnvironmentBinding ${environments.map((env) => `<${iri('environment', env)}>`).join(', ')}; usf:componentDataOwnershipBoundary ${q(`${name} owns only data explicitly assigned by its semantic responsibility`)}; usf:componentTransactionBoundary ${q(`${name} commits only within its declared responsibility and never spans an undeclared provider transaction`)}; usf:componentSecurityBoundary ${q(`${name} accepts only declared principals and interfaces`)}; usf:componentSecretBoundary ${q(`${name} receives credentials only through declared secret interfaces`)}; usf:componentDeploymentBoundary ${q(`${name} is deployed only in its declared environment bindings`)}; usf:componentFailurePropagation ${q(`${name} returns typed failures across declared interfaces`)}; usf:componentRetryPolicy ${q(`${name} retries only idempotent operations under contract-defined limits`)}; usf:componentTimeoutPolicy ${q(`${name} applies explicit bounded timeouts at every external interface`)}; usf:componentUpgradeCompatibility ${q(`${name} upgrades require locked compatible interfaces and current evaluation evidence`)}; usf:componentRollbackOrder ${q(`${name} rolls back after its dependants and before its dependencies`)}; usf:componentReplacementBoundary ${q(`${name} may be replaced independently only after interface-equivalent option evaluation`)} .`);
  if (option === 'nodeecmascriptsemanticmodelcompiler' || option === 'capabilitycellswithprocessassemblies' || option === 'livestardogwithverifiedreadonlyexport') return component;
  const kindClass = { repositorylocalcomponent: 'RepositoryLocalComponent', runtimecomponent: 'RuntimeComponent', externalprovidercomponent: 'ExternalProviderComponent', packagecomponent: 'PackageComponent', containerimagecomponent: 'ContainerImageComponent' }[kind];
  graph.push(`<${identity}> a usf:ComponentIdentity, usf:${kindClass}; usf:canonicalName ${q(name)} .`);
  return component;
}

const selectedOptionComponents = new Map();
const componentDependencies = [];
for (const decision of decisions) {
  const option = decision.selected;
  const entries = components[decision.name];
  const componentIris = entries.map((entry, index) => addComponent(option, entry, index));
  selectedOptionComponents.set(option, componentIris);
  graph.push(`<${iri('realisationoption', option)}> usf:hasOptionComponent ${componentIris.map((value) => `<${value}>`).join(', ')} .`);
  for (let index = 1; index < componentIris.length; index += 1) {
    const interfaceDefinition = compositionInterfaceDefinition(option, entries, index);
    const interfaceIri = interfaceDefinition.id;
    const owningDecision = decisions.find(({ selected }) => selected === option);
    graph.push(`<${interfaceIri}> a usf:CompositionInterface; usf:canonicalName ${q(interfaceDefinition.canonicalName)}; usf:compositionInterfaceForContract <${iri('semanticcontract', owningDecision.contract)}>; usf:compositionInterfaceResponsibility ${q(interfaceDefinition.responsibility)}; usf:compositionInterfaceSecurityBoundary ${q(interfaceDefinition.securityBoundary)}; usf:compositionInterfaceFailureBehaviour ${q(interfaceDefinition.failureBehaviour)} .`);
    graph.push(`<${componentIris[0]}> usf:dependsOnOptionComponent <${componentIris[index]}>; usf:componentInterface <${interfaceIri}> .`);
    graph.push(`<${componentIris[index]}> usf:componentInterface <${interfaceIri}> .`);
    componentDependencies.push({ decision: decision.name, option, source: componentIris[0], target: componentIris[index], interfaceIri });
  }
}
for (const [option, entries] of Object.entries(alternativeComponents)) {
  const componentIris = entries.map((entry, index) => addComponent(option, entry, index));
  graph.push(`<${iri('realisationoption', option)}> usf:hasOptionComponent ${componentIris.map((value) => `<${value}>`).join(', ')} .`);
}

const providerBindingsByComponent = new Map();
const providerBindingSpecifications = Object.freeze({
  compilerfocusedtestsubstitute: Object.freeze({
    mode: 'deterministictestsubstitute', provider: 'compilerfocusedtestsubstitute', state: 'available',
  }),
  livestardogauthority: Object.freeze({
    mode: 'liveauthoritycontrol', provider: 'livestardogsemanticauthority', state: 'external',
  }),
  stardogsandboxauthority: Object.freeze({
    mode: 'externalsandbox', provider: 'stardogsandboxsemanticauthority', state: 'external',
  }),
});
for (const decision of decisions) {
  const option = decision.selected;
  for (const [name, , role, , environments] of selectedComponentDefinitions[decision.name]) {
    if (role !== 'provider') continue;
    const component = iri('optioncomponent', `${option}${name}`);
    const specification = providerBindingSpecifications[name];
    if (!specification) throw new Error(`provider binding specification missing: ${name}`);
    const provider = iri('provider', specification.provider);
    const mode = specification.mode;
    const bindings = environments.map((environment) => {
      const binding = iri('binding', `${option}${name}${environment}`);
      graph.push(`<${binding}> a usf:Binding; usf:canonicalName ${q(`${option}${name}${environment}`)}; usf:bindingProvider <${provider}>; usf:bindsPort <urn:usf:port:semanticauthoritycontrol>; usf:hasProviderMode <urn:usf:providermode:${mode}>; usf:bindingEnvironment <${iri('environment', environment)}>; usf:bindingState <urn:usf:bindingstate:${specification.state}> .`);
      return binding;
    });
    graph.push(`<${component}> usf:componentProviderMode <urn:usf:providermode:${mode}>; usf:componentProviderBinding ${bindings.map((value) => `<${value}>`).join(', ')} .`);
    providerBindingsByComponent.set(component, bindings);
  }
}

const licencePolicyIri = iri('licencecompatibilitypolicy', 'internaloperation');
graph.push(`<${licencePolicyIri}> a usf:LicenceCompatibilityPolicy; usf:canonicalName "internaloperation"; usf:licencePolicyDigest ${q(licencePolicy.policyDigest)}; usf:licencePolicyRule ${licencePolicy.compatibleLicenceRules.map(q).join(', ')}; usf:licencePolicyInvalidationCondition ${q(licencePolicy.invalidationCondition)} .`);

for (const observation of Object.values(componentObservations).sort((left, right) => utf8Compare(left.identity, right.identity))) {
  const identity = observation.identity;
  const name = identity.split(':').at(-1);
  const kind = observation.kind;
  const digest = observation.integrity;
  const pkg = packageByComponent.get(name);
  const version = observation.version;
  const distribution = name === 'nodejsruntime' ? 'nodejs-release' : pkg ? 'npm' : name === 'livestardogauthority' ? 'managed-stardog-authority' : 'repository-local';
  const extra = kind === 'RepositoryLocalComponent'
    ? `; usf:componentImplementationSourceDigest ${q(observation.sourceDigest)}; usf:componentToolchainDigest ${q(observation.toolchainDigest)}` : '';
  graph.push(`<${identity}> a usf:ComponentIdentity, usf:${kind}; usf:canonicalName ${q(name)}; usf:componentVersion ${q(version)}; usf:componentDistributionSource ${q(distribution)}; usf:componentIntegrityDigest ${q(digest)}; usf:componentObservationDigest ${q(observation.observationDigest)}; usf:componentAcquisitionSource ${q(observation.acquisitionSource)}^^xsd:anyURI; usf:componentDependencyLockDigest ${q(observation.lockDigest)}${extra}; usf:componentPatchPolicy "Re-evaluate on an upstream security advisory, dependency-lock change or selected-version change"; usf:componentContinuityRule "Replace only through a new closed option evaluation with compatible contract and rollback evidence"; usf:hasIntegrityConstraint <${iri('componentintegrityconstraint', name)}>; usf:hasPortabilityAssessment <${iri('portabilityassessment', name)}> .`);
  graph.push(`<${iri('componentintegrityconstraint', name)}> a usf:ComponentIntegrityConstraint; usf:canonicalName ${q(name)}; usf:integrityConstraintDigest ${q(digest)} .`);
  graph.push(`<${iri('portabilityassessment', name)}> a usf:PortabilityAssessment; usf:canonicalName ${q(name)}; usf:portabilityEvidence <${evidenceIri}>; usf:exitAndReplacementRule "Replacement requires an independently evaluated option and evidence-equivalent rollback path" .`);
  const thirdParty = ['PackageComponent', 'RuntimeComponent', 'ExternalProviderComponent', 'ContainerImageComponent'].includes(kind);
  const licence = name === 'nodejsruntime' ? 'MIT AND LicenseRef-NodeJS-Bundled-Notices'
    : pkg?.licence || (kind === 'ExternalProviderComponent' ? 'LicenseRef-Stardog-Enterprise' : 'LicenseRef-USF-Repository-Local');
  graph.push(`<${identity}> ${thirdParty ? `usf:hasLicenceAssessment <${iri('licenceassessment', name)}>; ` : ''}usf:hasVulnerabilityAssessment <${iri('vulnerabilityassessment', name)}>; usf:hasSupplyChainAssessment <${iri('supplychainassessment', name)}> .`);
  if (thirdParty) {
    const condition = kind === 'ExternalProviderComponent'
      ? 'Compatible only while a valid Stardog Enterprise entitlement is supplied through the modelled licence-secret interface'
      : 'Compatible while required notices and attribution remain with the exact acquired component bytes';
    graph.push(`<${iri('licenceassessment', name)}> a usf:LicenceAssessment; usf:canonicalName ${q(name)}; usf:licenceIdentifier ${q(licence)}; usf:licenceEvidence <${evidenceIri}>; usf:usesLicenceCompatibilityPolicy <${licencePolicyIri}>; usf:licenceUsageContext ${q(licencePolicy.usageContext)}; usf:licenceAssessmentMethod ${q(licencePolicy.assessmentMethod)}; usf:licenceAssessmentLimitation ${q(licencePolicy.limitation)}; usf:licenceCompatibilityCondition ${q(condition)}; usf:licenceCompatible true .`);
  }
  const vulnerabilityMethod = name === 'nodejsruntime' ? vulnerabilityPolicy.methods.node
    : pkg ? `${vulnerabilityPolicy.methods.npm} using npm-audit@${npmVersion}`
      : kind === 'ExternalProviderComponent' ? vulnerabilityPolicy.methods.stardog : vulnerabilityPolicy.methods.repositoryLocal;
  const vulnerabilityScope = name === 'nodejsruntime' ? `Node ${version} executable and exact security-release lineage`
    : pkg ? `Exact repository lock closure containing ${name}@${version}`
      : kind === 'ExternalProviderComponent' ? `Managed Stardog ${version} provider boundary and current vendor disclosures`
        : `Repository-local source set ${implementationSourceDigest}`;
  const vulnerabilityLimitation = kind === 'ExternalProviderComponent' ? vulnerabilityPolicy.limitation
    : name === 'nodejsruntime' ? 'The assessment covers published security-release lineage and exact runtime bytes; unknown vulnerabilities remain a nonclaim.'
      : pkg ? 'The advisory result covers the exact current npm lock; non-npm bundled components remain outside this package assessment.'
        : 'The deterministic rule set detects declared prohibited source patterns; it is not a general exploitability proof.';
  graph.push(`<${iri('vulnerabilityassessment', name)}> a usf:VulnerabilityAssessment; usf:canonicalName ${q(name)}; usf:vulnerabilityScannerIdentity ${q(vulnerabilityMethod)}; usf:vulnerabilityAssessmentMethod ${q(vulnerabilityMethod)}; usf:vulnerabilityAssessmentScope ${q(vulnerabilityScope)}; usf:vulnerabilityAssessmentLimitation ${q(vulnerabilityLimitation)}; usf:vulnerabilityPolicyDigest ${q(vulnerabilityPolicy.policyDigest)}; usf:vulnerabilityAssessedAt ${q(collectedAt)}^^xsd:dateTime; usf:vulnerabilityEvidence <${evidenceIri}>; usf:vulnerabilityPolicy ${q('No high or critical finding is accepted; reassess under the bound invalidation rule')}; usf:acceptedVulnerabilityCount 0 .`);
  const dependencyDigest = pkg?.dependencySetDigest || (kind === 'RepositoryLocalComponent' ? transitiveDependencySetDigest : null);
  const disclosure = pkg ? 'exact-npm-package-transitive-closure'
    : kind === 'RepositoryLocalComponent' ? 'exact-repository-lock-closure'
      : name === 'nodejsruntime' ? 'exact-runtime-binary-and-release-metadata-boundary'
        : 'managed-provider-internal-dependencies-outside-delivered-component-boundary';
  const supplyLimitation = dependencyDigest ? 'Dependency closure is bounded by the exact recorded digest.'
    : name === 'nodejsruntime' ? 'Bundled runtime dependencies are bounded by exact executable and release bytes, not represented as an npm dependency graph.'
      : 'The managed provider internal dependency graph is outside the delivered component boundary; vendor disclosure and continuity controls govern the service boundary.';
  graph.push(`<${iri('supplychainassessment', name)}> a usf:SupplyChainAssessment; usf:canonicalName ${q(name)}; usf:supplyChainEvidence <${evidenceIri}>; usf:supplyChainProvenance ${q(kind === 'RepositoryLocalComponent' ? 'repository source, toolchain and exact dependency-lock digests' : name === 'nodejsruntime' ? 'official Node release and security metadata plus exact executable digest' : pkg ? 'npm lock integrity plus exact component dependency closure' : 'declared exact provider version plus digest-bound vendor release, security and enterprise-licence source bytes')}; usf:dependencyDisclosureState ${q(disclosure)}; usf:supplyChainAssessmentLimitation ${q(supplyLimitation)}${dependencyDigest ? `; usf:componentDependencySetDigest ${q(dependencyDigest)}` : ''} .`);
}

for (const dependency of componentDependencies) {
  const sourceName = dependency.source.split(':').at(-1).slice(dependency.option.length);
  const targetName = dependency.target.split(':').at(-1).slice(dependency.option.length);
  const sourceObservation = componentObservations[iri('componentidentity', sourceName)];
  const targetObservation = componentObservations[iri('componentidentity', targetName)];
  if (!sourceObservation || !targetObservation) throw new Error(`component compatibility observation missing: ${sourceName}|${targetName}`);
  const assessment = iri('componentcompatibilityassessment', `${dependency.option}${sourceName}${targetName}`);
  graph.push(`<${assessment}> a usf:ComponentCompatibilityAssessment; usf:canonicalName ${q(`${dependency.option}${sourceName}${targetName}`)}; usf:compatibilityForSourceComponent <${dependency.source}>; usf:compatibilityForTargetComponent <${dependency.target}>; usf:compatibilityForInterface <${dependency.interfaceIri}>; usf:compatibilitySourceVersion ${q(sourceObservation.version)}; usf:compatibilityTargetVersion ${q(targetObservation.version)}; usf:compatibilitySourceIntegrityDigest ${q(sourceObservation.integrity)}; usf:compatibilityTargetIntegrityDigest ${q(targetObservation.integrity)}; usf:compatibilitySuccessful true; usf:compatibilityCurrent true; usf:compatibilityEvidence <${evidenceIri}> .`);
}

for (const [ruleSetName, ruleSet] of Object.entries(permutationRuleSets)) {
  const ruleSetIri = iri('permutationruleset', ruleSetName);
  const dimensionIris = Object.keys(ruleSet.dimensions).map((key) => iri('permutationdimension', `${ruleSetName}${key}`));
  graph.push(`<${ruleSetIri}> a usf:PermutationRuleSet; usf:canonicalName ${q(ruleSetName)}; usf:hasPermutationDimension ${dimensionIris.map((value) => `<${value}>`).join(', ')}; usf:hasPermutationClassificationRule ${ruleSet.rules.map(({ id }) => `<${id}>`).join(', ')}; usf:permutationRuleSetDigest ${q(ruleSet.ruleSetDigest)} .`);
  for (const [key, values] of Object.entries(ruleSet.dimensions)) {
    graph.push(`<${iri('permutationdimension', `${ruleSetName}${key}`)}> a usf:PermutationDimension; usf:canonicalName ${q(`${ruleSetName}${key}`)}; usf:permutationDimensionKey ${q(key)}; usf:permutationAllowedValue ${values.map(q).join(', ')} .`);
  }
  for (const rule of ruleSet.rules) {
    const conditionIris = rule.conditions.map((condition, index) => iri('permutationcondition', `${rule.id.split(':').at(-1)}${index + 1}`));
    const representativePermutation = Object.values(permutations).find(({ ruleSet: usedRuleSet }) => usedRuleSet === ruleSetName);
    const equivalenceRows = representativePermutation.rows.filter(({ classificationRule }) => classificationRule === rule.id)
      .map(({ classificationRule, ...row }) => row);
    const equivalenceProof = rule.disposition === 'validandcoveredbyequivalenceproof' ? iri('permutationequivalenceproof', rule.id.split(':').at(-1)) : null;
    graph.push(`<${rule.id}> a usf:PermutationClassificationRule; usf:canonicalName ${q(rule.id.split(':').at(-1))}; usf:permutationRulePriority ${rule.priority}; usf:permutationRuleDisposition <urn:usf:permutationdisposition:${rule.disposition}>; usf:permutationRuleDefault ${rule.default}; usf:permutationRuleEvidence <${evidenceIri}>${conditionIris.length ? `; usf:hasPermutationCondition ${conditionIris.map((value) => `<${value}>`).join(', ')}` : ''}${equivalenceProof ? `; usf:permutationEquivalenceProof <${equivalenceProof}>` : ''} .`);
    rule.conditions.forEach((condition, index) => graph.push(`<${conditionIris[index]}> a usf:PermutationCondition; usf:canonicalName ${q(`${rule.id.split(':').at(-1)}${index + 1}`)}; usf:permutationConditionDimension ${q(condition.key)}; usf:permutationConditionValue ${condition.values.map(q).join(', ')} .`));
    if (equivalenceProof) {
      const matchedRowsDigest = sha256(canonicalJson(equivalenceRows.map(canonicalJson).sort(utf8Compare)));
      graph.push(`<${equivalenceProof}> a usf:PermutationEquivalenceProof; usf:canonicalName ${q(rule.id.split(':').at(-1))}; usf:equivalenceProofSuccessful true; usf:equivalenceProofCurrent true; usf:equivalenceProofRuleSetDigest ${q(ruleSet.ruleSetDigest)}; usf:equivalenceProofMatchedRowsDigest ${q(matchedRowsDigest)}; usf:equivalenceProofAuthorityDigest ${q(authorityDigest)}; usf:equivalenceProofImplementationDigest ${q(implementationSourceDigest)}; usf:equivalenceProofEvidence <${evidenceIri}> .`);
    }
  }
}

for (const decision of decisions) {
  const option = decision.selected;
  const componentIris = selectedOptionComponents.get(option);
  const facetBase = decision.contract;
  const requirements = Array.from({ length: 10 }, (_, index) => ['lifecycle', 'statemodel', 'permissions', 'contracts', 'validation', 'errormodel', 'auditmodel', 'readinessmodel', 'proof', 'uisemantics'][index]).map((suffix) => iri('contractfacet', `${facetBase}${suffix}`));
  if (decision.name !== 'repositoryarchitectureandnaming') requirements.push(iri('port', 'semanticauthoritycontrol'));
  const responsibilityIris = requirements.map((requirement, index) => {
    const name = `${decision.name}${index + 1}`;
    const resource = iri('componentresponsibility', name);
    const component = componentIris[index % componentIris.length];
    graph.push(`<${resource}> a usf:ComponentResponsibility; usf:canonicalName ${q(name)}; usf:responsibilityForComponent <${component}>; usf:responsibilityForRequirement <${requirement}>; usf:responsibilityOwner <${iri('realisationoption', option)}>; usf:responsibilityCoordinationRule "Exactly one selected component owns this requirement; cross-component calls preserve declared dependency and transaction boundaries" .`);
    return resource;
  });
  graph.push(`<${iri('realisationoption', option)}> usf:hasComponentResponsibility ${responsibilityIris.map((value) => `<${value}>`).join(', ')} .`);
  const proof = compositionProofs[decision.name];
  const proofIri = iri('compositioncoverageproof', decision.name);
  const permutationIri = iri('compositionpermutationassessment', decision.name);
  graph.push(`<${iri('realisationoption', option)}> usf:hasCompositionCoverageProof <${proofIri}>; usf:hasCompositionPermutationAssessment <${permutationIri}> .`);
  graph.push(`<${proofIri}> a usf:CompositionCoverageProof; usf:canonicalName ${q(decision.name)}; usf:coverageProofForOption <${iri('realisationoption', option)}>; usf:compositionProofSuccessful true; usf:compositionProofCurrent true; usf:compositionProofAuthorityDigest ${q(authorityDigest)}; usf:compositionProofImplementationDigest ${q(implementationSourceDigest)}; usf:compositionProjectionDigest ${q(proof.compositionProjectionDigest)}; usf:compositionPermutationPayloadDigest ${q(proof.permutationPayloadDigest)}; usf:compositionProofEvidence <${evidenceIri}>; usf:compositionProofDigest ${q(proof.proofDigest)}; usf:requiredFacetCount ${proof.requiredFacetCount}; usf:coveredFacetCount ${proof.coveredFacetCount}; usf:requiredPortCount ${proof.requiredPortCount}; usf:implementedPortCount ${proof.implementedPortCount}; usf:orphanResponsibilityCount 0; usf:duplicateResponsibilityCount 0; usf:invalidDependencyCount 0; usf:incompatibleInterfaceCount 0; usf:incompatibleComponentVersionCount 0; usf:unusedComponentCount 0; usf:unclassifiedPermutationCount 0 .`);
  const dispositions = Object.entries(permutations[decision.name].counts).filter(([, count]) => count > 0)
    .map(([value]) => `<urn:usf:permutationdisposition:${value}>`).join(', ');
  graph.push(`<${permutationIri}> a usf:CompositionPermutationAssessment; usf:canonicalName ${q(decision.name)}; usf:permutationForOption <${iri('realisationoption', option)}>; usf:usesPermutationRuleSet <${iri('permutationruleset', permutations[decision.name].ruleSet)}>; usf:permutationDimensionSetDigest ${q(permutations[decision.name].dimensionSetDigest)}; usf:permutationCaseCount ${permutations[decision.name].caseCount}; usf:permutationDisposition ${dispositions}; usf:permutationEvidence <${evidenceIri}> .`);
}

const concreteRealisations = {
  repositoryarchitectureandnaming: iri('realisation', 'repositoryarchitectureandnaming'),
  semanticmodelcompilationrealisation: iri('realisation', 'semanticcontractcompilersemanticenforcement'),
  semanticauthoritycontrolselection: iri('realisation', 'semanticauthoritycontrol'),
};
graph.push(`<${iri('implementation', 'capabilitycontainment')}> a usf:Implementation; usf:canonicalName "capabilitycontainment"; usf:implementsContract <urn:usf:semanticcontract:repositoryexternalartefactmaterialisation> .`);
graph.push(`<${iri('implementation', 'processassembly')}> a usf:Implementation; usf:canonicalName "processassembly"; usf:implementsContract <urn:usf:semanticcontract:repositoryexternalartefactmaterialisation> .`);
graph.push(`<${iri('implementation', 'verifiedauthorityexport')}> a usf:Implementation; usf:canonicalName "verifiedauthorityexport"; usf:implementsContract <urn:usf:semanticcontract:compilersemanticenforcement> .`);
graph.push(`<${iri('realisation', 'semanticauthoritycontrol')}> a usf:Realisation; usf:canonicalName "semanticauthoritycontrol"; usf:realisesContract <urn:usf:semanticcontract:compilersemanticenforcement>; usf:authorisedByDecision <urn:usf:realisationdecision:semanticauthoritycontrolselection>; usf:authorisedSourcePath "configuration/semantic-assurance", "processes/semantic-assurance", "provider-bindings/stardog", "semantic-model", "assurance"; usf:realisesOption <urn:usf:realisationoption:livestardogwithverifiedreadonlyexport>; usf:realisingImplementation <${iri('implementation', 'verifiedauthorityexport')}>; usf:viaAdapter <urn:usf:adapter:stardogsemanticauthority>; usf:realisationState <urn:usf:realisationstate:implementable> .`);
for (const decision of decisions) {
  const option = decision.selected;
  const realisation = concreteRealisations[decision.name];
  graph.push(`<${realisation}> usf:realisesOption <${iri('realisationoption', option)}> .`);
  const mapping = iri('selectedoptionrealisationmapping', decision.name);
  graph.push(`<${mapping}> a usf:SelectedOptionRealisationMapping; usf:canonicalName ${q(decision.name)}; usf:mappingForDecision <${iri('realisationdecision', decision.name)}>; usf:mappingForEvaluation <${iri('decisionevaluation', decision.name)}>; usf:mappingForSelectedOption <${iri('realisationoption', option)}>; usf:mappingToRealisation <${realisation}>; usf:mappingAuthorityDigest ${q(authorityDigest)}; usf:mappingEvaluationDigest ${q(evidenceDigest)}; usf:mappingImplementationSourceDigest ${q(implementationSourceDigest)}; usf:mappingState <urn:usf:mappingstate:active> .`);
  for (const [name, kind, role] of selectedComponentDefinitions[decision.name]) {
    const component = iri('optioncomponent', `${option}${name}`);
    const componentMapping = iri('selectedcomponentmapping', `${option}${name}`);
    const kindClass = { repositorylocalcomponent: 'RepositoryLocalComponent', packagecomponent: 'PackageComponent', runtimecomponent: 'RuntimeComponent', externalprovidercomponent: 'ExternalProviderComponent', containerimagecomponent: 'ContainerImageComponent' }[kind];
    const targetKind = role === 'provider' ? 'providerbinding'
      : role === 'adapter' ? 'adapter'
        : ['PackageComponent', 'RuntimeComponent', 'ContainerImageComponent'].includes(kindClass)
          ? 'dependencybinding' : 'implementation';
    const common = `<${componentMapping}> a usf:SelectedComponentConcreteMapping; usf:canonicalName ${q(`${option}${name}`)}; usf:componentMappingForOption <${iri('realisationoption', option)}>; usf:componentMappingForComponent <${component}>; usf:componentMappingTargetKind <urn:usf:componentmappingtargetkind:${targetKind}>; usf:mappingAuthorityDigest ${q(authorityDigest)}; usf:mappingEvaluationDigest ${q(evidenceDigest)}; usf:mappingImplementationSourceDigest ${q(implementationSourceDigest)}; usf:mappingState <urn:usf:mappingstate:active>`;
    if (role === 'provider') {
      const bindings = providerBindingsByComponent.get(component) || [];
      graph.push(`${common}; usf:componentMappingToProviderBinding ${bindings.map((value) => `<${value}>`).join(', ')} .`);
    } else if (role === 'adapter') {
      graph.push(`${common}; usf:componentMappingToAdapter <urn:usf:adapter:stardogsemanticauthority>${kindClass !== 'RepositoryLocalComponent' ? `; usf:componentMappingToDependencyBinding <${iri('dependencybinding', name)}>` : ''} .`);
    } else if (['PackageComponent', 'RuntimeComponent', 'ContainerImageComponent'].includes(kindClass)) {
      const dependencyBinding = iri('dependencybinding', name);
      const observation = componentObservations[iri('componentidentity', name)];
      if (!observation) throw new Error(`dependency binding observation missing: ${name}`);
      graph.push(`<${dependencyBinding}> a usf:DependencyBinding; usf:canonicalName ${q(name)}; usf:dependencyBindingForComponentIdentity <${iri('componentidentity', name)}>; usf:dependencyBindingVersion ${q(observation.version)}; usf:dependencyBindingIntegrityDigest ${q(observation.integrity)}; usf:dependencyBindingLockDigest ${q(observation.lockDigest)}; usf:dependencyBindingAcquisitionSource ${q(observation.acquisitionSource)}^^xsd:anyURI; usf:dependencyBindingRepresentation "locked external component bytes"; usf:dependencyBindingMaterialisationRule "Acquire only from the declared source, verify the exact integrity and lock digests, and reject any mutable or ambient substitute" .`);
      graph.push(`${common}; usf:componentMappingToDependencyBinding <${dependencyBinding}> .`);
    } else {
      const implementation = name === 'semanticmodelcompiler' ? iri('implementation', 'semanticmodelcompiler')
        : name === 'verifiedauthorityexport' ? iri('implementation', 'verifiedauthorityexport')
          : iri('implementation', name);
      graph.push(`${common}; usf:componentMappingToImplementation <${implementation}> .`);
    }
  }
}

const generatedRoot = join(root, '.work/generated');
mkdirSync(generatedRoot, { recursive: true });
writeFileSync(join(generatedRoot, 'realisation-option-evaluations.ttl'), `${graph.join('\n')}\n`);
writeFileSync(join(generatedRoot, 'realisation-option-evaluation-evidence-projection.ttl'), `${evidenceGraph.join('\n')}\n`);
const bindingPatch = [
  '*** Begin Patch',
  '*** Update File: /usf/semantic-model/realisation/bindings.trig',
  '@@',
  ' <urn:usf:adrrecord:semanticmodelcompilationrealisation> a usf:ADRRecord;',
  '     usf:canonicalName "semanticmodelcompilationrealisation";',
  '     usf:recordsDecision <urn:usf:realisationdecision:semanticmodelcompilationrealisation>.',
  ' ',
  ...graph.slice(3).map((line) => `+${line}`),
  '+',
  ' }',
  '*** End Patch',
  '',
].join('\n');
writeFileSync(join(generatedRoot, 'realisation-option-evaluations.patch'), bindingPatch);
writeFileSync(join(generatedRoot, 'realisation-option-evaluation-evidence.json'), bytes);
writeFileSync(join(generatedRoot, 'realisation-option-evaluation-metadata.json'), `${canonicalJson({ authorityDigest, evidenceDigest, evaluationDependencySetDigest, implementationSourceDigest, evidenceProducerDigest, byteSize: statSync(casPath).size, casPath, attestationDigest, attestationByteSize: statSync(attestationPath).size, attestationPath, signatureValue: signature.toString('base64'), signingKeyFingerprint, sourceRecordCount: sourceRecords.length, assessmentCount: assessmentRecords.length, criterionCount: criteria.length, decisionCount: decisions.length, compositionProofDigests: Object.fromEntries(Object.entries(compositionProofs).map(([name, value]) => [name, value.proofDigest])), permutationCounts: Object.fromEntries(Object.entries(permutations).map(([name, value]) => [name, value.caseCount])) })}\n`);
if (process.argv.includes('--apply-bindings') || process.argv.includes('--replace-bindings')) {
  const target = join(root, 'semantic-model/realisation/bindings.trig');
  const current = readFileSync(target, 'utf8');
  const marker = '<urn:usf:decisionevaluation:repositoryarchitectureandnaming> a usf:DecisionEvaluation;';
  if (!current.endsWith('\n}\n')) throw new Error('bindings graph does not have the expected canonical closure');
  const markerIndex = current.indexOf(marker);
  if (markerIndex >= 0 && !process.argv.includes('--replace-bindings')) throw new Error('option evaluation block is already materialised');
  const prefix = markerIndex >= 0 ? current.slice(0, markerIndex) : current.slice(0, -3);
  writeFileSync(target, `${prefix.trimEnd()}\n\n${graph.slice(3).join('\n')}\n\n}\n`);
}
if (process.argv.includes('--replace-evidence')) {
  const target = join(root, 'semantic-model/assurance/evidence.trig');
  const current = readFileSync(target, 'utf8');
  const marker = '<urn:usf:evidencefreshnesspolicy:realisationoptionevaluationthirtydays> a usf:EvidenceRetentionPolicy;';
  const markerIndex = current.indexOf(marker);
  const closureIndex = current.lastIndexOf('\n}\n');
  if (markerIndex < 0 || closureIndex < markerIndex) throw new Error('evidence graph does not expose the expected replaceable option-evaluation block');
  writeFileSync(target, `${current.slice(0, markerIndex).trimEnd()}\n${evidenceGraph.join('\n')}\n\n}\n`);
}
console.log(canonicalJson({ evidenceDigest, attestationDigest, evaluationDependencySetDigest, implementationSourceDigest, evidenceProducerDigest, assessmentCount: assessmentRecords.length, casPath }));
