// Unit tests for the USF semantic compiler.
//
// These never contact Stardog Cloud: the SDK adapter is replaced by a
// recording fake injected at the compiler boundary, and manifests are built in
// throwaway temp directories. Run with `npm test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DataFactory, Parser, Store } from 'n3';

// The real graph/census live in the parent usf repository and are used
// host-side only; inside the graph-free chroot these tests skip.
const REAL_GRAPH_DIR = process.env.USF_GRAPH_DIR
  || join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'graph');
const realGraphAbsent = (t) => {
  if (existsSync(join(REAL_GRAPH_DIR, 'manifest.yaml'))) return false;
  t.skip('real graph not present (graph/census live host-side, outside the chroot)');
  return true;
};


import { loadConfig, describeConfig, ConfigError } from '../src/config.js';
import { loadManifest, managedGraphs, ManifestError } from '../src/manifest.js';
import { checkLocal, compile, buildPlan, verify, verificationConforms, CompilerError, CONTAMINATION_PATTERNS } from '../src/compiler.js';
import { createClient } from '../src/stardog.js';
import { loadAuthorityDataset } from '../src/authority-dataset.js';
import { buildGenerationPlan, requireCompleteGenerationPlan } from '../src/generation-plan.js';
import {
  canonicalGraphDigest,
  canonicalGraphTrig,
  compareGraphDigests,
  liveAttestationInternals,
} from '../src/live-attestation.js';
import { generateAuthority, generatorInternals, verifyOutput } from '../src/generate.js';
import { collectRepositorySourceObservations, sourceObserverInternals } from '../src/source-observer.js';

// --- Fixtures --------------------------------------------------------------

// A minimal but structurally complete graph that passes all local checks.
function baseSpec() {
  const rule = (name) =>
    `PREFIX usf: <urn:usf:ontology:>\nCONSTRUCT { ?x a usf:${name} } WHERE { ?x a usf:Thing }\n`;
  return {
    'manifest.yaml': `version: 1
database: USF
baseIri: "urn:usf:"
definitionGraphs:
  - { file: ontology.ttl, graph: "urn:usf:graph:ontology", loadOrder: 1, validationOrder: 1 }
  - { file: registry.ttl, graph: "urn:usf:graph:registry", loadOrder: 2, validationOrder: 2 }
authoredGraphs:
  - { file: providers.ttl, graph: "urn:usf:graph:providers", loadOrder: 3, validationOrder: 3 }
shapeGraphs:
  - { file: shapes.ttl, graph: "urn:usf:graph:shapes", loadOrder: 4, validationOrder: 4 }
rules:
  - { file: rules/repository-structure.rq, output: "urn:usf:graph:derived:repositorystructure", kind: derivation }
  - { file: rules/source-dispositions.rq, output: "urn:usf:graph:derived:sourcedispositions", kind: derivation }
  - { file: rules/obligations.rq, output: "urn:usf:graph:derived:obligations", kind: derivation }
  - { file: rules/evidence.rq, output: "urn:usf:graph:derived:evidence", kind: derivation }
  - { file: rules/surfaces.rq, output: "urn:usf:graph:derived:surfaces", kind: derivation }
  - { file: rules/coverage.rq, output: "urn:usf:graph:derived:coverage", kind: derivation }
  - { file: rules/readiness.rq, output: "urn:usf:graph:derived:readiness", kind: derivation }
  - { file: rules/integrity.rq, kind: integrity }
derivedGraphs:
  - { file: derived/repository-structure.trig, graph: "urn:usf:graph:derived:repositorystructure", loadOrder: 9, validationOrder: 9 }
  - { file: derived/source-dispositions.trig, graph: "urn:usf:graph:derived:sourcedispositions", loadOrder: 10, validationOrder: 10 }
  - { file: derived/obligations.trig, graph: "urn:usf:graph:derived:obligations", loadOrder: 11, validationOrder: 11 }
  - { file: derived/evidence.trig, graph: "urn:usf:graph:derived:evidence", loadOrder: 12, validationOrder: 12 }
  - { file: derived/surfaces.trig, graph: "urn:usf:graph:derived:surfaces", loadOrder: 13, validationOrder: 13 }
  - { file: derived/coverage.trig, graph: "urn:usf:graph:derived:coverage", loadOrder: 14, validationOrder: 14 }
  - { file: derived/readiness.trig, graph: "urn:usf:graph:derived:readiness", loadOrder: 15, validationOrder: 15 }
fixtures:
  conforming: fixtures/conforming
  defects: fixtures/defects
  loadAsAuthority: false
`,
    'ontology.ttl': '@prefix usf: <urn:usf:ontology:> .\nusf:Thing a <http://www.w3.org/2002/07/owl#Class> .\n',
    'registry.ttl': `@prefix usf: <urn:usf:ontology:> .
@prefix ng: <urn:usf:namedgraph:> . @prefix rl: <urn:usf:rule:> . @prefix gcl: <urn:usf:graphclass:> .
ng:o a usf:NamedGraph ; usf:canonicalName "ontology" ; usf:graphIri "urn:usf:graph:ontology" ; usf:graphClass gcl:definitiongraph ; usf:loadOrder 1 ; usf:graphValidationOrder 1 .
ng:r a usf:NamedGraph ; usf:canonicalName "registry" ; usf:graphIri "urn:usf:graph:registry" ; usf:graphClass gcl:definitiongraph ; usf:loadOrder 2 ; usf:graphValidationOrder 2 .
ng:p a usf:NamedGraph ; usf:canonicalName "providers" ; usf:graphIri "urn:usf:graph:providers" ; usf:graphClass gcl:authoredgraph ; usf:loadOrder 3 ; usf:graphValidationOrder 3 .
ng:s a usf:NamedGraph ; usf:canonicalName "shapes" ; usf:graphIri "urn:usf:graph:shapes" ; usf:graphClass gcl:shapegraph ; usf:loadOrder 4 ; usf:graphValidationOrder 4 .
ng:dr a usf:NamedGraph ; usf:canonicalName "dr" ; usf:graphIri "urn:usf:graph:derived:repositorystructure" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 9 ; usf:graphValidationOrder 9 .
ng:d0 a usf:NamedGraph ; usf:canonicalName "d0" ; usf:graphIri "urn:usf:graph:derived:sourcedispositions" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 10 ; usf:graphValidationOrder 10 .
ng:d1 a usf:NamedGraph ; usf:canonicalName "d1" ; usf:graphIri "urn:usf:graph:derived:obligations" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 11 ; usf:graphValidationOrder 11 .
ng:d2 a usf:NamedGraph ; usf:canonicalName "d2" ; usf:graphIri "urn:usf:graph:derived:evidence" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 12 ; usf:graphValidationOrder 12 .
ng:d3 a usf:NamedGraph ; usf:canonicalName "d3" ; usf:graphIri "urn:usf:graph:derived:surfaces" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 13 ; usf:graphValidationOrder 13 .
ng:d4 a usf:NamedGraph ; usf:canonicalName "d4" ; usf:graphIri "urn:usf:graph:derived:coverage" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 14 ; usf:graphValidationOrder 14 .
ng:d5 a usf:NamedGraph ; usf:canonicalName "d5" ; usf:graphIri "urn:usf:graph:derived:readiness" ; usf:graphClass gcl:derivedgraph ; usf:loadOrder 15 ; usf:graphValidationOrder 15 .
rl:rr a usf:DerivationRule ; usf:canonicalName "repositorystructure" ; usf:inNamedGraph ng:dr .
rl:r0 a usf:DerivationRule ; usf:canonicalName "sourcedispositions" ; usf:inNamedGraph ng:d0 .
rl:r1 a usf:DerivationRule ; usf:canonicalName "obligations" ; usf:inNamedGraph ng:d1 .
rl:r2 a usf:DerivationRule ; usf:canonicalName "evidence" ; usf:inNamedGraph ng:d2 .
rl:r3 a usf:DerivationRule ; usf:canonicalName "surfaces" ; usf:inNamedGraph ng:d3 .
rl:r4 a usf:DerivationRule ; usf:canonicalName "coverage" ; usf:inNamedGraph ng:d4 .
rl:r5 a usf:DerivationRule ; usf:canonicalName "readiness" ; usf:inNamedGraph ng:d5 .
`,
    'providers.ttl': '@prefix usf: <urn:usf:> .\nusf:providers:acme a usf:ontology:Thing .\n',
    'shapes.ttl':
      '# SHACL detectors legitimately mention forbidden markers: github.com USF-1 commitSha\n@prefix sh: <http://www.w3.org/ns/shacl#> .\n',
    'rules/repository-structure.rq': rule('RepositoryWorkPackage'),
    'rules/source-dispositions.rq': rule('SourceArtefactDisposition'),
    'rules/obligations.rq': rule('ProofObligation'),
    'rules/evidence.rq': rule('EvidenceRequirement'),
    'rules/surfaces.rq': rule('Surface'),
    'rules/coverage.rq': rule('Coverage'),
    'rules/readiness.rq': rule('Readiness'),
    'rules/integrity.rq':
      'SELECT ?violation ?subject WHERE { ?subject a ?t . BIND("x" AS ?violation) FILTER(false) }\n',
    'derived/repository-structure.trig': 'GRAPH <urn:usf:graph:derived:repositorystructure> { <urn:usf:x> a <urn:usf:ontology:RepositoryWorkPackage> . }\n',
    'derived/source-dispositions.trig': 'GRAPH <urn:usf:graph:derived:sourcedispositions> { <urn:usf:x> a <urn:usf:ontology:SourceArtefactDisposition> . }\n',
    'derived/obligations.trig': '@prefix usf: <urn:usf:ontology:> .\nGRAPH <urn:usf:graph:derived:obligations> { usf:x a usf:ProofObligation }\n',
    'derived/evidence.trig': 'GRAPH <urn:usf:graph:derived:evidence> { <urn:usf:x> a <urn:usf:ontology:EvidenceRequirement> . }\n',
    'derived/surfaces.trig': 'GRAPH <urn:usf:graph:derived:surfaces> { <urn:usf:x> a <urn:usf:ontology:Surface> . }\n',
    'derived/coverage.trig': 'GRAPH <urn:usf:graph:derived:coverage> { <urn:usf:x> a <urn:usf:ontology:Coverage> . }\n',
    'derived/readiness.trig': 'GRAPH <urn:usf:graph:derived:readiness> { <urn:usf:x> a <urn:usf:ontology:Readiness> . }\n',
    'fixtures/conforming/sample.ttl': '# fixture, never loaded as authority\n<urn:usf:x> a <urn:usf:ontology:Thing> .\n',
  };
}

// A validator asserting a CompilerError whose failure list mentions `substr`.
const hasFailure = (substr) => (e) =>
  e instanceof CompilerError && Array.isArray(e.failures) && e.failures.some((f) => f.includes(substr));

let dirs = [];
function writeGraph(spec) {
  const dir = mkdtempSync(join(tmpdir(), 'usf-graph-'));
  dirs.push(dir);
  for (const [rel, content] of Object.entries(spec)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

function observedSpec() {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace(
    'shapeGraphs:',
    'observedGraphs:\n  - { collector: repositorysourceobserver, graph: "urn:usf:graph:observed:sourceartefacts", loadOrder: 5, validationOrder: 5 }\nshapeGraphs:'
  );
  spec['registry.ttl'] += 'ng:obs a usf:NamedGraph ; usf:canonicalName "sourceobservations" ; usf:graphIri "urn:usf:graph:observed:sourceartefacts" ; usf:graphClass gcl:observedgraph ; usf:loadOrder 5 ; usf:graphValidationOrder 5 .\n';
  return spec;
}

const observedCollector = async ({ entry }) => ({
  graph: entry.graph,
  contentType: 'text/turtle',
  content: '<urn:usf:source:s> <urn:usf:ontology:observedSourcePath> "x" .',
  sourceCount: 1,
  tripleCount: 1,
  observationSetDigest: 'a'.repeat(64),
});
test.after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

// A recording fake standing in for the SDK adapter.
function fakeClient(overrides = {}) {
  const rec = { cleared: [], added: [], committed: false, rolledBack: false, began: false };
  const client = {
    async connectivity() {
      return 0;
    },
    async begin() {
      rec.began = true;
      return 'tx-1';
    },
    async commit() {
      rec.committed = true;
    },
    async rollback() {
      rec.rolledBack = true;
    },
    async clearGraph(tx, graph) {
      assert.ok(graph, 'clearGraph must always receive a named graph');
      rec.cleared.push(graph);
    },
    async addData(tx, content, contentType, graph) {
      rec.added.push({ graph, contentType });
    },
    async constructInTx() {
      return '<urn:usf:x> a <urn:usf:ontology:ProofObligation> .';
    },
    async validateInTx() {
      return true;
    },
    async selectInTx(tx, q) {
      if (/REGEX/.test(q)) return [{ c: { value: '0' } }]; // contamination
      if (/\?violation/.test(q)) return []; // integrity: conforming
      return [{ c: { value: '5' } }]; // counts
    },
    async reportInTx() {
      return {};
    },
  };
  return { client: Object.assign(client, overrides), rec };
}

// --- config.js -------------------------------------------------------------

test('config: missing configuration is rejected', () => {
  assert.throws(() => loadConfig({}), ConfigError);
});

test('config: token authentication is accepted and takes precedence', () => {
  const c = loadConfig({
    STARDOG_SERVER: 'https://example.stardog.cloud:5820',
    STARDOG_DATABASE: 'USF',
    STARDOG_TOKEN: 'tok',
    STARDOG_USERNAME: 'u',
    STARDOG_PASSWORD: 'p',
  });
  assert.equal(c.auth.kind, 'token');
});

test('config: username and password authentication is accepted', () => {
  const c = loadConfig({
    STARDOG_SERVER: 'https://example.stardog.cloud:5820',
    STARDOG_USERNAME: 'u',
    STARDOG_PASSWORD: 'p',
  });
  assert.equal(c.auth.kind, 'basic');
  assert.equal(c.database, 'USF'); // documented default
});

test('config: a non-HTTPS endpoint is rejected', () => {
  assert.throws(
    () => loadConfig({ STARDOG_SERVER: 'http://example.stardog.cloud:5820', STARDOG_TOKEN: 't' }),
    ConfigError
  );
});

test('config: a localhost endpoint is rejected', () => {
  assert.throws(
    () => loadConfig({ STARDOG_SERVER: 'https://localhost:5820', STARDOG_TOKEN: 't' }),
    ConfigError
  );
});

test('config: credentials never appear in the describeConfig output', () => {
  const config = loadConfig({
    STARDOG_SERVER: 'https://example.stardog.cloud:5820',
    STARDOG_TOKEN: 'super-secret-token',
  });
  const described = describeConfig(config);
  const json = JSON.stringify(described);
  assert.ok(!json.includes('super-secret-token'));
  assert.deepEqual(Object.keys(described).sort(), ['authMode', 'database', 'endpoint']);
});

// --- manifest.js / checkLocal ---------------------------------------------

test('manifest: a missing manifest file throws', () => {
  assert.throws(() => loadManifest(join(tmpdir(), 'nope-does-not-exist')), Error);
});

test('manifest: a path escaping the graph directory is rejected', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace('file: ontology.ttl', 'file: ../ontology.ttl');
  const dir = writeGraph(spec);
  assert.throws(() => loadManifest(dir), ManifestError);
});

test('manifest: an unsupported (incorrect) content type is rejected', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace('file: ontology.ttl', 'file: ontology.md');
  spec['ontology.md'] = 'not rdf';
  const dir = writeGraph(spec);
  assert.throws(() => loadManifest(dir), ManifestError);
});

test('checkLocal: the base graph passes', () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  assert.equal(checkLocal(m).ok, true);
});

test('manifest: observed collector is registered separately from authority', () => {
  const manifest = loadManifest(writeGraph(observedSpec()));
  assert.equal(manifest.observed.length, 1);
  assert.equal(manifest.observed[0].collector, 'repositorysourceobserver');
  assert.equal(manifest.observed[0].path, null);
  assert.ok(managedGraphs(manifest).includes('urn:usf:graph:observed:sourceartefacts'));
});

test('source observer: progressive fixtures receive a non-accepting equivalence role', () => {
  const manifest = { fixtures: { conforming: 'fixtures/conforming', defects: 'fixtures/defects' } };
  const progressive = sourceObserverInternals.rolesFor({
    path: 'tools/validate-spec/provider-planted-defects/001.json',
    artifactFamily: 'repository-governance',
    universe: 'repository-output',
  }, new Map(), manifest);
  assert.deepEqual(progressive, ['equivalencefixture', 'repositorygovernance']);
  const graphFixture = sourceObserverInternals.rolesFor({
    path: 'v2/usf/graph/fixtures/defects/sample.trig',
    artifactFamily: 'machine-semantics',
    universe: 'v2-graph-authority',
  }, new Map(), { fixtures: { conforming: 'fixtures/conforming', defects: 'fixtures/defects' } });
  assert.deepEqual(graphFixture, ['fixture', 'machinesemantics']);
  assert.equal(sourceObserverInternals.isEquivalenceFixture({
    path: 'docs/fixture-governance.md', artifactFamily: 'documentation-assets', universe: 'repository-output',
  }), false);
});

test('source observer: TriG quad ordering is deterministic and avoids deep same-subject compaction', () => {
  const { namedNode, quad } = DataFactory;
  const graph = namedNode('urn:test:graph');
  const predicate = namedNode('urn:test:predicate');
  const dense = namedNode('urn:test:dense');
  const input = [];
  for (let index = 0; index < 40; index += 1) {
    input.push(quad(dense, predicate, namedNode(`urn:test:dense-object:${String(index).padStart(2, '0')}`), graph));
    input.push(quad(namedNode(`urn:test:subject:${String(index).padStart(2, '0')}`), predicate, namedNode(`urn:test:object:${index}`), graph));
  }
  const ordered = sourceObserverInternals.interleaveQuadsBySubject(input);
  assert.equal(ordered.length, input.length);
  for (let index = 1; index < ordered.length; index += 1) assert.notEqual(ordered[index - 1].subject.value, ordered[index].subject.value);
  assert.deepEqual(
    new Store(ordered).getQuads(null, null, null, null).map((item) => item.id).sort(),
    new Store(input).getQuads(null, null, null, null).map((item) => item.id).sort(),
  );
  assert.deepEqual(
    sourceObserverInternals.interleaveQuadsBySubject(input).map((item) => item.id),
    ordered.map((item) => item.id),
  );
});

function censusObserverFixture() {
  const sourceKey = 'a'.repeat(64);
  const targetKey = 'b'.repeat(64);
  const sourcePackage = `work-package-${'1'.repeat(20)}`;
  const targetPackage = `work-package-${'2'.repeat(20)}`;
  const canonicalArtefact = 'urn:usf:artefact:fixture';
  const row = (artifactKey, path) => ({
    artifactKey, path, contentDigest: 'c'.repeat(64), fileMode: '100644', parserImplementation: 'fixture-parser',
    syntaxKind: 'fixture', formatKind: 'fixture', universe: 'canonicalrepository', roles: ['implementation'], semanticReferences: [],
  });
  const relationship = {
    source: 'src/a.js', target: 'src/b.js', relationshipType: 'imports', targetKind: 'artifact', resolved: true,
    evidenceKind: 'structurally-proven', extractionMethod: 'fixture-parser', reasonCodes: ['structural-parser-evidence'],
    attributes: { importKind: 'static' }, confidence: { level: 'high', reasons: ['structural-parser-evidence'], score: 1 },
  };
  const relationshipEvidence = sourceObserverInternals.relationshipEvidenceDigest(relationship);
  const workPackage = (key, artifactKeys, canonicalArtifactKeys = []) => ({
    key, title: key, outcomeClass: `fixture:${key}`, artifactKeys, canonicalArtifactKeys,
    primaryOwnership: { artifactKeys, canonicalArtifactKeys },
  });
  const workPackageDocument = {
    ownership: {
      artifacts: [
        { ownedKey: sourceKey, primaryWorkPackage: sourcePackage },
        { ownedKey: targetKey, primaryWorkPackage: targetPackage },
      ],
      canonicalArtifacts: [{ ownedKey: canonicalArtefact, primaryWorkPackage: sourcePackage }],
    },
    workPackages: [workPackage(sourcePackage, [sourceKey], [canonicalArtefact]), workPackage(targetPackage, [targetKey])],
  };
  const dependency = {
    dependencyKey: `dependency-${'d'.repeat(64)}`, source: sourcePackage, prerequisite: targetPackage,
    dependencyType: 'canonical-artifact-input', status: 'required-prerequisite', reasonCode: 'canonical-artifact-input',
    resolutionStatus: 'resolved-retained', reviewStatus: 'machine-reviewed',
    satisfactionStatus: 'satisfied',
    satisfactionBasis: {
      exactEvidenceHashCount: 1, currentRelationshipHashCount: 1, structurallyProvenRelationshipHashCount: 1,
      directionMatchedRelationshipHashCount: 1, currentPrerequisiteArtifactHashCount: 1, currentPrerequisiteArtifactCount: 1,
      sourceEndpointExists: true, prerequisiteEndpointExists: true, edgeSurvivedTransitiveReduction: true, requiredPrerequisiteGraphAcyclic: true,
    },
    semanticEvidence: [], artifactEvidence: [], repositoryRelationshipEvidence: [relationshipEvidence], proofEquivalenceEvidence: [], migrationEvidence: [],
    confidence: { level: 'high', reasons: ['machine-observed-direct-evidence'], score: 1 },
    resolutionBasis: {
      evidenceCounts: { semantic: 0, artifact: 0, 'repository-relationship': 1, 'proof-equivalence': 0, migration: 0 },
      evidenceFamilies: ['repository-relationship'], cycleCheck: 'required-prerequisite-dag-verified', direction: 'source-requires-prerequisite',
      endpointOwnership: 'primary-work-package', reviewBasis: 'machine-reviewed', transitiveReduction: 'retained-direct-edge',
    },
  };
  const lineage = {
    baselinePrerequisite: 'baseline-prerequisite', baselineSource: 'baseline-source', disposition: 'retained-with-evidence',
    reason: 'successor direct edge has architectural evidence', successorSources: [sourcePackage], successorPrerequisites: [targetPackage],
  };
  const digest = 'e'.repeat(64);
  return {
    rows: [row(sourceKey, 'src/a.js'), row(targetKey, 'src/b.js')], relationships: [relationship], workPackageDocument,
    dependencies: [dependency], dependencyLineage: [lineage], parserManifest: { formatVersion: 1 },
    summary: {
      artifactCount: 2, relationshipCount: 1, workPackageCount: 2, requiredPrerequisiteRelationshipCount: 1,
      resolvedPrerequisiteRelationshipCount: 1, satisfiedPrerequisiteRelationshipCount: 1,
      blockingRelationshipCount: 0, activeBlockingRelationshipCount: 0, coordinationRelationshipCount: 0,
      universeCounts: { 'repository-output': 2 }, repositoryUniverseDigest: digest, v2CompilerUniverseDigest: digest,
      v2GraphUniverseDigest: digest, v2SupportUniverseDigest: digest, dependencyLineageDistribution: { 'retained-with-evidence': 1 },
    },
    universes: {
      universeCounts: { 'repository-output': 2 }, repositoryUniverseDigest: digest, v2CompilerUniverseDigest: digest,
      v2GraphUniverseDigest: digest, v2SupportUniverseDigest: digest,
    },
    inputs: [{ path: 'b.json', contentDigest: digest, byteCount: 2, recordCount: null }, { path: 'a.jsonl', contentDigest: digest, byteCount: 1, recordCount: 2 }],
    parserShards: [{ path: 'parser-results/b.gz', universe: 'repository-output' }, { path: 'parser-results/a.gz', universe: 'repository-output' }],
    authoredArtefacts: new Set([canonicalArtefact]),
  };
}

test('source observer: census expansion is deterministic and preserves exact relationship evidence', () => {
  const fixture = censusObserverFixture();
  assert.deepEqual(sourceObserverInternals.OBSERVATION_CONTAMINATION_PATTERNS, CONTAMINATION_PATTERNS);
  const left = sourceObserverInternals.censusObservationModel(fixture);
  const reordered = structuredClone(fixture);
  reordered.authoredArtefacts = new Set(fixture.authoredArtefacts);
  for (const field of ['rows', 'relationships', 'dependencies', 'dependencyLineage', 'inputs', 'parserShards']) reordered[field].reverse();
  reordered.workPackageDocument.workPackages.reverse();
  reordered.workPackageDocument.ownership.artifacts.reverse();
  const right = sourceObserverInternals.censusObservationModel(reordered);
  assert.equal(left.setDigest, right.setDigest);
  assert.equal(left.relationshipRecords.length, 1);
  assert.equal(left.relationshipRecords[0].fullDigest, sourceObserverInternals.recordDigest(fixture.relationships[0]));
  assert.equal(left.relationshipRecords[0].evidenceDigest, fixture.dependencies[0].repositoryRelationshipEvidence[0]);
  assert.deepEqual(left.dependencyRecords[0].relationshipMatches, [left.relationshipRecords[0].fullDigest]);
  assert.equal(sourceObserverInternals.workPackageObservationName(fixture.workPackageDocument.workPackages[0].key), `w${'1'.repeat(20)}`);
  assert.equal(sourceObserverInternals.workPackageDependencyObservationName(fixture.dependencies[0].dependencyKey), `d${'d'.repeat(64)}`);
  const digestRecord = structuredClone(fixture.dependencies[0]);
  digestRecord.repositoryRelationshipEvidence = ['f'.repeat(64), '0'.repeat(64)];
  const expectedBasisDigest = createHash('sha256').update(sourceObserverInternals.stableJson({
    dependencyKey: digestRecord.dependencyKey,
    satisfactionStatus: digestRecord.satisfactionStatus,
    satisfactionBasis: digestRecord.satisfactionBasis,
    repositoryRelationshipEvidence: [...digestRecord.repositoryRelationshipEvidence].sort(),
  })).digest('hex');
  assert.equal(sourceObserverInternals.dependencySatisfactionBasisDigest(digestRecord), expectedBasisDigest);
  digestRecord.repositoryRelationshipEvidence.reverse();
  assert.equal(sourceObserverInternals.dependencySatisfactionBasisDigest(digestRecord), expectedBasisDigest);
  const prohibited = 'origin github.com/example/repository refs/heads/main';
  const withheld = sourceObserverInternals.observationDisclosure(prohibited);
  assert.deepEqual(withheld, sourceObserverInternals.observationDisclosure(prohibited));
  assert.equal(withheld.digest, createHash('sha256').update(prohibited).digest('hex'));
  assert.equal(withheld.status, 'urn:usf:observationdisclosurestatus:withheldprohibitedmetadata');
  assert.equal(withheld.disclosedValue, null);
  assert.equal(sourceObserverInternals.observationDisclosure('safe-target').status, 'urn:usf:observationdisclosurestatus:disclosed');
  for (const mutate of [
    (copy) => { copy.relationships[0].attributes.importKind = 'dynamic'; },
    (copy) => { copy.workPackageDocument.workPackages[0].title += ' changed'; },
    (copy) => { copy.dependencies[0].reasonCode += '-changed'; },
    (copy) => { copy.dependencyLineage[0].reason += ' changed'; },
    (copy) => { copy.inputs[0].contentDigest = 'f'.repeat(64); },
    (copy) => { copy.parserShards[0].path += '.changed'; },
  ]) {
    const copy = structuredClone(fixture);
    copy.authoredArtefacts = new Set(fixture.authoredArtefacts);
    mutate(copy);
    assert.notEqual(sourceObserverInternals.censusObservationModel(copy).setDigest, left.setDigest);
  }
});

test('source observer: census expansion fails closed on endpoints, ownership, evidence, and counts', () => {
  const legacyBlockingStatus = censusObserverFixture();
  legacyBlockingStatus.dependencies[0].status = 'blocking';
  assert.throws(() => sourceObserverInternals.censusObservationModel(legacyBlockingStatus), /invalid dependency status/);
  const missingEndpoint = censusObserverFixture();
  missingEndpoint.relationships[0].target = 'src/missing.js';
  assert.throws(() => sourceObserverInternals.censusObservationModel(missingEndpoint), /target endpoint is missing/);
  const wrongOwnership = censusObserverFixture();
  wrongOwnership.workPackageDocument.ownership.artifacts[0].primaryWorkPackage = wrongOwnership.workPackageDocument.workPackages[1].key;
  assert.throws(() => sourceObserverInternals.censusObservationModel(wrongOwnership), /ownership index mismatch/);
  const missingEvidence = censusObserverFixture();
  missingEvidence.dependencies[0].repositoryRelationshipEvidence = ['f'.repeat(64)];
  assert.throws(() => sourceObserverInternals.censusObservationModel(missingEvidence), /relationship evidence must resolve exactly once/);
  const wrongCount = censusObserverFixture();
  wrongCount.summary.relationshipCount = 2;
  assert.throws(() => sourceObserverInternals.censusObservationModel(wrongCount), /relationship count mismatch/);
  const contradictorySatisfaction = censusObserverFixture();
  contradictorySatisfaction.dependencies[0].satisfactionStatus = 'unsatisfied';
  assert.throws(() => sourceObserverInternals.censusObservationModel(contradictorySatisfaction), /satisfaction status contradicts basis/);
  const incompleteBasis = censusObserverFixture();
  delete incompleteBasis.dependencies[0].satisfactionBasis.requiredPrerequisiteGraphAcyclic;
  assert.throws(() => sourceObserverInternals.censusObservationModel(incompleteBasis), /satisfaction basis fields differ/);
  const coordinationClaim = censusObserverFixture();
  coordinationClaim.dependencies[0].status = 'coordination';
  coordinationClaim.summary.requiredPrerequisiteRelationshipCount = 0;
  coordinationClaim.summary.coordinationRelationshipCount = 1;
  coordinationClaim.summary.resolvedPrerequisiteRelationshipCount = 0;
  coordinationClaim.summary.satisfiedPrerequisiteRelationshipCount = 0;
  assert.throws(() => sourceObserverInternals.censusObservationModel(coordinationClaim), /coordination dependency must not claim satisfaction/);
  const wrongSatisfactionCount = censusObserverFixture();
  wrongSatisfactionCount.summary.satisfiedPrerequisiteRelationshipCount = 0;
  wrongSatisfactionCount.summary.activeBlockingRelationshipCount = 1;
  assert.throws(() => sourceObserverInternals.censusObservationModel(wrongSatisfactionCount), /satisfied prerequisite dependency count does not match summary/);
  const activeBlocker = censusObserverFixture();
  activeBlocker.dependencies[0].satisfactionStatus = 'unsatisfied';
  activeBlocker.dependencies[0].satisfactionBasis.edgeSurvivedTransitiveReduction = false;
  activeBlocker.dependencies[0].resolutionBasis.transitiveReduction = 'not-retained-direct-edge';
  activeBlocker.summary.satisfiedPrerequisiteRelationshipCount = 0;
  activeBlocker.summary.activeBlockingRelationshipCount = 1;
  assert.throws(() => sourceObserverInternals.censusObservationModel(activeBlocker), /active blocking dependency remains/);
  const duplicateSatisfactionEvidence = censusObserverFixture();
  duplicateSatisfactionEvidence.dependencies[0].repositoryRelationshipEvidence.push(duplicateSatisfactionEvidence.dependencies[0].repositoryRelationshipEvidence[0]);
  duplicateSatisfactionEvidence.dependencies[0].resolutionBasis.evidenceCounts['repository-relationship'] = 2;
  for (const field of ['exactEvidenceHashCount', 'currentRelationshipHashCount', 'structurallyProvenRelationshipHashCount', 'directionMatchedRelationshipHashCount', 'currentPrerequisiteArtifactHashCount']) duplicateSatisfactionEvidence.dependencies[0].satisfactionBasis[field] = 2;
  assert.throws(() => sourceObserverInternals.censusObservationModel(duplicateSatisfactionEvidence), /duplicate relationship evidence/);
  const stalePrerequisite = censusObserverFixture();
  stalePrerequisite.rows[1].contentDigest = 'stale';
  assert.throws(() => sourceObserverInternals.censusObservationModel(stalePrerequisite), /prerequisite artifact has no current digest/);
  const wrongDependencyDirection = censusObserverFixture();
  [wrongDependencyDirection.dependencies[0].source, wrongDependencyDirection.dependencies[0].prerequisite] = [wrongDependencyDirection.dependencies[0].prerequisite, wrongDependencyDirection.dependencies[0].source];
  assert.throws(() => sourceObserverInternals.censusObservationModel(wrongDependencyDirection), /source ownership mismatch/);
  const prohibited = censusObserverFixture();
  prohibited.relationships[0].target = 'github.com/example/repository';
  prohibited.relationships[0].targetKind = 'external-resource';
  prohibited.relationships[0].attributes = { commitSha: 'abc123' };
  prohibited.dependencies[0].repositoryRelationshipEvidence = [sourceObserverInternals.relationshipEvidenceDigest(prohibited.relationships[0])];
  prohibited.dependencies[0].status = 'coordination';
  prohibited.dependencies[0].resolutionBasis.cycleCheck = 'not-applicable-coordination';
  delete prohibited.dependencies[0].satisfactionStatus;
  delete prohibited.dependencies[0].satisfactionBasis;
  prohibited.summary.requiredPrerequisiteRelationshipCount = 0;
  prohibited.summary.coordinationRelationshipCount = 1;
  prohibited.summary.resolvedPrerequisiteRelationshipCount = 0;
  prohibited.summary.satisfiedPrerequisiteRelationshipCount = 0;
  const withheld = sourceObserverInternals.censusObservationModel(prohibited).relationshipRecords[0];
  assert.equal(withheld.targetDisclosure.status, 'urn:usf:observationdisclosurestatus:withheldprohibitedmetadata');
  assert.equal(withheld.attributesDisclosure.status, 'urn:usf:observationdisclosurestatus:withheldprohibitedmetadata');
  assert.equal(withheld.targetDisclosure.disclosedValue, null);
  assert.equal(withheld.attributesDisclosure.disclosedValue, null);
});

test('source observer: current census emits the complete deterministic observation projection', async (t) => {
  if (realGraphAbsent(t)) return;
  const graphDir = REAL_GRAPH_DIR;
  const manifest = loadManifest(graphDir);
  const censusDir = join(graphDir, '..', 'census');
  const censusSummary = JSON.parse(readFileSync(join(censusDir, 'summary.json'), 'utf8'));
  const censusWorkPackages = JSON.parse(readFileSync(join(censusDir, 'workpackages.json'), 'utf8'));
  const censusDependencies = readFileSync(join(censusDir, 'dependencies.jsonl'), 'utf8').trim().split(/\r?\n/).filter(Boolean).map(JSON.parse);
  const collection = await collectRepositorySourceObservations({ manifest, entry: manifest.observed[0] });
  assert.deepEqual({
    sources: collection.sourceCount, relationships: collection.relationshipCount, workPackages: collection.workPackageCount,
    dependencies: collection.dependencyCount, retainedLineage: collection.retainedLineageCount,
    requiredPrerequisites: collection.requiredPrerequisiteDependencyCount,
    resolvedPrerequisites: collection.resolvedPrerequisiteDependencyCount, satisfiedPrerequisites: collection.satisfiedPrerequisiteDependencyCount,
    activeBlocking: collection.activeBlockingDependencyCount,
    sourceOwnership: collection.sourceOwnershipCount, canonicalOwnership: collection.canonicalOwnershipCount,
    dependencyRelationshipLinks: collection.dependencyRelationshipLinkCount, inputs: collection.inputCount, parserShards: collection.parserShardCount,
  }, {
    sources: censusSummary.artifactCount, relationships: censusSummary.relationshipCount, workPackages: censusSummary.workPackageCount,
    dependencies: censusDependencies.length, retainedLineage: censusSummary.dependencyLineageDistribution['retained-with-evidence'],
    requiredPrerequisites: censusSummary.requiredPrerequisiteRelationshipCount,
    resolvedPrerequisites: censusSummary.resolvedPrerequisiteRelationshipCount, satisfiedPrerequisites: censusSummary.satisfiedPrerequisiteRelationshipCount,
    activeBlocking: censusSummary.activeBlockingRelationshipCount,
    sourceOwnership: censusSummary.artifactCount, canonicalOwnership: censusWorkPackages.ownership.canonicalArtifacts.length,
    dependencyRelationshipLinks: 728, inputs: 9, parserShards: 4,
  });
  assert.match(collection.observationSetDigest, /^[0-9a-f]{64}$/);
  assert.match(collection.content, /urn:usf:ontology:SourceRelationshipObservation/);
  assert.match(collection.content, /urn:usf:ontology:WorkPackageDependencyObservation/);
  assert.match(collection.content, /urn:usf:dependencysatisfactionstatus:satisfied/);
  assert.match(collection.content, /urn:usf:ontology:WorkPackageDependencySatisfactionBasisObservation/);
  assert.match(collection.content, /urn:usf:ontology:satisfactionBasisExactEvidenceHashCount/);
  assert.match(collection.content, /urn:usf:ontology:satisfactionBasisRequiredPrerequisiteGraphAcyclic/);
  assert.match(collection.content, /urn:usf:ontology:observedRequiredPrerequisiteDependencyCount/);
  assert.match(collection.content, /urn:usf:ontology:observedResolvedPrerequisiteDependencyCount/);
  assert.match(collection.content, /urn:usf:ontology:observedSatisfiedPrerequisiteDependencyCount/);
  assert.match(collection.content, /urn:usf:ontology:observedActiveBlockingDependencyCount/);
  assert.doesNotMatch(collection.content, /urn:usf:ontology:observedBlockingDependencyCount/);
  assert.equal(Object.hasOwn(collection, 'blockingDependencyCount'), false);
  assert.match(collection.content, /urn:usf:ontology:supportedBySourceRelationshipObservation/);
  assert.match(collection.content, /urn:usf:workpackageobservation:w[0-9a-f]{20}/);
  assert.match(collection.content, /urn:usf:workpackagedependencyobservation:d[0-9a-f]{64}/);
  assert.doesNotMatch(collection.content, /urn:usf:workpackageobservation:work-package-/);
  assert.doesNotMatch(collection.content, /urn:usf:workpackagedependencyobservation:dependency-/);
  assert.match(collection.content, /urn:usf:ontology:canonicalName> "t[0-9a-f]{64}"/);
  assert.match(collection.content, /urn:usf:observationdisclosurestatus:disclosed/);
  assert.match(collection.content, /urn:usf:observationdisclosurestatus:withheldprohibitedmetadata/);
  for (const pattern of CONTAMINATION_PATTERNS) assert.doesNotMatch(collection.content, new RegExp(pattern));
});

function dispositionPolicySelections(store) {
  const rdfType = DataFactory.namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const usf = (local) => DataFactory.namedNode(`urn:usf:ontology:${local}`);
  const objects = (subject, local) => store.getObjects(subject, usf(local), null);
  const typed = (local) => store.getSubjects(rdfType, usf(local), null);
  const truth = (subject, local) => objects(subject, local).some((value) => value.value === 'true');
  const matches = (policy, source, observation) => {
    const bindings = objects(policy, 'policyMatchesSourceBinding');
    if (bindings.length) return bindings.some((binding) => objects(binding, 'sourceBindingSource').some((candidate) => candidate.equals(source)));
    for (const [selector, node, property] of [
      ['policyMatchesSourceIdentityDigest', source, 'sourceIdentityDigest'],
      ['policyMatchesUniverse', observation, 'observedUniverse'],
      ['policyMatchesContentRole', observation, 'observedContentRole'],
      ['policyMatchesExactSemanticReference', observation, 'hasExactSemanticReference'],
    ]) {
      for (const required of objects(policy, selector)) {
        if (!objects(node, property).some((actual) => actual.equals(required))) return false;
      }
    }
    return true;
  };
  const policies = typed('SourceDispositionPolicy');
  const candidates = policies.filter((policy) => truth(policy, 'isActiveDispositionPolicy') && !truth(policy, 'isDefaultDispositionPolicy'));
  const defaults = policies.filter((policy) => truth(policy, 'isActiveDispositionPolicy') && truth(policy, 'isDefaultDispositionPolicy'));
  return typed('SourceArtefact').map((source) => {
    const observation = objects(source, 'hasCurrentSourceObservation')[0];
    const matching = candidates.filter((policy) => matches(policy, source, observation));
    if (!matching.length) return { source: source.value, selected: defaults.map((policy) => policy.value), kind: 'default' };
    const maximum = Math.max(...matching.map((policy) => Number(objects(policy, 'policyPrecedence')[0]?.value)));
    const selected = matching.filter((policy) => Number(objects(policy, 'policyPrecedence')[0]?.value) === maximum);
    return { source: source.value, selected: selected.map((policy) => policy.value).sort(), kind: objects(selected[0], 'policyMatchesSourceBinding').length ? 'binding' : 'structural' };
  });
}

test('source disposition rule selects one highest-precedence policy for every current observation', (t) => {
  if (realGraphAbsent(t)) return;
  const graphDir = REAL_GRAPH_DIR;
  const manifest = loadManifest(graphDir);
  const dataset = loadAuthorityDataset(manifest);
  const observed = manifest.observed[0];
  dataset.store.addQuads(new Parser({ format: observed.contentType }).parse(readFileSync(observed.path, 'utf8')));
  const selections = dispositionPolicySelections(dataset.store);
  assert.ok(selections.length > 3000);
  assert.ok(selections.some((row) => row.kind === 'binding'));
  assert.ok(selections.some((row) => row.kind === 'structural'));
  assert.ok(selections.every((row) => row.selected.length === 1));
  const rule = readFileSync(join(graphDir, 'rules/source-dispositions.rq'), 'utf8');
  assert.match(rule, /MAX\s*\(\s*\?precedence\s*\)\s+AS\s+\?maximumPrecedence/i);
  assert.match(rule, /FILTER\s*\(\s*\?selectedPrecedence\s*=\s*\?maximumPrecedence\s*\)/i);
  assert.doesNotMatch(rule, /\?higherPrecedence\s*>\s*\?selectedPrecedence/);
  assert.match(rule, /SELECT DISTINCT \?source \?observation \?policy/i);
});

test('source disposition selector prefers binding/high precedence, preserves equal ties, and falls back to default', () => {
  const store = generationStore(`
<urn:usf:source:a> a usf:SourceArtefact ; usf:sourceIdentityDigest "${'a'.repeat(64)}" ; usf:hasCurrentSourceObservation <urn:usf:observation:a> .
<urn:usf:observation:a> a usf:SourceArtefactObservation ; usf:observedUniverse <urn:usf:sourceuniverse:test> ; usf:observedContentRole <urn:usf:sourcecontentrole:test> .
<urn:usf:policy:default> a usf:SourceDispositionPolicy ; usf:isActiveDispositionPolicy true ; usf:isDefaultDispositionPolicy true ; usf:policyPrecedence 0 .
<urn:usf:policy:structural> a usf:SourceDispositionPolicy ; usf:isActiveDispositionPolicy true ; usf:isDefaultDispositionPolicy false ; usf:policyPrecedence 10 ; usf:policyMatchesContentRole <urn:usf:sourcecontentrole:test> .
<urn:usf:policy:binding> a usf:SourceDispositionPolicy ; usf:isActiveDispositionPolicy true ; usf:isDefaultDispositionPolicy false ; usf:policyPrecedence 20 ; usf:policyMatchesSourceBinding <urn:usf:binding:a> .
<urn:usf:binding:a> usf:sourceBindingSource <urn:usf:source:a> .
`);
  assert.deepEqual(dispositionPolicySelections(store)[0].selected, ['urn:usf:policy:binding']);
  store.addQuad(DataFactory.namedNode('urn:usf:policy:structural'), DataFactory.namedNode('urn:usf:ontology:policyPrecedence'), DataFactory.literal('20', DataFactory.namedNode('http://www.w3.org/2001/XMLSchema#integer')));
  store.removeQuad(store.getQuads(DataFactory.namedNode('urn:usf:policy:structural'), DataFactory.namedNode('urn:usf:ontology:policyPrecedence'), null, null).find((quad) => quad.object.value === '10'));
  assert.equal(dispositionPolicySelections(store)[0].selected.length, 2);
  store.removeQuads(store.getQuads(DataFactory.namedNode('urn:usf:policy:structural'), DataFactory.namedNode('urn:usf:ontology:isActiveDispositionPolicy'), null, null));
  store.removeQuads(store.getQuads(DataFactory.namedNode('urn:usf:policy:binding'), DataFactory.namedNode('urn:usf:ontology:isActiveDispositionPolicy'), null, null));
  assert.deepEqual(dispositionPolicySelections(store)[0].selected, ['urn:usf:policy:default']);
});

test('checkLocal: a duplicate authored graph IRI fails', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace(
    '  - { file: providers.ttl, graph: "urn:usf:graph:providers", loadOrder: 3, validationOrder: 3 }',
    '  - { file: providers.ttl, graph: "urn:usf:graph:providers", loadOrder: 3, validationOrder: 3 }\n  - { file: providers2.ttl, graph: "urn:usf:graph:providers", loadOrder: 4, validationOrder: 4 }'
  );
  spec['providers2.ttl'] = '<urn:usf:providers:beta> a <urn:usf:ontology:Thing> .\n';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('duplicate authored graph IRI'));
});

test('checkLocal: a non-deterministic (duplicate) load order fails', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace('loadOrder: 2', 'loadOrder: 1');
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('load order'));
});

test('checkLocal: RDF registry graph class and order must match the manifest', () => {
  const spec = baseSpec();
  spec['registry.ttl'] = spec['registry.ttl'].replace(
    'usf:graphClass gcl:authoredgraph ; usf:loadOrder 3',
    'usf:graphClass gcl:definitiongraph ; usf:loadOrder 99',
  );
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('registry graph class mismatch'));
});

test('checkLocal: RDF registry derivation ownership must match compiler rule outputs', () => {
  const spec = baseSpec();
  spec['registry.ttl'] = spec['registry.ttl'].replace('usf:canonicalName "obligations" ; usf:inNamedGraph ng:d1', 'usf:canonicalName "obligations" ; usf:inNamedGraph ng:d2');
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('registry rule output mismatch'));
});

test('checkLocal: an unexpected unregistered graph file fails', () => {
  const spec = baseSpec();
  spec['stray.ttl'] = '<urn:usf:x> a <urn:usf:ontology:Thing> .\n';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('unregistered loadable file'));
});

test('checkLocal: malformed RDF fails before any live transaction', () => {
  const spec = baseSpec();
  spec['providers.ttl'] = '<urn:usf:broken';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('RDF parse failed'));
});

test('checkLocal: registered TriG cannot write to another named graph', () => {
  const spec = baseSpec();
  spec['derived/obligations.trig'] = 'GRAPH <urn:usf:graph:wrong> { <urn:usf:x> a <urn:usf:ontology:ProofObligation> . }\n';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('writes outside its graph'));
});

test('checkLocal: a derived graph treated as authored fails', () => {
  const spec = baseSpec();
  spec['manifest.yaml'] = spec['manifest.yaml'].replace(
    '  - { file: providers.ttl, graph: "urn:usf:graph:providers", loadOrder: 3, validationOrder: 3 }',
    '  - { file: providers.ttl, graph: "urn:usf:graph:derived:obligations", loadOrder: 3, validationOrder: 3 }'
  );
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('both authored and derived'));
});

test('checkLocal: forbidden contamination in an authored file fails', () => {
  const spec = baseSpec();
  spec['providers.ttl'] = '<urn:usf:x> <urn:usf:ontology:src> "see https://github.com/acme/repo" .\n';
  const dir = writeGraph(spec);
  assert.throws(() => checkLocal(loadManifest(dir)), hasFailure('forbidden content'));
});

test('checkLocal: the same markers inside the shapes file are allowed', () => {
  const spec = baseSpec();
  spec['shapes.ttl'] = '@prefix sh: <http://www.w3.org/ns/shacl#> .\n# detects github.com and USF-1 and commitSha\nsh:x a sh:NodeShape .\n';
  const dir = writeGraph(spec);
  assert.equal(checkLocal(loadManifest(dir)).ok, true);
});

// --- compile (mocked SDK) --------------------------------------------------

test('compile: only manifest-registered graphs are cleared, and never the whole database', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient();
  await compile({ manifest: m, client });
  assert.deepEqual([...rec.cleared].sort(), [...managedGraphs(m)].sort());
  // The adapter exposes no whole-database clear operation.
  assert.equal(typeof client.clearDatabase, 'undefined');
});

test('compile: commits after full success', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient();
  const result = await compile({ manifest: m, client });
  assert.equal(result.ok, true);
  assert.equal(rec.committed, true);
  assert.equal(rec.rolledBack, false);
});

test('compile: observed state is collected and validated inside the transaction', async () => {
  const manifest = loadManifest(writeGraph(observedSpec()));
  const { client, rec } = fakeClient();
  const result = await compile({ manifest, client, observedCollector });
  assert.equal(result.observedLoaded, 1);
  assert.equal(result.observed['urn:usf:graph:observed:sourceartefacts'].sourceCount, 1);
  assert.ok(rec.cleared.includes('urn:usf:graph:observed:sourceartefacts'));
  assert.ok(rec.added.some((entry) => entry.graph === 'urn:usf:graph:observed:sourceartefacts'));
  assert.equal(rec.committed, true);
});

test('compile: observed collection failure rolls back', async () => {
  const manifest = loadManifest(writeGraph(observedSpec()));
  const { client, rec } = fakeClient();
  await assert.rejects(
    compile({ manifest, client, observedCollector: async () => { throw new Error('collector failed'); } }),
    (error) => error instanceof CompilerError && error.phase === 'compile'
  );
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: observed validation failure rolls back', async () => {
  const manifest = loadManifest(writeGraph(observedSpec()));
  let validations = 0;
  const { client, rec } = fakeClient({ validateInTx: async () => (++validations) !== 2 });
  await assert.rejects(
    compile({ manifest, client, observedCollector }),
    (error) => error instanceof CompilerError && error.phase === 'validate:observed'
  );
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after a load failure', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async addData() {
      throw new Error('load boom');
    },
  });
  await assert.rejects(() => compile({ manifest: m, client }), CompilerError);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after a validation failure', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async validateInTx() {
      return false;
    },
  });
  await assert.rejects(() => compile({ manifest: m, client }), /SHACL validation/);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after a derivation failure', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async constructInTx() {
      throw new Error('derive boom');
    },
  });
  await assert.rejects(() => compile({ manifest: m, client }), CompilerError);
  assert.equal(rec.rolledBack, true);
  assert.equal(rec.committed, false);
});

test('compile: rolls back after an integrity violation', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client, rec } = fakeClient({
    async selectInTx(tx, q) {
      if (/REGEX/.test(q)) return [{ c: { value: '0' } }];
      if (/\?violation/.test(q)) return [{ violation: { value: 'hyphenatedidentifier' }, subject: { value: 'urn:usf:bad_name' } }];
      return [{ c: { value: '5' } }];
    },
  });
  await assert.rejects(() => compile({ manifest: m, client }), /integrity/);
  assert.equal(rec.rolledBack, true);
});

test('compile: an error never carries the token', async () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  const { client } = fakeClient({
    async addData() {
      throw new Error('network error at https://example.stardog.cloud:5820');
    },
  });
  await assert.rejects(
    () => compile({ manifest: m, client }),
    (e) => !JSON.stringify({ m: e.message, ...e }).includes('super-secret-token')
  );
});

test('buildPlan: repeated compilation produces an identical operation plan', () => {
  const dir = writeGraph(baseSpec());
  const m = loadManifest(dir);
  assert.deepEqual(buildPlan(m), buildPlan(m));
  // Evidence is derived before readiness; commit is last; no whole-db clear.
  const ops = buildPlan(m);
  const kinds = ops.map((o) => o.op);
  assert.ok(kinds.indexOf('derive') !== -1);
  assert.equal(ops[ops.length - 1].op, 'commit');
  assert.ok(!ops.some((o) => o.op === 'clear' && !o.graph));
});

test('adapter: createClient exposes no whole-database clear', () => {
  const client = createClient(
    loadConfig({ STARDOG_SERVER: 'https://example.stardog.cloud:5820', STARDOG_TOKEN: 't' })
  );
  assert.equal(typeof client.clearDatabase, 'undefined');
  assert.equal(typeof client.clearGraph, 'function');
});

test('generation plan fails closed when graph authority has no artefact plans', () => {
  const dir = writeGraph(baseSpec());
  const dataset = loadAuthorityDataset(loadManifest(dir));
  const plan = buildGenerationPlan(dataset.store);
  assert.equal(plan.complete, false);
  assert.ok(plan.obligations.some((item) => item.kind === 'missing-artefact-plans'));
  assert.throws(() => requireCompleteGenerationPlan(dataset.store), /generation plan is incomplete/);
});

function generationStore(body) {
  return new Store(new Parser({ format: 'text/turtle' }).parse(`
@prefix usf: <urn:usf:ontology:> .
${body}
`));
}

const completeGenerator = (name = 'complete') => `
<urn:usf:generator:${name}> a usf:CompilerComponent ;
  usf:semanticInputQuery "SELECT ?resource WHERE { ?resource a <urn:usf:ontology:SemanticContract> . }" ;
  usf:outputSchema <urn:usf:artefact:schema> ;
  usf:outputPathRule <urn:usf:pathrule:${name}> ;
  usf:integrityPolicy <urn:usf:policy:integrity> ;
  usf:normalisationPolicy <urn:usf:policy:normalisation> ;
  usf:missingSemanticsConstraint <urn:usf:constraint:missing> ;
  usf:requiresEquivalenceKind <urn:usf:equivalencekind:semantic> .
<urn:usf:pathrule:${name}> usf:pathPattern "generated/${name}.json" .
`;

test('generation plan rejects missing/multiple output plans, no-output plans, and orphan source-bound plans', () => {
  const store = generationStore(`
<urn:usf:repository:foundation> a usf:Repository .
<urn:usf:artefactplan:a> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:foundation> ; usf:plansArtefact <urn:usf:artefact:a> .
<urn:usf:artefactplan:b> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:foundation> ; usf:plansArtefact <urn:usf:artefact:b> .
<urn:usf:artefact:a> a usf:Artefact ; usf:canonicalPath "generated/a.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:a> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:artefact:b> a usf:Artefact ; usf:canonicalPath "generated/b.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:b> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:pathrule:a> usf:pathPattern "generated/a.json" .
<urn:usf:pathrule:b> usf:pathPattern "generated/b.json" .
${completeGenerator()}
<urn:usf:disposition:missing> a usf:SourceArtefactDisposition ; usf:hasDispositionOutputMode <urn:usf:dispositionoutputmode:canonicaloutput> .
<urn:usf:disposition:multiple> a usf:SourceArtefactDisposition ; usf:hasDispositionOutputMode <urn:usf:dispositionoutputmode:canonicaloutput> ; usf:assignedToArtefactPlan <urn:usf:artefactplan:a>, <urn:usf:artefactplan:b> .
<urn:usf:disposition:nooutput> a usf:SourceArtefactDisposition ; usf:hasDispositionOutputMode <urn:usf:dispositionoutputmode:nooutput> ; usf:assignedToArtefactPlan <urn:usf:artefactplan:a> .
<urn:usf:binding:orphan> a usf:SourceSemanticBinding ; usf:sourceBindingArtefactPlan <urn:usf:artefactplan:orphan> .
`);
  const plan = buildGenerationPlan(store);
  assert.equal(plan.complete, false);
  assert.ok(plan.obligations.some((item) => item.kind === 'output-disposition-plan-cardinality' && item.observed === 0));
  assert.ok(plan.obligations.some((item) => item.kind === 'output-disposition-plan-cardinality' && item.observed === 2));
  assert.ok(plan.obligations.some((item) => item.kind === 'no-output-disposition-has-plan' && item.observed === 1));
  assert.ok(plan.obligations.some((item) => item.kind === 'orphan-source-bound-plan'));
});

test('generation plan rejects zero/multiple plan owners and output paths', () => {
  const store = generationStore(`
<urn:usf:repository:a> a usf:Repository . <urn:usf:repository:b> a usf:Repository .
<urn:usf:artefactplan:noowner> a usf:ArtefactPlan ; usf:plansArtefact <urn:usf:artefact:noowner> .
<urn:usf:artefactplan:multiowner> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:a>, <urn:usf:repository:b> ; usf:plansArtefact <urn:usf:artefact:multiowner> .
<urn:usf:artefactplan:nopath> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:a> ; usf:plansArtefact <urn:usf:artefact:nopath> .
<urn:usf:artefactplan:multipath> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:a> ; usf:plansArtefact <urn:usf:artefact:multipath> .
<urn:usf:artefact:noowner> a usf:Artefact ; usf:canonicalPath "generated/noowner.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:noowner> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:artefact:multiowner> a usf:Artefact ; usf:canonicalPath "generated/multiowner.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:multiowner> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:artefact:nopath> a usf:Artefact ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:nopath> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:artefact:multipath> a usf:Artefact ; usf:canonicalPath "generated/left.json", "generated/right.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:multipath> ; usf:generatedByComponent <urn:usf:generator:complete> .
<urn:usf:pathrule:noowner> usf:pathPattern "generated/noowner.json" .
<urn:usf:pathrule:multiowner> usf:pathPattern "generated/multiowner.json" .
<urn:usf:pathrule:nopath> usf:pathPattern "generated/nopath.json" .
<urn:usf:pathrule:multipath> usf:pathPattern "generated/{side}.json" .
${completeGenerator()}
`);
  const plan = buildGenerationPlan(store);
  assert.ok(plan.obligations.some((item) => item.kind === 'plan-owner-cardinality' && item.observed === 0));
  assert.ok(plan.obligations.some((item) => item.kind === 'plan-owner-cardinality' && item.observed === 2));
  assert.ok(plan.obligations.some((item) => item.kind === 'plan-path-cardinality' && item.observed === 0));
  assert.ok(plan.obligations.some((item) => item.kind === 'plan-path-cardinality' && item.observed === 2));
});

test('generation plan reports an incomplete generator contract', () => {
  const store = generationStore(`
<urn:usf:repository:foundation> a usf:Repository .
<urn:usf:artefactplan:output> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:foundation> ; usf:plansArtefact <urn:usf:artefact:output> .
<urn:usf:artefact:output> a usf:Artefact ; usf:canonicalPath "generated/output.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:output> ; usf:generatedByComponent <urn:usf:generator:incomplete> .
<urn:usf:pathrule:output> usf:pathPattern "generated/output.json" .
<urn:usf:generator:incomplete> a usf:CompilerComponent ; usf:outputSchema <urn:usf:artefact:schema> ; usf:outputPathRule <urn:usf:pathrule:output> ; usf:integrityPolicy <urn:usf:policy:integrity> ; usf:normalisationPolicy <urn:usf:policy:normalisation> ; usf:missingSemanticsConstraint <urn:usf:constraint:missing> ; usf:requiresEquivalenceKind <urn:usf:equivalencekind:semantic> .
`);
  const plan = buildGenerationPlan(store);
  assert.ok(plan.obligations.some((item) => item.kind === 'missing-semantic-input-query'));
  assert.ok(plan.obligations.some((item) => item.kind === 'incomplete-generator' && item.observed.includes('missing-semantic-input-query')));
});

test('generation plan requires executable ownership and detects path collisions', () => {
  const spec = baseSpec();
  spec['providers.ttl'] = `@prefix usf: <urn:usf:ontology:> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<urn:usf:repository:foundation> a usf:Repository .
<urn:usf:artefactplan:a> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:foundation> ; usf:plansArtefact <urn:usf:artefact:a> .
<urn:usf:artefactplan:b> a usf:ArtefactPlan ; usf:ownedByRepository <urn:usf:repository:foundation> ; usf:plansArtefact <urn:usf:artefact:b> .
<urn:usf:artefact:a> a usf:Artefact ; usf:canonicalPath "contracts/index.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:a> ; usf:generatedByComponent <urn:usf:generator:a> .
<urn:usf:artefact:b> a usf:Artefact ; usf:canonicalPath "contracts/index.json" ; usf:artefactKind <urn:usf:artefactkind:contract> ; usf:governedByPathRule <urn:usf:pathrule:b> ; usf:generatedByComponent <urn:usf:generator:a> .
<urn:usf:pathrule:a> usf:pathPattern "contracts/index.json" .
<urn:usf:pathrule:b> usf:pathPattern "contracts/index.json" .
<urn:usf:generator:a> usf:semanticInputQuery "SELECT ?resource WHERE { ?resource a <urn:usf:ontology:SemanticContract> . }" ; usf:outputSchema <urn:usf:artefact:a> ; usf:outputPathRule <urn:usf:pathrule:a> ; usf:integrityPolicy <urn:usf:policy:integrity> ; usf:normalisationPolicy <urn:usf:policy:normalisation> ; usf:missingSemanticsConstraint <urn:usf:constraint:missing> ; usf:requiresEquivalenceKind <urn:usf:equivalencekind:semantic> .
`;
  const plan = buildGenerationPlan(loadAuthorityDataset(loadManifest(writeGraph(spec))).store);
  assert.equal(plan.complete, false);
  assert.ok(plan.obligations.some((item) => item.kind === 'path-collision'));
});

test('live attestation: RDF canonicalization ignores blank-node labels', async () => {
  const left = '_:left <urn:usf:p> "value" .\n';
  const right = '_:unrelated <urn:usf:p> "value" .\n';
  assert.deepEqual(await canonicalGraphDigest(left), await canonicalGraphDigest(right));
});

test('verification: zero readiness fails the verification contract', () => {
  const conforming = {
    reachable: true,
    validationConforms: true,
    integrityConforms: true,
    contaminationCount: 0,
    missingGraphs: [],
    unexpectedGraphs: [],
    readinessCount: 1,
  };
  assert.equal(verificationConforms(conforming), true);
  assert.equal(verificationConforms({ ...conforming, readinessCount: 0 }), false);
  assert.equal(liveAttestationInternals.verificationPasses({
    ...conforming,
    countScope: 'registered-usf-graphs',
  }), true);
  assert.equal(liveAttestationInternals.verificationPasses({
    ...conforming,
    countScope: 'registered-usf-graphs',
    readinessCount: 0,
  }), false);
});

test('live attestation: census-facing totals are explicitly registered-USF scoped', async () => {
  const manifest = loadManifest(writeGraph(baseSpec()));
  const registered = managedGraphs(manifest);
  const report = await verify({
    manifest,
    client: {
      async size() { return 999; },
      async select(query) {
        if (query.includes('GROUP BY ?g')) {
          return [
            ...registered.map((graph) => ({ g: { value: graph }, c: { value: '2' } })),
            { g: { value: 'urn:external:graph' }, c: { value: '100' } },
          ];
        }
        if (query.includes('?violation')) return [];
        if (query.includes('REGEX(CONCAT')) return [{ c: { value: '0' } }];
        if (query.includes('derived:readiness')) return [{ c: { value: '1' } }];
        throw new Error(`unexpected query: ${query}`);
      },
      async validate() { return true; },
    },
  });
  assert.equal(report.databaseGraphCount, registered.length + 1);
  assert.equal(report.databaseTripleCount, 999);
  assert.equal(report.registeredGraphCount, registered.length);
  assert.equal(report.registeredTripleCount, registered.length * 2);
  const projection = liveAttestationInternals.verificationProjection(report);
  assert.equal(projection.countScope, 'registered-usf-graphs');
  assert.equal(projection.graphCount, registered.length);
  assert.equal(projection.tripleCount, registered.length * 2);
  assert.equal(projection.readinessCount, 1);
});

test('live attestation: rollback contract includes explicit activation barriers', () => {
  assert.deepEqual(liveAttestationInternals.requiredRollbackFaults, [
    'clear-graph',
    'collect-observed',
    'commit',
    'contamination',
    'derive',
    'derived-insert',
    'integrity',
    'invalid-observed-rdf',
    'load',
    'rollback-response',
    'validate-authored',
    'validate-derived',
    'validate-observed',
    'verify-counts',
    'wrong-rule-output',
  ]);
});

test('derived snapshot: canonical TriG is deterministic across blank-node labels', async () => {
  const graph = 'urn:usf:graph:derived:test';
  const left = '_:left <urn:usf:p> "value" .\n';
  const right = '_:unrelated <urn:usf:p> "value" .\n';
  assert.equal(await canonicalGraphTrig(graph, left), await canonicalGraphTrig(graph, right));
  assert.match(await canonicalGraphTrig(graph, left), /^GRAPH <urn:usf:graph:derived:test>/);
});

test('UI semantic closure is exact, contract-scoped, and exposure-complete', (t) => {
  if (realGraphAbsent(t)) return;
  const graphDir = REAL_GRAPH_DIR;
  const store = loadAuthorityDataset(loadManifest(graphDir)).store;
  const rdfType = DataFactory.namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
  const usf = (local) => DataFactory.namedNode(`urn:usf:ontology:${local}`);
  const iri = (value) => DataFactory.namedNode(value);
  const values = (terms) => [...new Set(terms.map((term) => term.value))].sort();
  const subjects = (predicate, object) => values(store.getSubjects(predicate, object, null));
  const objects = (subject, predicate) => values(store.getObjects(iri(subject), predicate, null));
  const models = subjects(rdfType, usf('UISemanticModel'));
  const facets = subjects(usf('facetKind'), iri('urn:usf:facetkind:uisemantics'));
  const complete = facets.filter((facet) => objects(facet, usf('facetStatus')).includes('urn:usf:facetstatus:complete'));
  const notApplicable = facets.filter((facet) => objects(facet, usf('facetStatus')).includes('urn:usf:facetstatus:notapplicable'));
  const gaps = facets.filter((facet) => objects(facet, usf('facetStatus')).includes('urn:usf:facetstatus:gap'));
  const requiredNonclaims = [
    'urn:usf:nonclaim:noaccessibilitycompliance',
    'urn:usf:nonclaim:nohumanacceptance',
    'urn:usf:nonclaim:nolaunchi18n',
    'urn:usf:nonclaim:nouiproductparity',
  ];
  const expectedBindings = new Map([
    ['urn:usf:uisemanticmodel:authenticationplatform', {
      operations: ['urn:usf:operation:authloginpost'], permissions: ['urn:usf:permission:authlogin'],
    }],
    ['urn:usf:uisemanticmodel:apikeyspersonalaccesstokens', {
      operations: ['urn:usf:operation:apikeycreate'], permissions: ['urn:usf:permission:apikeycreate'],
    }],
    ['urn:usf:uisemanticmodel:apidocsdeveloperportalsdksratelimits', {
      operations: [], permissions: ['urn:usf:permission:routeaccessnone'],
    }],
    ['urn:usf:uisemanticmodel:enduserprofileandpreferencesselfservice', {
      operations: ['urn:usf:operation:profiledetailget', 'urn:usf:operation:profilelistget'], permissions: ['urn:usf:permission:tenantmembersread'],
    }],
    ['urn:usf:uisemanticmodel:notificationdeliveryandpreferencesandchannels', {
      operations: ['urn:usf:operation:notificationsget', 'urn:usf:operation:notificationslist'], permissions: ['urn:usf:permission:notificationlist', 'urn:usf:permission:notificationread'],
    }],
  ]);

  assert.equal(facets.length, 67);
  assert.equal(complete.length, 5);
  assert.equal(notApplicable.length, 62);
  assert.equal(gaps.length, 0);
  assert.deepEqual(models, [...expectedBindings.keys()].sort());
  assert.equal(notApplicable.filter((facet) => {
    const contract = subjects(usf('declaresFacet'), iri(facet))[0];
    return !objects(contract, usf('semanticLifecycleState')).includes('urn:usf:semanticlifecyclestate:deprecated');
  }).length, 61);

  for (const facet of facets) {
    const contracts = subjects(usf('declaresFacet'), iri(facet));
    assert.equal(contracts.length, 1, `${facet} must have one owning contract`);
    const contract = contracts[0];
    assert.deepEqual(objects(contract, usf('disclaims')).filter((value) => requiredNonclaims.includes(value)), requiredNonclaims);
    const capabilities = subjects(usf('hasContract'), iri(contract));
    assert.equal(capabilities.length, 1, `${contract} must have one owning capability`);
    const capability = capabilities[0];
    const exposure = objects(capability, usf('uiExposure'));
    const capabilityModels = objects(capability, usf('hasUISemanticModel'));
    if (complete.includes(facet)) {
      assert.deepEqual(exposure, ['urn:usf:uiexposureclass:uiexposed']);
      assert.equal(capabilityModels.length, 1);
    } else {
      assert.notEqual(exposure[0], 'urn:usf:uiexposureclass:uiexposed');
      assert.deepEqual(capabilityModels, []);
    }
  }

  for (const model of models) {
    assert.deepEqual(objects(model, usf('disclaims')), [], `${model} must not inherit SemanticContract through disclaims domain`);
    const viewModels = objects(model, usf('hasViewModel'));
    const surfaces = objects(model, usf('hasSurface'));
    const operations = values([
      ...viewModels.flatMap((viewModel) => store.getObjects(iri(viewModel), usf('loadsOperation'), null)),
      ...surfaces.flatMap((surface) => store.getObjects(iri(surface), usf('submitsOperation'), null)),
    ]);
    const permissions = values(surfaces.flatMap((surface) => store.getObjects(iri(surface), usf('uiRequiresPermission'), null)));
    assert.deepEqual(operations, expectedBindings.get(model).operations);
    assert.deepEqual(permissions, expectedBindings.get(model).permissions);
  }
});

test('generation: real authority has no semantic gaps and reuses deterministic incremental outputs', (t) => {
  const graphDir = REAL_GRAPH_DIR;
  const repositoryRoot = join(graphDir, '..');
  // Retained templates are declared with repository-root-relative paths. Inside
  // the clean-room chroot only /usf exists, so template-backed generation
  // cannot run there; skip explicitly rather than fail on a missing source root.
  if (!existsSync(join(repositoryRoot, '.git'))) {
    t.skip('repository source root not present (clean-room chroot); template-backed generation not testable here');
    return;
  }
  const manifest = loadManifest(graphDir);
  const dataset = loadAuthorityDataset(manifest);
  const webQuery = generatorInternals.componentQuery(dataset.store, 'urn:usf:generator:webui');
  const mobileQuery = generatorInternals.componentQuery(dataset.store, 'urn:usf:generator:mobileui');
  assert.deepEqual(webQuery.constraints, [
    { predicate: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type', object: 'urn:usf:ontology:RendererContract' },
    { predicate: 'urn:usf:ontology:rendererTarget', object: 'urn:usf:renderertarget:web' },
  ]);
  assert.deepEqual(mobileQuery.constraints, [
    { predicate: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type', object: 'urn:usf:ontology:RendererContract' },
    { predicate: 'urn:usf:ontology:rendererTarget', object: 'urn:usf:renderertarget:mobile' },
  ]);
  const incompleteOutput = mkdtempSync(join(tmpdir(), 'usf-incomplete-generation-'));
  dirs.push(incompleteOutput);
  const gapStatus = DataFactory.namedNode('urn:usf:facetstatus:gap');
  const facetStatus = DataFactory.namedNode('urn:usf:ontology:facetStatus');
  assert.equal(dataset.store.getQuads(null, facetStatus, gapStatus, null).length, 0);
  assert.throws(
    () => generateAuthority({ store: dataset.store, outputDir: join(incompleteOutput, 'output'), mode: 'full', sourceRoot: repositoryRoot }),
    (error) => error instanceof CompilerError && error.phase === 'generate:signing',
  );
  const semanticKind = DataFactory.namedNode('urn:usf:equivalencekind:semantic');
  const bindingEquivalenceKind = DataFactory.namedNode('urn:usf:ontology:sourceBindingEquivalenceKind');
  dataset.store.removeQuads(dataset.store.getQuads(null, bindingEquivalenceKind, semanticKind, null));
  const generationPlan = requireCompleteGenerationPlan(dataset.store);
  const authenticationOutput = generationPlan.outputs.find((output) => output.path === 'contracts/semantic/authenticationplatform.json');
  const authenticationData = generatorInternals.projection(dataset.store, authenticationOutput, 'a'.repeat(64));
  const bindingPlan = DataFactory.namedNode('urn:usf:ontology:sourceBindingArtefactPlan');
  const authenticationBinding = dataset.store.getSubjects(bindingPlan, DataFactory.namedNode(authenticationOutput.plan), null)[0];
  assert.equal(generatorInternals.semanticContractSourceEquivalence(dataset.store, authenticationOutput, authenticationData, repositoryRoot).structural, true);
  const bindingDigest = DataFactory.namedNode('urn:usf:ontology:sourceBindingContentDigest');
  const expectedBindingDigest = dataset.store.getObjects(authenticationBinding, bindingDigest, null)[0];
  dataset.store.removeQuads(dataset.store.getQuads(authenticationBinding, bindingDigest, null, null));
  dataset.store.addQuad(authenticationBinding, bindingDigest, DataFactory.literal('0'.repeat(64)));
  assert.throws(
    () => generatorInternals.semanticContractSourceEquivalence(dataset.store, authenticationOutput, authenticationData, repositoryRoot),
    (error) => error instanceof CompilerError && error.code === 'USF-SCG-005',
  );
  dataset.store.removeQuads(dataset.store.getQuads(authenticationBinding, bindingDigest, null, null));
  dataset.store.addQuad(authenticationBinding, bindingDigest, expectedBindingDigest);
  dataset.store.addQuad(authenticationBinding, bindingEquivalenceKind, semanticKind);
  assert.throws(
    () => generatorInternals.semanticContractSourceEquivalence(dataset.store, authenticationOutput, authenticationData, repositoryRoot),
    (error) => error instanceof CompilerError && error.code === 'USF-SCG-006' && error.failures.length > 0,
  );
  dataset.store.removeQuads(dataset.store.getQuads(authenticationBinding, bindingEquivalenceKind, semanticKind, null));
  const keys = generateKeyPairSync('ed25519');
  const fingerprint = createHash('sha256').update(keys.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  const identity = DataFactory.namedNode('urn:usf:signingidentity:foundationrelease');
  const predicate = DataFactory.namedNode('urn:usf:ontology:signingKeyFingerprint');
  dataset.store.removeQuads(dataset.store.getQuads(identity, predicate, null, null));
  dataset.store.addQuad(identity, predicate, DataFactory.literal(fingerprint));
  const root = mkdtempSync(join(tmpdir(), 'usf-real-generation-'));
  dirs.push(root);
  const keyPath = join(root, 'signing-key.pem');
  writeFileSync(keyPath, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const templateChecksum = DataFactory.namedNode('urn:usf:checksum:proofanchorworkflowchecksum');
  const checksumValue = DataFactory.namedNode('urn:usf:ontology:checksumValue');
  const expectedChecksum = dataset.store.getObjects(templateChecksum, checksumValue, null)[0];
  dataset.store.removeQuads(dataset.store.getQuads(templateChecksum, checksumValue, null, null));
  dataset.store.addQuad(templateChecksum, checksumValue, DataFactory.literal('0'.repeat(64)));
  assert.throws(
    () => generateAuthority({ store: dataset.store, outputDir: join(root, 'rejected-output'), mode: 'full', signingKeyPath: keyPath, sourceRoot: repositoryRoot }),
    (error) => error instanceof CompilerError && error.phase === 'generate:template-integrity',
  );
  dataset.store.removeQuads(dataset.store.getQuads(templateChecksum, checksumValue, null, null));
  dataset.store.addQuad(templateChecksum, checksumValue, expectedChecksum);
  const outputDir = join(root, 'output');
  const full = generateAuthority({ store: dataset.store, outputDir, mode: 'full', signingKeyPath: keyPath, sourceRoot: repositoryRoot });
  assert.ok(full.outputCount > 0);
  const semanticContractFiles = readdirSync(join(outputDir, 'contracts/semantic')).sort();
  assert.equal(semanticContractFiles.length, 66);
  const generatedContract = JSON.parse(readFileSync(join(outputDir, 'contracts/semantic/authenticationplatform.json'), 'utf8'));
  assert.equal(generatedContract.id, 'urn:usf:semanticcontract:authenticationplatform');
  assert.equal(generatedContract.facets.length, 10);
  assert.ok(generatedContract.facets.every((facet) => facet.status === 'complete' || facet.status === 'notapplicable'));
  assert.equal(generatedContract.sourceEquivalence.structural, true);
  assert.deepEqual(readFileSync(join(outputDir, '.github/workflows/proof-anchor.yml')), readFileSync(join(repositoryRoot, '.github/workflows/proof-anchor.yml')));
  assert.deepEqual(readFileSync(join(outputDir, '.github/workflows/validate-spec.yml')), readFileSync(join(repositoryRoot, '.github/workflows/validate-spec.yml')));
  assert.equal(verifyOutput(outputDir, true, fingerprint).independent.signingIdentityTrusted, true);

  const wrong = generateKeyPairSync('ed25519');
  const wrongPath = join(root, 'wrong-key.pem');
  writeFileSync(wrongPath, wrong.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  assert.throws(
    () => generateAuthority({ store: dataset.store, outputDir, mode: 'incremental', signingKeyPath: wrongPath, sourceRoot: repositoryRoot }),
    (error) => error instanceof CompilerError && error.phase === 'generate:signing-authority',
  );
  assert.equal(verifyOutput(outputDir, true, fingerprint).ok, true);

  const incremental = generateAuthority({ store: dataset.store, outputDir, mode: 'incremental', signingKeyPath: keyPath, sourceRoot: repositoryRoot });
  assert.equal(incremental.aggregateDigest, full.aggregateDigest);
  assert.equal(incremental.changed, 0);
  assert.ok(incremental.reused > 0);
});

test('live attestation: graph comparison reports missing, unexpected and mismatched graphs', () => {
  const source = [
    { graph: 'urn:g:a', sha256: 'a', triples: 1 },
    { graph: 'urn:g:b', sha256: 'b', triples: 2 },
  ];
  const database = [
    { graph: 'urn:g:a', sha256: 'changed', triples: 1 },
    { graph: 'urn:g:c', sha256: 'c', triples: 3 },
  ];
  assert.deepEqual(compareGraphDigests(source, database), {
    missingGraphs: ['urn:g:b'],
    unexpectedGraphs: ['urn:g:c'],
    mismatchedGraphs: ['urn:g:a'],
  });
});
