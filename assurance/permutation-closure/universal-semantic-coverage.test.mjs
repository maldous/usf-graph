import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import N3 from 'n3';

import { canonicalJson, sha256 } from '../semantic-model-compilation/realisation-option-evaluation.mjs';
import {
  analyseUniversalFamilyCompleteness,
  buildExactCoverageWitnessIndex,
  buildUniversalSemanticInventory,
  loadUniversalFamilyRegistry,
  loadUniversalReviewProjection,
  universalSemanticCoverageInternals,
  verifyUniversalAuthorityInputs,
} from './universal-semantic-coverage.mjs';
import {
  proveUniversalSemanticCoverage,
} from './universal-semantic-coverage-proof.mjs';

const O = 'urn:usf:ontology:';
const OWL = 'http://www.w3.org/2002/07/owl#';
const FIXTURE_AUTHORITY_DIGEST = 'sha256:1111111111111111111111111111111111111111111111111111111111111111';
const AUTHORITY_INPUT_PATHS = Object.freeze({
  authorityPacketPath: 'authority-input-packet.json',
  authorityProjectionPath: 'authority-input-projection.json',
});
const digest = (value) => sha256(canonicalJson(value));

function writeJsonFixture(root, relativePath, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  writeFileSync(join(root, relativePath), bytes, { flag: 'wx', mode: 0o600 });
  return sha256(bytes);
}

function createAuthorityInputFixture({
  authorityDigest = FIXTURE_AUTHORITY_DIGEST,
  immutable = true,
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'usf-universal-authority-input-'));
  try {
    const authorityPacketDigest = writeJsonFixture(root, AUTHORITY_INPUT_PATHS.authorityPacketPath, {
      authorityDigest,
      packetSchemaVersion: 1,
      recordKind: 'USF_PERMUTATION_AUTHORITY_INPUT_PACKET',
    });
    const authorityProjectionDigest = writeJsonFixture(root, AUTHORITY_INPUT_PATHS.authorityProjectionPath, {
      authorityDigest,
      basePacketDigest: authorityPacketDigest,
      projectedClassIris: [],
      projectedPredicateIris: [],
      projectionMethod: 'BOUNDED_USF_MCP_SELECT',
      recordKind: 'USF_PERMUTATION_AUTHORITY_PROJECTION',
      schemaVersion: 1,
      triples: [],
    });
    if (immutable) {
      chmodSync(join(root, AUTHORITY_INPUT_PATHS.authorityPacketPath), 0o400);
      chmodSync(join(root, AUTHORITY_INPUT_PATHS.authorityProjectionPath), 0o400);
      chmodSync(root, 0o500);
    }
    const cleanup = () => {
      if (!existsSync(root)) return;
      chmodSync(root, 0o700);
      rmSync(root, { force: true, recursive: true });
    };
    return Object.freeze({
      authorityBinding: Object.freeze({ authorityDigest, authorityPacketDigest, authorityProjectionDigest }),
      cleanup,
      immutable,
      paths: AUTHORITY_INPUT_PATHS,
      root,
    });
  } catch (error) {
    try { chmodSync(root, 0o700); } catch {}
    rmSync(root, { force: true, recursive: true });
    throw error;
  }
}

const authorityInputFixture = createAuthorityInputFixture();
const authorityInputRoot = authorityInputFixture.root;
const AUTHORITY_BINDING = Object.freeze({
  ...authorityInputFixture.authorityBinding,
});
after(authorityInputFixture.cleanup);

function foundationPair(binding = AUTHORITY_BINDING) {
  const shared = {
    fixtureDigest: `sha256:${'1'.repeat(64)}`,
    fixtureInputDigest: `sha256:${'2'.repeat(64)}`,
    fixtureProjectionDigest: `sha256:${'3'.repeat(64)}`,
    foundationStructuralProjectionDigest: `sha256:${'4'.repeat(64)}`,
    foundationStructuralProjectionRecordCount: 1,
    foundationStructuralProjectionRuleSetDigest: `sha256:${'5'.repeat(64)}`,
    metaModelDigest: `sha256:${'6'.repeat(64)}`,
  };
  const assessmentCore = {
    ...shared,
    baselineAuthorityBinding: binding,
    foundationDomainClosureComplete: true,
    foundationVerdict: 'FOUNDATION_DOMAIN_CLOSURE_COMPLETE',
    recordKind: 'USF_FOUNDATION_DOMAIN_CLOSURE_ASSESSMENT',
    schemaVersion: 2,
  };
  const assessment = { ...assessmentCore, assessmentDigest: digest(assessmentCore) };
  const proofCore = {
    ...shared,
    assessmentDigest: assessment.assessmentDigest,
    baselineAuthorityBinding: binding,
    recordKind: 'USF_FOUNDATION_DOMAIN_CLOSURE_INDEPENDENT_PROOF',
    results: { emptyDomainCount: 0, reconstructionMismatchCount: 0 },
    schemaVersion: 2,
    verdict: 'FOUNDATION_DOMAIN_CLOSURE_PROOF_PASS',
  };
  return { assessment, proof: { ...proofCore, proofDigest: digest(proofCore) } };
}

function expectCode(callback, code) {
  assert.throws(callback, (error) => error?.code === code && error.message.startsWith(`${code}:`));
}

function withProjectionDigest(value) {
  const { reviewProjectionDigest: omitted, ...core } = value;
  return { ...core, reviewProjectionDigest: digest(core) };
}

function createReviewPlaneRepository() {
  const root = mkdtempSync(join(tmpdir(), 'usf-universal-review-plane-'));
  const modelRoot = join(root, 'semantic-model');
  const write = (relativePath, bytes) => {
    const path = join(modelRoot, relativePath);
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, bytes);
  };
  write('manifest.yaml', `version: 1
definitionGraphs:
  - { file: ontology.ttl, graph: "urn:usf:graph:test-ontology", loadOrder: 1, validationOrder: 1 }
authoredGraphs:
  - { file: model.trig, graph: "urn:usf:graph:test-model", loadOrder: 2, validationOrder: 2 }
reviewGraphs:
  - { file: permutation/reviews.trig, graph: "urn:usf:graph:test-reviews", loadOrder: 3, validationOrder: 3 }
shapeGraphs: []
rules: []
derivedGraphs: []
`);
  write('ontology.ttl', `@prefix owl: <http://www.w3.org/2002/07/owl#> .
<urn:usf:test:ReviewedClass> a owl:Class .
`);
  write('model.trig', 'GRAPH <urn:usf:graph:test-model> { <urn:usf:test:item> a <urn:usf:test:ReviewedClass> . }\n');
  write('permutation/reviews.trig', `GRAPH <urn:usf:graph:test-reviews> {
  <urn:usf:test:review> a <urn:usf:ontology:SemanticTermPermutationReview> .
}
`);
  write('fixtures/conforming/universal-service-foundation.trig',
    'GRAPH <urn:usf:graph:foundation-conformance-fixture> { <urn:usf:test:fixture> a <urn:usf:test:ReviewedClass> . }\n');
  return {
    root,
    write,
    cleanup: () => rmSync(root, { force: true, recursive: true }),
  };
}

const repositoryRoot = process.cwd();
const authorityInputVerification = verifyUniversalAuthorityInputs({
  authorityBinding: AUTHORITY_BINDING,
  ...AUTHORITY_INPUT_PATHS,
  repositoryRoot: authorityInputRoot,
});
const inventory = buildUniversalSemanticInventory({
  authorityBinding: AUTHORITY_BINDING,
  authorityInputVerification,
  repositoryRoot,
});
const registry = loadUniversalFamilyRegistry({ repositoryRoot });
const reviewProjection = loadUniversalReviewProjection({ inventory, registry, repositoryRoot });
const foundation = foundationPair();
const analysis = analyseUniversalFamilyCompleteness({
  foundationAssessment: foundation.assessment,
  foundationProof: foundation.proof,
  inventory,
  reviewProjection,
  registry,
});

test('authority packet and projection are test-owned, byte-bound and fail closed when absent or modified', () => {
  assert.equal(AUTHORITY_INPUT_PATHS.authorityPacketPath.startsWith('.work/'), false);
  assert.equal(AUTHORITY_INPUT_PATHS.authorityProjectionPath.startsWith('.work/'), false);
  assert.equal(authorityInputRoot.startsWith(join(repositoryRoot, '.work')), false);
  assert.equal(authorityInputVerification.authorityPacket.contentDigest,
    AUTHORITY_BINDING.authorityPacketDigest);
  assert.equal(authorityInputVerification.authorityProjection.contentDigest,
    AUTHORITY_BINDING.authorityProjectionDigest);
  assert.equal(statSync(authorityInputRoot).mode & 0o777, 0o500);
  assert.equal(statSync(join(authorityInputRoot, AUTHORITY_INPUT_PATHS.authorityPacketPath)).mode & 0o777,
    0o400);
  assert.equal(statSync(join(authorityInputRoot, AUTHORITY_INPUT_PATHS.authorityProjectionPath)).mode & 0o777,
    0o400);

  const missing = createAuthorityInputFixture();
  try {
    expectCode(() => verifyUniversalAuthorityInputs({
      authorityBinding: missing.authorityBinding,
      authorityPacketPath: 'absent-authority-input-packet.json',
      authorityProjectionPath: missing.paths.authorityProjectionPath,
      repositoryRoot: missing.root,
    }), 'UNIVERSAL_AUTHORITY_PACKET_INVALID');
    expectCode(() => verifyUniversalAuthorityInputs({
      authorityBinding: missing.authorityBinding,
      authorityPacketPath: missing.paths.authorityPacketPath,
      authorityProjectionPath: 'absent-authority-input-projection.json',
      repositoryRoot: missing.root,
    }), 'UNIVERSAL_AUTHORITY_PROJECTION_INVALID');
  } finally {
    missing.cleanup();
  }

  for (const [field, code] of [
    ['authorityPacketPath', 'UNIVERSAL_AUTHORITY_PACKET_INVALID'],
    ['authorityProjectionPath', 'UNIVERSAL_AUTHORITY_PROJECTION_INVALID'],
  ]) {
    const modified = createAuthorityInputFixture({ immutable: false });
    try {
      writeFileSync(join(modified.root, modified.paths[field]), '{"modified":true}\n');
      expectCode(() => verifyUniversalAuthorityInputs({
        authorityBinding: modified.authorityBinding,
        ...modified.paths,
        repositoryRoot: modified.root,
      }), code);
    } finally {
      modified.cleanup();
    }
  }
});

test('fresh inventory and registry use exact current sources without census or generator reuse', () => {
  const source = readFileSync('assurance/permutation-closure/universal-semantic-coverage.mjs', 'utf8');
  for (const prohibitedImport of [
    "from './family-census.mjs'",
    "from './universe-generator.mjs'",
    "from './universe-proof.mjs'",
  ]) assert.equal(source.includes(prohibitedImport), false, prohibitedImport);

  const replay = buildUniversalSemanticInventory({
    authorityBinding: AUTHORITY_BINDING,
    authorityInputVerification,
    repositoryRoot,
  });
  const registryReplay = loadUniversalFamilyRegistry({ repositoryRoot });
  assert.equal(replay.inventoryDigest, inventory.inventoryDigest);
  assert.equal(registryReplay.registryDigest, registry.registryDigest);
  assert.equal(new Set(inventory.terms.map(({ termKey }) => termKey)).size, inventory.termCount);
  assert.equal(inventory.termCount, inventory.classCount + inventory.propertyCount + inventory.individualCount);
  assert.equal(inventory.sourceRecords.some(({ manifestGroup }) => manifestGroup === 'derivedGraphs'), false);
  assert.deepEqual(inventory.excludedSourceGroups, [
    'conformanceFixture', 'derivedGraphs', 'reviewGraphs', 'rules', 'shapeGraphs',
  ]);
  assert.equal(reviewProjection.schemaVersion, 2);
  assert.equal(reviewProjection.reviewSourceCount, 0);
  assert.deepEqual(reviewProjection.reviewSourceRecords, []);
  assert.equal(reviewProjection.reviewSourceSetDigest, digest([]));
  assert.equal(inventory.semanticInputSourceSetDigest, inventory.sourceSetDigest);
  assert.ok(inventory.individualCount > 0);
  assert.ok(inventory.controlledValueCount > 0);
  assert.ok(inventory.relationshipSignatureCount >= inventory.relationshipCategoryCount);
  assert.ok(inventory.validationDependencyCount > 0);
  assert.equal(authorityInputVerification.fullAuthorityTermParityState,
    'NOT_PROVEN_BY_BOUNDED_PROJECTION');

  assert.ok(inventory.externalStandardBindings.classes.some(({ standardIri, termIri }) => (
    standardIri === 'urn:usf:standard:owl2'
      && termIri === 'http://www.w3.org/2002/07/owl#Class'
  )));
  assert.ok(inventory.externalStandardBindings.properties.some(({ standardIri, termIri }) => (
    standardIri === 'urn:usf:standard:rdf11'
      && termIri === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'
  )));
  assert.equal(inventory.classes.find(({ iri }) => iri === 'http://www.w3.org/2002/07/owl#Class')
    ?.declarationState, 'EXTERNAL_STANDARD_BINDING');
  assert.equal(inventory.properties.find(({ iri }) => iri === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type')
    ?.declarationState, 'EXTERNAL_STANDARD_BINDING');
  assert.deepEqual(inventory.undeclaredClassIris, []);
  assert.deepEqual(inventory.undeclaredPredicateIris, []);

  const familyQuads = new N3.Parser({ format: 'application/trig' }).parse(readFileSync(
    'semantic-model/permutation/families.trig', 'utf8',
  ));
  const typedCount = (className) => new Set(familyQuads.filter(({ predicate, object }) => (
    predicate.value === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'
      && object.value === `${O}${className}`
  )).map(({ subject }) => subject.value)).size;
  assert.equal(registry.familyCount, typedCount('PermutationFamily'));
  assert.equal(registry.dimensionCount, typedCount('PermutationDimension'));
  assert.equal(registry.familyCount, registry.families.length);
  assert.equal(registry.dimensionCount, registry.dimensions.length);
  assert.equal(registry.families.every(({ orderedBindings }) => orderedBindings.length > 0), true);
  for (const family of registry.families) {
    const authoredBindingIris = familyQuads.filter(({ subject, predicate }) => (
      subject.value === family.familyIri && predicate.value === `${O}hasFamilyDimensionBinding`
    )).map(({ object }) => object.value).sort();
    assert.deepEqual(family.orderedBindings.map(({ bindingIri }) => bindingIri).sort(), authoredBindingIris,
      `${family.familyIri} must retain exact authored binding IRIs`);
  }
});

test('review graph bytes are separately bound and cannot recursively alter semantic inventory', () => {
  const fixture = createReviewPlaneRepository();
  try {
    const firstInventory = buildUniversalSemanticInventory({
      authorityBinding: AUTHORITY_BINDING,
      authorityInputVerification,
      repositoryRoot: fixture.root,
    });
    const candidateRegistry = { registryDigest: `sha256:${'7'.repeat(64)}` };
    const firstReview = loadUniversalReviewProjection({
      inventory: firstInventory,
      registry: candidateRegistry,
      repositoryRoot: fixture.root,
    });
    assert.equal(firstReview.reviewSourceCount, 1);
    assert.equal(firstReview.reviewSourceRecords[0].manifestGroup, 'reviewGraphs');
    assert.deepEqual(firstReview.termReviews[0].sourcePlanes, ['reviewGraphs']);
    assert.equal(firstInventory.sourceRecords.some(({ manifestGroup }) => (
      manifestGroup === 'reviewGraphs'
    )), false);

    fixture.write('permutation/reviews.trig', `GRAPH <urn:usf:graph:test-reviews> {
  <urn:usf:test:review> a <urn:usf:ontology:SemanticTermPermutationReview>;
    <urn:usf:ontology:termPermutationReasonCode> "changed-review-bytes" .
}
`);
    const secondInventory = buildUniversalSemanticInventory({
      authorityBinding: AUTHORITY_BINDING,
      authorityInputVerification,
      repositoryRoot: fixture.root,
    });
    const secondReview = loadUniversalReviewProjection({
      inventory: secondInventory,
      registry: candidateRegistry,
      repositoryRoot: fixture.root,
    });
    assert.equal(secondInventory.inventoryDigest, firstInventory.inventoryDigest);
    assert.notEqual(secondReview.reviewSourceSetDigest, firstReview.reviewSourceSetDigest);
    assert.notEqual(secondReview.reviewProjectionDigest, firstReview.reviewProjectionDigest);

    fixture.write('model.trig', `GRAPH <urn:usf:graph:test-model> {
  <urn:usf:test:item> a <urn:usf:test:ReviewedClass> .
  <urn:usf:test:misplaced-review> a <urn:usf:ontology:SemanticTermPermutationReview> .
}
`);
    const misplacedInventory = buildUniversalSemanticInventory({
      authorityBinding: AUTHORITY_BINDING,
      authorityInputVerification,
      repositoryRoot: fixture.root,
    });
    expectCode(() => loadUniversalReviewProjection({
      inventory: misplacedInventory,
      registry: candidateRegistry,
      repositoryRoot: fixture.root,
    }), 'UNIVERSAL_REVIEW_RESOURCE_PLANE_INVALID');
  } finally {
    fixture.cleanup();
  }
});

test('fresh analysis partitions every term but remains fail-closed while reviews are absent', () => {
  assert.equal(analysis.verdict, 'UNIVERSAL_FAMILY_MODEL_INCOMPLETE');
  assert.equal(analysis.gapCount, analysis.gaps.length);
  assert.ok(analysis.gapCount > 0);
  assert.equal(analysis.termDispositions.length, inventory.termCount);
  assert.equal(new Set(analysis.termDispositions.map(({ termKey }) => termKey)).size, inventory.termCount);
  assert.equal(Object.values(analysis.termDispositionPartition)
    .reduce((sum, count) => sum + count, 0), inventory.termCount);
  assert.equal(analysis.registeredFamilyModelReview.missingReviewCount, registry.familyCount);
  assert.equal(analysis.registeredFamilyModelReview.exactReviewCount, 0);
  assert.equal(analysis.registeredReviewCoverage.coverageState, 'COVERAGE_MISSING');
  assert.equal(analysis.reviewProjectionDigest, reviewProjection.reviewProjectionDigest);
  assert.equal(analysis.registeredFamilyModelReview.rows.every(({ reviewState }) => (
    reviewState === 'REVIEW_MISSING'
  )), true);
  assert.equal(analysis.gaps.filter(({ code }) => (
    code === 'UNIVERSAL_REGISTERED_FAMILY_REVIEW_MISSING'
  )).length, registry.familyCount);
  assert.equal(analysis.nonClaims.includes('NOT_SEMANTIC_AUTHORITY'), true);

  const termKeys = new Set(inventory.terms.map(({ termKey }) => termKey));
  assert.equal(analysis.witnesses.every(({ termKey }) => termKeys.has(termKey)), true);
  assert.equal(analysis.witnesses.some(({ role }) => /SUPER|REVERSE|SUBSUM/u.test(role)), false);
  assert.equal(analysis.atomicCandidates.every((candidate) => (
    candidate.candidateIri === `urn:usf:permutationfamilycandidate:${candidate.candidateDigest.slice(7)}`
      && candidate.classification === 'AUTHORITY_REVIEW_REQUIRED'
      && candidate.reasonCode === 'UNIVERSAL_RELATIONSHIP_SIGNATURE_UNDISPOSITIONED'
      && ['DATATYPE_RELATIONSHIP', 'OBJECT_RELATIONSHIP'].includes(candidate.candidateKind)
  )), true);

  const replay = analyseUniversalFamilyCompleteness({
    foundationAssessment: foundation.assessment,
    foundationProof: foundation.proof,
    inventory,
    reviewProjection,
    registry,
  });
  assert.equal(replay.analysisDigest, analysis.analysisDigest);
  assert.equal(replay.gapSetDigest, analysis.gapSetDigest);
});

test('review projection is mandatory and one exact family review closes only its own review gap', () => {
  expectCode(() => analyseUniversalFamilyCompleteness({
    foundationAssessment: foundation.assessment,
    foundationProof: foundation.proof,
    inventory,
    registry,
  }), 'UNIVERSAL_REVIEW_PROJECTION_INVALID');

  const countMismatch = withProjectionDigest({
    ...reviewProjection,
    familySignatureReviewCount: 1,
  });
  expectCode(() => analyseUniversalFamilyCompleteness({
    foundationAssessment: foundation.assessment,
    foundationProof: foundation.proof,
    inventory,
    registry,
    reviewProjection: countMismatch,
  }), 'UNIVERSAL_REVIEW_PROJECTION_INVALID');

  const family = registry.families[0];
  const decisionCore = {
    applicabilityRuleIri: family.ruleIri,
    authorityDigest: AUTHORITY_BINDING.authorityDigest,
    dimensionBindingIris: family.orderedBindings.map(({ bindingIri }) => bindingIri).sort(),
    dispositionIri: 'urn:usf:permutationfamilymodelreviewdisposition:warranted',
    familyIri: family.familyIri,
    registryDigest: registry.registryDigest,
    signatureDigest: family.familyRecordDigest,
    subjectRegistrationIri: family.registrationIri,
  };
  const reviewRecordCore = {
    applicabilityRuleIris: [family.ruleIri],
    authorityDigests: [AUTHORITY_BINDING.authorityDigest],
    dimensionBindingIris: decisionCore.dimensionBindingIris,
    dispositionIris: [decisionCore.dispositionIri],
    familyIris: [family.familyIri],
    registryDigests: [registry.registryDigest],
    reviewDigests: [digest(decisionCore)],
    reviewIri: 'urn:usf:test:family-signature-review:one',
    signatureDigests: [family.familyRecordDigest],
    sourcePlanes: ['reviewGraphs'],
    subjectRegistrationIris: [family.registrationIri],
  };
  const reviewRecord = {
    ...reviewRecordCore,
    projectionRecordDigest: digest(reviewRecordCore),
  };
  const oneReview = withProjectionDigest({
    ...reviewProjection,
    familySignatureReviewCount: 1,
    familySignatureReviews: [reviewRecord],
  });
  const result = analyseUniversalFamilyCompleteness({
    foundationAssessment: foundation.assessment,
    foundationProof: foundation.proof,
    inventory,
    registry,
    reviewProjection: oneReview,
  });
  assert.equal(result.registeredFamilyModelReview.exactReviewCount, 1);
  assert.equal(result.registeredFamilyModelReview.missingReviewCount, registry.familyCount - 1);
  assert.equal(result.registeredFamilyModelReview.rows.find(({ familyIri }) => (
    familyIri === family.familyIri
  )).reviewState, 'REVIEW_CURRENT');
  assert.equal(result.gaps.some(({ code, familyIri }) => (
    code === 'UNIVERSAL_REGISTERED_FAMILY_REVIEW_MISSING' && familyIri === family.familyIri
  )), false);

  const duplicateCore = {
    ...reviewRecordCore,
    reviewIri: 'urn:usf:test:family-signature-review:two',
  };
  const duplicate = { ...duplicateCore, projectionRecordDigest: digest(duplicateCore) };
  const duplicateProjection = withProjectionDigest({
    ...reviewProjection,
    familySignatureReviewCount: 2,
    familySignatureReviews: [reviewRecord, duplicate],
  });
  const duplicateResult = analyseUniversalFamilyCompleteness({
    foundationAssessment: foundation.assessment,
    foundationProof: foundation.proof,
    inventory,
    registry,
    reviewProjection: duplicateProjection,
  });
  assert.equal(duplicateResult.registeredFamilyModelReview.rows.find(({ familyIri }) => (
    familyIri === family.familyIri
  )).reviewState, 'REVIEW_DUPLICATE');
  assert.equal(duplicateResult.gaps.some(({ code, familyIri }) => (
    code === 'UNIVERSAL_REGISTERED_FAMILY_REVIEW_DUPLICATE' && familyIri === family.familyIri
  )), true);
});

test('a non-axis term review cannot override exact family coverage', () => {
  const term = {
    activeOccurrenceCount: 1,
    declarationKindIris: [`${OWL}Class`],
    fixtureOccurrenceCount: 0,
    iri: `${O}SyntheticReviewedClass`,
    sourcePaths: ['semantic-model/ontology.ttl'],
    termKey: `class\0${O}SyntheticReviewedClass`,
    termKind: 'class',
    termUsageStateIris: [],
  };
  const reviewCore = {
    authorityDigest: AUTHORITY_BINDING.authorityDigest,
    axisBindingIri: 'urn:usf:permutationaxisbindingclassification:notanaxis',
    familyCandidateStateIri: 'urn:usf:permutationfamilycandidateclassification:notafamilycandidate',
    inventoryDigest: `sha256:${'8'.repeat(64)}`,
    participationIri: 'urn:usf:permutationparticipationclassification:metadataprovenancenonaxis',
    reasonCode: 'UNIVERSAL_SYNTHETIC_NON_AXIS',
    reviewedTermIri: term.iri,
    sourcePlane: 'definitionGraphs',
  };
  const review = {
    authorityDigests: [reviewCore.authorityDigest],
    axisBindingIris: [reviewCore.axisBindingIri],
    familyCandidateStateIris: [reviewCore.familyCandidateStateIri],
    inventoryDigests: [reviewCore.inventoryDigest],
    participationIris: [reviewCore.participationIri],
    reasonCodes: [reviewCore.reasonCode],
    reviewDigests: [digest(reviewCore)],
    reviewIri: 'urn:usf:test:term-review:conflict',
    reviewedTermIris: [reviewCore.reviewedTermIri],
    sourcePlanes: ['reviewGraphs'],
    statedSourcePlanes: [reviewCore.sourcePlane],
  };
  const result = universalSemanticCoverageInternals.termDispositions({
    authorityBinding: AUTHORITY_BINDING,
    inventoryDigest: reviewCore.inventoryDigest,
    sourceRecords: [{ manifestGroup: 'definitionGraphs', path: 'semantic-model/ontology.ttl' }],
    terms: [term],
  }, {
    records: [{ role: 'EXACT_FAMILY_SUBJECT_ROOT', termKey: term.termKey, witnessDigest: `sha256:${'9'.repeat(64)}` }],
  }, { termReviews: [review] });
  assert.equal(result.dispositions[0].disposition, 'AUTHORITY_REVIEW_REQUIRED');
  assert.equal(result.dispositions[0].reviewClosureState, 'CONFLICT');
  assert.equal(result.gaps.some(({ code }) => (
    code === 'UNIVERSAL_TERM_REVIEW_CONTRADICTS_EXACT_COVERAGE'
  )), true);
});

test('independent proof reconstructs full subject-local family semantics and rejects exact substitutions', () => {
  const input = {
    algorithmSourceDigest: digest('universal-semantic-coverage-proof-test'),
    analysis,
    authorityBinding: AUTHORITY_BINDING,
    authorityInputRoot,
    ...AUTHORITY_INPUT_PATHS,
    foundationAssessment: foundation.assessment,
    foundationProof: foundation.proof,
    inventory,
    reviewProjection,
    registry,
    repositoryRoot,
  };
  const proof = proveUniversalSemanticCoverage(input);
  assert.equal(proof.verdict, 'UNIVERSAL_SEMANTIC_GAP_AND_CROSS_PRODUCT_RECONSTRUCTION_PASS');
  assert.equal(proof.results.familyReconstructionMismatchCount, 0);
  assert.equal(proof.results.reviewSourceReconstructionMismatchCount, 0);
  assert.equal(proof.reviewSourceSetDigest, reviewProjection.reviewSourceSetDigest);

  const reviewSourceTamper = withProjectionDigest({
    ...reviewProjection,
    reviewSourceSetDigest: `sha256:${'a'.repeat(64)}`,
  });
  const { analysisDigest: omittedAnalysisDigest, ...tamperedAnalysisCore } = {
    ...analysis,
    reviewProjectionDigest: reviewSourceTamper.reviewProjectionDigest,
  };
  const tamperedAnalysis = {
    ...tamperedAnalysisCore,
    analysisDigest: digest(tamperedAnalysisCore),
  };
  expectCode(() => proveUniversalSemanticCoverage({
    ...input,
    analysis: tamperedAnalysis,
    reviewProjection: reviewSourceTamper,
  }), 'UNIVERSAL_PROOF_REVIEW_SOURCE_BINDING_MISMATCH');

  for (const [field, code] of [
    ['authorityPacketPath', 'UNIVERSAL_PROOF_AUTHORITY_PACKET_INVALID'],
    ['authorityProjectionPath', 'UNIVERSAL_PROOF_AUTHORITY_PROJECTION_INVALID'],
  ]) {
    const modified = createAuthorityInputFixture({ immutable: false });
    try {
      writeFileSync(join(modified.root, modified.paths[field]), '{"modified":true}\n');
      expectCode(() => proveUniversalSemanticCoverage({
        ...input,
        authorityInputRoot: modified.root,
      }), code);
    } finally {
      modified.cleanup();
    }
  }

  const rebound = (mutate) => {
    const candidate = structuredClone(registry);
    mutate(candidate);
    const { registryDigest: omittedDigest, ...core } = candidate;
    candidate.registryDigest = digest(core);
    return candidate;
  };
  const target = registry.families[0];
  const subjectDonor = registry.families.find(({ subjectClassIri }) => (
    subjectClassIri !== target.subjectClassIri
  ));
  const applicabilityDonor = registry.families.find(({ ruleIri }) => ruleIri !== target.ruleIri);
  assert.ok(subjectDonor);
  assert.ok(applicabilityDonor);
  const substitutions = [
    ['UNIVERSAL_PROOF_FAMILY_IDENTITY_SUBSTITUTION', (candidate) => {
      [candidate.families[0].familyIri, candidate.families[1].familyIri]
        = [candidate.families[1].familyIri, candidate.families[0].familyIri];
    }],
    ['UNIVERSAL_PROOF_SUBJECT_SUBSTITUTION', (candidate) => {
      candidate.families[0].planeIri = subjectDonor.planeIri;
      candidate.families[0].registrationIri = subjectDonor.registrationIri;
      candidate.families[0].subjectClassClosure = structuredClone(subjectDonor.subjectClassClosure);
      candidate.families[0].subjectClassIri = subjectDonor.subjectClassIri;
    }],
    ['UNIVERSAL_PROOF_APPLICABILITY_SUBSTITUTION', (candidate) => {
      candidate.families[0].ruleDigest = applicabilityDonor.ruleDigest;
      candidate.families[0].ruleIri = applicabilityDonor.ruleIri;
      candidate.families[0].applicabilitySelectors = structuredClone(
        applicabilityDonor.applicabilitySelectors,
      );
    }],
    ['UNIVERSAL_PROOF_BINDING_SUBSTITUTION', (candidate) => {
      candidate.families[0].orderedBindings[0].bindingIri
        = candidate.families[0].orderedBindings[1].bindingIri;
    }],
    ['UNIVERSAL_PROOF_AXIS_SUBSTITUTION', (candidate) => {
      const donor = candidate.families[0].orderedBindings[1];
      candidate.families[0].orderedBindings[0].axisClassClosures
        = structuredClone(donor.axisClassClosures);
      candidate.families[0].orderedBindings[0].dimensionIri = donor.dimensionIri;
      candidate.families[0].orderedBindings[0].key = donor.key;
    }],
    ['UNIVERSAL_PROOF_DERIVATION_SUBSTITUTION', (candidate) => {
      const targetBinding = candidate.families[0].orderedBindings[0];
      const donor = candidate.families[0].orderedBindings[1];
      for (const field of [
        'derivationPredicateIris', 'sourceIri', 'sourceKind', 'sourceScopeIri',
        'valueDerivationRootIri', 'valueSourceDigest',
      ]) targetBinding[field] = structuredClone(donor[field]);
    }],
    ['UNIVERSAL_PROOF_PATH_SUBSTITUTION', (candidate) => {
      candidate.families[0].orderedBindings[0].selector
        = structuredClone(candidate.families[0].orderedBindings[1].selector);
    }],
  ];
  for (const [code, mutate] of substitutions) {
    expectCode(() => proveUniversalSemanticCoverage({
      ...input,
      registry: rebound(mutate),
    }), code);
  }
});

test('exact external standard dependencies fail closed when either bound term disappears', () => {
  for (const termKey of [
    'class\0http://www.w3.org/2002/07/owl#Class',
    'property\0http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
  ]) {
    const broken = structuredClone(inventory);
    broken.terms = broken.terms.filter((term) => term.termKey !== termKey);
    expectCode(
      () => buildExactCoverageWitnessIndex(broken, registry),
      'UNIVERSAL_COVERAGE_WITNESS_TERM_UNDECLARED',
    );
  }
});

test('atomic relationship discovery is mechanical and ambiguity has a distinct diagnostic', () => {
  const base = {
    activeOccurrenceCount: 1,
    objectClassIris: [`${O}Interface`],
    objectDatatypeIri: null,
    objectTermKind: 'NamedNode',
    predicateIri: `${O}syntheticUncoveredRelationship`,
    relationshipSignatureDigest: `sha256:${'7'.repeat(64)}`,
    relationshipSignatureIri: `urn:usf:relationshipsignature:${'7'.repeat(64)}`,
    subjectClassIris: [`${O}Capability`],
  };
  const current = universalSemanticCoverageInternals.discoverAtomicRelationshipCandidates({
    authorityBinding: AUTHORITY_BINDING,
    inventoryDigest: inventory.inventoryDigest,
    relationshipSignatures: [base],
  }, new Map());
  assert.equal(current.candidates.length, 1);
  assert.equal(current.gaps.length, 0);

  const ambiguous = universalSemanticCoverageInternals.discoverAtomicRelationshipCandidates({
    authorityBinding: AUTHORITY_BINDING,
    inventoryDigest: inventory.inventoryDigest,
    relationshipSignatures: [{ ...base, objectClassIris: [`${O}Interface`, `${O}Port`] }],
  }, new Map());
  assert.equal(ambiguous.candidates.length, 0);
  assert.deepEqual(ambiguous.gaps.map(({ code }) => code), [
    'UNIVERSAL_ATOMIC_CANDIDATE_ENDPOINT_AMBIGUOUS',
  ]);
});

test('foundation and authority bindings fail with exact reasons', () => {
  expectCode(() => analyseUniversalFamilyCompleteness({
    foundationAssessment: foundation.assessment,
    foundationProof: null,
    inventory,
    reviewProjection,
    registry,
  }), 'UNIVERSAL_FOUNDATION_PROOF_REQUIRED');

  const stale = foundationPair({
    ...AUTHORITY_BINDING,
    authorityDigest: `sha256:${'f'.repeat(64)}`,
  });
  expectCode(() => analyseUniversalFamilyCompleteness({
    foundationAssessment: stale.assessment,
    foundationProof: stale.proof,
    inventory,
    reviewProjection,
    registry,
  }), 'UNIVERSAL_FOUNDATION_PROOF_BINDING_MISMATCH');

  const corruptProof = { ...foundation.proof, proofDigest: `sha256:${'0'.repeat(64)}` };
  expectCode(() => analyseUniversalFamilyCompleteness({
    foundationAssessment: foundation.assessment,
    foundationProof: corruptProof,
    inventory,
    reviewProjection,
    registry,
  }), 'UNIVERSAL_FOUNDATION_PROOF_REQUIRED');
});
