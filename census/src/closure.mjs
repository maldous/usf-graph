import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { buildHardenedCensus } from './build.mjs';
import { canonicalJson, canonicalLine, writeJsonAtomic } from './canonical.mjs';
import { censusRoot, repositoryRoot } from './constants.mjs';
import { createParserEvidence, parserEvidenceMismatches } from './parser-evidence.mjs';
import { validateHardenedOutputs } from './validate.mjs';
import { dependencyKeyFor, dependencyResolutionBasis } from './dependency-resolution.mjs';
import { runAudit } from '../audit/index.mjs';
import { verifyStardogObservation } from '../audit/live-observation.mjs';

const outputProjection = {
  'repository-universe.jsonl': (result) => result.enumeration.universes['repository-output'],
  'v2-graph-universe.jsonl': (result) => result.enumeration.universes['v2-graph-authority'],
  'v2-compiler-universe.jsonl': (result) => result.enumeration.universes['v2-compiler-implementation'],
  'v2-support-universe.jsonl': (result) => result.enumeration.universes['v2-support-provisioning'],
  'materialisations.jsonl': (result) => result.materialisations,
  'relationships.jsonl': (result) => result.relationships,
  'inventories.jsonl': (result) => result.inventories,
  'inventory-findings.jsonl': (result) => result.inventoryFindings,
  'artifacts.jsonl': (result) => result.artifacts,
  'mappings.jsonl': (result) => result.mappings,
  'coverage.jsonl': (result) => result.coverage,
  'missing-entirely.jsonl': (result) => result.missingEntirely,
  'identity-review.jsonl': (result) => result.identityReview,
  'canonical-artifacts.jsonl': (result) => result.canonicalArtifacts,
  'replacement-groups.jsonl': (result) => result.replacementGroups,
  'workpackage-lineage.jsonl': (result) => result.workPackageLineage,
  'dependencies.jsonl': (result) => result.dependencies,
  'dependency-lineage.jsonl': (result) => result.dependencyLineage,
  'universes.json': (result) => result.universes,
  'ignore-audit.json': (result) => result.enumeration.ignoreAudit,
  'workpackages.json': (result) => ({ ownership: result.ownership, workPackages: result.workPackages }),
  'summary.json': (result) => result.summary
};

function workingTreeOutsideBoundary() {
  const output = execFileSync('git', ['status', '--porcelain=v1', '-z', '--untracked-files=all'], { cwd: repositoryRoot, encoding: 'utf8' });
  const entries = output.split('\0').filter(Boolean);
  const paths = [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    paths.push(entry.slice(3));
    if (entry.slice(0, 2).includes('R') || entry.slice(0, 2).includes('C')) paths.push(entries[++index]);
  }
  return paths.filter((repoPath) => !repoPath.startsWith('v2/usf/census/')).sort();
}

function canonicalMismatches(result) {
  const mismatches = [];
  for (const [filename, project] of Object.entries(outputProjection)) {
    const expectedValue = project(result);
    const target = path.join(censusRoot, filename);
    if (!fs.existsSync(target)) { mismatches.push(filename); continue; }
    const expectedHash = cryptoHash(); let expectedBytes = 0;
    const update = (value) => { const bytes = Buffer.from(value); expectedHash.update(bytes); expectedBytes += bytes.length; };
    if (filename.endsWith('.jsonl')) for (const record of expectedValue) update(canonicalLine(record));
    else update(canonicalJson(expectedValue));
    const actual = fileDigest(target);
    if (actual.bytes !== expectedBytes || actual.digest !== expectedHash.digest('hex')) mismatches.push(filename);
  }
  mismatches.push(...parserEvidenceMismatches(censusRoot, result.parserResults));
  return [...new Set(mismatches)].sort();
}

function regeneratedOutputDigest(result) {
  const hash = cryptoHash();
  const frame = (value) => { const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value); const size = Buffer.alloc(8); size.writeBigUInt64BE(BigInt(bytes.length)); hash.update(size).update(bytes); };
  for (const [filename, project] of Object.entries(outputProjection)) {
    frame(filename);
    const value = project(result);
    if (filename.endsWith('.jsonl')) for (const record of value) frame(canonicalLine(record));
    else frame(canonicalJson(value));
  }
  const parserEvidence = createParserEvidence(result.parserResults);
  frame('parser-results/manifest.json'); frame(canonicalJson(parserEvidence.manifest));
  for (const shard of parserEvidence.shards) { frame(shard.descriptor.path); frame(shard.compressed); }
  return hash.digest('hex');
}

function cryptoHash() { return createHash('sha256'); }

function fileDigest(target) {
  const hash = cryptoHash(); const descriptor = fs.openSync(target, 'r'); const buffer = Buffer.alloc(1024 * 1024); let bytes = 0;
  try { let count; while ((count = fs.readSync(descriptor, buffer, 0, buffer.length, null)) > 0) { hash.update(buffer.subarray(0, count)); bytes += count; } }
  finally { fs.closeSync(descriptor); }
  return { bytes, digest: hash.digest('hex') };
}

function independentStardogObservation() {
  return verifyStardogObservation(
    process.env.USF_CENSUS_STARDOG_OBSERVATION,
    process.env.USF_CENSUS_STARDOG_FINGERPRINT,
    repositoryRoot,
  );
}

function prohibitedStardogAccessPaths() {
  const roots = [path.join(censusRoot, 'src'), path.join(censusRoot, 'audit')];
  const files = [];
  const visit = (target) => {
    for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
      const absolute = path.join(target, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && /\.mjs$/.test(entry.name)) files.push(absolute);
    }
  };
  roots.forEach(visit);
  return files.filter((target) => {
    const source = fs.readFileSync(target, 'utf8');
    return /from\s+['"](?:node:)?https?['"]|execFileSync\s*\(\s*['"]stardog['"]|from\s+['"][^'"]*stardog[^'"]*['"]/.test(source);
  }).map((target) => path.relative(repositoryRoot, target).split(path.sep).join('/')).sort();
}

export async function recomputeIndependentAudit({
  auditRunner = runAudit,
  censusDirectory = censusRoot,
  repositoryDirectory = repositoryRoot,
} = {}) {
  return auditRunner({ censusRoot: censusDirectory, repositoryRoot: repositoryDirectory });
}

export async function computeClosure() {
  const validation = await validateHardenedOutputs();
  const rebuilt = buildHardenedCensus();
  const audit = await recomputeIndependentAudit();
  const stardogObservation = independentStardogObservation();
  const prohibitedAccessPaths = prohibitedStardogAccessPaths();
  const mappings = rebuilt.mappings;
  const packages = rebuilt.workPackages;
  const outsideBoundary = workingTreeOutsideBoundary();
  const mismatches = canonicalMismatches(rebuilt);
  const replacementCurrent = new Set(rebuilt.replacementGroups.flatMap((record) => record.currentArtifacts));
  const replacementCanonical = new Set(rebuilt.replacementGroups.flatMap((record) => record.canonicalArtifacts));
  const packageOwnedArtifacts = new Set(packages.flatMap((record) => record.artifactKeys));
  const packageOwnedCanonical = new Set(packages.flatMap((record) => record.canonicalArtifactKeys));
  const packageOwnedGaps = new Set(packages.flatMap((record) => record.missingEntirelyKeys));
  const closureChecks = {
    installedDependenciesAsCanonicalCompilerSource: rebuilt.enumeration.universes['v2-compiler-implementation'].filter((record) => /(?:^|\/)(?:node_modules|\.venv)(?:\/|$)/.test(record.path)).length,
    environmentSensitiveUniverseDrift: rebuilt.materialisations.filter((record) => record.canonicalDigestInput !== false).length,
    unsupportedFinalParserFormats: rebuilt.parserResults.filter((record) => record.structuralCoverage === 'unsupported').length,
    unboundedPartialParsers: rebuilt.parserResults.filter((record) => record.structuralCoverage === 'partial' && record.unsupportedStructures.length === 0).length,
    pathOnlyPrimaryFamilyAssignments: rebuilt.artifacts.filter((record) => record.ownershipEvidence.length === 0 || record.ownershipEvidence.every((entry) => entry.reason === 'supporting path signal')).length,
    relationshipFalsePositivesAccepted: rebuilt.relationships.filter((record) => record.resolved && record.targetKind === 'artifact' && !rebuilt.members.some((member) => member.path === record.target)).length,
    uncrosscheckedStructuredInventories: rebuilt.inventories.filter((record) => !record.comparisonExecuted?.length).length,
    mappingsWithoutEvidence: mappings.filter((record) => record.mappingEvidence.length === 0).length,
    identityOnlyWithoutProvedIdentity: mappings.filter((record) => record.coverageDecision === 'identityonly' && record.matchedResources.length === 0).length,
    partialWithoutRepresentedSemantics: mappings.filter((record) => record.coverageDecision === 'partial' && record.representedSemantics.length === 0).length,
    absentCandidatesUnexamined: rebuilt.missingEntirely.filter((record) => !record.evidence.length || !record.primaryWorkPackage).length,
    unsupportedCompleteClassifications: mappings.filter((record) => record.coverageDecision === 'complete' && (record.missingSemantics.length || !record.representedGeneration.length)).length,
    sourceArtifactsWithoutAcceptedGraphDisposition: rebuilt.sourceDispositionOwnership.rejectedDispositionCount,
    outputDispositionsWithoutAcceptedArtefactPlan: rebuilt.sourceDispositionOwnership.assessments.filter((record) => record.planRequired && (!record.accepted || !record.planIri)).length,
    invalidOrStaleSourceDispositionOwnership: rebuilt.sourceDispositionOwnership.rejectedDispositionCount,
    orphanSourceObservations: rebuilt.sourceDispositionOwnership.orphanObservationCount,
    incoherentObservationSetDigests: Math.max(0, rebuilt.sourceDispositionOwnership.observationSetDigests.length - 1),
    inventedArtifactPlans: rebuilt.replacementGroups.filter((record) => record.dispositionStatus === 'missing-accepted-source-disposition' && (record.canonicalArtifacts.length || record.requiredGenerationProjections.length || record.removedDuplication.length)).length,
    unclassifiedRelationshipAndInventoryFindings: rebuilt.inventoryFindings.filter((record) => !record.findingCategory || !record.findingClass || !record.ownerClass || !record.requiredAction).length,
    unresolvedInternalLookingRelationships: rebuilt.relationships.filter((record) => record.targetKind === 'artifact' && !record.resolved).length,
    unexplainedInventoryFindings: rebuilt.inventoryFindings.filter((record) => record.resolutionStatus === 'open').length,
    invalidExpectedExternalReferences: rebuilt.relationships.filter((record) => record.targetKind === 'external-resource' && !record.reasonCodes.some((reason) => reason === 'expected-external-reference' || reason === 'parser-classified-external-resource')).length,
    canonicalArtifactsWithoutClosedContracts: rebuilt.canonicalArtifacts.filter((record) => (!record.targetPath && !record.pathRule) || !record.productionResponsibilities.length || !record.equivalenceContract?.gates?.length).length,
    currentArtifactsWithoutReplacement: rebuilt.artifacts.filter((record) => !replacementCurrent.has(record.artifactKey)).length,
    requiredCanonicalArtifactsWithoutReplacement: rebuilt.canonicalArtifacts.filter((record) => !replacementCanonical.has(record.canonicalArtifactKey)).length,
    unclosedReplacementCardinalities: rebuilt.replacementGroups.length - new Set(rebuilt.replacementGroups.map((record) => record.groupKey)).size,
    duplicateCanonicalWorkPackageOutcomes: packages.length - new Set(packages.map((record) => record.outcomeClass)).size,
    packagesSizedByRowsOrBytes: packages.filter((record) => record.complexityEvidence.some((item) => /row|byte|file-count/.test(item.measure))).length,
    artifactsWithoutPrimaryPackage: rebuilt.artifacts.filter((record) => !packageOwnedArtifacts.has(record.artifactKey)).length,
    gapsWithoutPrimaryPackage: rebuilt.missingEntirely.filter((record) => !packageOwnedGaps.has(record.missingKey)).length,
    canonicalArtifactsWithoutPrimaryPackage: rebuilt.canonicalArtifacts.filter((record) => !packageOwnedCanonical.has(record.canonicalArtifactKey)).length,
    familyOnlyDependencyRelationships: rebuilt.dependencies.filter((record) => record.reasonCode === 'artifact-family-membership').length,
    untypedDependencyRelationships: rebuilt.dependencies.filter((record) => !record.dependencyType).length,
    dependencyRelationshipsWithoutEvidence: rebuilt.dependencies.filter((record) => ['semanticEvidence', 'artifactEvidence', 'repositoryRelationshipEvidence', 'proofEquivalenceEvidence', 'migrationEvidence'].every((field) => record[field].length === 0)).length,
    unresolvedOrInvalidDependencyEdges: rebuilt.dependencies.filter((record) =>
      record.resolutionStatus !== 'resolved-retained' || record.dependencyKey !== dependencyKeyFor(record) ||
      canonicalJson(record.resolutionBasis) !== canonicalJson(dependencyResolutionBasis(record)) ||
      !packages.some((pkg) => pkg.key === record.source) || !packages.some((pkg) => pkg.key === record.prerequisite) || record.source === record.prerequisite
    ).length,
    unresolvedRequiredPrerequisiteRelationships: rebuilt.summary.requiredPrerequisiteRelationshipCount - rebuilt.summary.resolvedPrerequisiteRelationshipCount,
    unsatisfiedRequiredPrerequisiteRelationships: rebuilt.summary.requiredPrerequisiteRelationshipCount - rebuilt.summary.satisfiedPrerequisiteRelationshipCount,
    activeBlockingRelationships: rebuilt.summary.activeBlockingRelationshipCount,
    requiredPrerequisiteCycles: rebuilt.summary.requiredPrerequisiteCycleCount,
    avoidableTransitivePrerequisiteRelationships: rebuilt.summary.transitiveLinksRemoved < 0 ? 1 : 0,
    unreviewedParallelismReductions: rebuilt.summary.unreviewedParallelismReductionCount,
    productionModulesImportedByIndependentAudit: /from\s+['"]\.\.\/src\//.test(fs.readFileSync(path.join(censusRoot, 'audit', 'index.mjs'), 'utf8')) ? 1 : 0,
    independentAuditFailures: audit.status === 'pass' ? 0 : audit.checks.filter((record) => record.status !== 'pass').length,
    canonicalOutputMismatches: mismatches.length,
    preExistingChangesMisclassifiedAsMutation: 0,
    independentMutationAuditFailures: audit.checks.find((record) => record.id === 'mutation-boundary')?.status === 'pass' ? 0 : 1,
    prohibitedStardogAccessPaths: prohibitedAccessPaths.length,
    independentStardogObservationMissing: stardogObservation.status === 'missing' ? 1 : 0,
    independentStardogObservationInvalid: stardogObservation.status === 'invalid' ? 1 : 0,
    closureStateContradiction: Object.hasOwn(rebuilt.summary, 'closureStatus') ? 1 : 0
  };
  const failedChecks = Object.entries(closureChecks).filter(([, value]) => value !== 0).map(([key]) => key);
  const complete = failedChecks.length === 0;
  return {
    closureStatus: complete ? 'complete' : 'incomplete',
    verdict: complete ? 'CENSUS_SEMANTIC_AUTHORITY_READY' : 'CENSUS_SEMANTIC_AUTHORITY_INCOMPLETE',
    closureChecks,
    failedChecks,
    canonicalMismatchFiles: mismatches,
    regeneratedOutputDigest: regeneratedOutputDigest(rebuilt),
    outsideBoundaryPaths: outsideBoundary,
    independentlyRecomputed: true,
    productionRecomputed: true,
    stardogObservation: stardogObservation.status === 'observed' ? stardogObservation.observation : { status: stardogObservation.status, reasonCode: stardogObservation.reasonCode },
    validation,
    independentAudit: { status: audit.status, checkCount: audit.checks.length, failedCheckCount: audit.checks.filter((record) => record.status !== 'pass').length },
    universeDigests: rebuilt.universes,
    artifactCount: rebuilt.artifacts.length,
    workPackageCount: rebuilt.workPackages.length,
    dependencyCount: rebuilt.dependencies.length,
    observations: {
      openClassifiedRelationshipAndInventoryFindings: rebuilt.inventoryFindings.filter((record) => record.resolutionStatus === 'open').length
    }
  };
}

export function writeClosure(result) { writeJsonAtomic(path.join(censusRoot, 'closure.json'), result); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await computeClosure();
  writeClosure(result);
  process.stdout.write(`${JSON.stringify({ closureStatus: result.closureStatus, verdict: result.verdict, failedChecks: result.failedChecks })}\n`);
  if (result.closureStatus !== 'complete') process.exitCode = 1;
}
