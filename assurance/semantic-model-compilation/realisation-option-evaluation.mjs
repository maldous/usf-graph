import { createHash, createPublicKey, verify } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { extname, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

import { DataFactory, Parser, Store } from 'n3';
import { parse as parseYaml } from 'yaml';

const { namedNode } = DataFactory;
const RDF_TYPE = namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type');
const USF = 'urn:usf:ontology:';
const term = (name) => namedNode(`${USF}${name}`);
const iri = (value) => namedNode(value);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const LOCKED_VERSION = /^(?!latest$)(?!next$)(?!stable$)(?!main$)(?!master$)(?!head$)(?!\^)(?!~)(?![><=*])[0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.-]+)?$|^source-digest-bound$/i;
const INTEGRITY = /^(?:sha256:[0-9a-f]{64}|sha512-[A-Za-z0-9+/=]+)$/;
const OCI_DIGEST_REFERENCE = /@sha256:([0-9a-f]{64})(?:$|[?#])/;

export const FAILURE_REGISTRY = Object.freeze([
  ['ACTIVE_CONTRACT_SELECTION_EVALUATION_MISSING', 'activeContractsRequiringTechnologySelectionWithoutEvaluatedCandidates'],
  ['DECISION_STATE_CARDINALITY', 'activeContractsRequiringTechnologySelectionWithoutEvaluatedCandidates'],
  ['DECISION_CONTRACT_CARDINALITY', 'activeContractsRequiringTechnologySelectionWithoutEvaluatedCandidates'],
  ['DECISION_EVALUATION_CARDINALITY', 'activeContractsRequiringTechnologySelectionWithoutEvaluatedCandidates'],
  ['EVALUATION_DEPENDENCY_DRIFT', 'criterionAssessmentsWithoutAdmittedCurrentEvidence'],
  ['FAILURE_REGISTRY_DRIFT', 'criterionAssessmentsWithoutAdmittedCurrentEvidence'],
  ['EVIDENCE_ASSESSMENT_RECORD_DUPLICATE', 'criterionAssessmentsWithoutAdmittedCurrentEvidence'],
  ['MISSING_SELECTED_OPTION', 'acceptedDecisionsWithoutExactlyOneSelectedOption'],
  ['MULTIPLE_SELECTED_OPTIONS', 'acceptedDecisionsWithoutExactlyOneSelectedOption'],
  ['SELECTED_OPTION_OUTSIDE_CANDIDATE_SET', 'acceptedDecisionsWithoutExactlyOneSelectedOption'],
  ['FAKE_OR_DUPLICATE_CREDIBLE_CANDIDATE', 'acceptedDecisionsWithoutMultipleCredibleCandidatesOrValidSoleCandidateProof'],
  ['INCOMPLETE_CANDIDATE_SET', 'acceptedDecisionsWithoutMultipleCredibleCandidatesOrValidSoleCandidateProof'],
  ['CANDIDATE_SEARCH_SPACE_INCOMPLETE', 'acceptedDecisionsWithoutMultipleCredibleCandidatesOrValidSoleCandidateProof'],
  ['MISSING_APPLICABLE_CRITERION', 'applicableCandidateCriterionAssessmentsMissing'],
  ['UNJUSTIFIED_NOT_APPLICABLE_CRITERION', 'applicableCandidateCriterionAssessmentsMissing'],
  ['MISSING_CANDIDATE_CRITERION_ASSESSMENT', 'applicableCandidateCriterionAssessmentsMissing'],
  ['ASSESSMENT_EVIDENCE_INVALID', 'criterionAssessmentsWithoutAdmittedCurrentEvidence'],
  ['MANDATORY_CRITERION_NOT_CLOSED', 'applicableCandidateCriterionAssessmentsMissing'],
  ['COMPONENT_CRITERION_ASSESSMENT_MISSING', 'applicableComponentCriterionAssessmentsMissing'],
  ['COMPONENT_CRITERION_ASSESSMENT_DUPLICATE', 'applicableComponentCriterionAssessmentsMissing'],
  ['COMPONENT_ASSESSMENT_RESPONSIBILITY_MISMATCH', 'applicableComponentCriterionAssessmentsMissing'],
  ['COMPONENT_ASSESSMENT_EVIDENCE_INVALID', 'criterionAssessmentsWithoutAdmittedCurrentEvidence'],
  ['COMPONENT_MANDATORY_CRITERION_NOT_CLOSED', 'applicableComponentCriterionAssessmentsMissing'],
  ['REJECTED_CANDIDATE_REASON_MISSING', 'credibleRejectedCandidatesWithoutEvidenceBackedRejectionReasons'],
  ['REJECTION_REASON_EVIDENCE_MISSING', 'credibleRejectedCandidatesWithoutEvidenceBackedRejectionReasons'],
  ['COMPONENT_KIND_CARDINALITY', 'selectedComponentsWithoutKindSpecificClosure'],
  ['FLOATING_COMPONENT_VERSION', 'selectedPackagesOrImagesWithoutExactVersionAndIntegrityBinding'],
  ['COMPONENT_INTEGRITY_BINDING_MISSING', 'selectedPackagesOrImagesWithoutExactVersionAndIntegrityBinding'],
  ['REPOSITORY_LOCAL_SOURCE_DIGEST_MISSING', 'selectedComponentsWithoutKindSpecificClosure'],
  ['REPOSITORY_LOCAL_SOURCE_INTEGRITY_MISMATCH', 'selectedComponentsWithoutKindSpecificClosure'],
  ['REPOSITORY_LOCAL_TOOLCHAIN_DIGEST_MISSING', 'selectedComponentsWithoutKindSpecificClosure'],
  ['EXTERNAL_PROVIDER_IDENTITY_INCOMPLETE', 'selectedComponentsWithoutKindSpecificClosure'],
  ['EXTERNAL_PROVIDER_BINDING_MISSING', 'providerChoicesWithoutRequiredEnvironmentBindings'],
  ['EXTERNAL_PROVIDER_MODE_OR_ENVIRONMENT_MISMATCH', 'providerChoicesWithoutRequiredEnvironmentBindings'],
  ['CONTAINER_IMAGE_MUTABLE_REFERENCE', 'selectedPackagesOrImagesWithoutExactVersionAndIntegrityBinding'],
  ['CONTAINER_IMAGE_DIGEST_MISMATCH', 'selectedPackagesOrImagesWithoutExactVersionAndIntegrityBinding'],
  ['LICENCE_ASSESSMENT_INVALID', 'selectedThirdPartyComponentsWithoutLicenceAssessment'],
  ['VULNERABILITY_ASSESSMENT_MISSING', 'selectedThirdPartyComponentsWithoutVulnerabilityAndSupplyChainAssessment'],
  ['SUPPLY_CHAIN_ASSESSMENT_MISSING', 'selectedThirdPartyComponentsWithoutVulnerabilityAndSupplyChainAssessment'],
  ['COMPONENT_RESPONSIBILITY_MISSING', 'selectedCompositionsWithoutCompleteComponentResponsibilityMapping'],
  ['COMPONENT_BOUNDARY_INCOMPLETE', 'selectedCompositionsWithoutCompleteComponentResponsibilityMapping'],
  ['COMPOSITION_FACET_UNCOVERED', 'selectedCompositionsWithoutCurrentWholeCompositionCoverageProof'],
  ['COMPOSITION_DEPENDENCY_INVALID', 'selectedCompositionsWithoutCurrentWholeCompositionCoverageProof'],
  ['COMPOSITION_INTERFACE_INCOMPATIBLE', 'selectedCompositionsWithoutCurrentWholeCompositionCoverageProof'],
  ['COMPONENT_VERSION_INCOMPATIBLE', 'selectedCompositionsWithoutCurrentWholeCompositionCoverageProof'],
  ['COMPOSITION_COVERAGE_PROOF_STALE_OR_MISSING', 'selectedCompositionsWithoutCurrentWholeCompositionCoverageProof'],
  ['PERMUTATION_RULE_SET_INVALID', 'compositionPermutationsLeftUnclassified'],
  ['PERMUTATION_EQUIVALENCE_PROOF_MISSING', 'compositionPermutationsLeftUnclassified'],
  ['UNCLASSIFIED_COMPOSITION_PERMUTATION', 'compositionPermutationsLeftUnclassified'],
  ['PROVIDER_ENVIRONMENT_BINDING_MISSING', 'providerChoicesWithoutRequiredEnvironmentBindings'],
  ['SELECTED_OPTION_REALISATION_MAPPING_CARDINALITY', 'selectedOptionsWithoutConcreteRealisationMappings'],
  ['SELECTED_COMPONENT_CONCRETE_MAPPING_CARDINALITY', 'selectedOptionsWithoutConcreteRealisationMappings'],
  ['SELECTED_COMPONENT_CONCRETE_MAPPING_TYPE_MISMATCH', 'selectedOptionsWithoutConcreteRealisationMappings'],
  ['SELECTION_MAPPING_DEPENDENCY_DRIFT', 'selectedOptionsWithoutConcreteRealisationMappings'],
  ['LEGACY_SELECTION_WITHOUT_INDEPENDENT_BASIS', 'legacySelectionsRetainedSolelyBecauseOfPreviousUse'],
  ['REALISATION_OPTION_VALIDATOR_GRAPH_SCOPE_MISMATCH', 'realisationOptionValidatorGraphScopeMismatches'],
].map(([reasonCode, gateCounter], precedence) => Object.freeze({ reasonCode, gateCounter, precedence })));
export const REASON_PRECEDENCE = Object.freeze(FAILURE_REGISTRY.map(({ reasonCode }) => reasonCode));
export const REASON_COUNTER = Object.freeze(Object.fromEntries(FAILURE_REGISTRY.map(({ reasonCode, gateCounter }) => [reasonCode, gateCounter])));
const REASON_RANK = new Map(REASON_PRECEDENCE.map((code, index) => [code, index]));
const OPTION_EVIDENCE = iri('urn:usf:evidenceresult:realisationoptionevaluation');
const OPTION_EVIDENCE_DESCRIPTOR = iri('urn:usf:externalpayloaddescriptor:realisationoptionevaluation');
const OPTION_ATTESTATION_DESCRIPTOR = iri('urn:usf:externalpayloaddescriptor:realisationoptionevaluationattestation');
const CLOSED_DISPOSITIONS = new Set([
  'requiredandvalidated', 'validandcoveredbyequivalenceproof', 'invalidandrejected',
  'unsupportedexplicitnonclaim', 'notapplicablewithprovenconstraint',
]);
const COMPONENT_BOUNDARY_PROPERTIES = Object.freeze([
  'componentDataOwnershipBoundary', 'componentTransactionBoundary', 'componentSecurityBoundary',
  'componentSecretBoundary', 'componentDeploymentBoundary', 'componentFailurePropagation',
  'componentRetryPolicy', 'componentTimeoutPolicy', 'componentUpgradeCompatibility',
  'componentRollbackOrder', 'componentReplacementBoundary',
]);
const utf8Compare = (left, right) => Buffer.compare(Buffer.from(String(left)), Buffer.from(String(right)));

export const GATE_COUNTER_NAMES = Object.freeze([
  'activeContractsRequiringTechnologySelectionWithoutEvaluatedCandidates',
  'acceptedDecisionsWithoutMultipleCredibleCandidatesOrValidSoleCandidateProof',
  'acceptedDecisionsWithoutExactlyOneSelectedOption',
  'applicableCandidateCriterionAssessmentsMissing',
  'applicableComponentCriterionAssessmentsMissing',
  'criterionAssessmentsWithoutAdmittedCurrentEvidence',
  'credibleRejectedCandidatesWithoutEvidenceBackedRejectionReasons',
  'selectedPackagesOrImagesWithoutExactVersionAndIntegrityBinding',
  'selectedComponentsWithoutKindSpecificClosure',
  'selectedThirdPartyComponentsWithoutLicenceAssessment',
  'selectedThirdPartyComponentsWithoutVulnerabilityAndSupplyChainAssessment',
  'selectedCompositionsWithoutCompleteComponentResponsibilityMapping',
  'selectedCompositionsWithoutCurrentWholeCompositionCoverageProof',
  'compositionPermutationsLeftUnclassified',
  'providerChoicesWithoutRequiredEnvironmentBindings',
  'selectedOptionsWithoutConcreteRealisationMappings',
  'legacySelectionsRetainedSolelyBecauseOfPreviousUse',
  'realisationOptionValidatorGraphScopeMismatches',
]);

const REALISATION_OPTION_VALIDATOR = iri('urn:usf:validatorrule:validaterealisationoptionevaluation');
const REQUIRED_VALIDATOR_TARGET_GRAPHS = Object.freeze([
  'urn:usf:namedgraph:bindings',
  'urn:usf:namedgraph:capabilities',
  'urn:usf:namedgraph:derivedreadiness',
  'urn:usf:namedgraph:evidence',
  'urn:usf:namedgraph:interfaces',
  'urn:usf:namedgraph:materialisation',
  'urn:usf:namedgraph:vocabulary',
]);

const stable = (value) => Array.isArray(value)
  ? value.map(stable)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(utf8Compare).map((key) => [key, stable(value[key])]))
    : value;
export const canonicalJson = (value) => JSON.stringify(stable(value));
export const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

const rdfTermKey = (value) => canonicalJson({
  termType: value.termType,
  value: value.value,
  datatype: value.datatype?.value || '',
  language: value.language || '',
});

function uniqueTerms(quads, position) {
  return [...new Map(quads.map((quad) => [rdfTermKey(quad[position]), quad[position]])).values()]
    .sort((left, right) => utf8Compare(rdfTermKey(left), rdfTermKey(right)));
}
const objects = (store, subject, predicate) => uniqueTerms(store.getQuads(subject, predicate, null, null), 'object');
const subjects = (store, predicate, object) => uniqueTerms(store.getQuads(null, predicate, object, null), 'subject');
const has = (store, subject, predicate, object = null) => store.countQuads(subject, predicate, object, null) > 0;
const literalValues = (store, subject, predicate) => objects(store, subject, predicate).map(({ value }) => value);
const oneLiteral = (store, subject, predicate) => literalValues(store, subject, predicate)[0];
const number = (store, subject, predicate) => Number(oneLiteral(store, subject, predicate));
const bool = (store, subject, predicate) => oneLiteral(store, subject, predicate) === 'true';
const isType = (store, subject, className) => has(store, subject, RDF_TYPE, term(className));

function containedBy(root, target) {
  const path = relative(root, target);
  return path !== '' && path !== '..' && !path.startsWith(`..${sep}`);
}

function readCasObject(casRoot, digest) {
  if (!SHA256.test(digest || '')) throw new Error('invalid CAS digest');
  const root = realpathSync(casRoot);
  const hexadecimal = digest.slice(7);
  const path = resolve(root, 'sha256', hexadecimal.slice(0, 2), hexadecimal);
  const stat = lstatSync(path);
  if (!containedBy(root, path) || stat.isSymbolicLink() || !stat.isFile() || !containedBy(root, realpathSync(path))) {
    throw new Error(`invalid CAS object ${digest}`);
  }
  const bytes = readFileSync(path);
  if (sha256(bytes) !== digest) throw new Error(`CAS digest mismatch ${digest}`);
  return bytes;
}

function canonicalDecisionProjection(store, decision) {
  const evaluation = objects(store, decision, term('hasDecisionEvaluation'))[0];
  const name = oneLiteral(store, decision, term('canonicalName'));
  const contract = objects(store, decision, term('decisionForContract'))[0];
  const selected = objects(store, decision, term('selectsOption'))[0];
  const options = objects(store, decision, term('considersOption'));
  const credibility = evaluation ? objects(store, evaluation, term('hasCandidateCredibilityAssessment')) : [];
  const credible = options.filter((option) => credibility.some((record) => has(store, record, term('credibilityForOption'), option)
    && has(store, record, term('credibilityState'), iri('urn:usf:candidatecredibilitystate:credible'))));
  const notApplicable = evaluation ? objects(store, evaluation, term('hasCriterionRequirement'))
    .filter((requirement) => has(store, requirement, term('criterionApplicability'), iri('urn:usf:criterionapplicability:notapplicable')))
    .map((requirement) => objects(store, requirement, term('requiresCriterion'))[0])
    .filter(Boolean) : [];
  return {
    name,
    contract: oneLiteral(store, contract, term('canonicalName')),
    selected: oneLiteral(store, selected, term('canonicalName')),
    options: options.map((option) => oneLiteral(store, option, term('canonicalName'))).sort(),
    credible: credible.map((option) => oneLiteral(store, option, term('canonicalName'))).sort(),
    notApplicable: notApplicable.map((criterion) => oneLiteral(store, criterion, term('canonicalName'))).sort(),
  };
}

const RAW_ACQUISITION_SCOPES = Object.freeze(['DECLARED_PROVIDER_METADATA_RAW', 'EXTERNAL_STATIC_RAW', 'HERMETIC_LOCAL_RAW']);
const RAW_SCOPE_MANIFEST_IDENTITIES = Object.freeze({
  DECLARED_PROVIDER_METADATA_RAW: 'urn:usf:evidencescopemanifest:realisationoptionevaluationdeclaredprovidermetadata',
  EXTERNAL_STATIC_RAW: 'urn:usf:evidencescopemanifest:realisationoptionevaluationexternalstatic',
  HERMETIC_LOCAL_RAW: 'urn:usf:evidencescopemanifest:realisationoptionevaluationhermeticlocal',
});
const RAW_SCOPE_PROVIDER_IDENTITIES = Object.freeze({
  DECLARED_PROVIDER_METADATA_RAW: 'urn:usf:provideridentity:declaredstardogmetadata',
  EXTERNAL_STATIC_RAW: 'urn:usf:provideridentity:declaredexternalsources',
  HERMETIC_LOCAL_RAW: 'urn:usf:provideridentity:repositorylocalacquisition',
});
const RAW_SCOPE_CLAIM_BOUNDARIES = Object.freeze({
  DECLARED_PROVIDER_METADATA_RAW: Object.freeze(['Declared Stardog product, exact version, edition and licence type for option evaluation only']),
  EXTERNAL_STATIC_RAW: Object.freeze(['Immutable official runtime release metadata, package advisory response bytes, and Stardog release, security and licence source bytes']),
  HERMETIC_LOCAL_RAW: Object.freeze(['Exact repository lock, runtime executable, licence bytes and selected package identities']),
});
const RAW_SCOPE_PROHIBITED_CLAIMS = Object.freeze({
  DECLARED_PROVIDER_METADATA_RAW: Object.freeze(['Live authority access', 'transaction behaviour', 'vulnerability status', 'licence compatibility']),
  EXTERNAL_STATIC_RAW: Object.freeze(['Repository-local execution', 'live authority behaviour']),
  HERMETIC_LOCAL_RAW: Object.freeze(['Live authority access', 'publication', 'rollback', 'source/live parity']),
});
const RAW_SCOPE_SUPPORTED_CRITERIA = Object.freeze({
  DECLARED_PROVIDER_METADATA_RAW: Object.freeze(['environmentcompatibility', 'providercompatibility', 'versionstability']),
  EXTERNAL_STATIC_RAW: Object.freeze(['licencecompatibility', 'supplychainrisk', 'updateandpatchpolicy', 'versionstability', 'vulnerabilityexposure']),
  HERMETIC_LOCAL_RAW: Object.freeze(['environmentcompatibility', 'evidenceandprooffeasibility', 'hermeticsubstitutefeasibility', 'licencecompatibility', 'portability', 'semanticderivation', 'supplychainrisk', 'testability', 'updateandpatchpolicy', 'versionstability', 'vulnerabilityexposure']),
});
const RAW_SCOPE_PROHIBITED_CRITERIA = Object.freeze({
  DECLARED_PROVIDER_METADATA_RAW: Object.freeze(['hermeticsubstitutefeasibility', 'licencecompatibility', 'vulnerabilityexposure']),
  EXTERNAL_STATIC_RAW: Object.freeze(['hermeticsubstitutefeasibility']),
  HERMETIC_LOCAL_RAW: Object.freeze(['productionshapedstagingfeasibility', 'providercompatibility']),
});
const DETERMINISTIC_EVALUATION_SCOPE = Object.freeze({
  identity: 'urn:usf:evidencescopemanifest:realisationoptionevaluationdeterministicassessment',
  scope: 'DETERMINISTIC_EVALUATION',
  providerIdentity: 'urn:usf:provideridentity:repositorylocalevaluator',
  classification: 'urn:usf:evidencescopeclassification:deterministicevaluation',
});
const PROHIBITED_RAW_FIELDS = new Set([
  'proofResult', 'proofSuccessful', 'proofState', 'evidenceAdmissionState', 'licenceCompatible',
  'selectedOption', 'selectedComponent', 'readinessState', 'evaluationClosureState', 'assessmentResult',
]);

function containsProhibitedRawField(value) {
  if (Array.isArray(value)) return value.some(containsProhibitedRawField);
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, item]) => PROHIBITED_RAW_FIELDS.has(key) || containsProhibitedRawField(item));
}

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && canonicalJson(Object.keys(value).sort(utf8Compare)) === canonicalJson([...keys].sort(utf8Compare));
}

function expectedSupportingManifests(acquisition) {
  return [...acquisition.manifests].sort((left, right) => utf8Compare(left.scope, right.scope)).map((manifest) => ({
    identity: RAW_SCOPE_MANIFEST_IDENTITIES[manifest.scope],
    scope: manifest.scope,
    providerIdentity: RAW_SCOPE_PROVIDER_IDENTITIES[manifest.scope],
    manifestDigest: manifest.manifestDigest,
    descriptorDigest: manifest.descriptorDigest,
    collectorDigest: manifest.collectorDigest,
    claimBoundary: [...RAW_SCOPE_CLAIM_BOUNDARIES[manifest.scope]],
    prohibitedClaims: [...RAW_SCOPE_PROHIBITED_CLAIMS[manifest.scope]],
    supportedCriteria: [...RAW_SCOPE_SUPPORTED_CRITERIA[manifest.scope]].sort(utf8Compare),
    prohibitedCriteria: [...RAW_SCOPE_PROHIBITED_CRITERIA[manifest.scope]].sort(utf8Compare),
  }));
}

function validateRawAcquisition(acquisition, payload, expectedCollectorDigest, casRoot) {
  if (acquisition?.recordKind !== 'USF_RAW_ACQUISITION_SET' || acquisition.schemaVersion !== 1
      || acquisition.authorityDigest !== payload.authorityDigest || acquisition.acquisitionSetDigest !== payload.acquisitionSetDigest
      || !exactKeys(acquisition, ['recordKind', 'schemaVersion', 'authorityDigest', 'acquisitionSetDigest', 'manifests'])
      || !Array.isArray(acquisition.manifests) || acquisition.manifests.length !== RAW_ACQUISITION_SCOPES.length) return false;
  const manifests = [...acquisition.manifests].sort((left, right) => utf8Compare(left.scope, right.scope));
  if (canonicalJson(manifests.map(({ scope }) => scope)) !== canonicalJson(RAW_ACQUISITION_SCOPES)) return false;
  const records = [];
  for (const manifest of manifests) {
    const { manifestDigest, ...core } = manifest;
    if (!exactKeys(manifest, ['scope', 'authorityDigest', 'collectedAt', 'validUntil', 'collectorDigest', 'descriptorDigest', 'observations', 'manifestDigest'])
        || !SHA256.test(manifestDigest || '') || sha256(canonicalJson(core)) !== manifestDigest
        || core.authorityDigest !== payload.authorityDigest || core.collectorDigest !== expectedCollectorDigest
        || !SHA256.test(core.descriptorDigest || '') || !Number.isFinite(Date.parse(core.collectedAt))
        || !Number.isFinite(Date.parse(core.validUntil)) || Date.parse(core.validUntil) <= Date.parse(core.collectedAt)
        || Date.parse(core.collectedAt) !== Date.parse(payload.collectedAt) || Date.parse(core.validUntil) !== Date.parse(payload.validUntil)
        || !core.observations || typeof core.observations !== 'object' || containsProhibitedRawField(core.observations)) return false;
    const observationDigest = sha256(canonicalJson(core.observations));
    const expectedDescriptor = sha256(canonicalJson({
      authorityDigest: core.authorityDigest, collectedAt: core.collectedAt, collectorDigest: core.collectorDigest,
      observationDigest, scope: core.scope, validUntil: core.validUntil,
    }));
    if (core.descriptorDigest !== expectedDescriptor) return false;
    if (core.scope === 'DECLARED_PROVIDER_METADATA_RAW') {
      if (!exactKeys(core.observations, ['stardog'])
          || !exactKeys(core.observations.stardog, ['product', 'version', 'edition', 'licenceType', 'declaredAuthorityDigest', 'sourceKind', 'metadataDigest'])) return false;
      const { metadataDigest, ...metadataCore } = core.observations.stardog;
      if (metadataCore.declaredAuthorityDigest !== payload.authorityDigest
          || metadataCore.sourceKind !== 'DECLARED_REALISATION_CONSTRAINT'
          || sha256(canonicalJson(metadataCore)) !== metadataDigest) return false;
    } else if (Object.hasOwn(core.observations, 'stardog')) return false;
    if (core.scope === 'HERMETIC_LOCAL_RAW') {
      if (!exactKeys(core.observations, ['nodeExecutableDigest', 'nodeLicenceDigest', 'nodeLicenceSourceDigest', 'npmVersion', 'packageLockDigest', 'packages', 'transitiveDependencySetDigest'])
          || !Array.isArray(core.observations.packages)
          || core.observations.packages.some((item) => !exactKeys(item, ['name', 'version', 'integrity', 'licence', 'dependencyCount', 'dependencySetDigest'])
            || !Number.isInteger(item.dependencyCount) || item.dependencyCount < 1 || !SHA256.test(item.dependencySetDigest || ''))
          || core.observations.nodeLicenceDigest !== core.observations.nodeLicenceSourceDigest) return false;
      try { readCasObject(casRoot, core.observations.nodeLicenceSourceDigest); } catch { return false; }
    }
    if (core.scope === 'EXTERNAL_STATIC_RAW') {
      if (!exactKeys(core.observations, ['nodeRelease', 'nodeReleaseNotes', 'npmAudit', 'npmAuditSourceDigest', 'npmAuditSource', 'stardogReleaseNotes', 'stardogSecurityStatement', 'stardogLicenceTerms'])
          || !exactKeys(core.observations.nodeRelease, ['version', 'date', 'files', 'lts', 'npm', 'openssl', 'sourceDigest', 'sourceUrl'])
          || !exactKeys(core.observations.nodeReleaseNotes, ['version', 'sourceDigest', 'sourceUrl'])
          || !exactKeys(core.observations.stardogReleaseNotes, ['version', 'sourceDigest', 'sourceUrl'])
          || !exactKeys(core.observations.stardogSecurityStatement, ['sourceDigest', 'sourceUrl'])
          || !exactKeys(core.observations.stardogLicenceTerms, ['licenceType', 'sourceDigest', 'sourceUrl'])) return false;
      try {
        const releaseBytes = readCasObject(casRoot, core.observations.nodeRelease.sourceDigest);
        const releaseRecords = JSON.parse(releaseBytes);
        const release = releaseRecords.find(({ version }) => version === core.observations.nodeRelease.version);
        if (!release || canonicalJson({
          version: release.version, date: release.date, files: [...release.files].sort(utf8Compare),
          lts: release.lts, npm: release.npm, openssl: release.openssl,
        }) !== canonicalJson({
          version: core.observations.nodeRelease.version, date: core.observations.nodeRelease.date,
          files: core.observations.nodeRelease.files, lts: core.observations.nodeRelease.lts,
          npm: core.observations.nodeRelease.npm, openssl: core.observations.nodeRelease.openssl,
        })) return false;
        const auditBytes = readCasObject(casRoot, core.observations.npmAuditSourceDigest);
        if (canonicalJson(JSON.parse(auditBytes)) !== canonicalJson(core.observations.npmAudit)) return false;
        const nodeReleaseNotes = readCasObject(casRoot, core.observations.nodeReleaseNotes.sourceDigest).toString('utf8');
        const releaseNotes = readCasObject(casRoot, core.observations.stardogReleaseNotes.sourceDigest).toString('utf8');
        const securityStatement = readCasObject(casRoot, core.observations.stardogSecurityStatement.sourceDigest).toString('utf8');
        const licenceTerms = readCasObject(casRoot, core.observations.stardogLicenceTerms.sourceDigest).toString('utf8');
        if (!nodeReleaseNotes.includes(core.observations.nodeReleaseNotes.version) || !/security release/i.test(nodeReleaseNotes)
            || !releaseNotes.includes(core.observations.stardogReleaseNotes.version)
            || !/vulnerabilit/i.test(securityStatement) || !/scan/i.test(securityStatement)
            || !/enterprise/i.test(licenceTerms) || !/licen[cs]e/i.test(licenceTerms)) return false;
      } catch { return false; }
    }
    records.push({
      scope: core.scope, digest: manifestDigest, collectorDigest: core.collectorDigest,
      descriptorDigest: core.descriptorDigest, collectedAt: core.collectedAt, validUntil: core.validUntil,
    });
  }
  const payloadRawManifests = (payload.supportingEvidenceManifests || [])
    .filter(({ scope }) => RAW_ACQUISITION_SCOPES.includes(scope))
    .sort((left, right) => utf8Compare(left.scope, right.scope));
  return sha256(canonicalJson(records)) === acquisition.acquisitionSetDigest
    && canonicalJson(payloadRawManifests) === canonicalJson(expectedSupportingManifests(acquisition));
}

function validateEvidenceContext(repositoryRoot, store, casRoot, expected = {}) {
  const failures = [];
  try {
    const evidenceDigest = oneLiteral(store, OPTION_EVIDENCE, term('contentDigest'));
    const descriptorDigest = oneLiteral(store, OPTION_EVIDENCE_DESCRIPTOR, term('descriptorDigest'));
    const attestationDigest = oneLiteral(store, OPTION_ATTESTATION_DESCRIPTOR, term('descriptorDigest'));
    if (evidenceDigest !== descriptorDigest) failures.push('EVIDENCE_DESCRIPTOR_DIGEST_MISMATCH');
    const evidenceBytes = readCasObject(casRoot, evidenceDigest);
    const attestationBytes = readCasObject(casRoot, attestationDigest);
    const payload = JSON.parse(evidenceBytes);
    const attestation = JSON.parse(attestationBytes);
    if (!SHA256.test(expected.authorityDigest || '') || payload.authorityDigest !== expected.authorityDigest) {
      failures.push('EXPECTED_AUTHORITY_WITNESS_MISSING_OR_MISMATCHED');
    }
    if (!/^[0-9a-f]{64}$/.test(expected.signerFingerprint || '')) failures.push('EXPECTED_SIGNER_WITNESS_MISSING');
    if (payload.schemaVersion !== 3 || payload.evidenceScope !== 'COMPOSITE_REALISATION_OPTION_EVALUATION'
        || !Array.isArray(payload.supportingEvidenceManifests)
        || payload.supportingEvidenceManifests.length !== RAW_ACQUISITION_SCOPES.length + 1
        || !SHA256.test(payload.acquisitionInputDigest || '') || !SHA256.test(payload.acquisitionSetDigest || '')) {
      failures.push('EVIDENCE_SCOPE_OR_ACQUISITION_BINDING_INVALID');
    } else {
      const acquisition = JSON.parse(readCasObject(casRoot, payload.acquisitionInputDigest));
      const collectorRecord = payload.sourceRecords?.find(({ path }) => path === 'assurance/semantic-model-compilation/realisation-option-acquisition.mjs');
      if (!collectorRecord || !validateRawAcquisition(acquisition, payload, collectorRecord.digest, casRoot)) {
        failures.push('EVIDENCE_SCOPE_OR_ACQUISITION_BINDING_INVALID');
      }
    }
    const scopeClassifications = {
      DECLARED_PROVIDER_METADATA_RAW: 'urn:usf:evidencescopeclassification:declaredprovidermetadata',
      DETERMINISTIC_EVALUATION: DETERMINISTIC_EVALUATION_SCOPE.classification,
      EXTERNAL_STATIC_RAW: 'urn:usf:evidencescopeclassification:externalstatic',
      HERMETIC_LOCAL_RAW: 'urn:usf:evidencescopeclassification:hermeticlocal',
    };
    const graphManifests = objects(store, OPTION_EVIDENCE, term('hasSupportingEvidenceManifest')).map((resource) => {
      const value = {
        identity: resource.value,
        scope: Object.entries(scopeClassifications).find(([, classification]) => has(store, resource, term('evidenceScopeClassification'), iri(classification)))?.[0],
        providerIdentity: objects(store, resource, term('scopeProviderIdentity'))[0]?.value,
        manifestDigest: oneLiteral(store, resource, term('scopeManifestDigest')),
        descriptorDigest: oneLiteral(store, resource, term('scopeDescriptorDigest')),
        collectorDigest: oneLiteral(store, resource, term('scopeCollectorDigest')),
        claimBoundary: literalValues(store, resource, term('scopeClaimBoundary')).sort(utf8Compare),
        prohibitedClaims: literalValues(store, resource, term('scopeProhibitedClaim')).sort(utf8Compare),
        supportedCriteria: objects(store, resource, term('scopeSupportsCriterion')).map(({ value: criterion }) => criterion.split(':').at(-1)).sort(utf8Compare),
        prohibitedCriteria: objects(store, resource, term('scopeProhibitsCriterion')).map(({ value: criterion }) => criterion.split(':').at(-1)).sort(utf8Compare),
      };
      const derivationInputDigest = oneLiteral(store, resource, term('scopeDerivationInputDigest'));
      const derivationResultDigest = oneLiteral(store, resource, term('scopeDerivationResultDigest'));
      if (derivationInputDigest) value.derivationInputDigest = derivationInputDigest;
      if (derivationResultDigest) value.derivationResultDigest = derivationResultDigest;
      return value;
    }).sort((left, right) => utf8Compare(left.identity, right.identity));
    const payloadManifests = (payload.supportingEvidenceManifests || []).map((manifest) => ({
      ...manifest,
      claimBoundary: [...manifest.claimBoundary].sort(utf8Compare),
      prohibitedClaims: [...manifest.prohibitedClaims].sort(utf8Compare),
      supportedCriteria: [...manifest.supportedCriteria].sort(utf8Compare),
      prohibitedCriteria: [...manifest.prohibitedCriteria].sort(utf8Compare),
    })).sort((left, right) => utf8Compare(left.identity, right.identity));
    if (!has(store, OPTION_EVIDENCE, RDF_TYPE, term('CompositeEvidenceResult'))
        || objects(store, OPTION_EVIDENCE, term('usesProviderMode')).length !== 0
        || objects(store, OPTION_EVIDENCE, term('inEnvironment')).length !== 0
        || canonicalJson(graphManifests) !== canonicalJson(payloadManifests)) {
      failures.push('EVIDENCE_SCOPE_OR_ACQUISITION_BINDING_INVALID');
    }
    if (payload.authorityDigest !== oneLiteral(store, OPTION_EVIDENCE, term('evaluatedAuthorityDigest'))
        || payload.evidenceProducerDigest !== oneLiteral(store, OPTION_EVIDENCE, term('evidenceProducerDigest'))) {
      failures.push('EVIDENCE_AUTHORITY_OR_PRODUCER_BINDING_MISMATCH');
    }
    const subject = attestation.subject?.find(({ name }) => name === 'realisation-option-evaluation');
    if (subject?.digest?.sha256 !== evidenceDigest.slice(7)) failures.push('ATTESTATION_SUBJECT_MISMATCH');
    const publicKeyBytes = Buffer.from(attestation.publicKeyDer || '', 'base64');
    const publicKey = createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
    const signatureBytes = Buffer.from(attestation.signature || '', 'base64');
    if (!verify(null, evidenceBytes, publicKey, signatureBytes)) failures.push('ATTESTATION_SIGNATURE_INVALID');
    const signatureResource = objects(store, OPTION_EVIDENCE, term('evidenceSignature'))[0];
    const identity = signatureResource && objects(store, signatureResource, term('signedBy'))[0];
    if (!signatureResource || !identity
        || oneLiteral(store, signatureResource, term('signatureValue')) !== attestation.signature
        || oneLiteral(store, identity, term('signingKeyFingerprint')) !== expected.signerFingerprint
        || sha256(publicKeyBytes).slice(7) !== expected.signerFingerprint) {
      failures.push('ATTESTATION_TRUST_BINDING_MISMATCH');
    }
    const prohibitedSourcePaths = new Set(['semantic-model/assurance/evidence.trig', 'semantic-model/realisation/bindings.trig']);
    if (!Array.isArray(payload.sourceRecords) || payload.sourceRecords.some(({ path }) => prohibitedSourcePaths.has(path)
        || path.startsWith('.work/') || path.startsWith('cas://'))) {
      failures.push('IMPLEMENTATION_SOURCE_DIGEST_SELF_REFERENCE');
    }
    const currentSourceRecords = (payload.sourceRecords || []).map((record) => {
      if (record.path.startsWith('cas://sha256/')) {
        const digest = `sha256:${record.path.slice('cas://sha256/'.length)}`;
        readCasObject(casRoot, digest);
        return { path: record.path, digest };
      }
      const root = realpathSync(repositoryRoot);
      const path = resolve(root, record.path);
      if (!containedBy(root, path) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()
          || !containedBy(root, realpathSync(path))) throw new Error(`invalid source path ${record.path}`);
      const before = sha256(readFileSync(path));
      const after = sha256(readFileSync(path));
      if (before !== after) throw new Error(`source changed during verification ${record.path}`);
      return { path: record.path, digest: after };
    }).sort((left, right) => utf8Compare(left.path, right.path));
    if (canonicalJson(currentSourceRecords) !== canonicalJson(payload.sourceRecords)) failures.push('SOURCE_RECORD_DRIFT');
    const implementationSourceDigest = sha256(canonicalJson(currentSourceRecords));
    if (payload.implementationSourceDigest !== implementationSourceDigest) failures.push('IMPLEMENTATION_SOURCE_DIGEST_MISMATCH');
    const dependencySet = {
      authorityDigest: payload.authorityDigest,
      criteria: payload.criteria,
      decisions: payload.decisions.map(({ name, contract, selected, options, credible, notApplicable }) => ({
        name, contract, selected, options, credible, notApplicable: [...notApplicable].sort(),
      })),
      componentObservations: payload.componentObservations,
      candidateSearchSpaces: payload.candidateSearchSpaces,
      permutationRuleSets: payload.permutationRuleSets,
      supportingEvidenceManifests: payload.supportingEvidenceManifests,
      sourceRecords: currentSourceRecords,
      licencePolicy: payload.licencePolicy,
      vulnerabilityPolicy: payload.vulnerabilityPolicy,
      repositorySecurityScan: payload.repositorySecurityScan,
    };
    const evaluationDependencySetDigest = sha256(canonicalJson(dependencySet));
    if (payload.evaluationDependencySetDigest !== evaluationDependencySetDigest) failures.push('DEPENDENCY_SET_DIGEST_MISMATCH');
    const graphCriteria = subjects(store, RDF_TYPE, term('EvaluationCriterion')).map((criterion) => oneLiteral(store, criterion, term('canonicalName'))).sort();
    if (canonicalJson([...payload.criteria].sort()) !== canonicalJson(graphCriteria)) failures.push('CRITERION_SET_DRIFT');
    const graphDecisions = subjects(store, RDF_TYPE, term('RealisationDecision'))
      .filter((decision) => has(store, decision, term('decisionState'), iri('urn:usf:decisionstate:accepted')))
      .map((decision) => canonicalDecisionProjection(store, decision)).sort((left, right) => utf8Compare(left.name, right.name));
    const payloadDecisions = payload.decisions.map(({ name, contract, selected, options, credible, notApplicable }) => ({
      name, contract, selected, options: [...options].sort(), credible: [...credible].sort(), notApplicable: [...notApplicable].sort(),
    })).sort((left, right) => utf8Compare(left.name, right.name));
    if (canonicalJson(graphDecisions) !== canonicalJson(payloadDecisions)) failures.push('DECISION_PROJECTION_DRIFT');
    if (!Array.isArray(payload.assessments) || !payload.assessments.every((record) => record && typeof record === 'object')) {
      failures.push('EVIDENCE_ASSESSMENT_RECORDS_INVALID');
    }
    const assessmentEntries = (payload.assessments || []).map((record) => [[
      record.scope, record.decision, record.option, record.component || '', record.criterion,
    ].join('|'), record]);
    const assessmentRecords = new Map(assessmentEntries);
    if (assessmentRecords.size !== assessmentEntries.length) failures.push('EVIDENCE_ASSESSMENT_RECORD_DUPLICATE');
    const componentObservationEntries = Object.entries(payload.componentObservations || {});
    const componentObservations = new Map(componentObservationEntries);
    if (componentObservationEntries.length === 0
        || componentObservationEntries.some(([key, observation]) => key !== observation?.identity
          || !SHA256.test(observation?.observationDigest || '')
          || sha256(canonicalJson({ ...observation, observationDigest: undefined })) !== observation.observationDigest)) {
      failures.push('COMPONENT_OBSERVATION_INVALID');
    }
    const licencePolicyCore = payload.licencePolicy && { ...payload.licencePolicy, policyDigest: undefined };
    const vulnerabilityPolicyCore = payload.vulnerabilityPolicy && { ...payload.vulnerabilityPolicy, policyDigest: undefined };
    if (!exactKeys(payload.licencePolicy, ['policyVersion', 'usageContext', 'compatibleLicenceRules', 'assessmentMethod', 'limitation', 'invalidationCondition', 'policyDigest'])
        || !SHA256.test(payload.licencePolicy?.policyDigest || '')
        || sha256(canonicalJson(licencePolicyCore)) !== payload.licencePolicy.policyDigest
        || !Array.isArray(payload.licencePolicy.compatibleLicenceRules) || payload.licencePolicy.compatibleLicenceRules.length < 3) {
      failures.push('LICENCE_POLICY_INVALID');
    }
    if (!exactKeys(payload.vulnerabilityPolicy, ['policyVersion', 'acceptedSeverity', 'methods', 'limitation', 'invalidationCondition', 'policyDigest'])
        || !SHA256.test(payload.vulnerabilityPolicy?.policyDigest || '')
        || sha256(canonicalJson(vulnerabilityPolicyCore)) !== payload.vulnerabilityPolicy.policyDigest
        || canonicalJson(payload.vulnerabilityPolicy.acceptedSeverity) !== canonicalJson(['none'])) {
      failures.push('VULNERABILITY_POLICY_INVALID');
    }
    const securityScanRules = [
      { id: 'dynamic-code-evaluation', pattern: '\\beval\\s*\\(|new\\s+Function\\s*\\(' },
      { id: 'disabled-tls-verification', pattern: `reject${'Unauthorized'}\\s*:\\s*false|${['NODE', 'TLS', 'REJECT', 'UNAUTHORIZED'].join('_')}` },
      { id: 'implicit-shell-execution', pattern: 'shell\\s*:\\s*true' },
    ];
    const securityScanFindings = [];
    for (const record of currentSourceRecords.filter(({ path }) => /\.(?:[cm]?js)$/.test(path))) {
      const text = readFileSync(resolve(repositoryRoot, record.path), 'utf8');
      for (const rule of securityScanRules) {
        if (new RegExp(rule.pattern, 'u').test(text)) securityScanFindings.push({ path: record.path, rule: rule.id });
      }
    }
    const expectedSecurityScan = {
      scannerIdentity: 'usf-repository-local-security-scan',
      ruleSetDigest: sha256(canonicalJson(securityScanRules)),
      scannedSourceDigest: implementationSourceDigest,
      findingCount: securityScanFindings.length,
      findingsDigest: sha256(canonicalJson(securityScanFindings)),
    };
    if (canonicalJson(payload.repositorySecurityScan) !== canonicalJson(expectedSecurityScan) || securityScanFindings.length !== 0) {
      failures.push('REPOSITORY_SECURITY_SCAN_INVALID');
    }
    const rawManifests = payloadManifests
      .filter(({ scope }) => RAW_ACQUISITION_SCOPES.includes(scope))
      .sort((left, right) => utf8Compare(left.scope, right.scope));
    const deterministicAssessmentInputCore = {
      authorityDigest: payload.authorityDigest,
      implementationSourceDigest,
      rawManifestDigests: rawManifests.map(({ identity: manifestIdentity, manifestDigest }) => ({ identity: manifestIdentity, manifestDigest })),
      criteria: payload.criteria,
      decisions: payload.decisions.map(({ name, contract, selected, options, credible, notApplicable }) => ({
        name, contract, selected, options, credible, notApplicable: [...notApplicable].sort(utf8Compare),
      })),
      componentObservations: payload.componentObservations,
      licencePolicy: payload.licencePolicy,
      vulnerabilityPolicy: payload.vulnerabilityPolicy,
      repositorySecurityScan: payload.repositorySecurityScan,
    };
    const deterministicAssessmentInputDigest = sha256(canonicalJson(deterministicAssessmentInputCore));
    const deterministicAssessmentResultDigest = sha256(canonicalJson({
      assessmentRecords: payload.assessments, compositionProofs: payload.compositionProofs, permutations: payload.permutations,
    }));
    const expectedDerivedCore = {
      identity: DETERMINISTIC_EVALUATION_SCOPE.identity,
      scope: DETERMINISTIC_EVALUATION_SCOPE.scope,
      providerIdentity: DETERMINISTIC_EVALUATION_SCOPE.providerIdentity,
      descriptorDigest: deterministicAssessmentInputDigest,
      collectorDigest: payload.evidenceProducerDigest,
      claimBoundary: ['Deterministic comparison of current authority requirements, candidates, selected-component observations, policies and composition closure'],
      prohibitedClaims: ['Live provider behaviour', 'legal advice or entitlement', 'independent third-party binary vulnerability scan', 'unobserved operational performance']
        .sort(utf8Compare),
      supportedCriteria: [...payload.criteria].sort(utf8Compare),
      prohibitedCriteria: [],
      derivationInputDigest: deterministicAssessmentInputDigest,
      derivationResultDigest: deterministicAssessmentResultDigest,
    };
    const expectedDerived = { ...expectedDerivedCore, manifestDigest: sha256(canonicalJson(expectedDerivedCore)) };
    const derivedManifests = payloadManifests.filter(({ scope }) => scope === DETERMINISTIC_EVALUATION_SCOPE.scope);
    if (derivedManifests.length !== 1 || canonicalJson(derivedManifests[0]) !== canonicalJson(expectedDerived)) {
      failures.push('DETERMINISTIC_EVALUATION_SCOPE_INVALID');
    }
    const supportingManifestMap = new Map(payloadManifests.map((manifest) => [manifest.identity, manifest]));
    if (supportingManifestMap.size !== payloadManifests.length || payloadManifests.some((manifest) =>
      !Array.isArray(manifest.supportedCriteria) || manifest.supportedCriteria.length === 0
      || manifest.supportedCriteria.some((criterion) => !payload.criteria.includes(criterion) || manifest.prohibitedCriteria.includes(criterion)))) {
      failures.push('EVIDENCE_SCOPE_CRITERION_BOUNDARY_INVALID');
    }
    return Object.freeze({
      ok: failures.length === 0,
      failures: Object.freeze(failures.sort()),
      payload,
      assessmentRecords,
      componentObservations,
      supportingManifests: supportingManifestMap,
      authorityDigest: payload.authorityDigest,
      evidenceDigest,
      evidenceProducerDigest: payload.evidenceProducerDigest,
      implementationSourceDigest,
      evaluationDependencySetDigest,
    });
  } catch (error) {
    return Object.freeze({ ok: false, failures: Object.freeze([`EVIDENCE_CONTEXT_ERROR:${error.message}`]) });
  }
}

function addFinding(findings, reasonCode, subject, detail = '') {
  findings.push({ reasonCode, subject: subject?.value ?? String(subject), detail });
}

const CURRENT_EVIDENCE_CACHE = Symbol('currentEvidenceCache');

function currentEvidence(store, evidence, context) {
  const cache = context?.[CURRENT_EVIDENCE_CACHE];
  const cacheKey = evidence ? rdfTermKey(evidence) : 'missing';
  if (cache?.has(cacheKey)) return cache.get(cacheKey);
  const invalid = !evidence || !isType(store, evidence, 'EvidenceResult')
      || !has(store, evidence, term('hasAdmissionState'), iri('urn:usf:evidenceadmissionstate:admitted'))
      || !has(store, evidence, term('hasFreshnessState'), iri('urn:usf:evidencefreshnessstate:fresh'))
      || !has(store, evidence, term('hasIntegrityState'), iri('urn:usf:evidenceintegritystate:valid'))
      || !bool(store, evidence, term('withinValidityScope'));
  const result = invalid ? false : (() => {
      const contentDigests = literalValues(store, evidence, term('contentDigest'));
      const digest = contentDigests[0];
      return Boolean(context?.ok) && SHA256.test(digest || '')
        && contentDigests.length === 1
        && digest === context.evidenceDigest
        && literalValues(store, evidence, term('evaluatedAuthorityDigest')).length === 1
        && oneLiteral(store, evidence, term('evaluatedAuthorityDigest')) === context.authorityDigest
        && literalValues(store, evidence, term('evidenceProducerDigest')).length === 1
        && oneLiteral(store, evidence, term('evidenceProducerDigest')) === context.evidenceProducerDigest;
    })();
  cache?.set(cacheKey, result);
  return result;
}

function validSoleCandidate(store, evaluation, selected, context) {
  const decisions = subjects(store, term('hasDecisionEvaluation'), evaluation);
  if (decisions.length !== 1) return false;
  const [decision] = decisions;
  const sole = objects(store, evaluation, term('hasSoleCandidateJustification'));
  if (sole.length !== 1 || !has(store, sole[0], term('soleCandidateForOption'), selected)
      || literalValues(store, sole[0], term('soleCandidateInvalidationCondition')).length !== 1) return false;
  const evidence = objects(store, sole[0], term('soleCandidateEvidence'));
  const exclusions = objects(store, sole[0], term('hasCandidateClassExclusion'));
  const spaces = objects(store, sole[0], term('hasCandidateSearchSpace'));
  if (evidence.length !== 1 || !currentEvidence(store, evidence[0], context) || spaces.length !== 1) return false;
  const space = spaces[0];
  const classes = objects(store, space, term('searchesRealisationClass'));
  const digest = oneLiteral(store, space, term('candidateSearchSpaceDigest'));
  const considered = objects(store, decision, term('considersOption'));
  const options = considered
    .filter((option) => objects(store, option, term('representsRealisationClass')).some((candidateClass) => classes.some(({ value }) => value === candidateClass.value)));
  const projection = {
    classes: classes.map(({ value }) => value).sort(utf8Compare),
    options: options.map((option) => ({ option: option.value, classes: objects(store, option, term('representsRealisationClass')).map(({ value }) => value).sort(utf8Compare) }))
      .sort((left, right) => utf8Compare(left.option, right.option)),
    exclusions: exclusions.map((exclusion) => ({
      exclusion: exclusion.value,
      classes: objects(store, exclusion, term('excludesRealisationClass')).map(({ value }) => value).sort(utf8Compare),
      reason: literalValues(store, exclusion, term('exclusionReason')),
    })).sort((left, right) => utf8Compare(left.exclusion, right.exclusion)),
  };
  const credibility = objects(store, evaluation, term('hasCandidateCredibilityAssessment'));
  const classCoverageValid = classes.every((candidateClass) => {
    const classOptions = options.filter((option) => has(store, option, term('representsRealisationClass'), candidateClass));
    const classExclusions = exclusions.filter((exclusion) => has(store, exclusion, term('excludesRealisationClass'), candidateClass));
    if (classOptions.length > 1 || classExclusions.length > 1) return false;
    if (classOptions.length === 0) return classExclusions.length === 1;
    const option = classOptions[0];
    const isCredible = credibility.some((record) => has(store, record, term('credibilityForOption'), option)
      && has(store, record, term('credibilityState'), iri('urn:usf:candidatecredibilitystate:credible')));
    return isCredible ? classExclusions.length === 0 : classExclusions.length === 1;
  });
  const decisionName = oneLiteral(store, decision, term('canonicalName'));
  const payloadProjection = context?.payload?.candidateSearchSpaces?.[decisionName];
  return isType(store, space, 'CandidateSearchSpace') && classes.length > 0
    && literalValues(store, space, term('candidateDiscoveryCriteria')).length === 1
    && objects(store, space, term('candidateSearchEvidence')).some((item) => currentEvidence(store, item, context))
    && literalValues(store, space, term('candidateSearchInvalidationCondition')).length === 1
    && SHA256.test(digest || '') && digest === sha256(canonicalJson(projection))
    && payloadProjection?.searchSpaceDigest === digest
    && canonicalJson({ ...payloadProjection, searchSpaceDigest: undefined }) === canonicalJson(projection)
    && objects(store, selected, term('representsRealisationClass')).some((candidateClass) => classes.some(({ value }) => value === candidateClass.value))
    && classCoverageValid
    && exclusions.every((exclusion) => objects(store, exclusion, term('excludesRealisationClass')).length === 1
      && literalValues(store, exclusion, term('exclusionReason')).length === 1
      && objects(store, exclusion, term('exclusionEvidence')).some((item) => currentEvidence(store, item, context)));
}

function validAssessmentEvidence(store, assessment, evaluation, context, decision, option, criterion, component = null) {
  const result = objects(store, assessment, term('assessmentResult'));
  const method = literalValues(store, assessment, term('assessmentMethod'));
  const evidence = objects(store, assessment, term('assessmentEvidence'));
  const bindings = objects(store, assessment, term('hasCriterionEvidenceBinding'));
  const confidence = Number(oneLiteral(store, assessment, term('assessmentConfidence')));
  const scope = component ? 'COMPONENT' : 'OPTION';
  const recordKey = [scope, oneLiteral(store, decision, term('canonicalName')), oneLiteral(store, option, term('canonicalName')),
    component ? oneLiteral(store, component, term('canonicalName')) : '', oneLiteral(store, criterion, term('canonicalName'))].join('|');
  const record = context?.assessmentRecords?.get(recordKey);
  const resultName = result[0]?.value.split(':').at(-1);
  const criterionName = oneLiteral(store, criterion, term('canonicalName'));
  const selectedDecision = context?.payload?.decisions?.find(({ name }) => name === oneLiteral(store, decision, term('canonicalName')));
  const expectedSupport = new Set([DETERMINISTIC_EVALUATION_SCOPE.identity]);
  const addScope = (scope) => {
    const manifest = [...(context?.supportingManifests?.values() || [])].find((item) => item.scope === scope);
    if (manifest?.supportedCriteria.includes(criterionName) && !manifest.prohibitedCriteria.includes(criterionName)) expectedSupport.add(manifest.identity);
  };
  if (record?.result === 'notapplicablewithjustification') {
    // Semantic non-applicability is supported only by the deterministic authority projection.
  } else if (component && record) {
    const componentName = record.component.slice(record.option.length);
    const observation = context?.componentObservations?.get(`urn:usf:componentidentity:${componentName}`);
    if (observation?.kind === 'RepositoryLocalComponent') addScope('HERMETIC_LOCAL_RAW');
    if (observation?.kind === 'PackageComponent') {
      addScope('HERMETIC_LOCAL_RAW');
      if (['supplychainrisk', 'updateandpatchpolicy', 'vulnerabilityexposure'].includes(criterionName)) addScope('EXTERNAL_STATIC_RAW');
    }
    if (observation?.kind === 'RuntimeComponent' || observation?.kind === 'ContainerImageComponent') {
      addScope('HERMETIC_LOCAL_RAW');
      addScope('EXTERNAL_STATIC_RAW');
    }
    if (observation?.kind === 'ExternalProviderComponent') {
      addScope('DECLARED_PROVIDER_METADATA_RAW');
      addScope('EXTERNAL_STATIC_RAW');
    }
  } else if (record && record.option === selectedDecision?.selected) {
    if (['licencecompatibility', 'supplychainrisk', 'updateandpatchpolicy', 'versionstability', 'vulnerabilityexposure'].includes(criterionName)) {
      addScope('HERMETIC_LOCAL_RAW');
      addScope('EXTERNAL_STATIC_RAW');
      addScope('DECLARED_PROVIDER_METADATA_RAW');
    }
    if (['environmentcompatibility', 'hermeticsubstitutefeasibility', 'semanticderivation', 'testability'].includes(criterionName)) addScope('HERMETIC_LOCAL_RAW');
    if (['environmentcompatibility', 'providercompatibility', 'versionstability'].includes(criterionName)) addScope('DECLARED_PROVIDER_METADATA_RAW');
  }
  const expectedSupportingManifests = [...expectedSupport].sort(utf8Compare);
  const supportCore = record && {
    scope: record.scope, decision: record.decision, option: record.option, component: record.component,
    criterion: record.criterion, result: record.result, method: record.method, supportingManifests: expectedSupportingManifests,
    authorityDigest: context?.authorityDigest, implementationSourceDigest: context?.implementationSourceDigest,
  };
  const graphSupportingManifests = bindings.length === 1
    ? objects(store, bindings[0], term('bindingSupportingManifest')).map(({ value }) => value).sort(utf8Compare) : [];
  const supportDigest = bindings.length === 1 ? oneLiteral(store, bindings[0], term('bindingSupportDigest')) : null;
  const supportValid = record && canonicalJson(record.supportingManifests) === canonicalJson(expectedSupportingManifests)
    && record.supportDigest === sha256(canonicalJson(supportCore))
    && supportDigest === record.supportDigest
    && canonicalJson(graphSupportingManifests) === canonicalJson(expectedSupportingManifests)
    && expectedSupportingManifests.every((identity) => {
      const manifest = context?.supportingManifests?.get(identity);
      const resource = iri(identity);
      return manifest && manifest.supportedCriteria.includes(criterionName) && !manifest.prohibitedCriteria.includes(criterionName)
        && has(store, evidence[0], term('hasSupportingEvidenceManifest'), resource)
        && has(store, resource, term('scopeSupportsCriterion'), criterion)
        && !has(store, resource, term('scopeProhibitsCriterion'), criterion);
    });
  const componentMatches = component
    ? objects(store, assessment, term('assessmentForComponent')).length === 1
      && has(store, assessment, term('assessmentForComponent'), component)
      && canonicalJson(objects(store, assessment, term('assessmentForResponsibility')).map(({ value }) => value).sort(utf8Compare))
        === canonicalJson([...(record?.responsibilities || [])].sort(utf8Compare))
    : objects(store, assessment, term('assessmentForComponent')).length === 0
      && objects(store, assessment, term('assessmentForResponsibility')).length === 0;
  return result.length === 1 && result[0].value !== 'urn:usf:assessmentresult:insufficientevidence'
    && method.length === 1 && evidence.length === 1 && currentEvidence(store, evidence[0], context)
    && oneLiteral(store, assessment, term('assessmentAuthorityDigest')) === context?.authorityDigest
    && oneLiteral(store, assessment, term('assessmentEvidenceDigest')) === context?.evidenceDigest
    && componentMatches
    && Number.isFinite(confidence) && confidence >= 0 && confidence <= 1
    && bindings.length === 1
    && has(store, bindings[0], term('bindingForAssessment'), assessment)
    && has(store, bindings[0], term('bindingEvidenceResult'), evidence[0])
    && oneLiteral(store, bindings[0], term('bindingAuthorityDigest')) === context?.authorityDigest
    && oneLiteral(store, bindings[0], term('bindingEvidenceDigest')) === context?.evidenceDigest
    && supportValid
    && has(store, assessment, term('assessmentForEvaluation'), evaluation)
    && record && record.scope === scope && record.result === resultName && record.method === method[0]
    && Number(record.confidence) === confidence
    && record.basis === oneLiteral(store, assessment, term('assessmentLimitation'));
}

function validMitigation(store, assessment, context) {
  const mitigations = objects(store, assessment, term('assessmentMitigation'));
  if (mitigations.length !== 1) return false;
  const mitigation = mitigations[0];
  const evidence = objects(store, mitigation, term('mitigationEvidence'));
  return isType(store, mitigation, 'CriterionMitigation')
    && literalValues(store, mitigation, term('mitigationAccepted')).length === 1
    && bool(store, mitigation, term('mitigationAccepted'))
    && literalValues(store, mitigation, term('mitigationStatement')).length === 1
    && literalValues(store, mitigation, term('mitigationInvalidationCondition')).length === 1
    && evidence.length === 1 && currentEvidence(store, evidence[0], context);
}

function readPermutationRuleSet(store, assessment, context) {
  const ruleSets = objects(store, assessment, term('usesPermutationRuleSet'));
  if (ruleSets.length !== 1) return null;
  const ruleSet = ruleSets[0];
  const dimensions = {};
  for (const dimension of objects(store, ruleSet, term('hasPermutationDimension'))) {
    const keys = literalValues(store, dimension, term('permutationDimensionKey'));
    const values = literalValues(store, dimension, term('permutationAllowedValue')).sort(utf8Compare);
    if (keys.length !== 1 || values.length === 0 || new Set(values).size !== values.length || dimensions[keys[0]]) return null;
    dimensions[keys[0]] = values;
  }
  const rules = objects(store, ruleSet, term('hasPermutationClassificationRule')).map((rule) => {
    const priorities = literalValues(store, rule, term('permutationRulePriority'));
    const dispositions = objects(store, rule, term('permutationRuleDisposition'));
    const conditions = objects(store, rule, term('hasPermutationCondition')).map((condition) => ({
      key: oneLiteral(store, condition, term('permutationConditionDimension')),
      values: literalValues(store, condition, term('permutationConditionValue')).sort(utf8Compare),
    })).sort((left, right) => utf8Compare(left.key, right.key));
    return {
      id: rule.value,
      priority: Number(priorities[0]),
      disposition: dispositions[0]?.value.split(':').at(-1),
      default: bool(store, rule, term('permutationRuleDefault')),
      conditions,
      evidenceCurrent: objects(store, rule, term('permutationRuleEvidence')).some((item) => currentEvidence(store, item, context)),
      equivalenceProofs: objects(store, rule, term('permutationEquivalenceProof')),
    };
  }).sort((left, right) => left.priority - right.priority || utf8Compare(left.id, right.id));
  if (Object.keys(dimensions).length === 0 || rules.length === 0
      || rules.filter(({ default: isDefault }) => isDefault).length !== 1
      || rules.some((rule, index) => !Number.isInteger(rule.priority) || rule.priority !== index + 1 || !CLOSED_DISPOSITIONS.has(rule.disposition)
        || !rule.evidenceCurrent || (rule.default && rule.conditions.length > 0) || (!rule.default && rule.conditions.length === 0)
        || rule.conditions.some(({ key, values }) => !dimensions[key] || values.length === 0 || values.some((value) => !dimensions[key].includes(value))))) return null;
  const core = {
    dimensions: Object.fromEntries(Object.entries(dimensions).sort(([left], [right]) => utf8Compare(left, right))),
    rules: rules.map(({ id, priority, disposition, default: isDefault, conditions }) => ({ id, priority, disposition, default: isDefault, conditions })),
  };
  if (oneLiteral(store, ruleSet, term('permutationRuleSetDigest')) !== sha256(canonicalJson(core))) return null;
  return { ruleSet, core, dimensions: core.dimensions, rules };
}

function classifyPermutation(ruleSet, row) {
  const matching = ruleSet.rules.filter(({ default: isDefault, conditions }) => isDefault
    || conditions.every(({ key, values }) => values.includes(row[key])));
  if (matching.length === 0) return null;
  return matching[0];
}

function validEquivalenceProof(store, rule, matchedRows, ruleSetDigest, context) {
  if (rule.disposition !== 'validandcoveredbyequivalenceproof') return true;
  if (rule.equivalenceProofs.length !== 1) return false;
  const proof = rule.equivalenceProofs[0];
  const rowDigest = sha256(canonicalJson(matchedRows.map(canonicalJson).sort(utf8Compare)));
  return isType(store, proof, 'PermutationEquivalenceProof')
    && bool(store, proof, term('equivalenceProofSuccessful'))
    && bool(store, proof, term('equivalenceProofCurrent'))
    && oneLiteral(store, proof, term('equivalenceProofRuleSetDigest')) === ruleSetDigest
    && oneLiteral(store, proof, term('equivalenceProofMatchedRowsDigest')) === rowDigest
    && oneLiteral(store, proof, term('equivalenceProofAuthorityDigest')) === context?.authorityDigest
    && oneLiteral(store, proof, term('equivalenceProofImplementationDigest')) === context?.implementationSourceDigest
    && objects(store, proof, term('equivalenceProofEvidence')).some((item) => currentEvidence(store, item, context));
}

function cartesianDimensions(dimensions) {
  let rows = [{}];
  for (const key of Object.keys(dimensions)) {
    const values = dimensions[key];
    if (!Array.isArray(values) || values.length === 0 || new Set(values).size !== values.length) return null;
    rows = rows.flatMap((row) => values.map((value) => ({ ...row, [key]: value })));
  }
  return rows;
}

const COMPONENT_KINDS = Object.freeze([
  'PackageComponent', 'RuntimeComponent', 'RepositoryLocalComponent', 'ExternalProviderComponent', 'ContainerImageComponent',
]);

function assessmentCurrent(store, assessment, context, evidencePredicate, expectedEvidence, required = true) {
  if (!assessment) return !required;
  const evidence = objects(store, assessment, evidencePredicate);
  return evidence.length === 1 && evidence[0].value === expectedEvidence?.value
    && currentEvidence(store, evidence[0], context);
}

function validateSupplyChainClosure(store, identity, kind, context, expectedEvidence, findings) {
  const thirdParty = ['PackageComponent', 'RuntimeComponent', 'ExternalProviderComponent', 'ContainerImageComponent'].includes(kind);
  const licences = objects(store, identity, term('hasLicenceAssessment'));
  if (thirdParty && (licences.length !== 1 || !bool(store, licences[0], term('licenceCompatible'))
      || !oneLiteral(store, licences[0], term('licenceIdentifier'))
      || /^unknown$/i.test(oneLiteral(store, licences[0], term('licenceIdentifier')) || '')
      || !assessmentCurrent(store, licences[0], context, term('licenceEvidence'), expectedEvidence)
      || literalValues(store, licences[0], term('licenceUsageContext')).length !== 1
      || literalValues(store, licences[0], term('licenceAssessmentMethod')).length !== 1
      || literalValues(store, licences[0], term('licenceAssessmentLimitation')).length !== 1
      || literalValues(store, licences[0], term('licenceCompatibilityCondition')).length !== 1
      || objects(store, licences[0], term('usesLicenceCompatibilityPolicy')).length !== 1
      || oneLiteral(store, objects(store, licences[0], term('usesLicenceCompatibilityPolicy'))[0], term('licencePolicyDigest')) !== context?.payload?.licencePolicy?.policyDigest)) {
    addFinding(findings, 'LICENCE_ASSESSMENT_INVALID', identity);
  }
  const vulnerabilities = objects(store, identity, term('hasVulnerabilityAssessment'));
  if (vulnerabilities.length !== 1 || !oneLiteral(store, vulnerabilities[0], term('vulnerabilityScannerIdentity'))
      || !oneLiteral(store, vulnerabilities[0], term('vulnerabilityAssessedAt'))
      || literalValues(store, vulnerabilities[0], term('vulnerabilityAssessmentMethod')).length !== 1
      || literalValues(store, vulnerabilities[0], term('vulnerabilityAssessmentScope')).length !== 1
      || literalValues(store, vulnerabilities[0], term('vulnerabilityAssessmentLimitation')).length !== 1
      || oneLiteral(store, vulnerabilities[0], term('vulnerabilityPolicyDigest')) !== context?.payload?.vulnerabilityPolicy?.policyDigest
      || number(store, vulnerabilities[0], term('acceptedVulnerabilityCount')) !== 0
      || !assessmentCurrent(store, vulnerabilities[0], context, term('vulnerabilityEvidence'), expectedEvidence)) {
    addFinding(findings, 'VULNERABILITY_ASSESSMENT_MISSING', identity);
  }
  const supply = objects(store, identity, term('hasSupplyChainAssessment'));
  const observation = context?.componentObservations?.get(identity.value);
  const expectedDependencyDigest = ['PackageComponent', 'RepositoryLocalComponent'].includes(kind) ? observation?.dependencySetDigest : null;
  if (supply.length !== 1 || literalValues(store, supply[0], term('dependencyDisclosureState')).length !== 1
      || literalValues(store, supply[0], term('supplyChainAssessmentLimitation')).length !== 1
      || (expectedDependencyDigest && oneLiteral(store, supply[0], term('componentDependencySetDigest')) !== expectedDependencyDigest)
      || (!expectedDependencyDigest && objects(store, supply[0], term('componentDependencySetDigest')).length !== 0)
      || !assessmentCurrent(store, supply[0], context, term('supplyChainEvidence'), expectedEvidence)) {
    addFinding(findings, 'SUPPLY_CHAIN_ASSESSMENT_MISSING', identity);
  }
}

function canonicalComponentIdentityProjection(store, identity, kind) {
  const projection = {
    identity: identity.value,
    kind,
    version: oneLiteral(store, identity, term('componentVersion')),
    integrity: oneLiteral(store, identity, term('componentIntegrityDigest')),
    lockDigest: oneLiteral(store, identity, term('componentDependencyLockDigest')),
    acquisitionSource: oneLiteral(store, identity, term('componentAcquisitionSource')),
  };
  if (kind === 'RepositoryLocalComponent') {
    projection.sourceDigest = oneLiteral(store, identity, term('componentImplementationSourceDigest'));
    projection.toolchainDigest = oneLiteral(store, identity, term('componentToolchainDigest'));
  }
  return projection;
}

function validateProviderRoleBindings(store, component, identity, kind, findings) {
  const role = objects(store, component, term('componentRole'))[0]?.value.split(':').at(-1);
  if (role !== 'provider') return;
  const bindings = objects(store, component, term('componentProviderBinding'));
  const environments = objects(store, component, term('componentEnvironmentBinding'));
  const componentModes = objects(store, component, term('componentProviderMode'));
  if (bindings.length !== environments.length || bindings.length === 0 || componentModes.length !== 1) {
    addFinding(findings, 'EXTERNAL_PROVIDER_BINDING_MISSING', component);
    return;
  }
  for (const environment of environments) {
    const matching = bindings.filter((binding) => has(store, binding, term('inEnvironment'), environment));
    if (matching.length !== 1) {
      addFinding(findings, 'EXTERNAL_PROVIDER_BINDING_MISSING', component, environment.value);
      continue;
    }
    const binding = matching[0];
    const providers = objects(store, binding, term('bindsProvider'));
    const ports = objects(store, binding, term('bindsPort'));
    const modes = objects(store, binding, term('hasProviderMode'));
    const expectedState = kind === 'ExternalProviderComponent' ? 'external' : 'available';
    if (providers.length !== 1 || ports.length !== 1 || modes.length !== 1
        || modes[0].value !== componentModes[0].value
        || !has(store, binding, term('bindingState'), iri(`urn:usf:bindingstate:${expectedState}`))
        || !has(store, providers[0], term('fulfilsPort'), ports[0])
        || !has(store, providers[0], term('hasProviderMode'), modes[0])) {
      addFinding(findings, 'EXTERNAL_PROVIDER_MODE_OR_ENVIRONMENT_MISMATCH', binding);
    }
  }
}

function validateComponentIdentity(store, component, identity, context, expectedEvidence, findings) {
  const kinds = COMPONENT_KINDS.filter((kind) => isType(store, identity, kind));
  if (kinds.length !== 1) {
    addFinding(findings, 'COMPONENT_KIND_CARDINALITY', identity, String(kinds.length));
    return;
  }
  const [kind] = kinds;
  const version = oneLiteral(store, identity, term('componentVersion'));
  const digest = oneLiteral(store, identity, term('componentIntegrityDigest'));
  const lock = oneLiteral(store, identity, term('componentDependencyLockDigest'));
  const constraints = objects(store, identity, term('hasIntegrityConstraint'));
  const observationDigest = oneLiteral(store, identity, term('componentObservationDigest'));
  const observation = context?.componentObservations?.get(identity.value);
  const identityProjection = canonicalComponentIdentityProjection(store, identity, kind);
  const observedProjection = observation && Object.fromEntries(Object.keys(identityProjection).map((key) => [key, observation[key]]));
  if (!observation || observation.observationDigest !== observationDigest
      || canonicalJson(identityProjection) !== canonicalJson(observedProjection)) {
    addFinding(findings, 'COMPONENT_INTEGRITY_BINDING_MISSING', identity, 'observation');
  }
  if (!LOCKED_VERSION.test(version || '') && kind !== 'ContainerImageComponent') {
    addFinding(findings, kind === 'ExternalProviderComponent' ? 'EXTERNAL_PROVIDER_IDENTITY_INCOMPLETE' : 'FLOATING_COMPONENT_VERSION', identity, version || 'missing');
  }
  if (!INTEGRITY.test(digest || '') || !SHA256.test(lock || '') || constraints.length !== 1
      || oneLiteral(store, constraints[0], term('integrityConstraintDigest')) !== digest) {
    addFinding(findings, 'COMPONENT_INTEGRITY_BINDING_MISSING', identity);
  }
  if (kind === 'RepositoryLocalComponent') {
    const sourceDigest = oneLiteral(store, identity, term('componentImplementationSourceDigest'));
    const toolchainDigest = oneLiteral(store, identity, term('componentToolchainDigest'));
    if (!SHA256.test(sourceDigest || '')) addFinding(findings, 'REPOSITORY_LOCAL_SOURCE_DIGEST_MISSING', identity);
    else if (sourceDigest !== digest) addFinding(findings, 'REPOSITORY_LOCAL_SOURCE_INTEGRITY_MISMATCH', identity);
    if (!SHA256.test(toolchainDigest || '')) addFinding(findings, 'REPOSITORY_LOCAL_TOOLCHAIN_DIGEST_MISSING', identity);
    if (version !== 'source-digest-bound' || oneLiteral(store, identity, term('componentAcquisitionSource')) !== 'urn:usf:repository:usf') {
      addFinding(findings, 'REPOSITORY_LOCAL_SOURCE_DIGEST_MISSING', identity, 'identity');
    }
  }
  if (kind === 'ExternalProviderComponent') {
    if (!/^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/.test(version || '') || !SHA256.test(digest || '')) {
      addFinding(findings, 'EXTERNAL_PROVIDER_IDENTITY_INCOMPLETE', identity);
    }
  }
  if (kind === 'ContainerImageComponent') {
    const source = oneLiteral(store, identity, term('componentAcquisitionSource'));
    const match = OCI_DIGEST_REFERENCE.exec(source || '');
    if (!match) addFinding(findings, 'CONTAINER_IMAGE_MUTABLE_REFERENCE', identity);
    else if (`sha256:${match[1]}` !== digest) addFinding(findings, 'CONTAINER_IMAGE_DIGEST_MISMATCH', identity);
  }
  validateProviderRoleBindings(store, component, identity, kind, findings);
  validateSupplyChainClosure(store, identity, kind, context, expectedEvidence, findings);
}

const assessmentTupleKey = (option, criterion, component = null) => canonicalJson([
  rdfTermKey(option), rdfTermKey(criterion), component ? rdfTermKey(component) : null,
]);

function buildAssessmentIndex(store, evaluation) {
  const index = new Map();
  const append = (key, assessment) => {
    const matches = index.get(key) || [];
    matches.push(assessment);
    index.set(key, matches);
  };
  for (const assessment of subjects(store, term('assessmentForEvaluation'), evaluation)) {
    const options = objects(store, assessment, term('assessmentForOption'));
    const criteria = objects(store, assessment, term('assessmentForCriterion'));
    const components = objects(store, assessment, term('assessmentForComponent'));
    for (const option of options) {
      for (const criterion of criteria) {
        if (components.length === 0) append(assessmentTupleKey(option, criterion), assessment);
        for (const component of components) append(assessmentTupleKey(option, criterion, component), assessment);
      }
    }
  }
  return index;
}

function indexedAssessments(index, option, criterion, component = null) {
  return index.get(assessmentTupleKey(option, criterion, component)) || [];
}

function validateComponentAssessments(store, decision, evaluation, option, components, globalCriteria,
  requirementByCriterion, assessmentIndex, context, findings) {
  for (const component of components) {
    const responsibilities = objects(store, option, term('hasComponentResponsibility'))
      .filter((responsibility) => has(store, responsibility, term('responsibilityForComponent'), component));
    const responsibilityIds = responsibilities.map(({ value }) => value).sort(utf8Compare);
    for (const criterion of globalCriteria) {
      const assessments = indexedAssessments(assessmentIndex, option, criterion, component);
      if (assessments.length === 0) {
        addFinding(findings, 'COMPONENT_CRITERION_ASSESSMENT_MISSING', component, criterion.value);
        continue;
      }
      if (assessments.length > 1) {
        addFinding(findings, 'COMPONENT_CRITERION_ASSESSMENT_DUPLICATE', component, criterion.value);
        continue;
      }
      const assessment = assessments[0];
      if (canonicalJson(objects(store, assessment, term('assessmentForResponsibility')).map(({ value }) => value).sort(utf8Compare)) !== canonicalJson(responsibilityIds)) {
        addFinding(findings, 'COMPONENT_ASSESSMENT_RESPONSIBILITY_MISMATCH', assessment);
      }
      if (!validAssessmentEvidence(store, assessment, evaluation, context, decision, option, criterion, component)) {
        addFinding(findings, 'COMPONENT_ASSESSMENT_EVIDENCE_INVALID', assessment);
      }
      const requirement = (requirementByCriterion.get(criterion.value) || [])[0];
      if (requirement && bool(store, requirement, term('criterionMandatory'))
          && has(store, requirement, term('criterionApplicability'), iri('urn:usf:criterionapplicability:applicable'))
          && !has(store, assessment, term('assessmentResult'), iri('urn:usf:assessmentresult:satisfies'))
          && !validMitigation(store, assessment, context)) {
        addFinding(findings, 'COMPONENT_MANDATORY_CRITERION_NOT_CLOSED', assessment, criterion.value);
      }
    }
  }
}

function validateConcreteMappings(store, decision, evaluation, option, contract, components, context, findings) {
  const realisationMappings = subjects(store, term('mappingForDecision'), decision)
    .filter((mapping) => has(store, mapping, term('mappingState'), iri('urn:usf:mappingstate:active')));
  if (realisationMappings.length !== 1 || !has(store, realisationMappings[0], term('mappingForEvaluation'), evaluation)
      || !has(store, realisationMappings[0], term('mappingForSelectedOption'), option)
      || objects(store, realisationMappings[0], term('mappingToRealisation')).length !== 1) {
    addFinding(findings, 'SELECTED_OPTION_REALISATION_MAPPING_CARDINALITY', decision);
    return;
  }
  const mapping = realisationMappings[0];
  const realisation = objects(store, mapping, term('mappingToRealisation'))[0];
  if (!has(store, realisation, term('authorisedByDecision'), decision) || !has(store, realisation, term('realisesContract'), contract)
      || !has(store, realisation, term('realisesOption'), option)
      || oneLiteral(store, mapping, term('mappingAuthorityDigest')) !== context?.authorityDigest
      || oneLiteral(store, mapping, term('mappingEvaluationDigest')) !== context?.evidenceDigest
      || oneLiteral(store, mapping, term('mappingImplementationSourceDigest')) !== context?.implementationSourceDigest) {
    addFinding(findings, 'SELECTION_MAPPING_DEPENDENCY_DRIFT', mapping);
  }
  for (const component of components) {
    const mappings = subjects(store, term('componentMappingForComponent'), component)
      .filter((item) => has(store, item, term('componentMappingForOption'), option)
        && has(store, item, term('mappingState'), iri('urn:usf:mappingstate:active')));
    if (mappings.length !== 1) {
      addFinding(findings, 'SELECTED_COMPONENT_CONCRETE_MAPPING_CARDINALITY', component, String(mappings.length));
      continue;
    }
    if (oneLiteral(store, mappings[0], term('mappingAuthorityDigest')) !== context?.authorityDigest
        || oneLiteral(store, mappings[0], term('mappingEvaluationDigest')) !== context?.evidenceDigest
        || oneLiteral(store, mappings[0], term('mappingImplementationSourceDigest')) !== context?.implementationSourceDigest) {
      addFinding(findings, 'SELECTION_MAPPING_DEPENDENCY_DRIFT', mappings[0]);
    }
    const implementations = objects(store, mappings[0], term('componentMappingToImplementation'));
    const adapters = objects(store, mappings[0], term('componentMappingToAdapter'));
    const providerBindings = objects(store, mappings[0], term('componentMappingToProviderBinding'));
    const dependencyBindings = objects(store, mappings[0], term('componentMappingToDependencyBinding'));
    const role = objects(store, component, term('componentRole'))[0]?.value.split(':').at(-1);
    const identity = objects(store, component, term('componentIdentity'))[0];
    const dependencyBacked = identity && (isType(store, identity, 'PackageComponent') || isType(store, identity, 'RuntimeComponent') || isType(store, identity, 'ContainerImageComponent'));
    const expected = role === 'provider'
      ? { implementations: 0, adapters: 0, providerBindings: objects(store, component, term('componentProviderBinding')).length, dependencyBindings: 0 }
      : role === 'adapter'
        ? { implementations: 0, adapters: 1, providerBindings: 0, dependencyBindings: dependencyBacked ? 1 : 0 }
        : dependencyBacked
          ? { implementations: 0, adapters: 0, providerBindings: 0, dependencyBindings: 1 }
          : { implementations: 1, adapters: 0, providerBindings: 0, dependencyBindings: 0 };
    const actual = { implementations: implementations.length, adapters: adapters.length, providerBindings: providerBindings.length, dependencyBindings: dependencyBindings.length };
    if (canonicalJson(actual) !== canonicalJson(expected)) addFinding(findings, 'SELECTED_COMPONENT_CONCRETE_MAPPING_CARDINALITY', mappings[0], canonicalJson(actual));
    if (implementations.some((target) => !isType(store, target, 'Implementation'))
        || adapters.some((target) => !isType(store, target, 'Adapter'))
        || providerBindings.some((target) => !isType(store, target, 'Binding'))
        || canonicalJson(providerBindings.map(({ value }) => value).sort(utf8Compare))
          !== canonicalJson(objects(store, component, term('componentProviderBinding')).map(({ value }) => value).sort(utf8Compare))
        || dependencyBindings.some((target) => !isType(store, target, 'DependencyBinding')
          || !has(store, target, term('dependencyBindingForComponentIdentity'), identity)
          || oneLiteral(store, target, term('dependencyBindingVersion')) !== oneLiteral(store, identity, term('componentVersion'))
          || oneLiteral(store, target, term('dependencyBindingIntegrityDigest')) !== oneLiteral(store, identity, term('componentIntegrityDigest'))
          || oneLiteral(store, target, term('dependencyBindingLockDigest')) !== oneLiteral(store, identity, term('componentDependencyLockDigest'))
          || oneLiteral(store, target, term('dependencyBindingAcquisitionSource')) !== oneLiteral(store, identity, term('componentAcquisitionSource'))
          || literalValues(store, target, term('dependencyBindingRepresentation')).length !== 1
          || literalValues(store, target, term('dependencyBindingMaterialisationRule')).length !== 1)) {
      addFinding(findings, 'SELECTED_COMPONENT_CONCRETE_MAPPING_TYPE_MISMATCH', mappings[0]);
    }
  }
}

function validateFailureRegistry(store) {
  const records = subjects(store, RDF_TYPE, term('ValidationFailureCode')).map((resource) => ({
    resource: resource.value,
    reasonCode: oneLiteral(store, resource, term('failureCodeLiteral')),
    gateCounter: oneLiteral(store, resource, term('failureForGateCounter')),
    precedence: number(store, resource, term('failurePrecedence')),
    layers: objects(store, resource, term('failureLayer')).map(({ value }) => value).sort(utf8Compare),
  })).sort((left, right) => left.precedence - right.precedence || utf8Compare(left.reasonCode, right.reasonCode));
  return records.length === FAILURE_REGISTRY.length
    && records.every((record, index) => record.reasonCode === FAILURE_REGISTRY[index].reasonCode
      && record.gateCounter === FAILURE_REGISTRY[index].gateCounter
      && record.precedence === index
      && record.layers.includes('urn:usf:validationlayer:evaluator')
      && record.layers.every((layer) => [
        'urn:usf:validationlayer:evaluator', 'urn:usf:validationlayer:integrity', 'urn:usf:validationlayer:shacl',
      ].includes(layer)));
}

function recomputeComposition(store, decision, evaluation, option, contract, components, context) {
  const decisionName = oneLiteral(store, decision, term('canonicalName'));
  const optionName = oneLiteral(store, option, term('canonicalName'));
  const contractName = oneLiteral(store, contract, term('canonicalName'));
  const facets = objects(store, contract, term('declaresFacet'));
  const ports = subjects(store, term('portForContract'), contract);
  const required = [...new Map([...facets, ...ports].map((item) => [item.value, item])).values()];
  const requiredSet = new Set(required.map(({ value }) => value));
  const componentSet = new Set(components.map(({ value }) => value));
  const responsibilities = objects(store, option, term('hasComponentResponsibility'));
  const ownership = new Map();
  let orphanResponsibilityCount = 0;
  for (const responsibility of responsibilities) {
    const owners = objects(store, responsibility, term('responsibilityOwner'));
    const assignedComponents = objects(store, responsibility, term('responsibilityForComponent'));
    const requirements = objects(store, responsibility, term('responsibilityForRequirement'));
    if (owners.length !== 1 || owners[0].value !== option.value || assignedComponents.length !== 1
        || !componentSet.has(assignedComponents[0].value) || requirements.length !== 1 || !requiredSet.has(requirements[0].value)) {
      orphanResponsibilityCount += 1;
      continue;
    }
    const list = ownership.get(requirements[0].value) || [];
    list.push({ responsibility, component: assignedComponents[0] });
    ownership.set(requirements[0].value, list);
  }
  const uncovered = required.filter(({ value }) => !ownership.has(value));
  const duplicateResponsibilityCount = [...ownership.values()].filter((items) => items.length !== 1).length;
  const usedComponents = new Set([...ownership.values()].flat().map(({ component }) => component.value));
  const unusedComponentCount = components.filter(({ value }) => !usedComponents.has(value)).length;

  let invalidDependencyCount = 0;
  let incompatibleInterfaceCount = 0;
  let incompatibleComponentVersionCount = 0;
  const adjacency = new Map(components.map(({ value }) => [value, new Set()]));
  const directed = new Map(components.map(({ value }) => [value, new Set()]));
  const interfaceUsers = new Map();
  const interfaceEdges = new Map();
  for (const component of components) {
    for (const interfaceResource of objects(store, component, term('componentInterface'))) {
      if (!isType(store, interfaceResource, 'CompositionInterface')
          || !has(store, interfaceResource, term('compositionInterfaceForContract'), contract)
          || literalValues(store, interfaceResource, term('compositionInterfaceResponsibility')).length !== 1
          || literalValues(store, interfaceResource, term('compositionInterfaceSecurityBoundary')).length !== 1
          || literalValues(store, interfaceResource, term('compositionInterfaceFailureBehaviour')).length !== 1) incompatibleInterfaceCount += 1;
      const users = interfaceUsers.get(interfaceResource.value) || new Set();
      users.add(component.value);
      interfaceUsers.set(interfaceResource.value, users);
    }
    for (const dependency of objects(store, component, term('dependsOnOptionComponent'))) {
      if (!componentSet.has(dependency.value) || dependency.value === component.value) {
        invalidDependencyCount += 1;
        continue;
      }
      const sourceInterfaces = new Set(objects(store, component, term('componentInterface')).map(({ value }) => value));
      const targetInterfaces = objects(store, dependency, term('componentInterface')).map(({ value }) => value);
      const sharedInterfaces = targetInterfaces.filter((value) => sourceInterfaces.has(value));
      if (sharedInterfaces.length !== 1) incompatibleInterfaceCount += 1;
      for (const interfaceId of sharedInterfaces) interfaceEdges.set(interfaceId, (interfaceEdges.get(interfaceId) || 0) + 1);
      const sourceIdentity = objects(store, component, term('componentIdentity'))[0];
      const targetIdentity = objects(store, dependency, term('componentIdentity'))[0];
      const compatibility = subjects(store, term('compatibilityForSourceComponent'), component)
        .filter((item) => has(store, item, term('compatibilityForTargetComponent'), dependency));
      const validCompatibility = compatibility.length === 1 && sourceIdentity && targetIdentity && sharedInterfaces.length === 1
        && has(store, compatibility[0], term('compatibilityForInterface'), iri(sharedInterfaces[0]))
        && oneLiteral(store, compatibility[0], term('compatibilitySourceVersion')) === oneLiteral(store, sourceIdentity, term('componentVersion'))
        && oneLiteral(store, compatibility[0], term('compatibilityTargetVersion')) === oneLiteral(store, targetIdentity, term('componentVersion'))
        && oneLiteral(store, compatibility[0], term('compatibilitySourceIntegrityDigest')) === oneLiteral(store, sourceIdentity, term('componentIntegrityDigest'))
        && oneLiteral(store, compatibility[0], term('compatibilityTargetIntegrityDigest')) === oneLiteral(store, targetIdentity, term('componentIntegrityDigest'))
        && bool(store, compatibility[0], term('compatibilitySuccessful'))
        && bool(store, compatibility[0], term('compatibilityCurrent'))
        && objects(store, compatibility[0], term('compatibilityEvidence')).some((item) => currentEvidence(store, item, context));
      if (!validCompatibility) incompatibleComponentVersionCount += 1;
      adjacency.get(component.value).add(dependency.value);
      adjacency.get(dependency.value).add(component.value);
      directed.get(component.value).add(dependency.value);
    }
  }
  incompatibleInterfaceCount += [...interfaceUsers.entries()].filter(([interfaceId, users]) => users.size !== 2 || interfaceEdges.get(interfaceId) !== 1).length;
  const visiting = new Set();
  const visited = new Set();
  const cyclic = (node) => {
    if (visiting.has(node)) return true;
    if (visited.has(node)) return false;
    visiting.add(node);
    for (const next of directed.get(node)) if (cyclic(next)) return true;
    visiting.delete(node);
    visited.add(node);
    return false;
  };
  if (components.some(({ value }) => cyclic(value))) invalidDependencyCount += 1;
  if (components.length > 1) {
    const seen = new Set();
    const queue = [components[0].value];
    while (queue.length) {
      const current = queue.shift();
      if (seen.has(current)) continue;
      seen.add(current);
      queue.push(...adjacency.get(current));
    }
    if (seen.size !== components.length) invalidDependencyCount += components.length - seen.size;
  }

  const permutation = context?.payload?.permutations?.[decisionName];
  const permutationAssessment = objects(store, option, term('hasCompositionPermutationAssessment'))[0];
  const semanticRuleSet = permutationAssessment ? readPermutationRuleSet(store, permutationAssessment, context) : null;
  let permutationValid = Boolean(permutation && semanticRuleSet);
  let equivalenceProofValid = true;
  let unclassifiedPermutationCount = 0;
  let calculatedRows = [];
  if (permutationValid) {
    const baseRows = cartesianDimensions(semanticRuleSet.dimensions);
    if (!baseRows || baseRows.length > 100000) permutationValid = false;
    else {
      calculatedRows = baseRows.map((row) => {
        const rule = classifyPermutation(semanticRuleSet, row);
        return { ...row, disposition: rule?.disposition || null, classificationRule: rule?.id || null };
      });
      if (calculatedRows.some(({ disposition }) => !disposition)) permutationValid = false;
      const rowKeys = calculatedRows.map(canonicalJson);
      const suppliedKeys = permutation.rows.map(canonicalJson);
      permutationValid = permutationValid && canonicalJson(permutation.dimensions) === canonicalJson(semanticRuleSet.dimensions)
        && permutation.ruleSetDigest === sha256(canonicalJson(semanticRuleSet.core))
        && oneLiteral(store, semanticRuleSet.ruleSet, term('permutationRuleSetDigest')) === permutation.ruleSetDigest
        && sha256(canonicalJson(permutation.dimensions)) === permutation.dimensionSetDigest
        && permutation.caseCount === calculatedRows.length
        && new Set(suppliedKeys).size === suppliedKeys.length
        && canonicalJson([...suppliedKeys].sort(utf8Compare)) === canonicalJson([...rowKeys].sort(utf8Compare));
      unclassifiedPermutationCount = calculatedRows.filter(({ disposition }) => !CLOSED_DISPOSITIONS.has(disposition)).length;
      const counts = Object.fromEntries([...CLOSED_DISPOSITIONS].map((value) => [value, calculatedRows.filter(({ disposition }) => disposition === value).length]));
      permutationValid = permutationValid && canonicalJson(permutation.counts) === canonicalJson(counts) && permutation.unclassified === unclassifiedPermutationCount;
      for (const rule of semanticRuleSet.rules) {
        const matchedRows = calculatedRows.filter(({ classificationRule }) => classificationRule === rule.id)
          .map(({ classificationRule, ...row }) => row);
        if (!validEquivalenceProof(store, rule, matchedRows, permutation.ruleSetDigest, context)) equivalenceProofValid = false;
      }
    }
  }
  const sortStrings = (values) => [...values].sort(utf8Compare);
  const componentProjection = components.map((component) => ({
    id: component.value,
    identity: objects(store, component, term('componentIdentity')).map(({ value }) => value),
    role: objects(store, component, term('componentRole')).map(({ value }) => value),
    responsibility: literalValues(store, component, term('componentResponsibility')),
    environments: sortStrings(objects(store, component, term('componentEnvironmentBinding')).map(({ value }) => value)),
    boundaries: Object.fromEntries(COMPONENT_BOUNDARY_PROPERTIES.map((property) => [property, literalValues(store, component, term(property))])),
    dependencies: sortStrings(objects(store, component, term('dependsOnOptionComponent')).map(({ value }) => value)),
    interfaces: sortStrings(objects(store, component, term('componentInterface')).map(({ value }) => value)),
  })).sort((left, right) => utf8Compare(left.id, right.id));
  const responsibilityProjection = responsibilities.map((responsibility) => ({
    id: responsibility.value,
    owner: objects(store, responsibility, term('responsibilityOwner')).map(({ value }) => value),
    component: objects(store, responsibility, term('responsibilityForComponent')).map(({ value }) => value),
    requirement: objects(store, responsibility, term('responsibilityForRequirement')).map(({ value }) => value),
  })).sort((left, right) => utf8Compare(left.id, right.id));
  const interfaces = [...interfaceUsers.keys()].sort(utf8Compare).map((interfaceId) => {
    const interfaceResource = iri(interfaceId);
    return {
      id: interfaceId,
      contracts: sortStrings(objects(store, interfaceResource, term('compositionInterfaceForContract')).map(({ value }) => value)),
      responsibility: literalValues(store, interfaceResource, term('compositionInterfaceResponsibility')),
      securityBoundary: literalValues(store, interfaceResource, term('compositionInterfaceSecurityBoundary')),
      failureBehaviour: literalValues(store, interfaceResource, term('compositionInterfaceFailureBehaviour')),
      users: sortStrings(interfaceUsers.get(interfaceId)),
    };
  });
  const compositionProjection = {
    decision: decision.value,
    evaluation: evaluation.value,
    option: option.value,
    contract: contract.value,
    facets: sortStrings(facets.map(({ value }) => value)),
    ports: sortStrings(ports.map(({ value }) => value)),
    components: componentProjection,
    responsibilities: responsibilityProjection,
    interfaces,
  };
  const compositionProjectionDigest = sha256(canonicalJson(compositionProjection));
  const permutationPayloadDigest = permutation ? sha256(canonicalJson(permutation)) : null;
  const proofCore = {
    option: optionName,
    contract: contractName,
    requiredFacetCount: facets.length,
    coveredFacetCount: facets.filter(({ value }) => (ownership.get(value) || []).length === 1).length,
    requiredPortCount: ports.length,
    implementedPortCount: ports.filter(({ value }) => (ownership.get(value) || []).length === 1).length,
    orphanResponsibilityCount,
    duplicateResponsibilityCount,
    invalidDependencyCount,
    incompatibleInterfaceCount,
    incompatibleComponentVersionCount,
    unusedComponentCount,
    unclassifiedPermutationCount,
    implementationSourceDigest: context?.implementationSourceDigest,
    compositionProjectionDigest,
    permutationDimensionSetDigest: permutation?.dimensionSetDigest,
    permutationRuleSetDigest: permutation?.ruleSetDigest,
    permutationCaseCount: permutation?.caseCount,
    permutationPayloadDigest,
  };
  const proofDigest = sha256(canonicalJson(proofCore));
  const payloadProofValid = canonicalJson(context?.payload?.compositionProofs?.[decisionName])
    === canonicalJson({ ...proofCore, proofDigest });
  return {
    facets, ports, required, uncovered, duplicateResponsibilityCount, orphanResponsibilityCount,
    unusedComponentCount, invalidDependencyCount, incompatibleInterfaceCount, incompatibleComponentVersionCount,
    permutation, permutationValid, equivalenceProofValid, semanticRuleSet,
    expectedDispositions: new Set(calculatedRows.map(({ disposition }) => disposition)), compositionProjection,
    compositionProjectionDigest, permutationPayloadDigest, proofCore, payloadProofValid, proofDigest,
  };
}

function evaluateDecision(store, decision, globalCriteria, findings, context) {
  const findingStart = findings.length;
  let evaluation;
  const finish = () => {
    for (let index = findingStart; index < findings.length; index += 1) {
      findings[index].decision = decision.value;
      if (evaluation) findings[index].evaluation = evaluation.value;
    }
  };
  const state = objects(store, decision, term('decisionState'));
  if (state.length !== 1) {
    addFinding(findings, 'DECISION_STATE_CARDINALITY', decision);
    finish();
    return;
  }
  if (state[0].value !== 'urn:usf:decisionstate:accepted') return;
  const contracts = objects(store, decision, term('decisionForContract'));
  if (contracts.length !== 1 || !isType(store, contracts[0], 'SemanticContract')) {
    addFinding(findings, 'DECISION_CONTRACT_CARDINALITY', decision);
    finish();
    return;
  }
  const evaluations = objects(store, decision, term('hasDecisionEvaluation'));
  if (evaluations.length !== 1 || !isType(store, evaluations[0], 'DecisionEvaluation')) {
    addFinding(findings, 'DECISION_EVALUATION_CARDINALITY', decision);
    finish();
    return;
  }
  evaluation = evaluations[0];
  const assessmentIndex = buildAssessmentIndex(store, evaluation);
  const authorityDigest = oneLiteral(store, evaluation, term('evaluationAuthorityDigest'));
  const evidenceDigest = oneLiteral(store, evaluation, term('evaluationEvidenceDigest'));
  const evaluationEvidence = objects(store, evaluation, term('evaluationEvidenceResult'));
  const duplicateEvidenceRecords = context?.failures?.includes('EVIDENCE_ASSESSMENT_RECORD_DUPLICATE');
  if (duplicateEvidenceRecords) addFinding(findings, 'EVIDENCE_ASSESSMENT_RECORD_DUPLICATE', evaluation);
  const remainingContextFailures = (context?.failures || []).filter((failure) => failure !== 'EVIDENCE_ASSESSMENT_RECORD_DUPLICATE');
  const contextDependencyFailures = (() => {
    if (!context) return ['MISSING_CONTEXT'];
    const failures = [];
    if (!context.ok || remainingContextFailures.length > 0) failures.push('CONTEXT_DRIFT');
    if (authorityDigest !== context?.authorityDigest) failures.push('AUTHORITY_DIGEST_MISMATCH');
    if (evidenceDigest !== context?.evidenceDigest) failures.push('EVIDENCE_DIGEST_MISMATCH');
    if (oneLiteral(store, evaluation, term('evaluationDependencySetDigest')) !== context?.evaluationDependencySetDigest) {
      failures.push('DEPENDENCY_SET_DIGEST_MISMATCH');
    }
    if (oneLiteral(store, evaluation, term('evaluationImplementationSourceDigest')) !== context?.implementationSourceDigest) {
      failures.push('IMPLEMENTATION_SOURCE_DIGEST_MISMATCH');
    }
    if (oneLiteral(store, evaluation, term('evaluationProducerDigest')) !== context?.evidenceProducerDigest) {
      failures.push('EVIDENCE_PRODUCER_DIGEST_MISMATCH');
    }
    if (evaluationEvidence.length !== 1 || !isType(store, evaluationEvidence[0], 'CompositeEvidenceResult')) {
      failures.push('EVIDENCE_RESULT_SHAPE_MISMATCH');
    } else if (!currentEvidence(store, evaluationEvidence[0], context)) {
      failures.push('EVIDENCE_RECORD_NOT_CURRENT');
    }
    return failures;
  })();
  const candidates = objects(store, decision, term('considersOption'));
  const selected = objects(store, decision, term('selectsOption'));
  if (selected.length === 0) addFinding(findings, 'MISSING_SELECTED_OPTION', decision);
  if (selected.length > 1) addFinding(findings, 'MULTIPLE_SELECTED_OPTIONS', decision);
  if (selected.length === 1 && !candidates.some(({ value }) => value === selected[0].value)) addFinding(findings, 'SELECTED_OPTION_OUTSIDE_CANDIDATE_SET', decision);

  const credibilityRecords = objects(store, evaluation, term('hasCandidateCredibilityAssessment'));
  const credibilityByOption = new Map();
  for (const record of credibilityRecords) {
    for (const option of objects(store, record, term('credibilityForOption'))) {
      const list = credibilityByOption.get(option.value) || [];
      list.push(record);
      credibilityByOption.set(option.value, list);
    }
  }
  const canonicalNames = new Map();
  for (const candidate of candidates) {
    const name = oneLiteral(store, candidate, term('canonicalName'));
    const duplicateName = name && canonicalNames.has(name) && canonicalNames.get(name) !== candidate.value;
    if (name) canonicalNames.set(name, candidate.value);
    const records = credibilityByOption.get(candidate.value) || [];
    if (!isType(store, candidate, 'RealisationOption') || duplicateName || records.length !== 1
        || objects(store, records[0], term('credibilityState')).length !== 1
        || !objects(store, records[0], term('credibilityEvidence')).some((item) => currentEvidence(store, item, context))) {
      addFinding(findings, 'FAKE_OR_DUPLICATE_CREDIBLE_CANDIDATE', candidate);
    }
  }
  const credible = candidates.filter((candidate) => (credibilityByOption.get(candidate.value) || [])
    .some((record) => has(store, record, term('credibilityState'), iri('urn:usf:candidatecredibilitystate:credible'))));
  if (credible.length < 2) {
    const sole = objects(store, evaluation, term('hasSoleCandidateJustification'));
    if (selected.length !== 1 || sole.length !== 1) addFinding(findings, 'INCOMPLETE_CANDIDATE_SET', decision);
    else if (!validSoleCandidate(store, evaluation, selected[0], context)) addFinding(findings, 'CANDIDATE_SEARCH_SPACE_INCOMPLETE', decision);
  }

  const requirements = objects(store, evaluation, term('hasCriterionRequirement'));
  const requirementByCriterion = new Map();
  for (const requirement of requirements) {
    for (const criterion of objects(store, requirement, term('requiresCriterion'))) {
      const list = requirementByCriterion.get(criterion.value) || [];
      list.push(requirement);
      requirementByCriterion.set(criterion.value, list);
    }
  }
  for (const criterion of globalCriteria) {
    const requirement = requirementByCriterion.get(criterion.value) || [];
    if (requirement.length !== 1 || (requirement.length === 1
        && (objects(store, requirement[0], term('requiresCriterion')).length !== 1
          || objects(store, requirement[0], term('criterionApplicability')).length !== 1
          || literalValues(store, requirement[0], term('criterionMandatory')).length !== 1
          || !['true', 'false'].includes(oneLiteral(store, requirement[0], term('criterionMandatory')))))) {
      addFinding(findings, 'MISSING_APPLICABLE_CRITERION', decision, criterion.value);
    }
  }
  for (const [criterion, requirementList] of requirementByCriterion) {
    for (const requirement of requirementList) {
      if (has(store, requirement, term('criterionApplicability'), iri('urn:usf:criterionapplicability:notapplicable'))
          && (literalValues(store, requirement, term('applicabilityJustification')).length !== 1
            || bool(store, requirement, term('criterionMandatory')))) {
        addFinding(findings, 'UNJUSTIFIED_NOT_APPLICABLE_CRITERION', requirement, criterion);
      }
    }
  }

  for (const candidate of candidates) {
    for (const criterion of globalCriteria) {
      const assessments = indexedAssessments(assessmentIndex, candidate, criterion);
      if (assessments.length !== 1) {
        addFinding(findings, 'MISSING_CANDIDATE_CRITERION_ASSESSMENT', decision, `${candidate.value}|${criterion.value}|${assessments.length}`);
        continue;
      }
      if (!validAssessmentEvidence(store, assessments[0], evaluation, context, decision, candidate, criterion)) {
        addFinding(findings, 'ASSESSMENT_EVIDENCE_INVALID', assessments[0]);
      }
      const requirement = (requirementByCriterion.get(criterion.value) || [])[0];
      if (requirement && has(store, requirement, term('criterionApplicability'), iri('urn:usf:criterionapplicability:notapplicable'))
          && !has(store, assessments[0], term('assessmentResult'), iri('urn:usf:assessmentresult:notapplicablewithjustification'))) {
        addFinding(findings, 'UNJUSTIFIED_NOT_APPLICABLE_CRITERION', assessments[0], criterion.value);
      }
      const mandatoryApplicable = requirement && bool(store, requirement, term('criterionMandatory'))
        && has(store, requirement, term('criterionApplicability'), iri('urn:usf:criterionapplicability:applicable'));
      const candidateCredible = credible.some(({ value }) => value === candidate.value);
      if (mandatoryApplicable && candidateCredible
          && !has(store, assessments[0], term('assessmentResult'), iri('urn:usf:assessmentresult:satisfies'))
          && !validMitigation(store, assessments[0], context)) {
        addFinding(findings, 'MANDATORY_CRITERION_NOT_CLOSED', assessments[0], criterion.value);
      }
    }
  }

  const selectedValue = selected[0]?.value;
  for (const candidate of credible.filter(({ value }) => value !== selectedValue)) {
    const rejections = objects(store, evaluation, term('hasOptionRejection')).filter((rejection) =>
      has(store, rejection, term('rejectsOption'), candidate) && has(store, rejection, term('rejectionForEvaluation'), evaluation));
    if (rejections.length !== 1 || objects(store, rejections[0], term('hasRejectionReason')).length === 0) {
      addFinding(findings, 'REJECTED_CANDIDATE_REASON_MISSING', candidate);
      continue;
    }
    for (const reason of objects(store, rejections[0], term('hasRejectionReason'))) {
      const evidence = objects(store, reason, term('rejectionEvidence'));
      if (objects(store, reason, term('rejectionCriterion')).length !== 1
          || objects(store, reason, term('rejectionDuration')).length !== 1
          || literalValues(store, reason, term('reopeningCondition')).length !== 1
          || evidence.length !== 1 || !currentEvidence(store, evidence[0], context)) {
        addFinding(findings, 'REJECTION_REASON_EVIDENCE_MISSING', reason);
      }
    }
  }

  if (selected.length !== 1) {
    finish();
    return;
  }
  const option = selected[0];
  const components = objects(store, option, term('hasOptionComponent'));
  for (const component of components) {
    if (COMPONENT_BOUNDARY_PROPERTIES.some((property) => literalValues(store, component, term(property)).length !== 1)) {
      addFinding(findings, 'COMPONENT_BOUNDARY_INCOMPLETE', component);
    }
    const identities = objects(store, component, term('componentIdentity'));
    if (identities.length !== 1) {
      addFinding(findings, 'COMPONENT_INTEGRITY_BINDING_MISSING', component);
      continue;
    }
    const identity = identities[0];
    validateComponentIdentity(store, component, identity, context, evaluationEvidence[0], findings);
  }

  const compositionRequired = components.length > 0;
  if (compositionRequired && !isType(store, option, 'ComposedRealisationOption')) {
    addFinding(findings, 'COMPONENT_RESPONSIBILITY_MISSING', option, 'component-bearing option is not typed as a composition');
  }
  if (compositionRequired || isType(store, option, 'ComposedRealisationOption')) {
    validateComponentAssessments(store, decision, evaluation, option, components, globalCriteria,
      requirementByCriterion, assessmentIndex, context, findings);
    const responsibilities = objects(store, option, term('hasComponentResponsibility'));
    for (const component of components) {
      if (!responsibilities.some((responsibility) => has(store, responsibility, term('responsibilityForComponent'), component)
          && objects(store, responsibility, term('responsibilityForRequirement')).length === 1
          && objects(store, responsibility, term('responsibilityOwner')).length === 1)) {
        addFinding(findings, 'COMPONENT_RESPONSIBILITY_MISSING', component);
      }
    }
    const composition = recomputeComposition(store, decision, evaluation, option, contracts[0], components, context);
    if (composition.uncovered.length || composition.duplicateResponsibilityCount || composition.orphanResponsibilityCount) {
      addFinding(findings, 'COMPOSITION_FACET_UNCOVERED', option,
        `uncovered=${composition.uncovered.length};duplicate=${composition.duplicateResponsibilityCount};orphan=${composition.orphanResponsibilityCount}`);
    }
    if (composition.unusedComponentCount) addFinding(findings, 'COMPONENT_RESPONSIBILITY_MISSING', option, `unused=${composition.unusedComponentCount}`);
    if (composition.invalidDependencyCount) addFinding(findings, 'COMPOSITION_DEPENDENCY_INVALID', option, `dependencies=${composition.invalidDependencyCount}`);
    if (composition.incompatibleInterfaceCount) addFinding(findings, 'COMPOSITION_INTERFACE_INCOMPATIBLE', option, `interfaces=${composition.incompatibleInterfaceCount}`);
    if (composition.incompatibleComponentVersionCount) addFinding(findings, 'COMPONENT_VERSION_INCOMPATIBLE', option, `versions=${composition.incompatibleComponentVersionCount}`);
    const proofs = objects(store, option, term('hasCompositionCoverageProof'));
    if (proofs.length !== 1) addFinding(findings, 'COMPOSITION_COVERAGE_PROOF_STALE_OR_MISSING', option);
    else {
      const proof = proofs[0];
      if (number(store, proof, term('requiredFacetCount')) !== composition.proofCore.requiredFacetCount
          || number(store, proof, term('coveredFacetCount')) !== composition.proofCore.coveredFacetCount
          || number(store, proof, term('requiredPortCount')) !== composition.proofCore.requiredPortCount
          || number(store, proof, term('implementedPortCount')) !== composition.proofCore.implementedPortCount) {
        addFinding(findings, 'COMPOSITION_FACET_UNCOVERED', proof);
      }
      if (number(store, proof, term('invalidDependencyCount')) !== composition.invalidDependencyCount) addFinding(findings, 'COMPOSITION_DEPENDENCY_INVALID', proof);
      if (number(store, proof, term('incompatibleInterfaceCount')) !== composition.incompatibleInterfaceCount) addFinding(findings, 'COMPOSITION_INTERFACE_INCOMPATIBLE', proof);
      if (number(store, proof, term('incompatibleComponentVersionCount')) !== composition.incompatibleComponentVersionCount) addFinding(findings, 'COMPONENT_VERSION_INCOMPATIBLE', proof);
      if (!bool(store, proof, term('compositionProofSuccessful')) || !bool(store, proof, term('compositionProofCurrent'))
          || !composition.payloadProofValid
          || oneLiteral(store, proof, term('compositionProofAuthorityDigest')) !== authorityDigest
          || oneLiteral(store, proof, term('compositionProofImplementationDigest')) !== context?.implementationSourceDigest
          || oneLiteral(store, proof, term('compositionProjectionDigest')) !== composition.compositionProjectionDigest
          || oneLiteral(store, proof, term('compositionPermutationPayloadDigest')) !== composition.permutationPayloadDigest
          || oneLiteral(store, proof, term('compositionProofDigest')) !== composition.proofDigest
          || !objects(store, proof, term('compositionProofEvidence')).some((item) => currentEvidence(store, item, context))
          || number(store, proof, term('orphanResponsibilityCount')) !== composition.orphanResponsibilityCount
          || number(store, proof, term('duplicateResponsibilityCount')) !== composition.duplicateResponsibilityCount
          || number(store, proof, term('invalidDependencyCount')) !== composition.invalidDependencyCount
          || number(store, proof, term('incompatibleInterfaceCount')) !== composition.incompatibleInterfaceCount
          || number(store, proof, term('incompatibleComponentVersionCount')) !== composition.incompatibleComponentVersionCount
          || number(store, proof, term('unusedComponentCount')) !== composition.unusedComponentCount
          || number(store, proof, term('unclassifiedPermutationCount')) !== composition.proofCore.unclassifiedPermutationCount) {
        addFinding(findings, 'COMPOSITION_COVERAGE_PROOF_STALE_OR_MISSING', proof);
      }
    }
    const permutations = objects(store, option, term('hasCompositionPermutationAssessment'));
    if (permutations.length !== 1 || !composition.semanticRuleSet) addFinding(findings, 'PERMUTATION_RULE_SET_INVALID', option);
    else if (!composition.equivalenceProofValid) addFinding(findings, 'PERMUTATION_EQUIVALENCE_PROOF_MISSING', option);
    if (permutations.length !== 1 || !composition.permutationValid
        || (proofs[0] && number(store, proofs[0], term('unclassifiedPermutationCount')) !== 0)
        || permutations.some((item) => !SHA256.test(oneLiteral(store, item, term('permutationDimensionSetDigest')) || '')
          || oneLiteral(store, item, term('permutationDimensionSetDigest')) !== composition.permutation?.dimensionSetDigest
          || number(store, item, term('permutationCaseCount')) < 1
          || number(store, item, term('permutationCaseCount')) !== composition.permutation?.caseCount
          || canonicalJson(objects(store, item, term('permutationDisposition')).map(({ value }) => value.split(':').at(-1)).sort())
            !== canonicalJson([...composition.expectedDispositions].sort())
          || !objects(store, item, term('permutationEvidence')).some((evidence) => currentEvidence(store, evidence, context)))) {
      addFinding(findings, 'UNCLASSIFIED_COMPOSITION_PERMUTATION', option);
    }
    const requiredEnvironments = ['localdev', 'hermetic', 'productionshaped'];
    for (const environment of requiredEnvironments) {
      if (!components.some((component) => has(store, component, term('componentEnvironmentBinding'), iri(`urn:usf:environment:${environment}`)))) {
        addFinding(findings, 'PROVIDER_ENVIRONMENT_BINDING_MISSING', option, environment);
      }
    }
  }

  validateConcreteMappings(store, decision, evaluation, option, contracts[0], components, context, findings);

  const basis = objects(store, evaluation, term('selectionBasisEvidence'));
  if (!bool(store, evaluation, term('independentSelectionBasis'))
      || basis.length !== 1 || !currentEvidence(store, basis[0], context)) {
    addFinding(findings, 'LEGACY_SELECTION_WITHOUT_INDEPENDENT_BASIS', decision);
  }

  const decisionSpecificFindings = findings.length - findingStart;
  if (decisionSpecificFindings === 0 && contextDependencyFailures.length > 0) {
    addFinding(findings, 'EVALUATION_DEPENDENCY_DRIFT', evaluation, contextDependencyFailures.join(','));
  }
  finish();
}

function gateCounters(findings) {
  return Object.fromEntries(GATE_COUNTER_NAMES.map((counter) => [counter, new Set(findings
    .filter(({ reasonCode }) => REASON_COUNTER[reasonCode] === counter)
    .map(({ decision, subject, detail }) => decision || `${subject}|${detail}`)).size]));
}

export function evaluateRealisationOptionClosure(store, context = null) {
  const findings = [];
  const invocationContext = context ? Object.create(context) : null;
  if (invocationContext) Object.defineProperty(invocationContext, CURRENT_EVIDENCE_CACHE, { value: new Map() });
  if (!validateFailureRegistry(store)) addFinding(findings, 'FAILURE_REGISTRY_DRIFT', 'urn:usf:validationregistry:realisationoptionevaluation');
  const validatorTargetGraphs = objects(store, REALISATION_OPTION_VALIDATOR, term('targetsGraph'))
    .map(({ value }) => value).sort(utf8Compare);
  if (canonicalJson(validatorTargetGraphs) !== canonicalJson(REQUIRED_VALIDATOR_TARGET_GRAPHS)) {
    addFinding(findings, 'REALISATION_OPTION_VALIDATOR_GRAPH_SCOPE_MISMATCH', REALISATION_OPTION_VALIDATOR);
  }
  const globalCriteria = subjects(store, RDF_TYPE, term('EvaluationCriterion'));
  const decisions = subjects(store, RDF_TYPE, term('RealisationDecision'));
  const accepted = decisions.filter((decision) => has(store, decision, term('decisionState'), iri('urn:usf:decisionstate:accepted')));
  for (const contract of subjects(store, RDF_TYPE, term('SemanticContract')).filter((item) => bool(store, item, term('requiresRealisationOptionEvaluation'))
    && has(store, item, term('hasActivationState'), iri('urn:usf:contractactivationstate:active')))) {
    const covered = accepted.some((decision) => {
      const evaluations = objects(store, decision, term('hasDecisionEvaluation'));
      return has(store, decision, term('decisionForContract'), contract) && evaluations.length === 1
        && isType(store, evaluations[0], 'DecisionEvaluation') && has(store, evaluations[0], term('evaluationForDecision'), decision);
    });
    if (!covered) addFinding(findings, 'ACTIVE_CONTRACT_SELECTION_EVALUATION_MISSING', contract);
  }
  for (const decision of decisions) evaluateDecision(store, decision, globalCriteria, findings, invocationContext);
  const ordered = findings.sort((left, right) => (REASON_RANK.get(left.reasonCode) ?? 999) - (REASON_RANK.get(right.reasonCode) ?? 999)
    || utf8Compare(left.subject, right.subject) || utf8Compare(left.detail, right.detail));
  const counters = gateCounters(ordered);
  const acceptedDecisions = accepted;
  const closureStates = acceptedDecisions.map((decision) => ({
    decision: decision.value,
    state: ordered.some((finding) => finding.decision === decision.value) ? 'INCOMPLETE' : 'COMPLETE',
  }));
  const core = {
    schemaVersion: 1,
    gate: 'REALISATION_OPTION_EVALUATION_CLOSURE',
    acceptedDecisionCount: acceptedDecisions.length,
    criterionCount: globalCriteria.length,
    findings: ordered,
    gateCounters: counters,
    closureStates,
    reasonCodeVocabularyDigest: sha256(canonicalJson(REASON_PRECEDENCE)),
  };
  return { ...core, ok: ordered.length === 0 && Object.values(counters).every((value) => value === 0), resultDigest: sha256(canonicalJson(core)) };
}

export function realisationOptionShaclFocusRoots(store) {
  const accepted = subjects(store, RDF_TYPE, term('RealisationDecision'))
    .filter((decision) => has(store, decision, term('decisionState'), iri('urn:usf:decisionstate:accepted')));
  const evaluations = accepted.flatMap((decision) => objects(store, decision, term('hasDecisionEvaluation')));
  const contracts = [
    ...accepted.flatMap((decision) => objects(store, decision, term('decisionForContract'))),
    ...subjects(store, RDF_TYPE, term('SemanticContract'))
      .filter((contract) => bool(store, contract, term('requiresRealisationOptionEvaluation'))),
  ];
  const requirements = evaluations.flatMap((evaluation) => objects(store, evaluation, term('hasCriterionRequirement')));
  const assessments = evaluations.flatMap((evaluation) => subjects(store, term('assessmentForEvaluation'), evaluation));
  const mitigations = assessments.flatMap((assessment) => objects(store, assessment, term('assessmentMitigation')));
  const credibility = evaluations.flatMap((evaluation) => objects(store, evaluation, term('hasCandidateCredibilityAssessment')));
  const rejections = evaluations.flatMap((evaluation) => objects(store, evaluation, term('hasOptionRejection')));
  const rejectionReasons = rejections.flatMap((rejection) => objects(store, rejection, term('hasRejectionReason')));
  const options = accepted.flatMap((decision) => [
    ...objects(store, decision, term('considersOption')),
    ...objects(store, decision, term('selectsOption')),
  ]);
  const components = options.flatMap((option) => objects(store, option, term('hasOptionComponent')));
  const identities = components.flatMap((component) => objects(store, component, term('componentIdentity')));
  const interfaces = components.flatMap((component) => objects(store, component, term('componentInterface')));
  const responsibilities = options.flatMap((option) => objects(store, option, term('hasComponentResponsibility')));
  const coverageProofs = options.flatMap((option) => objects(store, option, term('hasCompositionCoverageProof')));
  const permutations = options.flatMap((option) => objects(store, option, term('hasCompositionPermutationAssessment')));
  const permutationRuleSets = permutations.flatMap((item) => objects(store, item, term('usesPermutationRuleSet')));
  const permutationDimensions = permutationRuleSets.flatMap((item) => objects(store, item, term('hasPermutationDimension')));
  const permutationRules = permutationRuleSets.flatMap((item) => objects(store, item, term('hasPermutationClassificationRule')));
  const permutationConditions = permutationRules.flatMap((item) => objects(store, item, term('hasPermutationCondition')));
  const equivalenceProofs = permutationRules.flatMap((item) => objects(store, item, term('permutationEquivalenceProof')));
  const compatibilityAssessments = components.flatMap((component) => subjects(store, term('compatibilityForSourceComponent'), component));
  const searchSpaces = evaluations.flatMap((item) => objects(store, item, term('hasSoleCandidateJustification')))
    .flatMap((item) => objects(store, item, term('hasCandidateSearchSpace')));
  const realisationClasses = searchSpaces.flatMap((item) => objects(store, item, term('searchesRealisationClass')));
  const providerBindings = components.flatMap((component) => objects(store, component, term('componentProviderBinding')));
  const realisationMappings = accepted.flatMap((decision) => subjects(store, term('mappingForDecision'), decision));
  const componentMappings = components.flatMap((component) => subjects(store, term('componentMappingForComponent'), component));
  const failureCodes = subjects(store, RDF_TYPE, term('ValidationFailureCode'));
  const realisations = accepted.flatMap((decision) => subjects(store, term('authorisedByDecision'), decision));
  const implementationResources = realisations.flatMap((realisation) => [
    ...objects(store, realisation, term('realisingImplementation')),
    ...objects(store, realisation, term('viaAdapter')),
  ]);
  const evidenceResources = [OPTION_EVIDENCE, ...objects(store, OPTION_EVIDENCE, term('hasSupportingEvidenceManifest'))];
  const validatorResources = [REALISATION_OPTION_VALIDATOR];
  return [...new Set([
    ...accepted, ...evaluations, ...contracts, ...requirements, ...assessments, ...mitigations,
    ...credibility, ...rejections, ...rejectionReasons, ...options, ...components, ...identities,
    ...interfaces, ...responsibilities, ...coverageProofs, ...permutations, ...permutationRuleSets,
    ...permutationDimensions, ...permutationRules, ...permutationConditions, ...equivalenceProofs,
    ...compatibilityAssessments, ...searchSpaces, ...realisationClasses, ...providerBindings,
    ...realisationMappings, ...componentMappings, ...failureCodes, ...realisations, ...implementationResources,
    ...evidenceResources, ...validatorResources,
  ].map(({ value }) => value))].sort();
}

export function loadSemanticStore(repositoryRoot) {
  const root = resolve(repositoryRoot);
  const manifest = parseYaml(readFileSync(join(root, 'semantic-model', 'manifest.yaml'), 'utf8'));
  const entries = [...manifest.definitionGraphs, ...manifest.authoredGraphs, ...manifest.derivedGraphs];
  const store = new Store();
  const records = [];
  for (const entry of entries) {
    const path = join(root, 'semantic-model', entry.file);
    const bytes = readFileSync(path);
    const format = extname(path) === '.trig' ? 'application/trig' : 'text/turtle';
    store.addQuads(new Parser({ format, baseIRI: 'urn:usf:' }).parse(bytes.toString('utf8')));
    records.push({ path: `semantic-model/${entry.file}`, digest: sha256(bytes) });
  }
  return { store, sourceRecords: records.sort((left, right) => left.path.localeCompare(right.path)), sourceSetDigest: sha256(canonicalJson(records)) };
}

export function runRealisationOptionClosure(repositoryRoot, casRoot = '/var/lib/usf-cas', expected = {}) {
  const loaded = loadSemanticStore(repositoryRoot);
  const context = validateEvidenceContext(repositoryRoot, loaded.store, casRoot, expected);
  const result = evaluateRealisationOptionClosure(loaded.store, context);
  const core = {
    ...result,
    evaluatedAuthorityDigest: context.authorityDigest || null,
    evaluationEvidenceDigest: context.evidenceDigest || null,
    evaluationDependencySetDigest: context.evaluationDependencySetDigest || null,
    evaluationImplementationSourceDigest: context.implementationSourceDigest || null,
    sourceSetDigest: loaded.sourceSetDigest,
    sourceFileCount: loaded.sourceRecords.length,
  };
  return { ...core, evidenceDigest: sha256(canonicalJson(core)) };
}

export const evaluationInternals = Object.freeze({
  RDF_TYPE, term, iri, objects, subjects, has, currentEvidence, validateEvidenceContext, validateRawAcquisition,
  expectedSupportingManifests, RAW_ACQUISITION_SCOPES, recomputeComposition,
});

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const requiredCliValue = (name) => {
    const prefix = `--${name}=`;
    const values = process.argv.filter((value) => value.startsWith(prefix));
    if (values.length !== 1 || values[0].length === prefix.length) throw new Error(`exactly one ${prefix}<value> is required`);
    return values[0].slice(prefix.length);
  };
  const result = runRealisationOptionClosure(process.argv[2] || process.cwd(), '/var/lib/usf-cas', {
    authorityDigest: requiredCliValue('authority-digest'),
    signerFingerprint: requiredCliValue('signer-fingerprint'),
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
  if (!result.ok) process.exitCode = 1;
}
