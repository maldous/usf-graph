import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  canonicalJson,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';

const digest = (value) => sha256(canonicalJson(value));
const compareCodeUnits = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const AUTHORITY_DECISION_VALUE_SOURCES = new Set([
  'urn:usf:dimensionvaluesource:eventconsumer',
  'urn:usf:dimensionvaluesource:eventpublisher',
]);

const remediationRules = Object.freeze({
  actionreachability: {
    cause: 'DOWNSTREAM_DOMAIN_REQUIRING_FOUNDATION_VOCABULARY',
    relevance: 'A universal authorisation model must express whether an identity can reach a capability action.',
    replacementDimensionKey: 'state',
    resolution: 'ActionReachabilityState, ActionReachability and non-authorising foundation witness semantics now supply the finite language; live paths remain downstream derivations.',
  },
  apiprotocolsurface: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'A service capability can expose an authenticated protocol or route surface.',
    resolution: 'The foundation selector covers interfaces and routes; the affected capability must declare an applicable surface or an explicit non-applicability decision.',
  },
  claimconstraint: {
    cause: 'FOUNDATION_VOCABULARY_REPAIRED',
    relevance: 'Token and non-token execution modes require finite claim-constraint semantics.',
    replacementDimensionKey: 'tokenclaimconstrainttemplate',
    resolution: 'TokenClaimConstraintTemplate supplies a finite, digest-bound, non-authorising foundation catalogue.',
  },
  conditionprofile: {
    cause: 'FOUNDATION_VOCABULARY_REPAIRED',
    relevance: 'Conditional authorisation is a reusable service-foundation concept.',
    resolution: 'Structured AuthorisationConditionProfile resources and finite clauses, predicates, operators and compositions replace the absent domain.',
  },
  lifecycleobligation: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'Every deployable process requires explicit finite lifecycle obligations when the process family applies.',
    resolution: 'The finite lifecycle-obligation catalogue is present; each applicable capability must bind an accountable process and its exact obligations or prove matrix non-applicability.',
  },
  consumepermission: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'Event delivery can require a distinct consume permission.',
    resolution: 'requiredConsumePermission and event boundary semantics now exist; each event-bearing capability must bind them or prove non-applicability.',
  },
  consumer: {
    cause: 'AUTHORITY_DECISION_REQUIRED',
    relevance: 'Event delivery needs an accountable consumer identity.',
    resolution: 'requiredConsumer is structurally modelled; the affected capability still needs an evidence-backed consumer or explicit non-applicability decision.',
  },
  datafield: {
    cause: 'FOUNDATION_VOCABULARY_REPAIRED',
    relevance: 'Field-level privacy, tenancy, action and retention semantics are universal data concerns.',
    replacementDimensionKey: 'datamodel',
    resolution: 'DataField and its finite privacy, tenancy, mutability, action, masking, encryption, export, search, redaction and legal-hold relationships close the foundation omission.',
  },
  operation: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'Executable capability behaviour is expressed through commands, queries and gateway operations.',
    resolution: 'The operation closure supports every declared operation form and multiple permission requirements; the affected capability must supply operations or prove non-applicability.',
  },
  publisher: {
    cause: 'AUTHORITY_DECISION_REQUIRED',
    relevance: 'An event flow needs an accountable publisher identity.',
    resolution: 'requiredPublisher is structurally modelled; the affected capability still needs an evidence-backed publisher or explicit non-applicability decision.',
  },
  publishpermission: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'Publishing is an independently authorisable event action.',
    resolution: 'requiredPublishPermission and event boundary semantics now exist; each event-bearing capability must bind them or prove non-applicability.',
  },
  requiredpermutation: {
    cause: 'DOWNSTREAM_DOMAIN_REQUIRING_FOUNDATION_VOCABULARY',
    relevance: 'Required and allowed cells create test, evidence and proof obligations.',
    replacementDimensionKey: 'permutationcell',
    resolution: 'Foundation required-permutation witness and assurance-obligation semantics close expressibility; live values remain downstream of admitted dispositions.',
  },
  resource: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'A capability action needs an exact resource or data-model boundary.',
    resolution: 'The foundation selector derives declared data models and exact resource-class bindings; the affected capability must supply a resource or prove non-applicability.',
  },
  scheduledjob: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'A reusable service can execute scheduled work only through an explicit schedule or workflow relationship.',
    resolution: 'Schedule trigger and workflow vocabulary are present; each applicable capability must declare its scheduled job semantics or prove matrix non-applicability.',
  },
  serviceprocess: {
    cause: 'FOUNDATION_VOCABULARY_REPAIRED',
    relevance: 'Capabilities and deployable processes are distinct accountable semantic boundaries.',
    replacementDimensionKey: 'capability',
    resolution: 'ServiceIdentity, DeployableProcess bindings and finite lifecycle obligations close the missing process foundation.',
  },
  subscribepermission: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'Subscription administration is distinct from publication and delivery consumption.',
    resolution: 'requiredSubscribePermission and event boundary semantics now exist; each event-bearing capability must bind them or prove non-applicability.',
  },
  tokenprofile: {
    cause: 'FOUNDATION_VOCABULARY_REPAIRED',
    relevance: 'Token and explicit non-token execution modes require finite profile semantics.',
    replacementDimensionKey: 'tokenprofiletemplate',
    resolution: 'TokenProfileTemplate supplies six non-authorising finite modes; operational scopes remain prohibited until an active authorisation path exists.',
  },
  trigger: {
    cause: 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING',
    relevance: 'A state transition requires an explicit event or operation trigger.',
    resolution: 'The foundation selector derives onEvent/onOperation relationships; the affected transition must bind one or be explicitly inapplicable.',
  },
});

export function buildFoundationGapRemediationInventory({ foundationAssessment, legacyManifest }) {
  if (legacyManifest?.recordKind !== 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST'
    || !Array.isArray(legacyManifest.gaps)) {
    throw new TypeError('FOUNDATION_GAP_SOURCE_INVALID');
  }
  if (foundationAssessment?.recordKind !== 'USF_FOUNDATION_DOMAIN_CLOSURE_ASSESSMENT'
    || foundationAssessment.foundationDomainClosureComplete !== true) {
    throw new TypeError('FOUNDATION_ASSESSMENT_NOT_CLOSED');
  }
  const domains = new Map();
  for (const family of foundationAssessment.familyRecords) {
    for (const dimension of family.dimensions) {
      domains.set(`${family.family}\0${dimension.key}`, dimension);
    }
  }
  const findings = legacyManifest.gaps.map((gap) => {
    const rule = remediationRules[gap.dimensionKey];
    if (!rule) throw new TypeError(`FOUNDATION_GAP_RULE_ABSENT:${gap.dimensionKey}`);
    const domain = domains.get(`${gap.family}\0${rule.replacementDimensionKey ?? gap.dimensionKey}`);
    if (!domain || domain.valueCount < 1) {
      throw new TypeError(`FOUNDATION_REMEDIATED_DOMAIN_ABSENT:${gap.family}:${gap.dimensionKey}`);
    }
    const remainingCondition = ['CAPABILITY_SPECIFIC_SEMANTIC_MODELLING', 'AUTHORITY_DECISION_REQUIRED']
      .includes(rule.cause)
      ? 'Publish an evidence-backed capability relationship or explicit MATRIX_NOT_APPLICABLE decision; absence remains unresolved.'
      : rule.cause === 'DOWNSTREAM_DOMAIN_REQUIRING_FOUNDATION_VOCABULARY'
        ? 'Derive values only after prerequisite dispositions and authorisation paths exist.'
        : null;
    const core = {
      authorityProvenance: {
        baselineAuthorityDigest: foundationAssessment.baselineAuthorityBinding.authorityDigest,
        foundationAssessmentDigest: foundationAssessment.assessmentDigest,
        metaModelDigest: foundationAssessment.metaModelDigest,
      },
      capability: gap.capability,
      dependencies: [domain.source, ...domain.values ?? []].sort(compareCodeUnits),
      emptyDimension: gap.dimension,
      expectedValueSource: domain.source,
      family: gap.family,
      foundationCauseResolved: true,
      originalSourcePlane: gap.sourcePlane,
      proposedModelAdditionOrDecision: rule.resolution,
      remainingCondition,
      resultingFoundationValueCount: domain.valueCount,
      rootCauseGroup: rule.cause,
      universalRelevance: rule.relevance,
    };
    return { ...core, findingDigest: digest(core) };
  }).sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right)));
  const rootCauseCounts = Object.fromEntries([...new Set(findings.map(({ rootCauseGroup }) => rootCauseGroup))]
    .sort(compareCodeUnits)
    .map((group) => [group, findings.filter(({ rootCauseGroup }) => rootCauseGroup === group).length]));
  const core = {
    foundationAssessmentDigest: foundationAssessment.assessmentDigest,
    foundationVerdict: foundationAssessment.foundationVerdict,
    findingCount: findings.length,
    findings,
    legacyGapSetDigest: digest(legacyManifest.gaps),
    legacyManifestDigest: legacyManifest.universeDigest,
    programmePermutationClosureVerdict: 'PERMUTATION_CLOSURE_INCOMPLETE',
    recordKind: 'USF_FOUNDATION_GAP_REMEDIATION_INVENTORY',
    rootCauseCounts,
    schemaVersion: 1,
  };
  return { ...core, inventoryDigest: digest(core) };
}

export function buildCurrentFoundationGapRemediationInventory({ foundationAssessment, gapReport }) {
  if (gapReport?.recordKind !== 'USF_PERMUTATION_DISPOSITION_GAP_REPORT'
    || !Array.isArray(gapReport.gaps)
    || gapReport.gapSetDigest !== digest([...gapReport.gaps]
      .sort((left, right) => compareCodeUnits(canonicalJson(left), canonicalJson(right))))) {
    throw new TypeError('CURRENT_FOUNDATION_GAP_SOURCE_INVALID');
  }
  const baseline = buildFoundationGapRemediationInventory({
    foundationAssessment,
    legacyManifest: {
      gaps: gapReport.gaps,
      recordKind: 'USF_PERMUTATION_CELL_UNIVERSE_MANIFEST',
      universeDigest: gapReport.planDigest,
    },
  });
  const currentCause = (finding) => {
    const sourcePlane = gapReport.gaps.find((gap) => gap.family === finding.family
      && gap.capability === finding.capability
      && gap.dimension === finding.emptyDimension)?.sourcePlane;
    if (sourcePlane === 'DOWNSTREAM_CLOSURE_DERIVATION') {
      return 'DOWNSTREAM_DOMAIN_REQUIRING_FOUNDATION_VOCABULARY';
    }
    if (AUTHORITY_DECISION_VALUE_SOURCES.has(finding.expectedValueSource)) {
      return 'AUTHORITY_DECISION_REQUIRED';
    }
    return 'CAPABILITY_SPECIFIC_SEMANTIC_MODELLING';
  };
  const findings = baseline.findings.map((finding) => {
    const rootCauseGroup = currentCause(finding);
    const core = {
      ...finding,
      remainingCondition: rootCauseGroup === 'DOWNSTREAM_DOMAIN_REQUIRING_FOUNDATION_VOCABULARY'
        ? 'Derive the finite values only after prerequisite dispositions and authorisation paths close.'
        : 'Publish an evidence-backed capability relationship or explicit MATRIX_NOT_APPLICABLE decision; absence remains unresolved.',
      rootCauseGroup,
    };
    delete core.findingDigest;
    return { ...core, findingDigest: digest(core) };
  });
  const rootCauseCounts = Object.fromEntries([...new Set(findings.map(({ rootCauseGroup }) => rootCauseGroup))]
    .sort(compareCodeUnits)
    .map((group) => [group, findings.filter(({ rootCauseGroup }) => rootCauseGroup === group).length]));
  const core = {
    foundationAssessmentDigest: foundationAssessment.assessmentDigest,
    foundationVerdict: foundationAssessment.foundationVerdict,
    findingCount: findings.length,
    findings,
    gapReportDigest: gapReport.reportDigest,
    gapSetDigest: gapReport.gapSetDigest,
    programmePermutationClosureVerdict: 'PERMUTATION_CLOSURE_INCOMPLETE',
    recordKind: 'USF_CURRENT_FOUNDATION_GAP_REMEDIATION_INVENTORY',
    rootCauseCounts,
    schemaVersion: 1,
  };
  return { ...core, inventoryDigest: digest(core) };
}

function exactArgument(name) {
  const prefix = `--${name}=`;
  const values = process.argv.filter((argument) => argument.startsWith(prefix));
  if (values.length !== 1) throw new TypeError(`EXACT_ARGUMENT_REQUIRED:${name}`);
  return values[0].slice(prefix.length);
}

if (process.argv[1]?.endsWith('foundation-gap-remediation.mjs')) {
  const assessmentBytes = readFileSync(exactArgument('foundation-assessment'));
  if (process.argv.some((argument) => argument.startsWith('--foundation-assessment-digest='))
    && sha256(assessmentBytes) !== exactArgument('foundation-assessment-digest')) {
    throw new TypeError('FOUNDATION_ASSESSMENT_FILE_DIGEST_MISMATCH');
  }
  const assessment = JSON.parse(assessmentBytes.toString('utf8'));
  if (process.argv.some((argument) => argument.startsWith('--gap-report='))) {
    const gapReportBytes = readFileSync(exactArgument('gap-report'));
    if (sha256(gapReportBytes) !== exactArgument('gap-report-digest')) {
      throw new TypeError('FOUNDATION_GAP_REPORT_FILE_DIGEST_MISMATCH');
    }
    const gapReport = JSON.parse(gapReportBytes.toString('utf8'));
    const inventory = buildCurrentFoundationGapRemediationInventory({
      foundationAssessment: assessment,
      gapReport,
    });
    const content = `${canonicalJson(inventory)}\n`;
    const fileDigest = sha256(content);
    const outputPath = join('.work', 'generated', `current-foundation-gap-remediation-inventory-${fileDigest.slice('sha256:'.length)}.json`);
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, content);
    process.stdout.write(`${canonicalJson({
      findingCount: inventory.findingCount,
      inventoryDigest: inventory.inventoryDigest,
      outputPath,
      rootCauseCounts: inventory.rootCauseCounts,
      verdict: inventory.programmePermutationClosureVerdict,
    })}\n`);
  } else {
    const manifest = JSON.parse(readFileSync(exactArgument('legacy-manifest'), 'utf8'));
    process.stdout.write(`${canonicalJson(buildFoundationGapRemediationInventory({
      foundationAssessment: assessment,
      legacyManifest: manifest,
    }))}\n`);
  }
}

export const foundationGapRemediationInternals = Object.freeze({ remediationRules });
