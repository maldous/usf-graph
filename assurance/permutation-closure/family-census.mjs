// Deterministic permutation-family census generator (GOAL.md §16).
// Assigns exactly one family-applicability disposition per capability per
// census family, bound to the current authority digest, from observed
// repository-local semantic signals only. No timestamps, no randomness.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  canonicalJson,
  evaluationInternals,
  loadSemanticStore,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';

const { RDF_TYPE, term, iri, objects, subjects, has } = evaluationInternals;

export const DISPOSITIONS = Object.freeze({
  required: 'MATRIX_REQUIRED',
  notApplicable: 'MATRIX_NOT_APPLICABLE',
});

// Provider modes that are deterministic, repository-local substitutes. Any
// port permitting a mode outside this set declares an external dependency.
const DETERMINISTIC_PROVIDER_MODES = Object.freeze([
  'urn:usf:providermode:deterministictestsubstitute',
  'urn:usf:providermode:repositorylocalservice',
]);

const SECRET_CLASSIFICATION = 'urn:usf:secretclassification:secret';
const NOT_TIME_TRIGGERED_PREFIX = 'Not time-triggered';

const familyRecord = (key, title, applicabilitySignal) => Object.freeze({
  key,
  canonicalName: title.toLowerCase().replace(/[^a-z0-9]/g, ''),
  title,
  orderedDimensions: Object.freeze(title.split(' × ').map((part) => part.trim())),
  applicabilitySignal,
});

export const censusFamilies = Object.freeze([
  familyRecord('f01', 'Capability × Resource × Action', 'ALWAYS_APPLICABLE'),
  familyRecord('f02', 'Capability × Interface × Operation', 'INTERFACES_OR_GATEWAY_OPERATIONS'),
  familyRecord('f03', 'Interface × Transport × InteractionPattern × Direction × SessionModel', 'INTERFACES'),
  familyRecord('f04', 'Operation × PermissionAtom', 'OPERATIONS_OR_GATEWAY_OPERATIONS'),
  familyRecord('f05', 'Operation × Role × ConditionProfile', 'OPERATIONS_OR_GATEWAY_OPERATIONS'),
  familyRecord('f06', 'PermissionAtom × Role × TenantBoundary', 'PERMISSION_BEARING_OPERATIONS'),
  familyRecord('f07', 'PermissionAtom × PrincipalKind × EnvironmentClass', 'PERMISSION_BEARING_OPERATIONS'),
  familyRecord('f08', 'PermissionAtom × ResourceSelectorKind', 'PERMISSION_BEARING_OPERATIONS'),
  familyRecord('f09', 'Operation × SourceState × TargetState', 'STATES_AND_TRANSITIONS'),
  familyRecord('f10', 'Transition × Trigger × PermissionAtom × PrincipalKind', 'STATES_AND_TRANSITIONS'),
  familyRecord('f11', 'Port × Action × ProviderMode × EnvironmentClass', 'PORTS'),
  familyRecord('f12', 'Event × Publisher × Consumer × DeliverySemantics', 'EVENTS_OR_MESSAGES'),
  familyRecord('f13', 'Event × PublishPermission × SubscribePermission × ConsumePermission', 'EVENTS_OR_MESSAGES'),
  familyRecord('f14', 'Queue/Event × AckMode × RetryMode × ReplayMode × DeadLetterMode', 'EVENTS_OR_MESSAGES'),
  familyRecord('f15', 'DataModel × Action × PrivacyClassification × TenantBoundary', 'DATA_MODELS'),
  familyRecord('f16', 'ConfigurationKey × Action × Role × EnvironmentClass', 'CONFIGURATION_KEYS'),
  familyRecord('f17', 'SecretClass × Action × PrincipalKind × EnvironmentClass', 'SECRET_CONFIGURATION_KEYS'),
  familyRecord('f18', 'UI Surface × Action × PermissionAtom × RouteKind', 'UI_SURFACES_OR_ROUTES'),
  familyRecord('f19', 'Form/View × Operation × PermissionAtom', 'FORMS_OR_VIEW_MODELS'),
  familyRecord('f20', 'TokenProfile × PermissionAtom × ClaimConstraint', 'PERMISSION_BEARING_OPERATIONS'),
  familyRecord('f21', 'Operation × ExpectedOutcome × ErrorClass', 'OPERATIONS_OR_GATEWAY_OPERATIONS'),
  familyRecord('f22', 'Operation × AuditEvent × AuditOutcome', 'OPERATIONS_OR_GATEWAY_OPERATIONS'),
  familyRecord('f23', 'Capability × ProviderMode × ProofRung × EnvironmentClass', 'ALWAYS_APPLICABLE'),
  familyRecord('f24', 'RequiredPermutation × Test × Evidence × Proof', 'ALWAYS_APPLICABLE'),
  familyRecord('f25', 'Role × Capability × Action reachability', 'ALWAYS_APPLICABLE'),
  familyRecord('f26', 'Service/Process × Capability × Interface × LifecycleObligation', 'ALWAYS_APPLICABLE'),
  familyRecord('f27', 'ScheduledJob × Action × Role/ServiceIdentity × EnvironmentClass', 'SCHEDULED_WORKFLOWS'),
  familyRecord('f28', 'API/Command × RateLimitPolicy × PermissionAtom × TenantBoundary', 'OPERATIONS_OR_GATEWAY_OPERATIONS'),
  familyRecord('f29', 'Resource × DataField × Action × PrivacyClassification', 'DATA_MODELS'),
  familyRecord('f30', 'ExternalDependency × Operation × FailureMode × RecoveryAction', 'EXTERNAL_DEPENDENCY_PORTS'),
  familyRecord('f31', 'API/ProtocolSurface × Action × AuthenticationMode', 'INTERFACES_OR_ROUTES'),
  familyRecord('f32', 'Resource × Action × RetentionState × LegalHoldState', 'DATA_MODELS'),
  familyRecord('f33', 'PermissionAtom × DelegationMode × AuthenticationStrength', 'PERMISSION_BEARING_OPERATIONS'),
  familyRecord('f34', 'Operation × RateLimitClass × QuotaState × Outcome', 'OPERATIONS_OR_GATEWAY_OPERATIONS'),
]);

// Explicit applicability rule table: one entry per family. Each entry names
// the observed signals it consults, the predicate over those signals, and the
// controlled reason code recorded when the family is not applicable.
const rule = (signalKeys, applies, reasonCode) => Object.freeze({ signalKeys: Object.freeze(signalKeys), applies, reasonCode });
const always = () => rule([], () => true, null);
const FAMILY_RULES = Object.freeze({
  f01: always(),
  f02: rule(['interfaces', 'gatewayOperations'], (s) => s.interfaces > 0 || s.gatewayOperations > 0, 'NO_INTERFACES_DECLARED'),
  f03: rule(['interfaces'], (s) => s.interfaces > 0, 'NO_INTERFACES_DECLARED'),
  f04: rule(['operations', 'gatewayOperations'], (s) => s.operations + s.gatewayOperations > 0, 'NO_OPERATIONS_DECLARED'),
  f05: rule(['operations', 'gatewayOperations'], (s) => s.operations + s.gatewayOperations > 0, 'NO_OPERATIONS_DECLARED'),
  f06: rule(['operations', 'gatewayOperations'], (s) => s.operations > 0 || s.gatewayOperations > 0, 'NO_PERMISSION_ATOMS_DECLARED'),
  f07: rule(['operations', 'gatewayOperations'], (s) => s.operations > 0 || s.gatewayOperations > 0, 'NO_PERMISSION_ATOMS_DECLARED'),
  f08: rule(['operations', 'gatewayOperations'], (s) => s.operations > 0 || s.gatewayOperations > 0, 'NO_PERMISSION_ATOMS_DECLARED'),
  f09: rule(['states', 'transitions'], (s) => s.states > 0 && s.transitions > 0, 'NO_STATES_DECLARED'),
  f10: rule(['states', 'transitions'], (s) => s.states > 0 && s.transitions > 0, 'NO_TRANSITIONS_DECLARED'),
  f11: rule(['ports'], (s) => s.ports > 0, 'NO_PORTS_DECLARED'),
  f12: rule(['events', 'messages'], (s) => s.events > 0 || s.messages > 0, 'NO_EVENTS_DECLARED'),
  f13: rule(['events', 'messages'], (s) => s.events > 0 || s.messages > 0, 'NO_EVENTS_DECLARED'),
  f14: rule(['events', 'messages'], (s) => s.events > 0 || s.messages > 0, 'NO_EVENTS_DECLARED'),
  f15: rule(['dataModels'], (s) => s.dataModels > 0, 'NO_DATA_MODELS_DECLARED'),
  f16: rule(['configurationKeys'], (s) => s.configurationKeys > 0, 'NO_CONFIGURATION_KEYS_DECLARED'),
  f17: rule(['secretConfigurationKeys'], (s) => s.secretConfigurationKeys > 0, 'NO_SECRET_CONFIGURATION_KEYS_DECLARED'),
  f18: rule(['uiSurfaces', 'routes'], (s) => s.uiSurfaces > 0 || s.routes > 0, 'NO_UI_SURFACES_DECLARED'),
  f19: rule(['forms', 'viewModels'], (s) => s.forms > 0 || s.viewModels > 0, 'NO_FORMS_DECLARED'),
  f20: rule(['operations', 'gatewayOperations'], (s) => s.operations > 0 || s.gatewayOperations > 0, 'NO_PERMISSION_ATOMS_DECLARED'),
  f21: rule(['operations', 'gatewayOperations'], (s) => s.operations + s.gatewayOperations > 0, 'NO_OPERATIONS_DECLARED'),
  f22: rule(['operations', 'gatewayOperations'], (s) => s.operations + s.gatewayOperations > 0, 'NO_OPERATIONS_DECLARED'),
  f23: always(),
  f24: always(),
  f25: always(),
  f26: always(),
  f27: rule(['scheduledWorkflows'], (s) => s.scheduledWorkflows > 0, 'NO_SCHEDULED_WORKFLOWS_DECLARED'),
  f28: rule(['operations', 'gatewayOperations'], (s) => s.operations > 0 || s.gatewayOperations > 0, 'NO_OPERATIONS_DECLARED'),
  f29: rule(['dataModels'], (s) => s.dataModels > 0, 'NO_DATA_MODELS_DECLARED'),
  f30: rule(['externalDependencyPorts'], (s) => s.externalDependencyPorts > 0, 'NO_EXTERNAL_DEPENDENCY_PORTS_DECLARED'),
  f31: rule(['interfaces', 'routes'], (s) => s.interfaces > 0 || s.routes > 0, 'NO_PROTOCOL_SURFACES_DECLARED'),
  f32: rule(['dataModels'], (s) => s.dataModels > 0, 'NO_DATA_MODELS_DECLARED'),
  f33: rule(['operations', 'gatewayOperations'], (s) => s.operations > 0 || s.gatewayOperations > 0, 'NO_PERMISSION_ATOMS_DECLARED'),
  f34: rule(['operations', 'gatewayOperations'], (s) => s.operations + s.gatewayOperations > 0, 'NO_OPERATIONS_DECLARED'),
});

const values = (terms) => [...new Set(terms.map(({ value }) => value))].sort();
const isType = (store, subjectIri, className) => has(store, iri(subjectIri), RDF_TYPE, term(className));

function contractForCapability(store, capabilityIri) {
  const contracts = values(objects(store, iri(capabilityIri), term('hasContract')));
  if (contracts.length === 0) throw new Error(`capability ${capabilityIri} declares no usf:hasContract`);
  return contracts[0];
}

export function computeCapabilitySignals(store, capabilityIri) {
  const capability = iri(capabilityIri);
  const contract = iri(contractForCapability(store, capabilityIri));

  const interfaces = values(subjects(store, term('interfaceForContract'), contract));
  const operations = values(interfaces.flatMap((surface) => objects(store, iri(surface), term('hasOperation'))));
  const auditEmittingOperations = operations.filter((operation) => has(store, iri(operation), term('emitsAuditEvent')));

  // Gateway operations carry no contract predicate; they are attributed to
  // the capability declared inside the same named graph.
  const gatewayOperations = values(store
    .getQuads(null, RDF_TYPE, term('GatewayOperation'), null)
    .filter((quad) => store.countQuads(capability, RDF_TYPE, term('Capability'), quad.graph) > 0)
    .map(({ subject }) => subject));

  const ports = values(subjects(store, term('portForContract'), contract));
  const portModes = ports.map((port) => values(objects(store, iri(port), term('permitsProviderMode'))));
  const providerModePermits = portModes.reduce((total, modes) => total + modes.length, 0);
  const externalDependencyPorts = portModes
    .filter((modes) => modes.some((mode) => !DETERMINISTIC_PROVIDER_MODES.includes(mode))).length;

  const events = values(subjects(store, term('eventForContract'), contract));
  const messages = values(subjects(store, term('messageForContract'), contract));

  const workflows = values(subjects(store, term('workflowForContract'), contract));
  const states = values(workflows.flatMap((workflow) => objects(store, iri(workflow), term('hasState'))));
  const transitions = values(workflows.flatMap((workflow) => objects(store, iri(workflow), term('hasTransition'))));
  const scheduledWorkflows = workflows.filter((workflow) => values(objects(store, iri(workflow), term('workflowExecutionPolicy')))
    .flatMap((policy) => objects(store, iri(policy), term('scheduleBehaviour')).map(({ value }) => value))
    .some((behaviour) => !behaviour.startsWith(NOT_TIME_TRIGGERED_PREFIX)));

  // Data models bind to their owning capability through usf:backsCapability;
  // usf:ownedByCapability is used by schema-change/transaction/data-set
  // subjects. Accept both spellings, then keep typed data models only.
  const dataModels = values([
    ...subjects(store, term('backsCapability'), capability),
    ...subjects(store, term('ownedByCapability'), capability),
  ]).filter((subject) => isType(store, subject, 'DataModel'));

  const configurationKeys = values(subjects(store, term('configures'), capability))
    .filter((subject) => isType(store, subject, 'ConfigurationKey'));
  const secretConfigurationKeys = configurationKeys.filter((key) => values(objects(store, iri(key), term('hasSecretClassification')))
    .includes(SECRET_CLASSIFICATION));

  const uiModels = values(objects(store, capability, term('hasUISemanticModel')));
  const viewModels = values(uiModels.flatMap((model) => objects(store, iri(model), term('hasViewModel'))));
  const declaredSurfaces = values(uiModels.flatMap((model) => objects(store, iri(model), term('hasSurface'))));
  const uiSurfaces = declaredSurfaces.filter((subject) => isType(store, subject, 'Surface'));
  const forms = values([
    ...declaredSurfaces.filter((subject) => isType(store, subject, 'Form')).map((value) => ({ value })),
    ...viewModels.flatMap((viewModel) => objects(store, iri(viewModel), term('hasForm'))),
  ]);
  const routes = values(uiSurfaces.flatMap((surface) => objects(store, iri(surface), term('surfaceRoute'))))
    .filter((subject) => isType(store, subject, 'Route'));

  return {
    interfaces: interfaces.length,
    operations: operations.length,
    gatewayOperations: gatewayOperations.length,
    ports: ports.length,
    events: events.length,
    messages: messages.length,
    states: states.length,
    transitions: transitions.length,
    workflows: workflows.length,
    scheduledWorkflows: scheduledWorkflows.length,
    dataModels: dataModels.length,
    configurationKeys: configurationKeys.length,
    secretConfigurationKeys: secretConfigurationKeys.length,
    uiSurfaces: uiSurfaces.length,
    routes: routes.length,
    forms: forms.length,
    viewModels: viewModels.length,
    auditEmittingOperations: auditEmittingOperations.length,
    providerModePermits,
    externalDependencyPorts,
  };
}

export function evaluateFamilyApplicability(familyKey, signals) {
  const familyRule = FAMILY_RULES[familyKey];
  if (!familyRule) throw new Error(`unknown census family ${familyKey}`);
  const observedSignals = Object.fromEntries(familyRule.signalKeys.map((key) => {
    if (!Number.isInteger(signals[key])) throw new Error(`signal ${key} missing for family ${familyKey}`);
    return [key, signals[key]];
  }));
  const applicable = familyRule.applies(signals);
  return {
    disposition: applicable ? DISPOSITIONS.required : DISPOSITIONS.notApplicable,
    reasonCode: applicable ? null : familyRule.reasonCode,
    observedSignals,
  };
}

export function generateFamilyCensus({ repositoryRoot, authorityDigest }) {
  if (!/^sha256:[0-9a-f]{64}$/.test(String(authorityDigest))) {
    throw new Error('authorityDigest must be sha256:<64 lowercase hex>');
  }
  const { store } = loadSemanticStore(repositoryRoot);
  const capabilities = values(subjects(store, RDF_TYPE, term('Capability')));
  const records = [];
  const dispositionCounts = { [DISPOSITIONS.required]: 0, [DISPOSITIONS.notApplicable]: 0 };
  for (const capability of capabilities) {
    const contract = contractForCapability(store, capability);
    const signals = computeCapabilitySignals(store, capability);
    for (const family of censusFamilies) {
      const { disposition, reasonCode, observedSignals } = evaluateFamilyApplicability(family.key, signals);
      dispositionCounts[disposition] += 1;
      records.push({
        capability,
        contract,
        family: family.key,
        canonicalName: family.canonicalName,
        disposition,
        reasonCode,
        signals: observedSignals,
      });
    }
  }
  return {
    recordKind: 'USF_PERMUTATION_FAMILY_CENSUS',
    schemaVersion: 1,
    authorityDigest,
    subjectCount: capabilities.length,
    familyCount: censusFamilies.length,
    records,
    dispositionCounts,
    censusDigest: sha256(canonicalJson(records)),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const prefix = '--authority-digest=';
  const supplied = process.argv.filter((value) => value.startsWith(prefix));
  if (supplied.length !== 1) throw new Error(`exactly one ${prefix}sha256:<digest> argument is required`);
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const census = generateFamilyCensus({ repositoryRoot, authorityDigest: supplied[0].slice(prefix.length) });
  const content = `${canonicalJson(census)}\n`;
  const relativeOutputPath = join('.work', 'generated', `permutation-family-census-${sha256(content).slice('sha256:'.length)}.json`);
  mkdirSync(dirname(join(repositoryRoot, relativeOutputPath)), { recursive: true });
  writeFileSync(join(repositoryRoot, relativeOutputPath), content);
  process.stdout.write(`${canonicalJson({
    subjectCount: census.subjectCount,
    familyCount: census.familyCount,
    required: census.dispositionCounts[DISPOSITIONS.required],
    notApplicable: census.dispositionCounts[DISPOSITIONS.notApplicable],
    censusDigest: census.censusDigest,
    outputPath: relativeOutputPath,
  })}\n`);
}
