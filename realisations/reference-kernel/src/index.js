import { createHash } from 'node:crypto';

export const AUTHORITY_DIGEST = 'sha256:be782888b44161b2c20caf7631aeb0420c93948b9b66b43f1e6e641c7a299148';
export const CONTRACT_CONTEXT_DIGEST = 'sha256:172bc33c004eeb3833709770c17e2a54faa2fed032da3e79e805277827111a16';
export const NONCLAIMS = Object.freeze([
  'urn:usf:nonclaim:noaccessibilitycompliance',
  'urn:usf:nonclaim:nohumanacceptance',
  'urn:usf:nonclaim:nolaunchi18n',
  'urn:usf:nonclaim:nouiproductparity',
]);

export const CONTRACTS = Object.freeze([
  'accessibilitya11ygate',
  'buildversuscomposedecisionframework',
  'codequalityandsecretanddependencyscanning',
  'datagovernancecataloglineageclassificationpiidsrgdpr',
  'delegatedadministrationroles',
  'e2econfidenceladderstageaware',
  'enduserprofileandpreferencesselfservice',
  'environmentspecificvssharedservicemodel',
  'i18nruntimeandvalidation',
  'logsaggregationandtenantscopedsearch',
  'metricsandtraces',
  'openapidrifthardgate',
  'productcatalogplansprices',
  'providerenvironmentclassification',
  'relationalstorageandmigrationsandrls',
  'tenantidentityrecordandfqdn',
  'universalservicefoundationscopeandprinciples',
  'useridentityandtenantmembership',
  'browsertelemetrygrafanafarorumandbrowsertobfftracing',
  'customdomainsdnsownershiptlscanonical',
  'eventbusdurablequeuesdlqredrive',
  'historyreadmodelreadonlyprojection',
  'rbacrolesandpermissions',
  'runtimesecretsmanagement',
  'searchandindexingproductsearch',
  'suborganisations',
  'subscriptionsinvoicespaymentmethodsdunning',
  'tenantdataimportexport',
  'backgroundworkersjobrunner',
  'configurationregistryandhistory',
  'entitlementengine',
  'environmentregistryandbootstrap',
  'notificationdeliveryandpreferencesandchannels',
  'providerconfigurationplane',
  'scheduledjobsbuiltinontheeventsubstrate',
  'tenantdomainactivationauthclient',
  'tenanthostidentityresolution',
  'tenantlifecycleprovisionsuspenddeleteexport',
  'writeonlysecretsettings',
  'apikeyspersonalaccesstokens',
  'authenticationplatform',
  'backupandrestore',
  'brandingandtheming',
  'composedproviderreadinessspine',
  'observabilitybuiltinalertingandincidents',
  'ratelimitingapi',
  'tenantcanonicaldomainsetunset',
  'usagemeteringandmetereventingestion',
  'webhooksdeveloperfacing',
  'workflowenginescheduledjobsapprovals',
  'abacpolicydecisionpoint',
  'apidocsdeveloperportalsdksratelimits',
  'internalservicecatalogandreadiness',
  'pitrretentionlegalholddataresidency',
  'quotaenforcement',
  'supportmodebreakglassaccess',
  'tenantgroups',
  'auditofprivilegedaccess',
  'objectstorageandtenantprefixesandsignedurls',
  'supportticketscustomerhealthannouncements',
  'tenantserviceclickthroughpolicy',
  'compliancereportsaccessreviewsevidencepacks',
  'servicecatalogandproviderintegrationmodel',
  'tenantisolationproof',
]);

const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const array = value => Array.isArray(value);
const text = value => typeof value === 'string' && value.trim().length > 0;
const current = value => value?.freshness === 'fresh' && value?.integrity === 'valid' && value?.admission === 'admitted';
const clone = value => structuredClone(value);
const stable = value => Array.isArray(value)
  ? value.map(stable)
  : record(value)
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]))
    : value;
export const canonicalJson = value => JSON.stringify(stable(value));
export const digest = value => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;

const result = (ok, code, readiness, details = {}) => Object.freeze({
  ok,
  code,
  readiness,
  authorityDigest: AUTHORITY_DIGEST,
  contractContextDigest: CONTRACT_CONTEXT_DIGEST,
  nonclaims: NONCLAIMS,
  ...details,
});
const pass = (code = 'PASS', details = {}) => result(true, code, 'ready', details);
const fail = (code, findings = [], details = {}) => result(false, code, 'not-ready', { findings, ...details });
const degraded = (code, findings = [], details = {}) => result(false, code, 'degraded', { findings, ...details });
const validateEnvelope = input => {
  if (!record(input)) return fail('INVALID_INPUT', ['input must be an object']);
  if (input.authorityDigest !== AUTHORITY_DIGEST) return fail('AUTHORITY_DIGEST_MISMATCH', ['current authority digest is required']);
  return null;
};
const forbiddenSecret = value => record(value) && Object.keys(value).some(key => /password|secret|token|credential|privatekey/i.test(key));

function accessibility(input) {
  if (!array(input.expectations) || !input.expectations.length || !array(input.surfaces) || !input.surfaces.length) return fail('A11Y_INPUT_MISSING', ['expectations and rendered surfaces are required']);
  if (!current(input.evidence)) return fail('A11Y_EVIDENCE_NOT_CURRENT', ['missing, stale, unknown, or invalid results are not pass']);
  const byId = new Map(input.surfaces.map(surface => [surface.id, surface]));
  const findings = [];
  for (const expectation of input.expectations) {
    const surface = byId.get(expectation.surface);
    if (!surface) { findings.push(`missing surface:${expectation.surface}`); continue; }
    for (const landmark of expectation.landmarks ?? []) if (!(surface.landmarks ?? []).includes(landmark)) findings.push(`missing landmark:${expectation.surface}:${landmark}`);
    for (const role of expectation.roles ?? []) if (!(surface.roles ?? []).includes(role)) findings.push(`missing role:${expectation.surface}:${role}`);
    for (const aria of expectation.aria ?? []) if (!(surface.aria ?? []).includes(aria)) findings.push(`missing aria:${expectation.surface}:${aria}`);
    if (!Number.isInteger(surface.axeViolations) || surface.axeViolations !== 0) findings.push(`axe violation:${expectation.surface}`);
  }
  return findings.length ? fail('A11Y_GATE_FAILED', findings, { promotionAllowed: false }) : pass('A11Y_GATE_PASSED', { promotionAllowed: true, auditedSurfaces: byId.size });
}

function decisionFramework(input) {
  const allowed = new Set(['build', 'compose', 'adapter', 'defer', 'reject']);
  if (!array(input.capabilities) || !input.capabilities.length || !array(input.decisions)) return fail('DECISION_CORPUS_MISSING', ['capabilities and decisions are required']);
  const decisions = new Map(input.decisions.map(item => [item.capability, item]));
  const findings = [];
  for (const capability of input.capabilities.filter(item => item.inScope !== false)) {
    const decision = decisions.get(capability.id);
    if (!decision) { findings.push(`undecided:${capability.id}`); continue; }
    if (!allowed.has(decision.disposition)) findings.push(`invalid disposition:${capability.id}`);
    if (!text(decision.rationale) || !record(decision.criteria) || !Object.keys(decision.criteria).length) findings.push(`unjustified:${capability.id}`);
    if (!current(decision.evidence)) findings.push(`stale decision:${capability.id}`);
    if (decision.upgradesProofPosture === true || decision.contradictsContract === true) findings.push(`authority contradiction:${capability.id}`);
  }
  return findings.length ? fail('DECISION_FRAMEWORK_FAILED', findings) : pass('DECISION_FRAMEWORK_PASSED', { decisions: decisions.size });
}

function codeScanning(input) {
  if (!record(input.staticAnalysis) || !record(input.sbom) || !record(input.codeScanning)) return fail('SCANNING_INPUT_MISSING', ['static analysis, SBOM, and code-scanning results are required']);
  const findings = [];
  if ((input.staticAnalysis.errorFindings ?? -1) !== 0) findings.push('static-analysis-errors');
  if (!input.sbom.present || input.sbom.stale || !input.sbom.lockHashMatches || input.sbom.policyViolations) findings.push('sbom-invalid');
  if (!input.routeRegistered) findings.push('security-route-absent');
  if (!input.codeScanning.available) {
    if (input.codeScanning.authoritative) findings.push('authoritative-scanner-absent');
    else return degraded('SCANNER_HONEST_SKIP', ['optional scanner unavailable'], { skipped: true });
  } else if (!input.codeScanning.configValid || !input.codeScanning.databaseValid || (input.codeScanning.findings ?? []).some(item => item.severity === 'error')) findings.push('code-scanning-failed');
  return findings.length ? fail('SCANNING_GATE_FAILED', findings) : pass('SCANNING_GATE_PASSED');
}

function dataGovernance(input) {
  const classifications = new Set(['none', 'PII', 'sensitive']);
  const states = new Set(['open', 'fulfilled']);
  if (!array(input.datasets) || !array(input.requests)) return fail('GOVERNANCE_INPUT_MISSING', ['datasets and requests are required']);
  if (input.providerAvailable !== true) return degraded('GOVERNANCE_PROVIDER_UNAVAILABLE', ['governance adapter unavailable'], { mutationAllowed: false });
  const findings = [];
  for (const dataset of input.datasets) {
    if (!classifications.has(dataset.classification)) findings.push(`invalid classification:${dataset.id}`);
    if (forbiddenSecret(dataset.metadata ?? {})) findings.push(`secret metadata:${dataset.id}`);
  }
  for (const request of input.requests) {
    if (!states.has(request.state)) findings.push(`invalid request state:${request.id}`);
    if (request.state === 'fulfilled' && !record(request.fulfilmentEvidence)) findings.push(`missing fulfilment evidence:${request.id}`);
    if (!text(request.tenantId) || request.tenantId !== input.tenantId) findings.push(`tenant boundary:${request.id}`);
    if (request.state === 'fulfilled' && !text(request.fulfilledBy)) findings.push(`missing attribution:${request.id}`);
  }
  return findings.length ? fail('GOVERNANCE_VALIDATION_FAILED', findings, { mutationAllowed: false }) : pass('GOVERNANCE_VALIDATION_PASSED', { mutationAllowed: true });
}

function delegatedAdministration(input) {
  const operation = input.operation;
  const caller = input.caller;
  if (!record(caller) || !text(caller.id) || !text(caller.organisationId) || !array(input.records)) return fail('DELEGATION_INPUT_MISSING', ['caller and records are required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('DELEGATION_PROVIDER_UNAVAILABLE', ['delegation store unavailable'], { mutated: false });
  const before = canonicalJson(input.records);
  const records = clone(input.records);
  const role = caller.role;
  if (operation === 'grant') {
    if (!['system-admin', 'tenant-admin'].includes(role) || !caller.permissions?.includes('delegation:write')) return fail('STATIC_PERMISSION_DENIED', ['grant not authorised'], { mutated: false });
    if (!record(input.grant) || input.grant.organisationId !== caller.organisationId || !text(input.grant.granteeUserId)) return fail('INVALID_DELEGATION', ['invalid tenant-scoped grant'], { mutated: false });
    const duplicate = records.some(item => item.organisationId === caller.organisationId && item.granteeUserId === input.grant.granteeUserId && item.scope === input.grant.scope && !item.revokedAt && (!item.expiresAt || Date.parse(item.expiresAt) > Date.parse(input.now)));
    if (duplicate) return fail('DELEGATION_ALREADY_ACTIVE', ['duplicate active delegation'], { mutated: false });
    records.push({ ...clone(input.grant), granterUserId: caller.id, grantedBy: caller.id, grantedAt: input.now, revokedAt: null, revokedBy: null });
  } else if (operation === 'revoke') {
    if (role !== 'system-admin' || !caller.permissions?.includes('delegation:write')) return fail('STATIC_PERMISSION_DENIED', ['revoke is system-admin only'], { mutated: false });
    const item = records.find(row => row.id === input.id && row.organisationId === caller.organisationId);
    if (!item) return fail('NOT_FOUND', ['delegation not found'], { mutated: false });
    item.revokedAt = input.now; item.revokedBy = caller.id;
  } else if (operation === 'list') {
    if (!caller.permissions?.includes('delegation:read')) return fail('STATIC_PERMISSION_DENIED', ['list not authorised'], { mutated: false });
    const visible = records.filter(item => item.organisationId === caller.organisationId && (['system-admin', 'tenant-admin'].includes(role) || item.granteeUserId === caller.id));
    return pass('DELEGATION_LISTED', { records: visible, mutated: false });
  } else return fail('INVALID_OPERATION', ['unknown delegation operation'], { mutated: false });
  return before === canonicalJson(records) ? fail('NO_STATE_CHANGE', ['mutation produced no state change'], { mutated: false }) : pass('DELEGATION_MUTATED', { records, mutated: true });
}

function confidenceLadder(input) {
  if (!array(input.stages) || !array(input.results)) return fail('LADDER_INPUT_MISSING', ['stage registry and results are required']);
  const findings = [];
  for (const stage of input.stages) {
    for (const journey of stage.requiredJourneys ?? []) {
      const evidence = input.results.find(item => item.stage === stage.id && item.journey === journey);
      if (!evidence || evidence.passed !== true || !current(evidence)) findings.push(`stage evidence not-pass:${stage.id}:${journey}`);
      if (evidence && evidence.posture !== stage.requiredPosture) findings.push(`posture substitution:${stage.id}:${journey}`);
    }
  }
  return findings.length ? fail('CONFIDENCE_LADDER_FAILED', findings, { promotionAllowed: false }) : pass('CONFIDENCE_LADDER_PASSED', { promotionAllowed: true });
}

function profileSelfService(input) {
  const caller = input.caller;
  if (!record(caller) || !text(caller.userId) || !text(caller.tenantId)) return fail('NO_TENANT', ['authenticated tenant context is required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('PROFILE_PROVIDER_UNAVAILABLE', ['profile store unavailable'], { mutated: false });
  if (!caller.permissions?.includes('profile:self:update')) return fail('STATIC_PERMISSION_DENIED', ['self update permission required'], { mutated: false });
  if (!record(input.profile) || input.profile.userId !== caller.userId || input.profile.tenantId !== caller.tenantId) return fail('SELF_SCOPE_VIOLATION', ['user and tenant derive from session'], { mutated: false });
  if (!text(input.patch?.displayName)) return fail('VALIDATION_ERROR', ['display name must not be empty'], { mutated: false });
  if (forbiddenSecret(input.patch) || forbiddenSecret(input.notificationPayload ?? {})) return fail('NOT_NOTIFIABLE', ['secret-bearing fields are forbidden'], { mutated: false });
  const profile = { ...clone(input.profile), ...clone(input.patch), userId: caller.userId, tenantId: caller.tenantId };
  return pass('PROFILE_UPDATED', { profile, mutated: true });
}

function environmentServiceModel(input) {
  if (!array(input.services) || !input.services.length) return fail('SERVICE_CLASSIFICATION_MISSING', ['service classifications are required']);
  const findings = [];
  for (const service of input.services) {
    if (!['shared', 'environment-specific'].includes(service.classification)) findings.push(`invalid classification:${service.id}`);
    if (service.classification === 'environment-specific' && (!text(service.environment) || service.routesTo?.some(route => route.environment !== service.environment))) findings.push(`environment boundary:${service.id}`);
    if (service.classification === 'shared' && service.routesTo?.some(route => route.isolatedInstance === true)) findings.push(`inconsistent shared routing:${service.id}`);
    if (!current(service.evidence)) findings.push(`stale classification:${service.id}`);
  }
  return findings.length ? fail('ENVIRONMENT_SERVICE_MODEL_FAILED', findings) : pass('ENVIRONMENT_SERVICE_MODEL_PASSED');
}

const interpolation = value => [...String(value).matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)].map(match => match[1]).sort();
function i18n(input) {
  if (!record(input.locales) || !array(input.requiredKeys) || !array(input.usedKeys)) return fail('I18N_CORPUS_MISSING', ['locale maps and key sets are required']);
  const findings = [];
  const localeEntries = Object.entries(input.locales);
  for (const [locale, messages] of localeEntries) {
    for (const key of input.requiredKeys) if (!text(messages?.[key])) findings.push(`missing key:${locale}:${key}`);
    for (const duplicate of input.duplicates?.[locale] ?? []) findings.push(`duplicate key:${locale}:${duplicate}`);
  }
  const allKeys = new Set(localeEntries.flatMap(([, messages]) => Object.keys(messages ?? {})));
  for (const used of input.usedKeys) if (!allKeys.has(used)) findings.push(`used key missing:${used}`);
  for (const key of allKeys) {
    const signatures = localeEntries.filter(([, messages]) => own(messages ?? {}, key)).map(([, messages]) => interpolation(messages[key]).join(','));
    if (new Set(signatures).size > 1) findings.push(`interpolation mismatch:${key}`);
  }
  const exceptions = new Set(input.rawLiteralExceptions ?? []);
  for (const literal of input.rawLiterals ?? []) if (!exceptions.has(literal)) findings.push(`raw literal:${literal}`);
  if (findings.length && input.strictFailOnRawLiteral !== true && findings.every(item => item.startsWith('raw literal:'))) return pass('I18N_REPORT_ONLY_FINDINGS', { findings, reportOnly: true });
  return findings.length ? fail('I18N_VALIDATION_FAILED', findings) : pass('I18N_VALIDATION_PASSED');
}

function logSearch(input) {
  if (!record(input.caller) || !input.caller.permissions?.includes('logs:read') || !text(input.caller.tenantId)) return fail('STATIC_PERMISSION_DENIED', ['admin tenant-scoped permission required']);
  if (!record(input.query) || input.query.tenantId !== input.caller.tenantId) return fail('TENANT_SCOPE_REQUIRED', ['query must be hard-bound to caller tenant']);
  if (!Number.isFinite(input.query.from) || !Number.isFinite(input.query.to) || input.query.from >= input.query.to || input.query.to - input.query.from > 86_400_000) return fail('QUERY_BOUNDS_INVALID', ['bounded time range required']);
  if (input.providerAvailable !== true) return degraded('LOG_PROVIDER_UNAVAILABLE', ['search adapter unavailable'], { entries: null });
  const entries = (input.entries ?? []).filter(item => item.tenantId === input.caller.tenantId && item.timestamp >= input.query.from && item.timestamp <= input.query.to);
  if (entries.some(item => !text(item.service) || !text(item.level))) return fail('LOG_ENTRY_INVALID', ['service and level labels are required']);
  return pass('LOG_SEARCH_PASSED', { entries, complete: true });
}

function metricsTraces(input) {
  if (!record(input.caller) || !input.caller.permissions?.includes('observability:read')) return fail('STATIC_PERMISSION_DENIED', ['admin observability permission required']);
  if (input.providerAvailable !== true || input.collectorAvailable !== true) return degraded('OBSERVABILITY_PROVIDER_UNAVAILABLE', ['metrics provider and collector are required']);
  const metricVocabulary = new Set(['request_total', 'failure_total', 'readiness_state']);
  const attributeVocabulary = new Set(['tenant.id', 'request.id', 'route', 'usecase', 'provider']);
  const findings = [];
  for (const metric of input.metrics ?? []) if (!metricVocabulary.has(metric.name) || !text(metric.tenantId)) findings.push(`invalid metric:${metric.name}`);
  for (const span of input.spans ?? []) {
    if (!text(span.attributes?.['tenant.id']) || Object.keys(span.attributes ?? {}).some(key => !attributeVocabulary.has(key))) findings.push(`invalid span:${span.id}`);
  }
  return findings.length ? fail('METRICS_TRACES_VALIDATION_FAILED', findings) : pass('METRICS_TRACES_VALIDATION_PASSED');
}

function openapi(input) {
  if (!array(input.routes) || !array(input.operations)) return fail('OPENAPI_INPUT_MISSING', ['route table and OpenAPI operations are required']);
  const key = item => `${String(item.method).toUpperCase()} ${item.path}`;
  const routes = new Set(input.routes.map(key));
  const operations = new Map(input.operations.map(item => [key(item), item]));
  const findings = [];
  for (const route of routes) if (!operations.has(route)) findings.push(`missing route:${route}`);
  for (const operation of operations.keys()) if (!routes.has(operation)) findings.push(`extra route:${operation}`);
  for (const [operation, value] of operations) {
    if ((value.unresolvedReferences ?? []).length) findings.push(`unresolved reference:${operation}`);
    if (value.hasJsonRequestBody && !value.requestSchema) findings.push(`schemaless request:${operation}`);
    if (value.hasJsonResponseBody && !value.responseSchema && !value.bodylessStatus) findings.push(`schemaless response:${operation}`);
  }
  if (findings.length && input.strict !== true) return pass('OPENAPI_REPORT_ONLY_FINDINGS', { findings, reportOnly: true });
  return findings.length ? fail('OPENAPI_DRIFT', findings, { exitCode: 1 }) : pass('OPENAPI_GATE_PASSED', { exitCode: 0 });
}

function productCatalog(input) {
  if (!record(input.caller) || !array(input.products) || !array(input.plans) || !array(input.prices)) return fail('CATALOG_INPUT_MISSING', ['caller and catalog hierarchy are required']);
  if (input.providerAvailable !== true) return degraded('CATALOG_PROVIDER_UNAVAILABLE', ['catalog adapter unavailable'], { mutationAllowed: false });
  const operator = input.operation === 'tenant-read' ? input.caller.permissions?.includes('billing:read') : input.caller.permissions?.includes('platform:billing:admin');
  if (!operator) return fail('STATIC_PERMISSION_DENIED', ['catalog permission required'], { mutationAllowed: false });
  if (input.operation === 'tenant-read' && input.tenantId !== input.caller.tenantId) return fail('TENANT_SCOPE_VIOLATION', ['tenant catalog is caller-scoped'], { mutationAllowed: false });
  const productIds = new Set(input.products.map(item => item.id));
  const planIds = new Set(input.plans.map(item => item.id));
  const findings = [];
  for (const product of input.products) if (!text(product.id) || !text(product.name) || typeof product.active !== 'boolean') findings.push(`invalid product:${product.id}`);
  for (const plan of input.plans) if (!productIds.has(plan.productId) || !text(plan.currency) || !text(plan.billingPeriod)) findings.push(`invalid plan:${plan.id}`);
  for (const price of input.prices) if (!planIds.has(price.planId) || !Number.isInteger(price.version) || price.version < 1 || !Number.isInteger(price.unitAmount) || price.unitAmount < 0 || !text(price.priceType)) findings.push(`invalid price:${price.id}`);
  return findings.length ? fail('CATALOG_VALIDATION_FAILED', findings, { mutationAllowed: false }) : pass('CATALOG_VALIDATION_PASSED', { mutationAllowed: true });
}

function providerClassification(input) {
  if (!array(input.providers) || !input.providers.length) return fail('PROVIDER_CLASSIFICATION_MISSING', ['provider declarations are required']);
  const modes = new Set(['hermetic-mock', 'sandbox', 'live-external-provider']);
  const environments = new Set(['local', 'ci', 'staging', 'production-shaped', 'production-live']);
  const findings = [];
  for (const provider of input.providers) {
    if (!modes.has(provider.mode) || !environments.has(provider.environment)) findings.push(`invalid posture:${provider.id}`);
    if (provider.mode === 'hermetic-mock' && provider.satisfies?.includes('live-external-provider')) findings.push(`mode upgrade:${provider.id}`);
    if (provider.environment === 'production-shaped' && provider.satisfies?.includes('production-live')) findings.push(`environment upgrade:${provider.id}`);
    if (!current(provider.evidence)) findings.push(`stale posture:${provider.id}`);
  }
  return findings.length ? fail('PROVIDER_CLASSIFICATION_FAILED', findings) : pass('PROVIDER_CLASSIFICATION_PASSED');
}

function relationalStorage(input) {
  if (!array(input.migrations) || !array(input.tables) || !record(input.applicationRole)) return fail('RELATIONAL_INPUT_MISSING', ['migration ledger, tenant tables, and application role are required']);
  if (input.providerAvailable !== true) return degraded('RELATIONAL_PROVIDER_UNAVAILABLE', ['canonical relational substrate unavailable'], { mutationAllowed: false });
  const findings = [];
  const names = input.migrations.map(item => item.file);
  if (canonicalJson(names) !== canonicalJson([...names].sort())) findings.push('migration ordering');
  for (const migration of input.migrations) {
    const checksum = createHash('sha256').update(migration.content ?? '').digest('hex').slice(0, 16);
    if (migration.checksum !== checksum || migration.appliedChecksum !== checksum) findings.push(`migration checksum:${migration.file}`);
  }
  const role = input.applicationRole;
  if (role.superuser || role.bypassRls || role.noinherit !== true) findings.push('application role unsafe');
  for (const table of input.tables) if (!text(table.tenantColumn) || table.rlsEnabled !== true || table.rlsForced !== true || table.policy !== 'tenant-equals-current-or-explicit-bypass') findings.push(`RLS invariant:${table.name}`);
  if (!text(input.currentTenant)) findings.push('tenant context missing');
  if (typeof input.applicationPassword !== 'string' || /['\\\x00-\x1f\x7f]/.test(input.applicationPassword)) findings.push('secret materialisation boundary');
  return findings.length ? fail('RELATIONAL_VALIDATION_FAILED', findings, { mutationAllowed: false }) : pass('RELATIONAL_VALIDATION_PASSED', { mutationAllowed: true });
}

function tenantIdentity(input) {
  const raw = String(input.forwardedHost || input.host || '').trim().toLowerCase();
  const host = raw.split(',')[0].trim().replace(/:\d+$/, '');
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) return fail('NO_TENANT', ['malformed host'], { tenant: null });
  if ((input.reservedHosts ?? []).includes(host) || host === input.apexHost) return fail('NO_TENANT', ['reserved or apex host'], { tenant: null });
  if (input.registryAvailable !== true) return degraded('DOMAIN_REGISTRY_UNAVAILABLE', ['domain registry unavailable'], { tenant: null });
  const domain = (input.domains ?? []).find(item => item.fqdn === host);
  if (!domain || domain.state !== 'active' || domain.verified !== true) return fail('NO_TENANT', ['unknown, pending, inactive, or unverified host'], { tenant: null });
  return pass('TENANT_RESOLVED', { tenant: { organisationId: domain.organisationId, fqdn: host, realm: `tenant-${domain.organisationId}`, source: domain.source } });
}

function universalFoundation(input) {
  if (!array(input.assets) || !input.assets.length) return fail('FOUNDATION_ASSET_GRAPH_MISSING', ['foundation assets are required']);
  const findings = [];
  for (const asset of input.assets) {
    if (!text(asset.contract) || !text(asset.readiness)) findings.push(`incomplete asset:${asset.id}`);
    if (asset.reportStatus === asset.proofLevel && asset.reportStatus !== undefined) findings.push(`report treated as proof:${asset.id}`);
    if (!current(asset.evidence)) findings.push(`evidence not current:${asset.id}`);
    if (asset.providerMode === 'hermetic-mock' && asset.claims?.includes('live-external-provider')) findings.push(`provider overclaim:${asset.id}`);
    if (asset.environment === 'production-shaped' && asset.claims?.includes('production-live')) findings.push(`environment overclaim:${asset.id}`);
    if (asset.authorityOrder !== 'semantics>evidence>proof>contract>realisation>validation') findings.push(`authority inversion:${asset.id}`);
  }
  return findings.length ? fail('FOUNDATION_VALIDATION_FAILED', findings, { promotionAllowed: false }) : pass('FOUNDATION_VALIDATION_PASSED', { promotionAllowed: true });
}

function membership(input) {
  const caller = input.caller;
  if (!record(caller) || !text(caller.tenantId) || !array(input.members)) return fail('MEMBERSHIP_INPUT_MISSING', ['caller tenant and members are required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('IDENTITY_PROVIDER_UNAVAILABLE', ['identity store unavailable'], { mutated: false });
  const permission = { invite: 'members:invite', update: 'members:update-role', delete: 'members:delete', list: 'members:read' }[input.operation];
  if (!permission || !caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['specific member permission required'], { mutated: false });
  const scoped = input.members.filter(item => item.organisationId === caller.tenantId);
  if (input.operation === 'list') return pass('MEMBERS_LISTED', { members: scoped, mutated: false });
  const members = clone(input.members);
  if (input.operation === 'invite') {
    const email = String(input.invite?.email ?? '').toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || input.invite?.role === 'system-admin') return fail('INVALID_BODY', ['valid email and tenant role required'], { mutated: false });
    if (scoped.some(item => item.email === email)) return fail('ALREADY_INVITED', ['membership already exists'], { mutated: false });
    members.push({ ...clone(input.invite), email, organisationId: caller.tenantId, status: 'invited', invitedBy: caller.id });
  } else {
    const member = members.find(item => item.id === input.id && item.organisationId === caller.tenantId);
    if (!member) return fail('NOT_FOUND', ['member not found'], { mutated: false });
    const activeAdmins = scoped.filter(item => item.role === 'tenant-admin' && item.status === 'active');
    const removesLastAdmin = member.role === 'tenant-admin' && member.status === 'active' && activeAdmins.length === 1 && (input.operation === 'delete' || input.patch?.role !== 'tenant-admin' || input.patch?.status === 'disabled');
    if (removesLastAdmin) return fail('LAST_ADMIN_GUARD', ['last tenant admin cannot be demoted, disabled, or removed'], { mutated: false });
    if (input.operation === 'delete') members.splice(members.indexOf(member), 1);
    else {
      if (input.patch?.role === 'system-admin') return fail('INVALID_BODY', ['system-admin is not a tenant role'], { mutated: false });
      if (input.patch?.username !== undefined && !/^[a-zA-Z0-9._-]{3,64}$/.test(input.patch.username)) return fail('INVALID_BODY', ['username format invalid'], { mutated: false });
      if (input.patch?.status && !({ invited: ['active', 'disabled'], active: ['disabled'], disabled: ['active'] }[member.status] ?? []).includes(input.patch.status)) return fail('INVALID_TRANSITION', ['membership status transition invalid'], { mutated: false });
      Object.assign(member, clone(input.patch));
    }
  }
  return pass('MEMBERSHIP_MUTATED', { members, mutated: true });
}

function browserTelemetry(input) {
  if (!array(input.spans) || !input.spans.length || !text(input.tenantId)) return fail('TELEMETRY_INPUT_MISSING', ['tenant and spans are required']);
  if (input.providerAvailable !== true) return degraded('TELEMETRY_PIPELINE_UNAVAILABLE', ['RUM receiver, collector, and backend must be healthy'], { accepted: false });
  if (input.configValid !== true) return fail('TELEMETRY_CONFIGURATION_INVALID', ['invalid telemetry configuration'], { accepted: false });
  const allowed = new Set(['tenant.id', 'request.id', 'trace.id', 'route', 'provider']);
  const findings = [];
  for (const span of input.spans) {
    if (!text(span.traceId) || !text(span.requestId) || span.tenantId !== input.tenantId) findings.push(`unscoped span:${span.id}`);
    if (Object.keys(span.attributes ?? {}).some(key => !allowed.has(key)) || forbiddenSecret(span.attributes ?? {})) findings.push(`invalid attributes:${span.id}`);
  }
  const joined = new Set(input.spans.map(span => span.traceId)).size === 1 && new Set(input.spans.map(span => span.side)).has('browser') && new Set(input.spans.map(span => span.side)).has('bff');
  if (!joined) findings.push('browser-to-bff trace not joined');
  return findings.length ? fail('TELEMETRY_VALIDATION_FAILED', findings, { accepted: false }) : pass('TELEMETRY_VALIDATION_PASSED', { accepted: true, traceId: input.spans[0].traceId });
}

function customDomains(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.domains)) return fail('DOMAIN_INPUT_MISSING', ['tenant caller and domain registry are required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('DOMAIN_PROVIDER_UNAVAILABLE', ['DNS/auth-client adapter unavailable'], { mutated: false });
  if (!input.caller.permissions?.includes(input.operation === 'list' ? 'domains:read' : 'domains:write')) return fail('STATIC_PERMISSION_DENIED', ['domain permission required'], { mutated: false });
  const fqdn = String(input.domain?.fqdn ?? '').toLowerCase();
  if (input.operation !== 'list' && (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(fqdn) || /^\d+(?:\.\d+){3}$/.test(fqdn))) return fail('INVALID_DOMAIN', ['valid DNS name required'], { mutated: false });
  if (input.domains.some(item => item.fqdn === fqdn && item.tenantId !== input.caller.tenantId && item.enabled)) return fail('DOMAIN_ALREADY_CLAIMED', ['cross-tenant enabled claim'], { mutated: false, token: null });
  if (input.operation === 'set-canonical') {
    const domain = input.domains.find(item => item.fqdn === fqdn && item.tenantId === input.caller.tenantId);
    if (!domain || domain.ownership !== 'verified' || domain.authClient !== 'active' || domain.routing !== 'locally-active') return fail('DOMAIN_NOT_READY', ['verified ownership, auth client, and local routing required'], { mutated: false });
  }
  return pass('DOMAIN_OPERATION_PASSED', { mutated: input.operation !== 'list', publicDnsReady: false, tlsReady: false });
}

function eventBus(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.events)) return fail('EVENT_INPUT_MISSING', ['tenant caller and event records required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('EVENT_STORE_UNAVAILABLE', ['durable event substrate unavailable'], { mutated: false });
  const permission = input.operation === 'redrive' ? 'events:write' : 'events:read';
  if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['event permission required'], { mutated: false });
  if (input.events.some(item => item.tenantId !== input.caller.tenantId || forbiddenSecret(item.payload ?? {}))) return fail('EVENT_BOUNDARY_VIOLATION', ['tenant scope and secret-free payload required'], { mutated: false });
  if (input.operation === 'redrive') {
    const event = input.events.find(item => item.id === input.id && item.status === 'dead_letter');
    if (!event) return fail('NOT_FOUND', ['dead-letter event required'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['redrive audit must precede mutation'], { mutated: false });
  }
  return pass('EVENT_OPERATION_PASSED', { mutated: input.operation === 'redrive', events: input.events.filter(item => item.tenantId === input.caller.tenantId).map(({ payload, ...item }) => item) });
}

function historyProjection(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.entries)) return fail('HISTORY_INPUT_MISSING', ['tenant caller and entries required']);
  if (input.providerAvailable !== true) return degraded('HISTORY_STORE_UNAVAILABLE', ['history substrate unavailable'], { entries: null });
  if (!input.caller.permissions?.includes('history:read') || !Number.isInteger(input.limit) || input.limit < 1 || input.limit > 100 || !Number.isInteger(input.offset) || input.offset < 0) return fail('HISTORY_QUERY_INVALID', ['permission and bounded paging required']);
  const allowed = new Set(['id', 'tenantId', 'source', 'type', 'title', 'occurredAt', 'actor', 'status']);
  const entries = input.entries.filter(item => item.tenantId === input.caller.tenantId);
  if (entries.some(item => Object.keys(item).some(key => !allowed.has(key)) || forbiddenSecret(item))) return fail('HISTORY_SHAPE_UNSAFE', ['raw payloads and secrets are forbidden']);
  return pass('HISTORY_PROJECTED', { entries: entries.slice(input.offset, input.offset + input.limit), total: entries.length, limit: input.limit, offset: input.offset });
}

function rbac(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.members)) return fail('RBAC_INPUT_MISSING', ['tenant caller and memberships required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('RBAC_STORE_UNAVAILABLE', ['membership substrate unavailable'], { mutated: false });
  if (!input.caller.permissions?.includes(input.operation === 'resolve' ? 'permissions:read' : 'members:update-role')) return fail('STATIC_PERMISSION_DENIED', ['specific permission required'], { mutated: false });
  const member = input.members.find(item => item.id === input.id && item.tenantId === input.caller.tenantId);
  if (!member) return fail('NOT_FOUND', ['tenant membership not found'], { mutated: false });
  if (input.operation === 'update' && (!['tenant-admin', 'manager', 'member', 'viewer'].includes(input.role) || input.role === 'system-admin')) return fail('INVALID_ROLE', ['tenant role vocabulary required'], { mutated: false });
  const admins = input.members.filter(item => item.tenantId === input.caller.tenantId && item.role === 'tenant-admin' && item.status === 'active');
  if (input.operation === 'update' && member.role === 'tenant-admin' && admins.length === 1 && input.role !== 'tenant-admin') return fail('LAST_ADMIN_GUARD', ['last tenant admin cannot be demoted'], { mutated: false });
  return pass(input.operation === 'resolve' ? 'PERMISSIONS_RESOLVED' : 'ROLE_UPDATED', { mutated: input.operation === 'update', permissions: input.rolePermissions?.[input.operation === 'update' ? input.role : member.role] ?? [] });
}

function runtimeSecrets(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.records)) return fail('SECRET_INPUT_MISSING', ['tenant caller and secret metadata required'], { mutated: false });
  const permission = input.operation === 'list' || input.operation === 'readiness' ? 'secrets:read' : 'secrets:write';
  if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['secret permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('SECRET_PROVIDER_UNAVAILABLE', ['configured secret backend unavailable'], { mutated: false, fallbackUsed: false });
  const records = input.records.filter(item => item.tenantId === input.caller.tenantId);
  if (records.some(item => own(item, 'value') || forbiddenSecret(item.metadata ?? {}))) return fail('SECRET_METADATA_LEAK', ['metadata surfaces must be value-free'], { mutated: false });
  if (input.operation === 'put' && (!text(input.value) || input.auditWrittenBeforeChange !== true)) return fail('SECRET_PUT_INVALID', ['value and audit-before-change required'], { mutated: false });
  if (input.operation === 'resolve') {
    const record = records.find(item => item.ref === input.ref && !item.revoked && !item.deleted);
    if (!record || !text(input.resolvedValue)) return fail('SECRET_NOT_RESOLVABLE', ['active tenant ref required'], { value: null, mutated: false });
    return pass('SECRET_RESOLVED', { value: input.resolvedValue, mutated: false });
  }
  return pass('SECRET_OPERATION_PASSED', { records, mutated: !['list', 'readiness'].includes(input.operation), value: undefined });
}

function productSearch(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.documents)) return fail('SEARCH_INPUT_MISSING', ['tenant caller and documents required']);
  if (input.providerAvailable !== true) return degraded('SEARCH_PROVIDER_UNAVAILABLE', ['search adapter unavailable'], { results: null, mutationAllowed: false });
  if (!input.caller.permissions?.includes(input.operation === 'query' ? 'search:read' : 'search:reindex')) return fail('STATIC_PERMISSION_DENIED', ['search permission required']);
  if (input.documents.some(item => forbiddenSecret(item.metadata ?? {}) || !text(item.documentId) || !text(item.documentType))) return fail('SEARCH_DOCUMENT_INVALID', ['valid secret-free documents required']);
  const visible = input.documents.filter(item => item.tenantId === input.caller.tenantId && (!item.permissionKey || input.caller.permissions.includes(item.permissionKey)));
  if (input.operation === 'query' && input.queryTenantId !== input.caller.tenantId) return fail('TENANT_SCOPE_REQUIRED', ['query tenant must derive from caller']);
  return pass(input.operation === 'query' ? 'SEARCH_RESULTS' : 'SEARCH_REINDEXED', { results: input.operation === 'query' ? visible : undefined, mutationAllowed: input.operation !== 'query' });
}

function subOrganisations(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.organisations)) return fail('SUBORG_INPUT_MISSING', ['parent tenant and organisations required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('SUBORG_PROVIDER_UNAVAILABLE', ['organisation store unavailable'], { mutated: false });
  const permission = input.operation === 'list' ? 'suborgs:read' : 'suborgs:' + input.operation;
  if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['specific sub-organisation permission required'], { mutated: false });
  if (input.operation === 'create') {
    const slug = input.payload?.slug;
    if (!/^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$/.test(slug ?? '') || (input.reservedSlugs ?? []).includes(slug) || !text(input.payload?.displayName)) return fail('INVALID_BODY', ['valid non-reserved slug and display name required'], { mutated: false });
    if (input.organisations.some(item => item.slug === slug)) return fail('CONFLICT', ['slug already exists'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['audit must precede insert'], { mutated: false });
  }
  return pass('SUBORG_OPERATION_PASSED', { organisations: input.organisations.filter(item => item.parentId === input.caller.tenantId && item.active !== false), mutated: input.operation !== 'list' });
}

function billing(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.operations)) return fail('BILLING_INPUT_MISSING', ['tenant caller and billing operations required']);
  if (input.providerAvailable !== true) return degraded('BILLING_PROVIDER_UNAVAILABLE', ['billing provider unavailable'], { mutated: false });
  if (!input.caller.permissions?.includes('billing:write')) return fail('STATIC_PERMISSION_DENIED', ['billing permission required'], { mutated: false });
  const findings = [];
  const keys = new Map();
  for (const operation of input.operations) {
    if (operation.tenantId !== input.caller.tenantId || !text(operation.idempotencyKey) || !Number.isInteger(operation.amount) || operation.amount < 0 || !/^[A-Z]{3}$/.test(operation.currency ?? '')) findings.push('invalid billing operation:' + operation.id);
    if (keys.has(operation.idempotencyKey) && canonicalJson(keys.get(operation.idempotencyKey)) !== canonicalJson(operation.outcome)) findings.push('idempotency conflict:' + operation.idempotencyKey);
    keys.set(operation.idempotencyKey, operation.outcome);
  }
  return findings.length ? fail('BILLING_VALIDATION_FAILED', findings, { mutated: false }) : pass('BILLING_VALIDATION_PASSED', { mutated: true, ledgerAppendOnly: true });
}

function tenantPortability(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !record(input.archive) || !record(input.progress)) return fail('PORTABILITY_INPUT_MISSING', ['tenant archive and progress required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('PORTABILITY_PROVIDER_UNAVAILABLE', ['archive builder and applier required'], { mutated: false });
  if (!input.caller.permissions?.includes('data:' + input.operation)) return fail('STATIC_PERMISSION_DENIED', ['tenant portability permission required'], { mutated: false });
  if (input.archive.tenantId !== input.caller.tenantId || input.progress.tenantId !== input.caller.tenantId || input.progress.digest !== input.archive.digest || input.archive.encrypted !== true || input.archive.integrity !== 'valid') return fail('PORTABILITY_INTEGRITY_FAILED', ['tenant, digest, encryption, and integrity must agree'], { mutated: false });
  if (!array(input.progress.completedUnits) || input.progress.completedUnits.length !== new Set(input.progress.completedUnits).size || (input.progress.failedUnit && input.progress.completedUnits.includes(input.progress.failedUnit))) return fail('PORTABILITY_PROGRESS_INVALID', ['resumable units must be unique and failures preserved'], { mutated: false });
  return pass('PORTABILITY_VALIDATION_PASSED', { mutated: input.operation === 'import', resumable: true, silentLossAllowed: false });
}

function backgroundWorkers(input) {
  if (!record(input.caller) || !array(input.events) || !text(input.workerId)) return fail('WORKER_INPUT_MISSING', ['operator, events, and worker identity required']);
  if (input.providerAvailable !== true) return degraded('WORKER_SUBSTRATE_UNAVAILABLE', ['event and heartbeat stores unavailable'], { claimed: false });
  if (!input.caller.permissions?.includes('platform.workers.read')) return fail('STATIC_PERMISSION_DENIED', ['worker visibility permission required']);
  const event = input.events.find(item => item.id === input.eventId);
  if (!event || event.status !== 'pending') return pass('WORKER_IDEMPOTENT_SKIP', { claimed: false, heartbeat: true });
  if (!Number.isInteger(event.attempts) || !Number.isInteger(input.maxAttempts) || input.maxAttempts < 1) return fail('WORKER_ATTEMPT_STATE_INVALID', ['bounded attempt state required']);
  return pass(event.attempts + 1 >= input.maxAttempts ? 'WORKER_DEAD_LETTERED' : 'WORKER_COMPLETED', { claimed: true, heartbeat: true, tenantId: event.tenantId });
}

function configurationRegistry(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.definitions) || !array(input.overrides)) return fail('CONFIG_INPUT_MISSING', ['tenant caller and registry required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('CONFIG_STORE_UNAVAILABLE', ['configuration store unavailable'], { mutated: false });
  const write = ['set', 'clear'].includes(input.operation);
  if (!input.caller.permissions?.includes(write ? 'configuration:write' : 'configuration:read')) return fail('STATIC_PERMISSION_DENIED', ['configuration permission required'], { mutated: false });
  const definition = input.definitions.find(item => item.key === input.key);
  if (write && (!definition || definition.overridable !== true)) return fail('CONFIG_KEY_INVALID', ['known overridable key required'], { mutated: false });
  if (input.operation === 'set') {
    if (definition.type === 'string' && typeof input.value !== 'string') return fail('CONFIG_TYPE_INVALID', ['definition type mismatch'], { mutated: false });
    if (array(definition.allowed) && !definition.allowed.includes(input.value)) return fail('CONFIG_VALUE_INVALID', ['value outside allowed set'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['configuration audit must precede mutation'], { mutated: false });
  }
  const visible = input.definitions.filter(item => !item.readPermission || input.caller.permissions.includes(item.readPermission));
  return pass('CONFIG_OPERATION_PASSED', { mutated: write, definitions: write ? undefined : visible, tenantId: input.caller.tenantId });
}

function entitlementEngine(input) {
  if (!record(input.caller) || !text(input.tenantId) || !array(input.catalog) || !array(input.grants)) return fail('ENTITLEMENT_INPUT_MISSING', ['tenant, catalog, and grants required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('ENTITLEMENT_STORE_UNAVAILABLE', ['entitlement store unavailable'], { mutated: false });
  const write = ['grant', 'revoke'].includes(input.operation);
  const permission = write ? 'platform.entitlements.write' : (input.caller.tenantId === input.tenantId ? 'entitlements:read' : 'platform.entitlements.read');
  if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['entitlement permission required'], { mutated: false });
  const definition = input.catalog.find(item => item.key === input.key && item.kind === 'entitlement');
  if (write && (!definition || input.grantTenantId !== input.tenantId)) return fail('ENTITLEMENT_INVALID', ['known entitlement and exact tenant scope required'], { mutated: false });
  if (write && input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['entitlement audit must precede mutation'], { mutated: false });
  return pass('ENTITLEMENT_OPERATION_PASSED', { mutated: write, grants: input.grants.filter(item => item.tenantId === input.tenantId) });
}

function environmentBootstrap(input) {
  if (!record(input.caller) || !record(input.manifest) || !array(input.registry)) return fail('ENVIRONMENT_INPUT_MISSING', ['operator, manifest, and registry required'], { mutated: false });
  if (!input.caller.permissions?.includes('platform.environments.write')) return fail('STATIC_PERMISSION_DENIED', ['environment operator permission required'], { mutated: false });
  if (input.providerAvailable !== true || input.secretProviderAvailable !== true) return degraded('ENVIRONMENT_PROVIDER_UNAVAILABLE', ['config and secret providers required'], { mutated: false, generated: null });
  if (!text(input.manifest.name) || !array(input.manifest.requiredKeys) || input.manifest.requiredKeys.some(key => !own(input.manifest.values ?? {}, key))) return fail('ENVIRONMENT_MANIFEST_INVALID', ['complete declared manifest required'], { mutated: false, generated: null });
  if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['bootstrap audit must precede registration'], { mutated: false, generated: null });
  return pass('ENVIRONMENT_BOOTSTRAPPED', { mutated: true, generated: Object.fromEntries(input.manifest.requiredKeys.map(key => [key, input.manifest.values[key]])) });
}

function notifications(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.preferences)) return fail('NOTIFICATION_INPUT_MISSING', ['tenant caller and preferences required'], { dispatched: false });
  if (input.providerAvailable !== true) return degraded('NOTIFICATION_TRANSPORT_UNAVAILABLE', ['notification transport unavailable'], { dispatched: false });
  const self = ['get', 'patch'].includes(input.operation);
  const permission = self ? (input.operation === 'get' ? 'profile.read_self' : 'profile.update_self') : (input.operation === 'readiness' ? 'platform.notifications.read' : 'platform.notifications.write');
  if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['notification permission required'], { dispatched: false });
  if (forbiddenSecret(input.payload ?? {})) return fail('NOTIFICATION_PAYLOAD_UNSAFE', ['secret-bearing payload rejected'], { dispatched: false });
  if (input.operation === 'test-send' && (!text(input.recipient) || input.auditWrittenBeforeChange !== true)) return fail('NOTIFICATION_SEND_INVALID', ['recipient and audit-before-action required'], { dispatched: false });
  const preference = input.preferences.find(item => item.tenantId === input.caller.tenantId && item.channel === input.channel);
  return pass(preference?.enabled === false ? 'NOTIFICATION_SUPPRESSED' : 'NOTIFICATION_OPERATION_PASSED', { dispatched: input.operation === 'test-send' && preference?.enabled !== false });
}

function providerConfiguration(input) {
  if (!record(input.caller) || !array(input.providers) || !record(input.payload)) return fail('PROVIDER_CONFIG_INPUT_MISSING', ['operator and provider payload required'], { mutated: false });
  if (!input.caller.permissions?.includes('platform.providers.write')) return fail('STATIC_PERMISSION_DENIED', ['provider operator permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('PROVIDER_CONFIG_STORE_UNAVAILABLE', ['provider config store unavailable'], { mutated: false });
  if (!text(input.payload.kind) || !text(input.payload.lifecycleState) || (input.payload.requiresCredential === true && !text(input.payload.credentialRef))) return fail('PROVIDER_CONFIG_INVALID', ['required provider fields and credential ref required'], { mutated: false });
  if (input.payload.lifecycleState === 'ready' && input.healthProbePassed !== true) return fail('PROVIDER_NOT_HEALTHY', ['health probe must pass before ready'], { mutated: false });
  if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['provider audit must precede mutation'], { mutated: false });
  return pass('PROVIDER_CONFIG_UPDATED', { mutated: true, credentialExposed: false });
}

function scheduledJobs(input) {
  if (!record(input.caller) || !text(input.organisationId) || !array(input.jobs)) return fail('SCHEDULE_INPUT_MISSING', ['operator, organisation, and jobs required'], { enqueued: false });
  if (input.providerAvailable !== true) return degraded('SCHEDULE_SUBSTRATE_UNAVAILABLE', ['event substrate unavailable'], { enqueued: false });
  const read = input.operation === 'list';
  if (!input.caller.permissions?.includes(read ? 'platform.jobs.read' : 'platform.jobs.write')) return fail('STATIC_PERMISSION_DENIED', ['scheduled-job permission required'], { enqueued: false });
  const job = input.jobs.find(item => item.id === input.jobId && item.organisationId === input.organisationId);
  if (!read && (!job || job.enabled !== true)) return fail('SCHEDULE_JOB_INVALID', ['enabled scoped job required'], { enqueued: false });
  if (input.operation === 'tick' && job.lastWindow === input.window) return pass('SCHEDULE_IDEMPOTENT_SKIP', { enqueued: false });
  if (!read && input.operation !== 'tick' && input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['operator audit must precede action'], { enqueued: false });
  return pass('SCHEDULE_OPERATION_PASSED', { enqueued: ['tick', 'run-now'].includes(input.operation), jobs: read ? input.jobs.filter(item => item.organisationId === input.organisationId) : undefined });
}

function tenantDomainAuth(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.domains)) return fail('AUTH_CLIENT_INPUT_MISSING', ['tenant caller and domains required'], { mutated: false });
  if (!input.caller.permissions?.includes('domains:write')) return fail('STATIC_PERMISSION_DENIED', ['domain-write permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('AUTH_CLIENT_PROVIDER_UNAVAILABLE', ['auth-client adapter unavailable'], { mutated: false });
  const domain = input.domains.find(item => item.fqdn === input.fqdn && item.tenantId === input.caller.tenantId);
  const desired = input.operation === 'activate' ? 'inactive' : 'active';
  if (!domain || domain.ownership !== 'verified' || domain.authClient !== desired) return fail('AUTH_CLIENT_STATE_INVALID', ['verified domain in predecessor state required'], { mutated: false });
  if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['auth-client audit must precede external change'], { mutated: false });
  return pass('AUTH_CLIENT_OPERATION_PASSED', { mutated: true, fqdn: domain.fqdn });
}

function tenantHostIdentity(input) {
  if (!text(input.host) || !array(input.tenants) || !array(input.domains)) return fail('HOST_INPUT_MISSING', ['host and registries required'], { tenantId: null });
  const raw = text(input.forwardedHost) ? input.forwardedHost.split(',')[0].trim() : input.host;
  const host = raw.toLowerCase().replace(/:\d+$/, '');
  if (!/^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/.test(host)) return fail('HOST_MALFORMED', ['valid hostname required'], { tenantId: null });
  const domain = input.domains.find(item => item.fqdn === host && item.verified === true && item.active === true);
  if (domain) return pass('HOST_TENANT_RESOLVED', { tenantId: domain.tenantId, classification: 'custom-domain', mutated: false });
  const suffix = '.' + input.apex;
  const slug = host.endsWith(suffix) ? host.slice(0, -suffix.length) : null;
  if (!slug || (input.reservedSlugs ?? []).includes(slug)) return fail('HOST_NOT_TENANT', ['host is reserved or outside tenant apex'], { tenantId: null, mutated: false });
  const tenant = input.tenants.find(item => item.slug === slug && item.active === true);
  return tenant ? pass('HOST_TENANT_RESOLVED', { tenantId: tenant.id, classification: 'tenant-subdomain', mutated: false }) : fail('HOST_UNKNOWN', ['unknown tenant host'], { tenantId: null, mutated: false });
}

function tenantLifecycle(input) {
  if (!record(input.caller) || !text(input.tenantId) || !array(input.steps)) return fail('TENANT_LIFECYCLE_INPUT_MISSING', ['operator, tenant, and steps required'], { mutated: false });
  if (!input.caller.permissions?.includes('platform.tenants.' + input.operation)) return fail('STATIC_PERMISSION_DENIED', ['tenant lifecycle permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('TENANT_LIFECYCLE_PROVIDER_UNAVAILABLE', ['lifecycle subsystems unavailable'], { mutated: false });
  if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(input.tenantId) || input.auditWrittenBeforeChange !== true) return fail('TENANT_LIFECYCLE_INVALID', ['valid tenant and audit-before-change required'], { mutated: false });
  if (input.operation === 'delete' && (input.steps[0]?.name !== 'export' || input.steps.some((step, index) => step.ok !== true && input.steps.slice(index + 1).some(next => next.executed === true)))) return fail('TENANT_DELETE_COORDINATION_FAILED', ['export first and stop on subsystem failure'], { mutated: false });
  return pass('TENANT_LIFECYCLE_OPERATION_PASSED', { mutated: true, completed: input.steps.filter(step => step.ok === true).map(step => step.name) });
}

function writeOnlySecrets(input) {
  if (!record(input.caller) || !array(input.records) || !text(input.operation)) return fail('WRITE_ONLY_SECRET_INPUT_MISSING', ['caller, records, and operation required'], { mutated: false });
  if (!input.caller.permissions?.includes('secrets:write')) return fail('STATIC_PERMISSION_DENIED', ['owning-surface secret permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('WRITE_ONLY_SECRET_PROVIDER_UNAVAILABLE', ['secret store unavailable'], { mutated: false });
  if (input.operation === 'read' || input.records.some(item => own(item, 'value'))) return fail('SECRET_RETRIEVAL_FORBIDDEN', ['stored raw secrets are never readable'], { mutated: false });
  if (input.environment !== 'local' && input.encryptionKeyAvailable !== true) return fail('SECRET_ENCRYPTION_KEY_REQUIRED', ['higher environments require encryption key'], { mutated: false });
  if (input.auditWrittenBeforeChange !== true || forbiddenSecret(input.auditMetadata ?? {})) return fail('SECRET_AUDIT_INVALID', ['safe audit-before-write metadata required'], { mutated: false });
  return pass('WRITE_ONLY_SECRET_STORED', { mutated: text(input.secretInput), preservedExisting: input.secretInput === '', revealedOnce: input.operation === 'create-key' });
}

function apiKeys(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.records)) return fail('API_KEY_INPUT_MISSING', ['operation, caller, and key records required'], { mutated: false });
  const write = ['create', 'revoke'].includes(input.operation);
  const permission = input.operation === 'operator-list' ? 'platform.api-keys.read' : (write ? 'api-keys:write' : 'api-keys:read');
  if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['API-key permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('API_KEY_STORE_UNAVAILABLE', ['key store unavailable'], { mutated: false, records: null });
  const tenantId = input.operation === 'operator-list' ? input.tenantId : input.caller.tenantId;
  if (!text(tenantId)) return fail('API_KEY_TENANT_REQUIRED', ['tenant scope required'], { mutated: false });
  if (input.operation === 'create') {
    if (!input.caller.entitlements?.includes('api-access')) return fail('API_KEY_NOT_ENTITLED', ['API access entitlement required before key creation'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['key-created audit must precede storage'], { mutated: false });
    if (forbiddenSecret(input.metadata ?? {})) return fail('API_KEY_METADATA_UNSAFE', ['secret-bearing metadata rejected'], { mutated: false });
    return pass('API_KEY_CREATED', { mutated: true, tenantId, secretRevealedOnce: true, persistedPlaintext: false });
  }
  if (input.operation === 'revoke') {
    if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(input.keyId ?? '')) return fail('API_KEY_IDENTIFIER_INVALID', ['valid key identifier required'], { mutated: false });
    const key = input.records.find(item => item.id === input.keyId && item.tenantId === tenantId);
    if (!key) return fail('API_KEY_NOT_FOUND', ['key not found in tenant scope'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['key-revoked audit must precede mutation'], { mutated: false });
    return pass('API_KEY_REVOKED', { mutated: key.revokedAt == null, keyId: key.id });
  }
  const records = input.records.filter(item => item.tenantId === tenantId).map(({ hash, salt, ...metadata }) => metadata);
  return pass('API_KEY_METADATA_LISTED', { mutated: false, records, secretRevealedOnce: false });
}

function authenticationPlatform(input) {
  if (!text(input.operation) || !record(input.caller)) return fail('AUTH_PLATFORM_INPUT_MISSING', ['operation and caller required'], { mutated: false });
  const administrative = !['login', 'callback', 'session', 'logout'].includes(input.operation);
  if (!administrative) {
    if (input.providerAvailable !== true || input.sessionStoreAvailable !== true) return degraded('AUTH_PLATFORM_UNAVAILABLE', ['identity and session providers required'], { authenticated: false });
    if (input.operation === 'login' && (!text(input.returnTo) || !input.returnTo.startsWith('/') || input.returnTo.startsWith('//'))) return fail('AUTH_RETURN_TARGET_INVALID', ['safe local return target required']);
    if (input.operation === 'callback' && (!text(input.state) || input.state !== input.preAuthState || !text(input.code) || input.nonceValid !== true)) return fail('AUTH_CALLBACK_INVALID', ['state, code, and nonce validation required'], { authenticated: false });
    if (input.operation === 'session') return input.session?.authenticated === true ? pass('AUTH_SESSION_AUTHENTICATED', { actor: input.session.actor }) : fail('UNAUTHENTICATED', ['valid stored session required'], { authenticated: false });
    return pass(input.operation === 'logout' ? 'AUTH_SESSION_CLEARED' : 'AUTH_HANDOFF_CREATED', { authenticated: false, cookiesSecure: true });
  }
  const write = !['list-providers', 'read-policy', 'read-mapping', 'readiness'].includes(input.operation);
  if (!input.caller.permissions?.includes(write ? 'auth-settings:write' : 'auth-settings:read')) return fail('STATIC_PERMISSION_DENIED', ['tenant authentication-settings permission required'], { mutated: false });
  if (!text(input.caller.tenantId) || input.targetTenantId !== input.caller.tenantId) return fail('AUTH_TENANT_SCOPE_REQUIRED', ['exact tenant scope required'], { mutated: false });
  if (input.credentialState !== 'valid') return degraded('AUTH_TENANT_CREDENTIAL_UNAVAILABLE', ['valid tenant realm credential required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('AUTH_PROVIDER_UNAVAILABLE', ['identity provider unavailable'], { mutated: false });
  if (write) {
    const provider = input.provider ?? {};
    const localHttp = url => new RegExp('^http://(localhost|127[.]0[.]0[.]1)(?::[0-9]+)?(?:/|$)').test(url ?? '');
    if (!text(provider.alias) || ['master', 'platform'].includes(provider.alias) || !text(provider.issuer) || (!provider.issuer.startsWith('https://') && !localHttp(provider.issuer)) || provider.discoveryValid !== true || provider.jwksValid !== true) return fail('AUTH_PROVIDER_INVALID', ['safe issuer, non-reserved alias, discovery, and JWKS required'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['authentication administration audit must precede mutation'], { mutated: false });
  }
  return pass('AUTH_PLATFORM_OPERATION_PASSED', { mutated: write, tenantId: input.caller.tenantId, secretRedacted: true });
}

function backupRestore(input) {
  if (!text(input.operation) || !text(input.environment)) return fail('BACKUP_INPUT_MISSING', ['operation and environment required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('BACKUP_TOOLING_UNAVAILABLE', ['dump or restore tooling unavailable'], { mutated: false });
  const local = ['development', 'test'].includes(input.environment);
  if (input.operation === 'backup') {
    if (!local && input.allowEnvironment !== input.environment) return fail('BACKUP_ENVIRONMENT_GUARD', ['explicit matching higher-environment override required'], { mutated: false });
    if (!text(input.artifactPath) || !input.artifactPath.startsWith('artifacts/backups/') || !input.artifactPath.endsWith('.dump.gz') || input.ownerOnly !== true || input.gitIgnored !== true) return fail('BACKUP_ARTIFACT_INVALID', ['controlled owner-only ignored compressed artifact required'], { mutated: false });
    return pass('BACKUP_CREATED', { mutated: true, artifactPath: input.artifactPath, canonicalStoreOnly: true });
  }
  if (input.operation === 'restore') {
    if (!local || input.confirmationToken !== 'RESTORE:' + input.environment || input.destructiveAllowed !== true) return fail('RESTORE_CONFIRMATION_REQUIRED', ['local environment, exact confirmation, and stage permission required'], { mutated: false });
    return pass('RESTORE_AUTHORISED', { mutated: true, canonicalStoreOnly: true });
  }
  return fail('BACKUP_OPERATION_INVALID', ['backup or restore required'], { mutated: false });
}

function branding(input) {
  if (!text(input.operation) || !record(input.defaultTheme)) return fail('BRANDING_INPUT_MISSING', ['operation and default theme required'], { mutated: false });
  if (input.operation === 'bootstrap') {
    if (input.providerAvailable !== true || !text(input.tenantId)) return result(true, 'BRANDING_DEFAULT_FALLBACK', 'degraded', { theme: clone(input.defaultTheme), mutated: false });
    const override = (input.overrides ?? []).find(item => item.tenantId === input.tenantId)?.theme ?? {};
    return pass('BRANDING_THEME_RESOLVED', { theme: { ...clone(input.defaultTheme), ...clone(override) }, mutated: false });
  }
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.definitions)) return fail('BRANDING_MANAGEMENT_INPUT_MISSING', ['tenant caller and definitions required'], { mutated: false });
  const write = ['set', 'clear'].includes(input.operation);
  if (!input.caller.permissions?.includes(write ? 'configuration:write' : 'configuration:read')) return fail('STATIC_PERMISSION_DENIED', ['branding configuration permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('BRANDING_STORE_UNAVAILABLE', ['configuration store unavailable'], { mutated: false });
  const definition = input.definitions.find(item => item.key === input.key && item.overridable === true);
  if (write && !definition) return fail('BRANDING_KEY_INVALID', ['known overridable branding key required'], { mutated: false });
  if (input.operation === 'set' && ((definition.type === 'string' && !text(input.value)) || (array(definition.allowed) && !definition.allowed.includes(input.value)))) return fail('BRANDING_VALUE_INVALID', ['branding value violates its definition'], { mutated: false });
  if (write && input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['branding audit must precede mutation'], { mutated: false });
  return pass('BRANDING_OPERATION_PASSED', { mutated: write, tenantId: input.caller.tenantId });
}

function readinessSpine(input) {
  if (!array(input.providers) || !input.providers.length) return fail('READINESS_INPUT_MISSING', ['configured provider readiness inputs required'], { overall: 'blocked' });
  const untrusted = input.providers.filter(item => !text(item.id) || !current(item.evidence) || !['ready', 'degraded', 'blocked'].includes(item.state));
  if (untrusted.length) return fail('READINESS_INPUT_UNTRUSTED', untrusted.map(item => 'untrusted:' + (item.id ?? 'unknown')), { overall: 'blocked' });
  const blocked = input.providers.filter(item => item.required !== false && item.state !== 'ready');
  return blocked.length ? degraded('COMPOSED_PROVIDER_DEGRADED', blocked.map(item => item.id + ':' + item.state), { overall: 'degraded', providers: clone(input.providers) }) : pass('COMPOSED_PROVIDER_READY', { overall: 'ready', providers: clone(input.providers) });
}

function observabilityIncidents(input) {
  if (!text(input.operation) || !record(input.caller)) return fail('OBSERVABILITY_INPUT_MISSING', ['operation and caller required'], { mutated: false });
  const write = ['set-rule', 'transition', 'dispatch'].includes(input.operation);
  if (!input.caller.permissions?.includes(write ? 'platform.observability.write' : 'platform.observability.read')) return fail('STATIC_PERMISSION_DENIED', ['observability administration permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('OBSERVABILITY_PROVIDER_UNAVAILABLE', ['signal, incident, or notification provider unavailable'], { mutated: false });
  if (input.operation === 'set-rule') {
    if (!record(input.rule) || !['gt', 'gte', 'lt', 'lte', 'eq'].includes(input.rule.comparator) || !Number.isFinite(input.rule.threshold) || !['info', 'warning', 'critical'].includes(input.rule.severity) || !input.controlledSignals?.includes(input.rule.signal)) return fail('ALERT_RULE_INVALID', ['controlled signal, comparator, threshold, and severity required'], { mutated: false });
  }
  if (input.operation === 'transition') {
    const incident = (input.incidents ?? []).find(item => item.id === input.incidentId && item.tenantId === input.caller.tenantId);
    const legal = { open: ['acknowledged'], acknowledged: ['resolved'], resolved: [] };
    if (!incident || !legal[incident.state]?.includes(input.targetState)) return fail('INCIDENT_TRANSITION_INVALID', ['legal tenant-scoped incident transition required'], { mutated: false });
  }
  if (write && input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['observability action audit must precede effect'], { mutated: false });
  return pass('OBSERVABILITY_OPERATION_PASSED', { mutated: write, correlated: text(input.requestId) && text(input.traceId) });
}

function rateLimiting(input) {
  if (!text(input.operation) || !record(input.caller)) return fail('RATE_LIMIT_INPUT_MISSING', ['operation and caller required'], { mutated: false });
  if (['operator-read', 'operator-set'].includes(input.operation)) {
    const permission = input.operation === 'operator-set' ? 'platform.rate-limits.write' : 'platform.rate-limits.read';
    if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['platform rate-limit permission required'], { mutated: false });
    if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(input.tenantId ?? '')) return fail('RATE_LIMIT_TENANT_INVALID', ['valid tenant identifier required'], { mutated: false });
    if (input.operation === 'operator-set' && input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['rate-limit policy audit must precede mutation'], { mutated: false });
    return pass('RATE_LIMIT_POLICY_OPERATION_PASSED', { mutated: input.operation === 'operator-set' });
  }
  if (!record(input.policy)) return pass('RATE_LIMIT_OPT_IN_ALLOW', { allowed: true, used: 0, mutated: false });
  if (!input.caller.entitlements?.includes(input.policy.entitlementKey)) return fail('RATE_LIMIT_NOT_ENTITLED', ['entitlement required before counting'], { allowed: false, mutated: false });
  if (!Number.isInteger(input.policy.limit) || input.policy.limit < 1 || !Number.isInteger(input.policy.windowSeconds) || input.policy.windowSeconds < 1 || !Number.isInteger(input.used) || input.used < 0) return fail('RATE_LIMIT_POLICY_INVALID', ['positive fixed-window policy and count required'], { allowed: false, mutated: false });
  if (input.cacheAvailable !== true && input.relationalFallbackAvailable !== true) return degraded('RATE_LIMIT_PROVIDER_UNAVAILABLE', ['cache and relational counter unavailable'], { allowed: false, mutated: false });
  const used = input.used + 1;
  const allowed = used <= input.policy.limit;
  const readiness = input.cacheAvailable === true ? 'ready' : 'degraded';
  return result(allowed, allowed ? 'RATE_LIMIT_ALLOWED' : 'RATE_LIMIT_EXCEEDED', readiness, { allowed, used, windowBucket: input.windowBucket, fallback: input.cacheAvailable !== true });
}

function canonicalDomain(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.domains)) return fail('CANONICAL_DOMAIN_INPUT_MISSING', ['operation, caller, and domains required'], { mutated: false });
  if (!input.caller.permissions?.includes('domains:write')) return fail('STATIC_PERMISSION_DENIED', ['tenant domain-write permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('CANONICAL_DOMAIN_PROVIDER_UNAVAILABLE', ['domain registry unavailable'], { mutated: false });
  const domain = input.domains.find(item => item.fqdn === input.fqdn && item.tenantId === input.caller.tenantId);
  if (!domain) return fail('CANONICAL_DOMAIN_NOT_FOUND', ['domain not found in tenant scope'], { mutated: false });
  if (input.operation === 'set' && (domain.ownership !== 'verified' || domain.authClient !== 'active' || domain.routing !== 'locally-active')) return fail('CANONICAL_DOMAIN_NOT_READY', ['verified ownership, active auth client, and proven local routing required'], { mutated: false });
  if (!['set', 'unset'].includes(input.operation)) return fail('CANONICAL_DOMAIN_OPERATION_INVALID', ['set or unset required'], { mutated: false });
  if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['canonical-domain audit must precede mutation'], { mutated: false });
  return pass('CANONICAL_DOMAIN_OPERATION_PASSED', { mutated: input.operation === 'set' ? domain.canonical !== true : domain.canonical === true, canonical: input.operation === 'set' ? domain.fqdn : null, redirectPolicy: input.operation === 'set' ? 'redirect-slug-to-canonical' : 'none', publicDnsOrTlsClaimed: false });
}

function usageMetering(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.meters) || !array(input.events)) return fail('METERING_INPUT_MISSING', ['operation, caller, meter catalog, and events required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('METERING_PROVIDER_UNAVAILABLE', ['metering store unavailable'], { mutated: false });
  if (input.operation === 'ingest') {
    if (!input.caller.permissions?.includes('platform.metering.write') || input.event?.tenantId !== input.caller.tenantId) return fail('STATIC_PERMISSION_DENIED', ['tenant-scoped operator ingestion permission required'], { mutated: false });
    const meter = input.meters.find(item => item.key === input.event?.meterKey);
    if (!meter) return fail('METER_UNKNOWN', ['known meter required'], { mutated: false });
    if (!input.caller.entitlements?.includes(meter.entitlementKey)) return fail('METER_NOT_ENTITLED', ['meter entitlement required before ingestion'], { mutated: false });
    if (!Number.isFinite(input.event.quantity) || input.event.quantity === 0 || !text(input.event.idempotencyKey)) return fail('METER_QUANTITY_INVALID', ['non-zero signed quantity and idempotency key required'], { mutated: false });
    const duplicate = input.events.find(item => item.tenantId === input.event.tenantId && item.meterKey === input.event.meterKey && item.idempotencyKey === input.event.idempotencyKey);
    return pass(duplicate ? 'METER_EVENT_DEDUPLICATED' : 'METER_EVENT_INGESTED', { mutated: !duplicate, eventId: duplicate?.id ?? input.event.id, quantity: input.event.quantity });
  }
  const permission = input.caller.tenantId === input.tenantId ? 'metering:read' : 'platform.metering.read';
  if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['usage-read permission required'], { mutated: false });
  const events = input.events.filter(item => item.tenantId === input.tenantId);
  return pass('METER_USAGE_READ', { mutated: false, totals: Object.fromEntries(input.meters.map(meter => [meter.key, events.filter(item => item.meterKey === meter.key).reduce((sum, item) => sum + item.quantity, 0)])) });
}

function webhooks(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.subscriptions) || !array(input.deliveries)) return fail('WEBHOOK_INPUT_MISSING', ['operation, caller, subscriptions, and deliveries required'], { mutated: false });
  if (!input.caller.permissions?.includes('webhooks:write') || !text(input.caller.tenantId)) return fail('STATIC_PERMISSION_DENIED', ['tenant webhook permission required'], { mutated: false });
  if (input.providerAvailable !== true || input.workerAvailable !== true) return degraded('WEBHOOK_PROVIDER_UNAVAILABLE', ['webhook store and delivery worker required'], { mutated: false });
  if (input.subscriptions.some(item => own(item, 'secret') || own(item, 'plaintextSecret')) || forbiddenSecret(input.auditMetadata ?? {})) return fail('WEBHOOK_SECRET_EXPOSURE', ['plaintext signing secrets are never persisted or audited'], { mutated: false });
  if (input.operation === 'redrive') {
    const delivery = input.deliveries.find(item => item.id === input.deliveryId && item.tenantId === input.caller.tenantId && item.state === 'dead');
    if (!delivery || !text(input.idempotencyKey)) return fail('WEBHOOK_REDRIVE_INVALID', ['dead tenant-scoped delivery and idempotency key required'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['redrive audit must precede reset'], { mutated: false });
    return pass('WEBHOOK_REDRIVE_PENDING', { mutated: true, deliveryId: delivery.id, state: 'pending' });
  }
  const visibleSubscriptions = input.subscriptions.filter(item => item.tenantId === input.caller.tenantId).map(({ secretHash, ...metadata }) => ({ ...metadata, secretConfigured: text(secretHash) }));
  return pass(visibleSubscriptions.length ? 'WEBHOOK_CONFIGURED' : 'WEBHOOK_NO_SUBSCRIPTIONS', { mutated: false, subscriptions: visibleSubscriptions, hasDeadDeliveries: input.deliveries.some(item => item.tenantId === input.caller.tenantId && item.state === 'dead') });
}

function workflows(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.workflows)) return fail('WORKFLOW_INPUT_MISSING', ['operation, caller, and workflows required'], { mutated: false });
  const read = ['list', 'get', 'readiness'].includes(input.operation);
  const permission = input.caller.operator === true ? (read ? 'platform.workflow.read' : 'platform.workflow.write') : 'tenant.workflow.read';
  if (!input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['workflow permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('WORKFLOW_PROVIDER_UNAVAILABLE', ['workflow orchestrator unavailable'], { mutated: false });
  if (input.operation === 'start') {
    if (!text(input.workflowId) || !text(input.workflowKey) || !text(input.tenantId) || input.caller.tenantId !== input.tenantId) return fail('WORKFLOW_START_INVALID', ['workflow key, id, and exact tenant required'], { mutated: false });
  } else if (!read) {
    const workflow = input.workflows.find(item => item.id === input.workflowId);
    if (!workflow || workflow.tenantId !== input.caller.tenantId) return fail('WORKFLOW_ACCESS_DENIED', ['tenant-bound workflow required'], { mutated: false });
    const transitions = { 'approval.requested': { running: 'waiting' }, 'approval.granted': { waiting: 'completed' }, 'approval.denied': { waiting: 'failed' }, cancel: { running: 'cancelled', waiting: 'cancelled' } };
    const signal = input.operation === 'cancel' ? 'cancel' : input.signal;
    if (!transitions[signal]?.[workflow.status]) return fail('WORKFLOW_TRANSITION_INVALID', ['explicit legal workflow signal required'], { mutated: false });
  }
  if (!read && input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['workflow transition audit must precede effect'], { mutated: false });
  return pass('WORKFLOW_OPERATION_PASSED', { mutated: !read, tenantId: input.caller.tenantId });
}

function abacDecisionPoint(input) {
  if (!text(input.operation) || !record(input.caller)) return fail('ABAC_INPUT_MISSING', ['operation and caller required'], { mutated: false });
  if (['read-policy', 'replace-policy'].includes(input.operation)) {
    const write = input.operation === 'replace-policy';
    if (!input.caller.permissions?.includes(write ? 'auth-settings:write' : 'auth-settings:read') || !text(input.caller.tenantId)) return fail('STATIC_PERMISSION_DENIED', ['tenant policy-administration permission required'], { mutated: false });
    if (input.providerAvailable !== true) return degraded('ABAC_POLICY_PROVIDER_UNAVAILABLE', ['policy adapter unavailable'], { mutated: false });
    if (write && (!record(input.policy) || !text(input.policy.resource) || !text(input.policy.scope))) return fail('ABAC_POLICY_INVALID', ['resource and scope required'], { mutated: false });
    if (write && input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['resource-policy audit must precede mutation'], { mutated: false });
    return pass('ABAC_POLICY_OPERATION_PASSED', { mutated: write });
  }
  if (!text(input.requiredPermission) || !text(input.resource) || !text(input.scope)) return fail('ABAC_GUARD_METADATA_MISSING', ['permission, resource, and scope required'], { mutated: false });
  if (input.expectedToken === true && input.tokenPresent !== true) return fail('AUTHENTICATION_REQUIRED', ['expected token missing'], { mutated: false });
  if (input.tokenPresent === true && input.authorizationServerAvailable === true && input.resourceRegistered === true) {
    if (input.serverDecision === 'granted') return pass('ABAC_GRANTED', { mutated: false, decision: 'granted' });
    if (input.serverDecision === 'insufficient-auth-level') return fail('STEP_UP_REQUIRED', ['higher authentication level required'], { mutated: false });
    return fail('ABAC_POLICY_DENIED', ['authorization policy denied'], { mutated: false });
  }
  if (!input.caller.permissions?.includes(input.requiredPermission)) return fail('STATIC_PERMISSION_DENIED', ['static permission backstop denied'], { mutated: false });
  return result(true, 'ABAC_STATIC_FALLBACK_GRANTED', 'degraded', { mutated: false, decision: 'granted', fallback: true });
}

function developerPlatform(input) {
  if (!text(input.operation) || !record(input.caller)) return fail('DEVELOPER_PLATFORM_INPUT_MISSING', ['operation and caller required'], { mutated: false });
  if (input.openapiDrift === true || input.graphqlContractValid !== true) return fail('API_CONTRACT_DRIFT', ['OpenAPI and GraphQL contracts must match source'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('DEVELOPER_PLATFORM_PROVIDER_UNAVAILABLE', ['API-key or rate-limit provider unavailable'], { mutated: false });
  const keyWrite = ['create-key', 'revoke-key'].includes(input.operation);
  const permission = input.operation === 'portal-read' ? 'developer:read' : (keyWrite ? 'api-keys:write' : 'api-keys:read');
  if (!input.caller.permissions?.includes(permission) || !text(input.caller.tenantId)) return fail('STATIC_PERMISSION_DENIED', ['tenant developer permission required'], { mutated: false });
  if (input.operation === 'create-key' && !input.caller.entitlements?.includes('api-access')) return fail('DEVELOPER_API_NOT_ENTITLED', ['API-access entitlement required'], { mutated: false });
  if (keyWrite && input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['API-key audit must precede mutation'], { mutated: false });
  if ((input.keys ?? []).some(item => own(item, 'secret') || own(item, 'hash') || own(item, 'salt'))) return fail('DEVELOPER_SECRET_EXPOSURE', ['portal and list projections must be redacted'], { mutated: false });
  return pass('DEVELOPER_PLATFORM_OPERATION_PASSED', { mutated: keyWrite, secretRevealedOnce: input.operation === 'create-key', contractsReady: true });
}

function serviceCatalogReadiness(input) {
  if (!record(input.caller) || !text(input.caller.tenantId) || !array(input.services) || !input.services.length) return fail('SERVICE_CATALOG_INPUT_MISSING', ['tenant caller and service catalog required'], { overall: 'blocked' });
  if (!input.caller.permissions?.includes('services:read')) return fail('STATIC_PERMISSION_DENIED', ['tenant service-read permission required'], { overall: 'blocked' });
  if (input.providerAvailable !== true) return degraded('SERVICE_CATALOG_PROVIDER_UNAVAILABLE', ['readiness probe provider unavailable'], { overall: 'degraded', services: null });
  const visible = input.services.filter(item => item.tenantId === input.caller.tenantId || item.shared === true);
  if (!visible.length || visible.some(item => !text(item.id) || !current(item.evidence) || !['ready', 'degraded', 'blocked'].includes(item.state))) return fail('SERVICE_READINESS_UNTRUSTED', ['well-formed current probe results required'], { overall: 'blocked' });
  const notReady = visible.filter(item => item.state !== 'ready');
  return notReady.length ? degraded('SERVICE_CATALOG_DEGRADED', notReady.map(item => item.id + ':' + item.state), { overall: 'degraded', services: clone(visible) }) : pass('SERVICE_CATALOG_READY', { overall: 'ready', services: clone(visible) });
}

function dataProtection(input) {
  if (!text(input.operation) || !record(input.caller)) return fail('DATA_PROTECTION_INPUT_MISSING', ['operation and caller required'], { mutated: false });
  if (!input.caller.permissions?.includes('platform.data-protection.write')) return fail('STATIC_PERMISSION_DENIED', ['privileged data-protection permission required'], { mutated: false });
  if (input.providerAvailable !== true || input.restoreDrillPassed !== true) return degraded('DATA_PROTECTION_PROVIDER_UNAVAILABLE', ['stores and successful restore drill required'], { mutated: false });
  if (input.operation === 'residency-write') {
    if (!text(input.homeRegion) || input.targetRegion !== input.homeRegion) return fail('DATA_RESIDENCY_DENIED', ['target region must match tenant home region'], { mutated: false });
    return pass('DATA_RESIDENCY_ACCEPTED', { mutated: true, region: input.homeRegion });
  }
  if (input.operation === 'retention-tick') {
    if (!array(input.policies) || !array(input.candidates) || !array(input.holds)) return fail('RETENTION_INPUT_MISSING', ['policies, candidates, and holds required'], { mutated: false });
    const outcomes = [];
    for (const candidate of input.candidates) {
      const policy = input.policies.find(item => item.tenantId === candidate.tenantId && item.resourceClass === candidate.resourceClass && item.enabled === true);
      const held = input.holds.some(item => item.tenantId === candidate.tenantId && item.resourceId === candidate.id && item.releasedAt == null);
      const outcome = !policy ? 'pending' : (held ? 'held' : 'deleted');
      if (candidate.requestedOutcome && candidate.requestedOutcome !== outcome) return fail('LEGAL_HOLD_VIOLATION', ['retention outcome conflicts with active hold or policy'], { mutated: false });
      outcomes.push({ id: candidate.id, tenantId: candidate.tenantId, outcome });
    }
    return pass('RETENTION_EVALUATED', { mutated: outcomes.some(item => item.outcome === 'deleted'), outcomes });
  }
  if (['set-hold', 'release-hold'].includes(input.operation) && (!text(input.reason) || !text(input.actor) || input.auditWrittenBeforeChange !== true)) return fail('LEGAL_HOLD_INVALID', ['actor, reason, and audit-before-change required'], { mutated: false });
  return pass('DATA_PROTECTION_OPERATION_PASSED', { mutated: true });
}

function quotas(input) {
  if (!text(input.operation) || !record(input.caller)) return fail('QUOTA_INPUT_MISSING', ['operation and caller required'], { mutated: false });
  if (input.operation === 'set') {
    if (!input.caller.permissions?.includes('platform.quotas.write') || !text(input.tenantId)) return fail('STATIC_PERMISSION_DENIED', ['operator quota permission required'], { mutated: false });
    if (!record(input.quota) || !Number.isFinite(input.quota.limit) || input.quota.limit < 0) return fail('QUOTA_SCHEMA_INVALID', ['non-negative quota limit required'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['quota audit must precede upsert'], { mutated: false });
    return pass('QUOTA_SET', { mutated: true });
  }
  if (!record(input.quota)) return pass('QUOTA_NOT_CONFIGURED', { allowed: true, state: 'no-quota', projectedUsage: input.usage ?? 0, mutated: false });
  if (!input.caller.entitlements?.includes(input.quota.entitlementKey)) return fail('QUOTA_NOT_ENTITLED', ['entitlement must be evaluated before usage'], { allowed: false, state: 'no-entitlement', mutated: false });
  if (input.providerAvailable !== true || !Number.isFinite(input.usage) || !Number.isFinite(input.delta ?? 0)) return degraded('QUOTA_PROVIDER_UNAVAILABLE', ['quota and metering substrate required'], { allowed: false, mutated: false });
  const projectedUsage = input.usage + (input.delta ?? 0);
  const allowed = projectedUsage <= input.quota.limit;
  return result(allowed, allowed ? 'QUOTA_WITHIN' : 'QUOTA_EXCEEDED', 'ready', { allowed, state: allowed ? 'within' : 'exceeded', projectedUsage, mutated: false });
}

function supportMode(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.workflows) || !array(input.sessions)) return fail('SUPPORT_MODE_INPUT_MISSING', ['operation, caller, workflows, and sessions required'], { mutated: false });
  if (!input.caller.permissions?.includes('platform.support.enter') || input.caller.role !== 'system-admin') return fail('STATIC_PERMISSION_DENIED', ['system-admin support-enter permission required'], { mutated: false });
  if (!text(input.reason)) return fail('SUPPORT_REASON_REQUIRED', ['non-blank support reason required'], { mutated: false });
  if (!text(input.targetTenantId)) return fail('SUPPORT_TARGET_INVALID', ['target tenant required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('SUPPORT_MODE_PROVIDER_UNAVAILABLE', ['workflow or session provider unavailable'], { mutated: false });
  if (input.operation === 'approve') {
    const workflow = input.workflows.find(item => item.id === input.workflowId && item.targetTenantId === input.targetTenantId && item.state === 'waiting');
    if (!workflow) return fail('SUPPORT_WORKFLOW_INVALID', ['waiting approval for exact tenant required'], { mutated: false });
  }
  if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['support-session audit must precede creation'], { mutated: false });
  return pass('SUPPORT_SESSION_CREATED', { mutated: true, supportMode: true, effectiveTenantId: input.targetTenantId, ttlSeconds: 3600, tenantPermissions: [] });
}

function tenantGroups(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.groups)) return fail('GROUP_INPUT_MISSING', ['operation, caller, and groups required'], { mutated: false });
  const permission = 'groups:' + input.operation;
  if (!input.caller.permissions?.includes(permission) || !text(input.caller.tenantId)) return fail('STATIC_PERMISSION_DENIED', ['tenant-scoped group permission required'], { mutated: false });
  if (input.credentialState !== 'valid') return degraded('GROUP_TENANT_CREDENTIAL_UNAVAILABLE', ['valid tenant realm credential required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('GROUP_PROVIDER_UNAVAILABLE', ['realm group adapter unavailable'], { mutated: false });
  if (input.operation === 'list') return pass('GROUPS_LISTED', { mutated: false, groups: clone(input.groups) });
  const name = input.name ?? '';
  const unsafe = !text(name) || name.length > 64 || name.includes('/') || Array.from(name).some(character => character.charCodeAt(0) === 92 || character.charCodeAt(0) < 32) || (input.reservedNames ?? []).some(item => item.toLowerCase() === name.toLowerCase());
  if (unsafe) return fail('GROUP_NAME_INVALID', ['safe non-reserved group name required'], { mutated: false });
  if (input.groups.some(item => item.name.toLowerCase() === name.toLowerCase() && item.id !== input.groupId)) return fail('GROUP_CONFLICT', ['group name already exists'], { mutated: false });
  if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['group audit must precede mutation'], { mutated: false });
  return pass('GROUP_OPERATION_PASSED', { mutated: true });
}

const privilegedAuditContexts = Object.freeze({
  member: Object.freeze({ storedResource: 'member', permission: 'member:read' }),
  config: Object.freeze({ storedResource: 'config', permission: 'config:read' }),
  feature: Object.freeze({ storedResource: 'feature', permission: 'feature:read' }),
  'auth-settings': Object.freeze({ storedResource: 'auth-settings', permission: 'auth-settings:read' }),
});

function privilegedAudit(input) {
  if (input.operation !== 'query' || !record(input.caller) || !array(input.events)) return fail('PRIVILEGED_AUDIT_INPUT_INVALID', ['query operation, caller, and audit events required'], { mutated: false });
  if (!text(input.caller.tenantId) || !input.caller.permissions?.includes('audit:read')) return fail('STATIC_PERMISSION_DENIED', ['tenant audit-read permission required'], { mutated: false });
  const context = privilegedAuditContexts[input.resource];
  if (!context) return fail('PRIVILEGED_AUDIT_RESOURCE_INVALID', ['known logical audit resource required'], { mutated: false });
  if (!input.caller.permissions.includes(context.permission)) return fail('STATIC_PERMISSION_DENIED', ['per-context audit permission required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('PRIVILEGED_AUDIT_PROVIDER_UNAVAILABLE', ['durable privileged-audit evidence unavailable'], { mutated: false, events: null });
  const from = input.from == null ? -Infinity : Number(input.from);
  const to = input.to == null ? Infinity : Number(input.to);
  if (!Number.isFinite(from) && from !== -Infinity || !Number.isFinite(to) && to !== Infinity || from > to) return fail('PRIVILEGED_AUDIT_RANGE_INVALID', ['ordered numeric audit range required'], { mutated: false });
  const limit = Math.min(100, Math.max(1, Number.isInteger(input.limit) ? input.limit : 50));
  const visible = input.events
    .filter(event => event.tenantId === input.caller.tenantId && event.resource === context.storedResource)
    .filter(event => input.resourceId == null || event.resourceId === input.resourceId)
    .filter(event => input.action == null || event.action === input.action)
    .filter(event => input.actor == null || event.actorId === input.actor)
    .filter(event => Number(event.timestamp) >= from && Number(event.timestamp) <= to)
    .slice(0, limit)
    .map(event => ({
      id: event.id, action: event.action, actorId: event.actorId, resource: event.resource,
      resourceId: event.resourceId, timestamp: event.timestamp,
      metadata: Object.fromEntries(Object.entries(record(event.metadata) ? event.metadata : {}).filter(([key]) => !/password|secret|token|credential|privatekey/i.test(key))),
    }));
  return pass('PRIVILEGED_AUDIT_READ', { mutated: false, events: visible, limit });
}

function tenantObjectStorage(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.objects)) return fail('OBJECT_STORAGE_INPUT_MISSING', ['operation, caller, and object registry required'], { mutated: false });
  const write = ['upload', 'record-scan'].includes(input.operation);
  const permission = write ? 'objects:write' : 'objects:read';
  if (!text(input.caller.tenantId) || !input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['tenant object permission required'], { mutated: false });
  if (input.providerAvailable !== true || input.registryAvailable !== true) return degraded('OBJECT_STORAGE_PROVIDER_UNAVAILABLE', ['object store and registry must both be reachable'], { mutated: false, signedUrl: null });
  const prefix = 'tenants/' + input.caller.tenantId + '/';
  if (input.operation === 'issue-download-url') {
    const object = input.objects.find(item => item.id === input.objectId && item.tenantId === input.caller.tenantId && text(item.key) && item.key.startsWith(prefix));
    if (!object) return fail('OBJECT_ACCESS_DENIED', ['tenant-prefixed registry object required'], { mutated: false, signedUrl: null });
    if (object.scanState !== 'clean') return fail('OBJECT_NOT_CLEAN', ['only clean scanned objects may be served'], { mutated: false, signedUrl: null });
    if (!text(input.signedUrl) || !Number.isInteger(input.ttlSeconds) || input.ttlSeconds < 1 || input.ttlSeconds > 900) return fail('SIGNED_URL_INVALID', ['short-lived provider signed URL required'], { mutated: false, signedUrl: null });
    return pass('OBJECT_SIGNED_URL_ISSUED', { mutated: false, objectId: object.id, signedUrl: input.signedUrl, ttlSeconds: input.ttlSeconds });
  }
  if (input.operation === 'upload') {
    const object = input.object;
    if (!record(object) || object.tenantId !== input.caller.tenantId || !text(object.key) || !object.key.startsWith(prefix) || !text(object.contentType) || !Number.isFinite(object.sizeBytes) || object.sizeBytes <= 0) return fail('OBJECT_UPLOAD_INVALID', ['tenant prefix, content type, and positive size required'], { mutated: false });
    if (!Number.isFinite(input.usageBytes) || !Number.isFinite(input.quotaBytes) || input.usageBytes + object.sizeBytes > input.quotaBytes) return fail('OBJECT_STORAGE_QUOTA_EXCEEDED', ['storage-bytes quota must allow upload'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['object upload audit must precede registry mutation'], { mutated: false });
    return pass('OBJECT_UPLOAD_REGISTERED', { mutated: true, objectId: object.id, prefix, scanState: 'uploaded', meteredBytes: object.sizeBytes });
  }
  if (input.operation === 'record-scan') {
    const object = input.objects.find(item => item.id === input.objectId && item.tenantId === input.caller.tenantId && item.key?.startsWith(prefix));
    if (!object || object.scanState !== 'uploaded' || !['clean', 'quarantined', 'rejected'].includes(input.scanOutcome)) return fail('OBJECT_SCAN_TRANSITION_INVALID', ['uploaded tenant object and terminal scan outcome required'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['scan audit must precede lifecycle mutation'], { mutated: false });
    return pass('OBJECT_SCAN_RECORDED', { mutated: true, objectId: object.id, scanState: input.scanOutcome });
  }
  if (input.operation === 'readiness') return pass('OBJECT_STORAGE_READY', { mutated: false, prefix });
  return fail('OBJECT_STORAGE_OPERATION_INVALID', ['supported object-storage operation required'], { mutated: false });
}

function supportCustomerOperations(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.tickets) || !array(input.usage) || !array(input.announcements) || !array(input.workflows) || !array(input.sessions)) return fail('SUPPORT_INPUT_MISSING', ['operation, caller, and support state required'], { mutated: false });
  if (input.providerAvailable !== true) return degraded('SUPPORT_PROVIDER_UNAVAILABLE', ['support relational provider unavailable'], { mutated: false });
  const tenantId = input.caller.tenantId;
  if (input.operation === 'approve-support') {
    if (input.caller.role !== 'system-admin' || !input.caller.permissions?.includes('platform.support.approve') || !text(input.targetTenantId)) return fail('STATIC_PERMISSION_DENIED', ['system-admin support approval permission required'], { mutated: false });
    const workflow = input.workflows.find(item => item.id === input.workflowId && item.targetTenantId === input.targetTenantId && item.state === 'waiting');
    if (!workflow) return fail('SUPPORT_APPROVAL_REQUIRED', ['waiting approval for exact tenant required before support session'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['support approval audit must precede session creation'], { mutated: false });
    return pass('SUPPORT_SESSION_APPROVED', { mutated: true, targetTenantId: input.targetTenantId, workflowId: workflow.id });
  }
  if (!text(tenantId)) return fail('SUPPORT_TENANT_REQUIRED', ['resolved tenant context required'], { mutated: false });
  const read = ['list-tickets', 'health', 'list-announcements'].includes(input.operation);
  if (!input.caller.permissions?.includes(read ? 'support:read' : 'support:write')) return fail('STATIC_PERMISSION_DENIED', ['tenant support permission required'], { mutated: false });
  if (input.operation === 'list-tickets') return pass('SUPPORT_TICKETS_LISTED', { mutated: false, tickets: clone(input.tickets.filter(item => item.tenantId === tenantId)) });
  if (input.operation === 'health') {
    const tickets = input.tickets.filter(item => item.tenantId === tenantId);
    const usage = input.usage.filter(item => item.tenantId === tenantId).reduce((sum, item) => sum + (Number(item.quantity) || 0), 0);
    return pass('CUSTOMER_HEALTH_READ', { mutated: false, health: { ticketCount: tickets.length, meteredUsage: usage } });
  }
  if (input.operation === 'list-announcements') return pass('SUPPORT_ANNOUNCEMENTS_LISTED', { mutated: false, announcements: clone(input.announcements.filter(item => item.tenantId === tenantId).map(({ tenantId: _tenantId, ...item }) => item)) });
  if (input.operation === 'create-ticket') {
    if (!text(input.ticket?.id) || !text(input.ticket?.subject) || !text(input.ticket?.body)) return fail('SUPPORT_TICKET_INVALID', ['ticket id, subject, and body required'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['ticket audit must precede mutation'], { mutated: false });
    return pass('SUPPORT_TICKET_CREATED', { mutated: true, ticketId: input.ticket.id, tenantId });
  }
  if (input.operation === 'create-announcement') {
    if (!text(input.announcement?.id) || !text(input.announcement?.subject) || !text(input.announcement?.message)) return fail('SUPPORT_ANNOUNCEMENT_INVALID', ['announcement id, subject, and message required'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['announcement audit must precede mutation'], { mutated: false });
    return pass('SUPPORT_ANNOUNCEMENT_CREATED', { mutated: true, announcementId: input.announcement.id, tenantId });
  }
  return fail('SUPPORT_OPERATION_INVALID', ['supported support operation required'], { mutated: false });
}

function tenantClickthroughPolicy(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.services) || !array(input.systemAdminResources) || !array(input.tenantAdminResources)) return fail('CLICKTHROUGH_INPUT_MISSING', ['operation, caller, services, and resource sets required'], { mutated: false, decision: 'denied' });
  if (!text(input.caller.tenantId)) return fail('CLICKTHROUGH_TENANT_REQUIRED', ['resolved tenant context required'], { mutated: false, decision: 'denied' });
  if (input.providerAvailable !== true || input.reconcilerAvailable !== true) return degraded('CLICKTHROUGH_PROVIDER_UNAVAILABLE', ['policy substrate and proxy reconciler required'], { mutated: false, decision: 'denied' });
  const service = input.services.find(item => item.id === input.serviceId);
  const valid = service && text(service.resource) && text(service.apexPath) && text(service.tenantPath) && ['internal', 'composed', 'development'].includes(service.classification) && service.apexPath.startsWith('/') && service.tenantPath.startsWith('/') && !service.apexPath.includes('..') && !service.tenantPath.includes('..');
  if (!valid) return fail('CLICKTHROUGH_SERVICE_INVALID', ['valid service descriptor and safe paths required'], { mutated: false, decision: 'denied' });
  if (service.devOnly === true && input.environment !== 'development') return fail('CLICKTHROUGH_DENIED', ['development-only service excluded from this context'], { mutated: false, decision: 'denied', reason: 'dev-only' });
  const resources = input.caller.role === 'system-admin' ? input.systemAdminResources : (input.caller.role === 'tenant-admin' ? input.tenantAdminResources : []);
  if (!resources.includes(service.resource)) return fail('CLICKTHROUGH_DENIED', ['service resource is not explicitly granted'], { mutated: false, decision: 'denied', reason: 'resource-not-granted' });
  if (input.operation === 'decide') {
    if (input.auditWrittenBeforeDecision !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['clickthrough decision audit must be recorded'], { mutated: false, decision: 'denied' });
    const path = input.caller.role === 'system-admin' ? service.apexPath : service.tenantPath.replace('{tenantId}', input.caller.tenantId);
    if (!path.startsWith('/') || path.includes('{') || path.includes('..')) return fail('CLICKTHROUGH_PATH_INVALID', ['fully bound safe clickthrough path required'], { mutated: false, decision: 'denied' });
    return pass('CLICKTHROUGH_GRANTED', { mutated: false, decision: 'granted', reason: 'explicit-resource-grant', clickthroughUrl: path });
  }
  if (input.operation === 'reconcile') {
    if (input.caller.role !== 'system-admin' || !input.caller.permissions?.includes('platform.clickthrough.write')) return fail('STATIC_PERMISSION_DENIED', ['system-admin reconciliation permission required'], { mutated: false, decision: 'denied' });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['policy reconciliation audit must precede edge mutation'], { mutated: false, decision: 'denied' });
    const forwardAuth = { systemAdminResources: [...input.systemAdminResources].sort(), tenantAdminResources: [...input.tenantAdminResources].sort(), services: input.services.map(item => item.id).sort() };
    return pass('CLICKTHROUGH_RECONCILED', { mutated: true, decision: 'granted', forwardAuth, reconciliationDigest: digest(forwardAuth) });
  }
  return fail('CLICKTHROUGH_OPERATION_INVALID', ['decide or reconcile required'], { mutated: false, decision: 'denied' });
}

function complianceReport(input) {
  if (input.operation !== 'generate' || !record(input.caller) || !text(input.organisationId) || !record(input.sources) || !record(input.route) || !record(input.evidenceExport)) return fail('COMPLIANCE_REPORT_INPUT_MISSING', ['generate operation, operator, organisation, sources, route, and evidence export required'], { mutated: false, report: null });
  if (input.caller.role !== 'system-admin' || !input.caller.permissions?.includes('platform.compliance.read')) return fail('STATIC_PERMISSION_DENIED', ['system-admin compliance-read permission required'], { mutated: false, report: null });
  if (input.providerAvailable !== true) return degraded('COMPLIANCE_PROVIDER_UNAVAILABLE', ['compliance foundation providers unavailable'], { mutated: false, report: null });
  if (input.route.method !== 'GET' || input.route.resource !== 'compliance-report' || input.route.permission !== 'platform.compliance.read') return fail('COMPLIANCE_ROUTE_INVALID', ['registered GET compliance-report route and permission required'], { mutated: false, report: null });
  const required = ['metrics', 'incidents', 'legalHolds', 'retention', 'storage'];
  if (required.some((name) => !record(input.sources[name]))) return fail('COMPLIANCE_SOURCE_MISSING', ['all named foundation sources required'], { mutated: false, report: null });
  const { metrics, incidents, legalHolds, retention, storage } = input.sources;
  if (!array(metrics.signals) || !array(incidents.items) || !array(legalHolds.items) || !array(retention.policies) || typeof storage.configured !== 'boolean' || typeof storage.isolationProven !== 'boolean') return fail('COMPLIANCE_SOURCE_INVALID', ['typed metric, incident, hold, retention, and storage source data required'], { mutated: false, report: null });
  if (!text(input.generatedAt) || Number.isNaN(Date.parse(input.generatedAt)) || !/^sha256:[0-9a-f]{64}$/.test(input.evidenceExport.digest ?? '') || input.evidenceExport.available !== true) return fail('COMPLIANCE_EVIDENCE_EXPORT_INVALID', ['generated timestamp and immutable evidence export required'], { mutated: false, report: null });
  const scoped = (items) => items.filter((item) => item.organisationId === input.organisationId);
  const metricSignals = scoped(metrics.signals).map((item) => ({ key: item.key, ready: item.ready === true })).sort((a, b) => String(a.key).localeCompare(String(b.key)));
  if (metricSignals.some((item) => !text(item.key))) return fail('COMPLIANCE_METRIC_INVALID', ['named scoped metrics required'], { mutated: false, report: null });
  const ready = required.every((name) => input.sources[name].ready === true)
    && storage.configured === true && storage.isolationProven === true
    && metricSignals.length > 0 && metricSignals.every((item) => item.ready === true);
  const report = {
    organisationId: input.organisationId,
    generatedAt: input.generatedAt,
    metricSignals,
    openIncidentCount: scoped(incidents.items).filter((item) => item.state === 'open').length,
    legalHoldCount: scoped(legalHolds.items).filter((item) => item.releasedAt == null).length,
    retentionPolicyCount: scoped(retention.policies).filter((item) => item.enabled === true).length,
    storageConfigured: storage.configured,
    storageIsolationProven: storage.isolationProven,
    evidenceExportDigest: input.evidenceExport.digest,
    ready,
  };
  return ready
    ? pass('COMPLIANCE_REPORT_READY', { mutated: false, report, reportDigest: digest(report) })
    : degraded('COMPLIANCE_REPORT_NOT_READY', ['one or more foundation readiness signals are not ready'], { mutated: false, report, reportDigest: digest(report) });
}

function providerServiceCatalog(input) {
  if (!text(input.operation) || !record(input.caller) || !array(input.services) || input.services.length === 0) return fail('SERVICE_INTEGRATION_INPUT_MISSING', ['operation, caller, and service catalog required'], { mutated: false, services: null });
  if (input.providerAvailable !== true) return degraded('SERVICE_INTEGRATION_PROVIDER_UNAVAILABLE', ['catalog provider unavailable; mutation boundary remains closed'], { mutated: false, services: null });
  if (input.configValid !== true || input.tenantIsolationProven !== true || input.auditSignalAvailable !== true) return fail('SERVICE_INTEGRATION_CONFIGURATION_INVALID', ['valid configuration, tenant isolation, and audit signal required'], { mutated: false, services: null });
  const decisions = new Set(['build', 'compose', 'adapter', 'defer', 'reject']);
  const visibility = new Set(['tenant_scoped_safe', 'global_only', 'not_exposed']);
  const readiness = new Set(['ready', 'degraded', 'blocked']);
  const providerStates = new Set(['ready', 'degraded', 'unreachable']);
  const invalid = input.services.some((item) => !text(item.key) || !text(item.name) || !text(item.category) || !text(item.environmentModel)
    || !visibility.has(item.visibility) || !decisions.has(item.decision) || !text(item.entitlementKey)
    || !array(item.proofReferences) || item.proofReferences.length === 0 || item.proofReferences.some((proof) => !text(proof))
    || typeof item.consoleAccess !== 'boolean' || !readiness.has(item.readiness) || !record(item.provider)
    || !text(item.provider.kind) || !providerStates.has(item.provider.state) || forbiddenSecret(item.provider)
    || (item.visibility === 'tenant_scoped_safe' && !text(item.tenantId)));
  if (invalid) return fail('SERVICE_ENTRY_INVALID', ['coherent decision, visibility, entitlement, proof, readiness, and provider fields required'], { mutated: false, services: null });
  if (input.operation === 'migrate') {
    if (input.caller.role !== 'system-admin' || !input.caller.permissions?.includes('platform.catalog.write')) return fail('STATIC_PERMISSION_DENIED', ['system-admin catalog-write permission required'], { mutated: false });
    if (!array(input.migrations) || input.migrations.length === 0 || input.migrations.some((item, index) => item.order !== index + 1 || !text(item.checksum) || item.lineageVerified !== true || item.preservesTenantData !== true || !['forward-fix', 'guarded-restore'].includes(item.rollbackMode))) return fail('SERVICE_MIGRATION_INVALID', ['ordered lineage-verified tenant-preserving migrations required'], { mutated: false });
    if (input.auditWrittenBeforeChange !== true) return fail('AUDIT_BEFORE_CHANGE_REQUIRED', ['catalog migration audit must precede mutation'], { mutated: false });
    return pass('SERVICE_MIGRATION_ACCEPTED', { mutated: true, migrationCount: input.migrations.length });
  }
  if (!['read', 'readiness'].includes(input.operation)) return fail('SERVICE_INTEGRATION_OPERATION_INVALID', ['read, readiness, or migrate operation required'], { mutated: false, services: null });
  const platform = input.caller.role === 'system-admin';
  const permission = platform ? 'platform.catalog.read' : 'catalog:read';
  if (!text(input.caller.tenantId) || !input.caller.permissions?.includes(permission)) return fail('STATIC_PERMISSION_DENIED', ['resolved tenant and catalog-read permission required'], { mutated: false, services: null });
  const visible = input.services.filter((item) => item.visibility !== 'not_exposed')
    .filter((item) => item.visibility === 'global_only' ? platform : item.tenantId === input.caller.tenantId)
    .filter((item) => input.caller.entitlements?.includes(item.entitlementKey));
  if (visible.length === 0) return fail('SERVICE_CATALOG_EMPTY', ['no catalog entries satisfy visibility and entitlement gates'], { mutated: false, services: [] });
  const services = visible.map((item) => ({
    key: item.key, name: item.name, category: item.category, environmentModel: item.environmentModel,
    visibility: item.visibility, decision: item.decision, entitlementKey: item.entitlementKey,
    proofReferences: [...item.proofReferences].sort(), consoleAccess: item.consoleAccess,
    readiness: item.readiness, provider: clone(item.provider),
  })).sort((a, b) => a.key.localeCompare(b.key));
  const notReady = services.filter((item) => item.readiness !== 'ready' || item.provider.state !== 'ready');
  return notReady.length
    ? degraded('SERVICE_CATALOG_DEGRADED', notReady.map((item) => item.key + ':' + item.readiness + ':' + item.provider.state), { mutated: false, services, catalogDigest: digest(services) })
    : pass('SERVICE_CATALOG_READY', { mutated: false, services, catalogDigest: digest(services) });
}

function tenantIsolationProof(input) {
  if (!text(input.operation) || !text(input.apex) || !array(input.tenants) || !array(input.domains)) return fail('TENANT_ISOLATION_INPUT_MISSING', ['operation, apex, tenant registry, and domain registry required'], { mutated: false, tenantId: null, isolationProven: false });
  const resolution = tenantHostIdentity(input);
  if (!resolution.ok) return fail(resolution.code, resolution.findings ?? ['tenant host did not resolve'], { mutated: false, tenantId: null, isolationProven: false });
  if (input.operation === 'resolve') return pass('TENANT_CONTEXT_RESOLVED', { mutated: false, tenantId: resolution.tenantId, hostSource: resolution.classification, permissionsGranted: false });
  if (input.operation !== 'verify' || !record(input.caller) || !array(input.rlsChecks) || !array(input.storageChecks) || !array(input.probes) || !record(input.applicationRole)) return fail('TENANT_ISOLATION_PROOF_INPUT_MISSING', ['verify caller, RLS, storage, probes, and application role required'], { mutated: false, tenantId: resolution.tenantId, isolationProven: false });
  if (!['system', 'system-admin'].includes(input.caller.role) || !input.caller.permissions?.includes('platform.isolation.verify')) return fail('STATIC_PERMISSION_DENIED', ['explicit system isolation-verifier role required'], { mutated: false, tenantId: resolution.tenantId, isolationProven: false });
  if (input.providerAvailable !== true || input.rowSecurityAvailable !== true || input.storageAvailable !== true) return degraded('TENANT_ISOLATION_PROVIDER_UNAVAILABLE', ['resolver, row security, and storage providers must be reachable'], { mutated: false, tenantId: resolution.tenantId, isolationProven: false });
  if (input.applicationRole.superuser !== false || input.applicationRole.bypassRls !== false || input.applicationRole.noinherit !== true) return fail('TENANT_APPLICATION_ROLE_UNSAFE', ['application role must be non-superuser, non-bypass, and noinherit'], { mutated: false, tenantId: resolution.tenantId, isolationProven: false });
  const rlsSafe = input.rlsChecks.length > 0 && input.rlsChecks.every((check) => check.tenantId === resolution.tenantId && check.tenantSetting === resolution.tenantId && check.visibleForeignRows === 0 && check.foreignWriteRejected === true);
  const prefix = 'tenants/' + resolution.tenantId + '/';
  const storageSafe = input.storageChecks.length > 0 && input.storageChecks.every((check) => check.tenantId === resolution.tenantId && text(check.ownKey) && check.ownKey.startsWith(prefix) && text(check.foreignKey) && !check.foreignKey.startsWith(prefix) && check.foreignReadable === false);
  const requiredProbes = ['events', 'metering', 'observability', 'search', 'secrets', 'webhooks'];
  const probesSafe = requiredProbes.every((name) => input.probes.some((probe) => probe.name === name && probe.state === 'isolated' && current(probe.evidence)));
  if (!rlsSafe || !storageSafe || !probesSafe) return fail('TENANT_ISOLATION_FAILED', ['cross-tenant RLS, storage-prefix, and substrate probes must all prove isolation'], { mutated: false, tenantId: resolution.tenantId, isolationProven: false });
  const proof = { tenantId: resolution.tenantId, hostSource: resolution.classification, prefix, rlsChecks: input.rlsChecks.length, storageChecks: input.storageChecks.length, probes: requiredProbes };
  return pass('TENANT_ISOLATION_PROVEN', { mutated: false, tenantId: resolution.tenantId, hostSource: resolution.classification, prefix, isolationProven: true, proofDigest: digest(proof) });
}

const handlers = Object.freeze({
  accessibilitya11ygate: accessibility,
  buildversuscomposedecisionframework: decisionFramework,
  codequalityandsecretanddependencyscanning: codeScanning,
  datagovernancecataloglineageclassificationpiidsrgdpr: dataGovernance,
  delegatedadministrationroles: delegatedAdministration,
  e2econfidenceladderstageaware: confidenceLadder,
  enduserprofileandpreferencesselfservice: profileSelfService,
  environmentspecificvssharedservicemodel: environmentServiceModel,
  i18nruntimeandvalidation: i18n,
  logsaggregationandtenantscopedsearch: logSearch,
  metricsandtraces: metricsTraces,
  openapidrifthardgate: openapi,
  productcatalogplansprices: productCatalog,
  providerenvironmentclassification: providerClassification,
  relationalstorageandmigrationsandrls: relationalStorage,
  tenantidentityrecordandfqdn: tenantIdentity,
  universalservicefoundationscopeandprinciples: universalFoundation,
  useridentityandtenantmembership: membership,
  browsertelemetrygrafanafarorumandbrowsertobfftracing: browserTelemetry,
  customdomainsdnsownershiptlscanonical: customDomains,
  eventbusdurablequeuesdlqredrive: eventBus,
  historyreadmodelreadonlyprojection: historyProjection,
  rbacrolesandpermissions: rbac,
  runtimesecretsmanagement: runtimeSecrets,
  searchandindexingproductsearch: productSearch,
  suborganisations: subOrganisations,
  subscriptionsinvoicespaymentmethodsdunning: billing,
  tenantdataimportexport: tenantPortability,
  backgroundworkersjobrunner: backgroundWorkers,
  configurationregistryandhistory: configurationRegistry,
  entitlementengine: entitlementEngine,
  environmentregistryandbootstrap: environmentBootstrap,
  notificationdeliveryandpreferencesandchannels: notifications,
  providerconfigurationplane: providerConfiguration,
  scheduledjobsbuiltinontheeventsubstrate: scheduledJobs,
  tenantdomainactivationauthclient: tenantDomainAuth,
  tenanthostidentityresolution: tenantHostIdentity,
  tenantlifecycleprovisionsuspenddeleteexport: tenantLifecycle,
  writeonlysecretsettings: writeOnlySecrets,
  apikeyspersonalaccesstokens: apiKeys,
  authenticationplatform: authenticationPlatform,
  backupandrestore: backupRestore,
  brandingandtheming: branding,
  composedproviderreadinessspine: readinessSpine,
  observabilitybuiltinalertingandincidents: observabilityIncidents,
  ratelimitingapi: rateLimiting,
  tenantcanonicaldomainsetunset: canonicalDomain,
  usagemeteringandmetereventingestion: usageMetering,
  webhooksdeveloperfacing: webhooks,
  workflowenginescheduledjobsapprovals: workflows,
  abacpolicydecisionpoint: abacDecisionPoint,
  apidocsdeveloperportalsdksratelimits: developerPlatform,
  internalservicecatalogandreadiness: serviceCatalogReadiness,
  pitrretentionlegalholddataresidency: dataProtection,
  quotaenforcement: quotas,
  supportmodebreakglassaccess: supportMode,
  tenantgroups: tenantGroups,
  auditofprivilegedaccess: privilegedAudit,
  objectstorageandtenantprefixesandsignedurls: tenantObjectStorage,
  supportticketscustomerhealthannouncements: supportCustomerOperations,
  tenantserviceclickthroughpolicy: tenantClickthroughPolicy,
  compliancereportsaccessreviewsevidencepacks: complianceReport,
  servicecatalogandproviderintegrationmodel: providerServiceCatalog,
  tenantisolationproof: tenantIsolationProof,
});

export function evaluate(contract, input) {
  const envelopeFailure = validateEnvelope(input);
  if (envelopeFailure) return envelopeFailure;
  const handler = handlers[contract];
  if (!handler) return fail('UNKNOWN_CONTRACT', [`unknown contract:${contract}`]);
  const snapshot = canonicalJson(input);
  try {
    const output = handler(input);
    if (canonicalJson(input) !== snapshot) return fail('INPUT_MUTATED', ['reference kernel handlers must be pure']);
    return output;
  } catch (error) {
    return fail('TYPED_PLATFORM_ERROR', [error instanceof Error ? error.message : 'unknown local failure']);
  }
}

export function evaluateSuite(vectors) {
  if (!record(vectors)) return fail('SUITE_INPUT_MISSING', ['contract vectors are required']);
  const results = Object.fromEntries(CONTRACTS.map(contract => [contract, evaluate(contract, vectors[contract])]));
  const failed = Object.entries(results).filter(([, item]) => !item.ok).map(([contract, item]) => `${contract}:${item.code}`);
  return failed.length ? fail('SUITE_VALIDATION_FAILED', failed, { results, suiteDigest: digest(results) }) : pass('SUITE_VALIDATION_PASSED', { results, suiteDigest: digest(results) });
}
