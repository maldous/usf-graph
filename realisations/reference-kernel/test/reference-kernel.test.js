import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  AUTHORITY_DIGEST,
  CONTRACT_CONTEXT_DIGEST,
  CONTRACTS,
  NONCLAIMS,
  canonicalJson,
  digest,
  evaluate,
  evaluateSuite,
} from '../src/index.js';

const current = { admission: 'admitted', freshness: 'fresh', integrity: 'valid' };
const migrationContent = 'CREATE TABLE example(id text);';
const migrationChecksum = createHash('sha256').update(migrationContent).digest('hex').slice(0, 16);
const withAuthority = value => ({ authorityDigest: AUTHORITY_DIGEST, ...value });

function vectors() {
  return {
    accessibilitya11ygate: withAuthority({
      expectations: [{ surface: 'shell', landmarks: ['main'], roles: ['navigation'], aria: ['aria-label'] }],
      surfaces: [{ id: 'shell', landmarks: ['main'], roles: ['navigation'], aria: ['aria-label'], axeViolations: 0 }],
      evidence: current,
    }),
    buildversuscomposedecisionframework: withAuthority({
      capabilities: [{ id: 'catalog', inScope: true }],
      decisions: [{ capability: 'catalog', disposition: 'build', rationale: 'semantic fit', criteria: { security: 1 }, evidence: current, upgradesProofPosture: false, contradictsContract: false }],
    }),
    codequalityandsecretanddependencyscanning: withAuthority({
      staticAnalysis: { errorFindings: 0 },
      sbom: { present: true, stale: false, lockHashMatches: true, policyViolations: 0 },
      codeScanning: { available: true, authoritative: true, configValid: true, databaseValid: true, findings: [] },
      routeRegistered: true,
    }),
    datagovernancecataloglineageclassificationpiidsrgdpr: withAuthority({
      tenantId: 't1', providerAvailable: true,
      datasets: [{ id: 'd1', classification: 'PII', metadata: { lineage: 'source' } }],
      requests: [{ id: 'r1', tenantId: 't1', state: 'fulfilled', fulfilmentEvidence: { digest: 'sha256:x' }, fulfilledBy: 'operator' }],
    }),
    delegatedadministrationroles: withAuthority({
      operation: 'list', providerAvailable: true, now: '2026-07-15T00:00:00Z',
      caller: { id: 'u1', organisationId: 't1', role: 'tenant-admin', permissions: ['delegation:read'] },
      records: [{ id: 'g1', organisationId: 't1', granteeUserId: 'u2', scope: 'billing', revokedAt: null }],
    }),
    e2econfidenceladderstageaware: withAuthority({
      stages: [{ id: 'hermetic', requiredPosture: 'hermetic', requiredJourneys: ['login'] }],
      results: [{ stage: 'hermetic', posture: 'hermetic', journey: 'login', passed: true, ...current }],
    }),
    enduserprofileandpreferencesselfservice: withAuthority({
      providerAvailable: true,
      caller: { userId: 'u1', tenantId: 't1', permissions: ['profile:self:update'] },
      profile: { userId: 'u1', tenantId: 't1', displayName: 'Old', locale: 'en', timezone: 'UTC' },
      patch: { displayName: 'New', locale: 'en', timezone: 'UTC' }, notificationPayload: { category: 'profile' },
    }),
    environmentspecificvssharedservicemodel: withAuthority({
      services: [{ id: 'db', classification: 'environment-specific', environment: 'ci', routesTo: [{ environment: 'ci' }], evidence: current }],
    }),
    i18nruntimeandvalidation: withAuthority({
      locales: { en: { greeting: 'Hello {name}' }, fr: { greeting: 'Bonjour {name}' } },
      requiredKeys: ['greeting'], usedKeys: ['greeting'], duplicates: {}, rawLiterals: [], rawLiteralExceptions: [], strictFailOnRawLiteral: true,
    }),
    logsaggregationandtenantscopedsearch: withAuthority({
      caller: { tenantId: 't1', permissions: ['logs:read'] }, providerAvailable: true,
      query: { tenantId: 't1', from: 1, to: 10 },
      entries: [{ tenantId: 't1', timestamp: 5, service: 'api', level: 'info', message: 'ok' }, { tenantId: 't2', timestamp: 5, service: 'api', level: 'info', message: 'hidden' }],
    }),
    metricsandtraces: withAuthority({
      caller: { permissions: ['observability:read'] }, providerAvailable: true, collectorAvailable: true,
      metrics: [{ name: 'request_total', tenantId: 't1' }],
      spans: [{ id: 's1', attributes: { 'tenant.id': 't1', 'request.id': 'r1', route: '/health' } }],
    }),
    openapidrifthardgate: withAuthority({
      strict: true,
      routes: [{ method: 'GET', path: '/health' }],
      operations: [{ method: 'GET', path: '/health', unresolvedReferences: [], hasJsonRequestBody: false, hasJsonResponseBody: true, responseSchema: { type: 'object' } }],
    }),
    productcatalogplansprices: withAuthority({
      operation: 'operator-write', caller: { tenantId: 't1', permissions: ['platform:billing:admin'] }, providerAvailable: true,
      products: [{ id: 'p1', name: 'Product', active: true }],
      plans: [{ id: 'pl1', productId: 'p1', currency: 'USD', billingPeriod: 'month' }],
      prices: [{ id: 'pr1', planId: 'pl1', version: 1, unitAmount: 1000, priceType: 'fixed' }],
    }),
    providerenvironmentclassification: withAuthority({
      providers: [{ id: 'mail', mode: 'hermetic-mock', environment: 'ci', satisfies: ['hermetic-mock'], evidence: current }],
    }),
    relationalstorageandmigrationsandrls: withAuthority({
      providerAvailable: true, currentTenant: 't1', applicationPassword: 'safe-value',
      migrations: [{ file: '001.sql', content: migrationContent, checksum: migrationChecksum, appliedChecksum: migrationChecksum }],
      tables: [{ name: 'members', tenantColumn: 'organisation_id', rlsEnabled: true, rlsForced: true, policy: 'tenant-equals-current-or-explicit-bypass' }],
      applicationRole: { superuser: false, bypassRls: false, noinherit: true },
    }),
    tenantidentityrecordandfqdn: withAuthority({
      host: 'acme.example.com:443', forwardedHost: '', apexHost: 'example.com', reservedHosts: ['admin.example.com'], registryAvailable: true,
      domains: [{ fqdn: 'acme.example.com', organisationId: 't1', state: 'active', verified: true, source: 'custom_domain' }],
    }),
    universalservicefoundationscopeandprinciples: withAuthority({
      assets: [{ id: 'a1', contract: 'contract', readiness: 'ready', reportStatus: 'implemented', proofLevel: 'behaviour', evidence: current, providerMode: 'hermetic-mock', environment: 'ci', claims: [], authorityOrder: 'semantics>evidence>proof>contract>realisation>validation' }],
    }),
    useridentityandtenantmembership: withAuthority({
      operation: 'list', providerAvailable: true,
      caller: { id: 'admin', tenantId: 't1', permissions: ['members:read'] },
      members: [{ id: 'm1', organisationId: 't1', email: 'a@example.com', role: 'tenant-admin', status: 'active' }, { id: 'm2', organisationId: 't2', email: 'b@example.com', role: 'tenant-admin', status: 'active' }],
    }),
    browsertelemetrygrafanafarorumandbrowsertobfftracing: withAuthority({ tenantId: 't1', providerAvailable: true, configValid: true, spans: [{ id: 'b', side: 'browser', traceId: 'tr1', requestId: 'r1', tenantId: 't1', attributes: { 'tenant.id': 't1', 'trace.id': 'tr1' } }, { id: 's', side: 'bff', traceId: 'tr1', requestId: 'r1', tenantId: 't1', attributes: { 'tenant.id': 't1', 'request.id': 'r1' } }] }),
    customdomainsdnsownershiptlscanonical: withAuthority({ operation: 'set-canonical', providerAvailable: true, caller: { tenantId: 't1', permissions: ['domains:write'] }, domain: { fqdn: 'app.example.com' }, domains: [{ fqdn: 'app.example.com', tenantId: 't1', enabled: true, ownership: 'verified', authClient: 'active', routing: 'locally-active' }] }),
    eventbusdurablequeuesdlqredrive: withAuthority({ operation: 'redrive', providerAvailable: true, auditWrittenBeforeChange: true, id: 'e1', caller: { tenantId: 't1', permissions: ['events:write'] }, events: [{ id: 'e1', tenantId: 't1', status: 'dead_letter', payload: { kind: 'report' } }] }),
    historyreadmodelreadonlyprojection: withAuthority({ providerAvailable: true, limit: 20, offset: 0, caller: { tenantId: 't1', permissions: ['history:read'] }, entries: [{ id: 'h1', tenantId: 't1', source: 'audit', type: 'updated', title: 'Updated', occurredAt: '2026-07-15T00:00:00Z', actor: 'u1', status: 'ok' }] }),
    rbacrolesandpermissions: withAuthority({ operation: 'resolve', id: 'm1', providerAvailable: true, caller: { tenantId: 't1', permissions: ['permissions:read'] }, members: [{ id: 'm1', tenantId: 't1', role: 'manager', status: 'active' }], rolePermissions: { manager: ['members:read'] } }),
    runtimesecretsmanagement: withAuthority({ operation: 'list', providerAvailable: true, caller: { tenantId: 't1', permissions: ['secrets:read'] }, records: [{ ref: 'secret://1', tenantId: 't1', provider: 'postgres', version: 1, revoked: false, deleted: false, metadata: { name: 'api-key' } }] }),
    searchandindexingproductsearch: withAuthority({ operation: 'query', providerAvailable: true, queryTenantId: 't1', caller: { tenantId: 't1', permissions: ['search:read', 'catalog:read'] }, documents: [{ tenantId: 't1', documentId: 'd1', documentType: 'product', title: 'One', permissionKey: 'catalog:read', metadata: { category: 'test' } }, { tenantId: 't2', documentId: 'd2', documentType: 'product', title: 'Hidden', metadata: {} }] }),
    suborganisations: withAuthority({ operation: 'list', providerAvailable: true, caller: { tenantId: 't1', permissions: ['suborgs:read'] }, organisations: [{ id: 'o1', parentId: 't1', slug: 'child', displayName: 'Child', active: true }, { id: 'o2', parentId: 't2', slug: 'foreign', displayName: 'Foreign', active: true }] }),
    subscriptionsinvoicespaymentmethodsdunning: withAuthority({ providerAvailable: true, caller: { tenantId: 't1', permissions: ['billing:write'] }, operations: [{ id: 'c1', tenantId: 't1', idempotencyKey: 'k1', amount: 1000, currency: 'USD', outcome: { status: 'captured' } }, { id: 'c2', tenantId: 't1', idempotencyKey: 'k1', amount: 1000, currency: 'USD', outcome: { status: 'captured' } }] }),
    tenantdataimportexport: withAuthority({ operation: 'import', providerAvailable: true, caller: { tenantId: 't1', permissions: ['data:import'] }, archive: { tenantId: 't1', digest: 'sha256:archive', encrypted: true, integrity: 'valid' }, progress: { tenantId: 't1', digest: 'sha256:archive', completedUnits: ['members'], failedUnit: 'billing' } }),
    backgroundworkersjobrunner: withAuthority({ providerAvailable: true, workerId: 'w1', eventId: 'e1', maxAttempts: 3, caller: { permissions: ['platform.workers.read'] }, events: [{ id: 'e1', tenantId: 't1', status: 'pending', attempts: 0 }] }),
    configurationregistryandhistory: withAuthority({ operation: 'set', providerAvailable: true, key: 'mode', value: 'safe', auditWrittenBeforeChange: true, caller: { tenantId: 't1', permissions: ['configuration:write'] }, definitions: [{ key: 'mode', type: 'string', allowed: ['safe'], overridable: true }], overrides: [] }),
    entitlementengine: withAuthority({ operation: 'grant', providerAvailable: true, tenantId: 't1', grantTenantId: 't1', key: 'reports', auditWrittenBeforeChange: true, caller: { tenantId: 'ops', permissions: ['platform.entitlements.write'] }, catalog: [{ key: 'reports', kind: 'entitlement' }], grants: [] }),
    environmentregistryandbootstrap: withAuthority({ providerAvailable: true, secretProviderAvailable: true, auditWrittenBeforeChange: true, caller: { permissions: ['platform.environments.write'] }, manifest: { name: 'test', requiredKeys: ['region'], values: { region: 'eu-test' } }, registry: [] }),
    notificationdeliveryandpreferencesandchannels: withAuthority({ operation: 'test-send', providerAvailable: true, channel: 'email', recipient: 'ops@example.test', auditWrittenBeforeChange: true, payload: { template: 'status' }, caller: { tenantId: 't1', permissions: ['platform.notifications.write'] }, preferences: [{ tenantId: 't1', channel: 'email', enabled: true }] }),
    providerconfigurationplane: withAuthority({ providerAvailable: true, healthProbePassed: true, auditWrittenBeforeChange: true, caller: { permissions: ['platform.providers.write'] }, providers: [], payload: { kind: 'mail', lifecycleState: 'ready', requiresCredential: true, credentialRef: 'secret://mail' } }),
    scheduledjobsbuiltinontheeventsubstrate: withAuthority({ operation: 'run-now', providerAvailable: true, organisationId: 't1', jobId: 'j1', auditWrittenBeforeChange: true, caller: { permissions: ['platform.jobs.write'] }, jobs: [{ id: 'j1', organisationId: 't1', enabled: true, lastWindow: null }] }),
    tenantdomainactivationauthclient: withAuthority({ operation: 'activate', providerAvailable: true, fqdn: 'app.example.test', auditWrittenBeforeChange: true, caller: { tenantId: 't1', permissions: ['domains:write'] }, domains: [{ fqdn: 'app.example.test', tenantId: 't1', ownership: 'verified', authClient: 'inactive' }] }),
    tenanthostidentityresolution: withAuthority({ host: 'acme.example.test:443', apex: 'example.test', reservedSlugs: ['admin'], tenants: [{ id: 't1', slug: 'acme', active: true }], domains: [] }),
    tenantlifecycleprovisionsuspenddeleteexport: withAuthority({ operation: 'delete', providerAvailable: true, tenantId: 'tenant-one', auditWrittenBeforeChange: true, caller: { permissions: ['platform.tenants.delete'] }, steps: [{ name: 'export', ok: true, executed: true }, { name: 'realm', ok: true, executed: true }, { name: 'data', ok: true, executed: true }] }),
    writeonlysecretsettings: withAuthority({ operation: 'update', providerAvailable: true, environment: 'test', encryptionKeyAvailable: true, secretInput: 'opaque-input', auditWrittenBeforeChange: true, auditMetadata: { alias: 'mail', changed: true }, caller: { permissions: ['secrets:write'] }, records: [{ alias: 'mail', redacted: true }] }),
    apikeyspersonalaccesstokens: withAuthority({ operation: 'create', providerAvailable: true, auditWrittenBeforeChange: true, caller: { tenantId: 't1', permissions: ['api-keys:write'], entitlements: ['api-access'] }, metadata: { name: 'automation' }, records: [] }),
    authenticationplatform: withAuthority({ operation: 'update-provider', providerAvailable: true, credentialState: 'valid', auditWrittenBeforeChange: true, targetTenantId: 't1', caller: { tenantId: 't1', permissions: ['auth-settings:write'] }, provider: { alias: 'workforce', issuer: 'https://id.example.test', discoveryValid: true, jwksValid: true } }),
    backupandrestore: withAuthority({ operation: 'backup', environment: 'test', providerAvailable: true, artifactPath: 'artifacts/backups/test-20260716.dump.gz', ownerOnly: true, gitIgnored: true }),
    brandingandtheming: withAuthority({ operation: 'set', providerAvailable: true, defaultTheme: { mode: 'system', applicationName: 'USF' }, key: 'theme', value: 'dark', auditWrittenBeforeChange: true, caller: { tenantId: 't1', permissions: ['configuration:write'] }, definitions: [{ key: 'theme', type: 'string', allowed: ['system', 'light', 'dark'], overridable: true }] }),
    composedproviderreadinessspine: withAuthority({ providers: [{ id: 'database', state: 'ready', required: true, evidence: current }, { id: 'identity', state: 'ready', required: true, evidence: current }] }),
    observabilitybuiltinalertingandincidents: withAuthority({ operation: 'transition', providerAvailable: true, incidentId: 'i1', targetState: 'acknowledged', auditWrittenBeforeChange: true, requestId: 'r1', traceId: 'tr1', caller: { tenantId: 't1', permissions: ['platform.observability.write'] }, incidents: [{ id: 'i1', tenantId: 't1', state: 'open' }] }),
    ratelimitingapi: withAuthority({ operation: 'evaluate', cacheAvailable: true, relationalFallbackAvailable: true, used: 1, windowBucket: 42, caller: { tenantId: 't1', entitlements: ['api-access'] }, policy: { entitlementKey: 'api-access', limit: 2, windowSeconds: 60 } }),
    tenantcanonicaldomainsetunset: withAuthority({ operation: 'set', providerAvailable: true, fqdn: 'app.example.test', auditWrittenBeforeChange: true, caller: { tenantId: 't1', permissions: ['domains:write'] }, domains: [{ fqdn: 'app.example.test', tenantId: 't1', ownership: 'verified', authClient: 'active', routing: 'locally-active', canonical: false }] }),
    usagemeteringandmetereventingestion: withAuthority({ operation: 'ingest', providerAvailable: true, caller: { tenantId: 't1', permissions: ['platform.metering.write'], entitlements: ['reports'] }, meters: [{ key: 'reports.generated', entitlementKey: 'reports' }], event: { id: 'e1', tenantId: 't1', meterKey: 'reports.generated', quantity: 1, idempotencyKey: 'k1' }, events: [] }),
    webhooksdeveloperfacing: withAuthority({ operation: 'redrive', providerAvailable: true, workerAvailable: true, deliveryId: 'd1', idempotencyKey: 'redrive-1', auditWrittenBeforeChange: true, auditMetadata: { deliveryId: 'd1' }, caller: { tenantId: 't1', permissions: ['webhooks:write'] }, subscriptions: [{ id: 's1', tenantId: 't1', enabled: true, secretHash: 'hash-only' }], deliveries: [{ id: 'd1', tenantId: 't1', state: 'dead', attempts: 3 }] }),
    workflowenginescheduledjobsapprovals: withAuthority({ operation: 'signal', providerAvailable: true, workflowId: 'w1', signal: 'approval.granted', auditWrittenBeforeChange: true, caller: { tenantId: 't1', operator: true, permissions: ['platform.workflow.write'] }, workflows: [{ id: 'w1', tenantId: 't1', status: 'waiting' }] }),
    abacpolicydecisionpoint: withAuthority({ operation: 'evaluate', expectedToken: true, tokenPresent: true, authorizationServerAvailable: true, resourceRegistered: true, serverDecision: 'granted', resource: 'catalog', scope: 'read', requiredPermission: 'catalog:read', caller: { tenantId: 't1', permissions: [] } }),
    apidocsdeveloperportalsdksratelimits: withAuthority({ operation: 'portal-read', openapiDrift: false, graphqlContractValid: true, providerAvailable: true, caller: { tenantId: 't1', permissions: ['developer:read'] }, keys: [{ id: 'k1', prefix: 'usf_', revokedAt: null }] }),
    internalservicecatalogandreadiness: withAuthority({ providerAvailable: true, caller: { tenantId: 't1', permissions: ['services:read'] }, services: [{ id: 'database', tenantId: 't1', state: 'ready', evidence: current }, { id: 'identity', shared: true, state: 'ready', evidence: current }] }),
    pitrretentionlegalholddataresidency: withAuthority({ operation: 'retention-tick', providerAvailable: true, restoreDrillPassed: true, caller: { permissions: ['platform.data-protection.write'] }, policies: [{ tenantId: 't1', resourceClass: 'events', enabled: true, ttlDays: 30 }], candidates: [{ id: 'e1', tenantId: 't1', resourceClass: 'events', requestedOutcome: 'held' }], holds: [{ tenantId: 't1', resourceId: 'e1', reason: 'case', releasedAt: null }] }),
    quotaenforcement: withAuthority({ operation: 'evaluate', providerAvailable: true, usage: 7, delta: 2, caller: { tenantId: 't1', entitlements: ['reports'] }, quota: { entitlementKey: 'reports', meterKey: 'reports.generated', limit: 10 } }),
    supportmodebreakglassaccess: withAuthority({ operation: 'approve', providerAvailable: true, workflowId: 'w1', targetTenantId: 't1', reason: 'incident support', auditWrittenBeforeChange: true, caller: { role: 'system-admin', permissions: ['platform.support.enter'] }, workflows: [{ id: 'w1', targetTenantId: 't1', state: 'waiting' }], sessions: [] }),
    tenantgroups: withAuthority({ operation: 'create', credentialState: 'valid', providerAvailable: true, name: 'Operators', reservedNames: ['admins'], auditWrittenBeforeChange: true, caller: { tenantId: 't1', permissions: ['groups:create'] }, groups: [{ id: 'g1', name: 'Readers', path: '/Readers' }] }),
    auditofprivilegedaccess: withAuthority({ operation: 'query', resource: 'member', from: 1, to: 10, limit: 20, providerAvailable: true, caller: { tenantId: 't1', permissions: ['audit:read', 'member:read'] }, events: [{ id: 'a1', tenantId: 't1', action: 'support.enter', actorId: 'u1', resource: 'member', resourceId: 'm1', timestamp: 5, clientIp: 'hidden', userAgent: 'hidden', metadata: { reason: 'incident', accessToken: 'hidden' } }, { id: 'a2', tenantId: 't2', action: 'support.enter', actorId: 'u2', resource: 'member', resourceId: 'm2', timestamp: 5, metadata: {} }] }),
    objectstorageandtenantprefixesandsignedurls: withAuthority({ operation: 'issue-download-url', providerAvailable: true, registryAvailable: true, objectId: 'o1', signedUrl: 'https://objects.example.test/signed/o1', ttlSeconds: 300, caller: { tenantId: 't1', permissions: ['objects:read'] }, objects: [{ id: 'o1', tenantId: 't1', key: 'tenants/t1/o1', contentType: 'application/pdf', sizeBytes: 10, scanState: 'clean' }] }),
    supportticketscustomerhealthannouncements: withAuthority({ operation: 'approve-support', providerAvailable: true, workflowId: 'w1', targetTenantId: 't1', auditWrittenBeforeChange: true, caller: { role: 'system-admin', permissions: ['platform.support.approve'] }, tickets: [], usage: [], announcements: [], workflows: [{ id: 'w1', targetTenantId: 't1', state: 'waiting' }], sessions: [] }),
    tenantserviceclickthroughpolicy: withAuthority({ operation: 'decide', serviceId: 'catalog', environment: 'test', providerAvailable: true, reconcilerAvailable: true, auditWrittenBeforeDecision: true, caller: { tenantId: 't1', role: 'tenant-admin', permissions: [] }, systemAdminResources: ['platform.catalog'], tenantAdminResources: ['catalog.read'], services: [{ id: 'catalog', resource: 'catalog.read', apexPath: '/catalog', tenantPath: '/tenants/{tenantId}/catalog', classification: 'internal', devOnly: false }] }),
    compliancereportsaccessreviewsevidencepacks: withAuthority({ operation: 'generate', organisationId: 't1', generatedAt: '2026-07-16T00:00:00Z', providerAvailable: true, caller: { role: 'system-admin', permissions: ['platform.compliance.read'] }, route: { method: 'GET', resource: 'compliance-report', permission: 'platform.compliance.read' }, evidenceExport: { available: true, digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }, sources: { metrics: { ready: true, signals: [{ organisationId: 't1', key: 'requests', ready: true }] }, incidents: { ready: true, items: [{ organisationId: 't1', state: 'open' }, { organisationId: 't2', state: 'open' }] }, legalHolds: { ready: true, items: [{ organisationId: 't1', releasedAt: null }] }, retention: { ready: true, policies: [{ organisationId: 't1', enabled: true }] }, storage: { ready: true, configured: true, isolationProven: true } } }),
    servicecatalogandproviderintegrationmodel: withAuthority({ operation: 'read', providerAvailable: true, configValid: true, tenantIsolationProven: true, auditSignalAvailable: true, caller: { tenantId: 't1', role: 'tenant-admin', permissions: ['catalog:read'], entitlements: ['reports'] }, services: [{ key: 'reports', name: 'Reports', category: 'compliance', environmentModel: 'shared', visibility: 'tenant_scoped_safe', decision: 'build', entitlementKey: 'reports', proofReferences: ['proof:reports'], consoleAccess: false, readiness: 'ready', provider: { kind: 'internal', state: 'ready' }, tenantId: 't1' }, { key: 'platform', name: 'Platform', category: 'internal', environmentModel: 'shared', visibility: 'global_only', decision: 'compose', entitlementKey: 'reports', proofReferences: ['proof:platform'], consoleAccess: false, readiness: 'ready', provider: { kind: 'internal', state: 'ready' } }] }),
    tenantisolationproof: withAuthority({ operation: 'verify', host: 'ignored.example.test', forwardedHost: 'acme.example.test:443', apex: 'example.test', reservedSlugs: ['admin'], providerAvailable: true, rowSecurityAvailable: true, storageAvailable: true, caller: { role: 'system', permissions: ['platform.isolation.verify'] }, tenants: [{ id: 't1', slug: 'acme', active: true }], domains: [], applicationRole: { superuser: false, bypassRls: false, noinherit: true }, rlsChecks: [{ tenantId: 't1', tenantSetting: 't1', visibleForeignRows: 0, foreignWriteRejected: true }], storageChecks: [{ tenantId: 't1', ownKey: 'tenants/t1/report', foreignKey: 'tenants/t2/report', foreignReadable: false }], probes: ['events', 'metering', 'observability', 'search', 'secrets', 'webhooks'].map(name => ({ name, state: 'isolated', evidence: current })) }),
  };
}

test('authority and context constants are canonical and the contract set is exact', () => {
  assert.match(AUTHORITY_DIGEST, /^sha256:[0-9a-f]{64}$/);
  assert.match(CONTRACT_CONTEXT_DIGEST, /^sha256:[0-9a-f]{64}$/);
  assert.equal(CONTRACTS.length, 64);
  assert.equal(new Set(CONTRACTS).size, 64);
  assert.deepEqual(NONCLAIMS, [
    'urn:usf:nonclaim:noaccessibilitycompliance',
    'urn:usf:nonclaim:nohumanacceptance',
    'urn:usf:nonclaim:nolaunchi18n',
    'urn:usf:nonclaim:nouiproductparity',
  ]);
});

test('complete dependency Waves 0 through 6 vector suite passes deterministically', () => {
  const first = evaluateSuite(vectors());
  const second = evaluateSuite(vectors());
  assert.equal(first.ok, true);
  assert.equal(first.code, 'SUITE_VALIDATION_PASSED');
  assert.equal(first.suiteDigest, second.suiteDigest);
  assert.equal(Object.keys(first.results).length, 64);
  assert.match(first.suiteDigest, /^sha256:[0-9a-f]{64}$/);
});

const defects = [
  ['accessibilitya11ygate', input => { input.surfaces[0].axeViolations = 1; }, 'A11Y_GATE_FAILED'],
  ['buildversuscomposedecisionframework', input => { input.decisions = []; }, 'DECISION_FRAMEWORK_FAILED'],
  ['codequalityandsecretanddependencyscanning', input => { input.sbom.lockHashMatches = false; }, 'SCANNING_GATE_FAILED'],
  ['datagovernancecataloglineageclassificationpiidsrgdpr', input => { delete input.requests[0].fulfilmentEvidence; }, 'GOVERNANCE_VALIDATION_FAILED'],
  ['delegatedadministrationroles', input => { input.caller.permissions = []; }, 'STATIC_PERMISSION_DENIED'],
  ['e2econfidenceladderstageaware', input => { input.results[0].posture = 'unit'; }, 'CONFIDENCE_LADDER_FAILED'],
  ['enduserprofileandpreferencesselfservice', input => { input.patch.displayName = ''; }, 'VALIDATION_ERROR'],
  ['environmentspecificvssharedservicemodel', input => { input.services[0].routesTo[0].environment = 'prod'; }, 'ENVIRONMENT_SERVICE_MODEL_FAILED'],
  ['i18nruntimeandvalidation', input => { delete input.locales.fr.greeting; }, 'I18N_VALIDATION_FAILED'],
  ['logsaggregationandtenantscopedsearch', input => { input.query.tenantId = 't2'; }, 'TENANT_SCOPE_REQUIRED'],
  ['metricsandtraces', input => { input.metrics[0].name = 'arbitrary_metric'; }, 'METRICS_TRACES_VALIDATION_FAILED'],
  ['openapidrifthardgate', input => { input.operations = []; }, 'OPENAPI_DRIFT'],
  ['productcatalogplansprices', input => { input.prices[0].planId = 'missing'; }, 'CATALOG_VALIDATION_FAILED'],
  ['providerenvironmentclassification', input => { input.providers[0].satisfies = ['live-external-provider']; }, 'PROVIDER_CLASSIFICATION_FAILED'],
  ['relationalstorageandmigrationsandrls', input => { input.tables[0].rlsForced = false; }, 'RELATIONAL_VALIDATION_FAILED'],
  ['tenantidentityrecordandfqdn', input => { input.domains[0].verified = false; }, 'NO_TENANT'],
  ['universalservicefoundationscopeandprinciples', input => { input.assets[0].claims = ['live-external-provider']; }, 'FOUNDATION_VALIDATION_FAILED'],
  ['useridentityandtenantmembership', input => { input.caller.permissions = []; }, 'STATIC_PERMISSION_DENIED'],
  ['browsertelemetrygrafanafarorumandbrowsertobfftracing', input => { input.spans[1].traceId = 'other'; }, 'TELEMETRY_VALIDATION_FAILED'],
  ['customdomainsdnsownershiptlscanonical', input => { input.domains[0].routing = 'unknown'; }, 'DOMAIN_NOT_READY'],
  ['eventbusdurablequeuesdlqredrive', input => { input.auditWrittenBeforeChange = false; }, 'AUDIT_BEFORE_CHANGE_REQUIRED'],
  ['historyreadmodelreadonlyprojection', input => { input.entries[0].payload = { secret: 'x' }; }, 'HISTORY_SHAPE_UNSAFE'],
  ['rbacrolesandpermissions', input => { input.caller.permissions = []; }, 'STATIC_PERMISSION_DENIED'],
  ['runtimesecretsmanagement', input => { input.records[0].value = 'leak'; }, 'SECRET_METADATA_LEAK'],
  ['searchandindexingproductsearch', input => { input.queryTenantId = 't2'; }, 'TENANT_SCOPE_REQUIRED'],
  ['suborganisations', input => { input.caller.permissions = []; }, 'STATIC_PERMISSION_DENIED'],
  ['subscriptionsinvoicespaymentmethodsdunning', input => { input.operations[1].outcome.status = 'failed'; }, 'BILLING_VALIDATION_FAILED'],
  ['tenantdataimportexport', input => { input.progress.digest = 'sha256:other'; }, 'PORTABILITY_INTEGRITY_FAILED'],
  ['backgroundworkersjobrunner', input => { input.caller.permissions = []; }, 'STATIC_PERMISSION_DENIED'],
  ['configurationregistryandhistory', input => { input.auditWrittenBeforeChange = false; }, 'AUDIT_BEFORE_CHANGE_REQUIRED'],
  ['entitlementengine', input => { input.grantTenantId = 't2'; }, 'ENTITLEMENT_INVALID'],
  ['environmentregistryandbootstrap', input => { delete input.manifest.values.region; }, 'ENVIRONMENT_MANIFEST_INVALID'],
  ['notificationdeliveryandpreferencesandchannels', input => { input.recipient = ''; }, 'NOTIFICATION_SEND_INVALID'],
  ['providerconfigurationplane', input => { input.healthProbePassed = false; }, 'PROVIDER_NOT_HEALTHY'],
  ['scheduledjobsbuiltinontheeventsubstrate', input => { input.jobs[0].enabled = false; }, 'SCHEDULE_JOB_INVALID'],
  ['tenantdomainactivationauthclient', input => { input.domains[0].ownership = 'pending'; }, 'AUTH_CLIENT_STATE_INVALID'],
  ['tenanthostidentityresolution', input => { input.host = 'malformed'; }, 'HOST_MALFORMED'],
  ['tenantlifecycleprovisionsuspenddeleteexport', input => { input.steps[1].ok = false; input.steps[2].executed = true; }, 'TENANT_DELETE_COORDINATION_FAILED'],
  ['writeonlysecretsettings', input => { input.operation = 'read'; }, 'SECRET_RETRIEVAL_FORBIDDEN'],
  ['apikeyspersonalaccesstokens', input => { input.caller.entitlements = []; }, 'API_KEY_NOT_ENTITLED'],
  ['authenticationplatform', input => { input.provider.issuer = 'http://remote.example.test'; }, 'AUTH_PROVIDER_INVALID'],
  ['backupandrestore', input => { input.environment = 'production'; }, 'BACKUP_ENVIRONMENT_GUARD'],
  ['brandingandtheming', input => { input.value = 'neon'; }, 'BRANDING_VALUE_INVALID'],
  ['composedproviderreadinessspine', input => { input.providers[0].evidence.freshness = 'stale'; }, 'READINESS_INPUT_UNTRUSTED'],
  ['observabilitybuiltinalertingandincidents', input => { input.targetState = 'resolved'; }, 'INCIDENT_TRANSITION_INVALID'],
  ['ratelimitingapi', input => { input.caller.entitlements = []; }, 'RATE_LIMIT_NOT_ENTITLED'],
  ['tenantcanonicaldomainsetunset', input => { input.domains[0].routing = 'unknown'; }, 'CANONICAL_DOMAIN_NOT_READY'],
  ['usagemeteringandmetereventingestion', input => { input.event.quantity = 0; }, 'METER_QUANTITY_INVALID'],
  ['webhooksdeveloperfacing', input => { input.subscriptions[0].secret = 'leak'; }, 'WEBHOOK_SECRET_EXPOSURE'],
  ['workflowenginescheduledjobsapprovals', input => { input.workflows[0].tenantId = 't2'; }, 'WORKFLOW_ACCESS_DENIED'],
  ['abacpolicydecisionpoint', input => { input.authorizationServerAvailable = false; }, 'STATIC_PERMISSION_DENIED'],
  ['apidocsdeveloperportalsdksratelimits', input => { input.openapiDrift = true; }, 'API_CONTRACT_DRIFT'],
  ['internalservicecatalogandreadiness', input => { input.services[0].evidence.freshness = 'stale'; }, 'SERVICE_READINESS_UNTRUSTED'],
  ['pitrretentionlegalholddataresidency', input => { input.candidates[0].requestedOutcome = 'deleted'; }, 'LEGAL_HOLD_VIOLATION'],
  ['quotaenforcement', input => { input.caller.entitlements = []; }, 'QUOTA_NOT_ENTITLED'],
  ['supportmodebreakglassaccess', input => { input.reason = '   '; }, 'SUPPORT_REASON_REQUIRED'],
  ['tenantgroups', input => { input.name = 'admins'; }, 'GROUP_NAME_INVALID'],
  ['auditofprivilegedaccess', input => { input.caller.permissions = ['audit:read']; }, 'STATIC_PERMISSION_DENIED'],
  ['objectstorageandtenantprefixesandsignedurls', input => { input.objects[0].scanState = 'uploaded'; }, 'OBJECT_NOT_CLEAN'],
  ['supportticketscustomerhealthannouncements', input => { input.workflows[0].state = 'completed'; }, 'SUPPORT_APPROVAL_REQUIRED'],
  ['tenantserviceclickthroughpolicy', input => { input.tenantAdminResources = []; }, 'CLICKTHROUGH_DENIED'],
  ['compliancereportsaccessreviewsevidencepacks', input => { input.sources.storage.isolationProven = false; }, 'COMPLIANCE_REPORT_NOT_READY'],
  ['servicecatalogandproviderintegrationmodel', input => { input.services[0].proofReferences = []; }, 'SERVICE_ENTRY_INVALID'],
  ['tenantisolationproof', input => { input.rlsChecks[0].visibleForeignRows = 1; }, 'TENANT_ISOLATION_FAILED'],
];

for (const [contract, plant, code] of defects) {
  test(`planted defect is rejected exclusively: ${contract}`, () => {
    const input = structuredClone(vectors()[contract]);
    plant(input);
    const before = canonicalJson(input);
    const observed = evaluate(contract, input);
    assert.equal(observed.ok, false);
    assert.equal(observed.code, code);
    assert.equal(canonicalJson(input), before);
  });
}

test('authority drift and unknown contracts fail before domain evaluation', () => {
  const input = vectors().accessibilitya11ygate;
  input.authorityDigest = 'sha256:' + '0'.repeat(64);
  assert.equal(evaluate('accessibilitya11ygate', input).code, 'AUTHORITY_DIGEST_MISMATCH');
  assert.equal(evaluate('not-a-contract', withAuthority({})).code, 'UNKNOWN_CONTRACT');
});

test('delegation grant overwrites client grantor and duplicate is non-mutating', () => {
  const input = withAuthority({
    operation: 'grant', providerAvailable: true, now: '2026-07-15T00:00:00Z', records: [],
    caller: { id: 'admin', organisationId: 't1', role: 'tenant-admin', permissions: ['delegation:write'] },
    grant: { id: 'g1', organisationId: 't1', granteeUserId: 'u2', scope: 'billing', grantedBy: 'attacker' },
  });
  const granted = evaluate('delegatedadministrationroles', input);
  assert.equal(granted.ok, true);
  assert.equal(granted.records[0].grantedBy, 'admin');
  const duplicate = evaluate('delegatedadministrationroles', { ...input, records: granted.records });
  assert.equal(duplicate.code, 'DELEGATION_ALREADY_ACTIVE');
  assert.equal(duplicate.mutated, false);
});

test('last tenant admin guard prevents demotion without partial mutation', () => {
  const input = withAuthority({
    operation: 'update', providerAvailable: true, id: 'm1', patch: { role: 'member' },
    caller: { id: 'm1', tenantId: 't1', permissions: ['members:update-role'] },
    members: [{ id: 'm1', organisationId: 't1', email: 'a@example.com', role: 'tenant-admin', status: 'active' }],
  });
  const before = canonicalJson(input);
  const observed = evaluate('useridentityandtenantmembership', input);
  assert.equal(observed.code, 'LAST_ADMIN_GUARD');
  assert.equal(observed.mutated, false);
  assert.equal(canonicalJson(input), before);
});

test('degraded provider paths never fabricate authoritative results', () => {
  const logInput = vectors().logsaggregationandtenantscopedsearch;
  logInput.providerAvailable = false;
  const log = evaluate('logsaggregationandtenantscopedsearch', logInput);
  assert.equal(log.readiness, 'degraded');
  assert.equal(log.entries, null);
  const scanInput = vectors().codequalityandsecretanddependencyscanning;
  scanInput.codeScanning = { available: false, authoritative: false };
  const scan = evaluate('codequalityandsecretanddependencyscanning', scanInput);
  assert.equal(scan.code, 'SCANNER_HONEST_SKIP');
  assert.equal(scan.readiness, 'degraded');
});

test('report-only modes retain findings and never masquerade as strict passes', () => {
  const i18nInput = vectors().i18nruntimeandvalidation;
  i18nInput.rawLiterals = ['Ungoverned'];
  i18nInput.strictFailOnRawLiteral = false;
  const i18nResult = evaluate('i18nruntimeandvalidation', i18nInput);
  assert.equal(i18nResult.code, 'I18N_REPORT_ONLY_FINDINGS');
  assert.equal(i18nResult.reportOnly, true);
  const apiInput = vectors().openapidrifthardgate;
  apiInput.operations = [];
  apiInput.strict = false;
  const apiResult = evaluate('openapidrifthardgate', apiInput);
  assert.equal(apiResult.code, 'OPENAPI_REPORT_ONLY_FINDINGS');
  assert.equal(apiResult.reportOnly, true);
});

test('tenant isolation filters logs, memberships, and delegated grants', () => {
  const logs = evaluate('logsaggregationandtenantscopedsearch', vectors().logsaggregationandtenantscopedsearch);
  assert.deepEqual(logs.entries.map(item => item.tenantId), ['t1']);
  const members = evaluate('useridentityandtenantmembership', vectors().useridentityandtenantmembership);
  assert.deepEqual(members.members.map(item => item.organisationId), ['t1']);
  const delegated = vectors().delegatedadministrationroles;
  delegated.records.push({ id: 'g2', organisationId: 't2', granteeUserId: 'u3', scope: 'billing', revokedAt: null });
  const grants = evaluate('delegatedadministrationroles', delegated);
  assert.deepEqual(grants.records.map(item => item.organisationId), ['t1']);
});

test('canonical encoding and digest are order-independent for object keys', () => {
  assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
  assert.equal(digest({ b: 2, a: 1 }), digest({ a: 1, b: 2 }));
});

test('results contain no secret values or accidental live-readiness claims', () => {
  const output = canonicalJson(evaluateSuite(vectors()));
  assert.doesNotMatch(output, /safe-value|password|production-live|live-external-provider/);
  assert.match(output, /noaccessibilitycompliance/);
});
