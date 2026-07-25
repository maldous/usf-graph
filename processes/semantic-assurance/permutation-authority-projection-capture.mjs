// Mechanical re-capture of the permutation authority packet and projection
// from live semantic authority.
//
// The packet and projection are the snapshot of authority that the whole
// permutation-closure wave reads. Before this process existed they were
// hand-curated, their provenance recorded only as a prose sentence, and their
// scope recoverable only from the artefacts themselves. That made rebinding the
// wave to advanced authority impossible without hand-editing generated output.
//
// The capture scope — which classes and predicates the projection covers, and
// which packet sections are design input rather than authority observation — is
// tracked at assurance/permutation-closure/authority-capture-scope.json. Every
// authority-derived value in the packet is computed from the captured
// projection, so packet and projection cannot disagree by construction.
//
// Read-only: SELECT queries through the approved read gateway. No mutation.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig } from '../../configuration/semantic-assurance/stardog-connection.mjs';
import { createClient } from '../../provider-bindings/stardog/stardog-read-gateway.mjs';
import { readSemanticAuthorityWitness } from './semantic-authority-gateway.mjs';

const O = 'urn:usf:ontology:';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const SCOPE_PATH = 'assurance/permutation-closure/authority-capture-scope.json';

export class CaptureError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'CaptureError';
    this.code = code;
    this.details = details;
  }
}

const fail = (code, message, details) => {
  throw new CaptureError(code, message, details);
};

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortValue(value[key])]));
  }
  return value;
}

export const canonicalJson = (value) => JSON.stringify(sortValue(value), null, 2);
export const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

export function loadCaptureScope(repositoryRoot) {
  const scope = JSON.parse(readFileSync(join(repositoryRoot, SCOPE_PATH), 'utf8'));
  if (scope.recordKind !== 'USF_PERMUTATION_AUTHORITY_CAPTURE_SCOPE' || scope.schemaVersion !== 1) {
    fail('CAPTURE_SCOPE_INVALID', 'unexpected capture scope record kind or schema version');
  }
  for (const key of ['projectedClassIris', 'projectedPredicateIris']) {
    const values = scope[key];
    if (!Array.isArray(values) || values.length === 0) fail('CAPTURE_SCOPE_REGISTRY_EMPTY', `${key} is empty`);
    const sorted = [...values].sort();
    if (JSON.stringify(values) !== JSON.stringify(sorted) || new Set(values).size !== values.length) {
      fail('CAPTURE_SCOPE_REGISTRY_UNSORTED', `${key} must be unique and canonically sorted`);
    }
  }
  return scope;
}

// The projection records each authority statement as a fixed 6-tuple:
// [subject, predicate, objectKind, objectValue, datatype, language].
function tupleFromBinding(subject, predicate, object) {
  if (object.type === 'uri') return [subject, predicate, 'iri', object.value, null, null];
  return [
    subject,
    predicate,
    'literal',
    object.value,
    object.datatype ?? null,
    object['xml:lang'] ?? object.lang ?? null,
  ];
}

export async function captureProjectionTriples({ scope, select }) {
  const triples = [];
  for (const classIri of scope.projectedClassIris) {
    const rows = await select(`SELECT DISTINCT ?s WHERE { GRAPH ?g { ?s a <${classIri}> } } ORDER BY ?s`);
    for (const row of rows) {
      if (row.s?.type !== 'uri') fail('CAPTURE_NON_IRI_SUBJECT', 'class instance subject is not an IRI', { classIri });
      triples.push([row.s.value, RDF_TYPE, 'iri', classIri, null, null]);
    }
  }
  for (const predicateIri of scope.projectedPredicateIris) {
    if (predicateIri === RDF_TYPE) continue;
    const rows = await select(
      `SELECT DISTINCT ?s ?o WHERE { GRAPH ?g { ?s <${predicateIri}> ?o } } ORDER BY ?s ?o`,
    );
    for (const row of rows) {
      if (row.s?.type !== 'uri') continue;
      triples.push(tupleFromBinding(row.s.value, predicateIri, row.o));
    }
  }
  const keyed = new Map(triples.map((triple) => [JSON.stringify(triple), triple]));
  return [...keyed.keys()].sort().map((key) => keyed.get(key));
}

// Index helpers over the captured tuples. Every packet signal is derived from
// this index so packet and projection can never diverge.
export function indexProjection(triples) {
  const instancesByClass = new Map();
  const valuesBySubjectPredicate = new Map();
  for (const [subject, predicate, kind, value] of triples) {
    if (predicate === RDF_TYPE) {
      if (!instancesByClass.has(value)) instancesByClass.set(value, []);
      instancesByClass.get(value).push(subject);
    }
    const key = `${subject}\u0000${predicate}`;
    if (!valuesBySubjectPredicate.has(key)) valuesBySubjectPredicate.set(key, []);
    valuesBySubjectPredicate.get(key).push({ kind, value });
  }
  return {
    instances: (classIri) => [...(instancesByClass.get(classIri) ?? [])].sort(),
    count: (classIri) => (instancesByClass.get(classIri) ?? []).length,
    values: (subject, predicate) => (valuesBySubjectPredicate.get(`${subject}\u0000${predicate}`) ?? []).map(({ value }) => value),
  };
}

const localName = (iri) => iri.slice(iri.lastIndexOf(':') + 1);

// Unique, canonically sorted tuple list. The projection loader requires both
// properties of every binding array it accepts.
export function canonicalTuples(tuples) {
  const keyed = new Map(tuples.map((tuple) => [JSON.stringify(tuple), tuple]));
  return [...keyed.keys()].sort().map((key) => keyed.get(key));
}

export function derivePacket({ authorityDigest, index, operationClassBindings = [], scope }) {
  // Operation-family classes carry instances through the operation class
  // closure as well as through rdf:type. The packet must count them exactly as
  // the projection index does — union of both — or packet and projection
  // disagree on the same authority.
  const operationInstances = new Map();
  for (const [classIri, instanceIri] of operationClassBindings) {
    if (instanceIri === null) continue;
    if (!operationInstances.has(classIri)) operationInstances.set(classIri, new Set());
    operationInstances.get(classIri).add(instanceIri);
  }
  const unionInstances = (classIri) => {
    const union = new Set(index.instances(classIri));
    for (const instance of operationInstances.get(classIri) ?? []) union.add(instance);
    return [...union].sort();
  };
  const classCount = (name) => unionInstances(`${O}${name}`).length;
  const names = (name) => unionInstances(`${O}${name}`).map(localName).sort();

  const contracts = unionInstances(`${O}SemanticContract`);
  const active = contracts
    .filter((iri) => index.values(iri, `${O}hasActivationState`).includes('urn:usf:contractactivationstate:active'))
    .sort();
  const roles = unionInstances(`${O}Role`);
  const rolesWithGrants = {};
  const rolesEmpty = [];
  for (const role of roles) {
    const granted = index.values(role, `${O}grantsPermission`).map(localName).sort();
    if (granted.length === 0) rolesEmpty.push(localName(role));
    else rolesWithGrants[localName(role)] = granted.length === 1 ? granted[0] : granted;
  }
  const transitions = unionInstances(`${O}Transition`);
  const gatewayOperations = unionInstances(`${O}GatewayOperation`);
  const gatewayFlag = (predicate) => gatewayOperations
    .filter((iri) => index.values(iri, `${O}${predicate}`).includes('true'))
    .map((iri) => index.values(iri, `${O}gatewayOperationIdentifier`)[0] ?? localName(iri))
    .sort();

  return {
    activeIdentities: {
      capabilityCount: classCount('Capability'),
      capabilityIriPattern: 'urn:usf:capability:<canonicalname>',
      contractActivation: {
        active,
        proofBlocked: contracts.length - active.length,
      },
      contractCount: contracts.length,
      contractIriPattern: 'urn:usf:semanticcontract:<canonicalname>',
    },
    authorityDigest,
    controlledDimensions: {
      ...scope.packetDesignInputs.candidateCatalogues,
      environmentClasses: names('EnvironmentClass'),
      environments: names('Environment'),
      permissions: names('Permission'),
      privacyClassifications: names('PrivacyClassification'),
      proofRungs: names('ProofRung'),
      providerModes: names('ProviderMode'),
      roles: names('Role'),
      secretClassifications: names('SecretClassification'),
      tenantBoundaries: names('TenantBoundary'),
    },
    exemplars: scope.packetDesignInputs.exemplars,
    liveSignals: {
      auditEvents: classCount('AuditEvent'),
      capabilities: classCount('Capability'),
      configurationKeys: classCount('ConfigurationKey'),
      contractsActive: active.map(localName),
      contractsProofBlocked: contracts.length - active.length,
      dataModels: classCount('DataModel'),
      environmentClasses: classCount('EnvironmentClass'),
      environments: classCount('Environment'),
      events: classCount('Event'),
      forms: classCount('Form'),
      gatewayCoordinatorOnly: gatewayFlag('coordinatorOnly'),
      gatewayMutating: gatewayFlag('mutatesSemanticAuthority'),
      gatewayOperations: gatewayOperations.length,
      interfaces: classCount('Interface'),
      messages: classCount('Message'),
      operationTypes: { Command: classCount('Command'), Query: classCount('Query') },
      operations: classCount('Command') + classCount('Query'),
      permissions: classCount('Permission'),
      permissionAtoms: classCount('PermissionAtom'),
      ports: classCount('Port'),
      principalKinds: classCount('PrincipalKind'),
      privacyClassifications: classCount('PrivacyClassification'),
      providerModes: classCount('ProviderMode'),
      roles: roles.length,
      rolesEmpty: rolesEmpty.sort(),
      rolesWithGrants,
      routes: classCount('Route'),
      secretClassifications: classCount('SecretClassification'),
      states: classCount('State'),
      tenantBoundaries: classCount('TenantBoundary'),
      tokenClaimConstraints: classCount('TokenClaimConstraint'),
      tokenProfiles: classCount('TokenProfile'),
      transitions: transitions.length,
      transitionsWithOnEvent: transitions.filter((iri) => index.values(iri, `${O}onEvent`).length > 0).length,
      uiSurfaces: classCount('Surface'),
      viewModels: classCount('ViewModel'),
      workflows: classCount('Workflow'),
    },
    packetSchemaVersion: 1,
    predicateMap: scope.packetDesignInputs.predicateMap,
    recordKind: 'USF_PERMUTATION_AUTHORITY_INPUT_PACKET',
    workerRules: scope.packetDesignInputs.workerRules,
  };
}

export function buildProjection({ authorityDigest, basePacketDigest, scope, triples }) {
  return {
    authorityDigest,
    basePacketDigest,
    gatewayOperationCapabilityBindings: [],
    operationClassBindings: [],
    projectedClassIris: scope.projectedClassIris,
    projectedPredicateIris: scope.projectedPredicateIris,
    projectionMethod: 'BOUNDED_USF_MCP_SELECT',
    recordKind: 'USF_PERMUTATION_AUTHORITY_PROJECTION',
    schemaVersion: 1,
    triples,
  };
}

// Bindings the projection loader requires beyond the raw tuple set.
export function deriveBindings({ index, select }) {
  return { index, select };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
    const scope = loadCaptureScope(repositoryRoot);
    const config = loadConfig();
    const client = createClient(config);
    const witness = await readSemanticAuthorityWitness(client);
    const authorityDigest = witness.digest;

    const triples = await captureProjectionTriples({ scope, select: (sparql) => client.select(sparql) });
    const index = indexProjection(triples);

    // Gateway operation -> capability and operation-class closure bindings are
    // queried directly: they express relationships the flat tuple set does not.
    // [capability, gatewayOperation, graph]
    const gatewayRows = await client.select(`SELECT DISTINCT ?capability ?op ?g WHERE { GRAPH ?g {
      ?op a <${O}GatewayOperation> ; <${O}backsCapability> ?capability } }
      ORDER BY ?capability ?op ?g`);
    const gatewayOperationCapabilityBindings = canonicalTuples(
      gatewayRows.map((row) => [row.capability.value, row.op.value, row.g.value]),
    );

    // [operationClass, instance | null] over the rdfs:subClassOf* closure of
    // Operation. A class with no instances is recorded with an explicit null so
    // the closure itself stays visible rather than vanishing.
    const operationClassRows = await client.select(`SELECT DISTINCT ?class WHERE { GRAPH ?g {
      { ?class <http://www.w3.org/2000/01/rdf-schema#subClassOf>* <${O}Operation> }
      UNION { BIND(<${O}Operation> AS ?class) } } } ORDER BY ?class`);
    const operationClassBindings = [];
    for (const row of operationClassRows) {
      const classIri = row.class.value;
      const instanceRows = await client.select(
        `SELECT DISTINCT ?s WHERE { GRAPH ?g { ?s a <${classIri}> } } ORDER BY ?s`,
      );
      if (instanceRows.length === 0) operationClassBindings.push([classIri, null]);
      else for (const instance of instanceRows) operationClassBindings.push([classIri, instance.s.value]);
    }

    const packet = derivePacket({
      authorityDigest,
      index,
      operationClassBindings: canonicalTuples(operationClassBindings),
      scope,
    });
    const packetContent = `${canonicalJson(packet)}\n`;
    const packetDigest = sha256(packetContent);
    const packetPath = join('.work', 'generated', `permutation-authority-packet-${packetDigest.slice(7)}.json`);

    const projection = {
      ...buildProjection({ authorityDigest, basePacketDigest: packetDigest, scope, triples }),
      gatewayOperationCapabilityBindings,
      operationClassBindings: canonicalTuples(operationClassBindings),
    };
    const projectionContent = `${canonicalJson(projection)}\n`;
    const projectionDigest = sha256(projectionContent);
    const projectionPath = join('.work', 'generated', `permutation-authority-projection-${projectionDigest.slice(7)}.json`);

    mkdirSync(dirname(join(repositoryRoot, packetPath)), { recursive: true });
    writeFileSync(join(repositoryRoot, packetPath), packetContent);
    writeFileSync(join(repositoryRoot, projectionPath), projectionContent);
    process.stdout.write(`${JSON.stringify({
      authorityDigest,
      command: 'permutation-authority-projection-capture',
      packetDigest,
      packetPath,
      projectionDigest,
      projectionPath,
      tripleCount: triples.length,
    })}\n`);
  } catch (error) {
    process.stderr.write(`${error.code ?? error.name}: ${error.message}\n`);
    process.exitCode = 1;
  }
}
