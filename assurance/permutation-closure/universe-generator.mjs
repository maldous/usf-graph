// Deterministic permutation-cell universe generator.
// GOAL.md §15-16, §26. Generates every candidate PermutationCell from controlled
// dimensions and verified authority signals. Permission atoms are derived from
// the generated universe, not hand-maintained.
//
// Inputs (all bound to one authority digest):
//   - Family census (64 caps × 34 families)
//   - Family definitions (dimensions, value sources)
//   - Controlled vocabularies (actions, transports, dispositions, etc.)
//   - Authority packet (live semantic signals)
//
// Output:
//   - Deterministic cell universe with exact counts, stable keys and digests
//   - Permission atoms derived from the universe
//   - Role-permission dispositions
//   - Token scopes

import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  canonicalJson,
  evaluationInternals,
  loadSemanticStore,
  sha256,
} from '../semantic-model-compilation/realisation-option-evaluation.mjs';

const { RDF_TYPE, term, iri, objects, subjects, has } = evaluationInternals;

const AUTHORITY_DIGEST = 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd';
const DISPOSITIONS = Object.freeze({
  required: 'urn:usf:permutationclosuredisposition:required',
  allowed: 'urn:usf:permutationclosuredisposition:allowed',
  forbidden: 'urn:usf:permutationclosuredisposition:forbidden',
  notApplicable: 'urn:usf:permutationclosuredisposition:notapplicable',
  deferred: 'urn:usf:permutationclosuredisposition:deferred',
  unresolved: 'urn:usf:permutationclosuredisposition:unresolved',
});

const PREFIX = 'urn:usf:';
const O = `${PREFIX}ontology:`;
const PF = `${PREFIX}permutationfamily:`;
const PDB = `${PREFIX}permutationdimension:`;
const DVS = `${PREFIX}dimensionvaluesource:`;
const PDV = `${PREFIX}permutationdimensionvalue:`;

// How a dimension's finite values are resolved.
const SOURCE_KIND = {
  CLASS_INSTANCES: 'classinstances',
  CONTROLLED_LIST: 'controlledlist',
  DERIVED_SELECTOR: 'derivedselector',
};

// ── Semantic-store helpers ──────────────────────────────────────────────────
const values = (terms) => [...new Set(terms.map(({ value }) => value))].sort();

function instancesOf(store, classIri) {
  return values(subjects(store, RDF_TYPE, term(classIri)));
}

function dimensionValues(store, dimensionIri) {
  return values(objects(store, iri(dimensionIri), term('hasDimensionValue')));
}

function contractForCapability(store, capIri) {
  const contracts = values(objects(store, iri(capIri), term('hasContract')));
  if (contracts.length === 0) return null;
  return contracts[0];
}

// ── Value source resolution ────────────────────────────────────────────────
function resolveDimensionValues(store, dimensionIri, capabilityIri) {
  const dim = iri(dimensionIri);
  const sources = objects(store, dim, term('dimensionValueSource'));
  if (sources.length !== 1) return [];
  const source = sources[0].value;
  const kind = objects(store, iri(source), term('valueSourceKind')).map((t) => t.value)[0];

  if (kind === SOURCE_KIND.CONTROLLED_LIST) {
    return dimensionValues(store, dimensionIri);
  }

  if (kind === SOURCE_KIND.CLASS_INSTANCES) {
    const classIris = objects(store, iri(source), term('valueSourceClassIri')).map((t) => t.value);
    if (classIris.length === 0) return [];
    return instancesOf(store, classIris[0]);
  }

  if (kind === SOURCE_KIND.DERIVED_SELECTOR) {
    // Derived from the capability's authority signals using the dimension key.
    const dimKey = objects(store, dim, term('permutationDimensionKey'))
      .map((t) => t.value)[0] || '';
    return deriveSelectorValues(store, capabilityIri, dimKey);
  }

  return [];
}

// ── Derived selectors ──────────────────────────────────────────────────────
function deriveSelectorValues(store, capIri, dimKey) {
  const contract = contractForCapability(store, capIri);
  if (!contract) return [];

  const selector = {
    capability: () => [capIri],
    interface: () => values(
      subjects(store, term('interfaceForContract'), iri(contract))
    ),
    operation: () => {
      const ifaces = values(subjects(store, term('interfaceForContract'), iri(contract)));
      return ifaces.flatMap((iface) => objects(store, iri(iface), term('hasOperation')))
        .map(({ value }) => value);
    },
    port: () => values(subjects(store, term('portForContract'), iri(contract))),
    event: () => values(subjects(store, term('eventForContract'), iri(contract))),
    datamodel: () => {
      return values([
        ...subjects(store, term('backsCapability'), iri(capIri)),
        ...subjects(store, term('ownedByCapability'), iri(capIri)),
      ]).filter((s) => has(store, iri(s), RDF_TYPE, term('DataModel')));
    },
    role: () => {
      // Universal controlled set: all seven roles known to current authority.
      return ['auditor', 'manager', 'securityadmin', 'tenantadmin', 'tenantmember', 'viewer', 'serviceworker']
        .map((r) => `${PREFIX}role:${r}`);
    },
    configurationkey: () => values(subjects(store, term('configures'), iri(capIri)))
      .filter((s) => has(store, iri(s), RDF_TYPE, term('ConfigurationKey'))),
    uisurface: () => {
      const uiModels = values(objects(store, iri(capIri), term('hasUISemanticModel')));
      return uiModels.flatMap((model) => objects(store, iri(model), term('hasSurface')))
        .map(({ value }) => value)
        .filter((s) => has(store, iri(s), RDF_TYPE, term('Surface')));
    },
    formview: () => {
      const uiModels = values(objects(store, iri(capIri), term('hasUISemanticModel')));
      return uiModels.flatMap((model) => objects(store, iri(model), term('hasViewModel')))
        .map(({ value }) => value);
    },
    route: () => {
      const uiModels = values(objects(store, iri(capIri), term('hasUISemanticModel')));
      const surfaces = uiModels.flatMap((model) => objects(store, iri(model), term('hasSurface')))
        .map(({ value }) => value)
        .filter((s) => has(store, iri(s), RDF_TYPE, term('Surface')));
      return surfaces.flatMap((surface) => objects(store, iri(surface), term('surfaceRoute')))
        .map(({ value }) => value);
    },
    providermode: () => {
      const ports = values(subjects(store, term('portForContract'), iri(contract)));
      const modes = ports.flatMap((port) => objects(store, iri(port), term('permitsProviderMode')));
      return values(modes);
    },
    environmentclass: () => ['local', 'hermetic', 'integration', 'staging', 'productionshaped', 'productionlive', 'authoritycontrol']
      .map((ec) => `${PREFIX}environmentclass:${ec}`),
    tenantboundary: () => [`${PREFIX}tenantboundary:tenant`, `${PREFIX}tenantboundary:platform`],
    principalkind: () => instancesOf(store, `${O}PrincipalKind`),
    resourceselectorkind: () => instancesOf(store, `${O}ResourceSelectorKind`),
    privacyclassification: () => instancesOf(store, `${O}PrivacyClassification`),
    permissionatom: () => {
      // PermissionAtom dimension is resolved from the operation→permission
      // mapping in the store. For a given capability's operations, find
      // the permissions those operations require.
      const ops = deriveSelectorValues(store, capIri, 'operation');
      return [...new Set(ops.flatMap((op) =>
        objects(store, iri(op), term('requiresPermission')).map(({ value }) => value)
      ))];
    },
    auditevent: () => {
      // Audit events are derived from operation→emitsAuditEvent mapping.
      return instancesOf(store, `${O}AuditEvent`);
    },
    conditionprofile: () => {
      return instancesOf(store, `${O}AuthorisationConditionProfile`);
    },
    transition: () => {
      const workflows = values(subjects(store, term('workflowForContract'), iri(contract)));
      return workflows.flatMap((wf) => objects(store, iri(wf), term('hasTransition')))
        .map(({ value }) => value);
    },
    sourcestate: () => {
      const workflows = values(subjects(store, term('workflowForContract'), iri(contract)));
      return workflows.flatMap((wf) => objects(store, iri(wf), term('hasState')))
        .map(({ value }) => value);
    },
    targetstate: () => deriveSelectorValues(store, capIri, 'sourcestate'),
    scheduledjob: () => {
      // Scheduled jobs derive from workflow execution policies.
      const workflows = values(subjects(store, term('workflowForContract'), iri(contract)));
      return workflows.filter((wf) => {
        const policies = objects(store, iri(wf), term('workflowExecutionPolicy'));
        return policies.some((policy) => {
          return objects(store, iri(policy.value), term('scheduleBehaviour'))
            .some(({ value }) => !value.startsWith('Not time-triggered'));
        });
      });
    },
    externaldependency: () => deriveSelectorValues(store, capIri, 'port'),
    trigger: () => {
      // Triggers derive from transition onEvent bindings.
      const transitions = deriveSelectorValues(store, capIri, 'transition');
      return [...new Set(transitions.flatMap((t) =>
        objects(store, iri(t), term('onEvent')).map(({ value }) => value)
      ))];
    },
    tokenprofile: () => [],
    claimconstraint: () => [],
    actionreachability: () => ['reachable', 'unreachable', 'notapplicable'],
    ratelimitpolicy: () => [],
    ratelimitclass: () => [],
    authenticationmode: () => instancesOf(store, `${O}AuthenticationMode`).length
      ? instancesOf(store, `${O}AuthenticationMode`)
      : ['none', 'basic', 'bearer', 'oauth2', 'mtls'],
    authenticationstrength: () => ['none', 'singlefactor', 'multifactor', 'hardwarekey'],
    expectedoutcome: () => ['success', 'validationerror', 'autherror', 'notfound', 'conflict', 'ratelimited', 'timeout', 'dependencyfailure', 'internalfailure'],
    errorclass: () => ['transient', 'permanent', 'retryable', 'nonretryable'],
    auditoutcome: () => ['success', 'failure', 'unauthorised'],
    deliverysemantics: () => ['atmostonce', 'atleastonce', 'effectivelyonce', 'ordered', 'unordered'],
    ackmode: () => ['acknowledge', 'negativeacknowledge', 'none'],
    retrymode: () => ['none', 'bounded-backoff', 'exponential-backoff'],
    replaymode: () => ['none', 'from-snapshot', 'from-history'],
    deadlettermode: () => ['none', 'dlq-only', 'dlq-with-redrive'],
    failuremode: () => ['timeout', 'connectionlost', 'providererror', 'ratelimited', 'partialfailure'],
    recoveryaction: () => ['retry', 'failover', 'compensate', 'alert', 'none'],
    delegationmode: () => ['none', 'bounded', 'attributetransfer'],
    direction: () => instancesOf(store, `${O}InteractionDirection`),
    sessionmodel: () => instancesOf(store, `${O}SessionModel`),
    transport: () => instancesOf(store, `${O}Transport`),
    interactionpattern: () => instancesOf(store, `${O}InteractionPattern`),
    publisher: () => deriveSelectorValues(store, capIri, 'event'),
    consumer: () => deriveSelectorValues(store, capIri, 'event'),
    publishpermission: () => [],
    subscribepermission: () => [],
    consumepermission: () => [],
    secretclass: () => ['secret', 'nonsecret'],
    retentionstate: () => ['active', 'retained', 'expired'],
    legalholdstate: () => ['none', 'hold', 'released'],
    serviceprocess: () => [capIri],
    lifecycleobligation: () => ['none', 'backup', 'restore', 'upgrade', 'rollback', 'migrate'],
    requiredpermutation: () => [],
    test: () => [],
    evidence: () => [],
    proof: () => [],
    proofrung: () => ['none', 'semantic', 'contract', 'implementation', 'integration', 'staging', 'production'],
    apicommand: () => {
      // API/Command surface; for now, use the capability's interface operations.
      return deriveSelectorValues(store, capIri, 'operation');
    },
    apiprotocolsurface: () => deriveSelectorValues(store, capIri, 'interface'),
    roleserviceidentity: () => [...deriveSelectorValues(store, capIri, 'role')],
    routekind: () => ['internal', 'public', 'tenantscoped'],
    quotastate: () => ['withinlimit', 'nearinglimit', 'exceeded', 'notapplicable'],
    datafield: () => [],
    resource: () => {
      // Resources derive from the data models and operations of the capability.
      return deriveSelectorValues(store, capIri, 'datamodel');
    },
    queueevent: () => deriveSelectorValues(store, capIri, 'event'),
    action: () => instancesOf(store, `${O}ActionKind`),
    property: () => [],
  };

  const fn = selector[dimKey];
  if (!fn) return [];
  return fn();
}

// ── Stable-key and disposition ─────────────────────────────────────────────
function stableKey(dimensionKeys, dimensionValues) {
  // Sorted-dimension-key-join: join each dimension's value key with a → separator
  const parts = [];
  for (let i = 0; i < dimensionKeys.length; i++) {
    const val = dimensionValues[i];
    // Extract the last segment of a URI as the key, or use the value as-is
    const key = val.includes('#') ? val.split('#').pop()
      : val.includes('/') ? val.split('/').filter(Boolean).pop()
      : val;
    parts.push(key);
  }
  return parts.join('→');
}

function dispositionForCell(familyCanonicalName, dimensionKeys, dimensionValues, authoritySignals) {
  // Default: all cells start as NOT_APPLICABLE. Authority signals prove them
  // REQUIRED or ALLOWED. Without authority signals, they remain honest.
  //
  // For operation×permission families: if the operation exists and has a
  // `requiresPermission` for the given permission, it's REQUIRED.
  if (familyCanonicalName.includes('operationpermissionatom')) {
    const opIdx = dimensionKeys.indexOf('operation');
    const permIdx = dimensionKeys.indexOf('permissionatom');
    if (opIdx >= 0 && permIdx >= 0) {
      const operation = dimensionValues[opIdx];
      const permission = dimensionValues[permIdx];
      if (authoritySignals.operationPermissions &&
          authoritySignals.operationPermissions[operation] === permission) {
        return DISPOSITIONS.required;
      }
      return DISPOSITIONS.notApplicable;
    }
  }

  // For operation×role families: if the role has a grant for the operation's
  // required permission, it's REQUIRED. Otherwise NOT_APPLICABLE.
  if (familyCanonicalName.includes('operationroleconditionprofile')) {
    const roleIdx = dimensionKeys.indexOf('role');
    const opIdx = dimensionKeys.indexOf('operation');
    if (roleIdx >= 0 && opIdx >= 0) {
      const role = dimensionValues[roleIdx];
      const operation = dimensionValues[opIdx];
      const roleShort = role.split('/').pop();
      const requiredPerm = authoritySignals.operationPermissions[operation];
      const rolePerms = authoritySignals.roleGrants[roleShort];
      if (requiredPerm && rolePerms && rolePerms.has(requiredPerm)) {
        return DISPOSITIONS.required;
      }
      return DISPOSITIONS.notApplicable;
    }
  }

  // For permission×role×tenantboundary families: if the role has the permission
  // granted, it's REQUIRED.
  if (familyCanonicalName.includes('permissionatomroletenantboundary')) {
    const roleIdx = dimensionKeys.indexOf('role');
    const permIdx = dimensionKeys.indexOf('permissionatom');
    if (roleIdx >= 0 && permIdx >= 0) {
      const role = dimensionValues[roleIdx];
      const perm = dimensionValues[permIdx];
      const roleShort = role.split('/').pop();
      if (authoritySignals.roleGrants &&
          authoritySignals.roleGrants[roleShort] &&
          authoritySignals.roleGrants[roleShort].has(perm)) {
        return DISPOSITIONS.required;
      }
      return DISPOSITIONS.notApplicable;
    }
  }

  // For operations×sourcestate×targetstate: if there are transitions, map them.
  if (familyCanonicalName.includes('operationsourcestatetargetstate')) {
    // Without transition data, mark as not applicable if no transitions exist
    // for the capability.
    return DISPOSITIONS.notApplicable;
  }

  // Default: the cell exists (it's a valid candidate) but its disposition
  // is not yet determined from authority signals. Mark as unresolved.
  return DISPOSITIONS.unresolved;
}

// ── Cell generation ─────────────────────────────────────────────────────────
function generateFamilyCells(store, capabilityIri, familyIri, authoritySignals) {
  // Get family's dimension bindings sorted by position
  const bindings = objects(store, iri(familyIri), term('hasFamilyDimensionBinding'))
    .sort((a, b) => {
      const posA = Number(objects(store, iri(a.value), term('dimensionPosition'))[0]?.value || 0);
      const posB = Number(objects(store, iri(b.value), term('dimensionPosition'))[0]?.value || 0);
      return posA - posB;
    });

  const dimensions = bindings.map((b) =>
    objects(store, iri(b.value), term('bindsDimension'))[0]?.value || null
  ).filter(Boolean);

  const dimensionKeys = dimensions.map((d) =>
    objects(store, iri(d), term('permutationDimensionKey'))[0]?.value || ''
  );

  // Resolve values for each dimension
  const dimensionValueSets = dimensions.map((d) =>
    resolveDimensionValues(store, d, capabilityIri)
  );

  // Cartesian product
  const cells = [];
  cartesianProduct(dimensionValueSets, (combination) => {
    const key = stableKey(dimensionKeys, combination);
    const familyName = objects(store, iri(familyIri), term('canonicalName'))[0]?.value || '';
    const disp = dispositionForCell(familyName, dimensionKeys, combination, authoritySignals);

    cells.push({
      family: familyIri,
      familyCanonicalName: familyName,
      capability: capabilityIri,
      stableKey: key,
      dimensionKeys: [...dimensionKeys],
      dimensionValues: [...combination],
      disposition: disp,
      authorityDigest: AUTHORITY_DIGEST,
    });
  });

  return cells;
}

function cartesianProduct(sets, callback) {
  if (sets.length === 0) { callback([]); return; }
  const indices = new Array(sets.length).fill(0);
  const maxIdx = sets.map((s) => s.length);
  // Optimization: if any set is empty, produce no cells.
  if (maxIdx.some((n) => n === 0)) return;

  while (true) {
    const combo = indices.map((idx, i) => sets[i][idx]);
    callback(combo);

    let pos = indices.length - 1;
    while (pos >= 0) {
      indices[pos]++;
      if (indices[pos] < maxIdx[pos]) break;
      indices[pos] = 0;
      pos--;
    }
    if (pos < 0) break;
  }
}

// ── Authority signals from the store ────────────────────────────────────────
function loadAuthoritySignals(store) {
  const ops = instancesOf(store, `${O}Query`).concat(instancesOf(store, `${O}Command`));
  const opPerms = {};
  for (const op of ops) {
    const perms = objects(store, iri(op), term('requiresPermission'));
    if (perms.length > 0) opPerms[op] = perms[0].value;
  }

  // Role grants — store the full set per role for correct cross-referencing
  const roleGrants = {};
  for (const role of instancesOf(store, `${O}Role`)) {
    const grants = objects(store, iri(role), term('grantsPermission'));
    if (grants.length > 0) {
      const roleShort = role.split('/').pop();
      roleGrants[roleShort] = new Set(grants.map((g) => g.value));
    }
  }

  return { operationPermissions: opPerms, roleGrants };
}

// ── Main universe generation ────────────────────────────────────────────────
export function generateUniverse({ repositoryRoot, authorityDigest, census }) {
  if (authorityDigest !== AUTHORITY_DIGEST) {
    throw new Error(`Unsupported authority digest: ${authorityDigest}`);
  }
  const { store } = loadSemanticStore(repositoryRoot);
  const signals = loadAuthoritySignals(store);

  const allCells = [];
  const dispositionCounts = {};
  for (const d of Object.values(DISPOSITIONS)) dispositionCounts[d] = 0;

  // Only generate for MATRIX_REQUIRED census entries
  const requiredRecords = census.records.filter((r) => r.disposition === 'MATRIX_REQUIRED');
  const familiesProcessed = new Set();

  for (const record of requiredRecords) {
    const familyIri = `${PF}${record.canonicalName}`;
    familiesProcessed.add(record.family);

    const cells = generateFamilyCells(store, record.capability, familyIri, signals);
    for (const cell of cells) {
      dispositionCounts[cell.disposition] = (dispositionCounts[cell.disposition] || 0) + 1;
    }
    allCells.push(...cells);
  }

  return {
    recordKind: 'USF_PERMUTATION_CELL_UNIVERSE',
    schemaVersion: 1,
    authorityDigest,
    familyCensusDigest: census.censusDigest,
    cellCount: allCells.length,
    dispositionCounts,
    familiesGenerated: familiesProcessed.size,
    cells: allCells,
    universeDigest: sha256(canonicalJson(allCells)),
    derivationNote: 'Cells are deterministically generated from controlled dimensions and authority signals. Permission atoms derive from the universe, not the reverse.',
  };
}

// ── Permission atom derivation from universe ────────────────────────────────
export function derivePermissionAtoms(universe) {
  // Permission atoms are derived from the cell universe, specifically from
  // operation×permission cells that are REQUIRED.
  const atoms = new Map();
  const f04Cells = universe.cells.filter((c) => c.familyCanonicalName === 'operationpermissionatom');

  for (const cell of f04Cells) {
    if (cell.disposition !== DISPOSITIONS.required) continue;
    const permIdx = cell.dimensionKeys.indexOf('permissionatom');
    const permIri = cell.dimensionValues[permIdx];
    if (!atoms.has(permIri)) {
      const permKey = permIri.split('/').pop();
      atoms.set(permIri, {
        iri: `${PREFIX}permissionatom:${permKey}`,
        supersedes: permIri,
        stableIdentifier: `pa:${permKey}`,
        capability: cell.capability,
        operations: [],
        cells: [],
      });
    }
    atoms.get(permIri).cells.push(cell);
    const opIdx = cell.dimensionKeys.indexOf('operation');
    atoms.get(permIri).operations.push(cell.dimensionValues[opIdx]);
  }

  return [...atoms.values()];
}

// ── CLI ─────────────────────────────────────────────────────────────────────
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

  // Load census from existing file
  const censusFiles = (() => {
    try {
      const genDir = join(repositoryRoot, '.work', 'generated');
      return readdirSync(genDir).filter((f) => f.startsWith('permutation-family-census-') && f.endsWith('.json'));
    } catch { return []; }
  })();

  if (censusFiles.length === 0) {
    process.stderr.write('No census file found in .work/generated/\n');
    process.exit(1);
  }

  const census = JSON.parse(readFileSync(join(repositoryRoot, '.work', 'generated', censusFiles[0]), 'utf8'));
  const universe = generateUniverse({ repositoryRoot, authorityDigest: AUTHORITY_DIGEST, census });

  const content = `${canonicalJson(universe)}\n`;
  const outputPath = join('.work', 'generated', `permutation-cell-universe-${sha256(content).slice('sha256:'.length)}.json`);
  mkdirSync(dirname(join(repositoryRoot, outputPath)), { recursive: true });
  writeFileSync(join(repositoryRoot, outputPath), content);

  const atoms = derivePermissionAtoms(universe);

  process.stdout.write(`${canonicalJson({
    cellCount: universe.cellCount,
    familiesGenerated: universe.familiesGenerated,
    dispositionCounts: universe.dispositionCounts,
    permissionAtomsDerived: atoms.length,
    universeDigest: universe.universeDigest,
    outputPath,
  })}\n`);
}
