import { createHash } from 'node:crypto';
import { createReadStream, existsSync, lstatSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';

import { authorityWitness, validContractRef } from './semantic-bootstrap-packet.mjs';
import {
  PROOF_CURRENTNESS,
  PROOF_CURRENTNESS_CODES,
  proofCurrentnessVerdict,
} from './proof-currentness.mjs';

const CONTRACT = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const ACTIVE = 'urn:usf:contractactivationstate:active';
const ACTIVE_LIFECYCLE = 'urn:usf:semanticlifecyclestate:active';
const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
const ACCEPTED = 'urn:usf:decisionstate:accepted';
const RESOLVED_DECISION = new Set(['explicit', 'unique-accepted']);
const EXPECTED_MATERIALISATION_MODE = new Map([
  ['urn:usf:semanticcontract:repositoryexternalartefactmaterialisation', false],
  ['urn:usf:semanticcontract:compilersemanticenforcement', false],
  ['urn:usf:semanticcontract:providerconfigurationplane', true],
  ['urn:usf:semanticcontract:providerenvironmentclassification', true],
  ['urn:usf:semanticcontract:servicecatalogandproviderintegrationmodel', true],
]);
const EXPECTED_SCOPED_DECISION = new Map([
  ['urn:usf:semanticcontract:providerconfigurationplane', 'urn:usf:realisationdecision:providerconfigurationplanefactoryworkforce'],
  ['urn:usf:semanticcontract:providerenvironmentclassification', 'urn:usf:realisationdecision:providerenvironmentclassificationfactoryworkforce'],
  ['urn:usf:semanticcontract:servicecatalogandproviderintegrationmodel', 'urn:usf:realisationdecision:servicecatalogandproviderintegrationmodelfactoryworkforce'],
]);

// Factory action states. Every factory-consumed conclusion in this module
// resolves to exactly one of these, and absence never selects PROCEED.
export const ACTION_STATES = Object.freeze({
  proceed: 'PROCEED',
  reserved: 'RESERVED_NO_ACTION',
  block: 'BLOCK',
  unresolved: 'UNRESOLVED_FAIL_CLOSED',
});
// Precedence when several dispositions hold at once. An explicit negative
// outranks an unproven one because it is more actionable and equally closed;
// PROCEED is only ever reached when nothing else applies.
const ACTION_STATE_PRECEDENCE = [ACTION_STATES.block, ACTION_STATES.unresolved, ACTION_STATES.reserved, ACTION_STATES.proceed];

const APPLICABILITY = Object.freeze({
  required: 'urn:usf:validationapplicabilitystate:required',
  notRequired: 'urn:usf:validationapplicabilitystate:notrequired',
  conditional: 'urn:usf:validationapplicabilitystate:conditional',
  reserved: 'urn:usf:validationapplicabilitystate:reserved',
  unresolved: 'urn:usf:validationapplicabilitystate:unresolved',
});
const ACTIVATION = Object.freeze({
  reserved: 'urn:usf:validationactivationstate:reserved',
  activated: 'urn:usf:validationactivationstate:activated',
  blocked: 'urn:usf:validationactivationstate:blocked',
});

// One gap code -> one factory disposition. A code with no entry here is a
// programming error, not a silent PROCEED: resolveDisposition throws.
export const GAP_DISPOSITIONS = Object.freeze({
  'missing-successful-proof': ACTION_STATES.block,
  // Proof currentness. A successful historical result is not a current one, so
  // every way the currentness conclusion can fall short has its own disposition
  // and none of them reaches PROCEED.
  [PROOF_CURRENTNESS_CODES.currentnessUnresolved]: ACTION_STATES.unresolved,
  [PROOF_CURRENTNESS_CODES.currentnessAmbiguous]: ACTION_STATES.unresolved,
  [PROOF_CURRENTNESS_CODES.evidenceStale]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.evidenceInvalid]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.authorityBindingStale]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.implementationDigestStale]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.dependencyDigestStale]: ACTION_STATES.block,
  [PROOF_CURRENTNESS_CODES.algorithmDigestStale]: ACTION_STATES.block,
  'missing-current-passing-validation': ACTION_STATES.block,
  'validation-obligation-blocked': ACTION_STATES.block,
  'validation-satisfaction-not-current': ACTION_STATES.block,
  'validation-exemption-unwarranted': ACTION_STATES.block,
  'validation-obligation-reserved': ACTION_STATES.reserved,
  'validation-applicability-reserved': ACTION_STATES.reserved,
  'validation-applicability-unresolved': ACTION_STATES.unresolved,
  'validation-applicability-conditional-unevaluated': ACTION_STATES.unresolved,
  'validation-obligation-activation-unresolved': ACTION_STATES.unresolved,
});
// Gaps that withhold only the validated claim. A reserved validation obligation
// does not withdraw realisation authority that an accepted decision and a
// successful proof already granted; it withholds any claim of being validated.
const VALIDATION_SCOPED_GAPS = new Set(['validation-obligation-reserved', 'validation-applicability-reserved']);

// Stable authority reads.
//
// A witness read concurrently with the semantic queries proves nothing: the
// queries may observe a different authority state than the witness did. The
// witness must BRACKET the read — one before, one after — and both must agree on
// digest, graph inventory count and triple total. Only then is the conclusion a
// conclusion about one authority state.
export const AUTHORITY_MOVED_CODE = 'materialisation-authority-moved';

function witnessSummary(witness) {
  return Object.freeze({
    digest: `sha256:${witness.digest}`,
    graphCount: witness.inventory.length,
    triples: witness.triples,
    // Carried for the projection; identity is compared on digest, graph count and
    // triple total only, which is what "the same authority state" means here.
    inventory: Object.freeze(witness.inventory.map((record) => Object.freeze({
      graph: record.graph,
      sha256: `sha256:${record.sha256}`,
      triples: record.triples,
    }))),
  });
}

function assertWitnessUnchanged(before, after, phase) {
  if (before.digest === after.digest && before.graphCount === after.graphCount && before.triples === after.triples) return;
  throw new Error(
    `${AUTHORITY_MOVED_CODE}: live authority changed during ${phase} `
    + `(before ${before.digest}/${before.graphCount}g/${before.triples}t, `
    + `after ${after.digest}/${after.graphCount}g/${after.triples}t)`,
  );
}

// Run `read` bracketed by two inventory-derived witnesses and require exact
// equality. Nothing inside `read` may be treated as authoritative unless the
// bracket closes.
export async function stableAuthorityRead(client, phase, read) {
  const before = witnessSummary(await authorityWitness(client));
  const value = await read(before);
  const after = witnessSummary(await authorityWitness(client));
  assertWitnessUnchanged(before, after, phase);
  return { witness: before, value };
}

function resolveDisposition(code) {
  const disposition = GAP_DISPOSITIONS[code];
  if (!disposition) throw new Error(`work-plan gap code has no declared factory disposition: ${code}`);
  return disposition;
}

function strongestState(states) {
  for (const candidate of ACTION_STATE_PRECEDENCE) if (states.includes(candidate)) return candidate;
  return ACTION_STATES.unresolved;
}
const MAX_PACKET_BYTES = 65_536;
const MAX_PACKET_ITEMS = 256;
const SHA256 = /^sha256:[0-9a-f]{64}$/;

const value = (row, key) => row[key]?.value ?? null;
const MATERIALISATION_RULE_WHERE = `
  ?family a <urn:usf:ontology:ArtefactFamily> ;
          <urn:usf:ontology:canonicalName> ?familyName ;
          <urn:usf:ontology:usesMaterialisationRule> ?rule .
  ?rule <urn:usf:ontology:usesStorageClass> ?storage ;
        <urn:usf:ontology:usesRepresentationFormat> ?format ;
        <urn:usf:ontology:usesNamingRule> ?naming .
  ?naming <urn:usf:ontology:filenamePattern> ?namingPattern .
  OPTIONAL { ?rule <urn:usf:ontology:usesPathRole> ?pathRole }
  FILTER NOT EXISTS { ?family <urn:usf:ontology:semanticAdequacyDisposition> ?familyDisposition . FILTER(?familyDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
  FILTER NOT EXISTS { ?rule <urn:usf:ontology:semanticAdequacyDisposition> ?ruleDisposition . FILTER(?ruleDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
  FILTER NOT EXISTS { ?naming <urn:usf:ontology:semanticAdequacyDisposition> ?namingDisposition . FILTER(?namingDisposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) }
`;
// EVERY mechanical concern is imported, never reimplemented: path normalisation
// and containment, symlink rejection, operation validation, plan
// canonicalisation and digest, CAS lookup and verification, the filesystem
// apply, idempotence, rollback and rollback error aggregation all live once in
// the lower pure capability module. This gateway keeps exclusive ownership of
// the live authority read, the realisation verdict, the complete contract,
// decision and proof conclusions, witness bracketing, coordinator authorisation
// and the production create/validate/dry-run/apply tools.
import {
  MATERIALISATION_ACTIONS,
  MATERIALISATION_BOUNDS,
  PROVIDER_FACTORY_DIRECTORIES,
  PROVIDER_FACTORY_FAMILIES,
  PROVIDER_FACTORY_PATH_SCOPES,
  PROVIDER_FACTORY_REPOSITORY,
  PROVIDER_FACTORY_RULES,
  assertNoSymlinkSegments,
  canonicalJson,
  containedBy,
  executePlanOperations,
  sha256 as planDigestOf,
  sourceDigest as planSourceDigest,
  resolveCasObject,
  rollbackAndThrow as rethrowWithRollback,
  scopedPermissionSetDigest,
  stable as stableInput,
  utf8Compare,
  validatePlanOperation,
} from '../../capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs';

const { MAX_PLAN_BYTES, MAX_OPERATIONS, MAX_TRACKED_WRITE_BYTES } = MATERIALISATION_BOUNDS;
const ACTIONS = new Set(MATERIALISATION_ACTIONS);

export const stable = stableInput;
export const jcs = canonicalJson;
export const digest = planDigestOf;
export const sourceDigest = planSourceDigest;

function bounded(valueToMeasure, maximum, label) {
  const bytes = Buffer.byteLength(jcs(valueToMeasure));
  if (bytes > maximum) throw new Error(`${label} exceeds ${maximum} bytes`);
  return bytes;
}

async function hashFile(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return `sha256:${hash.digest('hex')}`;
}

async function resolveContract(client, reference = CONTRACT) {
  if (!validContractRef(reference)) throw new Error('invalid contract reference');
  if (reference.startsWith('urn:')) return reference;
  const rows = await client.select(`SELECT ?contract WHERE { ?contract a <urn:usf:ontology:SemanticContract> ; <urn:usf:ontology:canonicalName> "${reference}" } LIMIT 2`);
  if (rows.length !== 1) throw new Error('contract reference must resolve exactly once');
  return value(rows[0], 'contract');
}

// The semantic half of the layout read. It performs NO witness read, so a caller
// can bracket it — alone, or together with the validation scope — under one
// stable authority read.
async function readLayoutSemantics(ctx, args = {}) {
  const contract = await resolveContract(ctx.client, args.contract || CONTRACT);
  const [contractRows, decisionCountRows, permissionRows, permissionCountRows, roleRows, ruleRows, ruleCountRows] = await Promise.all([
    ctx.client.select(`SELECT DISTINCT ?canonicalName ?lifecycle ?activation ?proof ?proofState ?decisionScoped ?effectiveDecision ?decision ?decisionState WHERE {
      <${contract}> <urn:usf:ontology:canonicalName> ?canonicalName .
      OPTIONAL { <${contract}> <urn:usf:ontology:semanticLifecycleState> ?lifecycle }
      OPTIONAL { <${contract}> <urn:usf:ontology:hasActivationState> ?activation }
      OPTIONAL { <${contract}> <urn:usf:ontology:reliesOnProofResult> ?proof . ?proof <urn:usf:ontology:hasProofResultState> ?proofState . }
      OPTIONAL { <${contract}> <urn:usf:ontology:decisionScopedMaterialisationRequired> ?decisionScoped }
      OPTIONAL { <${contract}> <urn:usf:ontology:effectiveRealisationDecision> ?effectiveDecision }
      OPTIONAL {
        ?realisation <urn:usf:ontology:realisesContract> <${contract}> ; <urn:usf:ontology:authorisedByDecision> ?decision .
        ?decision <urn:usf:ontology:decisionForContract> <${contract}> ; <urn:usf:ontology:decisionState> ?decisionState .
      }
    } ORDER BY ?decision LIMIT 64`),
    ctx.client.select(`SELECT (COUNT(*) AS ?count) WHERE {
      {
        SELECT DISTINCT ?decision ?decisionState WHERE {
          ?realisation <urn:usf:ontology:realisesContract> <${contract}> ; <urn:usf:ontology:authorisedByDecision> ?decision .
          ?decision <urn:usf:ontology:decisionForContract> <${contract}> ; <urn:usf:ontology:decisionState> ?decisionState .
        }
      }
    }`),
    ctx.client.select(`SELECT DISTINCT ?decision ?permission ?permissionValue WHERE {
      ?realisation <urn:usf:ontology:realisesContract> <${contract}> ; <urn:usf:ontology:authorisedByDecision> ?decision .
      ?decision <urn:usf:ontology:decisionForContract> <${contract}> ;
                <urn:usf:ontology:decisionState> <urn:usf:decisionstate:accepted> ;
                ?permission ?permissionValue .
      VALUES ?permission {
        <urn:usf:ontology:authorisesRepository>
        <urn:usf:ontology:authorisesSourcePath>
        <urn:usf:ontology:authorisesSourceDirectory>
        <urn:usf:ontology:authorisesMaterialisationAction>
        <urn:usf:ontology:authorisesArtefactFamily>
      }
    } ORDER BY ?decision ?permission ?permissionValue LIMIT 512`),
    ctx.client.select(`SELECT (COUNT(*) AS ?count) WHERE {
      {
        SELECT DISTINCT ?decision ?permission ?permissionValue WHERE {
          ?realisation <urn:usf:ontology:realisesContract> <${contract}> ; <urn:usf:ontology:authorisedByDecision> ?decision .
          ?decision <urn:usf:ontology:decisionForContract> <${contract}> ;
                    <urn:usf:ontology:decisionState> <urn:usf:decisionstate:accepted> ;
                    ?permission ?permissionValue .
          VALUES ?permission {
            <urn:usf:ontology:authorisesRepository>
            <urn:usf:ontology:authorisesSourcePath>
            <urn:usf:ontology:authorisesSourceDirectory>
            <urn:usf:ontology:authorisesMaterialisationAction>
            <urn:usf:ontology:authorisesArtefactFamily>
          }
        }
      }
    }`),
    ctx.client.select('SELECT ?role ?canonicalName ?parent ?onDemand WHERE { ?role a <urn:usf:ontology:PathRole> ; <urn:usf:ontology:canonicalName> ?canonicalName ; <urn:usf:ontology:authorisedParentPath> ?parent ; <urn:usf:ontology:materialisesOnDemand> ?onDemand . FILTER NOT EXISTS { ?role <urn:usf:ontology:semanticAdequacyDisposition> ?disposition . FILTER(?disposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) } } ORDER BY ?canonicalName LIMIT 256'),
    ctx.client.select(`SELECT ?family ?familyName ?rule ?storage ?pathRole ?format ?canonicalExtension ?naming ?namingPattern WHERE { ${MATERIALISATION_RULE_WHERE} OPTIONAL { ?format <urn:usf:ontology:canonicalExtension> ?canonicalExtension } } ORDER BY ?familyName ?format LIMIT 512`),
    ctx.client.select(`SELECT (COUNT(*) AS ?count) WHERE { ${MATERIALISATION_RULE_WHERE} }`),
  ]);
  if (contractRows.length === 0) throw new Error('contract does not exist in live authority');
  const projectedDecisionCount = new Set(contractRows.map((row) => value(row, 'decision')).filter(Boolean)).size;
  const expectedDecisionCount = Number(value(decisionCountRows[0], 'count'));
  if (decisionCountRows.length !== 1
    || !Number.isSafeInteger(expectedDecisionCount)
    || expectedDecisionCount !== projectedDecisionCount) {
    throw new Error('materialisation decision projection is incomplete');
  }
  // Every scalar conclusion must resolve exactly once. The rows are a cross
  // product of OPTIONAL patterns, so repetition is expected but disagreement is
  // not: taking the first row would let a contradictory second row hide behind a
  // favourable one.
  const sole = (key, label) => {
    const distinct = [...new Set(contractRows.map((row) => value(row, key)).filter((item) => item !== null))];
    if (distinct.length > 1) throw new Error(`contract has ambiguous ${label} in live authority: ${distinct.join(', ')}`);
    return distinct[0] ?? null;
  };
  const canonicalName = sole('canonicalName', 'canonical name');
  const lifecycleState = sole('lifecycle', 'semantic lifecycle state');
  const activationState = sole('activation', 'activation state');
  const proofResult = sole('proof', 'proof result');
  const proofResultState = sole('proofState', 'proof result state');
  const decisionScopedValues = [...new Set(contractRows.map((row) => value(row, 'decisionScoped')).filter((item) => item !== null))];
  if (decisionScopedValues.length > 1) throw new Error('contract has ambiguous decision-scoped materialisation requirement');
  const decisionScopedMaterialisationRequired = decisionScopedValues.length === 0 ? null : (() => {
    const [lexical] = decisionScopedValues;
    if (lexical === 'true' || lexical === '1') return true;
    if (lexical === 'false' || lexical === '0') return false;
    throw new Error(`contract has invalid decision-scoped materialisation boolean: ${lexical}`);
  })();
  const expectedMaterialisationMode = EXPECTED_MATERIALISATION_MODE.get(contract);
  if (expectedMaterialisationMode !== undefined
    && decisionScopedMaterialisationRequired !== expectedMaterialisationMode) {
    throw new Error('contract decision-scoped materialisation mode differs from its authority-declared gateway mode');
  }
  if (expectedMaterialisationMode === undefined && decisionScopedMaterialisationRequired === true) {
    throw new Error('contract is not an authority-declared decision-scoped materialisation gateway contract');
  }
  if (canonicalName === null) throw new Error('contract has no canonical name in live authority');
  const expectedPermissionCount = Number(value(permissionCountRows[0], 'count'));
  if (permissionCountRows.length !== 1
    || !Number.isSafeInteger(expectedPermissionCount)
    || expectedPermissionCount !== permissionRows.length) {
    throw new Error('materialisation permission projection is incomplete');
  }
  const expectedRuleCount = Number(value(ruleCountRows[0], 'count'));
  if (ruleCountRows.length !== 1 || !Number.isSafeInteger(expectedRuleCount) || expectedRuleCount !== ruleRows.length) {
    throw new Error('materialisation rule projection is incomplete');
  }
  const decisions = new Map();
  const effectiveDecisionIds = new Set();
  for (const row of contractRows) {
    const effectiveDecision = value(row, 'effectiveDecision');
    if (effectiveDecision) effectiveDecisionIds.add(effectiveDecision);
    const id = value(row, 'decision');
    if (!id) continue;
    const state = value(row, 'decisionState');
    const existing = decisions.get(id) || {
      id,
      state,
      authorisedRepositories: new Set(),
      authorisedPaths: new Set(),
      authorisedDirectories: new Set(),
      authorisedActions: new Set(),
      authorisedFamilies: new Set(),
    };
    if (existing.state !== state) throw new Error('realisation decision has inconsistent state');
    decisions.set(id, existing);
  }
  const permissionPredicates = Object.freeze({
    'urn:usf:ontology:authorisesRepository': 'authorisedRepositories',
    'urn:usf:ontology:authorisesSourcePath': 'authorisedPaths',
    'urn:usf:ontology:authorisesSourceDirectory': 'authorisedDirectories',
    'urn:usf:ontology:authorisesMaterialisationAction': 'authorisedActions',
    'urn:usf:ontology:authorisesArtefactFamily': 'authorisedFamilies',
  });
  for (const row of permissionRows) {
    const id = value(row, 'decision');
    const target = permissionPredicates[value(row, 'permission')];
    const permissionValue = value(row, 'permissionValue');
    const decision = decisions.get(id);
    if (!decision || !target || !permissionValue) continue;
    decision[target].add(permissionValue);
  }
  const acceptedDecisions = [...decisions.values()].filter((decision) => decision.state === ACCEPTED);
  let decisionResolution = 'unresolved';
  let candidateDecision = null;
  if (effectiveDecisionIds.size === 1) {
    candidateDecision = decisions.get([...effectiveDecisionIds][0]) ?? null;
    decisionResolution = candidateDecision?.state === ACCEPTED ? 'explicit' : 'invalid-effective-decision';
  } else if (effectiveDecisionIds.size > 1) {
    decisionResolution = 'multiple-effective-decisions';
  } else if (!decisionScopedMaterialisationRequired && acceptedDecisions.length === 1) {
    [candidateDecision] = acceptedDecisions;
    decisionResolution = 'unique-accepted';
  } else if (decisionScopedMaterialisationRequired && acceptedDecisions.length > 0) {
    decisionResolution = 'missing-effective-decision';
  } else if (acceptedDecisions.length > 1) {
    decisionResolution = 'missing-effective-decision';
  } else {
    decisionResolution = 'no-accepted-decision';
  }
  if (candidateDecision?.authorisedRepositories.size !== 1) {
    candidateDecision = null;
    if (decisionResolution === 'explicit' || decisionResolution === 'unique-accepted') {
      decisionResolution = 'invalid-authorised-repository';
    }
  }
  const acceptedDecision = candidateDecision?.state === ACCEPTED ? candidateDecision : null;
  if (decisionScopedMaterialisationRequired
    && decisionResolution === 'explicit'
    && acceptedDecision?.id !== EXPECTED_SCOPED_DECISION.get(contract)) {
    throw new Error('decision-scoped materialisation effective decision differs from the authority-selected decision');
  }
  const repositories = acceptedDecision ? [...acceptedDecision.authorisedRepositories].sort() : [];
  const paths = acceptedDecision ? [...acceptedDecision.authorisedPaths].sort(utf8Compare) : [];
  const directories = acceptedDecision ? [...acceptedDecision.authorisedDirectories].sort() : [];
  const actions = acceptedDecision ? [...acceptedDecision.authorisedActions].sort() : [];
  const families = acceptedDecision ? [...acceptedDecision.authorisedFamilies].sort() : [];
  const projectedRules = ruleRows
    .map((row) => ({
      family: value(row, 'family'),
      familyName: value(row, 'familyName'),
      rule: value(row, 'rule'),
      storageClass: value(row, 'storage'),
      pathRole: value(row, 'pathRole'),
      representationFormat: value(row, 'format'),
      canonicalExtension: value(row, 'canonicalExtension'),
      namingRule: value(row, 'naming'),
      namingPattern: value(row, 'namingPattern'),
    }))
    .filter((rule) => !decisionScopedMaterialisationRequired || families.includes(rule.family));
  if (decisionScopedMaterialisationRequired) {
    const expectedPathScope = PROVIDER_FACTORY_PATH_SCOPES[contract];
    if (decisionResolution !== 'explicit') {
      throw new Error('decision-scoped materialisation requires one explicit effective accepted decision');
    }
    if (jcs(repositories) !== jcs([PROVIDER_FACTORY_REPOSITORY])
      || !expectedPathScope
      || paths.length !== expectedPathScope.count
      || digest(jcs(paths)) !== expectedPathScope.digest
      || jcs(directories) !== jcs([...PROVIDER_FACTORY_DIRECTORIES].sort(utf8Compare))
      || actions.length !== 1
      || actions[0] !== 'write-file'
      || jcs(families) !== jcs([...PROVIDER_FACTORY_FAMILIES].sort(utf8Compare))) {
      throw new Error('decision-scoped materialisation permissions are incomplete');
    }
    if (directories.some((directory) => paths.includes(directory))) {
      throw new Error('authorised source directory duplicates an exact authorised source path');
    }
    if (projectedRules.length !== families.length || new Set(projectedRules.map((rule) => rule.family)).size !== families.length) {
      throw new Error('decision-scoped materialisation families do not resolve to one exact rule each');
    }
    if (projectedRules.some((rule) => typeof rule.rule !== 'string'
      || rule.storageClass !== 'urn:usf:storageclass:gittrackedsource'
      || typeof rule.pathRole !== 'string'
      || typeof rule.representationFormat !== 'string'
      || typeof rule.canonicalExtension !== 'string'
      || typeof rule.namingRule !== 'string'
      || typeof rule.namingPattern !== 'string')) {
      throw new Error('decision-scoped materialisation rule is not one exact Git-tracked path/format tuple');
    }
    const comparableRules = projectedRules.map(({
      family, rule, storageClass, pathRole, representationFormat, canonicalExtension, namingRule, namingPattern,
    }) => ({
      family, rule, storageClass, pathRole, representationFormat, canonicalExtension, namingRule, namingPattern,
    })).sort((left, right) => utf8Compare(jcs(left), jcs(right)));
    const expectedRules = [...PROVIDER_FACTORY_RULES]
      .sort((left, right) => utf8Compare(jcs(left), jcs(right)));
    if (jcs(comparableRules) !== jcs(expectedRules)) {
      throw new Error('decision-scoped materialisation rule set differs from the exact authority-selected tuples');
    }
  }
  const authorisedActions = decisionScopedMaterialisationRequired ? actions : [...ACTIONS];
  const permissionAuthority = {
    authorisedRepositories: repositories,
    authorisedPaths: paths,
    authorisedDirectoryPrefixes: directories,
    authorisedActions,
    authorisedFamilies: families,
    rules: projectedRules,
  };
  return {
    schemaVersion: 1,
    contract: {
      id: contract,
      canonicalName,
      lifecycleState,
      activationState,
      proofResult,
      proofResultState,
      decision: acceptedDecision?.id ?? null,
      decisionState: acceptedDecision?.state ?? null,
      authorisedRepository: repositories[0] ?? null,
    },
    realisationDecisionCount: decisions.size,
    acceptedDecisionCount: acceptedDecisions.length,
    effectiveDecisionCount: effectiveDecisionIds.size,
    decisionResolution,
    decisionScopedMaterialisationRequired,
    materialisationGatewayContract: expectedMaterialisationMode !== undefined,
    authorisedRepositories: repositories,
    authorisedPaths: paths,
    authorisedDirectoryPrefixes: directories,
    authorisedActions,
    authorisedFamilies: families,
    authorisedStorageClasses: decisionScopedMaterialisationRequired
      ? [...new Set(projectedRules.map((rule) => rule.storageClass))].sort()
      : [],
    permissionSetDigest: decisionScopedMaterialisationRequired
      ? scopedPermissionSetDigest(permissionAuthority)
      : null,
    pathRoles: roleRows.map((row) => ({ id: value(row, 'role'), canonicalName: value(row, 'canonicalName'), parent: value(row, 'parent'), onDemand: value(row, 'onDemand') === 'true' })),
    materialisationRuleCount: projectedRules.length,
    authorityMaterialisationRuleCount: expectedRuleCount,
    rules: projectedRules,
  };
}

// Public layout context: the semantic read bracketed by two witnesses.
export async function layoutContext(ctx, args = {}) {
  const { witness, value } = await stableAuthorityRead(
    ctx.client,
    'layout context read',
    () => readLayoutSemantics(ctx, args),
  );
  return withAuthority(value, witness, ctx);
}

// Attach the bracketing witness to a semantic read and enforce any configured
// expected digest at the same boundary.
function withAuthority(semantics, witness, ctx) {
  if (ctx.client?.expectedAuthorityDigest && ctx.client.expectedAuthorityDigest !== witness.digest) {
    throw new Error('observed semantic authority digest differs from configured digest');
  }
  return {
    ...semantics,
    authorityDigest: witness.digest,
    authorityGraphCount: witness.graphCount,
    authorityTripleTotal: witness.triples,
    authorityGraphInventory: witness.inventory,
    authorityDigestAlgorithm: 'sha256-rdfc10-graph-inventory-v2',
    authorityWitness: witness,
  };
}

// The verdict is accepted from a caller that already read it, so plan creation,
// validation and apply all judge the same authority read. Absent one, it is read
// here rather than assumed.
export async function validateLayoutPlan(ctx, plan, verdict = null) {
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  const resolved = verdict || await realisationVerdict(ctx, { contract: plan?.contract });
  const { context } = resolved;
  const failures = [];
  if (context.materialisationGatewayContract !== true) failures.push({ code: 'plan-contract-not-materialisable' });
  if (plan?.schemaVersion !== 1) failures.push({ code: 'plan-schema-version' });
  if (plan?.authorityDigest !== context.authorityDigest) failures.push({ code: 'plan-authority-digest' });
  if (context.decisionScopedMaterialisationRequired
    && plan?.permissionSetDigest !== context.permissionSetDigest) failures.push({ code: 'plan-permission-set-digest' });
  if (context.decisionScopedMaterialisationRequired
    && plan?.repositoryIdentity !== context.contract.authorisedRepository) failures.push({ code: 'plan-repository-identity' });
  // One stable code per non-PROCEED realisation state, carrying the verdict's own
  // reasons. Calling this tool directly can no longer bypass the projection.
  if (resolved.actionState !== ACTION_STATES.proceed) {
    failures.push({ code: resolved.stateFailureCode, actionState: resolved.actionState, reasons: resolved.actionStateReasons });
  }
  // Retained specific codes for the conjuncts a reviewer reads directly.
  if (context.contract.lifecycleState !== ACTIVE_LIFECYCLE) failures.push({ code: 'plan-contract-lifecycle-not-active' });
  if (context.contract.activationState !== ACTIVE || context.contract.proofResultState !== SUCCESSFUL) failures.push({ code: 'plan-contract-not-active-proven' });
  if (!context.contract.decision || context.contract.decisionState !== ACCEPTED) {
    failures.push({ code: 'plan-decision-not-uniquely-accepted' });
  }
  if (!Array.isArray(plan?.operations) || plan.operations.length < 1 || plan.operations.length > MAX_OPERATIONS) failures.push({ code: 'plan-operation-bound' });
  else plan.operations.forEach((operation, index) => failures.push(...validatePlanOperation(operation, index, context)));
  const unsigned = { ...plan };
  delete unsigned.planDigest;
  const expectedDigest = digest(jcs(unsigned));
  if (plan?.planDigest !== expectedDigest) failures.push({ code: 'plan-digest' });
  return {
    ok: failures.length === 0,
    authorityDigest: context.authorityDigest,
    realisationActionState: resolved.actionState,
    realisationActionStateReasons: resolved.actionStateReasons,
    validationSatisfied: resolved.validation.validationSatisfied,
    expectedPlanDigest: expectedDigest,
    operationCount: plan?.operations?.length ?? 0,
    failures,
  };
}

export async function createLayoutPlan(ctx, args = {}) {
  if (!Array.isArray(args.operations)) throw new Error('operations must be an array');
  const verdict = await realisationVerdict(ctx, { contract: args.contract || CONTRACT });
  // Refuse before a plan exists. A plan is an authorisation artefact, so it must
  // not be constructible from a contract that does not authorise realisation.
  if (verdict.actionState !== ACTION_STATES.proceed) {
    throw new Error(`${verdict.stateFailureCode}: realisation action state is ${verdict.actionState} (${verdict.actionStateReasons.join(',') || 'no reasons'})`);
  }
  const { context } = verdict;
  if (context.materialisationGatewayContract !== true) {
    throw new Error('contract is not an authority-declared materialisation gateway contract');
  }
  const plan = {
    schemaVersion: 1,
    authorityDigest: context.authorityDigest,
    ...(context.decisionScopedMaterialisationRequired ? { permissionSetDigest: context.permissionSetDigest } : {}),
    ...(context.decisionScopedMaterialisationRequired ? { repositoryIdentity: context.contract.authorisedRepository } : {}),
    contract: context.contract.id,
    operations: args.operations,
  };
  plan.planDigest = digest(jcs(plan));
  const result = await validateLayoutPlan(ctx, plan, verdict);
  if (!result.ok) throw new Error(`invalid materialisation plan: ${result.failures.map((item) => `${item.index ?? '-'}:${item.code}`).join(',')}`);
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  return plan;
}

export async function applyLayoutPlan(ctx, args = {}) {
  const plan = args.plan;
  // Apply judges the same verdict as creation and validation, so a plan minted
  // under PROCEED cannot be applied after the state has moved.
  const verdict = await realisationVerdict(ctx, { contract: plan?.contract });
  const validation = await validateLayoutPlan(ctx, plan, verdict);
  if (!validation.ok) {
    return { applied: false, realisationActionState: verdict.actionState, stateFailureCode: verdict.stateFailureCode, validation };
  }
  if (args.apply !== true) return { applied: false, dryRun: true, validation };
  if (ctx.coordinator !== true) throw new Error('materialisation apply is coordinator-only');
  const expectedRepositoryIdentity = verdict.context.decisionScopedMaterialisationRequired
    ? verdict.context.contract.authorisedRepository
    : null;
  const repositoryRoot = expectedRepositoryIdentity === null
    ? ctx.repositoryRoot
    : ctx.repositoryRoots?.get?.(expectedRepositoryIdentity);
  if (!repositoryRoot) {
    throw new Error('authority-bound repository root is not configured for materialisation apply');
  }
  if (expectedRepositoryIdentity !== null
    && plan.repositoryIdentity !== expectedRepositoryIdentity) {
    throw new Error('materialisation coordinator repository identity does not match the authority-bound repository');
  }
  // Immediately before the first filesystem mutation, prove authority has not
  // moved since the verdict was taken and that the plan still describes it. A
  // verdict is a statement about one authority state; touching the filesystem on
  // the strength of a stale one is the whole hazard.
  const preApply = witnessSummary(await authorityWitness(ctx.client));
  assertWitnessUnchanged(verdict.witness, preApply, 'pre-apply authority check');
  if (plan.authorityDigest !== preApply.digest) {
    throw new Error(`${AUTHORITY_MOVED_CODE}: plan authority ${plan.authorityDigest} does not match live authority ${preApply.digest} at apply time`);
  }
  // The filesystem apply, CAS resolution, idempotence and rollback are the pure
  // module's, not a second copy: this call returns the still-open rollback stack
  // so the post-apply authority check below can undo the complete run through
  // that same implementation.
  const execution = executePlanOperations({
    plan,
    repositoryRoot,
    repositoryIdentity: expectedRepositoryIdentity ?? ctx.repositoryIdentity ?? null,
    expectedRepositoryIdentity,
    casRoot: ctx.casRoot,
  });
  // After every operation but before reporting success: if authority moved while
  // the filesystem was being changed, the plan was authorised against a state that
  // no longer exists. Run the complete rollback stack and fail closed; rollback
  // errors are preserved through AggregateError by the pure module.
  try {
    assertWitnessUnchanged(
      verdict.witness,
      witnessSummary(await authorityWitness(ctx.client)),
      'post-apply authority check',
    );
  } catch (error) {
    execution.rollbackAndThrow(error);
  }
  return {
    applied: true,
    validation,
    repositoryIdentity: expectedRepositoryIdentity,
    operations: execution.operations,
  };
}

export async function describeArtifact(ctx, args = {}) {
  if (!SHA256.test(args.digest || '')) throw new Error('digest must be sha256:<64 lowercase hex>');
  const rows = await ctx.client.select(`SELECT ?id ?family ?format ?mediaType ?byteSize ?locator ?artifactType ?storageClass WHERE {
    ?id a <urn:usf:ontology:ExternalPayloadDescriptor> ; <urn:usf:ontology:descriptorDigest> "${args.digest}" ; <urn:usf:ontology:descriptorArtefactFamily> ?family ; <urn:usf:ontology:descriptorRepresentationFormat> ?format ; <urn:usf:ontology:descriptorMediaType> ?mediaType ; <urn:usf:ontology:descriptorByteSize> ?byteSize ; <urn:usf:ontology:descriptorLocator> ?locator ; <urn:usf:ontology:descriptorArtefactType> ?artifactType ; <urn:usf:ontology:descriptorStorageClass> ?storageClass .
  } LIMIT 2`);
  if (rows.length !== 1) throw new Error('external payload descriptor must resolve exactly once');
  const row = rows[0];
  return { id: value(row, 'id'), digest: args.digest, artefactFamily: value(row, 'family'), representationFormat: value(row, 'format'), mediaType: value(row, 'mediaType'), byteSize: Number(value(row, 'byteSize')), locator: value(row, 'locator'), artifactType: value(row, 'artifactType'), storageClass: value(row, 'storageClass') };
}

export async function verifyArtifact(ctx, args = {}) {
  const descriptor = await describeArtifact(ctx, args);
  if (!ctx.casRoot) throw new Error('operator-local CAS root is not configured');
  // CAS locator layout and its containment, symlink and regular-file checks are
  // the pure module's single implementation, not a second copy here.
  const located = resolveCasObject(ctx.casRoot, descriptor.digest, { label: 'artifact' });
  if (!located.found) {
    if (located.code === 'cas-path-escaped-root') throw new Error('CAS path escaped configured root');
    return { verified: false, descriptor, code: located.code === 'cas-object-not-found' ? 'artifact-not-found' : 'artifact-not-regular-file' };
  }
  const observedDigest = await hashFile(located.path);
  const verified = located.byteSize === descriptor.byteSize && observedDigest === descriptor.digest;
  return { verified, descriptor, observed: { byteSize: located.byteSize, digest: observedDigest } };
}

// Applicability and obligation state for one contract. Every field is either an
// explicit IRI from live authority or null, and null is never read as a
// permission: callers map null onto UNRESOLVED_FAIL_CLOSED.
async function validationScope(client, contract) {
  const [applicabilityRows, obligationRows] = await Promise.all([
    client.select(`SELECT ?state ?reason ?authority ?authorityState ?condition WHERE {
      OPTIONAL { <${contract}> <urn:usf:ontology:hasValidationApplicability> ?state }
      OPTIONAL { <${contract}> <urn:usf:ontology:validationApplicabilityReason> ?reason }
      OPTIONAL { <${contract}> <urn:usf:ontology:validationApplicabilityAuthority> ?authority .
        OPTIONAL { ?authority <urn:usf:ontology:hasProofResultState> ?authorityState } }
      OPTIONAL { <${contract}> <urn:usf:ontology:validationApplicabilityCondition> ?condition }
    } LIMIT 64`),
    client.select(`SELECT ?id ?activation ?satisfaction ?boundObligation ?resultState ?boundAuthority ?boundHead ?invalidation ?superseded WHERE {
      ?id a <urn:usf:ontology:ValidationObligation> ; <urn:usf:ontology:validationForContract> <${contract}> .
      OPTIONAL { ?id <urn:usf:ontology:hasValidationActivationState> ?activation }
      OPTIONAL { ?id <urn:usf:ontology:satisfiedByValidationResult> ?satisfaction .
        OPTIONAL { ?satisfaction <urn:usf:ontology:resultForValidationObligation> ?boundObligation }
        OPTIONAL { ?satisfaction <urn:usf:ontology:resultState> ?resultState }
        OPTIONAL { ?satisfaction <urn:usf:ontology:validationEvaluatedAuthorityDigest> ?boundAuthority }
        OPTIONAL { ?satisfaction <urn:usf:ontology:validationEvaluatedSourceHead> ?boundHead }
        OPTIONAL { ?satisfaction <urn:usf:ontology:hasValidationInvalidationCondition> ?invalidation }
        OPTIONAL { ?satisfaction <urn:usf:ontology:supersededByValidationResult> ?superseded } }
    } ORDER BY ?id LIMIT 256`),
  ]);
  const head = applicabilityRows[0] || {};
  const states = new Set(applicabilityRows.map((row) => value(row, 'state')).filter(Boolean));
  if (states.size > 1) throw new Error('contract declares more than one validation applicability state');
  const obligations = new Map();
  for (const row of obligationRows) {
    const id = value(row, 'id');
    const existing = obligations.get(id) || { id, activation: value(row, 'activation'), satisfactions: [] };
    if (existing.activation !== value(row, 'activation')) throw new Error('validation obligation declares inconsistent activation state');
    const satisfaction = value(row, 'satisfaction');
    if (satisfaction) {
      existing.satisfactions.push({
        result: satisfaction,
        boundObligation: value(row, 'boundObligation'),
        resultState: value(row, 'resultState'),
        boundAuthorityDigest: value(row, 'boundAuthority'),
        boundSourceHead: value(row, 'boundHead'),
        invalidated: value(row, 'invalidation') !== null,
        superseded: value(row, 'superseded') !== null,
      });
    }
    obligations.set(id, existing);
  }
  return {
    applicability: [...states][0] ?? null,
    applicabilityReason: value(head, 'reason'),
    exemptionAuthorityProven: applicabilityRows.some((row) => value(row, 'authority') && value(row, 'authorityState') === SUCCESSFUL),
    conditionCount: new Set(applicabilityRows.map((row) => value(row, 'condition')).filter(Boolean)).size,
    obligations: [...obligations.values()],
  };
}

// A satisfaction survives only while it stays identity-bound to this obligation
// and bound to the exact authority the factory is acting on. Anything less is a
// historical record, not a current conclusion.
function satisfactionCurrent(obligation, authorityDigest) {
  return obligation.satisfactions.some((item) => item.boundObligation === obligation.id
    && item.resultState === 'urn:usf:resultstate:passed'
    && item.boundAuthorityDigest === authorityDigest
    && typeof item.boundSourceHead === 'string' && item.boundSourceHead.length > 0
    && !item.invalidated
    && !item.superseded);
}

// The complete gap set for one contract, as {code, subject} pairs. This is the
// single definition of "outstanding" that both the paged projection and the
// unpaged disposition census use, so a page boundary can never hide a state.
function validationGaps(contract, scope, authorityDigest) {
  const gaps = [];
  const { applicability } = scope;
  if (applicability === null || applicability === APPLICABILITY.unresolved) {
    gaps.push({ code: 'validation-applicability-unresolved', subject: contract });
  }
  if (applicability === APPLICABILITY.conditional) {
    gaps.push({ code: 'validation-applicability-conditional-unevaluated', subject: contract });
  }
  if (applicability === APPLICABILITY.reserved) {
    gaps.push({ code: 'validation-applicability-reserved', subject: contract });
  }
  if (applicability === APPLICABILITY.notRequired && !scope.exemptionAuthorityProven) {
    gaps.push({ code: 'validation-exemption-unwarranted', subject: contract });
  }
  for (const obligation of scope.obligations) {
    if (obligation.activation === null) {
      gaps.push({ code: 'validation-obligation-activation-unresolved', subject: obligation.id });
      continue;
    }
    if (obligation.activation === ACTIVATION.blocked) {
      gaps.push({ code: 'validation-obligation-blocked', subject: obligation.id });
      continue;
    }
    if (obligation.activation === ACTIVATION.reserved) {
      gaps.push({ code: 'validation-obligation-reserved', subject: obligation.id });
      continue;
    }
    if (obligation.activation !== ACTIVATION.activated) {
      gaps.push({ code: 'validation-obligation-activation-unresolved', subject: obligation.id });
      continue;
    }
    if (!satisfactionCurrent(obligation, authorityDigest)) {
      gaps.push({
        code: obligation.satisfactions.length > 0 ? 'validation-satisfaction-not-current' : 'missing-current-passing-validation',
        subject: obligation.id,
      });
    }
  }
  return gaps;
}

// May the factory execute validation for this contract right now? A separate
// question from whether validation is satisfied, and from whether realisation
// is authorised. One property answering all three is what let a reserved
// obligation read as a satisfied one.
function validationActionStateFor(scope) {
  const { applicability, obligations } = scope;
  if (applicability === null
    || applicability === APPLICABILITY.unresolved
    || applicability === APPLICABILITY.conditional) return ACTION_STATES.unresolved;
  // An unproven exemption is an unproven conclusion, not a licence.
  if (applicability === APPLICABILITY.notRequired) {
    return scope.exemptionAuthorityProven ? ACTION_STATES.reserved : ACTION_STATES.unresolved;
  }
  if (applicability === APPLICABILITY.reserved) return ACTION_STATES.reserved;
  if (applicability !== APPLICABILITY.required) return ACTION_STATES.unresolved;
  // required with nothing bound cannot say what to validate.
  if (obligations.length === 0) return ACTION_STATES.unresolved;
  if (obligations.some((item) => !Object.values(ACTIVATION).includes(item.activation))) return ACTION_STATES.unresolved;
  if (obligations.some((item) => item.activation === ACTIVATION.blocked)) return ACTION_STATES.block;
  if (obligations.some((item) => item.activation === ACTIVATION.activated)) return ACTION_STATES.proceed;
  return ACTION_STATES.reserved;
}

function validationVerdict(contract, scope, authorityDigest) {
  const gaps = validationGaps(contract, scope, authorityDigest);
  const dispositions = gaps.map((gap) => resolveDisposition(gap.code));
  const realisationBlocking = gaps.filter((gap) => !VALIDATION_SCOPED_GAPS.has(gap.code));
  const validationActionState = validationActionStateFor(scope);
  return {
    gaps,
    dispositions,
    realisationBlocking,
    // Satisfaction is a positive conclusion: it needs every obligation
    // activated and currently satisfied, never merely "no gap recorded".
    validationSatisfied: scope.applicability === APPLICABILITY.required
      && scope.obligations.length > 0
      && scope.obligations.every((item) => item.activation === ACTIVATION.activated && satisfactionCurrent(item, authorityDigest)),
    validationActionState,
  };
}

// The single authoritative realisation verdict. Every surface that can create,
// validate or apply a materialisation plan consumes this, so a plan tool cannot
// reach a conclusion the projection would refuse. Duplicating the state logic is
// what previously let usf_layout_plan succeed while usf_contract_project said
// BLOCK for the same contract.
//
// One digest-stable authority read: callers pass the verdict on rather than
// re-reading, so a plan cannot be validated against a different authority than
// the one it was created against.
export const REALISATION_STATE_FAILURE_CODES = Object.freeze({
  [ACTION_STATES.block]: 'plan-realisation-blocked',
  [ACTION_STATES.reserved]: 'plan-realisation-reserved',
  [ACTION_STATES.unresolved]: 'plan-realisation-unresolved',
});

export async function realisationVerdict(ctx, args = {}) {
  // One bracket over the COMPLETE semantic read: contract, lifecycle, activation,
  // proof, decision, authorisations, materialisation rules and the whole
  // validation scope. Previously the witness was read concurrently with the
  // contract queries and the validation scope was read afterwards with no closing
  // witness, so a verdict could be assembled across two authority states.
  const { witness, value } = await stableAuthorityRead(
    ctx.client,
    'realisation verdict read',
    async () => {
      const semantics = await readLayoutSemantics(ctx, { contract: args.contract || CONTRACT });
      const [validationScopeValue, mandatoryRows] = await Promise.all([
        validationScope(ctx.client, semantics.contract.id),
        ctx.client.select(`SELECT ?obligation WHERE { <${semantics.contract.id}> <urn:usf:ontology:mandatoryProofObligation> ?obligation } ORDER BY ?obligation LIMIT 64`),
      ]);
      // Currentness is read inside the SAME bracket as the contract and
      // validation state, so the verdict is one conclusion about one authority.
      const currentness = await proofCurrentnessVerdict(ctx.client, semantics.contract.id, {
        // `value` is in the temporal dead zone here: the enclosing
        // stableAuthorityRead destructures a binding of that name. Read the term
        // directly rather than shadowing the accessor.
        mandatoryObligations: mandatoryRows.map((row) => row.obligation?.value).filter(Boolean),
        observedAt: ctx.observedAt ?? null,
      });
      return { semantics, scope: validationScopeValue, currentness };
    },
  );
  const context = withAuthority(value.semantics, witness, ctx);
  const scope = value.scope;
  const currentness = value.currentness;
  const validation = validationVerdict(context.contract.id, scope, context.authorityDigest);

  // Each conjunct is explicit. A null state is unproven, not permission; a wrong
  // state is an explicit negative. Both withhold PROCEED, and they are reported
  // separately so the reason survives.
  const reasons = [];
  const require = (observed, expected, unresolvedCode, blockCode) => {
    if (observed === null) reasons.push({ code: unresolvedCode, state: ACTION_STATES.unresolved });
    else if (observed !== expected) reasons.push({ code: blockCode, state: ACTION_STATES.block });
  };
  require(context.contract.lifecycleState, ACTIVE_LIFECYCLE, 'contract-lifecycle-unresolved', 'contract-lifecycle-not-active');
  require(context.contract.activationState, ACTIVE, 'contract-activation-unresolved', 'contract-not-active');
  require(context.contract.proofResultState, SUCCESSFUL, 'contract-proof-result-unresolved', 'contract-proof-not-successful');
  if (context.contract.proofResult === null) reasons.push({ code: 'contract-proof-result-absent', state: ACTION_STATES.unresolved });
  if (context.decisionScopedMaterialisationRequired === null) {
    reasons.push({ code: 'decision-materialisation-scope-unresolved', state: ACTION_STATES.unresolved });
  }
  // A successful result is necessary and NOT sufficient. PROCEED additionally
  // requires the positive currentness conclusion; anything less contributes its
  // own reasons at their own dispositions.
  if (currentness.state !== PROOF_CURRENTNESS.current) {
    for (const code of currentness.reasons) reasons.push({ code, state: resolveDisposition(code) });
    if (currentness.reasons.length === 0) {
      reasons.push({ code: PROOF_CURRENTNESS_CODES.currentnessUnresolved, state: ACTION_STATES.unresolved });
    }
  }
  if (!RESOLVED_DECISION.has(context.decisionResolution)) {
    const unresolved = context.decisionResolution === 'unresolved' || context.decisionResolution === 'no-accepted-decision';
    reasons.push({ code: `decision-${context.decisionResolution}`, state: unresolved ? ACTION_STATES.unresolved : ACTION_STATES.block });
  } else if (context.contract.decisionState !== ACCEPTED) {
    reasons.push({ code: 'decision-not-accepted', state: ACTION_STATES.block });
  }
  // Validation-scoped gaps (both reserved axes) are excluded here on purpose: a
  // reserved obligation withholds the validated claim, not realisation authority
  // an accepted decision and a successful proof already granted.
  for (const gap of validation.realisationBlocking) reasons.push({ code: gap.code, state: resolveDisposition(gap.code) });

  const actionState = reasons.length === 0 ? ACTION_STATES.proceed : strongestState(reasons.map((item) => item.state));
  return Object.freeze({
    context,
    scope,
    validation,
    currentness,
    actionState,
    actionStateReasons: reasons.map((item) => item.code).sort(),
    stateFailureCode: REALISATION_STATE_FAILURE_CODES[actionState] ?? null,
    // The bracketing witness. Any later read that claims to describe the same
    // authority must still equal this exactly.
    witness,
  });
}

export async function projectContract(ctx, args = {}) {
  const contract = args.contract || CONTRACT;
  const verdict = args.verdict || await realisationVerdict(ctx, { contract });
  const { context, scope } = verdict;
  const [assertions, requirements, obligations] = await Promise.all([
    ctx.client.select(`SELECT ?relation ?id WHERE { <${context.contract.id}> ?relation ?id . FILTER(?relation IN (<urn:usf:ontology:asserts>, <urn:usf:ontology:disclaims>)) } ORDER BY ?relation ?id LIMIT 256`),
    ctx.client.select(`SELECT DISTINCT ?id WHERE { { ?id a <urn:usf:ontology:EvidenceRequirement> ; <urn:usf:ontology:obligationFor> <${context.contract.id}> } UNION { ?obligation <urn:usf:ontology:obligationFor> <${context.contract.id}> ; <urn:usf:ontology:requiresEvidence> ?id . ?id a <urn:usf:ontology:EvidenceRequirement> } } ORDER BY ?id LIMIT 256`),
    ctx.client.select(`SELECT DISTINCT ?id WHERE { ?id a <urn:usf:ontology:ProofObligation> ; <urn:usf:ontology:obligationFor> <${context.contract.id}> } ORDER BY ?id LIMIT 256`),
  ]);
  // The verdict was bracketed; these three projection queries ran after it, so
  // their closing witness must still equal the verdict witness exactly — digest,
  // graph count and triple total, not the digest alone.
  assertWitnessUnchanged(
    verdict.witness,
    witnessSummary(await authorityWitness(ctx.client)),
    'agent task packet projection',
  );
  const ids = (rows) => [...new Set(rows.map((row) => value(row, 'id')).filter(Boolean))].sort();
  const validationIds = scope.obligations.map((item) => item.id).sort();
  // Realisation authority comes from the one shared verdict, so this packet and
  // the plan tools can never disagree about the same contract.
  const { actionState, actionStateReasons, validation, currentness } = verdict;
  const authorised = actionState === ACTION_STATES.proceed;

  const packet = {
    schemaVersion: 2,
    semanticIdentifiers: [context.contract.id, context.contract.proofResult, context.contract.decision, ...validationIds].filter(Boolean),
    authorityDigest: context.authorityDigest,
    contractState: { lifecycle: context.contract.lifecycleState, activation: context.contract.activationState, decision: context.contract.decisionState, proof: context.contract.proofResultState, decisionResolution: context.decisionResolution },
    // Proof currentness is projected explicitly. Neither the graph nor the
    // factory has to infer it from prose or from a successful result state.
    proofCurrentness: {
      proofResult: currentness.facts.proofResult ?? null,
      proofResultState: currentness.facts.proofResultState ?? null,
      state: currentness.state,
      stateIri: currentness.stateIri,
      reasons: currentness.reasons,
      evidence: currentness.facts.evidence ?? [],
      evidenceSetDigest: currentness.facts.evidenceSetDigest ?? null,
      proofAlgorithm: currentness.facts.algorithm ?? null,
      proofAlgorithmSourceDigest: currentness.facts.algorithmSourceDigest ?? null,
      proofAlgorithmVersion: currentness.facts.algorithmVersion ?? null,
      implementationSourceSetDigest: currentness.facts.implementationSourceSetDigest ?? null,
      dependencySetDigest: currentness.facts.dependencySetDigest ?? null,
      authorityBinding: currentness.facts.authorityBinding ?? null,
      authorityBindingRule: currentness.facts.authorityBindingRule ?? null,
      postPublicationReevaluationState: currentness.facts.reevaluationState ?? null,
    },
    actionState,
    actionStateReasons,
    objective: args.objective || `Realise and validate ${context.contract.canonicalName} from current semantic authority.`,
    claims: ids(assertions.filter((row) => value(row, 'relation') === 'urn:usf:ontology:asserts')),
    nonclaims: ids(assertions.filter((row) => value(row, 'relation') === 'urn:usf:ontology:disclaims')),
    authorisedActions: authorised ? context.authorisedActions : [],
    authorisedRepositories: authorised ? context.authorisedRepositories : [],
    authorisedPaths: authorised ? context.authorisedPaths : [],
    authorisedDirectoryPrefixes: authorised && context.decisionScopedMaterialisationRequired
      ? context.authorisedDirectoryPrefixes
      : [],
    authorisedArtefactFamilies: authorised && context.decisionScopedMaterialisationRequired
      ? context.authorisedFamilies
      : [],
    authorisedFormats: authorised ? [...new Set(context.rules.map((item) => item.representationFormat))].sort() : [],
    authorisedStorageClasses: authorised && context.decisionScopedMaterialisationRequired
      ? context.authorisedStorageClasses
      : [],
    permissionSetDigest: authorised && context.decisionScopedMaterialisationRequired
      ? context.permissionSetDigest
      : null,
    acceptanceObligations: [...new Set([...ids(requirements), ...ids(obligations)])].sort(),
    validationApplicability: {
      state: scope.applicability,
      declared: scope.applicability !== null,
      reasonDeclared: typeof scope.applicabilityReason === 'string' && scope.applicabilityReason.length > 0,
      exemptionAuthorityProven: scope.exemptionAuthorityProven,
      conditionCount: scope.conditionCount,
    },
    validationObligations: scope.obligations.map((item) => ({
      id: item.id,
      activation: item.activation,
      satisfactionCurrent: satisfactionCurrent(item, context.authorityDigest),
      recordedSatisfactionCount: item.satisfactions.length,
    })),
    validationActionState: validation.validationActionState,
    validationSatisfied: validation.validationSatisfied,
    validationGaps: validation.gaps.map((gap) => ({ code: gap.code, subject: gap.subject, disposition: resolveDisposition(gap.code) })),
    resultRequirements: ['return changed paths and their digests', 'return every validation result and stable result code', 'return explicit nonclaims and residual risk'],
    stopConditions: [
      'authority digest changed',
      'contract or decision is not active',
      'actionState is not PROCEED',
      'path, format, action, or storage class is not authorised',
      'required evidence is missing, stale, invalid, or unknown',
      'payload digest or signature verification fails',
      'validationSatisfied is false and the task would claim validation',
    ],
    bounds: { maximumSerializedBytes: MAX_PACKET_BYTES, maximumItems: MAX_PACKET_ITEMS },
  };
  const itemCount = Object.values(packet).reduce((count, item) => count + (Array.isArray(item) ? item.length : 1), 0);
  if (itemCount > MAX_PACKET_ITEMS) throw new Error('agent task packet exceeds item bound');
  packet.itemCount = itemCount;
  packet.packetDigest = digest(jcs(packet));
  packet.serializedBytes = 0;
  for (;;) {
    const measured = bounded(packet, MAX_PACKET_BYTES, 'agent task packet');
    if (measured === packet.serializedBytes) break;
    packet.serializedBytes = measured;
  }
  return packet;
}

export async function planWork(ctx, args = {}) {
  const contract = await resolveContract(ctx.client, args.contract || CONTRACT);
  const offset = Number.isInteger(args.offset) && args.offset >= 0 ? args.offset : 0;
  if (offset > 10_000) throw new Error('work-plan offset exceeds bounded maximum');
  const pageSize = 50;
  const before = await authorityWitness(ctx.client);
  const authorityDigest = `sha256:${before.digest}`;
  const [proofRows, scope, mandatoryRows] = await Promise.all([
    ctx.client.select(`SELECT ?subject WHERE {
      <${contract}> <urn:usf:ontology:mandatoryProofObligation> ?subject .
      FILTER NOT EXISTS {
        <${contract}> <urn:usf:ontology:reliesOnProofResult> ?result .
        ?result <urn:usf:ontology:proofResultForObligation> ?subject ;
          <urn:usf:ontology:hasProofResultState> <urn:usf:proofresultstate:successful> .
      }
    } ORDER BY ?subject LIMIT 1024`),
    validationScope(ctx.client, contract),
    ctx.client.select(`SELECT ?obligation WHERE { <${contract}> <urn:usf:ontology:mandatoryProofObligation> ?obligation } ORDER BY ?obligation LIMIT 64`),
  ]);
  // The gap census consumes the same currentness conclusion the realisation
  // verdict does. Checking only hasProofResultState here is what let a stale
  // proof read as no gap at all.
  const currentness = await proofCurrentnessVerdict(ctx.client, contract, {
    mandatoryObligations: mandatoryRows.map((row) => value(row, 'obligation')).filter(Boolean),
    observedAt: ctx.observedAt ?? null,
  });
  const after = await authorityWitness(ctx.client);
  if (before.digest !== after.digest) throw new Error('live authority changed while building the work plan');

  const verdict = validationVerdict(contract, scope, authorityDigest);
  const all = [
    ...proofRows.map((row) => ({ code: 'missing-successful-proof', subject: value(row, 'subject') })),
    ...(currentness.state === PROOF_CURRENTNESS.current
      ? []
      : currentness.reasons.map((code) => ({ code, subject: currentness.facts.proofResult ?? contract }))),
    ...verdict.gaps,
  ]
    .map((gap) => ({ type: gap.code, subject: gap.subject, disposition: resolveDisposition(gap.code) }))
    .sort((left, right) => (left.type === right.type
      ? utf8Compare(left.subject, right.subject)
      : utf8Compare(left.type, right.type)));

  // The census is computed over the whole gap set, never over the page, so
  // paginating the projection cannot drop a blocked or unresolved state.
  const dispositionCounts = Object.fromEntries(ACTION_STATE_PRECEDENCE.map((state) => [state, all.filter((gap) => gap.disposition === state).length]));
  const present = ACTION_STATE_PRECEDENCE.filter((state) => dispositionCounts[state] > 0);
  const actionState = all.length === 0 ? ACTION_STATES.proceed : strongestState(present);
  const page = all.slice(offset, offset + pageSize);
  return {
    schemaVersion: 2,
    authorityDigest,
    contract,
    offset,
    pageSize,
    gapCount: all.length,
    truncated: offset + page.length < all.length,
    nextOffset: offset + page.length < all.length ? offset + page.length : null,
    gaps: page,
    dispositionCounts,
    actionState,
    validationApplicability: scope.applicability,
    validationSatisfied: verdict.validationSatisfied,
    proofCurrentness: { state: currentness.state, stateIri: currentness.stateIri, reasons: currentness.reasons },
    evaluatedFamilies: ['mandatory-proof-obligation', 'proof-currentness', 'validation-applicability', 'validation-obligation'],
    // An empty gap set is a statement about the families listed above at this
    // authority digest. It is never a completion claim, and this projection
    // grants no authority to create, close or schedule anything.
    completionClaim: false,
    issueProjectionAuthority: false,
  };
}

export function refuseLifecycleMutation(operation) {
  throw new Error(`${operation} is coordinator-only and must be realised by editing registered authored semantic source and running the compiler's validated single transaction; MCP never performs direct RDF mutation`);
}

export const materialisationConstants = Object.freeze({ CONTRACT, MAX_PLAN_BYTES, MAX_OPERATIONS, MAX_PACKET_BYTES, MAX_PACKET_ITEMS, MAX_TRACKED_WRITE_BYTES });
// Re-exported from the pure module so the gateway's own tests exercise the one
// shared implementation rather than a gateway-private copy of it.
export const materialisationInternals = Object.freeze({
  assertNoSymlinkSegments,
  containedBy,
  rethrowWithRollback,
});
