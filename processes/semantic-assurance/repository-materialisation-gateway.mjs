import { createHash } from 'node:crypto';
import {
  chmodSync, createReadStream, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync,
  readlinkSync, realpathSync, renameSync, rmdirSync, statSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, relative, resolve, sep } from 'node:path';

import { authorityWitness, validContractRef } from './semantic-bootstrap-packet.mjs';

const CONTRACT = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const ACTIVE = 'urn:usf:contractactivationstate:active';
const ACTIVE_LIFECYCLE = 'urn:usf:semanticlifecyclestate:active';
const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
const ACCEPTED = 'urn:usf:decisionstate:accepted';
const RESOLVED_DECISION = new Set(['explicit', 'unique-accepted']);

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
const MAX_PLAN_BYTES = 65_536;
const MAX_OPERATIONS = 256;
const MAX_PACKET_BYTES = 65_536;
const MAX_PACKET_ITEMS = 256;
const MAX_TRACKED_WRITE_BYTES = 16 * 1024 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ACTIONS = new Set(['create-directory', 'write-file', 'move-path', 'delete-path']);

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
export const stable = (input) => Array.isArray(input)
  ? input.map(stable)
  : input && typeof input === 'object'
    ? Object.fromEntries(Object.keys(input).sort().map((key) => [key, stable(input[key])]))
    : input;
export const jcs = (input) => JSON.stringify(stable(input));
export const digest = (input) => `sha256:${createHash('sha256').update(input).digest('hex')}`;

function bounded(valueToMeasure, maximum, label) {
  const bytes = Buffer.byteLength(jcs(valueToMeasure));
  if (bytes > maximum) throw new Error(`${label} exceeds ${maximum} bytes`);
  return bytes;
}

function safeRelativePath(path, label = 'path') {
  if (typeof path !== 'string' || path.length === 0 || path.length > 512 || path.startsWith('/') || path.includes('\\') || /[\x00-\x1f<>:"|?*]/.test(path)) {
    throw new Error(`${label} is not a portable repository-relative path`);
  }
  const segments = path.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) throw new Error(`${label} contains a prohibited segment`);
  if (segments.some((segment) => /[ .]$/.test(segment) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(segment))) throw new Error(`${label} is not portable across supported filesystems`);
  const skillException = path.startsWith('.claude/skills/usf/') || path.startsWith('.codex/skills/usf/');
  if (!skillException && segments.some((segment) => ['v2', 'legacy', 'old', 'new', 'temp', 'transitional', 'usf'].includes(segment.toLowerCase()))) throw new Error(`${label} contains a forbidden canonical segment`);
  return path;
}

function inside(root, relativePath) {
  const target = resolve(root, safeRelativePath(relativePath));
  const rel = relative(root, target);
  if (!rel || rel.startsWith('..') || rel.split(sep).includes('..')) throw new Error('path escapes repository root');
  return target;
}

function containedBy(root, target) {
  const rel = relative(root, target);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`);
}

function assertNoSymlinkSegments(root, target, label) {
  if (!containedBy(root, target)) throw new Error(`${label} escapes configured root`);
  let cursor = root;
  for (const segment of relative(root, target).split(sep)) {
    cursor = resolve(cursor, segment);
    if (existsSync(cursor) && lstatSync(cursor).isSymbolicLink()) {
      throw new Error(`${label} traverses a symbolic link`);
    }
  }
}

function rethrowWithRollback(primaryError, rollback) {
  const rollbackErrors = [];
  for (const undo of rollback.reverse()) {
    try { undo(); } catch (error) { rollbackErrors.push(error); }
  }
  if (rollbackErrors.length) {
    throw new AggregateError(
      [primaryError, ...rollbackErrors],
      'materialisation failed and rollback was not fully completed',
      { cause: primaryError },
    );
  }
  throw primaryError;
}

async function hashFile(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return `sha256:${hash.digest('hex')}`;
}

function treeEntries(root, base = root) {
  const stat = lstatSync(root);
  if (!stat.isDirectory()) return [{ path: relative(base, root).split(sep).join('/'), type: 'file', digest: digest(readFileSync(root)) }];
  return readdirSync(root, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)).flatMap((entry) => {
    const path = resolve(root, entry.name);
    if (entry.isSymbolicLink()) return [{ path: relative(base, path).split(sep).join('/'), type: 'symlink', target: readlinkSync(path) }];
    if (entry.isDirectory()) return [{ path: `${relative(base, path).split(sep).join('/')}/`, type: 'directory' }, ...treeEntries(path, base)];
    return [{ path: relative(base, path).split(sep).join('/'), type: 'file', digest: digest(readFileSync(path)) }];
  });
}

export function sourceDigest(path) {
  const stat = lstatSync(path);
  return stat.isDirectory() ? digest(jcs(treeEntries(path))) : digest(readFileSync(path));
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
  const [contractRows, roleRows, ruleRows, ruleCountRows] = await Promise.all([
    ctx.client.select(`SELECT ?canonicalName ?lifecycle ?activation ?proof ?proofState ?effectiveDecision ?decision ?decisionState ?authorisedRepository ?authorisedPath WHERE {
      <${contract}> <urn:usf:ontology:canonicalName> ?canonicalName .
      OPTIONAL { <${contract}> <urn:usf:ontology:semanticLifecycleState> ?lifecycle }
      OPTIONAL { <${contract}> <urn:usf:ontology:hasActivationState> ?activation }
      OPTIONAL { <${contract}> <urn:usf:ontology:reliesOnProofResult> ?proof . ?proof <urn:usf:ontology:hasProofResultState> ?proofState . }
      OPTIONAL { <${contract}> <urn:usf:ontology:effectiveRealisationDecision> ?effectiveDecision }
      OPTIONAL {
        ?realisation <urn:usf:ontology:realisesContract> <${contract}> ; <urn:usf:ontology:authorisedByDecision> ?decision .
        ?decision <urn:usf:ontology:decisionForContract> <${contract}> ; <urn:usf:ontology:decisionState> ?decisionState .
        OPTIONAL { ?decision <urn:usf:ontology:authorisesRepository> ?authorisedRepository }
        OPTIONAL { ?decision <urn:usf:ontology:authorisesSourcePath> ?authorisedPath }
      }
    } ORDER BY ?decision ?authorisedRepository ?authorisedPath LIMIT 512`),
    ctx.client.select('SELECT ?role ?canonicalName ?parent ?onDemand WHERE { ?role a <urn:usf:ontology:PathRole> ; <urn:usf:ontology:canonicalName> ?canonicalName ; <urn:usf:ontology:authorisedParentPath> ?parent ; <urn:usf:ontology:materialisesOnDemand> ?onDemand . FILTER NOT EXISTS { ?role <urn:usf:ontology:semanticAdequacyDisposition> ?disposition . FILTER(?disposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) } } ORDER BY ?canonicalName LIMIT 256'),
    ctx.client.select(`SELECT ?family ?familyName ?storage ?pathRole ?format ?namingPattern WHERE { ${MATERIALISATION_RULE_WHERE} } ORDER BY ?familyName ?format LIMIT 512`),
    ctx.client.select(`SELECT (COUNT(*) AS ?count) WHERE { ${MATERIALISATION_RULE_WHERE} }`),
  ]);
  if (contractRows.length === 0) throw new Error('contract does not exist in live authority');
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
  if (canonicalName === null) throw new Error('contract has no canonical name in live authority');
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
    };
    if (existing.state !== state) throw new Error('realisation decision has inconsistent state');
    const repository = value(row, 'authorisedRepository');
    if (repository) existing.authorisedRepositories.add(repository);
    const path = value(row, 'authorisedPath');
    if (path) existing.authorisedPaths.add(path);
    decisions.set(id, existing);
  }
  const acceptedDecisions = [...decisions.values()].filter((decision) => decision.state === ACCEPTED);
  let decisionResolution = 'unresolved';
  let candidateDecision = null;
  if (effectiveDecisionIds.size === 1) {
    candidateDecision = decisions.get([...effectiveDecisionIds][0]) ?? null;
    decisionResolution = candidateDecision?.state === ACCEPTED ? 'explicit' : 'invalid-effective-decision';
  } else if (effectiveDecisionIds.size > 1) {
    decisionResolution = 'multiple-effective-decisions';
  } else if (acceptedDecisions.length === 1) {
    [candidateDecision] = acceptedDecisions;
    decisionResolution = 'unique-accepted';
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
  const repositories = acceptedDecision ? [...acceptedDecision.authorisedRepositories].sort() : [];
  const paths = acceptedDecision ? [...acceptedDecision.authorisedPaths].sort() : [];
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
    authorisedRepositories: repositories,
    authorisedPaths: paths,
    pathRoles: roleRows.map((row) => ({ id: value(row, 'role'), canonicalName: value(row, 'canonicalName'), parent: value(row, 'parent'), onDemand: value(row, 'onDemand') === 'true' })),
    materialisationRuleCount: expectedRuleCount,
    rules: ruleRows.map((row) => ({ family: value(row, 'family'), familyName: value(row, 'familyName'), storageClass: value(row, 'storage'), pathRole: value(row, 'pathRole'), representationFormat: value(row, 'format'), namingPattern: value(row, 'namingPattern') })),
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

function decisionAuthorisesPath(path, authorisedPaths) {
  return authorisedPaths.some((authorised) => authorised === '.' ? !path.includes('/') : path === authorised || path.startsWith(`${authorised}/`));
}

function validateOperation(operation, index, context) {
  const failures = [];
  if (!operation || operation.index !== index) failures.push('operation-index');
  if (!ACTIONS.has(operation?.action)) failures.push('operation-action');
  let path;
  try { path = safeRelativePath(operation?.path); } catch { failures.push('operation-path'); }
  if (path && !decisionAuthorisesPath(path, context.authorisedPaths)) failures.push('operation-decision-path');
  const role = context.pathRoles.find((item) => item.id === operation?.pathRole);
  if (!role) failures.push('operation-path-role');
  if (path && role && role.parent !== '.' && path !== role.parent && !path.startsWith(`${role.parent}/`)) failures.push('operation-unauthorised-parent');
  if (path && role?.parent === '.' && path.includes('/')) failures.push('operation-root-descendant');
  if (operation?.sourceDigest !== undefined && !SHA256.test(operation.sourceDigest)) failures.push('operation-source-digest');
  if (operation?.action === 'move-path') {
    try {
      const sourcePath = safeRelativePath(operation.sourcePath, 'sourcePath');
      if (!decisionAuthorisesPath(sourcePath, context.authorisedPaths)) failures.push('operation-move-source-decision-path');
    } catch { failures.push('operation-move-source'); }
    if (operation?.sourceDigest === undefined) failures.push('operation-source-digest');
  }
  if (operation?.action === 'delete-path' && operation?.sourceDigest === undefined) failures.push('operation-source-digest');
  if (operation?.action === 'write-file') {
    if (!SHA256.test(operation.contentDigest || '')) failures.push('operation-content-digest');
    const authorised = context.rules.find((rule) => rule.family === operation.artefactFamily && rule.representationFormat === operation.representationFormat && rule.pathRole === operation.pathRole);
    if (!authorised) failures.push('operation-write-representation');
    else if (path && !new RegExp(authorised.namingPattern).test(basename(path))) failures.push('operation-filename');
    const inline = typeof operation.content === 'string' && ['utf8', 'base64'].includes(operation.contentEncoding);
    const located = typeof operation.contentLocator === 'string' && /^cas:\/\/sha256\/[0-9a-f]{64}$/.test(operation.contentLocator)
      && operation.contentLocator.slice('cas://sha256/'.length) === operation.contentDigest?.slice(7);
    if (inline === located) failures.push('operation-content');
    if (operation.fileMode !== undefined && !['0644', '0755'].includes(operation.fileMode)) failures.push('operation-file-mode');
    if (inline) {
      const bytes = Buffer.from(operation.content, operation.contentEncoding === 'base64' ? 'base64' : 'utf8');
      if (digest(bytes) !== operation.contentDigest) failures.push('operation-content-mismatch');
    }
  }
  return failures.map((code) => ({ index, code }));
}

// The verdict is accepted from a caller that already read it, so plan creation,
// validation and apply all judge the same authority read. Absent one, it is read
// here rather than assumed.
export async function validateLayoutPlan(ctx, plan, verdict = null) {
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  const resolved = verdict || await realisationVerdict(ctx, { contract: plan?.contract });
  const { context } = resolved;
  const failures = [];
  if (plan?.schemaVersion !== 1) failures.push({ code: 'plan-schema-version' });
  if (plan?.authorityDigest !== context.authorityDigest) failures.push({ code: 'plan-authority-digest' });
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
  else plan.operations.forEach((operation, index) => failures.push(...validateOperation(operation, index, context)));
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
  const plan = { schemaVersion: 1, authorityDigest: context.authorityDigest, contract: context.contract.id, operations: args.operations };
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
  if (ctx.coordinator !== true || !ctx.repositoryRoot) throw new Error('materialisation apply is coordinator-only');
  // Immediately before the first filesystem mutation, prove authority has not
  // moved since the verdict was taken and that the plan still describes it. A
  // verdict is a statement about one authority state; touching the filesystem on
  // the strength of a stale one is the whole hazard.
  const preApply = witnessSummary(await authorityWitness(ctx.client));
  assertWitnessUnchanged(verdict.witness, preApply, 'pre-apply authority check');
  if (plan.authorityDigest !== preApply.digest) {
    throw new Error(`${AUTHORITY_MOVED_CODE}: plan authority ${plan.authorityDigest} does not match live authority ${preApply.digest} at apply time`);
  }
  const root = realpathSync(ctx.repositoryRoot);
  const results = [];
  const rollback = [];
  try {
    for (const operation of plan.operations) {
      const target = inside(root, operation.path);
      assertNoSymlinkSegments(root, target, `materialisation target ${operation.path}`);
      if (operation.action === 'create-directory') {
        const existed = existsSync(target);
        mkdirSync(target, { recursive: true });
        if (!existed) rollback.push(() => { if (existsSync(target)) rmdirSync(target); });
      } else if (operation.action === 'write-file') {
        let bytes;
        if (operation.contentLocator) {
          if (!ctx.casRoot) throw new Error('operator-local CAS root is required for located plan content');
          const casRoot = realpathSync(ctx.casRoot);
          const hex = operation.contentDigest.slice(7);
          const located = resolve(casRoot, 'sha256', hex.slice(0, 2), hex);
          if (!containedBy(casRoot, located) || !existsSync(located)) throw new Error(`plan content not found: ${operation.path}`);
          const locatedStat = lstatSync(located);
          if (locatedStat.isSymbolicLink() || !locatedStat.isFile() || !containedBy(casRoot, realpathSync(located))) {
            throw new Error(`plan content is not a regular CAS object: ${operation.path}`);
          }
          if (locatedStat.size > MAX_TRACKED_WRITE_BYTES) throw new Error(`tracked write exceeds ${MAX_TRACKED_WRITE_BYTES} bytes: ${operation.path}`);
          bytes = readFileSync(located);
          if (digest(bytes) !== operation.contentDigest) throw new Error(`plan content digest mismatch: ${operation.path}`);
        } else {
          bytes = Buffer.from(operation.content, operation.contentEncoding === 'base64' ? 'base64' : 'utf8');
        }
        const existed = existsSync(target);
        const prior = existed ? readFileSync(target) : null;
        const priorMode = existed ? (statSync(target).mode & 0o777) : null;
        const intendedMode = Number.parseInt(operation.fileMode || '0644', 8);
        if (existed && digest(prior) === operation.contentDigest && priorMode === intendedMode) {
          results.push({ index: operation.index, action: operation.action, path: operation.path, state: 'already-applied' });
          continue;
        }
        if (existed && (!operation.sourceDigest || digest(prior) !== operation.sourceDigest)) throw new Error(`write source digest mismatch: ${operation.path}`);
        mkdirSync(dirname(target), { recursive: true });
        const temporary = `${target}.usf-materialise-${process.pid}-${operation.index}`;
        writeFileSync(temporary, bytes, { flag: 'wx' });
        chmodSync(temporary, intendedMode);
        renameSync(temporary, target);
        rollback.push(() => {
          if (prior === null) unlinkSync(target);
          else { writeFileSync(target, prior); chmodSync(target, priorMode); }
        });
      } else if (operation.action === 'move-path') {
        const source = inside(root, operation.sourcePath);
        assertNoSymlinkSegments(root, source, `materialisation source ${operation.sourcePath}`);
        if (!existsSync(source)) {
          if (!existsSync(target) || sourceDigest(target) !== operation.sourceDigest) throw new Error(`move source missing: ${operation.sourcePath}`);
          results.push({ index: operation.index, action: operation.action, path: operation.path, state: 'already-applied' });
          continue;
        }
        if (sourceDigest(source) !== operation.sourceDigest) throw new Error(`move source digest mismatch: ${operation.sourcePath}`);
        if (existsSync(target)) throw new Error(`move collision: ${operation.path}`);
        mkdirSync(dirname(target), { recursive: true });
        renameSync(source, target);
        rollback.push(() => renameSync(target, source));
      } else if (operation.action === 'delete-path') {
        if (!existsSync(target)) {
          results.push({ index: operation.index, action: operation.action, path: operation.path, state: 'already-applied' });
          continue;
        }
        if (sourceDigest(target) !== operation.sourceDigest) throw new Error(`delete source digest mismatch: ${operation.path}`);
        const stat = lstatSync(target);
        const priorType = stat.isDirectory() ? 'directory' : 'file';
        const prior = priorType === 'directory' ? null : readFileSync(target);
        const priorMode = stat.mode & 0o7777;
        if (stat.isDirectory()) rmdirSync(target); else unlinkSync(target);
        rollback.push(() => {
          if (priorType === 'directory') mkdirSync(target, { mode: priorMode });
          else writeFileSync(target, prior, { flag: 'wx', mode: priorMode });
          chmodSync(target, priorMode);
        });
      }
      results.push({ index: operation.index, action: operation.action, path: operation.path, state: 'applied' });
    }
  } catch (error) {
    rethrowWithRollback(error, rollback);
  }
  // After every operation but before reporting success: if authority moved while
  // the filesystem was being changed, the plan was authorised against a state that
  // no longer exists. Run the complete rollback stack and fail closed; rollback
  // errors are preserved through AggregateError by rethrowWithRollback.
  try {
    assertWitnessUnchanged(
      verdict.witness,
      witnessSummary(await authorityWitness(ctx.client)),
      'post-apply authority check',
    );
  } catch (error) {
    rethrowWithRollback(error, rollback);
  }
  return { applied: true, validation, operations: results };
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
  const casRoot = realpathSync(ctx.casRoot);
  const hex = descriptor.digest.slice(7);
  const path = resolve(casRoot, 'sha256', hex.slice(0, 2), hex);
  if (!containedBy(casRoot, path)) throw new Error('CAS path escaped configured root');
  if (!existsSync(path)) return { verified: false, descriptor, code: 'artifact-not-found' };
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || !containedBy(casRoot, realpathSync(path))) {
    return { verified: false, descriptor, code: 'artifact-not-regular-file' };
  }
  const observedDigest = await hashFile(path);
  const verified = stat.isFile() && stat.size === descriptor.byteSize && observedDigest === descriptor.digest;
  return { verified, descriptor, observed: { byteSize: stat.size, digest: observedDigest } };
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
      const validationScopeValue = await validationScope(ctx.client, semantics.contract.id);
      return { semantics, scope: validationScopeValue };
    },
  );
  const context = withAuthority(value.semantics, witness, ctx);
  const scope = value.scope;
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
  const { actionState, actionStateReasons, validation } = verdict;
  const authorised = actionState === ACTION_STATES.proceed;

  const packet = {
    schemaVersion: 2,
    semanticIdentifiers: [context.contract.id, context.contract.proofResult, context.contract.decision, ...validationIds].filter(Boolean),
    authorityDigest: context.authorityDigest,
    contractState: { lifecycle: context.contract.lifecycleState, activation: context.contract.activationState, decision: context.contract.decisionState, proof: context.contract.proofResultState, decisionResolution: context.decisionResolution },
    actionState,
    actionStateReasons,
    objective: args.objective || `Realise and validate ${context.contract.canonicalName} from current semantic authority.`,
    claims: ids(assertions.filter((row) => value(row, 'relation') === 'urn:usf:ontology:asserts')),
    nonclaims: ids(assertions.filter((row) => value(row, 'relation') === 'urn:usf:ontology:disclaims')),
    authorisedActions: authorised ? [...ACTIONS] : [],
    authorisedRepositories: authorised ? context.authorisedRepositories : [],
    authorisedPaths: authorised ? context.authorisedPaths : [],
    authorisedFormats: authorised ? [...new Set(context.rules.map((item) => item.representationFormat))].sort() : [],
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
  const [proofRows, scope] = await Promise.all([
    ctx.client.select(`SELECT ?subject WHERE {
      <${contract}> <urn:usf:ontology:mandatoryProofObligation> ?subject .
      FILTER NOT EXISTS {
        <${contract}> <urn:usf:ontology:reliesOnProofResult> ?result .
        ?result <urn:usf:ontology:proofResultForObligation> ?subject ;
          <urn:usf:ontology:hasProofResultState> <urn:usf:proofresultstate:successful> .
      }
    } ORDER BY ?subject LIMIT 1024`),
    validationScope(ctx.client, contract),
  ]);
  const after = await authorityWitness(ctx.client);
  if (before.digest !== after.digest) throw new Error('live authority changed while building the work plan');

  const verdict = validationVerdict(contract, scope, authorityDigest);
  const all = [
    ...proofRows.map((row) => ({ code: 'missing-successful-proof', subject: value(row, 'subject') })),
    ...verdict.gaps,
  ]
    .map((gap) => ({ type: gap.code, subject: gap.subject, disposition: resolveDisposition(gap.code) }))
    .sort((left, right) => (left.type === right.type ? left.subject.localeCompare(right.subject) : left.type.localeCompare(right.type)));

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
    evaluatedFamilies: ['mandatory-proof-obligation', 'validation-applicability', 'validation-obligation'],
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
export const materialisationInternals = Object.freeze({ assertNoSymlinkSegments, containedBy, rethrowWithRollback });
