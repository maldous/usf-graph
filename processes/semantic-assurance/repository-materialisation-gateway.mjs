import { createHash } from 'node:crypto';
import {
  chmodSync, createReadStream, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync,
  readlinkSync, realpathSync, renameSync, rmdirSync, statSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, relative, resolve, sep } from 'node:path';

import { authorityWitness, validContractRef } from './semantic-bootstrap-packet.mjs';

const CONTRACT = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
const ACTIVE = 'urn:usf:contractactivationstate:active';
const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
const ACCEPTED = 'urn:usf:decisionstate:accepted';
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

export async function layoutContext(ctx, args = {}) {
  const contract = await resolveContract(ctx.client, args.contract || CONTRACT);
  const [witness, contractRows, roleRows, ruleRows, ruleCountRows] = await Promise.all([
    authorityWitness(ctx.client),
    ctx.client.select(`SELECT ?canonicalName ?lifecycle ?activation ?proof ?proofState ?decision ?decisionState ?authorisedPath WHERE {
      <${contract}> <urn:usf:ontology:canonicalName> ?canonicalName .
      OPTIONAL { <${contract}> <urn:usf:ontology:semanticLifecycleState> ?lifecycle }
      OPTIONAL { <${contract}> <urn:usf:ontology:hasActivationState> ?activation }
      OPTIONAL { <${contract}> <urn:usf:ontology:reliesOnProofResult> ?proof . ?proof <urn:usf:ontology:hasProofResultState> ?proofState . }
      OPTIONAL { ?realisation <urn:usf:ontology:realisesContract> <${contract}> ; <urn:usf:ontology:authorisedByDecision> ?decision . ?decision <urn:usf:ontology:decisionState> ?decisionState . OPTIONAL { ?decision <urn:usf:ontology:authorisesSourcePath> ?authorisedPath } }
    } ORDER BY ?authorisedPath LIMIT 256`),
    ctx.client.select('SELECT ?role ?canonicalName ?parent ?onDemand WHERE { ?role a <urn:usf:ontology:PathRole> ; <urn:usf:ontology:canonicalName> ?canonicalName ; <urn:usf:ontology:authorisedParentPath> ?parent ; <urn:usf:ontology:materialisesOnDemand> ?onDemand . FILTER NOT EXISTS { ?role <urn:usf:ontology:semanticAdequacyDisposition> ?disposition . FILTER(?disposition != <urn:usf:semanticadequacydisposition:independentlywarrantedretained>) } } ORDER BY ?canonicalName LIMIT 256'),
    ctx.client.select(`SELECT ?family ?familyName ?storage ?pathRole ?format ?namingPattern WHERE { ${MATERIALISATION_RULE_WHERE} } ORDER BY ?familyName ?format LIMIT 512`),
    ctx.client.select(`SELECT (COUNT(*) AS ?count) WHERE { ${MATERIALISATION_RULE_WHERE} }`),
  ]);
  if (contractRows.length === 0) throw new Error('contract does not exist in live authority');
  const expectedRuleCount = Number(value(ruleCountRows[0], 'count'));
  if (ruleCountRows.length !== 1 || !Number.isSafeInteger(expectedRuleCount) || expectedRuleCount !== ruleRows.length) {
    throw new Error('materialisation rule projection is incomplete');
  }
  const head = contractRows[0];
  const decisions = new Map();
  for (const row of contractRows) {
    const id = value(row, 'decision');
    if (!id) continue;
    const state = value(row, 'decisionState');
    const existing = decisions.get(id) || { id, state, authorisedPaths: new Set() };
    if (existing.state !== state) throw new Error('realisation decision has inconsistent state');
    const path = value(row, 'authorisedPath');
    if (path) existing.authorisedPaths.add(path);
    decisions.set(id, existing);
  }
  const acceptedDecisions = [...decisions.values()].filter((decision) => decision.state === ACCEPTED);
  const acceptedDecision = acceptedDecisions.length === 1 ? acceptedDecisions[0] : null;
  const paths = acceptedDecision ? [...acceptedDecision.authorisedPaths].sort() : [];
  return {
    schemaVersion: 1,
    authorityDigest: `sha256:${witness.digest}`,
    authorityDigestAlgorithm: 'sha256-rdfc10-graph-inventory-v2',
    authorityGraphInventory: witness.inventory.map((record) => ({
      graph: record.graph,
      sha256: `sha256:${record.sha256}`,
      triples: record.triples,
    })),
    contract: {
      id: contract,
      canonicalName: value(head, 'canonicalName'),
      lifecycleState: value(head, 'lifecycle'),
      activationState: value(head, 'activation'),
      proofResult: value(head, 'proof'),
      proofResultState: value(head, 'proofState'),
      decision: acceptedDecision?.id ?? null,
      decisionState: acceptedDecision?.state ?? null,
    },
    realisationDecisionCount: decisions.size,
    acceptedDecisionCount: acceptedDecisions.length,
    authorisedPaths: paths,
    pathRoles: roleRows.map((row) => ({ id: value(row, 'role'), canonicalName: value(row, 'canonicalName'), parent: value(row, 'parent'), onDemand: value(row, 'onDemand') === 'true' })),
    materialisationRuleCount: expectedRuleCount,
    rules: ruleRows.map((row) => ({ family: value(row, 'family'), familyName: value(row, 'familyName'), storageClass: value(row, 'storage'), pathRole: value(row, 'pathRole'), representationFormat: value(row, 'format'), namingPattern: value(row, 'namingPattern') })),
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

export async function validateLayoutPlan(ctx, plan) {
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  const context = await layoutContext(ctx, { contract: plan?.contract });
  const failures = [];
  if (plan?.schemaVersion !== 1) failures.push({ code: 'plan-schema-version' });
  if (plan?.authorityDigest !== context.authorityDigest) failures.push({ code: 'plan-authority-digest' });
  if (context.contract.activationState !== ACTIVE || context.contract.proofResultState !== SUCCESSFUL) failures.push({ code: 'plan-contract-not-active-proven' });
  if (context.acceptedDecisionCount !== 1) failures.push({ code: 'plan-decision-not-uniquely-accepted' });
  if (!Array.isArray(plan?.operations) || plan.operations.length < 1 || plan.operations.length > MAX_OPERATIONS) failures.push({ code: 'plan-operation-bound' });
  else plan.operations.forEach((operation, index) => failures.push(...validateOperation(operation, index, context)));
  const unsigned = { ...plan };
  delete unsigned.planDigest;
  const expectedDigest = digest(jcs(unsigned));
  if (plan?.planDigest !== expectedDigest) failures.push({ code: 'plan-digest' });
  return { ok: failures.length === 0, authorityDigest: context.authorityDigest, expectedPlanDigest: expectedDigest, operationCount: plan?.operations?.length ?? 0, failures };
}

export async function createLayoutPlan(ctx, args = {}) {
  if (!Array.isArray(args.operations)) throw new Error('operations must be an array');
  const context = await layoutContext(ctx, { contract: args.contract || CONTRACT });
  const plan = { schemaVersion: 1, authorityDigest: context.authorityDigest, contract: context.contract.id, operations: args.operations };
  plan.planDigest = digest(jcs(plan));
  const result = await validateLayoutPlan(ctx, plan);
  if (!result.ok) throw new Error(`invalid materialisation plan: ${result.failures.map((item) => `${item.index ?? '-'}:${item.code}`).join(',')}`);
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  return plan;
}

export async function applyLayoutPlan(ctx, args = {}) {
  const plan = args.plan;
  const validation = await validateLayoutPlan(ctx, plan);
  if (!validation.ok) return { applied: false, validation };
  if (args.apply !== true) return { applied: false, dryRun: true, validation };
  if (ctx.coordinator !== true || !ctx.repositoryRoot) throw new Error('materialisation apply is coordinator-only');
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

export async function projectContract(ctx, args = {}) {
  const contract = args.contract || CONTRACT;
  const context = await layoutContext(ctx, { contract });
  const [assertions, requirements, obligations, validations] = await Promise.all([
    ctx.client.select(`SELECT ?relation ?id WHERE { <${context.contract.id}> ?relation ?id . FILTER(?relation IN (<urn:usf:ontology:asserts>, <urn:usf:ontology:disclaims>)) } ORDER BY ?relation ?id LIMIT 256`),
    ctx.client.select(`SELECT DISTINCT ?id WHERE { { ?id a <urn:usf:ontology:EvidenceRequirement> ; <urn:usf:ontology:obligationFor> <${context.contract.id}> } UNION { ?obligation <urn:usf:ontology:obligationFor> <${context.contract.id}> ; <urn:usf:ontology:requiresEvidence> ?id . ?id a <urn:usf:ontology:EvidenceRequirement> } } ORDER BY ?id LIMIT 256`),
    ctx.client.select(`SELECT DISTINCT ?id WHERE { ?id a <urn:usf:ontology:ProofObligation> ; <urn:usf:ontology:obligationFor> <${context.contract.id}> } ORDER BY ?id LIMIT 256`),
    ctx.client.select(`SELECT DISTINCT ?id WHERE { ?id a <urn:usf:ontology:ValidationObligation> ; <urn:usf:ontology:validationForContract> <${context.contract.id}> } ORDER BY ?id LIMIT 256`),
  ]);
  const after = await authorityWitness(ctx.client);
  if (context.authorityDigest !== `sha256:${after.digest}`) throw new Error('live authority changed while building agent task packet');
  const ids = (rows) => [...new Set(rows.map((row) => value(row, 'id')).filter(Boolean))].sort();
  const validationIds = ids(validations);
  const authorised = context.contract.activationState === ACTIVE
    && context.contract.proofResultState === SUCCESSFUL
    && context.acceptedDecisionCount === 1;
  const packet = {
    schemaVersion: 1,
    semanticIdentifiers: [context.contract.id, context.contract.proofResult, context.contract.decision, ...validationIds].filter(Boolean),
    authorityDigest: context.authorityDigest,
    contractState: { lifecycle: context.contract.lifecycleState, activation: context.contract.activationState, decision: context.contract.decisionState, proof: context.contract.proofResultState },
    objective: args.objective || `Realise and validate ${context.contract.canonicalName} from current semantic authority.`,
    claims: ids(assertions.filter((row) => value(row, 'relation') === 'urn:usf:ontology:asserts')),
    nonclaims: ids(assertions.filter((row) => value(row, 'relation') === 'urn:usf:ontology:disclaims')),
    authorisedActions: authorised ? [...ACTIONS] : [],
    authorisedPaths: authorised ? context.authorisedPaths : [],
    authorisedFormats: authorised ? [...new Set(context.rules.map((item) => item.representationFormat))].sort() : [],
    acceptanceObligations: [...new Set([...ids(requirements), ...ids(obligations)])].sort(),
    validationObligations: validationIds,
    resultRequirements: ['return changed paths and their digests', 'return every validation result and stable result code', 'return explicit nonclaims and residual risk'],
    stopConditions: ['authority digest changed', 'contract or decision is not active', 'path, format, action, or storage class is not authorised', 'required evidence is missing, stale, invalid, or unknown', 'payload digest or signature verification fails'],
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
  const rows = await ctx.client.select(`SELECT ?gap ?subject WHERE {
    { <${contract}> <urn:usf:ontology:mandatoryProofObligation> ?subject . FILTER NOT EXISTS { <${contract}> <urn:usf:ontology:reliesOnProofResult> ?result . ?result <urn:usf:ontology:proofResultForObligation> ?subject ; <urn:usf:ontology:hasProofResultState> <urn:usf:proofresultstate:successful> } BIND("missing-successful-proof" AS ?gap) }
    UNION { <${contract}> <urn:usf:ontology:requiredValidation> ?subject .
      FILTER NOT EXISTS {
        ?subject <urn:usf:ontology:semanticLifecycleState> ?validationLifecycle .
        FILTER (?validationLifecycle != <urn:usf:semanticlifecyclestate:active>)
      }
      FILTER NOT EXISTS {
      ?execution <urn:usf:ontology:executesValidation> ?subject ; <urn:usf:ontology:producesValidationResult> ?result .
      ?result <urn:usf:ontology:resultState> <urn:usf:resultstate:passed> ; <urn:usf:ontology:entersEvidenceLifecycleAs> ?evidence .
      ?evidence a <urn:usf:ontology:ValidationEvidence> ;
        <urn:usf:ontology:hasAdmissionState> <urn:usf:evidenceadmissionstate:admitted> ;
        <urn:usf:ontology:hasFreshnessState> <urn:usf:evidencefreshnessstate:fresh> ;
        <urn:usf:ontology:hasIntegrityState> <urn:usf:evidenceintegritystate:valid> ;
        <urn:usf:ontology:withinValidityScope> true ;
        <urn:usf:ontology:applicableToObligation> ?subject .
      } BIND("missing-current-passing-validation" AS ?gap) }
  } ORDER BY ?gap ?subject LIMIT ${pageSize + 1} OFFSET ${offset}`);
  const witness = await authorityWitness(ctx.client);
  const truncated = rows.length > pageSize;
  return {
    schemaVersion: 1,
    authorityDigest: `sha256:${witness.digest}`,
    contract,
    offset,
    pageSize,
    truncated,
    nextOffset: truncated ? offset + pageSize : null,
    gaps: rows.slice(0, pageSize).map((row) => ({ type: value(row, 'gap'), subject: value(row, 'subject') })),
    issueProjectionAuthority: false,
  };
}

export function refuseLifecycleMutation(operation) {
  throw new Error(`${operation} is coordinator-only and must be realised by editing registered authored semantic source and running the compiler's validated single transaction; MCP never performs direct RDF mutation`);
}

export const materialisationConstants = Object.freeze({ CONTRACT, MAX_PLAN_BYTES, MAX_OPERATIONS, MAX_PACKET_BYTES, MAX_PACKET_ITEMS, MAX_TRACKED_WRITE_BYTES });
export const materialisationInternals = Object.freeze({ assertNoSymlinkSegments, containedBy, rethrowWithRollback });
