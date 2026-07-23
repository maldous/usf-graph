import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, relative, resolve, sep } from 'node:path';

export const MATERIALISATION_CONTRACT = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
export const ACTIVE = 'urn:usf:contractactivationstate:active';
export const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
export const ACCEPTED = 'urn:usf:decisionstate:accepted';

const MAX_OPERATIONS = 256;
const MAX_PLAN_BYTES = 65_536;
const MAX_TRACKED_WRITE_BYTES = 16 * 1024 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ACTIONS = new Set(['create-directory', 'write-file', 'move-path', 'delete-path']);
const FORBIDDEN_SEGMENTS = new Set(['v2', 'legacy', 'migration', 'replacement', 'temporary', 'bootstrap', 'initial-suite', 'reference-kernel', 'executable-suite']);

export const stable = (input) => Array.isArray(input)
  ? input.map(stable)
  : input && typeof input === 'object'
    ? Object.fromEntries(Object.keys(input).sort().map((key) => [key, stable(input[key])]))
    : input;

export const canonicalJson = (input) => JSON.stringify(stable(input));
export const sha256 = (input) => `sha256:${createHash('sha256').update(input).digest('hex')}`;

function bounded(input, maximum, label) {
  const bytes = Buffer.byteLength(canonicalJson(input));
  if (bytes > maximum) throw new Error(`${label} exceeds ${maximum} bytes`);
  return bytes;
}

function safeRelativePath(path, label = 'path') {
  if (typeof path !== 'string' || path.length === 0 || path.length > 512 || path.startsWith('/') || path.includes('\\') || /[\x00-\x1f<>:"|?*]/.test(path)) {
    throw new Error(`${label} is not a portable repository-relative path`);
  }
  const segments = path.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) throw new Error(`${label} contains a prohibited segment`);
  if (segments.some((segment) => /[ .]$/.test(segment) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(segment))) {
    throw new Error(`${label} is not portable across supported filesystems`);
  }
  if (segments.some((segment) => FORBIDDEN_SEGMENTS.has(segment.toLowerCase()) || /^wave(?:-|_)?(?:zero|one|two|three|four|five|six|[0-9]+)$/i.test(segment) || /^usf-[0-9]+$/i.test(segment))) {
    throw new Error(`${label} contains a forbidden durable identity`);
  }
  return path;
}

function containedBy(root, target) {
  const rel = relative(root, target);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`);
}

function inside(root, relativePath) {
  const target = resolve(root, safeRelativePath(relativePath));
  if (!containedBy(root, target)) throw new Error('path escapes repository root');
  return target;
}

export function assertNoSymlinkSegments(root, target, label, filesystem = { existsSync, lstatSync }) {
  if (!containedBy(root, target)) throw new Error(`${label} escapes configured root`);
  let cursor = root;
  for (const segment of relative(root, target).split(sep)) {
    cursor = resolve(cursor, segment);
    if (filesystem.existsSync(cursor) && filesystem.lstatSync(cursor).isSymbolicLink()) throw new Error(`${label} traverses a symbolic link`);
  }
}

function orderedNames(left, right) {
  if (left.name < right.name) return -1;
  if (left.name > right.name) return 1;
  return 0;
}

function treeEntries(root, base = root) {
  const stat = lstatSync(root);
  if (!stat.isDirectory()) return [{ path: relative(base, root).split(sep).join('/'), type: 'file', digest: sha256(readFileSync(root)) }];
  return readdirSync(root, { withFileTypes: true }).sort(orderedNames).flatMap((entry) => {
    const path = resolve(root, entry.name);
    const relativePath = relative(base, path).split(sep).join('/');
    if (entry.isSymbolicLink()) return [{ path: relativePath, type: 'symlink', target: readlinkSync(path) }];
    if (entry.isDirectory()) return [{ path: `${relativePath}/`, type: 'directory' }, ...treeEntries(path, base)];
    return [{ path: relativePath, type: 'file', digest: sha256(readFileSync(path)) }];
  });
}

export function sourceDigest(path) {
  return lstatSync(path).isDirectory() ? sha256(canonicalJson(treeEntries(path))) : sha256(readFileSync(path));
}

function decisionAuthorisesPath(path, authorisedPaths) {
  return authorisedPaths.some((authorised) => authorised === '.' ? !path.includes('/') : path === authorised || path.startsWith(`${authorised}/`));
}

function authorityFailures(authority, contract) {
  const failures = [];
  if (!SHA256.test(authority?.authorityDigest || '')) failures.push({ code: 'authority-digest' });
  if (authority?.contract?.id !== contract) failures.push({ code: 'authority-contract' });
  if (authority?.contract?.activationState !== ACTIVE) failures.push({ code: 'contract-not-active' });
  if (authority?.contract?.proofResultState !== SUCCESSFUL) failures.push({ code: 'contract-not-proven' });
  if (authority?.contract?.decisionState !== ACCEPTED) failures.push({ code: 'decision-not-accepted' });
  if (authority?.acceptedDecisionCount !== 1) failures.push({ code: 'decision-not-unique' });
  if (!Array.isArray(authority?.authorisedPaths)) failures.push({ code: 'authorised-paths' });
  if (!Array.isArray(authority?.pathRoles)) failures.push({ code: 'path-roles' });
  if (!Array.isArray(authority?.rules)) failures.push({ code: 'materialisation-rules' });
  return failures;
}

function operationFailures(operation, index, authority) {
  const failures = [];
  if (!operation || operation.index !== index) failures.push({ index, code: 'operation-index' });
  if (!ACTIONS.has(operation?.action)) failures.push({ index, code: 'operation-action' });
  let path;
  try { path = safeRelativePath(operation?.path); } catch { failures.push({ index, code: 'operation-path' }); }
  if (path && !decisionAuthorisesPath(path, authority.authorisedPaths)) failures.push({ index, code: 'operation-decision-path' });
  const role = authority.pathRoles.find((item) => item.id === operation?.pathRole);
  if (!role) failures.push({ index, code: 'operation-path-role' });
  if (path && role && role.parent !== '.' && path !== role.parent && !path.startsWith(`${role.parent}/`)) failures.push({ index, code: 'operation-unauthorised-parent' });
  if (path && role?.parent === '.' && path.includes('/')) failures.push({ index, code: 'operation-root-descendant' });
  if (operation?.sourceDigest !== undefined && !SHA256.test(operation.sourceDigest)) failures.push({ index, code: 'operation-source-digest' });
  if (operation?.action === 'move-path') {
    let sourcePath;
    try { sourcePath = safeRelativePath(operation.sourcePath, 'sourcePath'); } catch { failures.push({ index, code: 'operation-move-source' }); }
    if (sourcePath && !decisionAuthorisesPath(sourcePath, authority.authorisedPaths)) failures.push({ index, code: 'operation-move-source-decision-path' });
    if (operation?.sourceDigest === undefined) failures.push({ index, code: 'operation-source-digest' });
  }
  if (operation?.action === 'delete-path' && operation?.sourceDigest === undefined) failures.push({ index, code: 'operation-source-digest' });
  if (operation?.action === 'write-file') {
    if (!SHA256.test(operation.contentDigest || '')) failures.push({ index, code: 'operation-content-digest' });
    const rule = authority.rules.find((item) => item.family === operation.artefactFamily && item.representationFormat === operation.representationFormat && item.pathRole === operation.pathRole);
    if (!rule) failures.push({ index, code: 'operation-write-representation' });
    else if (path && !new RegExp(rule.namingPattern).test(basename(path))) failures.push({ index, code: 'operation-filename' });
    const inline = typeof operation.content === 'string' && ['utf8', 'base64'].includes(operation.contentEncoding);
    const located = typeof operation.contentLocator === 'string' && /^cas:\/\/sha256\/[0-9a-f]{64}$/.test(operation.contentLocator)
      && operation.contentLocator.slice('cas://sha256/'.length) === operation.contentDigest?.slice(7);
    if (inline === located) failures.push({ index, code: 'operation-content' });
    if (operation.fileMode !== undefined && !['0644', '0755'].includes(operation.fileMode)) failures.push({ index, code: 'operation-file-mode' });
    if (inline) {
      const bytes = Buffer.from(operation.content, operation.contentEncoding === 'base64' ? 'base64' : 'utf8');
      if (sha256(bytes) !== operation.contentDigest) failures.push({ index, code: 'operation-content-mismatch' });
    }
  }
  return failures;
}

export function validateMaterialisationPlan(authority, plan) {
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  const failures = authorityFailures(authority, plan?.contract);
  if (plan?.schemaVersion !== 1) failures.push({ code: 'plan-schema-version' });
  if (plan?.authorityDigest !== authority?.authorityDigest) failures.push({ code: 'plan-authority-digest' });
  if (!Array.isArray(plan?.operations) || plan.operations.length < 1 || plan.operations.length > MAX_OPERATIONS) failures.push({ code: 'plan-operation-bound' });
  else plan.operations.forEach((operation, index) => failures.push(...operationFailures(operation, index, authority)));
  const unsigned = { ...plan };
  delete unsigned.planDigest;
  const expectedPlanDigest = sha256(canonicalJson(unsigned));
  if (plan?.planDigest !== expectedPlanDigest) failures.push({ code: 'plan-digest' });
  return { ok: failures.length === 0, authorityDigest: authority?.authorityDigest ?? null, expectedPlanDigest, operationCount: plan?.operations?.length ?? 0, failures };
}

export function createMaterialisationPlan(authority, operations, contract = MATERIALISATION_CONTRACT) {
  if (!Array.isArray(operations)) throw new TypeError('operations must be an array');
  const plan = { schemaVersion: 1, authorityDigest: authority?.authorityDigest, contract, operations };
  plan.planDigest = sha256(canonicalJson(plan));
  const validation = validateMaterialisationPlan(authority, plan);
  if (!validation.ok) throw new Error(`invalid materialisation plan: ${validation.failures.map((item) => `${item.index ?? '-'}:${item.code}`).join(',')}`);
  bounded(plan, MAX_PLAN_BYTES, 'materialisation plan');
  return plan;
}

function ensureDirectories(root, target, rollback) {
  const missing = [];
  let cursor = target;
  while (cursor !== root && !existsSync(cursor)) {
    missing.push(cursor);
    cursor = dirname(cursor);
  }
  for (const path of missing.reverse()) {
    mkdirSync(path);
    rollback.push(() => { if (existsSync(path)) rmdirSync(path); });
  }
}

function rollbackAndThrow(error, rollback) {
  const rollbackErrors = [];
  for (const undo of rollback.reverse()) {
    try { undo(); } catch (rollbackError) { rollbackErrors.push(rollbackError); }
  }
  if (rollbackErrors.length) throw new AggregateError([error, ...rollbackErrors], 'materialisation failed and rollback was incomplete', { cause: error });
  throw error;
}

function operationBytes(operation, casRoot) {
  if (!operation.contentLocator) return Buffer.from(operation.content, operation.contentEncoding === 'base64' ? 'base64' : 'utf8');
  if (!casRoot) throw new Error('operator-local CAS root is required for located content');
  const canonicalCasRoot = realpathSync(casRoot);
  const hex = operation.contentDigest.slice(7);
  const located = resolve(canonicalCasRoot, 'sha256', hex.slice(0, 2), hex);
  if (!containedBy(canonicalCasRoot, located) || !existsSync(located)) throw new Error(`plan content not found: ${operation.path}`);
  const stat = lstatSync(located);
  if (stat.isSymbolicLink() || !stat.isFile() || !containedBy(canonicalCasRoot, realpathSync(located))) throw new Error(`plan content is not a regular CAS object: ${operation.path}`);
  if (stat.size > MAX_TRACKED_WRITE_BYTES) throw new Error(`tracked write exceeds ${MAX_TRACKED_WRITE_BYTES} bytes: ${operation.path}`);
  const bytes = readFileSync(located);
  if (sha256(bytes) !== operation.contentDigest) throw new Error(`plan content digest mismatch: ${operation.path}`);
  return bytes;
}

export function materialisePlan({ authority, plan, repositoryRoot, casRoot, apply = false }) {
  const validation = validateMaterialisationPlan(authority, plan);
  if (!validation.ok) return { applied: false, validation };
  if (!apply) return { applied: false, dryRun: true, validation };
  if (!repositoryRoot) throw new Error('repository root is required');
  const root = realpathSync(repositoryRoot);
  const rollback = [];
  const operations = [];
  try {
    for (const operation of plan.operations) {
      const target = inside(root, operation.path);
      assertNoSymlinkSegments(root, target, `materialisation target ${operation.path}`);
      if (operation.action === 'create-directory') {
        const existed = existsSync(target);
        if (!existed) ensureDirectories(root, target, rollback);
        operations.push({ index: operation.index, action: operation.action, path: operation.path, state: existed ? 'already-applied' : 'applied' });
        continue;
      }
      if (operation.action === 'write-file') {
        const bytes = operationBytes(operation, casRoot);
        const existed = existsSync(target);
        const prior = existed ? readFileSync(target) : null;
        const priorMode = existed ? statSync(target).mode & 0o777 : null;
        const intendedMode = Number.parseInt(operation.fileMode || '0644', 8);
        if (existed && sha256(prior) === operation.contentDigest && priorMode === intendedMode) {
          operations.push({ index: operation.index, action: operation.action, path: operation.path, state: 'already-applied' });
          continue;
        }
        if (existed && (!operation.sourceDigest || sha256(prior) !== operation.sourceDigest)) throw new Error(`write source digest mismatch: ${operation.path}`);
        ensureDirectories(root, dirname(target), rollback);
        const temporary = `${target}.materialise-${process.pid}-${operation.index}`;
        writeFileSync(temporary, bytes, { flag: 'wx', mode: intendedMode });
        // Creation modes are filtered through the supervising process umask.
        // The authority-bound plan requires the exact declared mode, so bind it
        // explicitly before the atomic rename rather than inheriting ambient
        // service-manager policy.
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
          operations.push({ index: operation.index, action: operation.action, path: operation.path, state: 'already-applied' });
          continue;
        }
        if (sourceDigest(source) !== operation.sourceDigest) throw new Error(`move source digest mismatch: ${operation.sourcePath}`);
        if (existsSync(target)) throw new Error(`move collision: ${operation.path}`);
        ensureDirectories(root, dirname(target), rollback);
        renameSync(source, target);
        rollback.push(() => renameSync(target, source));
      } else if (operation.action === 'delete-path') {
        if (!existsSync(target)) {
          operations.push({ index: operation.index, action: operation.action, path: operation.path, state: 'already-applied' });
          continue;
        }
        if (sourceDigest(target) !== operation.sourceDigest) throw new Error(`delete source digest mismatch: ${operation.path}`);
        const stat = lstatSync(target);
        const prior = stat.isDirectory() ? null : readFileSync(target);
        const priorMode = stat.mode & 0o7777;
        if (stat.isDirectory()) rmdirSync(target); else unlinkSync(target);
        rollback.push(() => {
          if (prior === null) mkdirSync(target, { mode: priorMode });
          else writeFileSync(target, prior, { flag: 'wx', mode: priorMode });
          chmodSync(target, priorMode);
        });
      }
      operations.push({ index: operation.index, action: operation.action, path: operation.path, state: 'applied' });
    }
  } catch (error) {
    rollbackAndThrow(error, rollback);
  }
  return { applied: true, validation, operations };
}
