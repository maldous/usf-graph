import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
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
import { DataFactory } from 'n3';

const { namedNode } = DataFactory;

export const MATERIALISATION_CONTRACT = 'urn:usf:semanticcontract:repositoryexternalartefactmaterialisation';
export const PROVIDER_FACTORY_REPOSITORY = 'maldous/usf-factory';
export const PROVIDER_FACTORY_PATH_SCOPES = Object.freeze({
  'urn:usf:semanticcontract:providerconfigurationplane': Object.freeze({
    count: 102,
    digest: 'sha256:cfb3cc646ac93a523c5b108174114dd943ec46485dbc5fc4a955f3c51e8c11f9',
  }),
  'urn:usf:semanticcontract:providerenvironmentclassification': Object.freeze({
    count: 63,
    digest: 'sha256:13624cf373024e620d1b91a31a8d7539669c7853a72fc9815f3235a768a20d42',
  }),
  'urn:usf:semanticcontract:servicecatalogandproviderintegrationmodel': Object.freeze({
    count: 63,
    digest: 'sha256:13624cf373024e620d1b91a31a8d7539669c7853a72fc9815f3235a768a20d42',
  }),
});
export const PROVIDER_FACTORY_DIRECTORIES = Object.freeze([
  'src/usf_factory/providers',
  'tests/provider_workforce',
]);
export const PROVIDER_FACTORY_FAMILIES = Object.freeze([
  'urn:usf:artefactfamily:factoryconfiguration',
  'urn:usf:artefactfamily:factoryenvironmentexample',
  'urn:usf:artefactfamily:factorymarkdowndocumentation',
  'urn:usf:artefactfamily:factorypythonoperatorrealisation',
  'urn:usf:artefactfamily:factorypythonpackagerealisation',
  'urn:usf:artefactfamily:factorypythontestrealisation',
  'urn:usf:artefactfamily:factoryyamldocumentation',
]);
export const PROVIDER_FACTORY_RULES = Object.freeze([
  {
    rule: 'urn:usf:materialisationrule:factoryconfiguration',
    family: 'urn:usf:artefactfamily:factoryconfiguration',
    storageClass: 'urn:usf:storageclass:gittrackedsource',
    pathRole: 'urn:usf:pathrole:factoryconfigurationsource',
    representationFormat: 'urn:usf:representationformat:yamlconfiguration12',
    canonicalExtension: '.yaml',
    namingRule: 'urn:usf:namingrule:factoryyamlconfiguration',
    namingPattern: '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*[.]yaml$',
  },
  {
    rule: 'urn:usf:materialisationrule:factoryenvironmentexample',
    family: 'urn:usf:artefactfamily:factoryenvironmentexample',
    storageClass: 'urn:usf:storageclass:gittrackedsource',
    pathRole: 'urn:usf:pathrole:factoryenvironmentexample',
    representationFormat: 'urn:usf:representationformat:dotenvexample',
    canonicalExtension: '.env.example',
    namingRule: 'urn:usf:namingrule:factoryenvironmentexample',
    namingPattern: '^[.]env[.]example$',
  },
  {
    rule: 'urn:usf:materialisationrule:factorymarkdowndocumentation',
    family: 'urn:usf:artefactfamily:factorymarkdowndocumentation',
    storageClass: 'urn:usf:storageclass:gittrackedsource',
    pathRole: 'urn:usf:pathrole:factorydocumentationsource',
    representationFormat: 'urn:usf:representationformat:markdowncommonmark',
    canonicalExtension: '.md',
    namingRule: 'urn:usf:namingrule:factorymarkdowndocumentation',
    namingPattern: '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*[.]md$',
  },
  {
    rule: 'urn:usf:materialisationrule:factorypythonoperatorrealisation',
    family: 'urn:usf:artefactfamily:factorypythonoperatorrealisation',
    storageClass: 'urn:usf:storageclass:gittrackedsource',
    pathRole: 'urn:usf:pathrole:factoryproviderscriptsource',
    representationFormat: 'urn:usf:representationformat:python311source',
    canonicalExtension: '.py',
    namingRule: 'urn:usf:namingrule:factorypythonoperatorscript',
    namingPattern: '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*[.]py$',
  },
  {
    rule: 'urn:usf:materialisationrule:factorypythonpackagerealisation',
    family: 'urn:usf:artefactfamily:factorypythonpackagerealisation',
    storageClass: 'urn:usf:storageclass:gittrackedsource',
    pathRole: 'urn:usf:pathrole:factorypythonpackagesource',
    representationFormat: 'urn:usf:representationformat:python311source',
    canonicalExtension: '.py',
    namingRule: 'urn:usf:namingrule:factorypythonmodule',
    namingPattern: '^(?:__init__|[a-z][a-z0-9]*(?:_[a-z0-9]+)*)[.]py$',
  },
  {
    rule: 'urn:usf:materialisationrule:factorypythontestrealisation',
    family: 'urn:usf:artefactfamily:factorypythontestrealisation',
    storageClass: 'urn:usf:storageclass:gittrackedsource',
    pathRole: 'urn:usf:pathrole:factoryproviderworkforcetestsource',
    representationFormat: 'urn:usf:representationformat:python311source',
    canonicalExtension: '.py',
    namingRule: 'urn:usf:namingrule:factorypythontest',
    namingPattern: '^test_[a-z][a-z0-9]*(?:_[a-z0-9]+)*[.]py$',
  },
  {
    rule: 'urn:usf:materialisationrule:factoryyamldocumentation',
    family: 'urn:usf:artefactfamily:factoryyamldocumentation',
    storageClass: 'urn:usf:storageclass:gittrackedsource',
    pathRole: 'urn:usf:pathrole:factorydocumentationsource',
    representationFormat: 'urn:usf:representationformat:yamlconfiguration12',
    canonicalExtension: '.yaml',
    namingRule: 'urn:usf:namingrule:factoryyamldocumentation',
    namingPattern: '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*[.]yaml$',
  },
]);
export const ACTIVE = 'urn:usf:contractactivationstate:active';
export const SUCCESSFUL = 'urn:usf:proofresultstate:successful';
export const ACCEPTED = 'urn:usf:decisionstate:accepted';

// One declaration of every materialisation bound and of the closed action set.
// The canonical gateway imports these rather than restating them, so a bound can
// never be tighter on one surface than the other.
export const MATERIALISATION_BOUNDS = Object.freeze({
  MAX_OPERATIONS: 256,
  MAX_PLAN_BYTES: 65_536,
  MAX_TRACKED_WRITE_BYTES: 16 * 1024 * 1024,
});
export const MATERIALISATION_ACTIONS = Object.freeze(['create-directory', 'write-file', 'move-path', 'delete-path']);

const { MAX_OPERATIONS, MAX_PLAN_BYTES, MAX_TRACKED_WRITE_BYTES } = MATERIALISATION_BOUNDS;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ACTIONS = new Set(MATERIALISATION_ACTIONS);

function repositoryIdentityFromRemote(remote) {
  const value = String(remote).trim().replace(/[/.]git\/?$/u, '');
  const match = value.match(/^(?:https:\/\/github[.]com\/|ssh:\/\/git@github[.]com\/|git@github[.]com:)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)$/u);
  return match?.[1] ?? null;
}

function gitRead(repositoryRoot, args) {
  return execFileSync('git', ['-C', repositoryRoot, ...args], {
    encoding: 'utf8',
    maxBuffer: 4096,
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}

/**
 * Bind the semantic repository identity to a real Git worktree before any
 * filesystem mutation. The identity is never accepted from a caller alone:
 * the selected root must be the Git top-level and its GitHub origin must name
 * the exact authority-selected repository. Detached and linked worktrees are
 * supported; an arbitrary directory carrying only the asserted string is not.
 */
export function attestRepositoryRoot(repositoryRoot, expectedRepositoryIdentity) {
  if (typeof repositoryRoot !== 'string' || repositoryRoot.length === 0) {
    throw new Error('repository root is required');
  }
  if (typeof expectedRepositoryIdentity !== 'string' || expectedRepositoryIdentity.length === 0) {
    throw new Error('expected repository identity is required');
  }
  const unresolvedRoot = resolve(repositoryRoot);
  if (lstatSync(unresolvedRoot).isSymbolicLink()) {
    throw new Error('materialisation repository root must not be a symbolic link');
  }
  const canonicalRoot = realpathSync(unresolvedRoot);
  let gitTopLevel;
  let origin;
  try {
    gitTopLevel = realpathSync(gitRead(canonicalRoot, ['rev-parse', '--show-toplevel']));
    origin = gitRead(canonicalRoot, ['config', '--get', 'remote.origin.url']);
  } catch {
    throw new Error('materialisation repository root is not an attested Git worktree');
  }
  if (gitTopLevel !== canonicalRoot) {
    throw new Error('materialisation repository root must be the Git worktree top-level');
  }
  const observedRepositoryIdentity = repositoryIdentityFromRemote(origin);
  if (observedRepositoryIdentity !== expectedRepositoryIdentity) {
    throw new Error('materialisation repository origin does not match the authority-bound repository');
  }
  return Object.freeze({
    schemaVersion: 1,
    repositoryIdentity: observedRepositoryIdentity,
    repositoryRoot: canonicalRoot,
    originDigest: sha256(Buffer.from(origin, 'utf8')),
  });
}

// One path policy for every materialisation surface, COMPILED FROM SEMANTIC
// AUTHORITY rather than asserted to match it.
//
// This module and the canonical gateway previously each declared their own
// forbidden-segment vocabulary, so a path one rejected the other could accept.
// The surviving list then claimed to be
// `urn:usf:repositorynamingstandard:semanticpurpose`'s prohibitedCanonicalToken
// values, and was not: it carried a token authority does not declare and omitted
// nine that it does. A list that merely claims to match the graph is exactly the
// defect this replaces.
//
// `NAMING_STANDARD` is the compiled projection of that standard. Every field is
// traceable to a declared property, and `comparePathPolicyToAuthority` re-derives
// it from a loaded dataset so a graph/code difference fails the gate instead of
// silently permitting an unauthorised path.
export const NAMING_STANDARD_IRI = 'urn:usf:repositorynamingstandard:semanticpurpose';
export const REPOSITORY_CANONICAL_NAME = 'usf';

export const NAMING_STANDARD = Object.freeze({
  standard: NAMING_STANDARD_IRI,
  // usf:prohibitedCanonicalToken, verbatim and complete.
  prohibitedCanonicalTokens: Object.freeze([
    'bootstrap',
    'common',
    'core',
    'executable-suite',
    'external-tracker-identifier',
    'external-work-record-ordinal',
    'helpers',
    'initial-suite',
    'legacy',
    'migration',
    'misc',
    'reference-kernel',
    'replacement',
    'shared',
    'temporary',
    'transitional',
    'utils',
    'v2',
    'wave-five',
    'wave-four',
    'wave-one',
    'wave-six',
    'wave-three',
    'wave-two',
    'wave-zero',
  ]),
  // usf:operationalSequenceIdentityProhibited — a delivery-sequence identity is
  // prohibited as a class, not only for the exact wave tokens above.
  operationalSequenceIdentityProhibited: true,
  // usf:trackerDerivedIdentityProhibited — an external tracker identifier such
  // is prohibited as a class, not only for the exact tokens above.
  trackerDerivedIdentityProhibited: true,
  // usf:sourceDerivedIdentityProhibited — this is what authorises the structural
  // `usf` segment rule: an operation path is repository-relative, so re-embedding
  // the repository's own name is inherited-source identity.
  sourceDerivedIdentityProhibited: true,
});

// The one authorised exception, and it is authority-declared rather than
// invented here: the agent-integration path roles
// `urn:usf:pathrole:claudeagentintegration` and
// `urn:usf:pathrole:codexagentintegration` declare authorisedParentPath values
// that legitimately contain the repository name, matching the standard's
// "aliases or product integrations are explicit compatibility projections" and
// "product-required shim or skill filenames" rules.
export const AGENT_INTEGRATION_PATH_ROLES = Object.freeze([
  'urn:usf:pathrole:claudeagentintegration',
  'urn:usf:pathrole:codexagentintegration',
]);
const SKILL_EXCEPTION_PREFIXES = Object.freeze(['.claude/skills/usf/', '.codex/skills/usf/']);

const OPERATIONAL_SEQUENCE_IDENTITY = /^wave(?:-|_)?(?:zero|one|two|three|four|five|six|[0-9]+)$/i;
const TRACKER_DERIVED_IDENTITY = /^usf-[0-9]+$/i;

// Compile the runtime segment policy from the standard. The structural
// repository-name token is added only because sourceDerivedIdentityProhibited is
// declared; if authority ever withdrew that, the token would go with it.
export function compilePathPolicy(standard = NAMING_STANDARD) {
  const segments = new Set(standard.prohibitedCanonicalTokens.map((token) => token.toLowerCase()));
  if (standard.sourceDerivedIdentityProhibited) segments.add(REPOSITORY_CANONICAL_NAME);
  return Object.freeze({
    forbiddenSegments: segments,
    operationalSequenceIdentityProhibited: standard.operationalSequenceIdentityProhibited === true,
    trackerDerivedIdentityProhibited: standard.trackerDerivedIdentityProhibited === true,
  });
}

const PATH_POLICY = compilePathPolicy();
export const FORBIDDEN_SEGMENTS = PATH_POLICY.forbiddenSegments;

export const stable = (input) => Array.isArray(input)
  ? input.map(stable)
  : input && typeof input === 'object'
    ? Object.fromEntries(Object.keys(input).sort().map((key) => [key, stable(input[key])]))
    : input;

export const canonicalJson = (input) => JSON.stringify(stable(input));
export const sha256 = (input) => `sha256:${createHash('sha256').update(input).digest('hex')}`;
export const utf8Compare = (left, right) => Buffer.compare(
  Buffer.from(String(left), 'utf8'),
  Buffer.from(String(right), 'utf8'),
);

function bounded(input, maximum, label) {
  const bytes = Buffer.byteLength(canonicalJson(input));
  if (bytes > maximum) throw new Error(`${label} exceeds ${maximum} bytes`);
  return bytes;
}

export function safeRelativePath(path, label = 'path') {
  if (typeof path !== 'string' || path.length === 0 || path.length > 512 || path.startsWith('/') || path.includes('\\') || /[\x00-\x1f<>:"|?*]/.test(path)) {
    throw new Error(`${label} is not a portable repository-relative path`);
  }
  const segments = path.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) throw new Error(`${label} contains a prohibited segment`);
  if (segments.some((segment) => /[ .]$/.test(segment) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(segment))) {
    throw new Error(`${label} is not portable across supported filesystems`);
  }
  const skillException = SKILL_EXCEPTION_PREFIXES.some((prefix) => path.startsWith(prefix));
  const prohibited = (segment) => {
    const lowered = segment.toLowerCase();
    if (PATH_POLICY.forbiddenSegments.has(lowered)
      && !(skillException && lowered === REPOSITORY_CANONICAL_NAME)) return true;
    if (PATH_POLICY.operationalSequenceIdentityProhibited && OPERATIONAL_SEQUENCE_IDENTITY.test(segment)) return true;
    return PATH_POLICY.trackerDerivedIdentityProhibited && TRACKER_DERIVED_IDENTITY.test(segment);
  };
  if (segments.some(prohibited)) {
    throw new Error(`${label} contains a forbidden durable identity`);
  }
  return path;
}

// Re-derive the standard from a loaded dataset and report every difference from
// the compiled runtime policy. A non-empty result must fail the gate: it means
// the runtime is enforcing a policy authority does not declare, or is failing to
// enforce one it does.
export function readNamingStandard(store, {
  standardIri = NAMING_STANDARD_IRI,
  agentIntegrationPathRoles = AGENT_INTEGRATION_PATH_ROLES,
} = {}) {
  const ontology = 'urn:usf:ontology:';
  const values = (subject, predicate) => store
    .getObjects(namedNode(subject), namedNode(`${ontology}${predicate}`), null)
    .map((term) => term.value);
  const one = (predicate) => {
    const observed = values(standardIri, predicate);
    return observed.length === 1 ? observed[0] : null;
  };
  return Object.freeze({
    standard: standardIri,
    prohibitedCanonicalTokens: Object.freeze([...new Set(values(standardIri, 'prohibitedCanonicalToken'))].sort()),
    operationalSequenceIdentityProhibited: one('operationalSequenceIdentityProhibited'),
    trackerDerivedIdentityProhibited: one('trackerDerivedIdentityProhibited'),
    sourceDerivedIdentityProhibited: one('sourceDerivedIdentityProhibited'),
    agentIntegrationParentPaths: Object.freeze([...new Set(agentIntegrationPathRoles
      .flatMap((role) => values(role, 'authorisedParentPath')))].sort()),
  });
}

export function comparePathPolicyToAuthority(observed) {
  const standardIri = observed?.standard ?? NAMING_STANDARD_IRI;
  const one = (predicate) => observed?.[predicate] ?? null;

  const observedTokens = [...new Set(observed?.prohibitedCanonicalTokens ?? [])].sort();
  const declaredTokens = [...NAMING_STANDARD.prohibitedCanonicalTokens].sort();
  const differences = [];
  if (observedTokens.length === 0) {
    differences.push({ code: 'naming-standard-absent', standard: standardIri });
  }
  for (const token of observedTokens) {
    if (!declaredTokens.includes(token)) differences.push({ code: 'authority-token-not-enforced', token });
  }
  for (const token of declaredTokens) {
    if (!observedTokens.includes(token)) differences.push({ code: 'enforced-token-not-authority-declared', token });
  }
  for (const [predicate, expected] of [
    ['operationalSequenceIdentityProhibited', NAMING_STANDARD.operationalSequenceIdentityProhibited],
    ['trackerDerivedIdentityProhibited', NAMING_STANDARD.trackerDerivedIdentityProhibited],
    ['sourceDerivedIdentityProhibited', NAMING_STANDARD.sourceDerivedIdentityProhibited],
  ]) {
    const observed = one(predicate);
    if (observed === null) differences.push({ code: 'identity-prohibition-unresolved', predicate });
    else if ((observed === 'true') !== expected) {
      differences.push({ code: 'identity-prohibition-differs', predicate, observed, expected });
    }
  }

  // The `usf` exception must stay grounded in a declared authorisedParentPath.
  const authorisedParents = (observed?.agentIntegrationParentPaths ?? []).map((parent) => `${parent}/`);
  for (const prefix of SKILL_EXCEPTION_PREFIXES) {
    if (!authorisedParents.includes(prefix)) {
      differences.push({ code: 'skill-exception-not-authority-declared', prefix });
    }
  }

  return Object.freeze({
    ok: differences.length === 0,
    standard: standardIri,
    observedTokenCount: observedTokens.length,
    enforcedSegmentCount: PATH_POLICY.forbiddenSegments.size,
    differences: Object.freeze(differences
      .sort((left, right) => utf8Compare(JSON.stringify(left), JSON.stringify(right)))
      .map((item) => Object.freeze(item))),
  });
}

export function assertPathPolicyMatchesAuthority(store, options) {
  const report = comparePathPolicyToAuthority(readNamingStandard(store, options));
  if (!report.ok) {
    const error = new Error(`runtime path policy differs from ${report.standard}: ${report.differences.map((item) => `${item.code}${item.token ? `:${item.token}` : ''}`).join(', ')}`);
    error.report = report;
    throw error;
  }
  return report;
}

export function containedBy(root, target) {
  const rel = relative(root, target);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`);
}

export function inside(root, relativePath) {
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

export function treeEntries(root, base = root) {
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

export function decisionAuthorisesPath(path, authorisedPaths, authorisedDirectoryPrefixes = null) {
  if (Array.isArray(authorisedDirectoryPrefixes)) {
    return authorisedPaths.includes(path)
      || authorisedDirectoryPrefixes.some((directory) => path.startsWith(`${directory}/`));
  }
  return authorisedPaths.some((authorised) => authorised === '.' ? !path.includes('/') : path === authorised || path.startsWith(`${authorised}/`));
}

const sortedStrings = (items) => Array.isArray(items) ? [...items].sort(utf8Compare) : [];

export function scopedPermissionSet(authority) {
  const rules = Array.isArray(authority?.rules) ? authority.rules.map((rule) => ({
    family: rule.family,
    rule: rule.rule,
    storageClass: rule.storageClass,
    pathRole: rule.pathRole,
    representationFormat: rule.representationFormat,
    canonicalExtension: rule.canonicalExtension,
    namingRule: rule.namingRule,
    namingPattern: rule.namingPattern,
  })).sort((left, right) => utf8Compare(canonicalJson(left), canonicalJson(right))) : [];
  return {
    repositories: sortedStrings(authority?.authorisedRepositories),
    paths: sortedStrings(authority?.authorisedPaths),
    directories: sortedStrings(authority?.authorisedDirectoryPrefixes),
    actions: sortedStrings(authority?.authorisedActions),
    families: sortedStrings(authority?.authorisedFamilies),
    rules,
  };
}

export function scopedPermissionSetDigest(authority) {
  return sha256(canonicalJson(scopedPermissionSet(authority)));
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
  if (authority?.decisionScopedMaterialisationRequired === true) {
    if (!Array.isArray(authority?.authorisedRepositories)
      || canonicalJson(sortedStrings(authority.authorisedRepositories)) !== canonicalJson([PROVIDER_FACTORY_REPOSITORY])) {
      failures.push({ code: 'authorised-repositories' });
    }
    if (!Array.isArray(authority?.authorisedDirectoryPrefixes)
      || canonicalJson(sortedStrings(authority.authorisedDirectoryPrefixes)) !== canonicalJson(sortedStrings(PROVIDER_FACTORY_DIRECTORIES))) {
      failures.push({ code: 'authorised-directory-prefixes' });
    }
    else if (authority.authorisedDirectoryPrefixes.some((directory) => authority.authorisedPaths.includes(directory))) failures.push({ code: 'authorised-path-directory-overlap' });
    const expectedPathScope = PROVIDER_FACTORY_PATH_SCOPES[contract];
    if (!expectedPathScope
      || authority.authorisedPaths.length !== expectedPathScope.count
      || sha256(canonicalJson(sortedStrings(authority.authorisedPaths))) !== expectedPathScope.digest) {
      failures.push({ code: 'authorised-path-set' });
    }
    if (!Array.isArray(authority?.authorisedActions)
      || authority.authorisedActions.length !== 1
      || authority.authorisedActions[0] !== 'write-file') failures.push({ code: 'authorised-actions' });
    if (!Array.isArray(authority?.authorisedFamilies)
      || canonicalJson(sortedStrings(authority.authorisedFamilies)) !== canonicalJson(sortedStrings(PROVIDER_FACTORY_FAMILIES))) {
      failures.push({ code: 'authorised-families' });
    } else if (!Array.isArray(authority?.rules)
      || authority.rules.length !== authority.authorisedFamilies.length
      || new Set(authority.rules.map((rule) => rule.family)).size !== authority.authorisedFamilies.length
      || authority.rules.some((rule) => !authority.authorisedFamilies.includes(rule.family)
        || typeof rule.rule !== 'string'
        || rule.storageClass !== 'urn:usf:storageclass:gittrackedsource'
        || typeof rule.pathRole !== 'string'
        || typeof rule.representationFormat !== 'string'
        || typeof rule.canonicalExtension !== 'string'
        || typeof rule.namingRule !== 'string'
        || typeof rule.namingPattern !== 'string')) {
      failures.push({ code: 'authorised-family-rules' });
    } else if (canonicalJson(scopedPermissionSet({ rules: authority.rules }).rules)
      !== canonicalJson(scopedPermissionSet({ rules: PROVIDER_FACTORY_RULES }).rules)) {
      failures.push({ code: 'authorised-family-rule-set' });
    }
    if (!SHA256.test(authority?.permissionSetDigest || '')) failures.push({ code: 'permission-set-digest' });
    else if (authority.permissionSetDigest !== scopedPermissionSetDigest(authority)) failures.push({ code: 'permission-set-digest-mismatch' });
  }
  if (!Array.isArray(authority?.pathRoles)) failures.push({ code: 'path-roles' });
  if (!Array.isArray(authority?.rules)) failures.push({ code: 'materialisation-rules' });
  return failures;
}

export function validatePlanOperation(operation, index, authority) {
  const failures = [];
  if (!operation || operation.index !== index) failures.push({ index, code: 'operation-index' });
  if (!ACTIONS.has(operation?.action)) failures.push({ index, code: 'operation-action' });
  if (authority?.decisionScopedMaterialisationRequired === true
    && !authority.authorisedActions.includes(operation?.action)) failures.push({ index, code: 'operation-decision-action' });
  if (authority?.decisionScopedMaterialisationRequired === true
    && !authority.authorisedFamilies.includes(operation?.artefactFamily)) failures.push({ index, code: 'operation-decision-family' });
  let path;
  try { path = safeRelativePath(operation?.path); } catch { failures.push({ index, code: 'operation-path' }); }
  const directoryPrefixes = authority?.decisionScopedMaterialisationRequired === true
    ? authority.authorisedDirectoryPrefixes
    : null;
  if (path && !decisionAuthorisesPath(path, authority.authorisedPaths, directoryPrefixes)) failures.push({ index, code: 'operation-decision-path' });
  const role = authority.pathRoles.find((item) => item.id === operation?.pathRole);
  if (!role) failures.push({ index, code: 'operation-path-role' });
  if (path && role && role.parent !== '.' && path !== role.parent && !path.startsWith(`${role.parent}/`)) failures.push({ index, code: 'operation-unauthorised-parent' });
  if (path && role?.parent === '.' && path.includes('/')) failures.push({ index, code: 'operation-root-descendant' });
  if (operation?.sourceDigest !== undefined && !SHA256.test(operation.sourceDigest)) failures.push({ index, code: 'operation-source-digest' });
  if (operation?.action === 'move-path') {
    let sourcePath;
    try { sourcePath = safeRelativePath(operation.sourcePath, 'sourcePath'); } catch { failures.push({ index, code: 'operation-move-source' }); }
    if (sourcePath && !decisionAuthorisesPath(sourcePath, authority.authorisedPaths, directoryPrefixes)) failures.push({ index, code: 'operation-move-source-decision-path' });
    if (operation?.sourceDigest === undefined) failures.push({ index, code: 'operation-source-digest' });
  }
  if (operation?.action === 'delete-path' && operation?.sourceDigest === undefined) failures.push({ index, code: 'operation-source-digest' });
  if (operation?.action === 'write-file') {
    if (!SHA256.test(operation.contentDigest || '')) failures.push({ index, code: 'operation-content-digest' });
    const matchingRules = authority.rules.filter((item) => item.family === operation.artefactFamily
      && item.representationFormat === operation.representationFormat
      && item.pathRole === operation.pathRole);
    if (matchingRules.length !== 1) failures.push({ index, code: matchingRules.length === 0 ? 'operation-write-representation' : 'operation-write-representation-ambiguous' });
    else if (path) {
      const [rule] = matchingRules;
      if (!new RegExp(rule.namingPattern).test(basename(path))) failures.push({ index, code: 'operation-filename' });
      if (authority?.decisionScopedMaterialisationRequired === true
        && (typeof rule.canonicalExtension !== 'string' || !basename(path).endsWith(rule.canonicalExtension))) {
        failures.push({ index, code: 'operation-format-extension' });
      }
    }
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
  if (authority?.decisionScopedMaterialisationRequired === true
    && plan?.permissionSetDigest !== authority?.permissionSetDigest) failures.push({ code: 'plan-permission-set-digest' });
  if (authority?.decisionScopedMaterialisationRequired === true
    && plan?.repositoryIdentity !== PROVIDER_FACTORY_REPOSITORY) failures.push({ code: 'plan-repository-identity' });
  if (!Array.isArray(plan?.operations) || plan.operations.length < 1 || plan.operations.length > MAX_OPERATIONS) failures.push({ code: 'plan-operation-bound' });
  else plan.operations.forEach((operation, index) => failures.push(...validatePlanOperation(operation, index, authority)));
  const unsigned = { ...plan };
  delete unsigned.planDigest;
  const expectedPlanDigest = sha256(canonicalJson(unsigned));
  if (plan?.planDigest !== expectedPlanDigest) failures.push({ code: 'plan-digest' });
  return { ok: failures.length === 0, authorityDigest: authority?.authorityDigest ?? null, expectedPlanDigest, operationCount: plan?.operations?.length ?? 0, failures };
}

export function createMaterialisationPlan(authority, operations, contract = MATERIALISATION_CONTRACT) {
  if (!Array.isArray(operations)) throw new TypeError('operations must be an array');
  const plan = {
    schemaVersion: 1,
    authorityDigest: authority?.authorityDigest,
    ...(authority?.decisionScopedMaterialisationRequired === true
      ? {
        permissionSetDigest: authority.permissionSetDigest,
        repositoryIdentity: authority.authorisedRepositories[0],
      }
      : {}),
    contract,
    operations,
  };
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

// The ONE rollback error aggregator. Exported so the canonical gateway re-exports
// it rather than keeping a second copy that could aggregate differently.
export function rollbackAndThrow(error, rollback) {
  const rollbackErrors = [];
  for (const undo of rollback.reverse()) {
    try { undo(); } catch (rollbackError) { rollbackErrors.push(rollbackError); }
  }
  if (rollbackErrors.length) throw new AggregateError([error, ...rollbackErrors], 'materialisation failed and rollback was incomplete', { cause: error });
  throw error;
}

// The ONE operator-local CAS object resolver. Both the plan apply path and the
// gateway's artifact verification reach content through this, so the locator
// layout and the containment, regular-file, symlink and digest checks exist once.
export function resolveCasObject(casRoot, contentDigest, { label = 'CAS object' } = {}) {
  if (!casRoot) throw new Error('operator-local CAS root is required for located content');
  if (!SHA256.test(contentDigest || '')) throw new Error(`${label} digest must be sha256:<64 lowercase hex>`);
  const canonicalCasRoot = realpathSync(casRoot);
  const hex = contentDigest.slice(7);
  const path = resolve(canonicalCasRoot, 'sha256', hex.slice(0, 2), hex);
  if (!containedBy(canonicalCasRoot, path)) return { found: false, code: 'cas-path-escaped-root', path };
  if (!existsSync(path)) return { found: false, code: 'cas-object-not-found', path };
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || !containedBy(canonicalCasRoot, realpathSync(path))) {
    return { found: false, code: 'cas-object-not-regular-file', path };
  }
  return { found: true, path, byteSize: stat.size };
}

export function readCasObject(casRoot, contentDigest, {
  label = 'plan content',
  subject = contentDigest,
  maximumBytes = MAX_TRACKED_WRITE_BYTES,
} = {}) {
  const located = resolveCasObject(casRoot, contentDigest, { label });
  if (!located.found) {
    throw new Error(located.code === 'cas-object-not-found'
      ? `${label} not found: ${subject}`
      : `${label} is not a regular CAS object: ${subject}`);
  }
  if (located.byteSize > maximumBytes) throw new Error(`tracked write exceeds ${maximumBytes} bytes: ${subject}`);
  const bytes = readFileSync(located.path);
  if (sha256(bytes) !== contentDigest) throw new Error(`${label} digest mismatch: ${subject}`);
  return bytes;
}

function operationBytes(operation, casRoot) {
  if (!operation.contentLocator) return Buffer.from(operation.content, operation.contentEncoding === 'base64' ? 'base64' : 'utf8');
  return readCasObject(casRoot, operation.contentDigest, { label: 'plan content', subject: operation.path });
}

/**
 * The ONE filesystem apply and rollback implementation.
 *
 * It performs no authority decision and takes no verdict: a caller that owns the
 * live-authority conclusion (the canonical gateway) reaches this with a plan it
 * has already judged. The returned handle exposes the still-open rollback stack
 * so that caller can run a post-apply authority check and, if authority moved
 * while the filesystem was changing, undo the complete run through this same
 * implementation rather than a second copy of it.
 *
 * @returns {{operations: object[], rollbackAndThrow: (error: Error) => never}}
 */
export function executePlanOperations({
  plan,
  repositoryRoot,
  repositoryIdentity = null,
  expectedRepositoryIdentity = null,
  casRoot,
}) {
  if (!repositoryRoot) throw new Error('repository root is required');
  if (expectedRepositoryIdentity !== null
    && (repositoryIdentity !== expectedRepositoryIdentity || plan?.repositoryIdentity !== expectedRepositoryIdentity)) {
    throw new Error('materialisation repository identity does not match the authority-bound repository');
  }
  const root = expectedRepositoryIdentity === null
    ? realpathSync(repositoryRoot)
    : attestRepositoryRoot(repositoryRoot, expectedRepositoryIdentity).repositoryRoot;
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
  return Object.freeze({
    operations,
    rollbackAndThrow: (error) => rollbackAndThrow(error, rollback),
  });
}

export function materialisePlan({
  authority,
  plan,
  repositoryRoot,
  repositoryIdentity = null,
  casRoot,
  apply = false,
}) {
  const validation = validateMaterialisationPlan(authority, plan);
  if (!validation.ok) return { applied: false, validation };
  if (!apply) return { applied: false, dryRun: true, validation };
  const expectedRepositoryIdentity = authority?.decisionScopedMaterialisationRequired === true
    ? authority.authorisedRepositories[0]
    : null;
  const execution = executePlanOperations({
    plan,
    repositoryRoot,
    repositoryIdentity,
    expectedRepositoryIdentity,
    casRoot,
  });
  return {
    applied: true,
    validation,
    repositoryIdentity: expectedRepositoryIdentity,
    operations: execution.operations,
  };
}
