import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { compareBy, framedDigest, sha256 } from './canonical.mjs';

export const DEFAULT_REPOSITORY_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));

export const UNIVERSES = Object.freeze([
  'repository-output',
  'v2-graph-authority',
  'v2-compiler-implementation',
  'v2-support-provisioning'
]);

export const NONCANONICAL_SCRATCH_PREFIX = 'v2/usf/.work/';

export function observationCarrierPaths(repositoryRoot = DEFAULT_REPOSITORY_ROOT) {
  const manifestPath = path.join(repositoryRoot, 'v2/usf/graph/manifest.yaml');
  const manifest = parseYaml(fs.readFileSync(manifestPath, 'utf8'));
  if (!manifest || typeof manifest !== 'object') throw new Error('graph manifest is empty or invalid');
  const rows = [...(manifest.observedGraphs ?? []), ...(manifest.derivedGraphs ?? [])];
  const carriers = new Set();
  for (const row of rows) {
    if (!row || typeof row.file !== 'string' || !row.file || path.posix.isAbsolute(row.file) || row.file.includes('\\') || row.file.split('/').includes('..') || path.posix.normalize(row.file) !== row.file) {
      throw new Error('graph manifest carrier path must be a contained relative POSIX path');
    }
    carriers.add(`v2/usf/graph/${row.file}`);
  }
  if (carriers.size !== rows.length) throw new Error('graph manifest carrier paths must be unique');
  return carriers;
}

function runGit(repositoryRoot, args, options = {}) {
  return execFileSync('git', args, {
    cwd: repositoryRoot,
    encoding: options.encoding ?? 'buffer',
    input: options.input,
    maxBuffer: 1024 * 1024 * 1024
  });
}

function nulValues(value) {
  return Buffer.from(value).toString('utf8').split('\0').filter(Boolean);
}

export function trackedEntries(repositoryRoot = DEFAULT_REPOSITORY_ROOT) {
  const entries = new Map();
  for (const row of nulValues(runGit(repositoryRoot, ['ls-files', '--stage', '-z']))) {
    const match = /^(\d{6}) ([a-f0-9]{40,64}) (\d)\t([\s\S]+)$/.exec(row);
    if (!match) throw new Error(`unparseable git index row: ${row.slice(0, 80)}`);
    const [, mode, objectId, stage, repoPath] = match;
    if (stage !== '0') throw new Error(`unmerged index stage for ${repoPath}`);
    entries.set(repoPath, { mode, objectId });
  }
  return entries;
}

export function workingStates(repositoryRoot = DEFAULT_REPOSITORY_ROOT) {
  const states = new Map();
  const rows = nulValues(runGit(repositoryRoot, ['status', '--porcelain=v1', '-z', '--untracked-files=all']));
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const code = row.slice(0, 2);
    const repoPath = row.slice(3);
    let sourceState = 'tracked';
    if (code === '??') sourceState = 'untracked';
    else if (code.includes('R')) sourceState = 'renamed';
    else if (code.includes('D')) sourceState = 'deleted';
    else if (code[0] !== ' ') sourceState = 'staged';
    else if (code[1] !== ' ') sourceState = 'modified';
    states.set(repoPath, sourceState);
    if (code.includes('R') || code.includes('C')) index += 1;
  }
  return states;
}

export function universeForPath(repoPath, carrierPaths = new Set()) {
  if (repoPath.startsWith('v2/usf/census/')) return null;
  if (repoPath.startsWith(NONCANONICAL_SCRATCH_PREFIX)) return null;
  if (carrierPaths.has(repoPath)) return null;
  if (!repoPath.startsWith('v2/')) return 'repository-output';
  if (repoPath.startsWith('v2/usf/graph/')) return 'v2-graph-authority';
  if (repoPath.startsWith('v2/usf/compiler/')) return 'v2-compiler-implementation';
  return 'v2-support-provisioning';
}

export function identifyFormat(repoPath, bytes, mode) {
  if (mode === '120000') return { binary: false, extension: '', mediaType: 'inode/symlink', formatKind: 'symbolic-link' };
  if (mode === '160000') return { binary: false, extension: '', mediaType: 'application/x-gitlink', formatKind: 'gitlink' };
  const lower = repoPath.toLowerCase();
  const extension = path.posix.extname(lower);
  const sample = bytes.subarray(0, 8192);
  const binary = sample.includes(0);
  const text = binary ? '' : sample.toString('utf8');
  if (text.startsWith('version https://git-lfs.github.com/spec/v1')) return { binary: false, extension, mediaType: 'text/plain', formatKind: 'git-lfs-pointer' };
  if (binary) {
    if (['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico'].includes(extension)) return { binary, extension, mediaType: `image/${extension.slice(1).replace('jpg', 'jpeg')}`, formatKind: 'image-raster' };
    if (['.woff', '.woff2', '.ttf', '.otf'].includes(extension)) return { binary, extension, mediaType: 'font/unknown', formatKind: 'font' };
    if (['.zip', '.gz', '.tgz', '.xz', '.tar', '.jar'].includes(extension)) return { binary, extension, mediaType: 'application/octet-stream', formatKind: 'archive' };
    return { binary, extension, mediaType: 'application/octet-stream', formatKind: 'opaque-binary' };
  }
  const formats = new Map([
    ['.json', ['application/json', 'structured-json']], ['.jsonl', ['application/x-ndjson', 'data-jsonl']],
    ['.ndjson', ['application/x-ndjson', 'data-jsonl']], ['.yaml', ['application/yaml', 'structured-yaml']],
    ['.yml', ['application/yaml', 'structured-yaml']], ['.toml', ['application/toml', 'structured-toml']],
    ['.xml', ['application/xml', 'structured-xml']], ['.plist', ['application/xml', 'structured-xml']],
    ['.csv', ['text/csv', 'data-csv']], ['.md', ['text/markdown', 'document-markdown']],
    ['.html', ['text/html', 'document-html']], ['.htm', ['text/html', 'document-html']],
    ['.svg', ['image/svg+xml', 'image-vector']], ['.css', ['text/css', 'source-css']],
    ['.ttl', ['text/turtle', 'rdf-turtle']], ['.trig', ['application/trig', 'rdf-trig']],
    ['.rq', ['application/sparql-query', 'sparql-query']], ['.sparql', ['application/sparql-query', 'sparql-query']],
    ['.sql', ['application/sql', 'source-sql']], ['.pem', ['application/x-pem-file', 'certificate']],
    ['.crt', ['application/x-pem-file', 'certificate']], ['.cer', ['application/x-pem-file', 'certificate']]
  ]);
  if (formats.has(extension)) {
    const [mediaType, formatKind] = formats.get(extension);
    return { binary, extension, mediaType, formatKind };
  }
  if (['.sh', '.bash'].includes(extension) || /^#!.*\b(?:ba)?sh\b/.test(text)) return { binary, extension, mediaType: 'text/x-shellscript', formatKind: 'source-shell' };
  if (['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.tsx', '.jsx', '.py', '.java', '.go', '.rs', '.rb', '.php', '.swift', '.kt', '.c', '.h', '.cpp'].includes(extension)) return { binary, extension, mediaType: 'text/plain', formatKind: 'source-code' };
  if (['.env', '.ini', '.conf', '.config', '.properties'].includes(extension) || ['.gitignore', '.npmrc', '.editorconfig', 'makefile', 'dockerfile'].includes(path.posix.basename(lower))) return { binary, extension, mediaType: 'text/plain', formatKind: 'configuration-text' };
  return { binary, extension, mediaType: 'text/plain', formatKind: 'plain-text' };
}

function indexedContent(repositoryRoot, repoPath, entry) {
  if (entry.mode === '160000') return { bytes: Buffer.from(`gitlink:${entry.objectId}`), stat: null, symbolicLinkTarget: null };
  return { bytes: runGit(repositoryRoot, ['cat-file', 'blob', entry.objectId]), stat: null, symbolicLinkTarget: null };
}

function sourceContent(repositoryRoot, repoPath, entry) {
  const absolute = path.join(repositoryRoot, repoPath);
  try {
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) {
      const symbolicLinkTarget = fs.readlinkSync(absolute);
      return { bytes: Buffer.from(symbolicLinkTarget), stat, symbolicLinkTarget };
    }
    return { bytes: fs.readFileSync(absolute), stat, symbolicLinkTarget: null };
  } catch (error) {
    if (error.code !== 'ENOENT' || !entry) throw error;
    return indexedContent(repositoryRoot, repoPath, entry);
  }
}

function modeFor(entry, stat) {
  if (entry?.mode === '160000' || !stat) return entry.mode;
  if (stat.isSymbolicLink()) return '120000';
  return stat.mode & 0o111 ? '100755' : '100644';
}

function createMember(repositoryRoot, repoPath, universe, entries, states) {
  const entry = entries.get(repoPath);
  const { bytes, stat, symbolicLinkTarget } = sourceContent(repositoryRoot, repoPath, entry);
  const fileMode = modeFor(entry, stat);
  const format = identifyFormat(repoPath, bytes, fileMode);
  return {
    path: repoPath,
    universe,
    sourceState: states.get(repoPath) ?? (entry ? 'tracked' : 'untracked'),
    contentDigest: sha256(bytes),
    byteSize: bytes.length,
    fileMode,
    executable: fileMode === '100755',
    binary: format.binary,
    extension: format.extension,
    mediaType: format.mediaType,
    formatKind: format.formatKind,
    symbolicLinkTarget,
    canonicalSource: true
  };
}

function nonignoredUntracked(repositoryRoot) {
  return nulValues(runGit(repositoryRoot, ['ls-files', '--others', '--exclude-standard', '-z']));
}

const allowedIgnoreRules = [
  { pattern: /(?:^|\/)(?:node_modules|\.pnpm-store|\.venv|__pycache__)(?:\/|$)|(?:^|\/)\*\.pyc$/, pathClass: 'dependency-installation', reason: 'installed dependencies are external materialisations' },
  { pattern: /(?:^|\/)(?:dist|coverage|\.claude|\.codex|\.proof-review)(?:\/|$)/, pathClass: 'generated-or-cache-output', reason: 'generated or cache output is recreated from tracked source' },
  { pattern: /(?:^|\/)\.env(?:\.\*)?$/, pathClass: 'credential-boundary', reason: 'credential-bearing state is prohibited from source control' },
  { pattern: /^graph\/snapshots\/\*$/, pathClass: 'derived-graph-output', reason: 'graph snapshots are derived from tracked graph authority' },
  { pattern: /^\/etc(?:\/profile\.d)?\/\*$/, pathClass: 'chroot-runtime', reason: 'the chroot operating-system tree is external except for explicit tracked wiring' },
  { pattern: /^\/\*$/, pathClass: 'chroot-runtime', reason: 'the chroot filesystem is an external operating-system materialisation' }
];

const allowedNegations = new Set([
  '.env.example', '/.gitignore', '/usf/', '/etc/', '/etc/profile.d/',
  '/etc/profile.d/java.sh', '/etc/profile.d/stardog.sh', 'graph/snapshots/.gitkeep'
]);

export function auditIgnoreText(ignoreFile, text) {
  return text.split(/\r?\n/).flatMap((raw, index) => {
    const pattern = raw.trim();
    if (!pattern || pattern.startsWith('#')) return [];
    const negated = pattern.startsWith('!');
    const value = negated ? pattern.slice(1) : pattern;
    if (negated) {
      const allowed = allowedNegations.has(value);
      return [{
        ignoreFile, line: index + 1, pattern, negated, pathClass: 'source-boundary-exception',
        closureDecision: allowed ? 'allowed' : 'blocked',
        reason: allowed ? 'explicit tracked-source exception' : 'unrecognised ignore negation requires review'
      }];
    }
    const classification = allowedIgnoreRules.find((candidate) => candidate.pattern.test(value));
    return [{
      ignoreFile, line: index + 1, pattern, negated, pathClass: classification?.pathClass ?? 'unclassified',
      closureDecision: classification ? 'allowed' : 'blocked',
      reason: classification?.reason ?? 'unclassified ignore pattern requires an explicit materialisation or source decision'
    }];
  });
}

export function auditIgnoreRules({ repositoryRoot = DEFAULT_REPOSITORY_ROOT, entries = trackedEntries(repositoryRoot) } = {}) {
  const ignoreFiles = [...entries.keys()].filter((repoPath) => path.posix.basename(repoPath) === '.gitignore').sort();
  const rules = ignoreFiles.flatMap((repoPath) => {
    const { bytes } = sourceContent(repositoryRoot, repoPath, entries.get(repoPath));
    return auditIgnoreText(repoPath, bytes.toString('utf8'));
  });
  const blockedRules = rules.filter((rule) => rule.closureDecision === 'blocked');
  return {
    ignoreFiles,
    rules,
    blockedPatternCount: blockedRules.length,
    blockedRules,
    closureStatus: blockedRules.length === 0 ? 'complete' : 'incomplete'
  };
}

export function enumerateUniverses({ repositoryRoot = DEFAULT_REPOSITORY_ROOT } = {}) {
  const entries = trackedEntries(repositoryRoot);
  const states = workingStates(repositoryRoot);
  const paths = [...entries.keys(), ...nonignoredUntracked(repositoryRoot)].sort();
  const carrierPaths = observationCarrierPaths(repositoryRoot);
  const universes = Object.fromEntries(UNIVERSES.map((universe) => [universe, []]));
  for (const repoPath of paths) {
    const universe = universeForPath(repoPath, carrierPaths);
    if (universe === null) continue;
    const isTracked = entries.has(repoPath);
    if (!isTracked && universe === 'v2-support-provisioning') continue;
    universes[universe].push(createMember(repositoryRoot, repoPath, universe, entries, states));
  }
  for (const members of Object.values(universes)) {
    members.sort(compareBy(['path']));
    const unique = new Set(members.map((member) => member.path));
    if (unique.size !== members.length) throw new Error('duplicate universe path');
  }
  return { universes, ignoreAudit: auditIgnoreRules({ repositoryRoot, entries }) };
}

export function enumerateObservationCarrierMembers({ repositoryRoot = DEFAULT_REPOSITORY_ROOT } = {}) {
  const entries = trackedEntries(repositoryRoot);
  const states = workingStates(repositoryRoot);
  return [...observationCarrierPaths(repositoryRoot)].sort().map((repoPath) => {
    if (!fs.existsSync(path.join(repositoryRoot, repoPath))) throw new Error(`graph observation carrier is missing: ${repoPath}`);
    return createMember(repositoryRoot, repoPath, 'v2-graph-authority', entries, states);
  });
}

export const enumerateCurrent = enumerateUniverses;

export function universeSummary(universes) {
  const details = Object.fromEntries(UNIVERSES.map((universe) => {
    const members = universes[universe] ?? [];
    return [universe, {
      count: members.length,
      digest: framedDigest(members, ['universe', 'path', 'sourceState', 'fileMode', 'contentDigest'])
    }];
  }));
  return {
    repositoryUniverseDigest: details['repository-output'].digest,
    v2GraphUniverseDigest: details['v2-graph-authority'].digest,
    v2CompilerUniverseDigest: details['v2-compiler-implementation'].digest,
    v2SupportUniverseDigest: details['v2-support-provisioning'].digest,
    universeCounts: Object.fromEntries(UNIVERSES.map((universe) => [universe, details[universe].count]))
  };
}
