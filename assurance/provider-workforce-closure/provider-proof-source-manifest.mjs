import { createHash } from 'node:crypto';
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { posix, resolve } from 'node:path';
import { TextDecoder } from 'node:util';

const MANIFEST_PATH =
  'assurance/provider-workforce-closure/provider-proof-source-manifest.mjs';
const PUBLICATION_ENTRYPOINT =
  'processes/semantic-assurance/semantic-authority-publication.mjs';
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

const utf8Compare = (left, right) => Buffer.compare(
  Buffer.from(String(left), 'utf8'),
  Buffer.from(String(right), 'utf8'),
);
const utf8Sorted = (values) => [...values].sort(utf8Compare);
const frozenUtf8Sorted = (values) => Object.freeze(utf8Sorted(values));
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const canonical = (value) => Array.isArray(value)
  ? value.map(canonical)
  : value && typeof value === 'object'
    ? Object.fromEntries(
      Object.keys(value).sort(utf8Compare).map((key) => [key, canonical(value[key])]),
    )
    : value;
const canonicalJson = (value) => JSON.stringify(canonical(value));

export const PROVIDER_PROOF_SOURCE_MANIFEST_SCHEMA_VERSION = 1;

export const PROVIDER_PROOF_CORE_SOURCE_PATHS = frozenUtf8Sorted([
  'assurance/provider-workforce-closure/provider-materialisation-authority-mutations.mjs',
  'assurance/provider-workforce-closure/provider-workforce-authority-projection.mjs',
  'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs',
  'assurance/semantic-model-compilation/local-shacl-validation.mjs',
  'capabilities/repository-external-artefact-materialisation/materialisation-plan.mjs',
  'capabilities/semantic-model-compilation/authority-binding.mjs',
]);

export const CANONICAL_PUBLICATION_SOURCE_PATHS = frozenUtf8Sorted([
  'capabilities/semantic-model-compilation/compiler.mjs',
  'capabilities/semantic-model-compilation/manifest.mjs',
  'capabilities/semantic-model-compilation/origin-independence.mjs',
  'configuration/semantic-assurance/semantic-authority.mjs',
  'processes/semantic-assurance/publication-receipt.mjs',
  'processes/semantic-assurance/semantic-authority-gateway.mjs',
  PUBLICATION_ENTRYPOINT,
  'processes/semantic-assurance/semantic-model-compilation-command.mjs',
  'provider-bindings/stardog/semantic-authority.mjs',
]);

export const PROVIDER_PROOF_CURRENTNESS_SOURCE_PATHS = frozenUtf8Sorted([
  'processes/semantic-assurance/proof-currentness.mjs',
]);

export const PROVIDER_PROOF_MATERIALISATION_ATTESTATION_SOURCE_PATHS = frozenUtf8Sorted([
  'assurance/provider-workforce-closure/materialisation-proof-attestation-verifier.mjs',
]);

export const PROVIDER_PROOF_EXECUTION_HERMETICITY_SOURCE_PATHS = frozenUtf8Sorted([
  'assurance/provider-workforce-closure/authority-execution-hermeticity.mjs',
]);

export const PROVIDER_PROOF_HERMETIC_CAS_SOURCE_PATHS = frozenUtf8Sorted([
  'assurance/provider-workforce-closure/hermetic-cas.mjs',
]);

export const PROVIDER_PROOF_SOURCE_MANIFEST_SOURCE_PATHS = frozenUtf8Sorted([
  MANIFEST_PATH,
]);

export const PROVIDER_PROOF_SOURCE_CLASSIFICATIONS = Object.freeze({
  canonicalPublication: CANONICAL_PUBLICATION_SOURCE_PATHS,
  core: PROVIDER_PROOF_CORE_SOURCE_PATHS,
  executionHermeticity: PROVIDER_PROOF_EXECUTION_HERMETICITY_SOURCE_PATHS,
  hermeticCas: PROVIDER_PROOF_HERMETIC_CAS_SOURCE_PATHS,
  materialisationAttestation: PROVIDER_PROOF_MATERIALISATION_ATTESTATION_SOURCE_PATHS,
  proofCurrentness: PROVIDER_PROOF_CURRENTNESS_SOURCE_PATHS,
  sourceManifest: PROVIDER_PROOF_SOURCE_MANIFEST_SOURCE_PATHS,
});

export const PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS = frozenUtf8Sorted(
  Object.values(PROVIDER_PROOF_SOURCE_CLASSIFICATIONS).flat(),
);

export const PROVIDER_PROOF_ALGORITHM_ENTRYPOINT_PATHS = frozenUtf8Sorted([
  'assurance/provider-workforce-closure/authority-execution-hermeticity.mjs',
  'assurance/provider-workforce-closure/hermetic-cas.mjs',
  'assurance/provider-workforce-closure/materialisation-proof-attestation-verifier.mjs',
  MANIFEST_PATH,
  'assurance/provider-workforce-closure/provider-workforce-authority-projection.mjs',
  'assurance/provider-workforce-closure/provider-workforce-authority-proof.mjs',
  'processes/semantic-assurance/proof-currentness.mjs',
  PUBLICATION_ENTRYPOINT,
]);

export const PROVIDER_PROOF_SOURCE_MANIFEST = Object.freeze({
  schemaVersion: PROVIDER_PROOF_SOURCE_MANIFEST_SCHEMA_VERSION,
  entrypoints: PROVIDER_PROOF_ALGORITHM_ENTRYPOINT_PATHS,
  sources: PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
  subsets: PROVIDER_PROOF_SOURCE_CLASSIFICATIONS,
});

function exactArray(actual, expected, code) {
  if (
    !Array.isArray(actual)
    || actual.length !== expected.length
    || actual.some((value, index) => value !== expected[index])
  ) {
    throw new Error(code);
  }
}

function assertPlainObject(value, code) {
  if (
    !value
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(code);
  }
}

function exactKeys(value, expected, code) {
  assertPlainObject(value, code);
  exactArray(utf8Sorted(Object.keys(value)), utf8Sorted(expected), code);
}

function validateRepositoryPath(path, code = 'PROVIDER_PROOF_SOURCE_PATH_INVALID') {
  if (
    typeof path !== 'string'
    || path.length === 0
    || path.includes('\0')
    || path.includes('\\')
    || path.startsWith('/')
    || path.endsWith('/')
    || path !== posix.normalize(path)
    || path === '.'
    || path === '..'
    || path.startsWith('../')
    || path.includes('/../')
    || !path.endsWith('.mjs')
  ) {
    throw new Error(`${code}:${String(path)}`);
  }
  return path;
}

function validateTrackedRepositoryPath(
  path,
  code = 'PROVIDER_PROOF_TRACKED_SOURCE_PATHS_INVALID',
) {
  if (
    typeof path !== 'string'
    || path.length === 0
    || path.includes('\0')
    || path.includes('\\')
    || path.startsWith('/')
    || path.endsWith('/')
    || path !== posix.normalize(path)
    || path === '.'
    || path === '..'
    || path.startsWith('../')
    || path.includes('/../')
  ) {
    throw new Error(`${code}:${String(path)}`);
  }
  return path;
}

function assertUniqueSortedPaths(paths, code) {
  if (!Array.isArray(paths)) throw new Error(code);
  const validated = paths.map((path) => validateRepositoryPath(path, code));
  if (new Set(validated).size !== validated.length) throw new Error(`${code}:DUPLICATE`);
  exactArray(validated, utf8Sorted(validated), `${code}:NOT_UTF8_SORTED`);
  return validated;
}

function assertUniqueSortedTrackedPaths(paths, code) {
  if (!Array.isArray(paths)) throw new Error(code);
  const validated = paths.map((path) => validateTrackedRepositoryPath(path, code));
  if (new Set(validated).size !== validated.length) throw new Error(`${code}:DUPLICATE`);
  exactArray(validated, utf8Sorted(validated), `${code}:NOT_UTF8_SORTED`);
  return validated;
}

function validateManifestShape(manifest) {
  exactKeys(
    manifest,
    ['entrypoints', 'schemaVersion', 'sources', 'subsets'],
    'PROVIDER_PROOF_SOURCE_MANIFEST_SHAPE_INVALID',
  );
  if (manifest.schemaVersion !== PROVIDER_PROOF_SOURCE_MANIFEST_SCHEMA_VERSION) {
    throw new Error('PROVIDER_PROOF_SOURCE_MANIFEST_SCHEMA_UNSUPPORTED');
  }
  const sources = assertUniqueSortedPaths(
    manifest.sources,
    'PROVIDER_PROOF_SOURCE_MANIFEST_SOURCES_INVALID',
  );
  const entrypoints = assertUniqueSortedPaths(
    manifest.entrypoints,
    'PROVIDER_PROOF_SOURCE_MANIFEST_ENTRYPOINTS_INVALID',
  );
  exactArray(
    sources,
    PROVIDER_PROOF_ALGORITHM_SOURCE_PATHS,
    'PROVIDER_PROOF_SOURCE_MANIFEST_SOURCE_SET_MISMATCH',
  );
  exactArray(
    entrypoints,
    PROVIDER_PROOF_ALGORITHM_ENTRYPOINT_PATHS,
    'PROVIDER_PROOF_SOURCE_MANIFEST_ENTRYPOINT_SET_MISMATCH',
  );
  exactKeys(
    manifest.subsets,
    Object.keys(PROVIDER_PROOF_SOURCE_CLASSIFICATIONS),
    'PROVIDER_PROOF_SOURCE_MANIFEST_SUBSETS_INVALID',
  );
  const classified = [];
  for (const [classification, expectedPaths] of Object.entries(
    PROVIDER_PROOF_SOURCE_CLASSIFICATIONS,
  )) {
    const paths = assertUniqueSortedPaths(
      manifest.subsets[classification],
      `PROVIDER_PROOF_SOURCE_SUBSET_INVALID:${classification}`,
    );
    exactArray(
      paths,
      expectedPaths,
      `PROVIDER_PROOF_SOURCE_SUBSET_MISMATCH:${classification}`,
    );
    classified.push(...paths);
  }
  if (new Set(classified).size !== classified.length) {
    throw new Error('PROVIDER_PROOF_SOURCE_CLASSIFICATION_OVERLAP');
  }
  exactArray(
    utf8Sorted(classified),
    sources,
    'PROVIDER_PROOF_SOURCE_CLASSIFICATION_COVERAGE_MISMATCH',
  );
  exactArray(
    manifest.subsets.canonicalPublication,
    CANONICAL_PUBLICATION_SOURCE_PATHS,
    'CANONICAL_PUBLICATION_SOURCE_SUBSET_MISMATCH',
  );
  return { entrypoints, sources };
}

function skipTrivia(source, start) {
  let index = start;
  while (index < source.length) {
    const character = source[index];
    if (/\s/u.test(character)) {
      index += 1;
      continue;
    }
    if (source.startsWith('//', index)) {
      const newline = source.indexOf('\n', index + 2);
      return newline === -1 ? source.length : skipTrivia(source, newline + 1);
    }
    if (source.startsWith('/*', index)) {
      const end = source.indexOf('*/', index + 2);
      if (end === -1) throw new Error('PROVIDER_PROOF_SOURCE_UNTERMINATED_COMMENT');
      index = end + 2;
      continue;
    }
    break;
  }
  return index;
}

function readQuoted(source, start, sourcePath) {
  const quote = source[start];
  if (quote !== "'" && quote !== '"') return null;
  let value = '';
  for (let index = start + 1; index < source.length; index += 1) {
    const character = source[index];
    if (character === quote) return { end: index + 1, value };
    if (character === '\\') {
      throw new Error(`PROVIDER_PROOF_IMPORT_ESCAPE_UNSUPPORTED:${sourcePath}`);
    }
    if (character === '\n' || character === '\r') {
      throw new Error(`PROVIDER_PROOF_IMPORT_STRING_INVALID:${sourcePath}`);
    }
    value += character;
  }
  throw new Error(`PROVIDER_PROOF_IMPORT_STRING_UNTERMINATED:${sourcePath}`);
}

function skipQuotedString(source, start, sourcePath) {
  const quote = source[start];
  let escaped = false;
  for (let index = start + 1; index < source.length; index += 1) {
    const character = source[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      continue;
    }
    if (character === quote) return index + 1;
    if (character === '\n' || character === '\r') {
      throw new Error(`PROVIDER_PROOF_SOURCE_STRING_UNTERMINATED:${sourcePath}`);
    }
  }
  throw new Error(`PROVIDER_PROOF_SOURCE_STRING_UNTERMINATED:${sourcePath}`);
}

function canStartRegexAt(source, start) {
  let index = start - 1;
  while (index >= 0 && /\s/u.test(source[index])) index -= 1;
  if (index < 0) return true;
  if (source[index] === '}') return true;
  if (source[index] === ')') {
    let depth = 1;
    index -= 1;
    while (index >= 0 && depth > 0) {
      if (source[index] === ')') depth += 1;
      if (source[index] === '(') depth -= 1;
      index -= 1;
    }
    if (depth === 0) {
      while (index >= 0 && /\s/u.test(source[index])) index -= 1;
      const end = index + 1;
      while (index >= 0 && isIdentifierPart(source[index])) index -= 1;
      if (['catch', 'for', 'if', 'switch', 'while', 'with'].includes(
        source.slice(index + 1, end),
      )) {
        return true;
      }
    }
    return false;
  }
  if ('([{:;,=!?&|+-*%^~<>'.includes(source[index])) return true;
  let end = index + 1;
  while (index >= 0 && isIdentifierPart(source[index])) index -= 1;
  const previousWord = source.slice(index + 1, end);
  return [
    'await',
    'case',
    'delete',
    'do',
    'else',
    'in',
    'instanceof',
    'new',
    'return',
    'throw',
    'typeof',
    'void',
    'yield',
  ].includes(previousWord);
}

function skipRegexLiteral(source, start, sourcePath) {
  let escaped = false;
  let characterClass = false;
  for (let index = start + 1; index < source.length; index += 1) {
    const character = source[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      continue;
    }
    if (character === '\n' || character === '\r') {
      throw new Error(`PROVIDER_PROOF_SOURCE_REGEX_UNTERMINATED:${sourcePath}`);
    }
    if (character === '[') {
      characterClass = true;
      continue;
    }
    if (character === ']' && characterClass) {
      characterClass = false;
      continue;
    }
    if (character === '/' && !characterClass) {
      let end = index + 1;
      while (/[A-Za-z]/u.test(source[end] ?? '')) end += 1;
      return end;
    }
  }
  throw new Error(`PROVIDER_PROOF_SOURCE_REGEX_UNTERMINATED:${sourcePath}`);
}

function isIdentifierStart(character) {
  return character !== undefined && /[A-Za-z_$]/u.test(character);
}

function isIdentifierPart(character) {
  return character !== undefined && /[A-Za-z0-9_$]/u.test(character);
}

function readIdentifier(source, start) {
  let end = start + 1;
  while (isIdentifierPart(source[end])) end += 1;
  return { end, value: source.slice(start, end) };
}

function findFromSpecifier(source, start, sourcePath) {
  let index = start;
  while (index < source.length) {
    index = skipTrivia(source, index);
    const character = source[index];
    if (character === ';') return null;
    if (character === "'" || character === '"') {
      index = skipQuotedString(source, index, sourcePath);
      continue;
    }
    if (character === '`') throw new Error(`PROVIDER_PROOF_IMPORT_FROM_INVALID:${sourcePath}`);
    if (isIdentifierStart(character)) {
      const token = readIdentifier(source, index);
      if (token.value === 'from') {
        const quotedStart = skipTrivia(source, token.end);
        const quoted = readQuoted(source, quotedStart, sourcePath);
        if (!quoted) throw new Error(`PROVIDER_PROOF_IMPORT_FROM_INVALID:${sourcePath}`);
        return quoted;
      }
      index = token.end;
      continue;
    }
    index += 1;
  }
  return null;
}

function previousNonWhitespaceCharacter(source, start) {
  let index = start - 1;
  while (index >= 0 && /\s/u.test(source[index])) index -= 1;
  return index >= 0 ? source[index] : null;
}

function scanTemplateLiteral(source, start, sourcePath, imports) {
  let index = start + 1;
  while (index < source.length) {
    const character = source[index];
    if (character === '\\') {
      index += 2;
      continue;
    }
    if (character === '`') return index + 1;
    if (character === '$' && source[index + 1] === '{') {
      const expression = scanCode(source, sourcePath, {
        imports,
        start: index + 2,
        stopAtTemplateExpressionEnd: true,
      });
      index = expression.end;
      continue;
    }
    index += 1;
  }
  throw new Error(`PROVIDER_PROOF_SOURCE_TEMPLATE_UNTERMINATED:${sourcePath}`);
}

function scanCode(source, sourcePath, {
  imports,
  start = 0,
  stopAtTemplateExpressionEnd = false,
}) {
  let braceDepth = stopAtTemplateExpressionEnd ? 1 : 0;
  let index = start;
  while (index < source.length) {
    const character = source[index];
    if (source.startsWith('//', index) || source.startsWith('/*', index)) {
      index = skipTrivia(source, index);
      continue;
    }
    if (character === '/' && canStartRegexAt(source, index)) {
      index = skipRegexLiteral(source, index, sourcePath);
      continue;
    }
    if (character === "'" || character === '"') {
      index = skipQuotedString(source, index, sourcePath);
      continue;
    }
    if (character === '`') {
      index = scanTemplateLiteral(source, index, sourcePath, imports);
      continue;
    }
    if (stopAtTemplateExpressionEnd && character === '{') {
      braceDepth += 1;
      index += 1;
      continue;
    }
    if (stopAtTemplateExpressionEnd && character === '}') {
      braceDepth -= 1;
      index += 1;
      if (braceDepth === 0) return { end: index, imports };
      continue;
    }
    if (!isIdentifierStart(character)) {
      index += 1;
      continue;
    }
    const token = readIdentifier(source, index);
    if (token.value !== 'import' && token.value !== 'export') {
      index = token.end;
      continue;
    }
    if (
      token.value === 'import'
      && previousNonWhitespaceCharacter(source, index) === '.'
    ) {
      index = token.end;
      continue;
    }
    let cursor = skipTrivia(source, token.end);
    if (token.value === 'import' && source[cursor] === '.') {
      index = cursor + 1;
      continue;
    }
    if (token.value === 'import' && source[cursor] === '(') {
      cursor = skipTrivia(source, cursor + 1);
      const quoted = readQuoted(source, cursor, sourcePath);
      if (!quoted) {
        throw new Error(`PROVIDER_PROOF_DYNAMIC_IMPORT_NOT_LITERAL:${sourcePath}`);
      }
      const afterLiteral = skipTrivia(source, quoted.end);
      if (source[afterLiteral] !== ')' && source[afterLiteral] !== ',') {
        throw new Error(`PROVIDER_PROOF_DYNAMIC_IMPORT_NOT_LITERAL:${sourcePath}`);
      }
      imports.push({ kind: 'dynamic-import', specifier: quoted.value });
      index = quoted.end;
      continue;
    }
    const direct = readQuoted(source, cursor, sourcePath);
    if (direct) {
      imports.push({ kind: 'static-import', specifier: direct.value });
      index = direct.end;
      continue;
    }
    if (token.value === 'export' && source[cursor] !== '{' && source[cursor] !== '*') {
      index = token.end;
      continue;
    }
    const from = findFromSpecifier(source, cursor, sourcePath);
    if (from) {
      imports.push({
        kind: token.value === 'export' ? 'static-export' : 'static-import',
        specifier: from.value,
      });
      index = from.end;
      continue;
    }
    index = token.end;
  }
  if (stopAtTemplateExpressionEnd) {
    throw new Error(`PROVIDER_PROOF_SOURCE_TEMPLATE_EXPRESSION_UNTERMINATED:${sourcePath}`);
  }
  return { end: index, imports };
}

function scanModuleSpecifiers(source, sourcePath) {
  return scanCode(source, sourcePath, { imports: [] }).imports;
}

function resolveRelativeImport(importer, specifier) {
  if (!specifier.startsWith('./') && !specifier.startsWith('../')) return null;
  if (specifier.includes('?') || specifier.includes('#') || specifier.includes('\\')) {
    throw new Error(`PROVIDER_PROOF_RELATIVE_IMPORT_INVALID:${importer}:${specifier}`);
  }
  const resolved = posix.normalize(posix.join(posix.dirname(importer), specifier));
  validateRepositoryPath(resolved, 'PROVIDER_PROOF_RELATIVE_IMPORT_TRAVERSAL');
  return resolved;
}

function readExactRegularSource(repositoryRoot, path) {
  const root = resolve(repositoryRoot);
  const canonicalRoot = realpathSync(root);
  if (canonicalRoot !== root || !lstatSync(root).isDirectory()) {
    throw new Error('PROVIDER_PROOF_REPOSITORY_ROOT_INVALID');
  }
  let current = root;
  for (const segment of path.split('/')) {
    current = resolve(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) {
      throw new Error(`PROVIDER_PROOF_SOURCE_SYMLINK_REFUSED:${path}`);
    }
    if (current !== resolve(root, path) && !stat.isDirectory()) {
      throw new Error(`PROVIDER_PROOF_SOURCE_PARENT_INVALID:${path}`);
    }
  }
  const stat = lstatSync(current);
  if (!stat.isFile()) throw new Error(`PROVIDER_PROOF_SOURCE_NOT_REGULAR:${path}`);
  const bytes = readFileSync(current);
  let source;
  try {
    source = UTF8_DECODER.decode(bytes);
  } catch {
    throw new Error(`PROVIDER_PROOF_SOURCE_NOT_UTF8:${path}`);
  }
  return { bytes, source };
}

function closureFrom(entrypoints, importsByPath, sourceSet) {
  const visited = new Set();
  const pending = [...entrypoints].sort(utf8Compare);
  while (pending.length > 0) {
    const path = pending.shift();
    if (visited.has(path)) continue;
    if (!sourceSet.has(path)) {
      throw new Error(`PROVIDER_PROOF_ENTRYPOINT_NOT_DECLARED:${path}`);
    }
    visited.add(path);
    for (const target of importsByPath.get(path) ?? []) {
      if (!sourceSet.has(target)) {
        throw new Error(`PROVIDER_PROOF_RELATIVE_IMPORT_NOT_DECLARED:${path}:${target}`);
      }
      if (!visited.has(target)) pending.push(target);
    }
    pending.sort(utf8Compare);
  }
  return utf8Sorted(visited);
}

/**
 * Verifies the frozen provider proof algorithm source set against an exact
 * repository tree or snapshot. `trackedSourcePaths` must come from the
 * caller's independently verified signed-tree capture; this module never
 * treats a mutable Git index as evidence that a source is tracked. The
 * declared set is the exact union reachable from several declared
 * entrypoints; it is intentionally not represented as one import tree.
 */
export function verifyProviderProofSourceManifest({
  manifest = PROVIDER_PROOF_SOURCE_MANIFEST,
  repositoryRoot,
  trackedSourcePaths,
} = {}) {
  const { entrypoints, sources } = validateManifestShape(manifest);
  if (typeof repositoryRoot !== 'string' || repositoryRoot.length === 0) {
    throw new Error('PROVIDER_PROOF_REPOSITORY_ROOT_REQUIRED');
  }
  const tracked = assertUniqueSortedTrackedPaths(
    trackedSourcePaths,
    'PROVIDER_PROOF_TRACKED_SOURCE_PATHS_INVALID',
  );
  const trackedSet = new Set(tracked);
  const sourceSet = new Set(sources);
  const sourceRecords = [];
  const importEdges = [];
  const importsByPath = new Map();

  for (const path of sources) {
    if (!trackedSet.has(path)) throw new Error(`PROVIDER_PROOF_SOURCE_UNTRACKED:${path}`);
    let exact;
    try {
      exact = readExactRegularSource(repositoryRoot, path);
    } catch (error) {
      if (error?.code === 'ENOENT') throw new Error(`PROVIDER_PROOF_SOURCE_MISSING:${path}`);
      throw error;
    }
    const relativeTargets = [];
    const imports = scanModuleSpecifiers(exact.source, path);
    for (const item of imports) {
      const target = resolveRelativeImport(path, item.specifier);
      if (target === null) continue;
      relativeTargets.push(target);
      importEdges.push(Object.freeze({
        from: path,
        kind: item.kind,
        to: target,
      }));
    }
    const uniqueTargets = utf8Sorted(new Set(relativeTargets));
    importsByPath.set(path, uniqueTargets);
    sourceRecords.push(Object.freeze({
      byteSize: exact.bytes.length,
      digest: sha256(exact.bytes),
      path,
    }));
  }

  importEdges.sort((left, right) => utf8Compare(
    `${left.from}\0${left.to}\0${left.kind}`,
    `${right.from}\0${right.to}\0${right.kind}`,
  ));
  const reachableSourcePaths = closureFrom(entrypoints, importsByPath, sourceSet);
  exactArray(
    reachableSourcePaths,
    sources,
    'PROVIDER_PROOF_DECLARED_SOURCE_NOT_REACHABLE_FROM_DECLARED_ENTRYPOINTS',
  );
  const sourceRecordByPath = new Map(sourceRecords.map((record) => [record.path, record]));
  const entrypointClosures = entrypoints.map((entrypoint) => {
    const sourcePaths = closureFrom([entrypoint], importsByPath, sourceSet);
    const records = sourcePaths.map((path) => sourceRecordByPath.get(path));
    return Object.freeze({
      entrypoint,
      sourceCount: records.length,
      sourcePaths: Object.freeze(sourcePaths),
      sourceSetDigest: sha256(Buffer.from(canonicalJson(records), 'utf8')),
    });
  });
  const publicationClosure = closureFrom(
    [PUBLICATION_ENTRYPOINT],
    importsByPath,
    sourceSet,
  );
  exactArray(
    publicationClosure,
    CANONICAL_PUBLICATION_SOURCE_PATHS,
    'CANONICAL_PUBLICATION_IMPORT_CLOSURE_MISMATCH',
  );
  const publicationSet = new Set(CANONICAL_PUBLICATION_SOURCE_PATHS);
  const publicationSourceRecords = sourceRecords.filter(({ path }) => publicationSet.has(path));
  const sourceSetDigest = sha256(Buffer.from(canonicalJson(sourceRecords), 'utf8'));
  const publicationSourceSetDigest = sha256(
    Buffer.from(canonicalJson(publicationSourceRecords), 'utf8'),
  );
  const firstPartyImportEdgeSetDigest = sha256(
    Buffer.from(canonicalJson(importEdges), 'utf8'),
  );
  const entrypointClosureSetDigest = sha256(
    Buffer.from(canonicalJson(entrypointClosures), 'utf8'),
  );
  const manifestDigest = sha256(Buffer.from(canonicalJson(manifest), 'utf8'));
  if (
    !SHA256.test(sourceSetDigest)
    || !SHA256.test(publicationSourceSetDigest)
    || !SHA256.test(firstPartyImportEdgeSetDigest)
    || !SHA256.test(entrypointClosureSetDigest)
    || !SHA256.test(manifestDigest)
  ) {
    throw new Error('PROVIDER_PROOF_SOURCE_MANIFEST_DIGEST_INVALID');
  }
  return Object.freeze({
    declaredEntrypoints: Object.freeze([...entrypoints]),
    declaredSourceCount: sourceRecords.length,
    declaredSourceRecords: Object.freeze(sourceRecords),
    declaredSourceSetDigest: sourceSetDigest,
    entrypointClosureCount: entrypointClosures.length,
    entrypointClosures: Object.freeze(entrypointClosures),
    entrypointClosureSetDigest,
    firstPartyImportEdgeCount: importEdges.length,
    firstPartyImportEdges: Object.freeze(importEdges),
    firstPartyImportEdgeSetDigest,
    manifestDigest,
    publicationEntrypoint: PUBLICATION_ENTRYPOINT,
    publicationReachableSourcePaths: Object.freeze(publicationClosure),
    publicationSourceCount: publicationSourceRecords.length,
    publicationSourceRecords: Object.freeze(publicationSourceRecords),
    publicationSourceSetDigest,
    reachableSourceCount: reachableSourcePaths.length,
    reachableSourcePaths: Object.freeze(reachableSourcePaths),
    schemaVersion: PROVIDER_PROOF_SOURCE_MANIFEST_SCHEMA_VERSION,
  });
}
