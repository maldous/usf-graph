import fs from 'node:fs';
import path from 'node:path';
import { compareBy, sha256, sortUnique } from '../canonical.mjs';
import { repositoryRoot } from '../constants.mjs';
import { validateConfidence, validateParserResult } from '../contract.mjs';

const binaryKinds = new Set(['archive', 'font', 'image-raster', 'opaque-binary']);
const linkKinds = new Set(['gitlink', 'symbolic-link']);
const coordinationMetadata = /linearissue|linearproject|agentmetadata|gitbranch|gitcommit|USF-\d+|\/home\/[^/]+/i;

function containsCoordinationMetadata(value) {
  if (typeof value === 'string') return coordinationMetadata.test(value);
  if (Array.isArray(value)) return value.some(containsCoordinationMetadata);
  return Boolean(value && typeof value === 'object' && Object.entries(value).some(([key, item]) => coordinationMetadata.test(key) || containsCoordinationMetadata(item)));
}

function sanitizeParsed(member, parsed) {
  if (['AGENTS.md', 'CODEX.md', 'CLAUDE.md'].includes(path.posix.basename(member.path))) {
    const declaration = { kind: 'governance-directive', identifier: member.path, attributes: { contentExcluded: true } };
    return { ...parsed, declarations: [declaration], relationships: [], inventory: { inventoryKind: 'entity-collection', scope: member.path, declarations: [declaration], relationships: [], completenessClaims: ['directive-content-intentionally-excluded'], authorityAssessment: 'execution-directive-not-semantic-authority' } };
  }
  // Graph parsing is also the census' independent observation boundary.  It
  // must retain every RDF statement so contamination checks and
  // source-observation reconciliation see the dataset that is actually on
  // disk.  Filtering an observed path merely because the historical filename
  // contains coordination-looking text silently manufactures missing and
  // orphan observations.
  if (member.universe === 'v2-graph-authority') return parsed;
  const declarations = (parsed.declarations ?? []).filter((entry) => !containsCoordinationMetadata(entry));
  const relationships = (parsed.relationships ?? []).filter((entry) => !containsCoordinationMetadata(entry));
  const inventory = parsed.inventory ? { ...parsed.inventory, declarations: (parsed.inventory.declarations ?? declarations).filter((entry) => !containsCoordinationMetadata(entry)), relationships: (parsed.inventory.relationships ?? relationships).filter((entry) => !containsCoordinationMetadata(entry)) } : null;
  return { ...parsed, declarations, relationships, inventory };
}

function readText(member) {
  if (member.binary || binaryKinds.has(member.formatKind) || linkKinds.has(member.formatKind) || member.sourceState === 'deleted') return null;
  try {
    return fs.readFileSync(path.join(repositoryRoot, member.path), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function sniffSyntax(member, text) {
  const basename = path.posix.basename(member.path).toLowerCase();
  const lower = member.path.toLowerCase();
  if (binaryKinds.has(member.formatKind)) return 'binary';
  if (linkKinds.has(member.formatKind)) return 'link';
  if (member.formatKind === 'structured-json') {
    if (text?.includes('"$schema"') || text?.includes('"openapi"') || text?.includes('"asyncapi"')) return 'json-schema';
    return 'structured-json';
  }
  if (member.formatKind === 'data-jsonl') return 'data-jsonl';
  if (member.formatKind === 'structured-yaml') return /(?:^|\/)compose(?:[.-]|$)/.test(lower) ? 'compose-yaml' : /(?:^|\/)\.github\/workflows\//.test(lower) ? 'workflow-yaml' : 'yaml';
  if (member.formatKind === 'rdf-turtle' || member.formatKind === 'rdf-trig') return member.formatKind;
  if (member.formatKind === 'sparql-query') return 'sparql';
  if (member.formatKind === 'structured-toml') return 'toml';
  if (member.formatKind === 'structured-xml') return 'xml';
  if (member.formatKind === 'data-csv') return 'csv';
  if (member.formatKind === 'document-markdown') return 'markdown';
  if (member.formatKind === 'source-sql') return 'sql';
  if (member.formatKind === 'source-shell') return 'shell';
  if (basename === 'makefile' || lower.endsWith('.mk')) return 'make';
  if (basename === 'dockerfile' || /^dockerfile[.-]/.test(basename)) return 'dockerfile';
  if (/\.(?:graphql|gql)$/.test(lower)) return 'graphql';
  if (/\.(?:js|mjs|cjs|ts|mts|cts|tsx|jsx)$/.test(lower)) return 'javascript-typescript';
  if (/\.py$/.test(lower)) return 'python';
  if (member.formatKind === 'configuration-text') return 'configuration';
  if (member.formatKind === 'document-html') return 'html';
  if (member.formatKind === 'image-vector') return 'svg';
  if (member.formatKind === 'source-css') return 'css';
  if (member.formatKind === 'certificate') return 'certificate';
  if (member.formatKind === 'git-lfs-pointer') return 'git-lfs-pointer';
  if (text && /^\s*[[{]/.test(text)) {
    try {
      JSON.parse(text);
      return 'structured-json';
    } catch { /* not JSON: fall through to plain text */ }
  }
  return 'plain-text';
}

function pathContext(member, syntaxKind) {
  const lower = member.path.toLowerCase();
  if (syntaxKind === 'workflow-yaml') return 'workflow';
  if (syntaxKind === 'compose-yaml') return 'compose';
  if (lower.includes('/fixtures/') || lower.includes('/test/') || lower.includes('/tests/')) return 'fixture-or-test';
  if (lower.includes('manifest') || lower.includes('registry') || lower.includes('catalog')) return 'declared-inventory';
  if (lower.includes('schema') || lower.includes('openapi') || lower.includes('asyncapi')) return 'schema-or-interface';
  if (lower.startsWith('v2/usf/graph/')) return 'graph-authority';
  return 'ordinary';
}

function metadataResult(member, syntaxKind, mode, implementation) {
  return {
    path: member.path,
    universe: member.universe,
    contentDigest: member.contentDigest,
    formatKind: member.formatKind,
    syntaxKind,
    parserMode: mode,
    parserImplementation: implementation,
    parserVersion: '1',
    pathContext: pathContext(member, syntaxKind),
    cacheKey: sha256([member.contentDigest, syntaxKind, mode, pathContext(member, syntaxKind), member.path].join('\0')),
    structuralCoverage: 'not-applicable',
    unsupportedStructures: [],
    confidence: { level: 'high', score: 1, reasons: ['structural-parser-evidence'] },
    declarations: [],
    relationships: [],
    inventory: null
  };
}

export function createParserRegistry(implementations) {
  const ids = new Set();
  for (const implementation of implementations) {
    if (!implementation?.id || !implementation?.version || typeof implementation.supports !== 'function' || typeof implementation.parse !== 'function') {
      throw new Error('invalid parser implementation contract');
    }
    if (ids.has(implementation.id)) throw new Error(`duplicate parser implementation: ${implementation.id}`);
    ids.add(implementation.id);
  }
  return implementations.slice().sort((a, b) => a.id.localeCompare(b.id));
}

export function parseMembers(members, implementations) {
  const registry = createParserRegistry(implementations);
  const cache = new Map();
  const results = [];
  for (const member of members) {
    const text = readText(member);
    const syntaxKind = sniffSyntax(member, text);
    if (binaryKinds.has(member.formatKind)) {
      const result = metadataResult(member, syntaxKind, 'binary-metadata', 'builtin-binary-metadata');
      validateParserResult(result);
      results.push(result);
      continue;
    }
    if (linkKinds.has(member.formatKind)) {
      const result = metadataResult(member, syntaxKind, member.formatKind === 'gitlink' ? 'git-object-metadata' : 'link-metadata', 'builtin-link-metadata');
      validateParserResult(result);
      results.push(result);
      continue;
    }
    const context = { member, text: text ?? '', syntaxKind, pathContext: pathContext(member, syntaxKind) };
    const parser = registry.find((candidate) => candidate.supports(context));
    if (!parser) throw new Error(`unsupported parser format: ${member.path} (${syntaxKind})`);
    const parserMode = parser.mode ?? 'structural';
    const cacheKey = sha256([member.contentDigest, syntaxKind, parserMode, context.pathContext, member.path].join('\0'));
    let parsed = cache.get(cacheKey);
    if (!parsed) {
      parsed = sanitizeParsed(member, parser.parse(context));
      cache.set(cacheKey, parsed);
    }
    const result = {
      path: member.path,
      universe: member.universe,
      contentDigest: member.contentDigest,
      formatKind: member.formatKind,
      syntaxKind,
      parserMode,
      parserImplementation: parser.id,
      parserVersion: parser.version,
      pathContext: context.pathContext,
      cacheKey,
      structuralCoverage: parsed.structuralCoverage,
      unsupportedStructures: sortUnique(parsed.unsupportedStructures ?? []),
      confidence: parsed.confidence,
      declarations: parsed.declarations ?? [],
      relationships: parsed.relationships ?? [],
      inventory: parsed.inventory ?? null
    };
    validateConfidence(result.confidence);
    validateParserResult(result);
    results.push(result);
  }
  return results.sort(compareBy(['universe', 'path']));
}

export const parserInternals = { pathContext, sanitizeParsed, sniffSyntax };
