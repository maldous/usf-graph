import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareBy, readJsonl, sha256, sortUnique, writeJsonAtomic, writeJsonlAtomic } from './canonical.mjs';
import { censusRoot, repositoryRoot } from './constants.mjs';
import { assertUnique, validateInventory, validateRelationship } from './contract.mjs';

const confidence = {
  high: { level: 'high', score: 1, reasons: ['machine-verifiable-extraction'] },
  medium: { level: 'medium', score: 0.7, reasons: ['bounded-lexical-extraction'] },
  low: { level: 'low', score: 0.4, reasons: ['ambiguous-reference-shape'] }
};

function memberRecords() {
  return ['repository-universe.jsonl', 'v2-graph-universe.jsonl', 'v2-compiler-universe.jsonl', 'v2-support-universe.jsonl']
    .flatMap((file) => readJsonl(path.join(censusRoot, file)));
}

function safeText(member) {
  if (member.binary || member.formatKind === 'symbolic-link' || member.formatKind === 'gitlink' || member.sourceState === 'deleted') return null;
  const absolute = path.join(repositoryRoot, member.path);
  try {
    return fs.readFileSync(absolute, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function looksPathLike(value) {
  return typeof value === 'string' && value.length > 0 && value.length < 512 &&
    !value.includes('\n') && (/^(?:\.\.?\/|[a-zA-Z0-9_.-]+\/)/.test(value) || /\.(?:json|jsonl|ya?ml|md|js|mjs|cjs|ts|tsx|jsx|py|sh|sql|ttl|trig|rq|toml|xml|svg|png|jpg|jpeg|gif|webp|css|html|lock)$/i.test(value));
}

function extensionCandidates(value) {
  if (path.posix.extname(value)) return [value];
  return [value, `${value}.js`, `${value}.mjs`, `${value}.cjs`, `${value}.ts`, `${value}.json`, `${value}.yaml`, `${value}.yml`, `${value}/index.js`, `${value}/index.mjs`, `${value}/package.json`];
}

function resolveArtifactTarget(source, target, pathSet) {
  const clean = target.split('#')[0].split('?')[0];
  if (!clean) return { target, resolved: true };
  if (/^(?:https?:|urn:|mailto:|data:|node:)/.test(clean) || clean.startsWith('@')) return { target, resolved: true };
  if (clean.startsWith('/')) {
    const chrootCandidate = `v2${clean}`;
    for (const candidate of extensionCandidates(chrootCandidate)) if (pathSet.has(candidate)) return { target: candidate, resolved: true };
  }
  const base = clean.startsWith('/') ? clean.slice(1) : path.posix.normalize(path.posix.join(path.posix.dirname(source), clean));
  for (const candidate of extensionCandidates(base)) if (pathSet.has(candidate)) return { target: candidate, resolved: true };
  for (const candidate of extensionCandidates(clean.replace(/^\.\//, ''))) if (pathSet.has(candidate)) return { target: candidate, resolved: true };
  return { target: clean, resolved: false };
}

function relation(type, target, targetKind, method, level = 'high') {
  return { relationshipType: type, target, targetKind, extractionMethod: method, confidence: confidence[level] };
}

function extractJson(value) {
  const relations = [];
  const declarations = [];
  const paths = [];
  const ids = [];
  const visit = (item, key = '', depth = 0) => {
    if (depth > 20) return;
    if (Array.isArray(item)) {
      item.forEach((entry) => visit(entry, key, depth + 1));
      return;
    }
    if (!item || typeof item !== 'object') {
      if (typeof item !== 'string') return;
      if (/^(?:id|name|key|identifier|graph|output|event|command)$/i.test(key) && item.length < 256) ids.push(item);
      if (looksPathLike(item)) paths.push(item);
      return;
    }
    for (const [childKey, child] of Object.entries(item)) {
      if (/^(?:dependencies|devDependencies|peerDependencies|optionalDependencies)$/i.test(childKey) && child && typeof child === 'object' && !Array.isArray(child)) {
        for (const dependency of Object.keys(child)) relations.push(relation('depends-on', dependency, 'package', 'json-dependency-map'));
      }
      if (childKey === 'scripts' && child && typeof child === 'object' && !Array.isArray(child)) {
        for (const [command, invocation] of Object.entries(child)) {
          declarations.push(`command:${command}`);
          relations.push(relation('invokes', String(invocation).split(/\s+/)[0], 'command', 'json-command-map', 'medium'));
        }
      }
      if (/^(?:file|path|source|target|input|output|schema|extends|include|asset|document)$/i.test(childKey) && typeof child === 'string') paths.push(child);
      visit(child, childKey, depth + 1);
    }
  };
  visit(value);
  return { relations, declarations: sortUnique([...declarations, ...ids.map((id) => `entity:${id}`)]).slice(0, 5000), paths: sortUnique(paths).slice(0, 5000) };
}

export function inventoryKind(value, member, extracted) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const keys = new Set(Object.keys(value));
    if (keys.has('$schema') && (keys.has('properties') || keys.has('$defs'))) return 'schema-definition';
    if (keys.has('name') && (keys.has('scripts') || keys.has('dependencies') || keys.has('workspaces'))) return 'package-manifest';
    if (keys.has('jobs') && (keys.has('on') || keys.has('name'))) return 'workflow-definition';
    if (keys.has('closureStatus') || keys.has('closure')) return 'closure-record';
    if ([...keys].some((key) => /readiness/i.test(key))) return 'readiness-record';
    if ([...keys].some((key) => /evidence/i.test(key)) && [...keys].some((key) => /index|manifest|items|records/i.test(key))) return 'evidence-index';
    if ([...keys].some((key) => /authorit|governance|nonClaims/i.test(key))) return 'governance-record';
    if ([...keys].some((key) => /dependenc/i.test(key))) return 'dependency-record';
    const arrays = Object.values(value).filter(Array.isArray);
    if (arrays.some((array) => array.some((entry) => entry && typeof entry === 'object' && ('source' in entry || 'target' in entry || 'from' in entry || 'to' in entry)))) return 'relationship-collection';
    if (arrays.some((array) => array.some((entry) => entry && typeof entry === 'object'))) return 'entity-collection';
    if (Object.values(value).filter((entry) => entry && typeof entry === 'object').length >= 2) return 'keyed-map';
  }
  if (Array.isArray(value) && value.some((entry) => entry && typeof entry === 'object')) return 'entity-collection';
  if (member.formatKind === 'structured-yaml' && /manifest/i.test(member.path)) return 'graph-manifest';
  if (extracted.paths.length > 1 && extracted.declarations.length > 1) return 'relationship-collection';
  return null;
}

function extractText(text, member) {
  const relations = [];
  const declarations = [];
  const addMatches = (regex, type, kind, method, group = 1, level = 'high') => {
    for (const match of text.matchAll(regex)) relations.push(relation(type, match[group], kind, method, level));
  };
  addMatches(/\b(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g, 'imports', 'artifact', 'ecmascript-import');
  addMatches(/\brequire\(\s*['"]([^'"]+)['"]\s*\)/g, 'imports', 'artifact', 'commonjs-require');
  addMatches(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g, 'imports', 'artifact', 'dynamic-import');
  addMatches(/\[[^\]]*\]\(([^)\s]+)(?:\s+['"][^'"]*['"])?\)/g, 'references', 'artifact', 'markdown-link', 1, 'medium');
  addMatches(/^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*([^\s]+)\s+/gmi, 'copies', 'artifact', 'container-copy');
  addMatches(/^\s*FROM\s+([^\s]+)/gmi, 'depends-on', 'external-resource', 'container-base-image');
  addMatches(/^\s*uses:\s*['"]?([^'"\s]+)['"]?/gmi, 'uses-action', 'external-resource', 'workflow-uses');
  addMatches(/^\s*needs:\s*['"]?([^'"\s[\],]+)['"]?/gmi, 'needs', 'command', 'workflow-needs', 1, 'medium');
  addMatches(/^\s*(?:-\s*)?file:\s*['"]?([^'"\s]+)['"]?/gmi, 'references', 'artifact', 'structured-file-field');
  addMatches(/^\s*(?:-\s*)?(?:input|source):\s*['"]?([^'"\s]+)['"]?/gmi, 'consumes', 'artifact', 'structured-input-field');
  addMatches(/^\s*(?:-\s*)?output:\s*['"]?([^'"\s]+)['"]?/gmi, 'produces', 'semantic-entity', 'structured-output-field');
  addMatches(/\b(?:sourceMappingURL|href|src)=['"]([^'"]+)['"]/gi, 'references', 'artifact', 'document-asset-reference', 1, 'medium');
  addMatches(/\b(?:validate|test|proof|collect|generate|render|materiali[sz]e)[-_a-zA-Z0-9./]*\b/g, 'invokes', 'command', 'command-verb-reference', 0, 'low');

  if (member.formatKind === 'rdf-turtle' || member.formatKind === 'rdf-trig') {
    for (const match of text.matchAll(/^\s*([A-Za-z][\w-]*:[A-Za-z][\w.-]*)\s+(?:a|rdf:type)\s+/gm)) declarations.push(`semantic:${match[1]}`);
    addMatches(/<((?:urn|https?):[^>]+)>/g, 'references', 'semantic-entity', 'rdf-iri', 1, 'medium');
  }
  if (member.formatKind === 'sparql-query') {
    addMatches(/\b(?:GRAPH|FROM|INTO)\s*<([^>]+)>/gi, 'references', 'semantic-entity', 'sparql-graph-reference');
  }
  if (path.posix.basename(member.path).toLowerCase() === 'makefile' || member.path.endsWith('.mk')) {
    for (const match of text.matchAll(/^([A-Za-z0-9_.%/-]+)\s*:\s*([^=\n]*)$/gm)) {
      declarations.push(`command:${match[1]}`);
      for (const dependency of match[2].trim().split(/\s+/).filter(Boolean)) relations.push(relation('needs', dependency, 'command', 'make-prerequisite'));
    }
  }
  if (member.formatKind === 'source-shell') {
    addMatches(/(?:^|\s)(\.?\.?\/[A-Za-z0-9_./-]+\.(?:sh|js|mjs|py))(?:\s|$)/gm, 'invokes', 'artifact', 'shell-script-invocation', 1, 'medium');
  }
  return { relations, declarations: sortUnique(declarations).slice(0, 5000), paths: [] };
}

function parseDescriptor(member, text) {
  const textExtraction = extractText(text, member);
  if (member.formatKind === 'structured-json') {
    try {
      const value = JSON.parse(text);
      const jsonExtraction = extractJson(value);
      const merged = {
        relations: [...textExtraction.relations, ...jsonExtraction.relations],
        declarations: sortUnique([...textExtraction.declarations, ...jsonExtraction.declarations]),
        paths: jsonExtraction.paths
      };
      return { ...merged, inventoryKind: inventoryKind(value, member, merged), parseStatus: 'parsed-json' };
    } catch {
      return { ...textExtraction, inventoryKind: null, parseStatus: 'invalid-json' };
    }
  }
  if (member.formatKind === 'structured-yaml') {
    const pathValues = [...text.matchAll(/^\s*(?:-\s*)?(?:file|path|source|target|input):\s*['"]?([^'"\s]+)['"]?/gmi)].map((match) => match[1]);
    const declarations = [...text.matchAll(/^\s*(?:id|name|graph|database):\s*['"]?([^'"\n]+?)['"]?\s*$/gmi)].map((match) => `entity:${match[1]}`);
    const merged = { relations: textExtraction.relations, declarations: sortUnique([...textExtraction.declarations, ...declarations]), paths: sortUnique(pathValues) };
    return { ...merged, inventoryKind: inventoryKind(null, member, merged), parseStatus: 'parsed-yaml-lexically' };
  }
  return { ...textExtraction, inventoryKind: null, parseStatus: 'parsed-text' };
}

function inventoryRecord(member, descriptor, pathSet) {
  const missing = descriptor.paths.filter((target) => !resolveArtifactTarget(member.path, target, pathSet).resolved);
  const findings = missing.map((target) => ({ findingKind: 'missing-declaration', subject: target, detailCode: 'declared-path-not-observed' }));
  const record = {
    path: member.path,
    inventoryKind: descriptor.inventoryKind,
    scope: member.universe,
    declarations: descriptor.declarations,
    relationships: descriptor.paths,
    actualMatches: descriptor.paths.length - missing.length,
    missingDeclarations: missing,
    extraDeclarations: [],
    contradictions: [],
    ambiguities: [],
    authorityAssessment: member.universe === 'v2-graph-authority' ? 'normative-input' : 'cross-check-required',
    findings,
    confidence: confidence.high
  };
  validateInventory(record);
  return record;
}

function addManifestFindings(members, inventories, findings) {
  const manifest = inventories.find((record) => record.path === 'v2/usf/graph/manifest.yaml');
  if (!manifest) return;
  const graphPaths = new Set(members.filter((member) => member.universe === 'v2-graph-authority').map((member) => member.path));
  const registered = new Set(manifest.relationships.map((value) => path.posix.join('v2/usf/graph', value)));
  for (const target of registered) {
    if (!graphPaths.has(target)) findings.push({ source: manifest.path, findingKind: 'missing-target', subject: target, detailCode: 'graph-manifest-registration-missing', bounded: true, relationshipKey: null });
  }
  for (const member of graphPaths) {
    if (member === manifest.path || member.includes('/fixtures/') || registered.has(member)) continue;
    if (/\.(?:ttl|trig|rq)$/.test(member)) findings.push({ source: manifest.path, findingKind: 'extra-declaration', subject: member, detailCode: 'semantic-graph-file-unregistered', bounded: true, relationshipKey: null });
  }
}

export function addCrossArtifactFindings(members, relationships, findings = []) {
  const bySource = new Map();
  for (const relationship of relationships) {
    if (!bySource.has(relationship.source)) bySource.set(relationship.source, []);
    bySource.get(relationship.source).push(relationship);
  }
  const checks = [
    { pattern: /(?:^|\/)(?:generate|generator)[-_/.]/i, types: ['generates', 'produces'], detailCode: 'generator-output-not-linked' },
    { pattern: /(?:^|\/)(?:validate|validator)[-_/.]/i, types: ['validates', 'uses-fixture', 'tests'], detailCode: 'validator-rule-or-fixture-not-linked' },
    { pattern: /(?:^|\/)(?:proof|proofs)[-_/.]/i, types: ['proves'], detailCode: 'proof-obligation-not-linked' },
    { pattern: /(?:^|\/)(?:evidence|collector)[-_/.]/i, types: ['collects', 'ingests', 'normalises'], detailCode: 'evidence-collector-or-ingestion-not-linked' },
    { pattern: /checksum|sha256|integrity/i, types: ['checksums', 'protects', 'consumes'], detailCode: 'integrity-protected-input-not-linked' }
  ];
  for (const member of members) {
    const observed = bySource.get(member.path) ?? [];
    for (const check of checks) {
      if (!check.pattern.test(member.path) || observed.some((relationship) => check.types.includes(relationship.relationshipType))) continue;
      findings.push({ source: member.path, findingKind: 'missing-declaration', subject: member.path, detailCode: check.detailCode, bounded: true, relationshipKey: null });
    }
  }

  const support = members.filter((member) => member.universe === 'v2-support-provisioning').sort(compareBy(['path']));
  const anchor = support[0]?.path;
  if (!anchor) return findings;
  const supportRelationships = relationships.filter((relationship) => relationship.source.startsWith('v2/') &&
    !relationship.source.startsWith('v2/usf/graph/') && !relationship.source.startsWith('v2/usf/compiler/'));
  const requiredLinks = [
    { pattern: /v2\/usf\/compiler|compiler/i, subject: 'v2/usf/compiler', detailCode: 'support-compiler-invocation-not-observed' },
    { pattern: /\.github|workflow|automation/i, subject: 'repository-automation', detailCode: 'support-repository-automation-link-not-observed' },
    { pattern: /clean[- ]?room/i, subject: 'clean-room-generation', detailCode: 'support-clean-room-generation-link-not-observed' }
  ];
  for (const required of requiredLinks) {
    if (supportRelationships.some((relationship) => required.pattern.test(`${relationship.target} ${relationship.source}`))) continue;
    findings.push({ source: anchor, findingKind: 'missing-declaration', subject: required.subject, detailCode: required.detailCode, bounded: true, relationshipKey: null });
  }
  return findings;
}

export function buildIndex(members = memberRecords()) {
  const pathSet = new Set(members.map((member) => member.path));
  const cache = new Map();
  const relationships = [];
  const inventories = [];
  const findings = [];
  let textualInspected = 0;
  let binaryRepresented = 0;

  for (const member of members) {
    const text = safeText(member);
    if (text === null) {
      binaryRepresented += 1;
      continue;
    }
    textualInspected += 1;
    let descriptor = cache.get(member.contentDigest);
    if (!descriptor) {
      descriptor = parseDescriptor(member, text);
      cache.set(member.contentDigest, descriptor);
    }
    for (const raw of descriptor.relations) {
      const abstract = raw.targetKind !== 'artifact' || !looksPathLike(raw.target);
      const resolvedTarget = abstract ? { target: raw.target, resolved: true } : resolveArtifactTarget(member.path, raw.target, pathSet);
      const record = {
        source: member.path,
        relationshipType: raw.relationshipType,
        target: resolvedTarget.target,
        targetKind: raw.targetKind,
        extractionMethod: raw.extractionMethod,
        confidence: raw.confidence,
        resolved: resolvedTarget.resolved,
        reasonCodes: [resolvedTarget.resolved ? 'declared-relationship' : 'unresolved-target-finding']
      };
      validateRelationship(record);
      relationships.push(record);
      if (!record.resolved) findings.push({
        source: member.path,
        findingKind: 'missing-target',
        subject: record.target,
        detailCode: 'relationship-target-not-observed',
        bounded: true,
        relationshipKey: sha256(`${record.source}\0${record.relationshipType}\0${record.target}`)
      });
    }
    if (descriptor.inventoryKind) inventories.push(inventoryRecord(member, descriptor, pathSet));
  }

  const uniqueRelationships = [...new Map(relationships.map((record) => [
    [record.source, record.relationshipType, record.target, record.targetKind, record.extractionMethod].join('\0'), record
  ])).values()].sort(compareBy(['source', 'relationshipType', 'target', 'targetKind', 'extractionMethod']));
  const uniqueInventories = [...new Map(inventories.map((record) => [record.path, record])).values()].sort(compareBy(['path']));
  addManifestFindings(members, uniqueInventories, findings);
  addCrossArtifactFindings(members, uniqueRelationships, findings);
  const uniqueFindings = [...new Map(findings.map((record) => [[record.source, record.findingKind, record.subject, record.detailCode].join('\0'), record])).values()]
    .sort(compareBy(['source', 'findingKind', 'subject', 'detailCode']));
  assertUnique(uniqueInventories, 'path');
  return {
    relationships: uniqueRelationships,
    inventories: uniqueInventories,
    findings: uniqueFindings,
    summary: {
      consideredArtifactCount: members.length,
      textualInspectedCount: textualInspected,
      binaryOrStaticRepresentedCount: binaryRepresented,
      uniqueContentParseCount: cache.size,
      relationshipCount: uniqueRelationships.length,
      resolvedRelationshipCount: uniqueRelationships.filter((record) => record.resolved).length,
      boundedRelationshipFindingCount: uniqueFindings.filter((record) => record.detailCode === 'relationship-target-not-observed').length,
      inventoryCount: uniqueInventories.length,
      inventoryFindingCount: uniqueInventories.reduce((sum, record) => sum + record.findings.length, 0),
      manifestFindingCount: uniqueFindings.filter((record) => record.detailCode.includes('manifest') || record.detailCode.includes('unregistered')).length,
      unsupportedFormatCount: 0,
      unrepresentedArtifactCount: members.length - textualInspected - binaryRepresented,
      closureStatus: members.length === textualInspected + binaryRepresented ? 'complete' : 'incomplete'
    }
  };
}

export function writeIndexOutputs(index) {
  writeJsonlAtomic(path.join(censusRoot, 'references.jsonl'), index.relationships);
  writeJsonlAtomic(path.join(censusRoot, 'inventories.jsonl'), index.inventories);
  writeJsonlAtomic(path.join(censusRoot, 'reference-findings.jsonl'), index.findings);
  writeJsonAtomic(path.join(censusRoot, 'reference-summary.json'), index.summary);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const index = buildIndex();
  writeIndexOutputs(index);
  process.stdout.write(`${JSON.stringify(index.summary)}\n`);
}
