import { X509Certificate } from 'node:crypto';
import { SaxesParser } from 'saxes';
import { parse as parseSqlCst } from 'sql-parser-cst';
import { parse as parseToml } from 'smol-toml';
import { isAlias, isMap, isPair, isScalar, isSeq, parseAllDocuments, visit } from 'yaml';
import {
  confidence,
  declaration,
  inventory,
  pathLike,
  relationship,
  result,
  walkObject
} from './shared.mjs';

const STRUCTURED_SYNTAXES = new Set(['structured-json', 'data-jsonl', 'json-schema', 'yaml', 'compose-yaml', 'workflow-yaml', 'toml', 'xml', 'csv', 'svg', 'certificate', 'git-lfs-pointer']);
const BOUNDED_COMMAND_SYNTAXES = new Set(['make', 'shell']);
const BOUNDED_SYNTAXES = new Set(['markdown', 'configuration', 'html', 'css', 'plain-text']);
const STRUCTURED_PATH_FIELDS = new Set([
  '$ref', 'context', 'cwd', 'dockerfile', 'env_file', 'envfile', 'exclude', 'excludes',
  'extends', 'file', 'files', 'include', 'includes', 'manifest', 'path', 'paths',
  'working-directory', 'workingdirectory'
]);

function contextPath(parts) {
  return parts.length ? parts.join('.') : '$';
}

function addCommand(declarations, command, context) {
  const text = Array.isArray(command) ? command.join(' ') : String(command ?? '').trim();
  if (!text) return;
  declarations.push(declaration('command', `${context.owner}:${context.field}`, {
    command: text,
    executableContext: {
      kind: context.kind,
      owner: context.owner,
      field: context.field,
      interpreter: context.interpreter ?? null,
      condition: context.condition ?? null,
      workingDirectory: context.workingDirectory ?? null
    }
  }));
}

function addPathRelationship(relationships, source, value, extractionMethod, attributes = {}) {
  if (!pathLike(value)) return;
  // Path fields have schema-specific bases. Preserve the authored value here;
  // repository resolution owns root-, source-, fixture-, and non-file scope.
  relationships.push(relationship('references', value, 'artifact', extractionMethod, 'structurally-proven', confidence.structural, attributes));
}

function structuredField(keyPath) {
  const last = keyPath.at(-1);
  return /^\d+$/.test(String(last)) ? keyPath.at(-2) : last;
}

function addActionRelationship(relationships, value, extractionMethod, attributes = {}) {
  if (typeof value !== 'string') return;
  const local = /^(?:\.\.?\/)/.test(value);
  relationships.push(relationship('uses-action', value, local ? 'artifact' : 'external-resource', extractionMethod, 'structurally-proven', confidence.structural, { ...attributes, actionClass: local ? 'local-action' : 'external-action' }));
}

function structuredObjectEvidence(value, source, extractionMethod, rootKind = 'document') {
  const declarations = [declaration(rootKind, source, { valueType: Array.isArray(value) ? 'array' : typeof value })];
  const relationships = [];
  walkObject(value, (entry, keyPath) => {
    const field = structuredField(keyPath);
    if (keyPath.length > 0 && entry && typeof entry === 'object') {
      declarations.push(declaration(Array.isArray(entry) ? 'sequence' : 'mapping', contextPath(keyPath), {
        entryCount: Array.isArray(entry) ? entry.length : Object.keys(entry).length
      }));
    }
    if (typeof entry !== 'string') return;
    const normalisedField = String(field).toLowerCase();
    if (STRUCTURED_PATH_FIELDS.has(normalisedField)) addPathRelationship(relationships, source, entry, extractionMethod, { keyPath: contextPath(keyPath), pathField: String(field) });
    if (normalisedField === 'uses') addActionRelationship(relationships, entry, extractionMethod, { keyPath: contextPath(keyPath) });
    if (['command', 'entrypoint', 'run'].includes(String(field).toLowerCase())) {
      addCommand(declarations, entry, { kind: 'structured-command-field', owner: contextPath(keyPath.slice(0, -1)), field: String(field) });
    }
  });
  return { declarations, relationships };
}

function packageManifestEvidence(value, source, declarations, relationships) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  if (typeof value.name === 'string') declarations.push(declaration('package', value.name, { version: value.version ?? null, source }));
  for (const group of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    for (const [name, range] of Object.entries(value[group] ?? {})) {
      declarations.push(declaration('package-dependency', name, { group, range: String(range) }));
      relationships.push(relationship('depends-on', name, 'package', `json-pointer:/${group}/${name}`, 'inventory-declared', confidence.structural, { range: String(range), group }));
    }
  }
  for (const [name, command] of Object.entries(value.scripts ?? {})) {
    addCommand(declarations, command, { kind: 'package-script', owner: value.name ?? source, field: name, interpreter: 'package-manager-shell' });
  }
}

function parseJson({ text, member }) {
  const value = JSON.parse(text);
  const evidence = structuredObjectEvidence(value, member.path, 'json-pointer', 'json-document');
  packageManifestEvidence(value, member.path, evidence.declarations, evidence.relationships);
  const declarations = evidence.declarations;
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of Object.keys(value)) declarations.push(declaration('top-level-member', key, { valueType: Array.isArray(value[key]) ? 'array' : typeof value[key] }));
  }
  return result({
    declarations,
    relationships: evidence.relationships,
    inventory: inventory('keyed-map', member.path, declarations, evidence.relationships, ['all-json-members-parsed'])
  });
}

function parseJsonl({ text, member }) {
  const declarations = [];
  const relationships = [];
  const lines = text.split(/\r?\n/);
  let recordIndex = 0;
  lines.forEach((line, index) => {
    if (!line.trim()) return;
    const value = JSON.parse(line);
    recordIndex += 1;
    const identity = value && typeof value === 'object' && !Array.isArray(value)
      ? ['id', 'key', 'name', 'path'].map((key) => value[key]).find((item) => typeof item === 'string')
      : null;
    declarations.push(declaration('jsonl-record', identity ?? String(recordIndex), { line: index + 1, valueType: Array.isArray(value) ? 'array' : typeof value }));
    const evidence = structuredObjectEvidence(value, member.path, `json-pointer:line-${index + 1}`);
    declarations.push(...evidence.declarations.slice(1));
    relationships.push(...evidence.relationships);
  });
  return result({
    declarations,
    relationships,
    inventory: inventory('entity-collection', member.path, declarations, relationships, ['all-nonblank-lines-parsed'])
  });
}

function yamlNodeEvidence(documents, declarations, relationships) {
  documents.forEach((document, documentIndex) => {
    if (document.errors.length) throw document.errors[0];
    visit(document, {
      Node(_key, node, pathNodes) {
        if (node?.anchor) declarations.push(declaration('yaml-anchor', node.anchor, { document: documentIndex + 1, nodeType: node.constructor.name }));
        if (isAlias(node)) relationships.push(relationship('references', node.source, 'semantic-entity', 'yaml-alias', 'structurally-proven', confidence.structural, { document: documentIndex + 1 }));
        if (isScalar(node) && typeof node.value === 'string' && /\n/.test(node.value)) {
          declarations.push(declaration('yaml-multiline-scalar', `document-${documentIndex + 1}:${pathNodes.length}`, { style: node.type ?? 'plain', lineCount: node.value.split('\n').length }));
        }
        if (isMap(node) || isSeq(node)) return;
      },
      Pair(_key, pair) {
        if (!isPair(pair)) return;
      }
    });
  });
}

function composeEvidence(value, member, declarations, relationships) {
  for (const [serviceName, service] of Object.entries(value?.services ?? {})) {
    declarations.push(declaration('compose-service', serviceName, {
      image: service?.image ?? null,
      profiles: service?.profiles ?? [],
      ports: service?.ports ?? [],
      environment: service?.environment ?? null,
      volumes: service?.volumes ?? []
    }));
    if (service?.image) relationships.push(relationship('materialises', service.image, 'external-resource', 'compose.services.image'));
    const dependencies = Array.isArray(service?.depends_on) ? service.depends_on : Object.keys(service?.depends_on ?? {});
    for (const dependency of dependencies) relationships.push(relationship('depends-on', dependency, 'runtime-service', 'compose.services.depends_on'));
    for (const [field, interpreter] of [['command', null], ['entrypoint', null]]) {
      if (service?.[field] !== undefined) addCommand(declarations, service[field], { kind: 'compose-service', owner: serviceName, field, interpreter, workingDirectory: service.working_dir ?? null });
    }
    const healthCommand = Array.isArray(service?.healthcheck?.test) ? service.healthcheck.test : service?.healthcheck?.test;
    if (healthCommand) {
      addCommand(declarations, healthCommand, { kind: 'compose-healthcheck', owner: serviceName, field: 'healthcheck.test', interpreter: Array.isArray(healthCommand) ? healthCommand[0] : 'container-shell' });
      relationships.push(relationship('health-checks', serviceName, 'runtime-service', 'compose.services.healthcheck'));
    }
    for (const item of service?.volumes ?? []) {
      const host = typeof item === 'string' ? item.split(':')[0] : item?.source;
      if (host) addPathRelationship(relationships, member.path, host, 'compose.services.volumes', { service: serviceName });
    }
  }
  for (const [kind, entries] of [['compose-volume', value?.volumes], ['compose-network', value?.networks], ['compose-secret', value?.secrets], ['compose-config', value?.configs]]) {
    for (const name of Object.keys(entries ?? {})) declarations.push(declaration(kind, name));
  }
}

function workflowEvidence(value, declarations, relationships) {
  for (const [jobName, job] of Object.entries(value?.jobs ?? {})) {
    declarations.push(declaration('workflow-job', jobName, {
      condition: job?.if ?? null,
      runner: job?.['runs-on'] ?? null,
      permissions: job?.permissions ?? null,
      environment: job?.environment ?? null
    }));
    if (job?.if !== undefined) declarations.push(declaration('workflow-condition', `jobs.${jobName}.if`, { expression: String(job.if) }));
    const needs = Array.isArray(job?.needs) ? job.needs : job?.needs ? [job.needs] : [];
    for (const dependency of needs) relationships.push(relationship('needs', dependency, 'semantic-entity', 'workflow.jobs.needs'));
    if (job?.uses) addActionRelationship(relationships, job.uses, 'workflow.jobs.uses', { job: jobName });
    const matrix = job?.strategy?.matrix;
    if (matrix && typeof matrix === 'object') {
      for (const [axis, values] of Object.entries(matrix)) declarations.push(declaration('workflow-matrix-axis', `${jobName}.${axis}`, { values }));
    }
    for (const [stepIndex, step] of (job?.steps ?? []).entries()) {
      const owner = `${jobName}.steps.${step.id ?? stepIndex + 1}`;
      declarations.push(declaration('workflow-step', owner, { name: step.name ?? null, condition: step.if ?? null }));
      if (step.if !== undefined) declarations.push(declaration('workflow-condition', `${owner}.if`, { expression: String(step.if) }));
      if (step.uses) addActionRelationship(relationships, step.uses, 'workflow.jobs.steps.uses', { job: jobName, step: owner });
      if (step.run !== undefined) addCommand(declarations, step.run, {
        kind: 'workflow-step', owner, field: 'run', interpreter: step.shell ?? 'runner-default-shell', condition: step.if ?? null, workingDirectory: step['working-directory'] ?? null
      });
    }
  }
}

function parseYaml(context) {
  const documents = parseAllDocuments(context.text, { merge: true, prettyErrors: true, strict: true, uniqueKeys: true });
  const declarations = [];
  const relationships = [];
  yamlNodeEvidence(documents, declarations, relationships);
  const values = documents.map((document) => document.toJS({ maxAliasCount: 1000 }));
  values.forEach((value, index) => {
    declarations.push(declaration('yaml-document', String(index + 1), { valueType: Array.isArray(value) ? 'array' : typeof value }));
    const evidence = structuredObjectEvidence(value, context.member.path, `yaml-path:document-${index + 1}`);
    declarations.push(...evidence.declarations.slice(1));
    relationships.push(...evidence.relationships);
    if (context.syntaxKind === 'compose-yaml') composeEvidence(value, context.member, declarations, relationships);
    if (context.syntaxKind === 'workflow-yaml') workflowEvidence(value, declarations, relationships);
  });
  const inventoryKind = context.syntaxKind === 'workflow-yaml' ? 'workflow-definition' : context.syntaxKind === 'compose-yaml' ? 'entity-collection' : 'keyed-map';
  return result({
    declarations,
    relationships,
    inventory: inventory(inventoryKind, context.member.path, declarations, relationships, ['all-yaml-documents-and-aliases-parsed'])
  });
}

function parseTomlDocument({ text, member }) {
  const value = parseToml(text);
  const evidence = structuredObjectEvidence(value, member.path, 'toml-key-path', 'toml-document');
  for (const [key, entry] of Object.entries(value)) {
    evidence.declarations.push(declaration(entry && typeof entry === 'object' && !Array.isArray(entry) ? 'toml-table' : 'toml-key', key, { valueType: Array.isArray(entry) ? 'array' : typeof entry }));
  }
  return result({
    declarations: evidence.declarations,
    relationships: evidence.relationships,
    inventory: inventory('keyed-map', member.path, evidence.declarations, evidence.relationships, ['all-toml-values-parsed'])
  });
}

function parseXmlLike({ text, member, syntaxKind }) {
  const declarations = [];
  const relationships = [];
  const stack = [];
  const parser = new SaxesParser({ xmlns: true, fragment: false });
  parser.on('opentag', (tag) => {
    const identifier = [...stack, tag.name].join('/');
    declarations.push(declaration(syntaxKind === 'svg' ? 'svg-element' : 'xml-element', identifier, {
      localName: tag.local,
      namespace: tag.uri || null,
      attributes: Object.fromEntries(Object.entries(tag.attributes).map(([name, attribute]) => [name, attribute.value]))
    }));
    for (const attribute of Object.values(tag.attributes)) {
      if (['href', 'src'].includes(attribute.local)) addPathRelationship(relationships, member.path, attribute.value, `${syntaxKind}-attribute:${attribute.local}`, { element: identifier });
      if (attribute.local === 'id') declarations.push(declaration(`${syntaxKind}-id`, attribute.value, { element: identifier }));
    }
    stack.push(tag.name);
  });
  parser.on('closetag', () => stack.pop());
  parser.write(text).close();
  return result({
    declarations,
    relationships,
    inventory: inventory('entity-collection', member.path, declarations, relationships, ['all-elements-and-attributes-parsed'])
  });
}

function parseCsvRows(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  let closedQuote = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') { field += '"'; index += 1; }
      else if (character === '"') { quoted = false; closedQuote = true; }
      else field += character;
    } else if (character === '"' && field.length === 0 && !closedQuote) quoted = true;
    else if (character === ',') { row.push(field); field = ''; closedQuote = false; }
    else if (character === '\n') { row.push(field.replace(/\r$/, '')); rows.push(row); row = []; field = ''; closedQuote = false; }
    else if (closedQuote && character !== '\r') throw new Error('unexpected character after quoted CSV field');
    else if (character === '"') throw new Error('unexpected quote in unquoted CSV field');
    else field += character;
  }
  if (quoted) throw new Error('unterminated quoted CSV field');
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

function parseCsv({ text, member }) {
  const rows = parseCsvRows(text);
  const headers = rows[0] ?? [];
  if (new Set(headers).size !== headers.length) throw new Error('duplicate CSV header');
  const declarations = headers.map((header, index) => declaration('csv-column', header, { index }));
  const relationships = [];
  rows.slice(1).forEach((row, rowIndex) => {
    declarations.push(declaration('csv-row', String(rowIndex + 1), { values: Object.fromEntries(headers.map((header, index) => [header, row[index] ?? ''])) }));
    row.forEach((field, columnIndex) => addPathRelationship(relationships, member.path, field, 'csv-field', { row: rowIndex + 1, column: headers[columnIndex] ?? columnIndex }));
  });
  return result({ declarations, relationships, inventory: inventory('tabular-matrix', member.path, declarations, relationships, ['all-rfc4180-style-records-parsed']) });
}

function parseCertificate({ text, member }) {
  const declarations = [];
  const blocks = [...text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----\s*([A-Za-z0-9+/=\r\n]+?)\s*-----END \1-----/g)];
  if (!blocks.length || text.replace(/-----BEGIN [\s\S]*?-----END [A-Z0-9 ]+-----/g, '').trim()) throw new Error(`invalid PEM envelope: ${member.path}`);
  blocks.forEach((match, index) => {
    const bytes = Buffer.from(match[2].replace(/\s/g, ''), 'base64');
    const attributes = { index: index + 1, byteLength: bytes.length };
    if (match[1] === 'CERTIFICATE') {
      const certificate = new X509Certificate(match[0]);
      Object.assign(attributes, { subject: certificate.subject, issuer: certificate.issuer, serialNumber: certificate.serialNumber, validFrom: certificate.validFrom, validTo: certificate.validTo, fingerprint256: certificate.fingerprint256 });
    }
    declarations.push(declaration('pem-block', `${match[1]}:${index + 1}`, attributes));
  });
  return result({ declarations, inventory: inventory('entity-collection', member.path, declarations, [], ['all-pem-blocks-decoded']) });
}

function parseLfsPointer({ text, member }) {
  const match = text.match(/^version (https:\/\/git-lfs\.github\.com\/spec\/v1)\r?\noid (sha256:[a-f0-9]{64})\r?\nsize (\d+)\r?\n?$/);
  if (!match) throw new Error(`invalid Git LFS pointer: ${member.path}`);
  const declarations = [declaration('git-lfs-object', match[2], { byteSize: Number(match[3]), specification: match[1] })];
  return result({ declarations, inventory: inventory('closure-record', member.path, declarations, [], ['canonical-lfs-pointer-fields-parsed']) });
}

function parseMake({ text, member }) {
  const declarations = [];
  const relationships = [];
  let targets = [];
  let recipeIndex = 0;
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    if (/^\t/.test(rawLine)) {
      recipeIndex += 1;
      for (const target of targets) addCommand(declarations, rawLine.slice(1).replace(/^[@+-]+/, ''), { kind: 'make-recipe', owner: target, field: `recipe-${recipeIndex}`, interpreter: 'make-shell' });
      continue;
    }
    const include = rawLine.match(/^\s*-?include\s+(.+?)\s*$/);
    if (include) for (const target of include[1].split(/\s+/)) addPathRelationship(relationships, member.path, target, 'make-include');
    const assignment = rawLine.match(/^\s*([A-Za-z0-9_.-]+)\s*(?::|\?|\+|!)?=\s*(.*)$/);
    if (assignment) declarations.push(declaration('make-variable', assignment[1], { value: assignment[2], line: index + 1 }));
    const rule = rawLine.match(/^([^#\s][^:=]*?):\s*([^=].*)?$/);
    if (rule) {
      targets = rule[1].trim().split(/\s+/);
      recipeIndex = 0;
      for (const target of targets) declarations.push(declaration('make-target', target, { prerequisites: (rule[2] ?? '').trim().split(/\s+/).filter(Boolean), line: index + 1 }));
      for (const dependency of (rule[2] ?? '').trim().split(/\s+/).filter(Boolean)) addPathRelationship(relationships, member.path, dependency, 'make-prerequisite');
    } else if (rawLine.trim() && !/^\s*(?:#|\.)/.test(rawLine)) targets = [];
  }
  return result({
    declarations,
    relationships,
    inventory: inventory('workflow-definition', member.path, declarations, relationships, ['targets-variables-includes-and-recipe-contexts-scanned']),
    structuralCoverage: 'partial',
    unsupportedStructures: ['make-expansion-generated-rules-and-evaluation-semantics'],
    confidence: confidence.bounded
  });
}

function logicalShellLines(text) {
  const lines = [];
  let current = '';
  for (const line of text.split(/\r?\n/)) {
    current += (current ? '\n' : '') + line.replace(/\\$/, '');
    if (!/\\$/.test(line)) { lines.push(current); current = ''; }
  }
  if (current) lines.push(current);
  return lines;
}

function parseShell({ text, member }) {
  const declarations = [];
  const relationships = [];
  let functionName = null;
  for (const [index, line] of logicalShellLines(text).entries()) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const functionMatch = trimmed.match(/^(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\))?\s*\{/);
    if (functionMatch) { functionName = functionMatch[1]; declarations.push(declaration('shell-function', functionName, { line: index + 1 })); continue; }
    if (trimmed === '}') { functionName = null; continue; }
    const sourceMatch = trimmed.match(/^(?:source|\.)\s+(["']?)([^"'\s;]+)\1/);
    if (sourceMatch) addPathRelationship(relationships, member.path, sourceMatch[2], 'shell-source', { line: index + 1 });
    const assignment = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s);
    if (assignment) { declarations.push(declaration('shell-variable', assignment[1], { exported: trimmed.startsWith('export '), line: index + 1 })); continue; }
    if (/^(?:if|then|elif|else|fi|for|while|until|do|done|case|esac|select|\{|\})\b/.test(trimmed)) continue;
    addCommand(declarations, trimmed, { kind: 'shell-statement', owner: functionName ?? member.path, field: `line-${index + 1}`, interpreter: text.startsWith('#!') ? text.split(/\r?\n/, 1)[0].slice(2) : 'system-shell' });
  }
  return result({
    declarations,
    relationships,
    inventory: inventory('workflow-definition', member.path, declarations, relationships, ['functions-sources-assignments-and-command-contexts-parsed']),
    structuralCoverage: 'partial',
    unsupportedStructures: ['shell-expansion-and-control-flow-semantics'],
    confidence: confidence.bounded
  });
}

function dockerLogicalLines(text) {
  const lines = [];
  let current = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!current && (!line || line.startsWith('#'))) continue;
    current += (current ? '\n' : '') + raw.replace(/\\\s*$/, '').trim();
    if (!/\\\s*$/.test(raw)) { lines.push(current); current = ''; }
  }
  if (current) lines.push(current);
  return lines;
}

function parseDockerfile({ text, member }) {
  const declarations = [];
  const relationships = [];
  let stage = 'global';
  for (const [index, line] of dockerLogicalLines(text).entries()) {
    const match = line.match(/^([A-Za-z]+)\s+([\s\S]*)$/);
    if (!match) throw new Error(`invalid Dockerfile instruction at logical line ${index + 1}`);
    const instruction = match[1].toUpperCase();
    const argument = match[2].trim();
    declarations.push(declaration('dockerfile-instruction', `${stage}:${index + 1}:${instruction}`, { instruction, argument }));
    if (instruction === 'FROM') {
      const from = argument.match(/^(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?$/i);
      if (from) { relationships.push(relationship('materialises', from[1], 'external-resource', 'dockerfile-FROM')); stage = from[2] ?? from[1]; declarations.push(declaration('container-stage', stage, { base: from[1] })); }
    }
    if (['RUN', 'CMD', 'ENTRYPOINT', 'HEALTHCHECK'].includes(instruction)) addCommand(declarations, argument, { kind: 'dockerfile-instruction', owner: stage, field: instruction, interpreter: argument.startsWith('[') ? 'exec-form' : 'container-shell' });
    if (['COPY', 'ADD'].includes(instruction)) {
      const tokens = argument.replace(/^--\S+\s+/, '').split(/\s+/);
      tokens.slice(0, -1).forEach((target) => addPathRelationship(relationships, member.path, target, `dockerfile-${instruction}`));
    }
  }
  return result({ declarations, relationships, inventory: inventory('workflow-definition', member.path, declarations, relationships, ['all-logical-instructions-parsed']) });
}

function sqlIdentifier(node) {
  if (!node || typeof node !== 'object') return null;
  if (typeof node.name === 'string') return node.name;
  if (typeof node.text === 'string' && ['identifier', 'qualified_identifier'].includes(node.type)) return node.text;
  return null;
}

function parseSql({ text, member }) {
  let tree;
  let dialect;
  const failures = [];
  for (const candidate of ['postgresql', 'plpgsql', 'sqlite', 'mysql']) {
    try { tree = parseSqlCst(text, { dialect: candidate, filename: member.path, paramTypes: ['?', '?nr', '$nr', ':name', '$name', '@name', '`@name`'] }); dialect = candidate; break; }
    catch (error) { failures.push(`${candidate}:${error.name}`); }
  }
  if (!tree) throw new Error(`SQL failed supported dialects (${failures.join(', ')})`);
  const declarations = [declaration('sql-program', member.path, { dialect })];
  const relationships = [];
  walkObject(tree, (node, keyPath) => {
    if (!node || typeof node !== 'object' || Array.isArray(node) || typeof node.type !== 'string') return;
    if (/_stmt$/.test(node.type)) declarations.push(declaration('sql-statement', `${keyPath.join('.')}:${node.type}`, { statementType: node.type }));
    if (/^create_(?:table|view|index|schema|function)_stmt$/.test(node.type)) {
      const name = sqlIdentifier(node.name);
      if (name) declarations.push(declaration(node.type.replace(/^create_|_stmt$/g, ''), name, { dialect }));
    }
    for (const field of ['table', 'from', 'into']) {
      const name = sqlIdentifier(node[field]);
      if (name) relationships.push(relationship(field === 'into' || (field === 'table' && node.type === 'insert_clause') ? 'persists-to' : 'references', name, 'semantic-entity', `sql-cst:${node.type}.${field}`));
    }
  });
  return result({ declarations, relationships, inventory: inventory('entity-collection', member.path, declarations, relationships, [`sql-cst-dialect:${dialect}`]) });
}

function parseMarkdown({ text, member }) {
  const declarations = [declaration('markdown-document', member.path, { lineCount: text.split(/\r?\n/).length })];
  const relationships = [];
  let fence = null;
  let fenceIndex = 0;
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const fenceMatch = line.match(/^\s*(```+|~~~+)\s*([^\s]*)/);
    if (fenceMatch) {
      if (!fence) { fence = fenceMatch[1][0]; fenceIndex += 1; declarations.push(declaration('markdown-code-fence', String(fenceIndex), { language: fenceMatch[2] || null, startLine: index + 1 })); }
      else if (fence === fenceMatch[1][0]) fence = null;
      continue;
    }
    if (fence) continue;
    const heading = line.match(/^(#{1,6})\s+(.+?)\s*#*$/);
    if (heading) declarations.push(declaration('markdown-heading', heading[2], { level: heading[1].length, line: index + 1 }));
    const reference = line.match(/^\s*\[([^\]]+)\]:\s*(\S+)/);
    if (reference) { declarations.push(declaration('markdown-link-reference', reference[1], { target: reference[2] })); addPathRelationship(relationships, member.path, reference[2], 'markdown-reference-link'); }
    for (const match of line.matchAll(/!?\[[^\]]*\]\(([^\s)]+)(?:\s+["'][^"']*["'])?\)/g)) addPathRelationship(relationships, member.path, match[1].replace(/^<|>$/g, ''), 'markdown-inline-link');
    if (/^\s*\|.*\|\s*$/.test(line)) declarations.push(declaration('markdown-table-row', String(index + 1), { cells: line.split('|').slice(1, -1).map((cell) => cell.trim()) }));
  }
  return result({ declarations, relationships, inventory: inventory('entity-collection', member.path, declarations, relationships, ['block-headings-fences-tables-and-links-scanned']), structuralCoverage: 'partial', unsupportedStructures: ['markdown-extension-and-inline-formatting-semantics'], confidence: confidence.bounded });
}

function parseConfiguration({ text, member }) {
  const declarations = [];
  const relationships = [];
  let section = 'global';
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || /^[#;]/.test(line)) continue;
    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) { section = sectionMatch[1]; declarations.push(declaration('configuration-section', section)); continue; }
    const assignment = line.match(/^([^:=\s]+)\s*[:=]\s*(.*)$/);
    if (assignment) {
      declarations.push(declaration('configuration-entry', `${section}.${assignment[1]}`, { value: assignment[2], line: index + 1 }));
      addPathRelationship(relationships, member.path, assignment[2], 'configuration-value', { key: assignment[1], section });
    } else declarations.push(declaration('configuration-pattern', line, { line: index + 1 }));
  }
  return result({ declarations, relationships, inventory: inventory('keyed-map', member.path, declarations, relationships, ['sections-assignments-and-pattern-lines-scanned']), structuralCoverage: 'partial', unsupportedStructures: ['tool-specific-configuration-interpolation'], confidence: confidence.bounded });
}

function parsePlainText({ text, member }) {
  const declarations = [];
  const relationships = [];
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const dependency = line.match(/^([A-Za-z0-9_.-]+)\s*(?:===|==|~=|>=|<=|>|<)\s*([^\s;]+)(?:\s*;.*)?$/);
    const assignment = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (dependency) declarations.push(declaration('dependency-declaration', dependency[1], { constraint: dependency[2], line: index + 1 }));
    else if (assignment) declarations.push(declaration('configuration-entry', assignment[1], { value: assignment[2], line: index + 1 }));
    else declarations.push(declaration('prose-line', `line:${index + 1}`, { text: line, line: index + 1 }));
    addPathRelationship(relationships, member.path, line, 'plain-text-line', { line: index + 1 });
  }
  return result({ declarations, relationships, inventory: inventory('entity-collection', member.path, declarations, relationships, ['nonempty-lines-scanned']), structuralCoverage: 'partial', unsupportedStructures: ['format-specific-plain-text-semantics'], confidence: confidence.bounded });
}

function parseHtml({ text, member }) {
  const declarations = [];
  const relationships = [];
  const tagPattern = /<!--[^]*?-->|<![^>]*>|<\/?([A-Za-z][\w:-]*)([^>]*?)\/?\s*>/g;
  let match;
  while ((match = tagPattern.exec(text))) {
    if (!match[1] || text[match.index + 1] === '/') continue;
    const attributes = {};
    for (const attribute of match[2].matchAll(/([:\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) attributes[attribute[1]] = attribute[2] ?? attribute[3] ?? attribute[4] ?? true;
    const identifier = typeof attributes.id === 'string' ? attributes.id : `${match[1].toLowerCase()}:${match.index}`;
    declarations.push(declaration('html-element', identifier, { tag: match[1].toLowerCase(), attributes }));
    for (const key of ['href', 'src', 'action']) if (typeof attributes[key] === 'string') addPathRelationship(relationships, member.path, attributes[key], `html-attribute:${key}`, { element: identifier });
  }
  return result({ declarations, relationships, inventory: inventory('entity-collection', member.path, declarations, relationships, ['start-tags-and-attributes-scanned']), structuralCoverage: 'partial', unsupportedStructures: ['html-error-recovery-and-embedded-language-semantics'], confidence: confidence.bounded });
}

function parseCss({ text, member }) {
  const declarations = [];
  const relationships = [];
  const withoutComments = text.replace(/\/\*[\s\S]*?\*\//g, '');
  for (const match of withoutComments.matchAll(/@import\s+(?:url\()?\s*["']?([^\s"')]+)["']?\)?\s*;/gi)) addPathRelationship(relationships, member.path, match[1], 'css-import');
  for (const match of withoutComments.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/gi)) addPathRelationship(relationships, member.path, match[1], 'css-url');
  const ruleSource = withoutComments.replace(/@import\s+(?:url\()?[^;]+;/gi, '');
  for (const match of ruleSource.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = match[1].trim();
    if (!selector || selector.startsWith('@')) continue;
    const properties = [...match[2].matchAll(/([\w-]+)\s*:\s*([^;]+);?/g)].map((entry) => ({ property: entry[1], value: entry[2].trim() }));
    declarations.push(declaration('css-rule', selector, { properties }));
  }
  return result({ declarations, relationships, inventory: inventory('entity-collection', member.path, declarations, relationships, ['imports-urls-and-flat-rules-scanned']), structuralCoverage: 'partial', unsupportedStructures: ['nested-css-and-at-rule-semantics'], confidence: confidence.bounded });
}

export const structuredDataParser = {
  id: 'builtin-structured-data', version: '1', mode: 'structural',
  supports: ({ syntaxKind }) => STRUCTURED_SYNTAXES.has(syntaxKind),
  parse(context) {
    switch (context.syntaxKind) {
      case 'structured-json': case 'json-schema': return parseJson(context);
      case 'data-jsonl': return parseJsonl(context);
      case 'yaml': case 'compose-yaml': case 'workflow-yaml': return parseYaml(context);
      case 'toml': return parseTomlDocument(context);
      case 'xml': case 'svg': return parseXmlLike(context);
      case 'csv': return parseCsv(context);
      case 'certificate': return parseCertificate(context);
      case 'git-lfs-pointer': return parseLfsPointer(context);
      default: throw new Error(`unsupported structured syntax: ${context.syntaxKind}`);
    }
  }
};

export const dockerfileParser = {
  id: 'builtin-dockerfile', version: '1', mode: 'structural',
  supports: ({ syntaxKind }) => syntaxKind === 'dockerfile',
  parse: parseDockerfile
};

export const boundedCommandParser = {
  id: 'builtin-bounded-command-files', version: '1', mode: 'bounded-lexical',
  supports: ({ syntaxKind }) => BOUNDED_COMMAND_SYNTAXES.has(syntaxKind),
  parse(context) {
    if (context.syntaxKind === 'make') return parseMake(context);
    return parseShell(context);
  }
};

export const sqlParser = {
  id: 'builtin-sql-cst', version: '1', mode: 'structural',
  supports: ({ syntaxKind }) => syntaxKind === 'sql',
  parse: parseSql
};

export const boundedDocumentParser = {
  id: 'builtin-bounded-documents', version: '1', mode: 'bounded-lexical',
  supports: ({ syntaxKind }) => BOUNDED_SYNTAXES.has(syntaxKind),
  parse(context) {
    if (context.syntaxKind === 'markdown') return parseMarkdown(context);
    if (context.syntaxKind === 'configuration') return parseConfiguration(context);
    if (context.syntaxKind === 'html') return parseHtml(context);
    if (context.syntaxKind === 'plain-text') return parsePlainText(context);
    return parseCss(context);
  }
};

export const structuredParsers = [structuredDataParser, dockerfileParser, boundedCommandParser, sqlParser, boundedDocumentParser];
export const structuredParserImplementations = structuredParsers;
export default structuredParsers;
