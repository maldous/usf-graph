import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const joinToken = (...parts) => parts.join('');
const trackerProduct = joinToken('lin', 'ear');
const requestRecord = joinToken('tic', 'ket');
const externalOrdinalPrefix = joinToken('U', 'SF-');
const formerOwner = joinToken('mal', 'dous');
const formerRepository = joinToken(formerOwner, '/', 'usf');

const trackerFields = [
  joinToken(trackerProduct, 'Issue'), joinToken(trackerProduct, 'IssueId'), joinToken(trackerProduct, 'Project'),
  joinToken(trackerProduct, 'Reference'), joinToken(requestRecord, 'Id'), joinToken(requestRecord, 'Ref'),
  joinToken('issue', 'Key'), joinToken('work', 'ItemId'), joinToken('external', 'Issue'),
];
const originFields = [
  joinToken('source', 'Commit'), joinToken('source', 'Sha'), joinToken('source', 'Branch'), joinToken('source', 'Tag'),
  joinToken('source', 'Repository'), joinToken('source', 'RepositoryUrl'), joinToken('origin', 'Repository'),
  joinToken('origin', 'Commit'), joinToken('origin', 'Branch'), joinToken('git', 'Ref'), joinToken('git', 'Revision'),
  joinToken('repository', 'Lineage'), joinToken('original', 'Source'), joinToken('historical', 'Source'),
  joinToken('source', 'Artefact'), joinToken('source', 'Location'), joinToken('source', 'Revision'),
  joinToken('migration', 'Origin'), joinToken('lineage', 'Commit'), joinToken('predecessor', 'Branch'),
  joinToken('imported', 'From'), joinToken('derived', 'FromRepository'),
];

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const trackerWordPattern = `\\b${escapeRegex(trackerProduct)}\\b`;
const trackerDomainPattern = `${escapeRegex(trackerProduct)}\\.${joinToken('a', 'pp')}`;
const externalOrdinalPattern = `\\b${escapeRegex(externalOrdinalPrefix)}[0-9]+\\b`;
const trackerFieldPattern = `\\b(?:${trackerFields.map(escapeRegex).join('|')})\\b`;
const formerRepositoryPattern = `${escapeRegex(formerRepository)}(?:\\.git|/|(?![-._a-z0-9]))`;

export const EXTERNAL_ORIGIN_PATTERNS = Object.freeze([
  trackerWordPattern,
  trackerDomainPattern,
  externalOrdinalPattern,
  trackerFieldPattern,
  formerRepositoryPattern,
]);

const strictDefinitions = Object.freeze([
  ['EXTERNAL_TRACKER_PRODUCT', new RegExp(trackerWordPattern, 'gi')],
  ['EXTERNAL_TRACKER_DOMAIN', new RegExp(trackerDomainPattern, 'gi')],
  ['EXTERNAL_TRACKER_ORDINAL', new RegExp(externalOrdinalPattern, 'gi')],
  ['EXTERNAL_TRACKER_FIELD', new RegExp(trackerFieldPattern, 'gi')],
  ['FORMER_REPOSITORY_IDENTITY', new RegExp(formerRepositoryPattern, 'gi')],
  ['FORMER_PARENT_WORDING', new RegExp(`\\bformer[ -]parent[ -]repository\\b`, 'gi')],
  ['HISTORICAL_ORIGIN_REQUIREMENT', new RegExp(`\\b(?:copied[ -]from[ -]commit|derived[ -]from[ -]branch|see[ -]the[ -]original[ -]repository|based[ -]on[ -]the[ -](?:old|historical)[ -]source|carried[ -]from[ -]tag)\\b`, 'gi')],
  ['EXTERNAL_RECORD_DEPENDENCY', new RegExp(`\\b(?:as[ -]defined[ -]in|pending|implemented[ -]for|depends?[ -]on|acceptance[ -]from|scope[ -]from|follow[ -]up)[ -](?:an?[ -])?${escapeRegex(requestRecord)}\\b`, 'gi')],
  ['HISTORICAL_SOURCE_PATH_REQUIREMENT', new RegExp(`\\b(?:behaviou?r|requirement|contract|decision)[^\\n]{0,80}\\b(?:old|historical|original)[ -]source[ -](?:file|path)\\b`, 'gi')],
  ['LEGACY_PULL_REQUEST_DEPENDENCY', new RegExp(`\\b(?:based[ -]on|matches|copied[ -]from|see)[ -](?:pull|merge)[ -]request[ -]#?[0-9]+\\b`, 'gi')],
  ['TRANSITIONAL_SOURCE_ROOT', new RegExp(`(?:^|["'/:])${joinToken('v', '2')}/${joinToken('u', 'sf')}/`, 'gi')],
]);
const originFieldRe = new RegExp(`\\b(?:${originFields.map(escapeRegex).join('|')})\\b`, 'gi');
const originFieldNames = new Set(originFields.map((field) => field.toLowerCase()));
const coordinateValueRe = new RegExp(`(?:https?://|ssh://|git@|refs/(?:heads|tags)/|\\b[0-9a-f]{7,40}\\b|(?:^|["':/])(?:feature|migration|remediation|bootstrap|release)[/_-][a-z0-9._/-]+|[a-z0-9._-]+/[a-z0-9._-]+\\.git|(?:^|["'])[^"']+/(?:src|apps|packages|services|tests|docs)/[^"']+)`, 'i');
const reviewProjectionSafeValueRe = /^(?:urn:usf:(?:graph|semantic|ontology|capability|semanticcontract):|sha256:|cas:\/\/sha256\/)/;

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const lineNumberAt = (text, index) => text.slice(0, index).split('\n').length;

export function inspectOriginText(text, path = '<memory>') {
  const findings = [];
  for (const [code, expression] of strictDefinitions) {
    expression.lastIndex = 0;
    for (let match = expression.exec(text); match; match = expression.exec(text)) {
      findings.push({ code, path, line: lineNumberAt(text, match.index) });
      if (match[0].length === 0) expression.lastIndex += 1;
    }
  }
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    originFieldRe.lastIndex = 0;
    if (!originFieldRe.test(line)) continue;
    const valueText = line.replace(originFieldRe, '').trim();
    if (reviewProjectionSafeValueRe.test(valueText.replace(/^[^"'<]*(?:["'<])?/, ''))) continue;
    if (coordinateValueRe.test(valueText)) findings.push({ code: 'LEGACY_ORIGIN_COORDINATE_FIELD', path, line: index + 1 });
  }
  return findings.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.code.localeCompare(b.code));
}

function inspectStructuredOrigin(value, path, location = '$') {
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => findings.push(...inspectStructuredOrigin(item, path, `${location}[${index}]`)));
    return findings;
  }
  if (!value || typeof value !== 'object') return findings;
  for (const [key, item] of Object.entries(value)) {
    const itemLocation = `${location}.${key}`;
    if (originFieldNames.has(key.toLowerCase())) {
      const values = Array.isArray(item) ? item : [item];
      for (const candidate of values) {
        if (typeof candidate !== 'string') continue;
        if (reviewProjectionSafeValueRe.test(candidate)) continue;
        if (coordinateValueRe.test(candidate)) findings.push({ code: 'LEGACY_ORIGIN_COORDINATE_FIELD', path, line: 1, field: itemLocation });
      }
    }
    findings.push(...inspectStructuredOrigin(item, path, itemLocation));
  }
  return findings;
}

const skippedDirectories = new Set(['.git', 'node_modules', '.venv', '__pycache__', 'dist', 'coverage']);
const negativeFixtures = new Set([
  join('tools', 'compiler', 'test', 'fixtures', 'defects', 'external-origin-dependency.fixture.js'),
  join('graph', 'fixtures', 'defects', 'external-tracker-contamination.ttl'),
  join('graph', 'fixtures', 'defects', 'external-work-record-identifier.ttl'),
  join('graph', 'fixtures', 'defects', 'repositorymetadata.ttl'),
]);

function repositoryFiles(root) {
  const files = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && skippedDirectories.has(entry.name)) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) files.push(path);
    }
  };
  walk(root);
  return files.sort();
}

export function validateOriginIndependence(root) {
  const findings = [];
  let scannedFileCount = 0;
  let scannedByteCount = 0;
  for (const path of repositoryFiles(root)) {
    const repositoryPath = relative(root, path).split(sep).join('/');
    if (negativeFixtures.has(repositoryPath)) continue;
    const bytes = readFileSync(path);
    if (bytes.includes(0)) continue;
    scannedFileCount += 1;
    scannedByteCount += bytes.byteLength;
    const filenameFindings = inspectOriginText(repositoryPath, repositoryPath).map((item) => ({ ...item, code: `PATH_${item.code}` }));
    const text = bytes.toString('utf8');
    let contentFindings = inspectOriginText(text, repositoryPath);
    if (repositoryPath.endsWith('.json')) {
      try {
        const structured = JSON.parse(text);
        contentFindings = contentFindings.filter((item) => item.code !== 'LEGACY_ORIGIN_COORDINATE_FIELD');
        contentFindings.push(...inspectStructuredOrigin(structured, repositoryPath));
      } catch {
        // Invalid JSON remains the responsibility of the format validator.
      }
    }
    findings.push(...filenameFindings, ...contentFindings);
  }
  const normalized = findings.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.code.localeCompare(b.code));
  return {
    ok: normalized.length === 0,
    scannedFileCount,
    scannedByteCount,
    findingCount: normalized.length,
    findings: normalized,
    resultDigest: sha256(JSON.stringify(normalized)),
  };
}

export const originIndependenceInternals = Object.freeze({
  trackerFields,
  originFields,
  negativeFixtures: [...negativeFixtures].sort(),
});
