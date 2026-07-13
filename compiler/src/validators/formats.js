import { parseDocument } from 'yaml';

const finding = (code, path, message) => ({ code, path, message });

export function parseJsonDocument(content, path, code = 'invalid-json') {
  try {
    return { value: JSON.parse(content), findings: [] };
  } catch (error) {
    return { value: null, findings: [finding(code, path, error.message)] };
  }
}

function validateJsonSchema(value, path) {
  const findings = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) findings.push(finding('invalid-json-schema', path, 'schema root must be an object'));
  else {
    if (typeof value.$schema !== 'string' || !/^https?:\/\/json-schema\.org\//.test(value.$schema)) findings.push(finding('invalid-json-schema', path, 'schema must declare a JSON Schema dialect'));
    if (typeof value.type !== 'string' && !Array.isArray(value.type)) findings.push(finding('invalid-json-schema', path, 'schema must declare a root type'));
    if (value.required !== undefined && !Array.isArray(value.required)) findings.push(finding('invalid-json-schema', path, 'required must be an array'));
  }
  return findings;
}

function validateOpenApi(value, path) {
  const findings = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [finding('invalid-openapi', path, 'OpenAPI root must be an object')];
  if (typeof value.openapi !== 'string' || !/^3\.(0|1)\.[0-9]+$/.test(value.openapi)) findings.push(finding('invalid-openapi', path, 'openapi must declare a supported 3.0 or 3.1 version'));
  if (!value.info || typeof value.info !== 'object' || typeof value.info.title !== 'string' || typeof value.info.version !== 'string') findings.push(finding('invalid-openapi', path, 'info.title and info.version are required'));
  if (!value.paths || typeof value.paths !== 'object' || Array.isArray(value.paths)) findings.push(finding('invalid-openapi', path, 'paths must be an object'));
  return findings;
}

function validateGraphql(content, path) {
  const findings = [];
  let quote = false;
  let escaped = false;
  let comment = false;
  const stack = [];
  const pairs = { '}': '{', ')': '(', ']': '[' };
  for (const character of content) {
    if (comment) {
      if (character === '\n') comment = false;
      continue;
    }
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quote = false;
      continue;
    }
    if (character === '#') { comment = true; continue; }
    if (character === '"') { quote = true; continue; }
    if ('{(['.includes(character)) stack.push(character);
    else if ('})]'.includes(character) && stack.pop() !== pairs[character]) {
      findings.push(finding('invalid-graphql', path, 'GraphQL delimiters are unbalanced'));
      return findings;
    }
  }
  if (quote || stack.length) findings.push(finding('invalid-graphql', path, 'GraphQL string or delimiters are unterminated'));
  if (!/\btype\s+Query\s*\{/.test(content)) findings.push(finding('invalid-graphql', path, 'GraphQL schema must define a Query type'));
  if (!/^\s*(#.*\n|\s)*(schema|scalar|type|interface|enum|input|union|directive|extend)\b/m.test(content)) findings.push(finding('invalid-graphql', path, 'GraphQL document contains no schema definition'));
  return findings;
}

function validatePackage(value, path) {
  const findings = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [finding('invalid-package', path, 'package manifest root must be an object')];
  if (typeof value.name !== 'string' || !value.name) findings.push(finding('invalid-package', path, 'package name is required'));
  if (typeof value.version !== 'string' || !/^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$/.test(value.version)) findings.push(finding('invalid-package', path, 'package version must be SemVer-shaped'));
  if (value.private !== true) findings.push(finding('invalid-package', path, 'generated workspace package must be private'));
  for (const script of ['test', 'validate', 'proof']) {
    if (typeof value.scripts?.[script] !== 'string' || !value.scripts[script]) findings.push(finding('invalid-package', path, `package script ${script} is required`));
  }
  return findings;
}

function validateWorkflow(content, path) {
  const document = parseDocument(content, { prettyErrors: true, uniqueKeys: true });
  if (document.errors.length) return document.errors.map((error) => finding('invalid-workflow', path, error.message));
  const value = document.toJS();
  const findings = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [finding('invalid-workflow', path, 'workflow root must be a mapping')];
  if (typeof value.name !== 'string' || !value.name) findings.push(finding('invalid-workflow', path, 'workflow name is required'));
  if (!Object.prototype.hasOwnProperty.call(value, 'on')) findings.push(finding('invalid-workflow', path, 'workflow trigger is required'));
  if (!value.jobs || typeof value.jobs !== 'object' || Array.isArray(value.jobs) || Object.keys(value.jobs).length === 0) findings.push(finding('invalid-workflow', path, 'workflow must declare at least one job'));
  return findings;
}

export function validateApplicableFormat(path, content) {
  if (path.endsWith('.graphql')) return validateGraphql(content, path);
  if (/^\.github\/workflows\/.*\.ya?ml$/.test(path)) return validateWorkflow(content, path);
  if (!path.endsWith('.json')) return [];
  const parsed = parseJsonDocument(content, path);
  if (parsed.findings.length) return parsed.findings;
  if (path.endsWith('.openapi.json')) return validateOpenApi(parsed.value, path);
  if (path.endsWith('.schema.json')) return validateJsonSchema(parsed.value, path);
  if (path.endsWith('/package.json') || path === 'package.json') return validatePackage(parsed.value, path);
  return [];
}
