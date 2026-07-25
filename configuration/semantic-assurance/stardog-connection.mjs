// Stardog connection configuration for canonical semantic-assurance processes.
//
// Resolution order, mirroring the read-only MCP launcher in .mcp.json exactly:
//
//     set -a; [ -f "${USF_ENV_FILE:-./.env}" ] && . "${USF_ENV_FILE:-./.env}"; set +a
//
// The operator env file is loaded here and its values OVERRIDE the inherited
// process environment for the STARDOG_* keys. That inversion is deliberate.
// Stardog Cloud Free reclaims an endpoint after inactivity and the replacement
// endpoint has a different hostname, so a long-lived process that trusts only
// its inherited environment keeps a dead STARDOG_SERVER for the rest of its
// life while the operator's env file already names the live endpoint. Hardening
// only the read path left the MUTATING publication path able to target a dead
// or, worse, a different host; both paths must resolve identically.
//
// USF_ENV_FILE is read from the inherited environment only, exactly as the
// launcher expands it before sourcing: the file cannot choose which file loads.
// An absent, non-regular or unreadable env file is not an error — the inherited
// environment remains the fallback.
//
// Parsing is deliberately narrower than shell sourcing and executes nothing:
// only `KEY=VALUE` (optionally `export KEY=VALUE`) assignments are honoured,
// blank lines and whole-line `#` comments are ignored, one layer of matching
// surrounding quotes is removed, and no variable expansion, command
// substitution or trailing-comment stripping is performed. Trailing-comment
// stripping is refused on purpose: it cannot be done without risking silent
// truncation of a credential.
//
// Only STARDOG_* keys are overridden. An operator env file legitimately holds
// unrelated secrets, and loading it must never be able to replace an inherited
// PATH, HOME or any other ambient variable.
//
// Credentials are never logged, never persisted, and never placed in errors:
// every diagnostic in this module carries key NAMES and paths only, and a parse
// failure reports a line NUMBER rather than the line.
import { readFileSync, statSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

// The default database is USF, and only USF, when the environment omits one.
const DEFAULT_DATABASE = 'USF';

// The env-file location variable and the exact default the MCP launcher uses.
export const ENV_FILE_VARIABLE = 'USF_ENV_FILE';
export const DEFAULT_ENV_FILE = './.env';

// Only connection keys may be overridden by the file.
export const OVERRIDABLE_ENVIRONMENT_KEY = /^STARDOG_[A-Z0-9_]+$/u;

const ASSIGNMENT = /^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/u;

const isNonEmpty = (v) => typeof v === 'string' && v.trim().length > 0;

function unquote(raw) {
  const value = raw.trim();
  const quoted = value.length >= 2
    && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")));
  return quoted ? value.slice(1, -1) : value;
}

// Parse operator env-file text into assignments. Nothing is executed and no
// value ever reaches a message: an unparsable line is reported by number only.
export function parseEnvironmentFile(text, path = DEFAULT_ENV_FILE) {
  const values = {};
  String(text).split(/\r?\n/u).forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) return;
    const match = ASSIGNMENT.exec(trimmed);
    if (!match) throw new ConfigError(`${path} line ${index + 1} is not a KEY=VALUE assignment`);
    values[match[1]] = unquote(match[2]);
  });
  return values;
}

// Read the env file if it is a regular file this process can see. A stat
// failure is treated as absence, mirroring `[ -f … ] &&` in the launcher; a
// read failure on a file that does stat is fatal, exactly as `.` would be.
export function readEnvironmentFile(path, { readFile = readFileSync, statFile = statSync } = {}) {
  let stat;
  try {
    stat = statFile(path);
  } catch {
    return null;
  }
  if (!stat?.isFile?.()) return null;
  return parseEnvironmentFile(readFile(path, 'utf8'), path);
}

// Produce the effective environment: inherited values, then STARDOG_* values
// from the operator env file taking precedence. The record reports the file
// path, whether it loaded, and which key NAMES it overrode — never a value.
export function resolveEnvironment(env = process.env, {
  readEnvironmentFile: read = readEnvironmentFile,
  cwd = process.cwd(),
} = {}) {
  const configured = isNonEmpty(env[ENV_FILE_VARIABLE]) ? env[ENV_FILE_VARIABLE].trim() : DEFAULT_ENV_FILE;
  const envFilePath = isAbsolute(configured) ? configured : resolve(cwd, configured);
  const values = read(envFilePath);
  const merged = { ...env };
  const overriddenKeys = [];
  for (const key of Object.keys(values ?? {}).sort()) {
    if (!OVERRIDABLE_ENVIRONMENT_KEY.test(key)) continue;
    merged[key] = values[key];
    overriddenKeys.push(key);
  }
  return Object.freeze({
    env: Object.freeze(merged),
    envFilePath,
    envFileLoaded: values !== null,
    overriddenKeys: Object.freeze(overriddenKeys),
  });
}

// Require an explicit HTTPS Stardog Cloud endpoint. A missing scheme, a plain
// http endpoint, or a loopback host is rejected: this compiler targets the
// managed cloud, never a local server.
function requireCloudEndpoint(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError('STARDOG_SERVER is not a valid URL');
  }
  if (url.protocol !== 'https:') {
    throw new ConfigError('STARDOG_SERVER must use https');
  }
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0') {
    throw new ConfigError('STARDOG_SERVER must be a remote Stardog Cloud endpoint, not localhost');
  }
  // Stardog SDK expects an endpoint with no trailing slash.
  return raw.replace(/\/+$/, '');
}

// Produce the validated, immutable connection configuration from the resolved
// environment. Token authentication takes precedence over username/password.
// Absence of any usable credential is fatal.
export function loadConfig(env = process.env, options = {}) {
  const resolution = resolveEnvironment(env, options);
  const effective = resolution.env;
  if (!isNonEmpty(effective.STARDOG_SERVER)) {
    throw new ConfigError('STARDOG_SERVER is required');
  }
  const endpoint = requireCloudEndpoint(effective.STARDOG_SERVER.trim());
  const database = isNonEmpty(effective.STARDOG_DATABASE) ? effective.STARDOG_DATABASE.trim() : DEFAULT_DATABASE;

  let auth;
  if (isNonEmpty(effective.STARDOG_TOKEN)) {
    auth = Object.freeze({ kind: 'token', token: effective.STARDOG_TOKEN.trim() });
  } else if (isNonEmpty(effective.STARDOG_USERNAME) && isNonEmpty(effective.STARDOG_PASSWORD)) {
    auth = Object.freeze({
      kind: 'basic',
      username: effective.STARDOG_USERNAME.trim(),
      password: effective.STARDOG_PASSWORD,
    });
  } else {
    throw new ConfigError(
      'No credentials: set STARDOG_TOKEN, or STARDOG_USERNAME and STARDOG_PASSWORD'
    );
  }

  return Object.freeze({
    endpoint,
    database,
    auth,
    envFilePath: resolution.envFilePath,
    envFileLoaded: resolution.envFileLoaded,
    overriddenKeys: resolution.overriddenKeys,
  });
}

// A safe view for diagnostics: identifies the endpoint and auth mode without
// ever revealing the token, username, or password.
export function describeConfig(config) {
  return Object.freeze({
    endpoint: config.endpoint,
    database: config.database,
    authMode: config.auth.kind,
  });
}

// Where the effective connection values came from. Deliberately kept separate
// from describeConfig so the established diagnostic shape is unchanged. Key
// names only: this record must remain safe to print.
export function describeEnvironmentResolution(config) {
  return Object.freeze({
    envFilePath: config.envFilePath ?? null,
    envFileLoaded: config.envFileLoaded === true,
    envFileOverriddenKeys: Object.freeze([...(config.overriddenKeys ?? [])]),
  });
}
