// Configuration and credential handling for the USF semantic compiler.
//
// Reads connection configuration exclusively from the process environment.
// Credentials are never logged, never persisted, and never placed in errors.
// No dotenv file is loaded here: the environment is the sole source.

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

// The default database is USF, and only USF, when the environment omits one.
const DEFAULT_DATABASE = 'USF';

const isNonEmpty = (v) => typeof v === 'string' && v.trim().length > 0;

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

// Produce the validated, immutable connection configuration. Token
// authentication takes precedence over username/password. Absence of any
// usable credential is fatal.
export function loadConfig(env = process.env) {
  if (!isNonEmpty(env.STARDOG_SERVER)) {
    throw new ConfigError('STARDOG_SERVER is required');
  }
  const endpoint = requireCloudEndpoint(env.STARDOG_SERVER.trim());
  const database = isNonEmpty(env.STARDOG_DATABASE) ? env.STARDOG_DATABASE.trim() : DEFAULT_DATABASE;

  let auth;
  if (isNonEmpty(env.STARDOG_TOKEN)) {
    auth = Object.freeze({ kind: 'token', token: env.STARDOG_TOKEN.trim() });
  } else if (isNonEmpty(env.STARDOG_USERNAME) && isNonEmpty(env.STARDOG_PASSWORD)) {
    auth = Object.freeze({
      kind: 'basic',
      username: env.STARDOG_USERNAME.trim(),
      password: env.STARDOG_PASSWORD,
    });
  } else {
    throw new ConfigError(
      'No credentials: set STARDOG_TOKEN, or STARDOG_USERNAME and STARDOG_PASSWORD'
    );
  }

  return Object.freeze({ endpoint, database, auth });
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
