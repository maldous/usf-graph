const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SECRET_REFERENCE = /^secret:\/\/[a-z][a-z0-9]*(?:[./_-][a-z0-9]+)*$/;
const DATABASE_NAME = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;

export class SemanticAuthorityConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SemanticAuthorityConfigurationError';
  }
}

function nonEmpty(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function validateEndpoint(value) {
  let endpoint;
  try { endpoint = new URL(value); } catch { throw new SemanticAuthorityConfigurationError('semantic authority endpoint must be an absolute URL'); }
  if (endpoint.protocol !== 'https:') throw new SemanticAuthorityConfigurationError('semantic authority endpoint must use https');
  if (endpoint.username || endpoint.password) throw new SemanticAuthorityConfigurationError('semantic authority endpoint must not contain credentials');
  if (endpoint.search || endpoint.hash) throw new SemanticAuthorityConfigurationError('semantic authority endpoint must not contain query or fragment data');
  const host = endpoint.hostname.toLowerCase();
  if (['localhost', '127.0.0.1', '::1', '0.0.0.0'].includes(host)) throw new SemanticAuthorityConfigurationError('live semantic authority endpoint must not be loopback');
  return value.replace(/\/+$/, '');
}

function secretReference(value, label) {
  if (!SECRET_REFERENCE.test(value || '')) throw new SemanticAuthorityConfigurationError(`${label} must be an opaque secret:// reference`);
  return value;
}

function authentication(input) {
  if (!input || typeof input !== 'object') throw new SemanticAuthorityConfigurationError('live semantic authority authentication is required');
  if (input.mode === 'token') {
    if (input.usernameReference !== undefined || input.passwordReference !== undefined) throw new SemanticAuthorityConfigurationError('token authentication must not contain basic-auth references');
    return Object.freeze({ mode: 'token', tokenReference: secretReference(input.tokenReference, 'token reference') });
  }
  if (input.mode === 'basic') {
    if (input.tokenReference !== undefined) throw new SemanticAuthorityConfigurationError('basic authentication must not contain a token reference');
    return Object.freeze({
      mode: 'basic',
      usernameReference: secretReference(input.usernameReference, 'username reference'),
      passwordReference: secretReference(input.passwordReference, 'password reference'),
    });
  }
  throw new SemanticAuthorityConfigurationError('authentication mode must be token or basic');
}

export function validateSemanticAuthorityConfiguration(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new SemanticAuthorityConfigurationError('semantic authority configuration must be an object');
  if (!SHA256.test(input.expectedAuthorityDigest || '')) throw new SemanticAuthorityConfigurationError('expected authority digest is required');
  if (input.accessMode === 'live') {
    if (!nonEmpty(input.endpoint)) throw new SemanticAuthorityConfigurationError('live semantic authority endpoint is required');
    if (!DATABASE_NAME.test(input.database || '')) throw new SemanticAuthorityConfigurationError('live semantic authority database is required');
    return Object.freeze({
      accessMode: 'live',
      expectedAuthorityDigest: input.expectedAuthorityDigest,
      endpoint: validateEndpoint(input.endpoint.trim()),
      database: input.database,
      authentication: authentication(input.authentication),
    });
  }
  if (input.accessMode === 'verified-export') {
    if (!SHA256.test(input.exportDigest || '')) throw new SemanticAuthorityConfigurationError('verified authority export digest is required');
    const expectedLocator = `cas://sha256/${input.exportDigest.slice(7)}`;
    if (input.exportLocator !== expectedLocator) throw new SemanticAuthorityConfigurationError('verified authority export locator must match its digest');
    if (input.endpoint !== undefined || input.database !== undefined || input.authentication !== undefined) throw new SemanticAuthorityConfigurationError('verified-export mode must not contain live connection configuration');
    return Object.freeze({
      accessMode: 'verified-export',
      expectedAuthorityDigest: input.expectedAuthorityDigest,
      exportDigest: input.exportDigest,
      exportLocator: input.exportLocator,
    });
  }
  throw new SemanticAuthorityConfigurationError('semantic authority access mode must be live or verified-export');
}

export function resolveLiveSemanticAuthorityConfiguration(input, resolveSecret) {
  const configuration = validateSemanticAuthorityConfiguration(input);
  if (configuration.accessMode !== 'live') throw new SemanticAuthorityConfigurationError('live credential resolution requires live access mode');
  if (typeof resolveSecret !== 'function') throw new SemanticAuthorityConfigurationError('an explicit secret resolver is required');
  const resolve = (reference, label) => {
    const value = resolveSecret(reference);
    if (!nonEmpty(value)) throw new SemanticAuthorityConfigurationError(`${label} did not resolve to a non-empty secret`);
    return value;
  };
  const auth = configuration.authentication.mode === 'token'
    ? Object.freeze({ kind: 'token', token: resolve(configuration.authentication.tokenReference, 'token reference') })
    : Object.freeze({
      kind: 'basic',
      username: resolve(configuration.authentication.usernameReference, 'username reference'),
      password: resolve(configuration.authentication.passwordReference, 'password reference'),
    });
  return Object.freeze({ endpoint: configuration.endpoint, database: configuration.database, expectedAuthorityDigest: configuration.expectedAuthorityDigest, auth });
}

export function describeSemanticAuthorityConfiguration(input) {
  const configuration = validateSemanticAuthorityConfiguration(input);
  return configuration.accessMode === 'live'
    ? Object.freeze({ accessMode: 'live', endpoint: configuration.endpoint, database: configuration.database, expectedAuthorityDigest: configuration.expectedAuthorityDigest, authenticationMode: configuration.authentication.mode })
    : Object.freeze({ accessMode: 'verified-export', exportDigest: configuration.exportDigest, exportLocator: configuration.exportLocator, expectedAuthorityDigest: configuration.expectedAuthorityDigest });
}
