import assert from 'node:assert/strict';
import test from 'node:test';

import {
  SemanticAuthorityConfigurationError,
  describeSemanticAuthorityConfiguration,
  resolveLiveSemanticAuthorityConfiguration,
  validateSemanticAuthorityConfiguration,
} from './semantic-authority.mjs';

const digest = `sha256:${'a'.repeat(64)}`;

test('validates live configuration with opaque secret references', () => {
  const input = { accessMode: 'live', expectedAuthorityDigest: digest, endpoint: 'https://authority.example.test/', database: 'USF', authentication: { mode: 'token', tokenReference: 'secret://semantic-authority/token' } };
  const configuration = validateSemanticAuthorityConfiguration(input);
  assert.equal(configuration.endpoint, 'https://authority.example.test');
  const resolved = resolveLiveSemanticAuthorityConfiguration(input, (reference) => reference.endsWith('/token') ? 'credential' : null);
  assert.equal(resolved.auth.kind, 'token');
  assert.equal(describeSemanticAuthorityConfiguration(input).authenticationMode, 'token');
  assert.equal(JSON.stringify(describeSemanticAuthorityConfiguration(input)).includes('credential'), false);
});

test('requires complete basic authentication and an explicit resolver', () => {
  const input = { accessMode: 'live', expectedAuthorityDigest: digest, endpoint: 'https://authority.example.test', database: 'USF', authentication: { mode: 'basic', usernameReference: 'secret://semantic-authority/username', passwordReference: 'secret://semantic-authority/password' } };
  assert.equal(resolveLiveSemanticAuthorityConfiguration(input, (reference) => reference.split('/').at(-1)).auth.username, 'username');
  assert.throws(() => resolveLiveSemanticAuthorityConfiguration(input), SemanticAuthorityConfigurationError);
  assert.throws(() => validateSemanticAuthorityConfiguration({ ...input, authentication: { mode: 'basic', usernameReference: 'secret://semantic-authority/username' } }), /password reference/);
});

test('validates digest-bound verified exports without live connection fields', () => {
  const exportDigest = `sha256:${'b'.repeat(64)}`;
  const input = { accessMode: 'verified-export', expectedAuthorityDigest: digest, exportDigest, exportLocator: `cas://sha256/${'b'.repeat(64)}` };
  assert.equal(validateSemanticAuthorityConfiguration(input).accessMode, 'verified-export');
  assert.throws(() => validateSemanticAuthorityConfiguration({ ...input, endpoint: 'https://authority.example.test' }), /must not contain live/);
  assert.throws(() => validateSemanticAuthorityConfiguration({ ...input, exportLocator: `cas://sha256/${'c'.repeat(64)}` }), /must match/);
});

test('rejects ambient defaults, raw secrets and unsafe endpoints', () => {
  assert.throws(() => validateSemanticAuthorityConfiguration({}), /expected authority digest/);
  assert.throws(() => validateSemanticAuthorityConfiguration({ accessMode: 'live', expectedAuthorityDigest: digest, endpoint: 'http://localhost:5820', database: 'USF', authentication: { mode: 'token', tokenReference: 'raw-token' } }), SemanticAuthorityConfigurationError);
  assert.throws(() => validateSemanticAuthorityConfiguration({ accessMode: 'live', expectedAuthorityDigest: digest, endpoint: 'https://user:pass@authority.example.test', database: 'USF', authentication: { mode: 'token', tokenReference: 'secret://semantic-authority/token' } }), /must not contain credentials/);
});
