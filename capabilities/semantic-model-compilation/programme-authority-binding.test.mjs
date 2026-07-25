// Regression tests for the programme authority-binding input contract and for
// the absence of any compiled-in authority identity in programme generation.
//
// The defect these guard against is specific: a generator that pins its own
// authority digest emits a checkpoint, packet, projection, inventory, registry,
// analysis and proof set that all agree with one another while every one of
// them is bound to superseded truth. Mutual agreement is exactly what stops
// such a set from failing closed, so the guard cannot be "the digests match" —
// it has to be "no digest is compiled in at all".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AUTHORITY_BINDING_RECORD_KIND,
  AUTHORITY_BINDING_SCHEMA_VERSION,
  AUTHORITY_WITNESS_ALGORITHM,
  AuthorityBindingError,
  assertExactAuthorityPropagation,
  authorityIdentity,
  bindingDigest,
  canonicalBindingBytes,
  graphInventoryDigest,
  loadAuthorityBindingManifest,
  readAuthorityField,
  validateAuthorityBindingManifest,
} from './programme-authority-binding.mjs';
import { buildAuthorityBindingManifest } from '../../processes/semantic-assurance/programme-authority-capture.mjs';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

// The exact superseded values the generator used to carry. Kept here, in a
// test, so the constants exist in exactly one place in the repository and that
// place is the thing asserting they are gone.
const SUPERSEDED_AUTHORITY_DIGEST = 'sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd';
const SUPERSEDED_TRIPLE_COUNT = '86536';

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;

const inventory = (count = 2) => Array.from({ length: count }, (_, index) => ({
  graph: `urn:usf:graph:g${index}`,
  sha256: createHash('sha256').update(`g${index}`).digest('hex'),
  triples: index + 1,
}));

function manifest(overrides = {}) {
  const graphInventory = overrides.graphInventory ?? inventory();
  const base = {
    authority: {
      database: 'USF',
      digest: DIGEST_A,
      digestAlgorithm: AUTHORITY_WITNESS_ALGORITHM,
      endpoint: 'https://example.invalid:5820',
      graphCount: graphInventory.length,
      graphInventory,
      graphInventoryDigest: graphInventoryDigest(graphInventory),
      tripleCount: 1234,
    },
    capture: {
      capturedAt: '2026-07-25T00:00:00Z',
      method: 'USF_SEMANTIC_AUTHORITY_GATEWAY_WITNESS',
      toolDigest: DIGEST_B,
      witnessSource: 'readSemanticAuthorityWitness',
    },
    recordKind: AUTHORITY_BINDING_RECORD_KIND,
    schemaVersion: AUTHORITY_BINDING_SCHEMA_VERSION,
    waveArtefacts: [
      { authorityField: 'authorityDigest', fileDigest: DIGEST_B, path: '.work/generated/a.json', role: 'alpha' },
    ],
  };
  return {
    ...base,
    ...overrides,
    authority: { ...base.authority, ...(overrides.authority ?? {}) },
    capture: { ...base.capture, ...(overrides.capture ?? {}) },
  };
}

const codeOf = (fn) => {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof AuthorityBindingError, `expected AuthorityBindingError, got ${error}`);
    return error.code;
  }
  return null;
};

// ---------------------------------------------------------------------------
// No hard-coded authority in executable generation logic
// ---------------------------------------------------------------------------

test('no executable generation logic carries the superseded authority digest or triple count', () => {
  const generationSources = [
    'operations/programme/update-checkpoint.mjs',
    'capabilities/semantic-model-compilation/programme-authority-binding.mjs',
    'processes/semantic-assurance/programme-authority-capture.mjs',
    'processes/semantic-assurance/permutation-authority-projection-capture.mjs',
  ];
  for (const source of generationSources) {
    const text = readFileSync(join(repositoryRoot, source), 'utf8');
    assert.equal(
      text.includes(SUPERSEDED_AUTHORITY_DIGEST),
      false,
      `${source} still carries the superseded authority digest`,
    );
    assert.equal(
      text.includes(SUPERSEDED_TRIPLE_COUNT),
      false,
      `${source} still carries the superseded triple count`,
    );
  }
});

test('no generation source assigns an authority identity or count from a literal', () => {
  // A fresh digest pinned in source is the same defect wearing a new value.
  // Other digests legitimately appear in these files — the GOAL.md digest, CAS
  // acquisition digests, SHACL evidence digests — so the assertion is scoped to
  // assignments that establish authority identity or its observational counts,
  // which are the only values that must come from the supplied binding.
  const generationSources = [
    'operations/programme/update-checkpoint.mjs',
    'processes/semantic-assurance/programme-authority-capture.mjs',
    'processes/semantic-assurance/permutation-authority-projection-capture.mjs',
  ];
  // Scoped to key names that unambiguously denote authority identity.
  // `internalDigest` is deliberately excluded: it names content digests of
  // several unrelated inventories, and the wave binding that does use it now
  // reads from the supplied binding, which the propagation tests cover.
  const literalIdentity = /(authorityDigest|currentDigest|evaluatedAuthorityDigest)\s*[:=]\s*['"`]sha256:[0-9a-f]{64}/u;
  const literalCount = /(tripleCount|graphCount)\s*[:=]\s*[0-9]+/u;
  for (const source of generationSources) {
    const lines = readFileSync(join(repositoryRoot, source), 'utf8').split('\n');
    lines.forEach((line, index) => {
      assert.equal(
        literalIdentity.test(line),
        false,
        `${source}:${index + 1} assigns an authority identity from a literal: ${line.trim()}`,
      );
      assert.equal(
        literalCount.test(line),
        false,
        `${source}:${index + 1} assigns an authority count from a literal: ${line.trim()}`,
      );
    });
  }
});

// ---------------------------------------------------------------------------
// Explicit binding required; malformed bindings refused
// ---------------------------------------------------------------------------

test('the checkpoint generator fails closed when no authority binding is supplied', () => {
  let failed = false;
  let stderr = '';
  try {
    execFileSync('node', ['operations/programme/update-checkpoint.mjs'], {
      cwd: repositoryRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    failed = true;
    stderr = String(error.stderr ?? '');
  }
  assert.equal(failed, true, 'generation must not succeed without an authority binding');
  assert.match(stderr, /--authority-binding=<value> argument is required/u);
});

test('a manifest is refused without an exact expected digest', () => {
  const bytes = canonicalBindingBytes(manifest());
  assert.equal(
    codeOf(() => loadAuthorityBindingManifest({ bytes, expectedDigest: undefined })),
    'AUTHORITY_BINDING_EXPECTED_DIGEST_REQUIRED',
  );
});

test('a manifest whose bytes do not match the expected digest is refused', () => {
  const bytes = canonicalBindingBytes(manifest());
  assert.equal(
    codeOf(() => loadAuthorityBindingManifest({ bytes, expectedDigest: DIGEST_B })),
    'AUTHORITY_BINDING_DIGEST_MISMATCH',
  );
});

test('malformed and incomplete manifests are refused with stable codes', () => {
  const cases = [
    ['AUTHORITY_BINDING_MALFORMED', () => validateAuthorityBindingManifest(null)],
    ['AUTHORITY_BINDING_RECORD_KIND_INVALID', () => validateAuthorityBindingManifest(manifest({ recordKind: 'OTHER' }))],
    ['AUTHORITY_BINDING_SCHEMA_VERSION_INVALID', () => validateAuthorityBindingManifest(manifest({ schemaVersion: 99 }))],
    ['AUTHORITY_BINDING_DIGEST_INVALID', () => validateAuthorityBindingManifest(manifest({ authority: { digest: 'nope' } }))],
    ['AUTHORITY_BINDING_ALGORITHM_INVALID', () => validateAuthorityBindingManifest(manifest({ authority: { digestAlgorithm: 'md5' } }))],
    ['AUTHORITY_BINDING_TRIPLE_COUNT_INVALID', () => validateAuthorityBindingManifest(manifest({ authority: { tripleCount: -1 } }))],
    ['AUTHORITY_BINDING_GRAPH_COUNT_MISMATCH', () => validateAuthorityBindingManifest(manifest({ authority: { graphCount: 99 } }))],
    ['AUTHORITY_BINDING_DATABASE_INVALID', () => validateAuthorityBindingManifest(manifest({ authority: { database: '' } }))],
    ['AUTHORITY_BINDING_ENDPOINT_INVALID', () => validateAuthorityBindingManifest(manifest({ authority: { endpoint: 'ftp://x' } }))],
    ['AUTHORITY_BINDING_CAPTURED_AT_INVALID', () => validateAuthorityBindingManifest(manifest({ capture: { capturedAt: 'yesterday' } }))],
    ['AUTHORITY_BINDING_CAPTURE_METHOD_INVALID', () => validateAuthorityBindingManifest(manifest({ capture: { method: 'GUESSED' } }))],
    ['AUTHORITY_BINDING_CAPTURE_TOOL_DIGEST_INVALID', () => validateAuthorityBindingManifest(manifest({ capture: { toolDigest: 'x' } }))],
    ['AUTHORITY_BINDING_WAVE_ABSENT', () => validateAuthorityBindingManifest(manifest({ waveArtefacts: [] }))],
  ];
  for (const [expected, run] of cases) assert.equal(codeOf(run), expected, `expected ${expected}`);
});

test('an edited graph inventory is detected through its recorded digest', () => {
  const tampered = manifest();
  tampered.authority.graphInventory[0].triples += 1;
  assert.equal(
    codeOf(() => validateAuthorityBindingManifest(tampered)),
    'AUTHORITY_BINDING_INVENTORY_DIGEST_MISMATCH',
  );
});

test('the manifest records every required element of the captured binding', () => {
  const loaded = loadAuthorityBindingManifest({
    bytes: canonicalBindingBytes(manifest()),
    expectedDigest: bindingDigest(canonicalBindingBytes(manifest())),
  });
  for (const field of ['digest', 'tripleCount', 'graphCount', 'database', 'digestAlgorithm', 'endpoint', 'graphInventoryDigest']) {
    assert.notEqual(loaded.authority[field], undefined, `authority.${field} is required`);
  }
  for (const field of ['capturedAt', 'method', 'toolDigest', 'witnessSource']) {
    assert.notEqual(loaded.capture[field], undefined, `capture.${field} is required`);
  }
});

// ---------------------------------------------------------------------------
// Exact propagation, mismatch rejection, authority advancement
// ---------------------------------------------------------------------------

test('exact propagation accepts an artefact set that all binds the supplied identity', () => {
  const binding = validateAuthorityBindingManifest(manifest());
  const identity = assertExactAuthorityPropagation({
    artefacts: [
      { observedDigest: DIGEST_A, role: 'checkpoint' },
      { observedDigest: DIGEST_A, role: 'packet' },
      { observedDigest: DIGEST_A, role: 'projection' },
      { observedDigest: DIGEST_A, role: 'inventory' },
      { observedDigest: DIGEST_A, role: 'analysis' },
      { observedDigest: DIGEST_A, role: 'proof' },
      { boundByReference: true, observedDigest: null, role: 'registry' },
    ],
    binding,
  });
  assert.equal(identity, DIGEST_A);
});

test('a single divergent artefact fails the whole generation', () => {
  const binding = validateAuthorityBindingManifest(manifest());
  let caught;
  try {
    assertExactAuthorityPropagation({
      artefacts: [
        { observedDigest: DIGEST_A, role: 'checkpoint' },
        { observedDigest: DIGEST_A, role: 'packet' },
        { observedDigest: DIGEST_B, role: 'projection' },
      ],
      binding,
    });
  } catch (error) {
    caught = error;
  }
  assert.equal(caught?.code, 'AUTHORITY_PROPAGATION_MISMATCH');
  assert.deepEqual(caught.details.divergent, [{ observedDigest: DIGEST_B, role: 'projection' }]);
});

test('an artefact missing its authority binding entirely is divergent, not ignored', () => {
  const binding = validateAuthorityBindingManifest(manifest());
  const code = codeOf(() => assertExactAuthorityPropagation({
    artefacts: [
      { observedDigest: DIGEST_A, role: 'packet' },
      { observedDigest: undefined, role: 'analysis' },
    ],
    binding,
  }));
  assert.equal(code, 'AUTHORITY_PROPAGATION_MISMATCH');
});

test('an artefact declared bound-by-reference may not smuggle in a divergent digest', () => {
  const binding = validateAuthorityBindingManifest(manifest());
  const code = codeOf(() => assertExactAuthorityPropagation({
    artefacts: [
      { observedDigest: DIGEST_A, role: 'packet' },
      { boundByReference: true, observedDigest: DIGEST_B, role: 'registry' },
    ],
    binding,
  }));
  assert.equal(code, 'AUTHORITY_PROPAGATION_MISMATCH');
});

test('a propagation check with nothing to check fails rather than passing vacuously', () => {
  const binding = validateAuthorityBindingManifest(manifest());
  assert.equal(
    codeOf(() => assertExactAuthorityPropagation({
      artefacts: [{ boundByReference: true, observedDigest: null, role: 'registry' }],
      binding,
    })),
    'AUTHORITY_PROPAGATION_UNCHECKED',
  );
  assert.equal(
    codeOf(() => assertExactAuthorityPropagation({ artefacts: [], binding })),
    'AUTHORITY_PROPAGATION_EMPTY',
  );
});

test('authority advancement rebinds every artefact and retains nothing from the old identity', () => {
  const advanced = validateAuthorityBindingManifest(manifest({ authority: { digest: DIGEST_B } }));
  assert.equal(authorityIdentity(advanced), DIGEST_B);
  // The whole artefact set moves to B.
  assert.equal(
    assertExactAuthorityPropagation({
      artefacts: ['checkpoint', 'packet', 'projection', 'inventory', 'analysis', 'proof']
        .map((role) => ({ observedDigest: DIGEST_B, role })),
      binding: advanced,
    }),
    DIGEST_B,
  );
  // Any artefact still carrying A is rejected: silent retention is the defect.
  const code = codeOf(() => assertExactAuthorityPropagation({
    artefacts: [
      { observedDigest: DIGEST_B, role: 'checkpoint' },
      { observedDigest: DIGEST_A, role: 'inventory' },
    ],
    binding: advanced,
  }));
  assert.equal(code, 'AUTHORITY_PROPAGATION_MISMATCH');
});

// ---------------------------------------------------------------------------
// Triple count is observational metadata, never identity
// ---------------------------------------------------------------------------

test('authority identity reads the digest alone and ignores the observational counts', () => {
  const low = validateAuthorityBindingManifest(manifest({ authority: { tripleCount: 1, graphCount: 2 } }));
  const high = validateAuthorityBindingManifest(manifest({ authority: { tripleCount: 999999 } }));
  assert.equal(authorityIdentity(low), authorityIdentity(high));
  assert.equal(authorityIdentity(low), DIGEST_A);
});

test('a matching triple count cannot rescue a divergent authority digest', () => {
  // Same observational counts on both sides, different identity: the counts
  // must not make this pass.
  const binding = validateAuthorityBindingManifest(manifest({ authority: { tripleCount: 106783 } }));
  const code = codeOf(() => assertExactAuthorityPropagation({
    artefacts: [{ observedDigest: DIGEST_B, role: 'inventory' }],
    binding,
  }));
  assert.equal(code, 'AUTHORITY_PROPAGATION_MISMATCH');
});

test('a differing triple count cannot break an otherwise exact identity match', () => {
  const binding = validateAuthorityBindingManifest(manifest({ authority: { tripleCount: 7 } }));
  assert.equal(
    assertExactAuthorityPropagation({
      artefacts: [{ observedDigest: DIGEST_A, role: 'inventory' }],
      binding,
    }),
    DIGEST_A,
  );
});

// ---------------------------------------------------------------------------
// Capture-time behaviour
// ---------------------------------------------------------------------------

const witness = (digest = DIGEST_A) => ({
  algorithm: AUTHORITY_WITNESS_ALGORITHM,
  digest,
  inventory: inventory(),
  triples: 4242,
});

test('capture refuses to write a manifest when a wave artefact binds a different authority', () => {
  let caught;
  try {
    buildAuthorityBindingManifest({
      capturedAt: '2026-07-25T00:00:00Z',
      database: 'USF',
      endpoint: 'https://example.invalid:5820',
      readArtefact: () => Buffer.from(JSON.stringify({ authorityDigest: DIGEST_B })),
      toolDigest: DIGEST_B,
      waveArtefacts: [{ authorityField: 'authorityDigest', path: '.work/generated/stale.json', role: 'inventory' }],
      witness: witness(DIGEST_A),
    });
  } catch (error) {
    caught = error;
  }
  assert.equal(caught?.code, 'AUTHORITY_CAPTURE_WAVE_DIVERGENT');
  assert.equal(caught.details.capturedAuthorityDigest, DIGEST_A);
});

test('capture binds a wave that already agrees with live authority', () => {
  const built = buildAuthorityBindingManifest({
    capturedAt: '2026-07-25T00:00:00Z',
    database: 'USF',
    endpoint: 'https://example.invalid:5820',
    readArtefact: () => Buffer.from(JSON.stringify({ authorityBinding: { authorityDigest: DIGEST_A } })),
    toolDigest: DIGEST_B,
    waveArtefacts: [{ authorityField: 'authorityBinding.authorityDigest', path: '.work/generated/i.json', role: 'inventory' }],
    witness: witness(DIGEST_A),
  });
  assert.equal(built.authority.digest, DIGEST_A);
  assert.equal(built.authority.tripleCount, 4242);
  assert.equal(built.authority.graphCount, 2);
  assert.equal(built.capture.method, 'USF_SEMANTIC_AUTHORITY_GATEWAY_WITNESS');
});

test('capture rejects a bound-by-reference declaration on an artefact that does carry a digest', () => {
  let caught;
  try {
    buildAuthorityBindingManifest({
      capturedAt: '2026-07-25T00:00:00Z',
      database: 'USF',
      endpoint: 'https://example.invalid:5820',
      readArtefact: () => Buffer.from(JSON.stringify({ authorityDigest: DIGEST_A })),
      toolDigest: DIGEST_B,
      waveArtefacts: [{ authorityField: null, path: '.work/generated/r.json', role: 'registry' }],
      witness: witness(DIGEST_A),
    });
  } catch (error) {
    caught = error;
  }
  assert.equal(caught?.code, 'AUTHORITY_CAPTURE_FIELD_DECLARATION_INVALID');
});

// ---------------------------------------------------------------------------
// Deterministic generation for identical explicit inputs
// ---------------------------------------------------------------------------

test('identical repository tree and authority binding reproduce byte-identical output', (t) => {
  // Needs the operator-local CAS payload the generator verifies, plus a live
  // binding manifest. Skipped rather than failed where those are absent.
  const state = join(repositoryRoot, '.work', 'programme');
  const generated = join(repositoryRoot, '.work', 'generated');
  if (!existsSync(join(state, 'checkpoint.json')) || !existsSync(generated)) {
    return t.skip('programme state is not materialised in this environment');
  }
  const manifests = readdirSync(generated).filter((name) => name.startsWith('programme-authority-binding-'));
  if (manifests.length === 0) return t.skip('no captured authority binding manifest is present');
  const manifestPath = join('.work', 'generated', manifests.sort().at(-1));
  const manifestDigest = bindingDigest(readFileSync(join(repositoryRoot, manifestPath)));

  const prior = readFileSync(join(state, 'checkpoint.json'));
  const digestsOf = () => ['checkpoint.json', 'programme-ledger.json', 'changed-paths.json']
    .map((name) => bindingDigest(readFileSync(join(state, name))));

  const run = () => {
    writeFileSync(join(state, 'checkpoint.json'), prior);
    execFileSync('node', [
      'operations/programme/update-checkpoint.mjs',
      `--authority-binding=${manifestPath}`,
      `--authority-binding-digest=${manifestDigest}`,
      '--recorded-at=2026-01-01T00:00:00Z',
    ], { cwd: repositoryRoot, stdio: ['ignore', 'ignore', 'pipe'] });
    return digestsOf();
  };

  try {
    assert.deepEqual(run(), run(), 'identical inputs must reproduce identical generated bytes');
  } finally {
    writeFileSync(join(state, 'checkpoint.json'), prior);
  }
});

test('dotted authority field paths resolve, and absent paths read as undefined', () => {
  const record = { authorityBinding: { authorityDigest: DIGEST_A } };
  assert.equal(readAuthorityField(record, 'authorityBinding.authorityDigest'), DIGEST_A);
  assert.equal(readAuthorityField(record, 'missing.path'), undefined);
  assert.equal(readAuthorityField(record, null), null);
});
