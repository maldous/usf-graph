// Publication receipt contract, kept free of side effects so any consumer can
// import it without pulling in the publication entrypoint's transport setup.
//
// A receipt describes what a publication did. It is not itself an authority
// witness, and exactly one field in it may be read as current authority.
//
// Two defects shaped this module. The first: `postAuthorityDigest` folded an
// eventually consistent server statement count into a content digest, so a
// receipt read immediately after a commit named a digest that matched no settled
// authority state while looking exactly like one. The second: the guard trusted
// the receipt's own `settled.stable` boolean, so a receipt whose
// afterPublication and settled witnesses disagreed passed review by asserting
// `stable: true` about itself. Nothing in a receipt is evidence for itself now —
// stability is derived from the phase records, and a declared `stable` is only
// ever cross-checked against the derived result.

export const PUBLICATION_RECEIPT_SCHEMA_VERSION = 2;
export const WITNESS_TOTAL_SOURCE = 'canonical-graph-inventory';
export const WITNESS_ALGORITHM = 'sha256-rdfc10-graph-inventory-v2';
export const WITNESS_PHASES = Object.freeze(['beforePublication', 'afterPublication', 'settled']);
export const PUBLICATION_MODES = Object.freeze(['validate', 'commit']);

// Lowercase hex only. An uppercase or short digest is a different string from the
// one the witness produces, and accepting it would let two spellings of "the same"
// authority compare unequal elsewhere.
const EXACT_DIGEST = /^sha256:[0-9a-f]{64}$/;

// Fields that existed before the witness total became content-derived. A consumer
// still reading them is reading a witness that never existed.
export const REJECTED_RECEIPT_FIELDS = Object.freeze(['postAuthorityDigest', 'postTriples', 'evaluatedAuthorityDigest']);

function fail(message) {
  throw new Error(`publication receipt ${message}`);
}

function exactDigest(value, label) {
  if (typeof value !== 'string' || !EXACT_DIGEST.test(value)) {
    fail(`${label} is not an exact lowercase sha256:<64 hex> authority digest: ${JSON.stringify(value ?? null)}`);
  }
  return value;
}

function safeCount(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${label} is not a non-negative safe integer: ${JSON.stringify(value ?? null)}`);
  }
  return value;
}

function exactPhase(witness, phase) {
  const state = witness[phase];
  if (!state || typeof state !== 'object' || Array.isArray(state)) fail(`witness phase ${phase} is absent or not an object`);
  return {
    digest: exactDigest(state.digest, `witness phase ${phase} digest`),
    graphCount: safeCount(state.graphCount, `witness phase ${phase} graphCount`),
    triples: safeCount(state.triples, `witness phase ${phase} triples`),
    declaredStable: state.stable,
  };
}

// Stability is a conclusion about two independent reads of the same content, so
// it is computed from those reads and never taken from the receipt. Complete
// equality is required: equal digests with different counts would mean the two
// readings disagreed about what they measured.
function derivedStability(afterPublication, settled) {
  return afterPublication.digest === settled.digest
    && afterPublication.graphCount === settled.graphCount
    && afterPublication.triples === settled.triples;
}

// Call this before trusting any receipt field.
export function assertSupportedPublicationReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    fail('is absent or not an object');
  }
  if (receipt.receiptSchemaVersion !== PUBLICATION_RECEIPT_SCHEMA_VERSION) {
    fail(`schema is unsupported: expected ${PUBLICATION_RECEIPT_SCHEMA_VERSION}, saw ${JSON.stringify(receipt.receiptSchemaVersion ?? null)}`);
  }
  const superseded = REJECTED_RECEIPT_FIELDS.filter((field) => field in receipt);
  if (superseded.length > 0) {
    fail(`carries superseded fields that are not authority witnesses: ${superseded.join(', ')}`);
  }
  if (!PUBLICATION_MODES.includes(receipt.mode)) {
    fail(`mode must be one of ${PUBLICATION_MODES.join(', ')}, saw ${JSON.stringify(receipt.mode ?? null)}`);
  }
  const witness = receipt.authorityWitness;
  if (!witness || typeof witness !== 'object' || Array.isArray(witness)) fail('has no authority witness');
  if (witness.algorithm !== WITNESS_ALGORITHM) {
    fail(`witness algorithm must be ${WITNESS_ALGORITHM}, saw ${JSON.stringify(witness.algorithm ?? null)}`);
  }
  if (witness.totalSource !== WITNESS_TOTAL_SOURCE) {
    fail(`witness total must be derived from ${WITNESS_TOTAL_SOURCE}, saw ${JSON.stringify(witness.totalSource ?? null)}`);
  }

  const phases = Object.fromEntries(WITNESS_PHASES.map((phase) => [phase, exactPhase(witness, phase)]));
  const expected = exactDigest(witness.expected, 'witness expected');
  const evaluated = exactDigest(witness.evaluated, 'witness evaluated');

  // The publication is a compare-and-swap: it asserted live authority was at
  // `expected` before starting, and the compiler evaluated that same authority.
  // Any disagreement means the receipt describes a different operation than the
  // one its own fields claim.
  if (phases.beforePublication.digest !== expected) {
    fail(`witness beforePublication ${phases.beforePublication.digest} does not equal the expected authority ${expected}`);
  }
  if (evaluated !== expected) {
    fail(`witness evaluated ${evaluated} does not equal the expected authority ${expected}`);
  }

  const stable = derivedStability(phases.afterPublication, phases.settled);
  if (!stable) {
    fail('settled witness does not equal the post-publication witness; live authority was still changing');
  }
  // A declared flag is permitted in the schema but is never evidence. If present
  // it must agree with the derived result, so a forged value is a rejection
  // rather than a silent disagreement.
  if (phases.settled.declaredStable !== undefined && phases.settled.declaredStable !== stable) {
    fail(`settled.stable declares ${JSON.stringify(phases.settled.declaredStable)} but the phase records derive ${stable}`);
  }

  // validate-and-rollback must leave authority exactly as it found it. Proving
  // that is the whole point of the mode, so the receipt has to show it.
  if (receipt.mode === 'validate' && phases.settled.digest !== phases.beforePublication.digest) {
    fail(`validate mode did not restore the original authority: settled ${phases.settled.digest} differs from beforePublication ${phases.beforePublication.digest}`);
  }
  return receipt;
}

// The only field a consumer may treat as current authority, and only through this
// accessor so the complete guard can never be skipped.
export function settledAuthorityDigest(receipt) {
  return assertSupportedPublicationReceipt(receipt).authorityWitness.settled.digest;
}
