// Publication receipt contract, kept free of side effects so any consumer can
// import it without pulling in the publication entrypoint's transport setup.
//
// A receipt describes what a publication did. It is not itself an authority
// witness, and exactly one field in it may be read as current authority. The
// previous receipt shape violated that: `postAuthorityDigest` folded an
// eventually consistent server statement count into a content digest, so a
// receipt read immediately after a commit named a digest that matched no
// settled authority state while looking exactly like one. Those fields are now
// rejected on sight rather than tolerated.

export const PUBLICATION_RECEIPT_SCHEMA_VERSION = 2;
export const WITNESS_TOTAL_SOURCE = 'canonical-graph-inventory';
export const WITNESS_PHASES = Object.freeze(['beforePublication', 'afterPublication', 'settled']);
const SHA256 = /^sha256:[0-9a-f]{64}$/;

// Fields that existed before the witness total became content-derived. A
// consumer still reading them is reading a witness that never existed.
export const REJECTED_RECEIPT_FIELDS = Object.freeze(['postAuthorityDigest', 'postTriples', 'evaluatedAuthorityDigest']);

// Call this before trusting any receipt field. Fails closed on an absent, older
// or newer schema version, on any superseded field, on a witness total that did
// not come from the canonical inventory, on a malformed phase, and on a settled
// witness that never stabilised.
export function assertSupportedPublicationReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error('publication receipt is absent or not an object');
  }
  if (receipt.receiptSchemaVersion !== PUBLICATION_RECEIPT_SCHEMA_VERSION) {
    throw new Error(`unsupported publication receipt schema: expected ${PUBLICATION_RECEIPT_SCHEMA_VERSION}, saw ${JSON.stringify(receipt.receiptSchemaVersion ?? null)}`);
  }
  const superseded = REJECTED_RECEIPT_FIELDS.filter((field) => field in receipt);
  if (superseded.length > 0) {
    throw new Error(`publication receipt carries superseded fields that are not authority witnesses: ${superseded.join(', ')}`);
  }
  const witness = receipt.authorityWitness;
  if (!witness || typeof witness !== 'object' || Array.isArray(witness)) {
    throw new Error('publication receipt has no authority witness');
  }
  if (witness.totalSource !== WITNESS_TOTAL_SOURCE) {
    throw new Error(`publication receipt witness total must be derived from ${WITNESS_TOTAL_SOURCE}, saw ${JSON.stringify(witness.totalSource ?? null)}`);
  }
  for (const phase of WITNESS_PHASES) {
    const state = witness[phase];
    if (!state || typeof state !== 'object' || !SHA256.test(state.digest || '')
      || !Number.isSafeInteger(state.graphCount) || state.graphCount < 0
      || !Number.isSafeInteger(state.triples) || state.triples < 0) {
      throw new Error(`publication receipt witness phase ${phase} is absent or malformed`);
    }
  }
  if (witness.settled.stable !== true) {
    throw new Error('publication receipt settled witness is not stable; live authority was still changing');
  }
  return receipt;
}

// The only field a consumer may treat as current authority, and only through
// this accessor so the guard can never be skipped.
export function settledAuthorityDigest(receipt) {
  return assertSupportedPublicationReceipt(receipt).authorityWitness.settled.digest;
}
