# ADR 00000003: Bounded bootstrap packet

Status: accepted

Authority witness: sha256:d7e5057d419e2ad772ca5c58e1d9dfd6f66c512dde58c2e8f9ec9a365aaac30d

This record preserves rationale only and is not semantic authority. The accepted live decision is retrieved from Stardog.

## Decision

Retain the current bounded live bootstrap packet and deterministic continuation design. It preserves the model-to-validation trace, claim and nonclaim visibility, a verified authority witness, an 8192-byte and 50-binding bound, and traversal depth three.

## Alternatives

Unbounded semantic preload violates the bounded-consumption contract. Static snapshots drift from live authority. Both remain reversible future options only under a new active decision.

## Nonclaim

The bootstrap packet is a projection. This ADR does not activate a contract, admit evidence, establish proof, or grant implementation authority.
