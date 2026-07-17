# ADR 00000002: Compiler semantic enforcement

Status: accepted

Authority witness: sha256:ee0ef7e858f769ffdcb028b474b565bd8e7af2741a2806b68f74de6911bbc1e7

This record preserves rationale only and is not semantic authority. The accepted live decision is retrieved from Stardog.

## Decision

Retain and harden the existing transactional compiler and its bounded projection gateway. The evidence binds registered-source validation, derivation, SHACL, integrity, contamination checks, rollback behavior, proof-blocked projection denial, 113 compiler tests, and 21 positive/adversarial fixtures.

## Alternatives

A rewrite would increase migration risk without closing a current obligation. An external compiler would introduce a second authority boundary and cannot replace the validated Stardog transaction. Both remain reversible future options under a new active decision.

## Nonclaim

This ADR does not activate the contract, admit evidence, establish proof, or make bootstrap exceptions implementation authority.
