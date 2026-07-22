# Known limitations and nonclaims

This document describes the current `factory/activation-v1` boundary. Historical
build reports remain useful development records but do not override this status.

## Authority boundary

`usf-factory` is intentionally a traditional build-first orchestration system.
It is not semantic authority and does not derive its internal implementation
from the USF graph. At the integration boundary it must nevertheless consume the
current graph contract exactly and fail closed on drift.

A factory validation run creates a `FactoryValidationReceipt`. The receipt is an
operational observation, not admitted `usf:ValidationEvidence`, and cannot close
a graph obligation. The factory can transport independently produced,
content-addressed authority evidence through `AuthorityEvidenceTransport`; the
graph compiler, validate-and-rollback, transactional publication and
post-publication drift/work-plan checks remain authoritative.

The repository-external artefact-materialisation validation obligation currently
has no genuine authority-evidence producer. Its semantic intent is preserved in
`usf-graph`, but it must remain explicitly deferred rather than becoming
actionable work until that producer and admission lifecycle exist.

## Protected delivery

Protected actions are disabled by committed defaults. Enabling them requires a
current `RunAuthorization` whose repository, authority database, risk, action
and quota scopes all match. The delivery coordinator binds accepted diff,
review/validation receipts, policy, workforce, authorization and obligation set
into one identity. It uses exact PR heads and required checks and re-pins the
authority immediately before publication.

Cycle transitions and external-effect intents are durable. An ambiguous push,
PR operation, merge or publication is reconciled from exact CAS-bound input and
remote state before retry; unavailable reconciliation blocks.

The driver contracts and adverse outcomes are tested with disposable fakes and
the real `usf-graph` CLI schema. A live protected merge/publication against the
production GitHub repository or live Stardog is intentionally not part of the
test suite and is not claimed.

## Remaining release limitations

- `scripts/verify.sh --attest` is a local, commit-bound attestation rather than
  an independent required GitHub check. A merge-capable run must still observe
  at least one external required check on the exact reviewed head.
- Dependency versions are locked, but the Python lock does not yet carry hashes
  for every transitive artifact and no independent vulnerability attestation is
  bundled.
- Namespace-based filesystem and network confinement is unavailable in the
  present chroot. Privilege reduction, sanitized environments, scopes, rlimits
  and no-new-privileges remain enforced; mutation should stay disabled on hosts
  without the required containment capability.
- Some graph-specific assurance gates require the repository-local Node/compiler
  toolchain. When unavailable they fail closed; local Python SHACL or integrity
  results are never promoted as authority proof.
- External-provider qualification and billable routing are policy- and
  credential-dependent and have not been exhaustively exercised in this branch.
- A factory receipt corroborates executed bytes only. It does not establish
  evidence admission, semantic proof, contract closure or production readiness.

## Safe current use

Read-only observation, planning, qualification and isolated dry-run execution
are appropriate. Protected delivery is suitable only with an explicit bounded
authorization, exact current graph bindings, complete required checks and all
fail-closed gates passing. This branch must not be described as autonomous
production-ready until the full clean-clone attestation and cross-repository
scenarios pass.
