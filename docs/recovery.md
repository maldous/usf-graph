# Recovery & durability

## Durable state

All durable state lives outside the repository and outside `/usf`:

```
/root/.local/state/usf-factory/factory.sqlite   SQLite WAL: records + append-only event log
/root/.cache/usf-factory/cas/                    content-addressed artifacts
/root/.local/share/usf-factory/mirrors/usf.git   factory-owned bare mirror of /usf
/root/.local/share/usf-factory/workspaces/       disposable per-packet clones (ephemeral)
/root/.local/share/usf-factory/integration/      integration clone (ephemeral)
```

Locations are overridable via `USF_FACTORY_STATE`, `USF_FACTORY_CACHE`,
`USF_FACTORY_SHARE`, `USF_FACTORY_CONFIG`.

## Replay model

- The `events` table is **append-only** for cycle history. Protected delivery
  additionally has an immutable CAS transition chain and compare-and-swap head.
- Every cycle transition is persisted as it occurs. Protected external side
  effects additionally persist an `UNCERTAIN_SIDE_EFFECT` intent before the
  driver is invoked and clear it only after an exact result is recorded.
- Durable artifacts are **content-addressed**, so a cycle replays to identical
  ids for identical inputs.
- `usf-factory replay <cycle-id>` prints the event log for a cycle.

## Crash recovery (Phase 0)

`engine.preflight` runs before each cycle and:

- detects an **incomplete prior cycle** (a `cycles` row not in
  COMPLETE/FAILED/LEARNED) and reports `recoveredFrom`;
- re-establishes the mirror via a read-only fetch from `/usf`;
- verifies **no factory worktrees** exist under `/usf/.git/worktrees`;
- reconstructs protected-delivery input from integrity-verified CAS bytes and
  reconciles an uncertain push, PR creation/readiness, merge or publication
  against the remote system before allowing any retry;
- blocks when exact reconciliation is unavailable or the authorization binding
  has changed.
- reaps only expired packet claims, fences a prior adaptive invocation only
  after that durable timeout proves it irrecoverably unavailable, and blocks on
  any still-live or otherwise uncertain prior invocation. It never restores the
  old concurrency decision or launches a speculative replacement.

Worktrees are **ephemeral execution storage only** — ownership lives in the state
store, never in a worktree. A protected delivery persists a Git bundle for the
exact reviewed commit; recovery can reconstruct a deleted clone and verifies the
commit/tree before continuing. Digest-derived directory names prevent semantic
identifiers from becoming paths. The claim authority (`packet_claims`) prevents
double dispatch, and an expired claim cannot renew itself.

`resume_incomplete` handles every nonterminal delivery state in canonical
delivery-id order. A published delivery whose drift or closure check has not
completed remains `AUTHORITY_PUBLISHED` with reconciliation required; it is not
collapsed into an ordinary failure. Legacy active projections without a
versioned transition chain fail closed as `LEGACY_DELIVERY_TRANSITION_UNBOUND`.

## SQLite migration

Startup creates the additive transition, quota, budget, assurance-index and
adaptive decision/invocation/observation tables without rewriting prior history.
Schema-v1 assurance receipts cannot authorize a
protected delivery. Existing complete records remain readable; existing active
records without a transition head must be inspected and migrated explicitly.

## Uncertain mutations

An agent result classified `UNCERTAIN_MUTATION` is **never** automatically
retried (`result_validation`). A coordinator-owned protected-delivery intent is
different: preflight may reconcile it from exact persisted input and observed
remote state, but never repeats the side effect while its outcome is ambiguous.

## No-progress handling

The engine records a durable snapshot/packet-set repetition streak. After
`budgets.max_no_progress_cycles` unchanged cycles it stops safely even after a
process restart.

## Backup

Back up the SQLite database and the CAS directory:

```bash
sqlite3 /root/.local/state/usf-factory/factory.sqlite ".backup '/backup/factory.sqlite'"
cp -a /root/.cache/usf-factory/cas /backup/cas
```

The mirror and workspaces are reproducible from `/usf` and need not be backed up.
`/root/.env` (secrets) is **not** backed up by these commands and must be handled
through your secret store.

## Rebuilding the mirror

Deleting `/root/.local/share/usf-factory/mirrors/usf.git` is safe; it is
re-created on the next cycle by a read-only fetch from `/usf`. This never modifies
`/usf`.
