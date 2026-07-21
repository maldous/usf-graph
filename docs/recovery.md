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

- The `events` table is **append-only** and is the source of truth for history.
- A state transition is persisted **before and after** every side effect.
- Durable artifacts are **content-addressed**, so a cycle replays to identical
  ids for identical inputs.
- `usf-factory replay <cycle-id>` prints the event log for a cycle.

## Crash recovery (Phase 0)

`engine.preflight` runs before each cycle and:

- detects an **incomplete prior cycle** (a `cycles` row not in
  COMPLETE/FAILED/LEARNED) and reports `recoveredFrom`;
- re-establishes the mirror via a read-only fetch from `/usf`;
- verifies **no factory worktrees** exist under `/usf/.git/worktrees`;
- blocks (does not auto-retry) on an uncertain mutation.

Worktrees are **ephemeral execution storage only** — ownership lives in the state
store, never in a worktree. A crashed cycle's disposable clones can be deleted
safely; the claim authority (`packet_claims`) prevents double dispatch.

## Uncertain mutations

An `UNCERTAIN_MUTATION` result is **never** automatically retried
(`result_validation`). The cycle records it and blocks for operator attention.

## No-progress handling

The engine compares each cycle to the previous (`_detect_no_progress`). Repeated
cycles with the same snapshot and an empty selected set are flagged; after
`budgets.max_no_progress_cycles` the loop should stop safely.

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
