# USF Agent Bootstrap

Shared, tool-neutral kernel for every AI agent working on USF. Read it fully
before acting. It is small on purpose: detailed semantic context is queried on
demand from Stardog, never preloaded or copied into prompts.

## Semantic-first

    Semantics establish truth.      (Model)
    Truth demands evidence.         (Evidence)
    Evidence warrants proof.        (Proof)
    Proof specifies features.       (Contract)
    Features shape code.            (Toolchain)
    Code fulfils requirements.      (Validation)

Reject the build-first inversion:

    Requirements establish code.    (Ticket)
    Code demands features.          (Toolchain)
    Features warrant proof.         (Testing)
    Proof specifies evidence.       (Reports)
    Evidence shapes truth.          (Review)
    Truth fulfils semantics.        (Documentation)

Tickets track requested work. Source code is a candidate realisation. Tests
produce evidence. Reports describe outcomes. None establish semantic truth.

## Authority

The live semantic model in Stardog is the authority, ranked: semantic
definitions > ADRs > validators > runtime proof > source > generated reports.
Never claim done, proven, complete, or production-ready beyond what evidence
supports. Do not overclaim. On any authority conflict, stop and report.

## Load the USF skill

Before any task, load the `usf` skill. It defines how to retrieve bounded
semantic context, choose task scope, run query and mutation modes, and validate.

## Stardog access boundary

Query the model through the `usf` MCP server — `usf_bootstrap` (task
orientation and per-contract model→realisation traces), `usf_query` (bounded
read-only SPARQL), `usf_health` (liveness) — not by reading graph files or a
census. Workers are read-only. Only a coordinator may mutate, transactionally,
fail-closed with rollback. Mutation SPARQL on the read path is refused.
Credentials come only from the environment and never appear in output.

## Task ledger

Keep one compact ledger: objective, semantic identifiers, read scope, write
scope, invariants, acceptance, validation. Query before reading files; read the
smallest sufficient ranges. One bootstrap per task; reuse cached context by
authority digest.

## Parallel and Git hygiene

Bounded parallelism only; workers get compact packets, never transcripts. Every
modifying worker uses its own branch and worktree with a disjoint write scope.
Never use `git stash` for coordination. Never delete unknown or user-owned work.
Leave no stray worktree, stash, temporary branch, or unintegrated commit.

## Stop conditions

Stop and report on: authority conflict, unverified or drifted live state,
missing credentials, unexplained repository state, or any push to overclaim.
Prefer a fail-closed, degraded result over an unsupported claim.

## Final report

Report compactly: files read / modified / created, queries run, evidence,
residual risk, and an explicit readiness verdict. Structured output over
narrative; diffs and commits over pasted file bodies.
