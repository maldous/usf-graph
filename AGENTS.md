# USF Agent Bootstrap

Shared, tool-neutral kernel for every AI agent working on USF. Read it fully
before acting. It is small on purpose: detailed semantic context is queried on
demand from Stardog, never preloaded or copied into prompts.

## Semantic-first

    Semantics establish truth.      (Model)
    Truth demands evidence.         (Evidence)
    Evidence warrants proof.        (Proof)
    Proof warrants constraints.     (Contract)
    Contracts authorise code.       (Realisation)
    Code produces evidence.         (Validation)

Reject the build-first inversion:

    Requests establish code.        (External work record)
    Code demands features.          (Toolchain)
    Features warrant proof.         (Testing)
    Proof specifies evidence.       (Reports)
    Evidence shapes truth.          (Review)
    Truth fulfils semantics.        (Documentation)

External work records track requested work. Source code is a candidate realisation. Tests
produce evidence. Reports describe outcomes. None establish semantic truth.

## Authority and roles

Validated semantic state in Stardog is the sole USF semantic authority. The
storage technology alone does not establish truth: the state must satisfy the
live model, constraints, evidence admission, proof and contract lifecycle.

Model defines semantic truth. Evidence is an admitted observation or produced
fact satisfying a requirement. Proof deterministically evaluates an exact
admitted evidence set against an obligation. Contract records warranted
features and constraints. ADR records historical rationale and is never
semantic authority. Realisation is an authorised approach to satisfying an
active contract. Toolchain is a selected mechanism. Code is a candidate
realisation. Validation produces evidence. Report projects evidence and
results. External work records track work. None of the latter roles independently establish
or retrospectively override truth.

Never claim done, proven, complete, or production-ready beyond what evidence
supports. Do not overclaim. On any authority conflict, stop and report.

## Load the USF skill

Before any task, load the `usf` skill. It defines how to retrieve bounded
semantic context, choose task scope, run query and mutation modes, and validate.

## Stardog access boundary

Query the model through the `usf` MCP server — `usf_bootstrap` (task
orientation and per-contract model→evidence→proof→contract→realisation→validation traces), `usf_query` (bounded
read-only SPARQL), `usf_health` (liveness) — not by reading graph files or a
census. Workers are read-only. Only a coordinator may mutate, transactionally,
fail-closed with rollback. Mutation SPARQL on the read path is refused.
Credentials come only from the environment and never appear in output.

## Repository materialisation

Before creating, renaming or deleting any tracked path, or selecting a representation format, retrieve the active repository-materialisation contract and authority digest through the USF gateway. Materialise only paths, actions, formats and storage classes authorised by that current contract.

Generated projections, external work records, ADRs, source files and external payloads do not establish semantic truth. Verify every external artifact against its Stardog-recorded digest before use. Do not commit runtime evidence, proof logs or validation output unless the active contract explicitly requires a tracked representation.

## Session-transient .work

`.work/` is gitignored session scratch: assume it is empty at session start and
deletable at any time. Never store durable state or tooling there — tracked
commands regenerate everything: `node operations/programme/update-checkpoint.mjs`
(checkpoint, ledger, sidecars), `npm run publish:authority[:validate]`
(coordinator-only authority publication), `npm run authority:drift` and
`npm run authority:snapshot-derived` (source/live parity and derived snapshots).
The one operator-supplied file is the evidence signing key: copy it from the
operator secret store (`/var/lib/usf-programme/programme/`) to
`.work/programme/realisation-option-evaluation-signing-key.pk8` with mode 600
when a collector needs `--signing-key=`; it never enters Git or command output.

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
