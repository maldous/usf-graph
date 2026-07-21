# Completion report — factory/complete-runtime-v1

Authoritative, observed-fact status after the exhaustive completion task. Status
vocabulary: **VERIFIED** (production engine path invokes it + an e2e test proves
it), **PARTIAL**, **PLANNED**, **ENVIRONMENT_BLOCKED**, **DISABLED_BY_POLICY**.

## PR #1 review response (blockers addressed)

The blocking review of PR #1 was largely correct; each item was fixed and tested:

1. **CI failing** → root cause: CI installed **unpinned** deps and ran **non-root**,
   while several tests touched the default `/root/.local` paths. Fixed: CI now
   installs from `requirements.lock` (pinned, reproduces local green) on 3.11 (a
   non-blocking 3.12 leg added), and an autouse fixture points every test at temp
   factory dirs. 152 tests pass locally; ruff/mypy clean.
2. **CLI could not run the new path** → added `usf_factory/runtime.py`
   (`build_engine` + `production_worker_factory`); the `run` command now wires the
   worker factory + materialisation index. Live execution is still
   ENVIRONMENT_BLOCKED (no reachable model), which the engine turns into BLOCKED,
   never a false success.
3. **Broker path/scope vulnerabilities** → `_resolve` now uses real-path
   `relative_to` containment (defeats sibling-prefix and symlink escapes);
   `read_file_range`/`list_directory`/`search_repository` enforce packet scope and
   exclude `.git`; empty scope grants no reads. New adversarial tests in
   `tests/test_agent_runtime.py`.
4. **Materialisation index could authorize writes** → **quarantined**:
   `derive_scope(authorize_writes=False)` by default; the heuristic index never
   grants a write scope (read/validation analysis only). Real tests added at
   `tests/test_materialisation.py` (the earlier "VERIFIED" claim was unsupported;
   corrected below).
5. **Waves could finish LEARNED despite failure** → `_execute_wave` is now
   fail-closed: missing result, failed integration, required-review-unavailable
   (high/protected risk with only the noop reviewer), failed validation, or
   uncertain coordinator ownership → **BLOCKED**. Worker success is credited ONLY
   after the wave integrates AND validates; a post-wave snapshot is captured
   before terminal evaluation. Tested.
6. **Budget / probe / live routing overclaimed** → relabeled **PARTIAL** below.
7. **Coordinator/packet fencing** → the coordinator lease is now acquired **before**
   preflight recovery/mirror mutation; packet claim TTL derives from
   `max_packet_wall_s + grace`.

All protected actions remain **disabled** by default.

## Commits

- Starting: `56dc957104322ce06168facb73a0ffd472aa382d` (main).
- Final: this branch `factory/complete-runtime-v1` (see `git log`).
- Package version: `0.2.0`.

## Environment (observed)

`codex`, `claude`, `ollama`, `systemd-run`, `unshare`, `docker` present; `bwrap`,
`podman` absent. **Ollama server not running; docker daemon down; user
namespaces blocked.** No live/local model reachable; billable disabled. USF MCP
healthy (105,927 triples, 40 graphs). Consequence: **live mutating execution is
ENVIRONMENT_BLOCKED**; the mutating path is implemented and **fixture-tested with
a deterministic model**, defaults stay disabled.

## Capability status

| Capability | Status | Evidence |
| --- | --- | --- |
| Engine no longer hard-codes `DryRunWorker` for executable modes | **VERIFIED** | `DryRunWorker` removed from engine; `test_runtime.py` |
| Selected routing decision drives execution | **VERIFIED** | `_resolve_agent` + `test_routing_selects_agent_and_execution_uses_it` |
| Mode semantics (observe/plan-only/shadow/approve-wave/autonomous-safe) | **VERIFIED** | `test_runtime.py`, `test_e2e.py` |
| Brokered mutation (tool broker edits workspace; orchestrator derives git diff) | **VERIFIED (fixtures)** | `test_runtime::test_approve_wave_executes_fixture_packet_end_to_end` |
| Materialisation index (subject→paths/shapes/tests/generated) | **PARTIAL (analysis-only, quarantined)** | `materialisation.py`, `tests/test_materialisation.py`; regex heuristic — **never authorizes writes** (`authorize_writes=False`); a trustworthy parser/manifest-backed, snapshot-bound index remains PLANNED |
| Broker confinement (real-path containment, scope, .git exclusion, symlink/sibling escape) | **VERIFIED** | `tests/test_agent_runtime.py` adversarial cases |
| Fail-closed waves (missing/failed integration/validation/review → BLOCKED; success credited only after integrate+validate) | **VERIFIED** | `tests/test_runtime.py` |
| Coordinator lease **heartbeat** + config-derived claim TTL | **VERIFIED** | `_heartbeat`, `_lease_deadline(max_packet_wall_s+grace)` |
| Fencing tokens on claims + result submission | **VERIFIED** | `test_durable_state.py`, `_execute_one` token check |
| Snapshot fails closed (no synthesized digest, required tools, health) | **VERIFIED** | `test_review_fixes.py` |
| Programme-state compiler from live work-plan/bootstrap contents | **VERIFIED** | `programme_state.py`, `test_programme_state.py` |
| Real git-apply integration (base checkout, `--index`, git-derived diff) | **VERIFIED** | `test_integration_apply.py`; wave produced in approve-wave e2e |
| Validation runners; required gate w/o runner **fails** | **VERIFIED** | `validation.py`, `validation_runners.py`; approve-wave runs real ruff/mypy |
| Budget reservation ledger | **PARTIAL** | `budget.py` reserves pre-dispatch (`test_budget_reservation`); commit/release of ACTUAL cost + live-cost estimation not yet wired (fixture cost is 0) |
| `models probe` / `models qualify` | **PARTIAL (self-check only)** | CLI runs the real graders + admission on reference answers; invoking a discovered live model is ENVIRONMENT_BLOCKED / billable |
| Production runtime wiring in the installed CLI | **VERIFIED (wiring)** | `runtime.build_engine` wires worker_factory + index into `usf-factory run`; live exec ENVIRONMENT_BLOCKED |
| Coordinator lease acquired before preflight recovery/mirror | **VERIFIED** | `run_cycle` reorder |
| Provider-specific normalizers (OpenRouter) + native Anthropic adapter | **VERIFIED** | `test_p1.py` |
| Calibrated learning (raw observations + Beta-Bernoulli); wired into engine | **VERIFIED** | `learning.observe` called in `_execute_wave`; `test_p1.py` |
| Delivery handshake (prepare-only, gated, never pushes) | **VERIFIED** | `delivery.py`, `test_p1.py` |
| OS sandbox: privilege-drop blocks secret/`/usf` access | **VERIFIED (within env limits)** | `test_sandbox_runtime.py` escape suite |
| Namespace FS/network isolation for native CLI mutation | **ENVIRONMENT_BLOCKED** | userns blocked, bwrap absent; `capabilities()` reports it |
| Live mutating execution against a real model | **ENVIRONMENT_BLOCKED** | no local/live model; billable disabled |
| Live provider probe/qualification at scale | **PLANNED / billable** | requires budget + reachable model |
| Full USF validation toolchain (SHACL/integrity/competency…) | **ENVIRONMENT_BLOCKED** | runners fail-closed here (`_USF_GATES`) |
| Merge / Stardog publication / terminal completion | **DISABLED_BY_POLICY** | gated; interfaces only |
| systemd daemon / container worker service | **PLANNED** | docker daemon down; deploy-time |
| Event-sourced strict per-transition CAS + rebuild-projections CLI | **PARTIAL** | events + leases + fencing durable; strict CAS transitions still planned |

## Fixture autonomous/approve cycle result

`approve-wave` with a deterministic brokered worker and a materialisation-free
code packet: selected=1, **accepted=1**, a real git-derived wave patch produced
(`gen/thing.py`), integration applied to a factory-owned clone, validation ran
**real ruff format/lint/mypy green** (`unit-tests` n/a), learning observed the
outcome, delivery prepared (gated). `/usf` unchanged; no factory worktrees.

## Live read-only USF result

`run --mode plan-only` against the live MCP: state LEARNED, deterministic
snapshot, ProgrammePlanner produced obligations from live work-plan (0 open →
read-only verification packet), no execution, `/usf` unchanged.

## Tests / checks

- **152 tests pass** (89 unit, 16 contract, 30 adversarial, 17 e2e).
- `ruff check`, `ruff format --check`, `mypy` clean; wheel builds.
- Reproduced in a clean venv from the committed `requirements.lock` via
  `scripts/verify.sh --fresh`: 152 passed, ruff/mypy clean, wheel built, secret
  scan clean, `.env` untracked.

### CI: removed by operator decision — verified locally instead

The repository must remain **private** and the account keeps GitHub Actions at a
**$0 spending limit**, so GitHub-hosted runners cannot be scheduled (every run
failed at startup with no runner assigned and zero steps — a runner-provisioning
constraint, never a workflow or code defect). Rather than leave a permanently red
check, the operator authorized **removing the CI workflow** (`.github/workflows/`
deleted).

Quality is instead verified with **`scripts/verify.sh`**, which reproduces exactly
what the workflow used to run, pinned to `requirements.lock`: ruff format-check,
ruff lint, mypy, pytest, wheel build, and the tracked-file secret scan. Run
`scripts/verify.sh --fresh` to build a clean lockfile venv first. This is the
reproducible gate of record; run it before merging any change.

## Security posture (unchanged defaults)

All protected actions DISABLED; `autonomous_safe_enabled=false`; source egress
off; publication off; terminal completion off. Workers get no Stardog/GitHub
credentials; CLI subprocesses run with a sanitized env.

## Remaining environment blockers (not code defects)

Live mutation needs a runnable model + real OS/namespace isolation; the live USF
validation toolchain and the container/systemd worker service are deploy-time.
Native CLI repository mutation stays gated until a sandbox attestation passes.

## Exact next operator commands

```bash
usf-factory doctor
usf-factory materialisation build
usf-factory usf health && usf-factory run --mode plan-only
usf-factory models qualify              # zero-cost self-check
# To exercise mutation on a FIXTURE (never /usf), see tests/test_runtime.py.
# Enabling live mutation requires: a reachable model, an OS sandbox attestation,
# wired USF validation runners, and deliberately setting config/safety.yaml gates.
```
