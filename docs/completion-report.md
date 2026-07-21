# Completion report — factory/complete-runtime-v1

Authoritative, observed-fact status after the exhaustive completion task. Status
vocabulary: **VERIFIED** (production engine path invokes it + an e2e test proves
it), **PARTIAL**, **PLANNED**, **ENVIRONMENT_BLOCKED**, **DISABLED_BY_POLICY**.

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
| Materialisation index (subject→paths/shapes/tests/generated) + fail-closed scope | **VERIFIED** | `materialisation.py`, `test_materialisation.py`, compiler integration |
| Coordinator lease **heartbeat** + config-derived claim TTL | **VERIFIED** | `_heartbeat`, `_lease_deadline(max_packet_wall_s+grace)` |
| Fencing tokens on claims + result submission | **VERIFIED** | `test_durable_state.py`, `_execute_one` token check |
| Snapshot fails closed (no synthesized digest, required tools, health) | **VERIFIED** | `test_review_fixes.py` |
| Programme-state compiler from live work-plan/bootstrap contents | **VERIFIED** | `programme_state.py`, `test_programme_state.py` |
| Real git-apply integration (base checkout, `--index`, git-derived diff) | **VERIFIED** | `test_integration_apply.py`; wave produced in approve-wave e2e |
| Validation runners; required gate w/o runner **fails** | **VERIFIED** | `validation.py`, `validation_runners.py`; approve-wave runs real ruff/mypy |
| Budget reservation ledger | **VERIFIED** | `budget.py`, `test_durable_state::test_budget_reservation`, wired pre-dispatch |
| `models probe` / `models qualify` functional (real graders self-check) | **VERIFIED (self-check)** | CLI runs graders + admission; live model = ENVIRONMENT_BLOCKED |
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

- **141 tests pass** (83 unit, 16 contract, 27 adversarial, 15 e2e).
- `ruff check`, `ruff format --check`, `mypy` clean; wheel builds.

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
