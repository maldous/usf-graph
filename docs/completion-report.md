# Completion report — factory/complete-runtime-v1

Authoritative, observed-fact status after the exhaustive completion task. Status
vocabulary: **VERIFIED** (production engine path invokes it + an e2e test proves
it), **PARTIAL**, **PLANNED**, **ENVIRONMENT_BLOCKED**, **DISABLED_BY_POLICY**.

## Overall classification (per the second post-merge review)

```text
Gated orchestration foundation
Not ready for live semantic packet execution   (environment: no reachable model)
Not ready for autonomous operation             (policy: gates disabled)
Not ready for USF delivery or publication      (policy: gates disabled)
```

## P1 wave (applied on main after the P0 hotfix)

All P1 items from the second review are implemented and tested:

1. **Snapshot-bound materialisation contract (P1-6)** — `build_index_at(mirror,
   head)` builds from the git object store at the exact snapshot commit (bare
   mirror; uncommitted /usf content cannot leak in; proven by test). Semantic
   packets take writes ONLY from verified contract entries — planner write
   suggestions are ignored with a finding; ambiguous/unresolved subjects and
   stale/working-tree indexes fail closed to read-only. Non-semantic classes
   need explicit `planner_write_scope_allowed` (operator-approved config). The
   index digest is persisted and bound into every packet
   (`Packet.materialisation_digest`). Live: 10,227 subjects / 10,158 verified
   owners at /usf HEAD.
2. **Admission workflow (P1-7)** — `models probe/qualify <provider/model>`
   persist the AgentProfile from providers.yaml (unknown provider = hard
   error); `models admit` recomputes roles from STORED qualification evidence
   vs the trust policy (explicit grants require `--operator-override`, recorded
   as operator decisions); `models profiles` inventories. A gated qualify
   persists NO evidence — reference-answer self-checks are never stored as
   model evidence.
3. **Honest routing facts (P1-8)** — candidates carry catalogue context/pricing,
   RECORDED provider health (unrecorded ⇒ DEGRADED), adapter-derived tools
   (never `*`), and a paid-model quota rule (schedulable only with billing
   enabled + budget remaining). Dispatch reserves the catalogue-derived
   estimate, commits usage-derived actual cost, releases on failure.
4. **Verified attribution (P1-9)** — per-turn provider-REPORTED actual model +
   token usage flow through the tool loop into `PacketResult.usage`
   (actual_models, actual_model_verified, prompt/completion tokens, turns,
   wall_s). A router's actual model is never silently equated with the request.
5. **Packet claim heartbeats (P1-10)** — `renew_claim` (holder-fenced) runs on a
   heartbeat during execution; renewal failure cancels the worker immediately;
   `max_packet_wall_s` is a hard executor timeout; the initial coordinator
   lease now covers the synchronous preflight phase (`max_preflight_wall_s`).
6. **Substantive review (P1-12)** — every wave patch requires a real reviewer
   unless ALL selected packets are explicitly low-risk mechanical; no reviewer
   available ⇒ BLOCKED; reviewer rejection ⇒ BLOCKED; unparseable review ⇒ not
   approved. The production reviewer factory yields only ADMITTED
   reviewer-role profiles.

All protected actions remain disabled by default; the local verification gate
(`scripts/verify.sh`) is a reproducible operator process, NOT independently
executed CI evidence.

## Second post-merge review — P0 hotfix (applied on main after merge)

The second review confirmed the merge as a defaults-off foundation and listed
five defects to correct before any external-provider `shadow` run. All five are
fixed and tested:

1. **Source misclassification / egress bypass** — a read-only packet whose READ
   scope contains repository files was labeled `private-metadata` and could be
   routed to an external provider. Fixed: ANY file path in scope (read or
   write) now classifies the packet at least `private-source`
   (`packet_compiler`); additionally the tool broker **rechecks egress on every
   content-returning tool call** (`read_file_range`, `search_repository` — a
   content oracle) and refuses raw source unless policy allows it for THIS
   provider (`EgressPolicy.source_content_allowed`, wired per-provider in
   `runtime.py`). Mandated adversarial test: `tests/test_egress.py`
   (read-only packet + source read path + external provider + gate off ⇒ no
   route AND no source returned).
2. **Failed results could yield a green LEARNED cycle** — `_execute_wave` now
   fails closed on EVERY non-accepted qualification (worker FAILED, rejected,
   human-decision-required, skipped), not only on missing results. A recorded
   failure is never success. Tests: `test_failed_worker_result_blocks_cycle`,
   `test_readonly_completion_without_evidence_blocks`.
3. **Read-only workers could "complete" without work product** — `finish_packet`
   now carries `findings` + `criteria_results`; a read-only COMPLETED result
   must persist a CAS-backed analysis artifact (`PacketResult.analysis_ref`) or
   the worker fails; deterministic qualification independently rejects any
   read-only completion lacking the artifact (defense in depth, also covers
   non-brokered workers).
4. **Required validation could green-skip as "n/a"** — only explicitly
   CONDITIONAL gates (deterministic changed-file predicates: syntax-parse,
   format, lint, type, secret-scan, repository-cleanliness) may report
   not-applicable. Any other required gate reporting n/a **fails** — including
   `unit-tests`: a repository implementation must now carry its test within the
   packet write scope (the approve-wave e2e fixture does, and the gate runs
   real pytest). Tests: `tests/test_validation_gates.py`.
5. **Residual broker gaps** — `_resolve` now rejects EVERY symlink component
   via an lstat walk (blocks in-workspace symlink aliasing for reads AND
   writes, on top of real-path containment); tool exposure AND dispatch honor
   `packet.permitted_tools` (broker↔packet tool-name mapping, fail closed);
   byte/query caps on reads, search, patches, writes; the second
   `git apply --index` return code is checked. Tests in
   `tests/test_agent_runtime.py`.

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
- Package version: `0.3.0`.

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
| Materialisation write contract (snapshot-bound, verified owners only; planner writes ignored for semantic packets) | **VERIFIED** | `build_index_at` + compiler scope authority; `tests/test_materialisation.py` (stale/working-tree/ambiguous fail closed) |
| Broker confinement (real-path containment, scope, .git exclusion, symlink/sibling escape) | **VERIFIED** | `tests/test_agent_runtime.py` adversarial cases |
| Fail-closed waves (missing/FAILED/rejected/human-decision results, failed integration/validation, unavailable review → BLOCKED; success credited only after integrate+validate) | **VERIFIED** | `tests/test_runtime.py` |
| Egress: file-scoped packets are private-source; broker rechecks source egress per tool call | **VERIFIED** | `tests/test_egress.py` |
| Read-only completion requires a CAS-backed analysis artifact (`analysis_ref`) | **VERIFIED** | `tests/test_runtime.py`, `result_validation` check |
| Required validation gates cannot green-skip as n/a (conditional gates only) | **VERIFIED** | `tests/test_validation_gates.py` |
| Broker: symlink-component rejection, packet tool-profile enforcement, byte caps | **VERIFIED** | `tests/test_agent_runtime.py` |
| Coordinator lease **heartbeat** + config-derived claim TTL | **VERIFIED** | `_heartbeat`, `_lease_deadline(max_packet_wall_s+grace)` |
| Fencing tokens on claims + result submission | **VERIFIED** | `test_durable_state.py`, `_execute_one` token check |
| Snapshot fails closed (no synthesized digest, required tools, health) | **VERIFIED** | `test_review_fixes.py` |
| Programme-state compiler from live work-plan/bootstrap contents | **VERIFIED** | `programme_state.py`, `test_programme_state.py` |
| Real git-apply integration (base checkout, `--index`, git-derived diff) | **VERIFIED** | `test_integration_apply.py`; wave produced in approve-wave e2e |
| Validation runners; required gate w/o runner **fails** | **VERIFIED** | `validation.py`, `validation_runners.py`; approve-wave runs real ruff/mypy |
| Budget reserve → commit(actual) / release, catalogue-derived estimates | **VERIFIED** | engine `_settle_budget`; honest paid-model quota in candidates (`tests/test_p1_runtime.py`) |
| Admission workflow (`models probe/qualify/admit/profiles`; roles from evidence) | **VERIFIED (workflow)** | `admission.py`, `tests/test_p1_runtime.py`; LIVE qualification remains gated/ENVIRONMENT_BLOCKED and persists no evidence when refused |
| Routed-model attribution (per-turn actual model + tokens; unverified flagged) | **VERIFIED** | `PacketResult.usage`; `tests/test_p1_runtime.py` |
| Packet claim heartbeat + fence-and-cancel + executor timeout | **VERIFIED** | `renew_claim`, `_execute_with_claim_heartbeat`; `test_packet_claim_renewal_is_fenced` |
| Substantive review required for every non-mechanical wave patch | **VERIFIED** | `test_wave_without_reviewer_blocks`, `test_reviewer_rejection_blocks` |
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
(`gen/thing.py` + `tests/test_thing.py` — the required unit-tests gate may not
green-skip, so the wave carries its own test), integration applied to a
factory-owned clone, validation ran **real ruff format/lint/mypy/pytest green**,
learning observed the outcome, delivery prepared (gated). `/usf` unchanged; no
factory worktrees.

## Live read-only USF result

`run --mode plan-only` against the live MCP: state LEARNED, deterministic
snapshot, ProgrammePlanner produced obligations from live work-plan (0 open →
read-only verification packet), no execution, `/usf` unchanged.

## Tests / checks

- **184 tests pass** (107 unit, 18 contract, 37 adversarial, 22 e2e).
- `ruff check`, `ruff format --check`, `mypy` clean; wheel builds.
- Reproducible in a clean venv from the committed `requirements.lock` via
  `scripts/verify.sh --fresh`; `--attest` additionally requires a clean tree and
  prints a commit-bound verification receipt.

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
