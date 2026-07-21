# Known limitations & nonconformance

> **Update (branch `factory/complete-runtime-v1`, v0.2.0):** the runtime was
> substantially completed — routing-driven execution (no more `DryRunWorker`),
> brokered mutation with orchestrator-derived diffs, a materialisation index,
> coordinator heartbeat + fencing, real validation runners, budget ledger, and
> functional probe/qualify self-checks. The authoritative per-capability status
> is now **`docs/completion-report.md`**. Live mutating execution and native-CLI
> sandboxing remain **ENVIRONMENT_BLOCKED** in this chroot (no local model,
> namespaces unavailable); all protected actions stay disabled by default. The
> table below is retained as the prior baseline.


This document records, honestly, the gap between **current reality** and the
**target** semantic factory, incorporating an external adversarial review. It is
the authoritative status source; `BUILD_REPORT.md` summarizes it.

## What this is today

> A safe, replayable control-plane for the USF Semantic Factory with the full
> live path (agent runtime, OS sandbox, durable leases/fencing, real
> integration, programme-state planning) **implemented and tested but gated
> off**. Default operation remains non-mutating (observe / plan-only).

The mutating/autonomous path stays **disabled by default**. In particular, note
the environment caveat below: namespace-based filesystem/network isolation is not
available in this chroot, so mutation should remain disabled here even though the
code paths exist. Do not enable any of these without an operator decision:

```yaml
autonomous_safe_enabled: true
allow_source_egress: true
allow_main_integration: true
allow_stardog_publication: true
allow_terminal_completion: true
```

## Review findings — status

Fixed = corrected with a regression test in this repository. Partial = a bounded
mitigation landed; the full item remains. Planned = design is present but the
live implementation is a larger workstream.

| # | Finding | Status |
| --- | --- | --- |
| P0-2 | Snapshot could fail *open* (synthesized authority digest) | **Fixed** — `snapshots.compile_snapshot` fails closed: no synthesized digest, health must be ok, required tools must be present, triple/graph counts required. Engine BLOCKs on `SnapshotError`. |
| P0-3 | Malformed/unknown model result could become `COMPLETED` | **Fixed** — strict JSON parse (no regex recovery), strict schema (`additionalProperties:false`), unknown/missing status → `FAILED`, mutating packet requires a real patch; worker patches stored in CAS. |
| P0-4 | Adapter derived model id from opaque `agent_profile_id` | **Fixed** — `AgentRequest` carries explicit `provider_id`/`requested_model_id`/`adapter_id`; adapters refuse an `agent-…` id and validate provider match. |
| P0-9 | Packet compiler could select an unknown-task-class packet | **Fixed** — unknown task classes are excluded from selection. Full subject→file/shape/test mapping remains **Planned** (until then, live obligations compile to read-only packets, so there is no accidental mutation). |
| P0-11 | Qualification ignored missing answers | **Fixed** — every suite case counts; a missing answer scores 0. |
| P0-12 | "Hidden" holdout committed in repo | **Partial** — holdout dir is overridable; committed holdout treated as examples and rotated. True private holdout store is **Planned**. |
| P0-13 | Roles were a linear hierarchy (write escalation) | **Fixed** — roles are orthogonal; only `READ_ONLY_ANALYST` is implied by any admitted role. |
| P0-7 | Broad env inheritance to CLI subprocesses | **Fixed** — CLI adapters and the sandbox runner run with a sanitized, secret-free env. (Relocating `/root/.env` itself remains a deploy choice; the build task mandated `/root/.env`.) |
| P0-1 | Plan derived from a fixture, not current USF work | **Fixed** — `ProgrammePlanner` + `parse_programme_obligations` derive obligations deterministically from live MCP work-plan/bootstrap contents; snapshot carries `programme_obligations`, `checkpoint_present`, `ledger_present`. Fixtures are test-only. |
| P0-5 | No functional agent execution runtime | **Fixed** — bounded tool broker + tool-call loop (`agent_runtime.py`); real gated Codex (`codex exec --json`) / Claude (`--print --output-format json`) adapters and OpenAI tools chat; tested via stubs/fakes. |
| P0-6 | "Sandbox" is a string checker, not OS isolation | **Fixed (within environment limits)** — `sandbox_runtime.py` enforces via the OS: privilege-drop to `nobody` (blocks reading 0600 `/root/.env` and writing root-owned `/usf` — proven in the escape suite), rlimits, no-new-privs, process-group timeout, sanitized env. **Environment caveat:** user namespaces are blocked and `bwrap` is absent here, so filesystem confinement of *world-readable* files and per-process network isolation are NOT enforced (reported by `capabilities()`); a namespace wrapper engages automatically if one becomes available. The string checker is now a pre-flight check only. |
| P0-8 | Durable state not durable/atomic enough | **Fixed** — fencing tokens, coordinator + packet leases with heartbeat/expiry, crash reconciler (reap + fence), ULID cycle ids, CAS fsync + read-back integrity, `synchronous=FULL`, busy-timeout, foreign keys. |
| P0-10 | Integration cannot produce a correct wave patch | **Fixed** — patches stored in CAS; integration clone checks out the exact base, applies with `git apply --index`, and derives the combined diff + changed paths from ACTUAL git output. |

P1 items — **Implemented (gated where applicable):** concurrency execution
(bounded semaphore), per-provider egress policy, provider-specific catalogue
normalizer (OpenRouter `supported_parameters`/pricing/context) + **native
Anthropic adapter** (`/v1/messages`), calibrated learning (immutable raw
observations + Beta-Bernoulli estimate), operational controls (`maintenance
backup`/`gc`, CAS GC, online backup), and a **prepare-only** PR/publication
delivery handshake (`delivery.py`, gated; never pushes). Live health/quota/cost
feeding into scheduling and Thompson/UCB routing remain **Planned**.

## Overstated documentation, corrected

- The event log records **phase transitions and side-effect boundaries**; strict
  per-transition compare-and-swap with fencing tokens is **Planned** (P0-8), not
  yet implemented. Earlier "persisted before and after every side effect" wording
  described the target, not current reality.
- Content ids use a 16-hex (64-bit) display prefix; the full SHA-256 as the sole
  durable identity is a P2 improvement.
