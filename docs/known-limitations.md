# Known limitations & nonconformance

This document records, honestly, the gap between **current reality** and the
**target** semantic factory, incorporating an external adversarial review. It is
the authoritative status source; `BUILD_REPORT.md` summarizes it.

## What this is today

> A safe, replayable **plan-only control-plane** for the future USF Semantic
> Factory — not yet an operational autonomous factory.

Do **not** enable any of these until the corresponding P0 items are closed with
executable tests:

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
| P0-9 | Packet compiler could select an unknown-task-class packet | **Partial** — unknown task class is now excluded from selection; full subject→file/shape/test mapping and read/write-scope derivation remain **Planned**. |
| P0-11 | Qualification ignored missing answers | **Fixed** — every suite case counts; a missing answer scores 0. |
| P0-12 | "Hidden" holdout committed in repo | **Partial** — holdout dir is overridable (`qualification.corpus_dir`/`holdout_dir`); committed holdout should be treated as examples and rotated. True private holdout store is **Planned**. |
| P0-13 | Roles were a linear hierarchy (write escalation) | **Fixed** — roles are orthogonal; only `READ_ONLY_ANALYST` is implied by any admitted role. |
| P0-7 | Broad env inheritance to CLI subprocesses | **Partial** — CLI adapters now run with a sanitized env (no provider keys). Relocating credentials out of the shared `/root/.env` remains **Planned** (the build task mandated `/root/.env`). |
| P0-1 | Plan derived from a fixture, not current USF work | **Planned** — a deterministic USF programme-state compiler (checkpoint/ledger/GOAL contents, not just digests) replacing the fixture planner in the production path. |
| P0-5 | No functional agent execution runtime | **Planned** — real Codex (`codex exec --json`), Claude (`--print --output-format json`), Ollama and generic tool-loop workers with bounded turns/cancellation. |
| P0-6 | "Sandbox" is a string checker, not OS isolation | **Planned** — OS-enforced isolation (unprivileged user, no secret/`/usf` mounts, network-off, cgroup limits) via hardened `systemd-run`; adversarial escape suite at the OS boundary. The string checker remains a *pre-flight* check only. |
| P0-8 | Durable state not durable/atomic enough | **Planned** — event-sourced transitions, global + packet leases with fencing tokens, heartbeats, ULID cycle ids, CAS fsync, crash reconciler. |
| P0-10 | Integration cannot yet produce a correct wave patch | **Partial** — worker patches now stored in CAS; correct base checkout + `git apply --index` + real diff derivation + semantic delta parsing remain **Planned**. |

P1/P2 items (concurrency execution, live health/quota/cost feeding into
scheduling, per-provider egress policies, provider-specific catalogue
normalizers, native Anthropic adapter, calibrated learning, operational
controls, and the protected PR/publication handshake back into `usf-graph`)
remain **Planned** and are sequenced in `BUILD_REPORT.md`.

## Overstated documentation, corrected

- The event log records **phase transitions and side-effect boundaries**; strict
  per-transition compare-and-swap with fencing tokens is **Planned** (P0-8), not
  yet implemented. Earlier "persisted before and after every side effect" wording
  described the target, not current reality.
- Content ids use a 16-hex (64-bit) display prefix; the full SHA-256 as the sole
  durable identity is a P2 improvement.
