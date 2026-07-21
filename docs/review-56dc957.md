# Truth review at 56dc957 (start of factory/complete-runtime-v1)

Verified against the actual engine path (not just unit tests / unused modules)
before implementing the completion task.

## Environment facts (recorded)

- factory HEAD: `56dc957104322ce06168facb73a0ffd472aa382d` on `main` (clean).
- `/usf`: `d5d9d4f0165f…` on `main`, 0 changes, no worktrees.
- Tooling: `codex`, `claude`, `ollama`, `systemd-run`, `unshare`, `docker` present;
  `bwrap`, `podman` absent.
- **Ollama server is NOT running**; **docker daemon is NOT available**; user
  namespaces are blocked. => No live local model and no container/namespace
  isolation are usable in this chroot right now.
- Billable inference disabled by default; no zero-cost live model reachable.
- USF MCP healthy (105,927 triples, 40 graphs) — read-only.

Consequence: **live mutating execution is `ENVIRONMENT_BLOCKED`** here regardless
of code quality (no runnable worker model + no OS isolation + billable gated).
The completion work therefore makes the mutating path real and **fixture-tested
with a deterministic model**, and keeps live protected actions disabled.

## Verified vs overstated at 56dc957

| Area | Status at start |
| --- | --- |
| Deterministic control plane, event log, CAS | VERIFIED |
| Read-only USF MCP + snapshot fail-closed | VERIFIED |
| Programme-state compiler (obligations from work-plan) | VERIFIED (read-only) |
| Leases + fencing tokens + reconciler | PARTIAL — present, but no lease **heartbeat**; packet claim TTL was a flat deadline; results not fenced per side-effect |
| Event sourcing (CAS transitions) | PARTIAL — events logged at phase boundaries; no strict INTENT→SIDE_EFFECT→PROJECTION compare-and-swap |
| Engine execution | **DEFECT** — hard-codes `DryRunWorker` for every mode; routing decision computed but **ignored** during execution; mutating modes blocked |
| Subject→materialisation mapping | **ABSENT** — packet scope taken from planner-suggested paths |
| Brokered mutation executor | ABSENT — `AiWorker` validates a returned patch but does not edit a workspace or derive the diff from git |
| `models probe` / `models qualify` | DEFECT — commands refuse to run |
| Provider health/quota/cost feeding routing | PLANNED — scheduler supports fields; engine builds candidates with defaults |
| Validation runners | PARTIAL — `run_validation` with empty gate list returns green; no real runners wired in the engine |
| Delivery handshake | PARTIAL — `prepare_delivery` prepares (never pushes); no branch/PR path |
| Publication / terminal completion | DISABLED_BY_POLICY (interfaces only) |

## Work done by this task (branch factory/complete-runtime-v1)

See `docs/completion-report.md` (written at the end) for the authoritative,
per-item VERIFIED/PARTIAL/PLANNED/ENVIRONMENT_BLOCKED/DISABLED_BY_POLICY state.
Headline changes:

1. Deterministic **materialisation index** (subject → paths/shapes/tests/generated
   outputs) with conservative RDF/Turtle/SPARQL parsing; packet scope derived
   from it; fail-closed on unknown/ambiguous subjects.
2. **Brokered executor**: mutating tools that actually edit the disposable
   workspace; the orchestrator derives the exact git diff; wired as
   `BrokeredWorker`.
3. Engine **mode semantics** (observe / plan-only / shadow / approve-wave /
   autonomous-safe); `DryRunWorker` removed from executable modes; the **stored
   routing decision drives execution**; defaults remain non-mutating + gated.
4. Control-plane hardening: coordinator **lease heartbeat**, config-derived
   packet claim TTLs, per-side-effect **fencing** of results.
5. **Validation runner registry**: required gate without a runner = failure
   (never green-skip).
6. `models probe` / `models qualify` become **functional** (real graders; run
   against an injected/zero-cost responder; billable providers still gated).
7. Budget reservation ledger; provider-diverse review enforcement hook.
8. Truthful documentation + a completion report + a draft PR.

## Remaining environment blockers (not code defects)

- Live mutating execution (needs a runnable model + real OS isolation).
- Native CLI repository mutation (needs a passing sandbox attestation; namespaces
  unavailable).
- Live provider probe/qualification at scale (billable; disabled by default).
- systemd daemon / container worker service (docker daemon down; deploy-time).
