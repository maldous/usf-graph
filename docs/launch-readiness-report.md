# Launch-Readiness Report

> **Superseding validation-boundary correction:** this report records a
> historical run. Subsequent cross-repository review established that a
> factory validation receipt is operational provenance, not admitted
> `usf:ValidationEvidence`. The repository-external-materialisation validation
> obligation is retained but deferred until an authority-grade producer and
> admission path exist. The factory must not turn contract obligation inventory
> into work without an actionable `usf_work_plan` gap.

Rapid launch-readiness correction pass. All twelve confirmed blockers are fixed
and covered by focused tests; the production factory now processes a real USF
semantic packet, executes it in shadow with cache-efficient tokens, and the
runtime is roster-governed with token/cache-aware routing. `/usf` is untouched;
every protected gate stays false.

- Base commit: `b205d8fcbd630843a147da54638e00bc3bf82ecf`
- Verification receipt: `commit=470a4d2… dirty_paths=0 attest=1`
- Full suite: **279 passed, 2 skipped** (opt-in live CLI isolation probes); ruff + mypy clean.

## Blocker fixes (1–12)

| # | Blocker | Fix |
|---|---------|-----|
| 1 | plan/shadow produced zero packets | `parse_programme_obligations` now reads the live work-plan **`gaps`** shape; the deterministic compiler produces a real packet from the authority gap. |
| 2 | roster had no producer/reviewer | `bootstrap-runtime` live-qualified Claude (36/38) + Codex (37/38); both admitted; roster fills producer + reviewer. |
| 3 | Ollama active as planner/integrator despite weak scope/optimization | roster ranks by semantic quality + token efficiency; Claude/Codex outrank Ollama; Ollama is analyst-only fallback. |
| 4 | roster didn't govern scheduling | `candidate_agents(role)` restricts to the active roster's role entry + fallbacks (no all-profile scan). |
| 5 | candidates ordered by profile ID | 12-key lexicographic ranking (qual score, semantic fidelity/optimization, scope/evidence discipline, accepted-success, uncached/cache/latency/cost); profile ID is the final tie-break only. |
| 6 | CLI worker got paths, no source | bounded, digest-bound **context pack** (`context_pack.py`) from the mirror at `base_head`: rule-bundle prefix + task delta + subject RDF/SHACL/SPARQL excerpts. |
| 7 | usage/cache metrics dropped | `AiWorker` propagates normalized usage into `PacketResult.usage` (missing = unknown, not zero) + context/prefix/task digests. |
| 8 | routing ignored tokens/cache | per-profile metrics persisted; roster ranking + scheduler factors (uncached cost, cache reuse, context expansion, prior validation) — hard gates unchanged. |
| 9 | `--shadow-packets` marked deferred as missing | dispatched-set recorded; missing computed only vs dispatched; selected/dispatched/deferred/completed/failed reported distinctly. |
| 10 | generic caps overclaimed; edit hard-coded by name | tri-state `AdapterCapabilities` (implemented/observed/unavailable); `capabilities_for_kind` from the real adapter class; `_EDIT_CAPABLE_ADAPTERS` removed; unbuildable adapter ⇒ ineligible. |
| 11 | AI planner replaced deterministic compiler | deterministic `ProgrammePlanner` is always authoritative; `AiPlanOptimizer` may only rank/consolidate/annotate — never generate/invent/empty; fail-open to the authoritative graph. |
| 12 | no verified owner / real validation / candidate write | objective `subject-declaration` owner verification (blob-pinned); real rdflib/pyshacl/SPARQL validation prerequisite; candidate flow wired (see below). |

## Live acceptance run

1. `scripts/verify.sh --fresh --attest` → **ALL GATES PASSED** (`470a4d2`, dirty=0).
2. `usf-factory bootstrap-runtime --allow-inference --allow-subscription-inference --max-cost-usd 0`:
   - Claude CLI qualified live **36/38** (`qual-01KY2K4EW9A0384BRPNBCY45NN`); Codex CLI **37/38** (`qual-01KY2KDT2ZP28BHME3PC7KQNR7`); Ollama reused (33/38).
   - **Active roster** `roster-01KY2MZHWTZW619RTCKS44AAX1` (config digest `sha256:76541cb1…`, rule bundle `sha256:679710a5…`):

     | role | provider | model | transport |
     |---|---|---|---|
     | patch producer | claude-cli | claude-opus-4-8 | bounded_patch_synthesis |
     | read-only analyst | claude-cli | claude-opus-4-8 | plain_invoke |
     | integrator | claude-cli | claude-opus-4-8 | plain_invoke |
     | reviewer | codex-cli | gpt-5-codex | plain_invoke (independent, provider-diverse) |
     | planner | codex-cli | gpt-5-codex | plain_invoke |

     Source-bearing roles (producer/analyst/integrator) route to the **source-contained** provider (Claude); the reviewer is a **provider-diverse** uncontained provider (Codex) that only judges a bounded diff. `minimum_shadow_ok=True, minimum_candidate_ok=True`.
3. Live plan-only cycle → **1 authority-derived packet** selected (obligation `missing-current-passing-validation:urn:usf:validationobligation:repositoryexternalartefactmaterialisation`), state LEARNED, no blockers.
4. Live shadow `--shadow-packets 1` → **cyc-01KY2NN4MJE7BYDZ2WHRNGGETW**, state **LEARNED**, exactly **1 dispatched, 1 accepted**.
5. **Accepted factory finding** — Claude (`claude-opus-4-8`, verified) produced a source-grounded read-only finding (CAS `cas:sha256:f9d661ce…`). It was valid diagnostic output, but its proposed passing receipt was not authority-grade evidence and could not close the obligation.
6. **Token/cache metrics captured + influencing routing**: input 12331 (cached **12329**, uncached **2**), output 10157 — the stable rule-bundle prefix was cache-hit (cache reuse ≈ 0.9998). Context-pack digest `sha256:4fbf74b3…`, stable-prefix digest `sha256:679710a5…`.

## Candidate semantic patch — honest outcome

The candidate flow (`usf-factory candidate --allow-subscription-inference --approve-source-provider claude-cli`) verified the owner, built the bounded context pack, and dispatched the mutating packet to the admitted **producer (Claude)** with an independent **reviewer (Codex)** on a different provider.

**The producer correctly declined to fabricate authority evidence.** The bounded
context did not provide an authority-grade producer or admission path. It
returned no effective change and the fail-closed orchestrator rejected the
no-op (`WORKER_ERROR: mutating packet completed without an effective git-derived
change`); the cycle BLOCKED rather than inventing evidence.

This was a safe outcome, but it did not prove evidence admission or obligation
closure. The candidate-patch mechanism remains independently testable; genuine
authority evidence must arrive through the explicit digest-verified transport
interface and still pass canonical graph validation and publication.

## Isolation & protected-gate proof

- `/usf` HEAD before and after: `d5d9d4f0165f2a4f9e8436ab160a45cb986deac2`; working tree dirty paths **0**; no `/usf/.git/worktrees`; no push, no merge, no Stardog mutation.
- All 7 protected gates **false** (committed config): paid_inference, source_egress, main_integration, push_pr, stardog_publication, risk_acceptance, terminal_completion.
- Subscription inference + source egress were enabled **in-memory for the audited run only** (never committed); paid API spend $0; no paid-only model was routed (subscription CLIs are exempt from the paid budget; paid API stays quota-blocked).
- Codex is **not source-contained** (its read-only sandbox permits filesystem reads) so it never receives raw source — restricted to bounded metadata/review.

## Verification commands

```
scripts/verify.sh --fresh --attest
usf-factory bootstrap-runtime --allow-inference --allow-subscription-inference --max-cost-usd 0
usf-factory run --mode plan-only --allow-subscription-inference
usf-factory run --mode shadow --shadow-packets 1 --allow-subscription-inference --approve-source-provider claude-cli
usf-factory candidate --allow-subscription-inference --approve-source-provider claude-cli
```
