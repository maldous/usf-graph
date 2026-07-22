# Activation report — factory/activation-v1

First controlled operational assessment of the USF Adaptive Semantic Factory
against **live** USF authority and **genuine local inference**. All protected
actions remain disabled; `/usf` is never modified.

## Environment (observed)

- Factory branch `factory/activation-v1`; `/usf` HEAD
  `d5d9d4f0165f2a4f9e8436ab160a45cb986deac2` (unchanged, no factory worktrees).
- USF MCP authority: **healthy**, database `USF`, **105,927 triples**, authority
  digest `dd7ccdae05fa8723aee3c09b4465d0cf24e4d31836c1a8a033f8564782ec0d33`,
  snapshot `snap-b9af7781c753421d`.
- Providers: **15 enabled** (arcee, cerebras, claude-cli, codex-cli, deepseek,
  fireworks, gemini, groq, huggingface, mistral, ollama, openai-api, openrouter,
  sambanova, together); 13 credentials present by name.
- Local inference: **Ollama serving** — `lfm2.5:8b-a1b-q8_0` (9 GB, fast MoE),
  `north-mini-code-1.0:q4_K_M` (18 GB, slow). Codex + Claude CLIs present
  (subscription; not exercised this run — 0 USD budget).

## Assessment (local, free-only, 0 USD)

The first controlled activation was bounded to **local Ollama** to keep it
reproducible and zero-cost; external free models and subscription CLIs are
available for a wider sweep (`usf-factory activate` with no `--providers` /
`--allow-subscription-inference`).

| Step | Outcome |
| --- | --- |
| USF health + snapshot | ✅ healthy; deterministic snapshot compiled |
| Provider refresh + discovery | ✅ ollama catalogue refreshed; 2 local models discovered |
| Mechanical probing (`lfm2.5`) | ✅ **9/10** genuine probes (only prohibited-tool-compliance failed) — real model invocation, graded by the canonical graders |
| Qualification (`lfm2.5`, full 38-case corpus) | ✅ **33/38 passed** — genuine live answers |
| Evidence-based admission (`lfm2.5`) | ✅ **admitted READ_ONLY_ANALYST, PLANNER_CANDIDATE, INTEGRATOR** from the qualification run (immutable evidence + separate admission decision) |
| Live plan-only cycle | ✅ **LEARNED** — deterministic snapshot + programme plan, read-only, `/usf` untouched |
| Live shadow wave (`lfm2.5`) | see "Live shadow" below |
| Candidate semantic patch | not produced — prerequisites unmet (see below); honest blocker, no fabricated progress |

Model classifications this run:

```text
ollama/lfm2.5:8b-a1b-q8_0     QUALIFIED (analyst + planner + integrator, admitted)
ollama/north-mini-code-1.0    READY (discovered; not fully probed — 18 GB, slow)
openrouter/... (free)         READY (discovered; deferred to a wider sweep)
```

Token/cost accounting (real, from provider-reported usage where available):
probe run `lfm2.5` 379 in / 5,289 out, **$0.00** (local); qualification adds the
38-case run, **$0.00**. No paid inference was used; paid is never a silent
fallback.

## Live shadow

A live shadow cycle ran with the admitted local analyst (`lfm2.5`), state
**LEARNED** (clean, no blockers), `/usf` unchanged throughout:

- The **AI planner** (`lfm2.5`, admitted PLANNER_CANDIDATE) was invoked live and
  returned a **valid obligation graph** (schema-conformant JSON).
- The **independent planner critic** (deterministic adapter — no provider-diverse
  reviewer is admitted yet) approved the plan.
- The deterministic compiler selected **0 executable packets** from that plan:
  the small model's proposed obligations did not map to a known executable task
  class whose strict capability floor `lfm2.5` also clears, so nothing was
  dispatched — a correct, fail-safe outcome (no fabricated work).

Earlier shadow attempts with `lfm2.5` as the brokered worker showed the
fail-closed guarantee directly: when the model did not return durable analysis
(`finish_packet` with findings) the cycle **BLOCKED** rather than crediting a
non-result. The shadow path that PRODUCES a durable, CAS-backed analysis artifact
is proven end-to-end by `tests/test_runtime.py::test_shadow_mode_executes_without_integration`
with a competent (deterministic) model.

**Honest read:** the live pipeline runs end-to-end on genuine local inference and
succeeds (LEARNED); `lfm2.5` (a 1B-active MoE) is admissible as an analyst/planner
but is borderline for driving strict semantic packets to a durable work product.
A larger local model, or a subscription/paid model, is expected to produce
durable shadow analysis — that is the next assessment, not a code gap.

## Candidate semantic patch — not produced (prerequisites unmet)

A candidate semantic patch is generated ONLY when every prerequisite holds. This
run's unmet prerequisites (exact blockers, no fabricated progress):

- **No VERIFIED materialisation owner.** The snapshot-bound index over `/usf`
  found 9,774 *candidate* owners but **0 verified** — a parsed declaration is
  only a candidate; a write needs digest-bound evidence (USF layout contract or
  an operator approval via `materialisation approve`).
- **No admitted PATCH_PRODUCER** and **no admitted independent REVIEWER**
  (lfm2.5 qualified as analyst/planner/integrator, not producer/reviewer; and a
  producer + a provider-diverse reviewer are both required).
- **`autonomous_safe_enabled` is false** (committed default) — approve-wave
  mutation is disabled.

This is the correct fail-closed outcome: the factory can plan and analyse, but a
semantic write is gated until a verified owner, a qualified producer, and an
independent reviewer exist and the operator enables the mutating gate.

## Safety posture (unchanged)

All protected gates disabled (`config/safety.yaml`: 8 × false); source egress
off; publication/merge/terminal-completion off. No `/usf` write, no push to
`usf-graph`, no Stardog mutation. Workers received no credentials.

## Next action

Run `usf-factory run --continuous --mode shadow` to accumulate evidence-backed
shadow analysis. To reach a first candidate semantic patch: qualify a
PATCH_PRODUCER and a provider-diverse REVIEWER (a larger local model or a
subscription/paid model), approve at least one materialisation owner
(`materialisation approve <subject> --path <path>`), then run `activate
--candidate-packet` with the mutating gate explicitly enabled by the operator.
