# Dynamic Workforce — live acceptance & completion report

Branch `factory/activation-v1`, PR #2 (draft). Dynamic, evidence-based workforce
and provider/model allocation (spec §1–§16). All runs non-mutating; `/usf`
unchanged; committed protected gates false; paid API spend **$0**.

## Final commit
`163467d` — `workforce W6` (tip of W1–W6). Pushed to `origin/factory/activation-v1`.

## Effective WorkforcePolicy
- **Committed (code, `committed_defaults`)**: provider-neutral — excludes NO
  provider/model/family; non-paid inference allowed; paid off; safety
  requirements (containment, provider-diverse review, verified-actual-model) on.
- **Operator-maintained (`config/workforce-policy.yaml`)**: excludes `ollama`
  ("local inference too slow to be practical" — an operator choice, not a code
  default; §11).
- **Run overrides (per scenario below)**: repeatable CLI `--exclude-provider`,
  `--exclude-model`, `--only-*`, `--allow-*-inference`, `--max-paid-cost-usd`,
  `--workforce-policy`. Precedence: run exclusion > operator > committed >
  inclusion/preference > auto; an exclusion is never overridden by an inclusion.

## Discovered providers & models
15 providers enabled; **1012 models discovered** across 13 (openrouter 338,
together 272, huggingface 125, openai-api 125, mistral 60, gemini 55, groq 15,
deepseek 4, ollama 3, claude-cli 3, codex-cli 3, cerebras 3, sambanova 6).

## Current eligible population by role
Admitted profiles (reused, not re-qualified): `ollama/lfm2.5` (analyst/planner/
integrator — **excluded by operator policy**), `claude-cli/claude-opus-4-8` and
`codex-cli/gpt-5-codex` (all roles, subscription). Under the effective policy the
eligible workforce is `{claude-cli, codex-cli}` for every operational role.

## Live provider/model actually used
`codex-cli/gpt-5-codex` — live mechanical probe (subscription): **8/10 passed,
cost $0.0, 0 errors** (`text_response`, `strict_json`, `tool_result_followup`,
`iri_preservation`, `digest_preservation`, `explicit_uncertainty`,
`stop_condition`, `patch_format` passed; `forced_tool_call`,
`prohibited_tool_compliance` graded fail — strict graders, non-empty ≠ pass).
This proves live CLI invocation; qualification evidence for the roster was reused,
not regenerated (lazy, coverage-directed).

## Scenarios (over the REAL admitted workforce)
- **A — normal dynamic operation.** Workforce built from discovered + admitted
  candidates; planner providers `{claude-cli, codex-cli}` (ollama excluded).
  Adaptive Thompson routing over 40 low-risk draws distributed **claude-cli 18 /
  codex-cli 22** (not fixed to one). Sample receipt carried per-candidate utility,
  Beta posterior, normalized probability, mode=`adaptive`, policy + snapshot
  digests, and a fresh persisted seed.
- **B — `--exclude-provider claude-cli`.** claude-cli absent from the population
  (never probed/invoked), recorded excluded `source=run`; only codex-cli remained
  and filled the roles.
- **C — `--exclude-provider codex-cli`.** codex-cli absent; only claude-cli
  remained — which is the authoring provider — so reviewer selection **blocked
  honestly**: "no independent reviewer available (provider-diverse review
  required; an author is never silently reused)."
- **D — simulated primary transient failure.** First selected candidate returned
  `QUOTA_BLOCKED`; the coordinator removed it and **redrew** to the other
  candidate, which succeeded — same packet/authority binding preserved, distinct
  candidates, no repeated side effect.
- **E — `--exclude-model claude-cli/claude-opus-4-8`.** That exact model removed
  (`source=run`); `codex-cli/gpt-5-codex` remained.

## Fallback demonstration
Scenario D above (transient → redraw). Terminal (result-quality) failures are
never silently redrawn; exhaustion blocks honestly (unit-tested).

## Probability / score evidence
Recorded per routing decision: eligible + excluded candidates with reasons,
utilities, Beta posteriors, normalized probabilities, the fresh cryptographic
`run_seed`, mode, and policy + snapshot digests — replayable via
`deterministic-replay`.

## Token / cache / output metrics
Live probe cost `$0.0`, 0 errors; 51 recorded budget events, **$0 paid
committed**. Output-token/response-byte caps + `OUTPUT_BUDGET_EXCEEDED` are part of
the remaining delivery-lifecycle work (Phase F), not this workforce pass.

## Qualification reuse vs new
Roster reused 3 existing admitted profiles (fresh evidence); the live probe was a
fresh liveness invocation only. No whole-catalogue tournament was run.

## Exact unfilled capabilities / honest scope
- The W1–W6 modules (`workforce_policy`, `workforce`, `adaptive_routing`,
  `dispatch`, `lazy_qualification`) are built, unit-tested, and demonstrated live
  over the real admitted workforce.
- **W8 wired the effective WorkforcePolicy into the engine `run` loop**: live
  `candidate_agents` now drops any policy-excluded provider/model/family/adapter
  (an excluded target is never scheduled/probed/invoked in the run loop, not only
  in `bootstrap-runtime`), and the all-admitted fallback is fail-closed (§11) —
  the legacy scan runs only as a migration when no active-roster record has ever
  existed. `runtime.build_engine` + the CLI `run` command compose committed +
  operator + run policy layers.
- **Still remaining:** replacing the legacy `scheduler`'s ranking/selection in the
  run loop with `adaptive_routing` (Thompson) + `dispatch` (redraw) per packet —
  the policy exclusions and fail-closed selection are now enforced live, but the
  adaptive-sampling draw itself is not yet the run loop's selector (it is
  unit-tested and demonstrated over the real workforce).
- With only two subscription CLIs admitted and provider-diverse review required,
  excluding either still leaves a producer, but excluding one removes independent
  review for the other (Scenario C) — the correct fail-closed posture.

## Protected-gate state
All committed gates remain **false** (`allow_*` in `config/safety.yaml`);
`autonomous_safe_enabled=false`. No gate was enabled for this pass.

## Proof no provider-specific role preference remains
`committed_defaults` names no provider; `bootstrap.policy_candidates` derives the
population from discovery + policy with inference class from each candidate's own
evidence; `selection.default_filters` excludes nothing by default. Scenarios B/C/E
show any provider/model is absolutely excludable and never probed/invoked once
excluded; Scenario A shows selection is a distribution, not a fixed primary.

## Invariant
> Any provider or model may perform any role for which it currently satisfies the
> operator policy, semantic qualification, transport, containment, privacy,
> health, quota, risk and independence requirements. Any provider or model may be
> excluded absolutely. Availability or exclusion of a named provider is never a
> structural dependency of the USF Factory.
