# Provider Evaluation & Runtime-Wiring Report

Final provider-coverage and runtime-wiring completion pass. One bounded live
acceptance run; no paid API inference; `/usf` untouched; all protected gates
disabled.

- Eval suite: `provider-eval-v1`
- Rule bundle: `rule-bundle-v1` — `sha256:679710a5a081f7a5b2d065522c8929ad549ea6b2722f5210e380eb3f160cd96e`
- Eval payload digest: `sha256:c095744ffd71d3e6c31af7162b72639337d705fcbc64bd62989e4903984b53ae`
- Command:
  `usf-factory models evaluate-providers --allow-inference --allow-subscription-inference --max-cost-usd 0 --concurrency 4`
  (`--allow-paid-inference` **not** passed).

## 1. Provider coverage — every configured provider gets exactly one row

18 configured providers → 18 rows. Statuses are transport/authorization facts,
never model-quality claims. A representative model that was **not invoked**
(paid-only, disabled, no eligible model) is reported as such and never scored.

| provider | representative model | actual model | status | fidelity/opt/scope/evidence/struct/uncertainty |
|---|---|---|---|---|
| claude-cli | default | claude-opus-4-8 (verified) | EVALUATED | 1.0 / 1.0 / 1.0 / 1.0 / 1.0 / 1.0 |
| codex-cli | default | unverified (CLI did not report) | EVALUATED | 1.0 / 1.0 / 1.0 / 1.0 / 1.0 / 1.0 |
| openrouter | cohere/north-mini-code:free | cohere/north-mini-code:free (verified) | EVALUATED | 1.0 / 1.0 / 1.0 / 1.0 / 1.0 / 1.0 |
| ollama | lfm2.5:8b-a1b-q8_0 | lfm2.5:8b-a1b-q8_0 (verified) | EVALUATED | 1.0 / 0.0 / 0.0 / 1.0 / 1.0 / 1.0 |
| cerebras | gemma-4-31b | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| deepseek | deepseek-chat | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| gemini | models/antigravity-pre… | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| groq | allam-2-7b | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| huggingface | CohereLabs/aya-expanse | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| mistral | codestral-2508 | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| openai-api | babbage-002 | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| sambanova | gpt-oss-120b | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| together | BAAI/bge-base-en-v1.5 | — | PAID_INFERENCE_NOT_AUTHORIZED | not invoked |
| arcee | — | — | NO_ELIGIBLE_MODEL | not invoked |
| fireworks | — | — | NO_ELIGIBLE_MODEL | not invoked |
| anthropic-api | — | — | DISABLED_BY_CONFIG | not invoked |
| github-models | — | — | DISABLED_BY_CONFIG | not invoked |
| xai-grok | — | — | DISABLED_BY_CONFIG | not invoked |

Scores are the six deterministic dimensions: semantic rule fidelity, semantic
optimization (root-cause consolidation), scope discipline, evidence discipline,
structured output, uncertainty handling. Evidence for each EVALUATED row is
content-addressed in the CAS store (scores + truncated output).

**Invoked once each** (subscription CLIs / free API / local): claude-cli,
codex-cli, openrouter (free), ollama. Every other enabled API provider is
paid-only with a zero paid budget, so it received a coverage row but **no
inference call**. Quota/auth/model-id failures would be classified
QUOTA_BLOCKED / AUTH_FAILED / MODEL_UNAVAILABLE separately — none occurred this
run.

## 2. Cost accounting (split; paid budget is paid-API-only)

- **paid_api_spend_usd: $0.0000** — no paid API inference occurred; `--allow-paid-inference` stayed false.
- **subscription_reported_value_usd: $0.0990** — informational only (Claude CLI's self-reported cost via the operator subscription); never charged against the paid budget or a `--max-cost-usd` cap.
- **free_inference_cost_usd: $0.0000** — genuinely free API + local models.

## 3. Capability model — competence separated from transport

`AdapterCapabilities` records model competence (plain_invoke, structured_output,
usage/actual-model reporting) independently of transport (native_tool_calls,
brokered_tool_loop, bounded_patch_synthesis). Role transport requirements:

| role | required transport |
|---|---|
| planner / analyst / reviewer / integrator | `plain_invoke` (native tools **not** required) |
| patch producer | `brokered_tool_loop` **OR** `bounded_patch_synthesis` |

The legacy name-based gates (`_ADAPTERS_WITH_BROKER_TOOLS`, `_TOOL_ROLES`,
"no chat_with_tools ⇒ planner-only") are removed. When an adapter claims a
brokered tool loop, all three brokered gates (forced tool call, tool-result
follow-up, prohibited-tool compliance) are checked before it is trusted for
producer work.

Observed transports this run: **CLIs (claude-cli, codex-cli)** →
`bounded_patch_synthesis` (bounded producer); **openai-compatible / ollama** →
`brokered_tool_loop`.

## 4. Claude CLI + Codex CLI as first-class bounded producers

Both CLIs are invoked non-interactively, from a **fresh empty scratch dir**
(never the repo/workspace), with a **sanitized env** (provider API keys withheld)
and their **built-in tools disabled**:

- Codex: `codex exec --json --skip-git-repo-check -s read-only [-m MODEL] -` (prompt on stdin).
- Claude: `claude --print --output-format json --disallowed-tools <all> [--model MODEL]` (prompt on **stdin** — `--disallowed-tools` is variadic and would otherwise swallow a trailing positional prompt).

Model resolution: try the requested model, then **exactly one** retry with the
account/CLI default on an explicit model rejection (no id cycling). The
requested/actual/verified/fallback facts are recorded; if the CLI does not report
the model that ran, `actual_model` is left **UNVERIFIED** (never silently equated
with the request — see codex-cli above). CLI auth material is never read,
printed, logged, copied, or persisted.

### Live CLI fixture mutation (temporary factory-owned repo)

A disposable git repo (never `/usf`) with `rules/example.txt = "alpha"`; packet
write scope `rules/example.txt`; objective append `beta`. The CLI returns a
candidate unified diff via plain invoke; the **orchestrator** applies it inside
the disposable clone and **re-derives** the effective diff from git — the CLI
never touches the workspace.

| CLI | status | actual model | git-derived digest | changed paths | file result |
|---|---|---|---|---|---|
| claude-cli | COMPLETED | claude-opus-4-8 | `sha256:c5eaed762…` | `rules/example.txt` | `alpha` → `alpha`+`beta` |
| codex-cli | COMPLETED | gpt-5-codex | `sha256:c5eaed762…` | `rules/example.txt` | `alpha` → `alpha`+`beta` |

Both produced the identical git-re-derived diff. During iteration, one Claude
response wrapped the JSON in explanatory prose; the **strict fail-closed parser
rejected it** (FAILED, "result was not valid JSON") rather than accepting a
partial/false success — the sandbox behaving as designed. With the strict output
contract in the worker instructions, both CLIs conform.

## 5. Persisted role roster consumed by the runtime

A content-addressed `RoleRoster` (`roster-01KY2BVSGYQQ0NSB07NQ38QHJ3`) is
persisted and bound to the config + rule-bundle digest
(`sha256:679710a5…`, matching the runtime bundle). The runtime selects roles via
`roster_profile_for(...)` with dispatch-time revalidation — **not** first-found
storage order. Reviewer selection enforces provider independence.

| role | roster pick |
|---|---|
| planner | ollama / lfm2.5:8b-a1b-q8_0 |
| read-only analyst | ollama / lfm2.5:8b-a1b-q8_0 |
| integrator | ollama / lfm2.5:8b-a1b-q8_0 |
| patch producer | none admitted this run (fail-closed) |
| reviewer | none admitted this run (fail-closed) |

Empty roles fail closed: the engine BLOCKS waves needing a reviewer rather than
synthesizing approval.

## 6. Bounded live acceptance run

- `evaluate-providers` — 18 rows, one per configured provider (above).
- Plan-only cycle `cyc-01KY2BWBGSW86Q6T89QP1NEGJ3` — state LEARNED, read-only, 0 packets (USF authority unchanged).
- Shadow cycle `cyc-01KY2C08QK9HTRZBC4KA1Z0SDG` with `--shadow-packets 1` — state LEARNED, read-only, 0 packets. The dispatch cap is deterministic; with packets present it caps by sorted `packet_id` (covered by `test_shadow_packets_caps_dispatch`, 3 → 1).
- Live CLI fixture mutation — Claude + Codex once each, both COMPLETED (above).

## 7. Isolation & protected-gate proof

- `/usf` HEAD before **and** after: `d5d9d4f0165f2a4f9e8436ab160a45cb986deac2`; working tree dirty paths: **0**; no `/usf/.git/worktrees`; no Stardog mutation; no publication/push to the USF repo.
- All 7 protected gates **false**: paid_inference, source_egress, main_integration, push_pr, stardog_publication, risk_acceptance, terminal_completion.
- Source egress remains disabled; no private `/usf` source was sent during provider selection.
- No provider API keys in the CLI subprocess environment.

## 8. Verification commands

```
scripts/verify.sh --fresh --attest      # ruff format+check, mypy, pytest, wheel build, secret scan (clean tree)
python -m pytest -q                      # full suite
usf-factory models evaluate-providers --allow-inference --allow-subscription-inference --max-cost-usd 0 --concurrency 4
usf-factory run --mode plan-only
usf-factory run --mode shadow --shadow-packets 1
```

No SDKs are used: API providers use the existing HTTP adapters; Claude/Codex are
driven only via their installed `claude` / `codex` binaries as subprocesses.
