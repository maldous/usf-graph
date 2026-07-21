# Provider / model selection report

Staged non-Llama tournament (Stage A metadata → B genuine mechanical probes, repeated for LCB → role eligibility → central ranked selector). All protected actions disabled; `/usf` unchanged; no private source sent to external providers (probes use generic, non-sensitive prompts).

## Selection controls

- excluded providers: `['ollama']`
- excluded families: `['llama']`
- excluded models: `['lfm2.5:8b-a1b-q8_0', 'north-mini-code-1.0:q4_K_M']`
- include (forced): `[]`
- skip_valid_existing: `True`  force_reassess: `False`
- budget: spent $2.2448619 / cap $0.0

## Excluded models (with reason)

| provider | model | reason |
| --- | --- | --- |
| ollama | `lfm2.5:8b-a1b-q8_0` | provider ollama excluded |
| ollama | `north-mini-code-1.0:q4_K_M` | provider ollama excluded |
| ollama | `north-mini-code-1.0:latest` | provider ollama excluded |
| huggingface | `meta-llama/Llama-3.1-8B-Instruct` | family 'llama' excluded |
| huggingface | `meta-llama/Llama-3.3-70B-Instruct` | family 'llama' excluded |
| huggingface | `meta-llama/Llama-4-Scout-17B-16E-Instruct` | family 'llama' excluded |
| huggingface | `meta-llama/Llama-Guard-4-12B` | family 'llama' excluded |
| huggingface | `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8` | family 'llama' excluded |
| huggingface | `deepseek-ai/DeepSeek-R1-Distill-Llama-70B` | family 'llama' excluded |
| huggingface | `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` | family 'llama' excluded |
| groq | `llama-3.1-8b-instant` | family 'llama' excluded |
| groq | `meta-llama/llama-prompt-guard-2-22m` | family 'llama' excluded |
| groq | `meta-llama/llama-prompt-guard-2-86m` | family 'llama' excluded |
| groq | `llama-3.3-70b-versatile` | family 'llama' excluded |
| sambanova | `Meta-Llama-3.3-70B-Instruct` | family 'llama' excluded |
| openrouter | `meta-llama/llama-guard-4-12b` | family 'llama' excluded |
| openrouter | `meta-llama/llama-4-maverick` | family 'llama' excluded |
| openrouter | `meta-llama/llama-4-scout` | family 'llama' excluded |
| openrouter | `aion-labs/aion-rp-llama-3.1-8b` | family 'llama' excluded |
| openrouter | `deepseek/deepseek-r1-distill-llama-70b` | family 'llama' excluded |
| openrouter | `meta-llama/llama-3.3-70b-instruct` | family 'llama' excluded |
| openrouter | `meta-llama/llama-3.2-1b-instruct` | family 'llama' excluded |
| openrouter | `meta-llama/llama-3.2-3b-instruct` | family 'llama' excluded |
| openrouter | `nousresearch/hermes-3-llama-3.1-70b` | family 'llama' excluded |
| openrouter | `nousresearch/hermes-3-llama-3.1-405b` | family 'llama' excluded |
| openrouter | `meta-llama/llama-3.1-70b-instruct` | family 'llama' excluded |
| openrouter | `meta-llama/llama-3.1-8b-instruct` | family 'llama' excluded |
| together | `meta-llama/Llama-3.3-70B-Instruct-Turbo` | family 'llama' excluded |
| together | `meta-llama/Llama-Guard-4-12B` | family 'llama' excluded |
| together | `meta-llama/Llama-3-8b-chat-hf` | family 'llama' excluded |
| together | `meta-llama/Meta-Llama-3-8B-Instruct` | family 'llama' excluded |
| together | `meta-llama/Meta-Llama-3-70B-Instruct-Turbo` | family 'llama' excluded |
| together | `meta-llama/Meta-Llama-3.1-8B` | family 'llama' excluded |
| together | `meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo` | family 'llama' excluded |
| together | `Salesforce/Llama-Rank-V1` | family 'llama' excluded |
| together | `nvidia/Llama-3.1-Nemotron-70B-Instruct-HF` | family 'llama' excluded |
| together | `meta-llama/Llama-3.1-405B-Instruct` | family 'llama' excluded |
| together | `meta-llama/Llama-3.2-1B-Instruct` | family 'llama' excluded |
| together | `meta-llama/Llama-3.2-3B-Instruct` | family 'llama' excluded |
| together | `deepseek-ai/DeepSeek-R1-Distill-Llama-70B` | family 'llama' excluded |
| together | `meta-llama/Llama-3.2-3B` | family 'llama' excluded |
| together | `meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo` | family 'llama' excluded |
| together | `nim/meta/llama-3.2-11b-vision-instruct` | family 'llama' excluded |
| together | `nim/meta/llama-3.2-90b-vision-instruct` | family 'llama' excluded |
| together | `nim/meta/llama-3.3-70b-instruct` | family 'llama' excluded |
| together | `nim/nvidia/llama-3.1-nemotron-70b-instruct` | family 'llama' excluded |
| together | `nim/meta/llama-3.1-8b-instruct` | family 'llama' excluded |
| together | `nim/meta/llama-3.1-70b-instruct` | family 'llama' excluded |
| together | `nim/nvidia/llama-3.3-nemotron-super-49b-v1` | family 'llama' excluded |
| together | `meta-llama/Llama-2-7b-chat-hf` | family 'llama' excluded |
| together | `meta-llama/Llama-4-Scout-17B-16E-Instruct` | family 'llama' excluded |
| together | `deepcogito/cogito-v1-preview-llama-8B` | family 'llama' excluded |
| together | `deepcogito/cogito-v1-preview-llama-70B` | family 'llama' excluded |
| together | `deepcogito/cogito-v1-preview-llama-70B-Turbo` | family 'llama' excluded |
| together | `meta-llama/Llama-3.3-70B-Instruct` | family 'llama' excluded |
| together | `meta-llama/Meta-Llama-3.1-70B` | family 'llama' excluded |
| together | `meta-llama/Llama-3.2-1B` | family 'llama' excluded |
| together | `meta-llama/Llama-3.1-405B` | family 'llama' excluded |
| together | `meta-llama/Llama-4-Scout-17B-16E` | family 'llama' excluded |
| together | `togethercomputer/meta-llama-3.1-8B-Instruct-AWQ-INT4` | family 'llama' excluded |
| together | `meta-llama/Llama-3.3-70B-Instruct-FP8-Lora` | family 'llama' excluded |
| together | `meta-llama/Llama-4-Scout-17B-16E-Instruct-FP8-Lora` | family 'llama' excluded |
| together | `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP4` | family 'llama' excluded |

## Skipped (valid existing evidence)

_none_

## Assessment matrix (Stage B, repeated → LCB)

| provider | model | probes | class | structural | tool | actual model(s) | in/out tok | cached | cost | verified |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| claude-cli | `claude-haiku-4-5` | 8/10 | QUALIFIED_PLANNER | ✅ | — | claude-haiku-4-5 | 200/3485 | 436890 | $0.1898 | yes |
| claude-cli | `claude-opus-4-8` | 9/10 | QUALIFIED_PLANNER | ✅ | — | claude-haiku-4-5-20251001,claude-opus-4-8 | 40/4712 | 381304 | $0.662 | yes |
| openrouter | `google/gemma-4-31b-it:free` | 0/10 | FAILED_QUALIFICATION | ❌ | — | google/gemma-4-31b-it:free | 35/4 | 0 | $0.0 | est |
| openrouter | `nvidia/nemotron-3-super-120b-a12b:free` | 8/10 | QUALIFIED_PLANNER | ✅ | — | nvidia/nemotron-3-super-120b-a12b:free | 1274/14769 | 0 | $0.0 | est |
| openrouter | `openai/gpt-oss-20b:free` | 8/10 | FAILED_QUALIFICATION | ❌ | — | openai/gpt-oss-20b:free | 1940/5254 | 0 | $0.0 | est |
| openrouter | `openrouter/free` | 8/10 | QUALIFIED_PLANNER | ✅ | — | cohere/north-mini-code:free,google/gemma-4-26b-a4b-it:free,nvidia/nemotron-3-nano-30b-a3b:free,nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free,nvidia/nemotron-3-ultra-550b-a55b:free,nvidia/nemotron-3.5-content-safety:free,nvidia/nemotron-nano-12b-v2-vl:free,nvidia/nemotron-nano-9b-v2:free,openai/gpt-oss-20b:free,poolside/laguna-xs-2.1:free | 1538/3321 | 0 | $0.0 | est |

## Cache measurement

- aggregate cached input tokens: **818194**
- aggregate uncached input tokens: **5027** (principal efficiency metric)
- providers reporting cache reads (e.g. Claude CLI) demonstrate real provider-native caching across the repeated probe rounds.

## Proposed roster

### PRIMARY_PLANNER
- profile: `agent-6a3e997f32e408e9`
- provider / model: `claude-cli` / `claude-haiku-4-5`
- actual-model policy: `claude-haiku-4-5`
- role score (LCB): 1.0  structural=True tool=False
- cost: $0.1898 (verified)  uncached_tokens=200 cached=436890
- router: False

### PRIMARY_PATCH_PRODUCER
`NO_QUALIFIED_MODEL` — insufficient evidence; role left unfilled (not force-filled).

### PRIMARY_REVIEWER
`NO_QUALIFIED_MODEL` — insufficient evidence; role left unfilled (not force-filled).

### PRIMARY_INTEGRATOR
`NO_QUALIFIED_MODEL` — insufficient evidence; role left unfilled (not force-filled).

### FAST_ANALYST
- profile: `agent-6a3e997f32e408e9`
- provider / model: `claude-cli` / `claude-haiku-4-5`
- actual-model policy: `claude-haiku-4-5`
- role score (LCB): 1.0  structural=True tool=False
- cost: $0.1898 (verified)  uncached_tokens=200 cached=436890
- router: False

### LOCAL_PRIVATE_FALLBACK
`NO_QUALIFIED_MODEL` — insufficient evidence; role left unfilled (not force-filled).

### PLANNER_FALLBACK
- profile: `agent-c5d6fc58b17938a9`
- provider / model: `openrouter` / `nvidia/nemotron-3-super-120b-a12b:free`
- actual-model policy: `nvidia/nemotron-3-super-120b-a12b:free`
- role score (LCB): 1.0  structural=True tool=False
- cost: $0.0 (estimate)  uncached_tokens=1274 cached=0
- router: False

### PRODUCER_FALLBACK
`NO_QUALIFIED_MODEL` — insufficient evidence; role left unfilled (not force-filled).

### REVIEWER_FALLBACK
`NO_QUALIFIED_MODEL` — insufficient evidence; role left unfilled (not force-filled).

## Notes / known weaknesses

- CLI adapters (Codex/Claude) drive text/structured roles well but have no brokered `chat_with_tools`, so they are not eligible as brokered PATCH_PRODUCER/INTEGRATOR workers (tool_ok=—). Tool roles require an OpenAI-compatible adapter with native tool calling.
- Router aliases are treated as stochastic services; a mutation role is never assigned to a router whose actual model is not stable.
- Mutation-role admission uses the lower confidence bound over repeated rounds, never a single best run.
