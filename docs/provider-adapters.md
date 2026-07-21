# Provider adapters

A provider adapter is the only component that touches provider credentials. It
implements the `ProviderAdapter` protocol (`providers/base.py`):

```python
async def discover_models() -> list[DiscoveredModel]   # metadata-only, not billable
async def probe_auth() -> ProviderHealth               # cheap liveness/auth, not billable
async def probe_model(model_id, ProbeSpec) -> ProbeResult   # billable — gated
async def invoke(AgentRequest) -> AgentResponse             # billable — gated
```

## Adapter kinds

| Kind | Module | Providers |
| --- | --- | --- |
| `openai_compatible` | `providers/openai_compatible.py` | openai-api, openrouter, groq, mistral, gemini (OpenAI endpoint), sambanova, github-models, huggingface, fireworks, together, deepseek, cerebras, arcee, xai-grok, anthropic-api |
| `ollama` | `providers/ollama.py` | ollama (local, free, `local_only`) |
| `codex_cli` | `providers/cli_adapters.py` | codex-cli (OIDC CLI auth) |
| `claude_cli` | `providers/cli_adapters.py` | claude-cli (OIDC CLI auth) |

**Codebuff is excluded entirely** and never registered.

## Configuration

Providers are declared in `config/providers.yaml`. Every record carries:
`provider_id, display_name, auth_mode, credential_reference, adapter, base_url,
models_endpoint, catalog_ttl, health_ttl, quota_ttl, privacy_class,
default_enabled, supports_tool_probe, supports_structured_output_probe, notes`.

`credential_reference` is a **name only**: `env:OPENAI_API_KEY`, `cli:codex`, or
`none`.

## Enablement gating (registry)

`ProviderRegistry.enablement(id)` returns whether a provider is usable:

- excluded ids are never registered (Codebuff);
- `default_enabled: false` → disabled (`xai-grok`, `anthropic-api`);
- `api_token` provider with an absent credential → disabled ("missing credential");
- `github-models` → disabled pending a **Models-permission probe** even if a token exists.

`usf-factory providers status` prints the enablement table (credential presence
by name, never value).

## Discovery & normalization

`ProviderRegistry.discover_one` records a `ProviderHealth` event, fetches the
catalogue (metadata-only), stores a content-addressed `ProviderCatalogueSnapshot`,
and normalizes each model into a provider-independent `ModelRecord`
(`model_registry.normalize_model`). All facts are dated observations with a
source and (for catalogues) a TTL.

## Routed providers & actual-model receipts

For routed services (e.g. `openrouter/auto`, `*:free`), the adapter records the
**actual model** returned in each response (`AgentResponse.actual_model`),
separate from the requested id — so policy can reject a silent substitution.
Verified in `tests/test_contract.py::test_routed_provider_records_actual_model`.

## Billable gating

`probe_model` and `invoke` refuse to run unless billing is explicitly enabled
(`allow_billable`, set from `config/safety.yaml`). Local Ollama is free and not
gated. This is defense-in-depth; the primary budget gate is in the qualification
and worker layers (`--allow-billable`, `--budget-usd`).

## Adding a provider

Genuine additional providers can be added via `config/providers.yaml` using an
existing adapter kind (usually `openai_compatible`). Do **not** infer providers
from arbitrary environment-variable names. New API-token providers need a
canonical credential variable added to `secrets.ALIAS_TABLE`.
