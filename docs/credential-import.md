# Credential import

Model-provider credentials live in `/root/.env` — root-owned, **mode 0600**,
outside the repository, never printed/logged/committed/stored in SQLite.

## Commands

```bash
python scripts/import-provider-env.py --dry-run --from-process   # names only
python scripts/import-provider-env.py --from-process             # from current env
env -0 | python scripts/import-provider-env.py --stdin0          # from an outer shell
python scripts/import-provider-env.py --from-env-file /path/env  # from a dotenv file
python scripts/check-provider-env.py                             # verify conforming
```

The CLI mirrors these: `usf-factory env status`, `usf-factory env import ...`.

## Canonical variables (§5.1)

```
OPENAI_API_KEY  OPENROUTER_API_KEY  GROQ_API_KEY  MISTRAL_API_KEY  GEMINI_API_KEY
SAMBANOVA_API_KEY  GITHUB_MODELS_TOKEN  GITHUB_PERSONAL_ACCESS_TOKEN  HF_TOKEN
FIREWORKS_API_KEY  TOGETHER_API_KEY  DEEPSEEK_API_KEY  CEREBRAS_API_KEY  ARCEE_TOKEN
OLLAMA_API_KEY (optional)  XAI_API_KEY (optional)  ANTHROPIC_API_KEY (optional)
```

## Alias normalization & precedence (§5.2)

Each canonical variable is resolved from an ordered alias list (canonical name
first). Examples:

| Canonical | Accepted aliases |
| --- | --- |
| `OPENROUTER_API_KEY` | `OPENROUTER_API_KEY`, `OPENROUTER_TOKEN` |
| `GEMINI_API_KEY` | `GEMINI_API_KEY`, `GOOGLE_GEMINI_API_KEY`, `GEMINI_TOKEN` |
| `CEREBRAS_API_KEY` | `CEREBRAS_API_KEY`, `CEREBRAS_TOKEN`, `CERABRAS_TOKEN` |
| `HF_TOKEN` | `HF_TOKEN`, `HUGGING_TOKEN`, `HUGGING_FACE_READ_TOKEN` |
| `ARCEE_TOKEN` | `ARCEE_TOKEN`, `ARCEEAI_KEY` |

Full table in `secrets.ALIAS_TABLE`.

**Conflict rule:** if two non-empty aliases for the same canonical variable
**differ**, that variable's import is stopped and reported as a *conflict* (no
value printed). Identical values are not a conflict.

**GitHub exception:** `GITHUB_TOKEN` / `GITHUB_PERSONAL_ACCESS_TOKEN` legitimately
feed two canonicals, so those two use *precedence* (first non-empty wins) instead
of strict conflict detection.

## GitHub Models admission

A general GitHub PAT does **not** imply Models permission. `GITHUB_MODELS_TOKEN`
is only **written** to `/root/.env` when it comes from an explicit
`GITHUB_MODELS_TOKEN` source. If only a PAT is present, the PAT is stored under
`GITHUB_PERSONAL_ACCESS_TOKEN`, `github-models` stays disabled, and admission
requires a read-only Models-permission probe.

## Excluded (§5.3) — never imported

`STARDOG_TOKEN` and all `STARDOG_*` (the factory uses `/usf/.env` via MCP), plus
unrelated service credentials (`LINEAR_API_KEY`, `SENTRY_AUTH_TOKEN`,
`ATLASSIAN_TOKEN`, `NETLIFY_API_TOKEN`, …). See `secrets.EXCLUDED_VARS`.

`AIS_API_KEY` is recorded as an **unmapped candidate** by name only and never
imported (provider unknown).

## OIDC / CLI adapters (§5.4)

Codex and Claude use their **existing CLI authentication** — never env tokens.
`codex-cli` and `openai-api` are distinct provider profiles, as are `claude-cli`
and `anthropic-api`. `ANTHROPIC_API_KEY` is never invented.

## Idempotent conforming rewrite

Running the import against an existing non-conforming `/root/.env` (e.g. mode
0644 with `STARDOG_*`/`LINEAR_API_KEY` present) rewrites it atomically to a
conforming mode-0600 file containing only allowlisted canonical variables. The
excluded entries are dropped and copied nowhere.
