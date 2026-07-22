# BUILD REPORT — USF Adaptive Semantic Factory

First production-quality implementation of the architecture in `DESIGN.md`. Built
as an independent repository at `/root/usf-factory`, with strict isolation from
`/usf` and its Stardog semantic authority.

- **Build date (UTC):** 2026-07-21
- **Builder:** Claude (Opus 4.8, 1M context)
- **Result:** functioning, tested, safe-by-default orchestration package.

---

## 1. DESIGN source

| Item | Value |
| --- | --- |
| Source path | `/root/DESIGN.md` |
| SHA-256 | `803032308ae463be62d5bd9281f4af5ce037a9075a4d78b2d4fb1cf61a565dcf` |
| Preserved as | `/root/usf-factory/DESIGN.md` (byte-identical; hash verified) |

---

## 2. /usf isolation proof

| | Initial (baseline) | Final |
| --- | --- | --- |
| Branch | `main` | `main` |
| HEAD | `d5d9d4f0165f2a4f9e8436ab160a45cb986deac2` | `d5d9d4f0165f2a4f9e8436ab160a45cb986deac2` |
| Upstream | `origin/main` | `origin/main` |
| Working-tree changes | 0 | 0 |
| Tracked diff SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty) | identical |
| `/usf/.git/worktrees` | none | none |

**`/usf` was not modified by this task.** Branch, HEAD, tracked diff, and
working-tree status are identical to the baseline. No worktree was ever
registered under `/usf/.git/worktrees`.

**Concurrent process observed:** a `codex resume … execute GOAL.md` process
(PID 255952) and the USF MCP server (PID 1701554) were running throughout. No
change to `/usf` HEAD or tracked state was observed during this task; nothing is
attributed to that process.

**Isolation mechanism:** read-only fetch from `/usf` → factory-owned bare mirror
(`/root/.local/share/usf-factory/mirrors/usf.git`, created with
`clone --mirror --no-hardlinks --no-local`) → disposable clones per packet
(remotes removed) → centralized integration clone. All git reads of `/usf` use
`--no-optional-locks`.

---

## 3. Repository

> **Status labels (corrected per adversarial review):** version `0.1.0`;
> **state: safe plan-only control-plane prototype**; production readiness: **not
> ready**; autonomous-mutation readiness: **not ready**. See
> `docs/known-limitations.md` for the authoritative current-reality / nonconformance
> / target breakdown. The phrase "first production-quality implementation" refers
> to engineering quality of the control plane, not operational production readiness.

| Item | Value |
| --- | --- |
| Path | `/root/usf-factory` |
| VCS | independent git repo. Initially delivered with **no remote**; on explicit user request the original `origin` → `github.com/maldous/usf-factory.git` was restored and `main` was pushed. |
| Commits | `0a0a82d` (initial build) then review-fix commit(s); pushed to `origin/main`. |
| Python | 3.11.2 (only interpreter available in the chroot; `pyproject` targets `>=3.11`) |
| Package manager | `pip` + `venv` (no `uv` installed); reproducible lock at `requirements.lock` |
| Source size | ~9,300 LOC across `src/` + `tests/` |

### Dependency versions (from `requirements.lock`)

```
pydantic==2.13.4  typer==0.27.0  httpx==0.28.1  PyYAML==6.0.3  rich==15.0.0
jsonschema==4.26.0  python-dotenv==1.2.2  pytest==8.4.2  ruff==0.15.22
mypy==2.3.0  respx==0.23.1
```

---

## 4. Files created

```
DESIGN.md  README.md  AGENTS.md  LICENSE-NOTICE.md  BUILD_REPORT.md
pyproject.toml  requirements.lock  .gitignore  .env.example
config/    providers.yaml routing.yaml trust-policy.yaml data-egress-policy.yaml
           task-classes.yaml budgets.yaml qualification-suite.yaml safety.yaml
schemas/   semantic-snapshot, obligation-graph, packet, packet-set,
           packet-result, worker-result (JSON Schema, generated from models)
src/usf_factory/   40 modules (control plane, providers/, adapters)
qualifications/    semantic-planning, rdf-owl-shacl, implementation-review,
                   holdout/holdout-v1 (public + hidden holdout corpus)
fixtures/planner/  sample-obligations.yaml (deterministic planner fixture)
tests/     12 files, 89 tests (unit/contract/adversarial/e2e) + stub MCP server
scripts/   import-provider-env.py  check-provider-env.py
systemd/   usf-factory.service  usf-factory.timer  README.md
docs/      architecture, security, provider-adapters, model-qualification,
           usf-authority-boundary, packet-lifecycle, integration-and-attribution,
           operator-guide, recovery, credential-import
```

---

## 5. Architecture implemented

Deterministic control plane owning the full cycle (DESIGN §3): preflight/recovery
→ deterministic semantic snapshot (via read-only MCP) → AI planner + independent
critic → deterministic packet compiler + conflict DAG + antichain → task-specific
explainable scheduler with seeded exploration → isolated worker execution →
deterministic result qualification + failure taxonomy → deterministic
pre-integration + semantic conflict detection → advisory review → deterministic
validation gates → stage-specific attribution & learning → re-snapshot.

Four planes: control (deterministic), intelligence (planner/workers/integrator/
reviewers), execution (disposable clones/sandbox), assurance (SHACL/SPARQL/tests/
proof/publication). SQLite WAL + append-only event log + content-addressed store.
Full replay determinism (identical inputs → identical artifact ids).

---

## 6. Provider definitions

18 providers configured; **Codebuff excluded entirely** (present only in the
`exclude` list). Grok and Anthropic-API are disabled stubs.

| Enabled (15, credential-gated) | Disabled |
| --- | --- |
| codex-cli, claude-cli, openai-api, openrouter, groq, mistral, gemini, sambanova, huggingface, fireworks, together, deepseek, cerebras, arcee, ollama | github-models (probe-gated), xai-grok (no key), anthropic-api (no key) |

Adapters: generic OpenAI-compatible (with per-provider config), Ollama (local),
Codex CLI and Claude CLI (OIDC/CLI auth). Routed providers record the **actual**
model returned separately from the requested id.

### OIDC / CLI adapter status

- `codex-cli`: adapter present; auth probed via CLI presence + auth-material
  existence check (contents never read). Distinct from `openai-api`.
- `claude-cli`: adapter present; same probing approach. Distinct from
  `anthropic-api`.
- No OAuth/OIDC bearer token is copied into `/root/.env`.

---

## 7. Credentials (names only)

`/root/.env` is root-owned, **mode 0600**, outside the repo, never
printed/logged/committed/stored in SQLite. A pre-existing non-conforming
`/root/.env` (mode 0644, containing `STARDOG_*` and `LINEAR_API_KEY`) was
rewritten by the import script to a conforming file.

**Imported (13, by name):** `ARCEE_TOKEN, CEREBRAS_API_KEY, DEEPSEEK_API_KEY,
FIREWORKS_API_KEY, GEMINI_API_KEY, GITHUB_PERSONAL_ACCESS_TOKEN, GROQ_API_KEY,
HF_TOKEN, MISTRAL_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, SAMBANOVA_API_KEY,
TOGETHER_API_KEY`

**Missing (by name):** `GITHUB_MODELS_TOKEN` (a PAT is present but a general token
does not imply Models permission → withheld pending a read-only probe),
`ANTHROPIC_API_KEY`, `XAI_API_KEY`, `OLLAMA_API_KEY` (all optional/absent).

**Excluded and dropped (never imported/copied):** `STARDOG_TOKEN`,
`STARDOG_SERVER`, `STARDOG_DATABASE`, `STARDOG_USERNAME`, `LINEAR_API_KEY`.
`AIS_API_KEY` recorded as an unmapped candidate by name only (not present in the
source). Stardog credentials are used only via the `/usf` MCP boundary
(`/usf/.env`).

---

## 8. Provider / model discovery

- Provider discovery, model listing, and auth probes are **metadata-only and
  allowed**; billable inference is **disabled by default**.
- Discovery is dated and content-addressed (`ProviderCatalogueSnapshot`,
  `catalog_id`, `discovered_at`, TTLs) and normalized into provider-independent
  `ModelRecord`s.
- No live provider discovery was forced during the build (to avoid unnecessary
  external calls); the path is exercised by contract tests with mocked transports
  and is available via `usf-factory providers refresh`.

---

## 9. Qualification features implemented

- 10 versioned mechanical probes with deterministic grading (generic prompts;
  never `/usf` source).
- USF qualification corpus: 32 public regression cases + 6 hidden holdout cases
  covering the historical USF failure classes; deterministic graders.
- (agent, task_class, dimension)-segmented scores over 17 dimensions; admission
  roles earned from `trust-policy.yaml` thresholds (no automatic write access).
- Budget gating: billable probing/qualification disabled by default
  (`--allow-billable`, `--budget-usd`).

---

## 10. USF MCP validation (live)

- `usf_health`: `ok=true`, database `USF`, **triples=105927**, 14 tools exposed.
- Read-only allowlist enforced: mutation tools (`usf_evidence_admit`,
  `usf_materialise`, …) are **not callable** via the client; mutation SPARQL
  refused.
- Deterministic snapshot compiled from live authority + git:
  `snapshot_id=snap-978da27a4d3e7ed9`, graphs=40, triples=105927,
  0 unresolved obligations, `repository_head=d5d9d4f0165f`.

---

## 11. Safe dry-run result

Live non-mutating `plan-only` cycle: state `LEARNED`, snapshot
`snap-978da27a4d3e7ed9`, **2 packets selected** (SHACL repair + SPARQL authoring,
the correct first antichain), 0 accepted (dry-run), 0 blockers,
`no_progress=False`. Full pipeline events recorded
(preflight → snapshot.captured → plan.compiled → execute.done → cycle.finished).
No `/usf` writes; no billable inference. Cycle is deterministic (repeat run →
identical snapshot/set ids).

---

## 12. Tests & static checks

| Check | Result |
| --- | --- |
| `ruff format --check` | 53 files formatted, clean |
| `ruff check` | All checks passed |
| `mypy` | Success — no issues in 40 source files |
| `pytest` | **89 passed** (62 unit, 7 contract, 14 adversarial, 6 e2e) |
| `python -m build --wheel` | `usf_factory-0.1.0-py3-none-any.whl` built |

Adversarial coverage includes: prompt-injection via patch, `/root/.env` read
attempt, `/usf` write attempt, `git push`, forbidden tool, completion-without-
changes, planner over-fragmentation, hidden dependency, same-IRI-different-files,
stale packet, duplicate claim, uncertain mutation, model substitution, quota
expiry, git-clean-but-semantic-conflict, reviewer consensus ≠ proof, learning
cannot weaken policy, credential-alias disagreement, publication gate disabled.

---

## 13. Verifications

- **No `/usf` tracked change** caused (branch/HEAD/diff/status/worktrees all
  identical to baseline).
- **No credential value** appears in the tracked repository (0 matches for every
  `/root/.env` value; `.env` not tracked; no token-shaped strings in
  src/config/schemas/docs).
- **No secret value** in SQLite (0 matches), CAS (0), or event payloads (18 rows,
  0 token-shaped).

---

## 14. Known limitations (current reality vs target)

- Billable model probing/qualification and AI worker/integrator/reviewer
  execution are **implemented as interfaces but not wired to live inference** in
  this safe runtime (they refuse without explicit budget). Scoring, sandboxing,
  and integration logic are fully implemented and tested with mocks/fixtures.
- The default runtime executes only **non-mutating** cycles (observe / plan-only).
  `approve-wave` / `autonomous-safe` are implemented but blocked until
  `autonomous_safe_enabled` is set.
- Concurrency defaults to 2 workers; higher concurrency is supported by the model
  but not stress-tested here.
- Stardog publication is an interface + state machine only (fail-closed,
  disabled). Terminal `COMPLETE` is computed from GOAL/authority, never prose,
  and is disabled by default.
- Python 3.12 was not available in the chroot; the package targets and was
  validated on 3.11.2.
- This is **not** autonomous-production-ready and does not claim to be.

---

## 14b. Adversarial review response

An external adversarial review was incorporated. Bounded P0 correctness/safety
defects were **fixed with regression tests**:

- **P0-2** snapshot fails closed (no synthesized authority digest; health + required tools + counts required);
- **P0-3** worker results are strict/fail-closed (no default-`COMPLETED`; unknown/missing status and unknown fields → `FAILED`; mutating packets require a real patch; patches stored in CAS);
- **P0-4** explicit `provider_id`/`requested_model_id` routing (adapters refuse an opaque `agent-…` id);
- **P0-9** unknown task classes are excluded from selection;
- **P0-11** qualification scores missing answers as 0 (full-suite denominator);
- **P0-13** admission roles are orthogonal (no write-privilege escalation via rank);
- **P0-7 (partial)** CLI subprocesses run with a sanitized, secret-free environment.

Larger workstreams remain **Planned** and gated (real agent runtime, OS-level
sandbox, USF programme-state compiler, event-sourced durable state with fencing
tokens, real git-apply integration, concurrency, per-provider egress, calibrated
learning, operational controls, protected PR/publication handshake). The repo is
private and the account keeps GitHub Actions at a $0 spending limit, so hosted
runners cannot start; by operator decision the CI workflow was removed and quality
is verified reproducibly with `scripts/verify.sh` (ruff/mypy/pytest/build/secret
scan, pinned to `requirements.lock`). Full status: `docs/known-limitations.md`.

Test count after the first fix wave: **102 passed**.

## 14c. Adversarial review — remaining items completed

A second wave implemented the larger review items as real, tested, **gated** code
(defaults unchanged; no `/usf` mutation, no billable inference, no publication):

- **P0-8** durable state: fencing tokens, coordinator + packet leases
  (heartbeat/expiry), crash reconciler, ULID cycle ids, CAS fsync + read-back
  integrity, `synchronous=FULL`, busy-timeout, foreign keys.
- **P0-6** OS-enforced sandbox (`sandbox_runtime.py`): privilege-drop to `nobody`
  (blocks reading 0600 `/root/.env` and writing `/usf` — proven by the escape
  suite), rlimits, no-new-privs, process-group timeout, sanitized env. Honest
  caveat: namespace FS/network isolation is unavailable in this chroot and is
  reported as such; mutation stays disabled here for that reason.
- **P0-5** agent runtime: bounded tool broker + tool-call loop with turn budget;
  real gated Codex/Claude non-interactive adapters (JSON/JSONL parsing) and an
  OpenAI tools-chat turn; tested via stub binaries + fake models.
- **P0-1** deterministic USF programme-state compiler (`ProgrammePlanner`) that
  derives obligations from live MCP work-plan/bootstrap CONTENTS (not fixtures);
  the engine now plans from it. Fixtures are test-only.
- **P0-10** real git-apply integration: base checkout, `git apply --index`,
  combined diff + changed paths derived from actual git; patches stored in CAS.
- **P0-9/11/13/7** closed (unknown task classes excluded; missing qual answers
  score 0; orthogonal roles; sanitized subprocess env).
- **P1 (implemented, gated):** bounded-concurrency execution; per-provider egress
  policy; OpenRouter catalogue normalizer + native Anthropic Messages adapter;
  calibrated learning (immutable raw observations + Beta-Bernoulli); ops
  (`maintenance backup`/`gc`, CAS GC); prepare-only PR/publication delivery
  handshake (never pushes).

Still **Planned** (sequenced): full subject→file mapping for mutating packets,
private holdout store, live health/quota/cost feeding into scheduling, UCB/
Thompson routing, and the executed push/merge/publish steps. See
`docs/known-limitations.md` for the authoritative per-item status.

**Test count after this wave: 135 passed** (82 unit, 16 contract, 27
adversarial, 10 e2e); ruff + mypy clean; wheel builds. Live plan-only cycle
verified against the USF MCP; `/usf` confirmed unchanged.

## 15. Disabled protected actions (default)

`paid_inference`, `source_egress`, `main_integration`, `push_pr`,
`stardog_publication`, `risk_acceptance`, `terminal_completion` — all **disabled**.
`autonomous_safe_enabled = false`. The learning engine may never change these; it
writes only `model_task_scores`.

---

## 16. Exact next commands

```bash
cd /root/usf-factory && . .venv/bin/activate

# Inspect
usf-factory doctor
usf-factory providers status
usf-factory usf health
usf-factory cycle snapshot
usf-factory run --mode plan-only
usf-factory cycle plan
usf-factory routing explain <packet-id>

# Credentials (names only)
python scripts/check-provider-env.py
usf-factory env status

# When ready to enable more (deliberate, gated):
#   edit config/safety.yaml       (allow_billable, autonomous_safe_enabled, …)
#   edit config/budgets.yaml      (billable_usd and wall-time safety budgets;
#                                  concurrency is runtime-observed, not configured)
usf-factory models discover
usf-factory models qualify --allow-billable --budget-usd 20    # opt-in, billable
usf-factory models leaderboard --task shacl-repair --dimension shacl_sparql

# Continuous non-mutating operation
#   cp systemd/usf-factory.{service,timer} /etc/systemd/system/
#   systemctl enable --now usf-factory.timer
```

Do not add a git remote or push; do not enable a mutating mode or publication
without deliberate operator review.
