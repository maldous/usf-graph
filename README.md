# USF Adaptive Semantic Factory

A **deterministic, model-agnostic orchestration engine** that advances Universal
Service Foundation (USF) semantic work by treating AI providers and models as
replaceable, qualified workers.

The deterministic control plane owns the loop. Models are workers. The objective
is not to maximize model calls — it is to maximize:

```
accepted semantic obligations closed
────────────────────────────────────
wall-clock time × cost × regression risk
```

This is the first production-quality implementation of the architecture in
[`DESIGN.md`](DESIGN.md). It is **safe by default**: it does not mutate `/usf`,
does not mutate Stardog, does not spend money, and does not send private source
to external providers unless explicitly authorized.

---

## Status

Implements Build Stages 1–5 of the roadmap in `DESIGN.md` as a coherent,
replayable deterministic control plane, plus the interfaces and safe scaffolding
for stages 6–10 (concurrency, integration, review, adaptive routing, controlled
publication). See [`docs/architecture.md`](docs/architecture.md) for exactly
what is *current reality* vs *target behavior*, and `BUILD_REPORT.md` for the
build outcome.

**Not** autonomous-production-ready. Autonomous mutation is disabled.

---

## Safety posture (defaults)

| Action | Default |
| --- | --- |
| Provider discovery, model listing, auth probes | enabled |
| Zero-token / metadata-only probes | enabled |
| Billable inference | **disabled** (`--allow-billable` + `--budget-usd`) |
| Source-code egress to external providers | **disabled** (`--allow-source-egress`) |
| Writes to `/usf` | **never** |
| Stardog publication | **disabled** (interface only) |
| `run --mode observe` / `plan-only` | enabled |
| `run --mode autonomous-safe` | implemented, **disabled** until configured |

The factory reads USF state only via the **read-only USF MCP boundary** and
never treats repository graph files as semantic authority.

---

## Install

```bash
cd /root/usf-factory
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # or: pip install -r requirements.lock
```

Requires Python 3.11+ and the `git` CLI. Node is required only for the USF MCP
server (already present in the USF environment).

## First commands

```bash
usf-factory doctor                 # environment + config + isolation self-check
usf-factory env status             # credential presence by NAME only (no values)
usf-factory providers status       # configured providers and enablement
usf-factory usf health             # read-only USF MCP liveness
usf-factory cycle snapshot         # deterministic semantic snapshot (read-only)
usf-factory cycle plan             # plan-only obligation graph + packets (mock/fixture)
usf-factory run --mode plan-only   # a full non-mutating cycle
```

## Credential import

Credentials live in `/root/.env` (root-owned, mode 0600) — never in the repo.

```bash
python scripts/import-provider-env.py --dry-run      # names only, no values
python scripts/import-provider-env.py --from-process # import from current env
env -0 | python scripts/import-provider-env.py --stdin0   # from an outer shell
python scripts/check-provider-env.py                 # verify presence by name
```

See [`docs/credential-import.md`](docs/credential-import.md) for the alias table,
precedence, and conflict handling.

---

## Architecture at a glance

```
Provider discovery ─► Model registry ─► Qualification ─┐
                                                       ▼
USF MCP ─► Semantic snapshot ─► Planner ─► Critic ─► Deterministic packet
(read-only)   (deterministic)                          compiler + conflict DAG
                                                       │
                                          Scheduler (task-specific, explainable)
                                                       │
                                    Isolated workers (disposable clones, no /usf)
                                                       │
                          Result qualification ─► Deterministic pre-integration
                                                       │
                               AI integrator (only for semantic reconciliation)
                                                       │
                                Independent review ─► Deterministic validation
                                                       │
                              Attribution + learning ─► recompute state ─► repeat
```

Four planes: **control** (deterministic), **intelligence** (planner/workers/
integrator/reviewers), **execution** (clones/tools/tests), **assurance**
(SHACL/SPARQL/tests/evidence/proof/publication).

## Repository layout

```
usf-factory/
├── DESIGN.md                 authoritative architecture (verbatim)
├── config/                   providers, routing, trust, egress, tasks, budgets, qual suite
├── schemas/                  JSON Schemas for packets, results, obligation graph, snapshot
├── src/usf_factory/          the deterministic control plane + adapters
├── qualifications/           versioned USF qualification corpus (+ hidden holdout)
├── tests/                    unit, contract, adversarial, e2e (non-mutating)
├── scripts/                  credential import/check
├── systemd/                  service units for continuous safe operation
└── docs/                     architecture, security, adapters, boundaries, guides
```

## Operational state (outside the repo)

```
/root/.local/share/usf-factory/mirrors/usf.git   factory-owned bare mirror of /usf
/root/.local/share/usf-factory/workspaces/        disposable per-packet clones
/root/.local/share/usf-factory/integration/       centralized integration clone
/root/.local/state/usf-factory/                    SQLite WAL state + event log
/root/.cache/usf-factory/                          content-addressed artifacts
/root/.config/usf-factory/                         local overrides
```

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — implementation map, planes, phases
- [`docs/security.md`](docs/security.md) — isolation, secrets, egress, sandboxing
- [`docs/usf-authority-boundary.md`](docs/usf-authority-boundary.md) — the MCP boundary
- [`docs/provider-adapters.md`](docs/provider-adapters.md) — adapter model
- [`docs/model-qualification.md`](docs/model-qualification.md) — probes, roles, scoring
- [`docs/packet-lifecycle.md`](docs/packet-lifecycle.md) — snapshot → packet → result
- [`docs/integration-and-attribution.md`](docs/integration-and-attribution.md)
- [`docs/operator-guide.md`](docs/operator-guide.md) / [`docs/recovery.md`](docs/recovery.md)
- [`docs/credential-import.md`](docs/credential-import.md)

## License

See [`LICENSE-NOTICE.md`](LICENSE-NOTICE.md). Internal operational tool; all
rights reserved by default.
