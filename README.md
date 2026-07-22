# USF Adaptive Semantic Factory

A model-agnostic orchestration engine with a **deterministic integrity and
control plane** that advances Universal Service Foundation (USF) semantic work
by treating AI providers and models as replaceable, qualified workers. Runtime
invocation timing and concurrency deliberately adapt to observed conditions;
their decisions and outcomes are auditable rather than timing-replayable.

The deterministic control plane owns the loop. Models are workers. The objective
is not to maximize model calls — it is to maximize:

```
accepted semantic obligations closed
────────────────────────────────────
wall-clock time × cost × regression risk
```

This is a traditional build-first implementation of the architecture in
[`DESIGN.md`](DESIGN.md). It is an operational coordinator, not a second semantic
authority. It is **safe by default**: it does not mutate `/usf`, does not mutate
Stardog, does not spend money, and does not send private source to external
providers unless explicitly authorized.

---

## Status: not ready to run protected delivery

The branch contains a substantial implementation of dynamic worker discovery,
qualification and admission; deterministic planning and packet compilation;
isolated execution; integration and review; local validation; and a protected,
restartable GitHub/Stardog delivery coordinator. It remains a work in progress
until the full attestation and cross-repository scenarios pass against the
current `usf-graph` contract. See [`docs/architecture.md`](docs/architecture.md)
for *current reality* vs target behavior, and `BUILD_REPORT.md` for the original
build outcome.

**RUNTIME_READINESS: NOT_READY_TO_RUN.** Protected mutation remains disabled by
default. Ordinary `gh pr merge` cannot prove a base-pinned prospective merge
result, and this host cannot provide the required publication filesystem/network
containment. Both conditions fail closed. Read-only planning and isolated local
execution remain usable; a code path, passing local test or factory receipt is
never authority evidence or a readiness verdict.

**ADAPTIVE_NONDETERMINISTIC_EXECUTION: VERIFIED_LOCALLY.** Packet execution has
no configured worker-count target or model/provider slot limit. It begins at one
active invocation after every coordinator restart and continuously discovers
useful load from accepted and validated result throughput, response degradation,
host pressure and downstream backlog. See
[`docs/adaptive-execution.md`](docs/adaptive-execution.md). This does not waive
either protected-delivery blocker.

## Relationship with `usf-graph`

`usf-factory` and `usf-graph` have deliberately different roles:

- **`usf-graph`** owns validated semantic authority, contracts, evidence
  admission, proof and canonical transactional publication.
- **`usf-factory`** is the build-first execution system that reads bounded live
  authority, schedules qualified workers, validates candidate changes in
  disposable clones, and coordinates protected Git and publication operations.

The factory consumes actionable gaps from `usf_work_plan`. Contract-level proof
and validation obligation inventories provide context; they do not become work
merely because they are listed. A deferred or inactive validation obligation is
therefore visible to contract projection but absent from the actionable work
plan until explicitly activated.

### Validation receipt versus authority evidence

A factory-run deterministic suite produces a
`FactoryValidationReceipt`. That receipt records the exact repository head,
authority digest, checks and observed result for replay and diagnosis. It is
not `usf:ValidationEvidence`, is not admitted, and cannot close a semantic
validation obligation.

Genuine authority-evidence candidates must be produced independently and enter
the factory through the explicit `AuthorityEvidenceTransport` interface. The
interface verifies the exact patch digest, evidence identities, immutable
artifact digests and the actual content-addressed producer/reviewer receipt
bytes before the protected delivery lifecycle can begin. A claimed receipt
digest without locally verified bytes is rejected. Admission still requires
the canonical `usf-graph` tests, validate-and-rollback,
transactional publication, zero source/live drift and post-publication work-plan
reconciliation. The factory never upgrades its own receipt into authority
evidence.

---

## Safety posture (defaults)

| Action | Default |
| --- | --- |
| Provider discovery, model listing, auth probes | enabled |
| Zero-token / metadata-only probes | enabled |
| Billable inference | **disabled** (`--allow-billable` + `--budget-usd`) |
| Source-code egress to external providers | **disabled** (`--allow-source-egress`) |
| Writes to `/usf` | **never** |
| Stardog publication | **disabled** (implemented protected interface) |
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
scripts/verify.sh --attest         # full clean-HEAD local attestation
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
USF MCP ─► Semantic snapshot ─► Work-plan projection ─► Deterministic packet
(read-only)   (deterministic)                             compiler + conflict DAG
                                                       │
             Qualified dynamic workforce + adaptive routing/admission
                                                       │
                                    Isolated workers (disposable clones, no /usf)
                                                       │
                          Result qualification ─► Deterministic pre-integration
                                                       │
                       Semantic conflict ─► explicit operator-required block
                                                       │
                     Provider-diverse review ─► Deterministic local validation
                                                       │
                      Protected graph delivery ─► reconcile authority/work plan
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
