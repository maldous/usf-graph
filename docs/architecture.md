# Architecture

This document maps the architecture in [`DESIGN.md`](../DESIGN.md) to the
implementation, and separates **current reality** from **target behavior**.

## Four planes

| Plane | Responsibility | Modules |
| --- | --- | --- |
| **Control** (deterministic) | state machine, claims/leases, scheduling, freshness, recovery, event log | `state_machine`, `event_store`, `scheduler`, `engine` |
| **Intelligence** (AI, replaceable) | planner, critic, workers, integrator, reviewers | `planner`, `workers`, `integration`, `review` |
| **Execution** | disposable clones, tools, patches, tests | `isolation`, `sandbox`, `workers` |
| **Assurance** | SHACL/SPARQL/tests, evidence, proof, publication | `validation`, `authority` |

The **deterministic control plane owns the loop**; models are workers. AI never
owns leases, claims, freshness, merge order, quotas, publication, or terminal
completion.

## Module map

```
src/usf_factory/
├── canonical.py        content addressing (sha256 over canonical JSON)
├── clock.py            time source (metadata only; never in identity)
├── secrets.py          credential allowlist / aliases / conflicts / redaction
├── config.py           YAML config loading + validation
├── enums.py            controlled vocabularies
├── models.py           durable Pydantic records (DESIGN §4)
├── event_store.py      SQLite WAL + append-only events + claims + CAS
├── context.py          RuntimeContext (DI hub) + protected-action gates
├── paths.py            XDG-style locations, /usf + MCP command
├── errors.py           typed exception hierarchy
├── providers/          adapters (openai_compatible, ollama, codex/claude CLI) + registry
├── model_registry.py   normalize discovered models; agent-profile identity
├── probes.py           10 mechanical probes + deterministic grading
├── qualification.py    USF qualification suite, scoring, admission roles
├── authority.py        read-only USF MCP STDIO JSON-RPC client
├── snapshots.py        deterministic semantic snapshot compiler
├── planner.py          fixture/AI planner + deterministic critic
├── packet_compiler.py  deterministic packet compilation
├── conflict_graph.py   conflict classes + antichain selection
├── scheduler.py        eligibility + ranking + seeded exploration + explanations
├── isolation.py        /usf mirror + disposable clones (never touches /usf)
├── workers.py          worker adapters + sandbox enforcement
├── result_validation.py deterministic result qualification + failure taxonomy
├── attribution.py      stage attribution + integrator rewrite ratio
├── integration.py      deterministic pre-integration + semantic conflict + AI integrator
├── review.py           independent wave review (advisory)
├── validation.py       validation gates + publication state machine (gated)
├── learning.py         stage-specific metrics (EWMA, CI, min-sample)
├── engine.py           the cycle orchestrator
├── doctor.py           self-check
└── cli.py              Typer + Rich CLI
```

## The operating cycle (engine.run_cycle)

```
Phase 0  preflight/recovery   engine.preflight       ensure mirror, detect incomplete cycle, no /usf worktrees
Phase 1-4 snapshot            engine.capture_snapshot compile_snapshot() via read-only MCP + git
Phase 5  plan + critic        engine.plan_and_compile FixturePlanner (default) + DeterministicCritic
Phase 6  packet compile       compile_packets        deterministic packets + conflict DAG + antichain
Phase 8  schedule             engine.schedule_packets eligibility + ranking + explanation (RoutingDecision)
Phase 9  execute (isolated)   engine.execute_packets  DryRunWorker in the safe runtime (no mutation)
Phase 10 result qualify       engine.qualify_results  deterministic checks + failure taxonomy
Phase 11 pre-integrate        deterministic_preintegrate  semantic conflict check; AI integrator only if needed
Phase 12 review               NoopReviewer / AiReviewer   advisory only
Phase 13 validate             run_validation          deterministic gates; publication gated + disabled
Phase 14 learn                LearningEngine          stage-specific scores (skips non-worker faults)
Phase 15 re-snapshot          next cycle              packet set discarded; recompute from current state
```

Each wave is a **disposable antichain**; there is no pre-planned "Wave 2".

## Determinism & replay

- Content addressing (`canonical.content_digest`) over canonical JSON gives every
  durable artifact a stable id independent of wall-clock/locale/order.
- Snapshots, obligation graphs, packets, and packet sets reproduce identical ids
  for identical inputs (verified in `tests/test_e2e.py::test_cycle_is_deterministic`).
- Exploration uses a **seeded** RNG derived from `(seed, snapshot_id, packet_id)`
  — routing replays identically.
- Phase transitions and side-effect boundaries are recorded in the append-only
  event log (strict per-transition CAS + fencing tokens are a target; see
  `docs/known-limitations.md`).

## Current reality vs target

**Current reality (implemented and tested):**
- Deterministic control plane, event log, SQLite WAL state, CAS.
- Provider registry (17 providers + anthropic-api stub; Codebuff excluded), enablement gating, metadata-only discovery.
- Read-only USF MCP client + deterministic snapshot compiler (works against the live server).
- Mechanical probes + USF qualification suite + admission roles.
- Fixture planner + critic + deterministic packet compiler + conflict DAG + antichain.
- Task-specific, explainable scheduler with seeded exploration.
- Git mirror isolation + disposable clones; sandbox enforcement.
- Result qualification + failure taxonomy; deterministic pre-integration + semantic conflict detection; advisory review; validation gate runner; learning with CI.
- Full **non-mutating** cycle (observe / plan-only).

**Target behavior (interfaces present, gated/disabled):**
- Billable model probing/qualification (`--allow-billable`, `--budget-usd`).
- AI worker/integrator/reviewer execution (billable + egress gated).
- Concurrency beyond the default of 2 workers.
- Controlled Stardog publication (`PublicationStateMachine`, disabled).
- `autonomous-safe` mutating execution (disabled by config).

See `BUILD_REPORT.md` for the exact status and next commands.
