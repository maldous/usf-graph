# Architecture

This document maps the architecture in [`DESIGN.md`](../DESIGN.md) to the
implementation, and separates **current reality** from **target behavior**.

## Four planes

| Plane | Responsibility | Modules |
| --- | --- | --- |
| **Control** (deterministic) | state machine, claims/leases, scheduling, freshness, recovery, event log | `state_machine`, `event_store`, `scheduler`, `engine` |
| **Intelligence** (AI, replaceable) | planner, critic, workers, integrator, reviewers | `planner`, `workers`, `integration`, `review` |
| **Execution** | disposable clones, tools, patches, tests | `isolation`, `sandbox_runtime`, `agent_runtime`, `workers` |
| **Assurance** | local validation receipts, graph-bound evidence transport, protected publication | `validation_runners`, `validation_evidence`, `delivery_coordinator`, `stardog_publication` |

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
├── assurance.py        schema-v2 CAS assurance-bundle verification
├── context.py          RuntimeContext (DI hub) + protected-action gates
├── paths.py            XDG-style locations, /usf + MCP command
├── errors.py           typed exception hierarchy
├── providers/          adapters (openai_compatible, ollama, codex/claude CLI) + registry
├── model_registry.py   normalize discovered models; agent-profile identity
├── probes.py           10 mechanical probes + deterministic grading
├── qualification.py    USF qualification suite, scoring, admission roles
├── authority.py        read-only USF MCP STDIO JSON-RPC client
├── snapshots.py        deterministic semantic snapshot compiler
├── programme_state.py live work-plan projection into deterministic obligations
├── planner.py          optional fixture/AI planner + deterministic critic
├── packet_compiler.py  deterministic packet compilation
├── conflict_graph.py   conflict classes + antichain selection
├── workforce.py        qualified dynamic workforce snapshot
├── adaptive_routing.py eligibility + recorded candidate exploration
├── adaptive_execution.py observed-performance invocation admission and simulation
├── isolation.py        /usf mirror + disposable clones (never touches /usf)
├── workers.py          worker adapters + sandbox enforcement
├── result_validation.py deterministic result qualification + failure taxonomy
├── attribution.py      stage attribution + integrator rewrite ratio
├── integration.py      deterministic pre-integration + semantic conflict detection
├── review.py           independent wave review (advisory)
├── validation_runners.py deterministic local assurance gates
├── validation_evidence.py factory receipts + authority-evidence transport boundary
├── delivery_coordinator.py protected GitHub/graph delivery lifecycle
├── stardog_publication.py exact usf-graph publication command contract
├── learning.py         stage-specific metrics (EWMA, CI, min-sample)
├── engine.py           the cycle orchestrator
├── doctor.py           self-check
└── cli.py              Typer + Rich CLI
```

## The operating cycle (engine.run_cycle)

```
Phase 0  preflight/recovery   engine.preflight       ensure mirror, detect incomplete cycle, no /usf worktrees
Phase 1-4 snapshot            engine.capture_snapshot compile_snapshot() via read-only MCP + git
Phase 5  plan + critic        engine.plan_and_compile ProgrammePlanner + optional optimizer/critic
Phase 6  packet compile       compile_packets        deterministic packets + conflict DAG + antichain
Phase 8  schedule             engine.schedule_packets qualified dynamic workforce + adaptive routing
Phase 9  execute (isolated)   engine.execute_packets  adaptively admitted workers in disposable clones
Phase 10 result qualify       engine.qualify_results  deterministic checks + failure taxonomy
Phase 11 pre-integrate        deterministic_preintegrate  conflict check; unresolved conflict blocks for operator
Phase 12 review               provider-diverse substantive review where required
Phase 13 validate             run_validation          deterministic local gates, fail-closed
Delivery protected lifecycle delivery coordinator    branch/PR/check/merge/validate/publish/reconcile
Phase 14 learn                LearningEngine          stage-specific scores (skips non-worker faults)
Phase 15 re-snapshot          next cycle              packet set discarded; recompute from current state
```

Each wave is a **disposable antichain**; there is no pre-planned "Wave 2".

## Determinism & replay

- Content addressing (`canonical.content_digest`) over canonical JSON gives every
  durable artifact a stable id independent of wall-clock/locale/order.
- Snapshots, obligation graphs, packets, and packet sets reproduce identical ids
  for identical inputs (verified in `tests/test_e2e.py::test_cycle_is_deterministic`).
- Adaptive invocation admission starts at one after restart, measures exact
  outcomes and host conditions, and uses unseeded adjacent probing. Timing and
  chosen load are intentionally not replayed. Its immutable observations,
  decision digests, active-at-admission count, fences and result bindings explain
  each decision. Canonical packet identity, integration order and result
  qualification remain deterministic.
- Phase transitions are persisted as they occur. External delivery effects have
  CAS-bound input and persisted uncertain intent, and are reconciled before any
  retry. Coordinator and packet fencing tokens reject stale owners.
- Protected-delivery transitions use one versioned SQLite compare-and-swap that
  appends the immutable CAS transition, advances the projection and persists an
  effect intent/outcome atomically. Side-effect quotas are authorization-bound
  and remain consumed after later failures.

## Current reality vs target

**Current reality (implemented and tested):**
- Deterministic control plane, event log, SQLite WAL state, CAS.
- Provider registry (17 providers + anthropic-api stub; Codebuff excluded), enablement gating, metadata-only discovery.
- Read-only USF MCP client + deterministic snapshot compiler (works against the live server).
- Mechanical probes + USF qualification suite + admission roles.
- Live work-plan planner, optional optimizer/critic, deterministic packet compiler,
  conflict DAG and antichain.
- Qualified dynamic workforce with task-specific adaptive routing and recorded seeds.
- Runtime-discovered packet parallelism with atomic, coordinator- and
  packet-fenced invocation admission; no configured capacity target.
- Git mirror isolation + disposable clones; sandbox enforcement.
- Result qualification + failure taxonomy; deterministic pre-integration + semantic conflict detection; advisory review; validation gate runner; learning with CI.
- Full non-mutating cycle and a protected delivery coordinator whose mutation
  gates remain disabled by default.

**Not yet demonstrated as release-ready:**
- Billable model probing/qualification (`--allow-billable`, `--budget-usd`).
- an exact GitHub mechanism that can merge only the reviewed, base-pinned,
  tested prospective tree (ordinary `gh pr merge` is rejected);
- a host containment boundary for publication credentials, filesystem and
  outbound network (unavailable in the current chroot);
- clean-clone protected-delivery acceptance against disposable remotes and an
  isolated fixture authority database;
- independent CI/attestation bound to the exact PR head;
- namespace-enforced filesystem/network isolation on a host that supports it;
- `autonomous-safe` live mutation (disabled by committed config and run authorization).

See `BUILD_REPORT.md` for the exact status and next commands.
