# Packet lifecycle

From live authority to a qualified, attributed result — deterministically.

## 1. Snapshot (immutable)

`compile_snapshot` produces a content-addressed `SemanticSnapshot` from the
read-only MCP boundary + git. Everything downstream is bound to its
`snapshot_id`, `authority_digest`, and `repository_head`.

## 2. Obligation graph (planner + critic)

The planner receives a **compact projection** (no provider names) and returns an
`ObligationGraph`. Each `Obligation` has: id, root cause, semantic subjects,
dependencies, required outcomes, acceptance criteria, risk, task class, suggested
read/write scope, uncertainties, and a `human_decision_required` flag.

A `DeterministicCritic` (different provider where AI is used) checks for missing
dependencies, duplicates, over/under-fragmentation, hidden shared subjects, and
human decisions mislabeled as implementation work. It can amend (dedup) but never
executes work. The **compiler**, not the planner, decides executable packets.

## 3. Packet compilation (deterministic)

`compile_packets` binds each obligation to a content-addressed `Packet`:

```
obligation_id  snapshot_id  authority_digest  base_head
objective  task_class  risk
semantic_subjects  read_paths  write_paths  generated_outputs
input_digests (frozen from the mirror at base_head)
dependencies  conflicts_with
required_capabilities  acceptance_criteria  required_validation
permitted_tools  data_classification  human_decision_required
```

Oversized packets (beyond task-class `max_files` / `max_semantic_subjects`) are
excluded from selection and reported as compiler findings.

## 4. Conflict graph & antichain

`conflict_graph` classifies every packet pair:

```
DISJOINT  READ_OVERLAP  GENERATED_OUTPUT_OVERLAP  WRITE_OVERLAP
SEMANTIC_OVERLAP  AUTHORITY_DEPENDENT  HUMAN_DECISION_REQUIRED
```

`select_antichain` picks the **first eligible antichain**: dependency-ready,
mutually safe packets. It uses deterministic min-conflict-degree greedy ordering,
so the wave is reproducible and tends toward maximal size. The packet set is
**frozen** before execution; later waves are never pre-planned.

## 5. Scheduling (task-specific, explainable)

For each selected packet the scheduler applies hard eligibility (role, tools,
context, egress, health, quota, circuit breaker, task-class scores, risk) then
ranks survivors. Selection uses seeded exploration (85/10/5), disabled for
high/protected risk. Every decision is a stored `RoutingDecision` — see
`usf-factory routing explain <packet-id>`.

## 6. Execution (isolated)

Each packet runs in a **disposable clone** from the mirror (never `/usf`),
claimed via the single claim authority (idempotent; blocks double dispatch).
Workers get stable instructions + packet JSON + relevant ranges + permitted tools
+ result schema — never a transcript. In the safe runtime the `DryRunWorker`
produces a non-mutating result. An `AiWorker` (gated) enforces the sandbox on any
produced patch.

## 7. Result qualification (deterministic)

`qualify_result` checks: identity present, snapshot/base-commit match, staleness,
path scope, no `/usf` writes, semantic-subject scope, secret leakage, patch
applicability, and uncertain-mutation (never auto-retried). Failures are
**classified** (`FailureClass`) for fair attribution:

```
PLANNER_ERROR  PACKET_COMPILER_ERROR  WORKER_ERROR  ADAPTER_ERROR
PROVIDER_OUTAGE  QUOTA_BLOCKED  STALE_PACKET  SCOPE_VIOLATION
VALIDATION_FAILURE  ENVIRONMENT_FAILURE  UNCERTAIN_MUTATION
```

## 8. Onward

Accepted results flow to deterministic pre-integration, advisory review,
deterministic validation, and learning — see
[`integration-and-attribution.md`](integration-and-attribution.md). After an
integrated state change, the packet set is discarded and the cycle re-snapshots.
