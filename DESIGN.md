# USF Adaptive Semantic Factory — final design proposal

## Executive decision

Build a **separate deterministic orchestration application** that treats AI providers and models as replaceable workers.

The system should not be an AI agent that happens to call other agents. It should be a workflow engine with:

```text
Deterministic control plane
+ current USF semantic authority
+ qualified multi-provider agent pool
+ isolated packet execution
+ centralized integration
+ evidence-based learning
```

The objective is not to maximize the number of model calls. It is to maximize:

```text
accepted semantic obligations closed
────────────────────────────────────
wall-clock time × cost × regression risk
```

The existing USF assurance discipline is the correct foundation: model, evidence, proof, contract, realization and validation are distinct, and publication is digest-bound and fail-closed.  The orchestrator must preserve that discipline rather than creating a parallel, less-governed truth system.

ANQR provides useful implementation lessons: its harness is treated as a first-class system separate from the product, with one governor, bounded executors, strict evidence, rollback expectations and human gates.  Its own review also found that the primary weakness was control-plane correctness rather than model quality, and that safe operation requires one ownership authority and serialized merge-back.

The final design should reuse those lessons, but not copy ANQR’s Linear-centric control plane wholesale.

---

# 1. Core architectural principles

## 1.1 Current authority always wins

The previous USF audits are valuable as:

* benchmark cases;
* task-class definitions;
* regression fixtures;
* examples of semantic failure modes;
* candidate workstream ordering.

They must not become a static backlog. Many findings have since been addressed.

Every cycle begins from:

```text
Live USF authority digest
Current repository HEAD and working state
Current programme checkpoint
Current ledger
Current GOAL and governing instructions
Current admitted evidence and proofs
```

The previous audit itself states that validated Stardog state remains authoritative and that concurrent repository candidates cannot be treated as admitted semantic truth. 

## 1.2 The control plane is deterministic

AI may:

* interpret semantic state;
* propose obligations;
* design packets;
* implement bounded changes;
* review patches;
* resolve semantic integration conflicts.

AI must not own:

* leases;
* packet claims;
* freshness decisions;
* worktree allocation;
* provider quota state;
* merge order;
* publication authorization;
* terminal completion decisions;
* audit history.

## 1.3 One claim authority and one integration authority

Only the orchestrator may assign a packet.

Only the integration coordinator may modify the integration branch.

Only the authorized USF publication process may mutate Stardog.

This directly avoids ANQR’s historical duplicate-dispatch, split-authority and recovery-mutation failures.

## 1.4 A “model” is not an agent identity

Suitability attaches to this complete tuple:

```text
provider
+ model
+ adapter
+ authentication mode
+ tool profile
+ system prompt version
+ context settings
+ output schema
```

North through raw Ollama, North through Codex and North through OpenCode behaved as materially different agents. The registry must model them separately.

## 1.5 A wave is disposable

There is no predetermined Wave 2.

```text
capture current state
→ determine current packets
→ execute current packets
→ integrate
→ recalculate current state
→ determine new packets
```

Each wave is a temporary antichain from the current dependency graph. Once integration changes the repository or semantic authority, the next packet set must be recalculated.

## 1.6 Workers never publish

The production audit recommended a coordinator for semantic mutation and read-only workers. 

Workers may produce:

* patches;
* tests;
* fixtures;
* SPARQL or SHACL candidates;
* analysis;
* evidence candidates;
* newly discovered obligations.

They do not:

* update the main branch;
* push or merge;
* mutate Stardog;
* mark readiness;
* accept evidence;
* declare a phase complete.

---

# 2. Top-level architecture

```text
┌───────────────────────────────────────────────────────────┐
│                    USF SEMANTIC FACTORY                   │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  Provider Discovery ──► Model Registry ──► Qualification │
│                                │                          │
│                                ▼                          │
│                         Agent Scheduler                   │
│                                ▲                          │
│                                │                          │
│  USF MCP ──► Semantic State Compiler ──► Planner         │
│  Git      ──► Snapshot Builder           Planner Critic   │
│  Ledger  ──►                            │                 │
│                                          ▼                 │
│                               Deterministic Packet         │
│                               Compiler + Conflict DAG      │
│                                          │                 │
│                                          ▼                 │
│                  ┌──────── Worker Pool ──────────┐         │
│                  │ worktree A  worktree B ...   │         │
│                  └──────────────┬───────────────┘         │
│                                 ▼                          │
│                       Result Qualification                 │
│                                 ▼                          │
│                    Deterministic Pre-Integration           │
│                                 ▼                          │
│                        AI Wave Integrator                  │
│                                 ▼                          │
│                   Independent Wave Reviewer(s)             │
│                                 ▼                          │
│                  Full Validation / Proof / Publication     │
│                                 ▼                          │
│                    Attribution and Learning Engine         │
│                                 │                          │
│                                 └──────────► next cycle     │
└───────────────────────────────────────────────────────────┘
```

The system has four distinct planes:

| Plane              | Responsibility                                                 |
| ------------------ | -------------------------------------------------------------- |
| Control plane      | State machine, claims, leases, scheduling, freshness, recovery |
| Intelligence plane | Planner, workers, integrator, reviewers                        |
| Execution plane    | Worktrees, tools, commands, tests, patches                     |
| Assurance plane    | SHACL, SPARQL, tests, evidence, proof, publication             |

---

# 3. The complete operating cycle

## Phase 0 — Recovery, locking and preflight

**Owner:** deterministic orchestrator.

Before any planning:

* acquire the sole repository orchestration lease;
* detect incomplete prior cycles;
* inspect repository HEAD, worktrees and active processes;
* detect uncertain mutations;
* reconcile packet and integration state;
* verify USF MCP health;
* verify credentials without exposing values;
* verify disk, memory and concurrency capacity.

Output:

```json
{
  "cycleState": "READY",
  "recoveredFrom": null,
  "repositoryHead": "...",
  "authorityDigest": "...",
  "uncertainMutation": false
}
```

A prior uncertain mutation results in `BLOCKED`, not automatic retry.

---

## Phase 1 — Provider discovery and freshness

**Owner:** deterministic provider manager.

Initial configured pool:

```text
OpenAI Codex
Anthropic Claude
OpenRouter
Groq
Mistral
Google Gemini
SambaNova
GitHub Models
Hugging Face
Fireworks
Together
DeepSeek
Ollama
Grok and additional providers when supplied
```

ANQR already contains adapters or registry concepts for most of these providers, including dynamically populated OpenRouter models and a fallback to `openrouter/free`.

Each provider record contains:

```yaml
provider_id: openrouter
auth_mode: api_token
credential_reference: env:OPENROUTER_TOKEN
discovery_adapter: openrouter_catalog
catalog_ttl: 6h
health_ttl: 5m
quota_ttl: 2m
privacy_profile: external_cloud
enabled: true
```

OIDC providers such as Codex and Claude use configured CLI profiles plus active probes rather than assuming an API catalogue is available.

Discovery output is a content-addressed catalogue snapshot. A provider catalogue may refresh during a cycle, but the active cycle remains pinned to its starting snapshot.

---

## Phase 2 — Model discovery and normalization

**Owner:** deterministic model registry.

Every discovered model becomes a normalized record:

```yaml
provider_id: openrouter
requested_model_id: qwen/example:free
canonical_model_family: qwen-example
actual_model_id: null

declared:
  context_tokens: 131072
  output_tokens: 8192
  tools: true
  structured_output: true
  reasoning: true
  vision: false

commercial:
  free: true
  prompt_cost: 0
  output_cost: 0

provenance:
  catalog_digest: sha256:...
  discovered_at: ...
  expires_at: ...
```

Provider metadata is only a claim. It does not qualify the model for USF work.

For routed services such as `openrouter/free`, every response must record the **actual model selected**, not only the requested router.

---

## Phase 3 — Capability probes and USF qualification

**Owner:** qualification engine with deterministic scoring.

### Mechanical probes

Before expensive qualification:

1. Basic response
2. Strict JSON schema
3. Forced single tool call
4. Tool-result consumption
5. Multi-tool sequence
6. Prohibited-tool compliance
7. Exact IRI and digest preservation
8. Patch generation
9. Stop-condition compliance
10. Uncertainty rather than fabrication

### USF semantic qualification

Versioned tests should include:

* distinguish a capability from its realization;
* distinguish compiler proof from capability proof;
* identify an invalid state transition;
* reason about OWL open-world and SHACL closed-world requirements;
* correct domain/range intersection mistakes;
* generate bounded SPARQL;
* repair a SHACL constraint;
* preserve semantic authority and graph ownership;
* avoid readiness overclaim;
* detect stale evidence or mismatched authority digest;
* produce a bounded repository patch;
* preserve concurrent work.

The previous USF findings provide an excellent historical benchmark corpus, including proof-blocked capability breadth, synthetic lifecycle transitions, ambiguous realization selection and missing executable-action semantics. 

### Admission roles

```text
UNQUALIFIED
READ_ONLY_ANALYST
PLANNER_CANDIDATE
PATCH_PRODUCER
REVIEWER
INTEGRATOR
ADJUDICATOR
TRUSTED_COORDINATOR
```

No newly discovered free model begins with write access.

---

## Phase 4 — Semantic state compilation

**Owner:** deterministic state compiler.

This is a deliberate correction to the earlier idea that an AI model should “compile the bootstrap.”

The orchestrator itself should call:

```text
usf_health
usf_bootstrap
bounded usf_query operations
Git status and repository inspection
checkpoint and ledger readers
```

It then produces a compact immutable `SemanticSnapshot`.

```json
{
  "snapshotId": "snap-...",
  "authorityDigest": "sha256:...",
  "repositoryHead": "...",
  "workingTreeDigest": "...",
  "checkpointDigest": "...",
  "ledgerDigest": "...",
  "goalDigest": "...",
  "activePhase": "...",
  "unresolvedObligations": [],
  "admittedEvidence": [],
  "openTransactions": [],
  "capturedAt": "..."
}
```

This avoids:

* tool-selection failures;
* different models interpreting an empty resources list differently;
* repeated large bootstrap transcripts;
* authority facts depending on model output.

AI receives a compact projection, not ownership of the facts.

---

## Phase 5 — Semantic planning

**Owner:** selected planning model plus independent planning critic.

The planner is selected using its `semantic_planning` ranking. It receives:

* the immutable snapshot;
* current GOAL;
* governing constraints;
* unresolved obligation summaries;
* relevant semantic identifiers;
* historical remediation patterns.

It does **not** receive:

* provider names;
* provider rankings;
* worker availability;
* commercial preferences.

That prevents the planner from tailoring packets to favored agents.

The planner returns an **obligation graph**, not final packets:

```json
{
  "obligations": [
    {
      "id": "obl-...",
      "rootCause": "...",
      "semanticSubjects": [],
      "dependencies": [],
      "requiredOutcomes": [],
      "acceptanceCriteria": [],
      "risk": "medium",
      "suggestedTaskClass": "shacl-repair"
    }
  ]
}
```

A second model from a different provider reviews:

* missing dependencies;
* over-fragmentation;
* under-fragmentation;
* duplicate root causes;
* unsupported assumptions;
* opportunities for one foundational correction to close many obligations.

The critic can reject or amend the graph, but not execute work.

---

## Phase 6 — Deterministic packet compilation

**Owner:** packet compiler.

The compiler:

1. groups findings by root remediation;
2. resolves explicit dependencies;
3. maps semantic subjects to files and generated outputs;
4. calculates read and write scopes;
5. identifies conflicts;
6. sets required skills;
7. binds acceptance tests;
8. freezes input digests;
9. creates content-addressed packets.

Packet schema:

```json
{
  "packetId": "pkt-...",
  "snapshotId": "snap-...",
  "authorityDigest": "sha256:...",
  "baseHead": "...",

  "objective": "...",
  "taskClass": "ontology-lifecycle-repair",
  "risk": "medium",

  "semanticSubjects": [],
  "readPaths": [],
  "writePaths": [],
  "generatedOutputs": [],

  "dependencies": [],
  "conflictsWith": [],

  "requiredCapabilities": {
    "semanticReasoning": 0.85,
    "rdfOwl": 0.85,
    "structuredOutput": 0.95,
    "repositoryEditing": true
  },

  "acceptanceCriteria": [],
  "requiredValidation": [],
  "permittedTools": [],
  "dataClassification": "private-source"
}
```

### Wave selection

The wave is the first eligible **antichain** of the obligation DAG.

Packets may run together only when they have:

* no dependency relationship;
* no overlapping authored write paths;
* no overlapping semantic subjects;
* no shared mutable generated output;
* no shared publication transaction;
* no hidden shared global invariant known to the compiler.

The packet set is frozen before execution.

---

## Phase 7 — Pre-wave summary and approval policy

**Owner:** deterministic summarizer.

Before dispatch:

```text
Cycle 27

Authority: sha256:...
Repository: abc123

Packets selected: 6
Providers eligible: 9
Maximum safe concurrency: 4

Expected authored changes:
- ontology.ttl
- lifecycle shapes
- 3 negative fixtures
- 2 competency queries

Shared outputs deferred to integration:
- derived coverage
- readiness projections
- manifest

Protected actions:
- no Stardog publication
- no push
- no merge
```

Modes:

```text
observe
plan-only
approve-wave
autonomous-safe
```

`autonomous-safe` may execute low- and medium-risk packets. Protected actions still require a gate.

---

## Phase 8 — Scheduling and agent selection

**Owner:** deterministic scheduler.

First apply hard eligibility:

* qualified for role;
* required tools;
* sufficient context;
* allowed data-egress policy;
* current health;
* current quota;
* no circuit breaker;
* risk/trust permitted.

Then rank:

```text
expected success probability
× value of packet
+ diversity bonus
+ exploration bonus
− cost
− expected latency
− quota exhaustion risk
− reliability risk
```

Scores are task- and role-specific.

A strong semantic reviewer is not automatically a strong patch producer. A strong worker is not automatically a strong integrator.

ANQR’s provider ranking already separates base score, preference, recent success, health penalties and cache penalties; that is a useful starting pattern.

### Exploration

Use a controlled exploration budget, for example:

```text
85% exploit best qualified choices
10% choose second-tier qualified candidates
5% evaluate newer qualified candidates
```

Never explore on protected or high-risk publication work.

---

## Phase 9 — Concurrent packet execution

**Owner:** isolated worker runtime.

Each packet receives:

* a fresh worktree;
* the same base commit;
* a minimal tool profile;
* only relevant source ranges;
* bounded USF read tools;
* the packet schema;
* a strict result schema.

Worker types:

| Adapter                             | Typical use                                                                                      |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ |
| Codex CLI/SDK                       | Repository implementation and semantic work                                                      |
| Claude CLI/SDK                      | Planning, difficult reasoning, review, implementation                                            |
| OpenCode/Ollama                     | Local fallback and bounded implementation                                                        |
| Generic OpenAI-compatible tool loop | OpenRouter, Groq, Mistral, SambaNova, Fireworks, Together, DeepSeek, GitHub Models, Hugging Face |
| Gemini adapter                      | Native or compatible tool interface                                                              |
| Future Grok adapter                 | When configured and qualified                                                                    |

Workers cannot access:

* main worktree writes;
* Stardog mutation;
* secrets;
* unrelated home directories;
* arbitrary network access;
* push or merge.

ANQR’s own experience shows why worktree identity must not also act as pool slot, durable owner, repair surface and mutable sandbox.  Here, a worktree is temporary execution storage only.

---

## Phase 10 — Packet result qualification

**Owner:** deterministic result validator.

Every worker returns:

```json
{
  "packetId": "...",
  "status": "COMPLETED",
  "agentProfileId": "...",
  "actualProvider": "...",
  "actualModel": "...",

  "patchDigest": "sha256:...",
  "changedPaths": [],
  "semanticSubjectsChanged": [],
  "testsRun": [],
  "evidenceProduced": [],
  "obligationsClosed": [],
  "obligationsDiscovered": [],
  "uncertainties": [],
  "scopeViolation": false
}
```

The orchestrator verifies:

* snapshot freshness;
* base commit;
* permitted paths;
* patch applicability;
* no secret exposure;
* focused tests;
* claimed semantic subjects;
* no direct authority mutation;
* result schema;
* actual provider/model identity.

Failed packets are classified, not merely marked failed.

```text
WORKER_ERROR
PLANNER_ERROR
STALE_PACKET
PROVIDER_OUTAGE
TOOL_ADAPTER_ERROR
SCOPE_VIOLATION
VALIDATION_FAILURE
ENVIRONMENT_FAILURE
```

This classification is necessary for fair learning.

---

## Phase 11 — Wave amalgamation and integration

**Owner:** deterministic integrator first; AI integrator only where needed.

### Step 1: deterministic merge

Apply compatible patches to a dedicated integration worktree.

If patches merge cleanly and validations pass, no AI is needed.

### Step 2: semantic conflict detection

Check:

* affected IRIs;
* class/property definitions;
* SHACL targets;
* rule dependencies;
* lifecycle ownership;
* capability contracts;
* generated graph effects;
* graph manifest changes.

Git-clean does not imply semantically compatible.

### Step 3: selected AI wave integrator

If reconciliation is required, choose the model with the best current score for:

```text
semantic_wave_integration
cross-packet_reasoning
rdf_owl_reasoning
scope_discipline
regression_avoidance
```

The integrator receives:

* normalized packet results;
* patches;
* semantic deltas;
* conflict report;
* acceptance criteria;
* failing integrated validations.

It does not receive irrelevant worker transcripts.

It produces one **candidate effective wave patch**.

### Step 4: preserve attribution

Record:

* worker patch digest;
* lines and semantic subjects preserved;
* modifications introduced by integrator;
* discarded worker changes;
* reasons for reconciliation.

---

## Phase 12 — Independent wave review and adjudication

**Owner:** reviewer from a different provider.

The reviewer evaluates the complete wave, not only individual packets:

* Did one packet invalidate another?
* Did the integration reopen obligations?
* Were requirements broadened without authority?
* Were completion claims introduced without evidence?
* Were generated artifacts changed directly?
* Did the wave preserve backward compatibility?
* Are new negative tests sufficient?

AI review cannot establish correctness. It identifies risks and missing deterministic checks.

For high-risk waves:

```text
Reviewer A
Reviewer B from another provider
Adjudicator if material disagreement remains
```

Provider diversity reduces correlated failure but is not a substitute for tests.

---

## Phase 13 — Deterministic integrated validation and publication

**Owner:** assurance coordinator.

Run once per wave:

* syntax and parse checks;
* full SHACL;
* integrity SPARQL;
* negative fixtures;
* competency questions;
* relevant unit and integration tests;
* graph manifest checks;
* source/live drift;
* derived graph regeneration;
* proof/readiness recalculation;
* repository status and patch scope.

Only after all gates pass:

```text
candidate wave patch
→ authorized commit
→ optional PR
→ approved merge
→ authorized transactional Stardog publication
→ post-publication digest reconciliation
```

Workers remain read-only with respect to semantic authority, as recommended by the production audit. 

`COMPLETE` is never accepted from model prose. It is computed from current GOAL conditions, admitted evidence, proof and authority state.

---

## Phase 14 — Contribution attribution and adaptive learning

**Owner:** learning engine.

Separate scores for:

* planner;
* planner critic;
* packet compiler policy;
* scheduler;
* implementer;
* integrator;
* reviewer;
* provider adapter.

### Worker metrics

```text
focused-test success
scope adherence
schema validity
patch acceptance
semantic-delta preservation
integrator rewrite ratio
review findings confirmed
later regressions
false completion
valid new obligation discovery
latency
tokens
cost
```

### Planner metrics

```text
packets accepted
packets stale before execution
hidden conflicts
over-fragmentation
under-fragmentation
unnecessary packets
obligations missed
integration difficulty
```

### Integrator metrics

```text
wave validation success
worker changes preserved
new defects introduced
regressions in later cycles
unnecessary rewrites
```

### Reviewer metrics

```text
confirmed findings
false positives
missed regressions
useful validation recommendations
```

Scores should use:

* confidence intervals;
* minimum sample counts;
* recency decay;
* task-class segmentation;
* delayed rewards after later waves.

Do not punish a worker for:

* a stale packet caused by authority drift;
* a provider outage;
* an impossible planner specification;
* an unrelated environment failure.

---

## Phase 15 — Re-snapshot and repeat

After accepted integration:

```text
refresh repository state
refresh authority digest
update checkpoint and ledger
archive cycle receipt
invalidate prior packet set
return to Phase 0
```

There is no automatic “next wave” from the previous plan.

---

# 4. Durable artifacts

The durable system should revolve around these records:

```text
ProviderCatalogueSnapshot
ModelRecord
AgentProfile
QualificationRun
SemanticSnapshot
ObligationGraph
PacketSet
Packet
AgentRun
PacketResult
IntegrationAttempt
WavePatch
WaveReview
ValidationReceipt
PublicationReceipt
CycleReceipt
RoutingDecision
AvailabilityEvent
QuotaEvent
```

The orchestrator state should initially remain outside Stardog.

Recommended storage:

```text
SQLite WAL
+ append-only event table
+ content-addressed artifact directory
+ Git worktrees
```

Only accepted evidence summaries and publication receipts need later projection into USF.

This prevents the orchestrator from increasing USF graph size merely to manage its own internal scheduling.

---

# 5. Recommended package structure

```text
usf-semantic-factory/
├── pyproject.toml
├── config/
│   ├── providers.yaml
│   ├── routing.yaml
│   ├── trust-policy.yaml
│   ├── data-egress-policy.yaml
│   ├── task-classes.yaml
│   └── budgets.yaml
├── src/usf_factory/
│   ├── cli.py
│   ├── engine.py
│   ├── state_machine.py
│   ├── event_store.py
│   ├── authority.py
│   ├── snapshots.py
│   ├── planner.py
│   ├── packet_compiler.py
│   ├── conflict_graph.py
│   ├── scheduler.py
│   ├── worktrees.py
│   ├── integration.py
│   ├── validation.py
│   ├── attribution.py
│   ├── learning.py
│   ├── providers/
│   └── adapters/
├── schemas/
├── qualifications/
├── fixtures/
└── tests/
```

Recommended technology:

```text
Python 3.12+
Typer
Pydantic
asyncio
httpx
SQLAlchemy or sqlite3
SQLite WAL
JSON Schema
Git CLI
Rich/Textual for operator UI
systemd for service operation
```

---

# 6. Adversarial review

| Failure mode                                    | How it could fail                                                       | Required mitigation                                                                   |
| ----------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Orchestrator becomes larger than USF            | Months spent building a factory instead of closing semantic obligations | Deliver in controlled stages; enforce orchestration-overhead budget                   |
| Too many agents reduce throughput               | Coordination, prompts, review and merge exceed implementation time      | Optimize accepted progress/hour; cap concurrency by integration capacity              |
| Provider catalogue becomes stale                | Model removed, renamed or changed after qualification                   | Content-address catalogues, TTLs, actual-model receipts and automatic requalification |
| Routed provider substitutes a model             | Requested model and actual model differ                                 | Record returned model; reject when policy requires a pinned model                     |
| Free-provider quality collapses                 | Availability and behavior vary                                          | Circuit breakers, low initial trust, task-specific qualification and fallback         |
| OIDC session expires unattended                 | Codex or Claude stops mid-cycle                                         | Credential health probe; never launch packet when session freshness is uncertain      |
| Private code leaks to unsuitable providers      | Free providers may retain prompts or have different terms               | Per-packet data classification and provider egress policy                             |
| Prompt injection from repository content        | Malicious source text instructs a model to exfiltrate or bypass policy  | Tool enforcement outside the model; secrets never exposed; network constrained        |
| Planner creates hundreds of tiny packets        | Orchestration overhead dominates                                        | Root-cause consolidation and minimum packet-value threshold                           |
| Planner creates oversized packets               | Worker times out or changes too much                                    | Model-specific packet sizing and deterministic file/subject limits                    |
| Hidden semantic conflict survives path analysis | Separate files redefine the same IRI or invariant                       | Semantic-subject locks, graph/rule dependency analysis and wave validation            |
| Packet goes stale mid-wave                      | Another change alters assumptions                                       | Freeze wave from one base; no external writes; fail closed on drift                   |
| Duplicate execution occurs                      | Retry or crash causes two workers to mutate same obligation             | One claim authority, leases, idempotent run IDs and isolated worktrees                |
| Worktree becomes a durable ownership record     | Cleanup or recovery mutates active work                                 | Worktree is ephemeral only; ownership lives in the state store                        |
| AI reviewers agree but are wrong                | Consensus is mistaken for proof                                         | Deterministic tests and USF evidence dominate reviewer opinions                       |
| Integrator becomes bottleneck                   | Many worker results queue behind one model                              | Deterministic merge first; hierarchical integration only for large waves              |
| Metrics reward shallow completion               | Models optimize packet count or minimal changes                         | Reward accepted, durable obligation closure and delayed non-regression                |
| Model monopoly emerges                          | Early winner gets all traffic and all future evidence                   | Controlled exploration and provider-diversity constraints                             |
| Wrong component is blamed                       | Worker penalized for bad planning or environment failure                | Stage-specific failure taxonomy and causal attribution                                |
| Self-improvement corrupts safety policy         | Learning engine weakens gates to improve throughput                     | Auto-adjust scores/routing only; policy or code changes require reviewed PRs          |
| Factory loops without progress                  | Same packet or next action repeats forever                              | Progress tuples, no-progress thresholds and cycle-level blocker                       |
| False programme completion                      | Model declares success after local tests                                | Terminal state computed only from GOAL, authority, proof and readiness                |
| Publication corrupts live authority             | Parallel worker writes or uncertain transaction                         | Single coordinator, transactional publication and post-commit reconciliation          |
| Orchestrator crash loses state                  | In-memory queue disappears or packets execute twice                     | Durable event log, state transition persistence and lease recovery                    |
| Human decisions are fabricated                  | Model invents architecture, legal or risk acceptance                    | Explicit `HUMAN_DECISION_REQUIRED` packet status                                      |
| Benchmark overfitting                           | Models learn visible qualification cases                                | Public regression set plus hidden holdout set and periodic rotation                   |
| Provider costs spiral                           | Free route fails and silently escalates to paid                         | Hard budgets by provider, cycle, role and packet                                      |
| Integration hides poor worker quality           | Integrator rewrites everything and workers still score well             | Preserve original patches; measure rewrite and semantic contribution ratios           |
| USF graph size grows from factory telemetry     | Every agent event becomes RDF                                           | Keep operational state external; publish only accepted evidence receipts              |

ANQR’s live experience validates several of these concerns: it documented at-least-once rather than effectively-once execution, ancillary services influencing ownership, and overloaded worktree identity.

---

# 7. Self-improvement boundaries

## Automatically adaptable

The factory may automatically adjust:

* provider health and availability;
* quota cooldown;
* model ranking;
* packet-size preference by model;
* task-to-model routing;
* context and output budgets;
* concurrency limits;
* exploration percentage;
* timeout estimates;
* circuit breakers.

## Not automatically self-modifiable

The factory must not autonomously change:

* safety policy;
* protected-action gates;
* data-egress rules;
* credential access;
* Stardog publication policy;
* semantic authority rules;
* trust-tier definitions;
* its own source code on the running branch.

It may propose a PR to improve itself. That PR is reviewed like any other change.

This is adaptation, not uncontrolled recursive self-modification.

---

# 8. Implementation roadmap

## Build Stage 1 — Deterministic foundation

Deliver:

* Python package;
* SQLite event/state store;
* CLI;
* provider config;
* semantic snapshot compiler;
* packet and result schemas;
* worktree manager;
* dry-run mode;
* no AI execution yet.

Exit criterion:

```text
State capture and replay are deterministic.
```

## Build Stage 2 — Provider and model registry

Deliver:

* provider adapters;
* auth health;
* model discovery;
* catalogue freshness;
* capability probes;
* actual-model receipts;
* provider circuit breakers.

Exit criterion:

```text
Every available provider/model/adapter has a reproducible health and capability record.
```

## Build Stage 3 — Qualification system

Deliver:

* USF benchmark suite;
* task taxonomy;
* admission tiers;
* per-role scores;
* holdout tests;
* qualification CLI.

Exit criterion:

```text
The system can explain why a model is or is not eligible for a task.
```

## Build Stage 4 — Read-only planning

Deliver:

* planner adapter;
* planner critic;
* obligation graph;
* root-cause consolidation;
* packet compiler;
* conflict graph;
* plan summaries.

No writes.

Exit criterion:

```text
Repeated planning against the same snapshot produces valid, bounded, reviewable packet sets.
```

## Build Stage 5 — Sequential packet execution

Deliver:

* one worker at a time;
* isolated worktree;
* bounded tools;
* structured result;
* focused validation;
* no main merge;
* no Stardog publication.

Exit criterion:

```text
A packet can be executed and independently accepted or rejected without affecting main.
```

## Build Stage 6 — Multi-provider concurrency

Deliver:

* leases;
* parallel workers;
* provider quota limits;
* conflict-safe antichains;
* cancellation and timeout;
* failure isolation.

Exit criterion:

```text
Several non-conflicting packets can execute concurrently without shared-state corruption.
```

## Build Stage 7 — Integration and review

Deliver:

* deterministic patch merger;
* semantic conflict detector;
* selected AI integrator;
* independent reviewer;
* integrated validation;
* wave patch and attribution receipts.

Exit criterion:

```text
A wave produces one explainable, validated candidate patch.
```

## Build Stage 8 — Adaptive routing

Deliver:

* task-class performance;
* stage-specific attribution;
* recency-weighted scores;
* exploration;
* delayed regression metrics;
* routing explanations.

Exit criterion:

```text
Routing improves empirically without weakening trust or safety gates.
```

## Build Stage 9 — Controlled USF publication

Deliver:

* authorized commit/PR path;
* transactional semantic publication;
* digest reconciliation;
* evidence and proof receipts;
* protected human approval.

Exit criterion:

```text
An accepted wave can be published through the existing USF authority process and independently reconciled.
```

## Build Stage 10 — Continuous safe operation

Deliver:

* systemd service;
* pause/resume;
* TUI or local dashboard;
* cycle summaries;
* no-progress handling;
* quota-block handling;
* historical replay;
* backup and recovery.

Exit criterion:

```text
The factory can run continuously and stop safely on uncertainty, exhaustion, human decisions or terminal completion.
```

---

# 9. Operator interface

Recommended commands:

```bash
usf-factory doctor

usf-factory providers refresh
usf-factory providers status

usf-factory models discover
usf-factory models probe
usf-factory models qualify
usf-factory models leaderboard --task semantic-planning

usf-factory cycle snapshot
usf-factory cycle plan
usf-factory cycle show
usf-factory cycle execute
usf-factory cycle integrate
usf-factory cycle review
usf-factory cycle publish

usf-factory run --mode autonomous-safe
usf-factory pause
usf-factory resume
usf-factory status
usf-factory explain-routing <packet-id>
usf-factory replay <cycle-id>
```

An interactive cycle should display:

```text
Current authority and repository
Provider/model availability
Proposed packets
Conflicts and exclusions
Selected agents and reasons
Estimated cost/latency
Execution progress
Integration result
Validation result
Model contribution assessment
Newly determined next state
```

---

# 10. Final recommended design

The final architecture should be:

```text
A separate Python USF Semantic Factory

with

one deterministic state and claim authority
one deterministic semantic snapshot compiler
one AI planner plus independent planning critic
one deterministic packet compiler
a qualified multi-provider worker pool
isolated ephemeral worktrees
one centralized integration path
independent provider-diverse review
deterministic USF assurance and publication
stage-specific evidence and attribution
adaptive routing with controlled exploration
continuous state recalculation after every accepted wave
```

The most important design decisions are:

1. **Do not let AI retrieve or define authority facts.** Compile them deterministically.
2. **Do not use the old reports as a fixed queue.** Recompute obligations from current authority.
3. **Do not expose every model to every task.** Qualify by role and task class.
4. **Do not maximize agents blindly.** Maximize conflict-free accepted progress.
5. **Do not let workers touch main or Stardog.**
6. **Do not treat a Git merge as a semantic merge.**
7. **Do not let AI agreement replace validation.**
8. **Do not reward packet completion.** Reward durable integrated obligation closure.
9. **Do not permit self-improvement to alter safety policy automatically.**
10. **Do not pre-plan future waves.** Recalculate after every integrated state change.

The first practical implementation should stop at **Build Stage 5**: deterministic state, provider/model registry, qualification, planning, packet compilation and one isolated sequential worker. Once that path is demonstrably correct and replayable, concurrency and adaptive routing can be added without reproducing the control-plane failures already observed in ANQR.

