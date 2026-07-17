# GOAL.md — Complete Executable USF Suite Delivery Programme

## 1. Purpose

This file directs a long-running, restartable and predominantly unattended programme to deliver a complete, executable, repository-local realisation of the Universal Service Foundation suite.

The programme is not complete when it has only produced semantic contracts, JSON specifications, graph resources, generated packets, reports, reference-kernel demonstrations, adapters that do not execute the required behaviour, or references to code in another repository.

Completion requires a standalone clone of `maldous/usf-graph` to contain all source code, configuration, migrations, seeds, Compose definitions, test assets, proof assets and operational scripts necessary to build and run the complete in-scope suite in development, test and staging modes without access to the original or parent repository.

The required lifecycle remains strictly semantic-first:

```text
Model
  → Evidence
  → Proof
  → Contract
  → Realisation decision
  → Repository-local implementation
  → Environment deployment
  → Validation
  → newly admitted Evidence
  → re-evaluated Proof and Contract state
```

Semantics establish what must be true. Executable repository content must then fulfil it.

## 2. Terminal outcomes

End with exactly one terminal outcome:

```text
USF_INITIAL_SUITE_REALISATION_COMPLETE
USF_INITIAL_SUITE_REALISATION_BLOCKED_IRRECOVERABLY
```

`USF_INITIAL_SUITE_REALISATION_COMPLETE` is permitted only when every completion gate in this file passes for the executable dev/test/staging delivery.

`USF_INITIAL_SUITE_REALISATION_BLOCKED_IRRECOVERABLY` is permitted only when further progress requires an unavailable credential, explicit human or legal acceptance, a paid or irreversible external action not already authorised, inaccessible mandatory external evidence, an unexplained authority conflict, or an infrastructure limit that cannot be removed through an authorised self-healing or authority-migration path.

Routine ambiguity, missing code, missing Compose services, incomplete semantics, test failures, proof failures, stale evidence, missing collectors, Stardog failures, transaction rollback, dependency conflicts, architectural decisions, absent Linear issues, performance defects or incomplete environments are not irrecoverable blockers. Resolve them and continue.

## 3. Prior completion is reopened

Any earlier `USF_INITIAL_SUITE_REALISATION_COMPLETE` verdict predating this directive is not sufficient for this programme.

The previous programme state may be reused only as verified input. Reopen every contract whose claimed realisation is any of:

```text
specification-only
JSON-only
RDF-only
generated-packet-only
reference-kernel-only
placeholder or stub
legacy-source reference
parent-repository reference
external local-path reference
missing implementation path
unexecuted adapter
unverified package or service binding
```

A prior zero-row `usf_work_plan`, completed checkpoint, successful proof, active contract, accepted decision or clean Git state does not prevent reopening when the executable-delivery requirements are not met.

Preserve valid semantic, evidence, proof and implementation work. Do not redo work whose content, authority binding, repository locality and validation remain current.

## 4. Instruction precedence and authority

Read and obey, in this order:

1. Direct user instructions for this run.
2. `AGENTS.md`.
3. `CODEX.md`.
4. The loaded USF skill.
5. This `GOAL.md`.
6. Current digest-bound contract packets and focused live queries.
7. Repository source, tests, ADRs, reports, caches, the original repository and Linear tickets as non-authoritative inputs.

Validated live semantic state remains authoritative for requirements, claims, nonclaims and allowed realisation decisions.

Where prose or existing implementation conflicts with live authority, repair or clarify the semantic model through the authorised lifecycle, then implement against the new validated authority.

Graph source files are registered materialisations used to update authority. Their presence alone does not establish semantic truth or implementation completion.

## 5. Execution mode

Use one repository checkout on `main`.

```text
branch:                 main
new Git worktrees:      prohibited
modifying subagents:    prohibited
repository writer:      top-level coordinator only
semantic-store writer:  top-level coordinator only
read-only subagents:    permitted
intermediate commits:   prohibited
final commit:           only after every completion gate passes
push or pull request:   prohibited unless separately authorised
Git stash:              prohibited
```

Do not reset, clean, discard, overwrite or delete unknown or user-owned work.

Read-only subagents may inspect, query, run isolated tests, attack assumptions and return compact proposed patches. The coordinator applies repository and semantic changes sequentially.

Temporary clean-room copies may be created under `/tmp`. They must not be Git worktrees and must not depend on untracked source from the primary checkout.

## 6. Unattended-operation rule

Do not ask the user to make routine implementation, architecture, ordering, dependency, naming, remediation, testing or retry decisions.

Resolve decisions through:

1. current live authority;
2. admitted evidence;
3. credible option evaluation;
4. explicit claims and nonclaims;
5. proof of the selected option;
6. an accepted realisation decision;
7. repository-local implementation and validation.

Do not stop after creating a Linear issue, specification, contract, ADR, plan, report, checkpoint or generated packet. Continue implementation unless a genuinely irrecoverable external or human dependency exists.

Do not emit “standing by”, “waiting”, “continue later” or equivalent output while a safe recovery or implementation action remains.

## 7. Definition of a complete realisation

A semantic contract is realised only when all applicable behaviour is executable from files tracked in this repository.

A complete realisation must have:

```text
an accepted authority-bound realisation decision
repository-local source or a repository-local adapter for an external dependency
all referenced implementation paths present inside the repository
locked and reproducible dependencies
configuration schema and safe examples
required database migrations and seed data
required commands, APIs, workers, events and scheduled jobs
positive, negative, error and recovery behaviour
environment wiring for dev, test and staging
health and readiness checks
unit, contract, integration and end-to-end tests
semantic traceability from contract to implementation and tests
validation evidence admitted into the lifecycle
```

The following do not count as implementation:

```text
a semantic-contract JSON file
a path string naming code elsewhere
a source digest without the source bytes
a generated interface with no working behaviour
a mock used as the only staging implementation when the contract requires real behaviour
a test double with no production-shaped implementation
a package declaration that is never integrated and exercised
a Compose service that starts but does not fulfil its contract
a report asserting that implementation exists
```

## 8. Repository-locality and independence

The original repository, parent repository and local caches may be inspected read-only as migration evidence. They are not runtime, build, test or staging dependencies.

Before completion, eliminate every dependency on code outside this repository, including:

```text
relative paths escaping the repository
absolute host source paths
file: dependencies targeting another checkout
symlinks into another repository
Git submodules used to supply required suite code
volume mounts of original-repository source
commands that execute tools from the parent repository
specification fields that identify an external local source path as the implementation
implicit reliance on files available only in an agent cache or CAS
```

Third-party packages, container images and external services are permitted only when selected by an accepted semantic decision, version or digest locked, licence and supply-chain constraints satisfied, and integrated through repository-local code and configuration.

When an external service is selected:

1. implement the repository-local client, adapter, schemas and failure handling;
2. provide a hermetic substitute or emulator for deterministic development and test execution where the contract permits it;
3. provide staging configuration and validation for the production-shaped integration;
4. preserve explicit nonclaims for unavailable live-provider evidence.

When original code is suitable, copy or adapt the necessary source into this repository, preserve applicable provenance and licence information, remove the external path dependency, and validate it against current semantics. Do not merely point to it.

Every implementation, test, proof-algorithm and operational path referenced by semantic or JSON resources must:

```text
resolve beneath the repository root
exist in the final Git tree
have the expected representation
have a current content digest when the model requires one
be included in clean-room validation
```

## 9. Required delivered repository

The final Git tree must contain the complete tracked source of the suite, including the applicable equivalent of:

```text
apps/ or services/               executable applications and services
packages/ or capabilities/       shared and capability implementation modules
adapters/                         external-system and provider adapters
migrations/                       schema and data migrations
seeds/ or fixtures/               deterministic environment seed data
config/                           validated configuration definitions and examples
compose.yml                       common production-shaped topology
compose.dev.yml                   development overrides
compose.test.yml                  isolated deterministic test topology
compose.staging.yml               staging topology and controls
scripts/ or tools/                bootstrap, validation, migration, backup and operations
proof/ and validation assets      executable semantic compliance evidence
unit, contract, integration and e2e tests
CI workflows                      clean build and validation gates
operator documentation            exact commands and bounded troubleshooting
```

Equivalent names are allowed only when live layout authority selects them. Missing authorised path rules must be modelled, proved and published before files are created.

Source realisations and environment definitions must be tracked in Git. Runtime logs, large evidence payloads, caches, secrets and volatile outputs remain outside Git in their authorised locations.

No `TODO`, `FIXME`, deliberate no-op, `not implemented`, unconditional success, skipped mandatory test, empty handler or placeholder may remain in an in-scope executable path.

## 10. Required environments

Deliver three complete environments from the same versioned application source and images. Environment differences must be configuration, policy and infrastructure differences, not separate behavioural implementations.

### 10.1 Development

Development must provide:

```text
one-command build and start
local deterministic dependencies
safe defaults and example configuration
seeded representative tenants and users
fast feedback and optional hot reload
health, readiness and diagnostic endpoints
repeatable reset and teardown
```

### 10.2 Test

Test must provide:

```text
isolated deterministic execution
fresh data stores or proven rollback between runs
hermetic provider substitutes where permitted
parallel-safe test isolation
failure injection
machine-readable test and evidence output
complete teardown with no leaked state
```

### 10.3 Staging

Staging must be production-shaped while retaining explicit nonclaims that it is not production-live.

It must provide:

```text
built immutable application images
production-equivalent process model
persistent data services and migrations
reverse proxy or ingress where required
TLS or a documented local staging trust boundary where required
secrets injected outside source
health and readiness gates
restart and recovery behaviour
backup and restore validation
observability wiring
resource limits
upgrade and rollback procedure
no development-only code paths
```

A local or controlled staging deployment is acceptable when live cloud infrastructure is not authorised, provided it exercises the production-shaped topology and does not overclaim live-provider readiness.

## 11. Initial preflight and compatibility audit

Before modification:

1. Confirm the repository is `maldous/usf-graph` and branch is `main`.
2. Record HEAD, upstream state and the new `GOAL.md` digest.
3. Inspect status, ignored state, stashes, branches and worktrees.
4. Attribute every pre-existing modification or untracked path.
5. Confirm no other process is modifying the checkout.
6. Confirm required environment variables without printing secret values.
7. Confirm the operator-local CAS is outside Git and writable.
8. Load the USF skill.
9. Call `usf_health`.
10. Load the latest programme checkpoint and verify all available digests.
11. Treat the earlier terminal verdict as reopened under Section 3.
12. Reuse the previous bootstrap orientation when authority has not changed; otherwise obtain the minimum fresh authority witness and focused context required.

Do not call broad bootstrap or inventory tools repeatedly. One valid orientation plus focused queries is sufficient until authority changes.

## 12. Executable realisation audit

Before selecting new work, build a deterministic, paginated and digest-bound audit of every in-scope contract and every implementation reference.

For each contract record:

```text
contract IRI and lifecycle state
required capabilities and behaviour
accepted realisation decision
implementation type
all declared source, adapter, schema, migration, command and test paths
whether each path exists inside this repository
whether any path depends on the original repository
whether executable behaviour is present
which environments run it
which tests exercise it
which evidence and proof results bind it
current executable-delivery classification
```

Classify each contract into exactly one state:

```text
EXECUTABLE_VALIDATED_ALL_ENVIRONMENTS
EXECUTABLE_MISSING_ENVIRONMENT
EXECUTABLE_VALIDATION_MISSING
IMPLEMENTATION_INCOMPLETE
SPECIFICATION_ONLY
LEGACY_REFERENCE_ONLY
EXTERNAL_ADAPTER_MISSING
IMPLEMENTATION_PATH_MISSING
REALISATION_DECISION_MISSING
MODEL_INCOMPLETE
EVIDENCE_BLOCKED
PROOF_BLOCKED
EXPLICITLY_DEFERRED_BY_AUTHORITY
EXTERNAL_OR_HUMAN_BLOCKED
SUPERSEDED
RETIRED
```

Only `EXECUTABLE_VALIDATED_ALL_ENVIRONMENTS`, explicitly authority-deferred, external/human-blocked, superseded or retired contracts are terminal classifications.

A contract classified as `SPECIFICATION_ONLY`, `LEGACY_REFERENCE_ONLY`, `IMPLEMENTATION_PATH_MISSING`, `EXTERNAL_ADAPTER_MISSING`, `IMPLEMENTATION_INCOMPLETE`, `EXECUTABLE_MISSING_ENVIRONMENT` or `EXECUTABLE_VALIDATION_MISSING` is actionable regardless of `usf_work_plan` output.

Compute a canonical executable-realisation inventory digest and retain it in the programme ledger.

## 13. Dependency closure and delivery waves

Construct the dependency graph from live semantic relationships plus implementation and environment dependencies.

Include:

```text
model and controlled values
evidence collectors and payload formats
proof algorithms and prerequisite proofs
contract activation
realisation decisions
source, package and service dependencies
path and representation authorisation
data models and migrations
cross-service interfaces and events
identity, tenancy, permission and privacy boundaries
environment topology
validation obligations
release and recovery gates
```

Plan topological delivery waves. Prefer vertical, executable slices that close several tightly coupled contracts and can be demonstrated through Compose, rather than producing another broad layer of specifications without runnable behaviour.

Within a wave:

1. repair missing semantics only as required;
2. make or verify the accepted realisation decision;
3. create the repository-local code and environment wiring;
4. run focused tests immediately;
5. publish and admit evidence;
6. re-evaluate proof and contract state;
7. checkpoint compactly;
8. continue to the next dependency-blocking gap.

## 14. Contract closure state machine

For each actionable contract, retrieve a current digest-bound contract projection with the exact contract IRI and objective. Regenerate it only after authority changes affecting that contract.

### 14.1 Model

Verify the model defines applicable:

```text
subject, ownership, claims and nonclaims
features, constraints, states and transitions
permissions, tenancy and privacy boundaries
interfaces, commands, events and workflows
data, validation and error semantics
provider and environment scope
positive, negative, timeout, retry and failure behaviour
required evidence and proof obligations
permitted realisation types and repository containment
required environment and validation obligations
readiness and invalidation consequences
```

Do not infer missing product behaviour solely from old code, tickets or convention. Old code may provide evidence and candidate behaviour, but current authority must define the requirement.

Every semantic change requires positive fixtures and planted defects.

### 14.2 Evidence and proof

Implement missing collectors and versioned proof algorithms under authorised repository paths.

Evidence must be deterministic, integrity-valid, applicable and bound to its environment and provider mode. Store large payloads and raw logs in CAS, retain compact descriptors and exact digests, and admit results only through the authorised lifecycle.

Proof results must bind the exact admitted evidence set, algorithm version, source digests, environment, confidence basis, uncertainty and nonclaims. Failed or stale results remain in lineage and cannot activate contracts.

### 14.3 Realisation decision

Evaluate credible options using admitted evidence for semantic fit, security, maintenance, licence, portability, performance, supply-chain risk, provider compatibility, validation feasibility and exit cost.

The selected option must still result in complete repository-local executable delivery:

```text
new or adapted local implementation; or
repository-local integration and adapter for a locked third-party component; or
repository-local adapter, emulator and staging binding for an authorised external service.
```

An option that leaves required source in another local repository is invalid.

### 14.4 Implementation

Implement the minimum complete behaviour satisfying the active contract, but do not confuse “minimum” with a stub or demonstration.

Requirements:

```text
no guessed domain behaviour
no unauthorised paths or formats
no external local-source dependency
no hidden paid services
no secret material in source or output
no speculative future features
no test-only shortcut standing in for required behaviour
no report-derived truth
no unconditional or hard-coded success
no skipped negative or failure paths
```

Integrate implementation into dev, test and staging before classifying it complete.

### 14.5 Validation

Run applicable:

```text
format, lint, static and type checks
unit tests
semantic contract tests
API, command, event and data-contract tests
integration and cross-service tests
state-transition, permission, tenancy and privacy tests
negative, adversarial and failure-injection tests
SHACL, integrity and contamination checks
derivation parity and determinism checks
migration, backup and restore tests
restart, retry, timeout and rollback tests
security, licence and dependency checks
resource-bound and performance checks
Compose build, config and health checks
clean-room dev/test/staging deployment
end-to-end user and automation journeys
```

Every required validation produces a `ValidationResult` that enters the evidence lifecycle. Passing tests without evidence admission and proof re-evaluation do not close the contract.

## 15. Environment orchestration and acceptance commands

Create and maintain repository-local commands equivalent to:

```text
validate repository structure and semantic path closure
build all application and service artifacts
start development environment
run complete deterministic test environment
start production-shaped staging environment
wait for health and readiness
apply and verify migrations
seed representative data
run smoke and end-to-end suites
exercise failure and recovery paths
verify semantic compliance and source/live drift
stop environments and remove only authorised ephemeral state
```

Document exact commands in the repository. A fresh operator must not need conversational context or the original repository.

The final clean-room acceptance must begin from a standalone fresh clone and empty authorised runtime state. It must not use pre-existing `node_modules`, virtual environments, local build output, copied original-repository source, unverified CAS source payloads or agent caches.

## 16. Stardog mutation and self-healing

All semantic mutations are coordinator-only and occur through registered authored graph source and the authorised compiler publication path.

Never issue direct mutation SPARQL through MCP, raw HTTP, CLI or ad hoc scripts.

Before publication, verify repository preconditions, current authority, owned transactions, local validation, exact semantic delta and invalidation of stale packets.

After publication, record the new authority digest, verify SHACL, integrity, contamination, derivations, graph inventory and source/live drift, then invalidate stale packets and update the compact programme state.

Classify failures before acting. Use bounded retries for transient failures, never replay ambiguous mutations, never alter another owner’s transaction, minimise failing fixtures, preserve state and continue through safe recovery.

Resource limits must be addressed through bounded queries, indexing, batching, projections, external payload storage or an authorised semantic-store migration. Never weaken semantic completeness or implementation requirements to fit a service tier.

## 17. Linear work projection

Linear tracks actions and history; it never establishes semantic or implementation truth.

Search before creating issues. Update an existing issue representing the same semantic resource and executable gap. Mark Done only after the repository-local implementation exists, required environments execute it, validation evidence is admitted and live authority no longer reports the gap.

Issue creation is followed by implementation in the same programme unless the issue records an irrecoverable external or human dependency.

## 18. Parallelism and independent review

Use at most eight active agents and delegation depth at most two.

All subagents remain read-only. Use them for focused semantic inspection, implementation review, test attacks, dependency analysis and independent reconstruction of counts or digests.

At least two independent final review rounds are mandatory. The second final reviewer must not receive the first reviewer’s conclusion before reporting.

Every critical, high or claim-affecting medium finding reopens the affected lifecycle stage.

## 19. Mandatory adversarial attacks

Actively attempt to prove the delivery incomplete or unsound, including:

```text
specification or report treated as implementation
semantic path referring outside the repository
missing source behind a recorded digest
standalone clone requiring parent-repository files
Compose service present but behaviour absent
dev-only implementation passed off as staging
mock-only implementation overclaiming real provider readiness
active contract lacking executable behaviour
active contract lacking all-environment wiring
package declared but not integrated
adapter omitting errors, retries or security boundaries
placeholder, no-op or unconditional success
positive-only tests
cross-service interface disagreement
migration or seed nondeterminism
stale evidence or proof binding
source/live drift
CAS digest or locator mismatch
secret leakage
supply-chain or licence violation
rollback leaving partial filesystem, database or semantic mutation
clean-room build using hidden cache or host state
staging upgrade or recovery failure
unimplemented user, API or automation journey
```

Seed representative defects and require the intended validator to reject them exclusively.

## 20. Token-minimisation and context discipline

Token minimisation is mandatory and must not weaken delivery.

Treat conversation as temporary memory. Treat Git, live semantic authority, CAS, Linear and the compact programme ledger as durable state.

Maintain the atomic JCS-canonical ledger at:

```text
.work/materialisation/goal/goal-state.json
```

After the first complete read of this file, retain its digest and section index. Retrieve only the exact sections needed for the current operation.

After each contract or tightly coupled wave:

1. persist all durable semantic, implementation, evidence, proof, validation and work state in its authorised system;
2. write one atomic digest-bound checkpoint;
3. retain only identifiers, states, changed-path digests, result digests, unresolved findings and the next exact action;
4. remove raw packets, query output, logs, diffs, worker transcripts and duplicated explanations from active context once their verified descriptors are stored;
5. invalidate stale contract packets after authority changes;
6. retrieve only exact identifiers, predicates, files and line ranges needed next;
7. do not repeat broad inventory, bootstrap, census or foundational analysis unless a relevant digest changed;
8. use scripts and machine-readable summaries for counts, path checks and comparisons instead of model narration;
9. send workers compact, contract-specific, digest-bound packets;
10. require workers to return structured findings, proposed changed paths, digests, result codes and residual risks, not narrative transcripts;
11. retain one normalised signature for repeated failures rather than duplicate stack traces;
12. checkpoint before context pressure becomes material and resume from the exact next action;
13. never restate completed work in subsequent prompts;
14. do not spend tokens describing a plan when an authorised implementation action can be executed.

A checkpoint must contain at least:

```text
goal digest
repository HEAD and working-tree digest
current authority digest
executable-realisation inventory digest
completed and reopened contract IRIs
changed repository paths and content digests
admitted evidence and proof-result identifiers
validation result identifiers
current environment status
unresolved blockers and findings
next exact contract or command
Git, worktree, stash, CAS and transaction state
```

The checkpoint must allow a fresh invocation to resume without replaying two days of analysis.

## 21. Testing cadence

Run focused validation after every change and an integrated gate after every dependency wave.

Before final review, run the complete suite twice from independent clean temporary clones against the same authority digest. Require identical canonical outputs, source inventories, materialisation plans, evidence-set digests and attestations except for explicitly normalised volatile fields.

Flaky tests are defects. Find and remove nondeterminism rather than rerunning until green.

## 22. Completion gates

All gates must pass before the complete verdict.

### 22.1 Authority and semantic closure

```text
live authority health verified
one final authority digest recorded
SHACL violations = 0
integrity violations = 0
contamination = 0
source/live drift = 0
unknown registered graph drift = 0
unexplained semantic resources = 0
unclassified capabilities = 0
unclassified contracts = 0
```

### 22.2 Executable repository closure

```text
all in-scope active contracts have repository-local executable realisations
all declared implementation paths resolve beneath repository root
all declared implementation, adapter, migration, command and test paths exist
external local-repository references = 0
parent-repository runtime/build/test dependencies = 0
specification-only active realisations = 0
legacy-reference-only active realisations = 0
missing implementation paths = 0
placeholder or no-op in-scope implementations = 0
all required source is tracked in final Git tree
standalone clone requires no untracked source or agent cache
```

### 22.3 Environment closure

```text
dev environment builds, starts, becomes healthy and exercises required journeys
test environment is isolated, deterministic and complete
staging environment is production-shaped, starts healthy and has no dev-only shortcuts
all migrations and seed operations pass from empty state
all required services, workers and scheduled jobs execute
cross-service APIs, events and data contracts pass
backup, restore, restart, upgrade and rollback tests pass
environment teardown leaves no unauthorised residue
```

### 22.4 Evidence and proof

```text
all mandatory evidence admitted, fresh, integrity-valid and applicable
all mandatory proof obligations have current successful results
all successful results bind exact evidence-set and implementation-source digests
all confidence is warranted and current
all failed or stale results retain lineage and cannot activate contracts
all referenced CAS payloads verify
```

### 22.5 Contracts and realisations

```text
all in-scope warranted contracts are active
all active contracts have accepted realisation decisions
all required active contracts have valid executable realisations
all paths, formats, packages and services are authorised
all contract claims are supported
all nonclaims are preserved
all external dependencies have repository-local integration and required substitutes
```

### 22.6 Validation and integration

```text
all required ValidationResults pass and are admitted
all planted defects are rejected by the intended gate
all unit, contract, integration and end-to-end tests pass
all user, API and automation journeys required by authority pass
all rollback and recovery tests pass
clean-room runs pass twice
canonical outputs and digests are deterministic
security, licence and dependency gates pass
release, provenance, SBOM and signature gates pass where required
```

### 22.7 Independent adversarial review

```text
at least two independent final review rounds completed
second final reviewer unanchored by first report
critical findings = 0
high findings = 0
claim-affecting unresolved medium findings = 0
all resolved findings have regression tests or semantic constraints
```

### 22.8 Work and repository state

```text
executable-realisation audit has zero actionable in-scope gaps
broader semantic audit has zero actionable in-scope gaps
no duplicate or stale Linear issue remains actionable
main contains only intended programme changes
one worktree exists
no stash exists
no temporary repository artifact remains
all checkpoint and volatile runtime output is outside Git
```

### 22.9 Final evidence

```text
final suite evidence manifest verified
final exact evidence-set digest recorded
final repository-source inventory digest recorded
final dev/test/staging deployment evidence verified
final DSSE/in-toto attestation verified
post-publication proof rerun against final authority passes
final contract packets regenerate from final authority
```

## 23. Forbidden completion shortcuts

Never claim completion by:

```text
landing semantic-contract JSON without executable code
pointing implementation paths at the original repository
stopping when usf_work_plan returns no rows
calling a reference kernel the entire suite
using a local cache as the only source of implementation bytes
creating Compose files without exercising complete behaviour
using tests as proof without evidence admission
using hermetic evidence as live-provider evidence
closing Linear tickets without closing repository gaps
creating a report instead of an authoritative result
leaving active contracts without implementations
leaving implementations outside environment deployment
leaving validation outside the evidence lifecycle
skipping negative cases or adversarial review
accepting nondeterministic output
committing partial progress and declaring a milestone complete
weakening semantics, security or tests to finish faster
```

## 24. Finalisation and commit

Only after every completion gate passes:

1. archive final runtime evidence in CAS;
2. publish final evidence, proof, contract, realisation and validation metadata through the compiler transaction;
3. verify final authority and source/live drift;
4. rerun post-publication proof and final adversarial checks;
5. run two standalone-clone dev/test/staging acceptance passes;
6. remove authorised ephemeral state while preserving the compact ledger and checkpoint outside Git;
7. inspect the complete Git diff and verify no unrelated user change is included;
8. create the final commit on `main` with the final authority digest, suite evidence-set digest and repository-source inventory digest in the commit body;
9. do not push unless separately authorised;
10. report the exact commit and final live authority digest.

If the final commit cannot be created safely, retain the validated working tree and checkpoint, classify the programme as blocked and do not discard completed work.

## 25. Final report

Return one compact structured report containing:

```text
initial and final repository HEAD
initial and final authority digests
GOAL.md digest
executable-realisation inventory count and digest
contracts by executable-delivery classification
capabilities by terminal classification
semantic changes published
repository-local source and environment paths created
legacy and external-local references removed
realisations selected and delivered
dev/test/staging topology and acceptance results
migrations, seeds and operational commands delivered
evidence manifest and payload digests
proof algorithms and result digests
validation executions and results
Stardog failures and self-healing actions
Linear issues created, updated, completed or cancelled
adversarial review rounds and findings
complete test and clean-room results
final suite evidence-set digest
final repository-source inventory digest
final attestation digest
final commit
remaining explicit nonclaims
final Git, worktree, stash, CAS and transaction state
```

Do not paste unbounded logs or payloads. Report verified digests and locators.

## 26. Success condition

The programme succeeds only when the entire current semantic suite has been traversed and the repository itself contains the complete executable implementation required to run and demonstrate that suite in development, test and staging environments.

The final authority must warrant the completion claim, and two standalone clean clones must independently prove it without the original repository, parent checkout, untracked source, hidden agent cache or conversational history.
