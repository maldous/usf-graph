# GOAL.md — Complete Executable USF Delivery and Semantic-Exhaustiveness Programme

## 1. Purpose and immediate instruction

This file is the durable programme directive for a long-running, restartable and predominantly unattended delivery of the Universal Service Foundation.

When the user says **“Read GOAL.md and begin”**, do not return a plan and wait. Read the mandatory governing material, establish exact current state, report the measured usage baseline, and immediately execute the next safe critical-path action.

This revision records the direct user authorisation required by the Claude execution shim for bounded modifying workers. Modifying workers are permitted under the isolation and integration rules in this file. Only the coordinator may mutate Stardog, integrate worker changes, or make programme-level completion claims.

The programme has two inseparable objectives:

1. deliver the complete repository-local executable USF suite in development, deterministic-test and production-shaped-staging environments; and
2. establish a formal, executable and proof-bearing mechanism for semantic exhaustiveness across capabilities, resources, actions, transports, states, actors, roles, permissions, conditions, provider modes, environments, outcomes, token scopes, tests, evidence and proofs.

The programme is not complete when it has produced only semantic contracts, RDF, JSON specifications, generated packets, matrices, reports, reference demonstrations, adapters without required behaviour, or paths to code in another repository.

Completion requires a standalone clone of this repository to contain all source, configuration, migrations, seeds, orchestration, test assets, proof assets and operational tooling needed to build, run and validate the complete in-scope suite without access to an earlier or parent repository.

The lifecycle is strictly semantic-first:

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

Semantics establish what must be true. Code, tests, reports and work records are candidate realisations or evidence; none independently establish semantic truth.

## 2. Terminal outcomes

Continue until exactly one overall terminal outcome is warranted:

```text
USF_HERMETIC_SUITE_DELIVERY_COMPLETE
USF_HERMETIC_SUITE_DELIVERY_BLOCKED_IRRECOVERABLY
```

`USF_HERMETIC_SUITE_DELIVERY_COMPLETE` is permitted only when every completion gate in this file passes.

`USF_HERMETIC_SUITE_DELIVERY_BLOCKED_IRRECOVERABLY` is permitted only when progress requires an unavailable mandatory credential, explicit human or legal acceptance, a paid or irreversible external action not already authorised, inaccessible mandatory external evidence, an unexplained authority conflict, unexplained user-owned repository state, or an infrastructure limit with no authorised recovery path.

Routine ambiguity, missing semantics, missing code, test failures, proof failures, stale evidence, dependency conflicts, architectural decisions, Stardog failures, rollback, performance defects, incomplete matrices, absent permissions, missing collectors or incomplete environments are not irrecoverable blockers. Resolve them and continue.

The permutation work has an intermediate exact verdict:

```text
PERMUTATION_CLOSURE_COMPLETE
PERMUTATION_CLOSURE_INCOMPLETE
```

This intermediate verdict never substitutes for the overall terminal outcome. After permutation closure, continue executable-suite delivery unless the entire programme is complete.

## 3. Instruction precedence and semantic authority

Read the applicable execution shim, `AGENTS.md`, this file, the USF skill and the latest verified checkpoint before acting. A Claude session reads `CLAUDE.md`; a Codex session reads `CODEX.md`; another agent reads its equivalent shim when present.

Apply precedence in this order:

1. direct current user instructions and non-overridable host safety policy;
2. `AGENTS.md`;
3. this `GOAL.md`;
4. validated current live semantic authority;
5. the USF skill;
6. the applicable product shim for tool-specific orchestration;
7. current digest-bound packets and focused live queries;
8. repository source, tests, ADRs, reports, caches, earlier repositories and external work records as non-authoritative inputs.

Validated semantic state in Stardog is the sole current USF semantic authority. Stardog storage alone does not establish truth: the state must satisfy the live ontology, constraints, evidence-admission, proof, contract and realisation lifecycle.

Current authority may be corrected only through the authorised semantic publication path. Preserve lineage, produce evidence, evaluate alternatives, publish a coherent superseding decision transactionally, invalidate dependants, and regenerate affected projections. Never bypass authority informally.

Graph source files are registered materialisations used to update authority. Their presence does not independently establish truth, completeness or implementation readiness.

Do not embed volatile current-state digests in this directive. Repository bytes, the verified checkpoint, the programme ledger and live authority determine current state. Any prose snapshot, prior prompt or prior agent summary is subordinate to those sources.

## 4. Exact session start and continuation protocol

Before modification:

1. read `AGENTS.md`, the applicable shim, this file and the USF skill;
2. record the digest and section index of each governing document;
3. inspect repository identity, branch, upstream, HEAD, status, ignored state, stashes, branches and worktrees;
4. attribute every pre-existing modification and untracked path without changing it;
5. confirm no unowned process or transaction is modifying the checkout;
6. load and verify the latest programme checkpoint, ledger and available sidecar digests;
7. call `usf_health`;
8. call `usf_bootstrap` exactly once for this task unless a verified unchanged bootstrap result is already reusable;
9. record the exact live authority digest and compare it with the checkpoint;
10. retrieve the active repository-materialisation contract before creating, renaming or deleting tracked paths or selecting representation formats;
11. determine the current canonical semantic-source root and publication path rather than assuming `graph/`, `semantic-model/` or any historical directory is authoritative;
12. establish an actual token/cache telemetry baseline using Section 7;
13. identify the checkpoint’s exact next executable action and begin it.

Do not repeat broad bootstrap, census, contamination inventory, repository-wide analysis or foundational option evaluation while relevant digests remain unchanged. Query before reading files and read the smallest sufficient ranges.

A fresh invocation resumes from exact state. It does not replay the previous conversation or spend a new session proving already verified facts.

## 5. Execution mode, agent throughput and Git hygiene

Use one top-level coordinator. Only the coordinator may:

- mutate Stardog;
- publish semantic authority;
- integrate modifying-worker commits;
- resolve cross-scope conflicts;
- update the authoritative checkpoint;
- make readiness or completion claims.

Use bounded parallelism dynamically:

- begin with up to four independent workers when four real independent tasks exist;
- scale to at most eight active execution participants when scopes remain independent;
- delegation depth is at most two;
- do not spawn an agent for a task the coordinator can finish faster directly;
- prefer read-only exploration workers for search, evidence gathering, bounded comparison and test diagnosis;
- use modifying workers only for self-contained changes with disjoint write scopes;
- resume an existing worker for continuation of the same scope rather than creating a fresh one;
- stop completed or idle workers promptly.

Every modifying worker must use its own branch and worktree and receive this compact packet:

```text
objective
semantic identifiers
current authority digest
read scope
exclusive write scope
invariants
acceptance conditions
required validation
expected result format
stop conditions
```

Worker write scopes must not overlap. Workers do not mutate Stardog, rewrite shared programme state, edit the same generated projection concurrently or integrate one another.

Workers return only:

```text
result status
changed paths
commit or patch identifier
tests and validation executed
evidence produced
remaining defects or risks
recommended next action
```

Never send workers the conversation, full graph, full checkpoint, complete test logs or broad repository dumps.

Worker commits and coherent coordinator wave commits are permitted. Random partial commits, milestone overclaims and unintegrated worker commits are prohibited. Leave no stray worktree, stash, temporary branch or unintegrated commit. Never use `git stash` for coordination. Never reset, clean, overwrite, discard or delete unknown or user-owned work.

Push only when directly authorised for that session. The direct authorisation used to publish this revision does not silently authorise later agents to push unrelated implementation work.

## 6. Throughput-first delivery discipline

Throughput means **verified programme progress per token and per unit of wall time**, not raw tool-call volume.

Operate in coherent dependency-ordered delivery waves:

1. verify the exact checkpoint state and relevant digests;
2. select the smallest set of unblocked critical-path tasks that closes meaningful obligations;
3. partition independent tasks across workers;
4. while workers execute, complete non-overlapping serial work;
5. integrate results as they become available;
6. run the smallest targeted checks needed to detect immediate regressions;
7. correct failures at their source;
8. run integrated semantic, implementation and environment validation once at the end of the coherent wave;
9. publish semantic changes as the smallest safe transaction set only after local gates pass;
10. update the atomic checkpoint with exact identifiers, paths, digests, evidence and next action;
11. immediately begin the next unblocked wave.

Mandatory efficiency rules:

- prefer implementation over narration when an authorised action is available;
- batch compatible repository changes before integrated validation;
- do not run the complete compliance suite after each small edit;
- run exhaustive, adversarial, clean-room and deterministic validation at final gates or after a material authority, architecture, security or cross-system change;
- do not repeatedly ask whether the project is compliant; encode compliance in semantics, constraints and deterministic gates;
- use scripts for inventories, matrices, digests, transformations, traceability and repetitive checks;
- run independent long tests in background shells when safe;
- store large output in files and return only decisive excerpts and stable error signatures;
- do not construct orchestration, telemetry or reporting infrastructure beyond the smallest reusable mechanism required by this directive;
- use current authority and checkpoint digests as cache keys for semantic context and generated work;
- do not reopen accepted decisions without changed evidence or dependency digests.

Model effort discipline for Claude or an equivalent runtime:

- use `high` as the default balance for implementation and coordination;
- use `xhigh` or the runtime’s equivalent for hard semantic design, proof, security or cross-system reasoning;
- use `max` only for a bounded exceptional blocker, then return to the lower setting;
- do not run the entire long-lived multi-agent programme at maximum effort merely to increase activity;
- use faster or lower-cost workers for mechanical bounded tasks when the runtime supports safe model routing.

## 7. Token minimisation, cache preservation and measured usage

Token minimisation is mandatory and must not weaken delivery.

Treat conversation and model-local memory as temporary. Treat validated authority, Git, the programme checkpoint and ledger, CAS, evidence, proof and validation state as durable systems.

Preserve a stable prompt prefix and reusable working context:

- keep `AGENTS.md`, the applicable shim, this file, the loaded USF skill and shared agent definitions stable within a wave;
- after the first complete read, retain governing-document digests and section indexes and retrieve only exact sections later;
- perform one bootstrap per task and reuse it while its authority dependencies remain unchanged;
- use bounded SPARQL with exact identifiers, predicates and limits;
- read exact file ranges rather than complete large files;
- reference semantic resources and stored results by identifiers and digests rather than repeating contents;
- keep one compact task ledger containing objective, identifiers, scopes, invariants, acceptance, validation and next action;
- avoid volatile timestamps, random identifiers and reordered stable instructions in reusable prompt prefixes unless semantically required;
- do not paste worker conversations, large diffs, logs or repeated explanations into coordinator context;
- resume an existing subagent for the same semantic scope where possible;
- checkpoint before context pressure becomes material;
- compact only when needed and preserve authority digest, accepted decisions, active scopes, completed evidence, residual findings and exact next action;
- never make correctness depend on a cache hit.

### 7.1 Actual telemetry only

Do not infer token usage or caching from speed, elapsed time, estimated cost or subjective impressions. Use actual Claude Code/API telemetry when available.

At session start, perform one bounded local-only observability setup without overwriting existing settings. Confirm whether actual usage records provide:

```text
input_tokens
cache_creation_input_tokens
cache_read_input_tokens
output_tokens
context-window utilisation
model identity
request or message identity
```

Use `/usage`, the supported status-line input, or a compact transcript parser outside tracked repository content. Deduplicate cumulative records by stable request or message identity. Never sum repeated status-line refreshes or cumulative snapshots as independent usage.

Calculate:

```text
total_input =
    input_tokens
  + cache_creation_input_tokens
  + cache_read_input_tokens

fresh_input =
    input_tokens
  + cache_creation_input_tokens

cache_reuse_percent =
    cache_read_input_tokens / total_input * 100

cache_read_to_write_ratio =
    cache_read_input_tokens / cache_creation_input_tokens
```

Cache creation during initial warm-up is expected.

Use these status labels:

```text
CACHE_WORKING
  actual cache_read_input_tokens > 0

CACHE_EFFECTIVE
  cache reads materially exceed cache creation after warm-up and reuse remains stable or improves

CACHE_DEGRADED
  a stable repeated workload has zero cache reads, or cache creation equals or exceeds reads across three consecutive measured points

METRIC_UNAVAILABLE
  the runtime does not expose the value
```

Never state that caching is active without a positive measured cache-read field.

### 7.2 Reporting cadence

Report compact measured usage:

- after initial state establishment;
- at each delivery-wave boundary;
- after compaction;
- after a material cache-behaviour change;
- at least once per long-running wave, but not so frequently that telemetry itself harms throughput;
- before a usage-limit safe stop;
- in the final report.

Use this format:

```text
USAGE
elapsed:
model:
api calls:
uncached input:
cache creation:
cache read:
total input:
output:
cache reuse:
cache read:write:
context used:
measured token throughput:
active/completed agents:
cache status:

DELIVERY
wave:
completed:
evidence:
validation:
next critical action:
blockers:
```

Use actual numbers only. Mark unavailable values `METRIC_UNAVAILABLE`. Distinguish API processing time from wall time when both are available.

## 8. Complete repository-local realisation

A semantic contract is realised only when all applicable behaviour is executable from tracked repository files.

A complete realisation includes:

```text
accepted authority-bound realisation decision
repository-local source or repository-local adapter
all referenced paths beneath the repository root
locked reproducible dependencies
configuration schema and safe examples
migrations and representative seeds
commands, APIs, workers, events and scheduled jobs
positive, negative, error and recovery behaviour
dev, test and staging wiring
health and readiness
unit, contract, integration and end-to-end tests
semantic traceability to implementation and tests
validation evidence admitted into the lifecycle
```

The following do not count as implementation:

```text
RDF, JSON or a generated contract alone
a path naming code elsewhere
a source digest without source bytes
a generated interface without working behaviour
a mock as the only staging behaviour when real behaviour is required
a package declaration not integrated and exercised
an orchestration service that starts but does not fulfil its contract
a report asserting that implementation exists
```

Earlier repositories, histories, work trackers and local caches are not semantic inputs and are not required for build, run, test, staging or continuation. Eliminate paths escaping the repository, absolute source paths, `file:` dependencies to another checkout, source-supplying submodules, cross-repository symlinks, parent-source mounts, parent tools and implementation references that exist only in an agent cache or CAS.

Third-party packages, images and external services require an accepted option decision, exact version or digest, integrity verification, licence and supply-chain assessment, a declared acquisition process and replacement/continuity rule. At least one build and test run must execute with network disabled using only verified acquired inputs.

No `TODO`, `FIXME`, deliberate no-op, `not implemented`, unconditional success, skipped mandatory test, empty handler or placeholder may remain in an in-scope executable path.

## 9. Required environments and hermetic bootstrap

Deliver development, deterministic-test and production-shaped-staging environments from the same versioned application source and images. Differences are configuration, policy and infrastructure differences, not separate behavioural implementations.

Development requires one-command start, local deterministic dependencies, safe example configuration, representative tenants and users, fast feedback, health/readiness, reset and teardown.

Test requires isolated deterministic execution, fresh state or proven rollback, permitted hermetic provider substitutes, parallel-safe isolation, failure injection, machine-readable evidence and complete teardown.

Staging requires immutable application images, production-equivalent process model, persistent services and migrations, ingress/trust boundary where applicable, externally injected secrets, readiness gates, restart/recovery, backup/restore, observability, resource limits, upgrade/rollback and no development-only paths.

The bootstrap counterfactual is:

> If every earlier repository, tracker, branch, commit, source file, conversation, cache and current working directory disappeared, could an independent agent reconstruct, build, run, test and validate the entire project from the final repository, exact current authority and declared verified inputs alone?

Completion requires a demonstrated yes from two independent fresh clones and a poisoned-state test.

## 10. Semantic adequacy, contamination and realisation-option closure

Preserve the existing digest-bound semantic-adequacy and contamination review while its dependencies remain unchanged. Reopen only affected items when a relevant semantic, evidence, proof, representation or authority digest changes.

Every imported name, IRI, capability boundary, service/package boundary, interface, operation, event, workflow, state, technology choice, provider assumption, environment classification, nonclaim, path role and operational process must have an independent semantic basis rather than mere historical familiarity.

Every imported item has exactly one complete disposition:

```text
INDEPENDENTLY_WARRANTED_RETAINED
CORRECTED_OR_RENAMED
CONSOLIDATED
SPLIT
SUPERSEDED
HISTORICAL_PROVENANCE_ONLY
UNRESOLVED_EXTERNAL_DECISION
```

Operational sequencing must not become permanent capability, package, directory, filename, IRI or API identity unless it has genuine stable semantic meaning.

No realisation decision is grandfathered. Before implementation expansion, prove current candidate coverage, current criterion/evidence assessment, exact component/version binding, licence and supply-chain closure, responsibility mapping, composition coverage and required provider/environment bindings. Preserve independently validated unaffected behaviour within its proven scope.

The compiler, generators, validators, proof algorithms and materialisation tools are delivered system components. They must be repository-local, versioned, digest-bound, tested and free of historical-origin assumptions.

## 11. Mandatory semantic-exhaustiveness objective

Create a formal, generic and extensible mechanism proving that every semantically meaningful way of operating every active USF capability has been considered.

The mechanism must prove:

1. every active capability has an explicit operational-surface classification;
2. every applicable operational combination has one exact deterministic permutation cell;
3. every candidate cell has exactly one disposition;
4. every operation is bound to capability, contract, resource, action, interface or port, transport, interaction pattern, direction, state, permission, eligible principal path, tenant/security boundary, provider/environment conditions, outcomes, audit, evidence, proof, validation and token scope or explicit token non-applicability;
5. every relevant role-to-operation and principal-to-operation combination is explicitly classified;
6. every required operation has at least one satisfiable authorised execution path;
7. every active role has at least one meaningful authorised capability;
8. no operation, role, permission, event, transition, port, provider mode, token scope or active capability remains orphaned;
9. no active contract contains an unresolved or silently omitted applicable permutation;
10. the complete permutation universe is finite, deterministic, queryable and digest-bound.

### 11.1 Meaning of “all permutations realised”

Every finite candidate combination must be materialised as a queryable semantic cell and assigned exactly one closed disposition:

```text
REQUIRED
ALLOWED
FORBIDDEN
NOT_APPLICABLE
DEFERRED
UNRESOLVED
```

This does **not** mean every combination is allowed. Preserve deny-by-default and least privilege.

For every active contract:

- `UNRESOLVED` = 0 before closure;
- `DEFERRED` is prohibited unless the capability or contract is explicitly deferred by current authority;
- every `REQUIRED` or `ALLOWED` cell is executable or has a currently warranted proof-rung limitation;
- every `FORBIDDEN` cell is impossible to authorise or encode into a token;
- every `NOT_APPLICABLE` cell carries a controlled reason code, rationale and provenance.

Interpret the requirement that no platform role be unable to do anything as follows:

- no active role is empty;
- no required operation lacks an eligible human role or service principal;
- every platform operation has a normal operator path or a tightly controlled emergency path;
- every role-operation-context cell is explicitly granted, conditional, denied, delegated-only, service-only, break-glass-only or not applicable.

Do not grant every role every permission. A role intended to have no privileges must be inactive, retired or explicitly non-operational rather than silently empty.

## 12. Permutation meta-model

Implement an intentional semantic meta-layer defining how existing USF semantics are enumerated and proven. It describes the closure mechanism; it does not duplicate the domain model.

Derive final canonical names from current authority. The required conceptual resources are:

```text
PermutationFamily
PermutationDimension
PermutationDimensionValue
DimensionValueSource
ApplicabilityRule
PermutationCell
PermutationDisposition
PermutationDispositionReason
PermissionAtom
AuthorisationPath
AuthorisationConditionProfile
PrincipalKind
RolePermissionDisposition
TokenScope
TokenProfile
TokenClaimConstraint
PermutationCoverage
PermutationProof
PermutationUniverse
PermutationPartition
PermutationFamilyReview
```

Each `PermutationFamily` declares:

```text
canonical identity
semantic subject
ordered dimensions
finite value source for each dimension
conditionally active dimensions
applicability rules
required disposition set
closure requirements
generation algorithm
stable-key algorithm
partitioning rule
proof obligations
validation obligations
lifecycle state
```

Each `PermutationCell` declares:

```text
family
exact ordered dimension values
canonical stable key
content-sensitive digest
disposition
controlled reason code
reason text
provenance or derivation rule
authority digest
lifecycle state
permission atom where applicable
eligible authorisation paths
token scope or token-not-applicable state
required evidence, proof and validation identifiers
```

A cell identity is derived from canonical dimension identifiers, never insertion order, a tracker identifier or a runtime instance identifier. Duplicate semantic keys are forbidden. Every candidate key has exactly one cell, and no extra cell may exist outside the candidate universe.

## 13. Finite-domain rule

Exhaustiveness must be finite, reproducible and applicable.

Enumerate controlled semantic classes such as:

```text
capability and contract
resource class
selector kind
action kind
transport and interaction pattern
direction and session model
actor and principal kind
role and service identity
permission atom
condition profile
tenant/security boundary
lifecycle source and target state
provider mode
environment class
outcome and error class
audit category
proof rung
```

Do not enumerate every runtime user, tenant, resource instance, timestamp or arbitrary string. Represent runtime specificity through validated selector and claim constraints such as exact resource ID, owner relationship, tenant, organisation, tag/classification, bounded path prefix, approved predicate, time window, environment, session and delegation chain.

Every controlled-value domain must itself be closed, validated and digest-bound.

## 14. Permutation-family census

Review every active capability, contract and mandatory facet. Assign exactly one family-applicability disposition:

```text
MATRIX_REQUIRED
MATRIX_NOT_APPLICABLE
```

`MATRIX_NOT_APPLICABLE` requires a reason code and proof that no independently meaningful multi-axis operational behaviour exists.

At minimum, implement these families where applicable:

1. Capability × Resource × Action
2. Capability × Interface × Operation
3. Interface × Transport × InteractionPattern × Direction
4. Operation × Permission
5. Operation × Role × ConditionProfile
6. Permission × Role × TenantBoundary
7. Permission × PrincipalKind × EnvironmentClass
8. Permission × ResourceSelectorKind
9. Operation × SourceState × TargetState
10. Transition × Trigger × Permission × Actor
11. Port × Action × ProviderMode × EnvironmentClass
12. Event × Publisher × Consumer × DeliverySemantics
13. Event × PublishPermission × ConsumePermission
14. Queue/Event × AckMode × RetryMode × ReplayMode
15. DataModel × Action × PrivacyClassification × TenantBoundary
16. ConfigurationKey × Action × Role × Environment
17. Secret × Action × PrincipalKind × Environment
18. UI Surface × Action × Permission × RouteKind
19. Form/View × Operation × Permission
20. TokenProfile × PermissionAtom × ClaimConstraint
21. Operation × ExpectedOutcome × ErrorClass
22. Operation × AuditEvent × AuditOutcome
23. Capability × ProviderMode × ProofRung × EnvironmentClass
24. RequiredPermutation × Test × Evidence × Proof
25. Role × Capability × Action reachability
26. Service/Process × Capability × Interface × LifecycleObligation
27. ScheduledJob × Action × Role/ServiceIdentity × Environment
28. API/Command × RateLimitPolicy × Permission × TenantBoundary
29. Resource × DataField × Action × PrivacyClassification
30. ExternalDependency × Operation × FailureMode × RecoveryAction

The census covers lifecycle, state model, permission, contracts, validation, errors, audit, readiness, proof, UI, APIs, commands, events, workflows, storage, configuration, secrets, tenancy, privacy, operators and automation. No active facet may remain absent from the census.

## 15. Complete operation catalogue

Create a closed and extensible `ActionKind` taxonomy. Do not rely on operation names such as `get`, `post` or `create` to carry semantics.

Evaluate applicability of at least these generic resource actions:

```text
create, read, get, head, list, search, query,
update, replace, patch, upsert,
delete, purge, restore, archive, unarchive,
copy, move, import, export,
validate, verify, sign, scan, quarantine, release,
enable, disable, activate, deactivate,
approve, reject, lock, unlock
```

Connection and session actions:

```text
connect, open, authenticate, authorise,
read, write, send, receive,
subscribe, unsubscribe,
ping, pong, heartbeat,
close, disconnect, abort, reconnect, resume
```

Execution and workflow actions:

```text
create, schedule, start, signal,
pause, resume, stop, cancel,
retry, replay, redrive,
compensate, rollback, complete, fail,
acknowledge, reject, lease, renewLease
```

Security and identity actions:

```text
login, logout, refresh, exchange, introspect,
issue, delegate, impersonate, revoke, rotate,
recover, breakGlass, approveElevation, terminateSession
```

Event and messaging actions:

```text
publish, consume, subscribe, unsubscribe,
acknowledge, negativeAcknowledge,
retry, replay, redrive,
deadLetter, inspectDeadLetter, purgeDeadLetter
```

Data and transaction actions:

```text
begin, commit, rollback,
select, insert, update, upsert, delete,
migrate, seed, snapshot, backup, restore,
replicate, reconcile
```

Webhook actions:

```text
register, inspect, list, update, delete,
enable, disable, test, deliver, inspectDelivery,
retry, replay, rotateSecret, revokeSecret
```

Provider actions:

```text
configure, inspect, list, test,
enable, disable, failover, recover, rotateCredentials
```

Not every capability supports every action. Every generated candidate action must nonetheless receive an explicit disposition.

## 16. Transport and interaction taxonomy

Create explicit controlled values for at least:

Transports:

```text
HTTP
WebSocket
Server-Sent Events
gRPC
event bus
durable queue
scheduled invocation
internal process call
CLI
file exchange
database protocol
object-storage protocol
webhook callback
```

HTTP methods:

```text
GET
HEAD
OPTIONS
POST
PUT
PATCH
DELETE
```

Interaction patterns:

```text
request-response
fire-and-forget
publish-subscribe
point-to-point
client streaming
server streaming
bidirectional streaming
long polling
callback
scheduled
batch
transactional
```

Directions:

```text
inbound
outbound
bidirectional
internal
```

Session models:

```text
stateless
stateful
connection-oriented
resumable
leased
transactional
```

Every declared operation has explicit applicable values or an explicit `NOT_APPLICABLE` disposition.

Every WebSocket-capable surface must explicitly consider:

```text
connect
open
authenticate
authorise
read
write
send
receive
subscribe
unsubscribe
ping
pong
heartbeat
close
disconnect
abort
reconnect
resume
```

## 17. Permission atoms and complete authorisation matrix

Replace ambiguous permission naming with exact `PermissionAtom` semantics.

Each permission atom identifies:

```text
capability
resource or resource class
action
transport or interaction restriction where security-relevant
scope type
tenant boundary
selector kind
lifecycle-state restrictions
environment restrictions
principal-kind restrictions
delegability
break-glass eligibility
audit category
stable permission identifier
```

For every active role and every relevant permission atom, create exactly one role-permission disposition:

```text
GRANTED
CONDITIONALLY_GRANTED
DENIED
NOT_APPLICABLE
DELEGATED_ONLY
SERVICE_IDENTITY_ONLY
BREAK_GLASS_ONLY
```

Every conditional grant references a finite named `AuthorisationConditionProfile`.

Evaluate conditions including:

```text
tenant membership and ownership
platform scope
resource ownership
delegated administration
service identity
authentication strength
session state
network or trust boundary
environment and provider mode
lifecycle state
resource and privacy classification
consent and entitlement state
quota state
legal hold
time restriction
request origin
approval state
break-glass state
```

Required invariants:

1. every operation requires at least one permission atom, including an explicit public/anonymous atom when genuinely unauthenticated;
2. every permission atom is used by an operation or explicitly retired;
3. every active role has at least one granted or conditionally granted cell;
4. every required or allowed operation cell has at least one satisfiable principal path;
5. no forbidden cell has a role, ABAC, delegation, service-identity or token path;
6. no implicit grant exists;
7. no wildcard grant exists unless represented as a separately reviewed bounded resource and expanded to a proven finite set;
8. separation-of-duty conflicts are explicit and validated;
9. tenant and platform permission namespaces cannot silently overlap;
10. human roles and service identities remain distinguishable.

## 18. Authorisation reachability and break-glass

For every `REQUIRED` or `ALLOWED` operation-context cell, prove an authorisation path consisting of:

```text
active operation
active capability and contract
eligible principal kind
role, service identity or bounded ABAC rule
permission atom
satisfied condition profile
compatible tenant boundary
compatible environment and provider mode
valid token scope or explicit non-token execution mode
```

Prove additionally:

- no path is logically unsatisfiable;
- no path depends only on a retired role;
- no path depends only on an invalid environment;
- no required platform operation lacks a controlled operator or emergency path;
- no tenant operation is available solely through platform-wide authority without an explicit exception;
- every active role is non-empty;
- every required operation is reachable by at least one eligible principal.

Where normal access is unsafe, provide an explicit break-glass path with strong authentication, short lifetime, reason, approval where required, complete audit, revocation, no implicit persistence and post-use review.

## 19. Fine-grained token generation and verification

Derive token scopes only from active `REQUIRED` or `ALLOWED` authorisation cells.

Implement semantic definitions for:

```text
TokenProfile
TokenScope
TokenClaimConstraint
TokenAudience
TokenIssuerClass
DelegationConstraint
ResourceSelectorConstraint
TokenLifetimePolicy
AuthenticationStrengthRequirement
ProofOfPossessionRequirement
RevocationPolicy
BreakGlassTokenProfile
```

A token projection can express:

```text
subject and actor
principal kind and roles
tenant, organisation and suborganisation
audience and environment
capability and resource class
exact action
transport or interaction restriction
resource selector
lifecycle-state restriction
condition-profile identifier
delegation chain
authentication strength
issued-at, not-before and expiry
unique token identifier
proof-of-possession where required
break-glass reason and approval
```

Token invariants:

1. every token scope maps to exact active permission atoms;
2. every token-eligible permission atom maps to an exact token scope;
3. a token cannot encode a forbidden or not-applicable cell;
4. a token cannot broaden resource, tenant, action, environment or transport beyond its source cells;
5. refresh, exchange and delegation cannot increase privilege;
6. audience and bounded lifetime are mandatory;
7. break-glass tokens are short-lived, non-refreshable, fully audited and reviewed;
8. wildcards are forbidden unless expanded and proven equivalent to a finite exact set;
9. verification fails closed on unknown permission, stale authority digest, retired scope or condition mismatch;
10. scopes use stable semantic identifiers, not display names;
11. the generator can emit a least-privilege token for every satisfiable token-based authorisation path.

Do not store secrets or issued runtime tokens in Git or semantic authority.

## 20. Lifecycle and transition permutations

Correct any place where an unordered state enumeration has been mechanically converted into a sequential state machine.

Every transition declares where applicable:

```text
source state
target state
triggering operation or event
required permission
eligible principal kind
guard condition
success outcome
failure outcome
audit event
compensation or rollback behaviour
idempotency semantics
```

Generate and classify every applicable state × action candidate as:

```text
permitted transition
forbidden transition
not applicable
terminal-state no-op
idempotent repeat
compensating transition
```

Never infer transition order from lexical order, file order or list position.

## 21. Provider, environment and failure permutations

For every applicable port action, enumerate:

```text
port
× action
× provider mode
× environment class
× expected outcome
× failure class
```

At minimum consider deterministic test substitute, repository-local service, external sandbox, live external and authority-control modes where applicable, across local, hermetic, integration, staging, production-shaped, production-live and authority-control environments.

Each applicable cell defines timeout, retry, idempotency, circuit behaviour, tenant boundary, credential boundary, expected audit, required evidence, proof rung and readiness effect.

No provider-mode/environment combination may be silently omitted.

## 22. Event, queue and message permutations

For each event and message, model:

```text
publisher and consumer
publish, consume and subscribe permissions
acknowledgement semantics
retry, replay and redrive
dead-letter handling
ordering and deduplication
tenant filtering
payload classification
delivery semantics
environment and provider mode
audit requirements
```

Explicitly disposition applicable delivery modes including at-most-once, at-least-once, effectively-once, ordered and unordered. Do not assume one guarantee applies universally.

## 23. Data, privacy, configuration, secret and UI permutations

For every data/resource class, evaluate action × principal × tenant boundary × privacy classification × consent × retention × legal hold × ownership selector × environment × audit category.

Prove that:

- read and write are distinct;
- list/search are not silently equivalent to get;
- export is not silently equivalent to read;
- delete is distinct from purge;
- restore is distinct from create;
- metadata and payload access may be authorised separately;
- sensitive fields may have finer permissions than their containing resource;
- cross-tenant access is forbidden unless an explicit proven platform operation permits it.

For every configuration key and secret, classify read, list, create, update, rotate, revoke, delete and use across roles, service identities and environments.

For every UI surface, route, form and view, bind visible and invocable actions to the same exact operation and permission semantics used by APIs, commands and automation. UI hiding alone is never authorisation.

## 24. Deterministic derivation and materialisation

Do not hand-author millions of rows.

Implement deterministic rules or a proven generator that:

1. reads current finite semantic dimensions;
2. enumerates the complete candidate universe;
3. applies applicability rules;
4. materialises every cell;
5. assigns exactly one disposition;
6. generates permission atoms;
7. generates role-permission cells;
8. generates authorisation paths and reachability;
9. generates token scopes;
10. generates coverage and proof obligations;
11. emits deterministic counts, partitions and digests.

Authoritative queryable permutation cells must be available in Stardog. Partition large matrices deterministically by family and capability using bounded named graphs or another authorised layout.

Large tabular or compressed projections may be stored in the operator-owned CAS, but Stardog retains sufficient semantic state to query any cell. Every external payload has exact digest, media type, size and locator; it cannot replace semantic authority and must be reproducible from current authority.

Do not suppress rows merely to reduce volume. Address scale with partitioning, indexing, streaming generation, deterministic batching and compact identifiers.

## 25. Permutation coverage model

Coverage measures the generated permutation universe, not merely whether a pre-existing test obligation has a result.

For every required or allowed cell, derive:

```text
semantic-definition coverage
permission coverage
principal reachability
token-scope coverage
lifecycle coverage
test coverage
evidence coverage
proof coverage
environment/provider coverage
audit coverage
```

For every forbidden cell, derive:

```text
denial-rule coverage
token-denial coverage
negative-test coverage
bypass-resistance coverage
```

Every coverage record identifies the exact permutation key. No aggregate `100%` claim is permitted unless every required cell is covered and every forbidden cell has a proven denial path.

## 26. Formal semantic-exhaustiveness proof

Implement a deterministic proof algorithm bound to:

```text
authority digest
ontology digest
controlled-value digest
permutation-family census digest
applicability-rule digest
candidate-universe digest
generated-cell digest
permission-matrix digest
token-scope digest
test/evidence-set digest
implementation-source digest
```

The proof establishes:

1. every reviewed subject is `MATRIX_REQUIRED` or `MATRIX_NOT_APPLICABLE`;
2. every required family has finite closed dimensions;
3. every candidate key creates exactly one cell;
4. no extra cell exists outside the universe;
5. every cell has exactly one valid disposition;
6. active contracts have zero unresolved cells;
7. unauthorised deferred cells are zero;
8. every required and allowed cell is operationally reachable;
9. every forbidden cell has no authorisation or token path;
10. every operation has permission coverage;
11. every relevant role-operation combination has a disposition;
12. every active role is non-empty;
13. every required operation has an eligible principal;
14. every token scope is bounded by active permission cells;
15. every lifecycle transition is operation/event-triggered or explicitly justified;
16. every provider/environment cell has its required proof obligation;
17. every required cell has coverage;
18. every forbidden cell has negative coverage;
19. no wildcard or inherited permission silently broadens access;
20. unchanged authority reproduces identical counts, keys and digests.

The proof emits counts by family, dimension and disposition; zero-gate counters; orphan and reachability counters; unresolved and duplicate counters; missing/overbroad token counters; missing-test counters; exact digests; uncertainty and explicit nonclaims.

Admit the result through the normal USF evidence and proof lifecycle and rerun required post-publication authority-binding validation.

## 27. SHACL, integrity, fixtures and generated tests

Add fail-closed SHACL and integrity rules for every closure invariant.

Plant defects proving detection of:

```text
missing or duplicate permutation cell
multiple or absent dispositions
unresolved active cell
required operation without principal path
active role without privilege
permission without operation
operation without permission
permission without role, ABAC or service path
forbidden cell with a grant
forbidden cell in token scope
over-broad token scope
wildcard privilege broadening
cross-tenant leakage
platform/tenant namespace collision
unsatisfiable conditional grant
transition without trigger or permission
state enumeration falsely sequenced
incomplete WebSocket family
event missing publish or consume permission
provider/environment omission
operation missing audit behaviour
required cell missing test/evidence
NOT_APPLICABLE without rationale
stale authority digest
non-deterministic cell identity
```

Include conforming fixtures for every major family. Each negative fixture fails for its intended stable code and no unrelated code.

Generate deterministic executable tests from the matrix:

- positive tests for required and allowed cells;
- negative authorisation and token tests for forbidden cells;
- condition, tenant, state, transport, resource-selector and audit checks;
- proof-only dispositions only where runtime execution is impossible at the current warranted proof rung;
- fixed seeds and exact reproduction information for property-based tests;
- partitions by capability and family for diagnosis and parallel execution.

## 28. Migration of all current authority

Migrate every active capability, contract, interface, operation, port, event, message, workflow, transition, role, permission, provider mode, environment, UI surface and token-related capability into the closure mechanism.

No existing operation is a privileged legacy exception.

For every active capability:

1. assign operational-surface classification;
2. complete the family census;
3. generate applicable cells;
4. classify every cell;
5. bind permission atoms;
6. establish role/service reachability;
7. derive token scopes;
8. generate tests and proofs.

Where current semantics cannot justify allowed, forbidden or not applicable, create an explicit unresolved cell, identify the missing semantic decision, resolve it through evidence and publication, and return active unresolved count to zero. Do not guess.

## 29. Performance and scale evidence

Measure before publication:

```text
candidate permutation count
materialised cell count
triples added
generation time
validation time
proof time
exact-cell lookup latency
role-capability listing latency
token-scope derivation latency
serialised projection size
Stardog transaction size
peak memory and bounded-resource behaviour
deterministic repeatability
```

Do not reduce semantic coverage for performance. A decision query given role, operation and context must return final decision, exact cell, permission atom, conditions, reason, policy lineage, token scope, proof and evidence state.

## 30. Dependency closure and implementation lifecycle

Construct the dependency graph from live semantic relationships plus implementation and environment dependencies. Include model, controlled values, collectors, proofs, contract activation, realisation decisions, paths, data/migrations, interfaces/events, identity/tenancy/permissions/privacy, provider/environment topology, validation and recovery gates.

The semantic-exhaustiveness and permission-closure work is now a mandatory critical-path node before any permission, role, token, operation-catalogue or access-control implementation can be considered complete. Unaffected executable-environment work may proceed in parallel when its semantics and write scopes do not overlap.

For each actionable contract:

1. verify complete model behaviour and applicable permutation closure;
2. implement missing collectors and proof algorithms;
3. evaluate credible realisation options;
4. implement the minimum complete repository-local behaviour, never a stub;
5. integrate it into dev, test and staging;
6. run focused and aggregate validation;
7. admit validation evidence;
8. re-evaluate proof and contract state;
9. checkpoint and continue.

## 31. Stardog mutation and self-healing

All semantic mutations are coordinator-only and use registered authored semantic source and the authorised compiler publication transaction.

Never issue mutation SPARQL through a read gateway, raw HTTP, database CLI or ad hoc script.

Before publication, verify repository preconditions, current authority, transaction ownership, local validation, exact semantic delta and stale-packet invalidation.

After publication, record the new authority digest; verify SHACL, integrity, contamination, derivations, graph inventory, permutation closure and source/live drift; invalidate stale packets; update checkpoint and measured usage; continue.

Classify failures before acting. Retry only transient operations, never replay ambiguous mutations, never alter another owner’s transaction, minimise failing fixtures, preserve state and continue through safe recovery.

## 32. Validation, adversarial review and clean-room acceptance

Run applicable format, lint, static, type, unit, semantic-contract, API, command, event, data, integration, state-transition, permission, tenancy, privacy, token, negative, adversarial, SHACL, integrity, derivation, migration, backup, restore, retry, timeout, rollback, security, licence, dependency, performance, orchestration and end-to-end checks.

Every mandatory validation produces a `ValidationResult` entering the evidence lifecycle. A passing test alone does not close a contract.

Actively attack:

```text
specification or report treated as implementation
semantic or implementation path outside the repository
missing source behind a digest
hidden parent-repository dependency
mock-only readiness overclaim
active contract lacking executable behaviour or environment wiring
orphan operation, permission or role
implicit or wildcard grant
forbidden permission reachable through ABAC, delegation or token
cross-tenant leakage
operation/action/transport omission
state enumeration mistaken for transitions
provider/environment omission
positive-only tests
stale evidence or proof
source/live drift
secret leakage
supply-chain or licence violation
partial rollback
hidden cache or host-state dependency
unimplemented user, API, operator or automation journey
```

At least two independent final reviews are mandatory; the second reviewer is not shown the first conclusion before reporting.

Run the complete suite twice from independent clean temporary clones against the same authority digest. Require deterministic canonical outputs, inventories, matrices, plans, evidence-set digests and attestations except explicitly normalised volatile fields. Run a poisoned-state test. Flakiness is a defect, not a reason to rerun until green.

## 33. Checkpoint, handoff and usage-limit safe stop

Maintain the atomic JCS-canonical checkpoint at `.work/programme/checkpoint.json` and its verified sidecars using tracked regeneration commands. `.work/` is volatile and never the sole durable source of programme truth.

After each coherent wave, store durable semantic, implementation, evidence, proof and validation state in its authorised system, then write one compact checkpoint containing:

```text
goal and governing-document digests
repository HEAD, working-tree and patch digests
authority and candidate digests
current phase and semantic/executable node
inventory, census, universe, matrix and coverage digests
classified completed, reopened, actionable, superseded and blocked identifiers
changed paths and content digests
publication transaction outcome
evidence, proof and validation identifiers
dev/test/staging state
agent/worktree/branch ownership
process and transaction ownership
measured usage and cache status
unresolved findings
next exact semantic identifier, action and command
```

Before a model, context or execution limit prevents safe continuation:

1. finish the current atomic operation;
2. do not begin an operation that cannot be completed and reconciled;
3. run the smallest focused validation;
4. write and verify checkpoint and sidecars;
5. record exact next action;
6. verify Git, worktrees, stashes, CAS, processes and transactions;
7. leave no ambiguity or unowned state;
8. return a compact continuation report, not a terminal programme verdict.

## 34. Completion gates

All applicable gates must pass before overall completion.

### 34.1 Authority and semantic closure

```text
live authority health verified
final authority digest recorded
SHACL violations = 0
integrity violations = 0
contamination = 0
source/live drift = 0
unknown graph drift = 0
unexplained semantic resources = 0
unclassified capabilities or contracts = 0
silent inherited reuse = 0
implementation-derived semantic assumptions = 0
unjustified technology selections = 0
source paths treated as target architecture = 0
unreviewed nonclaims or deferred states = 0
proof-to-current-implementation mismatches = 0
directive and validator conflicts = 0
```

### 34.2 Semantic-exhaustiveness and permission closure

```text
active capabilities without family review = 0
mandatory facets without family review = 0
required families without finite dimensions = 0
candidate keys without cells = 0
cells outside the candidate universe = 0
duplicate cells = 0
cells without exactly one disposition = 0
active unresolved cells = 0
unauthorised deferred cells = 0
NOT_APPLICABLE cells without reason/proof = 0
operation/action omissions = 0
transport/interaction omissions = 0
WebSocket family omissions = 0
operations without permission atoms = 0
permission atoms without operation or retirement = 0
relevant role-permission cells without disposition = 0
active roles with zero reachable privilege = 0
required operations without eligible principal path = 0
unsatisfiable allowed paths = 0
forbidden cells with grant paths = 0
forbidden cells with token scopes = 0
over-broad token scopes = 0
wildcard privilege broadening = 0
cross-tenant privilege leakage = 0
invalid lifecycle transitions = 0
events without publish/consume authorisation = 0
provider/environment omissions = 0
required cells without coverage = 0
forbidden cells without negative coverage = 0
non-deterministic universe or digest results = 0
```

`PERMUTATION_CLOSURE_COMPLETE` is allowed only when all these counters are zero and the formal proof, fixtures, generated tests, validate-and-rollback, accepted publication, post-publication proof and zero-drift checks pass.

### 34.3 Executable repository closure

```text
all active contracts have repository-local executable realisations
repository artefacts without semantic derivation = 0
semantic obligations without delivered realisations = 0
implicit operational inputs = 0
unlocked external dependencies = 0
unmodelled configuration or secret interfaces = 0
origin-dependent knowledge = 0
semantic-to-artefact traceability gaps = 0
artefact-to-semantic traceability gaps = 0
external local-repository references = 0
specification-only active realisations = 0
missing implementation paths = 0
placeholder or no-op implementations = 0
all required source tracked in final Git tree
```

### 34.4 Environment closure

```text
dev builds, starts, becomes healthy and executes required journeys
test is isolated, deterministic and complete
staging is production-shaped and has no dev-only shortcut
migrations and seeds pass from empty state
services, workers and scheduled jobs execute
cross-service APIs, events and data contracts pass
backup, restore, restart, upgrade and rollback pass
teardown leaves no unauthorised residue
network-isolated rebuild succeeds
clean-clone hermetic failures = 0
```

### 34.5 Evidence, proof and validation

```text
mandatory evidence admitted, fresh, integrity-valid and applicable
mandatory proofs current and successful
results bind exact evidence, source, authority, decision, configuration, environment, provider, persistence, migration, interface and dependency scope
failed or stale results retain lineage and cannot activate contracts
CAS payloads verify
all planted defects rejected by intended gates
all required unit, contract, integration and end-to-end tests pass
all required user, API, operator and automation journeys pass
all rollback and recovery tests pass
two clean-room runs pass
canonical outputs and digests are deterministic
security, licence, dependency, provenance and signature gates pass
```

### 34.6 Independent review and repository state

```text
two independent final reviews complete
critical findings = 0
high findings = 0
claim-affecting unresolved medium findings = 0
all resolved findings have regression tests or semantic constraints
executable and semantic audits have zero actionable in-scope gaps
no unauthorised external-work dependency or identity
no stash
no stray worktree, branch or unintegrated commit
no temporary repository artefact
no unowned process or transaction
```

## 35. Forbidden shortcuts

Never claim completion by:

```text
landing semantics or matrices without executable behaviour
pointing implementation paths at an earlier repository
stopping when a work-plan query returns no rows
calling a reference implementation the suite
using a cache as the only source of implementation bytes
creating orchestration without exercising complete behaviour
using tests as proof without evidence admission
using hermetic evidence as live-provider evidence
creating a report instead of an authoritative result
leaving active contracts without implementations
leaving implementations outside environment deployment
skipping negative cases, matrix cells or adversarial review
accepting nondeterministic output
calling raw throughput delivery progress
weakening semantics, least privilege, security or tests to finish faster
```

## 36. Finalisation, commit and report

After all gates pass:

1. archive final runtime evidence in CAS;
2. publish final evidence, proof, contract, realisation, validation and permutation metadata through the compiler transaction;
3. verify final authority, permutation proof and source/live drift;
4. rerun post-publication proof and adversarial checks;
5. run two standalone-clone acceptance passes and poisoned-state test;
6. remove authorised ephemeral state;
7. inspect the complete Git diff and exclude unrelated user work;
8. create the final commit with authority, evidence-set, repository-source and permutation-universe digests in the body;
9. push only with direct current user authorisation;
10. report the exact commit and final authority digest.

The final report contains:

```text
terminal and permutation-closure verdicts
initial and final repository HEAD
initial and final authority digests
GOAL.md digest
commits integrated
files created, modified and removed
semantic queries and publications
capabilities and facets reviewed
permutation families and dimensions
candidate and materialised cell counts
counts by disposition
action and transport counts
permission atoms
roles and role-permission cells
authorisation paths and reachability counters
token profiles and scopes
positive and negative generated tests
coverage, evidence and proof digests
SHACL, integrity and drift results
performance and scale measurements
dev/test/staging results
adversarial findings
residual risks and explicit nonclaims
complete measured token totals
cache creation and cache-read totals
cache reuse percentage
agent counts and agent token totals where available
final Git, worktree, stash, CAS, process and transaction state
```

Do not paste unbounded logs or payloads. Report verified identifiers, counts, digests and locators.

## 37. Success condition

The programme succeeds only when the entire current semantic suite has been traversed, every meaningful operational and authorisation permutation has been explicitly dispositioned and proved, every required operation has a satisfiable least-privilege principal path, fine-grained token scopes cannot exceed those paths, and the repository contains the complete executable implementation required to run and demonstrate the suite in development, deterministic test and production-shaped staging.

The final authority must warrant the completion claim, and two standalone clean clones must independently prove it without an earlier repository, parent checkout, untracked source, hidden agent cache, external work tracker or conversational history.
