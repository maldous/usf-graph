# GOAL.md — Complete Initial USF Realisation Programme

## 1. Purpose

This file directs a long-running, restartable and predominantly unattended programme to deliver the first complete realisation and integrated evaluation of the Universal Service Foundation suite.

The programme must continue until every semantic item within the live USF scope has a defensible terminal classification and every in-scope actionable contract has been modelled, evidenced, proved, activated where warranted, realised, validated and re-evaluated against live semantic authority.

This file is an authored agent directive. It is not semantic authority. It cannot activate a contract, authorise a path, establish evidence, prove a claim, select a realisation or declare readiness. Validated live semantic state remains authoritative.

The required lifecycle is:

```text
Model
  → Evidence
  → Proof
  → Contract
  → Realisation
  → Validation
  → newly admitted Evidence
  → re-evaluated Proof and Contract state
```

The programme is not complete merely because code exists, tests pass, a report says ready, a ticket is closed, or an earlier implementation appears suitable.

## 2. Terminal outcomes

End with exactly one terminal outcome:

```text
USF_INITIAL_SUITE_REALISATION_COMPLETE
USF_INITIAL_SUITE_REALISATION_BLOCKED_IRRECOVERABLY
```

`USF_INITIAL_SUITE_REALISATION_COMPLETE` is permitted only when every completion gate in this file passes.

`USF_INITIAL_SUITE_REALISATION_BLOCKED_IRRECOVERABLY` is permitted only when further progress requires an unavailable credential, explicit human/legal acceptance, paid or irreversible external action not already authorised, inaccessible mandatory external evidence, an unexplained authority conflict, or an infrastructure limit that cannot be removed through an authorised self-healing or authority-migration path.

Routine ambiguity, test failures, missing code, incomplete semantics, missing evidence collectors, proof failures, Stardog query failures, transaction rollback, stale evidence, missing Linear issues, or architectural decisions are not irrecoverable blockers. Resolve them and continue.

## 3. Instruction precedence and authority

Read and obey, in this order:

1. Direct user instructions for this run.
2. `AGENTS.md`.
3. `CODEX.md`.
4. The loaded USF skill.
5. This `GOAL.md`.
6. Current digest-bound contract packets and focused live queries.
7. Repository source, tests, ADRs, reports and Linear tickets as non-authoritative inputs.

Where prose conflicts with live semantic authority, stop the conflicting action, repair or clarify the semantic model through the authorised lifecycle, and continue only from the new validated authority.

Never infer semantic truth from graph source files. Graph source is the registered materialisation used to update authority through the compiler transaction.

## 4. Execution mode for this programme

This programme deliberately uses one repository checkout on `main`.

Required execution model:

```text
branch:                 main
Git worktrees:          no new worktrees
modifying subagents:    prohibited
repository writer:      top-level coordinator only
Stardog writer:         top-level coordinator only
read-only subagents:    permitted
intermediate commits:   prohibited
final commit:           only after every completion gate passes
push or pull request:   prohibited unless separately authorised
Git stash:              prohibited
```

This does not conflict with the modifying-worker worktree rule because no worker may modify files. Workers inspect, query, test, challenge and return compact findings or proposed patches. The coordinator applies every repository change sequentially in the primary checkout.

Do not reset, clean, discard, overwrite or delete unknown or user-owned work.

Temporary clean-room evaluation copies may be created under `/tmp`. They must not be Git worktrees and must contain no credentials, `.git` directory, `.work` state or CAS payloads unless a test explicitly requires a bounded verified payload.

## 5. Unattended-operation rule

Do not ask the user to make routine implementation, architecture, ordering, test, naming, remediation or retry decisions.

Resolve decisions by:

1. querying current authority;
2. collecting relevant evidence;
3. evaluating credible options;
4. recording claims and nonclaims;
5. creating and evaluating the required proof;
6. authoring an accepted decision only when warranted;
7. validating the resulting realisation.

Do not pause after creating a Linear issue. Issue creation records work; it does not complete it. Continue the work unless the issue represents a genuinely irrecoverable external or human dependency.

Do not emit “standing by”, “waiting for the lock”, “will continue later”, or equivalent output while a safe recovery action remains available.

## 6. Restartable programme state

Maintain an atomic, JCS-canonical programme ledger at:

```text
.work/materialisation/goal/goal-state.json
```

The ledger is generated, untracked and non-authoritative. It must contain at least:

```text
schemaVersion
goalFileDigest
initialRepositoryHead
initialWorkingTreeDigest
initialAuthorityDigest
currentAuthorityDigest
currentPhase
currentWave
currentWorkItem
suiteInventoryDigest
contractLedger
capabilityLedger
evidenceLedger
proofLedger
realisationLedger
validationLedger
adversarialFindingLedger
linearIssueMap
attemptLedger
publicationLedger
checkpointLedger
lastSafeCheckpoint
terminalState
```

Write updates atomically through a temporary file and rename. Never leave partially written state.

Before every live authority publication, create a pre-publication recovery checkpoint containing the exact intended registered-source patch, changed-file digests, previous authority witness and expected post-publication graph/digest changes. Verify this checkpoint before opening a transaction.

At each safe checkpoint, preserve outside Git:

```text
current authority witness and digest
canonical inventory summary
JCS programme ledger
binary-capable Git diff or equivalent working-tree patch
patch digest
changed-file digest manifest
relevant CAS payload descriptors
test and validation result manifest
owned Stardog transaction/query inventory
```

Store checkpoint payloads in the operator-local CAS where suitable. The small descriptor, digest and locator may enter Stardog only through the evidence lifecycle when required.

On restart:

1. read `GOAL.md` and compute its digest;
2. inspect the working tree without modifying it;
3. load the ledger when present;
4. verify ledger, patch and authority digests;
5. reconcile only changes proven to belong to this programme;
6. resume from the last safe checkpoint;
7. never duplicate an admitted evidence result, proof result, Linear issue or completed realisation.

A changed `GOAL.md` digest requires a compatibility review of existing programme state before resumption.

## 7. Initial preflight

Before modification:

1. Confirm the repository is `maldous/usf-graph`.
2. Confirm the branch is `main`.
3. Record HEAD and upstream state.
4. Inspect status, ignored state, stashes, branches and worktrees.
5. Explain every pre-existing modification or untracked path.
6. Treat `GOAL.md` as user-owned input.
7. Confirm no other process is modifying this checkout.
8. Confirm required environment variables are present without printing their values.
9. Confirm the operator-local CAS is outside Git and writable.
10. Load the USF skill.
11. Call `usf_health`.
12. Call `usf_bootstrap` exactly once with the task:

```text
Complete the first end-to-end realisation and adversarial evaluation of the entire live USF suite.
```

Reuse that bootstrap orientation throughout the programme. After authority changes, do not call bootstrap again; invalidate stale packets and obtain fresh authority witnesses, focused queries, layout context and contract projections.

If the working tree contains unexplained state, do not modify it. Attempt to attribute it from programme checkpoints and repository history. Stop only when ownership cannot safely be determined.

Fetch remote metadata without merging. If `origin/main` advances during the programme, stop repository writes and evaluate the change in a clean temporary clone. Continue only when the remote change is proven disjoint and can be integrated without discarding, stashing or ambiguously rewriting programme/user work. Otherwise classify it as an unexplained repository-authority conflict and use the blocked outcome.

## 8. Validate this directive as a materialisation

Using live layout context, classify `GOAL.md` as an authorised root Markdown agent directive or repository document.

Validate its exact path, representation format and content digest through a bounded materialisation plan and dry run. Do not rewrite the file during this validation.

If the current semantic model cannot authorise `GOAL.md`:

1. record the missing materialisation rule as the first semantic gap;
2. define the minimum nonduplicative semantic rule for this root directive;
3. add shapes and planted defects;
4. collect evidence and evaluate proof;
5. publish through the compiler transaction;
6. regenerate the layout context;
7. validate `GOAL.md` again;
8. continue only after the path and representation are live-authorised.

The presence of this human-created file does not retroactively make its materialisation authoritative.

## 9. Establish the complete live suite inventory

Do not limit the programme to the first actionable contract or to gaps returned by `usf_work_plan`.

Build a complete, paginated and digest-bound inventory of at least:

```text
capabilities and capability domains
semantic contracts and facets
claims and nonclaims
policies and constraints
interfaces, operations, commands, events and workflows
data contracts and controlled values
provider modes, services, bindings and environments
permissions, tenancy and privacy boundaries
controls, risks and enterprise obligations
UI exposure, journeys and interaction semantics
evidence requirements, results, admissions and payload descriptors
proof obligations, algorithms, executions, evaluations and results
contract activation and supersession states
realisation options, decisions, implementations and realisations
validation obligations, validators, executions and results
artifact families, representation formats, path roles and materialisation rules
derivation, integrity, contamination and readiness resources
```

Use deterministic pagination and focused queries until the complete result set is accounted for. Bounded gateway output is a transport constraint, not permission to omit the remainder.

For every resource, record:

```text
semantic identifier
canonical name
owning contract or capability
lifecycle state
blocking dependencies
claims and nonclaims affected
required evidence and proof
current realisation state
required validation
current gap classification
```

Classify every contract into exactly one current state:

```text
ACTIVE_REALISATION_VALIDATED
ACTIVE_REALISATION_MISSING
ACTIVE_REALISATION_INVALID
ELIGIBLE_NOT_ACTIVE
PROOF_BLOCKED
EVIDENCE_BLOCKED
MODEL_INCOMPLETE
SUPERSEDED
RETIRED
EXPLICITLY_OUT_OF_SCOPE
EXTERNAL_OR_HUMAN_BLOCKED
```

No contract or capability may remain unclassified at completion. `EXPLICITLY_OUT_OF_SCOPE`, `SUPERSEDED` and `RETIRED` classifications require explicit live semantic state or a current contract nonclaim; the coordinator may not use them merely to reduce work.

The programme scope is the transitive closure of the live USF suite at the initial authority digest plus semantic resources necessarily introduced to satisfy its existing obligations. Do not add unrelated capabilities or speculative product scope. Any deliberate scope expansion requires an explicit model, claim/nonclaim boundary, evidence, proof and contract decision.

Compute and retain a canonical suite inventory digest.

## 10. Build the closure graph

Construct a dependency graph from live semantic relationships rather than ticket order or file order.

Include dependencies involving:

```text
model definitions and controlled values
evidence requirements and collectors
proof algorithms and prerequisite proofs
contract activation
realisation decisions
path and representation authorisation
provider/environment availability
implementation dependencies
validation obligations
readiness and release gates
```

Detect and resolve:

```text
cycles
orphan requirements
orphan obligations
contracts without capabilities
capabilities without contracts
active contracts without proof
active contracts without realisations
realisations without accepted decisions
validations without evidence admission
readiness inferred from partial or existential satisfaction
```

Plan work in topological waves. A wave may contain many read-only investigations in parallel, but repository and authority writes remain sequential and coordinator-owned.

Always select the next work item by semantic dependency and blocking impact. Do not select by apparent ease alone.

## 11. Contract closure state machine

For each in-scope contract, call `usf_contract_project` with the exact contract IRI and current objective before implementation or validation. Verify the packet authority digest and stop conditions. Regenerate it after every authority change. Then execute the following state machine until the contract reaches a valid terminal classification.

### 11.1 Model

Verify that the model defines, where applicable:

```text
semantic subject and ownership
claims and nonclaims
features and constraints
states and transitions
permissions and boundaries
interfaces and operations
data and error semantics
provider and environment scope
positive, negative and failure behaviour
required evidence
proof obligations and minimum rungs
permitted realisation types
required validation
readiness and invalidation consequences
```

Do not infer missing product behaviour from old code, tickets or convention.

When semantics are missing but can be derived from existing authoritative relationships and admitted evidence, add the minimum coherent definitions, shapes, rules and fixtures.

When semantics require a genuine product, legal or human-policy decision that cannot be derived, create or update a Linear issue and classify the contract as externally blocked. Do not invent the decision.

Every semantic change requires positive fixtures and adversarial planted defects.

### 11.2 Evidence

For every evidence requirement:

1. identify the exact subject, claim and obligation;
2. implement or select a collector when absent;
3. collect in the required environment and provider mode;
4. normalise deterministically;
5. store large or binary payloads in the operator-local CAS;
6. use Parquet for large tabular evidence where authorised;
7. produce a JCS-canonical evidence manifest;
8. produce an evidence envelope containing digest, media type, size, locator, producer, environment, collection time, expiry, applicability, admission, freshness, integrity, retention and supersession;
9. verify payload bytes against the descriptor;
10. admit only fresh, integrity-valid and applicable evidence.

A filename, report, test result or Linear attachment never establishes evidence by itself.

Do not store unbounded payloads in Stardog or Git.

### 11.3 Proof

For every proof obligation:

1. identify or implement a versioned proof algorithm under an authorised path;
2. bind it to an exact admitted evidence set;
3. compute the evidence-set digest;
4. run it in the required environment/provider scope;
5. record algorithm version, validator, environment, result, confidence basis, uncertainty, nonclaims, evaluation time and invalidation conditions;
6. emit a JCS evidence/result manifest;
7. emit an in-toto Statement and DSSE envelope when required;
8. store raw logs and attestations in CAS;
9. create the authoritative proof result in registered semantic source;
10. publish transactionally;
11. verify the result from live authority.

Confidence must be warranted by a successful proof against the exact admitted evidence set. Never author confidence as an analyst or AI opinion.

A failed proof blocks activation. Repair the model, evidence, algorithm or implementation; then rerun with a new result. Do not edit a failed result into success.

### 11.4 Contract

A contract may become active only when all mandatory obligations have current successful proof results and no blocking finding remains.

The contract must explicitly record:

```text
claims and nonclaims
features and constraints
proof results relied upon
confidence and uncertainty basis
permitted realisation types
required validation
activation state and reason
suspension and invalidation conditions
supersession lineage
```

Generate bounded contract projections for consumers. Projections are cacheable inputs, never authority, and become stale when the authority digest changes.

### 11.5 Realisation decision

For each active contract without a valid realisation, evaluate credible options rather than defaulting to new code:

```text
retain or adapt existing local code
consolidate existing code
maintained package
managed service
external product
composed solution
new local code
no local code where the contract requires only a binding or decision
```

Evaluate options using admitted evidence for:

```text
semantic fit
security
maintainability
licensing
operational cost
portability
performance
resource limits
supply-chain risk
provider and environment compatibility
validation feasibility
exit and migration cost
```

Record rejected alternatives and nonclaims. Author an accepted decision only when evidence and proof warrant it.

Before materialising a path or selecting a format, retrieve current layout context and use an authority-bound materialisation plan.

Create `realisations/` only when a specific accepted decision selects a local-code realisation and authorises its containment model.

### 11.6 Implementation

Implement the minimum complete realisation satisfying the active contract.

Requirements:

```text
no guessed domain behaviour
no unauthorised paths or formats
no hidden paid services
no secret material in source or output
no broad compatibility layer without a contract requirement
no speculative future features
no test-only implementation shortcuts
no report-derived truth
```

Generate or implement tests and proof assets in the order required by the contract. Existing code has no automatic priority.

Use ecosystem-native filenames inside an authorised local-code boundary. Governance artifacts use the selected eight-digit family-scoped naming model. Content-addressed payloads use their digest.

### 11.7 Validation

Run all contract-required validation, including applicable:

```text
static checks and type checks
unit tests
contract tests
integration tests
state-transition and permission tests
negative and adversarial tests
SHACL and integrity checks
contamination checks
derivation parity and determinism
rollback and failure injection
security and dependency checks
provider-mode and environment checks
accessibility and localisation checks
performance and resource bounds
backup, restore and migration checks
clean-room or isolated execution
```

Each execution produces a `ValidationResult` that enters the evidence lifecycle. A passing local test does not by itself activate, prove or validate a live claim.

After validation evidence is admitted, re-evaluate dependent proofs and contract states.

## 12. Stardog mutation and self-healing protocol

All semantic mutations are coordinator-only and occur through registered authored graph source plus:

```text
tools/compiler/bin/publish-authority.sh
```

Never issue direct mutation SPARQL through MCP, raw HTTP, Stardog CLI or an ad hoc script.

Before every publication:

```text
verify repository and source preconditions
verify current live authority witness
verify no unexplained drift
verify owned open transactions and queries
run local checks and compiler tests
run local RDF/SHACL/integrity validation where available
build the exact intended semantic delta
invalidate stale materialisation plans and packets
```

After every successful publication:

```text
record the new authority digest
verify SHACL, integrity, contamination and derivations
verify source/live drift is zero
verify expected graph inventory
invalidate every old packet and plan
regenerate focused contract packets
update the programme ledger and Linear issues
create a safe checkpoint
```

### 12.1 Failure classification

Classify each failure before acting:

```text
TRANSIENT_TRANSPORT
RATE_OR_QUOTA_LIMIT
QUERY_TIMEOUT
TRANSACTION_CONFLICT
TRANSACTION_TIMEOUT
AMBIGUOUS_COMMIT
STALE_PACKET_OR_PLAN
SOURCE_LIVE_DRIFT
SHACL_VIOLATION
INTEGRITY_VIOLATION
CONTAMINATION
DERIVATION_MISMATCH
MODEL_GAP
EVIDENCE_GAP
PROOF_FAILURE
IMPLEMENTATION_DEFECT
VALIDATION_DEFECT
CAS_INTEGRITY_FAILURE
EXTERNAL_PROVIDER_FAILURE
CREDENTIAL_OR_PERMISSION_FAILURE
RESOURCE_EXHAUSTION
UNKNOWN
```

### 12.2 Recovery rules

#### Transient transport, rate and service failures

Use at most five retries with increasing delay and jitter, respecting any server `Retry-After` signal. Recheck health before every retry. Record each attempt. Do not replay a mutation whose outcome may already have committed. Exhausting these retries triggers diagnosis and an alternative recovery path, not blind repetition.

#### Query timeout

Cancel only an owned query where supported. Reduce query scope, add selective bindings, inspect the query plan, precompute safe intermediate data locally, or rewrite the query with proven semantic equivalence. Never weaken a constraint merely to finish faster.

#### Transaction conflict or timeout

Rollback the exact owned transaction when its outcome is known. Verify closure and unchanged live state. Rebuild the delta against the current authority digest before a new attempt.

#### Ambiguous commit

Do not call commit again. Determine the result through read-only graph counts, canonical digests, authority witness and transaction visibility. Classify as committed, rolled back or irrecoverably ambiguous before proceeding.

#### Unknown transaction or lock

Never rollback, kill or alter another owner’s transaction or query. Stop only when the unknown state cannot be safely attributed or allowed to expire without risking authority.

#### SHACL, integrity, contamination or derivation failure

Capture a bounded normalized finding. Reproduce locally with a minimized fixture. Determine whether the defect belongs to model, data, shape, rule or implementation. Repair the semantic cause, add a planted defect, rerun all affected validations and republish.

#### Stale evidence or proof

Collect new evidence, retain supersession lineage, create a new proof evaluation/result, and allow dependent contracts to suspend until reevaluation succeeds.

#### CAS integrity failure

Quarantine the invalid local bytes. Never overwrite an object at an existing digest. Regenerate from the authoritative producer, verify bytes, create a new descriptor when content changes, and invalidate dependent evidence.

#### Resource exhaustion

Clean only authorised ephemeral state. Preserve admitted evidence and retained CAS payloads. Optimise indexes, batching, projections and query plans. Externalise large data rather than deleting semantic envelopes or weakening proof.

#### Stardog Cloud tier exhaustion

First attempt, with proof:

```text
minimal graph deltas
precomputed derived outputs
bounded validation queries
external CAS payloads
query optimisation
transaction reduction
retention/supersession cleanup permitted by policy
```

If the tier still prevents the required suite from completing, initiate a semantic store portability and authority-migration workstream. Evaluate at least RDF4J NativeStore plus ShaclSail as the primary local candidate and Jena as an independent oracle. Prove named-graph, canonical-digest, SPARQL, SHACL, transaction, rollback, derivation, integrity, backup and gateway parity. Stardog remains authority until a migration contract is active and cutover is validated. Never create split-brain authority.

#### External-provider failure

Use hermetic, sandbox or composed evidence only where the obligation permits it. Never infer live readiness from hermetic evidence. If mandatory live evidence cannot be obtained, create/update the exact Linear blocker and use the blocked terminal outcome.

#### Unknown failure

Preserve state, minimize reproduction, obtain independent read-only diagnosis, and continue only after the failure is classified. Do not blindly retry.

## 13. Linear work projection

Linear tracks work and never establishes truth.

At baseline and after every semantic publication:

1. run `usf_work_plan` for relevant contracts;
2. run broader focused semantic-gap queries because `usf_work_plan` is not an exhaustive suite auditor;
3. search Linear before creating an issue;
4. update the existing issue when it represents the same semantic resource and gap;
5. create an issue only when no current issue represents the gap;
6. cancel superseded ticket-driven work;
7. mark Done only after the live semantic gap is closed and required validation is admitted;
8. keep human/external blockers visible without treating them as authority.

Each issue must include:

```text
current authority digest
semantic resource identifiers
gap classification
why the gap is actionable
claims and nonclaims affected
authorised paths and formats
required evidence and proof
acceptance and validation obligations
stop conditions
link back to current contract projection or retrieval instruction
```

Never paste the entire contract as permanent ticket truth. Direct the next agent to retrieve current authority.

Issue creation is followed by execution in the same programme unless the issue represents an irrecoverable blocker.

## 14. Parallelism and authentic independent review

Use at most eight active agents and delegation depth at most two.

All subagents are read-only. They may run tests in isolated temporary copies, inspect live authority, evaluate options and return proposed patches, but they may not modify the primary checkout, create branches/worktrees, commit, push, mutate Linear or mutate Stardog.

Use compact digest-bound packets.

For major waves, commission independent roles such as:

```text
semantic authority and inversion auditor
evidence admission and proof-fraud auditor
contract completeness and overclaim auditor
implementation security and reliability auditor
test quality, determinism and rollback auditor
repository/CAS/materialisation auditor
operations, Linear and Git hygiene auditor
user-surface and integration coverage auditor
```

Authenticity requirements:

1. A reviewer must not rely solely on reports generated by the implementation under review.
2. At least one reviewer must reconstruct critical counts, digests and closure independently.
3. Reviewers receive live identifiers and requirements, not the coordinator’s conclusion.
4. At least one final reviewer must not receive the prior final-review report before submitting findings.
5. Findings include evidence, affected semantic resources, severity and a falsifiable remediation criterion.
6. Every critical, high or claim-affecting medium finding reopens the relevant lifecycle stage.
7. “No finding” is accepted only when the reviewer states what was tested and what remains a nonclaim.

## 15. Mandatory adversarial attack catalogue

Actively attempt to prove the programme incomplete or unsound.

At minimum test for:

```text
a ticket, report, ADR, source file or test treated as authority
authored evidence, proof, readiness or validation outcomes
active contracts without all mandatory current proofs
proof results bound to stale, inadmissible or inapplicable evidence
confidence without an exact successful evidence-bound proof
contract activation from existential rather than universal satisfaction
realisation without an accepted decision
code or paths materialised before authorisation
package/service decisions that unnecessarily create local code
hidden parent-repository or census dependency
cross-graph authority violations
undefined or unused unexplained terms
shape, rule, registry and manifest disagreement
stale derived output or nondeterministic generation
positive-only tests that fail to detect planted defects
rollback that leaves partial filesystem or semantic mutations
ambiguous transaction replay
credentials or raw provider errors in output
CAS locator, size or digest mismatch
unbounded payload in Git or Stardog
live-readiness claims from hermetic evidence
accessibility, localisation, privacy or security overclaims
provider, environment or tenant mismatch
unhandled state, error or negative path
release without provenance, SBOM or signature where required
Linear status used as completion evidence
stale contract packets surviving an authority change
resource limits silently weakening assurance
```

Seed representative defects after implementation and require the appropriate validator to reject each one exclusively.

## 16. Testing cadence

Run focused validation after every change.

Run an integrated wave gate after every dependency wave:

```text
compiler check
compiler test suite
schema validation
fixture suite
SHACL
integrity
contamination
derivation determinism
materialisation tests
CAS verification
affected proof algorithms
affected contract projections
source/live drift
```

Run a complete suite gate before final review.

Run the complete suite twice from clean temporary copies and the same authority digest. Require identical canonical semantic outputs, materialisation plans, evidence-set digests and attestations except for explicitly modelled volatile fields. Volatile values must be excluded from semantic digesting or normalised according to a proven rule.

Flaky tests are defects. Identify and remove nondeterminism; do not rerun until green and call it passed.

## 17. Whole-suite first evaluation

After every contract is closed or validly classified, perform the first integrated evaluation of the realised USF suite.

Evaluate at least:

```text
repository bootstrap and standalone operation
semantic gateway and bounded agent packets
complete capability-to-contract coverage
model/evidence/proof/contract/realisation/validation traceability
all local-code, package and service realisations
cross-realisation interfaces and data contracts
provider and environment matrices
permissions, tenancy, privacy and security boundaries
error, retry, timeout and failure behaviour
proof and evidence lifecycle
CAS retention and verification
materialisation and rollback
compiler publication and live drift
clean-room reproducibility
build and test orchestration
release, provenance, SBOM and signature obligations
UI/API/automation exposure classifications
enterprise/control claims and explicit nonclaims
operational resource limits
Linear projection and zero-gap reconciliation
```

The evaluation must produce:

```text
a JCS-canonical suite evidence manifest
an exact suite evidence-set digest
an in-toto Statement
an applicable DSSE signature
a machine-readable contract/realisation/validation inventory
a bounded human-readable evaluation projection
a normalized adversarial finding report
all external payload descriptors
```

Store large outputs in CAS. Admit the required envelopes and results into Stardog. Do not commit runtime evaluation output unless a live contract explicitly authorises a tracked representation.

## 18. Completion gates

All of the following must pass before the complete verdict.

### Authority and semantic closure

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

### Evidence and proof

```text
all mandatory evidence admitted, fresh, integrity-valid and applicable
all mandatory proof obligations have current successful results
all successful results bind exact evidence-set digests
all confidence is warranted and current
all failed/stale results retain lineage and cannot activate contracts
all referenced CAS payloads verify
```

### Contracts and realisations

```text
all in-scope warranted contracts are active
all active contracts have accepted realisation decisions
all required active contracts have valid realisations
all paths, formats, packages and services are authorised
all contract claims are supported
all nonclaims are preserved
no local-code directory exists for a non-local realisation
```

### Validation and integration

```text
all required ValidationResults pass and are admitted
all planted defects are rejected by the intended gate
all integration and cross-realisation tests pass
rollback and recovery tests pass
clean-room runs pass twice
canonical outputs and digests are deterministic
security and dependency gates pass
release/provenance/signature gates pass where required
```

### Adversarial review

```text
at least two independent final review rounds completed
second final reviewer unanchored by first report
critical findings = 0
high findings = 0
claim-affecting unresolved medium findings = 0
all resolved findings have regression tests or semantic constraints
```

### Work and repository state

```text
current semantic work projection has zero in-scope actionable gaps
no duplicate or stale Linear issue remains actionable
main contains only intended programme changes
no new branch or worktree exists
no stash exists
no temporary repository artifact remains
all checkpoint and runtime output is outside Git
```

### Final evidence

```text
final suite evidence manifest verified
final exact evidence-set digest recorded
final DSSE/in-toto attestation verified
post-publication proof rerun against final authority passes
final contract packets regenerate from final authority
```

## 19. Finalisation and commit

Only after every completion gate passes:

1. archive final runtime evidence in CAS;
2. publish final evidence, proof, contract, realisation and validation metadata through the compiler transaction;
3. verify final authority and drift;
4. rerun the post-publication proof and final adversarial checks;
5. remove authorised ephemeral state that is no longer required while preserving the final ledger and checkpoint outside Git;
6. inspect the complete Git diff;
7. verify no unrelated user change is included;
8. create the final commit on `main` with the final authority digest and suite evidence-set digest in the commit body;
9. do not push unless separately authorised;
10. report the exact commit and final live authority digest.

Do not create intermediate commits merely for convenience.

If the final commit cannot be created safely, retain the validated working tree and checkpoint, classify the programme as blocked, and do not discard completed work.

## 20. Final report

Return a compact structured report containing:

```text
initial and final repository HEAD
initial and final authority digests
GOAL.md digest
suite inventory count and digest
contracts by terminal classification
capabilities by terminal classification
semantic changes published
realisations selected and delivered
paths and formats materialised
evidence manifest and payload digests
proof algorithms and result digests
validation executions and results
Stardog failures and self-healing actions
store-migration activity, if any
Linear issues created, updated, completed or canceled
adversarial review rounds and findings
complete test and clean-room results
final suite evidence-set digest
final attestation digest
final commit
remaining explicit nonclaims
final Git, worktree, stash, CAS and transaction state
```

Do not paste unbounded logs or payloads. Report their digests and verified locators.

## 21. Forbidden completion shortcuts

Never claim completion by doing any of the following:

```text
implementing only the first actionable contract
stopping when usf_work_plan returns no rows
assuming bounded bootstrap output is the whole suite
closing Linear tickets without closing semantic gaps
marking draft or proof-blocked work out of scope without authority
using tests as proof without evidence admission
using local validation as live-provider evidence
weakening SHACL or integrity to obtain conformance
skipping negative cases or adversarial review
accepting nondeterministic output
leaving active contracts without realisations
leaving realisations without validation
leaving validation outside the evidence lifecycle
creating a report instead of an authoritative result
storing large payloads in Stardog or Git
introducing paid/cloud infrastructure without a separate accepted decision
silently abandoning work after a timeout, rollback or quota limit
committing partial progress and declaring a milestone complete
```

## 22. Token efficiency policy

Apply the following token-efficiency policy:

Treat conversational history as temporary working memory. Treat Stardog, Git, the CAS, Linear, and the programme ledger as persistent state.

After completing each contract or tightly coupled contract group:

1. Publish or record all durable semantic, implementation, evidence, proof, validation, and work-tracking state in its authorised system.
2. Write an atomic, digest-bound checkpoint containing only:
   - current authority digest;
   - completed contract IRIs and final states;
   - changed paths and content digests;
   - admitted evidence and proof-result identifiers;
   - validation results;
   - unresolved blockers;
   - next actionable contract or selection query;
   - repository status.
3. Remove raw contract packets, long query outputs, test logs, diffs, reports, and worker transcripts from the active task ledger once their durable digests and locations are recorded.
4. Do not restate completed work in subsequent prompts or worker packets.
5. Before starting the next contract, regenerate its current "usf_contract_project" packet from live authority. Do not reuse a packet whose authority digest predates any publication.
6. Retrieve only exact identifiers, predicates, files, and line ranges needed for the current contract.
7. Send workers only compact contract-specific packets. Workers must return structured findings, changed paths, digests, result codes, and residual risks, never narrative transcripts.
8. Store large logs, reports, manifests, attestations, and diagnostic payloads in the CAS. Keep only their descriptors and digests in active context.
9. Prefer machine-readable summaries over pasted command output. On successful commands, retain only the command, exit state, result digest, counts, and timing.
10. On repeated failures, retain one normalized failure signature and the latest materially different evidence. Do not carry duplicate stack traces or repeated diagnostic output.
11. Re-query current state rather than relying on old conversational descriptions.
12. Do not rerun exhaustive inventory or foundational analysis unless the authority digest or affected semantic dependencies changed.
13. Maintain a compact rolling programme ledger under the authorised generated-work path. Replace it atomically rather than appending an unbounded diary.
14. Before context pressure becomes material, finish the current atomic unit, persist the checkpoint, and return a continuation-ready status rather than beginning another contract with incomplete context capacity.

The checkpoint must be sufficient for a fresh Codex invocation to continue using only:

Read AGENTS.md, CODEX.md, GOAL.md, and the latest programme checkpoint.  Verify its authority and repository digests.  Continue GOAL.md from the recorded next action.

Do not assume MCP output is token-free. Every packet and query result must earn its place in active context.

Optimisation must not weaken semantic completeness, proof depth, validation, adversarial review, or fail-closed behavior.

## Note

The programme succeeds only when the entire current semantic suite has been traversed, every in-scope gap has been closed through the lifecycle, the integrated suite has been independently attacked and revalidated, and the final authority itself warrants the completion claim.
