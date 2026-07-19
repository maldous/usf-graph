# GOAL.md — Complete Executable USF Suite Delivery Programme

## 1. Purpose

This file directs a long-running, restartable and predominantly unattended programme to deliver a complete, executable, repository-local realisation of the Universal Service Foundation suite.

The programme is not complete when it has only produced semantic contracts, JSON specifications, graph resources, generated packets, reports, reference-implementation demonstrations, adapters that do not execute the required behaviour, or references to code in another repository.

Completion requires a standalone clone of the current programme repository to contain all source code, configuration, migrations, seeds, selected orchestration definitions, test assets, proof assets and operational tooling necessary to build and run the complete in-scope suite in development, test and production-shaped staging modes without access to the original or parent repository.

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

## Programme Remedial History

This history explains why the programme is open. It is not semantic authority and must not be used to retain an inherited decision.

1. The initial programme produced semantic specifications whose provenance and source-equivalence bindings referred to an earlier source repository.
2. Its first completion definition did not require complete repository-local executable delivery.
3. A later executable attempt reused inherited implementation paths, repository structure, package boundaries and technology assumptions before independently deriving them from complete current semantics.
4. Directory, filename, capability, technology and implementation boundaries therefore lacked independent counterfactual justification.
5. That executable-realisation attempt was rejected and marked `SUPERSEDED_FOR_HERMETIC_SEMANTIC_REDERIVATION`.
6. Programme-owned files were removed from the checkout and recoverably quarantined; unpublished semantic renames and broad path-authority edits were restored exactly to HEAD.
7. No evidence, proof, validation or completion claim from that rejected design may be admitted. Existing historical lineage remains preserved but cannot warrant current delivery.
8. The complete programme is reopened for hermetic semantic re-derivation, corrected authority publication and repository-local executable delivery.

## Current Verified Programme State

This is durable orientation, not volatile execution state. Exact GOAL, checkpoint,
ledger, patch, process and transaction digests are resolved through the verified
sidecars at `.work/programme/*.sha256`; embedding those changing digests here
would create a circular or stale directive. The checkpoint is execution state;
this file is programme authority subordinate only to live semantic authority.

```text
current committed HEAD:          resolved through the verified checkpoint (parent milestone 9670309d0d217eb7388ca7d76796c183b3ffc2f3)
current live authority:          sha256:aa7d94bad4fdb5f08ee08cab0e2a29596c90c39560358d05cf1465b1ca3798dd
current managed candidate:       sha256:7d260e5f743d35ff3bf460f133ceb6e1218d0c3615806d84d8e7d2c6266d0082
checkpoint:                      .work/programme/checkpoint.json(.sha256); regenerated from nothing by node operations/programme/update-checkpoint.mjs
programme ledger:                .work/programme/programme-ledger.json(.sha256)
contamination inventory:         6,458 rows; sha256:0bf10686bc1c93058091ab27c705ece083f9c2309bd00686bfb175d36bc07892
deliverable inventory:           452 rows; sha256:b8146982fc99b9ff343cc5e6ed6fc097fe1578e33eda52720826999fb450b3cc
source/live drift:               0 mismatched graphs of 36 (npm run authority:drift)
current phase:                   EXECUTABLE_DELIVERY_ENVIRONMENTS
next exact command:              npm run authority:drift && npm test
```

No overall percentage is asserted. The boundary gates are recorded without
collapsing unlike evidence into a progress percentage: semantic adequacy,
deliverable/layout authority, realisation-option evaluation closure and the
canonical compiler sole path (dependency closure, entrypoint cutover and
duplicate retirement) are `VERIFIED_CURRENT`; compiler proof admission is
reopened pending a proof refresh against the relocated canonical
implementation sources; executable environments and final hermetic closure are
`REMAINING_ACTIONABLE`. Any future percentage must record its metric name,
numerator, denominator, weighting algorithm, state source and calculation
digest. A remaining-executable-delivery metric must never be labelled overall
programme completion.

### VERIFIED_CURRENT

| identifier | classification | current binding | evidence or state digest | remaining condition |
| --- | --- | --- | --- | --- |
| `SEMANTIC_ADEQUACY_AND_CONTAMINATION` | `VERIFIED_CURRENT` | authority `d24b641a…`; 6,458 dispositions | inventory `sha256:0bf10686bc1c93058091ab27c705ece083f9c2309bd00686bfb175d36bc07892`; review `sha256:081b775881fac9c72fd0eb3bef6e7a8bdc23e2bbd009c6ad60d888dcdf4b7427` | none while relevant authority dependencies remain unchanged |
| `DELIVERABLE_AND_LAYOUT_AUTHORITY` | `VERIFIED_CURRENT` | authority `d24b641a…`; 452 deliverables; foundational layout materialised | inventory `sha256:b8146982fc99b9ff343cc5e6ed6fc097fe1578e33eda52720826999fb450b3cc`; plan `sha256:f2a1c37ab71ecee0136db640a45d89068e2ae4f52a8b80e311ccd2c1b28bb481` | none while relevant authority dependencies remain unchanged |
| `COMPILER_PROOF_ADMISSION` | `VERIFIED_CURRENT` | authority `d24b641a…`; active contract; accepted realisation; three successful proof results | implementation `sha256:05323e8c4b7e6b21d16e5e679c30cd80154b0bbb12907dcf05944b4cc2c00e4a`; evidence set `sha256:2049d80e0725b70c02a6f269d6819a3a36b4cb19745fcc2c5cb0015c52b5b737`; attestation `sha256:a7148e9b618f5dda16b588e45739742e0aa6ea0ae34dd5639daa41a6eed8224d` | reopen only if an exact authority, implementation, proof-algorithm, test-set or evidence dependency changes |
| `SOURCE_LIVE_PARITY` | `VERIFIED_CURRENT` | 36 graphs and 61,704 triples at authority `d24b641a…` | dependency set `sha256:1b7147be19433f3c0420c0d08559554b7a90e30d02b73cb12f508211916f588c` | zero drift must be reconfirmed after the next authority transaction |
| `MILESTONE_GIT_PUBLICATION` | `VERIFIED_CURRENT` | `main` and `origin/main` at `9670309d0d217eb7388ca7d76796c183b3ffc2f3` | Git commit identity `9670309d0d217eb7388ca7d76796c183b3ffc2f3` | later local work remains checkpoint-owned until its coherent wave is committed |

### PARTIALLY_DELIVERED

| identifier | classification | current binding | evidence or state digest | remaining condition |
| --- | --- | --- | --- | --- |
| `CANONICAL_COMPILER_SOLE_PATH` | `PARTIALLY_DELIVERED` | authority `d24b641a…`; canonical capability/process/configuration/provider surfaces exist at HEAD `9670309…` | dependency review `sha256:9c737137f12b38f51227b971d5d2d8b7da0e9965c01793836dcdf91e74f34dc2` | close canonical dependencies, switch all active entrypoints, prove ownership, then retire duplicate compiler authority |
| `HERMETIC_EXECUTABLE_SUITE` | `PARTIALLY_DELIVERED` | accepted semantic and layout boundaries at authority `d24b641a…`; executable environment delivery not yet closed | deliverable inventory `sha256:b8146982fc99b9ff343cc5e6ed6fc097fe1578e33eda52720826999fb450b3cc` | deliver development, deterministic-test and production-shaped-staging boundaries plus final system evidence |

### REMAINING_ACTIONABLE

The following dependency DAG is authoritative only while its authority and
review digests remain unchanged. The detailed machine-readable record is the
cutover dependency review named above.

1. `REALISATION_OPTION_EVALUATION_CLOSURE`
   - classification/blocker: `REMAINING_ACTIONABLE` / `SEMANTIC_CORRECTION_REQUIRED`
   - semantic owner: current decision, realisation, evidence, supply-chain and readiness authority; the correction must publish one independently derived final owner
   - binding/state digest: authority `d24b641a…`; candidate and publication digests remain checkpoint-owned until created
   - prerequisites: preserve current authority lineage; retain the already materialised compiler containment work only within its previously proven scope
   - local work: model single and composed options, complete criterion/evidence assessments, credible candidate or proven-sole-candidate closure, selected/rejected outcomes, component integrity, composition coverage proof, invalidation, SHACL, integrity, derivation, readiness and exact positive/negative fixtures; migrate every accepted decision
   - authority mutation required: yes, one validate-and-rollback followed by one accepted publication after all local gates pass
   - focused acceptance command: `npm run test:semantic-assurance && npm --prefix tools/compiler run check && npm --prefix tools/compiler test`
   - completion condition: the `REALISATION_OPTION_EVALUATION_CLOSURE` zero-counter gate passes and no evaluation-incomplete decision authorises implementation expansion
   - next unblocked node: `CANONICAL_COMPILER_DEPENDENCY_CLOSURE`

2. `CANONICAL_COMPILER_DEPENDENCY_CLOSURE`
   - classification/blocker: `REMAINING_ACTIONABLE` / `LOCAL_IMPLEMENTATION`
   - semantic owner: `urn:usf:semanticcontract:compilersemanticenforcement`
   - binding/state digest: authority `d24b641a…`; dependency review `sha256:9c737137f12b38f51227b971d5d2d8b7da0e9965c01793836dcdf91e74f34dc2`
   - prerequisites: `REALISATION_OPTION_EVALUATION_CLOSURE`; current layout authority remains current; no modifying worker or authority transaction
   - local work: close canonical witness/configuration/proof inputs and contain the SHACL harness under its authorised assurance boundary
   - authority mutation required: no for implementation; later proof refresh only after implementation-source bytes change
   - focused acceptance command: `npm run test:semantic-assurance`
   - completion condition: no proof-governing input resolves through `tools/compiler` or an unauthorised tools path; all focused controls pass
   - next unblocked node: `CANONICAL_COMPILER_ENTRYPOINT_CUTOVER`

3. `CANONICAL_COMPILER_ENTRYPOINT_CUTOVER`
   - classification/blocker: `REMAINING_ACTIONABLE` / `LOCAL_IMPLEMENTATION`
   - semantic owner: `urn:usf:semanticcontract:compilersemanticenforcement`
   - binding/state digest: authority `d24b641a…`; dependency review `sha256:9c737137f12b38f51227b971d5d2d8b7da0e9965c01793836dcdf91e74f34dc2`
   - prerequisites: dependency closure
   - local work: switch MCP, operator, chroot and CI wiring to canonical Node `22.23.1` command surfaces
   - authority mutation required: only if the current path/representation authority proves insufficient
   - focused acceptance command: `npm test && bash tools/chroot/verify-isolation.sh && bash tools/chroot/verify-agents.sh`
   - completion condition: discovered and executed tests match; all active entrypoints use canonical paths; directives and CI agree on Node `22.23.1`
   - next unblocked node: `DUPLICATE_COMPILER_RETIREMENT`

4. `DUPLICATE_COMPILER_RETIREMENT`
   - classification/blocker: `REMAINING_ACTIONABLE` / `LOCAL_VALIDATION`
   - semantic owner: `urn:usf:realisationdecision:semanticmodelcompilationrealisation`
   - binding/state digest: authority `d24b641a…`; dependency review `sha256:9c737137f12b38f51227b971d5d2d8b7da0e9965c01793836dcdf91e74f34dc2`
   - prerequisites: canonical entrypoint parity and ownership/supersession proof for every candidate path
   - local work: remove only proven duplicate implementation authority and block historical proof admission
   - authority mutation required: only if a semantic realisation or path-authority decision must be superseded
   - focused acceptance command: `rg -n 'tools/compiler/(src|bin)|cd /usf/tools/compiler|npm .*tools/compiler' .mcp.json package.json .github tools/chroot processes/semantic-assurance tools/proof`
   - completion condition: active duplicate compiler references are zero and no removed path lacks a current replacement
   - next unblocked node: `EXECUTABLE_ENVIRONMENT_DELIVERY`

5. `EXECUTABLE_ENVIRONMENT_DELIVERY`
   - classification/blocker: `REMAINING_ACTIONABLE` / `LOCAL_IMPLEMENTATION`
   - semantic owner: current environment, persistence, recovery and operator contracts in authority `d24b641a…`
   - binding/state digest: deliverable inventory `sha256:b8146982fc99b9ff343cc5e6ed6fc097fe1578e33eda52720826999fb450b3cc`
   - prerequisites: canonical compiler command surface; unaffected environment assets may proceed earlier when exact layout plans validate
   - local work: development, deterministic-test and production-shaped-staging orchestration; configuration/secrets; migrations, representative seeds, health, readiness, backup, restore, upgrade and rollback
   - authority mutation required: only for a genuine semantic omission; batch one correction set if needed
   - focused acceptance command: `npm test`
   - completion condition: all three environments execute their semantic journeys and recovery controls from repository-local declared inputs
   - next unblocked node: `BIDIRECTIONAL_TRACEABILITY_CLOSURE`

6. `BIDIRECTIONAL_TRACEABILITY_CLOSURE`
   - classification/blocker: `REMAINING_ACTIONABLE` / `LOCAL_VALIDATION`
   - semantic owner: current materialisation, evidence and validation contracts
   - binding/state digest: deliverable inventory review `sha256:953cf68731cde48b1246bd096edc2ea19faa72d8688ab07ae09fe01729d712c4`
   - prerequisites: environment artefact set stable
   - local work: regenerate semantic-to-artefact and artefact-to-semantic projections and reject every gap
   - authority mutation required: no unless a genuine model omission is found
   - focused acceptance command: `npm test`
   - completion condition: obligations without realisation and artefacts without semantic derivation are both zero
   - next unblocked node: `FINAL_HERMETIC_SYSTEM_GATES`

7. `FINAL_HERMETIC_SYSTEM_GATES`
   - classification/blocker: `REMAINING_ACTIONABLE` / `LOCAL_VALIDATION_THEN_AUTHORITY_PUBLICATION_REQUIRED`
   - semantic owner: current whole-suite completion, proof and readiness contracts
   - binding/state digest: authority `d24b641a…`; final digest is created only from the completed implementation
   - prerequisites: all preceding nodes complete
   - local work: two independent clean clones, empty-cache and poisoned-state runs, isolated declared-input rebuild, deterministic comparison and two independent adversarial reviews
   - authority mutation required: yes, once, for current final evidence/proof/readiness/contract closure
   - focused acceptance command: the final-gate commands specified by sections 21 and 22 of this directive
   - completion condition: every terminal gate passes and final source/live parity is zero
   - next unblocked node: terminal verdict evaluation

### SUPERSEDED_OR_INVALIDATED

| identifier | classification | current binding | evidence or state digest | remaining condition |
| --- | --- | --- | --- | --- |
| `REJECTED_EXECUTABLE_REALISATION` | `SUPERSEDED_OR_INVALIDATED` | inactive historical lineage only | removal plan `sha256:b37a2e69bf3e2c9bd223566343f849eb0d8504988edcef54b48644b1217c0962` | must never satisfy a current obligation |
| `STALE_MIXED_SCOPE_COMPILER_PROOF` | `SUPERSEDED_OR_INVALIDATED` | inactive CAS history only | evidence `sha256:c976ca68a8656dba2aec13b703a44378997996e11cbfd52ad8382f50254be9cc`; attestation `sha256:dac9ecbd1c3c20a35bb6e2008275a904baaf0d24ab2de9cd7de86ef0727a274f` | must never satisfy the compiler contract |
| `REFERENCE_OR_HISTORICAL_SOURCE_COMPLETION` | `SUPERSEDED_OR_INVALIDATED` | provenance only, outside current delivery | semantic adequacy attestation `sha256:446789c2531e29e74798a6fde1b9ddc365a2bc39d4d62aa0836f725659ed4828` | preserve lineage without admitting completion evidence |

### EXTERNAL_OR_HUMAN_BLOCKED

| identifier | classification | current binding | evidence or state digest | remaining condition |
| --- | --- | --- | --- | --- |
| `NONE` | `EXTERNAL_OR_HUMAN_BLOCKED` | no genuine external blocker is current at authority `d24b641a…` | checkpoint digest descriptor `.work/programme/checkpoint.json.sha256` | none; all current nodes are locally actionable or normal authority-bound work |

## 2. Terminal outcomes

End with exactly one terminal outcome:

```text
USF_HERMETIC_SUITE_DELIVERY_COMPLETE
USF_HERMETIC_SUITE_DELIVERY_BLOCKED_IRRECOVERABLY
```

`USF_HERMETIC_SUITE_DELIVERY_COMPLETE` is permitted only when every completion gate in this file passes for the executable dev/test/production-shaped-staging delivery.

`USF_HERMETIC_SUITE_DELIVERY_BLOCKED_IRRECOVERABLY` is permitted only when further progress requires an unavailable credential, explicit human or legal acceptance, a paid or irreversible external action not already authorised, inaccessible mandatory external evidence, an unexplained authority conflict, or an infrastructure limit that cannot be removed through an authorised self-healing or authority-change path.

Routine ambiguity, missing code, missing services, incomplete semantics, test failures, proof failures, stale evidence, missing collectors, Stardog failures, transaction rollback, dependency conflicts, architectural decisions, absent work-tracker items, performance defects or incomplete environments are not irrecoverable blockers. Resolve them and continue.

## 3. Prior completion is reopened

Any earlier completion verdict predating this directive is not sufficient for this programme.

The previous programme state may be reused only as verified input. Reopen every contract whose claimed realisation is any of:

```text
specification-only
JSON-only
RDF-only
generated-packet-only
reference-implementation-only
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

## Semantic Adequacy and Legacy-Contamination Gate

Before final implementation materialisation, perform one bounded, canonical, authority-digest-bound counterfactual review. Do not rerun it unless a relevant semantic dependency or inventory digest changes.

Review every imported canonical name, IRI, capability and contract boundary, service or package boundary, interface, operation, event, workflow, state model, technology choice, provider assumption, environment classification, lifecycle state, claim, nonclaim, proof scope, validation obligation, source reference, path role, naming rule, numbering rule and operational process.

For each item ask:

> If every earlier repository, source path, package structure, external work record, technology choice, implementation and naming convention had never existed, would current semantic relationships, admitted evidence and explicit claims or nonclaims still derive this exact concept, boundary, identity and requirement?

A validator pass, current IRI, active state, historical proof, existing code or familiar convention is not sufficient. A historical match is permitted only when independent evidence shows it remains the clearest stable final-state name; historical dependence is prohibited.

The canonical inventory assigns every imported item exactly one disposition:

```text
INDEPENDENTLY_WARRANTED_RETAINED
CORRECTED_OR_RENAMED
CONSOLIDATED
SPLIT
SUPERSEDED
HISTORICAL_PROVENANCE_ONLY
UNRESOLVED_EXTERNAL_DECISION
```

Every disposition contains:

```text
semantic identifier and item kind
historical source and current authority state
independent semantic basis and supporting evidence
affected claims and nonclaims
dependent resources
required corrective action
final canonical identity where applicable
```

There is no implicit retention. “Already active”, “validator accepted”, “used by code”, “familiar” and “too expensive to change” are not dispositions.

Technology choices are candidate realisation options unless independently proven to be semantic requirements. Review languages, frameworks, databases, queues, identity providers, object stores, container and orchestration systems, observability products, deployment tools, test frameworks, restricted-execution mechanisms and use of Stardog outside the semantic-authority boundary. Retain or change them only through evidence-backed option evaluation.

Audit every nonclaim, deferred state and out-of-scope classification. Record the exact excluded claim, justification, whether old implementation limits caused it, evidence that would remove it and whether hermetic development/test/staging delivery reopens it. Historical implementation weakness is not a permanent nonclaim.

No proof remains current unless it binds the current authority digest, realisation decision, repository-local implementation source digest, configuration, environment, provider mode, persistence and migration state, interfaces and dependent services. Reference-implementation, fixture, simulator, mock or historical-source results remain lineage only unless their exact scope is still applicable.

Operational sequencing must not enter permanent capability, contract, service, package, directory, filename, IRI or API identity. Unless the phrase genuinely denotes permanent semantic meaning, prohibit `wave-zero` through `wave-six`, `initial-suite`, `bootstrap`, `reference-kernel`, `executable-suite`, `migration`, `legacy`, `replacement`, `temporary` and `v2`. Delivery sequencing belongs only in the untracked programme ledger.

Do not begin final implementation materialisation until one deterministic gate proves:

```text
all imported items have exactly one complete disposition
silent inherited reuse = 0
implementation-derived semantic assumptions = 0
unjustified imported technology decisions = 0
source paths treated as target architecture = 0
operational wave identifiers in durable current identity = 0
external-tracker-derived durable identities = 0
unreviewed nonclaims and deferred states = 0
proof-to-current-implementation mismatches = 0
directive and validator policy conflicts = 0
accepted external repository authorisations = 0
undispositioned historical source-coordinate bindings = 0
requirements dependent on external work records or historical source access = 0
```

Preserve historical IRIs, CAS payloads and invalidated results when lineage requires them; make them non-current rather than deleting history. Publish all non-external corrections as the smallest safe coherent semantic transaction set, regenerate the canonical deliverable inventory from the corrected digest and obtain one independent review before layout materialisation.

## 4. Instruction precedence and authority

Read the applicable execution shim, `AGENTS.md`, this `GOAL.md`, the USF skill and the latest verified checkpoint before acting. A Claude session reads `CLAUDE.md`; a Codex session reads `CODEX.md`; another agent reads its equivalent shim when present.

Apply authority and instruction precedence as follows:

1. Direct current user instructions and non-overridable host safety policy.
2. `AGENTS.md`, the shared repository policy.
3. This `GOAL.md`, the durable programme directive.
4. Validated current live semantic authority for requirements, claims, nonclaims and allowed realisation decisions.
5. The USF skill for the authoritative query, mutation and materialisation protocol.
6. The applicable product shim for tool-specific orchestration only.
7. Current digest-bound packets and focused live queries.
8. Repository source, tests, ADRs, reports, caches, earlier repositories and external work records as non-authoritative inputs.

No product shim may weaken or override this directive or validated live authority. Live Stardog is the sole current semantic authority and controlled mutation boundary, but its present contents are not immutable, infallible or automatically independently warranted.

Where current authority is incomplete, legacy-contaminated, implementation-derived, source-path-derived, unjustifiably technology-prescriptive, environmentally overclaimed or otherwise defective, preserve lineage and correct it transactionally: identify affected resources, produce required evidence, evaluate alternatives, author a superseding decision, publish through the authorised compiler transaction, invalidate dependants and regenerate affected projections. Never bypass or contradict authority informally.

Graph source files are registered materialisations used to update authority. Their presence alone does not establish semantic truth or implementation completion.

## 5. Execution mode

Use one primary repository checkout. The verified checkpoint records its current branch and permitted coordination state.

```text
repository writer:      coordinator only for this programme
semantic-store writer:  coordinator only
read-only workers:      permitted when they reduce the critical path
modifying workers:      prohibited unless a later direct instruction explicitly authorises them
intermediate commits:   prohibited
final commit:           only after every completion gate passes
push or pull request:   prohibited unless separately authorised
Git stash:              prohibited
```

Do not reset, clean, discard, overwrite or delete unknown or user-owned work.

Read-only workers may inspect, query, run isolated tests, attack assumptions and return compact proposed patches. The coordinator applies repository and semantic changes sequentially.

Temporary clean-room copies may be created under an isolated operator temporary-storage root. They must not be Git worktrees and must not depend on untracked source from the primary checkout.

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

Do not stop after creating an external work item, specification, contract, ADR, plan, report, checkpoint or generated packet. Continue implementation unless a genuinely irrecoverable external or human dependency exists.

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
an orchestration service declaration that starts but does not fulfil its contract
a report asserting that implementation exists
```

## 8. Repository-locality and independence

Earlier repositories, their history and local caches are not semantic inputs and are not required for runtime, build, test, staging or continuation. Immutable historical bytes may remain only as inactive audit lineage outside current authority and current generated context; current requirements must be complete without consulting them.

Before completion, eliminate every dependency on code outside this repository, including:

```text
relative paths escaping the repository
absolute host source paths
file: dependencies targeting another checkout
symlinks into another repository
Git submodules used to supply required suite code
volume mounts of earlier-repository source
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

Every implementation, test, proof-algorithm and operational path referenced by semantic or JSON resources must:

```text
resolve beneath the repository root
exist in the final Git tree
have the expected representation
have a current content digest when the model requires one
be included in clean-room validation
```

## Complete Semantic Derivation and Hermetic Bootstrap Closure

Origin independence requires positive derivation, not merely deletion of historical names and coordinates. Every current directory, filename, semantic identity, application, process, module, adapter, API, command, event, worker, scheduled job, data model, schema, migration, seed, configuration key, environment variable, secret slot, permission, tenant boundary, container image, external dependency, build command, deployment resource, test, fixture, collector, proof algorithm, validator, workflow, generated artefact and operator procedure must have one machine-verifiable chain:

```text
current semantic requirement
→ claim, constraint or obligation
→ accepted realisation decision
→ authorised representation and path role
→ exact authority-digest-bound materialisation plan
→ repository-local artefact or locked external component
→ validation evidence
→ proof and contract re-evaluation
```

Traceability is bidirectional: every current semantic obligation has a delivered realisation, and every delivered artefact has one semantic owner and independent justification. Generated outputs also bind their generator, exact inputs and output digest. Operational provenance may occur only in reproducibility evidence and attestations; it never supplies semantic meaning, architecture, naming, requirements or completion criteria.

The minimal root of trust is exactly:

```text
current validated semantic authority
current repository source
version- and digest-locked toolchain inputs
verified authorised CAS payloads
required credentials supplied only through modelled secret interfaces
```

Everything else is reproducibly derived. Framework defaults, ambient host assumptions, undeclared network access, mutable tags, floating package versions, unverified host tools, hidden generated inputs, cache-dependent correctness, wall-clock-dependent canonical output, unseeded canonical randomness and locale/timezone/platform-dependent canonical behaviour are blocking defects.

External packages, images and standards require an accepted selection decision, exact version or digest, integrity verification, licence and supply-chain assessment, a declared acquisition process and an explicit replacement or continuity rule. Acquisition is a separate phase whose outputs are digest-bound and independently verified. At least one build and test run must then execute with network access disabled using only those acquired inputs.

The compiler, generators, validators and materialisation tools are delivered system components. They must be repository-local, versioned, digest-bound, tested, free of historical-origin assumptions and capable of rebuilding governed outputs from current authority.

The decisive bootstrap counterfactual is:

> If every earlier repository, tracker, branch, commit, tag, source file, conversation, cache and current working directory disappeared, could an independent agent reconstruct, build, run, test and validate the entire project from the final repository, the exact current authority digest and declared verified inputs alone?

Completion requires a demonstrated yes from a fresh clone at the final commit, exact authority access or export, empty build/runtime state, no history requirement beyond the checked-out tree, no external tracker, no agent memory, no pre-existing dependency directories, no prebuilt local images and no undeclared host files.

The following final counters are all zero:

```text
repository artefacts without semantic derivation
semantic obligations without delivered realisations
implicit operational inputs
unlocked external dependencies
unmodelled configuration or secret interfaces
origin-dependent knowledge
clean-clone hermetic rebuild failures
semantic-to-artefact traceability gaps
artefact-to-semantic traceability gaps
```

## 9. Required delivered repository

Before deriving paths, build one bounded, canonical, authority-digest-bound deliverable inventory. Rebuild it only when a relevant semantic dependency changes. Attempt to prove it incomplete before accepting it.

For every explicit, deterministically derived or unresolved deliverable record:

```text
semantic identifier
owning capability and contract
semantic basis, claims and nonclaims
required positive, negative, error and recovery behaviour
dependencies and deployment boundary
data ownership and security boundary
environment requirements
required evidence, proof and validation
candidate implementation form
explicit, derived or unresolved status
```

The inventory must cover every semantically required:

```text
deployable applications and executable processes
capability-owned implementation modules
cross-capability runtime mechanisms
external-system and provider bindings
data stores, ownership boundaries, schemas, schema changes and representative data
commands, administrative tools, APIs and protocol surfaces
events, publishers, consumers, workers, queues, retry handling and scheduled jobs
identity, sessions, permissions, tenant isolation and privacy controls
validated configuration schemas and environment profiles
development, deterministic-test and production-shaped-staging topology
health, readiness, logging, metrics and tracing
backup, restore, upgrade, rollback and operational automation
evidence collectors, proof algorithms and validators
unit, contract, integration, end-to-end, recovery and semantic tests
continuous-integration and release gates
operator, developer and user documentation
```

Explicitly attack omissions: contracts represented only by data, capabilities without behaviour, unpaired providers or consumers, events without publishers or handlers, workers without queues and retries, unscheduled jobs, schemas without changes and rollback, unchecked configuration, unenforced permissions or tenant boundaries, unwired external services, shallow readiness probes, implementation without environments, environments without recovery, proofs without source binding, mock-only staging claims and missing clean-clone/operator journeys.

The canonical 452-row inventory must additionally prove that every capability has exactly one accountable boundary classification and independently derived purpose; many-to-one capability/process mappings are explicit; runtime, operator-control and assurance boundaries are distinct; non-runtime capabilities receive no artificial product service; every process owns capabilities, interfaces and lifecycle obligations; and every capability behaviour has an executing or validating owner. Orphan processes, processes without capability ownership, contradictory capability boundaries, shared processes without tenant/security separation, cross-boundary interfaces without contracts, workers or scheduled jobs hidden inside request applications, and assurance tooling counted as product runtime are all zero.

The final Git tree must contain the complete tracked source of the suite. Derive canonical homes and names from semantic responsibility, capability ownership, deployable process boundaries, dependency direction, data ownership, security and tenancy boundaries, change cohesion, independent testing boundaries, environment deployment and operational ownership.

Before creating foundational paths, evaluate credible alternatives and publish one coherent semantic naming and repository-layout decision. It must define canonical top-level and child path roles, semantic owners, allowed and forbidden contents, dependency direction, directory and filename algorithms, language-native rules, configuration rules, schema-change and representative-data rules, test and environment rules, proof and validation rules, authored versus generated placement, singular/plural and case rules, abbreviation rules, prohibited vague or lifecycle/status names, and a disposition for every inherited convention.

Existing or historical path names are only candidates. Retain a historical match only when the disposition inventory independently proves it is the clearest stable name. Missing or conflicting path, naming, representation and dependency rules must be modelled, proved and published before files are created. Derive the exact foundational plan, invoke the current USF layout-plan operation, validate it through the current USF layout-validation operation, reject every unauthorised path, and only then materialise. Repeat this once per coherent digest-bound implementation wave rather than pre-authorising every future filename.

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

1. Confirm the repository identity and reconcile the active branch with the latest verified checkpoint; the snapshot in this file records the branch at its publication time.
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
whether any path depends on an earlier repository
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

Plan topological delivery waves. Prefer vertical, executable slices that close several tightly coupled contracts and can be demonstrated through the selected repository-local orchestration, rather than producing another broad layer of specifications without runnable behaviour. Wave identifiers remain ledger-only and never become durable semantic or repository identity.

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
purpose, accountable ownership, claims and nonclaims
features, constraints, states and transitions
commands, APIs, interfaces, events, consumers and workflows
data contracts, controlled values and validation semantics
permissions, authorisation, identity, tenancy and privacy boundaries
provider modes, external dependencies and environment requirements
positive, negative, error and failure behaviour
timeouts, retries, idempotency and concurrency
persistence, transaction boundaries, schema changes and rollback
health, readiness, backup, restore, upgrade and rollback
logging, metrics, tracing and resource limits
security and dependency/supply-chain obligations
user, API, operator and automation journeys
required evidence, proof and validation obligations
permitted realisation forms and implementation containment
readiness, lifecycle and invalidation consequences
```

Do not infer missing product behaviour solely from old code, external work records or convention. Old code may provide evidence and candidate behaviour, but current authority must define the requirement.

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
selected orchestration build, configuration and health checks
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

Document exact commands in the repository. A fresh operator must not need conversational context or an earlier repository.

The final clean-room acceptance must begin from a standalone fresh clone and empty authorised runtime state. It must use empty dependency caches and no pre-existing dependency directory, earlier repository, parent checkout, untracked source, prebuilt local image, mutable image tag, hidden environment default, prior database or volume, unverified CAS source payload, agent cache, conversation-derived file or external work-tracker export.

Run a poisoned-state test with unrelated host files, caches, environment values, databases and images present. The build and environments must either ignore them or fail closed; silently consuming them is a blocking defect.

## 16. Stardog mutation and self-healing

All semantic mutations are coordinator-only and occur through registered authored graph source and the authorised compiler publication path.

Never issue direct mutation SPARQL through a read gateway, raw HTTP, database CLI or ad hoc script. Registered authored semantic source and the compiler's validated single transaction are the only publication path.

Before publication, verify repository preconditions, current authority, owned transactions, local validation, exact semantic delta and invalidation of stale packets.

After publication, record the new authority digest, verify SHACL, integrity, contamination, derivations, graph inventory and source/live drift, then invalidate stale packets and update the compact programme state.

Classify failures before acting. Use bounded retries for transient failures, never replay ambiguous mutations, never alter another owner’s transaction, minimise failing fixtures, preserve state and continue through safe recovery.

Resource limits must be addressed through bounded queries, indexing, batching, projections, external payload storage or an authorised semantic-store migration. Never weaken semantic completeness or implementation requirements to fit a service tier.

## 17. External coordination policy

Normal durable programme state lives in validated live semantic authority, Git, the repository-local programme ledger, CAS and evidence/proof/validation state. An external work tracker is not a normal programme dependency and must not store semantic gaps, implementation gaps, test failures, architecture or naming decisions, dependency order, programme state or completion evidence.

External coordination may be used only when a required action belongs to an unavailable human or external organisation and is genuinely legal, commercial, credential, access or organisational work that cannot be resolved through semantics, implementation, evidence, proof or validation. Before use, record why the blocker is non-semantic, why the agent cannot deliver it, the responsible external actor, the exact unblock condition and why a repository-local semantic record is insufficient.

No external work-tracker identifier may enter a directory, filename, IRI, canonical name, package, service, schema change, test, branch, tag or generated artefact identity. If no qualifying external dependency exists, do not access an external work tracker.

## 18. Parallelism and independent review

Use at most eight active execution participants and delegation depth at most two.

All delegated workers remain read-only. Use them for focused semantic inspection, implementation review, test attacks, dependency analysis and independent reconstruction of counts or digests.

At least two independent final review rounds are mandatory. The second final reviewer must not receive the first reviewer’s conclusion before reporting.

Every critical, high or claim-affecting medium finding reopens the affected lifecycle stage.

## 19. Mandatory adversarial attacks

Actively attempt to prove the delivery incomplete or unsound, including:

```text
specification or report treated as implementation
semantic path referring outside the repository
missing source behind a recorded digest
standalone clone requiring parent-repository files
orchestration service declared but required behaviour absent
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

Treat conversation and model-local memory as temporary. Treat validated live semantic authority, Git, the repository-local programme ledger, CAS and evidence/proof/validation state as durable systems. External work trackers are never programme memory.

Maintain the atomic JCS-canonical ledger at:

```text
.work/programme/checkpoint.json
```

This `GOAL.md` is the durable programme directive. The ignored checkpoint is volatile execution state. Update it atomically after each coherent semantic or executable operation and verify its digest after every write.

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
repository HEAD, working-tree digest and patch digests
current authority and managed-candidate digests
checkpoint, ledger and detailed-sidecar paths and digests
current phase and active semantic item or executable node
semantic-adequacy, contamination, deliverable and executable-realisation inventory digests
VERIFIED_CURRENT, PARTIALLY_DELIVERED, REMAINING_ACTIONABLE,
SUPERSEDED_OR_INVALIDATED and EXTERNAL_OR_HUMAN_BLOCKED identifiers
completed and reopened identifiers, with the exact dependency change that caused every reopening
changed repository paths and content digests
published semantic resources and publication transaction outcome
admitted evidence and proof-result identifiers
validation result identifiers
current development, deterministic-test and production-shaped-staging state
unresolved blockers and findings
running process identifiers and ownership
next exact action, semantic identifier and command
Git, worktree, stash, CAS and transaction ownership/closure state
owned queries and transactions
```

The checkpoint must allow a fresh invocation to resume without replaying two days of analysis.

## Agent Continuation and Handoff

Every future agent must:

1. read `AGENTS.md`, the applicable product shim, this `GOAL.md` and the USF skill completely as required by those files;
2. load the latest checkpoint and programme ledger;
3. verify their goal, Git, authority, patch, inventory and state digests;
4. inspect the working tree and process state without modifying them;
5. reconcile `VERIFIED_CURRENT`, `PARTIALLY_DELIVERED`, `REMAINING_ACTIONABLE`, `SUPERSEDED_OR_INVALIDATED` and `EXTERNAL_OR_HUMAN_BLOCKED` work;
6. verify that no other process is modifying the checkout and that no unowned transaction is active;
7. resume from the checkpoint's next exact action;
8. avoid repeating bootstrap, broad inventory, contamination review or analysis whose relevant digest is unchanged;
9. preserve valid completed work and reopen it only when authority, evidence or implementation dependencies require it;
10. continue until exactly one terminal outcome is warranted.

Do not assume the prior agent stopped at the prose snapshot in this file or at the state described by a prompt. Repository bytes, live authority and the verified checkpoint determine how far the programme progressed.

## Usage-Limit Safe Stop

A model, context or execution allocation ending is not an irrecoverable programme blocker and never warrants a terminal programme outcome.

Before a limit prevents safe continuation:

1. finish the current atomic semantic or implementation operation;
2. do not begin a publication, materialisation or other non-atomic operation that cannot be completed and reconciled;
3. run the smallest focused validation required for the completed operation;
4. write the atomic programme ledger and recovery checkpoint;
5. write or update every required machine-readable detailed-state sidecar;
6. record the exact next command and semantic identifier;
7. verify every new digest and the Git, working-tree, patch, stash, CAS, process and transaction state;
8. leave no ambiguous mutation, lock, unowned process or transaction;
9. return a compact continuation status rather than a terminal verdict.

## Directive and Validator Harmonisation

After corrected architecture and naming authority is published, review `AGENTS.md`, `CODEX.md`, `CLAUDE.md`, other agent shims, the USF skill, this file, materialisation validators, CI workflows, layout schemas and proof algorithms. They must agree on authority, naming, architecture, worker permissions, materialisation, completion and external-coordination policy. A directive or validator enforcing superseded policy is a blocking defect.

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
imported items without one complete seven-state disposition = 0
silent inherited reuse = 0
implementation-derived semantic assumptions = 0
unjustified imported technology decisions = 0
source paths treated as target architecture = 0
operational delivery identifiers in durable current identity = 0
external-tracker-derived durable identities = 0
unreviewed nonclaims and deferred states = 0
proof-to-current-implementation mismatches = 0
directive and validator policy conflicts = 0
```

### 22.2 Realisation Option Evaluation Closure

`REALISATION_OPTION_EVALUATION_CLOSURE` is an ongoing and final gate. It runs
before accepting or materialising a decision, after relevant option,
component, version, authority or criterion changes, at each integrated wave,
and at final completion. Decision state alone never warrants an implementable
realisation. Closure requires an accepted decision, an explicit selected
option, complete current evidence-backed evaluation, current supply-chain
evidence, and a successful whole-composition proof where applicable.

```text
active contracts requiring technology selection without evaluated candidates = 0
accepted decisions without multiple credible candidates or a valid sole-candidate proof = 0
accepted decisions without exactly one selected option = 0
applicable candidate/criterion assessments missing = 0
applicable component/criterion assessments missing = 0
criterion assessments without admitted current evidence = 0
credible rejected candidates without evidence-backed rejection reasons = 0
selected packages or images without exact version and integrity binding = 0
selected components without kind-specific closure = 0
selected third-party components without licence assessment = 0
selected third-party components without vulnerability and supply-chain assessment = 0
selected compositions without complete component responsibility mapping = 0
selected compositions without current whole-composition coverage proof = 0
composition permutations left unclassified = 0
provider choices without required development, deterministic-test and production-shaped-staging bindings = 0
selected options without concrete realisation mappings = 0
legacy selections retained solely because of previous use = 0
```

No present or future decision is grandfathered. Stale or incomplete evaluation
prevents new implementation expansion but preserves independently validated
unaffected behaviour within its exact proven scope. Detailed matrices and
evidence remain in governed semantic resources and digest-bound sidecars, not
in this directive.

### 22.3 Executable repository closure

```text
all in-scope active contracts have repository-local executable realisations
repository artefacts without semantic derivation = 0
semantic obligations without delivered realisations = 0
implicit operational inputs = 0
unlocked external dependencies = 0
unmodelled configuration or secret interfaces = 0
origin-dependent knowledge = 0
semantic-to-artefact traceability gaps = 0
artefact-to-semantic traceability gaps = 0
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

### 22.4 Environment closure

```text
dev environment builds, starts, becomes healthy and exercises required journeys
test environment is isolated, deterministic and complete
staging environment is production-shaped, starts healthy and has no dev-only shortcuts
all migrations and seed operations pass from empty state
all required services, workers and scheduled jobs execute
cross-service APIs, events and data contracts pass
backup, restore, restart, upgrade and rollback tests pass
environment teardown leaves no unauthorised residue
network-isolated rebuild and test succeeds from verified acquired inputs
clean-clone hermetic rebuild failures = 0
```

### 22.5 Evidence and proof

```text
all mandatory evidence admitted, fresh, integrity-valid and applicable
all mandatory proof obligations have current successful results
all successful results bind exact evidence-set and implementation-source digests
all current proofs bind exact authority, decision, configuration, environment, provider, persistence, migration, interface and dependent-service scope
all confidence is warranted and current
all failed or stale results retain lineage and cannot activate contracts
all referenced CAS payloads verify
```

### 22.6 Contracts and realisations

```text
all in-scope warranted contracts are active
all active contracts have accepted realisation decisions
all required active contracts have valid executable realisations
all paths, formats, packages and services are authorised
all contract claims are supported
all independently warranted nonclaims are preserved and every inherited nonclaim or deferred state is reviewed
all external dependencies have repository-local integration and required substitutes
```

### 22.7 Validation and integration

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

### 22.8 Independent adversarial review

```text
at least two independent final review rounds completed
second final reviewer unanchored by first report
critical findings = 0
high findings = 0
claim-affecting unresolved medium findings = 0
all resolved findings have regression tests or semantic constraints
```

### 22.9 Work and repository state

```text
executable-realisation audit has zero actionable in-scope gaps
broader semantic audit has zero actionable in-scope gaps
no unauthorised external work-tracker dependency or identity exists
the checkpoint-recorded programme branch contains only intended programme changes
one worktree exists
no stash exists
no temporary repository artifact remains
all checkpoint and volatile runtime output is outside Git
```

### 22.10 Final evidence

```text
final suite evidence manifest verified
final exact evidence-set digest recorded
final repository-source inventory digest recorded
final dev/test/staging deployment evidence verified
final DSSE/in-toto attestation verified
post-publication proof rerun against final authority passes
final contract packets regenerate from final authority
two independent empty-cache clean clones and the poisoned-state test pass
```

## 23. Forbidden completion shortcuts

Never claim completion by:

```text
landing semantic-contract JSON without executable code
pointing implementation paths at an earlier repository
stopping when usf_work_plan returns no rows
calling a reference kernel the entire suite
using a local cache as the only source of implementation bytes
creating orchestration definitions without exercising complete behaviour
using tests as proof without evidence admission
using hermetic evidence as live-provider evidence
closing external tracker records without closing repository gaps
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
8. create the final commit on the checkpoint-recorded programme branch with the final authority digest, suite evidence-set digest and repository-source inventory digest in the commit body;
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
qualifying external-human blockers and their recorded justification, or none
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

The final authority must warrant the completion claim, and two standalone clean clones must independently prove it without an earlier repository, parent checkout, untracked source, hidden agent cache or conversational history.
