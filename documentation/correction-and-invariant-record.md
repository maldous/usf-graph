# Correction and invariant record

Each correction is recorded against the required six headings. Preference
throughout was to evolve an existing concept; new vocabulary appears only where
the model could not express the decision boundary safely.

## C1 — Explicit validation applicability

- **Descriptive intent.** Whether validation is in scope for a governed
  contract, as a first-class decision separate from which obligations exist and
  from whether they are satisfied.
- **Autonomous decision.** D8 realisation authority, D9 validation claim, D10
  work projection, D12 readiness.
- **Unsafe inference.** No `requiredValidation` ⇒ validation not required ⇒
  nothing outstanding ⇒ contract complete. Live for 61 of 64 contracts.
- **Operational contract.** `usf:hasValidationApplicability`, functional, range
  the closed set `required | notrequired | conditional | reserved | unresolved`,
  exactly one per governed contract, always with
  `usf:validationApplicabilityReason`. Per-state binding constraints in
  `urn:usf:shape:validationapplicabilityclosure`. `notrequired` additionally
  requires `usf:validationApplicabilityAuthority` naming a successful
  `ProofResult`; `conditional` requires a fully structured
  `usf:ValidationApplicabilityCondition`.
- **Fail-closed rule.** Absent, `unresolved` or `conditional` ⇒
  `UNRESOLVED_FAIL_CLOSED`; no authorisation is emitted and readiness is
  `unknown`. Absence can never select PROCEED.
- **Invalidation.** Changing the state changes the projection at the next
  authority digest. Removing the state re-opens
  `contractvalidationapplicabilityundeclared`. Adding an obligation to a
  `notrequired` or `unresolved` contract is a shape violation.
- **Tests.** Vocabulary closure; exactly-one-with-basis over all 64 authored
  contracts; the migration promoted nothing (A1–A5, M1–M5).

## C2 — One satisfaction definition for validation

- **Descriptive intent.** What it means for a `ValidationObligation` to be
  satisfied *now*.
- **Autonomous decision.** D9, D10, D2, D12.
- **Unsafe inference.** The work plan and the bootstrap packet decided
  satisfaction from the evidence-admission chain, which is weaker than the SHACL
  satisfaction contract. A passing result made a **reserved** obligation look
  satisfied, so `usf_work_plan` reported `gaps: []` for the materialisation
  contract.
- **Operational contract.** A satisfaction is current only when the result names
  this exact obligation through `resultForValidationObligation`, is in state
  `passed`, binds `validationEvaluatedAuthorityDigest` equal to the live witness
  and a non-empty `validationEvaluatedSourceHead`, and carries neither an
  invalidation condition nor a supersession.
- **Fail-closed rule.** Any missing conjunct ⇒ `validationSatisfied=false` plus
  `missing-current-passing-validation` (nothing recorded) or
  `validation-satisfaction-not-current` (something recorded but not current).
- **Invalidation.** A new authority digest invalidates every satisfaction bound
  to the previous one. So does an invalidation condition or a supersession.
- **Tests.** P2, P3, A10–A16, B4–B10, M7, M8.

## C3 — Explicit action states on every factory projection

- **Descriptive intent.** The factory's own decision vocabulary, made explicit
  in the projection rather than inferred from empty arrays.
- **Autonomous decision.** D8, D9, D10.
- **Unsafe inference.** `authorisedActions: []` and `gaps: []` were both
  ambiguous between "evaluated and clean", "not evaluated" and "withheld".
- **Operational contract.** Every projection carries
  `actionState ∈ {PROCEED, RESERVED_NO_ACTION, BLOCK, UNRESOLVED_FAIL_CLOSED}`.
  `usf_contract_project` adds `actionStateReasons`, and a separate
  `validationActionState` so that one field never answers three questions.
  `usf_work_plan` adds `dispositionCounts`, `gapCount` and
  `completionClaim: false`. Ten gap codes each map to exactly one disposition;
  `resolveDisposition` throws on an unmapped code rather than defaulting.
- **Fail-closed rule.** Precedence is BLOCK > UNRESOLVED_FAIL_CLOSED >
  RESERVED_NO_ACTION > PROCEED. Authorisation arrays are populated only when
  `actionState` is PROCEED.
- **Invalidation.** The projection is bound to an authority digest and is
  rebuilt when it changes; the before/after witness comparison rejects a
  projection built across a change.
- **Tests.** A1–A20, P1–P3, and the disposition-completeness test.

## C4 — Reserved validation is neither satisfied nor blocking

- **Descriptive intent.** Separate the explanation ("validation is in scope")
  from the authorisation ("validation may be executed") and from the conclusion
  ("validation is satisfied").
- **Autonomous decision.** D8 versus D9.
- **Unsafe inference.** Two symmetrical errors: reading a reserved obligation as
  satisfied, or letting it withdraw realisation authority that an accepted
  decision and a successful proof already granted.
- **Operational contract.** A reserved obligation yields
  `validationActionState=RESERVED_NO_ACTION`, `validationSatisfied=false`, and a
  `RESERVED_NO_ACTION` gap that is excluded from realisation blocking. An
  **activated** unsatisfied obligation does block realisation.
- **Fail-closed rule.** The packet carries the stop condition
  "validationSatisfied is false and the task would claim validation".
- **Invalidation.** Activating the obligation converts it from reserved to
  blocking until a current satisfaction exists.
- **Tests.** P1, P3, A8, A9.

## C5 — Negative states survive the byte bound

- **Descriptive intent.** A bounded packet must remain a truthful summary.
- **Autonomous decision.** D2.
- **Unsafe inference.** `openGaps` was last in the fill order, so truncation
  removed the negative states first and left a clean-looking packet.
- **Operational contract.** `openGaps` leads `ITEM_KEYS`, and at offset 0 the
  packet refuses to emit unless the complete gap set fits.
- **Fail-closed rule.** An error, not a shortened gap list.
- **Tests.** B3.

## C6 — Orientation mode declares that it evaluated nothing

- **Descriptive intent.** Distinguish "not evaluated" from "evaluated and clean".
- **Autonomous decision.** D1.
- **Unsafe inference.** Task-mode `openGaps: []` read as no outstanding work.
- **Operational contract.** `evaluationScope`, `gapEvaluation`, `actionState`,
  `completionClaim`.
- **Fail-closed rule.** Orientation mode always reports
  `UNRESOLVED_FAIL_CLOSED`.
- **Tests.** B2.

## C7 — Exact contract identity

- **Descriptive intent.** A reference denotes one contract or none.
- **Autonomous decision.** D2.
- **Unsafe inference.** `LIMIT 1` described the first of an ambiguous set without
  saying what was discarded.
- **Operational contract.** Exactly one distinct contract must resolve.
- **Fail-closed rule.** Ambiguity is a user-facing rejection.
- **Tests.** B1.

## C8 — Readiness cannot bypass validation

- **Descriptive intent.** Readiness accounts for every blocking obligation
  family, including validation.
- **Autonomous decision.** D12.
- **Unsafe inference.** `ValidationObligation` is neither an
  `AssuranceObligation` nor `obligationFor`-bound, so the blocking projection
  could not see it and `ready` was reachable past an activated, unsatisfied
  obligation.
- **Operational contract.** `?validationBlocked` and `?validationUnsatisfied`
  drive `notready` with `rr:validationblocked` / `rr:validationunsatisfied`;
  `?validationApplicabilityUnresolved` drives `unknown` with
  `rr:validationapplicabilityunresolved`.
- **Fail-closed rule.** The three terms sit after the existing negatives and
  before the ready/degraded tail, so existing, more specific negatives keep
  priority and `ready` is unreachable while validation is open.
- **Invalidation.** Losing a satisfaction, blocking an obligation or clearing an
  applicability state each withdraws readiness.
- **Tests.** M11 plus a precedence-ordering assertion. Derived readiness is
  byte-identical after re-deriving every snapshot with the corrected rule
  (`npm run authority:snapshot-derived` wrote all five derived graphs and changed
  none), because all 64 contracts already resolve at an earlier precedence
  branch. The correction closes the `ready` path without altering any current
  verdict.

## C9 — Freshness axes must agree

- **Descriptive intent.** One subject, one freshness meaning.
- **Autonomous decision.** D12 staleness versus D9/D10 admission.
- **Unsafe inference.** Evidence fresh on one axis and stale on the other,
  invisible to the projection that reads the other axis.
- **Operational contract.** Integrity violation
  `evidencefreshnessaxisdivergence` when both axes are present and their
  canonical names differ, or either lacks one.
- **Fail-closed rule.** A whole-dataset violation blocks publication.
- **Tests.** M9; live census 0 rows.

## C10 — Governed contracts are identified explicitly

- **Descriptive intent.** Which `SemanticContract` instances are under lifecycle
  governance.
- **Autonomous decision.** Every applicability requirement.
- **Unsafe inference.** The converse of the usual error: a blanket requirement
  demanded a lifecycle answer from 128 descriptive nodes that are contracts only
  by inference, which would have made the model unpublishable and invited a
  weakening of the constraint instead.
- **Operational contract.** Governance is marked by `hasActivationState`,
  `mandatoryProofObligation`, `requiredValidation` or `declaresFacet`. Both the
  shape and the integrity rule key on the same four marks.
- **Fail-closed rule.** A node with any mark and no applicability state is a
  violation; a node with no mark is not asked.
- **Tests.** M10, plus a regression that every authored contract carries a mark
  and that the eight descriptive subclasses are exactly as enumerated.

## C11 — The content witness is a pure function of graph content

- **Descriptive intent.** What "the current authority" is: a value derived only
  from the canonical graph inventory.
- **Autonomous decision.** D14 publication, and every projection that binds or
  compares an authority digest (D2, D3, D8, D9, D10).
- **Unsafe inference.** The digest folded a server-reported statement count into
  its body as `total=<n>`. `db.size` is eventually consistent, so a witness read
  immediately after a commit produced a *different digest over byte-identical
  content* — a value that looked exactly like an authority digest but matched no
  settled state. A consumer pinning it would fail closed against live forever.
- **Operational contract.** The witness total is the sum of the canonical
  per-graph inventory. `client.size()`/`client.connectivity()` are not consulted
  by either witness reader, and `totalSource` names the derivation. Receipt v2
  carries `receiptSchemaVersion`, explicit `beforePublication`,
  `afterPublication` and `settled` phases, and `settled.stable`. `usf_health`
  reports `serverStatementStatistic` and no longer exposes an ambiguous `triples`.
- **Fail-closed rule.** `assertSupportedPublicationReceipt` rejects an
  unsupported schema version, any superseded field, a non-inventory total, a
  malformed phase, and an unstable settled witness. `settledAuthorityDigest` is
  the only accessor for current authority and runs the full guard.
- **Invalidation.** A settled witness differing from the post-publication witness
  marks the receipt unstable, so no digest is presented as authority.
- **Tests.** W1–W13; W1 asserts the statistic is never even read.

## C12 — Both reserved axes are named and covered

- **Descriptive intent.** Separate "whether validation is in scope is deferred"
  (contract) from "the obligation is not yet executable" (obligation).
- **Autonomous decision.** D9, D10.
- **Unsafe inference.** One word for two axes invites reading a deferred
  applicability determination as a reserved obligation, or either as satisfied.
- **Operational contract.** Distinct IRIs and distinct gap codes
  (`validation-applicability-reserved` on the contract,
  `validation-obligation-reserved` on the obligation), both RESERVED_NO_ACTION,
  both validation-scoped so neither withdraws realisation authority.
- **Fail-closed rule.** Neither reports satisfaction; reserved applicability
  binding no obligation still withholds the conclusion.
- **Invalidation.** Resolving applicability to `required` moves the decision onto
  the activation axis.
- **Tests.** V1–V4, including a zero-instance census proving coverage was achieved
  without authoring a live instance.

## Invariants now asserted

1. Every governed contract declares exactly one applicability state with a
   stated basis. (live: 64/64, 0 undeclared)
2. No contract is exempt, conditional or reserved; 61 are `unresolved` and every
   one of them is `proofblocked`.
3. No `ValidationObligation` was created or promoted; 3 exist, all `reserved`.
4. No satisfaction claim exists that is not identity-, authority- and
   head-bound. (live: 0 violations)
5. The two freshness axes agree wherever both appear. (live: 0 violations)
6. No contract is `ready` or `degraded`. (live: 0)
7. Every gap code maps to exactly one disposition, and none maps to PROCEED.
8. Paging a work plan cannot change its action state or its disposition census.
9. A bounded bootstrap packet never omits a gap at offset 0.
10. Source and live authority agree: `authority:drift` `ok: true`, 40 graphs, no
    mismatches.
11. The authority digest is a pure function of the canonical graph inventory; no
    server statistic can move it. (W1–W3)
12. Exactly one receipt field may be read as current authority, and only through a
    guard that fails closed on every malformed or superseded shape. (W4–W13)
13. Applicability-level reserved has zero instances, remains declared vocabulary,
    and is distinct from activation-level reserved in code, subject and axis. (V1–V4)
