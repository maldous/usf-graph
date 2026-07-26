# Adversarial counterexample matrix

Each row is the smallest graph state that could plausibly have produced a
favourable conclusion. All are Node regressions in
`processes/semantic-assurance/repository-materialisation-gateway.test.mjs` and
`processes/semantic-assurance/semantic-authority-mcp.test.mjs`. Method: state the
positive path, construct the minimal incomplete or malformed state, check whether
the projection acts, and require it to resolve to a non-PROCEED state.

## Projection states (`usf_contract_project`, `usf_work_plan`)

| # | Adversarial state | Realisation `actionState` | `validationActionState` | Gap emitted | Satisfied |
|---|---|---|---|---|---|
| A1 | no applicability statement at all | UNRESOLVED_FAIL_CLOSED | UNRESOLVED_FAIL_CLOSED | `validation-applicability-unresolved` | false |
| A2 | applicability explicitly `unresolved` | UNRESOLVED_FAIL_CLOSED | UNRESOLVED_FAIL_CLOSED | `validation-applicability-unresolved` | false |
| A3 | `conditional` with no structured condition | UNRESOLVED_FAIL_CLOSED | UNRESOLVED_FAIL_CLOSED | `validation-applicability-conditional-unevaluated` | false |
| A4 | `notrequired` with no exemption authority | BLOCK | UNRESOLVED_FAIL_CLOSED | `validation-exemption-unwarranted` | false |
| A5 | `notrequired` citing a **failed** proof result | BLOCK | UNRESOLVED_FAIL_CLOSED | `validation-exemption-unwarranted` | false |
| A6 | obligation with no activation state | UNRESOLVED_FAIL_CLOSED | UNRESOLVED_FAIL_CLOSED | `validation-obligation-activation-unresolved` | false |
| A7 | obligation with an invented activation state | UNRESOLVED_FAIL_CLOSED | UNRESOLVED_FAIL_CLOSED | `validation-obligation-activation-unresolved` | false |
| A8 | obligation `blocked` | BLOCK | BLOCK | `validation-obligation-blocked` | false |
| A9 | `required` binding no obligation | PROCEED (realisation authority stands) | UNRESOLVED_FAIL_CLOSED | none | false |
| A10 | satisfying result bound to a **sibling** obligation | BLOCK | PROCEED | `validation-satisfaction-not-current` | false |
| A11 | satisfying result bound to a **superseded authority digest** | BLOCK | PROCEED | `validation-satisfaction-not-current` | false |
| A12 | satisfying result with **no** bound authority digest | BLOCK | PROCEED | `validation-satisfaction-not-current` | false |
| A13 | satisfying result with **no** bound source head | BLOCK | PROCEED | `validation-satisfaction-not-current` | false |
| A14 | satisfying result that did not pass | BLOCK | PROCEED | `validation-satisfaction-not-current` | false |
| A15 | satisfying result carrying an invalidation condition | BLOCK | PROCEED | `validation-satisfaction-not-current` | false |
| A16 | satisfying result already superseded | BLOCK | PROCEED | `validation-satisfaction-not-current` | false |
| A17 | contract declaring **two** applicability states | rejected | rejected | — | — |
| A18 | live authority changes mid-projection | rejected | rejected | — | — |
| A19 | a gap code with no declared disposition | throws | — | — | — |
| A20 | 61 gaps paged 50 at a time | BLOCK on **every** page; `dispositionCounts` identical and computed over the whole set | — | all | false |

Positive counterparts, each asserted separately:

| # | Positive state | Result |
|---|---|---|
| P1 | applicability `required`, obligation `reserved` | `actionState=PROCEED` with a full authorisation set, `validationActionState=RESERVED_NO_ACTION`, `validationSatisfied=false` |
| P2 | obligation `activated`, result names it, passed, binds the current authority digest and a source head, unrevoked, unsuperseded | `validationSatisfied=true`, no gaps, `actionState=PROCEED`, `completionClaim` still `false` |
| P3 | obligation `activated`, nothing satisfying it | `actionState=BLOCK`, `validationActionState=PROCEED` (validation is executable) |

## Bootstrap packet states

| # | Adversarial state | Required outcome |
|---|---|---|
| B1 | a canonical name resolving to two contracts | rejected — "exactly one semantic contract" |
| B2 | orientation mode (no contract) | `gapEvaluation=not-evaluated-contract-scope-required`, `actionState=UNRESOLVED_FAIL_CLOSED`, `completionClaim=false` |
| B3 | 200 padded claims exhausting the 8 KiB bound | `truncated=true` and the **complete** gap set retained; the packet refuses to emit at offset 0 if the gap set cannot be bounded |
| B4 | passing result with a full evidence-admission chain but no obligation identity, authority digest or source head | `evidenceAdmitted=true`, `current=false`, gap `current-validation-result-unavailable` retained |
| B5–B10 | that result mutated to: sibling obligation, no authority digest, no source head, invalidated, superseded, not passing | `current=false` in every case |
| B11 | reserved obligation | gap `validation-obligation-reserved` |
| B12 | applicability absent or unresolved | gap `validation-applicability-unresolved` |

## Model and rule states

| # | Adversarial state | Enforcement | Evidence |
|---|---|---|---|
| M1 | a governed contract with no applicability state | SHACL `contractvalidationapplicability` + integrity `contractvalidationapplicabilityundeclared` | live: 0 rows |
| M2 | applicability outside the closed vocabulary | `sh:class usf:ValidationApplicabilityState` | vocabulary regression asserts exactly 5 states |
| M3 | `required`/`reserved` binding no obligation, or binding one that does not bind back | `validationapplicabilityclosure` | shape constraint |
| M4 | `notrequired` while binding an obligation, or without successful-proof authority | `validationapplicabilityclosure` | shape constraint |
| M5 | `unresolved` smuggling an obligation or exemption authority | `validationapplicabilityclosure` | shape constraint + regression over the 61 migrated contracts |
| M6 | an obligation whose contract denies or defers validation | integrity `validationobligationoutsidecontractapplicability` | live: 0 rows |
| M7 | satisfaction without identity, passing state, admitted evidence, authority digest or source head, or after invalidation/supersession | integrity `validationsatisfactionwithoutcurrentidentitybinding` | live: 0 rows |
| M8 | a reserved or blocked obligation carrying a satisfaction claim | SHACL `reservedvalidationobligationnotsatisfied` + integrity `reservedvalidationobligationsatisfied` | live: 0 rows |
| M9 | the two freshness axes disagreeing on one subject | integrity `evidencefreshnessaxisdivergence` | live: 0 rows |
| M10 | a lifecycle requirement misfiring on a descriptive `SemanticContract` subclass | governance-mark discriminator in both the shape and the rule | live: 0 of 128 descriptive instances demanded an answer; first attempt without it produced 256 violations |
| M11 | readiness reaching `ready` past validation | three readiness terms inserted before the ready/degraded tail | live: 0 contracts `ready` or `degraded`; derived readiness byte-identical to the pre-change snapshot |

## Totals

- Adversarial cases: **43** (20 projection + 12 bootstrap + 11 model/rule)
- Unsafe states rejected or resolved to a non-PROCEED state: **43**
- Unsafe states accepted: **0**
- Remaining false-closure paths: **0** in this scope; R1–R5 in
  `operational-completeness-findings.md` are read-only or receipt-level and
  cannot select PROCEED.
