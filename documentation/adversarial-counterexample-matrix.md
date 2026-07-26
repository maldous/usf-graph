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

## Publication witness and receipt (R5)

External review found the first version of this guard trusted the receipt's own
`settled.stable` boolean. Stability is now **derived** from complete phase equality
and a declared flag is only ever cross-checked, so nothing in a receipt is evidence
for itself.

| # | Adversarial state | Required outcome |
|---|---|---|
| W1 | server count reports 2, 110,537, 0, 999,999 and −1 across reads while graph content is byte-identical | one digest for all five; total is the inventory sum; the statistic is **never read** (asserted by call count) |
| W2 | one graph's content changes | digest moves — the witness still tracks content |
| W3 | any total other than the inventory sum folded into the digest | different digest — the mechanism that produced the superseded receipt value |
| W4 | receipt carrying `postAuthorityDigest`, `postTriples` or top-level `evaluatedAuthorityDigest` | rejected as superseded fields |
| W5 | the full historical receipt shape | rejected on schema version before any field is read |
| W6 | `receiptSchemaVersion` absent, `null`, `0`, `1`, `3`, `99`, `"2"`, `{}`, `[]` | rejected — older and newer both fail closed |
| W7 | receipt that is `undefined`, `null`, a string, a number or an array | rejected |
| W8 | `totalSource` absent, `db.size`, `server-statement-statistic`, `connectivity` | rejected |
| W9 | `authorityWitness` absent, `null`, a string, a number or an array | rejected |
| W10 | any phase absent, `null`, a string, a number, `[]`, `{}`, digest-only, counts-only | rejected per phase |
| **W11** | **differing `afterPublication` and `settled` digests with forged `stable: true`** | **rejected — stability is derived, not read** |
| **W12** | **equal digests but different `graphCount` or `triples`** | **rejected — complete phase equality is required** |
| W13 | declared `settled.stable` of `false`, `"true"`, `0`, `null` against genuinely stable phases | rejected as self-contradictory; omitting the flag entirely is accepted |
| W14 | `algorithm` absent, `null`, `''`, `…-v1`, `sha256`, uppercased | rejected — the exact published algorithm is required |
| W15 | digests with uppercase hex, uppercase scheme, 63 or 65 hex chars, non-hex, no prefix, `sha1:`, trailing space, empty, `null`, `undefined`, number, object — for `expected`, `evaluated` and all three phases | rejected — exact lowercase `sha256:<64 hex>` only |
| W16 | `graphCount`/`triples` of `-1`, `1.5`, `NaN`, above `MAX_SAFE_INTEGER`, `"40"`, `null`, `undefined`, `true`, `{}` | rejected — non-negative safe integers only |
| W17 | `beforePublication` ≠ `expected`; `evaluated` ≠ `expected` | rejected — the receipt must describe one compare-and-swap |
| W18 | validate mode whose `settled` digest is not the original authority | rejected — rollback must be proven to have restored it |
| W19 | `mode` absent, `null`, `''`, `dry-run`, `COMMIT`, `apply`, a number | rejected — the relationship is mode-specific |
| W20 | `settledAuthorityDigest` on any of the above | throws — it is the only accessor and runs the complete guard |

## Materialisation plan and apply (review: execution-boundary bypass)

`projectContract` computed a validation-aware realisation state while
`createLayoutPlan`, `validateLayoutPlan` and `applyLayoutPlan` judged only
activation, proof and decision from `layoutContext`. An activated-but-unsatisfied
validation obligation therefore produced `actionState=BLOCK` in the projection
while `usf_layout_plan` still succeeded and coordinator apply remained reachable.
There is now one `realisationVerdict`, and these cases call the plan tools
**directly** so they prove the bypass is closed rather than that the projection
happens to agree.

| # | State | Required outcome at create / validate / apply |
|---|---|---|
| P1 | activated but unsatisfied validation obligation | BLOCK · `plan-realisation-blocked` · reason `missing-current-passing-validation` |
| P2 | blocked validation obligation | BLOCK · reason `validation-obligation-blocked` |
| P3 | absent applicability | UNRESOLVED_FAIL_CLOSED · `plan-realisation-unresolved` |
| P4 | explicitly unresolved applicability | UNRESOLVED_FAIL_CLOSED |
| P5 | unknown obligation activation value | UNRESOLVED_FAIL_CLOSED · reason `validation-obligation-activation-unresolved` |
| P6 | missing semantic lifecycle | UNRESOLVED_FAIL_CLOSED · reason `contract-lifecycle-unresolved` |
| P7 | non-active semantic lifecycle (`retired`) | BLOCK · reason `contract-lifecycle-not-active` |
| P8 | unsuccessful proof result | BLOCK · reason `contract-proof-not-successful` |
| P9 | absent proof result | UNRESOLVED_FAIL_CLOSED · reason `contract-proof-result-unresolved` |
| P10 | no accepted decision (draft) | UNRESOLVED_FAIL_CLOSED · reason `decision-no-accepted-decision` |
| P11 | ambiguous canonical name, lifecycle, activation, proof result or proof state | the verdict, `createLayoutPlan` and `projectContract` all reject with `ambiguous <conclusion>` |
| P12 | every declared gap code | none maps to PROCEED; the state→failure-code table is complete |
| P13 | **the live reserved-validation contract** | realisation **PROCEED**, validation `RESERVED_NO_ACTION`, `validationSatisfied=false`, dry-run completes and the passing plan still carries `validationSatisfied: false` |

P1–P10 are each asserted at all three surfaces (30 refusals) plus the verdict
itself; P11 at three surfaces (15 refusals). A plan minted while the contract did
authorise realisation is replayed against each state, so nothing about the plan is
malformed — only the authority is.

## Reserved applicability axis (R6)

Applicability-level `reserved` (is validation in scope?) and activation-level
`reserved` (is the obligation executable?) are different axes with distinct gap
codes on distinct subjects. Every RESERVED_NO_ACTION observed live comes from
activation-level `reserved` on the three bound obligations; the applicability axis
has zero live instances and is covered below **without authoring one**.

| # | Case | Required outcome |
|---|---|---|
| V1 | applicability-level `reserved` with an activated obligation | `validationActionState=RESERVED_NO_ACTION`; gap `validation-applicability-reserved`, disposition RESERVED_NO_ACTION, subject is the **contract**; not satisfied; not PROCEED |
| V2 | applicability-level vs activation-level `reserved`, obligation held constant | distinct codes on distinct subjects; the applicability axis adds exactly one conclusion and changes nothing else; neither reports satisfaction; neither withdraws realisation authority |
| V3 | applicability-level `reserved` binding no obligation | still non-PROCEED; the conclusion is withheld rather than downgraded |
| V4 | census of the authored model (the drift-verified source of live authority) | **zero** applicability-level reserved instances, the state still declared vocabulary, activation-level reserved ≥3 |

## Totals

- Adversarial cases: **80** (20 projection + 12 bootstrap + 11 model/rule + 20
  publication witness/receipt + 4 reserved applicability + 13 plan/apply)
- Unsafe states rejected or resolved to a non-PROCEED state: **80**
- Unsafe states accepted: **0**
- Remaining false-closure paths: **0** in this scope. The single residual boundary
  (R5, `usf_health`'s liveness statistic) is named so it cannot be read as a
  witness and cannot select PROCEED.
