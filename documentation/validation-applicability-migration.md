# Validation-applicability migration

## Why

`usf:requiredValidation` is a positive-only statement. Its absence carried no
meaning, so a consumer could read silence as "validation is not required" and
treat a contract as complete. 61 of 64 governed contracts were silent.

## The closed model

`usf:hasValidationApplicability` is an `owl:FunctionalProperty` with domain
`usf:SemanticContract` and range `usf:ValidationApplicabilityState`. The range is
a closed five-value set; a consumer that cannot match one of them has no answer
and must fail closed.

| State | Meaning | Binding requirement (SHACL) |
|---|---|---|
| `required` | validation is in scope | ≥1 `requiredValidation` obligation that binds back with `validationForContract` |
| `reserved` | the applicability determination is deliberately deferred | ≥1 bound obligation, same back-binding |
| `notrequired` | explicit exemption | **no** bound obligation **and** `validationApplicabilityAuthority` citing a `ProofResult` in state `successful` |
| `conditional` | applicability depends on structured conditions | ≥1 `validationApplicabilityCondition` carrying `conditionSubject`, `conditionPredicate` and `conditionRequiredValue` |
| `unresolved` | no current fact justifies any other state | **no** bound obligation and **no** exemption authority |

Every state also requires `usf:validationApplicabilityReason`.

Applicability and obligation activation are separate axes and are never
conflated. Both use the word "reserved", so each is always named in full:

- **applicability-level** `urn:usf:validationapplicabilitystate:reserved` — whether
  validation is in scope is deliberately deferred. Contract-level. **0 instances.**
- **activation-level** `urn:usf:validationactivationstate:reserved` — the obligation
  exists but is not yet executable. Obligation-level. **3 instances.**

`required` says validation is in scope; the obligation's own
`hasValidationActivationState` (`reserved` | `activated` | `blocked`) says whether
it is executable. Neither implies satisfaction. The two axes emit distinct gap
codes on distinct subjects (`validation-applicability-reserved` on the contract,
`validation-obligation-reserved` on the obligation) and both are
regression-covered.

## Enforcement

- **SHACL** — `urn:usf:shape:contractvalidationapplicability` (exactly one state
  and a stated basis, for governed contracts) and
  `urn:usf:shape:validationapplicabilityclosure` (five state-specific binding
  constraints, including the converse leak: a contract that binds an obligation
  must declare `required`, `reserved` or `conditional`).
- **Integrity rules** — `contractvalidationapplicabilityundeclared`,
  `validationobligationoutsidecontractapplicability`.
- **Governed population** — the requirement is keyed on the four governance
  marks (`hasActivationState`, `mandatoryProofObligation`, `requiredValidation`,
  `declaresFacet`), not on `a usf:SemanticContract`, because eight descriptive
  classes are `rdfs:subClassOf usf:SemanticContract` and contribute 128 inferred
  instances that carry no lifecycle. Live check: 64 governed contracts, 0 without
  a declared state, 0 descriptive instances required to answer.

## Result (live, `sha256:ecf2ed2a…`)

| State | Contracts |
|---|---|
| required | 3 |
| notRequired | 0 |
| conditional | 0 |
| reserved | 0 |
| unresolved | 61 |

The three `required` contracts are `repositoryexternalartefactmaterialisation`,
`compilersemanticenforcement` and `deterministicdevelopmentandtestsubstitutes` —
exactly the three that already bound a `ValidationObligation`. All three
obligations are `reserved`, so none is satisfied and none is executable.

## What was deliberately not migrated

- **No contract was migrated to `notrequired`.** No exemption proof exists, and
  an exemption is a positive claim.
- **No contract was migrated to `conditional` or `reserved`.** No authored
  condition or deferral decision supports either.
- **No `ValidationObligation` was fabricated to close a count.** The obligation
  set is unchanged at 3.
- **No historical result was promoted.** The 3 existing `ValidationResult`
  records remain unbound to any obligation via
  `resultForValidationObligation`; they are historical observations.
- Every one of the 61 `unresolved` contracts is `proofblocked`. No active
  contract is unresolved. This is asserted by a regression, so a future active
  contract cannot silently inherit `unresolved`.

## Migration reason recorded on the 61

> Validation applicability is unresolved: this contract is proof-blocked and no
> validation-evidence producer, admission path or exemption proof exists, so no
> current fact justifies required, notRequired, conditional or reserved.
> Unresolved is recorded deliberately, fails closed, and is not an exemption, a
> satisfaction or a completion claim.

## Downstream effect

`unresolved` is not inert. It produces the gap
`validation-applicability-unresolved` with disposition
`UNRESOLVED_FAIL_CLOSED`, makes `usf_contract_project` withhold every
authorisation, and drives readiness to `unknown` with reason
`rr:validationapplicabilityunresolved`.
