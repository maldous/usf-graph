# Operational-completeness findings

Two-layer review of every foundational family that can influence factory
behaviour. Layer 1 asks whether the model describes the domain; Layer 2 asks
whether it authorises each autonomous action and blocks each unsafe inference.

Findings are recorded only where they change an operational decision.

## Corrected

| # | Family | Layer 1 | Layer 2 defect | Evidence it was live | Status |
|---|---|---|---|---|---|
| F1 | validation applicability | complete | `usf:requiredValidation` was positive-only, so absence carried no meaning. 61 of 64 governed contracts said nothing, and a consumer could read that as "validation is not required". | live census: 3 contracts with `requiredValidation`, 61 silent | corrected — closed 5-state vocabulary, exactly once per governed contract |
| F2 | validation obligations / results | complete after the PR #14 satisfaction contract | `usf_work_plan` still decided satisfaction with the older evidence-admission chain, which is weaker than the contract SHACL enforces. The materialisation obligation is **reserved** (SHACL forbids satisfying it) yet the old chain reported no gap. | `usf_work_plan` returned `gaps: []` for `repositoryexternalartefactmaterialisation`; `oldChainPasses=true`, `satisfiedByValidationResult` absent | corrected — one satisfaction definition, identity- and authority-bound |
| F3 | work plans | complete | the projection had no action state and no way to express reserved, blocked or unresolved. An empty `gaps` array was indistinguishable from an evaluated, complete contract. | same call as F2 | corrected — `actionState`, `dispositionCounts`, `completionClaim: false` |
| F4 | contracts / realisations / permissions | complete | `authorisedActions` was granted from activation ∧ proof ∧ decision alone. Validation state was listed but never consulted, and a null state was not distinguished from a negative one. | `projectContract` returned a full authorisation set with an unsatisfied, reserved obligation | corrected — `actionState` + `actionStateReasons`; nulls resolve to UNRESOLVED |
| F5 | bootstrap orientation | complete | task-mode emitted every obligation array and `openGaps` as `[]` with no marker that nothing had been evaluated. | `usf_bootstrap {task}` returned `openGaps: []` | corrected — `gapEvaluation`, `actionState`, `completionClaim` |
| F6 | bootstrap bounding | complete | `openGaps` was last in the fill order, so byte-bound truncation dropped the negative states first. | contract packet truncated at 8 KiB with `truncated: true` | corrected — gaps lead the order; the packet refuses to emit an incomplete gap set at offset 0 |
| F7 | identity | complete | contract resolution used `LIMIT 1`, silently describing one of an ambiguous set. | code path in `semantic-bootstrap-packet.mjs` | corrected — exactly one resolution required |
| F8 | readiness / completion | complete | the blocking-obligation projection enumerates `ProofObligation`, `TestObligation` and `EvidenceRequirement`. `ValidationObligation` is neither an `AssuranceObligation` nor `obligationFor`-bound, so readiness could not see it and `ready` was reachable past an unsatisfied validation obligation. | `readiness.rq` satisfaction table; live `ValidationObligation` count with `obligationFor` = 0 | corrected — three new readiness terms and reasons, inserted after the existing negatives so current output is unchanged |
| F9 | evidence admission | descriptively complete but duplicated | two freshness axes coexist: `usf:hasFreshness`/`urn:usf:freshness:*` (readiness staleness, 13 uses) and `usf:hasFreshnessState`/`urn:usf:evidencefreshnessstate:*` (admission, 8 uses). Nothing required them to agree, so evidence could be fresh in one projection and stale in the other. | live: 8 subjects carry both, 5 carry only the legacy axis, 0 only the new one | corrected — integrity violation `evidencefreshnessaxisdivergence`; currently zero rows |
| F10 | contracts (class overloading) | incomplete | `usf:SemanticContract` is the superclass of `AccessibilityProfile`, `ArtefactPlan`, `AutomationWorkflowContract`, `CompatibilityContract`, `LocalisationProfile`, `RendererContract`, `UISemanticModel` and `ViewModel`. Under the reasoning schema 128 descriptive nodes are contracts, so "every contract" is not "every governed contract" and a universal lifecycle requirement misfires on a view model. | first publication attempt produced 256 SHACL violations, all on descriptive subclass instances | corrected in enforcement — governance keyed on activation state, mandatory proof obligation, required validation or declared facet; live check: 0 governed contracts undeclared, 0 descriptive instances demanded an answer |
| F11 | materialisation and publication (witness stability) | complete | the authority digest folded a server-reported statement count into a content digest as a trailing `total=<n>` term. `db.size` (exposed as both `client.size()` and `client.connectivity()`) is eventually consistent, so a witness read immediately after a commit produced a different digest over byte-identical content. | receipt named `sha256:f0b212be…`/110,537 while the settled witness was `sha256:ecf2ed2a…`/107,219; recomputing over the unchanged inventory with the receipt total reproduced `f0b212be…` exactly | corrected — the witness total is the canonical inventory sum and the statistic is never consulted; receipt v2 with explicit before/after/settled phases and superseded fields rejected |
| F12 | validation applicability (reserved axis coverage) | complete | applicability-level `reserved` had complete code paths but no regression, and the two `reserved` axes were reported ambiguously enough to be conflated. | disposition asserted only indirectly; zero live instances | corrected — dedicated regressions for the axis, its distinctness from activation-level reserved, and a zero-instance census, without authoring a live instance |

## Residual boundaries (precisely identified, all fail closed)

| # | Boundary | Why it is not closed here | Current behaviour |
|---|---|---|---|
| R1 | A satisfying `ValidationResult` binds `validationEvaluatedAuthorityDigest`, but no in-graph rule requires it to equal *current* authority, because the graph holds no current-authority resource. | Enforcing it in-graph would require publishing the authority digest into the authority it describes. | Enforced at the projection boundary instead: the gateway compares the bound digest against the live witness and reports `validation-satisfaction-not-current`. The same currentness gap applies to `evaluatedAuthorityDigest` on realisation-option evidence, which is checked only for internal consistency. |
| R2 | `decisionResolution`'s 8-value vocabulary lives only in JavaScript, not in the model. | Adding a model vocabulary would not change any decision; the underlying decision states are already model-governed. | Already closed and fail-closed in code; no state can be invented, but the label set is outside semantic authority. |
| R3 | Gate criteria (`ReadinessGateResult`) aggregate criteria, and validation obligations bind contracts, so validation does not reach the gate projection. | No criterion currently carries a validation obligation, so there is nothing to check; adding the join would encode a relation the model does not assert. | Gate readiness is unchanged; all 6 gates are `notready`. |
| R4 | `TestObligation` (130 instances) has no result or satisfaction predicate in use; readiness reads `satisfiedByTestResult`, which has 0 instances. | The family is descriptive today; fabricating results would be the exact defect under review. | Every test obligation counts as unsatisfied, so readiness stays `notready`. No projection claims otherwise. |
| R5 | `usf_health` still reports a `db.size` liveness statistic. | A liveness probe needs some signal, and it is not a witness. | Named `serverStatementStatistic` so it cannot be read as a content witness; the ambiguous `triples` field was removed. Any consumer needing a total must take the inventory-derived value from `usf_bootstrap`'s authority block. |

## Families reviewed with no operational defect found

capabilities, services, requirements, facets (descriptive only — deliberately
excluded from gap sets), deliverables, evidence requirements, proof obligations,
proof results, decisions, providers, components, storage, events and webhooks,
configuration, lifecycle, invalidation, supersession, materialisation and
publication, UI/UX capability gating, runtime assumptions.

Two notes recorded rather than changed:

- **Facet completeness is descriptive.** The materialisation contract declares
  `facetStatus complete` on its validation facet while its `ValidationObligation`
  is reserved and unsatisfied. That is consistent: the facet says the model
  describes validation. Facet status is deliberately absent from every gap set
  and from every authorisation condition.
- **Runtime assumption.** Cross-graph meaning depends on the endpoint's
  `query.all.graphs` option, which `operations/stardog/provision-authority-endpoint.mjs`
  sets. Nothing re-checks it at query time; if it were off, projections would
  under-report rather than over-authorise.
