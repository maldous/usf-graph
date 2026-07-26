# Factory decision inventory

Authority: `sha256:ecf2ed2af25dae21640cfc9ff2e58d572fea3268dcba9dfebe3a4745710ff537` (40 graphs, 107,219 triples).

Every row is a point where the factory may act on this foundation. "Absence"
records what the projection would previously have concluded from silence.

| # | Decision | Consumed graph facts | Authorising condition | Unsafe inference from absence | Required explicit state | Fail-closed behaviour |
|---|---|---|---|---|---|---|
| D1 | Orient on a task (`usf_bootstrap`, task mode) | contract inventory only | none — orientation only | empty `openGaps`/obligation arrays read as "nothing outstanding" | `gapEvaluation=not-evaluated-contract-scope-required`, `actionState=UNRESOLVED_FAIL_CLOSED` | packet states it evaluated nothing; `completionClaim=false` |
| D2 | Trace one contract (`usf_bootstrap`, contract mode) | activation, evidence, proof, realisation, decision, applicability, obligations, results | exactly one contract resolves | first row of an ambiguous name silently described; truncation dropped `openGaps` | exact single resolution; gaps lead the byte bound | ambiguous reference rejected; packet refuses to emit an incomplete gap set |
| D3 | Resolve layout authority (`usf_layout_context`) | activation, proof state, decision + `effectiveRealisationDecision`, path roles, rules | `decisionResolution ∈ {explicit, unique-accepted}` and exactly one authorised repository | multiple or missing accepted decisions collapsing to a usable context | closed `decisionResolution` vocabulary (8 values) | no decision ⇒ empty authorised repositories and paths |
| D4 | Build a materialisation plan (`usf_layout_plan`) | the shared `realisationVerdict` (D8's own verdict) | `realisationActionState=PROCEED` | a plan could be created while the projection said BLOCK, because plan tools judged only activation, proof and decision | same four-state vocabulary as D8, plus `plan-realisation-{blocked,reserved,unresolved}` | `createLayoutPlan` throws the stable state failure code before a plan exists |
| D5 | Validate a plan (`usf_layout_validate`) | the shared `realisationVerdict`, naming rule, family/format/role triple | `PROCEED` **and** every operation matches an authorised rule | validation passed on a contract the projection refused | per-operation failure codes plus `plan-realisation-*` carrying `realisationActionState` and its reasons | any failure ⇒ `ok:false`, no apply; the result also reports `validationSatisfied` so a passing plan makes no validation claim |
| D6 | Apply a plan (`usf_materialise`) | the shared `realisationVerdict`, exact source and content digests, modes | `PROCEED`, `apply`, **and** explicit coordinator | coordinator apply stayed reachable for a contract the projection blocked | coordinator flag plus `stateFailureCode` | dry-run by default; a non-PROCEED verdict refuses before any filesystem work; digest mismatch aborts and rolls back |
| D7 | Verify an external payload (`usf_artifact_*`) | descriptor digest, byte size | recorded digest equals observed bytes | — | `verified` boolean | missing descriptor ⇒ not verified |
| D8 | **Realise a contract** (`usf_contract_project` → `authorisedActions/Paths/Formats`) | activation, proof result state, decision resolution, validation applicability, obligation activation, satisfaction bindings | `actionState=PROCEED`: activation active ∧ proof successful ∧ decision resolved+accepted ∧ applicability declared and not unresolved ∧ no blocking validation state | a null activation/proof/decision, or silent validation applicability, still yielded a populated authorisation set | `actionState ∈ {PROCEED, RESERVED_NO_ACTION, BLOCK, UNRESOLVED_FAIL_CLOSED}` + `actionStateReasons` | any non-PROCEED ⇒ every authorisation array empty |
| D9 | **Claim validation** (`usf_contract_project` → `validationSatisfied`) | applicability, per-obligation activation, `satisfiedByValidationResult`, `resultForValidationObligation`, `resultState`, `validationEvaluatedAuthorityDigest`, `validationEvaluatedSourceHead`, invalidation, supersession | applicability `required` ∧ every obligation `activated` ∧ each satisfied by a result that names it, passed, and binds the current authority digest and a source head, unrevoked and unsuperseded | a passing result under the evidence-admission chain read as satisfaction for a **reserved** obligation | `validationActionState` + `validationSatisfied` + `validationGaps[].disposition` | absent or partial binding ⇒ `validationSatisfied=false` and an explicit gap |
| D10 | **Project outstanding work** (`usf_work_plan`) | mandatory proof obligations and results; applicability; obligation activation; satisfaction bindings | `actionState=PROCEED` only when the whole gap set is empty | empty `gaps` read as completion; a positive-only `requiredValidation` made 61 contracts silent | 10 gap codes each mapped to one disposition; `dispositionCounts` over the **whole** set; `completionClaim=false` | unmapped gap code throws; paging cannot hide a state |
| D11 | Mutate a lifecycle (`usf_evidence_admit`, `usf_proof_evaluate`, `usf_validation_record`) | — | never over MCP | — | explicit refusal | always refused; only the compiler transaction may change authority |
| D12 | Declare readiness (`derived:readiness`) | blocking/advisory obligation satisfaction, evidence freshness, provider and environment match, evaluation closure, **validation applicability and obligation state** | `ready` requires every blocking obligation satisfied and no unsatisfied, blocked or unresolved validation state | `ready` was reachable with an activated, unsatisfied validation obligation, because `ValidationObligation` is neither an `AssuranceObligation` nor `obligationFor`-bound | `rr:validationunsatisfied`, `rr:validationblocked`, `rr:validationapplicabilityunresolved` | unresolved applicability ⇒ `unknown`; blocked or unsatisfied ⇒ `notready` |
| D13 | Derive obligations (`rules/obligations.rq`) | governed subjects, assurance cells | every governed subject receives proof and test obligations | — | `obligationEffect` defaults to blocking | a subject with no authored effect is treated as blocking |
| D14 | Publish authority (compiler transaction) | source graphs, shapes, rules, expected authority digest, canonical graph inventory | expected digest equals live digest; SHACL conforms; integrity returns zero rows; budget passes; the settled witness equals the post-publication witness | a receipt digest folding a transient `db.size` total read as the settled authority | receipt v2: `receiptSchemaVersion`, `authorityWitness.{beforePublication,afterPublication,settled}`, `totalSource=canonical-graph-inventory` | compare-and-swap with full rollback; `assertSupportedPublicationReceipt` fails closed on an unsupported schema, a superseded field, a non-inventory total, a malformed phase or an unstable settled witness |
| D15 | Close a realisation-option decision (`evaluationClosureState`) | digest-bound admitted composite evidence, dependency/producer/authority digests | evidence admitted, fresh, integrity-valid, in scope, and digest-bound | — | `evaluationClosureState` | invalid evidence ⇒ closure incomplete ⇒ `rr:optionevaluationincomplete` |

## Which decisions carry which state

The four-state factory vocabulary is **not** a partition of the 15 decisions, and
an earlier draft of this file wrongly presented it as one. Four surfaces emit the
literal vocabulary; the other eleven resolve through their own explicit closed
vocabulary, an explicit failure result, or an unconditional refusal. A decision
can carry several states, and two of them can never reach some states at all.

| # | State mechanism | PROCEED | RESERVED_NO_ACTION | BLOCK | UNRESOLVED_FAIL_CLOSED |
|---|---|---|---|---|---|
| D1 | four-state `actionState` | — | — | — | always |
| D2 | explicit gap codes + `gapEvaluation`; **no action state** — a trace, never an authorisation | — | — | — | — |
| D3 | `decisionResolution` (8-value closed set); withholding is an empty authorisation set | — | — | via empty authorisations | `unresolved`, `no-accepted-decision` |
| D4 | error on refusal | — | — | error | — |
| D5 | `ok` + per-operation failure codes | — | — | `ok:false` | — |
| D6 | dry-run default, coordinator gate, digest-mismatch abort with rollback | — | — | error | — |
| D7 | `verified` boolean | — | — | `verified:false` | — |
| D8 | four-state `actionState` | yes | **never — by design** | yes | yes |
| D9 | four-state `validationActionState` | yes | yes | yes | yes |
| D10 | four-state `actionState` | yes | yes | yes | yes |
| D11 | unconditional refusal | — | — | always | — |
| D12 | readiness state + reason vocabulary | `ready` | — | `notready` | `unknown` |
| D13 | blocking-by-default `obligationEffect` | — | — | — | — |
| D14 | compare-and-swap; receipt v2 guard; error and full rollback | — | — | error / rejected receipt | — |
| D15 | `evaluationClosureState` vocabulary | `complete` | — | incomplete | incomplete |

D8 can never be RESERVED_NO_ACTION because the two validation-scoped gap codes
are excluded from `realisationBlocking`: reserved validation withholds the
validated claim, never the realisation authority an accepted decision and a
successful proof already granted. That is the intended asymmetry, not an
omission.

## Counts

- Decisions identified: **15**
- Carrying an explicit authority path: **15**
- Emitting the literal four-state vocabulary: **4** (D1, D8, D9, D10)
- Resolving through another explicit closed vocabulary: **3** (D3, D12, D15)
- Resolving through an explicit failure result or unconditional refusal: **6**
  (D4, D5, D6, D7, D11, D14)
- Carrying no consumer-facing state by construction: **2** (D2, a trace whose
  withholding is its gap set; D13, a derivation)
- Unsafe inference paths remaining: **0 within this scope**. Residual boundaries
  are R1–R6 in `operational-completeness-findings.md`; none can select PROCEED.
