# Final foundation readiness report

**OPERATIONALLY_COMPLETE_FOR_FACTORY_SCOPE: YES** — for the current factory
scope, which is the repository-external artefact materialisation contract and the
bounded MCP projection surface. Not a claim about the other 62 contracts, all of
which are proof-blocked and fail closed.

**FACTORY_CAN_ACT_WITHOUT_INVENTING_MEANING: YES** — every conclusion the factory
consumes now resolves to one of PROCEED, RESERVED_NO_ACTION, BLOCK or
UNRESOLVED_FAIL_CLOSED through an explicit authority path, and absence selects
UNRESOLVED_FAIL_CLOSED in every case tested.

## Foundational families reviewed

| Family | Descriptive | Operational | Remaining blocker |
|---|---|---|---|
| capabilities, services, requirements | complete | complete | none |
| contracts | complete | complete after C1, C3, C10 | none; `SemanticContract` class overloading recorded (F10) |
| facets | complete | complete — descriptive only, excluded from every gap set and authorisation condition | none |
| deliverables | complete | complete | none |
| evidence requirements, evidence admission | complete | complete after C9 | none |
| proof obligations, proof results | complete | complete — all 64 contracts carry a mandatory proof obligation; active contracts require a successful one | none |
| validation applicability | was positive-only | complete after C1 | none |
| validation obligations, validation results | complete | complete after C2, C4 | none |
| test obligations | complete | descriptive only | R4 — 130 obligations, no result predicate in use; every one counts unsatisfied |
| decisions, realisations | complete | complete | R2 — `decisionResolution` labels are code-side |
| providers, components | complete | not yet factory-consumed (all provider contracts proof-blocked) | none in scope |
| permissions and authority | complete | complete — mutation is coordinator-only, MCP refuses lifecycle writes | none |
| identity | complete | complete after C7 | none |
| storage, events and webhooks, configuration | complete | not yet factory-consumed | none in scope |
| lifecycle | complete | complete | none |
| readiness | complete | complete after C8 | R3 — gate criteria carry no validation obligations |
| completion | complete | complete after C3, C6 | none |
| work plans | complete | complete after C2, C3 | none |
| invalidation, supersession | complete | complete after C2 | R1 — currentness enforced at the projection boundary, not in-graph |
| runtime assumptions | complete | enforced at provisioning (`query.all.graphs`) | not re-checked per query; would under-report, not over-authorise |
| materialisation and publication | complete | complete | R5 — the publication receipt's post-digest field is not the settled witness |
| UI/UX capability gating | complete | not yet factory-consumed | none in scope |

## Factory decisions

The four action states are **not a partition** of the 15 decisions. An earlier
draft of this report presented them as one and quoted 12 BLOCK and 10 UNRESOLVED;
those figures were not derived from the implementation and are withdrawn. The
accurate breakdown, and the per-decision matrix, are in
`factory-decision-inventory.md`.

- Total identified: **15**
- Carrying an explicit authority path: **15**
- Emitting the literal four-state vocabulary: **4** — D1 (always
  UNRESOLVED_FAIL_CLOSED), D8 realisation `actionState`, D9
  `validationActionState`, D10 work-plan `actionState`
- Resolving through another explicit closed vocabulary: **3** — D3
  `decisionResolution` (8 values), D12 readiness state and reason, D15
  `evaluationClosureState`
- Resolving through an explicit failure result or unconditional refusal: **6** —
  D4, D5, D6, D7, D11, D14
- Carrying no consumer-facing action state by construction: **2** — D2, a trace
  whose withholding is its explicit gap set and which never authorises action;
  D13, a derivation
- D8 can never be RESERVED_NO_ACTION: reserved validation withholds the validated
  claim, never realisation authority already granted by an accepted decision and
  a successful proof. Intended asymmetry, documented in the inventory.
- Unsafe inference paths remaining: **0** in scope

## Validation applicability

| State | Contracts |
|---|---|
| required | 3 |
| notRequired | 0 |
| conditional | 0 |
| reserved | 0 |
| unresolved | 61 |

"Reserved" names two different axes, and the zero above is not a contradiction:

- **Applicability-level** `urn:usf:validationapplicabilitystate:reserved` — "whether
  validation applies is deliberately deferred". **Zero contracts.** It is declared,
  reachable, mapped to RESERVED_NO_ACTION and excluded from realisation blocking,
  but uninstantiated, and therefore not covered by a dedicated regression (R6).
- **Activation-level** `urn:usf:validationactivationstate:reserved` — "the obligation
  is not yet executable". **All three** bound obligations.

So nothing is satisfied and nothing is executable, and every RESERVED_NO_ACTION
observed live comes from activation-level `reserved`, not from the applicability
row reading zero.

## Adversarial validation

- Cases: **43**
- Unsafe states rejected or resolved to a non-PROCEED state: **43**
- Unsafe states accepted: **0**
- Remaining false-closure paths: **0** in scope

## Corrections

| Defect | Operational contract added | Fail-closed behaviour | Tests |
|---|---|---|---|
| positive-only applicability, 61 contracts silent | closed 5-state `hasValidationApplicability`, exactly once per governed contract, with per-state binding constraints | absent/unresolved/conditional ⇒ UNRESOLVED_FAIL_CLOSED | A1–A3, M1–M5 |
| two satisfaction definitions; the factory-facing one was weaker | one identity-, authority- and head-bound definition | any missing conjunct ⇒ unsatisfied + explicit gap | P2, A10–A16, B4–B10, M7 |
| empty projections indistinguishable from clean ones | `actionState`, `dispositionCounts`, `completionClaim: false`, `gapEvaluation` | absence never selects PROCEED | A1–A20, B2 |
| authorisation granted without consulting validation | `actionStateReasons`, separate `validationActionState` | activated + unsatisfied ⇒ BLOCK | P1, P3, A8 |
| truncation dropped negative states first | gaps lead the byte bound; refuse rather than shorten | error instead of a clean-looking packet | B3 |
| ambiguous contract identity | exactly one resolution | rejection | B1 |
| readiness blind to validation | three readiness terms and reasons | blocked/unsatisfied ⇒ notready; unresolved ⇒ unknown | M11 |
| two freshness axes with no coherence rule | `evidencefreshnessaxisdivergence` | whole-dataset violation blocks publication | M9 |
| governed vs descriptive contract population | four governance marks in both enforcement layers | a marked node with no state is a violation | M10 |

## Readiness

- Ready: **0** contracts, **0** gates
- Blocked (`notready`): **63** contracts, **6** gates
- Unresolved/incompatible: **1** contract (`incompatible`)
- Stale or invalidated: **0** satisfactions exist to invalidate; 0 stale-evidence
  readiness reasons
- Re-deriving every snapshot with the corrected rule
  (`npm run authority:snapshot-derived`) rewrote all five derived graphs and
  changed none: `derived/readiness.trig` is byte-identical. Every contract
  already resolves at an earlier precedence branch, so the correction closed the
  `ready` path without altering any current verdict.

## Authority

- Source HEAD: `1637909` (`main`, clean at session start); corrections are in the
  working tree and **not yet committed**
- Canonical validation: `npm run test:semantic-assurance` → **195 tests, 195
  pass, 0 fail, 0 skipped**
- Publication: `--mode=validate` `ok: true`, contamination 0, budget PASS;
  `--mode=commit` `ok: true`, `confirmed-response`
- Authority digest: `sha256:ecf2ed2af25dae21640cfc9ff2e58d572fea3268dcba9dfebe3a4745710ff537`
  (40 graphs, 107,219 triples; was
  `sha256:19b46fa43cf6cddebc53fa213569a38d762905b7e16c0082ec9c3b33b94bf45d` at
  107,005)
- Drift: `npm run authority:drift` → `ok: true`, 40 graphs, no mismatches
- Realisation-option evidence resealed against
  `sha256:19b46fa4…` with a fresh acquisition
  (`sha256:12f63ab981d6a330a8d15e8855a064b6419210dca2e32069c7e69c773b0a766e`);
  declared Stardog constraint carried forward unchanged (12.1.0, enterprise,
  enterprise)

## Remaining blockers

1. **Source is uncommitted.** Live authority is ahead of `origin/main`. Commit
   and push the branch, or revert the publication, before any other session
   relies on it.
2. **R1** — validation-satisfaction currentness is enforced at the projection
   boundary only; no in-graph rule ties a satisfaction to current authority.
3. **R3** — gate criteria carry no validation obligations, so gate readiness does
   not consider validation.
4. **R4** — `TestObligation` has no satisfaction path in use; the family is
   descriptive and every instance counts unsatisfied.
5. **R5** — the authority digest folds a server-reported statement count into a
   content digest, so a receipt read before the store settles yields a different
   digest over identical content. Proven: recomputing over the current, unchanged
   40-graph inventory with the receipt's total (110,537) reproduces
   `f0b212be…` exactly, so all 40 per-graph digests matched and only the total
   differed. Consumers must read the settled witness; the durable fix is to sum
   the inventory instead of trusting `db.size`.
6. **R6** — applicability-level `reserved` is uninstantiated and has no dedicated
   regression; it cannot select PROCEED.

None of these can produce success, exemption, readiness or completion from
silence. All fail closed.
