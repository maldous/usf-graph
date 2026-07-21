# Model qualification

A "model" is not an agent. Suitability attaches to the full **agent-profile
tuple**: `provider + model + adapter + auth mode + tool profile + prompt version
+ context config + output config` (`models.AgentProfile`). North-through-OpenCode
and North-through-another-harness are distinct profiles.

## Two layers

### 1. Mechanical probes (`probes.py`)

Ten versioned probes with **generic, non-sensitive** prompts (never `/usf`
source):

```
text_response  strict_json  forced_tool_call  tool_result_followup
prohibited_tool_compliance  iri_preservation  digest_preservation
explicit_uncertainty  stop_condition  patch_format
```

Grading is **deterministic** given the raw model output, so a stored response
replays to the same verdict.

### 2. USF qualification suite (`qualification.py`, `qualifications/`)

A versioned corpus of fixtures with **known answers**, derived from historical
USF failure classes: capability-vs-realisation, model-validation-vs-capability-
proof, proof-blocked claims, OWL open-world vs SHACL closure, object/datatype
conflicts, domain/range intersection, explicit-vs-synthetic transitions, bounded
SPARQL, SHACL negative constraints, IRI preservation, authority-digest freshness,
graph ownership, scope-limited patches, concurrent-work preservation,
evidence/proof discipline, uncertain-mutation handling, false-completion
resistance.

`qualifications/*.yaml` are public regression cases; `qualifications/holdout/`
are **hidden holdout** variants (`holdout: true`) to detect overfitting — rotate
periodically. Graders: `exact`, `contains`, `not_contains`, `regex`, `iri_exact`,
`choice`, `set_equal`, `json_schema`, `uncertainty`.

## Segmented scores

Scores are always segmented by **(agent_profile, task_class, dimension)** — there
is no single universal score. Dimensions (`enums.SCORE_DIMENSIONS`):

```
semantic_planning  rdf_owl_reasoning  shacl_sparql  repository_navigation
implementation  debugging  tool_selection  structured_output  scope_discipline
evidence_discipline  uncertainty_handling  review  wave_integration
latency  cost  false_completion  later_regression
```

## Admission roles

```
UNQUALIFIED  READ_ONLY_ANALYST  PLANNER_CANDIDATE  PATCH_PRODUCER
REVIEWER  INTEGRATOR  ADJUDICATOR  TRUSTED_COORDINATOR
```

Roles are **earned** from dimension scores against `config/trust-policy.yaml`
thresholds (`compute_admission_roles`). A profile holds a role only if it meets
*every* threshold. **No newly discovered model receives write access
automatically**; the default is `UNQUALIFIED`.

## Budget gating (default off)

Provider discovery, model listing, auth probes, and zero-token metadata probes
are allowed. **Billable inference is disabled by default.** Enable with:

```bash
usf-factory models probe   --allow-billable --budget-usd 5
usf-factory models qualify --allow-billable --budget-usd 20
```

In this safe-runtime build, billable probing/qualification is not wired to live
inference (it refuses); the scoring engine is fully implemented and tested with
fixture answers.

## Leaderboard & explainability

```bash
usf-factory models leaderboard --task shacl-repair --dimension shacl_sparql
usf-factory models show <agent-profile-id>
```

The system can explain why a model is or is not eligible for a task via the
routing decision (see `routing explain`).
