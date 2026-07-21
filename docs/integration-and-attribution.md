# Integration, review, validation & attribution

## Deterministic pre-integration first

`integration.deterministic_preintegrate` runs **before** any AI:

1. Collect accepted results that carry a patch.
2. **Semantic conflict detection** (`detect_semantic_conflicts`) by IRI/semantic
   subject and changed path — *a clean Git merge does not imply semantic
   compatibility.*
3. If no semantic conflict, compute the effective wave-patch identity (and, when
   execution is enabled, apply patches to a factory-owned integration clone in
   packet order). No AI is needed.

The integration clone lives under the factory's `integration/` directory, never
`/usf`.

## AI integrator only when necessary

If deterministic integration cannot resolve a semantic reconciliation, a
qualified `AiIntegrator` (selected for `wave_integration`, from a different
provider where possible; billable + gated) produces **one** candidate effective
wave patch from the normalized results, patches, semantic deltas, and conflict
report — never irrelevant worker transcripts.

## Attribution preserved

`attribution.compute_attribution` records, per packet:

- worker patch digest,
- lines preserved / modified-by-integrator / discarded,
- **integrator rewrite ratio** (0 = worker patch survived intact, 1 = fully
  rewritten).

This ensures a worker does not get full credit when the integrator replaces its
patch.

## Independent review (advisory)

`review.py` runs an independent wave review, preferably from a different provider.
Review answers the DESIGN Phase 12 questions (did one packet invalidate another?
reopened obligations? unauthorized broadening? completion claims without
evidence? direct edits to generated artifacts? backward compatibility? sufficient
negative tests?). **Review is advisory and risk-discovering — never proof.**

## Deterministic validation (authoritative)

`validation.run_validation` executes the requested gates via a pluggable runner
registry:

```
syntax-parse  shacl  integrity-sparql  negative-fixtures  competency-queries
unit-tests  integration-tests  manifest-check  derived-regen
source-live-drift  proof-readiness
```

A gate with no runner is recorded as *skipped* (never counted as passed); any
failing gate fails the receipt. Deterministic validation dominates AI reviewer
opinions.

## Publication (gated, disabled)

`PublicationStateMachine` models the lifecycle
(PREPARED→VALIDATED→AUTHORIZED→PUBLISHED→RECONCILED) but fails closed unless the
`stardog_publication` gate is enabled. The safe runtime never performs live
mutation; publication must go through the authorized USF publication process.

`compute_terminal_complete` computes terminal `COMPLETE` from GOAL + admitted
evidence/proof + authority state — **never** from model prose — and is disabled by
default.

## Learning (stage-specific)

`learning.LearningEngine` updates **(agent, task_class, dimension)** scores after
qualification/integration, using EWMA means with recency decay, minimum sample
counts, and confidence intervals. It:

- **does not penalize** the worker for non-worker faults (planner/provider/
  quota/stale/environment);
- measures integrator rewrite ratio;
- tracks delayed `later_regression`;
- rewards durable, integrated obligation closure — never packet count or
  self-report;
- **writes only `model_task_scores`.** It can never change safety policy, egress
  policy, trust tiers, credential access, publication gates, or source code —
  those are reviewed changes only.
