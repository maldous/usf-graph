---
name: usf
description: Use at the start of any USF task and whenever you need authoritative semantic context — contracts, claims/non-claims, proof/evidence obligations, realisations, validators, or repository-layout rules. Defines how to query the live Stardog model through the usf MCP server instead of reading graph files or a census, in bounded read-only or coordinator-only mutation modes.
---

# USF semantic operating skill

USF is semantic-first (see `AGENTS.md`): the live model in Stardog is the
authority. This skill is how you reach it. Query on demand; never preload the
corpus or read graph TriG/TTL files or a census to reconstruct meaning.

## When to retrieve context

- At task start: call `usf_bootstrap` exactly once. Include the contract
  canonical name or IRI when it is known; otherwise include a short task
  string. Reuse that digest-bound packet and make focused queries thereafter.
- Before realising or validating a capability, call `usf_contract_project`
  for its active contract. This is the bounded AI-agent execution packet;
  `usf_bootstrap` is not repeated.
- Whenever you would otherwise guess semantics, ownership, naming, or a path
  rule: query instead. If it is not in the model, it is not yet authoritative.

## Choosing scope

Work one contract or capability at a time. Take from `usf_bootstrap` only the
identifiers you need, then follow up with targeted `usf_query`. Prefer exact
IRIs and canonical names over broad scans. Read the smallest sufficient file
ranges only after querying.

## Query mode (default, read-only)

- `usf_health` — liveness and authority triple count.
- `usf_query { sparql }` — SELECT / ASK / CONSTRUCT / DESCRIBE only. Mutations
  (INSERT/DELETE/LOAD/CLEAR/DROP/CREATE/COPY/MOVE/ADD/WITH) are refused.
- `usf_bootstrap { task?, contract? }` — bounded orientation or per-contract
  trace. Results are capped (rows, bytes, traversal depth); use follow-up
  queries rather than asking for everything at once.
- `usf_layout_context { contract? }` — current authority digest, active proof
  and decision state, path roles, storage classes and representation rules.
- `usf_layout_plan { operations }` and `usf_layout_validate { plan }` — build
  and validate bounded, digest-bound materialisation plans.
- `usf_materialise { plan, apply? }` — dry-run by default. Apply is available
  only to a coordinator and verifies exact source/content digests and modes.
- `usf_artifact_describe { digest }` and `usf_artifact_verify { digest }` —
  retrieve Stardog metadata and verify bytes in the configured operator-local
  CAS outside Git.
- `usf_contract_project { contract, objective? }` — agent-ready realisation or
  validation packet containing semantic IDs, authority digest and state,
  objective, claims/nonclaims, authorised actions/paths/formats, acceptance and
  validation obligations, result requirements and stop conditions.
- `usf_work_plan { contract? }` — bounded semantic gaps for work projection;
  it creates no ticket and grants no authority.

Workers are always read-only.

## Mutation mode (coordinator only)

Only the top-level coordinator may change semantic authority, and only through
the compiler's transactional path (not the MCP read tools). Mutations are
transactional, fail-closed, scoped to registered authority boundaries, and roll
back on any validation, integrity, or connectivity failure.

The advertised `usf_evidence_admit`, `usf_proof_evaluate`, and
`usf_validation_record` boundaries deliberately refuse direct MCP mutation.
The coordinator realises those lifecycle changes in registered authored graph
source and runs `tools/compiler/bin/publish-authority.sh` so the complete change
is checked and committed in one Stardog transaction.

## Trust state

Trust live state only after `usf_health` succeeds and the `usf_bootstrap`
authority digest is stable across the task. If Stardog is unavailable, drifted,
or credentials are missing, stop and report a degraded result — never fabricate
or assume the model.

## Compact worker packets

Realisation and validation agents consume the current `usf_contract_project`
packet, not copied prose or a ticket body. They must stop if its digest is stale,
its contract/decision/proof state is not actionable, or a requested path,
format, action, storage class or evidence item is absent. Never send a
transcript or the full model. An agent returns changed paths and digests,
validation results and stable codes, explicit nonclaims, and remaining risk.

## Validation and completion

A task is complete only when its contract obligations are satisfied with real
evidence and the applicable validators pass — not because tests, reports,
tickets, or existing code say so. Report an explicit readiness verdict and any
residual gap. Do not overclaim.
