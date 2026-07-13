---
name: usf
description: Use at the start of any USF task and whenever you need authoritative semantic context — contracts, claims/non-claims, proof/evidence obligations, realisations, validators, or repository-layout rules. Defines how to query the live Stardog model through the usf MCP server instead of reading graph files or a census, in bounded read-only or coordinator-only mutation modes.
---

# USF semantic operating skill

USF is semantic-first (see `AGENTS.md`): the live model in Stardog is the
authority. This skill is how you reach it. Query on demand; never preload the
corpus or read graph TriG/TTL files or a census to reconstruct meaning.

## When to retrieve context

- At task start: call `usf_bootstrap` with a short `task` string to orient.
- Before realising or validating a capability: call `usf_bootstrap` with the
  `{ contract: "<canonicalName>" }` to get its model→facet→obligation→contract
  →realisation trace.
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

Workers are always read-only.

## Mutation mode (coordinator only)

Only the top-level coordinator may change semantic authority, and only through
the compiler's transactional path (not the MCP read tools). Mutations are
transactional, fail-closed, scoped to registered authority boundaries, and roll
back on any validation, integrity, or connectivity failure.

## Trust state

Trust live state only after `usf_health` succeeds and the `usf_bootstrap`
authority digest is stable across the task. If Stardog is unavailable, drifted,
or credentials are missing, stop and report a degraded result — never fabricate
or assume the model.

## Compact worker packets

When delegating, pass only: objective, semantic identifiers, read scope, write
scope, invariants, acceptance criteria, focused validation. Never send a
transcript or the full model. A worker returns: change, files, validation,
commit, remaining risk.

## Validation and completion

A task is complete only when its contract obligations are satisfied with real
evidence and the applicable validators pass — not because tests, reports,
tickets, or existing code say so. Report an explicit readiness verdict and any
residual gap. Do not overclaim.
