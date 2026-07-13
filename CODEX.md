# CODEX.md — Codex execution shim

Read `AGENTS.md` first; it is the shared policy. This file adds only
Codex-specific orchestration and restates no semantic policy.

- Load the `usf` skill before acting.
- Semantic context comes from the `usf` MCP server (`usf_bootstrap`,
  `usf_query`, `usf_health`) — never from graph files or a census.
- Parallelism: at most 8 active agents, delegation depth at most 2
  (1 coordinator, 0–7 workers). Prefer depth 1. A worker may spawn one depth-2
  specialist only when it materially reduces total work. Never exceed eight.
- Workers are read-only and get a compact packet (objective, identifiers,
  read/write scope, invariants, acceptance, validation) — never a transcript.
- Every modifying worker uses its own branch and worktree; write scopes are
  disjoint; only the coordinator mutates Stardog and integrates via Git.
- Stop and report on any stop condition in `AGENTS.md`.
