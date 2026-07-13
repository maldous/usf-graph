# CLAUDE.md — Claude execution shim

Read `AGENTS.md` first; it is the shared policy. This file adds only
Claude-specific orchestration and restates no semantic policy.

- Load the `usf` skill before acting.
- Get semantic context from the `usf` MCP server: `usf_bootstrap` for task
  orientation and per-contract traces, `usf_query` for bounded read-only
  SPARQL, `usf_health` for liveness. Do not read graph files or a census.
- Use bounded subagents for independent work; give each a compact packet, not
  the conversation. Read-only subagents may share this checkout; a modifying
  subagent gets its own branch and worktree with a disjoint write scope.
- Only this top-level session (the coordinator) performs Stardog mutations.
- Stop and report on any stop condition in `AGENTS.md`.
