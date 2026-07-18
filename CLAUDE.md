# CLAUDE.md — Claude execution shim

Read `AGENTS.md`, this shim, `GOAL.md`, the USF skill and the latest verified
programme checkpoint before acting. This file adds only Claude-specific
orchestration and restates no semantic policy. It cannot override `GOAL.md` or
validated live semantic authority.

- Load the `usf` skill before acting.
- Get semantic context from the `usf` MCP server: `usf_bootstrap` for task
  orientation and per-contract traces, `usf_query` for bounded read-only
  SPARQL, `usf_health` for liveness. Do not read graph files or a census.
- Use bounded subagents for independent work; give each a compact packet, not
  the conversation. Subagents remain read-only unless a direct current
  instruction explicitly permits modifying workers. When permitted, each uses
  a disjoint branch, worktree and write scope.
- Only this top-level session (the coordinator) performs Stardog mutations.
- Stop and report on any stop condition in `AGENTS.md`.
