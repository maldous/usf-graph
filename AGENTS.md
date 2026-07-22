# AGENTS.md — working on the USF Adaptive Semantic Factory

This file governs any AI agent (or human) modifying **this repository**
(`usf-factory`). It is distinct from `/usf/AGENTS.md`, which governs work on the
USF semantic programme itself.

## What this project is

A deterministic, model-agnostic orchestration engine that advances USF semantic
work. The **deterministic control plane owns the loop**; AI providers are
replaceable workers. Read `DESIGN.md` for the authoritative architecture and
`docs/architecture.md` for the implementation map.

## Non-negotiable invariants

These are enforced in code and must never be weakened by an automated change:

1. **Never mutate `/usf`.** The factory fetches read-only from `/usf` into a
   factory-owned bare mirror. Packets run in disposable clones outside `/usf`.
   No worktrees are registered under `/usf/.git/worktrees`.
2. **Never treat repository graph files as semantic authority.** Current
   semantic state is compiled deterministically through the USF MCP boundary
   (read-only tools only).
3. **Never mutate Stardog.** Publication is an interface + state machine, gated
   behind a protected action that is **disabled by default**.
4. **Never expose secrets.** Credentials live in `/root/.env` (root, 0600).
   They are never printed, logged, committed, or stored in SQLite. All log and
   report paths pass through the redaction layer (`usf_factory.secrets`).
5. **AI never owns control-plane state** — leases, claims, freshness, merge
   order, quotas, terminal completion. Those are deterministic.
6. **Workers are read-only w.r.t. authority.** They produce patches + evidence
   candidates only; they cannot push, merge, publish, or declare completion.
7. **Safety policy, egress policy, trust tiers, credential access, publication
   gates and this source tree are not automatically self-modifiable.** Learning
   may adjust scores/routing/timeouts/concurrency only. Improvements to policy
   or code are proposed as reviewed PRs.

## Determinism rules

- Protected delivery transitions use versioned compare-and-swap and append an
  immutable CAS transition in the same SQLite transaction as the projection and
  side-effect reservation. Invocation timing and adaptive concurrency may react
  nondeterministically to live conditions, but every decision and observation
  must be persisted well enough to explain it.
- No wall-clock, locale, or randomness in canonical artifact identity. Content
  addressing uses SHA-256 over canonical JSON (sorted keys, UTF-8).
- Canonical identities and integration order remain deterministic. Live routing
  and concurrency exploration need not reproduce timing or worker count; replay
  verifies durable inputs, fences, decisions and outcomes rather than pretending
  that server timing is deterministic.

## How to work here

- Python 3.11+. Use the project venv (`.venv`). Dependencies are declared in
  `pyproject.toml` and pinned in `requirements.lock`.
- Before committing: `ruff format`, `ruff check`, `mypy`, `pytest`.
- Add tests for every behavior change. Adversarial safety tests
  (`tests/adversarial/`) must keep passing.
- Keep modules small and single-purpose; match surrounding style.
- Do not add heavy infrastructure (brokers, k8s, external DBs). SQLite WAL +
  content-addressed files only.

## Stop conditions

Stop and report rather than guess when you hit: an authority conflict, uncertain
mutation, missing credential, unexplained repository state, or pressure to make
an unsupported completion claim. Prefer a fail-closed degraded result over an
overclaim.
