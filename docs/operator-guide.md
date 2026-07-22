# Operator guide

## Install

```bash
cd /root/usf-factory
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"     # or: pip install -r requirements.lock
```

## First run

```bash
usf-factory doctor                 # environment / config / isolation / safety
usf-factory env status             # credentials present, by NAME only
usf-factory providers status       # provider enablement
usf-factory usf health             # read-only USF MCP liveness
usf-factory cycle snapshot         # deterministic semantic snapshot
usf-factory run --mode plan-only   # a full non-mutating cycle
```

## Modes

| Mode | Effect |
| --- | --- |
| `observe` | non-mutating full pipeline; watch/report |
| `plan-only` | non-mutating; produce reviewable packet sets (default) |
| `approve-wave` | requires `autonomous_safe_enabled` (disabled by default) |
| `autonomous-safe` | requires `autonomous_safe_enabled` (disabled by default) |

`observe` and `plan-only` never write to `/usf`, never spend money, and never
publish. `approve-wave` / `autonomous-safe` are blocked until explicitly enabled
in `config/safety.yaml`.

## Inspecting a cycle

```bash
usf-factory status                      # recent cycles + pause state
usf-factory cycle show [cycle-id]       # a cycle receipt
usf-factory cycle plan                  # obligation graph + packet table
usf-factory routing explain <packet-id> # why an agent was (not) chosen
usf-factory replay <cycle-id>           # the deterministic event log
```

## Models

```bash
usf-factory providers refresh                       # metadata-only discovery
usf-factory models list [--provider P]
usf-factory models leaderboard --task T --dimension D
usf-factory models show <agent-profile-id>
usf-factory models probe   --allow-billable --budget-usd N   # gated
usf-factory models qualify --allow-billable --budget-usd N   # gated
```

## Pause / resume

```bash
usf-factory pause     # sets a flag the engine honors before a new cycle
usf-factory resume
```

## Enabling protected actions (deliberate)

Committed gates are one half of authorization and all are off by default. A
current `RunAuthorization` must independently permit the exact action, risk,
repository, database, provider, expiry and quota. CLI flags may narrow this
authorization but never widen it. The learning engine cannot change either
boundary.

```yaml
allow_billable: false
allow_source_egress: false
allow_main_integration: false
allow_push_pr: false
allow_stardog_publication: false
allow_risk_acceptance: false
allow_terminal_completion: false
autonomous_safe_enabled: false
```

Enable the minimum needed, with a budget, and review the resulting behavior.

## Budgets and protected-action accounting

`config/budgets.yaml`: `billable_usd` (0 default), `free_daily_request_limit`,
wall-time limits and `max_no_progress_cycles`. Paid requests reserve budget
atomically before invocation and settle provider-reported/locally calculated
actual cost. Push, PR creation, merge and publication reserve authorization-bound
side-effect quotas before invocation and retain consumption after later failure.

Worker concurrency is not an operator capacity setting. The runtime starts
conservatively and discovers useful parallelism from observed validated
throughput, quality, server pressure and downstream backlog. Emergency resource
cutoffs are safety boundaries, not worker-count formulas.

## Current protected-delivery blockers

- `EXACT_GITHUB_MERGE_MECHANISM_UNAVAILABLE`: the production driver refuses to
  use ordinary `gh pr merge` because it lacks an exact base-SHA precondition.
- `PUBLICATION_CONTAINMENT_UNAVAILABLE`: the current host lacks a demonstrated
  publication sandbox. Publication credentials must never be exposed to
  candidate-controlled npm scripts.

Do not enable merge or publication gates until those environmental mechanisms
are independently demonstrated.

## Continuous operation

See `systemd/` for a timer-driven `observe`/`plan-only` service. See
[`recovery.md`](recovery.md) for crash recovery and backups.
