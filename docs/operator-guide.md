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

### SAFE_ADAPTIVE_EXECUTION

The safe adaptive profile performs useful isolated `shadow` work while every
protected delivery capability remains disabled. It permits snapshot, complete
work-plan compilation, conflict-free packet execution in disposable workspaces,
local validation/review and CAS-backed factory receipts. It prohibits Git push,
PR creation, merge, committed authority publication, terminal completion, paid
API use and raw-source egress.

Create two root-owned files outside either repository:

- `/root/.config/usf-factory/safe-empty.env`: empty, mode `0600`;
- `/root/.config/usf-factory/safe-adaptive-authorization.json`: a current
  `RunAuthorization`, mode `0600`, with `permitted_actions: []`, every outward
  side-effect quota zero, `paid_api_budget_usd: 0`, no raw-source provider,
  subscription inference allowed, and explicit packet/cycle work-volume bounds.

Run a bounded canary with:

```bash
USF_FACTORY_SAFE_AUTHORIZATION=/root/.config/usf-factory/safe-adaptive-authorization.json \
  scripts/run-safe-adaptive.sh
```

The launcher validates this envelope before starting. CLI/provider subprocesses
receive an allowlisted environment; the coordinator reads the empty credential
file, so API, GitHub and Stardog credentials are absent. Only current admitted
subscription CLI identities may be selected by
`config/safe-adaptive-execution.yaml`. The adaptive controller determines live
concurrency; the authorization limits total work, not worker slots.

If the current authority exposes only one dependency-ready packet, that packet
is executed once. Do not manufacture duplicate work merely to demonstrate
overlap.

On a host without a usable systemd bus, install Supervisor and start the
repository-owned configuration:

```bash
install -d -m 0750 /var/log/usf-factory
supervisord -c /root/usf-factory/supervisor/usf-factory-safe.conf
supervisorctl -c /root/usf-factory/supervisor/usf-factory-safe.conf status
```

The child starts from `env -i`, reconciles durable state before redispatch, and
waits 15 minutes between bounded runs. A blocked cycle exits non-zero and is
reported as an unhealthy supervisor state rather than silently looping.

Every externally deployed non-transient asset, its destination, mode,
installation command and rollback command is preserved under
[`deployment/safe-adaptive/`](../deployment/safe-adaptive/). Active expiring
authorization bytes stay outside Git; the repository carries their complete
safe template and each run records the exact active digest.
