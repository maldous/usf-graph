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

Edit `config/safety.yaml`. Each is off by default and the learning engine can
never change them:

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

## Budgets & concurrency

`config/budgets.yaml`: `billable_usd` (0 default), `free_daily_request_limit`,
wall-time limits, `max_no_progress_cycles` (2), `max_concurrent_workers` (2).
Increase concurrency only when conflict analysis and capacity permit.

## Continuous operation

See `systemd/` for a timer-driven `observe`/`plan-only` service. See
[`recovery.md`](recovery.md) for crash recovery and backups.
