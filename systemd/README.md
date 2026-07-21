# systemd units

Timer-driven **non-mutating** operation of the factory.

- `usf-factory.service` — a oneshot unit running `usf-factory run --mode plan-only`.
- `usf-factory.timer` — fires the service on boot and every 30 minutes.

## Install

```bash
cp systemd/usf-factory.service systemd/usf-factory.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now usf-factory.timer
systemctl list-timers usf-factory.timer
journalctl -u usf-factory.service -f
```

## Safety

The unit runs in `plan-only` mode: it never writes to `/usf`, never incurs
billable inference, and never publishes. The hardening directives mount `/usf`
and the repository read-only and confine writes to the factory's XDG state/cache/
config directories.

Do **not** change `ExecStart` to a mutating mode (`approve-wave` /
`autonomous-safe`) unless you have deliberately enabled `autonomous_safe_enabled`
(and any required protected-action gates) in `config/safety.yaml` and understand
the consequences.

Adjust the virtualenv path in `ExecStart` if the factory is installed elsewhere.
