# systemd units

Timer-driven **non-mutating** operation of the factory.

- `usf-factory.service` — a oneshot unit running `usf-factory run --mode plan-only`.
- `usf-factory.timer` — fires the service on boot and every 30 minutes.
- `usf-factory-safe.service` — runs the adaptive `shadow` envelope using an
  external zero-side-effect `RunAuthorization` and an empty provider credential
  file.
- `usf-factory-safe.timer` — retries safe work every 15 minutes after the prior
  bounded run becomes inactive.

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

## Safe adaptive execution

Install the owner-only files described in the operator guide, then install the
safe units:

```bash
cp systemd/usf-factory-safe.service systemd/usf-factory-safe.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now usf-factory-safe.timer
systemctl status usf-factory-safe.service usf-factory-safe.timer
```

The launcher rejects any authorization with a protected action, outward
side-effect quota, paid budget or raw-source provider. Subscription CLI
authentication is used from the operator's existing CLI homes; API, GitHub and
Stardog credentials are explicitly removed from the service environment.

The authorization's packet and cycle limits bound work volume. They do not set
worker concurrency: the observed-performance controller starts conservatively
after restart and chooses invocation load from runtime evidence.
