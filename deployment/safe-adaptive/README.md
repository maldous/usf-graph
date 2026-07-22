# SAFE_ADAPTIVE_EXECUTION deployment assets

This directory is the recovery source for every reproducible non-transient
asset deployed outside the repository for safe adaptive operation. Active
operator authorizations remain outside Git, owner-only and expiring; they are
runtime grants rather than deployment assets. The complete schema and exact
conservative field set are preserved in the example file, but its placeholder
identity and timestamps intentionally cannot authorize a run.

| Repository source | Deployed path | Mode | Treatment |
| --- | --- | --- | --- |
| `safe-empty.env` | `/root/.config/usf-factory/safe-empty.env` | `0600` | Exact byte copy; intentionally empty. |
| `safe-adaptive-authorization.example.json` | `/root/.config/usf-factory/safe-adaptive-authorization.json` | `0600` | Instantiate current ID/timestamps; retain every safety field unchanged. |
| `../../supervisor/usf-factory-safe.conf` | Used directly from repository | `0644` | Supervisor configuration; not copied elsewhere on this host. |
| `../../scripts/run-safe-adaptive.sh` | Used directly from repository | `0755` | Fail-closed launcher. |
| `../../scripts/supervise-safe-adaptive.sh` | Used directly from repository | `0755` | Periodic supervisor child. |
| `../../systemd/usf-factory-safe.service` | `/etc/systemd/system/` on systemd hosts | `0644` | Optional deployable copy. |
| `../../systemd/usf-factory-safe.timer` | `/etc/systemd/system/` on systemd hosts | `0644` | Optional deployable copy. |

No other static file is required outside Git. The Supervisor configuration and
both launchers execute from their tracked repository copies. PID files, sockets,
logs, the SQLite state database and the active authorization are runtime state,
not deployed source assets.

The Debian `supervisor` package is the only added host package on the current
chroot. Record its installed version with `dpkg-query -W supervisor`; package
bytes remain supplied by the declared Debian repository rather than copied into
Git.

## Install or recover

```bash
install -d -m 0700 /root/.config/usf-factory
install -m 0600 deployment/safe-adaptive/safe-empty.env \
  /root/.config/usf-factory/safe-empty.env
cp deployment/safe-adaptive/safe-adaptive-authorization.example.json \
  /root/.config/usf-factory/safe-adaptive-authorization.json
chmod 0600 /root/.config/usf-factory/safe-adaptive-authorization.json
# Replace only authorization_id, issued_at and expires_at with current values.
scripts/run-safe-adaptive.sh
```

Before activation, validate the authorization through
`load_run_authorization`; never deploy the example timestamps unchanged.

## Current deployed witness

The active file is operational state, not semantic authority. Its digest is
recorded by every run and can be independently recomputed with:

```bash
sha256sum /root/.config/usf-factory/safe-adaptive-authorization.json \
  /root/.config/usf-factory/safe-empty.env
```

Supervisor creates `/run/usf-factory-safe-supervisor.{pid,sock}` and rotated
logs under `/var/log/usf-factory/`. These are transient runtime outputs, not
deployment inputs, and must not be copied into Git.

## Roll back

```bash
supervisorctl -c /root/usf-factory/supervisor/usf-factory-safe.conf shutdown
rm -f /run/usf-factory-safe-supervisor.pid \
  /run/usf-factory-safe-supervisor.sock
```

Removing an active authorization is an operator action. Preserve it until all
running coordinator and invocation state has been reconciled.
