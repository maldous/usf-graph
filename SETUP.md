# USF v2 graph — chroot + Stardog provisioning setup

Recreate the full chrooted Stardog provisioning environment for the semantic graph under
`v2/usf/graph`. Only the USF artefacts and the token-free `profile.d` wiring are tracked in git;
the OS rootfs, the Temurin JRE, the Stardog CLI, the Python venv, and your credentials are
provisioned locally by these steps.

## Prerequisites

- A Linux host with `sudo` and `debootstrap` (`sudo apt-get install -y debootstrap`).
- Network access to Adoptium, `downloads.stardog.com`, and your Stardog server.
- ~2 GB free disk for the chroot.
- A Stardog server and credentials (Stardog Cloud, or your own). The reference deployment uses
  Stardog Cloud with token auth.

Run every command from the repository root (the directory that contains `v2/`).

## 1. Create the base Debian chroot

`debootstrap` populates `v2/` with a minimal Debian rootfs. The tracked `v2/usf/` and
`v2/etc/profile.d/` are left in place.

```bash
sudo debootstrap --variant=minbase bookworm v2 http://deb.debian.org/debian
sudo cp /etc/resolv.conf v2/etc/resolv.conf        # DNS for downloads and the Stardog server
```

## 2. Provide credentials (never committed)

```bash
cp v2/usf/.env.example v2/usf/.env
```

Edit `v2/usf/.env` and set `STARDOG_SERVER`, `STARDOG_DATABASE` (default `USF`), and either
`STARDOG_TOKEN` or `STARDOG_USERNAME` + `STARDOG_PASSWORD`. `v2/usf/.env` is git-ignored; the
token is read from it at runtime and is never written into any tracked file.

## 3. Bootstrap the chroot dependencies

Installs everything a `minbase` chroot lacks: curl/unzip/ca-certificates/python3+venv+pip, the
Temurin JRE 21 (`/opt`), the Stardog CLI (`/opt`, symlinked into `/usr/local/bin`), and the
Python RDF toolchain venv (`/usf/.venv`). Idempotent; downloads Java and Stardog on first run.

```bash
sudo chroot v2 /bin/bash /usf/scripts/bootstrap-chroot.sh
```

Ends with a readiness check. Re-run any time; present components are skipped.

## 4. Provision and verify the database

Recreates the `USF` database solely from `v2/usf/graph`, loads the named graphs, shapes and
derived graphs, validates (SHACL), runs the integrity and contamination queries, derives
readiness, and proves guarded writes reject invalid transactions.

```bash
sudo chroot v2 /bin/bash /usf/scripts/provision-graph.sh
```

Expected: `sh:conforms true`, integrity and contamination queries return zero rows, readiness
derived for every capability, defect transactions rejected, conforming transaction committed.

## Optional helpers (all under `v2/usf/scripts/`)

- `enter-chroot.sh` — open an interactive shell in the chroot (mounts `/proc`, `/sys`, `/dev`
  and copies `resolv.conf`, working dir `/usf`).
- `verify-chroot.sh` — read-only Stardog connectivity check.
- `validate-graph.sh` — parse/validate the graph locally with the venv, no database.
- `load-graph.sh` — additive load of the graph files (no drop/create).

## Notes

- The chroot rootfs, `v2/usf/.venv`, and `v2/usf/.env` are intentionally untracked
  (`v2/.gitignore`, `v2/usf/.gitignore`). Only source artefacts and the token-free
  `v2/etc/profile.d/{java.sh,stardog.sh}` are committed.
- `provision-graph.sh` drops and recreates the `USF` database each run — point `.env` at a
  database dedicated to this graph.
