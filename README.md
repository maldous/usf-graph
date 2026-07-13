# USF v2 (graph-authority replacement scaffold)

Potential replacement for the USF project, built as a **graph-authority** project whose
canonical truth lives in RDF/TriG under `graph/` and is compiled/validated by tooling under
`compiler/`, `tools/`, and `scripts/`.

This tree lives **inside a Linux chroot** at `/usf` (host path `../` → the chroot root).
It is a scaffold only: all graph files are empty placeholders. **No semantic content has been
imported or generated yet.**

## Layout
- `graph/` — canonical graph authority (`.ttl` ontology/vocab/shapes, `.trig` named-graph
  contracts/governance/assurance/realisation/planning, `.rq` inference rules, `derived/`
  generated graphs, `fixtures/`, `snapshots/`).
- `compiler/` — Python semantic compiler (importers / generators / validators / transforms).
- `tools/` — Stardog, bootstrap, export, migration tooling.
- `scripts/` — chroot entry + Stardog provisioning + graph load/validate + verification.
- `tests/` — unit / integration / conformance.

## Environment
- Python venv: `/usf/.venv` (rdflib, pyshacl, requests, httpx, pydantic, pyyaml, click, pytest).
- Stardog CLI: `/usr/local/bin/stardog`, `/usr/local/bin/stardog-admin` (Java-backed).
- Copy `.env.example` → `.env` and fill Stardog credentials (never committed).

## Quick start
```
sudo ./scripts/enter-chroot.sh      # from the host, enters the chroot at /usf
./scripts/verify-chroot.sh          # inside the chroot: structural + tooling verification
```
