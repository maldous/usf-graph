#!/usr/bin/env bash
# Validate RDF / SHACL / generated graph files locally using the chroot venv (rdflib + pyshacl).
# Scaffold-safe: empty placeholder files parse as empty graphs (valid); reports counts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The graph lives in the parent usf repository; this validator runs host-side,
# outside the chroot. USF_GRAPH_DIR overrides the parent-checkout default.
GRAPH_DIR="${USF_GRAPH_DIR:-$(cd "$HERE/../../.." && pwd)/graph}"
# Host-side python with rdflib+pyshacl. Resolution: explicit override, then a
# .venv at the parent repository root, then the chroot venv (same-version
# hosts only). Create the host venv with:
#   python3 -m venv .venv && .venv/bin/pip install rdflib==7.6.0 pyshacl==0.40.0 pyyaml==6.0.3
usable(){ [ -x "$1" ] && "$1" -c 'import rdflib, pyshacl' 2>/dev/null; }
PY="${USF_GRAPH_PY:-}"
[ -n "$PY" ] || { p="$(cd "$HERE/../../.." && pwd)/.venv/bin/python"; usable "$p" && PY="$p"; } || true
[ -n "$PY" ] || { p="$(cd "$HERE/.." && pwd)/.venv/bin/python"; usable "$p" && PY="$p"; } || true
[ -n "$PY" ] || { echo "error: no python with rdflib+pyshacl found; create the parent-root .venv (see comment above) or set USF_GRAPH_PY" >&2; exit 1; }

exec "$PY" - "$GRAPH_DIR" <<'PY'
import sys, pathlib
from rdflib import Graph, Dataset
root = pathlib.Path(sys.argv[1])
ok = empty = errors = 0
fmt = {".ttl": "turtle", ".trig": "trig"}
for p in sorted(root.rglob("*")):
    if p.suffix not in fmt or not p.is_file():
        continue
    if p.stat().st_size == 0:
        empty += 1
        continue
    try:
        g = Dataset() if p.suffix == ".trig" else Graph()
        g.parse(str(p), format=fmt[p.suffix])
        ok += 1
    except Exception as e:  # noqa: BLE001
        errors += 1
        print(f"INVALID {p}: {e}", file=sys.stderr)
print(f"validate-graph: parsed_ok={ok} empty_placeholders={empty} invalid={errors}")
sys.exit(1 if errors else 0)
PY
