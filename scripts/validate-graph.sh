#!/usr/bin/env bash
# Validate RDF / SHACL / generated graph files locally using the chroot venv (rdflib + pyshacl).
# Scaffold-safe: empty placeholder files parse as empty graphs (valid); reports counts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRAPH_DIR="$(cd "$HERE/../graph" && pwd)"
PY="$(cd "$HERE/../.." && pwd)/usf/.venv/bin/python"
[ -x "$PY" ] || PY="/usf/.venv/bin/python"
[ -x "$PY" ] || { echo "error: venv python not found at $PY" >&2; exit 1; }

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
