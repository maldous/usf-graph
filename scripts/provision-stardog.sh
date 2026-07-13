#!/usr/bin/env bash
# Read-only Stardog verification through the official SDK only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/../.env" ] && { set -a; . "$HERE/../.env"; set +a; }
cd "$HERE/../compiler"
exec npm run verify
