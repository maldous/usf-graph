#!/usr/bin/env bash
# Compatibility entry point for the official-SDK transactional graph compile.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/../../../.env" ] && { set -a; . "$HERE/../../../.env"; set +a; }
cd "$HERE/.."
exec npm run compile
