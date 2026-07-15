#!/usr/bin/env bash
# Reproducible chroot graph provisioner using only the official Stardog SDK.
# The compiler owns the single transaction, registered per-graph clearing,
# authored/derived validation, ordered derivation, integrity, contamination,
# rollback, and commit boundary.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/../../../.env" ] && { set -a; . "$HERE/../../../.env"; set +a; }
cd "$HERE/.."
npm run check
npm test
# A dropped/recreated USF database returns to Stardog defaults; reassert the
# options the compiler and integrity rules require before the transactional load.
npm run provision:db
npm run compile
npm run verify
echo "provision: official-SDK transaction and read-only verification completed"
