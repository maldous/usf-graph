#!/usr/bin/env bash
# Publish registered authored semantic source through the compiler's single,
# validated Stardog transaction. No direct RDF mutation is permitted here.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd "$HERE/../../.." && pwd)"
[ -f "$REPOSITORY_ROOT/.env" ] && { set -a; . "$REPOSITORY_ROOT/.env"; set +a; }
cd "$HERE/.."
npm run check
npm test
npm run provision:db
npm run compile
npm run snapshot:derived
npm run verify
npm run drift
echo "publish-authority: validated transaction committed and live drift check passed"
