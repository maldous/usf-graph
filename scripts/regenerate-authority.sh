#!/usr/bin/env bash
# Regenerate the complete USF v2 semantic authority in one coherent, ordered
# pass: census outputs, observed carrier, live compile, derived carriers and
# census closure all end up bound to one repository state and one observation
# set digest.
#
# Usage:
#   scripts/regenerate-authority.sh [--signing-key <ed25519-pem>] \
#       [--attestation-output <file-outside-repository>]
#
# Requires STARDOG_SERVER and STARDOG_TOKEN (or STARDOG_USERNAME/PASSWORD) in
# the environment; v2/usf/.env is sourced when present. Credentials are never
# printed. When a signing key is supplied the run finishes with a signed live
# attestation and a census closure that consumes it; without one, closure runs
# without the external Stardog observation and reports it as missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USF_DIR="$(dirname "$SCRIPT_DIR")"
CENSUS_DIR="$USF_DIR/census"
COMPILER_DIR="$USF_DIR/compiler"

SIGNING_KEY=""
ATTESTATION_OUTPUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --signing-key) SIGNING_KEY="$2"; shift 2 ;;
    --attestation-output) ATTESTATION_OUTPUT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -n "$SIGNING_KEY" && -z "$ATTESTATION_OUTPUT" ]] || [[ -z "$SIGNING_KEY" && -n "$ATTESTATION_OUTPUT" ]]; then
  echo "--signing-key and --attestation-output must be supplied together" >&2
  exit 2
fi

if [[ -f "$USF_DIR/.env" ]]; then
  set -a; . "$USF_DIR/.env"; set +a
fi

step() { echo "== $*" >&2; }

observed_digest() {
  sha256sum "$USF_DIR/graph/observed/source-artefacts.trig" | cut -d' ' -f1
}

step "compiler: local check"
npm --prefix "$COMPILER_DIR" run check >/dev/null

step "stardog: ensure database options"
npm --prefix "$COMPILER_DIR" run provision:db

# Census build, observed snapshot, transactional compile and derived snapshot
# iterate to a fixpoint: the observed rows are fixed by the source tree, and
# the carrier-dependent census fields (mappings, input digests) stabilise on
# the second pass. A third differing pass is a hard failure.
previous=""
for iteration in 1 2 3 4 5; do
  step "census: build (iteration $iteration)"
  npm --prefix "$CENSUS_DIR" run build >/dev/null
  step "compiler: snapshot observed carrier (iteration $iteration)"
  npm --prefix "$COMPILER_DIR" run snapshot:observed >/dev/null
  current="$(observed_digest)"
  if [[ "$current" == "$previous" ]]; then
    step "observed carrier stable after iteration $iteration"
    break
  fi
  if [[ "$iteration" == "5" ]]; then
    echo "observed carrier failed to stabilise after 5 iterations" >&2
    exit 1
  fi
  previous="$current"
  step "compiler: fixture harness (iteration $iteration)"
  npm --prefix "$COMPILER_DIR" run verify:fixtures >/dev/null
  step "compiler: transactional compile (iteration $iteration)"
  npm --prefix "$COMPILER_DIR" run compile >/dev/null
  step "compiler: snapshot derived carriers (iteration $iteration)"
  npm --prefix "$COMPILER_DIR" run snapshot:derived >/dev/null
done

step "census: rebuild against stable carriers"
npm --prefix "$CENSUS_DIR" run build >/dev/null

# Unit tests run against the regenerated on-disk state: several census tests
# read the canonical outputs, so they are meaningful only after the fixpoint.
step "census: unit tests"
npm --prefix "$CENSUS_DIR" test >/dev/null

step "compiler: unit tests"
npm --prefix "$COMPILER_DIR" test >/dev/null

step "census: validate canonical outputs"
npm --prefix "$CENSUS_DIR" run validate

step "census: independent audit"
npm --prefix "$CENSUS_DIR" run audit

step "compiler: read-only verify"
npm --prefix "$COMPILER_DIR" run verify >/dev/null

step "compiler: source versus live drift"
npm --prefix "$COMPILER_DIR" run drift >/dev/null

step "census: universe drift"
npm --prefix "$CENSUS_DIR" run verify-drift

if [[ -n "$SIGNING_KEY" ]]; then
  step "compiler: signed live attestation"
  node "$COMPILER_DIR/src/cli.js" attest-live \
    --output "$ATTESTATION_OUTPUT" --signing-key "$SIGNING_KEY" >/dev/null
  FINGERPRINT="$(node -e '
    const { createPublicKey, createPrivateKey, createHash } = require("node:crypto");
    const { readFileSync } = require("node:fs");
    const key = createPublicKey(createPrivateKey(readFileSync(process.argv[1])));
    const der = key.export({ type: "spki", format: "der" });
    process.stdout.write(createHash("sha256").update(der).digest("hex"));
  ' "$SIGNING_KEY")"
  step "compiler: verify live attestation"
  node "$COMPILER_DIR/src/cli.js" verify-live-attestation \
    --input "$ATTESTATION_OUTPUT" --expected-key-fingerprint "$FINGERPRINT" >/dev/null
  export USF_CENSUS_STARDOG_OBSERVATION="$ATTESTATION_OUTPUT"
  export USF_CENSUS_STARDOG_FINGERPRINT="$FINGERPRINT"
fi

step "census: closure"
npm --prefix "$CENSUS_DIR" run closure
