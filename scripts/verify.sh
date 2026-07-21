#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Local verification gate — the reproducible replacement for CI.
#
# The repository is private and the account keeps GitHub Actions at a $0
# spending limit, so GitHub-hosted runners are not available (jobs fail to
# start with no runner assigned). By operator decision the CI workflow was
# removed; quality is verified here instead. This mirrors what the workflow
# used to run, pinned to requirements.lock for reproducibility.
#
# Usage:
#   scripts/verify.sh            # run in the current environment
#   scripts/verify.sh --fresh    # build a clean venv from requirements.lock first
#   scripts/verify.sh --attest   # additionally require a CLEAN working tree,
#                                # so the receipt attests exactly HEAD
#
# Exits non-zero on the first failing gate. Ends with a verification receipt
# (commit, dirty-file count, timestamp) for the run log.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."

FRESH=0 ATTEST=0
for arg in "$@"; do
  case "$arg" in
    --fresh) FRESH=1 ;;
    --attest) ATTEST=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

HEAD_SHA="$(git rev-parse HEAD)"
DIRTY_COUNT="$(git status --porcelain | wc -l | tr -d ' ')"
if [ "$ATTEST" = 1 ] && [ "$DIRTY_COUNT" != 0 ]; then
  echo "ERROR: --attest requires a clean working tree ($DIRTY_COUNT dirty paths)" >&2
  exit 1
fi

if [ "$FRESH" = 1 ]; then
  VENV="$(mktemp -d)/venv"
  echo "== fresh venv: $VENV (from requirements.lock) =="
  python3 -m venv "$VENV"
  # shellcheck disable=SC1091
  . "$VENV/bin/activate"
  python -m pip install --upgrade pip >/dev/null
  pip install -r requirements.lock
  pip install -e . --no-deps
fi

echo "== ruff format --check ==" && ruff format --check .
echo "== ruff check =="          && ruff check .
echo "== mypy =="                && mypy
echo "== pytest =="              && pytest -q

echo "== package build =="
python -m pip install --quiet build
python -m build --wheel
rm -rf build dist ./*.egg-info src/*.egg-info

echo "== secret scan: token-shaped strings in tracked files =="
# tests/ is excluded ONLY for the shape patterns: it contains deliberate fake
# token fixtures that exercise the secret scanner. The known-value scan below
# covers every tracked file with no exclusions.
if git grep -nE '(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{16,})' \
     -- ':!tests/**' ; then
  echo "ERROR: token-shaped string found in tracked files" >&2; exit 1
fi
if git ls-files | grep -E '(^|/)\.env$' ; then
  echo "ERROR: .env is tracked" >&2; exit 1
fi

echo "== secret scan: known local secret VALUES (all tracked files) =="
# Compare every real value from /root/.env against the tracked tree. Values are
# never echoed; only the variable NAME is reported on a hit.
if [ -r /root/.env ]; then
  while IFS='=' read -r key val; do
    case "$key" in ''|\#*) continue ;; esac
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
    [ "${#val}" -ge 12 ] || continue
    if git grep -qF -- "$val" ; then
      echo "ERROR: the value of $key appears in tracked files" >&2; exit 1
    fi
  done < /root/.env
  echo "no known secret values in tracked files"
else
  echo "note: /root/.env not readable; known-value scan skipped"
fi

if command -v shellcheck >/dev/null 2>&1; then
  echo "== shellcheck scripts/verify.sh =="
  shellcheck scripts/verify.sh
fi

echo
echo "ALL GATES PASSED"
echo "verification receipt: commit=$HEAD_SHA dirty_paths=$DIRTY_COUNT attest=$ATTEST at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
