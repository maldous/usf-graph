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
#
# Exits non-zero on the first failing gate.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "${1:-}" = "--fresh" ]; then
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

echo "== secret scan (tracked files must contain no token-shaped strings) =="
if git grep -nE '(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{16,})' \
     -- ':!tests/**' ':!docs/**' ; then
  echo "ERROR: token-shaped string found in tracked files" >&2; exit 1
fi
if git ls-files | grep -E '(^|/)\.env$' ; then
  echo "ERROR: .env is tracked" >&2; exit 1
fi

echo
echo "ALL GATES PASSED"
