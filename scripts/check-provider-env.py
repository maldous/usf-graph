#!/usr/bin/env python3
"""Verify /root/.env credential state — BY NAME ONLY, never a value.

Exit code 0 if the file is conforming (mode 0600, no excluded variables),
non-zero otherwise. Useful in CI / preflight.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from usf_factory import secrets  # noqa: E402
from usf_factory.paths import ENV_FILE  # noqa: E402


def main() -> int:
    target = ENV_FILE
    problems: list[str] = []

    if not target.exists():
        print(f"{target}: MISSING (no credentials imported)")
        # Absence is not a hard failure here, but nothing is usable.
        return 1

    mode = oct(target.stat().st_mode & 0o777)
    print(f"{target}: mode {mode}")
    if mode != "0o600":
        problems.append(f"mode is {mode}, expected 0o600")

    raw = secrets.load_env_file(target)
    allow = {k for k in raw if k in secrets.ALIAS_TABLE and raw[k].strip()}
    excluded = sorted(set(raw) & secrets.EXCLUDED_VARS)
    unknown = sorted(set(raw) - set(secrets.ALIAS_TABLE) - secrets.EXCLUDED_VARS)

    print("present (allowlisted):", ", ".join(sorted(allow)) or "(none)")
    missing = sorted(set(secrets.CANONICAL_VARS) - allow - secrets.OPTIONAL_CANONICALS)
    print("missing (non-optional):", ", ".join(missing) or "(none)")

    if excluded:
        problems.append(f"excluded variables present: {excluded}")
    if unknown:
        print("note: unrecognized (not written by the factory):", ", ".join(unknown))

    if problems:
        print("\nFAIL:")
        for p in problems:
            print("  -", p)
        return 2

    print("\nOK: env file is conforming.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
