#!/usr/bin/env python3
"""Import model-provider credentials into /root/.env.

Sources (choose one or more):
  --from-process     import from the current process environment
  --stdin0           read NUL-delimited `env -0` input from stdin
  --from-env-file P  read from an existing dotenv file

Behavior:
  * Filters through an exact allowlist of canonical model-provider variables.
  * Normalizes documented aliases; reports credential conflicts by NAME only.
  * Never imports excluded variables (Stardog, unrelated services).
  * github-models is only written from an explicit GITHUB_MODELS_TOKEN source.
  * Writes /root/.env atomically at mode 0600. Never prints a value.

Examples:
  python scripts/import-provider-env.py --from-process
  env -0 | python scripts/import-provider-env.py --stdin0
  python scripts/import-provider-env.py --from-env-file /root/.env
  python scripts/import-provider-env.py --dry-run --from-process
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from usf_factory import secrets  # noqa: E402
from usf_factory.paths import ENV_FILE  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Import model-provider credentials to /root/.env")
    parser.add_argument(
        "--from-process", action="store_true", help="import from current environment"
    )
    parser.add_argument(
        "--stdin0", action="store_true", help="read NUL-delimited env -0 from stdin"
    )
    parser.add_argument("--from-env-file", metavar="PATH", help="read from an existing dotenv file")
    parser.add_argument("--dry-run", action="store_true", help="report names only; write nothing")
    parser.add_argument(
        "--target", default=str(ENV_FILE), help="target env file (default /root/.env)"
    )
    args = parser.parse_args()

    sources: dict[str, str] = {}
    if args.from_process:
        sources.update(os.environ)
    if args.from_env_file:
        sources.update(secrets.load_env_file(Path(args.from_env_file)))
    if args.stdin0:
        sources.update(secrets.parse_env0(sys.stdin.buffer.read()))

    if not (args.from_process or args.stdin0 or args.from_env_file):
        print("error: specify --from-process, --stdin0, or --from-env-file", file=sys.stderr)
        return 2

    norm = secrets.normalize(sources)
    to_write = secrets.select_for_write(norm)
    gm_write, gm_reason = secrets.github_models_write_policy(norm)

    # Report NAMES only.
    print("would write:      ", ", ".join(to_write) or "(none)")
    print("conflicts:        ", ", ".join(norm.conflicts) or "(none)")
    print("missing:          ", ", ".join(norm.missing) or "(none)")
    print("excluded skipped: ", ", ".join(norm.excluded_present) or "(none)")
    print("unmapped candidates:", ", ".join(norm.unmapped_candidates) or "(none)")
    print("github-models:    ", ("write" if gm_write else "skip") + f" ({gm_reason})")

    if norm.conflicts:
        print(
            "\nwarning: some variables had conflicting alias values and were NOT imported.",
            file=sys.stderr,
        )

    if args.dry_run:
        print("\ndry-run: nothing written.")
        return 0

    if not to_write:
        print("\nno usable credentials to write; leaving target unchanged.", file=sys.stderr)
        return 1

    target = Path(args.target)
    content = secrets.render_env_content(norm, to_write)
    secrets.write_env_file(target, content)
    print(f"\nwrote {len(to_write)} variables to {target} (mode 0600).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
