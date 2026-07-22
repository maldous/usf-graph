"""Transactional Stardog authority publication + reconciliation (build task §14).

After the corresponding usf-graph change is merged, the COORDINATOR:

1. clones the repo at the exact merge commit,
2. reads the current authority digest (via the read-only MCP client),
3. verifies it matches the expected pre-publication digest (else STALE => replan),
4. runs a frozen install + the deterministic test suite,
5. runs canonical validate-and-rollback publication (require ok + zero contamination),
6. runs canonical committed authority publication (parse commitOutcome/postDigest/graphs),
7. runs source/live drift (require zero mismatch),
8. re-snapshots through MCP and confirms the exact obligation disappeared.

No direct arbitrary SPARQL mutation is issued: publication goes only through the
repo's canonical ``publish:authority`` npm scripts, which source their own Stardog
credentials. Those credentials live only in the coordinator's subprocess
environment and are never exposed to any model. If the authority digest changed
under us, the delivery is classified STALE rather than force-published.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .authority import UsfAuthorityClient
from .context import RuntimeContext
from .github_delivery import CommandResult, CommandRunner, SubprocessRunner


@dataclass
class PublishStep:
    name: str
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


def _last_json_object(text: str) -> dict[str, Any]:
    """Best-effort: the last balanced JSON object in ``text`` (the canonical
    publication scripts print a JSON summary). Returns {} when none is found."""
    depth = 0
    end = -1
    for i in range(len(text) - 1, -1, -1):
        c = text[i]
        if c == "}":
            if depth == 0:
                end = i
            depth += 1
        elif c == "{":
            depth -= 1
            if depth == 0 and end != -1:
                try:
                    return dict(json.loads(text[i : end + 1]))
                except (ValueError, TypeError):
                    end = -1
    return {}


def _digest_from_text(text: str) -> str:
    m = re.search(r"(?:post[_-]?digest|authority[_-]?digest)\W+([0-9a-f]{16,64}|sha256:[0-9a-f]+)", text, re.I)
    return m.group(1) if m else ""


class StardogPublisher:
    """Coordinator-owned canonical publication over a clone at the merge commit."""

    def __init__(
        self,
        ctx: RuntimeContext,
        *,
        runner: CommandRunner | None = None,
        env: dict[str, str] | None = None,
        authority_factory: Callable[[], UsfAuthorityClient] = UsfAuthorityClient,
    ) -> None:
        self.ctx = ctx
        self.runner = runner or SubprocessRunner()
        # Credentials for the canonical scripts flow through this subprocess env
        # only; no model ever receives them.
        self.env = env
        self._authority_factory = authority_factory

    def _npm(self, clone: Path, *args: str, timeout: float = 1800.0) -> CommandResult:
        return self.runner.run(["npm", *args], cwd=str(clone), env=self.env, timeout=timeout)

    # ---- MCP read-only re-reads ----------------------------------------- #

    def read_authority_digest(self) -> str:
        """The live authority digest via the read-only MCP client (never a mutation).
        Mirrors the snapshot compiler: bootstrap().authority.digest."""
        client = self._authority_factory()
        boot = client.bootstrap().json() or {}
        auth = boot.get("authority") or {}
        return str(auth.get("digest") or "").strip()

    def resnapshot(self) -> dict[str, Any]:
        """Re-read health + bootstrap + work_plan through MCP for reconciliation."""
        client = self._authority_factory()
        return {
            "health": client.health().json() or {},
            "bootstrap": client.bootstrap().json() or {},
            "work_plan": client.work_plan().json() or {},
        }

    @staticmethod
    def obligation_absent(resnapshot: dict[str, Any], obligation_id: str) -> bool:
        """True when ``obligation_id`` no longer appears anywhere in the re-read
        work plan / bootstrap (the delivery genuinely closed the gap)."""
        blob = json.dumps(resnapshot, sort_keys=True)
        return obligation_id not in blob

    # ---- frozen install + tests ----------------------------------------- #

    def install_frozen(self, clone: Path) -> PublishStep:
        r = self._npm(clone, "ci")
        return PublishStep("npm ci", r.ok, (r.err or r.out)[-500:])

    def run_tests(self, clone: Path) -> PublishStep:
        r = self._npm(clone, "test")
        return PublishStep("npm test", r.ok, (r.err or r.out)[-500:])

    # ---- canonical publication ------------------------------------------ #

    def validate_and_rollback(self, clone: Path) -> PublishStep:
        """Validate-and-rollback publication: require success AND zero contamination."""
        r = self._npm(clone, "run", "publish:authority:validate")
        data = _last_json_object(r.out)
        contamination = int(data.get("contamination", data.get("contaminationCount", 0)) or 0)
        ok = r.ok and contamination == 0
        return PublishStep(
            "publish:authority:validate",
            ok,
            f"contamination={contamination}; {(r.err or r.out)[-300:]}",
            {"contamination": contamination, **data},
        )

    def publish_committed(self, clone: Path) -> PublishStep:
        """Committed authority publication; parse commitOutcome/postDigest/graphs."""
        r = self._npm(clone, "run", "publish:authority")
        data = _last_json_object(r.out)
        post_digest = str(
            data.get("postDigest") or data.get("post_digest") or _digest_from_text(r.out)
        )
        commit_outcome = str(data.get("commitOutcome") or data.get("commit_outcome") or "")
        graphs = data.get("graphs") or data.get("graphsPublished") or []
        # Success requires a clean exit AND a recorded post-publication digest (we
        # must be able to record what the authority became), and the commit outcome
        # must not be an explicit failure.
        ok = r.ok and bool(post_digest) and commit_outcome.lower() not in ("failed", "error", "rolledback")
        return PublishStep(
            "publish:authority",
            ok,
            f"commitOutcome={commit_outcome} postDigest={post_digest[:16]}; {(r.err or r.out)[-300:]}",
            {"commitOutcome": commit_outcome, "postDigest": post_digest, "graphs": list(graphs)},
        )

    def drift(self, clone: Path) -> PublishStep:
        """Source/live drift: require zero mismatched graphs."""
        r = self._npm(clone, "run", "authority:drift")
        data = _last_json_object(r.out)
        mismatches = int(data.get("mismatches", data.get("mismatchCount", 0)) or 0)
        ok = r.ok and mismatches == 0
        return PublishStep(
            "authority:drift",
            ok,
            f"mismatches={mismatches}; {(r.err or r.out)[-300:]}",
            {"mismatches": mismatches, **data},
        )
