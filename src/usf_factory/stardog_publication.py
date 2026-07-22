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
from .canonical import canonical_authority_digest
from .context import RuntimeContext
from .github_delivery import (
    CommandResult,
    CommandRunner,
    SubprocessRunner,
    restricted_subprocess_environment,
)


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


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _require_digest(value: str, field: str) -> str:
    digest = canonical_authority_digest(str(value or ""))
    if not _DIGEST.fullmatch(digest):
        raise ValueError(f"{field} must be an exact sha256 digest")
    return digest


class StardogPublisher:
    """Coordinator-owned canonical publication over a clone at the merge commit."""

    def __init__(
        self,
        ctx: RuntimeContext,
        *,
        runner: CommandRunner | None = None,
        env: dict[str, str] | None = None,
        authority_factory: Callable[[], UsfAuthorityClient] = UsfAuthorityClient,
        credential_env_file: Path = Path("/usf/.env"),
    ) -> None:
        self.ctx = ctx
        self.runner = runner or SubprocessRunner()
        # Credentials for the canonical scripts flow through this subprocess env
        # only; no model ever receives them.
        self.env = dict(env) if env is not None else restricted_subprocess_environment(github=False)
        self._authority_factory = authority_factory
        self.credential_env_file = credential_env_file

    def _npm(
        self,
        clone: Path,
        *args: str,
        timeout: float = 1800.0,
        authority_credentials: bool = False,
    ) -> CommandResult:
        command = ["npm", *args]
        if authority_credentials:
            # The controlled child process, not the factory or any model, sources
            # Stardog credentials. Positional arguments avoid shell interpolation.
            command = [
                "bash",
                "-lc",
                'set -a; [ -f "$1" ] && . "$1"; set +a; shift; exec "$@"',
                "usf-factory-publication",
                str(self.credential_env_file),
                "npm",
                *args,
            ]
        return self.runner.run(command, cwd=str(clone), env=self.env, timeout=timeout)

    # ---- MCP read-only re-reads ----------------------------------------- #

    def read_authority_binding(self) -> tuple[str, str]:
        """Return exact live authority digest and database via one MCP session."""
        with self._authority_factory() as client:
            health = client.health().json() or {}
            boot = client.bootstrap().json() or {}
        auth = boot.get("authority") or {}
        digest = _require_digest(str(auth.get("digest") or ""), "live authority digest")
        database = str(health.get("database") or "").strip()
        if not database:
            raise ValueError("live authority database is absent")
        return digest, database

    def read_authority_digest(self) -> str:
        """The live authority digest via the read-only MCP client (never a mutation)."""
        return self.read_authority_binding()[0]

    def resnapshot(self) -> dict[str, Any]:
        """Re-read health + bootstrap + work_plan through MCP for reconciliation."""
        with self._authority_factory() as client:
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

    def validate_and_rollback(self, clone: Path, expected_authority_digest: str) -> PublishStep:
        """Validate-and-rollback publication: require success AND zero contamination."""
        expected = _require_digest(expected_authority_digest, "expected authority digest")
        r = self._npm(
            clone,
            "run",
            "publish:authority:validate",
            "--",
            f"--authority-digest={expected}",
            authority_credentials=True,
        )
        data = _last_json_object(r.out)
        contamination_raw = data.get("contaminationCount")
        contamination = int(contamination_raw) if contamination_raw is not None else -1
        evaluated = str(data.get("evaluatedAuthorityDigest") or "")
        post_digest = str(data.get("postAuthorityDigest") or "")
        commit_outcome = data.get("commitOutcome")
        outcome_state = (
            str(commit_outcome.get("state") or "") if isinstance(commit_outcome, dict) else ""
        )
        ok = (
            r.ok
            and data.get("mode") == "validate"
            and data.get("ok") is True
            and contamination == 0
            and evaluated == expected
            and post_digest == expected
            and isinstance(commit_outcome, dict)
            and outcome_state == "validated-rolled-back"
            and commit_outcome.get("exactCandidateStateVerified") is True
            and bool(_DIGEST.fullmatch(str(commit_outcome.get("candidateDigest") or "")))
            and bool(commit_outcome.get("candidateGraphs"))
        )
        return PublishStep(
            "publish:authority:validate",
            ok,
            f"contamination={contamination}; outcome={outcome_state}; {(r.err or r.out)[-300:]}",
            data,
        )

    def publish_committed(self, clone: Path, expected_authority_digest: str) -> PublishStep:
        """Committed authority publication; parse the canonical compiler result."""
        expected = _require_digest(expected_authority_digest, "expected authority digest")
        r = self._npm(
            clone,
            "run",
            "publish:authority",
            "--",
            f"--authority-digest={expected}",
            authority_credentials=True,
        )
        data = _last_json_object(r.out)
        post_digest = str(data.get("postAuthorityDigest") or "")
        evaluated = str(data.get("evaluatedAuthorityDigest") or "")
        commit_outcome = data.get("commitOutcome")
        outcome_state = (
            str(commit_outcome.get("state") or "") if isinstance(commit_outcome, dict) else ""
        )
        exact_state = isinstance(commit_outcome, dict) and (
            commit_outcome.get("exactCandidateStateVerified") is True
        )
        reconciled = (
            isinstance(commit_outcome, dict)
            and outcome_state == "reconciled-committed"
            and (
                commit_outcome.get("transactionClosedVerified") is True
                and commit_outcome.get("candidateDigest") == commit_outcome.get("observedDigest")
            )
        )
        ok = (
            r.ok
            and data.get("mode") == "commit"
            and data.get("ok") is True
            and evaluated == expected
            and bool(_DIGEST.fullmatch(post_digest))
            and exact_state
            and (outcome_state == "confirmed-response" or reconciled)
        )
        return PublishStep(
            "publish:authority",
            ok,
            f"commitOutcome={outcome_state} postDigest={post_digest[:16]}; "
            f"{(r.err or r.out)[-300:]}",
            data,
        )

    def drift(self, clone: Path) -> PublishStep:
        """Source/live drift: require zero mismatched graphs."""
        r = self._npm(
            clone,
            "run",
            "authority:drift",
            authority_credentials=True,
        )
        data = _last_json_object(r.out)
        mismatched = data.get("mismatched")
        mismatch_count = len(mismatched) if isinstance(mismatched, list) else -1
        ok = (
            r.ok
            and data.get("command") == "drift"
            and data.get("ok") is True
            and mismatch_count == 0
        )
        return PublishStep(
            "authority:drift",
            ok,
            f"mismatches={mismatch_count}; {(r.err or r.out)[-300:]}",
            data,
        )
