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
from .canonical import require_sha256_digest
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


_PUBLICATION_KEYS = {
    "mode",
    "ok",
    "commitOutcome",
    "contaminationCount",
    "graphsCleared",
    "authoredLoaded",
    "shapesLoaded",
    "evaluatedAuthorityDigest",
    "postAuthorityDigest",
    "postTriples",
}
_OUTCOME_KEYS = {
    "state",
    "exactCandidateStateVerified",
    "candidateDigest",
    "candidateGraphs",
    "transactionClosedVerified",
    "observedDigest",
}
_DRIFT_KEYS = {"command", "ok", "graphCount", "mismatched"}


def _single_json_document(text: str) -> dict[str, Any]:
    """Parse exactly one JSON object and reject logs, prefixes and extra objects."""
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError("PUBLICATION_OUTPUT_DOCUMENT_COUNT_INVALID")
    try:
        value = json.loads(lines[0])
    except (ValueError, TypeError) as exc:
        raise ValueError("PUBLICATION_OUTPUT_NOT_JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("PUBLICATION_OUTPUT_NOT_OBJECT")
    return value


def _publication_output(text: str, mode: str) -> dict[str, Any]:
    data = _single_json_document(text)
    if set(data) != _PUBLICATION_KEYS or data.get("mode") != mode:
        raise ValueError("PUBLICATION_OUTPUT_SCHEMA_V1_INVALID")
    if not isinstance(data.get("ok"), bool) or not isinstance(data.get("contaminationCount"), int):
        raise ValueError("PUBLICATION_OUTPUT_SCHEMA_V1_INVALID")
    for field_name in ("graphsCleared", "authoredLoaded", "shapesLoaded"):
        if not isinstance(data.get(field_name), int):
            raise ValueError("PUBLICATION_OUTPUT_SCHEMA_V1_INVALID")
    if data.get("postTriples") is not None and not isinstance(data.get("postTriples"), int):
        raise ValueError("PUBLICATION_OUTPUT_SCHEMA_V1_INVALID")
    outcome = data.get("commitOutcome")
    if not isinstance(outcome, dict) or not set(outcome).issubset(_OUTCOME_KEYS):
        raise ValueError("PUBLICATION_OUTCOME_SCHEMA_V1_INVALID")
    data["outputSchemaVersion"] = 1
    return data


def _drift_output(text: str) -> dict[str, Any]:
    data = _single_json_document(text)
    if set(data) != _DRIFT_KEYS or data.get("command") != "drift":
        raise ValueError("DRIFT_OUTPUT_SCHEMA_V1_INVALID")
    if not isinstance(data.get("ok"), bool) or not isinstance(data.get("graphCount"), int):
        raise ValueError("DRIFT_OUTPUT_SCHEMA_V1_INVALID")
    if not isinstance(data.get("mismatched"), list) or any(
        not isinstance(item, str) for item in data["mismatched"]
    ):
        raise ValueError("DRIFT_OUTPUT_SCHEMA_V1_INVALID")
    data["outputSchemaVersion"] = 1
    return data


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _require_digest(value: str, field: str) -> str:
    try:
        return require_sha256_digest(str(value or ""), field)
    except ValueError as exc:
        raise ValueError(f"{field} must be an exact sha256 digest") from exc


def _canonical_outcome_digest(outcome: dict[str, Any], key: str) -> str:
    try:
        return _require_digest(str(outcome.get(key) or ""), key)
    except ValueError:
        return ""


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
        containment_proven: bool = False,
    ) -> None:
        self.ctx = ctx
        self.runner = runner or SubprocessRunner()
        # Credentials for the canonical scripts flow through this subprocess env
        # only; no model ever receives them.
        self.env = dict(env) if env is not None else restricted_subprocess_environment(github=False)
        self._authority_factory = authority_factory
        self.credential_env_file = credential_env_file
        self._containment_proven = containment_proven

    def publication_containment_ready(self) -> bool:
        return self._containment_proven

    def _npm(
        self,
        clone: Path,
        *args: str,
        timeout: float = 1800.0,
        authority_credentials: bool = False,
    ) -> CommandResult:
        npm_args = ["--silent", *args] if args and args[0] == "run" else list(args)
        command = ["npm", *npm_args]
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
                *npm_args,
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
        """Read a complete, digest-stable work plan under one database binding."""
        with self._authority_factory() as client:
            health = client.health().json() or {}
            bootstrap = client.bootstrap().json() or {}
            authority = bootstrap.get("authority") or {}
            digest = _require_digest(str(authority.get("digest") or ""), "resnapshot digest")
            database = str(health.get("database") or "")
            gaps: list[dict[str, Any]] = []
            offset = 0
            seen: set[int] = set()
            while True:
                if offset in seen:
                    raise ValueError("WORK_PLAN_PAGINATION_REPEATED")
                seen.add(offset)
                page = client.work_plan({"offset": offset}).json() or {}
                if page.get("schemaVersion") != 1:
                    raise ValueError("WORK_PLAN_SCHEMA_INVALID")
                if page.get("offset") not in {None, offset}:
                    raise ValueError("WORK_PLAN_OFFSET_MISMATCH")
                if (
                    _require_digest(str(page.get("authorityDigest") or ""), "work-plan digest")
                    != digest
                ):
                    raise ValueError("WORK_PLAN_AUTHORITY_MOVED")
                page_gaps = page.get("gaps")
                if not isinstance(page_gaps, list) or any(
                    not isinstance(gap, dict) for gap in page_gaps
                ):
                    raise ValueError("WORK_PLAN_GAPS_INVALID")
                for gap in page_gaps:
                    identity = (str(gap.get("type") or ""), str(gap.get("subject") or ""))
                    if not all(identity):
                        raise ValueError("WORK_PLAN_GAP_IDENTITY_INVALID")
                    if any(
                        (str(existing.get("type") or ""), str(existing.get("subject") or ""))
                        == identity
                        for existing in gaps
                    ):
                        raise ValueError("WORK_PLAN_DUPLICATE_GAP_IDENTITY")
                    gaps.append(gap)
                if len(gaps) > 1_000:
                    raise ValueError("WORK_PLAN_LIMIT_EXCEEDED")
                if page.get("truncated") is not True:
                    break
                nxt = page.get("nextOffset")
                if not isinstance(nxt, int) or nxt <= offset:
                    raise ValueError("WORK_PLAN_CONTINUATION_INVALID")
                offset = nxt
            health_after = client.health().json() or {}
            bootstrap_after = client.bootstrap().json() or {}
            digest_after = _require_digest(
                str((bootstrap_after.get("authority") or {}).get("digest") or ""),
                "post-work-plan digest",
            )
            if digest_after != digest or str(health_after.get("database") or "") != database:
                raise ValueError("AUTHORITY_BINDING_MOVED_DURING_WORK_PLAN")
            return {
                "health": health_after,
                "bootstrap": bootstrap_after,
                "work_plan": {
                    "schemaVersion": 1,
                    "authorityDigest": digest,
                    "gaps": gaps,
                    "truncated": False,
                },
            }

    @staticmethod
    def obligation_absent(resnapshot: dict[str, Any], gap_type: str, subject: str) -> bool:
        """Closure is exact absence of one typed actionable work-plan identity."""
        work_plan = resnapshot.get("work_plan")
        if not isinstance(work_plan, dict):
            return False
        if work_plan.get("truncated") is not False or work_plan.get("schemaVersion") != 1:
            return False
        work_items = work_plan.get("gaps")
        if not isinstance(work_items, list):
            return False
        if any(not isinstance(item, dict) for item in work_items):
            return False
        identities = {
            (str(item.get("type") or ""), str(item.get("subject") or "")) for item in work_items
        }
        return (gap_type, subject) not in identities

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
        if not self.publication_containment_ready():
            return PublishStep(
                "publish:authority:validate", False, "PUBLICATION_CONTAINMENT_UNAVAILABLE"
            )
        expected = _require_digest(expected_authority_digest, "expected authority digest")
        r = self._npm(
            clone,
            "run",
            "publish:authority:validate",
            "--",
            f"--authority-digest={expected}",
            authority_credentials=True,
        )
        try:
            data = _publication_output(r.out, "validate")
        except ValueError as exc:
            return PublishStep("publish:authority:validate", False, str(exc), {})
        contamination_raw = data.get("contaminationCount")
        contamination = int(contamination_raw) if contamination_raw is not None else -1
        try:
            evaluated = _require_digest(
                str(data.get("evaluatedAuthorityDigest") or ""), "evaluated authority digest"
            )
            post_digest = _require_digest(
                str(data.get("postAuthorityDigest") or ""), "post authority digest"
            )
        except ValueError:
            evaluated = post_digest = ""
        commit_outcome = data.get("commitOutcome")
        outcome_state = (
            str(commit_outcome.get("state") or "") if isinstance(commit_outcome, dict) else ""
        )
        try:
            candidate_digest = _require_digest(
                str(commit_outcome.get("candidateDigest") or "")
                if isinstance(commit_outcome, dict)
                else "",
                "candidate digest",
            )
        except ValueError:
            candidate_digest = ""
        ok = (
            r.ok
            and data.get("ok") is True
            and contamination == 0
            and evaluated == expected
            and post_digest == expected
            and isinstance(commit_outcome, dict)
            and outcome_state == "validated-rolled-back"
            and commit_outcome.get("exactCandidateStateVerified") is True
            and bool(_DIGEST.fullmatch(candidate_digest))
            and bool(commit_outcome.get("candidateGraphs"))
        )
        return PublishStep(
            "publish:authority:validate",
            ok,
            f"contamination={contamination}; outcome={outcome_state}; {(r.err or r.out)[-300:]}",
            data,
        )

    def publish_committed(
        self, clone: Path, expected_authority_digest: str, expected_candidate_digest: str
    ) -> PublishStep:
        """Committed authority publication; parse the canonical compiler result."""
        if not self.publication_containment_ready():
            return PublishStep("publish:authority", False, "PUBLICATION_CONTAINMENT_UNAVAILABLE")
        expected = _require_digest(expected_authority_digest, "expected authority digest")
        candidate_expected = _require_digest(
            expected_candidate_digest, "validated candidate digest"
        )
        r = self._npm(
            clone,
            "run",
            "publish:authority",
            "--",
            f"--authority-digest={expected}",
            authority_credentials=True,
        )
        try:
            data = _publication_output(r.out, "commit")
        except ValueError as exc:
            return PublishStep("publish:authority", False, str(exc), {})
        post_digest = _require_digest(str(data.get("postAuthorityDigest") or ""), "post digest")
        evaluated = _require_digest(
            str(data.get("evaluatedAuthorityDigest") or ""), "evaluated digest"
        )
        commit_outcome = data.get("commitOutcome")
        outcome_state = (
            str(commit_outcome.get("state") or "") if isinstance(commit_outcome, dict) else ""
        )
        exact_state = isinstance(commit_outcome, dict) and (
            commit_outcome.get("exactCandidateStateVerified") is True
        )
        try:
            candidate_digest = _require_digest(
                str(commit_outcome.get("candidateDigest") or "")
                if isinstance(commit_outcome, dict)
                else "",
                "commit candidate digest",
            )
        except ValueError:
            candidate_digest = ""
        reconciled = (
            isinstance(commit_outcome, dict)
            and outcome_state == "reconciled-committed"
            and (
                commit_outcome.get("transactionClosedVerified") is True
                and _canonical_outcome_digest(commit_outcome, "candidateDigest")
                == _canonical_outcome_digest(commit_outcome, "observedDigest")
            )
        )
        ok = (
            r.ok
            and data.get("ok") is True
            and evaluated == expected
            and data.get("contaminationCount") == 0
            and candidate_digest == candidate_expected
            and post_digest == candidate_expected
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
        if not self.publication_containment_ready():
            return PublishStep("authority:drift", False, "PUBLICATION_CONTAINMENT_UNAVAILABLE")
        r = self._npm(
            clone,
            "run",
            "authority:drift",
            authority_credentials=True,
        )
        try:
            data = _drift_output(r.out)
        except ValueError as exc:
            return PublishStep("authority:drift", False, str(exc), {})
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
