"""Deterministic semantic snapshot compiler (DESIGN Phase 4).

The factory application — not an AI model — compiles the snapshot by calling the
read-only USF MCP boundary and inspecting Git. The result is an immutable,
content-addressed :class:`SemanticSnapshot`.

This is the deliberate correction to "let a model compile the bootstrap": authority
facts never depend on model output.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .authority import UsfAuthorityClient
from .canonical import digest_text
from .clock import utc_now_iso
from .errors import SnapshotError
from .isolation import RepoIsolation
from .models import SemanticSnapshot
from .paths import USF_REPO

# Tools the deterministic snapshot depends on; their absence fails closed.
REQUIRED_TOOLS = ("usf_health", "usf_bootstrap", "usf_query")

# An authority digest must be a non-trivial identifier (never manufactured).
_DIGEST_RE = re.compile(r"^[A-Za-z0-9:_\-]{16,}$")


def _valid_digest(value: str) -> bool:
    return bool(value) and " " not in value and bool(_DIGEST_RE.match(value))


def _read_digest(path: Path) -> str | None:
    try:
        if path.exists():
            return digest_text(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    return None


def _collect_obligation_ids(bootstrap: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for key in ("openGaps", "proofObligations", "validationObligations"):
        for item in bootstrap.get(key) or []:
            if isinstance(item, dict):
                oid = item.get("id") or item.get("iri") or item.get("obligation")
                if oid:
                    ids.append(str(oid))
            elif isinstance(item, str):
                ids.append(item)
    return sorted(set(ids))


def _collect_evidence_refs(bootstrap: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for item in bootstrap.get("evidenceResults") or []:
        if isinstance(item, dict):
            ref = item.get("id") or item.get("iri") or item.get("evidence")
            if ref:
                refs.append(str(ref))
    return sorted(set(refs))[:200]  # bounded — never a full transcript


def compile_snapshot(
    *,
    authority: UsfAuthorityClient,
    isolation: RepoIsolation,
    usf_repo: Path | None = None,
) -> SemanticSnapshot:
    """Compile an immutable semantic snapshot from live authority + Git."""
    repo = usf_repo or isolation.usf_repo or USF_REPO

    # --- Authority (read-only MCP) --- #
    # FAIL CLOSED. The snapshot must never be built on synthesized or degraded
    # authority: an authority digest is never manufactured, and required
    # read-only tools must be present.
    tools = authority.list_tools()
    missing_tools = [t for t in REQUIRED_TOOLS if t not in tools]
    if missing_tools:
        raise SnapshotError(f"USF MCP is missing required tools: {missing_tools}")

    health = authority.health()
    health_json = health.json() or {}
    health_ok = bool(health_json.get("ok", health.ok))
    if not health_ok:
        raise SnapshotError("USF authority health is not ok; refusing to snapshot")

    bootstrap = authority.bootstrap().json() or {}
    auth = bootstrap.get("authority") or {}
    authority_digest = str(auth.get("digest") or "").strip()
    if not _valid_digest(authority_digest):
        raise SnapshotError(
            "USF bootstrap did not supply a valid authority digest; refusing to "
            "synthesize one (fail closed)"
        )
    triple_count = auth.get("triples") or health_json.get("triples")
    graph_count = auth.get("coveredGraphCount")
    if triple_count is None or graph_count is None:
        raise SnapshotError("authority triple/graph count missing; refusing to snapshot")

    unresolved = _collect_obligation_ids(bootstrap)
    evidence = _collect_evidence_refs(bootstrap)
    active_phase = None
    task = bootstrap.get("task")
    if isinstance(task, dict):
        active_phase = task.get("phase") or task.get("node") or task.get("id")

    # --- Git (read-only, isolated) --- #
    try:
        repo_head = isolation.usf_head()
        wt_digest = isolation.working_tree_digest()
    except Exception as exc:
        raise SnapshotError(f"could not inspect repository state: {exc}") from exc

    goal_digest = _read_digest(repo / "GOAL.md")
    checkpoint_digest = _read_digest(repo / ".work" / "programme" / "checkpoint.json")
    ledger_digest = _read_digest(repo / ".work" / "programme" / "ledger.json")

    snap = SemanticSnapshot(
        authority_digest=authority_digest,
        graph_count=int(graph_count) if graph_count is not None else None,
        triple_count=int(triple_count) if triple_count is not None else None,
        repository_head=repo_head,
        working_tree_digest=wt_digest,
        checkpoint_digest=checkpoint_digest,
        ledger_digest=ledger_digest,
        goal_digest=goal_digest,
        active_phase=active_phase,
        unresolved_obligations=unresolved,
        admitted_evidence=evidence,
        open_transactions=[],
        health_ok=health_ok,
        mcp_tools=sorted(tools),
        captured_at=utc_now_iso(),
        source="usf-mcp",
    )
    return snap
