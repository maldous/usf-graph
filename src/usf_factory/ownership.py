"""Ownership evidence store + reconciliation (Phase 2).

Turns *candidate* owners (parsed declarations) into *verified* owners using
explicit, digest-bound evidence. Operator approvals are append-only and
digest-bound; a live USF layout/materialisation contract (via the MCP boundary)
is preferred when available. Verification is what authorizes a semantic write
scope — a parsed declaration never suffices.
"""

from __future__ import annotations

from typing import Any

from .clock import utc_now, utc_now_iso
from .context import RuntimeContext
from .errors import ConfigError
from .materialisation import MaterialisationIndex
from .models import OwnershipEvidence


def load_evidence(ctx: RuntimeContext, subject: str | None = None) -> list[dict[str, Any]]:
    if subject:
        return ctx.store.records("ownership_evidence", "subject=?", (subject,))
    return ctx.store.records("ownership_evidence")


def record_operator_approval(
    ctx: RuntimeContext,
    subject: str,
    owner_path: str,
    *,
    repository_commit: str = "",
    detail: str = "",
    revalidate_days: int = 90,
) -> OwnershipEvidence:
    """Append-only, digest-bound operator ownership approval. Stored under its own
    evidence_id so prior approvals are never overwritten (auditable history)."""
    from datetime import timedelta

    ev = OwnershipEvidence(
        subject=subject,
        owner_path=owner_path,
        evidence_kind="operator",
        source_reference="operator-approval",
        repository_commit=repository_commit,
        verified=True,
        verified_at=utc_now_iso(),
        revalidate_after=(utc_now() + timedelta(days=revalidate_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        detail=detail,
    )
    ev = ev.model_copy(update={"source_digest": ev.digest()})
    ctx.store.put(
        "ownership_evidence",
        ev.evidence_id + ":" + ev.verified_at,  # append-only key (never overwrite)
        ev.content_dict(),
        extra={"subject": subject, "owner_path": owner_path, "verified": "true"},
    )
    ctx.log_event(
        "ownership.approved",
        stage="INIT",
        cycle_id="-",
        payload={"subject": subject, "owner_path": owner_path, "commit": repository_commit},
    )
    return ev


def reconcile_from_authority(
    ctx: RuntimeContext, index: MaterialisationIndex, authority: Any, subjects: list[str]
) -> list[dict[str, Any]]:
    """Best-effort: ask the USF MCP layout/artifact contract for the authorized
    owner path of each subject. Returns evidence rows (verified) for subjects the
    contract resolves to a candidate owner. Never raises on a miss — a subject the
    contract cannot resolve simply stays candidate-only."""
    rows: list[dict[str, Any]] = []
    for subj in subjects:
        entry = index.resolve(subj)
        if entry is None:
            continue
        try:
            res = authority.artifact_describe({"iri": subj})
            data = res.json() if hasattr(res, "json") else None
        except Exception:
            data = None
        owner = None
        if isinstance(data, dict):
            owner = (
                data.get("owner_path")
                or data.get("path")
                or (data.get("artifact") or {}).get("path")
            )
        if owner and owner in entry.candidate_owners:
            rows.append(
                {
                    "subject": subj,
                    "owner_path": owner,
                    "evidence_kind": "layout-contract",
                    "verified": True,
                    "repository_commit": index.source_commit,
                    "source_reference": "usf_artifact_describe",
                }
            )
    return rows


def verify_index(
    ctx: RuntimeContext, index: MaterialisationIndex, authority: Any | None = None
) -> MaterialisationIndex:
    """Apply all stored ownership evidence (and, if an authority is supplied, live
    layout-contract evidence) to mark verified owners on the index."""
    evidence = load_evidence(ctx)
    if authority is not None:
        subjects = [s for s, e in index.entries.items() if e.candidate_owners and not e.verified]
        # Bound the authority reconciliation to a sane number of subjects.
        evidence = evidence + reconcile_from_authority(ctx, index, authority, subjects[:200])
    index.apply_ownership_evidence(evidence)
    return index


def approve_cli(ctx: RuntimeContext, subject: str, path: str) -> OwnershipEvidence:
    """CLI helper: approve ownership of ``subject`` by ``path`` at the current
    mirror head. Validates that ``path`` is a real candidate owner (or an explicit
    override for a path the index knows), so approvals stay grounded."""
    from .isolation import RepoIsolation
    from .materialisation import build_index_at

    iso = RepoIsolation(ctx.paths, ctx.usf_repo)
    iso.ensure_mirror()
    head = iso.usf_head()
    index = build_index_at(ctx.paths.mirror, head)
    entry = index.resolve(subject)
    if entry is None:
        raise ConfigError(f"subject not present in the materialisation index: {subject}")
    if path not in entry.candidate_owners and path not in entry.related_paths:
        raise ConfigError(
            f"path '{path}' is not a candidate/related path for {subject}; "
            f"candidates={entry.candidate_owners}"
        )
    return record_operator_approval(
        ctx, subject, path, repository_commit=head, detail="approved via CLI"
    )
