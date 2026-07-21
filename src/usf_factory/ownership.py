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
        ev.model_dump(mode="json"),  # id-keyed record: preserve verified_at/expiry
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


def verify_from_declaration(
    ctx: RuntimeContext,
    index: MaterialisationIndex,
    subjects: list[str],
    *,
    commit: str,
) -> list[dict[str, Any]]:
    """Verify ownership from OBJECTIVE declaration evidence: a subject with exactly
    ONE candidate owner (unambiguous) whose owner file is a non-generated canonical
    source that DECLARES the subject at the pinned commit. Records a digest-bound,
    commit-bound ``subject-declaration`` evidence row. Ambiguous (>1 candidate) or
    undeclared subjects are left candidate-only — ownership is never fabricated."""
    from .context_pack import _blob_digest, _local_subject, _read_blob

    rows: list[dict[str, Any]] = []
    for subj in subjects:
        entry = index.entries.get(subj)
        if entry is None or len(entry.candidate_owners) != 1:
            continue  # none or ambiguous => not objectively unambiguous
        owner = entry.candidate_owners[0]
        content = _read_blob(ctx.paths.mirror, commit, owner)
        if content is None or (subj not in content and _local_subject(subj) not in content):
            continue  # the subject is not genuinely declared in the candidate file
        digest = _blob_digest(ctx.paths.mirror, commit, owner)
        ev = OwnershipEvidence(
            subject=subj,
            owner_path=owner,
            evidence_kind="subject-declaration",
            source_reference=owner,
            repository_commit=commit,
            verified=True,
            verified_at=utc_now_iso(),
            detail="single unambiguous declaration in a non-generated canonical source (blob-pinned)",
        )
        ev = ev.model_copy(update={"source_digest": digest or ev.digest()})
        ctx.store.put(
            "ownership_evidence",
            ev.evidence_id + ":" + ev.verified_at,
            ev.model_dump(mode="json"),
            extra={"subject": subj, "owner_path": owner, "verified": "true"},
        )
        ctx.log_event(
            "ownership.verified_declaration",
            stage="INIT",
            cycle_id="-",
            payload={
                "subject": subj,
                "owner_path": owner,
                "commit": commit,
                "digest": ev.source_digest,
            },
        )
        rows.append(
            {
                "subject": subj,
                "owner_path": owner,
                "evidence_kind": "subject-declaration",
                "verified": True,
                "repository_commit": commit,
                "source_reference": owner,
            }
        )
    return rows


def verify_index(
    ctx: RuntimeContext,
    index: MaterialisationIndex,
    authority: Any | None = None,
    *,
    declare_subjects: list[str] | None = None,
) -> MaterialisationIndex:
    """Apply stored ownership evidence, plus (if supplied) live layout-contract
    evidence and objective subject-declaration evidence for the named subjects."""
    evidence = load_evidence(ctx)
    if authority is not None:
        subjects = [s for s, e in index.entries.items() if e.candidate_owners and not e.verified]
        # Bound the authority reconciliation to a sane number of subjects.
        evidence = evidence + reconcile_from_authority(ctx, index, authority, subjects[:200])
    if declare_subjects:
        evidence = evidence + verify_from_declaration(
            ctx, index, declare_subjects, commit=index.source_commit
        )
    index.apply_ownership_evidence(evidence)
    return index


def verify_owner_for_obligations(ctx: RuntimeContext) -> dict[str, Any]:
    """S8 entry point: establish (or report the best unverified candidate for) a
    verified owner for a CURRENT programme-obligation subject, using objective
    declaration evidence. Returns a status dict; never fabricates ownership."""
    from .isolation import RepoIsolation
    from .materialisation import build_index_at

    subjects, head = _current_obligation_subjects(ctx)
    iso = RepoIsolation(ctx.paths, ctx.usf_repo)
    if not iso.mirror_exists():
        iso.ensure_mirror()
    if not head:
        head = iso.usf_head()
    if not subjects:
        return {"status": "NO_OBLIGATION_SUBJECTS", "commit": head}
    try:
        index = build_index_at(ctx.paths.mirror, head)
    except Exception as exc:
        return {
            "status": "UNVERIFIED",
            "commit": head,
            "best_candidate": None,
            "missing": f"materialisation index unavailable at {head[:12]}: {type(exc).__name__}",
        }
    verify_index(ctx, index, declare_subjects=subjects)
    verified = [
        (s, index.entries[s].verified_owner)
        for s in subjects
        if index.resolve(s) and index.entries[s].verified
    ]
    if verified:
        return {
            "status": "VERIFIED",
            "commit": head,
            "subject": verified[0][0],
            "owner_path": verified[0][1],
        }
    # No objective evidence: report the best candidate + what's missing.
    best = None
    for s in subjects:
        e = index.entries.get(s)
        if e and e.candidate_owners:
            best = {
                "subject": s,
                "candidate_owners": e.candidate_owners,
                "ambiguous": len(e.candidate_owners) > 1,
            }
            break
    return {
        "status": "UNVERIFIED",
        "commit": head,
        "best_candidate": best,
        "missing": "objective single-declaration or operator/contract evidence",
    }


def _current_obligation_subjects(ctx: RuntimeContext) -> tuple[list[str], str]:
    """Semantic subjects of the latest snapshot's programme obligations, plus the
    snapshot's repository_head (the commit the obligations were compiled against)."""
    rows = list(ctx.store.items("semantic_snapshots"))
    if not rows:
        return [], ""
    _k, snap = sorted(rows, key=lambda kv: kv[1].get("captured_at", ""))[-1]
    subjects: list[str] = []
    for o in snap.get("programme_obligations") or []:
        for s in o.get("semantic_subjects") or []:
            if s not in subjects:
                subjects.append(s)
    return subjects, str(snap.get("repository_head") or "")


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
