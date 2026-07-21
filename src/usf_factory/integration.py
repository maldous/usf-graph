"""Wave integration (DESIGN Phase 11 / build task §15).

Deterministic pre-integration runs FIRST: compatible patches are applied to a
factory-owned integration clone; if they merge cleanly and no semantic conflict
is detected, no AI is needed. An AI integrator is invoked ONLY when a semantic
reconciliation cannot be resolved deterministically. Attribution between worker
patch, integrator rewrite, and discarded change is always preserved.

Semantic compatibility is checked by IRI/subject/generated-output/path — a clean
Git merge does not imply semantic compatibility.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from .attribution import compute_attribution
from .canonical import content_digest
from .clock import utc_now_iso
from .isolation import RepoIsolation
from .models import Attribution, IntegrationAttempt, PacketResult, WavePatch

PatchFetch = Callable[[PacketResult], str]  # result -> patch text


def detect_semantic_conflicts(results: list[PacketResult]) -> list[str]:
    """Pairwise semantic conflict detection across accepted results.

    Even if patches apply cleanly, two results may redefine the same IRI or share
    a generated output. This is the semantic gate the deterministic merger uses.
    """
    conflicts: list[str] = []
    ordered = sorted(results, key=lambda r: r.packet_id)
    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            a, b = ordered[i], ordered[j]
            subj = set(a.semantic_subjects_changed) & set(b.semantic_subjects_changed)
            if subj:
                conflicts.append(
                    f"semantic subject overlap between {a.packet_id} and {b.packet_id}: {sorted(subj)}"
                )
            paths = set(a.changed_paths) & set(b.changed_paths)
            if paths:
                conflicts.append(
                    f"changed-path overlap between {a.packet_id} and {b.packet_id}: {sorted(paths)}"
                )
    return conflicts


def _git_apply_check(clone: Path, patch_text: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(clone), "apply", "--check", "-"],
        input=patch_text,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _git_apply(clone: Path, patch_text: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(clone), "apply", "-"],
        input=patch_text,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


class AiIntegrator(Protocol):
    async def integrate(
        self, results: list[PacketResult], conflicts: list[str]
    ) -> tuple[str, dict[str, Attribution]]:
        """Return (effective_wave_patch, attributions). Billable; gated."""
        ...


def deterministic_preintegrate(
    set_id: str,
    accepted_results: list[PacketResult],
    isolation: RepoIsolation,
    *,
    base_head: str,
    patch_fetch: PatchFetch | None = None,
    apply_patches: bool = False,
) -> tuple[IntegrationAttempt, WavePatch | None]:
    """Attempt deterministic integration of accepted results.

    In the safe runtime ``apply_patches`` is False and no worker patches exist, so
    this simply records a clean (empty) attempt. When patches are present, they
    are applied to an integration clone in packet order and semantically checked.
    """
    with_patches = [r for r in accepted_results if r.patch_digest]
    semantic_conflicts = detect_semantic_conflicts(with_patches)

    attempt = IntegrationAttempt(
        set_id=set_id,
        accepted_packet_ids=sorted(r.packet_id for r in accepted_results),
        deterministic_merge_ok=not semantic_conflicts,
        semantic_conflicts=semantic_conflicts,
        used_ai_integrator=False,
        attempted_at=utc_now_iso(),
    )

    if not with_patches:
        # Nothing to merge (e.g., a non-mutating cycle). Clean by definition.
        return attempt, None

    if semantic_conflicts:
        # Deterministic merge cannot resolve semantics; caller may invoke the
        # gated AI integrator. We stop here in the safe runtime.
        return attempt, None

    if not apply_patches:
        # Metadata-only pre-integration (default safe mode): compute the combined
        # wave-patch identity without touching the filesystem.
        wave_digest = content_digest(
            {"set": set_id, "patches": sorted(r.patch_digest or "" for r in with_patches)}
        )
        for r in with_patches:
            wp = patch_fetch(r) if patch_fetch else ""
            attempt.attributions[r.packet_id] = compute_attribution(
                wp, wp, worker_patch_digest=r.patch_digest, reason="deterministic merge (preserved)"
            )
        wave = WavePatch(
            set_id=set_id,
            patch_digest=wave_digest,
            changed_paths=sorted({p for r in with_patches for p in r.changed_paths}),
            semantic_subjects=sorted(
                {s for r in with_patches for s in r.semantic_subjects_changed}
            ),
        )
        return attempt, wave

    # Real application path (used once execution is enabled).
    clone = isolation.integration_clone(set_id, base_head)
    applied: list[PacketResult] = []
    for r in sorted(with_patches, key=lambda x: x.packet_id):
        patch = patch_fetch(r) if patch_fetch else ""
        if not (_git_apply_check(clone, patch) and _git_apply(clone, patch)):
            attempt.deterministic_merge_ok = False
            attempt.semantic_conflicts.append(f"patch for {r.packet_id} failed to apply")
            return attempt, None
        applied.append(r)
        attempt.attributions[r.packet_id] = compute_attribution(
            patch, patch, worker_patch_digest=r.patch_digest, reason="applied cleanly"
        )
    diff = subprocess.run(
        ["git", "-C", str(clone), "diff", "--cached", "HEAD"], capture_output=True, text=True
    ).stdout
    wave = WavePatch(
        set_id=set_id,
        patch_digest=content_digest({"diff": diff}),
        changed_paths=sorted({p for r in applied for p in r.changed_paths}),
        semantic_subjects=sorted({s for r in applied for s in r.semantic_subjects_changed}),
    )
    return attempt, wave
