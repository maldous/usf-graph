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
from typing import Any, Protocol

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


def _git_apply_index(clone: Path, patch_text: str) -> bool:
    """Apply into the index AND working tree so the combined diff is capturable."""
    proc = subprocess.run(
        ["git", "-C", str(clone), "apply", "--index", "-"],
        input=patch_text,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


class AiIntegrator(Protocol):
    async def integrate(
        self, results: list[PacketResult], conflicts: list[str], patches: dict[str, str]
    ) -> tuple[str, dict[str, Attribution]]:
        """Return (effective_wave_patch, attributions). Billable; gated."""
        ...


INTEGRATOR_SYSTEM = (
    "You are a USF wave integrator. Bounded worker patches conflict semantically. "
    "Produce ONE reconciled unified diff (git format) that resolves the conflict "
    "while preserving every non-conflicting change. Return ONLY the diff. Do not "
    "broaden scope, invent IRIs, or delete unrelated work."
)


class SemanticAiIntegrator:
    """A qualified integrator agent that reconciles conflicting worker patches
    into one effective wave patch. Invoked ONLY on a deterministic semantic
    conflict; the orchestrator (not the model) applies and validates the result."""

    def __init__(
        self, invoke, agent_profile_id: str, provider_id: str = "", model_id: str = ""
    ) -> None:
        self._invoke = invoke
        self.agent_profile_id = agent_profile_id
        self.provider_id = provider_id
        self.model_id = model_id

    async def integrate(
        self, results: list[PacketResult], conflicts: list[str], patches: dict[str, str]
    ) -> tuple[str, dict[str, Attribution]]:
        import json

        from .models import AgentRequest

        prompt = (
            INTEGRATOR_SYSTEM
            + "\n\nCONFLICTS:\n"
            + json.dumps(conflicts, sort_keys=True)
            + "\n\nWORKER PATCHES (packet_id -> diff):\n"
            + json.dumps({k: v[:8000] for k, v in sorted(patches.items())}, sort_keys=True)
        )
        req = AgentRequest(
            agent_profile_id=self.agent_profile_id,
            packet_id="integration",
            instructions=prompt,
            provider_id=self.provider_id,
            requested_model_id=self.model_id,
        )
        resp = await self._invoke(req)
        effective = resp.output_text or ""
        # Attribution: the integrator rewrote these packets' changes.
        attrs: dict[str, Attribution] = {}
        for r in results:
            wp = patches.get(r.packet_id, "")
            attrs[r.packet_id] = compute_attribution(
                wp,
                effective,
                worker_patch_digest=r.patch_digest,
                reason=f"ai-integrator reconciliation by {self.agent_profile_id}",
            )
        return effective, attrs


def deterministic_preintegrate(
    set_id: str,
    accepted_results: list[PacketResult],
    isolation: RepoIsolation,
    *,
    base_head: str,
    patch_fetch: PatchFetch | None = None,
    apply_patches: bool = False,
    store: Any = None,
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
    # 1) clone + check out the EXACT base commit (populates worktree + index).
    clone = isolation.integration_clone(set_id, base_head)
    co = subprocess.run(
        ["git", "-C", str(clone), "checkout", "--force", base_head],
        capture_output=True,
        text=True,
    )
    if co.returncode != 0:
        attempt.deterministic_merge_ok = False
        attempt.semantic_conflicts.append(
            f"could not checkout base {base_head[:12]}: {co.stderr.strip()[:120]}"
        )
        return attempt, None

    # 2) apply each worker patch into the index in a deterministic order.
    applied: list[PacketResult] = []
    for r in sorted(with_patches, key=lambda x: x.packet_id):
        patch = patch_fetch(r) if patch_fetch else ""
        if not (_git_apply_check(clone, patch) and _git_apply_index(clone, patch)):
            attempt.deterministic_merge_ok = False
            attempt.semantic_conflicts.append(f"patch for {r.packet_id} failed to apply")
            return attempt, None
        applied.append(r)
        attempt.attributions[r.packet_id] = compute_attribution(
            patch, patch, worker_patch_digest=r.patch_digest, reason="applied cleanly"
        )

    # 3) derive the ACTUAL combined diff + changed paths from git (not the model).
    diff = subprocess.run(
        ["git", "-C", str(clone), "diff", "--cached", base_head], capture_output=True, text=True
    ).stdout
    names = subprocess.run(
        ["git", "-C", str(clone), "diff", "--cached", "--name-only", base_head],
        capture_output=True,
        text=True,
    ).stdout
    changed_paths = sorted(p for p in names.splitlines() if p.strip())
    patch_ref = store.cas_put_text(diff) if store is not None else None
    wave = WavePatch(
        set_id=set_id,
        patch_digest=content_digest({"diff": diff}),
        patch_ref=patch_ref,
        changed_paths=changed_paths,
        semantic_subjects=sorted({s for r in applied for s in r.semantic_subjects_changed}),
    )
    return attempt, wave
