"""Delivery handshake back into usf-graph (review P1-22).

Defines the single protected coordinator path that would carry an accepted,
validated wave patch toward the USF repository:

    validated wave patch
    -> factory-owned branch in the usf-graph remote
    -> draft PR -> CI -> human/trusted review -> merge
    -> authorized USF publication -> post-publication digest reconciliation

This module only PREPARES the artifact (branch name, PR title/body, wave-patch
reference). It performs no push, merge, or publication. Those require the
``push_pr`` / ``main_integration`` / ``stardog_publication`` gates, which are
disabled by default. Workers never receive a GitHub write token; only the
integration coordinator would, at the protected-action step (not implemented in
this runtime). Direct writes to /usf remain prohibited.
"""

from __future__ import annotations

from .canonical import short_digest
from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import ProtectedAction
from .models import DeliveryArtifact, SemanticSnapshot, ValidationReceipt, WavePatch


def prepare_delivery(
    ctx: RuntimeContext,
    wave: WavePatch,
    snapshot: SemanticSnapshot,
    validation: ValidationReceipt,
) -> DeliveryArtifact:
    """Prepare (never push) a delivery artifact for an accepted wave.

    Fails closed: unless the push_pr gate is enabled AND deterministic validation
    passed, returns an unprepared artifact with a reason.
    """
    if not validation.all_passed:
        return DeliveryArtifact(
            set_id=wave.set_id,
            prepared=False,
            gate_enabled=ctx.is_gate_enabled(ProtectedAction.PUSH_PR),
            reason="deterministic validation did not pass; delivery withheld",
            prepared_at=utc_now_iso(),
        )
    if not ctx.is_gate_enabled(ProtectedAction.PUSH_PR):
        return DeliveryArtifact(
            set_id=wave.set_id,
            prepared=False,
            gate_enabled=False,
            reason="push_pr gate disabled by default; delivery is prepare-only",
            prepared_at=utc_now_iso(),
        )

    branch = f"usf-factory/wave-{short_digest(wave.patch_digest)}"
    title = f"USF factory wave {short_digest(wave.set_id, 8)}"
    body = (
        f"Automated wave patch prepared by usf-factory.\n\n"
        f"- authority digest: `{snapshot.authority_digest}`\n"
        f"- base commit: `{snapshot.repository_head}`\n"
        f"- changed paths: {wave.changed_paths}\n"
        f"- semantic subjects: {wave.semantic_subjects}\n"
        f"- validation gates: {sorted(k for k, v in validation.gates.items() if v)}\n\n"
        f"This PR must pass CI and independent human/trusted review before merge. "
        f"USF semantic publication happens only through the authorized USF "
        f"publication process, with post-publication digest reconciliation."
    )
    return DeliveryArtifact(
        set_id=wave.set_id,
        prepared=True,
        gate_enabled=True,
        branch=branch,
        pr_title=title,
        pr_body=body,
        wave_patch_ref=wave.patch_ref,
        reason="prepared (not pushed); push/merge/publish require further gated steps",
        prepared_at=utc_now_iso(),
    )
