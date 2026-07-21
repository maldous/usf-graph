"""Deterministic packet-result qualification (DESIGN Phase 10 / build task §15).

Every worker result is validated deterministically before it can be integrated.
Failures are classified (not merely marked failed) so learning stays fair.
Uncertain mutations are never auto-retried.
"""

from __future__ import annotations

from collections.abc import Callable

from .enums import FailureClass, PacketResultStatus
from .models import Packet, PacketResult, ResultQualification
from .sandbox import assert_no_usf_paths, scan_secrets

ApplyCheck = Callable[[str], bool]  # given patch text -> applies cleanly?


def qualify_result(
    packet: Packet,
    result: PacketResult,
    *,
    current_head: str | None = None,
    patch_text: str | None = None,
    apply_check: ApplyCheck | None = None,
) -> ResultQualification:
    """Deterministically qualify a packet result."""
    checks: dict[str, bool] = {}
    reasons: list[str] = []
    failure: FailureClass | None = result.failure_class

    # Identity of the worker's provider/model must be present.
    checks["identity_present"] = bool(result.agent_profile_id)
    if not result.agent_profile_id:
        reasons.append("missing agent identity")

    # Base snapshot / commit must match the packet.
    checks["snapshot_match"] = result.snapshot_id == packet.snapshot_id
    if not checks["snapshot_match"]:
        reasons.append("snapshot mismatch")

    checks["base_commit_match"] = result.base_head == packet.base_head
    if not checks["base_commit_match"]:
        reasons.append("base commit mismatch")

    # Staleness: the packet base must still be current.
    if current_head is not None:
        fresh = packet.base_head == current_head
        checks["snapshot_fresh"] = fresh
        if not fresh:
            reasons.append("packet is stale (base head changed)")
            failure = FailureClass.STALE_PACKET

    # Path scope.
    changed = set(result.changed_paths)
    allowed = set(packet.write_paths)
    out_of_scope = sorted(changed - allowed)
    checks["paths_in_scope"] = not out_of_scope
    if out_of_scope:
        reasons.append(f"paths out of scope: {out_of_scope}")
        failure = FailureClass.SCOPE_VIOLATION

    # No /usf writes ever.
    usf_paths = assert_no_usf_paths(result.changed_paths)
    checks["no_usf_write"] = not usf_paths
    if usf_paths:
        reasons.append(f"attempted /usf write: {usf_paths}")
        failure = FailureClass.SCOPE_VIOLATION

    # Semantic subjects claimed must be within packet subjects.
    subj_out = sorted(set(result.semantic_subjects_changed) - set(packet.semantic_subjects))
    checks["semantic_subjects_in_scope"] = not subj_out
    if subj_out:
        reasons.append(f"semantic subjects out of scope: {subj_out}")
        failure = failure or FailureClass.SCOPE_VIOLATION

    # Secret leakage.
    if patch_text:
        leaks = scan_secrets(patch_text)
        checks["no_secret_leak"] = not leaks
        if leaks:
            reasons.append("secret leakage detected in patch")
            failure = FailureClass.SCOPE_VIOLATION

    # Explicit scope-violation flag from the worker layer.
    if result.scope_violation:
        checks["worker_scope_flag"] = False
        failure = failure or FailureClass.SCOPE_VIOLATION

    # Patch applicability.
    if patch_text and apply_check is not None:
        applies = apply_check(patch_text)
        checks["patch_applies"] = applies
        if not applies:
            reasons.append("patch does not apply cleanly")
            failure = failure or FailureClass.WORKER_ERROR

    # Uncertain mutation: never auto-retry.
    if (
        result.status == PacketResultStatus.FAILED
        and result.failure_class == FailureClass.UNCERTAIN_MUTATION
    ):
        failure = FailureClass.UNCERTAIN_MUTATION
        reasons.append("uncertain mutation — not retried automatically")

    # A worker-reported failure passes through its class.
    if result.status == PacketResultStatus.FAILED and failure is None:
        failure = result.failure_class or FailureClass.WORKER_ERROR

    # Human decision required is not a failure — it is a distinct outcome.
    if result.status == PacketResultStatus.HUMAN_DECISION_REQUIRED:
        return ResultQualification(
            packet_id=packet.packet_id,
            accepted=False,
            checks=checks,
            failure_class=None,
            reasons=["human decision required"],
        )

    # A SKIPPED (dry-run) result is not accepted for integration, but is not a
    # failure either.
    if result.status == PacketResultStatus.SKIPPED:
        return ResultQualification(
            packet_id=packet.packet_id,
            accepted=False,
            checks=checks,
            failure_class=None,
            reasons=["skipped (dry-run / non-mutating)"],
        )

    accepted = (
        result.status == PacketResultStatus.COMPLETED and failure is None and all(checks.values())
    )
    return ResultQualification(
        packet_id=packet.packet_id,
        accepted=accepted,
        checks=checks,
        failure_class=None if accepted else failure,
        reasons=reasons,
    )
