"""Contribution attribution (DESIGN Phase 14 / build task §15, §17).

Maps failures to the responsible stage so a worker is never penalized for a
planner error, stale packet, provider outage, or environment failure. Also
measures the integrator rewrite ratio so a worker does not receive full credit
when the integrator replaces its patch.
"""

from __future__ import annotations

import difflib

from .enums import NON_WORKER_FAULTS, FailureClass
from .models import Attribution

# Which stage owns each failure class.
FAILURE_STAGE: dict[FailureClass, str] = {
    FailureClass.PLANNER_ERROR: "planner",
    FailureClass.PACKET_COMPILER_ERROR: "packet_compiler",
    FailureClass.WORKER_ERROR: "worker",
    FailureClass.ADAPTER_ERROR: "adapter",
    FailureClass.PROVIDER_OUTAGE: "provider",
    FailureClass.QUOTA_BLOCKED: "provider",
    FailureClass.STALE_PACKET: "scheduler",
    FailureClass.SCOPE_VIOLATION: "worker",
    FailureClass.VALIDATION_FAILURE: "worker",
    FailureClass.ENVIRONMENT_FAILURE: "environment",
    FailureClass.UNCERTAIN_MUTATION: "environment",
}


def stage_for_failure(failure: FailureClass) -> str:
    return FAILURE_STAGE.get(failure, "unknown")


def is_worker_fault(failure: FailureClass) -> bool:
    """True only when the worker is genuinely responsible."""
    return failure not in NON_WORKER_FAULTS


def integrator_rewrite_ratio(worker_patch: str, final_patch: str) -> float:
    """Fraction of the worker's patch NOT preserved in the final wave patch.

    0.0 => the worker's patch survived intact; 1.0 => fully rewritten.
    """
    if not worker_patch:
        return 1.0 if final_patch else 0.0
    matcher = difflib.SequenceMatcher(a=worker_patch.splitlines(), b=final_patch.splitlines())
    ratio_preserved = matcher.ratio()
    return round(max(0.0, min(1.0, 1.0 - ratio_preserved)), 4)


def compute_attribution(
    worker_patch: str, final_patch: str, *, worker_patch_digest: str | None = None, reason: str = ""
) -> Attribution:
    """Line-level attribution between a worker patch and the final wave patch."""
    w_lines = worker_patch.splitlines()
    f_lines = final_patch.splitlines()
    matcher = difflib.SequenceMatcher(a=w_lines, b=f_lines)
    preserved = 0
    for tag, i1, i2, _j1, _j2 in matcher.get_opcodes():
        if tag == "equal":
            preserved += i2 - i1
    modified = max(0, len(f_lines) - preserved)
    discarded = max(0, len(w_lines) - preserved)
    return Attribution(
        worker_patch_digest=worker_patch_digest,
        lines_preserved=preserved,
        lines_modified_by_integrator=modified,
        lines_discarded=discarded,
        integrator_rewrite_ratio=integrator_rewrite_ratio(worker_patch, final_patch),
        reason=reason,
    )
