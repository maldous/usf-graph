"""Production dynamic-dispatch helpers (spec Part A).

The engine's live execution path selects a transport at the moment of use from the
current :class:`WorkforceSnapshot`, draws adaptively, invokes, and — on a
*transient* availability failure — removes that candidate and redraws, all while
the packet stays claimed. This module holds the pure classification + reporting
helpers that decide redraw-vs-stop; the async invoke/redraw loop lives on
``FactoryEngine`` (it needs workspace/heartbeat/budget/fencing).

Nothing here instantiates or calls the legacy ``Scheduler``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .enums import TRANSIENT_DISPATCH_FAILURES, DispatchFailure, FailureClass, PacketResultStatus

if TYPE_CHECKING:
    from .models import PacketResult, RoutingCandidate
    from .workforce import WorkforceSnapshot

# Worker-attribution FailureClass -> dispatch taxonomy. Availability/transport
# problems map to transient dispatch failures (redraw to another candidate);
# result-quality / safety / possible-side-effect problems map to terminal ones.
_FC_TO_DF: dict[FailureClass, DispatchFailure] = {
    FailureClass.QUOTA_BLOCKED: DispatchFailure.QUOTA_BLOCKED,
    FailureClass.PROVIDER_OUTAGE: DispatchFailure.MODEL_UNAVAILABLE,
    FailureClass.ADAPTER_ERROR: DispatchFailure.TRANSPORT_FAILED,
    FailureClass.ENVIRONMENT_FAILURE: DispatchFailure.MODEL_UNAVAILABLE,
    # Terminal — never a silent redraw:
    FailureClass.WORKER_ERROR: DispatchFailure.SEMANTIC_REJECTED,
    FailureClass.SCOPE_VIOLATION: DispatchFailure.VALIDATION_FAILED,
    FailureClass.VALIDATION_FAILURE: DispatchFailure.VALIDATION_FAILED,
    FailureClass.UNCERTAIN_MUTATION: DispatchFailure.VALIDATION_FAILED,
    FailureClass.STALE_PACKET: DispatchFailure.VALIDATION_FAILED,
    FailureClass.PLANNER_ERROR: DispatchFailure.SEMANTIC_REJECTED,
    FailureClass.PACKET_COMPILER_ERROR: DispatchFailure.SEMANTIC_REJECTED,
}


def classify_attempt(
    result: PacketResult | None, *, timed_out: bool = False, fenced: bool = False
) -> tuple[bool, DispatchFailure | None, bool]:
    """Classify one dispatch attempt.

    Returns ``(ok, dispatch_failure, transient)``:
    * ``ok`` — accepted result; use it and stop.
    * ``fenced`` (coordinator ownership uncertain) — ``(False, None, False)``: stop
      without redraw; this is not a candidate-availability problem.
    * ``timed_out`` — ``TIMEOUT`` (transient): remove candidate + redraw.
    * a failed result — mapped via :data:`_FC_TO_DF`; ``transient`` iff the mapped
      class is in :data:`TRANSIENT_DISPATCH_FAILURES`.
    """
    if fenced:
        return False, None, False
    if timed_out:
        return False, DispatchFailure.TIMEOUT, True
    if result is None:
        return False, None, False
    if result.status is PacketResultStatus.COMPLETED and result.failure_class is None:
        return True, None, False
    fc = result.failure_class
    df = (
        _FC_TO_DF.get(fc, DispatchFailure.SEMANTIC_REJECTED)
        if fc
        else DispatchFailure.SEMANTIC_REJECTED
    )
    return False, df, df in TRANSIENT_DISPATCH_FAILURES


def coverage_report(
    snapshot: WorkforceSnapshot,
    role: str,
    rejected: list[RoutingCandidate],
) -> dict[str, object]:
    """An exact, honest coverage report for a role that could not be filled — used
    when the run path BLOCKS for want of an eligible candidate (spec §10)."""
    return {
        "role": role,
        "snapshot_id": snapshot.snapshot_id,
        "role_coverage": snapshot.coverage.get(role, 0),
        "policy_excluded": list(snapshot.excluded),
        "snapshot_blockers": list(snapshot.blockers),
        "rejected": [
            {
                "profile_id": c.agent_profile_id,
                "provider_id": c.provider_id,
                "reasons": list(c.exclusion_reasons),
            }
            for c in rejected
        ],
    }
