"""Deterministic integrated validation + publication boundary (DESIGN Phase 13).

Deterministic validation is authoritative (AI review is not). Publication to the
USF semantic authority is implemented as an interface + state machine but gated
behind a protected action that is DISABLED by default. Terminal COMPLETE is
computed from GOAL + admitted evidence/proof — never accepted from model prose.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .clock import utc_now_iso
from .context import RuntimeContext
from .enums import ProtectedAction
from .errors import ProtectedActionError
from .models import PublicationReceipt, SemanticSnapshot, ValidationReceipt

# A gate runner returns (passed | None-if-skipped, detail).
GateRunner = Callable[[], "tuple[bool | None, str]"]

# The full set of validation hooks (build task §16). Runners are pluggable.
VALIDATION_GATES = (
    "syntax-parse",
    "shacl",
    "integrity-sparql",
    "negative-fixtures",
    "competency-queries",
    "unit-tests",
    "integration-tests",
    "manifest-check",
    "derived-regen",
    "source-live-drift",
    "proof-readiness",
)


def run_validation(
    set_id: str,
    gate_names: list[str],
    runners: dict[str, GateRunner] | None = None,
) -> ValidationReceipt:
    """Run the requested validation gates deterministically.

    A gate with no runner is recorded as skipped (detail), not as passed. The
    receipt's ``all_passed`` is False if ANY gate that ran failed.
    """
    runners = runners or {}
    gates: dict[str, bool] = {}
    detail: dict[str, str] = {}
    any_failed = False
    any_ran = False
    for name in gate_names:
        runner = runners.get(name)
        if runner is None:
            detail[name] = "skipped: no runner configured"
            continue
        passed, why = runner()
        if passed is None:
            detail[name] = f"skipped: {why}"
            continue
        any_ran = True
        gates[name] = passed
        detail[name] = why
        if not passed:
            any_failed = True
    return ValidationReceipt(
        set_id=set_id,
        gates=gates,
        all_passed=(not any_failed) and (any_ran or not gate_names),
        detail=detail,
        validated_at=utc_now_iso(),
    )


@dataclass
class PublicationStateMachine:
    """Publication lifecycle. All transitions to PUBLISHED are gated + disabled."""

    ctx: RuntimeContext
    state: str = "PREPARED"
    history: list[str] = field(default_factory=lambda: ["PREPARED"])

    def _advance(self, to: str) -> None:
        self.state = to
        self.history.append(to)

    def publish(
        self, set_id: str, authority_digest_before: str | None = None
    ) -> PublicationReceipt:
        """Attempt publication. Fails closed unless the gate is explicitly enabled."""
        gate_enabled = self.ctx.is_gate_enabled(ProtectedAction.STARDOG_PUBLICATION)
        if not gate_enabled:
            self._advance("BLOCKED")
            return PublicationReceipt(
                set_id=set_id,
                published=False,
                gate_enabled=False,
                authority_digest_before=authority_digest_before,
                reason="publication gate disabled by default (safe runtime)",
                receipt_at=utc_now_iso(),
            )
        # Even when enabled, the safe runtime does not implement live mutation;
        # this is where the authorized USF publication transaction would run.
        raise ProtectedActionError(
            "live Stardog publication is not implemented in this runtime; "
            "publication must go through the authorized USF publication process"
        )


def compute_terminal_complete(
    ctx: RuntimeContext, snapshot: SemanticSnapshot
) -> tuple[bool, list[str]]:
    """Compute terminal COMPLETE from GOAL + authority — never from prose.

    Returns (complete, reasons). In the safe runtime this is False unless the
    terminal-completion gate is enabled AND the deterministic conditions hold.
    """
    reasons: list[str] = []
    if not ctx.is_gate_enabled(ProtectedAction.TERMINAL_COMPLETION):
        reasons.append("terminal-completion gate disabled")
        return False, reasons
    if snapshot.unresolved_obligations:
        reasons.append(f"{len(snapshot.unresolved_obligations)} unresolved obligations")
    if not snapshot.health_ok:
        reasons.append("authority health not ok")
    complete = not reasons
    if complete:
        reasons.append("all deterministic completion conditions satisfied")
    return complete, reasons
