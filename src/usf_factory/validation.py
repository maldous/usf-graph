"""Deterministic integrated validation + publication boundary (DESIGN Phase 13).

Deterministic validation is authoritative (AI review is not). Publication to the
USF semantic authority is implemented as an interface + state machine but gated
behind a protected action that is DISABLED by default. Terminal COMPLETE is
computed from GOAL + admitted evidence/proof — never accepted from model prose.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .canonical import content_digest
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

# Gates whose "not applicable" verdict comes from a DETERMINISTIC predicate over
# the changed-file set (e.g. "no .py files changed" for format/lint/type, "no RDF
# files changed" for syntax-parse). Any OTHER required gate that reports
# not-applicable FAILS: a required test or USF gate can never green-skip — a
# repository implementation without a test must add one in scope, prove existing
# coverage, or carry an explicit human-approved waiver.
CONDITIONAL_GATES = frozenset(
    {
        "syntax-parse",
        "shacl",  # real (pyshacl); N/A only when no shape+data changed
        "integrity-sparql",  # real (rdflib); N/A only when no SPARQL changed
        "format",
        "lint",
        "type",
        "secret-scan",
        "repository-cleanliness",
    }
)


def run_validation(
    set_id: str,
    gate_names: list[str],
    runners: dict[str, GateRunner] | None = None,
    *,
    conditional: frozenset[str] | None = None,
    assurance_bindings: dict[str, Any] | None = None,
    max_wall_s: float | None = None,
) -> ValidationReceipt:
    """Run the requested validation gates deterministically.

    A REQUIRED gate with no runner is a FAILURE (never a green skip). A runner
    may return ``None`` to declare a gate not-applicable; that is allowed ONLY
    for ``conditional`` gates (deterministic applicability predicates) — for any
    other required gate a not-applicable verdict is a FAILURE. ``all_passed`` is
    False if any requested gate failed, lacked a runner, or green-skipped; a
    wave with no gates (``gate_names`` empty) is trivially passed.
    """
    runners = runners or {}
    conditional = CONDITIONAL_GATES if conditional is None else conditional
    gates: dict[str, bool] = {}
    detail: dict[str, str] = {}
    any_failed = False
    started = time.monotonic()
    for name in gate_names:
        if max_wall_s is not None and time.monotonic() - started >= max_wall_s:
            gates[name] = False
            detail[name] = "FAIL: integrated validation wall-clock limit exceeded"
            any_failed = True
            continue
        runner = runners.get(name)
        if runner is None:
            gates[name] = False  # required gate with no runner => FAIL closed
            detail[name] = "FAIL: no runner configured for a required gate"
            any_failed = True
            continue
        passed, why = runner()
        if passed is None:
            if name in conditional:
                if assurance_bindings is not None:
                    gates[name] = True
                detail[name] = f"n/a: {why}"  # deterministic applicability predicate
                continue
            gates[name] = False  # required gate may not declare itself n/a
            detail[name] = f"FAIL: required gate reported not-applicable ({why})"
            any_failed = True
            continue
        gates[name] = passed
        detail[name] = why
        if not passed:
            any_failed = True
    bindings = assurance_bindings or {}
    actual_runners = sorted(name for name in gate_names if name in runners)
    runner_inventory = {
        name: (
            f"{getattr(runners[name], '__module__', '')}:"
            f"{getattr(runners[name], '__qualname__', type(runners[name]).__qualname__)}"
        )
        for name in actual_runners
    }
    toolchain_bindings = {
        str(k): str(v) for k, v in dict(bindings.get("toolchain_bindings") or {}).items()
    }
    return ValidationReceipt(
        schema_version=2 if assurance_bindings is not None else 1,
        set_id=set_id,
        gates=gates,
        all_passed=not any_failed,
        detail=detail,
        patch_digest=str(bindings.get("patch_digest") or ""),
        patch_ref=str(bindings.get("patch_ref") or ""),
        integration_tree=str(bindings.get("integration_tree") or ""),
        integration_head=str(bindings.get("integration_head") or ""),
        repository_base_head=str(bindings.get("repository_base_head") or ""),
        authority_digest=str(bindings.get("authority_digest") or ""),
        required_gate_inventory=sorted(set(gate_names)),
        actual_runner_inventory=actual_runners,
        runner_bindings=runner_inventory,
        runner_inventory_digest=content_digest(runner_inventory),
        toolchain_bindings=toolchain_bindings,
        toolchain_inventory_digest=content_digest(toolchain_bindings),
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


def record_terminal_observation(
    ctx: RuntimeContext, cycle_id: str, snapshot: SemanticSnapshot
) -> None:
    """Persist one completed-cycle authority observation.

    The caller invokes this only after the immutable cycle receipt is durable.
    Re-evaluating a cycle therefore cannot manufacture a second observation.
    """
    cycle = ctx.store.get("cycles", cycle_id)
    if cycle is None or cycle.get("state") not in {"LEARNED", "COMPLETE"}:
        return
    zero_gap = (
        snapshot.health_ok
        and snapshot.work_plan_complete
        and snapshot.work_plan_authority_digest == snapshot.authority_digest
        and not snapshot.actionable_gap_identities
        and not snapshot.unresolved_obligations
    )
    ctx.store.put(
        "terminal_stability",
        cycle_id,
        {
            "cycle_id": cycle_id,
            "zero_gap": zero_gap,
            "snapshot_id": snapshot.snapshot_id,
            "authority_digest": snapshot.authority_digest,
            "work_plan_complete": snapshot.work_plan_complete,
        },
    )


def compute_terminal_complete(
    ctx: RuntimeContext, snapshot: SemanticSnapshot, *, require_two_snapshots: bool = True
) -> tuple[bool, list[str]]:
    """Compute terminal COMPLETE from GOAL + authority — never from prose.

    Returns (complete, reasons). Terminal completion requires, deterministically:
    the committed gate enabled, a live RunAuthorization that explicitly permits
    it, a complete digest-stable zero-gap work plan, and two observations from
    distinct previously completed cycles at the same authority digest.
    """
    reasons: list[str] = []
    if not ctx.is_gate_enabled(ProtectedAction.TERMINAL_COMPLETION):
        reasons.append("terminal-completion gate disabled")
        return False, reasons
    if ctx.run_authorization is None or not ctx.is_action_effective(
        ProtectedAction.TERMINAL_COMPLETION
    ):
        reasons.append("live RunAuthorization does not permit terminal completion (or expired)")
        return False, reasons
    if snapshot.unresolved_obligations:
        reasons.append(f"{len(snapshot.unresolved_obligations)} unresolved obligations")
    if not snapshot.health_ok:
        reasons.append("authority health not ok")
    if not snapshot.work_plan_complete:
        reasons.append("complete digest-stable work plan unavailable")
    if snapshot.work_plan_authority_digest != snapshot.authority_digest:
        reasons.append("work-plan authority digest does not match current authority")
    if snapshot.actionable_gap_identities:
        reasons.append(f"{len(snapshot.actionable_gap_identities)} actionable work-plan gaps")

    if require_two_snapshots:
        observations = [
            row
            for _key, row in ctx.store.items("terminal_stability")
            if row.get("authority_digest") == snapshot.authority_digest
            and (ctx.store.get("cycles", str(row.get("cycle_id") or "")) or {}).get("state")
            in {"LEARNED", "COMPLETE"}
        ]
        observations.sort(key=lambda row: str(row.get("cycle_id") or ""))
        latest_by_cycle = {
            str(row.get("cycle_id") or ""): row for row in observations if row.get("cycle_id")
        }
        latest = [latest_by_cycle[key] for key in sorted(latest_by_cycle)[-2:]]
        if len(latest) < 2 or any(
            not row.get("zero_gap") or not row.get("work_plan_complete") for row in latest
        ):
            reasons.append("awaiting zero-gap observations from two distinct completed cycles")

    complete = not reasons
    if complete:
        reasons.append(
            "all deterministic completion conditions satisfied (two distinct completed cycles)"
        )
    return complete, reasons
