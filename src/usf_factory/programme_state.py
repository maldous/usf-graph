"""USF programme-state compiler (review P0-1).

Deterministically derives the current obligation set from the live MCP
work-plan/bootstrap CONTENTS (not a fixture, not just digests). This is what a
production cycle plans from; fixtures are used only in tests.

Parsing is defensive across plausible shapes. Obligations produced from live
authority carry NO write scope unless authority provides an explicit
subject->file mapping (that mapping is P0-9 / still planned), so they compile to
read-only analysis packets — never accidental mutation.
"""

from __future__ import annotations

from typing import Any

from .clock import utc_now_iso
from .models import Obligation, ObligationGraph, SemanticSnapshot

MAX_OBLIGATIONS = 100

# Authority work-plan gap `type` -> deterministic task class. A missing validation
# is remediated by authoring a bounded validation (low-risk, repository-editing)
# whose WRITE scope still comes ONLY from a verified materialisation owner — so
# without a verified owner the packet compiles read-only regardless. Unknown gap
# types fall back to read-only semantic-planning (never an accidental mutation).
_GAP_TASK_CLASS = {
    "missing-current-passing-validation": "sparql-authoring",
    "missing-validation": "sparql-authoring",
    "missing-constraint": "sparql-authoring",
    "shacl-violation": "shacl-repair",
    "missing-shape": "shacl-repair",
    "missing-proof": "semantic-planning",
}


def _as_list(value: Any, *keys: str) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for k in keys:
            if isinstance(value.get(k), list):
                return value[k]
    return []


def _obl_id(item: dict[str, Any], index: int) -> str:
    explicit = item.get("id") or item.get("iri") or item.get("obligation")
    if explicit:
        return str(explicit)
    # Work-plan gaps identify by (type, subject); preserve that as provenance.
    typ = item.get("type")
    subj = item.get("subject")
    if typ and subj:
        return f"{typ}:{subj}"
    if subj:
        return str(subj)
    return f"obl-{index}"


def _deps(item: dict[str, Any]) -> list[str]:
    for k in ("dependencies", "dependsOn", "depends_on", "requires", "blockedBy"):
        v = item.get(k)
        if isinstance(v, list):
            return [str(x) for x in v]
    return []


def parse_programme_obligations(bootstrap: dict[str, Any], work_plan: Any) -> list[dict[str, Any]]:
    """Return a bounded, deterministic list of obligation dicts.

    Prefers the (richer) work-plan items; supplements with bootstrap gaps. Output
    is sorted by id for reproducibility.
    """
    out: dict[str, dict[str, Any]] = {}

    raw = _as_list(work_plan, "items", "plan", "workItems", "obligations", "tasks", "gaps")
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        oid = _obl_id(item, i)
        gap_type = str(item.get("type") or "")
        # A gap carries (type, subject); a richer work-plan item may carry
        # subjects[] + taskClass. Preserve the authority subject either way.
        subjects = [str(s) for s in _as_list(item.get("subjects"), "subjects")]
        if not subjects and item.get("subject"):
            subjects = [str(item["subject"])]
        task_class = str(
            item.get("taskClass") or _GAP_TASK_CLASS.get(gap_type, "semantic-planning")
        )
        root_cause = str(
            item.get("rootCause")
            or item.get("title")
            or item.get("description")
            or (f"authority gap '{gap_type}' on {item.get('subject')}" if gap_type else oid)
        )
        out[oid] = {
            "id": oid,
            "root_cause": root_cause,
            "dependencies": _deps(item),
            "semantic_subjects": subjects,
            "task_class": task_class,
            "acceptance_criteria": [
                str(c) for c in _as_list(item.get("acceptanceCriteria"), "acceptanceCriteria")
            ]
            or ["bounded analysis; no mutation without an authorised subject->file mapping"],
            "risk": str(item.get("risk") or "low"),
            "human_decision_required": bool(item.get("humanDecisionRequired", False)),
        }

    # Supplement with bootstrap obligation ids not already present.
    for key in ("openGaps", "proofObligations", "validationObligations"):
        for i, item in enumerate(bootstrap.get(key) or []):
            oid = _obl_id(item, i) if isinstance(item, dict) else str(item)
            if oid in out:
                continue
            out[oid] = {
                "id": oid,
                "root_cause": f"resolve {key} item {oid}",
                "dependencies": _deps(item) if isinstance(item, dict) else [],
                "semantic_subjects": [oid],
                "task_class": "semantic-planning",
                "acceptance_criteria": ["bounded analysis produced; no mutation"],
                "risk": "low",
                "human_decision_required": False,
            }

    ordered = sorted(out.values(), key=lambda o: o["id"])
    return ordered[:MAX_OBLIGATIONS]


class ProgrammePlanner:
    """Planner that builds an obligation graph deterministically from the
    snapshot's programme obligations (compiled from live authority)."""

    def __init__(self) -> None:
        self.planner_profile_id = "programme-state-compiler"

    async def plan(
        self, snapshot: SemanticSnapshot, goal_constraints: dict[str, Any] | None = None
    ) -> ObligationGraph:
        raw = snapshot.programme_obligations
        if raw:
            obligations = [Obligation(**o) for o in raw]
        else:
            # Nothing actionable reported — a single read-only verification
            # obligation (never proposes mutation on its own).
            obligations = [
                Obligation(
                    id="obl-verify-current-state",
                    root_cause="no actionable programme obligations reported; verify current state",
                    required_outcomes=["confirm no unblocked semantic gap remains"],
                    acceptance_criteria=["read-only confirmation; no mutation"],
                    risk="low",
                    task_class="semantic-planning",
                    uncertainties=["authority may change concurrently"],
                )
            ]
        return ObligationGraph(
            snapshot_id=snapshot.snapshot_id,
            obligations=obligations,
            planner_profile_id=self.planner_profile_id,
            produced_at=utc_now_iso(),
        )
