"""Planning stage (DESIGN Phase 5).

The planner receives a COMPACT semantic projection and returns a strict
obligation graph. It never receives provider names, rankings, or availability —
that prevents tailoring packets to favored agents.

Two planner implementations:

* ``FixturePlanner`` — deterministic, zero-cost. Reads a fixture obligation graph
  (or synthesizes a minimal valid one). Used by plan-only / safe cycles.
* ``AiPlanner`` — wraps a qualified agent adapter (billable; gated). Builds the
  prompt from the projection and validates the returned JSON.

An independent ``DeterministicCritic`` reviews the graph (never executes work).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

import yaml

from .clock import utc_now_iso
from .errors import PlanningError
from .models import Obligation, ObligationGraph, SemanticSnapshot


def compact_projection(
    snapshot: SemanticSnapshot, goal_constraints: dict[str, Any] | None = None
) -> dict[str, Any]:
    """The compact projection handed to a planner. Contains NO provider info."""
    return {
        "snapshotId": snapshot.snapshot_id,
        "authorityDigest": snapshot.authority_digest,
        "repositoryHead": snapshot.repository_head,
        "activePhase": snapshot.active_phase,
        "triples": snapshot.triple_count,
        "graphs": snapshot.graph_count,
        "unresolvedObligations": snapshot.unresolved_obligations,
        "admittedEvidence": snapshot.admitted_evidence[:50],
        "goalConstraints": goal_constraints or {},
    }


class Planner(Protocol):
    async def plan(
        self, snapshot: SemanticSnapshot, goal_constraints: dict[str, Any] | None = None
    ) -> ObligationGraph: ...


# --------------------------------------------------------------------------- #
# Deterministic fixture planner (zero-cost, safe).
# --------------------------------------------------------------------------- #


def _load_fixture(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    obs = data.get("obligations", [])
    if not isinstance(obs, list):
        raise PlanningError(f"fixture {path} has no 'obligations' list")
    return obs


class FixturePlanner:
    """Produces an obligation graph deterministically from a fixture."""

    def __init__(self, fixture_path: Path | None = None) -> None:
        self.fixture_path = fixture_path

    async def plan(
        self, snapshot: SemanticSnapshot, goal_constraints: dict[str, Any] | None = None
    ) -> ObligationGraph:
        raw: list[dict[str, Any]]
        if self.fixture_path and self.fixture_path.exists():
            raw = _load_fixture(self.fixture_path)
        else:
            raw = _synthesize(snapshot)
        obligations = [Obligation(**o) for o in raw]
        return ObligationGraph(
            snapshot_id=snapshot.snapshot_id,
            obligations=obligations,
            planner_profile_id="fixture-planner",
            critic_profile_id=None,
            critic_findings=[],
            produced_at=utc_now_iso(),
        )


def _synthesize(snapshot: SemanticSnapshot) -> list[dict[str, Any]]:
    """A minimal, valid graph when no fixture is provided.

    If the snapshot lists unresolved obligations, emit one analysis obligation per
    (bounded); otherwise emit a single read-only analysis obligation. This never
    proposes mutation on its own.
    """
    if snapshot.unresolved_obligations:
        out = []
        for i, oid in enumerate(snapshot.unresolved_obligations[:5]):
            out.append(
                {
                    "id": f"obl-analyze-{i}",
                    "root_cause": f"analyze unresolved obligation {oid}",
                    "semantic_subjects": [oid],
                    "dependencies": [],
                    "required_outcomes": ["bounded analysis of the obligation"],
                    "acceptance_criteria": ["analysis produced; no mutation"],
                    "risk": "low",
                    "task_class": "semantic-planning",
                    "uncertainties": [],
                    "human_decision_required": False,
                }
            )
        return out
    return [
        {
            "id": "obl-analyze-current-state",
            "root_cause": "no unresolved obligations reported; verify current state",
            "semantic_subjects": [],
            "dependencies": [],
            "required_outcomes": ["confirm no actionable semantic gap remains"],
            "acceptance_criteria": ["read-only confirmation; no mutation proposed"],
            "risk": "low",
            "task_class": "semantic-planning",
            "uncertainties": ["authority may change concurrently"],
            "human_decision_required": False,
        }
    ]


# --------------------------------------------------------------------------- #
# AI planner (billable; gated by the caller).
# --------------------------------------------------------------------------- #

PLANNER_SYSTEM = (
    "You are a USF semantic planner. Given a compact snapshot, return ONLY a JSON "
    "object matching the obligation-graph schema. Do not propose provider-specific "
    "work. Prefer root-cause consolidation. Mark human-only decisions explicitly. "
    "Express uncertainty rather than fabricating."
)


class AiPlanner:
    """Wraps a qualified agent adapter to produce an obligation graph."""

    def __init__(self, invoke, agent_profile_id: str, schema: dict[str, Any]) -> None:
        self._invoke = invoke  # async callable(AgentRequest)->AgentResponse
        self.agent_profile_id = agent_profile_id
        self.schema = schema

    async def plan(
        self, snapshot: SemanticSnapshot, goal_constraints: dict[str, Any] | None = None
    ) -> ObligationGraph:
        import json

        from .models import AgentRequest

        projection = compact_projection(snapshot, goal_constraints)
        prompt = (
            PLANNER_SYSTEM
            + "\n\nSNAPSHOT:\n"
            + json.dumps(projection, sort_keys=True)
            + "\n\nReturn ONLY the JSON obligation graph."
        )
        req = AgentRequest(
            agent_profile_id=self.agent_profile_id,
            packet_id="planning",
            instructions=prompt,
            result_schema=self.schema,
        )
        resp = await self._invoke(req)
        try:
            data = json.loads(resp.output_text)
        except (json.JSONDecodeError, TypeError) as exc:
            raise PlanningError(f"planner returned invalid JSON: {exc}") from exc
        obligations = [Obligation(**o) for o in data.get("obligations", [])]
        return ObligationGraph(
            snapshot_id=snapshot.snapshot_id,
            obligations=obligations,
            planner_profile_id=self.agent_profile_id,
            produced_at=utc_now_iso(),
        )


# --------------------------------------------------------------------------- #
# Deterministic planner critic (DESIGN Phase 5).
# --------------------------------------------------------------------------- #


class DeterministicCritic:
    """Reviews an obligation graph for structural defects. Advisory + amends
    (dedup only); never executes work."""

    OVER_FRAGMENTATION = 30

    def critique(self, graph: ObligationGraph) -> list[str]:
        findings: list[str] = []
        ids = [o.id for o in graph.obligations]
        id_set = set(ids)

        # Duplicate ids.
        if len(ids) != len(id_set):
            findings.append("duplicate obligation ids present")

        # Missing dependencies.
        for o in graph.obligations:
            for dep in o.dependencies:
                if dep not in id_set:
                    findings.append(f"obligation {o.id} depends on missing '{dep}'")

        # Over-fragmentation.
        if len(graph.obligations) > self.OVER_FRAGMENTATION:
            findings.append(f"possible over-fragmentation: {len(graph.obligations)} obligations")

        # Duplicate root causes.
        seen_rc: dict[str, str] = {}
        for o in graph.obligations:
            key = o.root_cause.strip().lower()
            if key in seen_rc:
                findings.append(f"duplicate root cause between {seen_rc[key]} and {o.id}")
            else:
                seen_rc[key] = o.id

        # Hidden shared semantic subjects between independent obligations.
        subj_owner: dict[str, str] = {}
        for o in graph.obligations:
            for s in o.semantic_subjects:
                if s in subj_owner and subj_owner[s] != o.id:
                    other = subj_owner[s]
                    if other not in o.dependencies and o.id not in _deps_of(graph, other):
                        findings.append(
                            f"hidden shared semantic subject '{s}' between {other} and {o.id}"
                        )
                else:
                    subj_owner[s] = o.id

        # Human decisions represented as implementation work.
        human_markers = ("legal", "license", "architecture decision", "risk acceptance")
        for o in graph.obligations:
            rc = o.root_cause.lower()
            if any(w in rc for w in human_markers) and not o.human_decision_required:
                findings.append(f"obligation {o.id} looks like a human decision but is not flagged")

        # Missing acceptance criteria.
        for o in graph.obligations:
            if not o.acceptance_criteria:
                findings.append(f"obligation {o.id} has no acceptance criteria")

        return findings

    def amend(self, graph: ObligationGraph) -> ObligationGraph:
        """Remove exact-duplicate obligations (same id)."""
        seen: set[str] = set()
        deduped: list[Obligation] = []
        for o in graph.obligations:
            if o.id in seen:
                continue
            seen.add(o.id)
            deduped.append(o)
        return graph.model_copy(update={"obligations": deduped})


def _deps_of(graph: ObligationGraph, oid: str) -> list[str]:
    for o in graph.obligations:
        if o.id == oid:
            return o.dependencies
    return []
