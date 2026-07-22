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

# Strict schema the AI planner must satisfy (unknown fields rejected).
OBLIGATION_GRAPH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "obligations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "root_cause": {"type": "string"},
                    "task_class": {"type": "string"},
                    "risk": {"type": "string"},
                    "semantic_subjects": {"type": "array", "items": {"type": "string"}},
                    "dependencies": {"type": "array", "items": {"type": "string"}},
                    "acceptance_criteria": {"type": "array", "items": {"type": "string"}},
                    "required_outcomes": {"type": "array", "items": {"type": "string"}},
                    "human_decision_required": {"type": "boolean"},
                    "suggested_read_scope": {"type": "array", "items": {"type": "string"}},
                    "suggested_write_scope": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["id", "root_cause", "task_class"],
            },
        }
    },
    "required": ["obligations"],
}


class AiPlanner:
    """Wraps a qualified agent adapter to produce an obligation graph."""

    def __init__(
        self,
        invoke,
        agent_profile_id: str,
        schema: dict[str, Any],
        provider_id: str = "",
        model_id: str = "",
        adapter_id: str = "",
    ) -> None:
        self._invoke = invoke  # async callable(AgentRequest)->AgentResponse
        self.agent_profile_id = agent_profile_id
        self.schema = schema
        self.provider_id = provider_id
        self.model_id = model_id
        self.adapter_id = adapter_id

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
            provider_id=self.provider_id,
            requested_model_id=self.model_id,
            adapter_id=self.adapter_id,
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
# AI plan OPTIMIZER (bounded; never a generator).
# --------------------------------------------------------------------------- #

# Optimizer output schema: the obligation array plus an optional deletions list
# (each deletion must carry a reason). Unknown fields rejected.
PLAN_OPTIMIZER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "obligations": OBLIGATION_GRAPH_SCHEMA["properties"]["obligations"],
        "deletions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "reason": {"type": "string"}},
                "required": ["id", "reason"],
            },
        },
    },
    "required": ["obligations"],
}


def _optimizer_system(task_classes: list[str]) -> str:
    from .provider_eval import RULE_BUNDLE

    return (
        RULE_BUNDLE + "\n"
        "You are a USF plan OPTIMIZER, NOT a generator. You are given a FIXED set of "
        "authoritative obligations compiled deterministically from the semantic "
        "authority. Return ONLY one JSON object matching the schema.\n"
        "You MAY: rank the obligations by actionability (order the array), consolidate "
        "duplicate root causes, improve acceptance_criteria, identify dependencies "
        "(referencing only supplied ids), and mark uncertainty or human_decision_required.\n"
        "You MUST NOT: invent an obligation whose id is not in the supplied set; alter "
        "any id or semantic_subjects or task_class; broaden scope (never add write "
        "scope); or return an empty obligations list while actionable obligations exist. "
        "To drop an obligation, list it in 'deletions' as {id, reason} — never silently.\n"
        "Permitted task classes: " + ", ".join(sorted(task_classes)) + "."
    )


class AiPlanOptimizer:
    """Optimizes (ranks/consolidates/annotates) a deterministic authoritative
    obligation graph. It can never create authority obligations, alter their ids/
    subjects/task_class/scope, or empty an actionable graph; on any failure the
    caller keeps the deterministic graph."""

    def __init__(
        self,
        invoke,
        agent_profile_id: str,
        *,
        task_classes: list[str] | None = None,
        provider_id: str = "",
        model_id: str = "",
        adapter_id: str = "",
    ) -> None:
        self._invoke = invoke
        self.agent_profile_id = agent_profile_id
        self._task_classes = task_classes or []
        self.provider_id = provider_id
        self.model_id = model_id
        self.adapter_id = adapter_id

    async def optimize(self, authoritative: ObligationGraph) -> ObligationGraph:
        """Return an optimized graph, or the authoritative graph unchanged if the
        model fails, invents, empties, or is otherwise non-conforming."""
        import json

        from .models import AgentRequest

        base = {o.id: o for o in authoritative.obligations}
        if not base:
            return authoritative
        projection = [
            {
                "id": o.id,
                "root_cause": o.root_cause,
                "task_class": o.task_class,
                "semantic_subjects": o.semantic_subjects,
                "dependencies": o.dependencies,
                "acceptance_criteria": o.acceptance_criteria,
                "risk": o.risk.value if hasattr(o.risk, "value") else str(o.risk),
            }
            for o in authoritative.obligations
        ]
        prompt = (
            _optimizer_system(self._task_classes)
            + "\n\nAUTHORITATIVE OBLIGATIONS:\n"
            + json.dumps({"obligations": projection}, sort_keys=True)
            + "\n\nReturn ONLY the optimized JSON object."
        )
        req = AgentRequest(
            agent_profile_id=self.agent_profile_id,
            packet_id="plan-optimize",
            instructions=prompt,
            provider_id=self.provider_id,
            requested_model_id=self.model_id,
            adapter_id=self.adapter_id,
            result_schema=PLAN_OPTIMIZER_SCHEMA,
        )
        try:
            resp = await self._invoke(req)
            data = json.loads(resp.output_text)
            if not isinstance(data, dict):
                return authoritative
        except Exception:
            return authoritative  # fail-open to the deterministic graph

        findings = list(authoritative.critic_findings)
        # Recorded deletions (id must be authoritative AND carry a reason).
        deleted: set[str] = set()
        for d in data.get("deletions") or []:
            if isinstance(d, dict) and d.get("id") in base and str(d.get("reason") or "").strip():
                deleted.add(str(d["id"]))
                findings.append(f"optimizer dropped {d['id']}: {str(d['reason'])[:120]}")

        merged: list[Obligation] = []
        seen: set[str] = set()
        allowed_ids = set(base)
        for item in data.get("obligations") or []:
            if not isinstance(item, dict):
                continue
            oid = str(item.get("id") or "")
            if oid not in base:
                findings.append(f"optimizer invented obligation {oid!r} — ignored")
                continue
            if oid in seen or oid in deleted:
                continue
            seen.add(oid)
            src = base[oid]
            # Preserve authority-owned fields EXACTLY; accept only improvements.
            deps = [str(x) for x in (item.get("dependencies") or []) if str(x) in allowed_ids]
            acc = [
                str(c) for c in (item.get("acceptance_criteria") or [])
            ] or src.acceptance_criteria
            unc = list(dict.fromkeys([*src.uncertainties, *(item.get("uncertainties") or [])]))
            merged.append(
                src.model_copy(
                    update={
                        "root_cause": str(item.get("root_cause") or src.root_cause),
                        "acceptance_criteria": acc,
                        "dependencies": deps or src.dependencies,
                        "uncertainties": [str(u) for u in unc],
                        # never clear a human-decision flag; allow raising it.
                        "human_decision_required": bool(item.get("human_decision_required"))
                        or src.human_decision_required,
                    }
                )
            )
        # Never lose an authoritative obligation that was neither ranked nor validly deleted.
        for oid, src in base.items():
            if oid not in seen and oid not in deleted:
                merged.append(src)
        # Never empty an actionable graph.
        if not merged:
            return authoritative
        return ObligationGraph(
            snapshot_id=authoritative.snapshot_id,
            obligations=merged,
            planner_profile_id=authoritative.planner_profile_id,
            critic_profile_id=self.agent_profile_id,
            critic_findings=findings,
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


# --------------------------------------------------------------------------- #
# Independent AI planner critic (DESIGN Phase 5): a SECOND model, from a
# different provider/family where possible, reviews the proposed plan for
# over-reach, hidden coupling, and unwarranted scope. Advisory + a verdict.
# --------------------------------------------------------------------------- #

PLANNER_CRITIC_SYSTEM = (
    "You are an INDEPENDENT critic of a proposed USF obligation graph. You did "
    "not write it. Judge only whether the plan is safe and well-formed: no "
    "requirement broadening beyond the snapshot, no hidden coupling between "
    "independent obligations, human decisions flagged, acceptance criteria "
    "present, risk classification plausible. Return ONLY JSON "
    '{"approved": bool, "findings": [string], "risk_flags": [string]}. '
    "Withhold approval if anything looks unwarranted."
)


class DeterministicCriticAdapter:
    """Wraps DeterministicCritic as an independent-critic-shaped verdict, used
    when no second model is available (findings are advisory, approval is granted
    only when the deterministic critic finds no structural defect)."""

    def __init__(self) -> None:
        self._c = DeterministicCritic()

    async def review_plan(
        self, graph: ObligationGraph, projection: dict[str, Any]
    ) -> dict[str, Any]:
        findings = self._c.critique(graph)
        return {
            "approved": not findings,
            "findings": findings,
            "risk_flags": [],
            "reviewer": "deterministic",
        }


class AiPlannerCritic:
    """A qualified reviewer agent (ideally a different provider/family than the
    planner) that judges the proposed plan and returns a verdict."""

    def __init__(
        self, invoke, agent_profile_id: str, provider_id: str = "", model_id: str = ""
    ) -> None:
        self._invoke = invoke
        self.agent_profile_id = agent_profile_id
        self.provider_id = provider_id
        self.model_id = model_id

    async def review_plan(
        self, graph: ObligationGraph, projection: dict[str, Any]
    ) -> dict[str, Any]:
        import json

        from .models import AgentRequest

        prompt = (
            PLANNER_CRITIC_SYSTEM
            + "\n\nSNAPSHOT:\n"
            + json.dumps(projection, sort_keys=True)
            + "\n\nPROPOSED GRAPH:\n"
            + json.dumps(graph.model_dump(mode="json").get("obligations", []), sort_keys=True)[
                :8000
            ]
        )
        req = AgentRequest(
            agent_profile_id=self.agent_profile_id,
            packet_id="plan-critique",
            instructions=prompt,
            provider_id=self.provider_id,
            requested_model_id=self.model_id,
        )
        resp = await self._invoke(req)
        try:
            data = json.loads(resp.output_text)
        except (json.JSONDecodeError, TypeError):
            # Fail closed: an unparseable critic withholds approval.
            return {
                "approved": False,
                "findings": ["planner critic output was not valid JSON"],
                "risk_flags": [],
                "reviewer": self.agent_profile_id,
            }
        return {
            "approved": bool(data.get("approved", False)),
            "findings": list(data.get("findings", [])),
            "risk_flags": list(data.get("risk_flags", [])),
            "reviewer": self.agent_profile_id,
        }
