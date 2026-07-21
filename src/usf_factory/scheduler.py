"""Deterministic scheduler (DESIGN Phase 8 / build task §13).

Hard eligibility is applied first; survivors are ranked by a task- and
role-specific weighted score. Selection uses a controlled exploration policy
(85/10/5 by default) driven by a SEEDED RNG derived from the packet + snapshot,
so routing is fully replayable. Exploration is disabled for high/protected risk.

There is no single universal model score — every score is (agent, task_class,
dimension)-segmented.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .config import EgressPolicy, RoutingConfig
from .enums import (
    AdmissionRole,
    HealthStatus,
    PrivacyClass,
    Risk,
)
from .models import AgentProfile, Packet, RoutingCandidate, RoutingDecision

# Map required-capability fields to score dimensions.
_CAP_TO_DIM = {
    "semantic_reasoning": "semantic_planning",
    "rdf_owl": "rdf_owl_reasoning",
    "shacl_sparql": "shacl_sparql",
    "structured_output": "structured_output",
}

_HEALTH_OK = {HealthStatus.HEALTHY, HealthStatus.DEGRADED}


@dataclass
class SchedulableAgent:
    profile: AgentProfile
    provider_id: str
    admission_roles: list[AdmissionRole]
    task_scores: dict[str, float]  # dimension -> score for this task class
    health: HealthStatus = HealthStatus.HEALTHY
    privacy_class: PrivacyClass = PrivacyClass.EXTERNAL_CLOUD
    context_tokens: int | None = None
    tools: list[str] = field(default_factory=lambda: ["*"])
    quota_ok: bool = True
    circuit_open: bool = False
    latency_ms: float = 1000.0
    cost_usd: float = 0.0

    @property
    def profile_id(self) -> str:
        return self.profile.profile_id

    def supports(self, tool: str) -> bool:
        return "*" in self.tools or tool in self.tools

    def has_role(self, role: AdmissionRole) -> bool:
        """Roles are ORTHOGONAL capabilities, not a linear hierarchy. A profile
        must be admitted to the exact role required. The sole exception is
        READ_ONLY_ANALYST (pure reading), which any admitted role implies —
        holding a write/specialist role never grants a *different* one."""
        if role in self.admission_roles:
            return True
        if role is AdmissionRole.READ_ONLY_ANALYST:
            return any(r is not AdmissionRole.UNQUALIFIED for r in self.admission_roles)
        return False


class Scheduler:
    def __init__(
        self,
        routing: RoutingConfig,
        egress: EgressPolicy,
        *,
        protected_allowed: bool = False,
    ) -> None:
        self.routing = routing
        self.egress = egress
        self.protected_allowed = protected_allowed

    # ---- hard eligibility ----------------------------------------------- #

    def _eligibility(
        self, agent: SchedulableAgent, packet: Packet, role: AdmissionRole
    ) -> list[str]:
        reasons: list[str] = []

        if not agent.has_role(role):
            reasons.append(f"lacks role {role.value}")

        for tool in packet.permitted_tools:
            if not agent.supports(tool):
                reasons.append(f"missing tool {tool}")
                break

        caps = packet.required_capabilities
        if agent.context_tokens is not None and agent.context_tokens < caps.min_context_tokens:
            reasons.append("insufficient context window")

        # Data-egress policy.
        if not self.egress.is_allowed(packet.data_classification, agent.privacy_class.value):
            reasons.append(
                f"egress not allowed: {packet.data_classification} -> {agent.privacy_class.value}"
            )
        if (
            packet.data_classification == "private-source"
            and agent.privacy_class is not PrivacyClass.LOCAL_ONLY
            and not self.egress.source_egress_enabled
        ):
            reasons.append("source egress disabled")

        if agent.health not in _HEALTH_OK:
            reasons.append(f"health {agent.health.value}")
        if not agent.quota_ok:
            reasons.append("quota exhausted")
        if agent.circuit_open:
            reasons.append("circuit breaker open")

        # Task-class minimum capability scores.
        for cap_field, dim in _CAP_TO_DIM.items():
            threshold = float(getattr(caps, cap_field))
            if threshold > 0 and agent.task_scores.get(dim, 0.0) < threshold:
                reasons.append(f"{dim} below {threshold}")

        # Risk permission.
        if packet.risk is Risk.PROTECTED and not self.protected_allowed:
            reasons.append("protected risk requires an enabled gate")
        if packet.risk is Risk.HIGH and not agent.has_role(AdmissionRole.INTEGRATOR):
            reasons.append("high risk requires INTEGRATOR-tier trust")

        return reasons

    # ---- ranking -------------------------------------------------------- #

    def _rank(self, agent: SchedulableAgent, packet: Packet) -> tuple[float, dict[str, float]]:
        w = self.routing.weights
        dims = packet.required_capabilities
        primary = [_CAP_TO_DIM[c] for c in _CAP_TO_DIM if float(getattr(dims, c)) > 0]
        tc_success = (
            sum(agent.task_scores.get(d, 0.0) for d in primary) / len(primary)
            if primary
            else agent.task_scores.get("structured_output", 0.5)
        )
        expected_success = tc_success  # deterministic proxy from qualification
        # Normalize latency/cost into [0,1]-ish penalties.
        latency_norm = min(agent.latency_ms / 10000.0, 1.0)
        cost_norm = min(agent.cost_usd / 1.0, 1.0)
        quota_risk = 0.0 if agent.quota_ok else 1.0

        breakdown = {
            "expected_success": w.get("expected_success", 0.0) * expected_success,
            "task_class_success": w.get("task_class_success", 0.0) * tc_success,
            "tool_reliability": w.get("tool_reliability", 0.0)
            * agent.task_scores.get("tool_selection", 0.5),
            "scope_discipline": w.get("scope_discipline", 0.0)
            * agent.task_scores.get("scope_discipline", 0.5),
            "evidence_discipline": w.get("evidence_discipline", 0.0)
            * agent.task_scores.get("evidence_discipline", 0.5),
            "latency": w.get("latency", 0.0) * latency_norm,
            "cost": w.get("cost", 0.0) * cost_norm,
            "quota_risk": w.get("quota_risk", 0.0) * quota_risk,
        }
        return sum(breakdown.values()), breakdown

    # ---- deterministic exploration -------------------------------------- #

    def _draw(self, packet: Packet) -> float:
        seed = f"{self.routing.default_seed}|{packet.snapshot_id}|{packet.packet_id}"
        h = hashlib.sha256(seed.encode("utf-8")).digest()
        return int.from_bytes(h[:8], "big") / 2**64

    def _exploration_enabled(self, packet: Packet) -> bool:
        return packet.risk not in self.routing.disable_exploration_for_risk

    # ---- top-level schedule --------------------------------------------- #

    def schedule(
        self, packet: Packet, role: AdmissionRole, candidates: list[SchedulableAgent]
    ) -> RoutingDecision:
        rcs: list[RoutingCandidate] = []
        eligible: list[tuple[SchedulableAgent, float]] = []
        for agent in sorted(candidates, key=lambda a: a.profile_id):
            reasons = self._eligibility(agent, packet, role)
            if reasons:
                rcs.append(
                    RoutingCandidate(
                        agent_profile_id=agent.profile_id, eligible=False, exclusion_reasons=reasons
                    )
                )
                continue
            score, breakdown = self._rank(agent, packet)
            rcs.append(
                RoutingCandidate(
                    agent_profile_id=agent.profile_id,
                    eligible=True,
                    score=round(score, 6),
                    score_breakdown={k: round(v, 6) for k, v in breakdown.items()},
                )
            )
            eligible.append((agent, score))

        # Deterministic tie-break: score desc, then profile_id asc.
        eligible.sort(key=lambda t: (-t[1], t[0].profile_id))

        selection_kind = "none"
        selected_id: str | None = None
        seed = f"{self.routing.default_seed}|{packet.snapshot_id}|{packet.packet_id}"

        if eligible:
            draw = self._draw(packet)
            if (
                not self._exploration_enabled(packet)
                or draw < self.routing.exploit_pct
                or len(eligible) == 1
            ):
                selected_id, selection_kind = eligible[0][0].profile_id, "exploit"
            elif draw < self.routing.exploit_pct + self.routing.second_tier_pct:
                idx = 1 if len(eligible) > 1 else 0
                selected_id, selection_kind = eligible[idx][0].profile_id, "second_tier"
            else:
                idx = len(eligible) - 1  # controlled exploration: the tail candidate
                selected_id, selection_kind = eligible[idx][0].profile_id, "explore"

        return RoutingDecision(
            packet_id=packet.packet_id,
            task_class=packet.task_class,
            role=role,
            selected_profile_id=selected_id,
            selection_kind=selection_kind,
            candidates=rcs,
            seed=seed,
        )
