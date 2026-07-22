"""Shared hard-eligibility gate (single source of truth).

The exact per-candidate hard gates (role, tools, context, egress, health, quota,
circuit, task-class capability minimums, risk permission) live here so that BOTH
the legacy deterministic ``Scheduler`` (kept only for compatibility tests and
deterministic migration) and the production DYNAMIC dispatch path apply the
IDENTICAL gates. A hard gate is never weakened by the dynamic path — it reuses
this function rather than re-deriving (or dropping) any rule.

This module contains no selection/ranking logic and never instantiates the
``Scheduler``; importing it does not pull the legacy scheduler into a code path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .enums import AdmissionRole, HealthStatus, PrivacyClass, Risk

if TYPE_CHECKING:
    from .config import EgressPolicy
    from .models import Packet
    from .scheduler import SchedulableAgent

# Map required-capability fields to score dimensions.
_CAP_TO_DIM = {
    "semantic_reasoning": "semantic_planning",
    "rdf_owl": "rdf_owl_reasoning",
    "shacl_sparql": "shacl_sparql",
    "structured_output": "structured_output",
}

_HEALTH_OK = {HealthStatus.HEALTHY, HealthStatus.DEGRADED}


def hard_eligibility(
    agent: SchedulableAgent,
    packet: Packet,
    role: AdmissionRole,
    egress: EgressPolicy,
    *,
    protected_allowed: bool = False,
) -> list[str]:
    """Return the list of hard-gate failure reasons for ``agent`` on ``packet`` in
    ``role`` — empty means eligible. Fail-closed: any unmet gate is a reason."""
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

    # Data-egress policy. A provider may receive the data class if the privacy-class
    # rule allows it OR the provider is explicitly approved (P1-19). Sensitive
    # classes to a non-local provider additionally require the global source-egress
    # gate AND explicit per-provider approval.
    data = packet.data_classification
    pc = agent.privacy_class.value
    class_ok = egress.is_allowed(data, pc)
    provider_ok = egress.provider_approved_for(agent.provider_id, data)
    if not (class_ok or provider_ok):
        reasons.append(f"egress not allowed: {data} -> {pc}")
    if data in ("private-source", "restricted") and agent.privacy_class is not PrivacyClass.LOCAL_ONLY:
        if not egress.source_egress_enabled:
            reasons.append("source egress disabled")
        elif not provider_ok:
            reasons.append(f"provider {agent.provider_id} not approved for {data}")

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
    if packet.risk is Risk.PROTECTED and not protected_allowed:
        reasons.append("protected risk requires an enabled gate")
    if packet.risk is Risk.HIGH and not agent.has_role(AdmissionRole.INTEGRATOR):
        reasons.append("high risk requires INTEGRATOR-tier trust")

    return reasons
