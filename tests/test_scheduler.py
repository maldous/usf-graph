"""Scheduler eligibility, ranking, deterministic exploration, egress gating."""

from __future__ import annotations

import pytest

from usf_factory.config import load_config
from usf_factory.enums import AdmissionRole, AuthMode, HealthStatus, PrivacyClass, Risk
from usf_factory.models import AgentProfile, Packet, RequiredCapabilities
from usf_factory.scheduler import SchedulableAgent, Scheduler


def _agent(
    pid, roles, scores, privacy=PrivacyClass.EXTERNAL_CLOUD, health=HealthStatus.HEALTHY, tools=None
):
    profile = AgentProfile(
        provider_id=pid,
        requested_model_id="m",
        adapter="openai_compatible",
        auth_mode=AuthMode.API_TOKEN,
    )
    return SchedulableAgent(
        profile=profile,
        provider_id=pid,
        admission_roles=roles,
        task_scores=scores,
        health=health,
        privacy_class=privacy,
        context_tokens=128000,
        tools=tools or ["*"],
    )


def _packet(risk=Risk.MEDIUM, data="private-metadata", write=None):
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="repository-implementation",
        risk=risk,
        data_classification=data,
        write_paths=write or [],
        permitted_tools=["read_file"],
        required_capabilities=RequiredCapabilities(
            structured_output=0.8, repository_editing=bool(write)
        ),
    )


def _sched(**kw):
    cfg = load_config()
    return Scheduler(cfg.routing, cfg.egress, **kw)


@pytest.mark.unit
def test_ineligible_when_role_missing():
    s = _sched()
    a = _agent("p", [AdmissionRole.READ_ONLY_ANALYST], {"structured_output": 0.9})
    d = s.schedule(_packet(write=["a.py"]), AdmissionRole.PATCH_PRODUCER, [a])
    assert d.selected_profile_id is None
    assert any("lacks role" in r for c in d.candidates for r in c.exclusion_reasons)


@pytest.mark.unit
def test_source_egress_disabled_blocks_external():
    s = _sched()
    a = _agent(
        "ext", [AdmissionRole.PATCH_PRODUCER], {"structured_output": 0.9, "implementation": 0.9}
    )
    d = s.schedule(
        _packet(data="private-source", write=["a.py"]), AdmissionRole.PATCH_PRODUCER, [a]
    )
    assert d.selected_profile_id is None
    reasons = [r for c in d.candidates for r in c.exclusion_reasons]
    assert any("egress" in r or "source egress" in r for r in reasons)


@pytest.mark.unit
def test_local_provider_allowed_for_private_source():
    s = _sched()
    a = _agent(
        "ollama",
        [AdmissionRole.PATCH_PRODUCER],
        {"structured_output": 0.9, "implementation": 0.9},
        privacy=PrivacyClass.LOCAL_ONLY,
    )
    d = s.schedule(
        _packet(data="private-source", write=["a.py"]), AdmissionRole.PATCH_PRODUCER, [a]
    )
    assert d.selected_profile_id == a.profile_id


@pytest.mark.unit
def test_ranking_prefers_higher_scores():
    # Ranking is independent of exploration: the higher-scored agent must rank
    # higher (selection may still explore, which is tested separately).
    s = _sched()
    good = _agent(
        "good",
        [AdmissionRole.PATCH_PRODUCER],
        {"structured_output": 0.95, "implementation": 0.95, "scope_discipline": 0.95},
    )
    weak = _agent(
        "weak",
        [AdmissionRole.PATCH_PRODUCER],
        {"structured_output": 0.8, "implementation": 0.6, "scope_discipline": 0.6},
    )
    d = s.schedule(_packet(write=["a.py"]), AdmissionRole.PATCH_PRODUCER, [good, weak])
    scores = {c.agent_profile_id: c.score for c in d.candidates if c.eligible}
    assert scores[good.profile_id] > scores[weak.profile_id]
    assert d.selected_profile_id is not None  # someone eligible was selected


@pytest.mark.unit
def test_high_risk_always_exploits_top_ranked():
    s = _sched()
    # High-risk PATCH_PRODUCER work needs both the PATCH_PRODUCER role and
    # INTEGRATOR-tier trust (roles are orthogonal, not a hierarchy).
    roles = [AdmissionRole.PATCH_PRODUCER, AdmissionRole.INTEGRATOR]
    good = _agent(
        "good", roles, {"structured_output": 0.95, "implementation": 0.95, "scope_discipline": 0.95}
    )
    weak = _agent(
        "weak", roles, {"structured_output": 0.85, "implementation": 0.7, "scope_discipline": 0.7}
    )
    d = s.schedule(
        _packet(risk=Risk.HIGH, write=["a.py"]), AdmissionRole.PATCH_PRODUCER, [good, weak]
    )
    assert d.selection_kind == "exploit"
    assert d.selected_profile_id == good.profile_id


@pytest.mark.unit
def test_roles_are_orthogonal_no_write_escalation():
    # A profile admitted only as REVIEWER/INTEGRATOR must NOT be eligible as a
    # PATCH_PRODUCER (P0-13: no privilege escalation via rank).
    s = _sched()
    reviewer = _agent(
        "rev",
        [AdmissionRole.REVIEWER, AdmissionRole.INTEGRATOR],
        {"structured_output": 0.95, "implementation": 0.95, "scope_discipline": 0.95},
    )
    d = s.schedule(_packet(write=["a.py"]), AdmissionRole.PATCH_PRODUCER, [reviewer])
    assert d.selected_profile_id is None
    assert any("lacks role" in r for c in d.candidates for r in c.exclusion_reasons)
    # But any admitted role can act as a pure read-only analyst.
    d2 = s.schedule(_packet(), AdmissionRole.READ_ONLY_ANALYST, [reviewer])
    assert d2.selected_profile_id == reviewer.profile_id


@pytest.mark.unit
def test_exploration_deterministic_and_disabled_for_high_risk():
    s = _sched()
    agents = [
        _agent(
            f"a{i}",
            [AdmissionRole.INTEGRATOR, AdmissionRole.PATCH_PRODUCER],
            {"structured_output": 0.9, "implementation": 0.9 - i * 0.01, "scope_discipline": 0.9},
        )
        for i in range(5)
    ]
    pkt = _packet(risk=Risk.HIGH, write=["a.py"])
    d1 = s.schedule(pkt, AdmissionRole.PATCH_PRODUCER, agents)
    d2 = s.schedule(pkt, AdmissionRole.PATCH_PRODUCER, agents)
    assert d1.selected_profile_id == d2.selected_profile_id  # deterministic
    assert d1.selection_kind == "exploit"  # exploration disabled for high risk


@pytest.mark.unit
def test_unhealthy_and_circuit_open_ineligible():
    s = _sched()
    a = _agent(
        "p",
        [AdmissionRole.PATCH_PRODUCER],
        {"structured_output": 0.9, "implementation": 0.9},
        health=HealthStatus.UNAVAILABLE,
    )
    d = s.schedule(_packet(write=["a.py"]), AdmissionRole.PATCH_PRODUCER, [a])
    assert d.selected_profile_id is None
