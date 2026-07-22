"""Per-packet eligibility + adaptive selection (spec §5-§7): hard gates give
probability zero, adaptive routing distributes low-risk traffic and adapts to
evidence, high/protected risk never explores, and decisions replay from receipts."""

from __future__ import annotations

import pytest

from usf_factory.adaptive_routing import (
    MODE_ADAPTIVE,
    MODE_REPLAY,
    adaptive_route,
    packet_eligibility,
    role_utility,
)
from usf_factory.enums import AdmissionRole, Risk
from usf_factory.models import Packet
from usf_factory.workforce import WorkforceProfile, WorkforceSnapshot

PLANNER = AdmissionRole.PLANNER_CANDIDATE
PRODUCER = AdmissionRole.PATCH_PRODUCER


def _profile(
    pid,
    *,
    accepted=0,
    rejected=0,
    success=0.5,
    contained=True,
    transports=None,
    roles=None,
    actual_model="",
    actual_model_verified=False,
    is_router=False,
):
    return WorkforceProfile(
        profile_id=pid,
        provider_id=pid.split("-")[0],
        requested_model_id="m",
        adapter="ollama",
        inference_mode="local",
        actual_model=actual_model,
        actual_model_verified=actual_model_verified,
        is_router=is_router,
        source_contained=contained,
        transports=transports if transports is not None else ["plain_invoke"],
        admitted_roles=roles if roles is not None else [PLANNER.value],
        accepted_success=success,
        accepted_count=accepted,
        rejected_count=rejected,
    )


def _packet(*, risk=Risk.LOW, data="private-metadata", task="semantic-planning"):
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class=task,
        risk=risk,
        data_classification=data,
    )


def _snapshot(profiles, role):
    return WorkforceSnapshot(
        policy_digest="pd",
        config_digest="cd",
        rule_bundle_digest="rd",
        profiles=profiles,
        role_order={role.value: [p.profile_id for p in profiles]},
    )


@pytest.mark.adversarial
def test_hard_gate_gives_probability_zero():
    from usf_factory.workforce_policy import committed_defaults, resolve_workforce_policy

    # A producer packet over private source; one candidate is NOT source-contained.
    contained = _profile(
        "a-1", contained=True, transports=["bounded_patch_synthesis"], roles=[PRODUCER.value]
    )
    uncontained = _profile(
        "b-1", contained=False, transports=["bounded_patch_synthesis"], roles=[PRODUCER.value]
    )
    snap = _snapshot([contained, uncontained], PRODUCER)
    policy = resolve_workforce_policy(committed_defaults())
    eligible, rejected = packet_eligibility(
        snap, policy, _packet(data="private-source", task="shacl-repair"), PRODUCER
    )
    assert [p.profile_id for p in eligible] == ["a-1"]
    assert any(c.agent_profile_id == "b-1" and not c.eligible for c in rejected)
    assert any("containment" in r for c in rejected for r in c.exclusion_reasons)


@pytest.mark.adversarial
def test_router_mutation_requires_preverified_unexcluded_actual_model():
    from usf_factory.workforce_policy import (
        WorkforcePolicyLayer,
        committed_defaults,
        resolve_workforce_policy,
    )

    packet = _packet(task="bounded-patch")
    profiles = [
        _profile(
            "router-unknown",
            transports=["bounded_patch_synthesis"],
            roles=[PRODUCER.value],
            is_router=True,
        ),
        _profile(
            "router-unverified",
            transports=["bounded_patch_synthesis"],
            roles=[PRODUCER.value],
            is_router=True,
            actual_model="model-a",
        ),
        _profile(
            "direct",
            transports=["bounded_patch_synthesis"],
            roles=[PRODUCER.value],
        ),
    ]
    policy = resolve_workforce_policy(committed_defaults())
    eligible, rejected = packet_eligibility(_snapshot(profiles, PRODUCER), policy, packet, PRODUCER)
    assert [profile.profile_id for profile in eligible] == ["direct"]
    assert {candidate.agent_profile_id: candidate.exclusion_reasons for candidate in rejected} == {
        "router-unknown": ["mutation requires a verified actual model"],
        "router-unverified": ["mutation requires a verified actual model"],
    }

    routed = _profile(
        "router-verified",
        transports=["bounded_patch_synthesis"],
        roles=[PRODUCER.value],
        is_router=True,
        actual_model="model-a",
        actual_model_verified=True,
    )
    excluded_policy = resolve_workforce_policy(
        committed_defaults(),
        None,
        WorkforcePolicyLayer(exclude_actual_models=["model-a"]),
    )
    eligible2, rejected2 = packet_eligibility(
        _snapshot([routed], PRODUCER), excluded_policy, packet, PRODUCER
    )
    assert eligible2 == []
    assert rejected2[0].exclusion_reasons == [
        "policy: actual routed model 'model-a' excluded (source=run)"
    ]


@pytest.mark.unit
def test_adaptive_distributes_low_risk():
    a, b = _profile("a-1"), _profile("b-1")
    picks = set()
    for i in range(60):
        d = adaptive_route([a, b], [], _packet(), PLANNER, mode=MODE_ADAPTIVE, seed=f"s-{i}")
        picks.add(d.selected_profile_id)
    assert picks == {"a-1", "b-1"}  # both explored across seeds


@pytest.mark.unit
def test_better_evidence_raises_selection_probability():
    good = _profile("a-1", accepted=40, rejected=0, success=0.95)
    bad = _profile("b-1", accepted=0, rejected=40, success=0.05)
    good_wins = sum(
        adaptive_route(
            [good, bad], [], _packet(), PLANNER, mode=MODE_ADAPTIVE, seed=f"s-{i}"
        ).selected_profile_id
        == "a-1"
        for i in range(80)
    )
    assert good_wins >= 72  # strong-evidence candidate dominates the draw


@pytest.mark.adversarial
def test_high_risk_never_explores():
    # High risk => deterministic exploitation; the highest-utility candidate is
    # always selected regardless of seed (no exploration).
    strong = _profile("a-1", success=0.95)
    weak = _profile("b-1", success=0.10)
    seen = {
        adaptive_route(
            [strong, weak], [], _packet(risk=Risk.HIGH), PLANNER, seed=f"s-{i}"
        ).selection_kind
        for i in range(20)
    }
    picks = {
        adaptive_route(
            [strong, weak], [], _packet(risk=Risk.HIGH), PLANNER, seed=f"s-{i}"
        ).selected_profile_id
        for i in range(20)
    }
    assert seen == {"exploit"}
    assert picks == {"a-1"}


@pytest.mark.unit
def test_deterministic_replay_reproduces():
    a, b = _profile("a-1", accepted=5), _profile("b-1", accepted=3)
    original = adaptive_route([a, b], [], _packet(), PLANNER, mode=MODE_ADAPTIVE, seed="fixed-seed")
    replay = adaptive_route(
        [a, b], [], _packet(), PLANNER, mode=MODE_REPLAY, seed=original.run_seed
    )
    assert replay.selected_profile_id == original.selected_profile_id
    assert replay.run_seed == original.run_seed


@pytest.mark.unit
def test_receipt_has_full_evidence():
    a, b = _profile("a-1"), _profile("b-1")
    d = adaptive_route(
        [a, b],
        [],
        _packet(),
        PLANNER,
        mode=MODE_ADAPTIVE,
        policy_digest="sha256:pol",
        snapshot_id="wf-123",
    )
    assert len(d.run_seed) >= 32  # cryptographic seed persisted
    assert d.policy_digest == "sha256:pol" and d.snapshot_id == "wf-123"
    elig = [c for c in d.candidates if c.eligible]
    assert {c.agent_profile_id for c in elig} == {"a-1", "b-1"}
    assert all(c.posterior >= 0.0 and 0.0 <= c.probability <= 1.0 for c in elig)


@pytest.mark.unit
def test_no_eligible_blocks():
    d = adaptive_route([], [], _packet(), PLANNER, mode=MODE_ADAPTIVE)
    assert d.selected_profile_id is None and d.selection_kind == "none"


@pytest.mark.unit
def test_role_utility_bounded_and_rewards_success():
    lo = role_utility(_profile("a-1", success=0.0), _packet(), PLANNER)
    hi = role_utility(_profile("a-1", success=1.0), _packet(), PLANNER)
    assert 0.0 <= lo <= hi <= 1.0 and hi > lo
