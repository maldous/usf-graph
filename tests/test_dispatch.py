"""Dynamic dispatch (spec §8/§9/§12/§13): transient-failure redraw preserving the
packet binding, honest block on exhaustion, terminal failure without silent
redraw, provider-diverse reviewer selection, router actual-model gating, and
continuous workforce refresh when stale."""

from __future__ import annotations

import pytest

from conftest import all_dimension_scores, seed_agent
from usf_factory.dispatch import (
    dispatch_with_fallback,
    refresh_active_workforce,
    router_ready_for_mutation,
    select_reviewer,
)
from usf_factory.enums import AdmissionRole, DispatchFailure, Risk
from usf_factory.models import Packet
from usf_factory.workforce import WorkforceProfile, WorkforceSnapshot
from usf_factory.workforce_policy import (
    WorkforcePolicyLayer,
    committed_defaults,
    resolve_workforce_policy,
)

PLANNER = AdmissionRole.PLANNER_CANDIDATE
REVIEWER = AdmissionRole.REVIEWER


def _profile(pid, *, provider=None, roles=None, actual="", verified=False):
    return WorkforceProfile(
        profile_id=pid,
        provider_id=provider or pid.split("-")[0],
        requested_model_id="m",
        adapter="ollama",
        inference_mode="local",
        source_contained=True,
        transports=["plain_invoke", "bounded_patch_synthesis"],
        admitted_roles=roles if roles is not None else [PLANNER.value],
        actual_model=actual,
        actual_model_verified=verified,
    )


def _packet(*, risk=Risk.LOW, data="private-metadata"):
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="semantic-planning",
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
def test_transient_failure_redraws_and_preserves_packet(ctx):
    snap = _snapshot([_profile("a-1"), _profile("b-1")], PLANNER)
    policy = resolve_workforce_policy(committed_defaults())
    calls = {"n": 0}

    def invoke(profile):
        calls["n"] += 1
        if calls["n"] == 1:
            return False, DispatchFailure.QUOTA_BLOCKED, None  # transient, no side effect
        return True, None, f"done:{profile.profile_id}"

    pkt = _packet()
    out = dispatch_with_fallback(ctx, snap, policy, pkt, PLANNER, invoke, max_attempts=3)
    assert out.ok and calls["n"] == 2
    assert out.packet_id == pkt.packet_id  # same packet/authority binding across redraw
    assert len(out.attempts) == 2 and out.attempts[0].failure == "QUOTA_BLOCKED"
    # The two attempts hit distinct candidates (the failed one was removed).
    assert out.attempts[0].profile_id != out.attempts[1].profile_id


@pytest.mark.adversarial
def test_exhaustion_blocks_without_repeating_side_effects(ctx):
    snap = _snapshot([_profile("a-1"), _profile("b-1")], PLANNER)
    policy = resolve_workforce_policy(committed_defaults())
    invoked: list[str] = []

    def invoke(profile):
        invoked.append(profile.profile_id)
        return False, DispatchFailure.RATE_LIMITED, None

    out = dispatch_with_fallback(ctx, snap, policy, _packet(), PLANNER, invoke, max_attempts=5)
    assert not out.ok and out.blocked_reason
    assert sorted(invoked) == ["a-1", "b-1"]  # each candidate tried exactly once


@pytest.mark.adversarial
def test_terminal_failure_is_not_silently_redrawn(ctx):
    snap = _snapshot([_profile("a-1"), _profile("b-1")], PLANNER)
    policy = resolve_workforce_policy(committed_defaults())
    calls = {"n": 0}

    def invoke(profile):
        calls["n"] += 1
        return False, DispatchFailure.VALIDATION_FAILED, None  # terminal result-quality

    out = dispatch_with_fallback(ctx, snap, policy, _packet(), PLANNER, invoke, max_attempts=5)
    assert not out.ok and "terminal" in out.blocked_reason
    assert calls["n"] == 1  # no redraw on a terminal failure


@pytest.mark.unit
def test_reviewer_is_provider_diverse_or_blocks(ctx):
    policy = resolve_workforce_policy(committed_defaults())
    both = _snapshot(
        [
            _profile("A-1", provider="A", roles=[REVIEWER.value]),
            _profile("B-1", provider="B", roles=[REVIEWER.value]),
        ],
        REVIEWER,
    )
    reviewer, reason = select_reviewer(both, policy, authoring_providers={"A"})
    assert reviewer is not None and reviewer.provider_id == "B"
    # Only the authoring provider is available ⇒ block (never reuse an author).
    only_author = _snapshot([_profile("A-1", provider="A", roles=[REVIEWER.value])], REVIEWER)
    reviewer2, reason2 = select_reviewer(only_author, policy, authoring_providers={"A"})
    assert reviewer2 is None and "independent reviewer" in reason2


@pytest.mark.adversarial
def test_router_mutation_requires_known_verified_unexcluded_actual(ctx):
    policy = resolve_workforce_policy(committed_defaults())
    unknown = _profile("r-1", actual="", verified=False)
    assert router_ready_for_mutation(unknown, policy)[0] is False
    unverified = _profile("r-1", actual="gpt-real", verified=False)
    assert router_ready_for_mutation(unverified, policy)[0] is False
    verified = _profile("r-1", actual="gpt-real", verified=True)
    assert router_ready_for_mutation(verified, policy)[0] is True
    # An excluded actual routed model is rejected even if verified.
    excl = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_actual_models=["gpt-real"])
    )
    assert router_ready_for_mutation(verified, excl)[0] is False


@pytest.mark.unit
def test_refresh_rebuilds_when_no_active_snapshot(ctx):
    seed_agent(
        ctx.store, roles=[PLANNER.value], scores=all_dimension_scores(), provider_id="ollama"
    )
    policy = resolve_workforce_policy(committed_defaults())
    snap = refresh_active_workforce(ctx, policy)
    assert snap is not None and snap.policy_digest == policy.digest()
