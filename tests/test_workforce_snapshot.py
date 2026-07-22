"""Dynamic WorkforceSnapshot (spec §4): built from evidence + policy, role views
generated (never fixed primaries), TTL + digest staleness, policy-driven exclusion."""

from __future__ import annotations

import pytest

from conftest import all_dimension_scores, seed_agent
from usf_factory.enums import AdmissionRole
from usf_factory.workforce import (
    active_workforce_snapshot,
    build_workforce_snapshot,
    persist_workforce_snapshot,
    workforce_stale,
)
from usf_factory.workforce_policy import (
    WorkforcePolicyLayer,
    committed_defaults,
    resolve_workforce_policy,
)

_ROLES = [
    AdmissionRole.PLANNER_CANDIDATE,
    AdmissionRole.READ_ONLY_ANALYST,
    AdmissionRole.REVIEWER,
]
FUTURE = "2999-01-01T00:00:00Z"
PAST = "2000-01-01T00:00:00Z"


@pytest.mark.unit
def test_snapshot_built_from_evidence_with_role_views(ctx):
    seed_agent(ctx.store, roles=_ROLES, scores=all_dimension_scores(), provider_id="ollama")
    eff = resolve_workforce_policy(committed_defaults())
    snap = build_workforce_snapshot(ctx, eff)
    # The seeded profile is eligible and appears in the population + a role view.
    assert snap.profiles, "expected at least one eligible profile"
    assert snap.policy_digest == eff.digest()
    planners = snap.role_candidates(AdmissionRole.PLANNER_CANDIDATE)
    assert any(p.provider_id == "ollama" for p in planners)
    # role_order is a generated VIEW, not a stored fixed primary.
    assert "PLANNER_CANDIDATE" in snap.role_order


@pytest.mark.adversarial
def test_policy_exclusion_removes_provider_from_snapshot(ctx):
    seed_agent(ctx.store, roles=_ROLES, scores=all_dimension_scores(), provider_id="ollama")
    eff = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_providers=["ollama"])
    )
    snap = build_workforce_snapshot(ctx, eff)
    assert not any(p.provider_id == "ollama" for p in snap.profiles)
    assert any("ollama" in e and "excluded" in e for e in snap.excluded)
    # The role is now uncovered → recorded as a blocker (fail-closed, honest).
    assert any("PLANNER_CANDIDATE" in b for b in snap.blockers)


@pytest.mark.unit
def test_staleness_on_policy_config_and_ttl(ctx):
    seed_agent(ctx.store, roles=_ROLES, scores=all_dimension_scores(), provider_id="ollama")
    eff = resolve_workforce_policy(committed_defaults())
    snap = build_workforce_snapshot(ctx, eff)
    # Fresh under the same policy + config + within TTL.
    fresh, _ = workforce_stale(ctx, snap, eff, now=snap.built_at)
    assert fresh is False
    # A changed effective policy makes it stale.
    other = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_providers=["x"])
    )
    stale, reason = workforce_stale(ctx, snap, other, now=snap.built_at)
    assert stale and "WorkforcePolicy" in reason
    # TTL elapsed makes it stale.
    stale2, reason2 = workforce_stale(ctx, snap, eff, now="2999-01-01T00:00:00Z")
    assert stale2 and "TTL" in reason2


@pytest.mark.unit
def test_persist_and_active_snapshot_fail_closed_when_stale(ctx):
    seed_agent(ctx.store, roles=_ROLES, scores=all_dimension_scores(), provider_id="ollama")
    eff = resolve_workforce_policy(committed_defaults())
    snap = build_workforce_snapshot(ctx, eff)
    persist_workforce_snapshot(ctx, snap)
    # Active + fresh under the same policy.
    got = active_workforce_snapshot(ctx, eff, now=snap.built_at)
    assert got is not None and got.snapshot_id == snap.snapshot_id
    # A different policy ⇒ stale ⇒ not returned (fail closed).
    other = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_providers=["y"])
    )
    assert active_workforce_snapshot(ctx, other, now=snap.built_at) is None
