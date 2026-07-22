"""Engine run-loop selection honours the WorkforcePolicy (exclusions effective in
live routing) and is fail-closed (§11): once a roster exists, a role with no fresh
entry never falls back to an all-admitted scan; a policy-excluded provider is never
a candidate (so never probed/invoked)."""

from __future__ import annotations

import pytest

from conftest import all_dimension_scores, seed_agent
from usf_factory.engine import FactoryEngine
from usf_factory.enums import AdmissionRole
from usf_factory.roster import build_roster, persist_active
from usf_factory.workforce_policy import (
    WorkforcePolicyLayer,
    committed_defaults,
    resolve_workforce_policy,
)

PLANNER = AdmissionRole.PLANNER_CANDIDATE
PRODUCER = AdmissionRole.PATCH_PRODUCER


@pytest.mark.adversarial
def test_candidate_agents_drop_policy_excluded_provider(ctx):
    seed_agent(ctx.store, roles=[PLANNER.value], scores=all_dimension_scores(), provider_id="groq")
    seed_agent(
        ctx.store, roles=[PLANNER.value], scores=all_dimension_scores(), provider_id="mistral"
    )
    policy = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_providers=["groq"])
    )
    eng = FactoryEngine(ctx, policy=policy)
    providers = {a.provider_id for a in eng.candidate_agents("semantic-planning", PLANNER)}
    assert "groq" not in providers  # excluded => never a candidate
    assert "mistral" in providers  # non-excluded remains


@pytest.mark.adversarial
def test_fail_closed_when_roster_exists_but_role_unfilled(ctx):
    # Only a PLANNER is admitted; persist the roster (so PATCH_PRODUCER has no primary).
    seed_agent(
        ctx.store, roles=[PLANNER.value], scores=all_dimension_scores(), provider_id="mistral"
    )
    persist_active(ctx, build_roster(ctx))
    eng = FactoryEngine(ctx, policy=resolve_workforce_policy(committed_defaults()))
    # A role with no fresh roster entry fails closed — NOT an all-admitted scan.
    assert eng.candidate_agents("shacl-repair", PRODUCER) == []
    # The covered role still resolves from the roster.
    assert eng.candidate_agents("semantic-planning", PLANNER)


@pytest.mark.unit
def test_migration_scan_allowed_when_no_roster_ever_existed(ctx):
    seed_agent(
        ctx.store, roles=[PLANNER.value], scores=all_dimension_scores(), provider_id="mistral"
    )
    eng = FactoryEngine(ctx, policy=resolve_workforce_policy(committed_defaults()))
    # No roster record has ever existed => legacy migration scan is permitted.
    assert eng.candidate_agents("semantic-planning", PLANNER)
