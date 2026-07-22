"""S3: clean-state bootstrap-runtime — builds + activates the ranked roster,
reports exact unfilled roles, and gates on the minimum launch roster. Uses
pre-seeded admitted profiles (no live inference)."""

from __future__ import annotations

import asyncio

import pytest

from conftest import all_dimension_scores, seed_agent
from usf_factory.bootstrap import bootstrap_runtime
from usf_factory.enums import AdmissionRole


@pytest.mark.e2e
def test_bootstrap_builds_roster_and_gates_on_minimum(ctx):
    # A planner + analyst are admitted -> minimum SHADOW roster satisfied; no
    # producer/reviewer -> candidate roster not satisfied, roles reported unfilled.
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.PLANNER_CANDIDATE, AdmissionRole.READ_ONLY_ANALYST],
        scores=all_dimension_scores(),
        provider_id="p-planner",
        model="m",
        adapter="ollama",
    )
    report = asyncio.run(bootstrap_runtime(ctx, candidates=[]))  # no live qualification
    assert report.roster_fresh is True
    assert "PLANNER_CANDIDATE" in report.filled_roles
    assert "READ_ONLY_ANALYST" in report.filled_roles
    assert report.minimum_shadow_ok is True
    assert "PATCH_PRODUCER" in report.unfilled_roles
    assert "REVIEWER" in report.unfilled_roles
    assert report.minimum_candidate_ok is False


@pytest.mark.e2e
def test_bootstrap_candidate_roster_requires_provider_diversity(ctx):
    # Planner + analyst + producer + reviewer, but producer and reviewer share a
    # provider -> candidate roster blocked on independence.
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.PLANNER_CANDIDATE, AdmissionRole.READ_ONLY_ANALYST],
        scores=all_dimension_scores(),
        provider_id="p-plan",
        model="m",
        adapter="ollama",
    )
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.PATCH_PRODUCER, AdmissionRole.REVIEWER],
        scores=all_dimension_scores(),
        provider_id="p-same",
        model="m",
        adapter="ollama",
    )
    report = asyncio.run(bootstrap_runtime(ctx, candidates=[]))
    assert report.minimum_shadow_ok is True
    assert report.minimum_candidate_ok is False  # producer == reviewer provider
    assert any("independence" in b for b in report.blockers)


@pytest.mark.e2e
def test_bootstrap_candidate_roster_ok_with_diverse_providers(ctx):
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.PLANNER_CANDIDATE, AdmissionRole.READ_ONLY_ANALYST],
        scores=all_dimension_scores(),
        provider_id="p-plan",
        model="m",
        adapter="ollama",
    )
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.PATCH_PRODUCER],
        scores=all_dimension_scores(),
        provider_id="p-prod",
        model="m",
        adapter="claude_cli",
    )
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.REVIEWER],
        scores=all_dimension_scores(),
        provider_id="p-rev",
        model="m",
        adapter="codex_cli",
    )
    report = asyncio.run(bootstrap_runtime(ctx, candidates=[]))
    assert report.minimum_candidate_ok is True  # producer/reviewer on distinct providers
