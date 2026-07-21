"""P1 wave: routed-model attribution, honest routing facts, budget settlement,
and the production admission workflow."""

from __future__ import annotations

import asyncio

import pytest

from conftest import all_dimension_scores, seed_agent
from usf_factory.engine import FactoryEngine
from usf_factory.enums import AdmissionRole, AuthMode, HealthStatus
from usf_factory.errors import ConfigError
from usf_factory.models import AgentProfile, Packet
from usf_factory.workers import BrokeredWorker

# ---- P1-9: attribution ---------------------------------------------------- #


def _reporting_chat(actual_model="router/actual-model-v2"):
    """Finishes immediately, REPORTING the routed model + token usage per turn."""

    async def chat(messages, tools):
        return {
            "content": "",
            "tool_calls": [
                {
                    "id": "fin",
                    "name": "finish_packet",
                    "arguments": {
                        "status": "COMPLETED",
                        "findings": ["analysis done"],
                        "criteria_results": {"ok": True},
                    },
                }
            ],
            "actual_model": actual_model,
            "usage": {"prompt_tokens": 120, "completion_tokens": 30},
        }

    return chat


def _silent_chat():
    """Same result but reports NOTHING about the routed model (no attribution)."""

    async def chat(messages, tools):
        return {
            "content": "",
            "tool_calls": [
                {
                    "id": "fin",
                    "name": "finish_packet",
                    "arguments": {
                        "status": "COMPLETED",
                        "findings": ["analysis done"],
                        "criteria_results": {"ok": True},
                    },
                }
            ],
        }

    return chat


def _ro_packet():
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="analyze",
        task_class="semantic-planning",
        acceptance_criteria=["done"],
        permitted_tools=["list_paths", "read_file"],
    )


def _agent():
    return AgentProfile(
        provider_id="openrouter",
        requested_model_id="openrouter/free",
        adapter="brokered",
        auth_mode=AuthMode.API_TOKEN,
    )


@pytest.mark.contract
def test_brokered_worker_records_verified_routed_model(ctx, tmp_path):
    w = BrokeredWorker(_reporting_chat(), store=ctx.store, mutating=False)
    r = asyncio.run(w.execute(_ro_packet(), tmp_path, _agent()))
    assert r.status.value == "COMPLETED"
    # The ACTUAL routed model is recorded, not the requested router id.
    assert r.actual_model == "router/actual-model-v2"
    assert r.usage["actual_model_verified"] is True
    assert r.usage["actual_models"] == ["router/actual-model-v2"]
    assert r.usage["prompt_tokens"] == 120 and r.usage["completion_tokens"] == 30
    assert r.usage["turns"] == 1 and r.usage["wall_s"] >= 0


@pytest.mark.contract
def test_brokered_worker_marks_unverified_attribution(ctx, tmp_path):
    w = BrokeredWorker(_silent_chat(), store=ctx.store, mutating=False)
    r = asyncio.run(w.execute(_ro_packet(), tmp_path, _agent()))
    # Fallback to the requested id is EXPLICITLY unverified — never silent.
    assert r.actual_model == "openrouter/free"
    assert r.usage["actual_model_verified"] is False
    assert r.usage["actual_models"] == []


# ---- P1-8: honest routing facts ------------------------------------------- #


@pytest.mark.unit
def test_candidates_use_recorded_facts_not_fabrications(ctx, tmp_usf):
    profile = seed_agent(
        ctx.store, roles=[AdmissionRole.READ_ONLY_ANALYST], scores=all_dimension_scores()
    )
    # Catalogue record: PAID model with pricing + context window.
    ctx.store.put(
        "models",
        "m1",
        {
            "provider_id": profile.provider_id,
            "requested_model_id": profile.requested_model_id,
            "context_tokens": 32000,
            "prompt_cost_per_mtok": 5.0,
            "output_cost_per_mtok": 15.0,
            "free": False,
        },
        extra={"provider_id": profile.provider_id},
    )
    eng = FactoryEngine(ctx)
    [cand] = eng.candidate_agents("semantic-planning")
    assert cand.context_tokens == 32000  # from the catalogue, not None
    assert cand.cost_usd > 0  # estimated from recorded pricing
    # Paid model + allow_billable=False (default) => NOT schedulable.
    assert cand.quota_ok is False
    # Unrecorded provider health is DEGRADED (never fabricated HEALTHY).
    assert cand.health is HealthStatus.DEGRADED
    # Tools from adapter capability, never "*".
    assert "*" not in cand.tools and "read_file" in cand.tools


@pytest.mark.unit
def test_free_model_and_recorded_health_are_schedulable(ctx, tmp_usf):
    profile = seed_agent(
        ctx.store, roles=[AdmissionRole.READ_ONLY_ANALYST], scores=all_dimension_scores()
    )
    ctx.store.put(
        "models",
        "m1",
        {
            "provider_id": profile.provider_id,
            "requested_model_id": profile.requested_model_id,
            "context_tokens": 8000,
            "free": True,
        },
        extra={"provider_id": profile.provider_id},
    )
    ctx.store.put(
        "provider_health",
        profile.provider_id,
        {"provider_id": profile.provider_id, "status": "healthy", "checked_at": "t"},
    )
    eng = FactoryEngine(ctx)
    [cand] = eng.candidate_agents("semantic-planning")
    assert cand.quota_ok is True and cand.cost_usd == 0.0
    assert cand.health is HealthStatus.HEALTHY  # recorded, not assumed


# ---- P1-7: admission workflow --------------------------------------------- #


@pytest.mark.unit
def test_ensure_profile_requires_known_provider(ctx):
    from usf_factory.admission import ensure_profile

    with pytest.raises(ConfigError):
        ensure_profile(ctx, "no-such-provider", "some-model")


@pytest.mark.unit
def test_ensure_profile_persists_from_provider_config(ctx):
    from usf_factory.admission import ensure_profile

    profile = ensure_profile(ctx, "openrouter", "meta-llama/llama-3-8b")
    row = ctx.store.get("agent_profiles", profile.profile_id)
    assert row and row["provider_id"] == "openrouter"
    assert profile.adapter  # from providers.yaml, never guessed


@pytest.mark.unit
def test_admit_from_evidence_computes_roles(ctx):
    from usf_factory.admission import admit_from_evidence

    profile = seed_agent(
        ctx.store,
        roles=[AdmissionRole.UNQUALIFIED],  # stored roles are stale/wrong on purpose
        scores=all_dimension_scores(0.99),  # evidence satisfies every threshold
    )
    roles = admit_from_evidence(ctx, profile.profile_id)
    assert AdmissionRole.UNQUALIFIED not in roles
    assert roles  # recomputed from evidence vs trust policy
    run = ctx.store.get("qualification_runs", profile.profile_id)
    assert set(run["roles_admitted"]) == {r.value for r in roles}


@pytest.mark.unit
def test_admit_without_evidence_fails(ctx):
    from usf_factory.admission import admit_from_evidence, ensure_profile

    profile = ensure_profile(ctx, "openrouter", "m")
    with pytest.raises(ConfigError):
        admit_from_evidence(ctx, profile.profile_id)


@pytest.mark.unit
def test_operator_override_is_recorded(ctx):
    from usf_factory.admission import grant_role_operator_override

    profile = seed_agent(
        ctx.store, roles=[AdmissionRole.READ_ONLY_ANALYST], scores=all_dimension_scores(0.1)
    )
    roles = grant_role_operator_override(ctx, profile.profile_id, AdmissionRole.REVIEWER)
    assert AdmissionRole.REVIEWER in roles
    run = ctx.store.get("qualification_runs", profile.profile_id)
    assert run["operator_overrides"][0]["role"] == AdmissionRole.REVIEWER.value


@pytest.mark.unit
def test_live_qualification_is_gated(ctx):
    from usf_factory.admission import ensure_profile, qualify_live
    from usf_factory.errors import ProtectedActionError

    profile = ensure_profile(ctx, "openrouter", "m")
    with pytest.raises(ProtectedActionError):
        asyncio.run(qualify_live(ctx, profile, allow_billable=False, budget_usd=0.0))
    # A gated qualify persists NO evidence.
    assert ctx.store.get("qualification_runs", profile.profile_id) is None
