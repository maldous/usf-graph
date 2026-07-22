"""S2: the active roster is authoritative for every role — ranked by semantic
quality and token efficiency (never profile_id), consumed by packet scheduling,
rejected when stale, and never granting capability on adapter-construction
failure."""

from __future__ import annotations

import pytest

from conftest import all_dimension_scores, seed_agent
from usf_factory.enums import AdmissionRole
from usf_factory.roster import (
    _profile_capabilities,
    active_roster,
    build_roster,
    persist_active,
)


def _provider_eval(ctx, provider_id, fidelity, optimization):
    from usf_factory.clock import utc_now_iso

    ctx.store.put(
        "provider_evaluations",
        f"{provider_id}:e",
        {
            "provider_id": provider_id,
            "status": "EVALUATED",
            "semantic_scores": {
                "semantic_rule_fidelity": fidelity,
                "semantic_optimization": optimization,
                "structured_output": 1.0,
            },
            "eval_suite_version": "provider-eval-v1",
            "evaluated_at": utc_now_iso(),
        },
        extra={"provider_id": provider_id, "eval_suite_version": "provider-eval-v1"},
    )


# ---- ranking uses semantic/token evidence, not profile_id ------------------- #


@pytest.mark.e2e
def test_roster_ranks_by_semantic_quality_not_profile_id(ctx):
    # Two analysts, identical qualification; provider "hi" has better semantic
    # scores than provider "lo". Ranking must prefer "hi" regardless of profile_id.
    picked = {}
    for prov, fidelity in [("prov-hi", 1.0), ("prov-lo", 0.0)]:
        prof = seed_agent(
            ctx.store,
            roles=[AdmissionRole.READ_ONLY_ANALYST],
            scores=all_dimension_scores(),
            provider_id=prov,
            model=f"m-{prov}",
            adapter="ollama",
        )
        picked[prov] = prof.profile_id
        _provider_eval(ctx, prov, fidelity, fidelity)
    roster = build_roster(ctx)
    entry = roster.entries["READ_ONLY_ANALYST"]
    assert entry["primary"] == picked["prov-hi"]  # higher semantic fidelity wins
    assert picked["prov-lo"] in entry["fallbacks"]


# ---- scheduling restricts candidates to the active roster ------------------- #


@pytest.mark.e2e
def test_scheduler_uses_only_roster_role_entries(ctx):
    from usf_factory.engine import FactoryEngine

    a = seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST],
        scores=all_dimension_scores(),
        provider_id="prov-a",
        model="m-a",
        adapter="ollama",
    )
    # A second admitted analyst that is NOT the roster primary/fallback.
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST],
        scores=all_dimension_scores(),
        provider_id="prov-b",
        model="m-b",
        adapter="ollama",
    )
    _provider_eval(ctx, "prov-a", 1.0, 1.0)  # make prov-a the primary
    _provider_eval(ctx, "prov-b", 0.0, 0.0)
    roster = build_roster(ctx)
    # Force a single-entry roster (no fallbacks) so we can prove restriction.
    roster.entries["READ_ONLY_ANALYST"]["fallbacks"] = []
    persist_active(ctx, roster)

    eng = FactoryEngine(ctx)
    cands = eng.candidate_agents("semantic-analysis", AdmissionRole.READ_ONLY_ANALYST)
    ids = {c.profile.profile_id for c in cands}
    assert ids == {a.profile_id}  # only the roster's entry, not every admitted analyst


# ---- stale roster is rejected at use ---------------------------------------- #


@pytest.mark.adversarial
def test_stale_roster_rejected_on_config_change(ctx):
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.READ_ONLY_ANALYST],
        scores=all_dimension_scores(),
        provider_id="prov-a",
        model="m-a",
        adapter="ollama",
    )
    persist_active(ctx, build_roster(ctx))
    assert active_roster(ctx) is not None  # fresh
    # Mutate the bound configuration (a trust threshold) -> roster is now stale.
    tp = ctx.config.trust
    role, thr = next(iter(tp.role_thresholds.items()))
    thr.min_scores["structured_output"] = thr.min_scores.get("structured_output", 0.5) + 0.01
    assert active_roster(ctx) is None  # stale roster is not served


# ---- adapter-construction failure cannot grant capabilities ----------------- #


@pytest.mark.adversarial
def test_unknown_adapter_kind_grants_no_capability(ctx):
    from usf_factory.capabilities import UNAVAILABLE, role_transport_ok
    from usf_factory.enums import AuthMode
    from usf_factory.models import AgentProfile

    profile = AgentProfile(
        provider_id="ghost",
        requested_model_id="m",
        adapter="does-not-exist",
        auth_mode=AuthMode.LOCAL,
    )
    cap = _profile_capabilities(ctx, profile)
    assert cap is UNAVAILABLE  # no capability granted
    for role in AdmissionRole:
        assert role_transport_ok(role, cap) is False or role == AdmissionRole.UNQUALIFIED
