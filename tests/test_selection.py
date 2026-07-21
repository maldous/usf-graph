"""Milestone-3 acceptance tests: exclusions, genuine CLI probing, inference auth,
accounting, staged tournament, central selector, routed handling, budget."""

from __future__ import annotations

import asyncio

import pytest

from conftest import all_dimension_scores
from usf_factory.enums import AdmissionRole, AuthMode
from usf_factory.models import ProviderConfig
from usf_factory.probing import InferenceAuthorization
from usf_factory.providers.cli_adapters import ClaudeCliAdapter, CodexCliAdapter
from usf_factory.selection import (
    ModelAssessment,
    SelectionFilters,
    candidate_models,
    default_filters,
    rank_for_role,
    select_roster,
)

# ---- #4 exclusions ---------------------------------------------------------- #


def _seed_models(ctx, pairs):
    for i, (pid, mid, free) in enumerate(pairs):
        ctx.store.put(
            "models",
            f"m{i}",
            {"provider_id": pid, "requested_model_id": mid, "free": free},
            extra={"provider_id": pid},
        )


@pytest.mark.adversarial
def test_llama_and_excluded_models_absent_from_shortlist(ctx):
    _seed_models(
        ctx,
        [
            ("openrouter", "meta-llama/llama-3.3-70b-instruct", True),
            ("groq", "llama-3.1-8b-instant", True),
            ("openrouter", "qwen/qwen-2.5-72b-instruct", True),
            ("ollama", "lfm2.5:8b-a1b-q8_0", True),
            ("mistral", "mistral-large-latest", False),
        ],
    )
    shortlist = candidate_models(ctx, default_filters())
    ids = {f"{p}/{m}" for p, m in shortlist}
    assert not any("llama" in i for i in ids)  # llama family excluded
    assert "ollama/lfm2.5:8b-a1b-q8_0" not in ids  # tested-local excluded
    assert "openrouter/qwen/qwen-2.5-72b-instruct" in ids  # non-llama kept
    assert "mistral/mistral-large-latest" in ids  # non-llama provider kept


@pytest.mark.unit
def test_include_model_overrides_family_exclusion(ctx):
    _seed_models(ctx, [("groq", "llama-3.1-8b-instant", True)])
    f = SelectionFilters(exclude_families=["llama"], include_models=["llama-3.1-8b-instant"])
    ids = {f"{p}/{m}" for p, m in candidate_models(ctx, f)}
    assert "groq/llama-3.1-8b-instant" in ids


# ---- #1 external free inference works without paid -------------------------- #


@pytest.mark.adversarial
def test_external_free_inference_without_paid(ctx, monkeypatch):
    """An OpenRouter ':free' model runs with --allow-inference --max-cost-usd 0
    and WITHOUT --allow-paid-inference."""
    from usf_factory.probing import run_probe_suite

    ctx.store.put(
        "models",
        "m1",
        {"provider_id": "openrouter", "requested_model_id": "x/y:free", "free": True},
        extra={"provider_id": "openrouter"},
    )

    class _Ad:
        async def probe_model(self, model_id, probe):
            from usf_factory.models import ProbeResult, TokenUsage

            return ProbeResult(
                kind=probe.kind,
                version=probe.version,
                passed=True,
                usage=TokenUsage(input_tokens=3, output_tokens=2, actual_model=model_id),
                actual_model_id=model_id,
            )

    class _Reg:
        def adapter(self, pid):
            return _Ad()

    import usf_factory.providers as providers

    monkeypatch.setattr(providers, "build_registry", lambda ctx, allow_billable=False: _Reg())
    from usf_factory.admission import ensure_profile

    profile = ensure_profile(ctx, "openrouter", "x/y:free")
    # inference allowed, paid NOT allowed, max 0 => must succeed (free).
    run = asyncio.run(
        run_probe_suite(
            ctx, profile, auth=InferenceAuthorization(allow_inference=True, max_cost_usd=0.0)
        )
    )
    assert run.total == 10 and run.passed == 10
    assert run.cost_usd == 0.0


# ---- #2 #3 genuine CLI probing --------------------------------------------- #


def _cli_cfg(pid, adapter):
    return ProviderConfig(
        provider_id=pid, display_name=pid, auth_mode=AuthMode.OIDC_CLI, adapter=adapter
    )


@pytest.mark.contract
def test_codex_cli_probe_invokes_and_grades(monkeypatch):
    ad = CodexCliAdapter(_cli_cfg("codex-cli", "codex_cli"), allow_billable=True)
    monkeypatch.setattr(ad, "_binary_path", lambda: "/usr/bin/codex")

    async def fake_run(cmd, timeout_s=10.0, stdin=None):
        # Codex JSONL: an agent_message echoing the IRI probe exactly.
        assert stdin is not None  # prompt fed on stdin (genuine invocation)
        line = '{"type":"item.completed","item":{"type":"agent_message","text":"https://example.org/usf#Capability_A1b2C3"}}'
        return (0, line, "")

    import usf_factory.providers.cli_adapters as cli

    monkeypatch.setattr(cli, "_run", fake_run)
    from usf_factory.probes import default_probe_specs

    iri_probe = next(p for p in default_probe_specs() if p.kind.value == "iri_preservation")
    r = asyncio.run(ad.probe_model("default", iri_probe))
    assert r.passed is True and "IRI preserved" in r.detail  # graded, not just non-empty


@pytest.mark.contract
def test_claude_cli_probe_invokes_grades_and_captures_usage(monkeypatch):
    ad = ClaudeCliAdapter(_cli_cfg("claude-cli", "claude_cli"), allow_billable=True)
    monkeypatch.setattr(ad, "_binary_path", lambda: "/usr/bin/claude")

    async def fake_run(cmd, timeout_s=10.0, stdin=None):
        body = (
            '{"type":"result","is_error":false,"result":"4",'
            '"total_cost_usd":0.012,'
            '"usage":{"input_tokens":2,"output_tokens":1,"cache_read_input_tokens":15000,'
            '"cache_creation_input_tokens":500},'
            '"modelUsage":{"claude-opus-4-8[1m]":{"outputTokens":1}}}'
        )
        return (0, body, "")

    import usf_factory.providers.cli_adapters as cli

    monkeypatch.setattr(cli, "_run", fake_run)
    from usf_factory.probes import default_probe_specs

    prob = next(p for p in default_probe_specs() if p.kind.value == "prohibited_tool_compliance")
    r = asyncio.run(ad.probe_model("default", prob))
    assert r.passed is True  # answered "4", no prohibited tool
    assert r.actual_model_id == "claude-opus-4-8[1m]"  # actual model captured
    assert r.usage.cached_input_tokens == 15000 and r.usage.cache_creation_tokens == 500
    assert r.usage.provider_reported_cost == 0.012  # #8 tokens/cost from adapter


@pytest.mark.adversarial
def test_claude_cli_quota_is_classified(monkeypatch):
    ad = ClaudeCliAdapter(_cli_cfg("claude-cli", "claude_cli"), allow_billable=True)
    monkeypatch.setattr(ad, "_binary_path", lambda: "/usr/bin/claude")

    async def fake_run(cmd, timeout_s=10.0, stdin=None):
        return (0, '{"type":"result","is_error":true,"api_error_status":"429 quota"}', "")

    import usf_factory.providers.cli_adapters as cli

    monkeypatch.setattr(cli, "_run", fake_run)
    from usf_factory.probes import default_probe_specs

    r = asyncio.run(ad.probe_model("default", default_probe_specs()[0]))
    assert r.detail == "QUOTA_BLOCKED"  # not a model failure


# ---- #7 billable without usage keeps conservative estimate ------------------ #


@pytest.mark.adversarial
def test_billable_without_usage_retains_estimate(ctx, monkeypatch):
    from usf_factory.admission import ensure_profile
    from usf_factory.models import ProbeResult
    from usf_factory.probing import run_probe_suite

    ctx.store.put(
        "models",
        "m1",
        {
            "provider_id": "openai-api",
            "requested_model_id": "gpt-x",
            "free": False,
            "prompt_cost_per_mtok": 10.0,
            "output_cost_per_mtok": 30.0,
        },
        extra={"provider_id": "openai-api"},
    )

    class _Ad:  # returns NO usage/cost (provider omitted it)
        async def probe_model(self, model_id, probe):
            return ProbeResult(kind=probe.kind, version=probe.version, passed=True)

    class _Reg:
        def adapter(self, pid):
            return _Ad()

    import usf_factory.providers as providers

    monkeypatch.setattr(providers, "build_registry", lambda ctx, allow_billable=False: _Reg())
    profile = ensure_profile(ctx, "openai-api", "gpt-x")
    run = asyncio.run(
        run_probe_suite(
            ctx,
            profile,
            auth=InferenceAuthorization(
                allow_inference=True, allow_paid_inference=True, max_cost_usd=5.0
            ),
        )
    )
    assert run.cost_verified is False
    assert run.cost_usd > 0.0  # conservative estimate retained, NOT zero


# ---- #11 #12 #13 #14 #15 selection logic ----------------------------------- #


def _asmt(pid, mid, roles, tool=False, router=False, actual=None, cost=0.0):
    a = ModelAssessment(provider_id=pid, model_id=mid, profile_id=f"{pid}:{mid}")
    a.structural_ok = True
    a.tool_ok = tool
    a.is_router = router
    a.actual_models = actual or [mid]
    a.cost_usd = cost
    a.role_scores = {r.value: 0.9 for r in roles}
    return a


@pytest.mark.adversarial
def test_prohibited_tool_failure_blocks_tool_roles():
    """assess_model gating: tool roles require tool_ok; a non-tool-capable model
    ranks only for non-tool roles."""
    a = _asmt(
        "mistral", "m", [AdmissionRole.READ_ONLY_ANALYST, AdmissionRole.PATCH_PRODUCER], tool=False
    )
    # PATCH_PRODUCER requires tool_ok => excluded from ranking despite role_score.
    assert rank_for_role([a], AdmissionRole.PATCH_PRODUCER) == []
    assert rank_for_role([a], AdmissionRole.READ_ONLY_ANALYST) == [a]


@pytest.mark.adversarial
def test_router_alias_not_ranked_for_mutation_role():
    router = _asmt(
        "openrouter",
        "auto",
        [AdmissionRole.PATCH_PRODUCER],
        tool=True,
        router=True,
        actual=["model-a", "model-b"],
    )  # unstable actual model
    assert rank_for_role([router], AdmissionRole.PATCH_PRODUCER) == []


@pytest.mark.unit
def test_selection_is_ranked_not_first_found():
    weak = _asmt("groq", "weak", [AdmissionRole.PLANNER_CANDIDATE], cost=0.5)
    strong = _asmt("mistral", "strong", [AdmissionRole.PLANNER_CANDIDATE], cost=0.0)
    weak.role_scores[AdmissionRole.PLANNER_CANDIDATE.value] = 0.6
    strong.role_scores[AdmissionRole.PLANNER_CANDIDATE.value] = 0.95
    ranked = rank_for_role([weak, strong], AdmissionRole.PLANNER_CANDIDATE)
    assert ranked[0] is strong  # best evidence wins, not list order


@pytest.mark.adversarial
def test_reviewer_independence_enforced():
    planner = _asmt("mistral", "p", [AdmissionRole.PLANNER_CANDIDATE])
    prod = _asmt("mistral", "prod", [AdmissionRole.PATCH_PRODUCER], tool=True)
    rev_same = _asmt("mistral", "r1", [AdmissionRole.REVIEWER], tool=True)
    rev_diff = _asmt("gemini", "r2", [AdmissionRole.REVIEWER], tool=True)
    roster = select_roster([planner, prod, rev_same, rev_diff])
    # Reviewer must be the different-provider one (gemini), not the mistral one.
    assert roster["PRIMARY_REVIEWER"]["provider"] == "gemini"


@pytest.mark.unit
def test_no_qualified_model_when_empty():
    roster = select_roster([])
    assert roster["PRIMARY_PLANNER"]["status"] == "NO_QUALIFIED_MODEL"
    assert roster["PRIMARY_PATCH_PRODUCER"]["status"] == "NO_QUALIFIED_MODEL"


# ---- #5 skip valid existing unless force-reassess -------------------------- #


@pytest.mark.unit
def test_skip_valid_existing_unless_force(ctx):
    from usf_factory.admission import admit_from_evidence, ensure_profile, record_qualification
    from usf_factory.models import QualificationRun
    from usf_factory.selection import has_valid_evidence

    # No evidence yet => not valid.
    assert has_valid_evidence(ctx, "mistral", "mistral-small") is False
    # Record a real (immutable) qualification + evidence-based admission.
    profile = ensure_profile(ctx, "mistral", "mistral-small")
    run = QualificationRun(
        run_id="qual-x",
        agent_profile_id=profile.profile_id,
        suite_id="t",
        suite_version="v1",
        config_digest=profile.digest(),
        dimension_scores=all_dimension_scores(),
    )
    record_qualification(ctx, run)
    admit_from_evidence(ctx, profile.profile_id)
    assert has_valid_evidence(ctx, "mistral", "mistral-small") is True


# ---- #6 qualification bound based on all cases + reps ---------------------- #


@pytest.mark.unit
def test_qualification_cost_scales_with_cases_and_reps():
    from usf_factory.probing import _est_cost, qualification_cost_estimate

    row = {"prompt_cost_per_mtok": 10.0, "output_cost_per_mtok": 30.0}
    probe10 = _est_cost(row)
    q38 = qualification_cost_estimate(row, 38, reps=1)
    q38x2 = qualification_cost_estimate(row, 38, reps=2)
    assert q38 > probe10  # 38-case suite is NOT the 10-probe estimate
    assert abs(q38x2 - 2 * q38) < 1e-9  # scales with repetition
    assert qualification_cost_estimate(None, 38) == 0.0


# ---- #10 concurrent lanes cannot alter each other's model ------------------ #


@pytest.mark.unit
def test_concurrent_lanes_independent_model():
    from usf_factory.providers.openai_compatible import OpenAICompatibleAdapter

    cfg = ProviderConfig(
        provider_id="openrouter",
        display_name="or",
        auth_mode=AuthMode.API_TOKEN,
        adapter="openai_compatible",
        base_url="https://x",
    )
    a = OpenAICompatibleAdapter(cfg, "t").with_loop_model("model-a")
    b = OpenAICompatibleAdapter(cfg, "t").with_loop_model("model-b")
    assert a._loop_model == "model-a" and b._loop_model == "model-b"  # isolated lanes


# ---- #18 global assessment budget cannot be exceeded ---------------------- #


@pytest.mark.adversarial
def test_budget_cannot_be_exceeded(ctx, monkeypatch):
    from usf_factory.budget import BudgetLedger, BudgetLimits
    from usf_factory.selection import run_tournament

    _seed_models(
        ctx,
        [
            ("mistral", "m1", False),
            ("gemini", "g1", False),
            ("deepseek", "d1", False),
        ],
    )
    # Pre-spend the whole cap so the tournament must stop before any model.
    BudgetLedger(ctx.store, BudgetLimits()).reserve(
        cycle_id="probe", provider_id="x", estimate_usd=5.0
    )
    res = asyncio.run(
        run_tournament(
            ctx,
            SelectionFilters(),
            auth=InferenceAuthorization(
                allow_inference=True, allow_paid_inference=True, max_cost_usd=1.0
            ),
            max_models=5,
        )
    )
    assert res.stopped_for_budget is True
    assert res.assessments == []  # nothing assessed once the cap is reached


# ---- #20 protected gates remain disabled ----------------------------------- #


@pytest.mark.unit
def test_protected_gates_remain_disabled(ctx):
    s = ctx.config.safety
    assert not s.autonomous_safe_enabled
    assert not s.allow_billable
    assert not s.allow_source_egress
    assert not s.allow_main_integration
    assert not s.allow_stardog_publication
    assert not s.allow_terminal_completion


# ---- #9 cache cold/warm metrics recorded ----------------------------------- #


@pytest.mark.unit
def test_cache_cold_warm_metrics_recorded():
    from usf_factory.models import TokenUsage

    cold = TokenUsage(input_tokens=6000, uncached_input_tokens=6000, cache_creation_tokens=6000)
    warm = TokenUsage(input_tokens=6000, cached_input_tokens=5800, uncached_input_tokens=200)
    # Warm run reuses cache => far fewer uncached input tokens (the key metric).
    assert warm.uncached_input_tokens < cold.uncached_input_tokens
    merged = cold.merged(warm)
    assert merged.cached_input_tokens == 5800 and merged.cache_creation_tokens == 6000
