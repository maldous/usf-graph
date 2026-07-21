"""Provider coverage (evaluate-providers), roster consumption, CLI cwd isolation,
and --shadow-packets."""

from __future__ import annotations

import asyncio

import pytest

from conftest import all_dimension_scores
from usf_factory.enums import AdmissionRole
from usf_factory.provider_eval import EvalAuth, evaluate_all_providers, grade_evaluation

# ---- §4 coverage: every configured provider gets exactly one row ------------ #


class _EvalAdapter:
    def __init__(self, provider_id, cfg=None):
        self.provider_id = provider_id

    def capabilities(self):
        from usf_factory.capabilities import AdapterCapabilities

        return AdapterCapabilities(
            plain_invoke=True, structured_output=True, bounded_patch_synthesis=True
        )

    async def invoke(self, req):
        from usf_factory.models import AgentResponse, TokenUsage

        good = (
            '{"authority_answer":"OPEN",'
            '"preserved_iri":"https://example.org/usf#Rule_A1",'
            '"preserved_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",'
            '"consolidated_obligations":["fix rule R","validate R"],'
            '"write_scope":["rules/example.ttl"],'
            '"validation_obligations":["regenerate + validate","add negative test"],'
            '"uncertainty":"owner cannot be established; human decision needed"}'
        )
        return AgentResponse(
            agent_profile_id=req.agent_profile_id,
            output_text=good,
            actual_provider=self.provider_id,
            actual_model=req.requested_model_id,
            usage=TokenUsage(
                input_tokens=200, output_tokens=120, actual_model=req.requested_model_id
            ),
        )


@pytest.fixture
def eval_env(ctx, monkeypatch):
    import usf_factory.providers as providers

    class _Reg:
        def adapter(self, pid):
            return _EvalAdapter(pid)

    monkeypatch.setattr(providers, "build_registry", lambda ctx, allow_billable=False: _Reg())
    # Seed a free model for each enabled API provider so representative selection works.
    for cfg in ctx.config.providers.providers:
        if cfg.default_enabled and cfg.auth_mode.value == "api_token":
            ctx.store.put(
                "models",
                f"m-{cfg.provider_id}",
                {"provider_id": cfg.provider_id, "requested_model_id": "free-x", "free": True},
                extra={"provider_id": cfg.provider_id},
            )
    return ctx


@pytest.mark.e2e
def test_every_configured_provider_gets_exactly_one_row(eval_env):
    ctx = eval_env
    evals = asyncio.run(
        evaluate_all_providers(
            ctx, EvalAuth(allow_inference=True, allow_subscription_inference=True), concurrency=4
        )
    )
    configured = {c.provider_id for c in ctx.config.providers.providers}
    rows = [e.provider_id for e in evals]
    assert set(rows) == configured  # one row per configured provider
    assert len(rows) == len(configured) == len(set(rows))  # exactly one each


@pytest.mark.unit
def test_disabled_provider_is_disabled_by_config(eval_env):
    ctx = eval_env
    evals = asyncio.run(evaluate_all_providers(ctx, EvalAuth(allow_inference=True)))
    by = {e.provider_id: e for e in evals}
    disabled = [c.provider_id for c in ctx.config.providers.providers if not c.default_enabled]
    for pid in disabled:
        assert by[pid].status == "DISABLED_BY_CONFIG"


@pytest.mark.adversarial
def test_paid_only_never_invoked_without_paid_auth(ctx, monkeypatch):
    import usf_factory.providers as providers

    invoked = {"n": 0}

    class _Reg:
        def adapter(self, pid):
            ad = _EvalAdapter(pid)
            orig = ad.invoke

            async def counting(req):
                invoked["n"] += 1
                return await orig(req)

            ad.invoke = counting
            return ad

    monkeypatch.setattr(providers, "build_registry", lambda ctx, allow_billable=False: _Reg())
    # A paid model only (no free) for an enabled api provider.
    cfg = next(
        c
        for c in ctx.config.providers.providers
        if c.default_enabled and c.auth_mode.value == "api_token"
    )
    ctx.store.put(
        "models",
        "paid1",
        {
            "provider_id": cfg.provider_id,
            "requested_model_id": "paid-x",
            "free": False,
            "prompt_cost_per_mtok": 10.0,
            "output_cost_per_mtok": 30.0,
        },
        extra={"provider_id": cfg.provider_id},
    )
    import usf_factory.provider_eval as pe2

    ev = asyncio.run(
        pe2.evaluate_provider(ctx, cfg, EvalAuth(allow_inference=True, max_cost_usd=0.0))
    )
    assert ev.status == "PAID_INFERENCE_NOT_AUTHORIZED"
    assert invoked["n"] == 0  # never called


@pytest.mark.adversarial
def test_free_external_evaluated_without_paid_and_no_paid_spend(eval_env):
    ctx = eval_env
    cfg = next(
        c
        for c in ctx.config.providers.providers
        if c.default_enabled and c.auth_mode.value == "api_token"
    )
    ev = asyncio.run(
        __import__("usf_factory.provider_eval", fromlist=["evaluate_provider"]).evaluate_provider(
            ctx, cfg, EvalAuth(allow_inference=True, max_cost_usd=0.0)
        )
    )
    assert ev.status == "EVALUATED"
    assert ev.paid_api_spend_usd == 0.0  # free => no paid spend


@pytest.mark.unit
def test_subscription_value_not_against_paid_budget(ctx, monkeypatch):
    import usf_factory.providers as providers

    class _SubAdapter(_EvalAdapter):
        async def invoke(self, req):
            r = await super().invoke(req)
            return r.model_copy(
                update={"usage": r.usage.model_copy(update={"provider_reported_cost": 0.06})}
            )

    class _Reg:
        def adapter(self, pid):
            return _SubAdapter(pid)

    monkeypatch.setattr(providers, "build_registry", lambda ctx, allow_billable=False: _Reg())
    cfg = next(c for c in ctx.config.providers.providers if c.auth_mode.value == "oidc_cli")
    ev = asyncio.run(
        __import__("usf_factory.provider_eval", fromlist=["evaluate_provider"]).evaluate_provider(
            ctx,
            cfg,
            EvalAuth(allow_inference=True, allow_subscription_inference=True, max_cost_usd=0.0),
        )
    )
    assert ev.status == "EVALUATED"
    assert ev.paid_api_spend_usd == 0.0  # subscription cost never hits the paid budget
    assert ev.subscription_reported_value_usd == 0.06  # recorded informationally


@pytest.mark.unit
def test_grade_evaluation_rewards_correct_answer():
    good = (
        '{"authority_answer":"OPEN","preserved_iri":"https://example.org/usf#Rule_A1",'
        '"preserved_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",'
        '"consolidated_obligations":["a","b"],"write_scope":["rules/example.ttl"],'
        '"validation_obligations":["regenerate and validate","negative test"],'
        '"uncertainty":"cannot be established"}'
    )
    s = grade_evaluation(good)
    assert s["semantic_rule_fidelity"] == 1.0 and s["scope_discipline"] == 1.0
    assert s["uncertainty_handling"] == 1.0 and s["structured_output"] == 1.0
    # A wrong authority answer + generated-file edit tanks fidelity/scope.
    bad = grade_evaluation('{"authority_answer":"CLOSED","write_scope":["generated/example.json"]}')
    assert bad["semantic_rule_fidelity"] < 1.0 and bad["scope_discipline"] == 0.0


# ---- §8 roster consumed by runtime; §9 shadow cap --------------------------- #


@pytest.mark.e2e
def test_runtime_consumes_active_roster_not_first_found(ctx, tmp_usf):
    from usf_factory.admission import admit_from_evidence, ensure_profile, record_qualification
    from usf_factory.models import QualificationRun
    from usf_factory.roster import build_roster, persist_active, roster_profile_for

    # Two admitted planners; the roster must pick deterministically, and the
    # runtime must consult the roster (not storage order).
    for prov, model in [("ollama", "m-a"), ("ollama", "m-b")]:
        p = ensure_profile(ctx, prov, model)
        record_qualification(
            ctx,
            QualificationRun(
                run_id=f"q-{model}",
                agent_profile_id=p.profile_id,
                suite_id="t",
                suite_version="v1",
                config_digest=p.digest(),
                dimension_scores=all_dimension_scores(),
            ),
        )
        admit_from_evidence(ctx, p.profile_id)
    persist_active(ctx, build_roster(ctx))
    chosen = roster_profile_for(ctx, AdmissionRole.PLANNER_CANDIDATE)
    assert chosen is not None
    entry = ctx.store.get("role_rosters", "active")["entries"]["PLANNER_CANDIDATE"]
    assert chosen.profile_id == entry["primary"]  # runtime uses the roster's pick


@pytest.mark.unit
def test_shadow_packets_caps_dispatch(ctx):
    """The engine caps shadow dispatch to --shadow-packets deterministically."""
    from usf_factory.engine import FactoryEngine
    from usf_factory.enums import RunMode
    from usf_factory.models import Packet, PacketSet

    eng = FactoryEngine(ctx, max_shadow_packets=1)
    pkts = [
        Packet(
            obligation_id=f"o{i}",
            snapshot_id="s",
            authority_digest="a",
            base_head="h",
            objective="x",
            task_class="semantic-planning",
        )
        for i in range(3)
    ]
    pset = PacketSet(
        snapshot_id="s", graph_id="g", packets=pkts, selected_packet_ids=[p.packet_id for p in pkts]
    )
    dispatched = {"n": 0}

    async def fake_one(packet, cycle_id, mode):
        dispatched["n"] += 1
        return None

    eng._execute_one = fake_one  # type: ignore[assignment]
    asyncio.run(eng.execute_packets(pset, RunMode.SHADOW, "cyc"))
    assert dispatched["n"] == 1  # capped from 3 -> 1


@pytest.mark.adversarial
def test_cli_runs_from_scratch_cwd_not_repo(monkeypatch):
    """The CLI adapter must run from a fresh temp scratch dir, never the repo."""
    import usf_factory.providers.cli_adapters as cli
    from usf_factory.enums import AuthMode
    from usf_factory.models import ProviderConfig
    from usf_factory.providers.cli_adapters import ClaudeCliAdapter

    seen = {}

    async def fake_run(cmd, timeout_s=10.0, stdin=None, cwd=None):
        seen["cwd"] = cwd
        return (0, '{"type":"result","result":"ok"}', "")

    monkeypatch.setattr(cli, "_run", fake_run)
    ad = ClaudeCliAdapter(
        ProviderConfig(
            provider_id="claude-cli",
            display_name="c",
            auth_mode=AuthMode.OIDC_CLI,
            adapter="claude_cli",
        ),
        allow_billable=True,
    )
    monkeypatch.setattr(ad, "_binary_path", lambda: "/usr/bin/claude")
    from usf_factory.probes import default_probe_specs

    asyncio.run(ad.probe_model("default", default_probe_specs()[0]))
    assert seen["cwd"] is not None  # a scratch dir was set
    assert "usf-cli-" in seen["cwd"]  # the temp scratch prefix, not the repo


# ---- §2 CLI first-class worker: model resolution + classification ----------- #


def _claude(monkeypatch, cli):
    from usf_factory.enums import AuthMode
    from usf_factory.models import ProviderConfig
    from usf_factory.providers.cli_adapters import ClaudeCliAdapter

    ad = ClaudeCliAdapter(
        ProviderConfig(
            provider_id="claude-cli",
            display_name="c",
            auth_mode=AuthMode.OIDC_CLI,
            adapter="claude_cli",
        ),
        allow_billable=True,
    )
    monkeypatch.setattr(ad, "_binary_path", lambda: "/usr/bin/claude")
    return ad


@pytest.mark.adversarial
def test_cli_model_rejection_retries_default_exactly_once(monkeypatch):
    """An explicit model rejection triggers ONE retry with the account default —
    no model-id cycling — and the fallback is recorded on usage."""
    import usf_factory.providers.cli_adapters as cli

    calls = []

    async def fake_run(cmd, timeout_s=10.0, stdin=None, cwd=None):
        calls.append(cmd)
        if "--model" in cmd:  # requested id rejected by the CLI
            return (1, "", "invalid model: no such model")
        return (
            0,
            '{"result":"ok","usage":{"input_tokens":5,"output_tokens":3},'
            '"modelUsage":{"claude-default":{"outputTokens":3}}}',
            "",
        )

    monkeypatch.setattr(cli, "_run", fake_run)
    ad = _claude(monkeypatch, cli)
    text, usage, quota, err = asyncio.run(ad._exec("claude-made-up", "hi", timeout_s=5.0))
    assert text == "ok" and not quota
    assert usage.requested_model == "claude-made-up"
    assert usage.fell_back_to_default is True
    assert usage.actual_model == "claude-default" and usage.actual_model_verified is True
    assert len(calls) == 2  # exactly one retry, not a cycle


@pytest.mark.adversarial
def test_cli_unreported_actual_model_is_unverified(monkeypatch):
    """If the CLI never reports which model ran, actual_model stays UNVERIFIED —
    never silently equated with the requested id."""
    import usf_factory.providers.cli_adapters as cli

    async def fake_run(cmd, timeout_s=10.0, stdin=None, cwd=None):
        return (0, '{"result":"ok"}', "")  # no modelUsage block

    monkeypatch.setattr(cli, "_run", fake_run)
    ad = _claude(monkeypatch, cli)
    _text, usage, _quota, _err = asyncio.run(ad._exec("default", "hi", timeout_s=5.0))
    assert usage.actual_model is None and usage.actual_model_verified is False


@pytest.mark.adversarial
def test_cli_quota_blocked_classified_not_quality(monkeypatch):
    """A usage-limit response is classified QUOTA_BLOCKED (invoke raises), never a
    model-quality failure."""
    import usf_factory.providers.cli_adapters as cli
    from usf_factory.models import AgentRequest
    from usf_factory.providers.base import AdapterError

    async def fake_run(cmd, timeout_s=10.0, stdin=None, cwd=None):
        return (1, '{"is_error":true,"api_error_status":"429 usage limit"}', "usage limit reached")

    monkeypatch.setattr(cli, "_run", fake_run)
    ad = _claude(monkeypatch, cli)
    _t, _u, quota, _e = asyncio.run(ad._exec("default", "hi", timeout_s=5.0))
    assert quota is True
    with pytest.raises(AdapterError, match="QUOTA_BLOCKED"):
        asyncio.run(
            ad.invoke(
                AgentRequest(
                    agent_profile_id="a",
                    packet_id="p",
                    provider_id="claude-cli",
                    requested_model_id="default",
                    instructions="hi",
                )
            )
        )


@pytest.mark.adversarial
def test_cli_env_sanitized_withholds_provider_keys(monkeypatch):
    """The subprocess env forwards only safe vars; provider API keys are withheld
    so an OIDC CLI never inherits credentials it must not see."""
    from usf_factory.providers.cli_adapters import _sanitized_env

    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret2")
    env = _sanitized_env()
    assert env.get("PATH") == "/usr/bin"
    assert "OPENAI_API_KEY" not in env and "ANTHROPIC_API_KEY" not in env


@pytest.mark.adversarial
def test_claude_cli_prompt_via_stdin_not_positional(monkeypatch):
    """The prompt must be delivered on stdin, never as a trailing positional arg:
    --disallowed-tools is variadic and would swallow a positional prompt, leaving
    the CLI with no input (the live-run OUTPUT_INVALID regression)."""
    import usf_factory.providers.cli_adapters as cli

    seen = {}

    async def fake_run(cmd, timeout_s=10.0, stdin=None, cwd=None):
        seen["cmd"] = cmd
        seen["stdin"] = stdin
        return (0, '{"result":"ok"}', "")

    monkeypatch.setattr(cli, "_run", fake_run)
    ad = _claude(monkeypatch, cli)
    asyncio.run(ad._exec("default", "THE-PROMPT-TEXT", timeout_s=5.0))
    assert seen["stdin"] == "THE-PROMPT-TEXT"  # prompt on stdin
    assert "THE-PROMPT-TEXT" not in seen["cmd"]  # never a positional arg


@pytest.mark.adversarial
def test_free_model_invoked_billable_and_recorded_as_free_cost(ctx, monkeypatch):
    """A genuinely free API model is invoked (registry built allow_billable=True)
    with a $0 paid budget; any reported cost lands on free_inference_cost_usd, not
    the paid budget."""
    import usf_factory.provider_eval as pe
    import usf_factory.providers as providers

    seen = {}

    class _FreeAdapter(_EvalAdapter):
        async def invoke(self, req):
            r = await super().invoke(req)
            return r.model_copy(
                update={"usage": r.usage.model_copy(update={"provider_reported_cost": 0.0})}
            )

    class _Reg:
        def adapter(self, pid):
            return _FreeAdapter(pid)

    def _build(ctx, allow_billable=False):
        seen["allow_billable"] = allow_billable
        return _Reg()

    monkeypatch.setattr(providers, "build_registry", _build)
    cfg = next(
        c
        for c in ctx.config.providers.providers
        if c.default_enabled and c.auth_mode.value == "api_token"
    )
    ctx.store.put(
        "models",
        "free1",
        {"provider_id": cfg.provider_id, "requested_model_id": "x:free", "free": True},
        extra={"provider_id": cfg.provider_id},
    )
    ev = asyncio.run(
        pe.evaluate_provider(ctx, cfg, EvalAuth(allow_inference=True, max_cost_usd=0.0))
    )
    assert ev.status == "EVALUATED"
    assert seen["allow_billable"] is True  # free inference is permitted to run
    assert ev.paid_api_spend_usd == 0.0  # never against the paid budget
