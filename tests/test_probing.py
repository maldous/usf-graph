"""Genuine probing (Phase 3) + immutable qualification (Phase 4).

Uses a deterministic in-process fake adapter (no network) so the probe path,
budget gating, and immutability are proven without a live model."""

from __future__ import annotations

import asyncio

import pytest

from usf_factory.admission import ensure_profile
from usf_factory.enums import ProbeKind
from usf_factory.errors import ProtectedActionError
from usf_factory.models import ProbeResult
from usf_factory.probing import InferenceAuthorization, run_probe_suite


class _FakeAdapter:
    """Grades every probe as passing with a recorded actual model + one call."""

    def __init__(self, calls):
        self._calls = calls

    async def probe_model(self, model_id, probe):
        self._calls.append(model_id)
        return ProbeResult(
            kind=probe.kind,
            version=probe.version,
            passed=True,
            score=1.0,
            detail="ok",
            actual_model_id="actual-" + model_id,
        )


def _patch_registry(monkeypatch, calls):
    import usf_factory.providers as providers

    class _Reg:
        def adapter(self, provider_id):
            return _FakeAdapter(calls)

    monkeypatch.setattr(providers, "build_registry", lambda ctx, allow_billable=False: _Reg())


@pytest.mark.contract
def test_probe_runs_real_invocation_and_grades(ctx, monkeypatch):
    """models probe invokes the model per probe and records graded results."""
    calls: list[str] = []
    _patch_registry(monkeypatch, calls)
    # A free/local-style profile.
    profile = ensure_profile(ctx, "ollama", "test-model")
    run = asyncio.run(
        run_probe_suite(ctx, profile, auth=InferenceAuthorization(allow_inference=True))
    )
    assert run.total == 10 and run.passed == 10
    assert len(calls) == 10  # one genuine invocation per probe
    assert run.actual_models == ["actual-test-model"]
    # Persisted immutably under its own run_id.
    stored = ctx.store.get("probe_runs", run.run_id)
    assert stored and stored["agent_profile_id"] == profile.profile_id


@pytest.mark.adversarial
def test_probe_requires_inference_authorization(ctx, monkeypatch):
    calls: list[str] = []
    _patch_registry(monkeypatch, calls)
    profile = ensure_profile(ctx, "ollama", "test-model")
    # No --allow-inference => refused, nothing invoked, nothing stored.
    with pytest.raises(ProtectedActionError):
        asyncio.run(run_probe_suite(ctx, profile, auth=InferenceAuthorization()))
    assert calls == []
    assert ctx.store.records("probe_runs", "agent_profile_id=?", (profile.profile_id,)) == []


@pytest.mark.adversarial
def test_paid_probe_budget_cannot_be_exceeded(ctx, monkeypatch):
    """A paid model with a priced catalogue row is refused when the estimate
    exceeds --max-cost-usd (budget cannot be exceeded)."""
    calls: list[str] = []
    _patch_registry(monkeypatch, calls)
    profile = ensure_profile(ctx, "openrouter", "expensive-model")
    ctx.store.put(
        "models",
        "m1",
        {
            "provider_id": "openrouter",
            "requested_model_id": "expensive-model",
            "prompt_cost_per_mtok": 100.0,
            "output_cost_per_mtok": 100.0,
            "free": False,
        },
        extra={"provider_id": "openrouter"},
    )
    auth = InferenceAuthorization(
        allow_inference=True, allow_paid_inference=True, max_cost_usd=0.001
    )
    with pytest.raises(ProtectedActionError):
        asyncio.run(run_probe_suite(ctx, profile, auth=auth))
    assert calls == []  # never invoked


@pytest.mark.unit
def test_probe_gates_require_structural_probes():
    from usf_factory.models import ProbeRun
    from usf_factory.probing import probe_gates_pass

    def _r(kind, passed):
        return ProbeResult(kind=kind, version="v1", passed=passed)

    ok = ProbeRun(
        run_id="p1",
        agent_profile_id="a",
        provider_id="ollama",
        requested_model_id="m",
        adapter_id="ollama",
        results=[
            _r(ProbeKind.IRI_PRESERVATION, True),
            _r(ProbeKind.DIGEST_PRESERVATION, True),
            _r(ProbeKind.STRICT_JSON, True),
            _r(ProbeKind.STOP_CONDITION, True),
        ],
    )
    assert probe_gates_pass(ok) is True
    bad = ok.model_copy(update={"results": [_r(ProbeKind.IRI_PRESERVATION, False)]})
    assert probe_gates_pass(bad) is False


@pytest.mark.e2e
def test_qualification_history_is_immutable(ctx, monkeypatch):
    """Two live qualifications of the same profile create two distinct immutable
    runs; neither overwrites the other."""
    from usf_factory.admission import qualify_live

    class _QAdapter:
        async def invoke(self, req):
            from usf_factory.models import AgentResponse

            return AgentResponse(
                agent_profile_id=req.agent_profile_id,
                actual_model="actual-m",
                output_text="I do not know; insufficient evidence.",
                tokens_in=5,
                tokens_out=3,
            )

    import usf_factory.providers as providers

    class _Reg:
        def adapter(self, provider_id):
            return _QAdapter()

    monkeypatch.setattr(providers, "build_registry", lambda ctx, allow_billable=False: _Reg())
    profile = ensure_profile(ctx, "ollama", "test-model")
    auth = InferenceAuthorization(allow_inference=True)
    r1 = asyncio.run(qualify_live(ctx, profile, auth=auth))
    r2 = asyncio.run(qualify_live(ctx, profile, auth=auth))
    assert r1.run_id != r2.run_id
    rows = ctx.store.records("qualification_runs", "agent_profile_id=?", (profile.profile_id,))
    assert len(rows) == 2  # both retained; nothing overwritten
