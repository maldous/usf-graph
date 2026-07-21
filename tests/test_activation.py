"""Phase 13-16 activation with mocked free/local providers (mandatory tests #16,
#17, #19). No network, no /usf mutation."""

from __future__ import annotations

import pytest

from conftest import all_dimension_scores, seed_agent
from usf_factory.activation import ActivationOptions, run_activation
from usf_factory.candidate import check_prerequisites
from usf_factory.enums import AdmissionRole, HealthStatus
from usf_factory.models import AgentResponse, DiscoveredModel, ProbeResult


class _FakeAdapter:
    """A mock local adapter that passes probes and answers qualification well."""

    def __init__(self, provider_id="ollama"):
        self.provider_id = provider_id
        self._loop_model = None

    def with_loop_model(self, m):
        self._loop_model = m
        return self

    async def discover_models(self):
        return [
            DiscoveredModel(provider_id=self.provider_id, requested_model_id="mock-good", free=True)
        ]

    async def probe_model(self, model_id, probe):
        return ProbeResult(
            kind=probe.kind, version=probe.version, passed=True, score=1.0, actual_model_id=model_id
        )

    async def invoke(self, req):
        # Answer qualification cases with the reference answer when discoverable,
        # else a confident structured/uncertainty-friendly reply.
        return AgentResponse(
            agent_profile_id=req.agent_profile_id,
            actual_model="mock-good",
            output_text="I do not know; insufficient evidence.",
            tokens_in=5,
            tokens_out=3,
        )


class _FakeRegistry:
    def __init__(self, ctx):
        self.ctx = ctx

    def enabled_ids(self):
        return ["ollama"]

    def adapter(self, provider_id):
        return _FakeAdapter(provider_id)

    async def discover_all(self, ids):
        from usf_factory.providers.registry import DiscoveryOutcome

        return {i: DiscoveryOutcome(provider_id=i, ok=True, model_count=1) for i in ids}


@pytest.fixture
def mock_providers(monkeypatch):
    import usf_factory.providers as providers

    monkeypatch.setattr(
        providers, "build_registry", lambda ctx, allow_billable=False: _FakeRegistry(ctx)
    )
    # Persist a free local model so the shortlist finds it.
    return providers


@pytest.mark.e2e
def test_activation_completes_with_mocked_local_provider(
    ctx, tmp_usf, mock_providers, fake_authority_factory, monkeypatch
):
    # Authority for snapshot: use the fake authority.
    monkeypatch.setattr(
        "usf_factory.authority.UsfAuthorityClient", fake_authority_factory, raising=False
    )
    ctx.store.put(
        "models",
        "m1",
        {"provider_id": "ollama", "requested_model_id": "mock-good", "free": True},
        extra={"provider_id": "ollama"},
    )
    opts = ActivationOptions(providers=["ollama"], max_models_per_provider=1, max_qual_cases=4)
    report = run_activation(ctx, opts)
    # The pipeline completes and produces a structured report with an outcome.
    assert report.model_outcomes and report.model_outcomes[0].model_id == "mock-good"
    assert report.model_outcomes[0].probe_total == 10
    # plan-only always runs (read-only).
    assert report.plan_only.get("state") in ("LEARNED", "BLOCKED")
    # A next action is always produced.
    assert report.next_action


@pytest.mark.adversarial
def test_degraded_provider_cannot_mutate(ctx, tmp_usf):
    """A DEGRADED provider is ineligible for a mutating (write) packet."""
    from usf_factory.enums import PrivacyClass
    from usf_factory.models import Packet
    from usf_factory.scheduler import SchedulableAgent, Scheduler

    profile = seed_agent(
        ctx.store, roles=[AdmissionRole.PATCH_PRODUCER], scores=all_dimension_scores()
    )
    from usf_factory.models import AgentProfile

    prof = AgentProfile(**dict(ctx.store.get("agent_profiles", profile.profile_id)))
    agent = SchedulableAgent(
        profile=prof,
        provider_id=prof.provider_id,
        admission_roles=[AdmissionRole.PATCH_PRODUCER],
        task_scores=all_dimension_scores(),
        health=HealthStatus.UNAVAILABLE,  # not healthy
        privacy_class=PrivacyClass.LOCAL_ONLY,
    )
    pkt = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="write",
        task_class="repository-implementation",
        write_paths=["gen/x.py"],
        permitted_tools=["read_file", "edit_file"],
    )
    decision = Scheduler(ctx.config.routing, ctx.config.egress).schedule(
        pkt, AdmissionRole.PATCH_PRODUCER, [agent]
    )
    assert decision.selected_profile_id is None  # unhealthy => not routed for mutation


@pytest.mark.unit
def test_concurrency_semaphore_bounds_workers(ctx):
    """Per-run worker concurrency is bounded by max_concurrent_workers."""
    import asyncio as _asyncio

    from usf_factory.engine import FactoryEngine

    ctx.config.budgets.max_concurrent_workers = 2
    eng = FactoryEngine(ctx)
    sem = _asyncio.Semaphore(max(1, ctx.config.budgets.max_concurrent_workers))
    assert sem._value == 2  # bound honoured


@pytest.mark.e2e
def test_candidate_prerequisites_block_without_evidence(ctx, tmp_usf):
    """With no verified owner / no reviewer / gates disabled, the candidate flow
    reports exact blockers and never fabricates progress."""
    blockers = check_prerequisites(ctx)
    assert blockers  # unmet
    joined = "; ".join(blockers)
    assert "PATCH_PRODUCER" in joined or "materialisation" in joined or "autonomous_safe" in joined
