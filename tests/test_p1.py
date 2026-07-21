"""P1: concurrency, per-provider egress, calibrated learning, delivery,
provider normalizers, native Anthropic adapter, CAS GC."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from conftest import FakeAuthority
from usf_factory.config import load_config
from usf_factory.delivery import prepare_delivery
from usf_factory.engine import FactoryEngine
from usf_factory.enums import (
    AdmissionRole,
    AuthMode,
    PrivacyClass,
    RunMode,
)
from usf_factory.event_store import open_store
from usf_factory.learning import LearningEngine
from usf_factory.models import (
    AgentProfile,
    AgentRequest,
    Packet,
    ProviderConfig,
    RequiredCapabilities,
    ValidationReceipt,
    WavePatch,
)
from usf_factory.providers.anthropic import AnthropicAdapter
from usf_factory.providers.openai_compatible import OpenAICompatibleAdapter
from usf_factory.scheduler import SchedulableAgent, Scheduler

# ---- P1-14 concurrency ---- #


@pytest.mark.e2e
def test_concurrent_execution_runs_all_packets(ctx, tmp_usf):
    items = [{"id": f"O{i}", "title": f"indep {i}", "dependencies": []} for i in range(4)]
    eng = FactoryEngine(ctx, authority_factory=lambda: FakeAuthority(work_plan_items=items))
    receipt = asyncio.run(eng.run_cycle(RunMode.PLAN_ONLY))
    # 4 independent obligations -> 4 packets selected and executed (bounded by
    # max_concurrent_workers but all complete).
    assert receipt.selected_packets == 4
    assert ctx.store.count("packet_results") == 4


# ---- P1-19 per-provider egress ---- #


def _packet(data, provider_write=True):
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="repository-implementation",
        data_classification=data,
        write_paths=["a.py"] if provider_write else [],
        permitted_tools=["read_file"],
        required_capabilities=RequiredCapabilities(structured_output=0.8, repository_editing=True),
    )


def _agent(pid, privacy):
    prof = AgentProfile(
        provider_id=pid,
        requested_model_id="m",
        adapter="openai_compatible",
        auth_mode=AuthMode.API_TOKEN,
    )
    return SchedulableAgent(
        profile=prof,
        provider_id=pid,
        admission_roles=[AdmissionRole.PATCH_PRODUCER],
        task_scores={"structured_output": 0.9, "implementation": 0.9},
        privacy_class=privacy,
    )


@pytest.mark.unit
def test_private_source_requires_provider_approval():
    cfg = load_config()
    cfg.egress.source_egress_enabled = True  # global gate on, but per-provider still required
    sched = Scheduler(cfg.routing, cfg.egress)
    d = sched.schedule(
        _packet("private-source"),
        AdmissionRole.PATCH_PRODUCER,
        [_agent("groq", PrivacyClass.EXTERNAL_CLOUD)],
    )
    assert d.selected_profile_id is None
    assert any("not approved" in r for c in d.candidates for r in c.exclusion_reasons)


@pytest.mark.unit
def test_provider_approval_allows_private_source():
    cfg = load_config()
    cfg.egress.source_egress_enabled = True
    cfg.egress.provider_overrides = {"groq": ["private-source"]}
    sched = Scheduler(cfg.routing, cfg.egress)
    d = sched.schedule(
        _packet("private-source"),
        AdmissionRole.PATCH_PRODUCER,
        [_agent("groq", PrivacyClass.EXTERNAL_CLOUD)],
    )
    assert d.selected_profile_id is not None


# ---- P1-20 calibrated learning ---- #


@pytest.mark.unit
def test_beta_estimate_from_raw_observations(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    le = LearningEngine(st)
    for _ in range(8):
        le.observe("worker", "agentX", "shacl-repair", "implementation", 1.0)
    for _ in range(2):
        le.observe("worker", "agentX", "shacl-repair", "implementation", 0.0)
    mean, lo, hi, n = le.beta_estimate("agentX", "shacl-repair", "implementation")
    assert n == 10
    assert 0.7 < mean < 0.9  # ~ (0.5+8)/(1+10)
    assert lo < mean < hi
    # Raw observations are retained immutably.
    assert st.count("observations") == 10
    st.close()


# ---- P1-22 delivery handshake ---- #


@pytest.mark.e2e
def test_delivery_is_prepare_only_and_gated(ctx, tmp_usf, fake_authority_factory):
    eng = FactoryEngine(ctx, authority_factory=fake_authority_factory)
    eng.preflight("adhoc")
    snap = eng.capture_snapshot("adhoc")
    wave = WavePatch(
        set_id="s1",
        patch_digest="sha256:" + "0" * 64,
        patch_ref="cas:sha256:" + "0" * 64,
        changed_paths=["semantic/x.ttl"],
    )
    passed = ValidationReceipt(set_id="s1", gates={"shacl": True}, all_passed=True)
    # Gate disabled by default -> not prepared.
    art = prepare_delivery(ctx, wave, snap, passed)
    assert art.prepared is False and art.gate_enabled is False
    # Enable the gate -> prepared but never pushed.
    ctx.config.safety.allow_push_pr = True
    art2 = prepare_delivery(ctx, wave, snap, passed)
    assert art2.prepared is True
    assert art2.branch and art2.branch.startswith("usf-factory/wave-")
    assert "authorized USF publication" in art2.pr_body
    # Failed validation withholds delivery even when gated.
    failed = ValidationReceipt(set_id="s1", gates={"shacl": False}, all_passed=False)
    assert prepare_delivery(ctx, wave, snap, failed).prepared is False


# ---- P1-16 provider normalizers + native Anthropic ---- #


@pytest.mark.contract
def test_openrouter_normalizer_captures_supported_parameters():
    cfg = ProviderConfig(
        provider_id="openrouter",
        display_name="OR",
        auth_mode=AuthMode.API_TOKEN,
        adapter="openai_compatible",
        base_url="https://openrouter.ai/api/v1",
        models_endpoint="/models",
        privacy_class=PrivacyClass.EXTERNAL_CLOUD,
    )

    def handler(request):
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "vendor/model:free",
                        "name": "Vendor Model",
                        "context_length": 131072,
                        "supported_parameters": ["tools", "reasoning", "structured_outputs"],
                        "top_provider": {"max_completion_tokens": 8192},
                        "pricing": {"prompt": "0", "completion": "0"},
                    }
                ]
            },
        )

    adapter = OpenAICompatibleAdapter(cfg, token="t", transport=httpx.MockTransport(handler))
    models = asyncio.run(adapter.discover_models())
    m = models[0]
    assert m.claims_tools and m.claims_reasoning and m.claims_structured_output
    assert m.context_tokens == 131072 and m.output_tokens == 8192 and m.free is True
    assert "tools" in m.supported_parameters


@pytest.mark.contract
def test_anthropic_adapter_native_messages():
    cfg = ProviderConfig(
        provider_id="anthropic-api",
        display_name="A",
        auth_mode=AuthMode.API_TOKEN,
        adapter="anthropic",
        base_url="https://api.anthropic.com/v1",
        privacy_class=PrivacyClass.EXTERNAL_CLOUD,
    )
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["hdr"] = request.headers.get("x-api-key")
        seen["ver"] = request.headers.get("anthropic-version")
        return httpx.Response(
            200,
            json={
                "model": "claude-sonnet-5",
                "content": [{"type": "text", "text": "hi"}],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    adapter = AnthropicAdapter(
        cfg, token="sk-ant", allow_billable=True, transport=httpx.MockTransport(handler)
    )
    resp = asyncio.run(
        adapter.invoke(
            AgentRequest(
                agent_profile_id="a",
                packet_id="p",
                instructions="hi",
                requested_model_id="claude-sonnet-5",
            )
        )
    )
    assert resp.output_text == "hi"
    assert seen["path"].endswith("/messages") and seen["hdr"] == "sk-ant" and seen["ver"]


# ---- P1-21 CAS GC ---- #


@pytest.mark.unit
def test_cas_gc_removes_unreferenced(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    kept = st.cas_put_text("referenced blob")
    st.cas_put_text("orphan blob")  # not referenced anywhere
    # Reference `kept` from a record payload.
    st.put("wave_patches", "w1", {"patch_ref": kept}, extra={"set_id": "s1"})
    removed = st.cas_gc()
    assert removed == 1
    assert st.cas_has(kept)
    st.close()
