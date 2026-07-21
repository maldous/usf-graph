"""Contract tests: OpenAI-compatible discovery, routed actual-model receipt,
Ollama adapter, USF MCP STDIO client, git mirror isolation."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
import pytest

from usf_factory.authority import AuthorityError, UsfAuthorityClient
from usf_factory.enums import AuthMode, HealthStatus, PrivacyClass
from usf_factory.models import ProviderConfig
from usf_factory.providers.ollama import OllamaAdapter
from usf_factory.providers.openai_compatible import OpenAICompatibleAdapter

STUB = Path(__file__).parent / "stub_mcp_server.py"


def _openai_cfg():
    return ProviderConfig(
        provider_id="openrouter",
        display_name="OR",
        auth_mode=AuthMode.API_TOKEN,
        adapter="openai_compatible",
        base_url="https://openrouter.ai/api/v1",
        models_endpoint="/models",
        privacy_class=PrivacyClass.EXTERNAL_CLOUD,
    )


@pytest.mark.contract
def test_openai_compatible_discovery_parses_models():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models")
        return httpx.Response(
            200, json={"data": [{"id": "m1"}, {"id": "m2", "context_length": 8192}]}
        )

    adapter = OpenAICompatibleAdapter(
        _openai_cfg(), token="t", transport=httpx.MockTransport(handler)
    )
    models = asyncio.run(adapter.discover_models())
    assert {m.requested_model_id for m in models} == {"m1", "m2"}
    assert next(m for m in models if m.requested_model_id == "m2").context_tokens == 8192


@pytest.mark.contract
def test_routed_provider_records_actual_model():
    def handler(request: httpx.Request) -> httpx.Response:
        # Router asked for 'auto' but returns a concrete model.
        return httpx.Response(
            200,
            json={
                "model": "vendor/concrete-model",
                "choices": [{"message": {"content": "hi"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    cfg = _openai_cfg()
    adapter = OpenAICompatibleAdapter(
        cfg, token="t", allow_billable=True, transport=httpx.MockTransport(handler)
    )
    from usf_factory.models import AgentRequest

    resp = asyncio.run(
        adapter.invoke(
            AgentRequest(agent_profile_id="openrouter:auto", packet_id="p", instructions="hi")
        )
    )
    assert resp.actual_model == "vendor/concrete-model"  # requested != actual


@pytest.mark.contract
def test_billable_disabled_refuses_invoke():
    adapter = OpenAICompatibleAdapter(_openai_cfg(), token="t", allow_billable=False)
    from usf_factory.models import AgentRequest

    with pytest.raises(Exception):
        asyncio.run(
            adapter.invoke(
                AgentRequest(agent_profile_id="openrouter:m", packet_id="p", instructions="x")
            )
        )


@pytest.mark.contract
def test_auth_probe_maps_status_codes():
    def unauthorized(request):
        return httpx.Response(401, json={"error": "no"})

    adapter = OpenAICompatibleAdapter(
        _openai_cfg(), token=None, transport=httpx.MockTransport(unauthorized)
    )
    health = asyncio.run(adapter.probe_auth())
    assert health.status is HealthStatus.UNAUTHENTICATED


@pytest.mark.contract
def test_ollama_discovery():
    def handler(request):
        return httpx.Response(
            200, json={"models": [{"name": "llama3.2:latest", "details": {"family": "llama"}}]}
        )

    cfg = ProviderConfig(
        provider_id="ollama",
        display_name="O",
        auth_mode=AuthMode.LOCAL,
        adapter="ollama",
        base_url="http://localhost:11434",
        models_endpoint="/api/tags",
        privacy_class=PrivacyClass.LOCAL_ONLY,
    )
    adapter = OllamaAdapter(cfg, transport=httpx.MockTransport(handler))
    models = asyncio.run(adapter.discover_models())
    assert models[0].requested_model_id == "llama3.2:latest"


@pytest.mark.contract
def test_mcp_stdio_client_handshake_and_readonly_enforcement():
    cmd = f"{sys.executable} {STUB}"
    with UsfAuthorityClient(command=cmd) as c:
        tools = c.list_tools()
        assert "usf_health" in tools
        assert "usf_evidence_admit" in tools  # server exposes it
        assert c.list_resources() == []
        hj = c.health().json()
        assert hj["ok"] is True and hj["triples"] == 42
        b = c.bootstrap().json()
        assert b["authority"]["digest"] == "sha256:stub"
        # Read-only enforcement: mutation tool is NOT callable via the client.
        with pytest.raises(AuthorityError):
            c.call_tool("usf_evidence_admit", {})
        # Mutation SPARQL refused before it reaches the server.
        with pytest.raises(AuthorityError):
            c.query("INSERT DATA { <a> <b> <c> }")


@pytest.mark.contract
def test_git_mirror_isolation_no_usf_writes(tmp_usf, factory_paths):
    import subprocess

    from usf_factory.isolation import RepoIsolation
    from usf_factory.paths import resolve_paths

    paths = resolve_paths().ensure()
    iso = RepoIsolation(paths, tmp_usf)
    head_before = subprocess.run(
        ["git", "-C", str(tmp_usf), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    iso.ensure_mirror()
    ws = iso.create_workspace("pkt", "run", iso.mirror_head())
    # Workspace has no remote (cannot push/fetch) and is outside /usf.
    remotes = subprocess.run(
        ["git", "-C", str(ws), "remote"], capture_output=True, text=True
    ).stdout.strip()
    assert remotes == ""
    assert str(tmp_usf) not in str(ws)
    iso.cleanup(ws)
    head_after = subprocess.run(
        ["git", "-C", str(tmp_usf), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    assert head_before == head_after
    assert iso.assert_no_factory_worktrees() == []
