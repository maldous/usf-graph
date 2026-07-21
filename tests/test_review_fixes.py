"""Regression tests for the adversarial-review P0 fixes."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from usf_factory.authority import ToolCallResult
from usf_factory.enums import AuthMode, FailureClass, PacketResultStatus, PrivacyClass
from usf_factory.errors import SnapshotError
from usf_factory.models import AgentProfile, AgentRequest, AgentResponse, Packet, ProviderConfig
from usf_factory.providers.openai_compatible import OpenAICompatibleAdapter
from usf_factory.snapshots import compile_snapshot
from usf_factory.workers import AiWorker


def _packet(write=("allowed.ttl",)):
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        write_paths=list(write),
    )


def _agent():
    return AgentProfile(
        provider_id="x",
        requested_model_id="m",
        adapter="openai_compatible",
        auth_mode=AuthMode.API_TOKEN,
    )


async def _run(patch_or_text, *, raw=False):
    agent = _agent()

    async def invoke(req):
        text = patch_or_text if raw else json.dumps({"status": "COMPLETED", "patch": patch_or_text})
        return AgentResponse(agent_profile_id=agent.profile_id, output_text=text)

    return await AiWorker(invoke, isolation=None).execute(_packet(), None, agent)


# ---- P0-3: fail-closed worker results ---- #


@pytest.mark.adversarial
def test_malformed_json_fails_not_completed():
    r = asyncio.run(_run("this is prose, not json", raw=True))
    assert r.status is PacketResultStatus.FAILED
    assert r.failure_class is FailureClass.WORKER_ERROR


@pytest.mark.adversarial
def test_empty_object_fails_not_completed():
    r = asyncio.run(_run("{}", raw=True))
    assert r.status is PacketResultStatus.FAILED  # missing status -> fail


@pytest.mark.adversarial
def test_unknown_status_fails():
    r = asyncio.run(_run(json.dumps({"status": "DEFINITELY_DONE"}), raw=True))
    assert r.status is PacketResultStatus.FAILED


@pytest.mark.adversarial
def test_unknown_field_rejected_by_strict_schema():
    r = asyncio.run(_run(json.dumps({"status": "COMPLETED", "sneaky": "x"}), raw=True))
    assert r.status is PacketResultStatus.FAILED


@pytest.mark.adversarial
def test_mutating_completion_without_patch_fails():
    r = asyncio.run(_run(json.dumps({"status": "COMPLETED"}), raw=True))
    assert r.status is PacketResultStatus.FAILED
    assert "without an effective" in r.failure_detail or "without a patch" in r.failure_detail


@pytest.mark.adversarial
def test_valid_patch_in_scope_completes():
    patch = "--- a/allowed.ttl\n+++ b/allowed.ttl\n@@ -0,0 +1 @@\n+ok\n"
    r = asyncio.run(_run(patch))
    assert r.status is PacketResultStatus.COMPLETED
    assert r.changed_paths == ["allowed.ttl"]


# ---- P0-4: explicit model routing ---- #


def _oai_cfg():
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
def test_adapter_uses_explicit_requested_model():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(
            200, json={"model": "vendor/real", "choices": [{"message": {"content": "hi"}}]}
        )

    adapter = OpenAICompatibleAdapter(
        _oai_cfg(), token="t", allow_billable=True, transport=httpx.MockTransport(handler)
    )
    req = AgentRequest(
        agent_profile_id="agent-deadbeefdeadbeef",
        packet_id="p",
        instructions="hi",
        provider_id="openrouter",
        requested_model_id="vendor/requested",
    )
    asyncio.run(adapter.invoke(req))
    assert seen["model"] == "vendor/requested"  # NOT the opaque agent-... id


@pytest.mark.contract
def test_adapter_refuses_opaque_profile_id():
    adapter = OpenAICompatibleAdapter(_oai_cfg(), token="t", allow_billable=True)
    req = AgentRequest(agent_profile_id="agent-deadbeefdeadbeef", packet_id="p", instructions="hi")
    with pytest.raises(Exception):
        asyncio.run(adapter.invoke(req))


# ---- P0-2: snapshot fails closed ---- #


class _Auth:
    def __init__(self, digest="sha256:validdigest0000000000", ok=True, tools=None):
        self._d, self._ok = digest, ok
        self._tools = tools if tools is not None else ["usf_health", "usf_bootstrap", "usf_query"]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return None

    def list_tools(self):
        return self._tools

    def _tcr(self, o):
        return ToolCallResult(ok=True, content=[{"type": "text", "text": json.dumps(o)}])

    def health(self):
        return self._tcr({"ok": self._ok, "triples": 10})

    def bootstrap(self, arguments=None):
        return self._tcr({"authority": {"digest": self._d, "triples": 10, "coveredGraphCount": 2}})


@pytest.mark.unit
def test_snapshot_fails_closed_without_digest(tmp_usf):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.paths import resolve_paths

    iso = RepoIsolation(resolve_paths(), tmp_usf)
    with pytest.raises(SnapshotError):
        compile_snapshot(authority=_Auth(digest=""), isolation=iso)


@pytest.mark.unit
def test_snapshot_fails_closed_when_unhealthy(tmp_usf):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.paths import resolve_paths

    iso = RepoIsolation(resolve_paths(), tmp_usf)
    with pytest.raises(SnapshotError):
        compile_snapshot(authority=_Auth(ok=False), isolation=iso)


@pytest.mark.unit
def test_snapshot_fails_closed_missing_required_tool(tmp_usf):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.paths import resolve_paths

    iso = RepoIsolation(resolve_paths(), tmp_usf)
    with pytest.raises(SnapshotError):
        compile_snapshot(authority=_Auth(tools=["usf_health"]), isolation=iso)


# ---- P0-11: qualification missing answers score zero ---- #


@pytest.mark.unit
def test_missing_answers_score_zero():
    from usf_factory.models import QualificationCase, QualificationSuite
    from usf_factory.qualification import score_answers

    cases = [
        QualificationCase(
            case_id=f"c{i}",
            task_class="t",
            dimension="semantic_planning",
            prompt="p",
            grader="choice",
            expected={"value": "yes"},
        )
        for i in range(4)
    ]
    suite = QualificationSuite(suite_id="s", version="v1", cases=cases)
    # Answer only one of four correctly.
    dims, _tc, passed, total = score_answers(suite, {"c0": "yes"})
    assert total == 4  # unanswered cases still counted
    assert passed == 1
    assert dims["semantic_planning"] == 0.25  # 1 of 4, not 1.0
