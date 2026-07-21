"""P0-5: agent runtime (tool broker + tool-call loop) and CLI adapter parsing."""

from __future__ import annotations

import asyncio
import os
import stat

import pytest

from usf_factory.agent_runtime import GenericToolLoop, ToolBroker
from usf_factory.enums import AuthMode, PrivacyClass
from usf_factory.models import AgentRequest, Packet, ProviderConfig
from usf_factory.providers.cli_adapters import ClaudeCliAdapter, CodexCliAdapter


def _packet(workspace):
    (workspace / "allowed.ttl").write_text("line1\nline2\nline3\n")
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="add a triple",
        task_class="shacl-repair",
        read_paths=["allowed.ttl"],
        write_paths=["allowed.ttl"],
    )


@pytest.mark.unit
def test_tool_broker_reads_in_scope_and_blocks_out_of_scope(tmp_path):
    p = _packet(tmp_path)
    broker = ToolBroker(workspace=tmp_path, packet=p)
    ok = broker.dispatch("read_file_range", {"path": "allowed.ttl", "start": 1, "end": 2})
    assert ok["lines"] == ["line1", "line2"]
    blocked = broker.dispatch("read_file_range", {"path": "secret.txt"})
    assert "error" in blocked


@pytest.mark.unit
def test_tool_broker_apply_patch_scope(tmp_path):
    p = _packet(tmp_path)
    broker = ToolBroker(workspace=tmp_path, packet=p)
    good = broker.dispatch(
        "apply_patch", {"patch": "--- a/allowed.ttl\n+++ b/allowed.ttl\n@@ -0,0 +1 @@\n+ok\n"}
    )
    assert good["accepted"] and good["changed_paths"] == ["allowed.ttl"]
    bad = broker.dispatch(
        "apply_patch", {"patch": "--- a/other.py\n+++ b/other.py\n@@ -0,0 +1 @@\n+x\n"}
    )
    assert bad["accepted"] is False


@pytest.mark.unit
def test_tool_loop_drives_model_to_finish(tmp_path):
    p = _packet(tmp_path)
    broker = ToolBroker(workspace=tmp_path, packet=p)

    # A deterministic fake model: read a file, then finish with a patch.
    script = [
        {
            "content": "",
            "tool_calls": [
                {"id": "1", "name": "read_file_range", "arguments": {"path": "allowed.ttl"}}
            ],
        },
        {
            "content": "",
            "tool_calls": [
                {
                    "id": "2",
                    "name": "finish_packet",
                    "arguments": {
                        "status": "COMPLETED",
                        "patch": "--- a/allowed.ttl\n+++ b/allowed.ttl\n@@ -0,0 +1 @@\n+ok\n",
                    },
                }
            ],
        },
    ]
    calls = {"n": 0}

    async def fake_chat(messages, tools):
        i = calls["n"]
        calls["n"] += 1
        return script[i]

    result = asyncio.run(GenericToolLoop(fake_chat, max_turns=5).run(p, broker))
    assert result.stopped_reason == "finished"
    assert result.finished["status"] == "COMPLETED"
    assert result.turns == 2


@pytest.mark.unit
def test_tool_loop_respects_turn_budget(tmp_path):
    p = _packet(tmp_path)
    broker = ToolBroker(workspace=tmp_path, packet=p)

    async def never_finish(messages, tools):
        return {
            "content": "",
            "tool_calls": [{"id": "x", "name": "list_directory", "arguments": {"path": "."}}],
        }

    result = asyncio.run(GenericToolLoop(never_finish, max_turns=3).run(p, broker))
    assert result.stopped_reason == "max_turns"
    assert result.turns == 3
    assert result.finished is None


# ---- CLI adapter parsing via stub binaries ---- #


def _stub(tmp_path, name, script_body):
    p = tmp_path / name
    p.write_text("#!/usr/bin/env bash\n" + script_body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXUSR)
    return p


def _cfg(pid, adapter):
    return ProviderConfig(
        provider_id=pid,
        display_name=pid,
        auth_mode=AuthMode.OIDC_CLI,
        credential_reference=f"cli:{pid}",
        adapter=adapter,
        privacy_class=PrivacyClass.FIRST_PARTY_CLI,
    )


@pytest.mark.contract
def test_codex_adapter_parses_jsonl(tmp_path, monkeypatch):
    stub = _stub(
        tmp_path, "codex", 'echo \'{"type":"agent_message","message":"hello from codex"}\'\n'
    )
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    adapter = CodexCliAdapter(_cfg("codex-cli", "codex_cli"), allow_billable=True)
    resp = asyncio.run(
        adapter.invoke(
            AgentRequest(
                agent_profile_id="a", packet_id="p", instructions="hi", requested_model_id="gpt-5"
            )
        )
    )
    assert resp.output_text == "hello from codex"
    assert resp.actual_model == "gpt-5"


@pytest.mark.contract
def test_claude_adapter_parses_json(tmp_path, monkeypatch):
    stub = _stub(tmp_path, "claude", 'echo \'{"type":"result","result":"hello from claude"}\'\n')
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    adapter = ClaudeCliAdapter(_cfg("claude-cli", "claude_cli"), allow_billable=True)
    resp = asyncio.run(
        adapter.invoke(
            AgentRequest(
                agent_profile_id="a",
                packet_id="p",
                instructions="hi",
                requested_model_id="claude-opus-4-8",
            )
        )
    )
    assert resp.output_text == "hello from claude"


@pytest.mark.contract
def test_cli_adapter_billable_gated(tmp_path, monkeypatch):
    stub = _stub(tmp_path, "codex", "echo x\n")
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    adapter = CodexCliAdapter(_cfg("codex-cli", "codex_cli"), allow_billable=False)
    with pytest.raises(Exception):
        asyncio.run(
            adapter.invoke(AgentRequest(agent_profile_id="a", packet_id="p", instructions="hi"))
        )
