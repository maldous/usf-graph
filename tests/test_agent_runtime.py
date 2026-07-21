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

_ALL_TOOLS = ["edit_file", "list_paths", "read_file", "run_focused_tests", "write_patch"]
_READ_TOOLS = ["list_paths", "read_file"]


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
        permitted_tools=_ALL_TOOLS,
    )


@pytest.mark.unit
def test_tool_broker_reads_in_scope_and_blocks_out_of_scope(tmp_path):
    p = _packet(tmp_path)
    broker = ToolBroker(workspace=tmp_path, packet=p)
    ok = broker.dispatch("read_file_range", {"path": "allowed.ttl", "start": 1, "end": 2})
    assert ok["lines"] == ["line1", "line2"]
    blocked = broker.dispatch("read_file_range", {"path": "secret.txt"})
    assert "error" in blocked


@pytest.mark.adversarial
def test_broker_sibling_prefix_and_symlink_escape_blocked(tmp_path):
    import os

    ws = tmp_path / "packet"
    ws.mkdir()
    (ws / "allowed.ttl").write_text("in scope\n")
    # Sibling dir sharing a name prefix; a naive startswith check would allow it.
    sib = tmp_path / "packet-other"
    sib.mkdir()
    (sib / "secret.txt").write_text("SECRET\n")
    # A symlink inside the workspace pointing outside it.
    (tmp_path / "outside.txt").write_text("OUTSIDE\n")
    os.symlink(tmp_path / "outside.txt", ws / "link.ttl")

    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        read_paths=["allowed.ttl", "link.ttl", "../packet-other/secret.txt"],
        permitted_tools=_READ_TOOLS,
    )
    broker = ToolBroker(workspace=ws, packet=p)
    # sibling-prefix escape (via .. in a declared read path) is rejected.
    assert "error" in broker.dispatch("read_file_range", {"path": "../packet-other/secret.txt"})
    # symlink escape is rejected even though the path is "in scope".
    assert "error" in broker.dispatch("read_file_range", {"path": "link.ttl"})
    # the in-scope real file still reads.
    assert broker.dispatch("read_file_range", {"path": "allowed.ttl"})["lines"] == ["in scope"]


@pytest.mark.adversarial
def test_broker_scope_and_git_exclusion(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".git").mkdir()
    (ws / ".git" / "config").write_text("[core]\n")
    (ws / "a.ttl").write_text("has SECRETMARK\n")
    (ws / "unrelated.py").write_text("SECRETMARK here\n")
    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        read_paths=["a.ttl"],
        permitted_tools=_READ_TOOLS,
    )
    broker = ToolBroker(workspace=ws, packet=p)
    # read_file_range: out-of-scope file denied.
    assert "error" in broker.dispatch("read_file_range", {"path": "unrelated.py"})
    # search only sees in-scope files (not unrelated.py, not .git).
    hits = broker.dispatch("search_repository", {"query": "SECRETMARK"})["hits"]
    assert [h["path"] for h in hits] == ["a.ttl"]
    # list_directory of root reveals only scoped entries, never .git.
    entries = broker.dispatch("list_directory", {"path": "."})["entries"]
    assert ".git" not in entries and "unrelated.py" not in entries and "a.ttl" in entries


@pytest.mark.adversarial
def test_broker_empty_scope_grants_no_reads(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "x.ttl").write_text("data\n")
    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        permitted_tools=_READ_TOOLS,
    )
    broker = ToolBroker(workspace=ws, packet=p)  # empty read+write scope
    assert "error" in broker.dispatch("read_file_range", {"path": "x.ttl"})


@pytest.mark.adversarial
def test_broker_inside_workspace_symlink_alias_blocked(tmp_path):
    """A symlink whose TARGET is inside the workspace must still be refused —
    it aliases a file other than the declared scoped path (read AND write)."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "hidden.txt").write_text("HIDDEN\n")  # in workspace, NOT in scope
    os.symlink(ws / "hidden.txt", ws / "link.ttl")  # in-scope name -> out-of-scope file
    (ws / "real_dir").mkdir()
    (ws / "real_dir" / "victim.py").write_text("victim\n")
    os.symlink(ws / "real_dir", ws / "gen")  # symlinked directory component

    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        read_paths=["link.ttl"],
        write_paths=["gen/victim.py"],
        permitted_tools=_ALL_TOOLS,
    )
    broker = ToolBroker(workspace=ws, packet=p, mutating=True)
    # Read through an in-workspace symlink: refused.
    assert "error" in broker.dispatch("read_file_range", {"path": "link.ttl"})
    # Write through a symlinked directory component: refused.
    out = broker.dispatch("write_new_file", {"path": "gen/victim.py", "content": "x = 1\n"})
    assert out.get("accepted") is not True
    assert (ws / "real_dir" / "victim.py").read_text() == "victim\n"  # untouched


@pytest.mark.adversarial
def test_broker_honors_packet_tool_profile(tmp_path):
    """Tool exposure and dispatch follow packet.permitted_tools, not just mode."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.ttl").write_text("data\n")
    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        read_paths=["a.ttl"],
        write_paths=["a.ttl"],
        permitted_tools=["read_file"],  # no list_paths, no edit/write tools
    )
    broker = ToolBroker(workspace=ws, packet=p, mutating=True)
    names = {s["function"]["name"] for s in broker.tool_specs()}
    assert "read_file_range" in names and "finish_packet" in names
    assert "list_directory" not in names and "write_new_file" not in names
    # Dispatch enforces the same profile (not only advertisement).
    assert "error" in broker.dispatch("list_directory", {"path": "."})
    denied = broker.dispatch("write_new_file", {"path": "a.ttl", "content": "x"})
    assert "not permitted" in str(denied.get("error", ""))
    assert broker.dispatch("read_file_range", {"path": "a.ttl"})["lines"] == ["data"]


@pytest.mark.adversarial
def test_broker_byte_and_query_limits(tmp_path, monkeypatch):
    import usf_factory.agent_runtime as ar

    monkeypatch.setattr(ar, "MAX_FILE_BYTES", 64)
    monkeypatch.setattr(ar, "MAX_PATCH_BYTES", 64)
    monkeypatch.setattr(ar, "MAX_WRITE_BYTES", 64)
    monkeypatch.setattr(ar, "MAX_QUERY_CHARS", 16)
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "big.ttl").write_text("x" * 200)
    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        read_paths=["big.ttl"],
        write_paths=["new.py"],
        permitted_tools=_ALL_TOOLS,
    )
    broker = ToolBroker(workspace=ws, packet=p, mutating=True)
    assert "error" in broker.dispatch("read_file_range", {"path": "big.ttl"})
    assert "error" in broker.dispatch("search_repository", {"query": "q" * 32})
    big_patch = broker.dispatch("apply_unified_patch", {"patch": "-" * 128})
    assert big_patch.get("accepted") is not True
    big_write = broker.dispatch("write_new_file", {"path": "new.py", "content": "y" * 128})
    assert big_write.get("accepted") is not True


@pytest.mark.adversarial
def test_broker_denies_source_content_when_egress_disallowed(tmp_path):
    """Egress recheck at the tool boundary: content-returning tools are refused
    when policy does not allow raw source to this provider."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "src.py").write_text("SECRET_LOGIC = 1\n")
    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        read_paths=["src.py"],
        permitted_tools=_READ_TOOLS,
    )
    broker = ToolBroker(workspace=ws, packet=p, source_content_allowed=False)
    r = broker.dispatch("read_file_range", {"path": "src.py"})
    assert "not permitted" in str(r.get("error", ""))
    s = broker.dispatch("search_repository", {"query": "SECRET_LOGIC"})
    assert "not permitted" in str(s.get("error", ""))
    # Directory names are metadata (already in the packet JSON): still listable.
    assert "entries" in broker.dispatch("list_directory", {"path": "."})


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
