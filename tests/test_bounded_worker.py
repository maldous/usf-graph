"""Bounded context-and-patch worker (AiWorker) — the CLI-backed producer path.
The orchestrator applies + re-derives the diff via git; the model never touches
the workspace."""

from __future__ import annotations

import asyncio
import subprocess

import pytest

from usf_factory.enums import AuthMode, PacketResultStatus
from usf_factory.models import AgentProfile, AgentResponse, Packet


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


@pytest.fixture
def clone(tmp_path):
    """A disposable git clone standing in for the packet workspace."""
    repo = tmp_path / "clone"
    repo.mkdir()
    _git(["init", "-q", "-b", "main"], repo)
    _git(["config", "user.email", "t@e"], repo)
    _git(["config", "user.name", "t"], repo)
    (repo / "gen").mkdir()
    (repo / "gen" / "thing.py").write_text("x = 1\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "base"], repo)
    return repo


def _agent():
    return AgentProfile(
        provider_id="claude-cli",
        requested_model_id="claude-opus-4-8",
        adapter="claude_cli",
        auth_mode=AuthMode.OIDC_CLI,
    )


def _packet(write=("gen/thing.py",)):
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="edit gen/thing.py",
        task_class="repository-implementation",
        write_paths=list(write),
        permitted_tools=["read_file", "edit_file", "write_patch"],
    )


def _worker(ctx, chat_json):
    from usf_factory.isolation import RepoIsolation
    from usf_factory.workers import AiWorker

    async def invoke(req):
        return AgentResponse(
            agent_profile_id=req.agent_profile_id,
            output_text=chat_json,
            actual_provider="claude-cli",
            actual_model="claude-opus-4-8",
        )

    return AiWorker(invoke, isolation=RepoIsolation(ctx.paths, ctx.usf_repo), store=ctx.store)


_INSCOPE_PATCH = "--- a/gen/thing.py\n+++ b/gen/thing.py\n@@ -1 +1,2 @@\n x = 1\n+y = 2\n"


@pytest.mark.e2e
def test_bounded_worker_applies_and_rederives_via_git(ctx, clone):
    import json

    result = asyncio.run(
        _worker(ctx, json.dumps({"status": "COMPLETED", "patch": _INSCOPE_PATCH})).execute(
            _packet(), clone, _agent()
        )
    )
    assert result.status is PacketResultStatus.COMPLETED
    assert result.changed_paths == ["gen/thing.py"]  # git-DERIVED, not model-asserted
    # The clone was actually mutated (orchestrator applied it).
    assert "y = 2" in (clone / "gen" / "thing.py").read_text()
    assert result.patch_digest  # git-derived diff persisted


@pytest.mark.adversarial
def test_bounded_worker_out_of_scope_patch_fails(ctx, clone):
    import json

    out = "--- a/other.py\n+++ b/other.py\n@@ -0,0 +1 @@\n+bad\n"
    result = asyncio.run(
        _worker(ctx, json.dumps({"status": "COMPLETED", "patch": out})).execute(
            _packet(), clone, _agent()
        )
    )
    assert result.status is PacketResultStatus.FAILED
    assert result.scope_violation is True


@pytest.mark.adversarial
def test_bounded_worker_false_completion_fails(ctx, clone):
    import json

    result = asyncio.run(
        _worker(ctx, json.dumps({"status": "COMPLETED", "patch": ""})).execute(
            _packet(), clone, _agent()
        )
    )
    assert result.status is PacketResultStatus.FAILED
    assert "effective" in result.failure_detail


@pytest.mark.adversarial
def test_bounded_worker_malformed_json_fails(ctx, clone):
    result = asyncio.run(_worker(ctx, "not json at all").execute(_packet(), clone, _agent()))
    assert result.status is PacketResultStatus.FAILED


@pytest.mark.e2e
def test_bounded_worker_readonly_analysis(ctx, clone):
    import json

    ro = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="analyze",
        task_class="semantic-planning",
        acceptance_criteria=["analysis"],
        permitted_tools=["read_file"],
    )
    good = json.dumps({"status": "COMPLETED", "evidence_produced": ["finding: ok"]})
    result = asyncio.run(_worker(ctx, good).execute(ro, clone, _agent()))
    assert result.status is PacketResultStatus.COMPLETED and result.analysis_ref
    # read-only completion without durable evidence fails.
    bad = asyncio.run(
        _worker(ctx, json.dumps({"status": "COMPLETED"})).execute(ro, clone, _agent())
    )
    assert bad.status is PacketResultStatus.FAILED
