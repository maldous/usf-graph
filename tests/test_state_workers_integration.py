"""State machine, workers (dry-run + sandbox), and deterministic integration."""

from __future__ import annotations

import asyncio

import pytest

from usf_factory.enums import AuthMode, CycleState, FailureClass, PacketResultStatus
from usf_factory.errors import FactoryError
from usf_factory.integration import detect_semantic_conflicts, deterministic_preintegrate
from usf_factory.models import AgentProfile, AgentResponse, Packet, PacketResult
from usf_factory.state_machine import CycleStateMachine
from usf_factory.workers import AiWorker, DryRunWorker


@pytest.mark.unit
def test_state_machine_valid_and_invalid_transitions():
    sm = CycleStateMachine()
    sm.transition(CycleState.READY)
    sm.transition(CycleState.SNAPSHOT)
    assert sm.state is CycleState.SNAPSHOT
    with pytest.raises(FactoryError):
        sm.transition(CycleState.COMPLETE)  # not reachable from SNAPSHOT


@pytest.mark.unit
def test_dry_run_worker_never_mutates(tmp_path):
    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        write_paths=["a.ttl"],
    )
    agent = AgentProfile(
        provider_id="dry", requested_model_id="dry", adapter="dry", auth_mode=AuthMode.LOCAL
    )
    result = asyncio.run(DryRunWorker().execute(p, tmp_path, agent))
    assert result.status is PacketResultStatus.SKIPPED
    assert result.patch_digest is None
    assert result.changed_paths == []


@pytest.mark.unit
def test_ai_worker_rejects_out_of_scope_patch(tmp_path):
    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        write_paths=["allowed.ttl"],
    )
    agent = AgentProfile(
        provider_id="x",
        requested_model_id="m",
        adapter="openai_compatible",
        auth_mode=AuthMode.API_TOKEN,
    )

    async def fake_invoke(req):
        # Model tries to write outside its scope.
        patch = "--- a/other.py\n+++ b/other.py\n@@ -0,0 +1 @@\n+bad\n"
        return AgentResponse(
            agent_profile_id=agent.profile_id,
            actual_provider="x",
            actual_model="m",
            output_text='{"status":"COMPLETED","patch":' + repr(patch).replace("'", '"') + "}",
        )

    worker = AiWorker(fake_invoke, isolation=None)
    result = asyncio.run(worker.execute(p, tmp_path, agent))
    assert result.status is PacketResultStatus.FAILED
    assert result.failure_class is FailureClass.SCOPE_VIOLATION
    assert result.scope_violation is True


@pytest.mark.unit
def test_ai_worker_rejects_secret_leak(tmp_path):
    p = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        write_paths=["allowed.ttl"],
    )
    agent = AgentProfile(
        provider_id="x",
        requested_model_id="m",
        adapter="openai_compatible",
        auth_mode=AuthMode.API_TOKEN,
    )

    async def fake_invoke(req):
        patch = (
            "--- a/allowed.ttl\n+++ b/allowed.ttl\n@@ -0,0 +1 @@\n+sk-abcdef0123456789ABCDEFGH\n"
        )
        import json

        return AgentResponse(
            agent_profile_id=agent.profile_id,
            output_text=json.dumps({"status": "COMPLETED", "patch": patch}),
        )

    result = asyncio.run(AiWorker(fake_invoke, isolation=None).execute(p, tmp_path, agent))
    assert result.status is PacketResultStatus.FAILED
    assert result.failure_class is FailureClass.SCOPE_VIOLATION


@pytest.mark.unit
def test_detect_semantic_conflicts():
    r1 = PacketResult(
        packet_id="p1",
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="a",
        patch_digest="d1",
        semantic_subjects_changed=["iri1"],
        changed_paths=["a.ttl"],
    )
    r2 = PacketResult(
        packet_id="p2",
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="a",
        patch_digest="d2",
        semantic_subjects_changed=["iri1"],
        changed_paths=["b.ttl"],
    )
    conflicts = detect_semantic_conflicts([r1, r2])
    assert any("semantic subject overlap" in c for c in conflicts)


@pytest.mark.unit
def test_preintegrate_clean_when_no_patches():
    attempt, wave = deterministic_preintegrate("set1", [], isolation=None, base_head="h")
    assert attempt.deterministic_merge_ok
    assert wave is None
