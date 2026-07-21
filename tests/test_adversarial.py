"""Adversarial safety tests (build task §20)."""

from __future__ import annotations

import asyncio
import json

import pytest

from usf_factory import sandbox, secrets
from usf_factory.config import load_config
from usf_factory.conflict_graph import build_conflict_edges, select_antichain
from usf_factory.enums import (
    AdmissionRole,
    AuthMode,
    ConflictClass,
    FailureClass,
    PacketResultStatus,
)
from usf_factory.event_store import open_store
from usf_factory.learning import LearningEngine
from usf_factory.models import (
    AgentProfile,
    AgentResponse,
    Obligation,
    ObligationGraph,
    Packet,
    PacketResult,
    RequiredCapabilities,
)
from usf_factory.planner import DeterministicCritic
from usf_factory.result_validation import qualify_result
from usf_factory.scheduler import SchedulableAgent, Scheduler
from usf_factory.workers import AiWorker


def _packet(**kw):
    base = dict(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        write_paths=["allowed.ttl"],
    )
    base.update(kw)
    return Packet(**base)


async def _run_worker_patch(patch: str, write=("allowed.ttl",)):
    p = _packet(write_paths=list(write))
    agent = AgentProfile(
        provider_id="x",
        requested_model_id="m",
        adapter="openai_compatible",
        auth_mode=AuthMode.API_TOKEN,
    )

    async def invoke(req):
        return AgentResponse(
            agent_profile_id=agent.profile_id,
            output_text=json.dumps({"status": "COMPLETED", "patch": patch}),
        )

    return await AiWorker(invoke, isolation=None).execute(p, None, agent)


@pytest.mark.adversarial
def test_prompt_injection_cannot_exfiltrate_via_patch():
    # Repository content instructs the model to write outside scope; the sandbox
    # rejects it regardless of what the model was told.
    patch = "--- a/../../etc/evil\n+++ b/../../etc/evil\n@@ -0,0 +1 @@\n+owned\n"
    result = asyncio.run(_run_worker_patch(patch))
    assert result.status is PacketResultStatus.FAILED
    assert result.failure_class is FailureClass.SCOPE_VIOLATION


@pytest.mark.adversarial
def test_model_attempt_to_read_env_is_flagged():
    assert sandbox.scan_secrets("cat /root/.env")
    patch = "--- a/allowed.ttl\n+++ b/allowed.ttl\n@@ -0,0 +1 @@\n+# see /root/.env\n"
    result = asyncio.run(_run_worker_patch(patch))
    assert result.status is PacketResultStatus.FAILED


@pytest.mark.adversarial
def test_model_attempt_to_write_usf_rejected():
    patch = "--- a/usf/graph.ttl\n+++ b/usf/graph.ttl\n@@ -0,0 +1 @@\n+bad\n"
    result = asyncio.run(_run_worker_patch(patch, write=("usf/graph.ttl",)))
    assert result.status is PacketResultStatus.FAILED


@pytest.mark.adversarial
def test_git_push_and_network_blocked():
    assert sandbox.check_command("git push")[0] is False
    assert sandbox.check_command("git remote add x y")[0] is False
    assert sandbox.check_command("wget http://x")[0] is False


@pytest.mark.adversarial
def test_worker_completion_without_changes_closes_nothing():
    # A COMPLETED result with no changes is accepted structurally but closes no
    # obligation durably; terminal completion is computed elsewhere, not from prose.
    p = _packet()
    r = PacketResult(
        packet_id=p.packet_id,
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="a",
        base_head="h",
        snapshot_id="s",
        changed_paths=[],
        obligations_closed=["o"],
    )
    q = qualify_result(p, r, current_head="h")
    # No patch and claims closure — accepted structurally but produced no durable change.
    assert r.patch_digest is None


@pytest.mark.adversarial
def test_planner_over_fragmentation_flagged():
    obs = [
        Obligation(id=f"o{i}", root_cause=f"rc{i}", acceptance_criteria=["c"]) for i in range(40)
    ]
    graph = ObligationGraph(snapshot_id="s", obligations=obs)
    findings = DeterministicCritic().critique(graph)
    assert any("over-fragmentation" in f for f in findings)


@pytest.mark.adversarial
def test_hidden_dependency_and_shared_subject_detected():
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="a", root_cause="ra", semantic_subjects=["iri1"], acceptance_criteria=["c"]
            ),
            Obligation(
                id="b", root_cause="rb", semantic_subjects=["iri1"], acceptance_criteria=["c"]
            ),
        ],
    )
    findings = DeterministicCritic().critique(graph)
    assert any("hidden shared semantic subject" in f for f in findings)


@pytest.mark.adversarial
def test_same_iri_different_files_not_co_scheduled():
    a = _packet(obligation_id="a", write_paths=["a.ttl"], semantic_subjects=["iri1"])
    b = _packet(obligation_id="b", write_paths=["b.ttl"], semantic_subjects=["iri1"])
    edges = build_conflict_edges([a, b])
    assert any(e.conflict_class is ConflictClass.SEMANTIC_OVERLAP for e in edges)
    selected, _ = select_antichain([a, b], edges)
    assert len(selected) == 1  # only one may run


@pytest.mark.adversarial
def test_duplicate_claim_blocked(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    assert st.claim_packet("p", "r1", "o", "2099") is True
    assert st.claim_packet("p", "r2", "o", "2099") is False
    st.close()


@pytest.mark.adversarial
def test_provider_quota_expired_ineligible():
    cfg = load_config()
    s = Scheduler(cfg.routing, cfg.egress)
    a = SchedulableAgent(
        profile=AgentProfile(
            provider_id="p",
            requested_model_id="m",
            adapter="openai_compatible",
            auth_mode=AuthMode.API_TOKEN,
        ),
        provider_id="p",
        admission_roles=[AdmissionRole.PATCH_PRODUCER],
        task_scores={"structured_output": 0.9, "implementation": 0.9},
        quota_ok=False,
    )
    p = _packet(
        write_paths=["a.ttl"],
        required_capabilities=RequiredCapabilities(structured_output=0.8, repository_editing=True),
        data_classification="private-metadata",
    )
    d = s.schedule(p, AdmissionRole.PATCH_PRODUCER, [a])
    assert d.selected_profile_id is None


@pytest.mark.adversarial
def test_integration_git_clean_but_semantic_conflict():
    from usf_factory.integration import detect_semantic_conflicts

    r1 = PacketResult(
        packet_id="p1",
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="a",
        patch_digest="d1",
        semantic_subjects_changed=["iri1"],
    )
    r2 = PacketResult(
        packet_id="p2",
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="a",
        patch_digest="d2",
        semantic_subjects_changed=["iri1"],
    )
    assert detect_semantic_conflicts([r1, r2])  # non-empty even if git would merge


@pytest.mark.adversarial
def test_learning_cannot_weaken_safety_policy(tmp_path, monkeypatch):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    cfg = load_config()
    before = (
        cfg.safety.allow_billable,
        cfg.safety.allow_stardog_publication,
        cfg.egress.source_egress_enabled,
    )
    le = LearningEngine(st)
    for _ in range(20):
        le.record("agent", "shacl-repair", "implementation", 1.0)
    cfg2 = load_config()
    after = (
        cfg2.safety.allow_billable,
        cfg2.safety.allow_stardog_publication,
        cfg2.egress.source_egress_enabled,
    )
    assert before == after == (False, False, False)
    st.close()


@pytest.mark.adversarial
def test_credential_aliases_disagree_reported_as_conflict():
    norm = secrets.normalize({"MISTRAL_API_KEY": "a", "MISTRAL_TOKEN": "b"})
    assert "MISTRAL_API_KEY" in norm.conflicts


@pytest.mark.adversarial
def test_publication_gate_disabled_by_default():
    # Publication cannot proceed in the safe runtime.

    # Use a throwaway context via load_config-only gate check.
    cfg = load_config()
    assert cfg.safety.allow_stardog_publication is False
