"""Sandbox enforcement, result qualification, attribution, learning."""

from __future__ import annotations

import pytest

from usf_factory import sandbox
from usf_factory.attribution import (
    compute_attribution,
    integrator_rewrite_ratio,
    is_worker_fault,
    stage_for_failure,
)
from usf_factory.enums import FailureClass, PacketResultStatus
from usf_factory.event_store import open_store
from usf_factory.learning import LearningEngine, update_task_score
from usf_factory.models import Packet, PacketResult
from usf_factory.result_validation import qualify_result


def _packet(write=None, subj=None):
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="shacl-repair",
        write_paths=write or ["a.ttl"],
        semantic_subjects=subj or [],
    )


# ---- sandbox ---- #


@pytest.mark.unit
def test_patch_scope_detects_out_of_scope_and_usf_and_escape():
    patch = (
        "--- a/allowed.ttl\n+++ b/allowed.ttl\n@@ -0,0 +1 @@\n+ok\n"
        "--- a/usf/secret.ttl\n+++ b/usf/secret.ttl\n@@ -0,0 +1 @@\n+bad\n"
        "--- a/../escape.ttl\n+++ b/../escape.ttl\n@@ -0,0 +1 @@\n+bad\n"
        "--- a/other.py\n+++ b/other.py\n@@ -0,0 +1 @@\n+bad\n"
    )
    v = sandbox.validate_patch_scope(patch, ["allowed.ttl"])
    assert any("usf" in x for x in v)
    assert any("escape" in x for x in v)
    assert any("outside write scope" in x for x in v)
    # clean patch:
    ok = sandbox.validate_patch_scope(
        "--- a/allowed.ttl\n+++ b/allowed.ttl\n@@ -0,0 +1 @@\n+ok\n", ["allowed.ttl"]
    )
    assert ok == []


@pytest.mark.unit
def test_scan_secrets():
    assert sandbox.scan_secrets("token sk-abcdefghij0123456789 here")
    assert sandbox.scan_secrets("please read /root/.env")
    assert sandbox.scan_secrets("nothing sensitive here") == []


@pytest.mark.unit
def test_command_allowlist():
    assert sandbox.check_command("pytest tests/")[0] is True
    assert sandbox.check_command("git status")[0] is True
    assert sandbox.check_command("git push origin main")[0] is False
    assert sandbox.check_command("curl http://evil")[0] is False
    assert sandbox.check_command("rm -rf /")[0] is False


# ---- result validation ---- #


@pytest.mark.unit
def test_result_validation_accepts_clean_completed():
    p = _packet()
    r = PacketResult(
        packet_id=p.packet_id,
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="agent",
        base_head="h",
        snapshot_id="s",
        changed_paths=["a.ttl"],
        actual_provider="x",
        actual_model="y",
    )
    q = qualify_result(p, r, current_head="h")
    assert q.accepted


@pytest.mark.unit
def test_result_validation_rejects_out_of_scope_path():
    p = _packet(write=["a.ttl"])
    r = PacketResult(
        packet_id=p.packet_id,
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="agent",
        base_head="h",
        snapshot_id="s",
        changed_paths=["b.ttl"],
    )
    q = qualify_result(p, r, current_head="h")
    assert not q.accepted
    assert q.failure_class is FailureClass.SCOPE_VIOLATION


@pytest.mark.unit
def test_result_validation_detects_stale_packet():
    p = _packet()
    r = PacketResult(
        packet_id=p.packet_id,
        status=PacketResultStatus.COMPLETED,
        agent_profile_id="agent",
        base_head="h",
        snapshot_id="s",
        changed_paths=["a.ttl"],
    )
    q = qualify_result(p, r, current_head="DIFFERENT")
    assert not q.accepted
    assert q.failure_class is FailureClass.STALE_PACKET


@pytest.mark.unit
def test_uncertain_mutation_not_accepted():
    p = _packet()
    r = PacketResult(
        packet_id=p.packet_id,
        status=PacketResultStatus.FAILED,
        agent_profile_id="agent",
        base_head="h",
        snapshot_id="s",
        failure_class=FailureClass.UNCERTAIN_MUTATION,
    )
    q = qualify_result(p, r, current_head="h")
    assert not q.accepted
    assert q.failure_class is FailureClass.UNCERTAIN_MUTATION


# ---- attribution ---- #


@pytest.mark.unit
def test_non_worker_faults_not_worker_attributed():
    assert not is_worker_fault(FailureClass.PLANNER_ERROR)
    assert not is_worker_fault(FailureClass.PROVIDER_OUTAGE)
    assert not is_worker_fault(FailureClass.STALE_PACKET)
    assert is_worker_fault(FailureClass.SCOPE_VIOLATION)
    assert stage_for_failure(FailureClass.PLANNER_ERROR) == "planner"


@pytest.mark.unit
def test_integrator_rewrite_ratio():
    assert integrator_rewrite_ratio("a\nb\nc", "a\nb\nc") == 0.0  # preserved
    assert integrator_rewrite_ratio("a\nb\nc", "x\ny\nz") == pytest.approx(1.0)
    attr = compute_attribution("a\nb\nc\nd", "a\nb\nX\nd")
    assert attr.lines_preserved == 3


# ---- learning ---- #


@pytest.mark.unit
def test_learning_ci_tightens_with_samples():
    s = None
    for _ in range(3):
        s = update_task_score(
            s, 1.0, agent_profile_id="a", task_class="t", dimension="implementation"
        )
    wide = s.ci_high - s.ci_low
    for _ in range(10):
        s = update_task_score(
            s, 1.0, agent_profile_id="a", task_class="t", dimension="implementation"
        )
    narrow = s.ci_high - s.ci_low
    assert narrow < wide


@pytest.mark.unit
def test_learning_does_not_penalize_non_worker_fault(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    le = LearningEngine(st)
    updated = le.record_worker_outcome(
        "agent", "shacl-repair", accepted=False, failure_class=FailureClass.PROVIDER_OUTAGE
    )
    assert updated == []  # provider outage does not touch worker scores
    st.close()


@pytest.mark.unit
def test_learning_only_writes_scores_table(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    le = LearningEngine(st)
    le.record("agent", "shacl-repair", "implementation", 1.0)
    assert st.count("model_task_scores") == 1
    # No other record table was touched.
    for t in ("cycles", "packets", "providers"):
        assert st.count(t) == 0
    st.close()
