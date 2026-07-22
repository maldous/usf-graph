"""Remediation classification (build task §1) + operator RunAuthorization (scope).

These cover: deterministic gap→RemediationKind classification; that a
VALIDATION_EVIDENCE / PROOF_EVIDENCE / ANALYSIS_ONLY worker remediation never
receives repository write scope even from a verified materialisation owner; and that the
RunAuthorization loads fail-closed, is owner-only, expires, and is the sole
per-run enabler of protected actions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from usf_factory.config import load_config
from usf_factory.engine import FactoryEngine
from usf_factory.enums import AdmissionRole, AuthMode, ProtectedAction, RemediationKind, Risk
from usf_factory.errors import RunAuthorizationError
from usf_factory.materialisation import ScopeResult
from usf_factory.models import AgentProfile, Obligation, ObligationGraph, Packet, SemanticSnapshot
from usf_factory.packet_compiler import compile_packets
from usf_factory.programme_state import classify_remediation, parse_programme_obligations
from usf_factory.run_authorization import (
    RunAuthorization,
    load_run_authorization,
    write_run_authorization,
)
from usf_factory.workforce import WorkforceProfile

FUTURE = "2999-01-01T00:00:00Z"
PAST = "2000-01-01T00:00:00Z"


# --- §1 classification ------------------------------------------------------ #


@pytest.mark.unit
def test_classify_remediation_exact_mapping():
    assert (
        classify_remediation("missing-current-passing-validation")
        is RemediationKind.VALIDATION_EVIDENCE
    )
    assert classify_remediation("missing-validation") is RemediationKind.VALIDATION_EVIDENCE
    assert classify_remediation("missing-successful-proof") is RemediationKind.PROOF_EVIDENCE
    assert classify_remediation("missing-proof") is RemediationKind.PROOF_EVIDENCE
    assert classify_remediation("missing-constraint") is RemediationKind.SOURCE_CHANGE
    assert classify_remediation("missing-shape") is RemediationKind.SOURCE_CHANGE
    assert classify_remediation("shacl-violation") is RemediationKind.SOURCE_CHANGE
    # Unknown → ANALYSIS_ONLY; explicit human-decision marker → HUMAN_DECISION.
    assert classify_remediation("something-new") is RemediationKind.ANALYSIS_ONLY
    assert (
        classify_remediation("missing-shape", human_decision=True) is RemediationKind.HUMAN_DECISION
    )


@pytest.mark.unit
def test_missing_current_passing_validation_is_not_sparql_authoring():
    wp = {"gaps": [{"type": "missing-current-passing-validation", "subject": "urn:usf:vo"}]}
    obls = parse_programme_obligations({}, wp)
    assert obls[0]["remediation_kind"] == "VALIDATION_EVIDENCE"
    assert obls[0]["task_class"] == "semantic-planning"
    assert obls[0]["task_class"] != "sparql-authoring"


@pytest.mark.unit
def test_contract_obligation_inventory_is_not_actionable_without_work_plan_gap():
    bootstrap = {
        "proofObligations": ["urn:usf:proofobligation:declared"],
        "validationObligations": ["urn:usf:validationobligation:deferred"],
        "openGaps": [],
    }
    assert parse_programme_obligations(bootstrap, {"gaps": []}) == []


@pytest.mark.unit
def test_source_change_gap_keeps_editing_task_class():
    wp = {"gaps": [{"type": "shacl-violation", "subject": "urn:usf:shape"}]}
    obls = parse_programme_obligations({}, wp)
    assert obls[0]["remediation_kind"] == "SOURCE_CHANGE"
    assert obls[0]["task_class"] == "shacl-repair"


# --- §1 write-scope gate ---------------------------------------------------- #


class _ContractIndex:
    """Minimal snapshot-bound contract with a verified owner for every subject."""

    snapshot_bound = True
    source_digest = "sha256:" + "0" * 64

    def __init__(self, head: str) -> None:
        self.source_commit = head

    def derive_scope(self, subjects: list[str], *, authorize_writes: bool = False) -> ScopeResult:
        return ScopeResult(
            read_paths=["semantic-model/x.trig"],
            write_paths=["semantic-model/x.trig"] if authorize_writes else [],
            validation_profiles=["syntax-parse"],
        )


def _graph(kind: RemediationKind) -> ObligationGraph:
    return ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="o",
                root_cause="rc",
                task_class="shacl-repair",
                remediation_kind=kind,
                semantic_subjects=["urn:usf:x"],
                acceptance_criteria=["ok"],
            )
        ],
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "kind,expect_write",
    [
        (RemediationKind.SOURCE_CHANGE, True),
        (RemediationKind.VALIDATION_EVIDENCE, False),
        (RemediationKind.PROOF_EVIDENCE, False),
        (RemediationKind.ANALYSIS_ONLY, False),
        (RemediationKind.HUMAN_DECISION, False),
    ],
)
def test_only_source_change_gets_write_scope(kind, expect_write):
    cfg = load_config()
    snap = SemanticSnapshot(authority_digest="a", repository_head="h", working_tree_digest="w")
    pset, findings = compile_packets(
        _graph(kind), snap, cfg.task_classes, materialisation_index=_ContractIndex("h")
    )
    pkt = next(p for p in pset.packets if p.obligation_id == "o")
    assert pkt.remediation_kind is kind
    if expect_write:
        assert pkt.write_paths == ["semantic-model/x.trig"]
    else:
        assert pkt.write_paths == []
        assert any("read-only" in f for f in findings)


# --- RunAuthorization ------------------------------------------------------- #


def _auth(**over) -> RunAuthorization:
    base = dict(
        authorization_id="run-1",
        issued_at="2026-07-21T00:00:00Z",
        expires_at=FUTURE,
        repositories=["maldous/usf-factory", "maldous/usf-graph"],
        authority_database="USF",
        permitted_actions=[ProtectedAction.PUSH_PR, ProtectedAction.STARDOG_PUBLICATION],
    )
    base.update(over)
    return RunAuthorization(**base)


@pytest.mark.unit
def test_run_authorization_roundtrip_and_digest(tmp_path: Path):
    a = _auth()
    p = tmp_path / "auth.json"
    digest = write_run_authorization(a, p)
    assert (p.stat().st_mode & 0o777) == 0o600
    loaded = load_run_authorization(p)
    assert loaded.digest() == digest == a.digest()
    assert loaded.authorization_id == "run-1"


@pytest.mark.unit
def test_run_authorization_permits_only_listed_and_unexpired():
    a = _auth()
    assert a.permits_action(ProtectedAction.PUSH_PR, now="2026-07-22T00:00:00Z")
    assert a.permits_action(ProtectedAction.STARDOG_PUBLICATION, now="2026-07-22T00:00:00Z")
    # Not listed → refused.
    assert not a.permits_action(ProtectedAction.TERMINAL_COMPLETION, now="2026-07-22T00:00:00Z")
    # Expired → nothing permitted.
    expired = _auth(issued_at="1999-01-01T00:00:00Z", expires_at=PAST)
    assert not expired.permits_action(ProtectedAction.PUSH_PR, now="2026-07-22T00:00:00Z")


@pytest.mark.unit
def test_run_authorization_risk_and_paid_budget():
    a = _auth()
    assert a.permits_risk(Risk.LOW) and a.permits_risk(Risk.MEDIUM)
    assert not a.permits_risk(Risk.HIGH) and not a.permits_risk(Risk.PROTECTED)
    # USD 0 budget ⇒ paid inference never allowed even if the action were listed.
    paid = _auth(permitted_actions=[ProtectedAction.PAID_INFERENCE], paid_api_budget_usd=0.0)
    assert not paid.paid_inference_allowed()


@pytest.mark.adversarial
def test_run_authorization_provider_and_subscription_scopes_are_enforced(ctx):
    ctx.run_authorization = _auth(
        raw_source_provider="local-safe",
        metadata_review_provider="review-only",
        allow_subscription_inference=False,
    )
    engine = FactoryEngine(ctx)
    packet = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="repository-implementation",
        risk=Risk.MEDIUM,
        data_classification="private-source",
        write_paths=["x.py"],
    )
    wrong_raw = WorkforceProfile(
        profile_id="raw", provider_id="cloud", requested_model_id="model", inference_mode="free"
    )
    assert "committed safety gate" in engine._authorization_provider_reason(
        packet, AdmissionRole.PATCH_PRODUCER, wrong_raw
    )
    ctx.config.safety.allow_source_egress = True
    ctx.run_authorization.permitted_actions.append(ProtectedAction.SOURCE_EGRESS)
    assert "restricts raw source" in engine._authorization_provider_reason(
        packet, AdmissionRole.PATCH_PRODUCER, wrong_raw
    )
    wrong_review = WorkforceProfile(
        profile_id="review",
        provider_id="cloud",
        requested_model_id="model",
        inference_mode="free",
    )
    assert "metadata review" in engine._authorization_provider_reason(
        packet, AdmissionRole.REVIEWER, wrong_review
    )
    subscription = WorkforceProfile(
        profile_id="subscription",
        provider_id="local-safe",
        requested_model_id="model",
        inference_mode="subscription",
    )
    assert "subscription" in engine._authorization_provider_reason(
        packet, AdmissionRole.PATCH_PRODUCER, subscription
    )


@pytest.mark.adversarial
def test_private_source_invocation_requires_and_records_point_of_use_grant(ctx):
    ctx.config.safety.allow_source_egress = True
    ctx.config.egress.source_egress_enabled = True
    ctx.config.egress.provider_overrides = {"openai-api": ["private-source"]}
    ctx.run_authorization = _auth(
        permitted_actions=[ProtectedAction.SOURCE_EGRESS],
        raw_source_provider="openai-api",
    )
    packet = Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="sha256:" + "a" * 64,
        base_head="a" * 40,
        objective="x",
        task_class="repository-implementation",
        data_classification="private-source",
    )
    agent = AgentProfile(
        provider_id="openai-api",
        requested_model_id="model",
        adapter="openai_compatible",
        auth_mode=AuthMode.API_TOKEN,
    )
    engine = FactoryEngine(ctx)
    assert engine._authorise_source_egress(packet, agent, "run-1") is None
    records = ctx.store.records("source_egress_authorizations")
    assert len(records) == 1
    assert records[0]["run_authorization_digest"] == ctx.run_authorization.digest()
    assert ctx.store.cas_get(records[0]["event_ref"])

    agent.adapter = "codex_cli"
    assert "containment" in engine._authorise_source_egress(packet, agent, "run-2")
    assert ctx.store.count("source_egress_authorizations") == 1


@pytest.mark.adversarial
def test_paid_budget_is_intersection_of_config_and_run_authorization(ctx):
    ctx.config.safety.allow_billable = True
    ctx.config.budgets.billable_usd = 10.0
    ctx.run_authorization = _auth(
        permitted_actions=[ProtectedAction.PAID_INFERENCE], paid_api_budget_usd=3.0
    )
    assert FactoryEngine(ctx)._paid_budget_limit() == 3.0
    ctx.run_authorization = _auth(paid_api_budget_usd=3.0, permitted_actions=[])
    assert FactoryEngine(ctx)._paid_budget_limit() == 0.0


@pytest.mark.adversarial
def test_run_authorization_rejects_insecure_file(tmp_path: Path):
    p = tmp_path / "auth.json"
    p.write_text(json.dumps(_auth().content_dict()), encoding="utf-8")
    os.chmod(p, 0o644)  # group/other readable → must be refused
    with pytest.raises(RunAuthorizationError):
        load_run_authorization(p)


@pytest.mark.adversarial
def test_run_authorization_rejects_symlink(tmp_path: Path):
    real = tmp_path / "real.json"
    write_run_authorization(_auth(), real)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(RunAuthorizationError):
        load_run_authorization(link)


@pytest.mark.unit
def test_context_action_effective_requires_authorization(ctx):
    # No authorization ⇒ no protected action is effective, even though the
    # capability may exist in code.
    assert ctx.run_authorization is None
    assert not ctx.is_action_effective(ProtectedAction.PUSH_PR)
    ctx.run_authorization = _auth()
    # Both the immutable committed gate and the expiring run grant are required.
    assert not ctx.is_action_effective(ProtectedAction.PUSH_PR)
    assert not ctx.is_action_effective(ProtectedAction.STARDOG_PUBLICATION)
    ctx.config.safety.allow_push_pr = True
    ctx.config.safety.allow_stardog_publication = True
    assert ctx.is_action_effective(ProtectedAction.PUSH_PR)
    assert ctx.is_action_effective(ProtectedAction.STARDOG_PUBLICATION)
    assert not ctx.is_action_effective(ProtectedAction.TERMINAL_COMPLETION)
    assert ctx.is_gate_enabled(ProtectedAction.PUSH_PR)


@pytest.mark.adversarial
def test_run_authorization_rejects_malformed_or_reversed_timestamps():
    with pytest.raises(Exception, match="exact UTC timestamp"):
        _auth(expires_at="tomorrow")
    with pytest.raises(Exception, match="later than issued_at"):
        _auth(issued_at=FUTURE, expires_at="2998-01-01T00:00:00Z")
