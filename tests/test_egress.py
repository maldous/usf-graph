"""Hotfix P0-1: read-only packets carrying repository source are private-source,
external providers cannot be routed to them while source egress is disabled, and
the tool broker refuses to return source content even if one were reached."""

from __future__ import annotations

import pytest

from conftest import all_dimension_scores
from usf_factory.agent_runtime import ToolBroker
from usf_factory.config import load_config
from usf_factory.enums import AdmissionRole, AuthMode, PrivacyClass
from usf_factory.models import AgentProfile, Obligation, ObligationGraph, SemanticSnapshot
from usf_factory.packet_compiler import compile_packets
from usf_factory.scheduler import SchedulableAgent, Scheduler


def _compile(read_scope, write_scope=()):
    cfg = load_config()
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="o1",
                root_cause="inspect ontology",
                task_class="shacl-repair",
                semantic_subjects=[],
                suggested_read_scope=list(read_scope),
                suggested_write_scope=list(write_scope),
                acceptance_criteria=["ok"],
            )
        ],
    )
    snap = SemanticSnapshot(authority_digest="a", repository_head="h", working_tree_digest="w")
    pset, _ = compile_packets(graph, snap, cfg.task_classes)
    return cfg, pset.packets[0]


@pytest.mark.unit
def test_readonly_source_packet_classified_private_source():
    _, pkt = _compile(["semantic/ontology.ttl"])
    assert pkt.write_paths == []
    # Source content in the READ scope is still source: never private-metadata.
    assert pkt.data_classification == "private-source"


@pytest.mark.unit
def test_pathless_packet_stays_private_metadata():
    _, pkt = _compile([])
    assert pkt.read_paths == [] and pkt.write_paths == []
    assert pkt.data_classification == "private-metadata"


@pytest.mark.adversarial
def test_readonly_source_packet_external_provider_gets_no_route_and_no_source():
    """Mandated adversarial case: read-only packet + source read path + external
    provider + source_egress_enabled=false => NO route and NO source returned."""
    cfg, pkt = _compile(["semantic/ontology.ttl"])
    assert cfg.egress.source_egress_enabled is False  # committed default

    profile = AgentProfile(
        provider_id="groq",
        requested_model_id="m",
        adapter="openai_compatible",
        auth_mode=AuthMode.API_TOKEN,
    )
    agent = SchedulableAgent(
        profile=profile,
        provider_id="groq",
        admission_roles=[AdmissionRole.READ_ONLY_ANALYST],
        task_scores=all_dimension_scores(),
        privacy_class=PrivacyClass.EXTERNAL_CLOUD,
    )
    decision = Scheduler(cfg.routing, cfg.egress).schedule(
        pkt, AdmissionRole.READ_ONLY_ANALYST, [agent]
    )
    assert decision.selected_profile_id is None  # no route
    reasons = decision.candidates[0].exclusion_reasons
    assert any("egress" in r for r in reasons)

    # Defense in depth: even a broker reached out-of-band returns no source.
    allowed, why = cfg.egress.source_content_allowed("groq", PrivacyClass.EXTERNAL_CLOUD.value)
    assert allowed is False
    broker = ToolBroker(workspace=None, packet=pkt, source_content_allowed=allowed)
    r = broker.dispatch("read_file_range", {"path": "semantic/ontology.ttl"})
    assert "not permitted" in str(r.get("error", ""))


@pytest.mark.unit
def test_source_content_allowed_truth_table():
    cfg = load_config()
    eg = cfg.egress
    # Local providers never egress: always allowed.
    assert eg.source_content_allowed("ollama", "local_only")[0] is True
    # External cloud, defaults: class rule already refuses.
    ok, why = eg.source_content_allowed("groq", "external_cloud")
    assert ok is False and "not allowed" in why
    # First-party CLI passes the class rule but the GLOBAL gate is off.
    ok, why = eg.source_content_allowed("claude-cli", "first_party_cli")
    assert ok is False and "disabled" in why
    # Gate on but provider not explicitly approved: still refused.
    eg2 = eg.model_copy(update={"source_egress_enabled": True})
    ok, why = eg2.source_content_allowed("claude-cli", "first_party_cli")
    assert ok is False and "not approved" in why
    # Gate on + explicit approval: allowed.
    eg3 = eg2.model_copy(update={"provider_overrides": {"claude-cli": ["private-source"]}})
    assert eg3.source_content_allowed("claude-cli", "first_party_cli")[0] is True
