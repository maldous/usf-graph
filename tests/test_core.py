"""Canonical addressing, model identity, event store, config."""

from __future__ import annotations

import pytest

from usf_factory import canonical
from usf_factory.config import load_config
from usf_factory.enums import AuthMode
from usf_factory.event_store import open_store
from usf_factory.models import AgentProfile, Event, Packet, SemanticSnapshot


@pytest.mark.unit
def test_canonical_json_is_key_order_independent():
    a = canonical.canonical_json({"b": 1, "a": 2})
    b = canonical.canonical_json({"a": 2, "b": 1})
    assert a == b
    assert canonical.content_digest({"x": 1}) == canonical.content_digest({"x": 1})


@pytest.mark.unit
def test_snapshot_id_ignores_volatile_timestamp():
    s1 = SemanticSnapshot(
        authority_digest="d", repository_head="h", working_tree_digest="w", captured_at="2020"
    )
    s2 = SemanticSnapshot(
        authority_digest="d", repository_head="h", working_tree_digest="w", captured_at="2099"
    )
    assert s1.snapshot_id == s2.snapshot_id


@pytest.mark.unit
def test_agent_profiles_are_distinct_by_tuple():
    p1 = AgentProfile(
        provider_id="ollama", requested_model_id="x", adapter="ollama", auth_mode=AuthMode.LOCAL
    )
    p2 = AgentProfile(
        provider_id="ollama", requested_model_id="x", adapter="opencode", auth_mode=AuthMode.LOCAL
    )
    assert p1.profile_id != p2.profile_id  # different harness => different agent


@pytest.mark.unit
def test_packet_id_excludes_conflicts_with():
    base = dict(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class="t",
    )
    p1 = Packet(**base)
    p2 = Packet(**base, conflicts_with=["pkt-other"])
    assert p1.packet_id == p2.packet_id


@pytest.mark.unit
def test_event_store_claim_authority(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    assert st.claim_packet("p", "r1", "o", "2099") is True
    assert st.claim_packet("p", "r2", "o", "2099") is False
    st.release_packet("p", "r1")
    assert st.claim_packet("p", "r3", "o", "2099") is True
    st.close()


@pytest.mark.unit
def test_event_store_cas_dedup(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    ref1 = st.cas_put_text("blob")
    ref2 = st.cas_put_text("blob")
    assert ref1 == ref2
    assert st.cas_get(ref1) == b"blob"
    st.close()


@pytest.mark.unit
def test_event_store_events_append_only_order(tmp_path):
    st = open_store(tmp_path / "f.sqlite", tmp_path / "cas")
    st.append_event(Event(cycle_id="c", kind="a"))
    st.append_event(Event(cycle_id="c", kind="b"))
    evs = st.events("c")
    assert [e["kind"] for e in evs] == ["a", "b"]
    st.close()


@pytest.mark.unit
def test_config_loads_and_excludes_codebuff():
    cfg = load_config()
    ids = {p.provider_id for p in cfg.providers.providers}
    assert "codebuff" not in ids
    assert "codebuff" in cfg.providers.exclude
    assert cfg.safety.default_mode.value == "observe"
    assert cfg.safety.autonomous_safe_enabled is False


@pytest.mark.unit
def test_routing_split_sums_to_one():
    cfg = load_config()
    cfg.routing.validate_split()  # raises if not ~1.0


@pytest.mark.unit
def test_grok_and_github_models_disabled_by_default():
    cfg = load_config()
    by = cfg.providers.by_id()
    assert by["xai-grok"].default_enabled is False
    assert by["github-models"].default_enabled is False
