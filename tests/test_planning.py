"""Planner, critic, conflict classification, packet compilation, antichain."""

from __future__ import annotations

import asyncio

import pytest

from usf_factory.config import load_config
from usf_factory.conflict_graph import build_conflict_edges, classify_conflict, select_antichain
from usf_factory.enums import ConflictClass
from usf_factory.models import Obligation, ObligationGraph, Packet, SemanticSnapshot
from usf_factory.packet_compiler import compile_packets
from usf_factory.paths import repo_root
from usf_factory.planner import DeterministicCritic, FixturePlanner


def _snap():
    return SemanticSnapshot(authority_digest="a", repository_head="h", working_tree_digest="w")


def _packet(oid, write=None, read=None, subj=None, deps=None, human=False, tc="shacl-repair"):
    return Packet(
        obligation_id=oid,
        snapshot_id="s",
        authority_digest="a",
        base_head="h",
        objective="x",
        task_class=tc,
        write_paths=write or [],
        read_paths=read or [],
        semantic_subjects=subj or [],
        dependencies=deps or [],
        human_decision_required=human,
    )


@pytest.mark.unit
def test_conflict_classes():
    a = _packet("a", write=["f.ttl"])
    b = _packet("b", write=["f.ttl"])
    assert classify_conflict(a, b)[0] is ConflictClass.WRITE_OVERLAP
    c = _packet("c", subj=["iri1"])
    d = _packet("d", subj=["iri1"])
    assert classify_conflict(c, d)[0] is ConflictClass.SEMANTIC_OVERLAP
    e = _packet("e", write=["o.ttl"])
    f = _packet("f", read=["o.ttl"])
    assert classify_conflict(e, f)[0] is ConflictClass.AUTHORITY_DEPENDENT
    g = _packet("g", read=["r.ttl"])
    h = _packet("h", read=["r.ttl"])
    assert classify_conflict(g, h)[0] is ConflictClass.READ_OVERLAP
    i = _packet("i", human=True)
    j = _packet("j")
    assert classify_conflict(i, j)[0] is ConflictClass.HUMAN_DECISION_REQUIRED
    assert classify_conflict(_packet("x"), _packet("y"))[0] is ConflictClass.DISJOINT


@pytest.mark.unit
def test_antichain_excludes_unsafe_and_dependencies_and_human():
    # two safe (read overlap) + one write-conflicting + one dependent + one human
    p_safe1 = _packet("s1", read=["o.ttl"], write=["a.ttl"])
    p_safe2 = _packet("s2", read=["o.ttl"], write=["b.ttl"])
    p_conflict = _packet("c1", write=["a.ttl"])  # write overlap with s1
    p_dep = _packet("d1", write=["c.ttl"], deps=["s1"])  # not ready
    p_human = _packet("h1", human=True)
    packets = [p_safe1, p_safe2, p_conflict, p_dep, p_human]
    edges = build_conflict_edges(packets)
    selected, deferred = select_antichain(packets, edges)
    sel_obl = {p.obligation_id for p in packets if p.packet_id in selected}
    def_obl = {p.obligation_id for p in packets if p.packet_id in deferred}
    assert "d1" in def_obl  # dependency
    assert "h1" in def_obl  # human decision
    # exactly one of the write-conflicting pair is selected
    assert len({"s1", "c1"} & sel_obl) == 1


@pytest.mark.unit
def test_packet_compiler_deterministic():
    cfg = load_config()
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="o1",
                root_cause="rc1",
                task_class="shacl-repair",
                suggested_write_scope=["a.ttl"],
                acceptance_criteria=["ok"],
            ),
            Obligation(
                id="o2",
                root_cause="rc2",
                task_class="sparql-authoring",
                suggested_write_scope=["b.rq"],
                acceptance_criteria=["ok"],
            ),
        ],
    )
    snap = _snap()
    p1, _ = compile_packets(graph, snap, cfg.task_classes)
    p2, _ = compile_packets(graph, snap, cfg.task_classes)
    assert p1.set_id == p2.set_id


@pytest.mark.unit
def test_packet_compiler_defers_oversized():
    cfg = load_config()
    # repository-implementation is the operator-approved planner-write-scope
    # class; 50 files exceeds its max_files=20.
    many = [f"gen/f{i}.py" for i in range(50)]
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="big",
                root_cause="rc",
                task_class="repository-implementation",
                suggested_write_scope=many,
                acceptance_criteria=["ok"],
            )
        ],
    )
    pset, findings = compile_packets(graph, _snap(), cfg.task_classes)
    assert pset.selected_packet_ids == []  # oversized excluded from selection
    assert any("exceeds task limits" in f for f in findings)


@pytest.mark.unit
def test_unapproved_task_class_write_scope_is_stripped():
    """A NON-semantic obligation may take planner write scope only when its
    task class is explicitly operator-approved for it (P1-6 scope authority)."""
    cfg = load_config()
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="w",
                root_cause="rc",
                task_class="shacl-repair",  # not planner_write_scope_allowed
                suggested_write_scope=["semantic/shapes/x.ttl"],
                acceptance_criteria=["ok"],
            )
        ],
    )
    pset, findings = compile_packets(graph, _snap(), cfg.task_classes)
    assert pset.packets[0].write_paths == []  # stripped, fail closed
    assert any("not approved for planner-supplied write scope" in f for f in findings)


@pytest.mark.unit
def test_fixture_planner_and_critic():
    fixture = repo_root() / "fixtures" / "planner" / "sample-obligations.yaml"
    planner = FixturePlanner(fixture)
    graph = asyncio.run(planner.plan(_snap()))
    assert len(graph.obligations) == 5
    critic = DeterministicCritic()
    findings = critic.critique(graph)
    assert isinstance(findings, list)  # may be empty; must not crash


@pytest.mark.unit
def test_critic_detects_missing_dependency_and_hidden_subject():
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="a",
                root_cause="ra",
                dependencies=["ghost"],
                semantic_subjects=["iri1"],
                acceptance_criteria=["c"],
            ),
            Obligation(
                id="b", root_cause="rb", semantic_subjects=["iri1"], acceptance_criteria=["c"]
            ),
        ],
    )
    findings = DeterministicCritic().critique(graph)
    assert any("missing 'ghost'" in f for f in findings)
    assert any("hidden shared semantic subject" in f for f in findings)


@pytest.mark.unit
def test_critic_flags_human_decision_as_implementation():
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="a",
                root_cause="architecture decision for storage",
                acceptance_criteria=["c"],
                human_decision_required=False,
            )
        ],
    )
    findings = DeterministicCritic().critique(graph)
    assert any("looks like a human decision" in f for f in findings)
