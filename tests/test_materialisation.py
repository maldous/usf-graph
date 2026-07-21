"""Materialisation index: parsing, ownership, quarantine (analysis-only)."""

from __future__ import annotations

import pytest

from usf_factory.config import load_config
from usf_factory.materialisation import build_index
from usf_factory.models import Obligation, ObligationGraph, SemanticSnapshot
from usf_factory.packet_compiler import compile_packets


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "semantic").mkdir()
    (tmp_path / "semantic" / "ontology.ttl").write_text(
        "@prefix ex: <https://ex/ns#> .\nex:Widget a ex:Class .\nex:Gadget a ex:Class .\n"
    )
    (tmp_path / "semantic" / "shapes").mkdir()
    # Widget is ALSO declared (a) here => two owners => ambiguous.
    (tmp_path / "semantic" / "shapes" / "widget.shacl.ttl").write_text(
        "@prefix ex: <https://ex/ns#> .\n@prefix sh: <http://www.w3.org/ns/shacl#> .\n"
        "ex:Widget a sh:NodeShape .\n"
    )
    (tmp_path / "semantic" / "queries").mkdir()
    (tmp_path / "semantic" / "queries" / "integrity.rq").write_text(
        "PREFIX ex: <https://ex/ns#>\nSELECT ?s WHERE { ?s a ex:Widget } LIMIT 10\n"
    )
    return tmp_path


@pytest.mark.unit
def test_index_resolves_owner_and_related(repo):
    idx = build_index(repo)
    g = idx.resolve("https://ex/ns#Gadget")
    assert g.owner_path == "semantic/ontology.ttl" and g.verified is True
    w = idx.resolve("https://ex/ns#Widget")
    # Declared in ontology.ttl AND (as a type) in the shape file => ambiguous.
    assert w.method == "ambiguous" and w.verified is False
    assert "semantic/shapes/widget.shacl.ttl" in w.related_paths


@pytest.mark.unit
def test_index_is_deterministic(repo):
    a = build_index(repo).source_digest
    b = build_index(repo).source_digest
    assert a == b and a.startswith("sha256:")


@pytest.mark.unit
def test_affected_by(repo):
    idx = build_index(repo)
    subs = idx.affected_by("semantic/ontology.ttl")
    assert "https://ex/ns#Gadget" in subs


@pytest.mark.unit
def test_index_never_authorizes_writes_by_default(repo):
    idx = build_index(repo)
    # Even a verified owner yields NO write scope when quarantined (default).
    s = idx.derive_scope(["https://ex/ns#Gadget"])
    assert s.write_paths == []
    assert "semantic/ontology.ttl" in s.read_paths
    # Explicit opt-in (future manifest-backed trust) can authorize writes.
    s2 = idx.derive_scope(["https://ex/ns#Gadget"], authorize_writes=True)
    assert s2.write_paths == ["semantic/ontology.ttl"]


@pytest.mark.unit
def test_unresolved_and_ambiguous_reported(repo):
    idx = build_index(repo)
    s = idx.derive_scope(["https://ex/ns#Unknown", "https://ex/ns#Widget"])
    assert "https://ex/ns#Unknown" in s.unresolved
    assert "https://ex/ns#Widget" in s.ambiguous
    assert s.write_paths == []  # quarantined


def _git(args, cwd):
    import subprocess

    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo(repo):
    """The same fixture tree, committed — so a snapshot-bound index can build."""
    _git(["init", "-q", "-b", "main"], repo)
    _git(["config", "user.email", "t@e"], repo)
    _git(["config", "user.name", "t"], repo)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "init"], repo)
    import subprocess

    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    return repo, head


@pytest.mark.unit
def test_build_index_at_is_snapshot_bound_and_ignores_working_tree(git_repo):
    from usf_factory.materialisation import build_index_at

    repo, head = git_repo
    # Mutate the WORKING TREE after the commit: a new subject appears on disk.
    (repo / "semantic" / "ontology.ttl").write_text(
        "@prefix ex: <https://ex/ns#> .\nex:Widget a ex:Class .\nex:Gadget a ex:Class .\n"
        "ex:Sneaky a ex:Class .\n"
    )
    idx = build_index_at(repo, head)
    assert idx.snapshot_bound is True and idx.source_commit == head
    assert idx.resolve("https://ex/ns#Gadget") is not None
    # Uncommitted working-tree content can never leak into the contract.
    assert idx.resolve("https://ex/ns#Sneaky") is None


@pytest.mark.e2e
def test_semantic_write_scope_comes_from_contract_not_planner(git_repo):
    """P1-6 scope authority: a semantic obligation's writes come ONLY from the
    snapshot-bound contract (verified owner); the planner suggestion is ignored."""
    from usf_factory.materialisation import build_index_at

    repo, head = git_repo
    cfg = load_config()
    idx = build_index_at(repo, head)
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="o1",
                root_cause="fix gadget",
                task_class="shacl-repair",
                semantic_subjects=["https://ex/ns#Gadget"],
                suggested_write_scope=["anything/the/planner/wants.py"],  # must be ignored
                acceptance_criteria=["ok"],
            )
        ],
    )
    snap = SemanticSnapshot(authority_digest="a", repository_head=head, working_tree_digest="w")
    pset, findings = compile_packets(graph, snap, cfg.task_classes, materialisation_index=idx)
    pkt = pset.packets[0]
    assert pkt.write_paths == ["semantic/ontology.ttl"]  # verified owner, from contract
    assert pkt.materialisation_digest == idx.source_digest  # bound into the packet
    assert any("IGNORED" in f for f in findings)
    # A STALE contract (different head) must not authorize writes.
    snap2 = SemanticSnapshot(
        authority_digest="a", repository_head="other-head", working_tree_digest="w"
    )
    pset2, findings2 = compile_packets(graph, snap2, cfg.task_classes, materialisation_index=idx)
    assert pset2.packets[0].write_paths == []
    assert any("not a snapshot-bound contract" in f for f in findings2)


@pytest.mark.unit
def test_ambiguous_subject_never_gets_contract_writes(git_repo):
    from usf_factory.materialisation import build_index_at

    repo, head = git_repo
    cfg = load_config()
    idx = build_index_at(repo, head)
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="o1",
                root_cause="fix widget",
                task_class="shacl-repair",
                semantic_subjects=["https://ex/ns#Widget"],  # two declarations => ambiguous
                acceptance_criteria=["ok"],
            )
        ],
    )
    snap = SemanticSnapshot(authority_digest="a", repository_head=head, working_tree_digest="w")
    pset, findings = compile_packets(graph, snap, cfg.task_classes, materialisation_index=idx)
    assert pset.packets[0].write_paths == []  # fail closed
    assert any("ambiguous" in f for f in findings)


@pytest.mark.unit
def test_compiler_uses_index_for_read_scope_not_writes(repo):
    cfg = load_config()
    idx = build_index(repo)
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="o1",
                root_cause="fix gadget",
                task_class="shacl-repair",
                semantic_subjects=["https://ex/ns#Gadget"],
                suggested_write_scope=[],  # no explicit write scope
                acceptance_criteria=["ok"],
            )
        ],
    )
    snap = SemanticSnapshot(authority_digest="a", repository_head="h", working_tree_digest="w")
    pset, findings = compile_packets(graph, snap, cfg.task_classes, materialisation_index=idx)
    pkt = pset.packets[0]
    # Index contributed read scope + validation, but NO write scope (quarantined).
    assert "semantic/ontology.ttl" in pkt.read_paths
    assert pkt.write_paths == []
    assert "shacl" in pkt.required_validation
