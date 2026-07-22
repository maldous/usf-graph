"""Materialisation ownership contract (Phase 2): candidate vs verified owners,
multi-line Turtle / TriG parsing, shapes/fixtures/generated never owners, and
evidence-bound write authorization."""

from __future__ import annotations

import subprocess

import pytest

from usf_factory.config import load_config
from usf_factory.enums import RemediationKind
from usf_factory.materialisation import build_index, build_index_at
from usf_factory.models import Obligation, ObligationGraph, SemanticSnapshot
from usf_factory.ownership import record_operator_approval, verify_index
from usf_factory.packet_compiler import compile_packets


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "semantic").mkdir()
    # Multi-line Turtle: subject on its own line, `a` on the next.
    (tmp_path / "semantic" / "ontology.ttl").write_text(
        "@prefix ex: <https://ex/ns#> .\n"
        "ex:Widget\n    a ex:Class ;\n    ex:label 'widget' .\n"
        "ex:Gadget a ex:Class .\n"
        "# ex:Commented a ex:Class .   (a comment, not a declaration)\n"
    )
    (tmp_path / "semantic" / "shapes").mkdir()
    # A SHAPE that types ex:Widget as its target — must NOT become an owner.
    (tmp_path / "semantic" / "shapes" / "widget.shacl.ttl").write_text(
        "@prefix ex: <https://ex/ns#> .\n@prefix sh: <http://www.w3.org/ns/shacl#> .\n"
        "ex:WidgetShape a sh:NodeShape ; sh:targetClass ex:Widget .\n"
        "ex:Widget a sh:NodeShape .\n"
    )
    (tmp_path / "semantic" / "fixtures").mkdir()
    # A FIXTURE that types ex:Gadget — must NOT become an owner.
    (tmp_path / "semantic" / "fixtures" / "neg.ttl").write_text(
        "@prefix ex: <https://ex/ns#> .\nex:Gadget a ex:Class .\n"
    )
    (tmp_path / "semantic" / "generated").mkdir()
    (tmp_path / "semantic" / "generated" / "proj.ttl").write_text(
        "@prefix ex: <https://ex/ns#> .\nex:Gadget a ex:Class .\n"
    )
    (tmp_path / "semantic" / "queries").mkdir()
    # Reference-before-declaration: this query references ex:Widget.
    (tmp_path / "semantic" / "queries" / "integrity.rq").write_text(
        "PREFIX ex: <https://ex/ns#>\nSELECT ?s WHERE { ?s a ex:Widget } LIMIT 10\n"
    )
    # TriG named graph declaring ex:Thing.
    (tmp_path / "semantic" / "graph.trig").write_text(
        "@prefix ex: <https://ex/ns#> .\nex:g {\n  ex:Thing a ex:Class .\n}\n"
    )
    return tmp_path


@pytest.fixture
def git_repo(repo):
    _git(["init", "-q", "-b", "main"], repo)
    _git(["config", "user.email", "t@e"], repo)
    _git(["config", "user.name", "t"], repo)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "init"], repo)
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    return repo, head


@pytest.mark.unit
def test_multiline_turtle_and_trig_declarations_are_candidates(repo):
    idx = build_index(repo)
    widget = idx.resolve("https://ex/ns#Widget")
    gadget = idx.resolve("https://ex/ns#Gadget")
    thing = idx.resolve("https://ex/ns#Thing")
    # Multi-line Turtle subject is detected.
    assert widget is not None and widget.candidate_owners == ["semantic/ontology.ttl"]
    # TriG named-graph subject is detected.
    assert thing is not None and thing.candidate_owners == ["semantic/graph.trig"]
    # A parsed declaration is only a CANDIDATE — never verified by parsing alone.
    assert widget.verified is False and gadget.verified is False
    # A commented-out line is not a declaration.
    assert idx.resolve("https://ex/ns#Commented") is None


@pytest.mark.adversarial
def test_shapes_fixtures_generated_are_never_owners(repo):
    idx = build_index(repo)
    widget = idx.resolve("https://ex/ns#Widget")
    gadget = idx.resolve("https://ex/ns#Gadget")
    # The shape file types ex:Widget but is NOT a candidate owner.
    assert "semantic/shapes/widget.shacl.ttl" not in widget.candidate_owners
    assert "semantic/shapes/widget.shacl.ttl" in widget.shapes
    # The fixture and generated projection type ex:Gadget but are NOT owners.
    assert gadget.candidate_owners == ["semantic/ontology.ttl"]
    assert "semantic/fixtures/neg.ttl" not in gadget.candidate_owners
    assert "semantic/generated/proj.ttl" in gadget.generated_outputs


@pytest.mark.unit
def test_reference_before_declaration_links_related(repo):
    idx = build_index(repo)
    widget = idx.resolve("https://ex/ns#Widget")
    # The integrity query references Widget (declared later in file order).
    assert "semantic/queries/integrity.rq" in widget.related_paths


@pytest.mark.adversarial
def test_multiple_candidate_owners_are_ambiguous(tmp_path):
    (tmp_path / "a.ttl").write_text("@prefix ex: <https://ex/ns#> .\nex:Dup a ex:Class .\n")
    (tmp_path / "b.ttl").write_text("@prefix ex: <https://ex/ns#> .\nex:Dup a ex:Class .\n")
    idx = build_index(tmp_path)
    e = idx.resolve("https://ex/ns#Dup")
    assert set(e.candidate_owners) == {"a.ttl", "b.ttl"} and e.method == "ambiguous"
    s = idx.derive_scope(["https://ex/ns#Dup"], authorize_writes=True)
    assert s.write_paths == [] and "https://ex/ns#Dup" in s.ambiguous


@pytest.mark.unit
def test_candidate_alone_never_authorizes_writes(git_repo):
    repo, head = git_repo
    idx = build_index_at(repo, head)
    # No evidence applied: Gadget has one candidate owner but is unverified.
    s = idx.derive_scope(["https://ex/ns#Gadget"], authorize_writes=True)
    assert s.write_paths == []  # candidate-only => no write
    assert "semantic/ontology.ttl" in s.read_paths


@pytest.mark.e2e
def test_operator_evidence_authorizes_exactly_one_path(ctx, git_repo, monkeypatch):
    repo, head = git_repo
    monkeypatch.setattr(ctx, "usf_repo", repo, raising=False)
    # Approve ownership at the exact commit.
    record_operator_approval(
        ctx, "https://ex/ns#Gadget", "semantic/ontology.ttl", repository_commit=head
    )
    idx = build_index_at(repo, head)
    verify_index(ctx, idx)
    g = idx.resolve("https://ex/ns#Gadget")
    assert g.verified is True and g.verified_owner == "semantic/ontology.ttl"
    s = idx.derive_scope(["https://ex/ns#Gadget"], authorize_writes=True)
    assert s.write_paths == ["semantic/ontology.ttl"]  # exactly one path


@pytest.mark.adversarial
def test_stale_and_commit_mismatched_evidence_ignored(ctx, git_repo):
    repo, head = git_repo
    # Approve at a DIFFERENT commit than the index is built at.
    record_operator_approval(
        ctx, "https://ex/ns#Gadget", "semantic/ontology.ttl", repository_commit="deadbeef"
    )
    idx = build_index_at(repo, head)
    verify_index(ctx, idx)
    g = idx.resolve("https://ex/ns#Gadget")
    assert g.verified is False  # commit mismatch => evidence ignored (stale)
    s = idx.derive_scope(["https://ex/ns#Gadget"], authorize_writes=True)
    assert s.write_paths == []


@pytest.mark.e2e
def test_semantic_write_scope_requires_verified_owner(ctx, git_repo):
    """A semantic obligation's write scope comes ONLY from a verified owner; the
    planner's suggested write scope is ignored, and a candidate-only subject
    yields NO write."""
    repo, head = git_repo
    cfg = load_config()
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="o1",
                root_cause="fix gadget",
                task_class="shacl-repair",
                remediation_kind=RemediationKind.SOURCE_CHANGE,
                semantic_subjects=["https://ex/ns#Gadget"],
                suggested_write_scope=["whatever/the/planner/wants.py"],  # ignored
                acceptance_criteria=["ok"],
            )
        ],
    )
    snap = SemanticSnapshot(authority_digest="a", repository_head=head, working_tree_digest="w")

    # Before approval: candidate-only => no write.
    idx = build_index_at(repo, head)
    verify_index(ctx, idx)
    pset, findings = compile_packets(graph, snap, cfg.task_classes, materialisation_index=idx)
    assert pset.packets[0].write_paths == []
    assert any("IGNORED" in f for f in findings)

    # After operator approval at this commit: write scope = the verified owner.
    record_operator_approval(
        ctx, "https://ex/ns#Gadget", "semantic/ontology.ttl", repository_commit=head
    )
    idx2 = build_index_at(repo, head)
    verify_index(ctx, idx2)
    pset2, _ = compile_packets(graph, snap, cfg.task_classes, materialisation_index=idx2)
    assert pset2.packets[0].write_paths == ["semantic/ontology.ttl"]
    assert pset2.packets[0].materialisation_digest == idx2.source_digest


@pytest.mark.unit
def test_build_at_ignores_working_tree(git_repo):
    repo, head = git_repo
    (repo / "semantic" / "ontology.ttl").write_text(
        "@prefix ex: <https://ex/ns#> .\nex:Sneaky a ex:Class .\n"
    )
    idx = build_index_at(repo, head)
    assert idx.snapshot_bound is True and idx.source_commit == head
    assert idx.resolve("https://ex/ns#Sneaky") is None  # uncommitted content excluded


@pytest.mark.unit
def test_compiler_uses_index_for_read_scope_not_writes(git_repo, ctx):
    repo, head = git_repo
    cfg = load_config()
    idx = build_index_at(repo, head)
    verify_index(ctx, idx)  # no evidence => Gadget stays candidate-only
    graph = ObligationGraph(
        snapshot_id="s",
        obligations=[
            Obligation(
                id="o1",
                root_cause="fix gadget",
                task_class="shacl-repair",
                semantic_subjects=["https://ex/ns#Gadget"],
                suggested_write_scope=[],
                acceptance_criteria=["ok"],
            )
        ],
    )
    snap = SemanticSnapshot(authority_digest="a", repository_head=head, working_tree_digest="w")
    pset, _findings = compile_packets(graph, snap, cfg.task_classes, materialisation_index=idx)
    pkt = pset.packets[0]
    assert "semantic/ontology.ttl" in pkt.read_paths  # candidate contributes READ
    assert pkt.write_paths == []  # but not WRITE
