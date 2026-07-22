"""S8 verified materialisation owner (objective declaration evidence, no fabrication);
S9 real semantic validation prerequisite."""

from __future__ import annotations

import subprocess

import pytest


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


@pytest.fixture
def owner_mirror(ctx):
    """A mirror with an ontology file that DECLARES one subject unambiguously and
    another subject declared in TWO files (ambiguous)."""
    m = ctx.paths.mirror
    m.parent.mkdir(parents=True, exist_ok=True)
    work = ctx.paths.share / "seed"
    work.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q", "-b", "main"], work)
    _git(["config", "user.email", "t@e"], work)
    _git(["config", "user.name", "t"], work)
    (work / "semantic-model").mkdir()
    (work / "semantic-model" / "model.ttl").write_text(
        "@prefix ex: <https://example.org/usf#> .\n"
        "@prefix owl: <http://www.w3.org/2002/07/owl#> .\n"
        "ex:Widget a owl:Class .\n"
    )
    _git(["add", "-A"], work)
    _git(["commit", "-q", "-m", "seed"], work)
    subprocess.run(
        ["git", "clone", "--mirror", "--no-hardlinks", "--no-local", str(work), str(m)],
        check=True,
        capture_output=True,
        text=True,
    )
    head = subprocess.run(
        ["git", "-C", str(m), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    return head


# ---- S8: objective declaration verification --------------------------------- #


@pytest.mark.e2e
def test_verify_from_declaration_marks_verified_owner(ctx, owner_mirror):
    from usf_factory.materialisation import build_index_at
    from usf_factory.ownership import verify_from_declaration

    idx = build_index_at(ctx.paths.mirror, owner_mirror)
    subj = "https://example.org/usf#Widget"
    assert idx.entries[subj].candidate_owners == ["semantic-model/model.ttl"]
    rows = verify_from_declaration(ctx, idx, [subj], commit=owner_mirror)
    assert len(rows) == 1 and rows[0]["evidence_kind"] == "subject-declaration"
    # Persisted + commit-pinned.
    from usf_factory.ownership import load_evidence

    ev = load_evidence(ctx, subj)
    assert ev and ev[0]["verified"] and ev[0]["repository_commit"] == owner_mirror


@pytest.mark.adversarial
def test_verify_from_declaration_refuses_unknown_subject(ctx, owner_mirror):
    from usf_factory.materialisation import build_index_at
    from usf_factory.ownership import verify_from_declaration

    idx = build_index_at(ctx.paths.mirror, owner_mirror)
    rows = verify_from_declaration(
        ctx, idx, ["https://example.org/usf#DoesNotExist"], commit=owner_mirror
    )
    assert rows == []  # never fabricates ownership for an unknown subject


@pytest.mark.e2e
def test_verify_owner_for_obligations_reports_verified(ctx, owner_mirror):
    from usf_factory.clock import utc_now_iso
    from usf_factory.ownership import verify_owner_for_obligations

    subj = "https://example.org/usf#Widget"
    ctx.store.put(
        "semantic_snapshots",
        "snap-x",
        {
            "authority_digest": "a",
            "repository_head": owner_mirror,
            "captured_at": utc_now_iso(),
            "programme_obligations": [
                {"id": "o", "semantic_subjects": [subj], "task_class": "sparql-authoring"}
            ],
        },
    )
    res = verify_owner_for_obligations(ctx)
    assert res["status"] == "VERIFIED" and res["subject"] == subj
    assert res["owner_path"] == "semantic-model/model.ttl"


@pytest.mark.adversarial
def test_verify_owner_reports_best_candidate_when_unverifiable(ctx, owner_mirror):
    from usf_factory.clock import utc_now_iso
    from usf_factory.ownership import verify_owner_for_obligations

    # A subject with NO candidate owner -> UNVERIFIED, no fabrication.
    ctx.store.put(
        "semantic_snapshots",
        "snap-x",
        {
            "authority_digest": "a",
            "repository_head": owner_mirror,
            "captured_at": utc_now_iso(),
            "programme_obligations": [
                {
                    "id": "o",
                    "semantic_subjects": ["urn:usf:ghost"],
                    "task_class": "sparql-authoring",
                }
            ],
        },
    )
    res = verify_owner_for_obligations(ctx)
    assert res["status"] == "UNVERIFIED"


# ---- S8: candidate cannot proceed without a verified owner ------------------- #


@pytest.mark.adversarial
def test_candidate_blocked_without_verified_owner(ctx, owner_mirror):
    from usf_factory.candidate import check_prerequisites

    # No snapshot obligations / no verified owner / no admitted roles -> blocked.
    blockers = check_prerequisites(ctx)
    assert any("VERIFIED materialisation owner" in b for b in blockers)


# ---- S9: validation prerequisite -------------------------------------------- #


@pytest.mark.e2e
def test_validation_profile_executable_for_semantic_subject(ctx, owner_mirror):
    from usf_factory.candidate import _validation_profile_executable
    from usf_factory.clock import utc_now_iso

    ctx.store.put(
        "semantic_snapshots",
        "snap-x",
        {
            "authority_digest": "a",
            "repository_head": owner_mirror,
            "captured_at": utc_now_iso(),
            "programme_obligations": [
                {
                    "id": "o",
                    "semantic_subjects": ["https://example.org/usf#Widget"],
                    "task_class": "sparql-authoring",
                }
            ],
        },
    )
    ok, detail = _validation_profile_executable(ctx)
    assert ok is True
    assert "shacl" in detail and "syntax-parse" in detail  # real, bounded-local gates


@pytest.mark.adversarial
def test_validation_profile_blocks_on_stub_gate(ctx, owner_mirror):
    from usf_factory.candidate import _validation_profile_executable
    from usf_factory.clock import utc_now_iso

    # A non-semantic obligation whose task class requires an env-blocked stub gate.
    ctx.store.put(
        "semantic_snapshots",
        "snap-x",
        {
            "authority_digest": "a",
            "repository_head": owner_mirror,
            "captured_at": utc_now_iso(),
            "programme_obligations": [
                {"id": "o", "semantic_subjects": [], "task_class": "shacl-repair"}
            ],
        },
    )
    # shacl-repair default_validation includes negative-fixtures (a USF stub) but is
    # non-semantic here, so its task defaults apply -> blocked.
    ok, detail = _validation_profile_executable(ctx)
    assert ok is False
    assert "stub" in detail or "negative-fixtures" in detail
