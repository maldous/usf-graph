"""Hotfix P0-4: a required validation gate may only report not-applicable when it
is explicitly CONDITIONAL (deterministic changed-file predicate). Anything else
fails closed — required tests and USF gates can never green-skip."""

from __future__ import annotations

import pytest

from usf_factory.validation import CONDITIONAL_GATES, run_validation


def _na():
    return None, "nothing applicable"


def _pass():
    return True, "ok"


def _fail():
    return False, "broken"


@pytest.mark.unit
def test_required_gate_without_runner_fails():
    receipt = run_validation("s", ["unit-tests"], {})
    assert receipt.all_passed is False
    assert receipt.gates["unit-tests"] is False


@pytest.mark.adversarial
def test_required_gate_reporting_na_fails():
    # unit-tests is NOT conditional: "no tests/ directory" may not green-skip.
    assert "unit-tests" not in CONDITIONAL_GATES
    receipt = run_validation("s", ["unit-tests"], {"unit-tests": _na})
    assert receipt.all_passed is False
    assert receipt.gates["unit-tests"] is False
    assert "not-applicable" in receipt.detail["unit-tests"]


@pytest.mark.unit
def test_conditional_gate_na_is_allowed():
    # format's n/a predicate is deterministic ("no .py files changed").
    assert "format" in CONDITIONAL_GATES
    receipt = run_validation("s", ["format"], {"format": _na})
    assert receipt.all_passed is True
    assert "format" not in receipt.gates  # recorded as n/a, not as a pass


@pytest.mark.unit
def test_real_verdicts_still_apply():
    receipt = run_validation("s", ["format", "unit-tests"], {"format": _pass, "unit-tests": _fail})
    assert receipt.all_passed is False
    assert receipt.gates["format"] is True and receipt.gates["unit-tests"] is False


@pytest.mark.adversarial
def test_live_usf_gates_are_not_conditional():
    # Gates that need the live USF Node/authority toolchain must fail on N/A.
    for gate in ("proof-readiness", "negative-fixtures", "competency-queries", "integration-tests"):
        assert gate not in CONDITIONAL_GATES
        receipt = run_validation("s", [gate], {gate: _na})
        assert receipt.all_passed is False, f"{gate} green-skipped"


@pytest.mark.unit
def test_real_rdf_gates_are_conditional():
    # shacl / integrity-sparql are REAL (rdflib/pyshacl); their N/A is a
    # deterministic changed-file predicate, so they may report N/A.
    for gate in ("shacl", "integrity-sparql", "syntax-parse"):
        assert gate in CONDITIONAL_GATES


def _git(args, cwd):
    import subprocess

    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


@pytest.fixture
def clone_with(tmp_path):
    """A git clone helper: stage given files so build_runners sees them changed."""
    counter = {"n": 0}

    def make(files: dict[str, str], *, baseline: dict[str, str] | None = None) -> object:
        counter["n"] += 1
        repo = tmp_path / f"clone{counter['n']}"
        repo.mkdir()
        _git(["init", "-q", "-b", "main"], repo)
        _git(["config", "user.email", "t@e"], repo)
        _git(["config", "user.name", "t"], repo)
        (repo / ".keep").write_text("")
        for rel, content in (baseline or {}).items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        _git(["add", "-A"], repo)
        _git(["commit", "-q", "-m", "base"], repo)
        for rel, content in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        _git(["add", "-A"], repo)
        return repo

    return make


@pytest.mark.e2e
def test_real_rdflib_syntax_parse_catches_bad_turtle(clone_with):
    from usf_factory.validation_runners import build_runners

    good = build_runners(
        clone_with({"semantic/a.ttl": "@prefix ex: <https://ex/ns#> .\nex:A a ex:Class .\n"})
    )
    passed, detail = good["syntax-parse"]()
    assert passed is True and "rdflib" in detail
    # Genuinely invalid Turtle (bracket counting would MISS this — it is balanced).
    bad = build_runners(
        clone_with({"semantic/b.ttl": "@prefix ex: <https://ex/ns#> .\nex:A ex:p ex:o\n"})
    )
    passed, detail = bad["syntax-parse"]()
    assert passed is False and "parse failed" in detail


@pytest.mark.e2e
def test_real_pyshacl_shacl_validation(clone_with):
    from usf_factory.validation_runners import build_runners

    shape = (
        "@prefix ex: <https://ex/ns#> .\n@prefix sh: <http://www.w3.org/ns/shacl#> .\n"
        "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n"
        "ex:PersonShape a sh:NodeShape ; sh:targetClass ex:Person ;\n"
        "  sh:property [ sh:path ex:age ; sh:datatype xsd:integer ; sh:maxCount 1 ] .\n"
    )
    conforming = (
        "@prefix ex: <https://ex/ns#> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n"
        'ex:alice a ex:Person ; ex:age "30"^^xsd:integer .\n'
    )
    violating = (
        "@prefix ex: <https://ex/ns#> .\n"
        'ex:bob a ex:Person ; ex:age "x" ; ex:age "y" .\n'  # wrong datatype + maxCount
    )
    ok = build_runners(
        clone_with({"semantic/shapes/p.shacl.ttl": shape, "semantic/data.ttl": conforming})
    )
    passed, detail = ok["shacl"]()
    assert passed is True and "conforms" in detail
    bad = build_runners(
        clone_with({"semantic/shapes/p.shacl.ttl": shape, "semantic/data.ttl": violating})
    )
    passed, _detail = bad["shacl"]()
    assert passed is False  # real pyshacl caught the violation


@pytest.mark.adversarial
def test_shacl_uses_tracked_baseline_shapes_for_changed_data(clone_with):
    from usf_factory.validation_runners import build_runners

    shape = (
        "@prefix ex: <https://ex/ns#> .\n@prefix sh: <http://www.w3.org/ns/shacl#> .\n"
        "ex:S a sh:NodeShape ; sh:targetClass ex:Person ;\n"
        " sh:property [ sh:path ex:name ; sh:minCount 1 ] .\n"
    )
    changed = "@prefix ex: <https://ex/ns#> .\nex:alice a ex:Person .\n"
    repo = clone_with(
        {"semantic/data.ttl": changed},
        baseline={"semantic/shapes/person.shacl.ttl": shape},
    )
    passed, detail = build_runners(repo)["shacl"]()
    assert passed is False and "SHACL violations" in detail


@pytest.mark.adversarial
def test_integrity_queries_fail_when_select_or_ask_returns_a_violation(clone_with):
    from usf_factory.validation_runners import build_runners

    data = "@prefix ex: <https://ex/ns#> .\nex:a ex:p ex:o .\n"
    select = "PREFIX ex: <https://ex/ns#> SELECT ?s WHERE { ?s ex:p ex:o }"
    ask = "PREFIX ex: <https://ex/ns#> ASK { ?s ex:p ex:o }"
    for query in (select, ask):
        repo = clone_with(
            {"semantic/integrity.rq": query},
            baseline={"semantic/data.ttl": data},
        )
        passed, detail = build_runners(repo)["integrity-sparql"]()
        assert passed is False and "integrity violations" in detail


@pytest.mark.adversarial
def test_changed_file_discovery_failure_cannot_become_empty_green_set(tmp_path):
    from usf_factory.validation_runners import build_runners

    not_a_repository = tmp_path / "not-a-repository"
    not_a_repository.mkdir()
    passed, detail = build_runners(not_a_repository)["syntax-parse"]()
    assert passed is False and "git changed-file discovery failed" in detail


@pytest.mark.adversarial
def test_assurance_toolchain_change_requires_pinned_independent_verifier(clone_with):
    from usf_factory.validation_runners import build_runners

    repo = clone_with({"processes/semantic-assurance/publish.mjs": "export default 1;\n"})
    passed, detail = build_runners(repo)["independent-trust-boundary"]()
    assert passed is False
    assert "pinned external verifier required" in detail


@pytest.mark.adversarial
def test_validation_subprocess_environment_excludes_ambient_credentials(monkeypatch):
    monkeypatch.setenv("STARDOG_PASSWORD", "must-not-propagate")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-propagate")
    from usf_factory.github_delivery import restricted_subprocess_environment

    env = restricted_subprocess_environment(github=False)
    assert "STARDOG_PASSWORD" not in env
    assert "OPENAI_API_KEY" not in env
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
