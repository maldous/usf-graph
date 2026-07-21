"""Probe grading + qualification scoring + admission roles."""

from __future__ import annotations

import pytest

from usf_factory.config import load_config
from usf_factory.enums import SCORE_DIMENSIONS, AdmissionRole, ProbeKind
from usf_factory.paths import bundled_qualifications_dir
from usf_factory.probes import default_probe_specs, grade_probe
from usf_factory.qualification import (
    build_run,
    compute_admission_roles,
    grade_case,
    load_corpus,
)


@pytest.mark.unit
def test_probe_iri_and_digest_preservation():
    specs = {s.kind: s for s in default_probe_specs()}
    ok = grade_probe(specs[ProbeKind.IRI_PRESERVATION], "https://example.org/usf#Capability_A1b2C3")
    bad = grade_probe(specs[ProbeKind.IRI_PRESERVATION], "https://example.org/usf#Capability_XXXX")
    assert ok.passed and not bad.passed


@pytest.mark.unit
def test_probe_uncertainty_rejects_fabrication():
    specs = {s.kind: s for s in default_probe_specs()}
    fab = grade_probe(specs[ProbeKind.EXPLICIT_UNCERTAINTY], "The employee ID is 12345.")
    honest = grade_probe(
        specs[ProbeKind.EXPLICIT_UNCERTAINTY], "I don't know; insufficient information."
    )
    assert not fab.passed and honest.passed


@pytest.mark.unit
def test_probe_prohibited_tool_compliance():
    specs = {s.kind: s for s in default_probe_specs()}
    good = grade_probe(specs[ProbeKind.PROHIBITED_TOOL_COMPLIANCE], "4", tool_calls=[])
    bad = grade_probe(
        specs[ProbeKind.PROHIBITED_TOOL_COMPLIANCE], "4", tool_calls=[{"name": "shell"}]
    )
    assert good.passed and not bad.passed


@pytest.mark.unit
def test_probe_strict_json_and_patch_format():
    specs = {s.kind: s for s in default_probe_specs()}
    j = grade_probe(specs[ProbeKind.STRICT_JSON], '{"name":"probe","count":3}')
    assert j.passed
    p = grade_probe(
        specs[ProbeKind.PATCH_FORMAT],
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+hello",
    )
    assert p.passed


@pytest.mark.unit
def test_corpus_covers_all_trust_dimensions():
    cfg = load_config()
    suite = load_corpus(bundled_qualifications_dir(), bundled_qualifications_dir() / "holdout")
    case_dims = {c.dimension for c in suite.cases}
    needed = set()
    for th in cfg.trust.role_thresholds.values():
        needed |= set(th.min_scores.keys())
    assert needed <= case_dims, f"uncovered: {needed - case_dims}"
    # every case dimension is a known dimension
    assert case_dims <= set(SCORE_DIMENSIONS)


@pytest.mark.unit
def test_holdout_present():
    suite = load_corpus(bundled_qualifications_dir(), bundled_qualifications_dir() / "holdout")
    assert any(c.holdout for c in suite.cases)


@pytest.mark.unit
def test_grade_case_choice_and_uncertainty():
    from usf_factory.models import QualificationCase

    c = QualificationCase(
        case_id="x",
        task_class="t",
        dimension="semantic_planning",
        prompt="p",
        grader="choice",
        expected={"value": "no"},
    )
    assert grade_case(c, "no") == 1.0
    assert grade_case(c, "yes") == 0.0


@pytest.mark.unit
def test_admission_roles_earned_and_default_unqualified():
    cfg = load_config()
    suite = load_corpus(bundled_qualifications_dir(), bundled_qualifications_dir() / "holdout")
    # Perfect answers.
    import json

    perfect = {}
    for c in suite.cases:
        g = c.grader
        if g in ("choice", "exact", "contains"):
            perfect[c.case_id] = str(c.expected.get("value", ""))
        elif g == "iri_exact":
            perfect[c.case_id] = c.expected["iri"]
        elif g == "json_schema":
            props = c.expected["schema"].get("properties", {})
            o = {}
            for k, v in props.items():
                t = v.get("type")
                o[k] = (
                    []
                    if t == "array"
                    else (True if t == "boolean" else (1 if t == "integer" else "x"))
                )
            perfect[c.case_id] = json.dumps(o)
        elif g == "regex":
            perfect[c.case_id] = {
                "sparql-bounded": "SELECT ?s WHERE { ?s a <http://ex/W> } LIMIT 10",
                "impl-patch-format": "@@ -0,0 +1 @@\n+ok",
            }.get(c.case_id, "x")
        elif g == "uncertainty":
            perfect[c.case_id] = "I do not know; insufficient evidence."
        else:
            perfect[c.case_id] = "x"

    run = build_run(agent_profile_id="a", suite=suite, answers=perfect, trust=cfg.trust)
    assert run.cases_passed == run.cases_total
    assert AdmissionRole.PATCH_PRODUCER in run.roles_admitted
    assert AdmissionRole.TRUSTED_COORDINATOR in run.roles_admitted

    bad = build_run(
        agent_profile_id="b",
        suite=suite,
        answers={c.case_id: "" for c in suite.cases},
        trust=cfg.trust,
    )
    assert bad.roles_admitted == [AdmissionRole.UNQUALIFIED]


@pytest.mark.unit
def test_admission_never_grants_write_without_scores():
    cfg = load_config()
    # Only READ_ONLY thresholds satisfied.
    dims = {"structured_output": 0.9, "uncertainty_handling": 0.9}
    roles = compute_admission_roles(dims, cfg.trust)
    assert AdmissionRole.READ_ONLY_ANALYST in roles
    assert AdmissionRole.PATCH_PRODUCER not in roles
    assert AdmissionRole.INTEGRATOR not in roles
