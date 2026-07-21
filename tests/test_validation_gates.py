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
def test_usf_gates_are_not_conditional():
    for gate in ("shacl", "integrity-sparql", "proof-readiness", "integration-tests"):
        assert gate not in CONDITIONAL_GATES
        receipt = run_validation("s", [gate], {gate: _na})
        assert receipt.all_passed is False, f"{gate} green-skipped"
