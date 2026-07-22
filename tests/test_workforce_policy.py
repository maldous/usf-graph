"""Unified WorkforcePolicy (dynamic workforce spec §2): layering, precedence,
exclusion-source tracking, inclusion/inference gating, requirement strictness,
and a stable digest. No provider name is privileged; every axis is operator-set."""

from __future__ import annotations

import json

import pytest

from usf_factory.enums import InferenceMode
from usf_factory.errors import ConfigError
from usf_factory.workforce_policy import (
    WorkforcePolicyLayer,
    build_run_policy_layer,
    committed_defaults,
    effective_policy,
    load_policy_layer,
    resolve_workforce_policy,
)


@pytest.mark.unit
def test_committed_defaults_are_provider_neutral():
    d = committed_defaults()
    assert d.exclude_providers == [] and d.exclude_families == [] and d.exclude_models == []
    # Non-paid inference allowed; paid off; safety requirements on.
    assert d.allow_local and d.allow_free and d.allow_subscription and d.allow_paid is False
    assert d.require_source_containment_for_private_source is True
    assert d.require_provider_diverse_review is True


@pytest.mark.unit
def test_exclusion_union_and_source_precedence():
    committed = WorkforcePolicyLayer(exclude_providers=["p_committed"])
    operator = WorkforcePolicyLayer(exclude_providers=["p_operator", "shared"])
    run = WorkforcePolicyLayer(exclude_providers=["p_run", "shared"])
    eff = resolve_workforce_policy(committed, operator, run)
    # Union of all layers.
    assert set(eff.excluded_providers) == {"p_committed", "p_operator", "p_run", "shared"}
    # Source is the highest-precedence layer that lists it.
    assert eff.excluded_providers["p_committed"] == "committed"
    assert eff.excluded_providers["p_operator"] == "operator"
    assert eff.excluded_providers["p_run"] == "run"
    assert eff.excluded_providers["shared"] == "run"  # run wins as source


@pytest.mark.unit
def test_exclusion_beats_inclusion():
    # only_providers would include p, but a run exclusion still wins.
    eff = resolve_workforce_policy(
        committed_defaults(),
        WorkforcePolicyLayer(only_providers=["p", "q"]),
        WorkforcePolicyLayer(exclude_providers=["p"]),
    )
    assert eff.candidate_exclusion(provider_id="p").excluded is True
    q = eff.candidate_exclusion(provider_id="q")
    assert q.excluded is False
    r = eff.candidate_exclusion(provider_id="r")  # not in only_providers
    assert r.excluded is True and r.source == "only_providers"


@pytest.mark.unit
def test_candidate_exclusion_axes():
    run = WorkforcePolicyLayer(
        exclude_models=["prov/m1"],
        exclude_families=["llama"],
        exclude_adapters=["ollama"],
        exclude_actual_models=["gpt-secret"],
    )
    eff = resolve_workforce_policy(committed_defaults(), None, run)
    assert eff.candidate_exclusion(provider_id="prov", model_id="m1").excluded
    assert eff.candidate_exclusion(provider_id="x", model_id="llama-3-8b").excluded
    assert eff.candidate_exclusion(provider_id="x", adapter="ollama").excluded
    assert eff.candidate_exclusion(
        provider_id="x", model_id="m", actual_model="gpt-secret"
    ).excluded
    assert not eff.candidate_exclusion(provider_id="prov", model_id="m2").excluded


@pytest.mark.unit
def test_inference_gating():
    eff = resolve_workforce_policy(committed_defaults(), None, None)
    assert eff.inference_allowed(InferenceMode.SUBSCRIPTION)
    assert not eff.inference_allowed(InferenceMode.PAID)  # default off
    # only_inference_modes restricts to the allowlist.
    only_free = resolve_workforce_policy(
        committed_defaults(),
        None,
        WorkforcePolicyLayer(only_inference_modes=[InferenceMode.FREE]),
    )
    assert only_free.inference_allowed(InferenceMode.FREE)
    assert not only_free.inference_allowed(InferenceMode.SUBSCRIPTION)
    # A candidate whose mode is disallowed is excluded.
    hit = eff.candidate_exclusion(provider_id="p", model_id="m", inference_mode=InferenceMode.PAID)
    assert hit.excluded and hit.source == "inference_gate"


@pytest.mark.unit
def test_requirements_strictest_wins_and_allow_precedence():
    # A run layer cannot relax a committed safety requirement.
    eff = resolve_workforce_policy(
        committed_defaults(),
        None,
        WorkforcePolicyLayer(require_source_containment_for_private_source=False, allow_paid=True),
    )
    assert eff.require_source_containment_for_private_source is True  # cannot be relaxed
    assert eff.allow_paid is True  # allow_* honours the highest explicit layer


@pytest.mark.unit
def test_only_lists_highest_layer_wins():
    eff = resolve_workforce_policy(
        committed_defaults(),
        WorkforcePolicyLayer(only_providers=["op1", "op2"]),
        WorkforcePolicyLayer(only_providers=["run1"]),
    )
    assert eff.only_providers == ["run1"]  # run overrides operator


@pytest.mark.unit
def test_digest_stable_and_sensitive():
    a = resolve_workforce_policy(committed_defaults(), None, None)
    b = resolve_workforce_policy(committed_defaults(), None, None)
    assert a.digest() == b.digest()
    c = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_providers=["x"])
    )
    assert c.digest() != a.digest()


@pytest.mark.unit
def test_load_policy_layer_yaml_and_json(tmp_path):
    y = tmp_path / "p.yaml"
    y.write_text("exclude_providers: [foo]\nallow_paid: true\n", encoding="utf-8")
    layer = load_policy_layer(y)
    assert layer.exclude_providers == ["foo"] and layer.allow_paid is True
    j = tmp_path / "p.json"
    j.write_text(json.dumps({"exclude_models": ["a/b"]}), encoding="utf-8")
    assert load_policy_layer(j).exclude_models == ["a/b"]
    with pytest.raises(ConfigError):
        load_policy_layer(tmp_path / "missing.yaml")


@pytest.mark.unit
def test_effective_policy_composes_run_cli_layer(tmp_path):
    op = tmp_path / "operator.yaml"
    op.write_text("exclude_providers: [op_excluded]\n", encoding="utf-8")
    run = build_run_policy_layer(exclude_providers=["run_excluded"], allow_paid=True)
    eff = effective_policy(config_dir=None, operator_policy_path=op, run_layer=run)
    assert eff.candidate_exclusion(provider_id="op_excluded").excluded  # operator layer applied
    assert eff.candidate_exclusion(provider_id="run_excluded").excluded  # run layer applied
    assert eff.allow_paid is True  # run CLI override
    # A provider named nowhere is not excluded.
    assert not eff.candidate_exclusion(provider_id="other").excluded
