"""Dynamic workforce spec §1/§11/§14: the bootstrap candidate population comes
entirely from discovery + the effective WorkforcePolicy — no provider, model or
family is hard-coded, and any of them can be excluded absolutely."""

from __future__ import annotations

import pytest

from usf_factory.bootstrap import _infer_mode, policy_candidates
from usf_factory.enums import InferenceMode
from usf_factory.workforce_policy import (
    WorkforcePolicyLayer,
    committed_defaults,
    resolve_workforce_policy,
)


def _seed(ctx, pairs):
    for i, (pid, mid, free) in enumerate(pairs):
        ctx.store.put(
            "models",
            f"m{i}",
            {"provider_id": pid, "requested_model_id": mid, "free": free},
            extra={"provider_id": pid},
        )


_MODELS = [
    ("openrouter", "meta-llama/llama-3.3-70b-instruct", True),
    ("groq", "llama-3.1-8b-instant", True),
    ("openrouter", "qwen/qwen-2.5-72b-instruct", True),
    ("ollama", "some-local-model:q4", True),
    ("mistral", "mistral-large-latest", False),
]


@pytest.mark.unit
def test_candidates_come_from_discovery_and_policy(ctx):
    _seed(ctx, _MODELS)
    eff = resolve_workforce_policy(committed_defaults())
    cands, excluded = policy_candidates(ctx, eff)
    got = {f"{c.provider_id}/{c.model_id}" for c in cands}
    # Free/local models appear from discovery; no provider/family is privileged.
    assert "openrouter/qwen/qwen-2.5-72b-instruct" in got
    assert any("llama" in g for g in got)  # llama NOT excluded by default (§11)
    assert any(g.startswith("ollama/") for g in got)  # ollama NOT excluded by default
    # mistral-large is a metered PAID transport; paid is off by default, so it is
    # gated out (not by name — by its derived inference class).
    assert "mistral/mistral-large-latest" not in got
    assert any("mistral/mistral-large-latest" in e for e in excluded)
    # No candidate exists that was not seeded (discovery is the sole source).
    assert got <= {f"{p}/{m}" for p, m, _ in _MODELS}


@pytest.mark.adversarial
def test_excluding_provider_and_family_removes_matches(ctx):
    _seed(ctx, _MODELS)
    eff = resolve_workforce_policy(
        committed_defaults(),
        None,
        WorkforcePolicyLayer(exclude_providers=["ollama"], exclude_families=["llama"]),
    )
    cands, excluded = policy_candidates(ctx, eff)
    got = {f"{c.provider_id}/{c.model_id}" for c in cands}
    assert not any("llama" in g for g in got)  # family gone
    assert not any(g.startswith("ollama/") for g in got)  # provider gone
    assert "openrouter/qwen/qwen-2.5-72b-instruct" in got  # non-matching kept
    # Every removal is recorded with a reason + source for the report.
    assert any("family 'llama' excluded" in e for e in excluded)
    assert any("provider 'ollama' excluded" in e for e in excluded)


@pytest.mark.unit
def test_only_inference_mode_gates_population(ctx):
    _seed(ctx, _MODELS)
    # Only FREE inference allowed: paid mistral drops; free models remain.
    eff = resolve_workforce_policy(
        committed_defaults(),
        None,
        WorkforcePolicyLayer(only_inference_modes=[InferenceMode.FREE]),
    )
    cands, _excluded = policy_candidates(ctx, eff)
    got = {f"{c.provider_id}/{c.model_id}" for c in cands}
    assert "mistral/mistral-large-latest" not in got  # paid mode gated out
    assert "openrouter/qwen/qwen-2.5-72b-instruct" in got  # free kept


@pytest.mark.unit
def test_infer_mode_from_evidence_not_name(ctx):
    providers = ctx.config.providers.by_id()
    # ollama (local transport) -> LOCAL regardless of the model's free flag.
    if "ollama" in providers:
        assert _infer_mode(providers["ollama"], {"free": True}) is InferenceMode.LOCAL
    # a free-priced cloud model -> FREE; a metered one -> PAID.
    if "mistral" in providers:
        assert _infer_mode(providers["mistral"], {"free": True}) is InferenceMode.FREE
        assert _infer_mode(providers["mistral"], {"free": False}) is InferenceMode.PAID
