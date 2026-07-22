"""Lazy, coverage-directed qualification (spec §10) + §14 de-hardcoding checks:
qualify only enough to fill role coverage, cheapest-by-metadata, bounded; never
provider/catalogue order as a quality signal; any provider is fully excludable and
excluding the CLIs still permits other qualified providers."""

from __future__ import annotations

import pytest

from usf_factory.enums import AdmissionRole
from usf_factory.lazy_qualification import (
    coverage_directed_candidates,
    coverage_gaps,
    rank_candidates_to_qualify,
)
from usf_factory.workforce import WorkforceSnapshot
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


def _snap(coverage):
    return WorkforceSnapshot(
        policy_digest="pd", config_digest="cd", rule_bundle_digest="rd", coverage=coverage
    )


@pytest.mark.unit
def test_coverage_gaps_lists_uncovered_operational_roles():
    snap = _snap({AdmissionRole.PLANNER_CANDIDATE.value: 1})  # others absent => 0
    gaps = coverage_gaps(snap)
    assert AdmissionRole.PLANNER_CANDIDATE.value not in gaps
    assert AdmissionRole.PATCH_PRODUCER.value in gaps
    assert AdmissionRole.REVIEWER.value in gaps


@pytest.mark.unit
def test_full_coverage_qualifies_nothing(ctx):
    full = {r.value: 1 for r in AdmissionRole}
    policy = resolve_workforce_policy(committed_defaults())
    cands, gaps = coverage_directed_candidates(ctx, policy, _snap(full))
    assert cands == [] and gaps == []  # reuse valid evidence; no new qualification


@pytest.mark.unit
def test_rank_cheapest_by_metadata_and_bounded(ctx):
    # local < free < subscription (a genuine cost signal, not provider order).
    _seed(
        ctx,
        [
            ("mistral", "paid-model", False),  # paid -> excluded by default
            ("claude-cli", "sub-model", False),  # subscription
            ("openrouter", "free-model", True),  # free
            ("ollama", "local-model", False),  # local
        ],
    )
    policy = resolve_workforce_policy(committed_defaults())
    ranked = rank_candidates_to_qualify(ctx, policy, max_new=2)
    modes = [c.mode for c in ranked]
    assert modes == ["local", "free"]  # cheapest first, bounded to 2, paid excluded


@pytest.mark.adversarial
def test_excluded_provider_never_in_qualification_plan(ctx):
    _seed(ctx, [("ollama", "local-model", False), ("openrouter", "free-model", True)])
    policy = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_providers=["ollama"])
    )
    ranked = rank_candidates_to_qualify(ctx, policy)
    assert not any(c.provider_id == "ollama" for c in ranked)
    assert any(c.provider_id == "openrouter" for c in ranked)


@pytest.mark.adversarial
def test_excluding_both_clis_still_permits_other_providers(ctx):
    from usf_factory.bootstrap import policy_candidates

    _seed(
        ctx,
        [
            ("claude-cli", "c", False),
            ("codex-cli", "x", False),
            ("openrouter", "free-model", True),
            ("ollama", "local-model", False),
        ],
    )
    policy = resolve_workforce_policy(
        committed_defaults(),
        None,
        WorkforcePolicyLayer(exclude_providers=["claude-cli", "codex-cli"]),
    )
    cands, excluded = policy_candidates(ctx, policy)
    providers = {c.provider_id for c in cands}
    assert "claude-cli" not in providers and "codex-cli" not in providers
    assert {"openrouter", "ollama"} <= providers  # other providers still available
