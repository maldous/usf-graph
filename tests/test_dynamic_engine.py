"""Spec Part A — the dynamic workforce is the SOLE live execution authority.

These tests exercise the production engine's dynamic dispatch path directly:
selection comes from the current WorkforceSnapshot (never RoleRoster.primary), the
legacy Scheduler is never instantiated in the run path, live dispatches draw fresh
seeds, transient failures redraw to a second provider while the claim is held once,
exclusions apply before every attempt, reviewer/integrator selection is dynamic and
independent, and lazy qualification can restore missing capability.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from conftest import all_dimension_scores, seed_agent
from usf_factory.engine import FactoryEngine
from usf_factory.enums import AdmissionRole, FailureClass, PacketResultStatus, Risk, RunMode
from usf_factory.models import Packet, PacketResult, PacketSet, RequiredCapabilities
from usf_factory.workforce_policy import (
    WorkforcePolicyLayer,
    committed_defaults,
    resolve_workforce_policy,
)

CID = "cyc-parta"
ANALYST = AdmissionRole.READ_ONLY_ANALYST


def _base(eng: FactoryEngine) -> str:
    """Ensure the factory mirror exists (preflight normally does this) and return
    its head, so direct ``_execute_one`` calls have a real base commit to clone.

    Direct invocation tests also establish the coordinator fence that a normal
    ``run_cycle`` owns before execution.
    """
    if eng._coordinator_token is None:
        eng._coordinator_token = eng.ctx.store.acquire_lease(
            "coordinator", CID, "2999-01-01T00:00:00Z"
        )
        assert eng._coordinator_token is not None
    eng.iso.ensure_mirror()
    return eng.iso.mirror_head()


def _ro_packet(base_head: str, *, risk: Risk = Risk.MEDIUM) -> Packet:
    return Packet(
        obligation_id="o",
        snapshot_id="s",
        authority_digest="a",
        base_head=base_head,
        objective="analyze",
        task_class="semantic-analysis",
        risk=risk,
        data_classification="public",
        write_paths=[],
        permitted_tools=[],
        required_capabilities=RequiredCapabilities(),
    )


class _Worker:
    """A fake worker whose behaviour is chosen per provider by a policy callback."""

    def __init__(self, behave, agent, calls):
        self._behave = behave
        self._agent = agent
        self._calls = calls

    async def execute(self, packet, workspace, agent):
        self._calls.append(agent.provider_id)
        return self._behave(packet, agent, len(self._calls))


def _factory(behave, calls):
    def make(mode, agent):
        return _Worker(behave, agent, calls)

    return make


def _completed(packet, agent):
    return PacketResult(
        packet_id=packet.packet_id,
        status=PacketResultStatus.COMPLETED,
        agent_profile_id=agent.profile_id,
        actual_provider=agent.provider_id,
        actual_model=agent.requested_model_id,
        base_head=packet.base_head,
    )


def _transient(packet, agent):
    return PacketResult(
        packet_id=packet.packet_id,
        status=PacketResultStatus.FAILED,
        agent_profile_id=agent.profile_id,
        actual_provider=agent.provider_id,
        base_head=packet.base_head,
        failure_class=FailureClass.PROVIDER_OUTAGE,  # transient => redraw
        failure_detail="temporary outage",
    )


# --------------------------------------------------------------------------- #


@pytest.mark.e2e
def test_selection_comes_from_workforce_not_roster(ctx, tmp_usf):
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="alpha")
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="beta")
    calls: list[str] = []
    eng = FactoryEngine(ctx, worker_factory=_factory(lambda p, a, n: _completed(p, a), calls))
    packet = _ro_packet(_base(eng))
    result = asyncio.run(eng._execute_one(packet, CID, RunMode.SHADOW))
    assert result is not None and result.status is PacketResultStatus.COMPLETED
    assert result.actual_provider in {"alpha", "beta"}  # a snapshot member, not a fixed primary
    # The recorded routing decision selected from the snapshot population.
    dec = ctx.store.get("routing_decisions", f"{packet.packet_id}:{CID}")
    assert dec["snapshot_id"].startswith("wf-")
    assert dec["selected_profile_id"] is not None


@pytest.mark.e2e
def test_production_engine_never_invokes_legacy_scheduler(ctx, tmp_usf, monkeypatch):
    import usf_factory.scheduler as sched

    def _boom(*a, **k):
        raise AssertionError("production path must not instantiate the legacy Scheduler")

    monkeypatch.setattr(sched.Scheduler, "__init__", _boom)
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="alpha")
    calls: list[str] = []
    eng = FactoryEngine(ctx, worker_factory=_factory(lambda p, a, n: _completed(p, a), calls))
    packet = _ro_packet(_base(eng))
    pset = PacketSet(
        snapshot_id="s", graph_id="g", packets=[packet], selected_packet_ids=[packet.packet_id]
    )
    # Both the dispatch-plan stage and live execution must avoid the Scheduler.
    eng.schedule_packets(pset, CID)
    result = asyncio.run(eng._execute_one(packet, CID, RunMode.SHADOW))
    assert result is not None and result.status is PacketResultStatus.COMPLETED


@pytest.mark.e2e
def test_live_dispatches_draw_distinct_seeds(ctx, tmp_usf):
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="alpha")
    calls: list[str] = []
    eng = FactoryEngine(ctx, worker_factory=_factory(lambda p, a, n: _completed(p, a), calls))
    base = _base(eng)
    seeds = set()
    for _ in range(3):
        asyncio.run(eng._execute_one(_ro_packet(base), CID, RunMode.SHADOW))
    for _key, row in ctx.store.items("routing_decisions"):
        if row.get("run_seed"):
            seeds.add(row["run_seed"])
    assert len(seeds) >= 2  # independent live dispatches use fresh cryptographic seeds


@pytest.mark.adversarial
def test_transient_failure_redraws_to_second_provider(ctx, tmp_usf):
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="alpha")
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="beta")
    calls: list[str] = []

    def behave(packet, agent, n):
        # First candidate (whichever is drawn) fails transiently; the redraw
        # necessarily lands on the OTHER provider, which completes the packet.
        return _transient(packet, agent) if n == 1 else _completed(packet, agent)

    eng = FactoryEngine(ctx, worker_factory=_factory(behave, calls))
    packet = _ro_packet(_base(eng))
    result = asyncio.run(eng._execute_one(packet, CID, RunMode.SHADOW))
    assert result is not None and result.status is PacketResultStatus.COMPLETED
    assert len(calls) == 2 and calls[0] != calls[1]  # redrew to a DIFFERENT provider
    # The full dispatch outcome records both attempts (transient then success).
    rows = [r for _k, r in ctx.store.items("dispatch_outcomes")]
    assert rows and len(rows[0]["attempts"]) == 2
    assert rows[0]["attempts"][0]["ok"] is False and rows[0]["attempts"][1]["ok"] is True


@pytest.mark.adversarial
def test_claim_and_budget_correct_across_redraws(ctx, tmp_usf):
    from usf_factory.budget import BudgetLedger, BudgetLimits

    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="alpha")
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="beta")
    calls: list[str] = []

    def behave(packet, agent, n):
        return _transient(packet, agent) if n == 1 else _completed(packet, agent)

    eng = FactoryEngine(ctx, worker_factory=_factory(behave, calls))
    packet = _ro_packet(_base(eng))
    asyncio.run(eng._execute_one(packet, CID, RunMode.SHADOW))
    # Local/free providers draw no paid budget; nothing is left reserved.
    ledger = BudgetLedger(ctx.store, BudgetLimits(global_usd=ctx.config.budgets.billable_usd))
    assert ledger.spent_total() == 0.0
    # The packet claim was released (a fresh claim can be acquired again).
    tok = ctx.store.claim_packet_fenced(
        packet.packet_id, "rerun", "engine", eng._lease_deadline(60)
    )
    assert tok is not None


@pytest.mark.adversarial
def test_exclusion_applies_before_dispatch(ctx, tmp_usf):
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="alpha")
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="beta")
    calls: list[str] = []
    policy = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_providers=["alpha"])
    )
    eng = FactoryEngine(
        ctx, worker_factory=_factory(lambda p, a, n: _completed(p, a), calls), policy=policy
    )
    packet = _ro_packet(_base(eng))
    result = asyncio.run(eng._execute_one(packet, CID, RunMode.SHADOW))
    assert result is not None and result.actual_provider == "beta"
    assert "alpha" not in calls  # excluded provider is never invoked


@pytest.mark.adversarial
def test_scenario_e_run_model_exclusion_precedes_invocation(ctx, tmp_usf):
    """An excluded CLI/model is absent before dispatch while the allowed peer runs."""
    excluded_ref = "claude-cli/claude-opus-4-8"
    seed_agent(
        ctx.store,
        roles=[ANALYST.value],
        scores=all_dimension_scores(),
        provider_id="claude-cli",
        model="claude-opus-4-8",
        adapter="claude_cli",
        actual_models=["claude-opus-4-8"],
    )
    seed_agent(
        ctx.store,
        roles=[ANALYST.value],
        scores=all_dimension_scores(),
        provider_id="codex-cli",
        model="gpt-5-codex",
        adapter="codex_cli",
        actual_models=["gpt-5-codex"],
    )
    calls: list[str] = []
    policy = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_models=[excluded_ref])
    )
    eng = FactoryEngine(
        ctx,
        worker_factory=_factory(lambda p, a, n: _completed(p, a), calls),
        policy=policy,
    )
    packet = _ro_packet(_base(eng))
    result = asyncio.run(eng._execute_one(packet, CID, RunMode.SHADOW))
    assert result is not None and result.actual_provider == "codex-cli"
    assert calls == ["codex-cli"]
    snapshot = eng._current_workforce()
    assert any(excluded_ref in note and "source=run" in note for note in snapshot.excluded)
    assert all(profile.provider_id != "claude-cli" for profile in snapshot.profiles)


@pytest.mark.adversarial
def test_lazy_qualification_restores_capability(ctx, tmp_usf):
    # No candidate is admitted initially => the run path would block. The lazy
    # qualifier admits one and reports it changed; the engine rebuilds the snapshot
    # and retries eligibility once, then dispatches.
    calls: list[str] = []
    restored: dict[str, bool] = {"done": False}

    def qualifier(roles):
        if restored["done"]:
            return False
        seed_agent(
            ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="late"
        )
        restored["done"] = True
        return True

    eng = FactoryEngine(
        ctx,
        worker_factory=_factory(lambda p, a, n: _completed(p, a), calls),
        lazy_qualifier=qualifier,
    )
    packet = _ro_packet(_base(eng))
    result = asyncio.run(eng._execute_one(packet, CID, RunMode.SHADOW))
    assert result is not None and result.actual_provider == "late"


@pytest.mark.adversarial
def test_reviewer_selection_is_adaptive_and_independent(ctx, tmp_usf):
    from usf_factory.dispatch import select_reviewer
    from usf_factory.workforce import build_workforce_snapshot

    # Two reviewers on distinct providers; one shares the authoring provider.
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.REVIEWER.value],
        scores=all_dimension_scores(),
        provider_id="author",
    )
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.REVIEWER.value],
        scores=all_dimension_scores(),
        provider_id="indep",
    )
    policy = resolve_workforce_policy(committed_defaults())
    snap = build_workforce_snapshot(ctx, policy)
    prof, reason = select_reviewer(snap, policy, authoring_providers={"author"})
    assert prof is not None and prof.provider_id == "indep"  # never an authoring provider
    # With ONLY the authoring provider available, review blocks (no silent reuse).
    prof2, reason2 = select_reviewer(snap, policy, authoring_providers={"author", "indep"})
    assert prof2 is None and "independent reviewer" in reason2


@pytest.mark.adversarial
def test_integrator_selection_is_dynamic(ctx, tmp_usf):
    from usf_factory.dispatch import select_integrator
    from usf_factory.workforce import build_workforce_snapshot

    seed_agent(
        ctx.store,
        roles=[AdmissionRole.INTEGRATOR.value],
        scores=all_dimension_scores(),
        provider_id="author",
    )
    seed_agent(
        ctx.store,
        roles=[AdmissionRole.ADJUDICATOR.value, AdmissionRole.INTEGRATOR.value],
        scores=all_dimension_scores(),
        provider_id="neutral",
    )
    policy = resolve_workforce_policy(committed_defaults())
    snap = build_workforce_snapshot(ctx, policy)
    prof, _reason = select_integrator(snap, policy, authoring_providers={"author"})
    assert prof is not None and prof.provider_id == "neutral"  # independent, chosen dynamically


@pytest.mark.adversarial
def test_policy_change_invalidates_active_snapshot(ctx, tmp_usf):
    from usf_factory.workforce import active_workforce_snapshot

    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="alpha")
    seed_agent(ctx.store, roles=[ANALYST.value], scores=all_dimension_scores(), provider_id="beta")
    eng = FactoryEngine(ctx, worker_factory=_factory(lambda p, a, n: _completed(p, a), []))
    snap1 = eng._current_workforce()  # built + persisted under the default policy
    assert active_workforce_snapshot(ctx, eng.policy) is not None  # fresh under same policy
    # An operator exclusion added mid-run changes the effective policy digest, so the
    # persisted snapshot is stale and MUST be rebuilt before the next dispatch.
    eng.policy = resolve_workforce_policy(
        committed_defaults(), None, WorkforcePolicyLayer(exclude_providers=["alpha"])
    )
    assert active_workforce_snapshot(ctx, eng.policy) is None  # stale under the new policy
    snap2 = eng._current_workforce()
    assert snap2.snapshot_id != snap1.snapshot_id
    assert "alpha" not in {p.provider_id for p in snap2.role_candidates(ANALYST)}


@pytest.mark.adversarial
def test_no_provider_name_in_run_path_source():
    root = Path(__file__).resolve().parents[1] / "src" / "usf_factory"
    names = (
        "claude",
        "codex",
        "ollama",
        "openrouter",
        "openai",
        "gemini",
        "mistral",
        "groq",
        "deepseek",
        "together",
        "huggingface",
        "cerebras",
        "sambanova",
        "anthropic",
    )
    for mod in (
        "engine.py",
        "dynamic_dispatch.py",
        "adaptive_routing.py",
        "dispatch.py",
        "eligibility.py",
    ):
        text = (root / mod).read_text(encoding="utf-8").lower()
        hits = [n for n in names if n in text]
        assert not hits, f"{mod} references provider name(s) {hits} in the run path"
